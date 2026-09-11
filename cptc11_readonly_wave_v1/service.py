"""Local Unix sequence-packet authority for the read-only wave."""

from __future__ import annotations

from dataclasses import dataclass
import json
import os
import re
from pathlib import Path
from typing import Any


class ServiceError(RuntimeError):
    """The local service rejected a peer or packet."""


@dataclass(frozen=True, slots=True)
class ServiceConfig:
    socket_path: Path
    stop_path: Path
    peer_uids: frozenset[int] = frozenset()
    max_packet: int = 16 * 1024
    owner_uid: int | None = None
    group_gid: int | None = None
    peer_primary_gids: frozenset[int] = frozenset()
    socket_mode: int = 0o660
    parent_mode: int = 0o750

    def __post_init__(self) -> None:
        if (self.max_packet < 256 or self.max_packet > 1 << 20
                or any(type(uid) is not int or uid < 0 for uid in self.peer_uids | self.peer_primary_gids)
                or self.owner_uid is not None and (type(self.owner_uid) is not int or self.owner_uid < 0)
                or self.group_gid is not None and (type(self.group_gid) is not int or self.group_gid < 0)
                or self.socket_mode != 0o660 or self.parent_mode != 0o750):
            raise ValueError("service configuration is invalid")
        object.__setattr__(self, "socket_path", Path(self.socket_path))
        object.__setattr__(self, "stop_path", Path(self.stop_path))


@dataclass(frozen=True, slots=True)
class PeerIdentity:
    uid: int
    gid: int
    pid: int


def _pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in items:
        if key in result: raise ServiceError("duplicate JSON field")
        result[key] = value
    return result


def _decode_request(packet: bytes | str, *, maximum: int = 16 * 1024) -> dict[str, Any]:
    if isinstance(packet, str): packet = packet.encode("utf-8")
    if type(packet) is not bytes or not packet or len(packet) > maximum or b"\x00" in packet:
        raise ServiceError("packet is invalid")
    try:
        value = json.loads(packet.decode("utf-8"), object_pairs_hook=_pairs,
                           parse_constant=lambda _: (_ for _ in ()).throw(ServiceError("nonfinite JSON")))
    except (UnicodeDecodeError, json.JSONDecodeError, ServiceError, RecursionError) as exc:
        raise ServiceError("request JSON is invalid") from exc
    if not isinstance(value, dict) or not isinstance(value.get("method"), str): raise ServiceError("request method is invalid")
    method = value["method"]
    fields = {"info": {"method"}, "plan": {"method"}, "inspect": {"method"}, "stop": {"method"},
              "execute": {"method", "wave_id", "plan_id", "action_id", "profile_id"}}
    if method not in fields or set(value) != fields[method]: raise ServiceError("request fields are not admitted")
    if method == "execute" and any(type(value[key]) is not str or not value[key] or len(value[key]) > 256 for key in fields[method] - {"method"}): raise ServiceError("request identity is invalid")
    return value


def _encode_request(value: dict[str, Any]) -> bytes:
    # Round-trip through the decoder to apply the same closed schema to all
    # callers.  Canonical JSON makes the packet hash stable for audit records.
    try:
        checked = _decode_request(json.dumps(value, ensure_ascii=True, allow_nan=False).encode("ascii"))
    except (TypeError, ValueError) as exc:
        raise ServiceError("request is not canonical JSON") from exc
    return json.dumps(checked, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")


_RESPONSE_FIELDS = {
    "info": {"status", "service"}, "plan": {"status", "actions"},
    "inspect": {"status", "stopped"}, "stop": {"status"},
    "execute": {"status", "wave_id", "action_id", "profile_id", "target_id", "evidence_sha256"},
}
_RESPONSE_STATUS = {
    "info": {"ready"}, "plan": {"ready"}, "inspect": {"ready", "stopped"},
    "stop": {"stopped"}, "execute": {"complete", "cancelled", "uncertain", "failed"},
}
_RESPONSE_DIGEST = re.compile(r"^[0-9a-f]{64}$")


def _bounded_text(value: Any) -> bool:
    return type(value) is str and bool(value) and len(value) <= 256 and "\x00" not in value


def _validate_response_types(value: dict[str, Any], method: str) -> None:
    if value.get("status") not in _RESPONSE_STATUS[method]: raise ServiceError("response status is invalid")
    if method == "info":
        if not _bounded_text(value.get("service")): raise ServiceError("service identity is invalid")
    elif method == "plan":
        if type(value.get("actions")) is not int or value["actions"] < 0: raise ServiceError("action count is invalid")
    elif method == "inspect":
        if type(value.get("stopped")) is not bool: raise ServiceError("stop state is invalid")
    elif method == "execute":
        for key in ("wave_id", "action_id", "profile_id", "target_id"):
            if not _bounded_text(value.get(key)): raise ServiceError(f"{key} is invalid")
        if _RESPONSE_DIGEST.fullmatch(value.get("evidence_sha256", "")) is None: raise ServiceError("evidence digest is invalid")


def _decode_response(packet: bytes, *, maximum: int = 16 * 1024, method: str | None = None) -> dict[str, Any]:
    if type(packet) is not bytes or not packet or len(packet) > maximum:
        raise ServiceError("response packet is invalid")
    try:
        value = json.loads(packet.decode("utf-8"), object_pairs_hook=_pairs,
                           parse_constant=lambda _: (_ for _ in ()).throw(ServiceError("nonfinite JSON")))
    except (UnicodeDecodeError, json.JSONDecodeError, ServiceError, RecursionError) as exc:
        raise ServiceError("response JSON is invalid") from exc
    if not isinstance(value, dict): raise ServiceError("response is not an object")
    from .metadata import validate_metadata
    try: validate_metadata(value)
    except Exception as exc: raise ServiceError("response contains restricted metadata") from exc
    if value.get("status") == "rejected":
        if set(value) != {"status", "reason"} or type(value.get("reason")) is not str: raise ServiceError("rejection response is invalid")
    elif method is not None and method in _RESPONSE_FIELDS and set(value) != _RESPONSE_FIELDS[method]:
        raise ServiceError("response fields do not match method")
    elif method is None and set(value) - set().union(*_RESPONSE_FIELDS.values()):
        raise ServiceError("response fields are not admitted")
    if value.get("status") != "rejected" and method is not None and method in _RESPONSE_FIELDS: _validate_response_types(value, method)
    return value


def _encode_response(value: dict[str, Any], *, method: str | None = None) -> bytes:
    if type(value) is not dict: raise ServiceError("response is invalid")
    forbidden = {"raw", "body", "headers", "url", "path", "credential", "ciphertext", "command", "password", "token", "secret"}
    def check(item: Any) -> None:
        if isinstance(item, dict):
            if forbidden.intersection(item): raise ServiceError("response contains restricted fields")
            for child in item.values(): check(child)
        elif isinstance(item, list):
            for child in item: check(child)
    check(value)
    try: encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")
    except (TypeError, ValueError): raise ServiceError("response is not metadata") from None
    if len(encoded) > 16 * 1024: raise ServiceError("response is oversized")
    _decode_response(encoded, method=method)
    return encoded


def _validate_peer(peer: PeerIdentity, config: ServiceConfig) -> None:
    if (not isinstance(peer, PeerIdentity) or type(peer.uid) is not int or peer.uid < 0
            or type(peer.gid) is not int or peer.gid < 0 or type(peer.pid) is not int or peer.pid <= 0
            or (peer.uid not in config.peer_uids and peer.gid not in config.peer_primary_gids)):
        raise ServiceError("peer is not enrolled")


def _peer_from_socket(server_socket: Any) -> PeerIdentity:
    """Read Linux ``SO_PEERCRED`` without trusting packet fields."""
    try:
        module = _socket_module()
        raw = server_socket.getsockopt(module.SOL_SOCKET, module.SO_PEERCRED, 12)
        uid = int.from_bytes(raw[4:8], "little")
        gid = int.from_bytes(raw[8:12], "little")
        pid = int.from_bytes(raw[0:4], "little", signed=True)
        return PeerIdentity(uid, gid, pid)
    except Exception as exc:
        raise ServiceError("peer credentials are unavailable") from exc


def _socket_module():
    # Keep the source-only package import-free for package-1 collectors.  IPC
    # is loaded only by the local authority entry point.
    return __import__("socket")


class ReadonlyWaveService:
    def __init__(self, config: ServiceConfig, broker: Any):
        self.config, self.broker = config, broker
        self._stopped = config.stop_path.exists()

    def _durable_stop(self, reason: str = "operator stop") -> None:
        path = self.config.stop_path
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True); path.parent.chmod(0o700)
        if path.is_symlink() or path.exists() and not path.is_file():
            raise ServiceError("stop path is invalid")
        if not path.exists():
            fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                json.dump({"reason": reason}, stream, separators=(",", ":")); stream.flush(); os.fsync(stream.fileno())
        self._stopped = True

    def handle_packet(self, packet: bytes | str, peer: PeerIdentity) -> dict[str, Any]:
        _validate_peer(peer, self.config)
        request = _decode_request(packet, maximum=self.config.max_packet)
        method = request["method"]
        if method == "stop":
            self._durable_stop(); return {"status": "stopped"}
        if self._stopped or self.config.stop_path.exists(): raise ServiceError("service is stopped")
        if method == "info": return {"status": "ready", "service": "cptc11-readonly-wave-v1"}
        if method == "plan": return {"status": "ready", "actions": 4}
        if method == "inspect": return {"status": "ready", "stopped": False}
        if method == "execute":
            if self.broker is None: raise ServiceError("broker is unavailable")
            try: result = self.broker.execute(request["wave_id"], request["plan_id"], request["action_id"], request["profile_id"])
            except Exception as exc: raise ServiceError("execution was rejected") from exc
            return {"status": result.outcome, "wave_id": request["wave_id"], "action_id": result.action_id, "profile_id": result.profile_id,
                    "target_id": result.target_id, "evidence_sha256": result.evidence_sha256}
        raise ServiceError("method is not admitted")

    def _handle_request(self, packet: bytes | str, peer: PeerIdentity) -> bytes:
        request = _decode_request(packet, maximum=self.config.max_packet)
        return _encode_response(self.handle_packet(packet, peer), method=request["method"])

    def serve_once(self, server_socket: Any, peer: PeerIdentity) -> bytes:
        packet = server_socket.recv(self.config.max_packet)
        return self._handle_request(packet, peer)

    def serve_forever(self) -> None:
        module = _socket_module()
        path = self.config.socket_path
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True); path.parent.chmod(0o700)
        if path.exists() or path.is_symlink(): raise ServiceError("service socket path already exists")
        if self.config.owner_uid is None or self.config.group_gid is None:
            raise ServiceError("explicit socket owner and group policy are required")
        owner_uid = self.config.owner_uid; group_gid = self.config.group_gid
        try:
            os.chown(path.parent, owner_uid, group_gid); os.chmod(path.parent, self.config.parent_mode)
        except OSError as exc: raise ServiceError("service parent ownership could not be established") from exc
        server = module.socket(module.AF_UNIX, module.SOCK_SEQPACKET)
        try:
            server.bind(str(path)); os.chown(path, owner_uid, group_gid); os.chmod(path, self.config.socket_mode)
            if path.stat().st_uid != owner_uid or path.stat().st_gid != group_gid or path.stat().st_mode & 0o777 != self.config.socket_mode:
                raise ServiceError("service socket permissions differ")
            server.listen(1)
            server.settimeout(0.25)
            while not self._stopped and not self.config.stop_path.exists():
                try: client, _ = server.accept()
                except TimeoutError: continue
                with client:
                    client.settimeout(self.config.max_packet / 1024)
                    try:
                        response = self._handle_request(client.recv(self.config.max_packet + 1), _peer_from_socket(client))
                    except ServiceError as exc:
                        response = _encode_response({"status": "rejected", "reason": str(exc)}, method="error")
                    sent = client.send(response)
                    if sent != len(response): raise ServiceError("short response send")
        finally:
            server.close()
            try: path.unlink()
            except FileNotFoundError: pass


class ReadonlyWaveClient:
    def __init__(self, socket_path: str | Path, *, timeout: float = 2.0):
        self.socket_path = str(socket_path); self.timeout = timeout

    def request(self, value: dict[str, Any]) -> dict[str, Any]:
        module = _socket_module(); sock = module.socket(module.AF_UNIX, module.SOCK_SEQPACKET)
        response = b""
        try:
            sock.settimeout(self.timeout); sock.connect(self.socket_path)
            request = _encode_request(value)
            sent = sock.send(request)
            if sent != len(request): raise ServiceError("short request send")
            response = sock.recv(16 * 1024 + 1)
        finally: sock.close()
        return _decode_response(response, method=value.get("method"))
