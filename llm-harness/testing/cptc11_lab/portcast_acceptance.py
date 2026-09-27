"""Fixed synthetic proof used only by the reviewed systemd acceptance unit."""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import time
from typing import Any


_RUN_ID = re.compile(r"^accept-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}$")
_ACCEPTANCE_ROOT = Path("/acceptance")
_AUDIT_ROOT = Path(
    "/var/lib/cptc-harness/portcast-live-v1/runtime/v3/runtime/audit"
)
_AGE = Path("/app/vendor/portcast-rootfs-runtime/bin/age")
_RECIPIENT = "age1wkvzdqsamcwuug4nk3q6g4c3zp44dkx2taak89ywh2ztvpdcpu0qavdfrv"
_SYNTHETIC = b"portcast-local-synthetic-systemd-acceptance-v1\n"


def _require_service_identity():
    """Use the same in-root nonroot identity guard as production."""

    from testing.cptc11_lab.portcast_service import _require_service_identity as require

    return require()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace(
        "+00:00", "Z"
    )


def _status() -> dict[str, str]:
    return dict(
        line.split(":", 1)
        for line in Path("/proc/self/status").read_text().splitlines()
        if ":" in line
    )


def _atomic_receipt(value: dict[str, Any]) -> None:
    path = _ACCEPTANCE_ROOT / "worker-receipt.json"
    temporary = path.with_name(path.name + ".new")
    descriptor = os.open(
        temporary,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
        0o600,
    )
    try:
        raw = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("ascii") + b"\n"
        offset = 0
        while offset < len(raw):
            offset += os.write(descriptor, raw[offset:])
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.replace(temporary, path)
    directory = os.open(_ACCEPTANCE_ROOT, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def main(*, verified_release: Any, run_id: str) -> int:
    try:
        service_identity = _require_service_identity()
    except RuntimeError:
        return 1
    if _RUN_ID.fullmatch(run_id) is None:
        return 1
    if Path("/run/credentials").exists():
        return 1
    for root in (_ACCEPTANCE_ROOT, _AUDIT_ROOT):
        info = root.stat()
        if (
            not stat.S_ISDIR(info.st_mode)
            or info.st_uid != service_identity.uid
            or info.st_gid != service_identity.gid
            or stat.S_IMODE(info.st_mode) != 0o700
        ):
            return 1
    status = _status()
    if status.get("CapEff", "").strip() != "0000000000000000":
        return 1
    started_at = _now()
    started_monotonic_ns = time.monotonic_ns()
    parent_netns = os.stat("/proc/self/ns/net").st_ino
    from cptc_harness.audit_service import AuditService
    from cptc_harness.contracts import PolicySnapshot, ScopeSpec

    policy = PolicySnapshot(
        "synthetic-systemd-acceptance",
        "portcast-live-v1",
        "synthetic-local",
        "local-rootdirectory",
        "root",
        ScopeSpec(),
    )
    audit = AuditService(
        _AUDIT_ROOT,
        policy,
        age_binary=_AGE,
        age_recipient=_RECIPIENT,
        verified_release=verified_release,
    )
    try:
        sandbox = dict(audit.sandbox_info)
        if (
            sandbox.get("cap_eff") != "0000000000000000"
            or sandbox.get("netns_inode") == parent_netns
            or sandbox.get("interfaces") not in ([], ["lo"])
            or sandbox.get("entry_fds") != [0, 1, 2]
            or sandbox.get("traffic")
            != {
                "af_inet_attempts": 0,
                "af_inet6_attempts": 0,
                "target_bytes": 0,
            }
            or sandbox.get("af_inet_attempts") != 0
            or sandbox.get("credential_fds") != 0
            or sandbox.get("target_addresses") is not False
        ):
            return 1
        request_id = "synthetic-systemd-acceptance"
        audit.reserve_output(request_id, len(_SYNTHETIC))
        reference = audit.capture(
            request_id, "raw", _SYNTHETIC, "client_confidential_human_only"
        )
        audit.release_output(request_id)
        verification = audit.verify()
        ciphertext_path = _AUDIT_ROOT / reference.artifact_relpath
        ciphertext = ciphertext_path.read_bytes()
        if not verification.valid or not ciphertext.startswith(b"age-encryption.org/"):
            return 1
        completed_at = _now()
        completed_monotonic_ns = time.monotonic_ns()
        receipt = {
            "schema_version": 2,
            "started_at": started_at,
            "completed_at": completed_at,
            "started_monotonic_ns": started_monotonic_ns,
            "completed_monotonic_ns": completed_monotonic_ns,
            "service_identity": {
                "account": service_identity.account,
                "group": service_identity.group,
                "uid": service_identity.uid,
                "gid": service_identity.gid,
                "cap_eff": status["CapEff"].strip(),
            },
            "audit_worker": {
                "cap_eff": sandbox["cap_eff"],
                "netns_isolated": True,
                "interfaces": sandbox["interfaces"],
                "entry_fds": sandbox["entry_fds"],
                "traffic": sandbox["traffic"],
                "af_inet_attempts": sandbox["af_inet_attempts"],
                "credential_fds": sandbox["credential_fds"],
                "target_addresses": sandbox["target_addresses"],
            },
            "ciphertext": {
                "artifacts": 1,
                "bytes": len(ciphertext),
                "sha256": hashlib.sha256(ciphertext).hexdigest(),
                "integrity_valid": True,
            },
            "credentials": False,
            "live_action": False,
            "af_inet_attempts": 0,
            "target_addresses": False,
            "automatic_retry": False,
            "limitations": [
                "privileged acceptance is local synthetic evidence only"
            ],
        }
        _atomic_receipt(receipt)
    finally:
        audit.close()
    return 0


__all__ = ("main",)
