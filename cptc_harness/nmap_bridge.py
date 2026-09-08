"""A one-connect native Nmap bridge with a parent-owned TCP decision."""
from __future__ import annotations

import errno
import hashlib
import ipaddress
import os
from pathlib import Path
import resource
import select
import selectors
import signal
import socket
import struct
import subprocess
import time

from .collectors.base import batch_result, stopped
from .contracts import ExecutionContext, OperationResult, PolicyError, SourceRef
from .integrity import verified_executable
from .isolation import fork_denial_filter
from .parsers import parse_nmap_xml
from .parsers.common import in_scope
from .tool_catalog import verified_native_file


# The AF_UNIX endpoints are on one host.  These layouts intentionally mirror
# the reviewed C structs; the source includes fixed-width fields and no host
# data crosses this local IPC boundary.
_REQUEST = struct.Struct("=IHHHH16s")
_RESPONSE = struct.Struct("=Iii")
_REQUEST_MAGIC = 0x43504E51
_RESPONSE_MAGIC = 0x43504E52
_OUTPUT_CAP = 131072
_DEADLINE_S = 30.0
_PROCESS_DEADLINE_S = 30.0
_RPC_POLL_S = 0.05


class _BridgeFailure(RuntimeError):
    def __init__(self, reason: str, evidence=()):
        super().__init__(reason)
        self.evidence = tuple(evidence)


class _BridgeStopped(RuntimeError):
    def __init__(self, *, probe_seen: bool, evidence=()):
        super().__init__("native Nmap stop requested")
        self.probe_seen = probe_seen
        self.evidence = tuple(evidence)


def _child_limits() -> None:
    """Apply fixed ceilings before bubblewrap execs the scanner."""
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_AS, (268435456, 268435456))
    resource.setrlimit(resource.RLIMIT_CPU, (30, 30))
    resource.setrlimit(resource.RLIMIT_NOFILE, (32, 32))


def _terminate(process: subprocess.Popen[bytes] | None) -> None:
    if process is None or process.poll() is not None:
        return
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    try:
        process.wait(timeout=2)
    except subprocess.TimeoutExpired:
        raise _BridgeFailure("scanner containment did not exit") from None


def _close_streams(process: subprocess.Popen[bytes] | None) -> None:
    if process is None:
        return
    for stream in (process.stdin, process.stdout, process.stderr):
        if stream is not None:
            try:
                stream.close()
            except OSError:
                pass


class _StreamCapture:
    """Retain only bounded raw stream bytes and capture them as they arrive."""
    def __init__(self, context: ExecutionContext, network) -> None:
        self.context, self.network = context, network
        self.buffers = {"stdout": bytearray(), "stderr": bytearray()}
        self.evidence = []
        self.seen = set()
        self.completed = set()

    def add(self, stream: str, data: bytes) -> None:
        available = _OUTPUT_CAP - len(self.buffers["stdout"]) - len(self.buffers["stderr"])
        retained = data[:max(0, available)]
        if retained:
            self.buffers[stream].extend(retained)
            self.seen.add(stream)
            self._capture(stream, retained)
        if len(retained) != len(data):
            self.network._event("native_nmap_capture_incomplete", {
                "stream": stream, "retained_bytes": len(retained), "discarded_bytes": len(data) - len(retained),
            })
            raise _BridgeFailure("scanner output exceeded fixed capture limit", self.evidence)

    def drain(self, stream: str, data: bytes) -> None:
        """Capture the retained suffix after containment, never raising again."""
        available = _OUTPUT_CAP - len(self.buffers["stdout"]) - len(self.buffers["stderr"])
        retained = data[:max(0, available)]
        if retained:
            self.buffers[stream].extend(retained)
            self.seen.add(stream)
            self._capture(stream, retained)
        if len(retained) != len(data):
            self.network._event("native_nmap_capture_incomplete", {
                "stream": stream, "retained_bytes": len(retained), "discarded_bytes": len(data) - len(retained),
            })

    def finish_stream(self, stream: str) -> None:
        if stream in self.completed:
            return
        self.completed.add(stream)
        if stream not in self.seen:
            self._capture(stream, b"")

    def _capture(self, stream: str, payload: bytes) -> None:
        if self.context.capture is None:
            return
        try:
            reference = self.context.capture(stream, payload, "client_confidential_human_only")
        except Exception:
            raise _BridgeFailure("native Nmap raw capture failed", self.evidence) from None
        if reference is not None:
            self.evidence.append(reference)


class NmapCollector:
    """Run one fixed connect scan while the parent mediates its sole connect."""

    def collect(self, context: ExecutionContext) -> OperationResult:
        if context.stopped():
            return stopped()
        try:
            target, address, shim, nmap, bwrap = self._preflight(context)
        except PolicyError as exc:
            return OperationResult("blocked", reason=str(exc))

        network = context.network
        assert network is not None
        network._event("native_nmap_intent", {
            "target": target.target_id,
            "address": address,
            "port": target.port,
            "profile": "nmap-connect-one-v1",
            "nmap_sha256": hashlib.sha256(nmap.read_bytes()).hexdigest(),
            "shim_sha256": hashlib.sha256(shim.read_bytes()).hexdigest(),
        })

        process = None
        parent = child = None
        seccomp_fd = None
        dispatched = False
        evidence = ()
        captured = None
        cancelled = False
        completion_reason = None
        cleanup_failed = False
        def cleanup():
            nonlocal cleanup_failed
            try:
                _terminate(process)
            except Exception:
                cleanup_failed = True
                # Latch before any subsequent cleanup/audit operation can fail.
                network._stop("native Nmap containment termination failed")
        try:
            parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
            parent.setblocking(False)
            # bubblewrap deliberately closes non-standard inherited descriptors.
            # stdin is its one stable pass-through descriptor, and Nmap's fixed
            # XML-to-stdout profile never consumes it.  It therefore carries the
            # sole AF_UNIX RPC socket into the networkless worker as fd 0.
            command = self._command(bwrap, nmap, shim, 0, address, target.port)
            seccomp_fd = fork_denial_filter()
            command[6:6] = ["--seccomp", str(seccomp_fd)]
            network._event("native_nmap_process_intent", {
                "target": target.target_id,
                "address": address,
                "port": target.port,
                "profile": "nmap-connect-one-v1",
                "timeout_s": _DEADLINE_S,
                "output_bytes": _OUTPUT_CAP,
                "cwd": "/",
                "environment": {"LD_PRELOAD": "/nmap-connect.so", "CPTC_NMAP_RPC_FD": "0"},
                "command": command,
            })
            process = subprocess.Popen(
                command, stdin=child, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                close_fds=True, pass_fds=(seccomp_fd,), start_new_session=True,
                env={}, preexec_fn=_child_limits,
            )
            dispatched = True
            child.close()
            child = None
            network._event("native_nmap_process_started", {"pid": process.pid, "target": target.target_id})
            captured = _StreamCapture(context, network)
            stdout, stderr, observed_state, evidence = self._run(context, process, parent, target, address, captured)
            if process.returncode != 0:
                raise _BridgeFailure("scanner exited unsuccessfully", evidence)
            source = SourceRef("native-nmap", hashlib.sha256(stdout).hexdigest(), tool="nmap")
            batch = parse_nmap_xml(stdout, source, context.policy.scope)
            try:
                self._cross_check(batch, address, target.port, observed_state)
            except _BridgeFailure as exc:
                exc.evidence = evidence
                raise
            network._event("native_nmap_result", {
                "target": target.target_id, "address": address, "port": target.port,
                "state": observed_state, "exit_code": process.returncode,
            })
            return batch_result(batch, evidence)
        except _BridgeStopped as exc:
            cancelled = True
            completion_reason = "operator_stop"
            cleanup()
            retained = tuple(exc.evidence) or evidence
            if exc.probe_seen:
                network._stop("native Nmap stopped after parent probe")
                return OperationResult("uncertain", evidence=retained,
                                       reason="native Nmap stopped after parent probe; human review required")
            return OperationResult("stopped", evidence=retained, reason="operator stop requested")
        except (OSError, PolicyError, _BridgeFailure, subprocess.SubprocessError) as exc:
            cancelled = True
            completion_reason = str(exc)
            cleanup()
            if dispatched:
                network._stop("native Nmap bridge outcome uncertain")
                return OperationResult("uncertain", evidence=tuple(getattr(exc, "evidence", ())) or evidence,
                                       reason="native Nmap bridge outcome uncertain; human review required")
            return OperationResult("blocked", reason="native Nmap bridge could not start")
        finally:
            if seccomp_fd is not None:
                os.close(seccomp_fd)
            if child is not None:
                child.close()
            if parent is not None:
                parent.close()
            if process is not None:
                cleanup()
                network._event("native_nmap_process_completed", {
                    "pid": process.pid, "exit_code": process.returncode, "cancelled": cancelled,
                    "reason": completion_reason,
                    "stdout_bytes": len(captured.buffers["stdout"]) if captured is not None else 0,
                    "stderr_bytes": len(captured.buffers["stderr"]) if captured is not None else 0,
                })
                _close_streams(process)
            if cleanup_failed:
                return OperationResult("uncertain", evidence=tuple(captured.evidence) if captured else evidence,
                                       reason="native Nmap containment termination failed; human review required")

    @staticmethod
    def _preflight(context: ExecutionContext):
        target, network = context.request.target, context.network
        if target is None or network is None:
            raise PolicyError("native bridge requires a brokered target")
        bounds = context.spec.bounds
        if (bounds.request_limit != 1 or bounds.output_bytes != _OUTPUT_CAP or
                bounds.process_limit != 1 or bounds.timeout_s != _DEADLINE_S):
            raise PolicyError("native bridge requires fixed one-probe bounds")
        policy_target = next((item for item in context.policy.targets if item.target.target_id == target.target_id), None)
        if policy_target is None or policy_target.target != target:
            raise PolicyError("native bridge target does not exactly match policy")
        addresses = getattr(context.transport, "_addresses", ())
        if not isinstance(addresses, tuple) or len(addresses) != 1:
            raise PolicyError("native bridge requires one broker-pinned address")
        try:
            address = str(ipaddress.ip_address(addresses[0]))
        except ValueError:
            raise PolicyError("native bridge address is invalid") from None
        if ipaddress.ip_address(address).version != 4:
            raise PolicyError("this native Nmap release admits IPv4 only; IPv6 requires a reviewed profile")
        if not in_scope(address, context.policy.scope):
            raise PolicyError("native bridge address is outside approved scope")
        if target.port not in range(1, 65536):
            raise PolicyError("native bridge port is invalid")
        # Every deployment artifact is reviewed before the process can emit a
        # request.  The build step is offline and never runs here.
        shim = verified_native_file("nmap-shim")
        nmap = verified_native_file("nmap")
        bwrap = verified_executable("/usr/bin/bwrap")
        return target, address, shim, nmap, bwrap

    @staticmethod
    def _command(bwrap: Path, nmap: Path, shim: Path, rpc_fd: int, address: str, port: int) -> list[str]:
        try:
            nmap.relative_to("/usr")
            scanner = str(nmap)
            scanner_bind: list[str] = []
        except ValueError:
            # Synthetic acceptance uses a fixture outside /usr.  Production
            # pins /usr/bin/nmap, so the fixed native binary remains the only
            # scanner executable in normal operation.
            scanner = "/nmap"
            scanner_bind = ["--ro-bind", str(nmap), scanner]
        return [
            str(bwrap), "--unshare-all", "--cap-drop", "ALL", "--die-with-parent", "--new-session",
            "--clearenv", "--ro-bind", "/usr", "/usr", "--symlink", "usr/lib", "/lib",
            "--symlink", "usr/lib", "/lib64", "--symlink", "usr/bin", "/bin", "--proc", "/proc",
            "--dev", "/dev", "--dir", "/tmp", "--ro-bind", str(shim), "/nmap-connect.so",
            *scanner_bind,
            "--setenv", "LD_PRELOAD", "/nmap-connect.so", "--setenv", "CPTC_NMAP_RPC_FD", str(rpc_fd),
            "--", scanner, "-sT", "--unprivileged", "-Pn", "-n", "-p", str(port),
            "--max-retries", "0", "--max-parallelism", "1", "--host-timeout", "8s", "-oX", "-", address,
        ]

    def _run(self, context: ExecutionContext, process: subprocess.Popen[bytes], parent: socket.socket,
             target, address: str, captured: _StreamCapture) -> tuple[bytes, bytes, str, tuple]:
        if process.stdout is None or process.stderr is None:
            raise _BridgeFailure("scanner output pipes are unavailable")
        selector = selectors.DefaultSelector()
        selector.register(parent, selectors.EVENT_READ, "rpc")
        selector.register(process.stdout, selectors.EVENT_READ, "stdout")
        selector.register(process.stderr, selectors.EVENT_READ, "stderr")
        observed_state = None
        deadline = time.monotonic() + _PROCESS_DEADLINE_S
        try:
            while selector.get_map():
                if context.stopped():
                    raise _BridgeStopped(probe_seen=observed_state is not None, evidence=captured.evidence)
                if time.monotonic() >= deadline:
                    raise _BridgeFailure("scanner deadline exceeded")
                events = selector.select(_RPC_POLL_S)
                for key, _ in events:
                    if key.data == "rpc":
                        request, _ancillary, flags, _address = parent.recvmsg(_REQUEST.size + 1)
                        if not request:
                            selector.unregister(parent)
                            continue
                        if (flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC) or _ancillary or
                                len(request) != _REQUEST.size):
                            raise _BridgeFailure("native bridge request is malformed", captured.evidence)
                        if observed_state is not None:
                            raise _BridgeFailure("scanner requested more than one TCP connect")
                        observed_state = self._parent_connect(context, parent, request, target, address, deadline)
                    else:
                        data = os.read(key.fileobj.fileno(), 65536)
                        if not data:
                            captured.finish_stream(key.data)
                            selector.unregister(key.fileobj)
                            continue
                        captured.add(key.data, data)
                if process.poll() is not None and not events:
                    # Poll once more so EOF on the pipe descriptors is consumed.
                    continue
            process.wait(timeout=1)
        except _BridgeFailure as exc:
            self._drain_after_failure(process, captured)
            exc.evidence = tuple(captured.evidence)
            raise
        except _BridgeStopped as exc:
            self._drain_after_failure(process, captured)
            exc.evidence = tuple(captured.evidence)
            raise
        finally:
            selector.close()
        if observed_state is None:
            raise _BridgeFailure("scanner did not use the native connect bridge", captured.evidence)
        return (bytes(captured.buffers["stdout"]), bytes(captured.buffers["stderr"]),
                observed_state, tuple(captured.evidence))

    @staticmethod
    def _drain_after_failure(process: subprocess.Popen[bytes], captured: _StreamCapture) -> None:
        """Kill the scanner, then drain bounded pipe data before they are closed."""
        if process.poll() is None:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        for stream_name, stream in (("stdout", process.stdout), ("stderr", process.stderr)):
            if stream is None:
                continue
            ended = False
            try:
                while True:
                    readable, _writable, _exceptional = select.select([stream], [], [], 0.2)
                    if not readable:
                        break
                    data = os.read(stream.fileno(), 65536)
                    if not data:
                        ended = True
                        break
                    captured.drain(stream_name, data)
            except (OSError, _BridgeFailure):
                pass
            if ended:
                try:
                    captured.finish_stream(stream_name)
                except _BridgeFailure:
                    pass
            else:
                captured.network._event("native_nmap_capture_incomplete", {
                    "stream": stream_name, "retained_bytes": len(captured.buffers[stream_name]),
                    "discarded_bytes": 0,
                })

    @staticmethod
    def _parent_connect(context: ExecutionContext, parent: socket.socket, packet: bytes, target, address: str,
                        deadline: float) -> str:
        if len(packet) != _REQUEST.size:
            raise _BridgeFailure("native bridge request is malformed")
        magic, version, family, port, reserved, packed_address = _REQUEST.unpack(packet)
        if magic != _REQUEST_MAGIC or version != 1 or reserved != 0 or port != target.port:
            raise _BridgeFailure("native bridge request is outside its grant")
        try:
            requested = ipaddress.ip_address(packed_address[:4] if family == socket.AF_INET else packed_address)
            expected = ipaddress.ip_address(address)
        except ValueError:
            raise _BridgeFailure("native bridge address is malformed") from None
        expected_family = socket.AF_INET if expected.version == 4 else socket.AF_INET6
        if family != expected_family or requested != expected:
            raise _BridgeFailure("native bridge request is outside its grant")
        network = context.network
        network._event("native_nmap_connection_intent", {
            "target": target.target_id, "address": address, "port": target.port,
        })
        network._rate(target.target_id)
        started = time.monotonic()
        error_number = 0
        sock = socket.socket(family, socket.SOCK_STREAM)
        try:
            sock.setblocking(False)
            if family == socket.AF_INET6:
                error_number = sock.connect_ex((address, target.port, 0, 0))
            else:
                error_number = sock.connect_ex((address, target.port))
            while error_number in {errno.EINPROGRESS, errno.EALREADY, errno.EWOULDBLOCK}:
                if context.stopped():
                    raise _BridgeStopped(probe_seen=True)
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise _BridgeFailure("parent TCP connect deadline exceeded")
                _readable, writable, exceptional = select.select([], [sock], [sock], min(_RPC_POLL_S, remaining))
                if writable or exceptional:
                    error_number = sock.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
            state = "open" if error_number == 0 else "closed" if error_number == errno.ECONNREFUSED else "uncertain"
        except OSError as exc:
            error_number = exc.errno or errno.EIO
            state = "closed" if error_number == errno.ECONNREFUSED else "uncertain"
        finally:
            sock.close()
        parent.sendall(_RESPONSE.pack(_RESPONSE_MAGIC, 0 if error_number == 0 else -1, error_number))
        network._event("native_nmap_connection_result", {
            "target": target.target_id, "address": address, "port": target.port, "state": state,
            "errno": error_number, "elapsed_ms": int((time.monotonic() - started) * 1000),
        })
        return state

    @staticmethod
    def _cross_check(batch, address: str, port: int, observed_state: str) -> None:
        if observed_state not in {"open", "closed"} or len(batch.issues) or len(batch.observations) != 1:
            raise _BridgeFailure("native Nmap XML outcome is not exact")
        observation = batch.observations[0]
        ports = observation.facts.get("ports")
        if observation.target != address or not isinstance(ports, tuple) or len(ports) != 1:
            raise _BridgeFailure("native Nmap XML target is not exact")
        record = ports[0]
        if record.get("port") != port or record.get("state") != observed_state:
            raise _BridgeFailure("native Nmap XML state disagrees with parent connect")
