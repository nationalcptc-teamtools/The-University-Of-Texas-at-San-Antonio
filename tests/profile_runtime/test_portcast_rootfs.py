"""Production trust-boundary tests for the sealed PortCast root filesystem."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import re
import importlib.util
from dataclasses import asdict
import shutil
import socket
import struct
import time

import pytest

from cptc_harness.contracts import canonical_json
from cptc_harness.memfd import MFD_ALLOW_SEALING, MFD_CLOEXEC, memfd_create
from tests.test_audit_rotation import policy


ROOT = Path(__file__).parents[2]
RUNTIME_LOCK = ROOT / "cptc_harness/resources/portcast-cpython-runtime-v1.json"
_DEPLOYMENT_SPEC = importlib.util.spec_from_file_location(
    "rootfs_deployment", ROOT / "deployment/manage-portcast-service.py"
)
deployment = importlib.util.module_from_spec(_DEPLOYMENT_SPEC)
assert _DEPLOYMENT_SPEC.loader is not None
_DEPLOYMENT_SPEC.loader.exec_module(deployment)


def _elf(path: Path, *arguments: str) -> str:
    return subprocess.run(
        ("/usr/bin/readelf", *arguments, str(path)),
        check=True,
        capture_output=True,
        text=True,
    ).stdout


def _rootfs(tmp_path: Path) -> tuple[Path, dict, Path]:
    manifest_path = ROOT / "cptc_harness/resources/release-integrity.json"
    manifest = json.loads(manifest_path.read_text())
    rootfs = tmp_path / "rootfs"
    for relative, payload in deployment._payloads(manifest).items():
        destination = rootfs / "app" / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(payload)
    anchor = rootfs / "etc/cptc-harness/trust/portcast-live-v1.sha256"
    anchor.parent.mkdir(parents=True)
    digest = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
    anchor.write_bytes(deployment._anchor_payload(manifest, digest))
    plan_path = rootfs / "app/testing/cptc11_lab/portcast-live-plan-v6.json"
    plan = json.loads(plan_path.read_text())
    audit = rootfs / "var/lib/cptc-harness/portcast-live-v1/runtime/v6/runtime/audit"
    audit.mkdir(parents=True)
    old_ledger = rootfs / "var/lib/cptc-harness/portcast-live-v1/runtime/ledger/cptc11-dell-validation"
    old_ledger.mkdir(parents=True)
    v6_ledger = rootfs / "var/lib/cptc-harness/portcast-live-v1/runtime/v6/ledger/cptc11-dell-validation-portcast-v6"
    v6_ledger.mkdir(parents=True)
    admission = rootfs / "var/lib/cptc-harness/portcast-live-v1/admission"
    projection = rootfs / "var/lib/cptc-harness/portcast-live-v1/admission-projection"
    admission.mkdir(parents=True)
    projection.mkdir(parents=True)
    (projection / "v6-start.marker").write_bytes(
        (
            "PORTCAST-START-V1\n"
            f"release {digest}\n"
            f"plan {hashlib.sha256(plan_path.read_bytes()).hexdigest()}\n"
            f"action {plan['action_id']}\n"
        ).encode()
    )
    (audit.parents[3] / "deployment.lock").write_bytes(b"")
    for relative in ("run/cptc-harness", "proc", "dev", "tmp"):
        (rootfs / relative).mkdir(parents=True, exist_ok=True)
    v5_admission = rootfs / "var/lib/cptc-harness/portcast-live-v1/predecessors/v5/admission"
    v5_projection = rootfs / "var/lib/cptc-harness/portcast-live-v1/predecessors/v5/admission-projection"
    v5_runtime = rootfs / "var/lib/cptc-harness/portcast-live-v1/runtime/v5-predecessor"
    v5_admission.mkdir(parents=True)
    v5_projection.mkdir(parents=True)
    v5_runtime.mkdir(parents=True)
    v5_marker = v5_admission / deployment._V5_MARKER_NAME
    v5_marker.write_bytes(deployment._V5_MARKER_PAYLOAD)
    receipt = v5_admission.parent / "receipt.json"
    receipt.write_bytes(deployment._V5_RECEIPT_BYTES)
    writable = {audit, v6_ledger, *audit.parents, *v6_ledger.parents}
    for item in rootfs.rglob("*"):
        item.chmod(0o700 if item.is_dir() and item in writable else 0o555 if item.is_dir() or item.name in {"portcast-bootstrap", "python3.14", "bwrap", "age", "ld-linux-x86-64.so.2"} else 0o444)
    admission.chmod(0o700)
    projection.chmod(0o755)
    v5_admission.chmod(0o700)
    v5_projection.chmod(0o755)
    v5_runtime.chmod(0o700)
    v5_marker.chmod(0o600)
    receipt.chmod(0o444)
    if os.geteuid() == 0:
        os.chown(v5_runtime, 12345, 12345)
    rootfs.chmod(0o555)
    return rootfs, manifest, audit


def _rpc(channel: socket.socket, method: str):
    raw = canonical_json({"method": method, "arguments": {}, "clock": {"synchronized": True, "offset_seconds": 0.0, "source": "synthetic"}})
    channel.sendall(struct.pack("!I", len(raw)) + raw)
    size = struct.unpack("!I", channel.recv(4))[0]
    return json.loads(channel.recv(size))


def test_bootstrap_is_static_and_has_no_loader_or_dynamic_dependencies():
    launcher = ROOT / "deployment/portcast-bootstrap"
    assert launcher.is_file()
    assert os.access(launcher, os.X_OK)
    assert "INTERP" not in _elf(launcher, "-l")
    dynamic = _elf(launcher, "-d")
    assert "NEEDED" not in dynamic
    assert "RPATH" not in dynamic
    assert "RUNPATH" not in dynamic


def test_bootstrap_build_is_reproducible_with_the_recorded_fixed_inputs(tmp_path):
    lock = json.loads(RUNTIME_LOCK.read_text())
    build = lock["build_tools"]
    outputs = []
    for index in range(2):
        output = tmp_path / f"launcher-{index}"
        environment = dict(build["launcher_environment"])
        environment["GOCACHE"] = str(tmp_path / f"go-cache-{index}")
        subprocess.run(
            (*build["launcher_argv"][:4], "-o", str(output), build["launcher_argv"][-1]),
            cwd=ROOT,
            env=environment,
            check=True,
            capture_output=True,
        )
        outputs.append(output.read_bytes())
    assert outputs[0] == outputs[1] == (ROOT / "deployment/portcast-bootstrap").read_bytes()


def test_rootfs_runtime_lock_covers_exact_cpython_bwrap_and_age_files():
    lock = json.loads(RUNTIME_LOCK.read_text())
    assert set(lock) == {
        "schema_version", "python_abi", "root", "entrypoints", "packages",
        "files", "elf_files", "build_tools", "external_tools", "transformations",
    }
    assert lock["schema_version"] == 1
    assert lock["python_abi"] == "cp314-x86_64-linux-gnu"
    assert lock["root"] == "vendor/portcast-rootfs-runtime"
    assert lock["entrypoints"] == {
        "age": "bin/age",
        "bubblewrap": "bin/bwrap",
        "loader": "lib/ld-linux-x86-64.so.2",
        "python": "bin/python3.14",
        "stdlib": "lib/python3.14",
    }
    runtime = ROOT / lock["root"]
    physical = {
        path.relative_to(runtime).as_posix()
        for path in runtime.rglob("*")
        if path.is_file() and not path.is_symlink()
    }
    assert physical == set(lock["files"])
    assert not any(path.is_symlink() for path in runtime.rglob("*"))
    for relative, expected in lock["files"].items():
        assert hashlib.sha256((runtime / relative).read_bytes()).hexdigest() == expected
    assert set(lock["elf_files"]) <= physical
    assert "bin/python3.14" in lock["elf_files"]
    assert "bin/bwrap" in lock["elf_files"]
    assert "lib/libpython3.14.so.1.0" in lock["elf_files"]
    assert lock["external_tools"]["age"]["version"] == "1.3.2"
    assert lock["external_tools"]["age"]["sha256"] == lock["files"]["bin/age"]
    assert all(
        "RPATH" not in _elf(runtime / relative, "-d")
        and "RUNPATH" not in _elf(runtime / relative, "-d")
        for relative in lock["elf_files"]
    )
    for relative in lock["elf_files"]:
        needed = re.findall(r"Shared library: \[([^]]+)\]", _elf(runtime / relative, "-d"))
        assert all(f"lib/{name}" in lock["elf_files"] for name in needed)


def test_service_unit_enters_private_root_and_has_no_host_runtime_fallback():
    unit = (ROOT / "deployment/portcast-live-v1.service").read_text()
    assert "RootDirectory=/usr/lib/cptc-harness/portcast-live-v1" in unit
    assert "ExecStart=/app/deployment/portcast-bootstrap" in unit
    assert "MountAPIVFS=yes" in unit
    assert "BindReadOnlyPaths=/etc/cptc-harness/trust/portcast-live-v1.sha256" in unit
    assert "BindReadOnlyPaths=/run/cptc-harness-clock/portcast-live-v1.json" in unit
    assert "BindReadOnlyPaths=/etc/cptc-harness/trust\n" not in unit
    assert "BindPaths=/var/lib/cptc-harness/portcast-live-v6/runtime:/var/lib/cptc-harness/portcast-live-v1/runtime/v6" in unit
    assert "BindReadOnlyPaths=/var/lib/cptc-harness/portcast-live-v5/runtime:/var/lib/cptc-harness/portcast-live-v1/runtime/v5-predecessor" in unit
    assert "BindReadOnlyPaths=/var/lib/cptc-harness/portcast-live-v4/runtime:/var/lib/cptc-harness/portcast-live-v1/runtime/v4" in unit
    assert "BindReadOnlyPaths=/var/lib/cptc-harness/portcast-live-v3/runtime:/var/lib/cptc-harness/portcast-live-v1/runtime/v3-predecessor" in unit
    assert "BindReadOnlyPaths=/var/lib/cptc-harness/portcast-live-v1/runtime/ledger/cptc11-dell-validation:/var/lib/cptc-harness/portcast-live-v1/runtime/ledger/cptc11-dell-validation" in unit
    assert "BindReadOnlyPaths=/var/lib/cptc-harness/portcast-live-v1/runtime/runtime/audit:/var/lib/cptc-harness/portcast-live-v1/runtime/runtime/audit" in unit
    assert "BindPaths=/var/lib/cptc-harness/portcast-live-v1/runtime\n" not in unit
    assert "BindPaths=/run/cptc-harness" in unit
    assert "ExecStart=/usr/bin/" not in unit
    assert "ReadOnlyPaths=/usr" not in unit
    assert "IPAddressDeny=any" in unit
    assert "IPAddressAllow=100.85.84.30/32" in unit
    assert "RestrictAddressFamilies=AF_UNIX AF_INET AF_NETLINK\n" in unit
    assert "CapabilityBoundingSet=\n" in unit
    assert "AmbientCapabilities=\n" in unit
    assert "PrivateDevices=yes" in unit
    assert "ProtectKernelTunables=no" in unit
    assert "ProtectKernelModules=yes" in unit
    assert "ProtectKernelLogs=no" in unit
    assert "ProtectControlGroups=yes" in unit
    assert "ProtectClock=yes" in unit
    assert "ProtectProc=invisible" in unit
    assert "ProcSubset=all" in unit
    assert "RestrictNamespaces=mnt ipc net pid user uts" in unit
    assert "ProtectHostname=no" in unit
    assert "RemoveIPC=yes" in unit
    assert "DevicePolicy=closed" in unit
    assert "NoNewPrivileges=yes" in unit
    assert "LockPersonality=yes" in unit
    assert "MemoryDenyWriteExecute=yes" in unit
    assert "RestrictSUIDSGID=no" in unit
    assert "SystemCallArchitectures=native" in unit
    assert "RestrictRealtime=yes" in unit


def test_v6_start_gate_is_root_prestart_and_projection_is_permission_read_only():
    unit = (ROOT / "deployment/portcast-live-v1.service").read_text()
    launcher = (ROOT / "deployment/portcast-bootstrap.go").read_text()
    assert "ExecStartPre=+/app/deployment/portcast-bootstrap --admit-start\n" in unit
    assert "BindPaths=/var/lib/cptc-harness/portcast-live-v6/admission:/var/lib/cptc-harness/portcast-live-v1/admission\n" in unit
    assert "BindPaths=/var/lib/cptc-harness/portcast-live-v6/admission-projection:/var/lib/cptc-harness/portcast-live-v1/admission-projection\n" in unit
    assert "BindReadOnlyPaths=/var/lib/cptc-harness/portcast-live-v6/admission-projection:" not in unit
    assert 'arguments[0] == "--admit-start"' in launcher
    assert "createStartAdmission()" in launcher
    assert "verifyStartProjection()" in launcher
    assert "syscall.O_CREAT|syscall.O_EXCL" in launcher
    assert "writeExclusive(admission, admissionMarker, payload, 0600)" in launcher
    assert "writeExclusive(projection, admissionMarker, payload, 0444)" in launcher
    assert "exactDirectory(admission, 0700)" in launcher
    private_write = launcher.index(
        "writeExclusive(admission, admissionMarker, payload, 0600)"
    )
    private_sync = launcher.index("syscall.Fsync(int(admission.Fd()))", private_write)
    projection_write = launcher.index(
        "writeExclusive(projection, admissionMarker, payload, 0444)", private_sync
    )
    projection_sync = launcher.index("syscall.Fsync(int(projection.Fd()))", projection_write)
    assert private_write < private_sync < projection_write < projection_sync
    assert launcher.index("verifyV5Predecessor()") < private_write
    assert "requireReadOnlyMount(admission)" in launcher
    assert "requireReadOnlyMount(projection)" in launcher
    assert "requireReadOnlyMount(runtimeState)" in launcher
    gate = launcher.split('arguments[0] == "--admit-start"', 1)[1].split(
        'if len(arguments) == 0', 1
    )[0]
    assert "credentials" not in gate
    assert "SOCK" not in gate
    assert "--unshare-net" not in gate
    assert "runtime.LockOSThread()" in launcher
    assert "os.Clearenv()" in launcher
    assert "syscall.Unshare(syscall.CLONE_NEWNET)" in launcher


def test_v6_start_gate_is_one_shot_outside_writable_runtime(tmp_path):
    rootfs, _manifest, _audit = _rootfs(tmp_path)
    # The checked-in release metadata is sealed by the parent release task.
    # Make this isolated launcher exercise self-consistent after rebuilding the
    # binary locally, without changing the repository's integrity artifacts.
    launcher = rootfs / "app/deployment/portcast-bootstrap"
    bootstrap_path = rootfs / "app/cptc_harness/resources/portcast-bootstrap-v1.sha256"
    bootstrap_lines = bootstrap_path.read_text().splitlines()
    bootstrap_entries = {
        line.split("  ", 1)[1]: line.split("  ", 1)[0]
        for line in bootstrap_lines[1:]
    }
    bootstrap_path.chmod(0o644)
    bootstrap_path.write_text(
        "PORTCAST-BOOTSTRAP-V1\n"
        + "\n".join(
            f"{hashlib.sha256((rootfs / 'app' / relative).read_bytes()).hexdigest()}  {relative}"
            for relative in bootstrap_entries
        )
        + "\n"
    )
    bootstrap_path.chmod(0o444)
    release_path = rootfs / "app/cptc_harness/resources/release-integrity.json"
    release = json.loads(release_path.read_text())
    release["portcast-live-v1"]["bootstrap_manifest"]["sha256"] = hashlib.sha256(
        bootstrap_path.read_bytes()
    ).hexdigest()
    release["portcast-live-v1"]["launcher"]["sha256"] = hashlib.sha256(
        launcher.read_bytes()
    ).hexdigest()
    release_path.chmod(0o644)
    release_path.write_text(json.dumps(release, indent=2) + "\n")
    release_path.chmod(0o444)
    release_digest = hashlib.sha256(release_path.read_bytes()).hexdigest()
    anchor = rootfs / "etc/cptc-harness/trust/portcast-live-v1.sha256"
    anchor.chmod(0o644)
    anchor.write_bytes(deployment._anchor_payload(release, release_digest))
    anchor.chmod(0o444)
    admission = rootfs / "var/lib/cptc-harness/portcast-live-v1/admission"
    projection = rootfs / "var/lib/cptc-harness/portcast-live-v1/admission-projection"
    runtime = rootfs / "var/lib/cptc-harness/portcast-live-v1/runtime/v6"
    projection_marker = projection / "v6-start.marker"
    projection_marker.unlink()
    trace = tmp_path / "gate.strace"

    def run_gate():
        command = (
            "/usr/sbin/strace", "-f", "-qq", "-e", "trace=unshare", "-o", str(trace),
            "/usr/sbin/bwrap", "--unshare-user", "--uid", "0", "--gid", "0",
            "--die-with-parent",
            "--ro-bind", str(rootfs), "/",
            "--bind", str(admission), "/var/lib/cptc-harness/portcast-live-v1/admission",
            "--bind", str(projection), "/var/lib/cptc-harness/portcast-live-v1/admission-projection",
            "--proc", "/proc", "--dev", "/dev",
            "/app/deployment/portcast-bootstrap", "--admit-start",
        )
        return subprocess.run(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=30,
        )

    first = run_gate()
    trace_text = trace.read_text() if trace.exists() else ""
    if first.returncode != 0 and (
        b"Operation not permitted" in first.stderr
        or ("unshare(CLONE_NEWNET)" in trace_text and "EPERM" in trace_text)
    ):
        pytest.skip("test host forbids the namespace required by the root start gate")
    assert first.returncode == 0, first.stderr.decode("utf-8", "replace")
    assert re.search(r"unshare\(CLONE_NEWNET\)\s+= 0", trace_text)
    marker = admission / "v6-start.marker"
    assert marker.stat().st_mode & 0o777 == 0o600
    assert projection_marker.stat().st_mode & 0o777 == 0o444
    shutil.rmtree(runtime)
    second = run_gate()
    assert second.returncode != 0


@pytest.mark.parametrize("mutation", ("missing", "tampered"))
def test_broker_worker_requires_start_projection_before_worker_channel(tmp_path, mutation):
    rootfs, _manifest, _audit = _rootfs(tmp_path)
    projection_marker = rootfs / "var/lib/cptc-harness/portcast-live-v1/admission-projection/v6-start.marker"
    if mutation == "missing":
        projection_marker.unlink()
    else:
        projection_marker.chmod(0o644)
        projection_marker.write_bytes(b"tampered\n")
        projection_marker.chmod(0o444)
    parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    process = subprocess.Popen(
        (
            "/usr/sbin/bwrap", "--unshare-user", "--uid", "0", "--gid", "0",
            "--die-with-parent", "--new-session", "--ro-bind", str(rootfs), "/",
            "--proc", "/proc", "--dev", "/dev",
            "/app/deployment/portcast-bootstrap", "--broker-worker",
        ),
        stdin=child,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        close_fds=True,
    )
    child.close()
    try:
        parent.settimeout(5)
        try:
            packet = parent.recv(65536)
        except (ConnectionResetError, TimeoutError):
            packet = b""
        assert packet == b""
        assert process.wait(timeout=10) != 0
    finally:
        parent.close()
        if process.poll() is None:
            process.kill()
            process.wait()


def test_unprivileged_user_namespace_starts_with_zero_capabilities():
    """This is a direct bwrap proof only; it is never systemd acceptance evidence."""

    completed = subprocess.run(
        (
            "/usr/sbin/bwrap", "--unshare-user", "--uid", "0", "--gid", "0",
            "--die-with-parent", "--new-session", "--cap-drop", "ALL", "--clearenv",
            "--ro-bind", "/", "/", "--proc", "/proc", "--dev", "/dev", "/bin/sh", "-c",
            "grep '^CapEff:[[:space:]]*0000000000000000$' /proc/self/status",
        ),
        capture_output=True,
        text=True,
        timeout=30,
    )
    if completed.returncode and any(
        phrase in completed.stderr
        for phrase in ("Operation not permitted", "Creating new namespace failed", "setting up uid map")
    ):
        pytest.skip("host kernel policy forbids unprivileged user namespaces")
    assert completed.returncode == 0, completed.stderr


def test_root_with_zero_capabilities_cannot_create_the_nested_user_namespace():
    """The direct falsifier explains why systemd must switch to its nonroot user first."""

    completed = subprocess.run(
        (
            "/usr/sbin/bwrap", "--unshare-user", "--uid", "0", "--gid", "0",
            "--cap-drop", "ALL", "--die-with-parent", "--new-session",
            "--ro-bind", "/", "/", "--proc", "/proc", "--dev", "/dev",
            "/usr/sbin/bwrap", "--unshare-user", "--uid", "0", "--gid", "0",
            "--ro-bind", "/", "/", "/bin/true",
        ),
        capture_output=True,
        text=True,
        timeout=30,
    )
    if any(
        phrase in completed.stderr
        for phrase in ("Creating new namespace failed", "Operation not permitted")
    ) and "setting up uid map" not in completed.stderr:
        pytest.skip("host kernel policy does not expose nested user namespace behavior")
    assert completed.returncode != 0
    assert "setting up uid map" in completed.stderr


def test_service_and_audit_workers_enforce_verified_maps_and_zero_network_child():
    service = (ROOT / "testing/cptc11_lab/portcast_service.py").read_text()
    audit = (ROOT / "cptc_harness/audit_service.py").read_text()
    launcher = (ROOT / "deployment/portcast-bootstrap.go").read_text()
    worker = (ROOT / "cptc_harness/audit_worker.py").read_text()
    assert "_assert_verified_process_maps" in service
    assert 'Path("/app")' in service
    assert '"--audit-worker"' in audit
    assert '"--unshare-net"' in launcher
    assert '"--unshare-user", "--uid", "0", "--gid", "0"' in launcher
    assert '"--clearenv"' in launcher
    assert "close_fds=True" in audit
    assert "_assert_exact_worker_descriptors" in worker
    assert "Nlink != 1" in launcher


def test_production_launcher_and_unit_use_v6_audit_and_ledger_paths():
    launcher = (ROOT / "deployment/portcast-bootstrap.go").read_text()
    unit = (ROOT / "deployment/portcast-live-v1.service").read_text()
    broker = launcher.split('arguments[0] == "--broker-worker"', 1)[1].split(
        "if syscall.Exec(loaderPath, bwrapArgs", 1
    )[0]
    audit = launcher.split('arguments[0] == "--audit-worker"', 1)[1].split(
        "if syscall.Exec(loaderPath, bwrapArgs", 1
    )[0]
    v6_ledger = "/var/lib/cptc-harness/portcast-live-v1/runtime/v6/ledger/cptc11-dell-validation-portcast-v6"
    v6_audit = "/var/lib/cptc-harness/portcast-live-v1/runtime/v6/runtime/audit"
    assert f'ledger := "{v6_ledger}"' in broker
    assert "verifyStartProjection()" in broker
    assert f'"--bind", ledger, ledger' in broker
    assert f'"--bind", "{v6_audit}", "/audit"' in audit
    assert "/var/lib/cptc-harness/portcast-live-v1/runtime/v3/runtime/audit" not in audit
    assert "/var/lib/cptc-harness/portcast-live-v1/runtime/v4/runtime/audit" not in audit
    assert (
        "BindPaths=/var/lib/cptc-harness/portcast-live-v6/runtime:"
        "/var/lib/cptc-harness/portcast-live-v1/runtime/v6"
    ) in unit
    assert (
        "BindReadOnlyPaths=/var/lib/cptc-harness/portcast-live-v4/runtime:"
        "/var/lib/cptc-harness/portcast-live-v1/runtime/v4"
    ) in unit
    assert (
        "BindReadOnlyPaths=/var/lib/cptc-harness/portcast-live-v3/runtime:"
        "/var/lib/cptc-harness/portcast-live-v1/runtime/v3-predecessor"
    ) in unit


def test_child_launchers_close_their_own_deployment_lock_before_bwrap_exec():
    source = (ROOT / "deployment/portcast-bootstrap.go").read_text()
    broker = source.split('arguments[0] == "--broker-worker"', 1)[1].split(
        'if syscall.Exec(loaderPath, bwrapArgs', 1
    )[0]
    audit = source.split('arguments[0] == "--audit-worker"', 1)[1].split(
        'if syscall.Exec(loaderPath, bwrapArgs', 1
    )[0]
    assert "releaseDeploymentLock()" in broker
    assert "releaseDeploymentLock()" in audit
    assert "heldDeploymentLock = nil" in source


def test_launcher_rejects_a_manifest_file_with_an_external_hardlink(tmp_path):
    rootfs, _manifest, _audit = _rootfs(tmp_path)
    victim = rootfs / "app/cptc_harness/__init__.py"
    rootfs.chmod(0o755)
    os.link(victim, rootfs / "external-hardlink")
    rootfs.chmod(0o555)
    completed = subprocess.run(
        (
            "/usr/sbin/bwrap", "--unshare-user", "--uid", "0", "--gid", "0",
            "--die-with-parent", "--new-session", "--ro-bind", str(rootfs), "/",
            "--proc", "/proc", "--dev", "/dev",
            "/app/deployment/portcast-bootstrap", "--verify-startup-only",
        ),
        capture_output=True,
        timeout=30,
    )
    assert completed.returncode == 126


def test_production_root_audit_worker_encrypts_inside_private_network_namespace(tmp_path):
    rootfs, manifest, audit = _rootfs(tmp_path)
    identity = tmp_path / "identity.agekey"
    subprocess.run((str(ROOT / ".tools/age-keygen"), "-o", str(identity)), check=True, capture_output=True)
    recipient = subprocess.run((str(ROOT / ".tools/age-keygen"), "-y", str(identity)), check=True, capture_output=True, text=True).stdout.strip()
    config = memfd_create("cptc-audit-config", MFD_CLOEXEC | MFD_ALLOW_SEALING)
    section = manifest["portcast-live-v1"]
    os.write(config, canonical_json({
        "policy": asdict(policy()),
        "age_recipient": recipient,
        "profile_worker_sha256": section["current_profile_workers"]["web.http_jellyfin_public_identity"],
        "compatible_profile_workers": section["compatible_profile_workers"]["web.http_jellyfin_public_identity"],
        "parent_netns": os.stat("/proc/self/ns/net").st_ino,
    }))
    os.lseek(config, 0, os.SEEK_SET)
    parent, child = socket.socketpair()
    process = subprocess.Popen(
        (
            "/usr/sbin/bwrap", "--unshare-all", "--share-net", "--unshare-user", "--uid", "0", "--gid", "0",
            "--die-with-parent", "--new-session",
            "--ro-bind", str(rootfs), "/", "--bind", str(audit.parents[3]), "/var/lib/cptc-harness/portcast-live-v1",
            "--proc", "/proc", "--dev", "/dev",
            "/app/deployment/portcast-bootstrap", "--audit-worker", str(config),
        ),
        stdin=child,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        pass_fds=(config,),
        close_fds=True,
    )
    child.close()
    try:
        time.sleep(0.2)
        if process.poll() is not None:
            detail = process.stdout.read().decode("utf-8", "replace")
            if (
                "Creating new namespace failed: Operation not permitted" in detail
                or "setting up uid map: Operation not permitted" in detail
            ):
                pytest.skip("test host forbids the nested network namespace required by the RootDirectory fixture")
            pytest.fail(detail)
        assert _rpc(parent, "info")["ok"] is True
        assert _rpc(parent, "encryption_ready") == {"ok": True, "result": True}
        assert _rpc(parent, "close")["ok"] is True
        assert process.wait(timeout=20) == 0, process.stdout.read().decode("utf-8", "replace")
    finally:
        parent.close()
        os.close(config)
        if process.poll() is None:
            process.kill()
            process.wait()


def test_production_shaped_broker_has_zero_capabilities_and_rejects_adversarial_credentials(
    tmp_path,
):
    rootfs, _manifest, _audit = _rootfs(tmp_path)
    parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    process = subprocess.Popen(
        (
            "/usr/sbin/bwrap", "--unshare-user", "--uid", "0", "--gid", "0",
            "--die-with-parent", "--new-session", "--ro-bind", str(rootfs), "/",
            "--proc", "/proc", "--dev", "/dev",
            "/app/deployment/portcast-bootstrap", "--broker-worker",
        ),
        stdin=child,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        close_fds=True,
    )
    child.close()
    try:
        parent.settimeout(10)
        try:
            packet = parent.recv(65536)
        except (ConnectionResetError, TimeoutError):
            packet = b""
        if not packet and process.poll() is not None:
            detail = process.stdout.read().decode("utf-8", "replace")
            if "bwrap:" in detail and "Operation not permitted" in detail:
                pytest.skip(
                    "test host forbids the nested user namespace required by the RootDirectory fixture"
                )
            pytest.fail(detail or f"broker launcher exited {process.returncode}")
        ready = json.loads(packet)
        assert ready == {
            "kind": "sandbox_ready",
            "cap_eff": "0000000000000000",
            "allowed_route": "100.85.84.30/32",
        }
        parent.send(canonical_json({
            "method": "credentials", "names": ["cptc11-dell", "cptc11-kali"]
        }))
        assert process.wait(timeout=20) == 1
    finally:
        parent.close()
        if process.poll() is None:
            process.kill()
            process.wait()


def test_real_broker_bwrap_has_fixed_mounts_fds_and_zero_capabilities(tmp_path):
    rootfs, _manifest, _audit = _rootfs(tmp_path)
    ledger = rootfs / "var/lib/cptc-harness/portcast-live-v1/runtime/v6/ledger/cptc11-dell-validation-portcast-v6"
    runtime = ROOT / json.loads(RUNTIME_LOCK.read_text())["root"]
    parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    process = subprocess.Popen(
        (
            str(runtime / "lib/ld-linux-x86-64.so.2"), "--inhibit-cache",
            "--library-path", str(runtime / "lib"), str(runtime / "bin/bwrap"),
            "--unshare-user", "--uid", "0", "--gid", "0", "--unshare-pid",
            "--unshare-ipc", "--unshare-uts", "--share-net", "--die-with-parent",
            "--new-session", "--cap-drop", "ALL", "--clearenv",
            "--ro-bind", str(rootfs / "app"), "/app",
            "--dir", "/etc", "--dir", "/etc/cptc-harness", "--dir", "/etc/cptc-harness/trust",
            "--ro-bind", str(rootfs / "etc/cptc-harness/trust/portcast-live-v1.sha256"),
            "/etc/cptc-harness/trust/portcast-live-v1.sha256",
            "--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp",
            "--dir", "/var", "--dir", "/var/lib", "--dir", "/var/lib/cptc-harness",
            "--dir", "/var/lib/cptc-harness/portcast-live-v1",
            "--ro-bind", str(rootfs / "var/lib/cptc-harness/portcast-live-v1/admission-projection"),
            "/var/lib/cptc-harness/portcast-live-v1/admission-projection",
            "--dir", "/var/lib/cptc-harness/portcast-live-v1/runtime",
            "--dir", "/var/lib/cptc-harness/portcast-live-v1/runtime/v6",
            "--dir", "/var/lib/cptc-harness/portcast-live-v1/runtime/v6/ledger",
            "--bind", str(ledger), "/var/lib/cptc-harness/portcast-live-v1/runtime/v6/ledger/cptc11-dell-validation-portcast-v6",
            "--chdir", "/var/lib/cptc-harness/portcast-live-v1/runtime/v6/ledger/cptc11-dell-validation-portcast-v6",
            "/app/vendor/portcast-rootfs-runtime/lib/ld-linux-x86-64.so.2",
            "--inhibit-cache", "--library-path", "/app/vendor/portcast-rootfs-runtime/lib",
            "/app/vendor/portcast-rootfs-runtime/bin/python3.14", "-I", "-S", "-B",
            "/app/testing/cptc11_lab/portcast_service.py", "--broker-worker",
        ),
        stdin=child,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        close_fds=True,
    )
    child.close()
    try:
        parent.settimeout(10)
        ready_raw = parent.recv(65536)
        if not ready_raw:
            process.wait(timeout=10)
            pytest.fail(
                "broker worker exited before readiness: "
                + process.stdout.read().decode("utf-8", "backslashreplace")
            )
        ready = json.loads(ready_raw)
        assert ready == {
            "kind": "sandbox_ready",
            "cap_eff": "0000000000000000",
            "allowed_route": "100.85.84.30/32",
        }
        parent.send(canonical_json({
            "method": "credentials", "names": ["cptc11-dell", "cptc11-kali"]
        }))
        assert process.wait(timeout=20) == 1
    finally:
        parent.close()
        if process.poll() is None:
            process.kill()
            process.wait()


def test_vendored_bubblewrap_creates_a_network_namespace_without_interfaces():
    lock = json.loads(RUNTIME_LOCK.read_text())
    runtime = ROOT / lock["root"]
    loader = runtime / lock["entrypoints"]["loader"]
    bwrap = runtime / lock["entrypoints"]["bubblewrap"]
    code = (
        "import json,os,socket; "
        "names=[x.split(':',1)[0].strip() for x in open('/proc/net/dev').read().splitlines()[2:] if ':' in x]; "
        "s=socket.socket(); rc=s.connect_ex(('127.0.0.1',9)); s.close(); "
        "print(json.dumps({'inode':os.stat('/proc/self/ns/net').st_ino,'interfaces':names,'loopback_connect':rc}))"
    )
    completed = subprocess.run(
        (
            str(loader), "--inhibit-cache", "--library-path", str(runtime / "lib"), str(bwrap),
            "--unshare-net", "--die-with-parent", "--clearenv", "--ro-bind", "/usr", "/usr",
            "--ro-bind", str(runtime), "/runtime", "--proc", "/proc", "--dev", "/dev",
            "/runtime/lib/ld-linux-x86-64.so.2", "--inhibit-cache", "--library-path", "/runtime/lib",
            "/runtime/bin/python3.14", "-I", "-S", "-B", "-c", code,
        ),
        check=True,
        capture_output=True,
        text=True,
    )
    result = json.loads(completed.stdout)
    assert result["inode"] != os.stat("/proc/self/ns/net").st_ino
    assert set(result["interfaces"]) in ({"lo"}, set())
    assert result["loopback_connect"] != 0
