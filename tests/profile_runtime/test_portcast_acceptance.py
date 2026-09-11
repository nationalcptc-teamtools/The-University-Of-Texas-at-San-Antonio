"""Offline contract tests for the fixed privileged synthetic acceptance tool."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
from types import SimpleNamespace

import pytest


ROOT = Path(__file__).parents[2]
TOOL = ROOT / "deployment/portcast-systemd-acceptance.py"
WORKER = ROOT / "testing/cptc11_lab/portcast_acceptance.py"
UNIT = ROOT / "deployment/portcast-live-v1-acceptance@.service"
MANIFEST = ROOT / "cptc_harness/resources/release-integrity.json"


def _load_tool():
    spec = importlib.util.spec_from_file_location("portcast_acceptance_tool", TOOL)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def _property_readback(module, run_id, deny="any"):
    worker = module.STATE_ROOT / run_id / "worker"
    audit = worker / "audit"
    return {
        "Id": module._unit_id(run_id),
        "FragmentPath": str(module.RUNTIME_UNIT_PATH),
        "LoadState": "loaded",
        "ActiveState": "active",
        "SubState": "exited",
        "RootDirectory": "/usr/lib/cptc-harness/portcast-live-v1",
        "CapabilityBoundingSet": "",
        "AmbientCapabilities": "",
        "PrivateDevices": "yes",
        "PrivateTmp": "yes",
        "DevicePolicy": "closed",
        "PrivateNetwork": "yes",
        "RestrictAddressFamilies": "AF_UNIX AF_NETLINK",
        "IPAddressDeny": deny,
        "NoNewPrivileges": "yes",
        "ProtectHostname": "no",
        "RemoveIPC": "yes",
        "LockPersonality": "yes",
        "MemoryDenyWriteExecute": "yes",
        "MountAPIVFS": "yes",
        "ProtectSystem": "strict",
        "ProtectHome": "yes",
        "ProtectKernelTunables": "no",
        "ProtectKernelModules": "yes",
        "ProtectKernelLogs": "no",
        "ProtectControlGroups": "yes",
        "ProtectClock": "yes",
        "ProtectProc": "invisible",
        "ProcSubset": "all",
        "RestrictSUIDSGID": "no",
        "RestrictRealtime": "yes",
        "RestrictNamespaces": "mnt ipc net pid user uts",
        "SystemCallArchitectures": "native",
        "UMask": "0077",
        "Restart": "no",
        "User": "_cptc-portcast",
        "Group": "cptc-harness",
        "DynamicUser": "no",
        "Result": "success",
        "NRestarts": "0",
        "ExecMainCode": "1",
        "ExecMainStatus": "0",
        "BindPaths": " ".join(
            (
                f"{worker}:/acceptance:rbind",
                f"{audit}:/var/lib/cptc-harness/portcast-live-v1/runtime/audit:rbind",
            )
        ),
        "BindReadOnlyPaths": " ".join(
            (
                "/etc/cptc-harness/trust/portcast-live-v1.sha256:/etc/cptc-harness/trust/portcast-live-v1.sha256:rbind",
                "/var/lib/cptc-harness/portcast-live-v1/deployment.lock:/var/lib/cptc-harness/portcast-live-v1/deployment.lock:rbind",
            )
        ),
    }


def _receipt(module, run_id="accept-20260910T000000Z-0123abcd", deny="any"):
    properties = _property_readback(module, run_id, deny)
    return {
        "schema_version": 2,
        "run_id": run_id,
        "release_id": "portcast-live-v1",
        "manifest_sha256": "1" * 64,
        "unit_id": module._unit_id(run_id),
        "unit_sha256": "2" * 64,
        "invocation_id": module.INVOCATION_ID,
        "started_at": "2026-09-10T00:00:00.000000Z",
        "completed_at": "2026-09-10T00:00:01.000000Z",
        "started_monotonic_ns": 1,
        "completed_monotonic_ns": 2,
        "property_readback": properties,
        "service_identity": {
            "account": "_cptc-portcast",
            "group": "cptc-harness",
            "uid": 501,
            "gid": 502,
            "cap_eff": "0000000000000000",
        },
        "audit_worker": {
            "cap_eff": "0000000000000000",
            "netns_isolated": True,
            "interfaces": ["lo"],
            "entry_fds": [0, 1, 2],
            "traffic": {
                "af_inet_attempts": 0,
                "af_inet6_attempts": 0,
                "target_bytes": 0,
            },
            "af_inet_attempts": 0,
            "credential_fds": 0,
            "target_addresses": False,
        },
        "ciphertext": {
            "artifacts": 1,
            "bytes": 128,
            "sha256": "3" * 64,
            "integrity_valid": True,
        },
        "credentials": False,
        "live_action": False,
        "af_inet_attempts": 0,
        "target_addresses": False,
        "automatic_retry": False,
        "status": "success",
        "cleanup_status": "pending",
        "limitations": ["privileged acceptance is local synthetic evidence only"],
    }


def _service_identity(module):
    return module.ServiceIdentity("_cptc-portcast", "cptc-harness", 501, 502)


def _patch_run_tree(module, monkeypatch):
    identity = _service_identity(module)
    monkeypatch.setattr(module, "_resolve_service_identity", lambda: identity)

    def prepare(run_id, resolved):
        assert resolved == identity
        root = module.STATE_ROOT / run_id
        (root / "worker" / "audit").mkdir(parents=True)
        return root

    monkeypatch.setattr(module, "_prepare_run_tree", prepare)


def test_acceptance_artifacts_are_fixed_nonexecutable_and_have_no_target_surface():
    assert TOOL.is_file() and not os.access(TOOL, os.X_OK)
    assert WORKER.is_file()
    assert UNIT.is_file()
    text = "\n".join(path.read_text() for path in (TOOL, WORKER, UNIT))
    assert "LabSession" not in text
    assert "portcast_broker" not in text
    assert "transport" not in text
    assert "100.85.84.30" not in text
    assert "10.0.1.30" not in text
    assert "LoadCredential" not in UNIT.read_text()
    assert "RestrictAddressFamilies=AF_UNIX AF_NETLINK\n" in UNIT.read_text()
    assert "ProtectHostname=no\n" in UNIT.read_text()
    assert "ProtectKernelTunables=no\n" in UNIT.read_text()
    assert "ProtectKernelLogs=no\n" in UNIT.read_text()
    assert "ProcSubset=all\n" in UNIT.read_text()
    assert "RestrictSUIDSGID=no\n" in UNIT.read_text()
    assert "IPAddressDeny=any" in UNIT.read_text()
    assert "PrivateNetwork=yes" in UNIT.read_text()
    assert "PrivateTmp=yes\n" in UNIT.read_text()
    assert "CapabilityBoundingSet=\n" in UNIT.read_text()
    assert "AmbientCapabilities=\n" in UNIT.read_text()
    assert "--acceptance-audit %i" in UNIT.read_text()
    launcher = (ROOT / "deployment/portcast-bootstrap.go").read_text()
    service = (ROOT / "testing/cptc11_lab/portcast_service.py").read_text()
    assert "validAcceptanceRunID" in launcher
    assert 'arguments[0] == "--acceptance-audit"' in launcher
    assert "portcast_acceptance import main" in service
    assert '"--broker-worker"' not in WORKER.read_text()
    for field in (
        '"cap_eff"', '"netns_isolated"', '"interfaces"', '"entry_fds"',
        '"credential_fds"', '"traffic"', '"ciphertext"', '"integrity_valid"',
    ):
        assert field in WORKER.read_text()
    guide = (ROOT / "docs/harness/PORTCAST-SERVICE-DEPLOYMENT.md").read_text()
    assert "portcast-systemd-acceptance.py plan" in guide
    assert "portcast-systemd-acceptance.py run" in guide
    assert "portcast-systemd-acceptance.py verify --run-id" in guide
    assert "portcast-systemd-acceptance.py cleanup --run-id" in guide
    assert "portcast-systemd-acceptance.py reconcile --run-id" in guide
    assert "failed before target" in guide
    assert "traffic and was reconciled as uncertain" in guide
    assert "Neither result is acceptance evidence" in guide
    assert "schema-v2 privileged run" in guide


def test_acceptance_plan_binds_reviewed_manifest_and_is_metadata_only():
    module = _load_tool()
    expected = hashlib.sha256(MANIFEST.read_bytes()).hexdigest()
    result = module.plan(expected)
    assert result == {
        "operation": "plan",
        "release_id": "portcast-live-v1",
        "manifest_sha256": expected,
        "unit_id": "portcast-live-v1-acceptance@.service",
        "unit_sha256": hashlib.sha256(UNIT.read_bytes()).hexdigest(),
        "invocation_id": module.INVOCATION_ID,
        "synthetic_only": True,
        "credentials": False,
        "af_inet_attempts": 0,
        "target_addresses": False,
        "writes_system_state": False,
    }
    with pytest.raises(module.AcceptanceError, match="manifest"):
        module.plan("0" * 64)
    assert set(module.COMMANDS) == {
        "plan", "run", "verify", "cleanup", "reconcile", "recover-cleanup"
    }


@pytest.mark.parametrize(
    "run_id",
    ("../escape", "accept-20260910T000000Z-ABCDEF12", "accept-1", "x" * 128),
)
def test_acceptance_run_identifier_is_fixed_and_path_safe(run_id):
    module = _load_tool()
    with pytest.raises(module.AcceptanceError, match="run identifier"):
        module._validate_run_id(run_id)


def test_acceptance_receipt_schema_rejects_content_and_requires_full_attestation():
    module = _load_tool()
    valid = _receipt(module)
    assert module.validate_receipt(valid) == valid
    for key, value in {
        "output": "synthetic plaintext",
        "credentials": True,
        "target_addresses": True,
        "automatic_retry": True,
    }.items():
        invalid = dict(valid, **{key: value})
        with pytest.raises(module.AcceptanceError, match="receipt"):
            module.validate_receipt(invalid)
    invalid = json.loads(json.dumps(valid))
    invalid["audit_worker"]["entry_fds"] = [0, 1, 2, 8]
    with pytest.raises(module.AcceptanceError, match="receipt"):
        module.validate_receipt(invalid)
    for key, value in {
        "plaintext": "SECRET-SENTINEL",
        "output": "unexpected nested output",
    }.items():
        invalid = json.loads(json.dumps(valid))
        invalid["ciphertext"][key] = value
        with pytest.raises(module.AcceptanceError, match="receipt"):
            module.validate_receipt(invalid)


def test_acceptance_worker_refuses_root_or_wrong_dynamic_service_identity(monkeypatch):
    """Synthetic acceptance must prove the same nonroot identity as production."""

    from testing.cptc11_lab import portcast_acceptance

    monkeypatch.setattr(portcast_acceptance.os, "geteuid", lambda: 0)
    monkeypatch.setattr(portcast_acceptance.os, "getegid", lambda: 0)
    monkeypatch.setattr(portcast_acceptance.os, "getgroups", lambda: [0])
    with pytest.raises(RuntimeError, match="service identity"):
        portcast_acceptance._require_service_identity()

    monkeypatch.setattr(portcast_acceptance.os, "geteuid", lambda: 501)
    monkeypatch.setattr(portcast_acceptance.os, "getegid", lambda: 502)
    monkeypatch.setattr(portcast_acceptance.os, "getgroups", lambda: [502])
    resolved = portcast_acceptance._require_service_identity()
    assert (resolved.account, resolved.group, resolved.uid, resolved.gid) == (
        "_cptc-portcast", "cptc-harness", 501, 502
    )


def test_receipt_v2_requires_exact_resolved_service_identity():
    module = _load_tool()
    receipt = _receipt(module)
    assert module.validate_receipt(receipt)["service_identity"]["account"] == "_cptc-portcast"
    for field, value in (
        ("uid", 0), ("uid", 65534), ("uid", True),
        ("gid", 0), ("gid", 65534), ("gid", False),
        ("account", "nobody"), ("group", "root"), ("cap_eff", "1" * 16),
    ):
        invalid = json.loads(json.dumps(receipt))
        invalid["service_identity"][field] = value
        with pytest.raises(module.AcceptanceError, match="receipt"):
            module.validate_receipt(invalid)

    identity = module.ServiceIdentity("_cptc-portcast", "cptc-harness", 501, 502)
    assert module.validate_receipt(receipt, identity=identity) == receipt
    wrong = module.ServiceIdentity("_cptc-portcast", "cptc-harness", 503, 502)
    with pytest.raises(module.AcceptanceError, match="receipt"):
        module.validate_receipt(receipt, identity=wrong)


def test_controller_resolves_one_exact_nonroot_service_identity(monkeypatch):
    module = _load_tool()
    account = SimpleNamespace(pw_name="_cptc-portcast", pw_uid=501, pw_gid=502)
    group = SimpleNamespace(gr_name="cptc-harness", gr_gid=502, gr_mem=[])
    monkeypatch.setattr(module.pwd, "getpwnam", lambda name: account)
    monkeypatch.setattr(module.grp, "getgrnam", lambda name: group)
    monkeypatch.setattr(module.os, "getgrouplist", lambda name, gid: [502])
    assert module._resolve_service_identity() == module.ServiceIdentity(
        "_cptc-portcast", "cptc-harness", 501, 502
    )

    group.gr_mem = ["operator"]
    assert module._resolve_service_identity() == module.ServiceIdentity(
        "_cptc-portcast", "cptc-harness", 501, 502
    )

    for changed in (
        {"pw_uid": 0}, {"pw_uid": 65534}, {"pw_gid": 503},
    ):
        bad = SimpleNamespace(**(account.__dict__ | changed))
        monkeypatch.setattr(module.pwd, "getpwnam", lambda name, bad=bad: bad)
        with pytest.raises(module.AcceptanceError, match="identity"):
            module._resolve_service_identity()

    monkeypatch.setattr(module.pwd, "getpwnam", lambda name: account)
    monkeypatch.setattr(module.os, "getgrouplist", lambda name, gid: [502, 503])
    with pytest.raises(module.AcceptanceError, match="identity"):
        module._resolve_service_identity()


def test_prepare_run_tree_keeps_control_root_separate_from_worker_state(
    tmp_path, monkeypatch
):
    module = _load_tool()
    run_id = "accept-20260910T000000Z-0123abcd"
    monkeypatch.setattr(module, "STATE_ROOT", tmp_path)
    identity = module.ServiceIdentity(
        "_cptc-portcast", "cptc-harness", os.geteuid(), os.getegid()
    )
    calls = []
    real_chown = module.os.chown

    def chown(path, uid, gid):
        calls.append(Path(path))
        real_chown(path, uid, gid)

    monkeypatch.setattr(module.os, "chown", chown)
    root = module._prepare_run_tree(run_id, identity)
    worker = root / "worker"
    audit = worker / "audit"
    assert calls == [worker, audit]
    assert root.stat().st_uid == os.geteuid()
    assert root.stat().st_gid == os.getegid()
    assert root.stat().st_mode & 0o777 == 0o700
    assert worker.stat().st_mode & 0o777 == 0o700
    assert audit.stat().st_mode & 0o777 == 0o700


def test_worker_receipt_is_bounded_nofollow_and_service_owned(tmp_path, monkeypatch):
    module = _load_tool()
    run_id = "accept-20260910T000000Z-0123abcd"
    monkeypatch.setattr(module, "STATE_ROOT", tmp_path)
    identity = module.ServiceIdentity(
        "_cptc-portcast", "cptc-harness", os.geteuid(), os.getegid()
    )
    path = tmp_path / run_id / "worker" / "worker-receipt.json"
    path.parent.mkdir(parents=True)
    path.write_text("{}\n")
    path.chmod(0o600)
    assert module._worker_receipt(run_id, identity) == {}

    path.chmod(0o644)
    with pytest.raises(module.AcceptanceError, match="metadata"):
        module._worker_receipt(run_id, identity)
    path.unlink()
    path.symlink_to("/dev/null")
    with pytest.raises(module.AcceptanceError, match="unavailable"):
        module._worker_receipt(run_id, identity)


def test_controller_lock_rejects_permission_drift(tmp_path, monkeypatch):
    module = _load_tool()
    monkeypatch.setattr(module, "STATE_ROOT", tmp_path)
    lock = tmp_path / "acceptance.lock"
    lock.write_text("drift")
    lock.chmod(0o644)
    with pytest.raises(module.AcceptanceError, match="lock metadata"):
        with module._controller_lock():
            raise AssertionError("unsafe lock should not be acquired")


@pytest.mark.parametrize(
    "deny",
    ("any", "0.0.0.0/0 ::/0", "::/0 0.0.0.0/0"),
)
def test_acceptance_allows_systemd_deny_all_serializations(deny):
    module = _load_tool()
    run_id = "accept-20260910T000000Z-0123abcd"
    properties = _property_readback(module, run_id, deny)
    output = "".join(f"{key}={value}\n" for key, value in properties.items()).encode()
    module._systemctl = lambda *_arguments: (0, output, b"")

    assert module._read_properties(run_id) == properties
    assert module.validate_receipt(_receipt(module, run_id, deny))["property_readback"] == properties


@pytest.mark.parametrize(
    "deny",
    (
        "0.0.0.0/0",
        "::/0",
        "any 10.0.0.0/8",
        "0.0.0.0/0 ::/0 10.0.0.0/8",
        "not-a-range",
    ),
)
def test_acceptance_rejects_missing_extra_or_invalid_deny_ranges(deny):
    module = _load_tool()
    run_id = "accept-20260910T000000Z-0123abcd"
    properties = _property_readback(module, run_id, deny)
    output = "".join(f"{key}={value}\n" for key, value in properties.items()).encode()
    module._systemctl = lambda *_arguments: (0, output, b"")

    with pytest.raises(module.AcceptanceError, match="property state differs"):
        module._read_properties(run_id)
    with pytest.raises(module.AcceptanceError, match="receipt"):
        module.validate_receipt(_receipt(module, run_id, deny))


@pytest.mark.parametrize(
    ("field", "reordered", "invalid"),
    (
        (
            "RestrictAddressFamilies",
            "AF_NETLINK AF_UNIX",
            ("AF_UNIX", "AF_UNIX AF_NETLINK AF_INET"),
        ),
        (
            "RestrictNamespaces",
            "uts user pid net ipc mnt",
            ("mnt ipc net pid user", "mnt ipc net pid user uts uts"),
        ),
    ),
)
def test_acceptance_set_properties_compare_members_without_changing_receipt(
    field, reordered, invalid
):
    module = _load_tool()
    run_id = "accept-20260910T000000Z-0123abcd"
    properties = _property_readback(module, run_id)
    properties[field] = reordered
    assert module._properties_match(properties, run_id) is True
    output = "".join(
        f"{key}={value}\n" for key, value in properties.items()
    ).encode()
    module._systemctl = lambda *_arguments: (0, output, b"")
    assert module._read_properties(run_id)[field] == reordered

    receipt = _receipt(module, run_id)
    receipt["property_readback"][field] = reordered
    assert module.validate_receipt(receipt)["property_readback"][field] == reordered

    for replacement in invalid:
        invalid_properties = _property_readback(module, run_id)
        invalid_properties[field] = replacement
        assert module._properties_match(invalid_properties, run_id) is False
        invalid_receipt = _receipt(module, run_id)
        invalid_receipt["property_readback"][field] = replacement
        with pytest.raises(module.AcceptanceError, match="receipt"):
            module.validate_receipt(invalid_receipt)


def test_acceptance_property_equivalence_is_order_insensitive_but_scalar_exact():
    module = _load_tool()
    run_id = "accept-20260910T000000Z-0123abcd"
    left = _property_readback(module, run_id)
    right = _property_readback(module, run_id)
    right["RestrictAddressFamilies"] = "AF_NETLINK AF_UNIX"
    right["RestrictNamespaces"] = "uts user pid net ipc mnt"
    assert module._properties_equivalent(left, right, run_id) is True
    right["PrivateTmp"] = "no"
    assert module._properties_equivalent(left, right, run_id) is False


def test_acceptance_rejects_missing_private_tmp_readback():
    module = _load_tool()
    run_id = "accept-20260910T000000Z-0123abcd"
    properties = _property_readback(module, run_id)
    del properties["PrivateTmp"]
    assert module._properties_match(properties, run_id) is False


def test_uncertain_diagnostics_are_fixed_and_never_include_process_details(
    tmp_path, monkeypatch
):
    module = _load_tool()
    run_id = "accept-20260910T000000Z-0123abcd"
    monkeypatch.setattr(module, "STATE_ROOT", tmp_path)
    (tmp_path / run_id).mkdir(parents=True)
    module._write_uncertain_phase(run_id, "start-uncertain", "unit-start")
    journal = (tmp_path / run_id / "journal.jsonl").read_text()
    assert "start_uncertain" in journal
    for sentinel in (
        "SECRET-SENTINEL", "stderr", "/private/path", "systemctl start",
        "AF_INET",
    ):
        assert sentinel not in journal
    with pytest.raises(module.AcceptanceError, match="diagnostic stage"):
        module._write_uncertain_phase(run_id, "not-a-stage", "unit-start")


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("User", "root"),
        ("Group", "root"),
        ("DynamicUser", "yes"),
        ("Result", "exit-code"),
        ("NRestarts", "1"),
        ("ExecMainCode", "2"),
        ("ExecMainStatus", "1"),
    ),
)
def test_acceptance_rejects_wrong_runtime_identity_or_result(field, value):
    module = _load_tool()
    run_id = "accept-20260910T000000Z-0123abcd"
    properties = _property_readback(module, run_id)
    properties[field] = value
    output = "".join(f"{key}={item}\n" for key, item in properties.items()).encode()
    module._systemctl = lambda *_arguments: (0, output, b"")
    with pytest.raises(module.AcceptanceError, match="property state differs"):
        module._read_properties(run_id)


@pytest.mark.parametrize(
    ("field", "replacement"),
    (
        ("BindPaths", "/var/lib/cptc-harness/portcast-live-v1/systemd-acceptance:/acceptance:rbind"),
        ("BindPaths", "/tmp/worker:/acceptance:rbind"),
        ("BindReadOnlyPaths", "/etc/cptc-harness/trust/portcast-live-v1.sha256:/etc/cptc-harness/trust/portcast-live-v1.sha256:rbind"),
        ("BindReadOnlyPaths", "/var/lib/cptc-harness/portcast-live-v1/deployment.lock:/var/lib/cptc-harness/portcast-live-v1/deployment.lock:rbind /tmp:/tmp:rbind"),
    ),
)
def test_acceptance_rejects_missing_extra_or_widened_mounts(field, replacement):
    module = _load_tool()
    run_id = "accept-20260910T000000Z-0123abcd"
    properties = _property_readback(module, run_id)
    properties[field] = replacement
    output = "".join(f"{key}={item}\n" for key, item in properties.items()).encode()
    module._systemctl = lambda *_arguments: (0, output, b"")
    with pytest.raises(module.AcceptanceError, match="property state differs"):
        module._read_properties(run_id)


def test_run_refuses_active_or_unknown_production_before_any_mutation(monkeypatch):
    module = _load_tool()
    monkeypatch.setattr(module, "_require_root", lambda: None)
    monkeypatch.setattr(module, "_source_manifest", lambda digest: {})
    monkeypatch.setattr(module, "_resolve_service_identity", lambda: _service_identity(module))
    calls = []
    monkeypatch.setattr(module, "_write_phase", lambda *args: calls.append(args))
    for state in ("active", "unknown"):
        monkeypatch.setattr(module, "_production_state", lambda state=state: state)
        with pytest.raises(module.AcceptanceError, match="production"):
            module.run("1" * 64)
    assert calls == []


def test_run_rechecks_production_state_inside_lock_before_mutation(tmp_path, monkeypatch):
    module = _load_tool()
    monkeypatch.setattr(module, "STATE_ROOT", tmp_path)
    monkeypatch.setattr(module, "_require_root", lambda: None)
    monkeypatch.setattr(module, "_source_manifest", lambda digest: {})
    monkeypatch.setattr(module, "_resolve_service_identity", lambda: _service_identity(module))
    states = iter(("inactive", "active"))
    state_calls = []
    monkeypatch.setattr(
        module,
        "_production_state",
        lambda: state_calls.append(next(states)) or state_calls[-1],
    )
    mutations = []
    monkeypatch.setattr(
        module,
        "_verify_installed_release",
        lambda digest: mutations.append("verify"),
    )
    monkeypatch.setattr(
        module,
        "_prepare_run_tree",
        lambda *args: mutations.append("prepare") or (_ for _ in ()).throw(
            AssertionError("run tree mutation occurred")
        ),
    )
    monkeypatch.setattr(
        module,
        "_install_ephemeral_unit",
        lambda: mutations.append("install"),
    )
    monkeypatch.setattr(
        module,
        "_systemctl",
        lambda *args: mutations.append(("systemctl", args)),
    )
    with pytest.raises(module.AcceptanceError, match="production"):
        module.run("1" * 64)
    assert state_calls == ["inactive", "active"]
    assert mutations == []
    assert list(tmp_path.glob("accept-*")) == []


def test_run_records_uncertain_once_and_never_retries_ambiguous_start(tmp_path, monkeypatch):
    module = _load_tool()
    run_id = "accept-20260910T000000Z-0123abcd"
    monkeypatch.setattr(module, "STATE_ROOT", tmp_path)
    monkeypatch.setattr(module, "_require_root", lambda: None)
    monkeypatch.setattr(module, "_source_manifest", lambda digest: {})
    monkeypatch.setattr(module, "_new_run_id", lambda: run_id)
    monkeypatch.setattr(module, "_production_state", lambda: "inactive")
    monkeypatch.setattr(module, "_verify_installed_release", lambda digest: None)
    monkeypatch.setattr(module, "_install_ephemeral_unit", lambda: None)
    _patch_run_tree(module, monkeypatch)
    calls = []

    def systemctl(*arguments):
        calls.append(arguments)
        return 1, b"", b"SYSTEMCTL-SECRET-SENTINEL"

    monkeypatch.setattr(module, "_systemctl", systemctl)
    with pytest.raises(module.AcceptanceError, match="uncertain"):
        module.run("1" * 64)
    assert calls == [("start", module._unit_id(run_id))]
    phases = [json.loads(line)["phase"] for line in (tmp_path / run_id / "journal.jsonl").read_text().splitlines()]
    assert phases == ["prepared", "unit-installed", "start-uncertain"]
    events = [
        json.loads(line)
        for line in (tmp_path / run_id / "journal.jsonl").read_text().splitlines()
    ]
    assert events[-1]["uncertain_stage"] == "unit-start"
    assert events[-1]["diagnostic_code"] == "start_uncertain"
    assert "SYSTEMCTL-SECRET-SENTINEL" not in (
        tmp_path / run_id / "journal.jsonl"
    ).read_text()


@pytest.mark.parametrize(
    "failure",
    (
        subprocess.TimeoutExpired(("/usr/bin/systemctl", "start"), 30),
        OSError("synthetic systemctl failure"),
        RuntimeError("EXCEPTION-SECRET-SENTINEL"),
    ),
)
def test_run_durably_records_raised_start_failures_without_retry(
    tmp_path, monkeypatch, failure
):
    module = _load_tool()
    run_id = "accept-20260910T000000Z-0123abcd"
    monkeypatch.setattr(module, "STATE_ROOT", tmp_path)
    monkeypatch.setattr(module, "_require_root", lambda: None)
    monkeypatch.setattr(module, "_source_manifest", lambda digest: {})
    monkeypatch.setattr(module, "_new_run_id", lambda: run_id)
    monkeypatch.setattr(module, "_production_state", lambda: "inactive")
    monkeypatch.setattr(module, "_verify_installed_release", lambda digest: None)
    monkeypatch.setattr(module, "_install_ephemeral_unit", lambda: None)
    _patch_run_tree(module, monkeypatch)
    calls = []

    def systemctl(*arguments):
        calls.append(arguments)
        raise failure

    monkeypatch.setattr(module, "_systemctl", systemctl)
    with pytest.raises(module.AcceptanceError, match="uncertain"):
        module.run("1" * 64)
    assert calls == [("start", module._unit_id(run_id))]
    journal = (tmp_path / run_id / "journal.jsonl").read_text().splitlines()
    events = [json.loads(line) for line in journal]
    assert [event["phase"] for event in events] == [
        "prepared", "unit-installed", "start-uncertain"
    ]
    assert events[-1]["automatic_retry"] is False
    assert events[-1]["uncertain_stage"] == "unit-start"
    assert events[-1]["diagnostic_code"] == "start_uncertain"
    assert "EXCEPTION-SECRET-SENTINEL" not in (
        tmp_path / run_id / "journal.jsonl"
    ).read_text()


@pytest.mark.parametrize(
    ("stage", "code"),
    (
        ("property-readback", "property_readback_uncertain"),
        ("worker-receipt", "worker_receipt_uncertain"),
        ("receipt-finalization", "receipt_finalization_uncertain"),
    ),
)
def test_run_records_distinct_post_start_uncertain_stages(
    tmp_path, monkeypatch, stage, code
):
    module = _load_tool()
    run_id = "accept-20260910T000000Z-0123abcd"
    monkeypatch.setattr(module, "STATE_ROOT", tmp_path)
    monkeypatch.setattr(module, "_require_root", lambda: None)
    monkeypatch.setattr(module, "_source_manifest", lambda digest: {})
    monkeypatch.setattr(module, "_new_run_id", lambda: run_id)
    monkeypatch.setattr(module, "_production_state", lambda: "inactive")
    monkeypatch.setattr(module, "_verify_installed_release", lambda digest: None)
    monkeypatch.setattr(module, "_install_ephemeral_unit", lambda: None)
    _patch_run_tree(module, monkeypatch)
    monkeypatch.setattr(
        module,
        "_read_properties",
        lambda _run_id: (
            _property_readback(module, run_id)
            if stage != "property-readback"
            else (_ for _ in ()).throw(RuntimeError("PROPERTY-SECRET-SENTINEL"))
        ),
    )
    monkeypatch.setattr(
        module,
        "_worker_receipt",
        lambda _run_id, _identity: (
            {}
            if stage != "worker-receipt"
            else (_ for _ in ()).throw(RuntimeError("WORKER-SECRET-SENTINEL"))
        ),
    )
    monkeypatch.setattr(
        module,
        "_assemble_receipt",
        lambda *_args: (
            _receipt(module, run_id)
            if stage != "receipt-finalization"
            else (_ for _ in ()).throw(RuntimeError("RECEIPT-SECRET-SENTINEL"))
        ),
    )
    monkeypatch.setattr(
        module, "_systemctl", lambda *_arguments: (0, b"", b"SYSTEMCTL-SECRET-SENTINEL")
    )
    with pytest.raises(module.AcceptanceError, match="uncertain"):
        module.run("1" * 64)
    events = [
        json.loads(line)
        for line in (tmp_path / run_id / "journal.jsonl").read_text().splitlines()
    ]
    assert events[-1]["phase"] == "post-start-uncertain"
    assert events[-1]["uncertain_stage"] == stage
    assert events[-1]["diagnostic_code"] == code
    assert events[-1]["automatic_retry"] is False
    journal = (tmp_path / run_id / "journal.jsonl").read_text()
    for sentinel in (
        "PROPERTY-SECRET-SENTINEL", "WORKER-SECRET-SENTINEL",
        "RECEIPT-SECRET-SENTINEL", "SYSTEMCTL-SECRET-SENTINEL",
    ):
        assert sentinel not in journal


def test_reconcile_and_cleanup_preserve_receipt_and_never_restart(tmp_path, monkeypatch):
    module = _load_tool()
    run_id = "accept-20260910T000000Z-0123abcd"
    monkeypatch.setattr(module, "STATE_ROOT", tmp_path)
    run_root = tmp_path / run_id
    run_root.mkdir(parents=True)
    receipt = _receipt(module, run_id)
    monkeypatch.setattr(module, "RUNTIME_UNIT_PATH", tmp_path / "acceptance@.service")
    (run_root / "receipt.json").write_text(json.dumps(receipt))
    (run_root / "receipt.json").chmod(0o600)
    monkeypatch.setattr(module, "_require_root", lambda: None)
    calls = []

    def systemctl(*arguments):
        calls.append(arguments)
        if arguments[0] == "is-active":
            return 3, b"inactive\n", b""
        if arguments[0] in {"stop", "daemon-reload"}:
            return 0, b"", b""
        raise AssertionError(arguments)

    monkeypatch.setattr(module, "_systemctl", systemctl)
    assert module.reconcile(run_id)["status"] == "resolved-inactive"
    assert module.cleanup(run_id)["cleanup_status"] == "complete"
    assert (run_root / "receipt.json").exists()
    assert not any(call[0] == "start" for call in calls)


def test_uncertain_run_can_be_cleaned_without_inventing_a_receipt(tmp_path, monkeypatch):
    module = _load_tool()
    run_id = "accept-20260910T000000Z-0123abcd"
    (tmp_path / run_id).mkdir(parents=True)
    monkeypatch.setattr(module, "STATE_ROOT", tmp_path)
    monkeypatch.setattr(module, "RUNTIME_UNIT_PATH", tmp_path / "acceptance@.service")
    monkeypatch.setattr(module, "_require_root", lambda: None)
    monkeypatch.setattr(
        module, "_systemctl", lambda *arguments: (3, b"inactive\n", b"")
    )
    result = module.cleanup(run_id)
    assert result["cleanup_status"] == "complete"
    assert result["receipt_preserved"] is False
    assert not (tmp_path / run_id / "receipt.json").exists()
    cleanup = json.loads((tmp_path / run_id / "cleanup.json").read_text())
    assert cleanup["journal_preserved"] is True
    journal = [
        json.loads(line)
        for line in (tmp_path / run_id / "journal.jsonl").read_text().splitlines()
    ]
    assert journal[-1]["phase"] == "cleanup-complete"
    assert journal[-1]["preserved_receipt"] is False


def test_repeated_cleanup_after_ambiguous_stop_is_recover_only(tmp_path, monkeypatch):
    module = _load_tool()
    run_id = "accept-20260910T000000Z-0123abcd"
    run_root = tmp_path / run_id
    run_root.mkdir(parents=True)
    unit = tmp_path / "acceptance@.service"
    unit.write_bytes(b"reviewed-old-synthetic-unit\n")
    unit.chmod(0o644)
    unit_sha256 = hashlib.sha256(unit.read_bytes()).hexdigest()
    journal = run_root / "journal.jsonl"
    journal.write_text(
        json.dumps(
            {"run_id": run_id, "phase": "unit-installed", "unit_sha256": unit_sha256}
        )
        + "\n"
    )
    journal.chmod(0o600)
    monkeypatch.setattr(module, "STATE_ROOT", tmp_path)
    monkeypatch.setattr(module, "RUNTIME_UNIT_PATH", unit)
    monkeypatch.setattr(module, "_require_root", lambda: None)
    calls = []

    def ambiguous_stop(*arguments):
        calls.append(arguments)
        if arguments[0] == "is-active":
            return 0, b"active\n", b""
        if arguments[0] == "stop":
            return 1, b"", b"STOP-SECRET-SENTINEL"
        raise AssertionError(arguments)

    monkeypatch.setattr(module, "_systemctl", ambiguous_stop)
    with pytest.raises(module.AcceptanceError, match="uncertain"):
        module.cleanup(run_id)
    assert calls == [("is-active", module._unit_id(run_id)), ("stop", module._unit_id(run_id))]
    journal_after_first = journal.read_text()
    assert json.loads(journal_after_first.splitlines()[-1])["phase"] == "cleanup-uncertain"
    assert "STOP-SECRET-SENTINEL" not in journal_after_first

    calls.clear()
    with pytest.raises(module.AcceptanceError, match="recover-cleanup"):
        module.cleanup(run_id)
    assert calls == []
    assert unit.exists()
    assert journal.read_text() == journal_after_first
    assert not (run_root / "cleanup.json").exists()

    monkeypatch.setattr(module, "ROOT_UID", os.getuid())
    monkeypatch.setattr(module, "ROOT_GID", os.getgid())

    def recover_systemctl(*arguments):
        calls.append(arguments)
        if arguments[0] == "is-active":
            return 3, b"failed\n", b""
        if arguments[0] in {"reset-failed", "daemon-reload"}:
            return 0, b"", b""
        raise AssertionError(arguments)

    monkeypatch.setattr(module, "_systemctl", recover_systemctl)
    assert module.recover_cleanup(run_id)["cleanup_status"] == "complete"


@pytest.mark.parametrize(
    "terminal_event",
    ({}, {"phase": None}, {"phase": 7}, {"phase": ""}, {"phase": "unknown"}),
)
def test_cleanup_rejects_invalid_terminal_journal_phase_before_mutation(
    tmp_path, monkeypatch, terminal_event
):
    module = _load_tool()
    run_id = "accept-20260910T000000Z-0123abcd"
    run_root = tmp_path / run_id
    run_root.mkdir(parents=True)
    unit = tmp_path / "acceptance@.service"
    unit.write_bytes(b"reviewed-old-synthetic-unit\n")
    unit.chmod(0o644)
    journal = run_root / "journal.jsonl"
    events = [
        {"run_id": run_id, "phase": "unit-installed", "unit_sha256": "1" * 64},
        {"run_id": run_id, **terminal_event},
    ]
    journal.write_text("".join(json.dumps(event) + "\n" for event in events))
    journal.chmod(0o600)
    monkeypatch.setattr(module, "STATE_ROOT", tmp_path)
    monkeypatch.setattr(module, "RUNTIME_UNIT_PATH", unit)
    monkeypatch.setattr(module, "_require_root", lambda: None)
    calls = []
    monkeypatch.setattr(
        module,
        "_systemctl",
        lambda *arguments: calls.append(arguments) or (_ for _ in ()).throw(
            AssertionError("systemctl called")
        ),
    )
    before = journal.read_text()
    with pytest.raises(module.AcceptanceError, match="journal.*phase"):
        module.cleanup(run_id)
    assert calls == []
    assert unit.exists()
    assert journal.read_text() == before
    assert not (run_root / "cleanup.json").exists()


def test_uncertain_cleanup_recovery_is_journal_bound_and_never_starts_or_stops(
    tmp_path, monkeypatch
):
    module = _load_tool()
    run_id = "accept-20260910T000000Z-0123abcd"
    run_root = tmp_path / run_id
    run_root.mkdir(parents=True)
    unit = tmp_path / "acceptance@.service"
    unit.write_bytes(b"reviewed-old-synthetic-unit\n")
    unit.chmod(0o644)
    unit_sha256 = hashlib.sha256(unit.read_bytes()).hexdigest()
    events = (
        {"run_id": run_id, "phase": "unit-installed", "unit_sha256": unit_sha256},
        {"run_id": run_id, "phase": "cleanup-uncertain"},
    )
    journal = run_root / "journal.jsonl"
    journal.write_text("".join(json.dumps(event) + "\n" for event in events))
    journal.chmod(0o600)
    monkeypatch.setattr(module, "STATE_ROOT", tmp_path)
    monkeypatch.setattr(module, "RUNTIME_UNIT_PATH", unit)
    monkeypatch.setattr(module, "ROOT_UID", os.getuid())
    monkeypatch.setattr(module, "ROOT_GID", os.getgid())
    monkeypatch.setattr(module, "_require_root", lambda: None)
    calls = []

    def systemctl(*arguments):
        calls.append(arguments)
        if arguments[0] == "is-active":
            return 3, b"failed\n", b""
        if arguments[0] in {"reset-failed", "daemon-reload"}:
            return 0, b"", b""
        raise AssertionError(arguments)

    monkeypatch.setattr(module, "_systemctl", systemctl)
    result = module.recover_cleanup(run_id)
    assert result == {
        "operation": "recover-cleanup",
        "run_id": run_id,
        "cleanup_status": "complete",
        "receipt_preserved": False,
        "audit_preserved": True,
        "automatic_retry": False,
    }
    assert not unit.exists()
    assert not any(call[0] in {"start", "stop"} for call in calls)
    assert json.loads((run_root / "cleanup.json").read_text())[
        "recovered_from_uncertain_cleanup"
    ] is True
    assert json.loads(journal.read_text().splitlines()[-1])["phase"] == "cleanup-recovered"
