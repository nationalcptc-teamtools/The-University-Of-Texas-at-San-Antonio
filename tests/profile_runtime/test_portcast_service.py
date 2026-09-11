from __future__ import annotations

import importlib.util
import inspect
import hashlib
import json
import os
import fcntl
import copy
from contextlib import contextmanager
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
import shutil
import socket
import stat
import subprocess
import sys
import threading
import time
from types import SimpleNamespace

import pytest

from cptc_harness.integrity import VerifiedRelease
from cptc_harness.contracts import PolicyError
from cptc_harness.profile_runtime.service_client import PortcastServiceClient
from cptc_harness.profile_runtime import service_client
from cptc_harness.runtime import Runtime
from testing.cptc11_lab import portcast_live as live
from testing.cptc11_lab import portcast_service
from testing.cptc11_lab.portcast_service import _CanonicalPortcastService
from tests.test_portcast_live import SyntheticClient, _seed_blocked_clock_predecessor


_DEPLOYMENT_SPEC = importlib.util.spec_from_file_location(
    "manage_portcast_service",
    Path(__file__).parents[2] / "deployment/manage-portcast-service.py",
)
deployment = importlib.util.module_from_spec(_DEPLOYMENT_SPEC)
assert _DEPLOYMENT_SPEC.loader is not None
_DEPLOYMENT_SPEC.loader.exec_module(deployment)


def _age_identity(tmp_path: Path) -> tuple[Path, str]:
    root = Path(__file__).parents[2]
    age = root / ".tools" / "age"
    keygen = root / ".tools" / "age-keygen"
    identity = tmp_path / "identity.agekey"
    subprocess.run([str(keygen), "-o", str(identity)], check=True, capture_output=True)
    recipient = subprocess.run(
        [str(keygen), "-y", str(identity)],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    return age, recipient


def _release(plan) -> VerifiedRelease:
    return VerifiedRelease(
        plan.release_id,
        "3" * 64,
        {},
        {plan.profile_id: plan.worker_sha256},
        {plan.profile_id: (plan.worker_sha256,)},
    )


def _create_synthetic_historical_inputs(state: Path) -> None:
    ledger = state / "runtime/ledger/cptc11-dell-validation"
    audit = state / "runtime/runtime/audit"
    result = state / (
        "runtime/runtime/results/cptc11-portcast-public-identity-action-v2.json"
    )
    ledger.mkdir(parents=True, mode=0o700)
    audit.mkdir(parents=True, mode=0o700)
    result.parent.mkdir(parents=True, exist_ok=True)
    result.write_bytes(b"synthetic-v2-result\n")
    result.chmod(0o600)


def _legacy_v2_service_request_for_test(
    socket_path: Path, method: str, release_id: str
):
    """Exercise the historical v2 service fixture without relaxing its v3 client."""

    connection = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    try:
        connection.connect(str(socket_path))
        connection.send(
            json.dumps({"method": method, "release_id": release_id}).encode()
        )
        response = json.loads(connection.recv(64 * 1024))
    finally:
        connection.close()
    assert response == {"ok": True, "result": response["result"]}
    return response["result"]


def _complete_service_result() -> dict:
    return {
        "action_id": "cptc11-portcast-public-identity-action-v3",
        "audit_verified": True,
        "automatic_retry": False,
        "cleanup_status": "passed",
        "profile_id": "web.http_jellyfin_public_identity",
        "receipt_outcome": "complete",
        "status": "complete",
        "workspace": "cptc11-portcast-workspace",
        "execution": {
            "reservation_state": "complete",
            "attempt_count": 1,
            "attempt_state": "complete",
            "transport_counters": {
                "tcp_connects": 1,
                "udp_datagrams": 0,
                "protocol_requests": 1,
                "tx_bytes": 103,
                "rx_bytes": 282,
            },
            "wire_counters_verified": True,
            "result_receipt_present": True,
        },
    }


def test_service_result_validator_accepts_only_proven_complete_metadata():
    value = _complete_service_result()

    assert service_client.validate_portcast_result(value) == value


def test_service_result_validator_accepts_only_fixed_failure_stage_metadata():
    value = _complete_service_result()
    value.update(
        status="failed",
        receipt_outcome="uncertain",
        reason="PortCast profile transport did not complete",
    )
    value["execution"].update(
        reservation_state="uncertain",
        attempt_state="uncertain",
        transport_counters={
            "tcp_connects": 0,
            "udp_datagrams": 0,
            "protocol_requests": 0,
            "tx_bytes": 0,
            "rx_bytes": 0,
        },
        failure_stage="target_open",
    )

    assert service_client.validate_portcast_result(value) == value
    value["execution"]["failure_stage"] = "target_open: token=secret"
    with pytest.raises(PolicyError, match="invalid metadata"):
        service_client.validate_portcast_result(value)


def test_complete_service_result_rejects_failure_stage():
    value = _complete_service_result()
    value["execution"]["failure_stage"] = "target_open"
    with pytest.raises(PolicyError, match="invalid metadata"):
        service_client.validate_portcast_result(value)


@pytest.mark.parametrize(
    "mutation",
    (
        "missing_execution",
        "extra_execution_field",
        "second_attempt",
        "negative_counter",
        "floating_counter",
        "extra_counter",
        "oversized_counter",
        "null_complete_counters",
        "unverified_complete",
        "failed_complete_cleanup",
        "missing_result_receipt",
        "absolute_workspace",
        "traversal_workspace",
        "control_workspace",
        "arbitrary_workspace",
        "control_reason",
        "arbitrary_reason",
        "oversized_reason",
        "complete_reason",
        "raw_body",
    ),
)
def test_service_result_validator_rejects_unproven_or_disclosed_metadata(mutation):
    value = copy.deepcopy(_complete_service_result())
    if mutation == "missing_execution":
        value.pop("execution")
    elif mutation == "extra_execution_field":
        value["execution"]["evidence_path"] = "/restricted/raw.age"
    elif mutation == "second_attempt":
        value["execution"]["attempt_count"] = 2
    elif mutation == "negative_counter":
        value["execution"]["transport_counters"]["rx_bytes"] = -1
    elif mutation == "floating_counter":
        value["execution"]["transport_counters"]["rx_bytes"] = 282.0
    elif mutation == "extra_counter":
        value["execution"]["transport_counters"]["capture_bytes"] = 282
    elif mutation == "oversized_counter":
        value["execution"]["transport_counters"]["rx_bytes"] = 8193
    elif mutation == "null_complete_counters":
        value["execution"]["attempt_count"] = 0
        value["execution"]["attempt_state"] = None
        value["execution"]["transport_counters"] = None
    elif mutation == "unverified_complete":
        value["execution"]["wire_counters_verified"] = False
    elif mutation == "failed_complete_cleanup":
        value["cleanup_status"] = "failed"
    elif mutation == "missing_result_receipt":
        value["execution"]["result_receipt_present"] = False
    elif mutation == "absolute_workspace":
        value["workspace"] = "/var/lib/cptc-harness/portcast-live-v1/runtime"
    elif mutation == "traversal_workspace":
        value["workspace"] = "../cptc11-portcast-workspace"
    elif mutation == "control_workspace":
        value["workspace"] = "cptc11-portcast-workspace\nraw"
    elif mutation == "arbitrary_workspace":
        value["workspace"] = "another-workspace"
    elif mutation == "control_reason":
        value["reason"] = "blocked\nclient data"
    elif mutation == "arbitrary_reason":
        value["reason"] = "printable target value token=secret"
    elif mutation == "oversized_reason":
        value["reason"] = "x" * 257
    elif mutation == "complete_reason":
        value["reason"] = "unexpected reason on complete result"
    else:
        value["body"] = "client data"

    with pytest.raises(PolicyError, match="invalid metadata"):
        service_client.validate_portcast_result(value)


def _synthetic_open_window_plan():
    now = datetime.now(timezone.utc)
    return replace(
        live.load_frozen_portcast_plan(),
        schema_version=1,
        reviewed_by="approved:synthetic-reviewer",
        window_start=(now - timedelta(minutes=5)).strftime(
            "%Y-%m-%dT%H:%M:%S.%fZ"
        ),
        window_end=(now + timedelta(minutes=5)).strftime(
            "%Y-%m-%dT%H:%M:%S.%fZ"
        ),
    )


def _synthetic_legacy_open_window_plan():
    now = datetime.now(timezone.utc)
    return replace(
        live.load_frozen_portcast_plan_v2(),
        schema_version=1,
        reviewed_by="approved:synthetic-reviewer",
        window_start=(now - timedelta(minutes=5)).strftime(
            "%Y-%m-%dT%H:%M:%S.%fZ"
        ),
        window_end=(now + timedelta(minutes=5)).strftime(
            "%Y-%m-%dT%H:%M:%S.%fZ"
        ),
    )


def test_two_fresh_clients_share_one_canonical_one_shot_authority(
    tmp_path, monkeypatch
):
    plan = _synthetic_open_window_plan()
    release = _release(plan)
    SyntheticClient.instances.clear()
    monkeypatch.setattr(live, "load_frozen_portcast_plan", lambda: plan)
    monkeypatch.setattr(live, "validate_current_release", lambda _plan: release)
    monkeypatch.setattr(live, "_require_open_window", lambda _plan: None)
    age, recipient = _age_identity(tmp_path)
    socket_path = tmp_path / "service.sock"
    service = _CanonicalPortcastService._for_test(
        state_root=tmp_path / "canonical-state",
        socket_path=socket_path,
        expected_client_uid=os.getuid(),
        verified_release=release,
        wire_broker_factory=SyntheticClient,
        age_binary=age,
        age_recipient=recipient,
    )
    thread = threading.Thread(
        target=service.serve, kwargs={"maximum_connections": 2}, daemon=True
    )
    thread.start()
    ready_deadline = time.monotonic() + 10
    while time.monotonic() < ready_deadline:
        if socket_path.exists() or not thread.is_alive():
            break
        time.sleep(0.01)
    assert thread.is_alive()
    assert socket_path.exists()

    first = PortcastServiceClient._for_test(socket_path).execute()
    second = PortcastServiceClient._for_test(socket_path).execute()
    thread.join(timeout=10)

    assert first["status"] == "complete"
    assert first["execution"] == {
        "reservation_state": "complete",
        "attempt_count": 1,
        "attempt_state": "complete",
        "transport_counters": {
            "tcp_connects": 1,
            "udp_datagrams": 0,
            "protocol_requests": 1,
            "tx_bytes": 103,
            "rx_bytes": 282,
        },
        "wire_counters_verified": True,
        "result_receipt_present": True,
        "failure_stage": None,
    }
    assert second["status"] == "blocked"
    assert second["automatic_retry"] is False
    assert second["execution"] == first["execution"]
    assert len(SyntheticClient.instances) == 1


def test_root_peer_can_only_use_parsed_inspect_method(tmp_path, monkeypatch):
    plan = live.load_frozen_portcast_plan()
    age, recipient = _age_identity(tmp_path)
    service = _CanonicalPortcastService._for_test(
        state_root=tmp_path / "state",
        socket_path=tmp_path / "unused.sock",
        expected_client_uid=12345,
        verified_release=_release(plan),
        wire_broker_factory=SyntheticClient,
        age_binary=age,
        age_recipient=recipient,
    )
    monkeypatch.setattr(service, "_peer_uid", lambda _connection: 0)
    dispatched = []
    monkeypatch.setattr(service, "_dispatch", lambda request: dispatched.append(request) or None)
    for method, allowed in (("execute", False), ("inspect", True)):
        server, client = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        client.send(json.dumps({"method": method, "release_id": plan.release_id}).encode())
        service.handle(server)
        response = json.loads(client.recv(65536))
        server.close(); client.close()
        assert response["ok"] is allowed
    assert dispatched == [{"method": "inspect", "release_id": plan.release_id}]


def test_authorized_operator_inspect_uses_canonical_socket_and_no_wire_broker(tmp_path, monkeypatch):
    plan = _synthetic_open_window_plan()
    age, recipient = _age_identity(tmp_path)
    socket_path = tmp_path / "canonical.sock"
    service = _CanonicalPortcastService._for_test(
        state_root=tmp_path / "state",
        socket_path=socket_path,
        expected_client_uid=os.getuid(),
        verified_release=_release(plan),
        wire_broker_factory=lambda *_args, **_kwargs: pytest.fail("inspect opened wire broker"),
        age_binary=age,
        age_recipient=recipient,
    )
    monkeypatch.setattr(live, "load_frozen_portcast_plan", lambda: plan)
    monkeypatch.setattr(live, "validate_current_release", lambda _plan: _release(plan))
    monkeypatch.setattr(live, "_require_open_window", lambda _plan: None)
    monkeypatch.setattr(live, "_inspect_frozen_portcast_state_at_root", lambda **_kwargs: None)
    thread = threading.Thread(target=service.serve, kwargs={"maximum_connections": 1}, daemon=True)
    thread.start()
    for _ in range(100):
        if socket_path.exists(): break
        time.sleep(0.01)
    assert PortcastServiceClient._for_test(socket_path).inspect() is None
    thread.join(timeout=5)
    assert not thread.is_alive()


def test_idle_peer_times_out_and_service_accepts_the_next_valid_request(
    tmp_path, monkeypatch
):
    plan = _synthetic_open_window_plan()
    age, recipient = _age_identity(tmp_path)
    socket_path = tmp_path / "canonical.sock"
    service = _CanonicalPortcastService._for_test(
        state_root=tmp_path / "state",
        socket_path=socket_path,
        expected_client_uid=os.getuid(),
        verified_release=_release(plan),
        wire_broker_factory=lambda *_args, **_kwargs: pytest.fail("inspect opened broker"),
        age_binary=age,
        age_recipient=recipient,
    )
    monkeypatch.setattr(portcast_service, "_CLIENT_IDLE_TIMEOUT_S", 0.05)
    monkeypatch.setattr(live, "load_frozen_portcast_plan", lambda: plan)
    monkeypatch.setattr(live, "validate_current_release", lambda _plan: _release(plan))
    monkeypatch.setattr(live, "_require_open_window", lambda _plan: None)
    monkeypatch.setattr(live, "_inspect_frozen_portcast_state_at_root", lambda **_kwargs: None)
    thread = threading.Thread(target=service.serve, kwargs={"maximum_connections": 2}, daemon=True)
    thread.start()
    for _ in range(100):
        if socket_path.exists():
            break
        time.sleep(0.01)
    idle = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    idle.connect(str(socket_path))
    time.sleep(0.1)
    idle.close()
    assert PortcastServiceClient._for_test(socket_path).inspect() is None
    thread.join(timeout=5)
    assert not thread.is_alive()


def test_broken_response_peer_is_contained():
    plan = live.load_frozen_portcast_plan()
    service = object.__new__(_CanonicalPortcastService)
    service._expected_client_uid = os.getuid()
    service._verified_release = _release(plan)
    service._peer_uid = lambda _connection: os.getuid()
    service._dispatch = lambda _request: None

    class DisconnectedPeer:
        def settimeout(self, value):
            assert value == portcast_service._CLIENT_IDLE_TIMEOUT_S

        def recv(self, _maximum):
            return json.dumps({"method": "inspect", "release_id": plan.release_id}).encode()

        def send(self, _value):
            raise BrokenPipeError()

    service.handle(DisconnectedPeer())


def test_production_client_and_coordinator_accept_no_state_root():
    assert tuple(inspect.signature(PortcastServiceClient).parameters) == ()
    assert tuple(inspect.signature(live.run_frozen_portcast_action).parameters) == ()
    assert tuple(inspect.signature(live.run_frozen_portcast_session).parameters) == ()
    assert tuple(inspect.signature(live.inspect_frozen_portcast_state).parameters) == ()


def test_deployment_unit_exposes_only_the_authenticated_fixed_socket():
    root = Path(__file__).parents[2]
    unit = (root / "deployment/portcast-live-v1.service").read_text()

    assert "ExecStart=/app/deployment/portcast-bootstrap" in unit
    assert "RootDirectory=/usr/lib/cptc-harness/portcast-live-v1" in unit
    assert "LoadCredentialEncrypted=cptc11-dell:" in unit
    assert "LoadCredentialEncrypted=cptc11-kali:" in unit
    assert "Group=cptc-harness" in unit
    assert "RuntimeDirectory=cptc-harness" in unit
    assert "RuntimeDirectoryMode=0750" in unit
    assert "BindReadOnlyPaths=/etc/cptc-harness/trust/portcast-live-v1.sha256" in unit
    assert "BindReadOnlyPaths=/run/cptc-harness-clock/portcast-live-v1.json" in unit
    assert "BindReadOnlyPaths=/etc/cptc-harness/trust\n" not in unit
    assert "BindPaths=/run/cptc-harness" in unit
    assert "BindPaths=/var/lib/cptc-harness/portcast-live-v1" in unit
    assert "RestrictAddressFamilies=AF_UNIX AF_INET AF_NETLINK\n" in unit
    assert "AF_INET6" not in unit
    assert "IPAddressDeny=any" in unit
    assert "IPAddressAllow=100.85.84.30/32" in unit


def test_sysusers_and_units_require_the_dedicated_nonroot_service_identity():
    """A root unit or mutable control-plane bind would reintroduce EPERM bwrap startup."""

    root = Path(__file__).parents[2]
    sysusers = (root / "deployment/portcast-live-v1.sysusers").read_text()
    service_unit = (root / "deployment/portcast-live-v1.service").read_text()
    acceptance_unit = (root / "deployment/portcast-live-v1-acceptance@.service").read_text()

    assert sysusers == (
        "# Dedicated, dynamically allocated PortCast service identity.\n"
        "g cptc-harness -\n"
        "u _cptc-portcast -:cptc-harness \"CPTC PortCast service\" /nonexistent\n"
    )
    for unit in (service_unit, acceptance_unit):
        assert "User=_cptc-portcast\n" in unit
        assert "Group=cptc-harness\n" in unit
        assert "NoNewPrivileges=yes\n" in unit
        assert "CapabilityBoundingSet=\n" in unit
        assert "AmbientCapabilities=\n" in unit
        assert "User=root\n" not in unit
    assert "BindPaths=/var/lib/cptc-harness/portcast-live-v3/runtime:/var/lib/cptc-harness/portcast-live-v1/runtime/v3\n" in service_unit
    assert "BindPaths=/var/lib/cptc-harness/portcast-live-v1/runtime/ledger/cptc11-dell-validation:/var/lib/cptc-harness/portcast-live-v1/runtime/ledger/cptc11-dell-validation\n" in service_unit
    assert "BindReadOnlyPaths=/var/lib/cptc-harness/portcast-live-v1/runtime/runtime/audit:/var/lib/cptc-harness/portcast-live-v1/runtime/runtime/audit\n" in service_unit
    assert "BindReadOnlyPaths=/var/lib/cptc-harness/portcast-live-v1/runtime/runtime/results:/var/lib/cptc-harness/portcast-live-v1/runtime/runtime/results\n" in service_unit
    assert "BindReadOnlyPaths=/var/lib/cptc-harness/portcast-live-v1/runtime/runtime/results/cptc11-portcast-public-identity-action-v2.json:" not in service_unit
    assert "BindPaths=/var/lib/cptc-harness/portcast-live-v1/runtime\n" not in service_unit
    assert "BindPaths=/var/lib/cptc-harness/portcast-live-v1\n" not in service_unit
    assert "BindReadOnlyPaths=/var/lib/cptc-harness/portcast-live-v1/deployment.lock\n" in service_unit
    assert "BindPaths=/var/lib/cptc-harness/portcast-live-v1/systemd-acceptance/%i/worker:/acceptance\n" in acceptance_unit
    assert "BindPaths=/var/lib/cptc-harness/portcast-live-v1/systemd-acceptance/%i/worker/audit:/var/lib/cptc-harness/portcast-live-v1/runtime/v3/runtime/audit\n" in acceptance_unit
    assert "BindPaths=/var/lib/cptc-harness/portcast-live-v1/systemd-acceptance/%i\n" not in acceptance_unit


@pytest.mark.parametrize(
    "account, uid, primary_gid, members",
    (
        ("root", 0, 501, ("root",)),
        ("nobody", 65534, 501, ("nobody",)),
        ("_cptc-portcast", 501, 777, ("_cptc-portcast",)),
    ),
)
def test_deployment_rejects_unsafe_dynamic_service_identity_before_mutation(
    monkeypatch, account, uid, primary_gid, members
):
    """Wrong account, numeric sentinel, or primary group must stop apply."""

    monkeypatch.setattr(deployment.pwd, "getpwnam", lambda _name: SimpleNamespace(
        pw_name=account, pw_uid=uid, pw_gid=primary_gid
    ))
    monkeypatch.setattr(deployment.grp, "getgrnam", lambda _name: SimpleNamespace(
        gr_name="cptc-harness", gr_gid=501, gr_mem=members
    ))
    monkeypatch.setattr(deployment.os, "getgrouplist", lambda *_args: [501])

    with pytest.raises(deployment.DeploymentError, match="service identity"):
        deployment._resolve_service_identity()


def test_deployment_resolves_valid_nonroot_sysusers_identity(monkeypatch):
    monkeypatch.setattr(deployment.pwd, "getpwnam", lambda _name: SimpleNamespace(
        pw_name="_cptc-portcast", pw_uid=501, pw_gid=502
    ))
    monkeypatch.setattr(deployment.grp, "getgrnam", lambda _name: SimpleNamespace(
        gr_name="cptc-harness", gr_gid=502, gr_mem=()
    ))
    monkeypatch.setattr(deployment.os, "getgrouplist", lambda *_args: [502])

    assert deployment._resolve_service_identity() == deployment.ServiceIdentity(
        "_cptc-portcast", 501, 502
    )


def test_deployment_identity_allows_authorized_socket_group_members(monkeypatch):
    """Human socket users do not become supplementary groups of the service."""

    monkeypatch.setattr(deployment.pwd, "getpwnam", lambda _name: SimpleNamespace(
        pw_name="_cptc-portcast", pw_uid=501, pw_gid=502
    ))
    monkeypatch.setattr(deployment.grp, "getgrnam", lambda _name: SimpleNamespace(
        gr_name="cptc-harness", gr_gid=502, gr_mem=("operator",)
    ))
    monkeypatch.setattr(deployment.os, "getgrouplist", lambda *_args: [502])

    assert deployment._resolve_service_identity() == deployment.ServiceIdentity(
        "_cptc-portcast", 501, 502
    )


def test_deployment_lock_is_root_owned_group_readable_and_nonwritable(
    tmp_path, monkeypatch
):
    state = tmp_path / "state"
    state.mkdir()
    identity = deployment.ServiceIdentity(
        "_cptc-portcast", os.getuid(), os.getgid()
    )
    v3_parent = tmp_path / "portcast-live-v3"
    monkeypatch.setattr(deployment, "STATE_PATH", state)
    monkeypatch.setattr(deployment, "V3_STATE_PATH", v3_parent)
    monkeypatch.setattr(deployment, "V3_RUNTIME_PATH", v3_parent / "runtime")
    monkeypatch.setattr(deployment, "ROOT_UID", os.getuid())

    with deployment._deployment_lock(exclusive=True, identity=identity):
        lock = state / "deployment.lock"
        info = lock.stat()
        assert stat.S_IMODE(info.st_mode) == 0o640
        assert (info.st_uid, info.st_gid) == (os.getuid(), os.getgid())
        descriptor = os.open(lock, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        try:
            with pytest.raises(BlockingIOError):
                fcntl.flock(descriptor, fcntl.LOCK_SH | fcntl.LOCK_NB)
        finally:
            os.close(descriptor)

    descriptor = os.open(lock, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_SH | fcntl.LOCK_NB)
    finally:
        os.close(descriptor)


def test_apply_holds_deployment_lock_before_runtime_preparation(monkeypatch):
    order = []
    identity = deployment.ServiceIdentity("_cptc-portcast", 501, 502)

    @contextmanager
    def locked(*, exclusive, identity):
        assert exclusive is True
        order.append(("lock", identity))
        yield 9
        order.append(("unlock", identity))

    monkeypatch.setattr(deployment.os, "geteuid", lambda: deployment.ROOT_UID)
    monkeypatch.setattr(deployment, "verify_tree", lambda *_args, **_kwargs: {})
    monkeypatch.setattr(deployment, "_resolve_service_identity", lambda: identity)
    monkeypatch.setattr(deployment, "_deployment_lock", locked)
    monkeypatch.setattr(deployment, "_service_is_active", lambda: False)
    monkeypatch.setattr(
        deployment,
        "_prerequisites",
        lambda resolved=None: order.append(("prerequisites", resolved)) or identity,
    )
    monkeypatch.setattr(
        deployment,
        "_apply_locked",
        lambda *_args: order.append(("apply", identity)) or {"ok": True},
    )
    monkeypatch.setattr(Path, "exists", lambda _self: False)

    assert deployment.apply("a" * 64) == {"ok": True}
    assert order == [
        ("lock", identity),
        ("prerequisites", identity),
        ("apply", identity),
        ("unlock", identity),
    ]


def test_deployment_creates_only_the_service_owned_runtime_subtree(tmp_path, monkeypatch):
    """Changing ownership of deployment state would let the worker alter release control state."""

    state = tmp_path / "portcast-live-v1"
    state.mkdir()
    state.chmod(0o700)
    before = state.stat()
    identity = deployment.ServiceIdentity("_cptc-portcast", os.getuid(), os.getgid())
    monkeypatch.setattr(deployment, "STATE_PATH", state)
    v3_parent = tmp_path / "portcast-live-v3"
    monkeypatch.setattr(deployment, "V3_STATE_PATH", v3_parent)
    monkeypatch.setattr(deployment, "V3_RUNTIME_PATH", v3_parent / "runtime")
    monkeypatch.setattr(deployment, "ROOT_UID", os.getuid())
    monkeypatch.setattr(deployment, "ROOT_GID", os.getgid())

    runtime = deployment._prepare_runtime_subtree(identity)

    assert runtime == v3_parent / "runtime"
    assert stat.S_IMODE(state.stat().st_mode) == 0o700
    assert (state.stat().st_uid, state.stat().st_gid) == (before.st_uid, before.st_gid)
    assert stat.S_IMODE(v3_parent.stat().st_mode) == 0o755
    assert (v3_parent.stat().st_uid, v3_parent.stat().st_gid) == (
        deployment.ROOT_UID,
        deployment.ROOT_GID,
    )
    assert (runtime.stat().st_uid, runtime.stat().st_gid) == (identity.uid, identity.gid)
    assert stat.S_IMODE(runtime.stat().st_mode) == 0o700


def test_service_requires_exact_dynamic_identity_and_service_owned_credentials(monkeypatch):
    """A root, nobody, wrong group, or supplemental group must not reach the service."""

    identity = portcast_service.ServiceIdentity("_cptc-portcast", "cptc-harness", 501, 502)
    monkeypatch.setattr(portcast_service.os, "geteuid", lambda: 501)
    monkeypatch.setattr(portcast_service.os, "getegid", lambda: 502)
    monkeypatch.setattr(portcast_service.os, "getgroups", lambda: [502])
    assert portcast_service._require_service_identity() == identity
    monkeypatch.setattr(portcast_service.os, "getgroups", lambda: [502, 999])
    with pytest.raises(RuntimeError, match="service identity"):
        portcast_service._require_service_identity()


def test_production_main_accepts_read_only_rootfs_parent_and_private_bound_runtime(
    monkeypatch,
):
    """The sealed parent is immutable; only the bound runtime is service-owned."""

    class StaticPath:
        def __init__(self, metadata):
            self._metadata = metadata

        def lstat(self):
            return self._metadata

    identity = portcast_service.ServiceIdentity(
        "_cptc-portcast", "cptc-harness", 501, 502
    )
    control = StaticPath(
        SimpleNamespace(st_mode=stat.S_IFDIR | 0o555, st_uid=0, st_gid=0)
    )
    runtime = StaticPath(
        SimpleNamespace(
            st_mode=stat.S_IFDIR | 0o555,
            st_uid=0,
            st_gid=0,
        )
    )
    served = []
    prepared = []
    closed = []
    order = []
    plan = object()
    runtime_authority = object.__new__(Runtime)

    class Service:
        def __init__(self, **kwargs):
            order.append("service")
            assert kwargs["state_root"] is runtime
            assert kwargs["prepared_runtime"] is runtime_authority

        def serve(self):
            order.append("serve")
            served.append(True)

    read_fd, write_fd = os.pipe()
    monkeypatch.setattr(sys, "argv", ["portcast_service.py"])
    monkeypatch.setattr(portcast_service, "PRODUCTION_CONTROL_ROOT", control)
    monkeypatch.setattr(portcast_service, "PRODUCTION_STATE_ROOT", runtime)
    monkeypatch.setattr(portcast_service, "_require_service_identity", lambda: identity)
    monkeypatch.setattr(portcast_service, "_bootstrap_release", lambda: {})
    monkeypatch.setattr(portcast_service, "_activate_verified_imports", lambda _manifest: None)
    monkeypatch.setattr(portcast_service, "_assert_verified_imports", lambda _release: None)
    monkeypatch.setattr(portcast_service, "_assert_verified_process_maps", lambda: None)
    monkeypatch.setattr(
        portcast_service,
        "_load_service_credentials",
        lambda: order.append("credentials") or (read_fd, write_fd),
    )
    monkeypatch.setattr(portcast_service, "_CanonicalPortcastService", Service)
    monkeypatch.setattr(live, "load_frozen_portcast_plan", lambda: plan)
    monkeypatch.setattr(
        live,
        "open_frozen_portcast_runtime_at_root",
        lambda **kwargs: order.append("runtime") or prepared.append(kwargs) or runtime_authority,
    )
    monkeypatch.setattr(
        live,
        "_close_runtime",
        lambda authority, primary=None: closed.append((authority, primary)),
    )
    monkeypatch.setattr(
        sys.modules["cptc_harness.integrity"],
        "verify_portcast_release",
        lambda: SimpleNamespace(release_id="portcast-live-v1"),
    )

    assert portcast_service.main() == 0
    assert served == [True]
    assert closed == [(runtime_authority, None)]
    assert order == ["runtime", "credentials", "service", "serve"]
    assert prepared == [{
        "state_root": runtime,
        "plan": plan,
        "verified_release": SimpleNamespace(release_id="portcast-live-v1"),
        "age_binary": portcast_service._PRODUCTION_AGE_BINARY,
        "age_recipient": portcast_service._PRODUCTION_AGE_RECIPIENT,
    }]


def test_production_service_dispatch_reuses_the_prepared_sealed_runtime(
    monkeypatch,
):
    plan = live.load_frozen_portcast_plan()
    release = _release(plan)
    prepared_runtime = object.__new__(Runtime)
    monkeypatch.setattr(live, "load_frozen_portcast_plan", lambda: plan)

    service = _CanonicalPortcastService(
        state_root=portcast_service.PRODUCTION_STATE_ROOT,
        socket_path=portcast_service.PRODUCTION_SOCKET,
        expected_client_uid=os.getuid(),
        verified_release=release,
        wire_broker_factory=SyntheticClient,
        prepared_runtime=prepared_runtime,
    )

    assert service._age_binary == portcast_service._PRODUCTION_AGE_BINARY
    assert service._age_recipient == plan.evidence_recipient
    assert service._provision is False


def test_production_dispatch_uses_one_prepared_runtime_and_one_broker(
    tmp_path, monkeypatch
):
    legacy_plan = _synthetic_legacy_open_window_plan()
    age, recipient = _age_identity(tmp_path)
    legacy_plan = replace(legacy_plan, evidence_recipient=recipient)
    plan = replace(legacy_plan, schema_version=2)
    release = replace(
        _release(plan),
        native_file_sha256={
            "bin/age": hashlib.sha256(age.read_bytes()).hexdigest()
        },
    )
    state = tmp_path / "production-state"
    socket_path = tmp_path / "production.sock"
    SyntheticClient.instances.clear()
    monkeypatch.setattr(live, "load_frozen_portcast_plan", lambda: plan)
    monkeypatch.setattr(live, "validate_current_release", lambda _plan: release)
    synthetic_predecessor = json.loads(
        live._PREDECESSOR_PLAN_PATH.read_text()
    )
    synthetic_predecessor["evidence_recipient"] = recipient
    monkeypatch.setattr(
        live,
        "_read_predecessor_plan",
        lambda _plan: synthetic_predecessor,
    )
    monkeypatch.setattr(portcast_service, "PRODUCTION_STATE_ROOT", state)
    monkeypatch.setattr(portcast_service, "PRODUCTION_SOCKET", socket_path)
    monkeypatch.setattr(portcast_service, "_PRODUCTION_AGE_BINARY", age)
    monkeypatch.setattr(
        portcast_service, "_PRODUCTION_AGE_RECIPIENT", recipient
    )
    runtime = live._open_frozen_portcast_runtime_at_root_core(
        state_root=state,
        plan=legacy_plan,
        verified_release=release,
        age_binary=age,
        age_recipient=recipient,
    )
    _seed_blocked_clock_predecessor(runtime, plan)
    service = _CanonicalPortcastService(
        state_root=state,
        socket_path=socket_path,
        expected_client_uid=os.getuid(),
        verified_release=release,
        wire_broker_factory=SyntheticClient,
        prepared_runtime=runtime,
    )
    thread = threading.Thread(
        target=service.serve, kwargs={"maximum_connections": 3}, daemon=True
    )
    thread.start()
    for _ in range(1000):
        if socket_path.exists() or not thread.is_alive():
            break
        time.sleep(0.01)
    assert thread.is_alive()

    try:
        first = _legacy_v2_service_request_for_test(
            socket_path, "execute", plan.release_id
        )
        second = _legacy_v2_service_request_for_test(
            socket_path, "execute", plan.release_id
        )

        def snapshot(root):
            return {
                path.relative_to(root).as_posix(): (
                    path.lstat().st_mode,
                    path.lstat().st_uid,
                    path.lstat().st_gid,
                    path.lstat().st_mtime_ns,
                    path.lstat().st_ctime_ns,
                    hashlib.sha256(path.read_bytes()).hexdigest()
                    if path.is_file()
                    else None,
                )
                for path in sorted(root.rglob("*"))
            }

        before_inspect = snapshot(state)
        runtime.audit.ready = lambda: pytest.fail(
            "production inspect probed audit write access"
        )
        inspected = _legacy_v2_service_request_for_test(
            socket_path, "inspect", plan.release_id
        )
        assert snapshot(state) == before_inspect
        thread.join(timeout=10)
        assert not thread.is_alive()

        assert first["status"] == "complete"
        assert first["cleanup_status"] == "passed"
        assert second["status"] == "blocked"
        assert second["automatic_retry"] is False
        assert inspected["status"] == "blocked"
        assert inspected["automatic_retry"] is False
        assert inspected["execution"] == first["execution"]
        assert len(SyntheticClient.instances) == 1
        assert SyntheticClient.instances[0].executions == 1
        assert SyntheticClient.instances[0].closed is True

        audit = runtime.audit.profile_inspection_snapshot(plan.action_id)
        assert audit["has_result_receipt"] is True
        assert audit["cleanup_receipt"]["status"] == "passed"
        counters = audit["wire_receipt"]["counters"]
        assert counters == {
            "capture_bytes": audit["wire_receipt"]["evidence_bytes"],
            "protocol_requests": 1,
            "rx_bytes": audit["wire_receipt"]["evidence_bytes"],
            "tcp_connects": 1,
            "tls_handshakes": 0,
            "tx_bytes": 103,
            "udp_datagrams": 0,
        }
        assert runtime.ledger._db.execute(
            "SELECT COUNT(*) FROM reservation_attempts WHERE request_id=?",
            (plan.action_id,),
        ).fetchone() == (1,)
        encrypted = list((state / "runtime/audit/evidence").iterdir())
        assert len(encrypted) == 1
        assert encrypted[0].suffix == ".age"
    finally:
        if thread.is_alive():
            thread.join(timeout=1)
        live._close_runtime(runtime)


def test_production_provisioning_failure_occurs_before_credentials_or_listener(
    monkeypatch,
):
    identity = portcast_service.ServiceIdentity(
        "_cptc-portcast", "cptc-harness", 501, 502
    )
    plan = live.load_frozen_portcast_plan()
    release = _release(plan)
    control = SimpleNamespace(
        lstat=lambda: SimpleNamespace(st_mode=stat.S_IFDIR | 0o555, st_uid=0, st_gid=0)
    )
    runtime = SimpleNamespace(
        lstat=lambda: SimpleNamespace(
            st_mode=stat.S_IFDIR | 0o555, st_uid=0, st_gid=0
        )
    )
    monkeypatch.setattr(sys, "argv", ["portcast_service.py"])
    monkeypatch.setattr(portcast_service, "PRODUCTION_CONTROL_ROOT", control)
    monkeypatch.setattr(portcast_service, "PRODUCTION_STATE_ROOT", runtime)
    monkeypatch.setattr(portcast_service, "_require_service_identity", lambda: identity)
    monkeypatch.setattr(portcast_service, "_bootstrap_release", lambda: {})
    monkeypatch.setattr(portcast_service, "_activate_verified_imports", lambda _manifest: None)
    monkeypatch.setattr(portcast_service, "_assert_verified_imports", lambda _release: None)
    monkeypatch.setattr(portcast_service, "_assert_verified_process_maps", lambda: None)
    monkeypatch.setattr(live, "load_frozen_portcast_plan", lambda: plan)
    monkeypatch.setattr(
        live,
        "open_frozen_portcast_runtime_at_root",
        lambda **_kwargs: (_ for _ in ()).throw(PolicyError("provision failed")),
    )
    monkeypatch.setattr(
        portcast_service,
        "_load_service_credentials",
        lambda: pytest.fail("credentials loaded after failed provisioning"),
    )
    monkeypatch.setattr(
        portcast_service,
        "_CanonicalPortcastService",
        lambda **_kwargs: pytest.fail("listener constructed after failed provisioning"),
    )
    monkeypatch.setattr(
        sys.modules["cptc_harness.integrity"],
        "verify_portcast_release",
        lambda: release,
    )

    with pytest.raises(PolicyError, match="provision failed"):
        portcast_service.main()


def test_production_main_rejects_symlinked_control_path_before_runtime_open(
    tmp_path, monkeypatch
):
    control_target = tmp_path / "control-target"
    control_target.mkdir(mode=0o755)
    control = tmp_path / "control-link"
    control.symlink_to(control_target, target_is_directory=True)
    runtime = tmp_path / "runtime"
    runtime.mkdir(mode=0o700)
    plan = live.load_frozen_portcast_plan()
    release = _release(plan)
    identity = portcast_service.ServiceIdentity(
        "_cptc-portcast", "cptc-harness", os.getuid(), os.getgid()
    )
    monkeypatch.setattr(sys, "argv", ["portcast_service.py"])
    monkeypatch.setattr(portcast_service, "PRODUCTION_CONTROL_ROOT", control)
    monkeypatch.setattr(portcast_service, "PRODUCTION_STATE_ROOT", runtime)
    monkeypatch.setattr(portcast_service, "_require_service_identity", lambda: identity)
    monkeypatch.setattr(portcast_service, "_bootstrap_release", lambda: {})
    monkeypatch.setattr(portcast_service, "_activate_verified_imports", lambda _manifest: None)
    monkeypatch.setattr(portcast_service, "_assert_verified_imports", lambda _release: None)
    monkeypatch.setattr(live, "load_frozen_portcast_plan", lambda: plan)
    monkeypatch.setattr(
        sys.modules["cptc_harness.integrity"],
        "verify_portcast_release",
        lambda: release,
    )
    monkeypatch.setattr(
        live,
        "open_frozen_portcast_runtime_at_root",
        lambda **_kwargs: pytest.fail("runtime opened through control symlink"),
    )

    assert portcast_service.main() == 1


@pytest.mark.parametrize("kind", ("file", "symlink"))
def test_failed_socket_bind_preserves_preexisting_path(tmp_path, kind):
    plan = live.load_frozen_portcast_plan()
    age, recipient = _age_identity(tmp_path)
    socket_path = tmp_path / "service.sock"
    if kind == "file":
        socket_path.write_text("preserve")
    else:
        target = tmp_path / "target"
        target.write_text("preserve")
        socket_path.symlink_to(target)
    before = socket_path.lstat()
    service = _CanonicalPortcastService._for_test(
        state_root=tmp_path / "state",
        socket_path=socket_path,
        expected_client_uid=os.getuid(),
        verified_release=_release(plan),
        wire_broker_factory=SyntheticClient,
        age_binary=age,
        age_recipient=recipient,
    )

    with pytest.raises(OSError):
        service.serve(maximum_connections=1)

    after = socket_path.lstat()
    assert (after.st_dev, after.st_ino, after.st_mode) == (
        before.st_dev,
        before.st_ino,
        before.st_mode,
    )


def test_production_socket_never_uses_root_chown(tmp_path, monkeypatch):
    """The socket inherits the service user and cptc-harness group from the unit."""

    plan = live.load_frozen_portcast_plan()
    service = _CanonicalPortcastService._for_test(
        state_root=tmp_path / "state",
        socket_path=tmp_path / "service.sock",
        expected_client_uid=os.getuid(),
        verified_release=_release(plan),
        wire_broker_factory=SyntheticClient,
        age_binary=Path("/bin/false"),
        age_recipient="age1test",
    )
    monkeypatch.setattr(portcast_service.os, "chown", lambda *_args: pytest.fail("socket ownership was rewritten"))
    thread = threading.Thread(target=service.serve, kwargs={"maximum_connections": 1}, daemon=True)
    thread.start()
    for _ in range(100):
        if (tmp_path / "service.sock").exists():
            break
        time.sleep(0.01)
    client = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    client.connect(str(tmp_path / "service.sock"))
    client.close()
    thread.join(timeout=5)
    assert not thread.is_alive()


def test_deployment_helper_plan_is_no_target_and_requires_reviewed_release():
    root = Path(__file__).parents[2]
    manifest = root / "cptc_harness/resources/release-integrity.json"
    expected = hashlib.sha256(manifest.read_bytes()).hexdigest()
    result = deployment.plan(expected)

    assert result["manifest_sha256"] == expected
    assert result["service_start_requested"] is False
    assert result["target_traffic"] is False
    assert result["state_preserved"] is True
    helper = root / "deployment/manage-portcast-service.py"
    assert not os.access(helper, os.X_OK)
    direct = subprocess.run(
        ("/usr/bin/python3.14", "-I", "-S", str(helper), "plan", "--expected-manifest-sha256", expected),
        cwd=root,
        env={"PYTHONPATH": "/untrusted/site-packages"},
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert direct.returncode == 0
    assert json.loads(direct.stdout)["result"]["target_traffic"] is False
    with pytest.raises(deployment.DeploymentError, match="manifest"):
        deployment.plan("0" * 64)


def test_attest_clock_is_root_only_atomic_and_fixed_path(tmp_path, monkeypatch):
    path = tmp_path / "trust" / "portcast-clock-attestation.json"
    monkeypatch.setattr(deployment, "CLOCK_ATTESTATION_PATH", path)
    monkeypatch.setattr(deployment, "ROOT_UID", os.getuid())
    monkeypatch.setattr(deployment, "ROOT_GID", os.getgid())
    monkeypatch.setattr(deployment.os, "geteuid", lambda: os.getuid())
    monkeypatch.setattr(
        deployment,
        "_resolve_service_identity",
        lambda: deployment.ServiceIdentity("_cptc-portcast", 12345, os.getgid()),
    )
    monkeypatch.setattr(deployment, "_timedatectl_clock", lambda: (True, 0.001))
    monkeypatch.setattr(
        deployment, "_boot_identity", lambda: "11111111-2222-4333-8444-555555555555"
    )

    result = deployment.attest_clock()
    assert result["target_traffic"] is False
    assert result["ttl_seconds"] == 30
    info = path.stat()
    assert stat.S_IMODE(info.st_mode) == 0o440
    assert (info.st_uid, info.st_gid) == (os.getuid(), os.getgid())
    value = json.loads(path.read_text())
    assert set(value) == {
        "version", "boot_id", "observed_utc", "observed_monotonic_ns",
        "expires_utc", "expires_monotonic_ns", "synchronized", "offset_s", "source",
    }
    assert value["expires_monotonic_ns"] - value["observed_monotonic_ns"] == 30_000_000_000
    assert not (path.parent / ("." + path.name + ".new")).exists()

    # A fresh attestation replaces the prior valid 0440 file atomically. The
    # production workflow attests once for acceptance and again for execution.
    second = deployment.attest_clock()
    assert second["target_traffic"] is False
    assert stat.S_IMODE(path.stat().st_mode) == 0o440
    assert not (path.parent / ("." + path.name + ".new")).exists()

    monkeypatch.setattr(deployment.os, "geteuid", lambda: os.getuid() + 1)
    with pytest.raises(deployment.DeploymentError, match="root"):
        deployment.attest_clock()


def test_deployment_helper_apply_verify_and_rollback_preserve_state(
    tmp_path, monkeypatch
):
    release = tmp_path / "usr/lib/cptc-harness/portcast-live-v1"
    unit = tmp_path / "etc/systemd/system/portcast-live-v1.service"
    sysusers = tmp_path / "usr/lib/sysusers.d/cptc-harness-portcast.conf"
    anchor = tmp_path / "etc/cptc-harness/trust/portcast-live-v1.sha256"
    state = tmp_path / "var/lib/cptc-harness/portcast-live-v1"
    credentials = (
        tmp_path / "etc/cptc-harness/credentials/cptc11-dell.cred",
        tmp_path / "etc/cptc-harness/credentials/cptc11-kali.cred",
    )
    state.mkdir(parents=True)
    state.chmod(0o700)
    marker = state / "preserved-state"
    marker.write_text("unchanged")
    # The production helper validates the exact v2 continuation inputs. Keep
    # this lifecycle test self-contained with service-owned synthetic inputs.
    historical_ledger = state / "runtime/ledger/cptc11-dell-validation"
    historical_audit = state / "runtime/runtime/audit"
    historical_result = state / (
        "runtime/runtime/results/cptc11-portcast-public-identity-action-v2.json"
    )
    historical_ledger.mkdir(parents=True, mode=0o700)
    historical_audit.mkdir(parents=True, mode=0o700)
    historical_result.parent.mkdir(parents=True, exist_ok=True)
    historical_result.write_bytes(b"synthetic-v2-result\n")
    historical_result.chmod(0o600)
    for path in credentials:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"synthetic-encrypted-credential")
        path.chmod(0o400)
    monkeypatch.setattr(deployment, "RELEASE_PATH", release)
    monkeypatch.setattr(deployment, "UNIT_PATH", unit)
    monkeypatch.setattr(deployment, "SYSUSERS_PATH", sysusers)
    monkeypatch.setattr(deployment, "ANCHOR_PATH", anchor)
    monkeypatch.setattr(deployment, "STATE_PATH", state)
    monkeypatch.setattr(deployment, "CREDENTIAL_PATHS", credentials)
    monkeypatch.setattr(
        deployment,
        "CLOCK_ATTESTATION_PATH",
        tmp_path / "host/clock/portcast-live-v1.json",
    )
    monkeypatch.setattr(deployment, "ROOT_UID", os.getuid())
    monkeypatch.setattr(deployment, "ROOT_GID", os.getgid())
    monkeypatch.setattr(
        deployment,
        "_resolve_service_identity",
        lambda: deployment.ServiceIdentity("_cptc-portcast", os.getuid(), os.getgid()),
    )
    monkeypatch.setattr(deployment, "_service_is_active", lambda: False)
    manifest = deployment.SOURCE_ROOT / deployment.MANIFEST_RELATIVE
    expected = hashlib.sha256(manifest.read_bytes()).hexdigest()

    first = deployment.apply(expected)
    assert first["service_started"] is False
    deployment.apply(expected)
    previous = deployment._verified_static_generation(
        release.with_name(release.name + ".previous"),
        unit.with_name(unit.name + ".previous"),
        sysusers.with_name(sysusers.name + ".previous"),
        anchor.with_name(anchor.name + ".previous"),
        expected_manifest_sha256=expected,
    )
    assert previous["manifest_sha256"] == expected
    assert previous["sysusers_pin_source"] == "manifest"
    with pytest.raises(deployment.DeploymentError, match="reviewed previous"):
        deployment._verified_static_generation(
            release.with_name(release.name + ".previous"),
            unit.with_name(unit.name + ".previous"),
            sysusers.with_name(sysusers.name + ".previous"),
            anchor.with_name(anchor.name + ".previous"),
            expected_manifest_sha256="0" * 64,
        )
    with pytest.raises(deployment.DeploymentError, match="legacy sysusers digest is not permitted"):
        deployment._verified_static_generation(
            release.with_name(release.name + ".previous"),
            unit.with_name(unit.name + ".previous"),
            sysusers.with_name(sysusers.name + ".previous"),
            anchor.with_name(anchor.name + ".previous"),
            expected_manifest_sha256=expected,
            expected_legacy_sysusers_sha256=previous["sysusers_sha256"],
        )
    verify_tree = deployment.verify_tree
    previous_manifest = verify_tree(
        release.with_name(release.name + ".previous") / "app",
        expected,
        installed=True,
    )
    legacy_manifest = json.loads(json.dumps(previous_manifest))
    del legacy_manifest[deployment.RELEASE_ID]["files"][
        deployment.SYSUSERS_SOURCE.as_posix()
    ]
    monkeypatch.setattr(deployment, "verify_tree", lambda *_a, **_k: legacy_manifest)
    with pytest.raises(deployment.DeploymentError, match="legacy sysusers digest is required"):
        deployment._verified_static_generation(
            release.with_name(release.name + ".previous"),
            unit.with_name(unit.name + ".previous"),
            sysusers.with_name(sysusers.name + ".previous"),
            anchor.with_name(anchor.name + ".previous"),
            expected_manifest_sha256=expected,
        )
    with pytest.raises(deployment.DeploymentError, match="legacy sysusers digest differs"):
        deployment._verified_static_generation(
            release.with_name(release.name + ".previous"),
            unit.with_name(unit.name + ".previous"),
            sysusers.with_name(sysusers.name + ".previous"),
            anchor.with_name(anchor.name + ".previous"),
            expected_manifest_sha256=expected,
            expected_legacy_sysusers_sha256="0" * 64,
        )
    legacy = deployment._verified_static_generation(
        release.with_name(release.name + ".previous"),
        unit.with_name(unit.name + ".previous"),
        sysusers.with_name(sysusers.name + ".previous"),
        anchor.with_name(anchor.name + ".previous"),
        expected_manifest_sha256=expected,
        expected_legacy_sysusers_sha256=previous["sysusers_sha256"],
    )
    assert legacy["sysusers_pin_source"] == "operator-reviewed-legacy"
    monkeypatch.setattr(deployment, "verify_tree", verify_tree)
    verified = deployment.verify(inspect=False)
    sysusers.write_text("new policy\n")
    sysusers.with_name(sysusers.name + ".previous").write_text("old policy\n")
    rolled_back = deployment.rollback()

    assert verified["startup_smoke"] == "release-only-no-target"
    assert verified["clock_admission_checked"] is False
    assert verified["inspect"] == "not-requested"
    assert rolled_back["state_preserved"] is True
    assert marker.read_text() == "unchanged"
    assert release.is_dir()
    assert unit.is_file()
    assert sysusers.read_text() == "old policy\n"
    assert sysusers.with_name(sysusers.name + ".rolled-back").read_text() == "new policy\n"
    assert anchor.read_text().startswith("PORTCAST-TRUST-V2\nrelease " + expected + "\n")


def test_deployment_helper_retires_verified_previous_generation_idempotently(
    tmp_path, monkeypatch
):
    release = tmp_path / "usr/lib/cptc-harness/portcast-live-v1"
    unit = tmp_path / "etc/systemd/system/portcast-live-v1.service"
    sysusers = tmp_path / "usr/lib/sysusers.d/cptc-harness-portcast.conf"
    anchor = tmp_path / "etc/cptc-harness/trust/portcast-live-v1.sha256"
    state = tmp_path / "var/lib/cptc-harness/portcast-live-v1"
    state.mkdir(parents=True)
    state.chmod(0o700)
    _create_synthetic_historical_inputs(state)
    marker = state / "preserved-state"
    marker.write_text("unchanged")
    release.mkdir(parents=True)
    release.with_name(release.name + ".previous").mkdir()
    for path in (unit, sysusers, anchor):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("current")
        path.with_name(path.name + ".previous").write_text("previous")
    monkeypatch.setattr(deployment, "RELEASE_PATH", release)
    monkeypatch.setattr(deployment, "UNIT_PATH", unit)
    monkeypatch.setattr(deployment, "SYSUSERS_PATH", sysusers)
    monkeypatch.setattr(deployment, "ANCHOR_PATH", anchor)
    monkeypatch.setattr(deployment, "STATE_PATH", state)
    monkeypatch.setattr(deployment, "CREDENTIAL_PATHS", ())
    monkeypatch.setattr(deployment, "ROOT_UID", os.getuid())
    monkeypatch.setattr(deployment, "ROOT_GID", os.getgid())
    monkeypatch.setattr(deployment.os, "geteuid", lambda: os.getuid())
    monkeypatch.setattr(
        deployment,
        "_resolve_service_identity",
        lambda: deployment.ServiceIdentity("_cptc-portcast", os.getuid(), os.getgid()),
    )
    service_state_checks = []
    monkeypatch.setattr(
        deployment,
        "_service_is_active",
        lambda: service_state_checks.append("checked") or False,
    )
    expected = "1" * 64
    current_generation = {
        "manifest_sha256": "2" * 64,
        "unit_sha256": "3" * 64,
        "sysusers_sha256": "4" * 64,
        "sysusers_pin_source": "manifest",
        "anchor_sha256": "5" * 64,
    }
    previous_generation = {
        "manifest_sha256": expected,
        "unit_sha256": "6" * 64,
        "sysusers_sha256": "7" * 64,
        "sysusers_pin_source": "operator-reviewed-legacy",
        "anchor_sha256": "8" * 64,
    }

    def verify_generation(path, *_args, expected_manifest_sha256=None, **_kwargs):
        if path.name.endswith(".previous") or ".retired-" in path.name:
            assert expected_manifest_sha256 == expected
            assert _kwargs["expected_legacy_sysusers_sha256"] == "7" * 64
            return previous_generation
        assert expected_manifest_sha256 is None
        return current_generation

    monkeypatch.setattr(deployment, "_verified_static_generation", verify_generation)
    result = deployment.retire_previous(expected, "7" * 64)
    repeated = deployment.retire_previous(expected, "7" * 64)

    assert result["operation"] == "retire-previous"
    assert result["retired_manifest_sha256"] == expected
    assert result["already_retired"] is False
    assert result["service_started"] is False
    assert result["target_traffic"] is False
    assert repeated == {**result, "already_retired": True}
    assert service_state_checks == ["checked", "checked"]
    assert marker.read_text() == "unchanged"
    for current in (release, unit, sysusers, anchor):
        previous = current.with_name(current.name + ".previous")
        retired = current.with_name(current.name + f".retired-{expected}")
        assert not previous.exists()
        assert retired.exists()
    receipt = state / "deployment-history" / f"{expected}.json"
    assert receipt.is_file()
    assert stat.S_IMODE(receipt.stat().st_mode) == 0o600
    original_receipt = json.loads(receipt.read_text())
    inconsistent = dict(original_receipt, current_manifest_sha256="9" * 64)
    receipt.write_text(json.dumps(inconsistent, sort_keys=True) + "\n")
    with pytest.raises(deployment.DeploymentError, match="receipt differs"):
        deployment.retire_previous(expected, "7" * 64)
    for invalid_time in ("garbageZ", "2026-99-10T18:47:58.679725Z"):
        malformed_time = dict(original_receipt, retired_at_utc=invalid_time)
        receipt.write_text(json.dumps(malformed_time, sort_keys=True) + "\n")
        with pytest.raises(deployment.DeploymentError, match="receipt differs"):
            deployment.retire_previous(expected, "7" * 64)


def test_deployment_helper_refuses_partial_or_unreviewed_previous_generation(
    tmp_path, monkeypatch
):
    release = tmp_path / "release"
    unit = tmp_path / "unit"
    sysusers = tmp_path / "sysusers"
    anchor = tmp_path / "anchor"
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    _create_synthetic_historical_inputs(state)
    release.mkdir(mode=0o555)
    release.with_name(release.name + ".previous").mkdir(mode=0o555)
    unit.write_text("current")
    sysusers.write_text("current")
    anchor.write_text("current")
    monkeypatch.setattr(deployment, "RELEASE_PATH", release)
    monkeypatch.setattr(deployment, "UNIT_PATH", unit)
    monkeypatch.setattr(deployment, "SYSUSERS_PATH", sysusers)
    monkeypatch.setattr(deployment, "ANCHOR_PATH", anchor)
    monkeypatch.setattr(deployment, "STATE_PATH", state)
    monkeypatch.setattr(deployment, "CREDENTIAL_PATHS", ())
    monkeypatch.setattr(deployment, "ROOT_UID", os.getuid())
    monkeypatch.setattr(deployment, "ROOT_GID", os.getgid())
    monkeypatch.setattr(deployment.os, "geteuid", lambda: os.getuid())
    monkeypatch.setattr(
        deployment,
        "_resolve_service_identity",
        lambda: deployment.ServiceIdentity("_cptc-portcast", os.getuid(), os.getgid()),
    )
    monkeypatch.setattr(deployment, "_service_is_active", lambda: False)

    with pytest.raises(deployment.DeploymentError, match="incomplete"):
        deployment.retire_previous("0" * 64)
    assert release.with_name(release.name + ".previous").is_dir()
    assert not (state / "deployment-history").exists()


def test_deployment_previous_retirement_compensates_interrupted_archive(
    tmp_path, monkeypatch
):
    release = tmp_path / "release"
    unit = tmp_path / "unit"
    sysusers = tmp_path / "sysusers"
    anchor = tmp_path / "anchor"
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    release.mkdir(mode=0o555)
    release.with_name(release.name + ".previous").mkdir(mode=0o555)
    for path in (unit, sysusers, anchor):
        path.write_text("current")
        path.with_name(path.name + ".previous").write_text("previous")
    monkeypatch.setattr(deployment, "RELEASE_PATH", release)
    monkeypatch.setattr(deployment, "UNIT_PATH", unit)
    monkeypatch.setattr(deployment, "SYSUSERS_PATH", sysusers)
    monkeypatch.setattr(deployment, "ANCHOR_PATH", anchor)
    monkeypatch.setattr(deployment, "STATE_PATH", state)
    monkeypatch.setattr(deployment, "ROOT_UID", os.getuid())
    monkeypatch.setattr(deployment, "ROOT_GID", os.getgid())
    expected = "1" * 64
    current_generation = {
        "manifest_sha256": "2" * 64,
        "unit_sha256": "3" * 64,
        "sysusers_sha256": "4" * 64,
        "sysusers_pin_source": "manifest",
        "anchor_sha256": "5" * 64,
    }
    previous_generation = {
        "manifest_sha256": expected,
        "unit_sha256": "6" * 64,
        "sysusers_sha256": "7" * 64,
        "sysusers_pin_source": "manifest",
        "anchor_sha256": "8" * 64,
    }

    def verify_generation(path, *_args, expected_manifest_sha256=None, **_kwargs):
        if path.name.endswith(".previous"):
            assert expected_manifest_sha256 == expected
            return previous_generation
        assert expected_manifest_sha256 is None
        return current_generation

    monkeypatch.setattr(deployment, "_verified_static_generation", verify_generation)
    replace = os.replace
    previous_moves = 0

    def fail_second_previous_move(source, destination):
        nonlocal previous_moves
        if str(source).endswith(".previous"):
            previous_moves += 1
            if previous_moves == 2:
                raise OSError("synthetic retirement interruption")
        return replace(source, destination)

    monkeypatch.setattr(deployment.os, "replace", fail_second_previous_move)
    with pytest.raises(OSError, match="synthetic retirement interruption"):
        deployment._retire_previous_locked(expected)

    for current in (release, unit, sysusers, anchor):
        assert current.with_name(current.name + ".previous").exists()
        assert not current.with_name(current.name + f".retired-{expected}").exists()
    assert not (state / "deployment-journal.json").exists()
    assert not (state / "deployment-history" / f"{expected}.json").exists()


@pytest.mark.parametrize(
    ("stdout", "expected"),
    (
        (b"LoadState=loaded\nActiveState=active\nSubState=running\n", True),
        (b"LoadState=loaded\nActiveState=inactive\nSubState=dead\n", False),
    ),
)
def test_service_state_accepts_only_exact_active_or_inactive(
    tmp_path, monkeypatch, stdout, expected
):
    unit = tmp_path / "portcast-live-v1.service"
    unit.write_text("synthetic unit\n")
    monkeypatch.setattr(deployment, "UNIT_PATH", unit)
    completed = subprocess.CompletedProcess([], 0, stdout, b"")
    monkeypatch.setattr(deployment.subprocess, "run", lambda *_a, **_k: completed)
    assert deployment._service_is_active() is expected


def test_service_state_accepts_exact_not_found_only_when_unit_path_is_absent(
    tmp_path, monkeypatch
):
    unit = tmp_path / "portcast-live-v1.service"
    monkeypatch.setattr(deployment, "UNIT_PATH", unit)
    completed = subprocess.CompletedProcess(
        [],
        0,
        b"LoadState=not-found\nActiveState=inactive\nSubState=dead\n",
        b"",
    )
    monkeypatch.setattr(deployment.subprocess, "run", lambda *_a, **_k: completed)
    assert deployment._service_is_active() is False


@pytest.mark.parametrize(
    ("returncode", "stdout"),
    (
        (1, b""),
        (0, b"LoadState=loaded\nActiveState=failed\nSubState=failed\n"),
        (0, b"LoadState=loaded\nActiveState=activating\nSubState=start\n"),
        (0, b"LoadState=masked\nActiveState=inactive\nSubState=dead\n"),
        (0, b"LoadState=loaded\nActiveState=inactive\n"),
    ),
)
def test_service_state_query_failure_blocks_mutation(
    tmp_path, monkeypatch, returncode, stdout
):
    unit = tmp_path / "portcast-live-v1.service"
    unit.write_text("synthetic unit\n")
    monkeypatch.setattr(deployment, "UNIT_PATH", unit)
    completed = subprocess.CompletedProcess([], returncode, stdout, b"")
    monkeypatch.setattr(deployment.subprocess, "run", lambda *_a, **_k: completed)
    with pytest.raises(deployment.DeploymentError, match="service state"):
        deployment._service_is_active()


def test_service_state_rejects_not_found_when_a_unit_path_exists(tmp_path, monkeypatch):
    unit = tmp_path / "portcast-live-v1.service"
    unit.write_text("synthetic unit\n")
    monkeypatch.setattr(deployment, "UNIT_PATH", unit)
    completed = subprocess.CompletedProcess(
        [],
        0,
        b"LoadState=not-found\nActiveState=inactive\nSubState=dead\n",
        b"",
    )
    monkeypatch.setattr(deployment.subprocess, "run", lambda *_a, **_k: completed)
    with pytest.raises(deployment.DeploymentError, match="service state"):
        deployment._service_is_active()


def test_deployment_replace_compensates_a_failure_after_displacing_current(
    tmp_path, monkeypatch
):
    staged = tmp_path / "staged"
    current = tmp_path / "current"
    previous = tmp_path / "previous"
    staged.write_text("new")
    current.write_text("old")
    replace = os.replace
    calls = 0

    def fail_second(source, destination):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError("synthetic replace failure")
        return replace(source, destination)

    monkeypatch.setattr(deployment.os, "replace", fail_second)
    with pytest.raises(OSError, match="synthetic replace failure"):
        deployment._replace_triplet(staged, current, previous)
    assert current.read_text() == "old"
    assert staged.read_text() == "new"
    assert not previous.exists()


def test_deployment_inspect_refuses_root_and_accepts_only_fixed_operator(
    monkeypatch,
):
    monkeypatch.setattr(deployment.os, "geteuid", lambda: 0)
    with pytest.raises(deployment.DeploymentError, match="authorized operator"):
        deployment.inspect_service()
    monkeypatch.setattr(deployment.os, "geteuid", lambda: deployment.OPERATOR_UID)
    monkeypatch.setattr(deployment, "_inspect_service", lambda: {"status": "blocked"})
    result = deployment.inspect_service()
    assert result == {
        "operation": "inspect",
        "result": {"status": "blocked"},
        "target_traffic": False,
    }


@pytest.mark.parametrize(
    "mutation",
    (
        "missing",
        "symlink",
        "permissive",
        "empty",
        "wrong_uid",
        "wrong_gid",
        "wrong_mode",
    ),
)
def test_service_credentials_fail_closed_before_any_network(tmp_path, monkeypatch, mutation):
    path = tmp_path / "cptc11-dell"
    if mutation == "symlink":
        target = tmp_path / "actual"
        target.write_bytes(b"synthetic-password")
        path.symlink_to(target)
    elif mutation != "missing":
        path.write_bytes(b"" if mutation == "empty" else b"synthetic-password")
        path.chmod(
            0o644
            if mutation == "permissive"
            else 0o400
            if mutation == "wrong_mode"
            else 0o440
        )
    network = []
    monkeypatch.setattr(portcast_service.socket, "create_connection", lambda *a, **k: network.append(a))
    owner_uid = os.getuid() + 1 if mutation == "wrong_uid" else os.getuid()
    owner_gid = os.getgid() + 1 if mutation == "wrong_gid" else os.getgid()
    with pytest.raises(RuntimeError, match="credential"):
        portcast_service._seal_service_credential(
            path, owner_uid=owner_uid, owner_gid=owner_gid
        )
    assert network == []


def test_service_credential_production_defaults_require_root_owner_and_group(
    tmp_path,
):
    path = tmp_path / "cptc11-dell"
    path.write_bytes(b"synthetic-password")
    path.chmod(0o440)

    with pytest.raises(RuntimeError, match="credential"):
        portcast_service._seal_service_credential(path)


def test_service_credential_is_copied_to_a_sealed_anonymous_descriptor(tmp_path):
    path = tmp_path / "cptc11-dell"
    path.write_bytes(b"synthetic-password")
    path.chmod(0o440)
    descriptor = portcast_service._seal_service_credential(
        path, owner_uid=os.getuid(), owner_gid=os.getgid()
    )
    try:
        assert os.read(descriptor, 1024) == b"synthetic-password"
        assert "/memfd:portcast-credential" in os.readlink(f"/proc/self/fd/{descriptor}")
    finally:
        os.close(descriptor)


def test_bootstrap_source_removes_site_packages_before_import_activation():
    source = Path(portcast_service.__file__).read_text()
    assert "importlib.invalidate_caches()" in source
    assert "site-packages" in source
    assert "_activate_verified_imports" in source
    assert "_assert_verified_imports" in source
    assert '"--verify-startup-only"' in source
    assert "_assert_verified_process_maps" in source


def test_prepare_tree_installs_only_reviewed_commands_and_loader_as_executable(
    tmp_path, monkeypatch
):
    root = Path(__file__).parents[2]
    manifest = json.loads(
        (root / "cptc_harness/resources/release-integrity.json").read_text()
    )
    rootfs = tmp_path / "rootfs"
    monkeypatch.setattr(deployment, "ROOT_UID", os.getuid())
    monkeypatch.setattr(deployment, "ROOT_GID", os.getgid())

    deployment._prepare_tree(rootfs, deployment._payloads(manifest))

    executable = {
        path.relative_to(rootfs / "app").as_posix()
        for path in (rootfs / "app").rglob("*")
        if path.is_file() and path.stat().st_mode & 0o111
    }
    assert executable == {
        "deployment/portcast-bootstrap",
        "vendor/portcast-rootfs-runtime/bin/age",
        "vendor/portcast-rootfs-runtime/bin/bwrap",
        "vendor/portcast-rootfs-runtime/bin/python3.14",
        "vendor/portcast-rootfs-runtime/lib/ld-linux-x86-64.so.2",
    }
    assert stat.S_IMODE(
        (rootfs / "app/vendor/portcast-rootfs-runtime/lib/libcrypto.so.3").stat().st_mode
    ) == 0o444
    assert stat.S_IMODE(
        (rootfs / "app/vendor/portcast-rootfs-runtime/lib/python3.14/os.py").stat().st_mode
    ) == 0o444
    assert all(
        stat.S_IMODE(path.stat().st_mode) == 0o555
        for path in rootfs.rglob("*")
        if path.is_dir()
    )


@pytest.mark.parametrize(
    ("relative", "mode"),
    (
        ("deployment/portcast-bootstrap", 0o444),
        ("vendor/portcast-rootfs-runtime/lib/libcrypto.so.3", 0o555),
    ),
)
def test_installed_tree_verification_rejects_executable_mode_drift(
    tmp_path, monkeypatch, relative, mode
):
    root = Path(__file__).parents[2]
    manifest_relative = Path("cptc_harness/resources/release-integrity.json")
    manifest = json.loads((root / manifest_relative).read_text())
    rootfs = tmp_path / "rootfs"
    monkeypatch.setattr(deployment, "ROOT_UID", os.getuid())
    monkeypatch.setattr(deployment, "ROOT_GID", os.getgid())
    deployment._prepare_tree(rootfs, deployment._payloads(manifest))
    (rootfs / "app" / relative).chmod(mode)
    digest = hashlib.sha256((rootfs / "app" / manifest_relative).read_bytes()).hexdigest()

    with pytest.raises(deployment.DeploymentError, match="mode"):
        deployment.verify_tree(rootfs / "app", digest, installed=True)


def test_no_target_startup_smoke_uses_the_prepared_installed_tree(tmp_path, monkeypatch):
    root = Path(__file__).parents[2]
    manifest_relative = Path("cptc_harness/resources/release-integrity.json")
    manifest = json.loads((root / manifest_relative).read_text())
    rootfs = tmp_path / "rootfs"
    anchor = tmp_path / "host/trust/portcast-live-v1.sha256"
    state = tmp_path / "host/state"
    anchor.parent.mkdir(parents=True)
    state.mkdir(parents=True)
    monkeypatch.setattr(deployment, "ROOT_UID", os.getuid())
    monkeypatch.setattr(deployment, "ROOT_GID", os.getgid())
    monkeypatch.setattr(deployment, "RELEASE_PATH", rootfs)
    monkeypatch.setattr(deployment, "ANCHOR_PATH", anchor)
    monkeypatch.setattr(deployment, "STATE_PATH", state)
    v3_parent = tmp_path / "host/portcast-live-v3"
    old_ledger = state / "runtime/ledger/cptc11-dell-validation"
    old_audit = state / "runtime/runtime/audit"
    old_result = state / "runtime/runtime/results/cptc11-portcast-public-identity-action-v2.json"
    old_ledger.mkdir(parents=True)
    old_audit.mkdir(parents=True)
    old_result.parent.mkdir(parents=True, exist_ok=True)
    old_result.write_bytes(b"synthetic-v2-result\n")
    v3_parent.mkdir(parents=True)
    (v3_parent / "runtime").mkdir()
    monkeypatch.setattr(deployment, "V3_STATE_PATH", v3_parent)
    monkeypatch.setattr(deployment, "V3_RUNTIME_PATH", v3_parent / "runtime")
    monkeypatch.setattr(deployment, "OLD_LEDGER_PATH", old_ledger)
    monkeypatch.setattr(deployment, "OLD_AUDIT_PATH", old_audit)
    monkeypatch.setattr(deployment, "OLD_RESULT_PATH", old_result)
    monkeypatch.setattr(
        deployment,
        "CLOCK_ATTESTATION_PATH",
        tmp_path / "host/clock/portcast-live-v1.json",
    )
    deployment._prepare_tree(rootfs, deployment._payloads(manifest))
    digest = hashlib.sha256((rootfs / "app" / manifest_relative).read_bytes()).hexdigest()
    anchor.write_bytes(deployment._anchor_payload(manifest, digest))
    anchor.chmod(0o444)
    (state / "deployment.lock").write_bytes(b"")
    (state / "deployment.lock").chmod(0o600)

    deployment._startup_smoke(manifest)


def test_no_target_startup_smoke_does_not_mount_engagement_state(tmp_path, monkeypatch):
    state = tmp_path / "state"
    state.mkdir()
    (state / "deployment.lock").write_bytes(b"")
    monkeypatch.setattr(deployment, "STATE_PATH", state)
    monkeypatch.setattr(
        deployment,
        "CLOCK_ATTESTATION_PATH",
        tmp_path / "missing-clock-attestation.json",
    )
    captured = {}

    def run(arguments, **kwargs):
        captured["arguments"] = tuple(arguments)
        captured["kwargs"] = kwargs
        return subprocess.CompletedProcess(arguments, 0, b"", b"")

    monkeypatch.setattr(deployment.subprocess, "run", run)
    deployment._startup_smoke({})

    arguments = captured["arguments"]
    assert "--unshare-net" in arguments
    assert arguments[-2:] == (
        "/app/deployment/portcast-bootstrap",
        "--verify-startup-only",
    )
    assert str(state / "deployment.lock") in arguments
    assert not any(
        value.startswith(str(state / "runtime"))
        or value.startswith("/var/lib/cptc-harness/portcast-live-v3")
        for value in arguments
    )
    assert captured["kwargs"]["env"] == {}
    assert captured["kwargs"]["close_fds"] is True
