"""Human-only encrypted replay uses synthetic evidence and actual age isolation."""
import base64
import hashlib
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from cptc_harness.contracts import (OperationRequest, OperationResult, PolicyError,
                                    PolicySnapshot, ScopeSpec, TargetRef, canonical_json)
from cptc_harness.operator_replay import replay_capture
from cptc_harness.policy import save_policy
from cptc_harness.runtime import Runtime, initialize
from test_integration import age_identity, private


@pytest.fixture
def capture_runtime(private, age_identity):
    age, identity, recipient = age_identity
    policy = PolicySnapshot("capture-fixture", "v1", "workspace", "device", "operator", ScopeSpec(("192.0.2.0/24",)))
    policy_path = private / "policy.json"
    save_policy(policy_path, policy)
    initialize(private / "workspace", policy_path, recipient=recipient, age_binary=age)
    runtime = Runtime(private / "workspace", ledger_root=private / "ledger")
    target = TargetRef("synthetic", "http://192.0.2.10/", "http", "192.0.2.10", 80)
    response = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nSet-Cookie: synthetic-secret=private\r\n\r\nok"
    payload = canonical_json({"version": 1, "target": target.canonical_url,
                              "response_base64": base64.b64encode(response).decode()})
    runtime.audit.reserve_output("capture-action", 49152)
    evidence = runtime.audit.capture("capture-action", "response", payload, "restricted_raw")
    runtime.audit.release_output("capture-action")
    request = OperationRequest("capture-action", "workspace", "device", "operator", "web.response_capture",
                               target, {}, "operator", None, "v1")
    runtime._record_result(request, OperationResult("complete", evidence=(evidence,)))
    yield runtime, identity, evidence, payload
    runtime.audit.close()


def test_exact_capture_replay_decrypts_in_memory_and_keeps_parent_link(capture_runtime, monkeypatch):
    runtime, identity, evidence, payload = capture_runtime
    calls = []
    encrypted_path = runtime.audit.root / evidence.artifact_relpath
    original = encrypted_path.read_bytes()
    def execute(request, **kwargs):
        calls.append((request, kwargs))
        return OperationResult("complete", {"observations": [], "issues": [], "duplicates": 0})
    monkeypatch.setattr(runtime.broker, "execute", execute)
    result = replay_capture(runtime, module_id="web.nuclei_observation", action_id="capture-action",
                            evidence_id=evidence.evidence_id, identity=identity)
    assert result["result"]["status"] == "complete"
    request, arguments = calls[0]
    assert request.source == "operator" and request.target is None and request.parent_action_id == "capture-action"
    assert arguments["input_bytes"] == payload and arguments["source"].sha256 == hashlib.sha256(payload).hexdigest()
    assert b"synthetic-secret" not in runtime.audit.transcript_path.read_bytes()
    assert runtime.audit.verify().valid
    assert encrypted_path.read_bytes() == original


@pytest.mark.parametrize("change", ["module", "action", "evidence", "identity_symlink", "identity_permissions", "ciphertext"])
def test_replay_rejects_bad_selection_before_passive_execution(capture_runtime, monkeypatch, change):
    runtime, identity, evidence, _ = capture_runtime
    monkeypatch.setattr(runtime.broker, "execute", lambda *a, **kw: pytest.fail("scanner must not run"))
    kwargs = dict(module_id="web.nuclei_observation", action_id="capture-action",
                  evidence_id=evidence.evidence_id, identity=identity)
    if change == "module":
        kwargs["module_id"] = "web.nuclei"
    elif change == "action":
        kwargs["action_id"] = "missing"
    elif change == "evidence":
        kwargs["evidence_id"] = "missing"
    elif change == "identity_symlink":
        link = identity.with_name("identity-link")
        link.symlink_to(identity)
        kwargs["identity"] = link
    elif change == "identity_permissions":
        identity.chmod(0o644)
    else:
        path = runtime.audit.root / evidence.artifact_relpath
        path.write_bytes(path.read_bytes() + b"tamper")
    with pytest.raises(PolicyError):
        replay_capture(runtime, **kwargs)


def test_failed_capture_and_stopped_workspace_cannot_replay(capture_runtime, monkeypatch):
    runtime, identity, evidence, _ = capture_runtime
    records = runtime._records()
    records[0]["result"]["status"] = "failed"
    monkeypatch.setattr(runtime, "_records", lambda: records)
    with pytest.raises(PolicyError, match="complete operator"):
        replay_capture(runtime, module_id="web.zap_observation", action_id="capture-action",
                       evidence_id=evidence.evidence_id, identity=identity)
    runtime.ledger.stop("synthetic stop")
    with pytest.raises(PolicyError, match="unstopped"):
        replay_capture(runtime, module_id="web.zap_observation", action_id="capture-action",
                       evidence_id=evidence.evidence_id, identity=identity)


def test_wrong_identity_does_not_run_scanner_or_change_source(capture_runtime, monkeypatch):
    runtime, identity, evidence, _ = capture_runtime
    wrong = identity.with_name("wrong-identity")
    executable = Path(__file__).parents[1] / ".tools" / "age-keygen"
    subprocess.run([str(executable), "-o", str(wrong)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
    original = (runtime.audit.root / evidence.artifact_relpath).read_bytes()
    monkeypatch.setattr(runtime.broker, "execute", lambda *a, **kw: pytest.fail("scanner must not run"))
    with pytest.raises(PolicyError, match="replay failed"):
        replay_capture(runtime, module_id="web.zap_observation", action_id="capture-action",
                       evidence_id=evidence.evidence_id, identity=wrong)
    assert (runtime.audit.root / evidence.artifact_relpath).read_bytes() == original
    assert runtime.audit.verify().valid
