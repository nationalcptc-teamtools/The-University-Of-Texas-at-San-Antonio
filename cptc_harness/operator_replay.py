"""Explicit human selection of encrypted capture evidence for offline analysis.

This module is never registered as a model, MCP, or workflow capability. The
identity is mounted only in a networkless age process; plaintext stays in memory.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import uuid

from .contracts import AuditEvent, OperationRequest, PolicyError, SourceRef, to_json
from .integrity import verified_executable
from .passive import capture_input
from .storage import private_directory, read_private


def _decrypt(runtime, artifact: bytes, identity: Path) -> bytes:
    identity = Path(identity).absolute()
    private_directory(identity.parent)
    descriptor = os.open(identity, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        metadata = os.fstat(descriptor)
        if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.getuid()
                or metadata.st_mode & 0o077 or not 0 < metadata.st_size <= 16384):
            raise PolicyError("identity requires an owner-only bounded regular file")
        config = json.loads(read_private(runtime.root / "runtime.json", 65536))
        age = Path(config["age_binary"])
        if age.is_symlink() or hashlib.sha256(age.read_bytes()).hexdigest() != config["age_sha256"]:
            raise PolicyError("age executable changed")
        command = [str(verified_executable("/usr/bin/bwrap")), "--unshare-all", "--die-with-parent",
                   "--new-session", "--cap-drop", "ALL", "--clearenv", "--ro-bind", "/usr", "/usr",
                   "--symlink", "usr/lib", "/lib", "--symlink", "usr/lib", "/lib64",
                   "--proc", "/proc", "--dev", "/dev", "--ro-bind", str(age), "/age",
                   "--ro-bind-data", str(descriptor), "/identity", "--", "/age", "--decrypt", "-i", "/identity"]
        completed = subprocess.run(command, input=artifact, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                   env={}, close_fds=True, pass_fds=(descriptor,), timeout=15, check=False)
        if completed.returncode or len(completed.stdout) > 49152:
            raise PolicyError("selected evidence could not be decrypted within its allowance")
        return completed.stdout
    finally:
        os.close(descriptor)


def replay_capture(runtime, *, module_id: str, action_id: str, evidence_id: str, identity: Path):
    if module_id not in {"web.nuclei_observation", "web.zap_observation"}:
        raise PolicyError("capture replay accepts reviewed offline passive modules only")
    if runtime.ledger.stopped() or not runtime.audit.verify().valid or not runtime.audit.ready():
        raise PolicyError("capture replay requires an unstopped workspace and verified audit")
    matches = [record for record in runtime._records() if record["request"]["request_id"] == action_id]
    if len(matches) != 1:
        raise PolicyError("selected capture action is unavailable")
    record = matches[0]
    if (record["request"]["module_id"] != "web.response_capture" or record["request"]["source"] != "operator"
            or record["result"]["status"] != "complete"):
        raise PolicyError("replay requires a complete operator response capture")
    matches = [item for item in record["result"].get("evidence", []) if item["evidence_id"] == evidence_id]
    if len(matches) != 1:
        raise PolicyError("selected evidence is not linked to the capture action")
    evidence = matches[0]
    relative = Path(evidence.get("artifact_relpath") or "")
    if (relative.is_absolute() or ".." in relative.parts or len(relative.parts) != 2
            or relative.parts[0] != "evidence" or relative.suffix != ".age"
            or evidence["check_id"] != "response" or not 0 < evidence["bytes"] <= 49152):
        raise PolicyError("selected evidence is not a bounded encrypted response")
    directory = private_directory(runtime.audit.root / "evidence")
    artifact = read_private(directory / relative.name, 65536)
    replay_id = uuid.uuid4().hex
    event = {"source_action": action_id, "evidence_id": evidence_id, "module": module_id,
             "sha256": evidence["sha256"], "maximum_bytes": evidence["bytes"], "destination": "local_offline_scanner"}
    runtime.audit.emit(AuditEvent("operator_capture_replay_intent", replay_id, event))
    try:
        plaintext = _decrypt(runtime, artifact, identity)
        if len(plaintext) != evidence["bytes"] or hashlib.sha256(plaintext).hexdigest() != evidence["sha256"]:
            raise PolicyError("selected capture failed plaintext integrity verification")
        target, *_ = capture_input(plaintext, runtime.policy.scope)
        if target.canonical_url != record["request"]["target"]["canonical_url"]:
            raise PolicyError("selected capture target differs from its action")
        request = OperationRequest(replay_id, runtime.policy.workspace_id, runtime.policy.device_id,
                                   runtime.policy.operator_id, module_id, None, {}, "operator", None,
                                   runtime.policy.revision, parent_action_id=action_id)
        result = runtime.broker.execute(request, actor="operator", input_bytes=plaintext,
                                       source=SourceRef(evidence_id, evidence["sha256"]))
        runtime.audit.emit(AuditEvent("operator_capture_replay_result", replay_id,
                                     {**event, "status": result.status}))
        return {"version": 1, "classification": "client_confidential",
                "request": to_json(request), "result": to_json(result)}
    except Exception:
        runtime.audit.emit(AuditEvent("operator_capture_replay_failed", replay_id,
                                     {**event, "reason": "selected capture replay failed"}))
        raise PolicyError("selected capture replay failed; inspect local audit metadata") from None
