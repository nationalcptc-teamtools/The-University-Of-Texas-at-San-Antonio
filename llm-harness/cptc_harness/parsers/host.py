"""Strict, typed Linux and Windows/AD observation imports."""
from __future__ import annotations

import re
from typing import Any

from ..contracts import Observation, ParseBatch, ScopeSpec, SourceRef
from .common import bounded_int, bounded_string, finish, in_scope, issue, json_records, load_json, start, text

SCHEMA_LINUX = "cptc.linux.inventory.v1"
SCHEMA_WINDOWS = "cptc.windows_ad.inventory.v1"
SAFE_STATES = {"running", "stopped", "enabled", "disabled", "unknown"}
PROVENANCE_VALUES = {"os_inventory", "operator_reviewed", "unknown"}
WRITABLE_BASIS_VALUES = {"administrator", "current_principal", "low_privilege", "unknown"}
RISKY_CAPS = {"cap_setuid", "cap_setgid", "cap_dac_override", "cap_sys_admin", "cap_sys_ptrace", "cap_chown"}
CAP_RE = re.compile(r"^cap_[a-z0-9_]+(?:\+(?:eip|ep|ei|p))?$")
MODE_RE = re.compile(r"^[0-7]{4}$")
SID_RE = re.compile(r"^(?:S-\d-\d+(?:-\d+){1,15}|[A-Za-z0-9_.-]{1,128})$")
REF_RE = re.compile(r"^[A-Za-z0-9_.:/-]{1,128}$")
COLLECTOR_ISSUES = frozenset({
    "unsupported_capability_inventory", "unsupported_identity", "unsupported_service_metadata",
    "unsupported_service_acl", "unsupported_task_acl", "manual_controlled_account_review_required",
    "unsupported_smb_ldap_policy_metadata", "collector_group_limit", "collector_directory_limit",
    "collector_suid_limit", "collector_capability_limit", "collector_record_limit",
    "collector_directory_unreadable", "collector_metadata_unavailable", "collector_walk_limit",
})
_ALLOWED_RECORD_KEYS = {"kind", "type", "facts", "target", "uid", "euid", "gid", "groups", "path", "mode", "owner",
                        "world_writable", "name", "state", "writable", "expected_binary", "capabilities", "reviewed",
                        "provenance", "writable_basis", "privileged",
                        "sudo_access_observed", "evidence_ref", "sid", "domain_sid", "domain_name", "owner_sid",
                        "non_admin_write", "inherited", "ace_count", "signing_required", "channel_binding_required",
                        "accessible", "verified", "realtime_protection_enabled", "on_access_protection_enabled",
                        "ioav_protection_enabled", "behavior_monitoring_enabled"}


def _str(value: object, maximum: int = 128) -> str | None:
    return bounded_string(value, maximum=maximum)


def _path(value: object) -> str | None:
    path = _str(value, 256)
    if not path or ".." in path or any(ord(char) < 32 for char in path):
        return None
    return path


def _bool(value: object) -> bool | None:
    return value if type(value) is bool else None


def _enum(value: object, allowed: set[str]) -> str | None:
    return value if isinstance(value, str) and value in allowed else None


def _sid(value: object) -> str | None:
    value = _str(value)
    return value if value and SID_RE.fullmatch(value) else None


def _ref(value: object) -> str | None:
    value = _str(value)
    return value if value and REF_RE.fullmatch(value) else None


def _controls(value: object) -> bool:
    if not isinstance(value, dict) or set(value) != {"network_access", "sudo_used", "service_changes"}:
        return False
    return all(value[key] is False for key in ("network_access", "sudo_used", "service_changes"))


def _legacy(raw: bytes, source: SourceRef | str, scope: ScopeSpec, track: str, check_id: str,
            allowed: tuple[str, ...]) -> ParseBatch:
    """Parse the original field/presence format without making candidates."""
    payload, source_value, issues = start(raw, source)
    observations: list[Observation] = []
    try:
        records = json_records(load_json(payload))
    except (ValueError, TypeError):
        records = []
        for number, line in enumerate(text(payload).splitlines()[:2048], 1):
            fields = [part.strip() for part in line.split("|", 2)]
            if len(fields) == 3:
                records.append({"target": fields[0], "name": fields[1], "value": fields[2]})
            elif line.strip():
                issues.append(issue("malformed_record", number))
    for number, record in enumerate(records, 1):
        target = _str(record.get("target"))
        name = _str(record.get("name"), 64)
        value = record.get("value")
        if target is None or not in_scope(target, scope):
            issues.append(issue("out_of_scope", number))
            continue
        if name not in allowed or not (isinstance(value, (str, int, bool)) and (not isinstance(value, str) or len(value) <= 128)):
            issues.append(issue("invalid_record", number))
            continue
        facts: dict[str, object] = {"field": name, "present": True}
        if isinstance(value, bool):
            facts["value_is_true"] = value
        elif isinstance(value, int):
            facts["value_is_nonzero"] = value != 0
        else:
            facts["value_length"] = len(value)
        observations.append(Observation(track, target, check_id, "observed", facts, source_value))
    if not records and payload.strip() and not issues:
        issues.append(issue("malformed_record"))
    return finish(observations, issues)


def _identity_facts(record: dict[str, Any], windows: bool) -> dict[str, object] | None:
    if windows:
        sid = _sid(record.get("sid"))
        domain_sid = _sid(record.get("domain_sid"))
        domain_name = _str(record.get("domain_name"))
        if not sid or not domain_sid or not domain_name:
            return None
        return {"sid": sid, "domain_sid": domain_sid, "domain_name": domain_name}
    values = [bounded_int(record.get(key), 0, 2**31 - 1) for key in ("uid", "euid", "gid")]
    groups = record.get("groups")
    if any(value is None for value in values) or not isinstance(groups, list) or len(groups) > 64:
        return None
    group_ids = [bounded_int(value, 0, 2**31 - 1) for value in groups]
    if not all(value is not None for value in group_ids):
        return None
    return {"uid": values[0], "euid": values[1], "gid": values[2], "groups": group_ids}


def _record(record: dict[str, Any], target: str, source: SourceRef, windows: bool) -> tuple[Observation | None, str | None]:
    kind = _str(record.get("kind"), 32) or _str(record.get("type"), 32)
    nested = isinstance(record.get("facts"), dict)
    value = record.get("facts") if nested else record
    if not kind or not isinstance(value, dict):
        return None, "invalid_record"
    if windows and kind != "defender" and any(key in value for key in ("provenance", "writable_basis", "privileged")):
        return None, "unknown_record_field"
    if nested and set(record) - {"kind", "type", "facts", "target"}:
        return None, "unknown_record_field"
    if nested and set(value) - (_ALLOWED_RECORD_KEYS - {"kind", "type", "facts", "target"}):
        return None, "unknown_record_field"
    track = "windows_ad" if windows else "linux"
    if kind == "identity":
        facts = _identity_facts(value, windows)
        check = "windows_identity" if windows else "linux_identity"
        return (Observation(track, target, check, "observed", facts, source), None) if facts else (None, "invalid_identity")
    if not windows and kind == "permission":
        path, mode, owner = _path(value.get("path")), _str(value.get("mode"), 4), _str(value.get("owner"))
        writable = _bool(value.get("world_writable"))
        if not path or not mode or not MODE_RE.fullmatch(mode) or not owner or writable is None:
            return None, "invalid_permission"
        if "writable_basis" in value or "privileged" in value:
            return None, "unknown_record_field"
        facts = {"path": path, "mode": mode, "owner": owner, "world_writable": writable}
        if "provenance" in value:
            provenance = _enum(value.get("provenance"), PROVENANCE_VALUES)
            if provenance is None:
                return None, "invalid_permission"
            facts["provenance"] = provenance
        return Observation("linux", target, "linux_permission", "candidate" if writable else "observed",
                           facts, source), None
    if kind in {"service", "task", "service_acl", "task_acl"}:
        name, state = _str(value.get("name")), _str(value.get("state"), 16) or "unknown"
        if not name or state not in SAFE_STATES:
            return None, "invalid_service_or_task"
        if windows:
            if kind == "service":
                return Observation("windows_ad", target, "windows_service", "observed", {"name": name, "state": state}, source), None
            owner_sid = _sid(value.get("owner_sid"))
            writable, inherited = _bool(value.get("non_admin_write")), _bool(value.get("inherited"))
            ace_count = bounded_int(value.get("ace_count"), 0, 256)
            if kind not in {"service_acl", "task_acl"} or not owner_sid or writable is None or inherited is None or ace_count is None:
                return None, "invalid_acl_record"
            check = "windows_service_acl" if kind == "service_acl" else "windows_task_acl"
            facts = {"name": name, "state": state, "owner_sid": owner_sid, "non_admin_write": writable,
                     "inherited": inherited, "ace_count": ace_count}
            return Observation("windows_ad", target, check, "candidate" if writable else "observed", facts, source), None
        owner, writable = _str(value.get("owner")), _bool(value.get("writable"))
        if not owner or writable is None:
            return None, "invalid_service_or_task"
        if "provenance" in value:
            return None, "unknown_record_field"
        if "writable_basis" in value:
            writable_basis = _enum(value.get("writable_basis"), WRITABLE_BASIS_VALUES)
            if writable_basis is None:
                return None, "invalid_service_or_task"
        else:
            writable_basis = None
        if "privileged" in value:
            privileged = _bool(value.get("privileged"))
            if privileged is None:
                return None, "invalid_service_or_task"
        else:
            privileged = None
        check = "linux_service" if kind == "service" else "linux_task"
        facts = {"name": name, "state": state, "owner": owner, "writable": writable}
        if writable_basis is not None:
            facts["writable_basis"] = writable_basis
        if privileged is not None:
            facts["privileged"] = privileged
        return Observation("linux", target, check, "observed", facts, source), None
    if not windows and kind == "suid":
        path, owner = _path(value.get("path")), _str(value.get("owner"))
        if not path or not owner:
            return None, "invalid_suid"
        return Observation("linux", target, "linux_suid", "observed", {"path": path, "owner": owner}, source), None
    if not windows and kind == "capability":
        path, caps = _path(value.get("path")), value.get("capabilities")
        if not path or not isinstance(caps, list) or not caps or len(caps) > 32:
            return None, "invalid_capability"
        canonical = sorted(set(cap for cap in caps if isinstance(cap, str) and CAP_RE.fullmatch(cap.split("+", 1)[0])))
        if len(canonical) != len(caps):
            return None, "invalid_capability"
        risky = any(cap.split("+", 1)[0] in RISKY_CAPS for cap in canonical)
        return Observation("linux", target, "linux_capability", "candidate" if risky else "observed",
                           {"path": path, "capabilities": canonical, "risky_capability": risky}, source), None
    if not windows and kind == "sudo":
        reviewed, observed, evidence = _bool(value.get("reviewed")), _bool(value.get("sudo_access_observed")), _ref(value.get("evidence_ref"))
        if reviewed is not True or observed is None or not evidence:
            return None, "sudo_requires_reviewed_evidence"
        return Observation("linux", target, "linux_sudo", "observed", {"reviewed": True, "sudo_access_observed": observed, "evidence_ref": evidence}, source), None
    if windows and kind in {"smb", "ldap"}:
        signing, channel = _bool(value.get("signing_required")), _bool(value.get("channel_binding_required"))
        if signing is None or (kind == "ldap" and channel is None):
            return None, "invalid_directory_policy"
        facts = {"signing_required": signing}
        if kind == "ldap":
            facts["channel_binding_required"] = channel
        check = "windows_smb_policy" if kind == "smb" else "windows_ldap_policy"
        return Observation("windows_ad", target, check, "observed", facts, source), None
    if windows and kind == "defender":
        fields = (
            "realtime_protection_enabled", "on_access_protection_enabled",
            "ioav_protection_enabled", "behavior_monitoring_enabled",
        )
        states = {key: _bool(value.get(key)) for key in fields}
        provenance = _enum(value.get("provenance"), PROVENANCE_VALUES)
        if any(state is None for state in states.values()) or provenance is None:
            return None, "invalid_defender_state"
        return Observation("windows_ad", target, "windows_defender_protection", "observed",
                           states | {"provenance": provenance}, source), None
    if windows and kind == "controlled_account":
        reviewed, accessible, verified = (_bool(value.get(key)) for key in ("reviewed", "accessible", "verified"))
        evidence = _ref(value.get("evidence_ref"))
        if reviewed is not True or accessible is None or verified is None or not evidence:
            return None, "controlled_account_requires_reviewed_evidence"
        return Observation("windows_ad", target, "windows_controlled_account", "observed",
                           {"reviewed": True, "accessible": accessible, "verified": verified, "evidence_ref": evidence}, source), None
    return None, "unsupported_field"


def _versioned(raw: bytes | str, source: SourceRef | str, scope: ScopeSpec, *, windows: bool) -> ParseBatch:
    payload, source_value, issues = start(raw, source)
    try:
        root = load_json(payload)
    except (ValueError, TypeError):
        return ParseBatch(issues=tuple(issues + [issue("malformed_json")]))
    if not isinstance(root, dict):
        return ParseBatch(issues=tuple(issues + [issue("invalid_envelope")]))
    expected = SCHEMA_WINDOWS if windows else SCHEMA_LINUX
    if root.get("schema") != expected or set(root) - {"schema", "target", "controls", "records", "issues"}:
        return ParseBatch(issues=tuple(issues + [issue("unsupported_schema")]))
    if not _controls(root.get("controls")):
        return ParseBatch(issues=tuple(issues + [issue("unsafe_controls")]))
    limitations = root.get("issues", [])
    if not isinstance(limitations, list) or len(limitations) > 32:
        issues.append(issue("invalid_collector_issues"))
    else:
        # These are collector-declared limitations, never permissions or raw
        # target prose. Unknown values reduce completeness without reflection.
        codes = {value if isinstance(value, str) and value in COLLECTOR_ISSUES else
                 "invalid_collector_issues" for value in limitations}
        issues.extend(issue(code) for code in sorted(codes))
    target, records = _str(root.get("target"), 256), root.get("records")
    if not target or not in_scope(target, scope) or not isinstance(records, list) or len(records) > 256:
        return ParseBatch(issues=tuple(issues + [issue("invalid_envelope")]))
    observations: list[Observation] = []
    for number, record in enumerate(records, 1):
        if not isinstance(record, dict):
            issues.append(issue("invalid_record", number))
            continue
        if set(record) - _ALLOWED_RECORD_KEYS:
            issues.append(issue("unknown_record_field", number))
            continue
        record_target = _str(record.get("target"), 256) or target
        if record_target != target or not in_scope(record_target, scope):
            issues.append(issue("out_of_scope", number))
            continue
        observation, error = _record(record, target, source_value, windows)
        if observation is None:
            issues.append(issue(error or "invalid_record", number))
        else:
            observations.append(observation)
    return finish(observations, issues)


def parse_linux_output(raw: bytes | str, source: SourceRef | str, scope: ScopeSpec) -> ParseBatch:
    payload = raw.encode() if isinstance(raw, str) else bytes(raw)
    try:
        root = load_json(payload)
    except (ValueError, TypeError):
        root = None
    return _versioned(payload, source, scope, windows=False) if isinstance(root, dict) and "schema" in root else _legacy(payload, source, scope, "linux", "linux_inventory", ("identity", "permission", "service", "task", "sudo", "suid", "capability"))


def parse_windows_ad_output(raw: bytes | str, source: SourceRef | str, scope: ScopeSpec) -> ParseBatch:
    payload = raw.encode() if isinstance(raw, str) else bytes(raw)
    try:
        root = load_json(payload)
    except (ValueError, TypeError):
        root = None
    return _versioned(payload, source, scope, windows=True) if isinstance(root, dict) and "schema" in root else _legacy(payload, source, scope, "windows_ad", "windows_ad_inventory", ("identity", "domain", "service", "task", "smb", "ldap", "acl"))
