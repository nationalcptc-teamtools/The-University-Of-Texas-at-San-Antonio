"""Deterministic, finite detection for reviewed CPTC observations.

This module consumes already captured records and an optional validated
advisory catalog.  It has no transport, model, filesystem, or advisory lookup
capability.  A detector result is a candidate or a check-level observation.
It never confirms exploitation or a CVE.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import re
from types import MappingProxyType
from typing import Any, Iterable, Mapping, Sequence

from .advisories import AdvisoryCatalog, catalog_is_validated, match_components
from .assessment_contracts import ComponentIdentity


CATALOG_VERSION = 3
VERSION = 1
CLASSIFICATION = "client_confidential"
DEFAULT_ROLE = "unauthenticated"
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_VERSION = re.compile(r"^(\d+)\.(\d+)(?:\.(\d+))?(.*)$")
_MODE = re.compile(r"^[0-7]{4}$")


def _freeze(value: Any) -> Any:
    if isinstance(value, dict):
        return MappingProxyType({key: _freeze(item) for key, item in value.items()})
    if isinstance(value, (list, tuple)):
        return tuple(_freeze(item) for item in value)
    return value


# This is intentionally a source-level finite catalog.  Do not add rules from
# records, advisories, plugins, or runtime configuration.
CATALOG = tuple(_freeze(item) for item in (
    {"rule_id": "linux_world_writable_critical_path", "track": "linux",
     "check_ids": ("linux_permission",), "cwe_ids": ("CWE-732",),
     "attack_techniques": ()},
    {"rule_id": "linux_writable_service_or_task", "track": "linux",
     "check_ids": ("linux_service", "linux_task"), "cwe_ids": ("CWE-732",),
     "attack_techniques": ()},
    {"rule_id": "linux_suid_inventory", "track": "linux",
     "check_ids": ("linux_suid",), "cwe_ids": (), "attack_techniques": ()},
    {"rule_id": "linux_capability_privilege", "track": "linux",
     "check_ids": ("linux_capability",), "cwe_ids": ("CWE-269",),
     "attack_techniques": ()},
    {"rule_id": "windows_service_acl", "track": "windows_ad",
     "check_ids": ("windows_service_acl",), "cwe_ids": ("CWE-732",),
     "attack_techniques": ("T1574.010",)},
    {"rule_id": "windows_task_acl", "track": "windows_ad",
     "check_ids": ("windows_task_acl",), "cwe_ids": ("CWE-732",),
     "attack_techniques": ("T1053.005",)},
    {"rule_id": "windows_smb_signing", "track": "windows_ad",
     "check_ids": ("windows_smb_policy",), "cwe_ids": (),
     "attack_techniques": ()},
    {"rule_id": "windows_ldap_signing", "track": "windows_ad",
     "check_ids": ("windows_ldap_policy",), "cwe_ids": (),
     "attack_techniques": ()},
    {"rule_id": "windows_defender_disabled", "track": "windows_ad",
     "check_ids": ("windows_defender_protection",), "cwe_ids": ("CWE-693",),
     "attack_techniques": ("T1562.001",)},
    {"rule_id": "web_missing_security_headers", "track": "web",
     "check_ids": ("web_headers",), "cwe_ids": (), "attack_techniques": ()},
    {"rule_id": "apache_httpd_path_traversal", "track": "linux",
     "check_ids": ("linux_version", "package_version", "component_identity"),
     "cwe_ids": ("CWE-22",), "attack_techniques": ()},
    {"rule_id": "samba_shared_module_loading", "track": "linux",
     "check_ids": ("linux_version", "package_version", "component_identity"),
     "cwe_ids": (), "attack_techniques": ()},
    {"rule_id": "jellyfin_version_advisory_candidates", "track": "web",
     "check_ids": ("component_identity",), "cwe_ids": (),
     "attack_techniques": ()},
))
RULE_CATALOG = CATALOG
DETECTION_CATALOG = CATALOG
_RULES = MappingProxyType({item["rule_id"]: item for item in CATALOG})
_CHECK_TO_RULE = MappingProxyType({
    check: rule["rule_id"]
    for rule in CATALOG
    for check in rule["check_ids"]
    if check not in {"linux_version", "package_version", "component_identity"}
})
_CRITICAL_PATHS = frozenset({
    "/etc/passwd", "/etc/shadow", "/etc/group", "/etc/gshadow",
    "/etc/sudoers", "/etc/sudoers.d", "/etc/ssh/sshd_config",
    "/etc/ld.so.preload", "/etc/crontab",
})
_HEADER_NAMES = frozenset({
    "hsts", "csp", "content_type_options", "frame_options",
    "referrer_policy", "permissions_policy",
})
_TRUSTED_PROVENANCE = frozenset({"os_inventory", "package_database", "operator_reviewed"})
_LOW_PRIVILEGE = "low_privilege"


@dataclass
class _Outcome:
    target: str
    rule_id: str
    component_id: str
    role_id: str
    check_id: str
    disposition: str
    collection_complete: bool
    cve_ids: set[str] = field(default_factory=set)
    cwe_ids: set[str] = field(default_factory=set)
    attack_techniques: set[str] = field(default_factory=set)
    source_actions: set[str] = field(default_factory=set)
    evidence_fields: set[str] = field(default_factory=set)
    evidence_ids: set[str] = field(default_factory=set)
    limitations: set[str] = field(default_factory=set)


def _text(value: Any, maximum: int = 256) -> str | None:
    if not isinstance(value, str) or not value or len(value) > maximum:
        return None
    if any(ord(char) < 32 or ord(char) == 127 for char in value):
        return None
    return value


def _target(value: Any) -> str | None:
    if isinstance(value, dict):
        value = value.get("canonical_url") or value.get("target_id") or value.get("id")
    return _text(value, 512)


def _request_target_matches(request: Mapping[str, Any], observation: Mapping[str, Any], target: str) -> bool:
    approved = request.get("target")
    if approved is None:
        # Offline imports have their own scope-checked, source-bound records.
        return True
    if isinstance(approved, Mapping):
        if observation.get("track") == "web":
            return target == approved.get("canonical_url")
        return target == approved.get("host")
    return target == _target(approved)


def _safe_ids(value: Any, maximum: int = 64) -> set[str]:
    if isinstance(value, str):
        value = [value]
    if not isinstance(value, (tuple, list, set, frozenset)):
        return set()
    return {item for item in value if isinstance(item, str) and _text(item, maximum)}


def _sha(value: Any) -> str | None:
    return value if isinstance(value, str) and _SHA256.fullmatch(value) else None


def _source_hash(observation: Mapping[str, Any]) -> str | None:
    # The receipt belongs to the observation envelope.  A similarly named
    # fact is untrusted payload and cannot bind captured evidence to it.
    return _sha(observation.get("source_sha256"))


def _role(request: Mapping[str, Any]) -> str:
    for key in ("role_id", "account_role", "account_role_id", "role"):
        value = _text(request.get(key), 128)
        if value:
            return value
    return DEFAULT_ROLE


def _request_context(record: Mapping[str, Any]) -> tuple[str | None, str, set[str], bool]:
    request = record.get("request")
    if not isinstance(request, Mapping):
        return None, DEFAULT_ROLE, set(), False
    target = _target(request.get("target"))
    role = _role(request)
    # Only the immutable originating request identity can link an observation
    # to an action.  Caller-provided action lists and module IDs are not proof.
    actions = set()
    request_id = _text(request.get("request_id"), 256)
    if request_id:
        actions.add(request_id)
    # These fields are the minimum immutable request identity needed to trust
    # an observation's source/action linkage.  Values are never copied out.
    identity_ok = (all(_text(request.get(key), 256) for key in
                       ("request_id", "module_id", "source", "operator_id"))
                   and request.get("source") in {"operator", "human", "collector"})
    return target, role, actions, identity_ok


def _evidence_ids(result: Mapping[str, Any], source_sha256: str | None = None) -> set[str]:
    values = result.get("evidence", ())
    if not isinstance(values, (tuple, list)):
        return set()
    found: set[str] = set()
    for item in values:
        if isinstance(item, Mapping):
            value = item.get("evidence_id")
            evidence_sha = item.get("sha256")
            if (_text(value, 128) and _sha(evidence_sha)
                    and (source_sha256 is None or evidence_sha == source_sha256)):
                found.add(value)
    return found


def _facts(observation: Mapping[str, Any]) -> Mapping[str, Any]:
    value = observation.get("facts")
    return value if isinstance(value, Mapping) else {}


def _component_id(observation: Mapping[str, Any], facts: Mapping[str, Any],
                  check_id: str, target: str) -> str:
    supplied = _text(facts.get("component_id"), 128)
    if supplied:
        return supplied
    if check_id in {"linux_permission", "linux_suid", "linux_capability"}:
        value = _text(facts.get("path"), 256)
        if value:
            return "path:" + value
    if check_id in {"linux_service", "linux_task", "windows_service_acl", "windows_task_acl"}:
        value = _text(facts.get("name"), 256)
        if value:
            return check_id + ":" + value
    if check_id == "network_inventory":
        port = facts.get("port")
        protocol = _text(facts.get("protocol"), 32) or "unknown"
        if type(port) is int and 1 <= port <= 65535:
            return "port:" + str(port) + "/" + protocol.lower()
    if check_id in {"linux_version", "package_version", "component_identity"}:
        product = _text(facts.get("product"), 128) or _text(facts.get("component"), 128)
        version = _text(facts.get("version"), 128)
        release = _text(facts.get("release"), 128) or ""
        if product and version:
            return "package:" + product + ":" + version + ":" + release
    return "target:" + target


def _base(target: str, role: str, component_id: str, observation: Mapping[str, Any], rule_id: str,
          disposition: str, complete: bool, *, check_id: str,
          actions: set[str], evidence: set[str], source_ok: bool) -> _Outcome:
    result = _Outcome(target, rule_id, component_id, role, check_id, disposition,
                      complete and source_ok)
    result.source_actions.update(actions)
    result.evidence_ids.update(evidence)
    source = _source_hash(observation)
    if source:
        result.evidence_fields.add("source_sha256")
    else:
        result.limitations.add("source_sha256_missing_or_invalid")
    if not source_ok:
        result.limitations.add("untrusted_source_or_action")
        result.collection_complete = False
        if result.disposition in {"observed_condition", "not_observed"}:
            result.disposition = "incomplete"
    return result


def _missing(result: _Outcome, *fields: str) -> _Outcome:
    result.disposition = "unknown"
    result.collection_complete = False
    result.limitations.add("missing_predicate_fields")
    result.evidence_fields.update(fields)
    return result


def _conclusion(result: _Outcome, disposition: str, source_ok: bool) -> None:
    result.disposition = disposition if source_ok else "incomplete"
    result.collection_complete = source_ok


def _issue_state(result: Mapping[str, Any], *, issue: bool) -> str | None:
    status = result.get("status", "complete")
    if status in {"failed", "failure"}:
        return "failed"
    if status in {"blocked", "stopped"}:
        return status
    if status in {"uncertain", "incomplete"}:
        return "incomplete"
    if issue:
        return "incomplete"
    return None


def _common(target: str, role: str, component_id: str, observation: Mapping[str, Any], rule: str,
            check_id: str, actions: set[str], evidence: set[str], source_ok: bool,
            state: str, *, complete: bool, fields: Iterable[str]) -> _Outcome:
    result = _base(target, role, component_id, observation, rule, state, complete, check_id=check_id,
                   actions=actions, evidence=evidence, source_ok=source_ok)
    result.evidence_fields.update(fields)
    return result


def _evaluate_observation(target: str, role: str, observation: Mapping[str, Any],
                          result: Mapping[str, Any], actions: set[str], source_ok: bool,
                          evidence: set[str], component_id: str,
                          advisory_catalog: AdvisoryCatalog | None) -> list[_Outcome]:
    track = _text(observation.get("track"), 64)
    check_id = _text(observation.get("check_id"), 128)
    if not track or not check_id:
        return []
    facts = _facts(observation)
    failed = _issue_state(result, issue=bool(result.get("facts", {}).get("issues"))
                          if isinstance(result.get("facts"), Mapping) else False)
    rule_id = _CHECK_TO_RULE.get(check_id)
    if track == "network" and check_id == "network_inventory":
        ports = facts.get("ports")
        if not isinstance(ports, (tuple, list)):
            ports = (facts,)
        results: list[_Outcome] = []
        for port in ports:
            if not isinstance(port, Mapping) or port.get("state") != "open":
                continue
            version = _text(port.get("version"), 128)
            product = (_text(port.get("product"), 128)
                       or _text(port.get("service"), 128)
                       or _text(port.get("name"), 128))
            if not version or not product:
                continue
            port_facts = dict(port)
            port_facts.update({"product": product, "version": version, "provenance": "banner"})
            port_observation = dict(observation)
            port_observation["facts"] = port_facts
            port_id = _component_id(port_observation, port_facts, check_id, target)
            results.extend(_evaluate_versions(target, role, port_id, port_observation,
                                              port_facts, actions, source_ok, evidence,
                                              failed, check_id, advisory_catalog))
        return results
    if ((track == "linux" and check_id in {"linux_version", "package_version", "component_identity"})
            or (track == "web" and check_id == "component_identity")):
        return _evaluate_versions(target, role, component_id, observation, facts, actions, source_ok,
                                  evidence, failed, check_id, advisory_catalog)
    if not rule_id or _RULES[rule_id]["track"] != track:
        return []
    if failed:
        return [_common(target, role, component_id, observation, rule_id, check_id, actions, evidence,
                        source_ok, failed, complete=False, fields=())]
    if check_id == "linux_permission":
        path, mode, owner = (_text(facts.get(key), 256 if key == "path" else 128)
                             for key in ("path", "mode", "owner"))
        writable = facts.get("world_writable")
        provenance = _text(facts.get("provenance"), 64)
        if path not in _CRITICAL_PATHS:
            return []
        out = _common(target, role, component_id, observation, rule_id, check_id, actions, evidence,
                      source_ok, "unknown", complete=False,
                      fields=("path", "mode", "owner", "world_writable", "provenance"))
        if not path or not mode or not owner or type(writable) is not bool or not provenance:
            return [_missing(out, "path", "mode", "owner", "world_writable", "provenance")]
        if not _MODE.fullmatch(mode) or provenance not in _TRUSTED_PROVENANCE:
            out.limitations.add("permission_provenance_unverified")
            return [_missing(out, "mode", "provenance")]
        mode_writable = mode[-1] in "2367"
        if mode_writable != writable:
            out.limitations.add("conflicting_permission_fields")
            return [_missing(out, "mode", "world_writable")]
        _conclusion(out, "observed_condition" if writable else "not_observed", source_ok)
        out.cwe_ids.add("CWE-732")
        return [out]
    if check_id in {"linux_service", "linux_task"}:
        required = ("name", "state", "owner", "writable", "writable_basis", "privileged")
        out = _common(target, role, component_id, observation, rule_id, check_id, actions, evidence,
                      source_ok, "unknown", complete=False, fields=required)
        if (any(key not in facts for key in required)
                or not all(_text(facts.get(key), 256 if key == "name" else 128)
                           for key in ("name", "state", "owner"))
                or type(facts.get("writable")) is not bool
                or type(facts.get("privileged")) is not bool):
            return [_missing(out, *required)]
        if facts.get("writable_basis") != _LOW_PRIVILEGE or facts.get("privileged") is not True:
            out.limitations.add("low_privilege_basis_required")
            return [_missing(out, "writable_basis", "privileged")]
        _conclusion(out, "observed_condition" if facts["writable"] else "not_observed", source_ok)
        out.cwe_ids.add("CWE-732")
        return [out]
    if check_id == "linux_suid":
        required = ("path", "owner")
        out = _common(target, role, component_id, observation, rule_id, check_id, actions, evidence,
                      source_ok, "unknown", complete=False, fields=required)
        if not all(_text(facts.get(key), 256) for key in required):
            return [_missing(out, *required)]
        out.limitations.add("inventory_only_no_finding")
        out.disposition = "unknown"
        out.collection_complete = source_ok
        return [out]
    if check_id == "linux_capability":
        caps = facts.get("capabilities")
        out = _common(target, role, component_id, observation, rule_id, check_id, actions, evidence,
                      source_ok, "unknown", complete=False, fields=("path", "capabilities"))
        if not _text(facts.get("path"), 256) or not isinstance(caps, (tuple, list)) or not caps or not all(isinstance(item, str) for item in caps):
            return [_missing(out, "path", "capabilities")]
        risky = {item.split("+", 1)[0].lower() for item in caps} & {"cap_setuid", "cap_setgid"}
        out.disposition = "candidate" if risky else "not_observed"
        out.collection_complete = source_ok
        if risky:
            out.cwe_ids.add("CWE-269")
        else:
            out.limitations.add("capability_inventory_no_risky_capability")
        return [out]
    if check_id in {"windows_service_acl", "windows_task_acl"}:
        required = ("name", "state", "owner_sid", "non_admin_write", "inherited", "ace_count")
        out = _common(target, role, component_id, observation, rule_id, check_id, actions, evidence,
                      source_ok, "unknown", complete=False, fields=required)
        if (any(key not in facts for key in required)
                or not _text(facts.get("name"), 256)
                or not _text(facts.get("state"), 128)
                or not _text(facts.get("owner_sid"), 256)
                or type(facts.get("non_admin_write")) is not bool
                or type(facts.get("inherited")) is not bool
                or type(facts.get("ace_count")) is not int
                or facts.get("ace_count") < 0):
            return [_missing(out, *required)]
        _conclusion(out, "observed_condition" if facts["non_admin_write"] else "not_observed", source_ok)
        out.cwe_ids.add("CWE-732")
        out.attack_techniques.add("T1574.010" if check_id == "windows_service_acl" else "T1053.005")
        return [out]
    if check_id in {"windows_smb_policy", "windows_ldap_policy"}:
        required = ("signing_required",) if check_id == "windows_smb_policy" else ("signing_required", "channel_binding_required")
        out = _common(target, role, component_id, observation, rule_id, check_id, actions, evidence,
                      source_ok, "unknown", complete=False, fields=required)
        if any(type(facts.get(key)) is not bool for key in required):
            return [_missing(out, *required)]
        weak = not facts["signing_required"] or (check_id == "windows_ldap_policy" and not facts["channel_binding_required"])
        out.disposition = "candidate" if weak else "not_observed"
        out.collection_complete = source_ok
        if weak:
            out.limitations.add("prerequisites_unverified")
        return [out]
    if check_id == "windows_defender_protection":
        required = (
            "realtime_protection_enabled", "on_access_protection_enabled",
            "ioav_protection_enabled", "behavior_monitoring_enabled", "provenance",
        )
        out = _common(target, role, component_id, observation, rule_id, check_id, actions, evidence,
                      source_ok, "unknown", complete=False, fields=required)
        states = [facts.get(key) for key in required[:-1]]
        provenance = _text(facts.get("provenance"), 64)
        if any(type(value) is not bool for value in states) or provenance not in _TRUSTED_PROVENANCE:
            out.limitations.add("protection_state_or_provenance_unverified")
            return [_missing(out, *required)]
        disabled = any(value is False for value in states)
        _conclusion(out, "observed_condition" if disabled else "not_observed", source_ok)
        out.cwe_ids.add("CWE-693")
        out.attack_techniques.add("T1562.001")
        return [out]
    if check_id == "web_headers":
        status, present, redirect = facts.get("status"), facts.get("headers_present"), facts.get("redirect")
        out = _common(target, role, component_id, observation, rule_id, check_id, actions, evidence,
                      source_ok, "unknown", complete=False,
                      fields=("status", "headers_present", "redirect"))
        if type(status) is not int or not isinstance(present, (tuple, list)) or type(redirect) is not bool:
            return [_missing(out, "status", "headers_present", "redirect")]
        present_set = {item for item in present if isinstance(item, str)}
        if not present_set <= _HEADER_NAMES or status < 100 or status > 599:
            return [_missing(out, "status", "headers_present")]
        if status >= 400:
            out.limitations.add("response_not_successful")
            return [_missing(out, "status")]
        missing = sorted(_HEADER_NAMES - present_set)
        if status < 400 and missing:
            out.disposition = "candidate"
        else:
            _conclusion(out, "not_observed", source_ok)
        if missing:
            out.limitations.add("missing_security_headers_configuration")
        return [out]
    return []


def _parse_version(value: Any) -> tuple[tuple[int, int, int], str] | None:
    text = _text(value, 128)
    if not text:
        return None
    match = _VERSION.fullmatch(text)
    if not match:
        return None
    return (int(match.group(1)), int(match.group(2)), int(match.group(3) or 0)), match.group(4)


def _product(facts: Mapping[str, Any]) -> str | None:
    for key in ("product", "component", "name", "package"):
        value = _text(facts.get(key), 128)
        if value:
            return value
    return None


def _evaluate_versions(target: str, role: str, component_id: str, observation: Mapping[str, Any], facts: Mapping[str, Any],
                       actions: set[str], source_ok: bool, evidence: set[str], failed: str | None,
                       check_id: str, advisory_catalog: AdvisoryCatalog | None) -> list[_Outcome]:
    product = _product(facts)
    parsed = _parse_version(facts.get("version"))
    provenance = _text(facts.get("provenance"), 64)
    product_key = product.strip().lower() if product else ""
    product_alias = {
        "apache http server": "apache", "apache httpd": "apache", "httpd": "apache", "apache2": "apache",
        "samba": "samba", "samba server": "samba",
        "jellyfin server": "jellyfin",
    }.get(product_key)
    if not product_alias or not parsed:
        return []
    version, suffix = parsed
    rules: list[tuple[str, bool, set[str]]] = []
    if product_alias == "apache":
        if version == (2, 4, 49):
            rules.append(("apache_httpd_path_traversal", True, {"CVE-2021-41773", "CVE-2021-42013"}))
        elif version == (2, 4, 50):
            rules.append(("apache_httpd_path_traversal", True, {"CVE-2021-42013"}))
        else:
            rules.append(("apache_httpd_path_traversal", False, set()))
    elif product_alias == "samba":
        # Samba's official record states "since 3.5.0" and fixes the
        # branches at 4.4.14, 4.5.10, and 4.6.4.
        affected = version >= (3, 5, 0) and (
            version < (4, 4, 0)
            or ((version[0], version[1]) == (4, 4) and version[2] < 14)
            or ((version[0], version[1]) == (4, 5) and version[2] < 10)
            or ((version[0], version[1]) == (4, 6) and version[2] < 4)
        )
        rules.append(("samba_shared_module_loading", affected, {"CVE-2017-7494"} if affected else set()))
    else:
        out = _common(
            target, role, component_id, observation,
            "jellyfin_version_advisory_candidates", check_id, actions, evidence,
            source_ok, "unknown", complete=False,
            fields=("ecosystem", "product", "version", "provenance"),
        )
        out.collection_complete = False
        out.limitations.update({"version_only", "configuration_unverified"})
        if provenance not in _TRUSTED_PROVENANCE or suffix or provenance == "banner":
            out.limitations.add("backport_unverified")
        ecosystem = _text(facts.get("ecosystem"), 64)
        if advisory_catalog is None:
            out.limitations.add("advisory_catalog_required")
        elif ecosystem != "semver":
            out.limitations.add("component_identity_mismatch")
        else:
            component = ComponentIdentity(
                component_id=component_id,
                target_id=target,
                ecosystem=ecosystem,
                product=product or "",
                version=_text(facts.get("version"), 128) or "",
                provenance=provenance if provenance in {
                    "banner", "package_database", "os_inventory", "operator_reviewed",
                } else "unknown",
            )
            matches = tuple(
                match for match in match_components((component,), advisory_catalog)
                if match.state != "unsupported"
            )
            candidates = tuple(
                match for match in matches if match.state == "affected_candidate"
            )
            for match in matches:
                out.limitations.update(match.limitations)
            for match in candidates:
                out.cve_ids.update(match.cve_ids)
            if candidates:
                out.disposition = "candidate"
            elif not matches:
                out.limitations.add("advisory_catalog_no_match")
        if failed:
            out.disposition = failed
        return [out]
    outcomes: list[_Outcome] = []
    for rule_id, affected, cves in rules:
        out = _common(target, role, component_id, observation, rule_id, check_id, actions, evidence,
                      source_ok, "candidate" if affected else "unknown", complete=False,
                      fields=("product", "version", "provenance"))
        out.cve_ids.update(cves)
        out.collection_complete = False  # version alone never proves a CVE
        out.limitations.update({"version_only", "configuration_unverified"})
        if provenance not in _TRUSTED_PROVENANCE or suffix or provenance == "banner":
            out.limitations.add("backport_unverified")
        if failed:
            out.disposition = failed
            out.collection_complete = False
        elif not affected:
            # A version without a complete package/advisory relationship cannot
            # be called hardened.  Keep the unresolved state visible.
            out.disposition = "unknown"
        outcomes.append(out)
    return outcomes


def _module_rules(module_id: Any) -> tuple[str, ...]:
    value = _text(module_id, 128) or ""
    if value in {"linux.output_import", "linux_inventory"}:
        return tuple(item["rule_id"] for item in CATALOG if item["track"] == "linux")
    if value in {"windows_ad.output_import", "windows_ad_inventory"}:
        return tuple(item["rule_id"] for item in CATALOG if item["track"] == "windows_ad")
    if value in {"web.headers", "web_headers"}:
        return ("web_missing_security_headers",)
    if value == "web.portcast_identity":
        return ("jellyfin_version_advisory_candidates",)
    if value in {"network.nmap_import", "network_inventory", "service_inventory"}:
        return ("apache_httpd_path_traversal", "samba_shared_module_loading")
    return ()


def _expected(expected_checks: Sequence[Mapping[str, Any]] | None) -> list[tuple[str, str, str]]:
    if expected_checks is None:
        return []
    if not isinstance(expected_checks, (tuple, list)):
        raise TypeError("expected_checks must be an operator tuple or list")
    result: list[tuple[str, str, str]] = []
    for item in expected_checks:
        if not isinstance(item, Mapping) or set(item) != {"target", "rule_id", "role_id"}:
            raise ValueError("expected_checks accepts only target, rule_id, and role_id")
        target, rule_id, role = (_target(item.get("target")), _text(item.get("rule_id"), 128), _text(item.get("role_id"), 128))
        if not target or not rule_id or rule_id not in _RULES or not role:
            raise ValueError("invalid expected check")
        result.append((target, rule_id, role))
    return sorted(set(result))


def _merge(group: list[_Outcome]) -> _Outcome:
    first = sorted(group, key=lambda item: (item.check_id, item.component_id,
                                            tuple(sorted(item.source_actions)), tuple(sorted(item.evidence_ids))))[0]
    result = _Outcome(first.target, first.rule_id, first.component_id, first.role_id,
                      first.check_id, first.disposition,
                      all(item.collection_complete for item in group))
    for item in group:
        result.cve_ids.update(item.cve_ids)
        result.cwe_ids.update(item.cwe_ids)
        result.attack_techniques.update(item.attack_techniques)
        result.source_actions.update(item.source_actions)
        result.evidence_fields.update(item.evidence_fields)
        result.evidence_ids.update(item.evidence_ids)
        result.limitations.update(item.limitations)
    dispositions = {item.disposition for item in group}
    positive = {"candidate", "observed_condition"} & dispositions
    if positive and "not_observed" in dispositions:
        result.disposition = "unknown"
        result.collection_complete = False
        result.limitations.add("conflicting_observations")
    elif "failed" in dispositions:
        result.disposition = "failed"
        result.collection_complete = False
    elif "blocked" in dispositions:
        result.disposition = "blocked"
        result.collection_complete = False
    elif "incomplete" in dispositions:
        result.disposition = "incomplete"
        result.collection_complete = False
    elif "unknown" in dispositions:
        result.disposition = "unknown"
        result.collection_complete = False
    elif "observed_condition" in dispositions:
        result.disposition = "observed_condition"
    elif "candidate" in dispositions:
        result.disposition = "candidate"
    elif "not_observed" in dispositions:
        result.disposition = "not_observed"
    return result


def _row(outcome: _Outcome) -> dict[str, Any]:
    return {
        "rule_id": outcome.rule_id,
        "target": outcome.target,
        "component_id": outcome.component_id,
        "check_id": outcome.check_id,
        "role_id": outcome.role_id,
        "disposition": outcome.disposition,
        "cve_ids": sorted(outcome.cve_ids),
        "cwe_ids": sorted(outcome.cwe_ids),
        "attack_techniques": sorted(outcome.attack_techniques),
        "source_actions": sorted(outcome.source_actions),
        "evidence_fields": sorted(outcome.evidence_fields),
        "evidence_ids": sorted(outcome.evidence_ids),
        "limitations": sorted(outcome.limitations),
        "collection_complete": bool(outcome.collection_complete),
    }


def classify_records(records: Iterable[Mapping[str, Any]], *,
                    expected_checks: Sequence[Mapping[str, Any]] = (),
                    advisory_catalog: AdvisoryCatalog | None = None) -> dict[str, Any]:
    """Classify synthetic or operator-provided records deterministically.

    Only finite catalog rules are evaluated.  Invalid or unrelated records are
    ignored, and expected operator check assignments make absent checks visible
    as ``not_tested``. Jellyfin CVE candidates require a catalog returned by
    :func:`cptc_harness.advisories.load_catalog`. The function performs no
    network or model calls.
    """
    if isinstance(records, (str, bytes, Mapping)):
        raise TypeError("records must be an iterable of record mappings")
    try:
        record_iter = iter(records)
    except TypeError:
        raise TypeError("records must be an iterable of record mappings") from None
    if advisory_catalog is not None and not catalog_is_validated(advisory_catalog):
        raise TypeError("advisory_catalog must be returned by load_catalog")
    expected = _expected(expected_checks)
    outcomes: list[_Outcome] = []
    failed_keys: set[tuple[str, str, str]] = set()
    for record in record_iter:
        if not isinstance(record, Mapping):
            continue
        request_target, role, actions, identity_ok = _request_context(record)
        result = record.get("result")
        if not isinstance(result, Mapping):
            continue
        observations = result.get("facts", {}).get("observations", ()) if isinstance(result.get("facts"), Mapping) else ()
        if not isinstance(observations, (tuple, list)):
            observations = ()
        for observation in observations:
            if not isinstance(observation, Mapping):
                continue
            target = _target(observation.get("target")) or request_target
            if not target:
                continue
            source_hash = _source_hash(observation)
            evidence = _evidence_ids(result, source_hash)
            target_matches = _request_target_matches(record.get("request", {}), observation, target)
            source_ok = identity_ok and target_matches and source_hash is not None and bool(actions) and bool(evidence)
            component_id = _component_id(observation, _facts(observation),
                                         _text(observation.get("check_id"), 128) or "", target)
            evaluated = _evaluate_observation(target, role, observation, result, actions,
                                              source_ok, evidence, component_id,
                                              advisory_catalog)
            if not target_matches:
                for outcome in evaluated:
                    outcome.disposition = "incomplete"
                    outcome.collection_complete = False
                    outcome.limitations.add("request_target_mismatch")
            outcomes.extend(evaluated)
        failed = _issue_state(result, issue=bool(result.get("facts", {}).get("issues"))
                              if isinstance(result.get("facts"), Mapping) else False)
        if failed in {"failed", "blocked", "stopped", "incomplete"} and request_target:
            for rule_id in _module_rules(record.get("request", {}).get("module_id") if isinstance(record.get("request"), Mapping) else None):
                failed_keys.add((request_target, rule_id, role))
    grouped: dict[tuple[str, str, str, str], list[_Outcome]] = {}
    for outcome in outcomes:
        grouped.setdefault((outcome.target, outcome.rule_id, outcome.role_id,
                            outcome.component_id), []).append(outcome)
    merged = {_key: _merge(value) for _key, value in grouped.items()}
    for key in sorted(failed_keys):
        target, rule_id, role = key
        component_key = (*key, "target:" + target)
        if component_key not in merged:
            merged[component_key] = _Outcome(target, rule_id, "target:" + target, role, "", "failed", False,
                                   limitations={"operation_failed"})
    for target, rule_id, role in expected:
        if not any(key[:3] == (target, rule_id, role) for key in merged):
            key = (target, rule_id, role, "target:" + target)
            merged[key] = _Outcome(target, rule_id, "target:" + target, role, "", "not_tested", False,
                                                       limitations={"no_matching_observation"})
    rows = [_row(merged[key]) for key in sorted(merged)]
    coverage = [{"target": row["target"], "rule_id": row["rule_id"], "role_id": row["role_id"],
                 "component_id": row["component_id"],
                 "disposition": row["disposition"], "collection_complete": row["collection_complete"]}
                for row in rows]
    return {"version": VERSION, "catalog_version": CATALOG_VERSION,
            "classification": CLASSIFICATION, "detections": rows, "coverage": coverage}


__all__ = ["CATALOG", "CATALOG_VERSION", "CLASSIFICATION", "DEFAULT_ROLE",
           "DETECTION_CATALOG", "RULE_CATALOG", "VERSION", "classify_records"]
