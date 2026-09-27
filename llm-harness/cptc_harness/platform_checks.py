"""Finite, offline platform posture checks.

The catalog and predicates in this module are deliberately closed.  Facts are
typed before evaluation; no rule can be added by importing data, registering a
plugin, or changing runtime configuration.  A candidate is a review lead, not
proof of exploitation or a confirmed vulnerability.
"""
from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Mapping
import re


CATALOG_VERSION = 1
_MAX_LIST = 32
_MAX_TEXT = 128
_ID = re.compile(r"^[A-Za-z0-9_.:/@+-]{1,128}$")
_DISPOSITIONS = frozenset({"candidate", "observed_condition", "not_observed", "unknown",
                           "incomplete", "unsupported", "not_tested", "blocked"})
_COLLECTION_STATES = frozenset({"complete", "incomplete", "access_denied", "absent", "unsupported"})
_PROVENANCES = frozenset({"operator_reviewed", "os_inventory", "network_observation",
                          "application_test", "database_observation", "unknown"})


@dataclass(frozen=True)
class PlatformRule:
    check_id: str
    track: str
    required_fields: tuple[str, ...]
    references: tuple[str, ...]
    version: str = "1"
    mode: str = "offline"


@dataclass(frozen=True)
class PlatformDecision:
    check_id: str
    track: str
    disposition: str
    collection_state: str
    provenance: str
    prerequisites_verified: bool
    source_trusted: bool
    limitations: tuple[str, ...] = ()
    references: tuple[str, ...] = ()
    catalog_version: int = CATALOG_VERSION

    @property
    def rule_id(self) -> str:
        return self.check_id

    @property
    def collection_complete(self) -> bool:
        return self.disposition in {"candidate", "observed_condition", "not_observed"}

    def as_dict(self) -> dict[str, Any]:
        return {
            "catalog_version": self.catalog_version,
            "check_id": self.check_id,
            "track": self.track,
            "disposition": self.disposition,
            "collection_state": self.collection_state,
            "provenance": self.provenance,
            "prerequisites_verified": self.prerequisites_verified,
            "source_trusted": self.source_trusted,
            "collection_complete": self.collection_complete,
            "limitations": list(self.limitations),
            "references": list(self.references),
        }


def _rule(check_id: str, track: str, fields: tuple[str, ...], references: tuple[str, ...]) -> PlatformRule:
    return PlatformRule(check_id, track, fields, references)


_REF_TLS = "https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html"
_REF_ADCS = "https://learn.microsoft.com/en-us/defender-for-identity/security-posture-assessments/certificates"
_REF_ADCS_TEMPLATE = "https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/certificate-template-concepts"
_REF_DB = "https://www.postgresql.org/docs/17/role-attributes.html"
_REF_SESSION = "https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html"

CATALOG = (
    _rule("network_tls_certificate_protocol_posture", "network",
          ("policy_reviewed", "protocols", "policy_protocols", "certificate_valid",
           "hostname_valid", "chain_valid"), (_REF_TLS,)),
    _rule("linux_sudo_privilege_boundary", "linux",
          ("reviewed", "low_privileged_principal", "unrestricted_root", "nopasswd", "command_scope"), ()),
    _rule("domain_account_policy", "windows_ad",
          ("policy_reviewed", "reversible_encryption_enabled", "deviation_ids"), ()),
    _rule("delegation_relationships", "windows_ad",
          ("relationship_present", "relationship_type", "enabled", "trusted_to_authenticate",
           "target_service", "prerequisite_ids"), ()),
    _rule("gpo_permissions", "windows_ad",
          ("acl_complete", "non_admin_effective_write", "principal_class", "gpo_id"), ()),
    _rule("adcs_configuration_relationships", "windows_ad",
          ("template_enabled", "low_privilege_enrollment", "subject_supply", "authentication_eku",
           "manager_approval", "authorized_signatures", "template_id"), (_REF_ADCS, _REF_ADCS_TEMPLATE)),
    _rule("route_account_role_authorization", "web",
          ("controlled_identity_a", "controlled_identity_b", "operator_designated_ownership",
           "authorized_control_succeeded", "denied_expectation_violated", "protected_record_match"), ()),
    _rule("session_lifecycle", "web",
          ("independent_observation", "rotation_observed", "logout_invalidation_observed",
           "reuse_rejected", "cookie_only"), (_REF_SESSION,)),
    _rule("database_versions_transport_roles_grants", "database",
          ("engine", "policy_reviewed", "transport_required", "transport_encrypted", "deviation_ids"), (_REF_DB,)),
)
PLATFORM_RULES = CATALOG
RULE_CATALOG = CATALOG
_RULES = MappingProxyType({rule.check_id: rule for rule in CATALOG})

_PROTOCOLS = frozenset({"sslv3", "tls1.0", "tls1.1", "tls1.2", "tls1.3"})
_RELATIONSHIPS = frozenset({"unconstrained_delegation", "constrained_delegation",
                            "resource_based_constrained_delegation"})
_PRINCIPALS = frozenset({"non_admin", "authenticated_non_admin"})
_ENGINES = frozenset({"postgresql", "mysql"})
_DB_DEVIATIONS = frozenset({"public_schema_create", "public_execute", "trust_authentication",
                            "anonymous_account", "remote_root", "cleartext_transport"})

_FIELD_KINDS: Mapping[str, Mapping[str, str]] = MappingProxyType({
    "network_tls_certificate_protocol_posture": MappingProxyType({
        "policy_reviewed": "bool", "protocols": "protocols", "policy_protocols": "protocols",
        "certificate_valid": "bool", "hostname_valid": "bool", "chain_valid": "bool",
    }),
    "linux_sudo_privilege_boundary": MappingProxyType({
        "reviewed": "bool", "low_privileged_principal": "bool", "unrestricted_root": "bool",
        "nopasswd": "bool", "command_scope": "scope",
    }),
    "domain_account_policy": MappingProxyType({
        "policy_reviewed": "bool", "reversible_encryption_enabled": "bool", "deviation_ids": "domain_deviations",
    }),
    "delegation_relationships": MappingProxyType({
        "relationship_present": "bool", "relationship_type": "relationship", "enabled": "bool",
        "trusted_to_authenticate": "bool", "target_service": "id", "prerequisite_ids": "ids",
    }),
    "gpo_permissions": MappingProxyType({
        "acl_complete": "bool", "non_admin_effective_write": "bool", "principal_class": "principal",
        "gpo_id": "id",
    }),
    "adcs_configuration_relationships": MappingProxyType({
        "template_enabled": "bool", "low_privilege_enrollment": "bool", "subject_supply": "bool",
        "authentication_eku": "bool", "manager_approval": "bool", "authorized_signatures": "bool",
        "template_id": "id",
    }),
    "route_account_role_authorization": MappingProxyType({
        "controlled_identity_a": "id", "controlled_identity_b": "id", "operator_designated_ownership": "bool",
        "authorized_control_succeeded": "bool", "denied_expectation_violated": "bool",
        "protected_record_match": "bool",
    }),
    "session_lifecycle": MappingProxyType({
        "independent_observation": "bool", "rotation_observed": "bool", "logout_invalidation_observed": "bool",
        "reuse_rejected": "bool", "cookie_only": "bool",
    }),
    "database_versions_transport_roles_grants": MappingProxyType({
        "engine": "engine", "policy_reviewed": "bool", "transport_required": "bool",
        "transport_encrypted": "bool", "deviation_ids": "db_deviations",
    }),
})


def _bounded_text(value: Any, *, name: str = "fact") -> str:
    if not isinstance(value, str) or not value or len(value) > _MAX_TEXT or not _ID.fullmatch(value):
        raise ValueError(f"invalid {name}")
    return value


def _boolean(value: Any, *, name: str) -> bool:
    if type(value) is not bool:
        raise ValueError(f"invalid {name}")
    return value


def _values(value: Any, *, allowed: frozenset[str], name: str) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple)) or len(value) > _MAX_LIST:
        raise ValueError(f"invalid {name}")
    result = tuple(_bounded_text(item, name=name) for item in value)
    if len(set(result)) != len(result) or any(item not in allowed for item in result):
        raise ValueError(f"invalid {name}")
    return result


def _normalize_field(kind: str, value: Any, name: str) -> Any:
    if kind == "bool":
        return _boolean(value, name=name)
    if kind == "id":
        return _bounded_text(value, name=name)
    if kind == "scope":
        if value not in {"all", "restricted"}:
            raise ValueError(f"invalid {name}")
        return value
    if kind == "protocols":
        return _values(value, allowed=_PROTOCOLS, name=name)
    if kind == "domain_deviations":
        return _values(value, allowed=frozenset({"reversible_encryption", "operator_policy_deviation"}), name=name)
    if kind == "db_deviations":
        return _values(value, allowed=_DB_DEVIATIONS, name=name)
    if kind == "ids":
        return _values(value, allowed=frozenset(_ID_VALUES), name=name)
    if kind == "relationship":
        if value not in _RELATIONSHIPS:
            raise ValueError(f"invalid {name}")
        return value
    if kind == "principal":
        if value not in _PRINCIPALS:
            raise ValueError(f"invalid {name}")
        return value
    if kind == "engine":
        if value not in _ENGINES:
            raise ValueError(f"invalid {name}")
        return value
    raise ValueError(f"unsupported field type for {name}")


_ID_VALUES = frozenset({"spn_present", "target_service_reachable", "operator_reviewed_prerequisite",
                        "delegation_scope_verified", "relationship_owner_verified"})


def validate_facts(check_id: str, facts: Mapping[str, Any]) -> Mapping[str, Any]:
    """Validate and freeze one finite rule's fact object."""
    rule = _RULES.get(check_id) if isinstance(check_id, str) else None
    if rule is None:
        raise ValueError("unsupported platform check")
    if not isinstance(facts, Mapping):
        raise TypeError("platform facts must be a mapping")
    kinds = _FIELD_KINDS[check_id]
    unknown = set(facts) - set(kinds)
    if unknown:
        raise ValueError("unknown platform fact field")
    missing = set(rule.required_fields) - set(facts)
    if missing:
        raise ValueError("missing platform fact field")
    normalized = {key: _normalize_field(kind, facts[key], key) for key, kind in kinds.items()}
    return MappingProxyType(normalized)


def fact_schema(check_id: str) -> dict[str, Any]:
    """Return a JSON-schema-subset description for one rule's flat facts."""
    kinds = _FIELD_KINDS.get(check_id) if isinstance(check_id, str) else None
    rule = _RULES.get(check_id) if isinstance(check_id, str) else None
    if kinds is None or rule is None:
        raise ValueError("unsupported platform check")
    properties: dict[str, dict[str, Any]] = {}
    for name, kind in kinds.items():
        if kind == "bool":
            properties[name] = {"type": "boolean"}
        elif kind == "id":
            properties[name] = {"type": "string", "maxLength": _MAX_TEXT}
        elif kind == "scope":
            properties[name] = {"type": "string", "enum": ("all", "restricted")}
        elif kind == "protocols":
            properties[name] = {"type": "array", "items": {"type": "string", "enum": tuple(sorted(_PROTOCOLS))},
                                "maxItems": _MAX_LIST}
        elif kind == "domain_deviations":
            properties[name] = {"type": "array", "items": {"type": "string", "enum": ("reversible_encryption", "operator_policy_deviation")},
                                "maxItems": _MAX_LIST}
        elif kind == "db_deviations":
            properties[name] = {"type": "array", "items": {"type": "string", "enum": tuple(sorted(_DB_DEVIATIONS))},
                                "maxItems": _MAX_LIST}
        elif kind == "ids":
            properties[name] = {"type": "array", "items": {"type": "string", "maxLength": _MAX_TEXT},
                                "maxItems": _MAX_LIST}
        elif kind == "relationship":
            properties[name] = {"type": "string", "enum": tuple(sorted(_RELATIONSHIPS))}
        elif kind == "principal":
            properties[name] = {"type": "string", "enum": tuple(sorted(_PRINCIPALS))}
        elif kind == "engine":
            properties[name] = {"type": "string", "enum": tuple(sorted(_ENGINES))}
        else:
            raise ValueError(f"unsupported field type for {name}")
    return {"type": "object", "properties": properties, "required": rule.required_fields}


def _decision(rule: PlatformRule, disposition: str, collection_state: str, provenance: str,
              prerequisites_verified: bool, source_trusted: bool, *limitations: str) -> PlatformDecision:
    if disposition not in _DISPOSITIONS:
        raise ValueError("invalid platform disposition")
    return PlatformDecision(rule.check_id, rule.track, disposition, collection_state, provenance,
                             prerequisites_verified, source_trusted,
                             tuple(sorted({item for item in limitations if item})), rule.references)


def evaluate(check_id: str, facts: Mapping[str, Any], *, collection_state: str,
             provenance: str, prerequisites_verified: bool, source_trusted: bool) -> PlatformDecision:
    """Evaluate a validated finite check without transport or runtime state."""
    rule = _RULES.get(check_id) if isinstance(check_id, str) else None
    if rule is None:
        raise ValueError("unsupported platform check")
    normalized = validate_facts(check_id, facts)
    if collection_state not in _COLLECTION_STATES:
        raise ValueError("invalid collection state")
    if provenance not in _PROVENANCES:
        raise ValueError("invalid platform provenance")
    if type(prerequisites_verified) is not bool or type(source_trusted) is not bool:
        raise ValueError("platform metadata booleans must be exact bool")
    if collection_state == "absent":
        return _decision(rule, "not_tested", collection_state, provenance, prerequisites_verified, source_trusted,
                         "no_collection_attempt")
    if collection_state == "unsupported":
        return _decision(rule, "unsupported", collection_state, provenance, prerequisites_verified, source_trusted,
                         "unsupported_collection")
    if collection_state == "access_denied":
        return _decision(rule, "blocked", collection_state, provenance, prerequisites_verified, source_trusted,
                         "access_denied")
    if collection_state == "incomplete" or not source_trusted:
        return _decision(rule, "incomplete", collection_state, provenance, prerequisites_verified, source_trusted,
                         "incomplete_capture" if collection_state == "incomplete" else "untrusted_source")
    if provenance == "unknown":
        return _decision(rule, "unknown", collection_state, provenance, prerequisites_verified, source_trusted,
                         "provenance_unverified")
    if not prerequisites_verified:
        return _decision(rule, "unknown", collection_state, provenance, prerequisites_verified, source_trusted,
                         "prerequisites_unverified")

    f = normalized
    if check_id == "network_tls_certificate_protocol_posture":
        if not f["policy_reviewed"]:
            return _decision(rule, "unknown", collection_state, provenance, prerequisites_verified, source_trusted,
                             "policy_baseline_unreviewed")
        deviation = not set(f["protocols"]).issubset(f["policy_protocols"])
        certificate_bad = not (f["certificate_valid"] and f["hostname_valid"] and f["chain_valid"])
        return _decision(rule, "candidate" if deviation or certificate_bad else "not_observed", collection_state,
                         provenance, prerequisites_verified, source_trusted,
                         "reviewed_policy_deviation" if deviation else "certificate_policy_deviation" if certificate_bad else "")
    if check_id == "linux_sudo_privilege_boundary":
        if not f["reviewed"]:
            return _decision(rule, "unknown", collection_state, provenance, prerequisites_verified, source_trusted,
                             "sudo_rule_unreviewed")
        vulnerable = (f["reviewed"] and f["low_privileged_principal"] and f["unrestricted_root"]
                      and f["nopasswd"] and f["command_scope"] == "all")
        return _decision(rule, "candidate" if vulnerable else "not_observed", collection_state, provenance,
                         prerequisites_verified, source_trusted,
                         "reviewed_unrestricted_nopasswd_root" if vulnerable else "")
    if check_id == "domain_account_policy":
        if not f["policy_reviewed"]:
            return _decision(rule, "unknown", collection_state, provenance, prerequisites_verified, source_trusted,
                             "policy_baseline_unreviewed")
        deviations = bool(f["deviation_ids"]) or f["reversible_encryption_enabled"]
        return _decision(rule, "candidate" if deviations else "not_observed", collection_state, provenance,
                         prerequisites_verified, source_trusted,
                         "explicit_policy_deviation" if deviations else "")
    if check_id == "delegation_relationships":
        exact = (f["relationship_present"] and f["enabled"] and f["trusted_to_authenticate"]
                 and bool(f["prerequisite_ids"]))
        return _decision(rule, "candidate" if exact else "not_observed", collection_state, provenance,
                         prerequisites_verified, source_trusted,
                         "exact_delegation_relationship" if exact else "")
    if check_id == "gpo_permissions":
        candidate = f["acl_complete"] and f["non_admin_effective_write"] and f["principal_class"] in _PRINCIPALS
        if not f["acl_complete"]:
            return _decision(rule, "unknown", collection_state, provenance, prerequisites_verified, source_trusted,
                             "acl_incomplete")
        return _decision(rule, "candidate" if candidate else "not_observed", collection_state, provenance,
                         prerequisites_verified, source_trusted,
                         "non_admin_effective_write" if candidate else "")
    if check_id == "adcs_configuration_relationships":
        candidate = (f["template_enabled"] and f["low_privilege_enrollment"] and f["subject_supply"]
                     and f["authentication_eku"] and not f["manager_approval"] and not f["authorized_signatures"])
        return _decision(rule, "candidate" if candidate else "not_observed", collection_state, provenance,
                         prerequisites_verified, source_trusted,
                         "esc1_prerequisite_set" if candidate else "")
    if check_id == "route_account_role_authorization":
        distinct = f["controlled_identity_a"] != f["controlled_identity_b"]
        candidate = (distinct and f["operator_designated_ownership"] and f["authorized_control_succeeded"]
                     and f["denied_expectation_violated"] and f["protected_record_match"])
        if not distinct:
            return _decision(rule, "unknown", collection_state, provenance, prerequisites_verified, source_trusted,
                             "controlled_identities_not_distinct")
        return _decision(rule, "candidate" if candidate else "not_observed", collection_state, provenance,
                         prerequisites_verified, source_trusted,
                         "protected_record_authorization_mismatch" if candidate else "")
    if check_id == "session_lifecycle":
        if f["cookie_only"] or not f["independent_observation"]:
            return _decision(rule, "unknown", collection_state, provenance, prerequisites_verified, source_trusted,
                             "cookie_only_or_independent_observation_missing")
        candidate = not (f["rotation_observed"] and f["logout_invalidation_observed"] and f["reuse_rejected"])
        return _decision(rule, "candidate" if candidate else "not_observed", collection_state, provenance,
                         prerequisites_verified, source_trusted,
                         "lifecycle_control_deviation" if candidate else "")
    if check_id == "database_versions_transport_roles_grants":
        if not f["policy_reviewed"]:
            return _decision(rule, "unknown", collection_state, provenance, prerequisites_verified, source_trusted,
                             "policy_baseline_unreviewed")
        candidate = (f["deviation_ids"] or (f["transport_required"] and not f["transport_encrypted"]))
        return _decision(rule, "candidate" if candidate else "not_observed", collection_state, provenance,
                         prerequisites_verified, source_trusted,
                         "reviewed_database_policy_deviation" if candidate else "")
    raise ValueError("unsupported platform check")


__all__ = ["CATALOG", "CATALOG_VERSION", "PLATFORM_RULES", "PlatformDecision", "PlatformRule",
           "RULE_CATALOG", "evaluate", "fact_schema", "validate_facts"]
