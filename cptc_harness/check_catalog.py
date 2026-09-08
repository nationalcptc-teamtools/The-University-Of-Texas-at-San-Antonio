"""Finite coverage expectations. These metadata never admit a collector.

The catalog describes capabilities to account for, including unavailable ones.
It contains no benchmark answers, target data, commands or execution plugins.
"""
from __future__ import annotations

from .detection import CATALOG

# Keep missing platform capabilities visible until each is implemented, reviewed
# and validated. A release must not infer support from a module's existence.
GAPS = (
    ("network", "tls_certificate_protocol_posture", "unsupported"),
    ("linux", "package_distribution_patch_applicability", "unsupported"),
    ("linux", "sudo_privilege_boundary", "unsupported"),
    ("windows_ad", "windows_build_patch_supersedence", "unsupported"),
    ("windows_ad", "domain_account_policy", "unsupported"),
    ("windows_ad", "delegation_relationships", "unsupported"),
    ("windows_ad", "gpo_permissions", "unsupported"),
    ("windows_ad", "adcs_configuration_relationships", "unsupported"),
    ("web", "route_account_role_authorization", "unsupported"),
    ("web", "session_lifecycle", "unsupported"),
    ("web", "application_specific_injection", "unsupported"),
    ("web", "application_specific_upload", "unsupported"),
    ("web", "business_logic", "unsupported"),
    ("database", "database_versions_transport_roles_grants", "unsupported"),
    ("ot", "fragile_systems_evidence_review", "manual_only"),
    ("exploitation", "zerologon", "manual_only"),
    ("exploitation", "password_spraying", "manual_only"),
    ("exploitation", "credential_dumping", "manual_only"),
    ("exploitation", "coercion_or_disruptive_tests", "manual_only"),
)


def capability_status() -> list[dict]:
    implemented = [{"track": rule["track"], "check_id": rule["rule_id"],
                    "implementation": "deterministic_predicate", "live_validation": "unverified"}
                   for rule in CATALOG]
    return implemented + [{"track": track, "check_id": check, "implementation": state,
                           "live_validation": "unverified"} for track, check, state in GAPS]


def expected_checks(policy, registry) -> list[dict]:
    """Conservative unauthenticated baseline for explicitly assigned targets.

    A frozen assessment can provide a more precise account-role matrix. Until
    then, inferred track applicability never claims that collection ran or that
    a target is clean. Credentialed coverage is not inferred from an open port.
    """
    rows = set()
    for entry in policy.targets:
        if entry.assigned_workspace != policy.workspace_id:
            continue
        tracks = {registry.get(module).track for module in entry.permitted_modules}
        for rule in CATALOG:
            applicable = rule["track"] in tracks
            if rule["rule_id"] in {"apache_httpd_path_traversal", "samba_shared_module_loading"}:
                applicable = applicable or "network" in tracks
            if not applicable:
                continue
            target = entry.target.canonical_url if rule["track"] == "web" else entry.target.host
            rows.add((target, rule["rule_id"], "unauthenticated"))
    return [{"target": target, "rule_id": rule, "role_id": role} for target, rule, role in sorted(rows)]
