"""Operator-only policy loading. MCP and model envelopes cannot mutate this state."""
from dataclasses import asdict, fields
from datetime import datetime
import ipaddress
import json
import re
from pathlib import Path
from urllib.parse import urlsplit
from .contracts import (Approval, BudgetLimit, PolicyError, PolicySnapshot, ScopeSpec,
                        TargetPolicy, TargetRef, digest)
from .storage import read_private, write_json

ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,95}\Z")


def identifier(value):
    if not isinstance(value, str) or not ID.fullmatch(value):
        raise PolicyError("invalid identifier")
    return value


def strict_object(cls, value):
    if not isinstance(value, dict) or set(value) - {f.name for f in fields(cls)}:
        raise PolicyError("unknown policy field")
    try:
        return cls(**value)
    except (TypeError, ValueError):
        raise PolicyError("missing or invalid policy field") from None


def _host_identity(host):
    if isinstance(host, str):
        try:
            return "ip", ipaddress.ip_address(host)
        except ValueError:
            pass
    return "dns", host


def _canonical_origin(scheme, host, port):
    kind, identity = _host_identity(host)
    if kind == "ip":
        rendered_host = identity.compressed
        if identity.version == 6:
            rendered_host = f"[{rendered_host}]"
    else:
        rendered_host = host
    return f"{scheme}://{rendered_host}:{port}"


def _canonical_ip_origin(value):
    try:
        url = urlsplit(value)
        port = url.port
    except (TypeError, ValueError):
        return None
    if (url.scheme not in ("http", "https") or url.username or url.password
            or url.path or url.query or url.fragment or not url.hostname or port is None):
        return None
    kind, address = _host_identity(url.hostname)
    if kind != "ip":
        return None
    if address.version == 6 and not url.netloc.startswith("["):
        return None
    return _canonical_origin(url.scheme, url.hostname, port)


def parse_target(value) -> TargetRef:
    target = strict_object(TargetRef, value)
    identifier(target.target_id)
    try:
        url = urlsplit(target.canonical_url)
        url_port = url.port
    except (TypeError, ValueError):
        raise PolicyError("target must be a canonical HTTP origin/base path") from None
    if url.scheme not in ("http", "https") or url.username or url.password or url.query or url.fragment:
        raise PolicyError("target must be a canonical HTTP origin/base path")
    if not url.hostname or not isinstance(target.port, int) or isinstance(target.port, bool) or not 1 <= target.port <= 65535:
        raise PolicyError("invalid target port/host")
    if any(ord(c) < 33 or ord(c) > 126 for c in target.canonical_url) or "\\" in target.canonical_url:
        raise PolicyError("invalid target URL characters")
    if (url.scheme, _host_identity(url.hostname), url_port or (443 if url.scheme == "https" else 80), url.path or "/") != (target.scheme, _host_identity(target.host), target.port, target.base_path):
        raise PolicyError("target identity does not match canonical URL")
    if not target.base_path.startswith("/") or ".." in target.base_path or "%" in target.base_path:
        raise PolicyError("invalid target base path")
    return target


def parse_policy(value) -> PolicySnapshot:
    if not isinstance(value, dict):
        raise PolicyError("policy must be an object")
    value = dict(value)
    scope = strict_object(ScopeSpec, value.get("scope"))
    for name in ("allowed_cidrs", "excluded_cidrs", "allowed_hosts"):
        entries = getattr(scope, name)
        if not isinstance(entries, (tuple, list)) or len(entries) > 4096 or any(not isinstance(x, str) for x in entries):
            raise PolicyError("invalid scope entries")
    try:
        for network in (*scope.allowed_cidrs, *scope.excluded_cidrs):
            ipaddress.ip_network(network, strict=True)
    except ValueError:
        raise PolicyError("invalid scope network") from None
    if type(scope.allow_http_login) is not bool:
        raise PolicyError("invalid HTTP login setting")
    value["scope"] = ScopeSpec(tuple(scope.allowed_cidrs), tuple(scope.excluded_cidrs), tuple(scope.allowed_hosts), scope.allow_http_login)
    targets = []
    for entry in value.get("targets", []):
        entry = dict(entry)
        entry["target"] = parse_target(entry.get("target"))
        entry["permitted_modules"] = tuple(entry.get("permitted_modules", ()))
        target = strict_object(TargetPolicy, entry)
        if type(target.eligible) is not bool or type(target.request_limit) is not int or not 0 <= target.request_limit <= 24:
            raise PolicyError("target allowance exceeds release limits")
        if type(target.auth_attempts) is not int or not 0 <= target.auth_attempts <= 2:
            raise PolicyError("authentication allowance exceeds release limit")
        if target.auth_attempts and not target.auth_method:
            raise PolicyError("authentication method is required")
        targets.append(target)
    if len({t.target.target_id for t in targets}) != len(targets):
        raise PolicyError("duplicate target identifier")
    target_identities = {
        (
            t.target.scheme,
            _host_identity(t.target.host),
            t.target.port,
            t.target.base_path,
        )
        if _host_identity(t.target.host)[0] == "ip"
        else t.target.canonical_url
        for t in targets
    }
    if len(target_identities) != len(targets):
        raise PolicyError("duplicate target origin")
    value["targets"] = tuple(targets)
    value["approvals"] = tuple(strict_object(Approval, a) for a in value.get("approvals", []))
    limits = value.get("budget_limits", ())
    if not isinstance(limits, (list, tuple)) or len(limits) > 256:
        raise PolicyError("invalid policy budget limits")
    limits = tuple(strict_object(BudgetLimit, limit) for limit in limits)
    if len({(limit.scope, limit.key, limit.counter) for limit in limits}) != len(limits):
        raise PolicyError("duplicate policy budget limit")
    value["budget_limits"] = limits
    if "exclusions" in value:
        value["exclusions"] = tuple(value["exclusions"])
    policy = strict_object(PolicySnapshot, value)
    for name in ("engagement_id", "revision", "workspace_id", "device_id", "operator_id"):
        identifier(getattr(policy, name))
    target_aliases = {}
    for target_policy in policy.targets:
        target = target_policy.target
        origin = _canonical_origin(target.scheme, target.host, target.port)
        for alias in (target.target_id, origin):
            target_aliases.setdefault(alias, set()).add(target.target_id)
    allowed_budget_keys = {
        "engagement": {policy.engagement_id}, "device": {policy.device_id}, "workspace": {policy.workspace_id},
        "realm": {t.auth_realm for t in policy.targets if t.auth_realm},
    }
    target_limits = set()
    for limit in policy.budget_limits:
        if limit.scope == "workflow":
            identifier(limit.key)
        elif limit.scope == "target":
            matching_targets = target_aliases.get(limit.key)
            if matching_targets is None:
                canonical_ip_origin = _canonical_ip_origin(limit.key)
                matching_targets = target_aliases.get(canonical_ip_origin, ())
            if len(matching_targets) != 1:
                raise PolicyError("budget scope key does not match policy")
            logical_limit = (next(iter(matching_targets)), limit.counter)
            if logical_limit in target_limits:
                raise PolicyError("duplicate policy target budget limit")
            target_limits.add(logical_limit)
        elif limit.key not in allowed_budget_keys[limit.scope]:
            raise PolicyError("budget scope key does not match policy")
    if policy.contract_version != 1:
        raise PolicyError("unsupported policy contract version")
    for name, ceiling in (("model_calls", 6), ("model_actions", 12), ("format_repairs", 1), ("excerpt_bytes", 2048), ("decision_bytes", 8192)):
        number = getattr(policy, name)
        if type(number) is not int or not 0 <= number <= ceiling:
            raise PolicyError("policy exceeds release ceiling")
    if type(policy.http_rate) not in (int, float) or not 0 < policy.http_rate <= 1:
        raise PolicyError("HTTP rate exceeds release ceiling")
    if type(policy.encrypted_storage) is not bool:
        raise PolicyError("invalid storage attestation")
    times = []
    for timestamp in (policy.window_start, policy.window_end):
        if timestamp:
            try:
                instant = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
                if instant.tzinfo is None:
                    raise ValueError()
                times.append(instant)
            except ValueError:
                raise PolicyError("operating window requires explicit UTC offset") from None
    if len(times) == 2 and times[0] >= times[1]:
        raise PolicyError("invalid operating window")
    return policy


def load_policy(path: Path) -> PolicySnapshot:
    try:
        return parse_policy(json.loads(read_private(path)))
    except (ValueError, TypeError, KeyError):
        raise PolicyError("invalid policy document") from None


def save_policy(path: Path, policy: PolicySnapshot):
    # Revalidate even operator-created dataclasses; no permissive deserialization.
    parse_policy(asdict(policy))
    write_json(path, policy_document(policy))


def policy_hash(policy: PolicySnapshot) -> str:
    return digest(policy_document(policy))


def policy_document(policy: PolicySnapshot) -> dict:
    """Preserve the v1 policy document/hash when additive limits are absent."""
    value = asdict(policy)
    if not policy.budget_limits:
        value.pop("budget_limits")
    return value
