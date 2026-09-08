"""Static release registry for guarded CPTC observations.

There is intentionally no registration hook.  Adding a capability requires a
reviewed source change and a new release profile.
"""
from __future__ import annotations

from typing import Any
from types import MappingProxyType
import hashlib
from pathlib import Path

from .collectors import (Collector, ManualOnlyCollector, ToolCollector,
                         UnsupportedScannerCollector, WebCollector)
from .contracts import (ExecutionContext, ModuleSpec, OperationResult,
                        Bounds, PolicyError, validate_schema)
from .parsers import (parse_linux_output, parse_network_output, parse_nmap_xml,
                      parse_windows_ad_output)
from .collectors.imports import (exploit_import, linux_import, network_import,
                                 nmap_import, reporting_import, web_import,
                                 windows_import)
from .passive import PassiveCollector
from .nmap_bridge import NmapCollector


class _FrozenDict(dict):
    """JSON-compatible immutable mapping for the static release registry."""
    def _deny(self, *args: Any, **kwargs: Any) -> None:
        raise TypeError("release registry mappings are immutable")
    __setitem__ = __delitem__ = __ior__ = clear = pop = popitem = setdefault = update = _deny


def _freeze(value: Any) -> Any:
    if isinstance(value, dict):
        return _FrozenDict({key: _freeze(item) for key, item in value.items()})
    if isinstance(value, list):
        return tuple(_freeze(item) for item in value)
    return value


def _schema(properties: dict[str, Any] | None = None) -> dict[str, Any]:
    return _freeze({"type": "object", "properties": properties or {}, "required": ()})


def _batch_schema(facts: dict[str, Any], *, source: bool = True) -> dict[str, Any]:
    observation_props = {"track": {"type": "string", "maxLength": 64},
                         "target": {"type": "string", "maxLength": 256},
                         "check_id": {"type": "string", "maxLength": 128},
                         "state": {"type": "string", "maxLength": 32},
                         "facts": facts}
    required = ("track", "target", "check_id", "state", "facts")
    if source:
        observation_props["source_sha256"] = {"type": "string", "maxLength": 64}
        required = required + ("source_sha256",)
    item = {"type": "object", "properties": observation_props, "required": required}
    return _schema({"observations": {"type": "array", "items": item, "maxItems": 2048},
                    "issues": {"type": "array", "items": {"type": "string", "maxLength": 64}},
                    "duplicates": {"type": "integer", "minimum": 0}})


_STRING_ARRAY = {"type": "array", "items": {"type": "string", "maxLength": 256}, "maxItems": 256}
_PORT = {"type": "object", "properties": {
    "port": {"type": "integer", "minimum": 1, "maximum": 65535},
    "state": {"type": "string", "maxLength": 32}, "protocol": {"type": "string", "maxLength": 64},
    "name": {"type": "string", "maxLength": 64},
    "service": {"type": "string", "maxLength": 64}, "product": {"type": "string", "maxLength": 64},
    "version": {"type": "string", "maxLength": 64}, "tunnel": {"type": "string", "maxLength": 64}},
    "required": ("port", "state")}
_NETWORK_FACTS = _schema({"addresses": _STRING_ARRAY, "hostnames": _STRING_ARRAY,
                          "ports": {"type": "array", "items": _PORT, "maxItems": 256},
                          "port": {"type": "integer", "minimum": 1, "maximum": 65535},
                          "state": {"type": "string", "maxLength": 32}, "protocol": {"type": "string", "maxLength": 64},
                          "service": {"type": "string", "maxLength": 64}, "product": {"type": "string", "maxLength": 64},
                          "version": {"type": "string", "maxLength": 64}})
_WEB_HEADER_FACTS = _schema({"status": {"type": "integer", "minimum": 100, "maximum": 599},
                             "headers_present": _STRING_ARRAY, "headers_missing": _STRING_ARRAY,
                             "redirect": {"type": "boolean"}, "truncated": {"type": "boolean"},
                             "path_depth": {"type": "integer", "minimum": 0, "maximum": 128}})
_WEB_SESSION_FACTS = _schema({"status": {"type": "integer", "minimum": 100, "maximum": 599},
                              "cookie_header_present": {"type": "boolean"}, "session_ref_present": {"type": "boolean"},
                              "truncated": {"type": "boolean"}})
_WEB_CAPTURE_FACTS = _schema({**dict(_WEB_HEADER_FACTS["properties"]),
                              "cookie_header_present": {"type": "boolean"}, "session_ref_present": {"type": "boolean"}})
_PASSIVE_FACTS = _schema({"scanner": {"type": "string", "enum": ("nuclei", "zap")},
                         "rule_id": {"type": "string", "maxLength": 64},
                         "severity": {"type": "string", "enum": ("info", "low", "medium", "high", "critical")},
                         "confidence": {"type": "integer", "minimum": 0, "maximum": 4},
                         "matches": {"type": "integer", "minimum": 0, "maximum": 16}})
_HOST_FACTS = _schema({
    "field": {"type": "string", "maxLength": 64}, "present": {"type": "boolean"},
    "value_length": {"type": "integer", "minimum": 0, "maximum": 128},
    "value_is_true": {"type": "boolean"}, "value_is_nonzero": {"type": "boolean"},
    "uid": {"type": "integer", "minimum": 0, "maximum": 2147483647},
    "euid": {"type": "integer", "minimum": 0, "maximum": 2147483647},
    "gid": {"type": "integer", "minimum": 0, "maximum": 2147483647},
    "groups": {"type": "array", "items": {"type": "integer", "minimum": 0, "maximum": 2147483647}, "maxItems": 64},
    "path": {"type": "string", "maxLength": 256}, "mode": {"type": "string", "maxLength": 4},
    "owner": {"type": "string", "maxLength": 128}, "world_writable": {"type": "boolean"},
    "expected_binary": {"type": "boolean"},
    "name": {"type": "string", "maxLength": 128}, "state": {"type": "string", "maxLength": 16},
    "writable": {"type": "boolean"}, "capabilities": {"type": "array", "items": {"type": "string", "maxLength": 64}, "maxItems": 32},
    "risky_capability": {"type": "boolean"}, "reviewed": {"type": "boolean"},
    "sudo_access_observed": {"type": "boolean"}, "evidence_ref": {"type": "string", "maxLength": 128},
    "sid": {"type": "string", "maxLength": 128}, "domain_sid": {"type": "string", "maxLength": 128},
    "domain_name": {"type": "string", "maxLength": 128}, "owner_sid": {"type": "string", "maxLength": 128},
    "non_admin_write": {"type": "boolean"}, "inherited": {"type": "boolean"},
    "ace_count": {"type": "integer", "minimum": 0, "maximum": 256},
    "signing_required": {"type": "boolean"}, "channel_binding_required": {"type": "boolean"},
    "accessible": {"type": "boolean"}, "verified": {"type": "boolean"},
})
_EXPLOIT_FACTS = _schema({"human_result": {"type": "string", "maxLength": 32},
                          "evidence_attached": {"type": "boolean"}, "evidence_ref_present": {"type": "boolean"}})
_REPORT_FACTS = _schema({"finding_id": {"type": "string", "maxLength": 64}, "severity": {"type": "string", "maxLength": 16},
                         "evidence_state": {"type": "string", "maxLength": 24}, "retest_state": {"type": "string", "maxLength": 24},
                         "coverage_state": {"type": "string", "maxLength": 24}, "duplicate": {"type": "boolean"},
                         "reviewed": {"type": "boolean"}, "evidence_ref": {"type": "string", "maxLength": 128}})


_CODE_ROOT = Path(__file__).parent
_CODE_HASH = hashlib.sha256(b"".join(str(path.relative_to(_CODE_ROOT)).encode() + b"\0" + path.read_bytes()
                                   for path in sorted(_CODE_ROOT.rglob("*.py")))).hexdigest()


def _spec(module_id: str, track: str, mode: str, description: str, *, tool_id: str | None = None,
          effects: tuple[str, ...] = (), output_schema: dict[str, Any] | None = None) -> ModuleSpec:
    profile_hash = hashlib.sha256((module_id + "|1.0.0|" + track + "|" + mode + "|" + description + "|" + (tool_id or "") + "|" + _CODE_HASH).encode()).hexdigest()
    return ModuleSpec(module_id=module_id, version="1.0.0", track=track, mode=mode, effects=effects,
                      bounds=Bounds(
                          timeout_s=30.0, request_limit=1 if mode == "bounded" else 0,
                          output_bytes=131072, process_limit=1),
                      input_schema=_schema(), output_schema=_freeze(output_schema or _batch_schema(_NETWORK_FACTS)),
                      tool_id=tool_id, source_hash=profile_hash,
                      description=description)


# IDs are the only accepted capability identifiers.  Keep this tuple in source
# order for deterministic preambles and audit output.
_SPECS = (
    _spec("network.nmap_import", "network", "offline", "Import Nmap XML service inventory.", output_schema=_batch_schema(_NETWORK_FACTS)),
    _spec("network.output_import", "network", "offline", "Import a reviewed network inventory.", output_schema=_batch_schema(_NETWORK_FACTS)),
    _spec("network.nmap_inventory", "network", "bounded", "Observe one approved IPv4 TCP port with pinned Nmap and a parent-only connect broker.",
          tool_id="nmap-cptc-inventory-v1", effects=("network_observation",)),
    _spec("web.capture_import", "web", "offline", "Import a reviewed web response capture.", output_schema=_batch_schema(_WEB_CAPTURE_FACTS)),
    _spec("web.nuclei_observation", "web", "offline", "Analyze one human-selected response with networkless pinned Nuclei.",
          tool_id="nuclei", output_schema=_batch_schema(_PASSIVE_FACTS)),
    _spec("web.zap_observation", "web", "offline", "Analyze one human-selected response with networkless pinned ZAP passive rules.",
          tool_id="zap", output_schema=_batch_schema(_PASSIVE_FACTS)),
    _spec("web.headers", "web", "bounded", "Read response metadata and browser security header presence.",
          effects=("http_request", "human_only_capture"), output_schema=_batch_schema(_WEB_HEADER_FACTS, source=False)),
    _spec("web.session", "web", "bounded", "Record session-cookie metadata for human review.",
          effects=("http_request", "human_only_capture"), output_schema=_batch_schema(_WEB_SESSION_FACTS, source=False)),
    _spec("web.nuclei", "web", "bounded", "Pinned Nuclei profile; unsupported without reviewed containment.",
          tool_id="nuclei-cptc-reviewed-v1", effects=("network_observation",)),
    _spec("web.zap", "web", "bounded", "Pinned ZAP workflow; unsupported without reviewed containment.",
          tool_id="zap-cptc-reviewed-v1", effects=("network_observation",)),
    _spec("linux.output_import", "linux", "offline", "Import structured Linux identity and privilege observations.", output_schema=_batch_schema(_HOST_FACTS)),
    _spec("linux.inventory", "linux", "bounded", "Run the pinned Linux inventory profile.",
          tool_id="linux-cptc-inventory-v1", effects=("host_observation",)),
    _spec("windows_ad.output_import", "windows_ad", "offline", "Import structured Windows and AD observations.", output_schema=_batch_schema(_HOST_FACTS)),
    _spec("windows_ad.inventory", "windows_ad", "bounded", "Run the pinned Windows/AD inventory profile.",
          tool_id="windows-ad-cptc-inventory-v1", effects=("host_observation",)),
    _spec("exploitation.result_intake", "exploitation", "offline", "Import a reviewed human-only result card.", output_schema=_batch_schema(_EXPLOIT_FACTS)),
    _spec("exploitation.zerologon", "exploitation", "manual_only", "Zerologon validation requires a human operator."),
    _spec("exploitation.dos", "exploitation", "manual_only", "DoS or crash testing is manual-only."),
    _spec("exploitation.spraying", "exploitation", "manual_only", "Password spraying is manual-only."),
    _spec("exploitation.domain_change", "exploitation", "manual_only", "Domain changes are manual-only."),
    _spec("reporting.records", "reporting", "offline", "Import typed finding, coverage, deduplication, and retest records.", output_schema=_batch_schema(_REPORT_FACTS)),
)
_SPECS = tuple(_SPECS)

_HANDLERS: dict[str, Collector] = {
    "network.nmap_import": nmap_import(),
    "network.output_import": network_import(),
    "network.nmap_inventory": NmapCollector(),
    "web.capture_import": web_import(),
    "web.nuclei_observation": PassiveCollector("nuclei"),
    "web.zap_observation": PassiveCollector("zap"),
    "web.headers": WebCollector("web_headers"),
    "web.session": WebCollector("web_session"),
    "web.nuclei": UnsupportedScannerCollector("Nuclei"),
    "web.zap": UnsupportedScannerCollector("ZAP"),
    "linux.output_import": linux_import(),
    "linux.inventory": ToolCollector(tool_id="linux-cptc-inventory-v1", parser=parse_linux_output, scoped=True),
    "windows_ad.output_import": windows_import(),
    "windows_ad.inventory": ToolCollector(tool_id="windows-ad-cptc-inventory-v1", parser=parse_windows_ad_output, scoped=True),
    "exploitation.result_intake": exploit_import(),
    "exploitation.zerologon": ManualOnlyCollector("Zerologon"),
    "exploitation.dos": ManualOnlyCollector("DoS or crash testing"),
    "exploitation.spraying": ManualOnlyCollector("password spraying"),
    "exploitation.domain_change": ManualOnlyCollector("domain changes"),
    "reporting.records": reporting_import(),
}
_HANDLERS = MappingProxyType(_HANDLERS)
_SPEC_BY_ID = MappingProxyType({item.module_id: item for item in _SPECS})


def _validate_result(result: OperationResult) -> None:
    facts = result.facts
    if not isinstance(facts, dict) or set(facts) - {"observations", "issues", "duplicates", "tool_completed", "bytes"}:
        raise PolicyError("collector returned untyped facts")
    observations = facts.get("observations", [])
    if not isinstance(observations, list) or len(observations) > 2048:
        raise PolicyError("collector returned invalid observations")
    allowed_fact_keys = {
        "addresses", "ports", "hostnames", "port", "state", "protocol", "service", "product", "version",
        "status", "headers_present", "headers_missing", "redirect", "path_depth", "truncated",
        "cookie_header_present", "session_ref_present", "field", "present", "value", "value_length",
        "value_is_true", "value_is_nonzero",
        "uid", "euid", "gid", "groups", "path", "mode", "owner", "world_writable", "expected_binary", "name", "writable",
        "capabilities", "risky_capability", "reviewed", "sudo_access_observed", "evidence_ref", "sid", "domain_sid",
        "domain_name", "owner_sid", "non_admin_write", "inherited", "ace_count", "signing_required",
        "channel_binding_required", "accessible", "verified",
        "human_result", "evidence_attached", "evidence_ref_present", "finding_id", "severity",
        "evidence_state", "retest_state", "coverage_state", "duplicate", "reviewed", "evidence_ref",
        "scanner", "rule_id", "confidence", "matches",
    }
    for item in observations:
        if not isinstance(item, dict) or set(item) - {"track", "target", "check_id", "state", "facts", "source_sha256"}:
            raise PolicyError("collector returned an untyped observation")
        if not all(isinstance(item.get(key), str) and len(item[key]) <= 256
                   for key in ("track", "target", "check_id", "state")):
            raise PolicyError("collector returned invalid observation identity")
        if not isinstance(item.get("facts", {}), dict) or set(item["facts"]) - allowed_fact_keys:
            raise PolicyError("collector returned untyped observation facts")
        _typed(item["facts"])
        if "source_sha256" in item and (not isinstance(item["source_sha256"], str) or len(item["source_sha256"]) != 64):
            raise PolicyError("collector returned invalid source identity")
    for key in ("issues",):
        if key in facts and (not isinstance(facts[key], list) or not all(isinstance(x, str) for x in facts[key])):
            raise PolicyError("collector returned invalid issue list")
    for key in ("duplicates", "bytes"):
        if key in facts and (isinstance(facts[key], bool) or not isinstance(facts[key], int) or facts[key] < 0):
            raise PolicyError("collector returned invalid count")
    if "tool_completed" in facts and not isinstance(facts["tool_completed"], bool):
        raise PolicyError("collector returned invalid completion flag")


def _typed(value: Any, depth: int = 0) -> None:
    if depth > 4 or isinstance(value, (bytes, bytearray)):
        raise PolicyError("collector returned unsupported fact value")
    if isinstance(value, dict):
        if len(value) > 64:
            raise PolicyError("collector returned too many fact fields")
        for key, item in value.items():
            if not isinstance(key, str) or len(key) > 64:
                raise PolicyError("collector returned invalid fact key")
            _typed(item, depth + 1)
    elif isinstance(value, (list, tuple)):
        if len(value) > 512:
            raise PolicyError("collector returned too many fact items")
        for item in value:
            _typed(item, depth + 1)
    elif not (value is None or isinstance(value, (str, int, float, bool))):
        raise PolicyError("collector returned unsupported fact value")


class TrustedToolRegistry:
    def specs(self) -> tuple[ModuleSpec, ...]:
        return _SPECS

    def get(self, module_id: str) -> ModuleSpec:
        try:
            return _SPEC_BY_ID[module_id]
        except (KeyError, TypeError):
            raise PolicyError("unknown module") from None

    def handler(self, module_id: str) -> Collector:
        self.get(module_id)
        return _HANDLERS[module_id]

    def dispatch(self, context: ExecutionContext) -> OperationResult:
        try:
            spec = self.get(context.request.module_id)
        except PolicyError as exc:
            return OperationResult(status="blocked", reason=str(exc))
        if context.spec.module_id != spec.module_id:
            return OperationResult(status="blocked", reason="execution context module mismatch")
        if context.request.workspace_id != context.policy.workspace_id or context.request.policy_revision != context.policy.revision:
            return OperationResult(status="blocked", reason="policy revision or workspace mismatch")
        try:
            validate_schema(context.request.args, spec.input_schema)
        except PolicyError as exc:
            return OperationResult(status="blocked", reason=str(exc))
        if spec.mode == "manual_only":
            return OperationResult(status="blocked", reason="module is manual-only")
        if spec.mode == "offline" and context.request.target is not None:
            return OperationResult(status="blocked", reason="offline module cannot receive a target")
        target = context.request.target
        if spec.mode == "bounded":
            if target is None:
                return OperationResult(status="blocked", reason="bounded module requires a target")
            target_policy = next((item for item in context.policy.targets if item.target.target_id == target.target_id), None)
            if target_policy is None or not target_policy.eligible or context.policy.workspace_id != target_policy.assigned_workspace:
                return OperationResult(status="blocked", reason="target is not eligible for this workspace")
            if spec.module_id not in target_policy.permitted_modules:
                return OperationResult(status="blocked", reason="module is not permitted for this target")
        if context.stopped():
            return OperationResult(status="stopped", reason="operator stop requested")
        try:
            result = self.handler(spec.module_id).collect(context)
            _validate_result(result)
            return result
        except PolicyError as exc:
            return OperationResult(status="failed", reason=str(exc))
        except Exception:
            return OperationResult(status="failed", reason="collector failed safely")


def build_registry() -> TrustedToolRegistry:
    return TrustedToolRegistry()


__all__ = ["TrustedToolRegistry", "build_registry"]
