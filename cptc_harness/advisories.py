"""Offline, exact advisory matching for typed component identities.

The matcher consumes a reviewed normalized catalog.  It has no network,
subprocess, filesystem, or natural-language advisory interpretation path.
Version matches are candidates only and do not confirm a vulnerability.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import hashlib
import json
import re
from types import MappingProxyType
from typing import Any, Iterable, Mapping
from urllib.parse import urlsplit

from .assessment_contracts import ComponentIdentity


SCHEMA = "cptc.advisories.v1"
MAX_RECORDS = 4096
MAX_TEXT = 512
MAX_CATALOG_BYTES = 16 * 1024 * 1024
_HASH = re.compile(r"^[0-9a-f]{64}$")
_CVE = re.compile(r"^CVE-[0-9]{4}-[0-9]{4,19}$")
_KB = re.compile(r"^KB[0-9]{6,8}$", re.IGNORECASE)
_UTC = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z$")
_SEMVER = re.compile(r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$")
_WINDOWS = re.compile(r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")

_TOP_KEYS = frozenset({"schema", "release_sha256", "records"})
_RECORD_KEYS = frozenset({
    "advisory_id", "cve_ids", "state", "publisher", "source_url",
    "source_sha256", "acquired_at", "ecosystem", "product", "distribution",
    "comparator", "introduced", "fixed", "last_affected",
    "required_patch_ids", "superseding_patch_ids",
})
_COMPARATORS = frozenset({"debian", "rpm", "semver", "windows_build"})


def _text(value: Any, *, empty: bool = False, limit: int = MAX_TEXT) -> str:
    if not isinstance(value, str) or len(value) > limit or (not value and not empty):
        raise ValueError("invalid advisory text")
    if any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise ValueError("invalid advisory text")
    return value


def _hash(value: Any, *, name: str = "hash") -> str:
    if not isinstance(value, str) or not _HASH.fullmatch(value):
        raise ValueError(f"invalid advisory {name}")
    return value


def _ids(value: Any, *, patch: bool = False) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple)) or len(value) > MAX_RECORDS:
        raise ValueError("invalid advisory identifiers")
    result = tuple(_text(item, limit=128) for item in value)
    if len(set(result)) != len(result):
        raise ValueError("duplicate advisory identifiers")
    pattern = _KB if patch else _CVE
    if any(not pattern.fullmatch(item) for item in result):
        raise ValueError("malformed CVE or KB identifier")
    return tuple(item.upper() for item in result) if patch else result


def _canonical_json(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _parse_raw(raw: Any) -> tuple[Mapping[str, Any], bytes]:
    if isinstance(raw, bytes):
        payload = bytes(raw)
        if len(payload) > MAX_CATALOG_BYTES: raise ValueError("advisory catalog exceeds allowance")
        try:
            root = json.loads(payload.decode("utf-8"), object_pairs_hook=_reject_duplicate_pairs)
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
            raise ValueError("invalid advisory JSON") from None
    elif isinstance(raw, str):
        payload = raw.encode()
        if len(payload) > MAX_CATALOG_BYTES: raise ValueError("advisory catalog exceeds allowance")
        try:
            root = json.loads(raw, object_pairs_hook=_reject_duplicate_pairs)
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
            raise ValueError("invalid advisory JSON") from None
    elif isinstance(raw, Mapping):
        root = dict(raw)
        payload = _canonical_json(root)
        if len(payload) > MAX_CATALOG_BYTES: raise ValueError("advisory catalog exceeds allowance")
    else:
        raise TypeError("catalog must be JSON bytes, text, or mapping")
    if not isinstance(root, Mapping):
        raise ValueError("advisory catalog must be an object")
    return root, payload


def _alias(value: str, aliases: Mapping[str, str], *, name: str, empty: bool = False) -> str:
    normalized = value.strip().lower()
    if not normalized and empty:
        return ""
    if normalized not in aliases:
        raise ValueError(f"unsupported advisory {name}")
    return aliases[normalized]


_ECOSYSTEM_ALIASES = MappingProxyType({
    "debian": "debian", "deb": "debian", "ubuntu": "debian",
    "rpm": "rpm", "redhat": "rpm", "rhel": "rpm", "fedora": "rpm",
    "semver": "semver", "generic_semver": "semver",
    "windows": "windows", "windows_build": "windows",
})
_PRODUCT_ALIASES = MappingProxyType({
    "apache_http_server": "apache_http_server",
    "apache http server": "apache_http_server", "apache httpd": "apache_http_server",
    "httpd": "apache_http_server", "apache2": "apache_http_server",
    "samba": "samba", "samba server": "samba",
    "windows server 2016": "windows_server_2016", "windows_server_2016": "windows_server_2016",
    "windows server 2019": "windows_server_2019", "windows_server_2019": "windows_server_2019",
    "windows server 2022": "windows_server_2022", "windows_server_2022": "windows_server_2022",
    "windows server 2025": "windows_server_2025", "windows_server_2025": "windows_server_2025",
    "windows 10": "windows_10", "windows_10": "windows_10",
})
# Finite edition/build families from Microsoft's release-information tables.
# Client and Server products sharing a build remain distinct products. Other
# products/builds stay unsupported until reviewed; no nearest-build inference.
_WINDOWS_FAMILIES = MappingProxyType({
    "windows_server_2016": frozenset({14393}), "windows_server_2019": frozenset({17763}),
    "windows_server_2022": frozenset({20348}), "windows_server_2025": frozenset({26100}),
    "windows_10": frozenset({10240, 10586, 14393, 15063, 16299, 17134, 17763,
                             18362, 18363, 19041, 19042, 19043, 19044, 19045}),
})
_DIST_ALIASES = MappingProxyType({
    "": "", "debian": "debian", "ubuntu": "ubuntu", "linux mint": "linux_mint",
    "rhel": "rhel", "redhat": "rhel", "red hat enterprise linux": "rhel", "centos": "centos",
    "fedora": "fedora", "rocky": "rocky", "almalinux": "almalinux",
    "windows": "windows", "windows server": "windows",
})


@dataclass(frozen=True)
class AdvisoryRecord:
    advisory_id: str
    cve_ids: tuple[str, ...]
    state: str
    publisher: str
    source_url: str
    source_sha256: str
    acquired_at: str
    ecosystem: str
    product: str
    distribution: str
    comparator: str
    introduced: str = ""
    fixed: str = ""
    last_affected: str = ""
    required_patch_ids: tuple[str, ...] = ()
    superseding_patch_ids: tuple[str, ...] = ()


@dataclass(frozen=True)
class AdvisoryCatalog:
    schema: str
    release_sha256: str
    records: tuple[AdvisoryRecord, ...]
    catalog_sha256: str

    @property
    def publisher_authenticated(self) -> bool:
        """Always false: a local catalog hash does not authenticate a publisher."""
        return False


@dataclass(frozen=True)
class AdvisoryMatch:
    advisory_id: str
    component_id: str
    state: str
    cve_ids: tuple[str, ...]
    source_sha256: str
    source_url: str
    comparator: str
    limitations: tuple[str, ...] = ()

    def __getitem__(self, key: str) -> Any:
        return getattr(self, key)


def _record(value: Any) -> AdvisoryRecord:
    if not isinstance(value, Mapping) or set(value) != _RECORD_KEYS:
        raise ValueError("invalid advisory record fields")
    advisory_id = _text(value["advisory_id"], limit=128)
    cve_ids = _ids(value["cve_ids"])
    state = _text(value["state"], limit=32)
    if state not in {"active", "withdrawn"}:
        raise ValueError("invalid advisory state")
    publisher = _text(value["publisher"])
    source_url = _text(value["source_url"], limit=2048)
    parsed_url = urlsplit(source_url)
    if parsed_url.scheme != "https" or not parsed_url.netloc or parsed_url.username or parsed_url.password:
        raise ValueError("advisory source must be HTTPS")
    source_sha256 = _hash(value["source_sha256"], name="source checksum")
    acquired_at = _text(value["acquired_at"], limit=64)
    if not _UTC.fullmatch(acquired_at):
        raise ValueError("advisory acquisition time must be UTC")
    try:
        datetime.fromisoformat(acquired_at[:-1] + "+00:00")
    except ValueError:
        raise ValueError("invalid advisory acquisition time") from None
    ecosystem = _alias(_text(value["ecosystem"], limit=64), _ECOSYSTEM_ALIASES, name="ecosystem")
    product = _alias(_text(value["product"], limit=128), _PRODUCT_ALIASES, name="product")
    distribution = _alias(_text(value["distribution"], empty=True, limit=64), _DIST_ALIASES,
                           name="distribution", empty=True)
    comparator = _text(value["comparator"], limit=32)
    if comparator not in _COMPARATORS:
        raise ValueError("invalid advisory comparator")
    if comparator != {"debian": "debian", "rpm": "rpm", "semver": "semver", "windows": "windows_build"}[ecosystem]:
        raise ValueError("advisory comparator does not match ecosystem")
    if ecosystem == "windows" and (product not in _WINDOWS_FAMILIES or publisher != "Microsoft"
            or parsed_url.hostname not in {"msrc.microsoft.com", "api.msrc.microsoft.com", "support.microsoft.com", "learn.microsoft.com"}):
        raise ValueError("Windows advisory needs a reviewed Microsoft product and source")
    bounds = tuple(_text(value[key], empty=True, limit=128)
                   for key in ("introduced", "fixed", "last_affected"))
    if not any(bounds):
        raise ValueError("advisory needs a version bound")
    if any(bound and _parse_version(bound, comparator) is None for bound in bounds):
        raise ValueError("invalid advisory version bound")
    if ecosystem == "windows":
        families = {_parse_version(bound, comparator)[:3] for bound in bounds if bound}
        if len(families) != 1 or any(family[:2] != (10, 0) or family[2] not in _WINDOWS_FAMILIES[product] for family in families):
            raise ValueError("Windows advisory bounds cross or mismatch build families")
    required = _ids(value["required_patch_ids"], patch=True)
    superseding = _ids(value["superseding_patch_ids"], patch=True)
    if set(required) & set(superseding):
        raise ValueError("duplicate required and superseding patch")
    if (required or superseding) and ecosystem != "windows":
        raise ValueError("KB patch evidence is Windows-specific")
    return AdvisoryRecord(advisory_id, cve_ids, state, publisher, source_url,
                          source_sha256, acquired_at, ecosystem, product, distribution,
                          comparator, bounds[0], bounds[1], bounds[2], required, superseding)


def load_catalog(raw: Any, *, expected_sha256: str, release_sha256: str) -> AdvisoryCatalog:
    """Validate and freeze a normalized advisory catalog."""
    expected_sha256 = _hash(expected_sha256, name="expected checksum")
    release_sha256 = _hash(release_sha256, name="release checksum")
    root, payload = _parse_raw(raw)
    if hashlib.sha256(payload).hexdigest() != expected_sha256:
        raise ValueError("advisory catalog checksum mismatch")
    if set(root) != _TOP_KEYS or root.get("schema") != SCHEMA:
        raise ValueError("unsupported advisory catalog schema")
    if root.get("release_sha256") != release_sha256:
        raise ValueError("advisory release checksum mismatch")
    records = root.get("records")
    if not isinstance(records, list) or len(records) > MAX_RECORDS:
        raise ValueError("invalid advisory catalog records")
    parsed = tuple(_record(item) for item in records)
    return AdvisoryCatalog(SCHEMA, release_sha256, parsed, hashlib.sha256(payload).hexdigest())


def _parse_version(value: Any, comparator: str) -> Any:
    if not isinstance(value, str) or not value:
        return None
    if comparator == "semver":
        match = _SEMVER.fullmatch(value)
        if not match:
            return None
        prerelease = tuple(match.group(4).split(".")) if match.group(4) else ()
        if any(part.isdigit() and len(part) > 1 and part.startswith("0") for part in prerelease):
            return None
        return (int(match.group(1)), int(match.group(2)), int(match.group(3)), prerelease)
    if comparator == "windows_build":
        match = _WINDOWS.fullmatch(value)
        return tuple(int(match.group(index)) for index in range(1, 5)) if match else None
    if comparator == "debian":
        return _debian_parts(value)
    if comparator == "rpm":
        return _rpm_parts(value)
    return None


def _debian_parts(value: str) -> tuple[int, str, str] | None:
    if any(char.isspace() or ord(char) < 32 for char in value) or value.count(":") > 1:
        return None
    epoch_text, separator, rest = value.partition(":")
    if not separator:
        rest = value
    if not re.fullmatch(r"[0-9]{1,32}", epoch_text if separator else "0") or not rest:
        return None
    epoch = int(epoch_text) if separator else 0
    upstream, dash, revision = rest.rpartition("-")
    if not dash:
        upstream, revision = rest, ""
    if not upstream or not upstream[0].isdigit() or not upstream.isascii() or not revision.isascii() or any(not (char.isalnum() or char in ".+~:-") for char in upstream + revision):
        return None
    return epoch, upstream, revision


def _rpm_parts(value: str) -> tuple[int, str, str] | None:
    if any(char.isspace() or ord(char) < 32 for char in value) or value.count(":") > 1:
        return None
    epoch_text, separator, rest = value.partition(":")
    if not separator:
        rest = value
    if not re.fullmatch(r"[0-9]{1,32}", epoch_text if separator else "0") or not rest:
        return None
    epoch = int(epoch_text) if separator else 0
    if not rest or not rest.isascii() or any(not (char.isalnum() or char in "._+~-^") for char in rest):
        return None
    version, separator, release = rest.rpartition("-")
    if not separator:
        version, release = rest, ""
    if not version:
        return None
    return epoch, version, release


def _debian_segment_compare(left: str, right: str) -> int:
    # Debian policy 5.6.12: alternate non-digit ordering and numeric runs.
    # Digits have order zero in a non-digit comparison; punctuation follows
    # letters. Never invent a numeric zero for a non-digit character.
    def order(char):
        if char == "~": return -1
        if not char or char.isdigit(): return 0
        return ord(char) if char.isalpha() else ord(char) + 256
    i = j = 0
    while i < len(left) or j < len(right):
        while (i < len(left) and not left[i].isdigit()) or (j < len(right) and not right[j].isdigit()):
            a, b = left[i:i+1], right[j:j+1]
            if order(a) != order(b): return (order(a) > order(b)) - (order(a) < order(b))
            i += bool(a); j += bool(b)
        while i < len(left) and left[i] == "0": i += 1
        while j < len(right) and right[j] == "0": j += 1
        ai, bj = i, j
        while i < len(left) and left[i].isdigit(): i += 1
        while j < len(right) and right[j].isdigit(): j += 1
        a, b = left[ai:i], right[bj:j]
        if len(a) != len(b): return (len(a) > len(b)) - (len(a) < len(b))
        if a != b: return (a > b) - (a < b)
    return 0


def _rpm_segment_compare(left: str, right: str) -> int:
    # RPM version(7): separators are ignored; numeric/alpha runs, tilde and
    # caret have distinct ordering. Inputs are bounded ASCII by the parser.
    i = j = 0
    while i < len(left) or j < len(right):
        while i < len(left) and not left[i].isalnum() and left[i] not in "~^": i += 1
        while j < len(right) and not right[j].isalnum() and right[j] not in "~^": j += 1
        a, b = left[i:i+1], right[j:j+1]
        if a == "~" or b == "~":
            if a != "~": return 1
            if b != "~": return -1
            i += 1; j += 1
            continue
        if a == "^" or b == "^":
            if not a: return -1
            if not b: return 1
            if a != "^": return 1
            if b != "^": return -1
            i += 1; j += 1
            continue
        if not a or not b: break
        numeric = a.isdigit()
        ai, bj = i, j
        predicate = str.isdigit if numeric else str.isalpha
        while i < len(left) and predicate(left[i]): i += 1
        while j < len(right) and predicate(right[j]): j += 1
        if j == bj: return 1 if numeric else -1
        a, b = left[ai:i], right[bj:j]
        if numeric:
            a, b = a.lstrip("0"), b.lstrip("0")
            if len(a) != len(b): return (len(a) > len(b)) - (len(a) < len(b))
        if a != b: return (a > b) - (a < b)
    return (i < len(left)) - (j < len(right))


def _compare(left: Any, right: Any, comparator: str) -> int:
    if comparator == "debian":
        if left[0] != right[0]:
            return 1 if left[0] > right[0] else -1
        for left_part, right_part in ((left[1], right[1]), (left[2], right[2])):
            value = _debian_segment_compare(left_part, right_part)
            if value:
                return value
        return 0
    if comparator == "rpm":
        if left[0] != right[0]:
            return 1 if left[0] > right[0] else -1
        value = _rpm_segment_compare(left[1], right[1])
        return value or _rpm_segment_compare(left[2], right[2])
    if comparator == "semver":
        if left[:3] != right[:3]:
            return 1 if left[:3] > right[:3] else -1
        if not left[3] and not right[3]:
            return 0
        if not left[3]:
            return 1
        if not right[3]:
            return -1
        for lpart, rpart in zip(left[3], right[3]):
            if lpart == rpart:
                continue
            lnum, rnum = lpart.isdigit(), rpart.isdigit()
            if lnum and rnum:
                return 1 if int(lpart) > int(rpart) else -1
            if lnum != rnum:
                return -1 if lnum else 1
            return 1 if lpart > rpart else -1
        return (len(left[3]) > len(right[3])) - (len(left[3]) < len(right[3]))
    return (left > right) - (left < right)


def _component_version(component: ComponentIdentity, comparator: str) -> Any:
    if comparator == "windows_build":
        return _parse_version(component.os_build or component.version, comparator)
    if comparator in {"debian", "rpm"}:
        if not component.release:
            return None
        value = component.version
        if ":" not in value and "-" not in value:
            value = value + "-" + component.release
        return _parse_version(value, comparator)
    return _parse_version(component.version, comparator)


def _component_identity(component: ComponentIdentity, record: AdvisoryRecord) -> str:
    if component.ecosystem.strip().lower() not in _ECOSYSTEM_ALIASES:
        return "unsupported"
    if _ECOSYSTEM_ALIASES[component.ecosystem.strip().lower()] != record.ecosystem:
        return "unsupported"
    product = component.product.strip().lower()
    if product not in _PRODUCT_ALIASES or _PRODUCT_ALIASES[product] != record.product:
        return "unsupported"
    distribution = component.distribution.strip().lower()
    if distribution and distribution not in _DIST_ALIASES:
        return "unsupported"
    canonical_distribution = _DIST_ALIASES.get(distribution)
    if record.distribution and canonical_distribution != record.distribution:
        return "unsupported" if distribution else "unknown"
    return "matched"


def _applicability(component: ComponentIdentity, record: AdvisoryRecord) -> tuple[str, set[str]]:
    limitations: set[str] = set()
    value = _component_version(component, record.comparator)
    if value is None:
        limitations.add("unsupported_version_or_missing_release")
        return "unknown", limitations
    if record.comparator == "windows_build":
        bound = next(bound for bound in (record.introduced, record.fixed, record.last_affected) if bound)
        if value[:3] != _parse_version(bound, record.comparator)[:3]:
            return "unknown", {"windows_build_family_not_applicable"}
    if component.provenance == "banner":
        limitations.update({"version_only", "backport_unverified", "configuration_unverified"})
    elif component.provenance not in {"package_database", "os_inventory", "operator_reviewed"}:
        limitations.add("provenance_unverified")
        return "unknown", limitations
    if record.required_patch_ids or record.superseding_patch_ids:
        patches = {patch.upper() for patch in component.patch_ids}
        if patches & (set(record.required_patch_ids) | set(record.superseding_patch_ids)):
            return "fixed", limitations
        if component.provenance == "package_database" and not patches:
            limitations.add("patch_inventory_missing")
            return "unknown", limitations
    introduced = _parse_version(record.introduced, record.comparator) if record.introduced else None
    fixed = _parse_version(record.fixed, record.comparator) if record.fixed else None
    last = _parse_version(record.last_affected, record.comparator) if record.last_affected else None
    if introduced is not None and _compare(value, introduced, record.comparator) < 0:
        return "fixed", limitations
    if fixed is not None and _compare(value, fixed, record.comparator) >= 0:
        return "fixed", limitations
    if last is not None and _compare(value, last, record.comparator) > 0:
        return "fixed", limitations
    if any(bound is not None for bound in (introduced, fixed, last)):
        return "affected", limitations
    return "unknown", limitations


def _match_group(component: ComponentIdentity, records: list[AdvisoryRecord]) -> AdvisoryMatch:
    records = sorted(records, key=lambda item: (item.advisory_id, item.source_sha256, item.source_url))
    advisory_id = records[0].advisory_id
    cves = tuple(sorted({cve for item in records for cve in item.cve_ids}))
    source = records[0]
    limitations: set[str] = set()
    if all(item.state == "withdrawn" for item in records):
        state = "withdrawn"
        limitations.add("withdrawn_advisory")
    else:
        active = [item for item in records if item.state == "active"]
        evaluations = [_applicability(component, item) for item in active]
        values = {value for value, _ in evaluations}
        for _, item_limits in evaluations:
            limitations.update(item_limits)
        if len(values) > 1:
            state = "conflict"
            limitations.add("conflicting_applicability")
        elif "affected" in values:
            state = "affected_candidate"
        elif "fixed" in values:
            state = "fixed" if component.provenance != "banner" else "unknown"
        else:
            state = "unknown"
        if len({(item.source_sha256, item.source_url) for item in active}) > 1:
            limitations.add("multiple_publication_sources")
    if component.provenance == "banner" and state == "fixed":
        state = "unknown"
    return AdvisoryMatch(advisory_id, component.component_id, state, cves,
                         source.source_sha256, source.source_url, source.comparator,
                         tuple(sorted(limitations)))


def match_components(components: Iterable[ComponentIdentity], catalog: AdvisoryCatalog) -> tuple[AdvisoryMatch, ...]:
    """Match components against the immutable catalog without external calls."""
    if not isinstance(catalog, AdvisoryCatalog):
        raise TypeError("catalog must be an AdvisoryCatalog")
    grouped: dict[str, list[AdvisoryRecord]] = {}
    for item in catalog.records:
        grouped.setdefault(item.advisory_id, []).append(item)
    matches: list[AdvisoryMatch] = []
    for component in components:
        if not isinstance(component, ComponentIdentity):
            raise TypeError("components must contain ComponentIdentity values")
        for advisory_id in sorted(grouped):
            records = grouped[advisory_id]
            identities = {_component_identity(component, item) for item in records}
            if "matched" in identities:
                matches.append(_match_group(component, [item for item in records if _component_identity(component, item) == "matched"]))
            else:
                source = sorted(records, key=lambda item: (item.source_sha256, item.source_url))[0]
                state = "unknown" if "unknown" in identities else "unsupported"
                limitations = {"component_identity_mismatch"} if state == "unsupported" else {"distribution_missing"}
                matches.append(AdvisoryMatch(advisory_id, component.component_id, state,
                                             tuple(sorted({cve for item in records for cve in item.cve_ids})),
                                             source.source_sha256, source.source_url, source.comparator,
                                             tuple(sorted(limitations))))
    return tuple(sorted(matches, key=lambda item: (item.component_id, item.advisory_id)))


__all__ = ["AdvisoryCatalog", "AdvisoryMatch", "AdvisoryRecord", "MAX_RECORDS",
           "SCHEMA", "load_catalog", "match_components"]
