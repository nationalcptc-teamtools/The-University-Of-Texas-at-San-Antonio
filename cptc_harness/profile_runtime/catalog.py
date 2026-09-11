"""Hash-anchored catalog for finite bounded network profiles.

Callers select an exact profile identifier. They cannot supply an endpoint,
method, header, payload, budget, parser, or runtime option.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import stat
from typing import Any
from weakref import ref

from ..contracts import PolicyError
from .contracts import ProfileBudget, ProfileContractError, ProfileOperation, parse_operation


PROFILE_CATALOG_SHA256 = "d37bc4a0ba5368e02306f52cce5927d5a5db6e7dee90dda0cc0ee3d243e66113"
_CATALOG_PATH = Path(__file__).parent.parent / "resources" / "bounded-profiles-v1.json"
_MAX_CATALOG_BYTES = 128 * 1024
_ENVELOPE_FIELDS = frozenset({"schema_version", "catalog_sha256", "profiles"})
_PROFILE_FIELDS = frozenset(
    {
        "profile_id",
        "module_id",
        "target_id",
        "admission",
        "runtime_pinset_sha256",
        "operation",
        "budget",
        "parser_id",
        "runtime_options",
        "limitations",
    }
)
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_LIMITATION = re.compile(r"^[a-z][a-z0-9_]{0,95}$")
_ADMISSIONS = frozenset({"fixture_only", "lab_candidate", "live_admitted"})


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")


def _sha256(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate JSON key")
        value[key] = item
    return value


def _read_catalog(path: Path) -> Any:
    if path.is_symlink():
        raise ProfileContractError("profile catalog symlink rejected")
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    except OSError:
        raise ProfileContractError("profile catalog unavailable") from None
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > _MAX_CATALOG_BYTES:
            raise ProfileContractError("profile catalog file is invalid")
        raw = os.read(descriptor, _MAX_CATALOG_BYTES + 1)
        if len(raw) != metadata.st_size:
            raise ProfileContractError("profile catalog changed during read")
    finally:
        os.close(descriptor)
    try:
        return json.loads(raw, object_pairs_hook=_pairs)
    except (UnicodeDecodeError, ValueError, RecursionError):
        raise ProfileContractError("profile catalog JSON is invalid") from None


def _text_id(value: Any, label: str) -> str:
    if not isinstance(value, str) or _ID.fullmatch(value) is None:
        raise ProfileContractError(f"invalid {label}")
    return value


def _operation_dict(operation: ProfileOperation) -> dict[str, Any]:
    value = asdict(operation)
    if "headers" in value:
        value["headers"] = [list(item) for item in operation.headers]  # type: ignore[union-attr]
    return value


@dataclass(frozen=True, slots=True, weakref_slot=True)
class SealedProfile:
    profile_id: str
    module_id: str
    target_id: str
    admission: str
    runtime_pinset_sha256: str
    operation: ProfileOperation
    budget: ProfileBudget
    parser_id: str
    runtime_options: tuple[str, ...]
    limitations: tuple[str, ...]
    profile_sha256: str
    catalog_sha256: str


@dataclass(frozen=True, slots=True)
class ProfileCatalog:
    schema_version: int
    catalog_sha256: str
    profiles: tuple[SealedProfile, ...]
    path: Path


_PROFILE_IDENTITIES: dict[int, tuple[Any, str, str]] = {}


def _register_profile(profile: SealedProfile) -> None:
    identity = id(profile)

    def discard(reference: Any, *, identity: int = identity) -> None:
        current = _PROFILE_IDENTITIES.get(identity)
        if current is not None and current[0] is reference:
            _PROFILE_IDENTITIES.pop(identity, None)

    reference = ref(profile, discard)
    _PROFILE_IDENTITIES[identity] = (
        reference,
        profile.catalog_sha256,
        profile.profile_sha256,
    )


def _profile_payload(profile: SealedProfile) -> dict[str, Any]:
    return {
        "profile_id": profile.profile_id,
        "module_id": profile.module_id,
        "target_id": profile.target_id,
        "admission": profile.admission,
        "runtime_pinset_sha256": profile.runtime_pinset_sha256,
        "operation": _operation_dict(profile.operation),
        "budget": profile.budget.as_dict(),
        "parser_id": profile.parser_id,
        "runtime_options": list(profile.runtime_options),
        "limitations": list(profile.limitations),
    }


def _parse_profile(value: Any, catalog_sha256: str) -> SealedProfile:
    if not isinstance(value, dict) or frozenset(value) != _PROFILE_FIELDS:
        raise ProfileContractError("unknown or missing profile field")
    admission = value["admission"]
    if admission not in _ADMISSIONS:
        raise ProfileContractError("invalid profile admission")
    if value["runtime_options"] != []:
        raise ProfileContractError("profile runtime options are forbidden")
    raw_limitations = value["limitations"]
    if (
        not isinstance(raw_limitations, list)
        or not 1 <= len(raw_limitations) <= 8
        or len(raw_limitations) != len(set(raw_limitations))
        or any(not isinstance(item, str) or _LIMITATION.fullmatch(item) is None for item in raw_limitations)
    ):
        raise ProfileContractError("invalid profile limitations")
    operation = parse_operation(value["operation"])
    budget = ProfileBudget.from_dict(value["budget"])
    runtime_pinset_sha256 = value["runtime_pinset_sha256"]
    if (
        not isinstance(runtime_pinset_sha256, str)
        or re.fullmatch(r"[0-9a-f]{64}", runtime_pinset_sha256) is None
    ):
        raise ProfileContractError("invalid runtime pinset hash")
    payload_hash = _sha256(value)
    profile = SealedProfile(
        profile_id=_text_id(value["profile_id"], "profile id"),
        module_id=_text_id(value["module_id"], "module id"),
        target_id=_text_id(value["target_id"], "target id"),
        admission=admission,
        runtime_pinset_sha256=runtime_pinset_sha256,
        operation=operation,
        budget=budget,
        parser_id=_text_id(value["parser_id"], "parser id"),
        runtime_options=(),
        limitations=tuple(raw_limitations),
        profile_sha256=payload_hash,
        catalog_sha256=catalog_sha256,
    )
    if _sha256(_profile_payload(profile)) != payload_hash:
        raise ProfileContractError("normalized profile differs from catalog")
    _register_profile(profile)
    return profile


def load_catalog(path: Path | None = None) -> ProfileCatalog:
    resolved = _CATALOG_PATH if path is None else Path(path)
    value = _read_catalog(resolved)
    if not isinstance(value, dict) or frozenset(value) != _ENVELOPE_FIELDS:
        raise ProfileContractError("unknown or missing catalog field")
    if type(value["schema_version"]) is not int or value["schema_version"] != 1:
        raise ProfileContractError("invalid catalog schema")
    if not isinstance(value["profiles"], list) or not value["profiles"]:
        raise ProfileContractError("profile catalog is empty")
    actual = _sha256(
        {"schema_version": value["schema_version"], "profiles": value["profiles"]}
    )
    if value["catalog_sha256"] != actual or actual != PROFILE_CATALOG_SHA256:
        raise ProfileContractError("profile catalog hash differs")
    profiles = tuple(_parse_profile(row, actual) for row in value["profiles"])
    identifiers = tuple(profile.profile_id for profile in profiles)
    if identifiers != tuple(sorted(identifiers)) or len(set(identifiers)) != len(identifiers):
        raise ProfileContractError("profile catalog identifiers differ")
    return ProfileCatalog(1, actual, profiles, resolved)


def load_profile(profile_id: str) -> SealedProfile:
    if not isinstance(profile_id, str) or _ID.fullmatch(profile_id) is None:
        raise ProfileContractError("unknown profile")
    for profile in load_catalog().profiles:
        if profile.profile_id == profile_id:
            return profile
    raise ProfileContractError("unknown profile")


def validate_sealed_profile(profile: Any) -> SealedProfile:
    if not isinstance(profile, SealedProfile):
        raise ProfileContractError("profile is not sealed")
    try:
        registered = _PROFILE_IDENTITIES.get(id(profile))
        payload_hash = _sha256(_profile_payload(profile))
    except (AttributeError, TypeError, ValueError):
        raise ProfileContractError("profile identity is invalid") from None
    if (
        registered is None
        or registered[0]() is not profile
        or registered[1:] != (PROFILE_CATALOG_SHA256, profile.profile_sha256)
        or profile.catalog_sha256 != PROFILE_CATALOG_SHA256
        or payload_hash != profile.profile_sha256
    ):
        raise ProfileContractError("profile seal differs")
    return profile


def require_live_admission(profile: Any) -> SealedProfile:
    """Require an authentic profile whose admission is exactly live."""

    try:
        profile = validate_sealed_profile(profile)
    except ProfileContractError:
        raise PolicyError("profile is not sealed for live admission") from None
    if profile.admission != "live_admitted":
        raise PolicyError("profile is not live admitted")
    return profile


__all__ = (
    "PROFILE_CATALOG_SHA256",
    "ProfileCatalog",
    "SealedProfile",
    "load_catalog",
    "load_profile",
    "require_live_admission",
    "validate_sealed_profile",
)
