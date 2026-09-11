"""Exact public-source identity and typed source receipts for CPTC11 images."""

from __future__ import annotations

from dataclasses import asdict, dataclass, replace
import json
import re
from collections.abc import Iterable, Sequence
from typing import Literal


SCHEMA = "cptc11-image-source-v1"
SOURCE_SCHEME = "http"
SOURCE_HOST = "cptc.rit.edu"
SOURCE_PORT = 80
SOURCE_ORIGIN = "http://cptc.rit.edu:80"
SOURCE_PATH_PREFIX = "/cptc11/vms/"
_SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")


class SourceRejected(ValueError):
    """The source does not match the frozen public-source contract."""


@dataclass(frozen=True)
class SourceDescriptor:
    asset_id: str
    filename: str
    content_length: int
    role: Literal["production", "support"]

    @property
    def url(self) -> str:
        return f"{SOURCE_SCHEME}://{SOURCE_HOST}{SOURCE_PATH_PREFIX}{self.filename}"

    @property
    def origin(self) -> str:
        return SOURCE_ORIGIN

    def to_dict(self) -> dict[str, object]:
        return {
            "asset_id": self.asset_id,
            "content_length": self.content_length,
            "filename": self.filename,
            "origin": self.origin,
            "role": self.role,
            "url": self.url,
        }


_DESCRIPTORS = (
    SourceDescriptor("APT-CREWCOMMS", "cptc11-export-team-01-APT-CREWCOMMS.qcow2", 11_071_979_520, "production"),
    SourceDescriptor("APT-DC-01", "cptc11-export-team-01-APT-DC-01.qcow2", 8_404_598_784, "production"),
    SourceDescriptor("APT-ENVCTRL", "cptc11-export-team-01-APT-ENVCTRL.qcow2", 10_225_451_008, "production"),
    SourceDescriptor("APT-GPS", "cptc11-export-team-01-APT-GPS.qcow2", 10_668_670_976, "production"),
    SourceDescriptor("Penny", "cptc11-export-team-01-Penny.qcow2", 22_096_838_656, "production"),
    SourceDescriptor("PortCast", "cptc11-export-team-01-PortCast.qcow2", 12_454_264_832, "production"),
    SourceDescriptor("ShorePass", "cptc11-export-team-01-ShorePass.qcow2", 9_387_704_320, "production"),
    SourceDescriptor("kali01", "cptc11-export-team-01-kali01.qcow2", 15_381_561_344, "support"),
    SourceDescriptor("win01", "cptc11-export-team-01-win01.qcow2", 12_307_070_976, "support"),
)
_BY_ASSET = {item.asset_id: item for item in _DESCRIPTORS}
_BY_FILENAME = {item.filename: item for item in _DESCRIPTORS}
ADVERTISED_LENGTHS = {item.asset_id: item.content_length for item in _DESCRIPTORS}


def list_sources(*, include_support: bool = False) -> tuple[SourceDescriptor, ...]:
    """Return the frozen allowlist, excluding support images unless requested."""

    return tuple(
        item for item in _DESCRIPTORS if include_support or item.role == "production"
    )


def source_descriptor(asset_id: str, *, allow_support: bool = False) -> SourceDescriptor:
    try:
        item = _BY_ASSET[asset_id]
    except KeyError as error:
        raise SourceRejected(f"unknown CPTC11 image asset: {asset_id!r}") from error
    if item.role == "support" and not allow_support:
        raise SourceRejected(f"support image {asset_id!r} requires explicit opt-in")
    return item


HeaderFields = Sequence[tuple[str, str]]


def _headers_lower(headers: HeaderFields) -> dict[str, str]:
    if isinstance(headers, (dict, str, bytes)):
        raise SourceRejected("source requires ordered header fields that preserve duplicates")
    lowered: dict[str, str] = {}
    for field in headers:
        if not isinstance(field, tuple) or len(field) != 2:
            raise SourceRejected("source requires ordered header fields")
        name, value = field
        if not isinstance(name, str) or not isinstance(value, str):
            raise SourceRejected("source headers must be strings")
        key = name.strip().lower()
        if not key or key in lowered:
            raise SourceRejected("duplicate or empty source header")
        lowered[key] = value.strip()
    return lowered


@dataclass(frozen=True)
class ImageSource:
    schema: str
    asset_id: str
    filename: str
    url: str
    origin: str
    listing_sha256: str
    content_length: int
    etag: str | None
    last_modified: str
    accept_ranges: bool
    role: Literal["production", "support"]

    def __post_init__(self) -> None:
        if self.schema != SCHEMA:
            raise SourceRejected("invalid image source schema")
        descriptor = _BY_ASSET.get(self.asset_id)
        if descriptor is None:
            raise SourceRejected("unknown image source asset")
        expected = {
            "filename": descriptor.filename,
            "url": descriptor.url,
            "origin": descriptor.origin,
            "content_length": descriptor.content_length,
            "role": descriptor.role,
        }
        for field, value in expected.items():
            if getattr(self, field) != value:
                raise SourceRejected(f"image source {field} does not match allowlist")
        if not _SHA256_RE.fullmatch(self.listing_sha256):
            raise SourceRejected("listing_sha256 must be lowercase SHA-256")
        if self.etag is not None and (not self.etag or "\r" in self.etag or "\n" in self.etag):
            raise SourceRejected("invalid ETag")
        if not self.last_modified or "\r" in self.last_modified or "\n" in self.last_modified:
            raise SourceRejected("invalid Last-Modified")
        if self.accept_ranges is not True:
            raise SourceRejected("source must advertise byte ranges")

    def to_dict(self) -> dict[str, object]:
        return asdict(self)

    def canonical_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":")) + "\n"

    def with_identity(
        self, *, etag: str | None = None, last_modified: str | None = None
    ) -> "ImageSource":
        return replace(
            self,
            etag=self.etag if etag is None else etag,
            last_modified=self.last_modified if last_modified is None else last_modified,
        )


def build_image_source(
    *,
    asset_id: str,
    url: str,
    listing_sha256: str,
    headers: HeaderFields,
    allow_support: bool = False,
    redirected: bool = False,
) -> ImageSource:
    """Validate metadata and construct an immutable source receipt."""

    descriptor = source_descriptor(asset_id, allow_support=allow_support)
    if redirected:
        raise SourceRejected("source redirect is forbidden")
    if url != descriptor.url:
        raise SourceRejected("source URL, origin, path, or filename does not match allowlist")
    normalized = _headers_lower(headers)
    raw_length = normalized.get("content-length")
    if raw_length is None or not re.fullmatch(r"[1-9][0-9]*", raw_length):
        raise SourceRejected("valid Content-Length is required")
    length = int(raw_length)
    if length != descriptor.content_length:
        raise SourceRejected("source advertised length changed")
    if normalized.get("accept-ranges", "").lower() != "bytes":
        raise SourceRejected("source must advertise Accept-Ranges: bytes")
    last_modified = normalized.get("last-modified")
    if not last_modified:
        raise SourceRejected("source Last-Modified is required")
    etag = normalized.get("etag")
    return ImageSource(
        schema=SCHEMA,
        asset_id=descriptor.asset_id,
        filename=descriptor.filename,
        url=descriptor.url,
        origin=descriptor.origin,
        listing_sha256=listing_sha256,
        content_length=length,
        etag=etag,
        last_modified=last_modified,
        accept_ranges=True,
        role=descriptor.role,
    )


def validate_listing(entries: Iterable[tuple[str, int]]) -> tuple[SourceDescriptor, ...]:
    """Require the listing to contain each frozen filename exactly once."""

    seen: dict[str, int] = {}
    for filename, length in entries:
        if filename in seen:
            raise SourceRejected(f"duplicate listing entry: {filename}")
        if filename not in _BY_FILENAME:
            raise SourceRejected(f"unknown listing entry: {filename}")
        if not isinstance(length, int) or isinstance(length, bool):
            raise SourceRejected("listing length must be an integer")
        expected = _BY_FILENAME[filename].content_length
        if length != expected:
            raise SourceRejected(f"advertised length changed for {filename}")
        seen[filename] = length
    missing = sorted(set(_BY_FILENAME) - set(seen))
    if missing:
        raise SourceRejected(f"missing allowlisted listing entries: {', '.join(missing)}")
    return _DESCRIPTORS
