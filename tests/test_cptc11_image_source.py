from __future__ import annotations

from dataclasses import replace
import hashlib
import json

import pytest

from testing.cptc11_benchmark.http_source import HttpResponse, build_range_request, validate_range_response
from testing.cptc11_benchmark.source_allowlist import (
    ADVERTISED_LENGTHS,
    ImageSource,
    SourceRejected,
    build_image_source,
    list_sources,
    source_descriptor,
    validate_listing,
)


LISTING_HASH = "a" * 64


def _headers(asset_id: str) -> tuple[tuple[str, str], ...]:
    return (
        ("Content-Length", str(ADVERTISED_LENGTHS[asset_id])),
        ("ETag", '"fixture-v1"'),
        ("Last-Modified", "2026-09-01T00:00:00Z"),
        ("Accept-Ranges", "bytes"),
    )


def _source(asset_id: str = "APT-DC-01", *, allow_support: bool = False) -> ImageSource:
    descriptor = source_descriptor(asset_id, allow_support=allow_support)
    return build_image_source(
        asset_id=asset_id,
        url=descriptor.url,
        listing_sha256=LISTING_HASH,
        headers=_headers(asset_id),
        allow_support=allow_support,
    )


def test_allowlist_has_exact_seven_production_and_two_explicit_support_images():
    production = list_sources()
    all_sources = list_sources(include_support=True)
    assert [item.asset_id for item in production] == [
        "APT-CREWCOMMS", "APT-DC-01", "APT-ENVCTRL", "APT-GPS", "Penny", "PortCast", "ShorePass"
    ]
    assert [item.asset_id for item in all_sources[-2:]] == ["kali01", "win01"]
    assert all(item.role == "production" for item in production)
    assert all(item.role == "support" for item in all_sources[-2:])


def test_support_source_requires_explicit_flag():
    with pytest.raises(SourceRejected, match="support image"):
        source_descriptor("kali01")
    assert source_descriptor("kali01", allow_support=True).role == "support"


@pytest.mark.parametrize("url", [
    "http://evil.example/cptc11/vms/cptc11-export-team-01-APT-DC-01.qcow2",
    "https://cptc.rit.edu/cptc11/vms/cptc11-export-team-01-APT-DC-01.qcow2",
    "http://cptc.rit.edu:8080/cptc11/vms/cptc11-export-team-01-APT-DC-01.qcow2",
    "http://cptc.rit.edu/other/cptc11-export-team-01-APT-DC-01.qcow2",
    "http://cptc.rit.edu/cptc11/vms/cptc11-export-team-01-APT-DC-01.qcow2?x=1",
    "http://cptc.rit.edu/cptc11/vms/cptc11-export-team-01-APT-DC-01.qcow2#x",
    "http://cptc.rit.edu/cptc11/vms/%63ptc11-export-team-01-APT-DC-01.qcow2",
    "http://cptc.rit.edu/cptc11/vms/unknown.qcow2",
])
def test_source_rejects_origin_path_query_fragment_and_filename_drift(url: str):
    with pytest.raises(SourceRejected):
        build_image_source(asset_id="APT-DC-01", url=url, listing_sha256=LISTING_HASH, headers=_headers("APT-DC-01"))


def test_source_requires_ordered_duplicate_preserving_headers():
    descriptor = source_descriptor("APT-DC-01")
    with pytest.raises(SourceRejected, match="ordered header fields"):
        build_image_source(
            asset_id="APT-DC-01", url=descriptor.url, listing_sha256=LISTING_HASH,
            headers=dict(_headers("APT-DC-01")),  # type: ignore[arg-type]
        )
    with pytest.raises(SourceRejected, match="duplicate"):
        build_image_source(
            asset_id="APT-DC-01", url=descriptor.url, listing_sha256=LISTING_HASH,
            headers=(*_headers("APT-DC-01"), ("content-length", str(descriptor.content_length))),
        )


def test_source_rejects_redirect_unknown_length_and_advertised_length_drift():
    descriptor = source_descriptor("APT-DC-01")
    with pytest.raises(SourceRejected, match="redirect"):
        build_image_source(asset_id="APT-DC-01", url=descriptor.url, listing_sha256=LISTING_HASH, headers=_headers("APT-DC-01"), redirected=True)
    with pytest.raises(SourceRejected, match="Content-Length"):
        build_image_source(asset_id="APT-DC-01", url=descriptor.url, listing_sha256=LISTING_HASH, headers=_headers("APT-DC-01")[1:])
    changed = list(_headers("APT-DC-01"))
    changed[0] = ("Content-Length", str(descriptor.content_length + 1))
    with pytest.raises(SourceRejected, match="advertised length"):
        build_image_source(asset_id="APT-DC-01", url=descriptor.url, listing_sha256=LISTING_HASH, headers=tuple(changed))


def test_listing_requires_every_allowlisted_file_once_with_fixed_lengths():
    entries = [(item.filename, item.content_length) for item in list_sources(include_support=True)]
    assert len(validate_listing(entries)) == 9
    with pytest.raises(SourceRejected, match="duplicate"):
        validate_listing(entries + [entries[0]])
    with pytest.raises(SourceRejected, match="missing"):
        validate_listing(entries[:-1])
    with pytest.raises(SourceRejected, match="unknown"):
        validate_listing(entries + [("unknown.qcow2", 1)])


def test_range_request_pins_source_and_requires_streaming_receive_cap():
    source = _source()
    request = build_range_request(source, start=4096, size=4 * 1024 * 1024)
    assert request.headers == {
        "Accept-Encoding": "identity", "If-Match": '"fixture-v1"', "Range": "bytes=4096-4198399"
    }
    assert request.follow_redirects is False
    assert request.response_limits.max_body_bytes == 4 * 1024 * 1024
    assert request.response_limits.max_header_bytes == 64 * 1024
    assert request.response_limits.require_streaming is True
    with pytest.raises(SourceRejected, match="4 MiB"):
        build_range_request(source, start=0, size=4 * 1024 * 1024 + 1)


def _response(source: ImageSource, body: bytes = b"synthetic-range") -> HttpResponse:
    return HttpResponse(
        status=206,
        headers=(
            ("Content-Range", f"bytes 0-{len(body) - 1}/{source.content_length}"),
            ("Content-Length", str(len(body))),
            ("Content-Encoding", "identity"),
            ("ETag", source.etag or ""),
            ("Last-Modified", source.last_modified),
        ),
        body=body,
        final_url=source.url,
        streaming_receive_cap=len(body),
        streaming_cap_enforced=True,
    )


def test_range_response_accepts_exact_partial_content_and_hashes_body():
    source = _source()
    body = b"synthetic-range"
    chunk = validate_range_response(source, start=0, requested_size=len(body), response=_response(source, body))
    assert chunk.start == 0
    assert chunk.end == len(body) - 1
    assert chunk.sha256 == hashlib.sha256(body).hexdigest()
    assert chunk.body == body


def test_range_response_rejects_duplicate_headers_and_missing_stream_cap():
    source = _source()
    response = _response(source, b"x")
    with pytest.raises(SourceRejected, match="duplicate"):
        validate_range_response(source, start=0, requested_size=1, response=replace(response, headers=(*response.headers, ("content-length", "1"))))
    with pytest.raises(SourceRejected, match="streaming receive cap"):
        validate_range_response(source, start=0, requested_size=1, response=replace(response, streaming_cap_enforced=False))
    with pytest.raises(SourceRejected, match="streaming receive cap"):
        validate_range_response(source, start=0, requested_size=1, response=replace(response, streaming_receive_cap=2))


def test_range_response_rejects_mapping_headers_and_oversized_headers():
    source = _source()
    response = _response(source, b"x")
    with pytest.raises(SourceRejected, match="ordered header fields"):
        validate_range_response(source, start=0, requested_size=1, response=replace(response, headers=dict(response.headers)))  # type: ignore[arg-type]
    with pytest.raises(SourceRejected, match="headers exceed"):
        validate_range_response(source, start=0, requested_size=1, response=replace(response, headers=(*response.headers, ("X-Padding", "x" * (64 * 1024)))))


@pytest.mark.parametrize(
    ("change", "message"),
    [
        ({"status": 200}, "206"),
        ({"status": 302}, "redirect"),
        ({"final_url": "http://evil.example/file"}, "final URL"),
        ({"headers": (("Content-Range", "bytes 1-1/10"),)}, "Content-Range"),
        ({"headers": (("Content-Encoding", "gzip"),)}, "compressed"),
        ({"headers": (("Transfer-Encoding", "chunked"),)}, "exact body length"),
        ({"headers": (("ETag", '"fixture-v2"'),)}, "ETag"),
        ({"headers": (("Last-Modified", "2026-09-02T00:00:00Z"),)}, "Last-Modified"),
    ],
)
def test_range_response_rejects_protocol_and_source_identity_drift(change, message):
    source = _source()
    response = _response(source, b"x")
    if "headers" in change:
        replacements = {name.lower(): value for name, value in change["headers"]}
        headers = tuple((name, replacements.get(name.lower(), value)) for name, value in response.headers)
        known = {name.lower() for name, _value in response.headers}
        headers += tuple((name, value) for name, value in change["headers"] if name.lower() not in known)
        response = replace(response, headers=headers)
    response = replace(response, **{key: value for key, value in change.items() if key != "headers"})
    with pytest.raises(SourceRejected, match=message):
        validate_range_response(source, start=0, requested_size=1, response=response)


def test_image_source_canonical_json_is_stable_and_round_trips():
    source = _source()
    first = source.canonical_json()
    assert first == replace(source).canonical_json()
    assert json.loads(first)["schema"] == "cptc11-image-source-v1"
    assert first.endswith("\n")
