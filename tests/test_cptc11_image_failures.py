from __future__ import annotations

import json
from pathlib import Path

import pytest

from testing.cptc11_benchmark.__main__ import main
from testing.cptc11_benchmark.http_source import HttpResponse, validate_range_response
from testing.cptc11_benchmark.source_allowlist import build_image_source, source_descriptor


def _source():
    descriptor = source_descriptor("APT-DC-01")
    return build_image_source(
        asset_id=descriptor.asset_id,
        url=descriptor.url,
        listing_sha256="d" * 64,
        headers=(("Content-Length", str(descriptor.content_length)), ("ETag", '"v1"'), ("Last-Modified", "2026-09-01T00:00:00Z"), ("Accept-Ranges", "bytes")),
    )


def test_range_validation_rejects_short_and_oversized_bodies():
    source = _source()
    headers = (("Content-Range", f"bytes 0-3/{source.content_length}"), ("Content-Length", "4"), ("ETag", source.etag or ""), ("Last-Modified", source.last_modified))
    for body in (b"abc", b"abcde"):
        with pytest.raises(Exception, match="body length"):
            validate_range_response(
                source, start=0, requested_size=4,
                response=HttpResponse(status=206, headers=headers, body=body, final_url=source.url, streaming_receive_cap=4, streaming_cap_enforced=True),
            )


def test_cli_lists_production_only_by_default_and_support_on_explicit_flag(capsys):
    assert main(["list-sources"]) == 0
    default = json.loads(capsys.readouterr().out)
    assert len(default["sources"]) == 7
    assert {item["role"] for item in default["sources"]} == {"production"}
    assert main(["list-sources", "--include-support"]) == 0
    all_sources = json.loads(capsys.readouterr().out)
    assert len(all_sources["sources"]) == 9


def test_cli_doctor_only_validates_restricted_state_root(tmp_path: Path, capsys):
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    state.chmod(0o700)
    assert main(["doctor", "--state-root", str(state)]) == 0
    assert json.loads(capsys.readouterr().out) == {"phase": "A", "state_root": str(state.absolute()), "state_root_valid": True}


@pytest.mark.parametrize("command", ["acquire", "inventory", "extract", "verify", "export-derivative", "cleanup"])
def test_later_phase_cli_commands_are_explicitly_unavailable(command: str, capsys):
    assert main([command]) == 2
    assert "unavailable until a later phase" in capsys.readouterr().err
