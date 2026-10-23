import pytest

from fieldkit.core.http import FetchResult
from fieldkit.core.targets import read_targets, target_urls
from fieldkit.modules.web_artifacts import discover_scripts, validate_path


def test_targets_combine_file_and_values_and_deduplicate(tmp_path):
    path = tmp_path / "targets.txt"
    path.write_text("# team targets\nlocalhost\n192.0.2.1,192.0.2.2\n\n")
    assert read_targets(["localhost", "192.0.2.3 192.0.2.1"], str(path)) == [
        "localhost",
        "192.0.2.3",
        "192.0.2.1",
        "192.0.2.2",
    ]


@pytest.mark.parametrize(
    ("target", "scheme", "expected"),
    [
        ("example.test", "auto", ["https://example.test/", "http://example.test/"]),
        ("example.test:8080", "http", ["http://example.test:8080/"]),
        ("https://example.test:8443", "http", ["https://example.test:8443/"]),
        ("::1", "http", ["http://[::1]/"]),
        ("[::1]:8080", "http", ["http://[::1]:8080/"]),
    ],
)
def test_origin_normalization(target, scheme, expected):
    assert target_urls(target, scheme) == expected


@pytest.mark.parametrize(
    "target",
    [
        "ftp://example.test",
        "http://",
        "http://user:secret@example.test",
        "http://example.test/app",
        "http://example.test?x=1",
        "http://example.test#x",
        "localhost:bad",
        "localhost:99999",
        "localhost:0",
        "http://host\\name/",
    ],
)
def test_invalid_targets_are_rejected(target):
    with pytest.raises(ValueError):
        target_urls(target, "auto")


@pytest.mark.parametrize(
    "path",
    [
        "http://outside.test/script.js",
        "//outside.test/script.js",
        "app.js",
        "/a#b",
        "/a b",
    ],
)
def test_custom_paths_cannot_change_origin(path):
    with pytest.raises(ValueError):
        validate_path(path)


def test_malformed_html_urls_do_not_break_script_discovery():
    page = FetchResult(
        "http://lab/",
        "http://lab/",
        200,
        "text/html",
        b'<base href="http://[bad"><link href="http://[bad">'
        b'<script src="http://[bad"></script><script src="/valid.js"></script>',
    )
    assert discover_scripts(page, "http://lab/") == ["http://lab/valid.js"]
