import io

import pytest
from rich.console import Console

from fieldkit.cli import main
from fieldkit.console import InteractiveConsole


def test_console_retains_options_and_routes_run_to_module(monkeypatch):
    console = InteractiveConsole(Console(file=io.StringIO()))
    console.execute("use web/artifacts")
    console.execute("set TARGETS localhost 127.0.0.1")
    console.execute('set OUTPUT "folder with spaces"')
    console.execute("set INSECURE true")
    console.execute("set CONCURRENCY 3")
    received = []
    monkeypatch.setattr(
        console.registry["web/artifacts"], "run", lambda s, c: received.append(s) or 0
    )
    console.execute("run")
    assert received[0]["TARGETS"] == ["localhost", "127.0.0.1"]
    assert received[0]["OUTPUT"] == "folder with spaces"
    assert received[0]["INSECURE"] is True
    assert received[0]["CONCURRENCY"] == 3
    console.execute("back")
    console.execute("use web/artifacts")
    console.execute("unset CONCURRENCY")
    assert console.settings["web/artifacts"]["CONCURRENCY"] == 8
    assert console.settings["web/artifacts"]["INSECURE"] is True
    assert console.execute("exit") is False


def test_console_invalid_boolean_does_not_change_settings():
    console = InteractiveConsole(Console(file=io.StringIO()))
    console.execute("use web/artifacts")
    with pytest.raises(ValueError):
        console.execute("set INSECURE perhaps")
    assert console.settings["web/artifacts"]["INSECURE"] is False


def test_cli_invalid_inputs_return_status_2():
    assert main(["collect"]) == 2
    assert main(["run", "web/artifacts", "http://example.test/path"]) == 2


def test_cli_supplied_list_replaces_defaults(monkeypatch):
    from fieldkit.modules.tls_review import TLSReview

    received = []
    monkeypatch.setattr(
        TLSReview, "run", lambda self, settings, console: received.append(settings) or 0
    )
    assert main(["run", "web/tls-review", "https://lab.test", "--protocol", "TLSv1.2"]) == 0
    assert received[0]["PROTOCOLS"] == ["TLSv1.2"]


@pytest.mark.parametrize(
    "name,argv,command,key,expected",
    [
        (
            "web/parameter-discovery",
            ["--name", "method", "--name", "bearer"],
            "set NAMES method bearer",
            "NAMES",
            ["method", "bearer"],
        ),
        ("web/jwt-check", ["--test", "none"], "set TESTS none", "TESTS", ["none"]),
        ("web/ffuf", ["--max-words", "7"], "set MAX_WORDS 7", "MAX_WORDS", 7),
        (
            "integrations/burp-bridge",
            ["--origin", "https://fixture.test"],
            "set ORIGINS https://fixture.test",
            "ORIGINS",
            ["https://fixture.test"],
        ),
    ],
)
def test_agent_assessment_tools_use_same_typed_options_in_cli_and_console(
    monkeypatch, name, argv, command, key, expected
):
    from fieldkit.registry import modules

    received = []
    monkeypatch.setattr(
        type(modules()[name]),
        "run",
        lambda self, settings, console: received.append(settings) or 0,
    )
    assert main(["run", name, *argv]) == 0
    interactive = InteractiveConsole(Console(file=io.StringIO()))
    interactive.execute("use " + name)
    interactive.execute(command)
    interactive.execute("run")
    assert len(received) == 2
    assert all(settings[key] == expected for settings in received)
