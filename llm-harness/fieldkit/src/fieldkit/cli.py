"""Command line entry point. Module options are shared with the interactive console."""

import argparse
from typing import Any

from rich.console import Console

from fieldkit import __version__
from fieldkit.core.module import Module
from fieldkit.registry import modules


def add_options(parser: argparse.ArgumentParser, module: Module) -> None:
    parser.set_defaults(module=module)
    if module.accepts_targets:
        parser.add_argument("targets", nargs="*", help="Hostnames, IPs, or HTTP(S) origins")
    for option in module.options:
        kwargs: dict[str, Any] = {
            "dest": option.name,
            "default": None if option.kind is list else option.default,
            "help": option.description,
        }
        if option.kind is bool:
            kwargs["action"] = argparse.BooleanOptionalAction
        elif option.kind is list:
            kwargs["action"] = "append"
        else:
            kwargs["type"] = option.kind
        parser.add_argument(option.flag, **kwargs)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="fieldkit", description="Modular assessment toolkit")
    parser.add_argument("--version", action="version", version=f"Fieldkit {__version__}")
    commands = parser.add_subparsers(dest="command")
    commands.add_parser("console", help="Start the interactive terminal console")
    commands.add_parser("modules", help="List installed modules")
    mcp = commands.add_parser("mcp", help="Serve Fieldkit tools to local AI agents over MCP stdio")
    mcp.add_argument("--workspace", default=".", help="Working directory for assessment inputs")
    mcp.add_argument("--output", default="artifacts/mcp", help="Private MCP job storage")
    mcp.add_argument("--max-jobs", type=int, default=2, help="Maximum active assessment jobs")
    mcp.add_argument("--job-timeout", type=float, default=600, help="Hard job deadline in seconds")
    mcp.add_argument("--max-output", type=int, default=1048576, help="Per-job process log limit")
    registry = modules()
    collect = commands.add_parser(
        "collect", help="Collect web artifacts", description=registry["web/artifacts"].description
    )
    add_options(collect, registry["web/artifacts"])
    run = commands.add_parser("run", help="Run a module directly")
    module_commands = run.add_subparsers(dest="module_name", required=True)
    for name, module in registry.items():
        subparser = module_commands.add_parser(name, help=module.description)
        add_options(subparser, module)
    ingest = commands.add_parser("ingest", help="Import captures/documents into the private vault")
    formats = ingest.add_subparsers(dest="ingest_format", required=True)
    for format_name in (
        "burp",
        "har",
        "raw",
        "report",
        "js",
        "openapi",
        "actuator",
        "oidc",
        "artifact",
    ):
        subparser = formats.add_parser(format_name)
        add_options(subparser, registry["evidence/ingest"])
        subparser.set_defaults(FORMAT=format_name)
        subparser.add_argument("inputs", nargs="+", help="Explicit local input files")
    alias_groups = {
        "web": {
            "routes": "web/routes",
            "ids": "web/ids",
            "resolve": "web/host-resolver",
            "vault": "web/request-vault",
            "actuator": "web/actuator-analyze",
            "auth-flows": "web/auth-flow-map",
        },
        "inspect": {"artifact": "artifacts/triage", "serialization": "artifacts/serialization"},
        "workflow": {"baseline": "web/workflow-verify"},
        "findings": {"draft": "evidence/report", "hypotheses": "evidence/hypotheses"},
    }
    for command, aliases in alias_groups.items():
        group = commands.add_parser(command)
        choices = group.add_subparsers(dest="alias", required=True)
        for alias, module_name in aliases.items():
            subparser = choices.add_parser(alias, help=registry[module_name].description)
            add_options(subparser, registry[module_name])
            if command == "inspect" and alias == "artifact":
                subparser.add_argument("artifact_file", nargs="?")
            if command == "workflow":
                subparser.add_argument(
                    "--request", dest="REQUEST_IDS", action="append", default=argparse.SUPPRESS
                )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "mcp":
        from fieldkit.mcp_server import main as mcp_main

        return mcp_main(
            [
                "--workspace",
                args.workspace,
                "--output",
                args.output,
                "--max-jobs",
                str(args.max_jobs),
                "--job-timeout",
                str(args.job_timeout),
                "--max-output",
                str(args.max_output),
            ]
        )
    console = Console()
    if args.command in {None, "console"}:
        from fieldkit.console import InteractiveConsole

        return InteractiveConsole(console).run()
    if args.command == "modules":
        for name, module in modules().items():
            console.print(f"{name:<24} {module.description}")
        return 0
    module = args.module
    settings = {
        option.name: (
            list(option.default)
            if option.kind is list and getattr(args, option.name) is None
            else getattr(args, option.name)
        )
        for option in module.options
    }
    if module.accepts_targets:
        settings["TARGETS"] = [*settings["TARGETS"], *args.targets]
    if getattr(args, "inputs", None):
        settings["INPUT"] = [*settings["INPUT"], *args.inputs]
    if getattr(args, "artifact_file", None):
        settings["INPUT"] = [*settings["INPUT"], args.artifact_file]
    try:
        return module.run(settings, console)
    except (ValueError, OSError) as exc:
        console.print(f"Error: {exc}", style="red", markup=False)
        return 2
    except KeyboardInterrupt:
        return 130
