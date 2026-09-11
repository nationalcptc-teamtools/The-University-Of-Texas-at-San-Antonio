"""Phase A CLI: deterministic source listing and state-root validation only."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from .source_allowlist import list_sources
from .staging import StagingRejected, validate_state_root


_LATER_PHASE = ("acquire", "inventory", "extract", "verify", "export-derivative", "cleanup")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m testing.cptc11_benchmark")
    commands = parser.add_subparsers(dest="command", required=True)
    listing = commands.add_parser("list-sources")
    listing.add_argument("--include-support", action="store_true")
    doctor = commands.add_parser("doctor")
    doctor.add_argument("--state-root", type=Path, required=True)
    for name in _LATER_PHASE:
        commands.add_parser(name)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.command == "list-sources":
        payload = {
            "phase": "A",
            "schema": "cptc11-source-list-v1",
            "sources": [
                source.to_dict()
                for source in list_sources(include_support=args.include_support)
            ],
        }
        print(json.dumps(payload, sort_keys=True, separators=(",", ":")))
        return 0
    if args.command == "doctor":
        try:
            state_root = validate_state_root(args.state_root)
        except StagingRejected as error:
            print(f"doctor rejected state root: {error}", file=sys.stderr)
            return 2
        try:
            print(
                json.dumps(
                    {
                        "phase": "A",
                        "state_root": str(state_root.path),
                        "state_root_valid": True,
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                )
            )
        finally:
            state_root.close()
        return 0
    print(f"{args.command} is unavailable until a later phase", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
