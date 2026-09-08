"""Standalone operator-directed CPTC toolkit.

This entry point intentionally exposes only local lifecycle and offline import
operations.  It does not import provider, model, or MCP modules while showing
help, listing modules, or running preflight checks.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import sys
from typing import Any

from .contracts import PolicyError, to_json


def _workspace_argument(command: argparse.ArgumentParser) -> None:
    command.add_argument("--workspace", dest="workspace_after", type=Path,
                         help="owner-only engagement workspace (may also precede the command)")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", type=Path, help="owner-only engagement workspace")
    commands = parser.add_subparsers(dest="command", required=True)

    commands.add_parser("modules", help="list the static reviewed module registry")
    commands.add_parser("checks", help="list finite detection checks and visible unsupported capabilities")
    preflight = commands.add_parser("preflight", help="inspect local prerequisites without opening a runtime")
    _workspace_argument(preflight)
    preflight.add_argument("--age", type=Path, help="pinned age executable to inspect")

    init = commands.add_parser("init", help="create a human-operated engagement workspace")
    init.add_argument("path", type=Path)
    init.add_argument("--policy", type=Path, required=True)
    init.add_argument("--recipient", required=True)
    init.add_argument("--age", type=Path, default=Path(__file__).resolve().parents[1] / ".tools" / "age")

    run = commands.add_parser("run", help="run one explicitly selected registered operation")
    _workspace_argument(run)
    run.add_argument("module")
    run.add_argument("--target")
    run.add_argument("--input", type=Path)
    run.add_argument("--args", default="{}")
    run.add_argument("--approval")

    import_command = commands.add_parser("import", help="import one owner-selected offline artifact")
    _workspace_argument(import_command)
    import_command.add_argument("module")
    import_command.add_argument("--input", type=Path, required=True)

    replay = commands.add_parser("replay-capture", help="analyze one explicitly selected encrypted capture offline")
    _workspace_argument(replay)
    replay.add_argument("module", choices=("web.nuclei_observation", "web.zap_observation"))
    replay.add_argument("--action-id", required=True)
    replay.add_argument("--evidence-id", required=True)
    replay.add_argument("--identity", type=Path, required=True, help="owner-only age identity; used only by an isolated local decryptor")

    for name in ("coverage", "report", "findings", "gaps", "audit-verify", "stop"):
        command = commands.add_parser(name)
        _workspace_argument(command)
        if name == "stop":
            command.add_argument("--reason", choices=("operator_request", "suspected_lockout", "health_degradation", "audit_failure"), default="operator_request", help="durable stop reason code")
    from .campaign import add_cli_commands
    add_cli_commands(commands, _workspace_argument)
    return parser


def _workspace(args: argparse.Namespace) -> Path:
    value = getattr(args, "workspace", None) or getattr(args, "workspace_after", None)
    if value is None:
        raise PolicyError("this command requires --workspace")
    return Path(value)


def _strict_object(raw: str) -> dict[str, Any]:
    def reject_constant(value: str) -> None:
        raise ValueError("non-finite JSON value")

    value = json.loads(raw, parse_constant=reject_constant)
    if not isinstance(value, dict):
        raise PolicyError("--args must be a JSON object")
    return value


def _modules() -> list[dict[str, Any]]:
    # Deliberately lazy: registry imports only deterministic collectors/parsers,
    # and this path never imports Runtime or the provider/model adapters.
    from .registry import build_registry

    catalog = _catalog_status()
    dependencies = {
        "network.nmap_inventory": {"nmap", "nmap-shim"},
        "web.nuclei_observation": {"nuclei"},
        "web.zap_observation": {"zap", "java"},
    }
    result = []
    for spec in build_registry().specs():
        item = to_json(spec)
        if spec.mode == "manual_only":
            item["catalog"] = {"status": "manual_only", "admission": "manual_only", "admitted": False}
        elif spec.tool_id is None:
            item["catalog"] = {"status": "not_applicable", "admission": "registry_offline"}
        else:
            matches = [entry for entry in catalog if spec.module_id in entry.get("profiles", [])]
            expected = dependencies.get(spec.module_id, set())
            complete = bool(expected) and len(matches) == len(expected) and {entry.get("tool_id") for entry in matches} == expected
            admitted = complete and all(entry.get("admitted") is True for entry in matches)
            item["catalog"] = ({"status": "available" if all(entry.get("available") for entry in matches) else "unavailable",
                                 "admission": "fixture_tested" if admitted else "not_admitted",
                                 "admitted": admitted,
                                 "pinned": complete and all(entry.get("pinned") is True for entry in matches),
                                 "tool_ids": [entry["tool_id"] for entry in matches]} if matches else
                                {"status": "unavailable", "admission": "not_admitted",
                                 "admitted": False,
                                 "reason": "no matching reviewed catalog entry"})
        result.append(item)
    return result


def _catalog_status() -> list[dict[str, Any]]:
    """Return catalog availability without making availability an admission."""
    try:
        from .tool_catalog import catalog_status
    except (ImportError, ModuleNotFoundError):
        return [{"catalog": "tool-catalog", "status": "unavailable",
                 "reason": "catalog module is not installed"}]
    try:
        value = catalog_status()
    except Exception:
        return [{"catalog": "tool-catalog", "status": "unavailable",
                 "reason": "catalog could not be read"}]
    if not isinstance(value, list):
        return [{"catalog": "tool-catalog", "status": "unavailable",
                 "reason": "catalog returned an invalid shape"}]
    return [item for item in value if isinstance(item, dict)]


def _catalog_entries() -> list[dict[str, Any]]:
    try:
        path = Path(__file__).parent / "resources" / "tool-catalog.json"
        value = json.loads(path.read_bytes())
        return [item for item in value.get("tools", []) if isinstance(item, dict)]
    except (OSError, TypeError, ValueError):
        return []


def _binary_status(label: str, candidates: tuple[str, ...], *, catalog: list[dict[str, Any]],
                   known_version: str | None = None) -> dict[str, Any]:
    path_text = next((path for candidate in candidates if (path := shutil.which(candidate))), None)
    if not path_text:
        return {"name": label, "availability": "unavailable", "admission": "not admitted",
                "reason": "executable is not installed"}
    try:
        path = Path(path_text).resolve(strict=True)
        hasher = hashlib.sha256()
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                hasher.update(chunk)
        actual_hash = hasher.hexdigest()
        pinned = next((entry for entry in catalog if entry.get("path") == str(path) and
                       entry.get("sha256") == actual_hash), None)
        return {"name": label, "availability": "available", "path": str(path),
                "sha256": actual_hash, "version": (pinned or {}).get("version", known_version or "unknown"),
                "pinned": pinned is not None,
                "admission": ((pinned or {}).get("admission", "not admitted") if pinned else "not admitted"),
                "version_probe": "disabled for read-only preflight"}
    except OSError:
        return {"name": label, "availability": "unavailable", "path": str(path),
                "admission": "not admitted", "reason": "executable metadata could not be read"}


def _preflight(workspace: Path | None, age: Path | None) -> dict[str, Any]:
    catalog = _catalog_entries()
    age_candidates = ((str(age),) if age else
                      (str(Path(__file__).resolve().parents[1] / ".tools" / "age"), "age"))
    binaries = [
        _binary_status("python", (Path(sys.executable).name, "python3"), catalog=catalog, known_version=sys.version.split()[0]),
        _binary_status("bubblewrap", ("bwrap",), catalog=catalog),
        _binary_status("age", age_candidates, catalog=catalog),
        _binary_status("nmap", ("nmap",), catalog=catalog),
        _binary_status("nuclei", ("nuclei",), catalog=catalog),
        _binary_status("zap", ("zaproxy", "zap.sh"), catalog=catalog),
    ]
    seccomp = {"availability": "unavailable", "admission": "requires reviewed containment"}
    try:
        status = Path("/proc/self/status").read_text(encoding="ascii", errors="replace")
        seccomp_value = next((line.split(":", 1)[1].strip() for line in status.splitlines()
                              if line.startswith("Seccomp:")), None)
        if seccomp_value is not None:
            seccomp = {"availability": "available", "mode": seccomp_value,
                       "admission": "requires reviewed containment"}
    except OSError:
        pass
    result: dict[str, Any] = {"version": 1, "classification": "operator_local",
                              "python": sys.version.split()[0], "binaries": binaries,
                              "seccomp": seccomp, "catalog": _catalog_status(),
                              "admission": "availability is separate from module admission; manual-only and unsupported profiles remain blocked"}
    if workspace is not None:
        result["workspace"] = str(workspace)
        runtime = workspace / "runtime.json"
        try:
            from .storage import read_private
            config = json.loads(read_private(runtime, 65536))
            age_path = Path(config["age_binary"])
            result["workspace_runtime"] = {"status": "available", "age_binary": str(age_path),
                                            "age_sha256_matches": hashlib.sha256(age_path.read_bytes()).hexdigest() == config["age_sha256"]}
        except (OSError, ValueError, KeyError, TypeError, PolicyError):
            result["workspace_runtime"] = {"status": "unavailable", "reason": "workspace runtime metadata is unavailable"}
    return result


def _runtime(workspace: Path):
    # Runtime (and therefore provider/model adapter modules) is opened only for
    # an operator lifecycle command that actually needs workspace state.
    from .runtime import Runtime
    return Runtime(workspace)


def _stop(workspace: Path, reason: str) -> dict[str, Any]:
    from .audit_control import operator_stop
    from .policy import load_policy
    from .runtime import device_root

    policy = load_policy(workspace / "policy.json")
    return operator_stop(device_root() / policy.engagement_id, policy, interface="human", reason=reason)


def _execute(args: argparse.Namespace) -> Any:
    if args.command == "checks":
        from .check_catalog import capability_status
        return {"checks": capability_status(), "model_calls": 0, "benchmark_complete": False}
    if args.command == "modules":
        return _modules()
    if args.command == "preflight":
        return _preflight(getattr(args, "workspace", None) or getattr(args, "workspace_after", None), args.age)
    if args.command == "init":
        from .runtime import initialize
        return initialize(args.path, args.policy, recipient=args.recipient, age_binary=args.age)
    workspace = _workspace(args)
    if args.command == "stop":
        return _stop(workspace, args.reason)
    if args.command == "replay-capture":
        from .operator_replay import replay_capture
        runtime = _runtime(workspace)
        try:
            return replay_capture(runtime, module_id=args.module, action_id=args.action_id,
                                  evidence_id=args.evidence_id, identity=args.identity)
        finally:
            runtime.close()
    if args.command == "run":
        runtime = _runtime(workspace)
        try:
            return runtime.run(args.module, target_id=args.target, input_path=args.input,
                               args=_strict_object(args.args), approval_id=args.approval)
        finally:
            runtime.close()
    if args.command == "import":
        from .registry import build_registry
        spec = build_registry().get(args.module)
        if spec.mode != "offline":
            raise PolicyError("human import accepts offline modules only")
        runtime = _runtime(workspace)
        try:
            return runtime.run(args.module, input_path=args.input)
        finally:
            runtime.close()
    runtime = _runtime(workspace)
    try:
        if args.command.startswith("assessment-"):
            from .campaign import execute_cli
            return execute_cli(runtime, args)
        if args.command == "coverage":
            return runtime.coverage()
        if args.command == "report":
            return runtime.report()
        if args.command == "findings":
            data = runtime.report(include_data=True)
            return {"classification": "client_confidential", "model_calls": 0,
                    "detections": data["detections"], "evidence_index": data["evidence_index"],
                    "confirmation_policy": data["confirmation_policy"]}
        if args.command == "gaps":
            data = runtime.coverage()
            return {"classification": "client_confidential", "model_calls": 0,
                    "checks": [row for row in data["checks"] if not row.get("collection_complete") or row.get("limitations")],
                    "capabilities": [row for row in data["capabilities"] if row["live_validation"] != "accepted"]}
        if args.command == "audit-verify":
            return to_json(runtime.audit.verify())
    finally:
        runtime.close()
    raise PolicyError("unknown command")


def main(argv: list[str] | None = None) -> int:
    os.umask(0o077)
    try:
        try:
            args = _parser().parse_args(argv)
        except SystemExit as exc:
            return int(exc.code)
        result = _execute(args)
        print(json.dumps(to_json(result), indent=2, ensure_ascii=True, allow_nan=False))
        if isinstance(result, dict):
            outcome = result.get("result", result)
            if isinstance(outcome, dict) and outcome.get("status") in {"blocked", "failed", "stopped", "uncertain"} and not (args.command == "stop" and outcome.get("status") == "stopped"):
                return 2
            if args.command == "audit-verify" and result.get("valid") is not True:
                return 2
        return 0
    except (PolicyError, OSError, ValueError, KeyError, TypeError) as exc:
        message = str(exc) if isinstance(exc, PolicyError) else "invalid local input or unavailable operation"
        print(json.dumps({"status": "blocked", "reason": message}, ensure_ascii=True), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
