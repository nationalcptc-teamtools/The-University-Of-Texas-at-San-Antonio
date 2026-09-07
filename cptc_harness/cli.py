"""Human terminal entry point. AI clients receive only the restricted MCP/envelope interface."""
from __future__ import annotations
import argparse
from dataclasses import asdict
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
from .clockcheck import current_clock
from .contracts import AuditEvent, PolicyError, canonical_json, to_json
from .exports import ExportReview, encrypted_export, prepare_export, offline_timeline
from .migrations import migrate_legacy
from .orchestrator import rules_reference
from .policy import load_policy
from .preambles import build_preamble
from .providers import load_profile
from .registry import build_registry
from .runtime import Runtime, device_root, initialize
from .storage import private_directory, read_private, write_json


def parser():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--workspace", type=Path)
    sub = p.add_subparsers(dest="command", required=True)
    init = sub.add_parser("init")
    init.add_argument("path", type=Path)
    init.add_argument("--policy", type=Path, required=True)
    init.add_argument("--recipient", required=True)
    init.add_argument("--age", type=Path, default=Path(__file__).resolve().parents[1] / ".tools" / "age")
    sub.add_parser("doctor")
    sub.add_parser("modules")
    sub.add_parser("preamble")
    run = sub.add_parser("run")
    run.add_argument("module")
    run.add_argument("--target")
    run.add_argument("--input", type=Path)
    run.add_argument("--args", default="{}")
    run.add_argument("--approval")
    stop = sub.add_parser("stop")
    stop.add_argument("--reason", default="operator stop")
    sub.add_parser("coverage")
    sub.add_parser("report")
    sub.add_parser("audit-verify")
    sub.add_parser("audit-seal")
    migrate = sub.add_parser("migrate-legacy")
    migrate.add_argument("path", type=Path)
    migrate.add_argument("--encrypted-volume-verified", action="store_true")
    wf = sub.add_parser("workflow-create")
    wf.add_argument("id")
    wf.add_argument("--provider", type=Path, required=True)
    wf.add_argument("--module", action="append", required=True)
    wf.add_argument("--target")
    wf.add_argument("--synthetic", action="store_true")
    step = sub.add_parser("ai-step")
    step.add_argument("id")
    step.add_argument("--provider", type=Path, required=True)
    step.add_argument("--credential-prompt", action="store_true", help="Read one ephemeral provider credential in the local hidden prompt")
    sub.add_parser("tui")
    mcp = sub.add_parser("mcp")
    mcp.add_argument("--workflow", required=True)
    mcp.add_argument("--provider", type=Path, required=True)
    review = sub.add_parser("export-review")
    review.add_argument("files", nargs="+")
    review.add_argument("--output", type=Path, required=True)
    export = sub.add_parser("export")
    export.add_argument("--review", type=Path, required=True)
    export.add_argument("--approved-hash", required=True)
    export.add_argument("--recipient", required=True)
    export.add_argument("--identity", type=Path, required=True)
    export.add_argument("--output", type=Path, required=True)
    export.add_argument("--age", type=Path, default=Path(__file__).resolve().parents[1] / ".tools" / "age")
    timeline = sub.add_parser("merge-timeline")
    timeline.add_argument("sources", type=Path, nargs="+")
    timeline.add_argument("--output", type=Path, required=True)
    handover = sub.add_parser("handover-export")
    handover.add_argument("--recipient-device", required=True)
    handover.add_argument("--recipient-key-ref", type=Path, required=True)
    handover.add_argument("--signing-key-ref", type=Path, required=True)
    handover.add_argument("--seal-id")
    handover.add_argument("--output", type=Path, required=True)
    accept = sub.add_parser("handover-import")
    accept.add_argument("--bundle", type=Path, required=True)
    accept.add_argument("--source-key-ref", type=Path, required=True)
    accept.add_argument("--recipient-key-ref", type=Path, required=True)
    accept.add_argument("--approved-digest", required=True)
    return p


def doctor():
    clock = current_clock()
    bwrap = shutil.which("bwrap")
    isolation = False
    if bwrap:
        try:
            result = subprocess.run([bwrap, "--unshare-all", "--die-with-parent", "--ro-bind", "/usr", "/usr", "--symlink", "usr/lib", "/lib", "--symlink", "usr/lib", "/lib64", "--symlink", "usr/bin", "/bin", "/usr/bin/true"], capture_output=True, timeout=5, env={})
            isolation = result.returncode == 0
        except (OSError, subprocess.TimeoutExpired):
            pass
    return {"python": sys.version.split()[0], "clock": asdict(clock), "bubblewrap_isolation": isolation,
            "active_clock_eligible": clock.synchronized and clock.offset_s is not None and abs(clock.offset_s) <= 2,
            "native_scanners": "Require an admitted containment profile; no automatic cloud/update/callback services",
            "provider": "No service is implicitly authorized by availability"}


def main(argv=None):
    os.umask(0o077)
    args = parser().parse_args(argv)
    runtime = None
    try:
        if args.command == "init":
            result = initialize(args.path, args.policy, recipient=args.recipient, age_binary=args.age)
        elif args.command == "doctor":
            result = doctor()
        elif args.command == "modules":
            result = [to_json(s) for s in build_registry().specs()]
        elif args.command == "migrate-legacy":
            result = migrate_legacy(args.path, encrypted_storage_verified=args.encrypted_volume_verified)
        elif args.command == "merge-timeline":
            result = offline_timeline(tuple(args.sources), args.output)
        else:
            if args.workspace is None:
                raise PolicyError("this command requires --workspace")
            if args.command == "stop":
                # Stop must not wait for the active writer's lock. The running broker
                # sees the persisted latch and records cancellation itself.
                from .ledger import Ledger
                policy = load_policy(args.workspace / "policy.json")
                ledger = Ledger(device_root() / policy.engagement_id, policy.engagement_id, policy.device_id)
                ledger.stop(args.reason)
                result = {"stopped": True, "new_work": "blocked", "reason": args.reason}
            else:
                runtime = Runtime(args.workspace)
                if args.command == "run":
                    result = runtime.run(args.module, target_id=args.target, input_path=args.input, args=json.loads(args.args), approval_id=args.approval)
                elif args.command == "preamble":
                    result = to_json(build_preamble(runtime.policy, rules_reference(), runtime.registry.specs()))
                elif args.command == "coverage":
                    result = runtime.coverage()
                elif args.command == "report":
                    result = runtime.report()
                elif args.command == "audit-verify":
                    result = to_json(runtime.audit.verify())
                elif args.command == "audit-seal":
                    result = to_json(runtime.audit.seal())
                elif args.command == "workflow-create":
                    result = runtime.workflows.create(args.id, load_profile(args.provider), tuple(args.module), target_id=args.target, synthetic=args.synthetic)
                elif args.command == "ai-step":
                    profile = load_profile(args.provider)
                    if args.credential_prompt:
                        import getpass
                        from .secrets import SecretBroker, CredentialRef
                        with SecretBroker() as secrets:
                            reference = secrets.deposit(getpass.getpass("Provider credential (local, ephemeral): "), profile)
                            runtime.audit.emit(AuditEvent("credential_reference_created", data={"reference": reference, "provider": profile.name}))
                            result = runtime.workflows.step(args.id, profile, credential=CredentialRef(secrets, reference, profile))
                    else:
                        result = runtime.workflows.step(args.id, profile)
                elif args.command == "mcp":
                    from .mcp_server import serve
                    return serve(runtime, args.workflow, load_profile(args.provider))
                elif args.command == "tui":
                    return tui(runtime)
                elif args.command == "export-review":
                    runtime.audit.emit(AuditEvent("export_review_started", data={"file_count": len(args.files)}))
                    review = prepare_export(args.workspace, tuple(args.files), operator=runtime.policy.operator_id)
                    write_json(args.output, {"review": to_json(review), "review_hash": review.review_hash}, replace=False)
                    result = {"review_file": str(args.output), "review_hash": review.review_hash, "files": review.files}
                elif args.command == "export":
                    value = json.loads(read_private(args.review))
                    review = ExportReview(**{**value["review"], "files": tuple(value["review"]["files"])})
                    if Path(review.root) != runtime.root:
                        raise PolicyError("export review belongs to another workspace")
                    result = encrypted_export(review, args.output, approved_hash=args.approved_hash,
                        recipient=args.recipient, age=args.age, verify_identity=args.identity)
                    runtime.audit.emit(AuditEvent("export_verified", data={k: v for k, v in result.items() if k != "destination"}))
                elif args.command == "handover-export":
                    from .signing import public_key, SigningReference
                    from .contracts import digest
                    _, fingerprint = public_key(args.recipient_key_ref)
                    bundle = runtime.export_handover(args.recipient_device, fingerprint,
                        SigningReference(args.signing_key_ref), seal_id=args.seal_id)
                    write_json(args.output, to_json(bundle), replace=False)
                    result = {"bundle": str(args.output), "review_digest": digest(to_json(bundle)),
                              "source_stopped": True, "seal_id": bundle.payload["seal_id"]}
                elif args.command == "handover-import":
                    from .signing import public_key
                    from .contracts import MergeBundle
                    value = json.loads(read_private(args.bundle, 8 * 1024 * 1024))
                    if set(value) != {"engagement_id", "device_id", "payload"}:
                        raise PolicyError("invalid handover envelope")
                    bundle = MergeBundle(**value)
                    source_key, _ = public_key(args.source_key_ref)
                    _, fingerprint = public_key(args.recipient_key_ref)
                    result = runtime.import_handover(bundle, {bundle.device_id: source_key}, fingerprint, args.approved_digest)
                else:
                    raise PolicyError("unknown command")
        print(json.dumps(to_json(result), indent=2, ensure_ascii=True, allow_nan=False))
        return 0
    except (PolicyError, OSError, ValueError, KeyError, TypeError) as exc:
        # Do not reflect raw file/target/provider errors into AI-facing stderr.
        message = str(exc) if isinstance(exc, PolicyError) else "invalid local input or unavailable operation"
        print(json.dumps({"status": "blocked", "reason": message}, ensure_ascii=True), file=sys.stderr)
        return 2
    finally:
        if runtime is not None:
            runtime.audit.close()


def tui(runtime):
    if not sys.stdin.isatty():
        raise PolicyError("interactive terminal required")
    print("CPTC guarded terminal | m modules | c coverage | a verify audit | s stop | q quit")
    while True:
        choice = input("cptc> ").strip()
        if choice == "q":
            return 0
        if choice == "m":
            result = [{"id": s.module_id, "mode": s.mode} for s in runtime.registry.specs()]
        elif choice == "c":
            result = runtime.coverage()
        elif choice == "a":
            result = to_json(runtime.audit.verify())
        elif choice == "s":
            runtime.ledger.stop("operator TUI stop")
            runtime.audit.emit(AuditEvent("operator_stop", data={"interface": "TUI"}))
            result = {"stopped": True}
        else:
            result = {"help": "Use m, c, a, s, q. Target execution uses explicit CLI profiles."}
        print(json.dumps(to_json(result), indent=2, ensure_ascii=True))
