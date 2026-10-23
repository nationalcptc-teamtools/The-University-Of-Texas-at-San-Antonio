"""Host inventory and bounded exposure candidates, without escalation or validation."""

import json
import sys
import time
from pathlib import Path

from fieldkit.core.assessment import write_private
from fieldkit.core.local import LOCAL_OPTIONS, LocalModule
from fieldkit.core.local_worker import candidates
from fieldkit.core.module import Option
from fieldkit.core.process import ProcessResult, run_process

ROOT_OPTIONS = (
    Option("ROOTS", list, [], "Explicit files/directories to inspect (repeat)", "--root"),
    Option("EXCLUSIONS", list, [], "Path/name glob exclusion (repeat)", "--exclude"),
    Option(
        "FOLLOW_SYMLINKS",
        bool,
        False,
        "Follow links only within explicit roots",
        "--follow-symlinks",
    ),
    Option("MAX_FILES", int, 10000, "Maximum regular files inspected", "--max-files"),
    Option("MAX_OUTPUT", int, 8388608, "Combined worker output ceiling", "--max-output"),
)


async def filesystem(ctx, mode):
    config = {
        "roots": ctx.settings["ROOTS"],
        "mode": mode,
        "exclusions": [*ctx.settings["EXCLUSIONS"], str(ctx.store.root) + "*"],
        "follow_symlinks": ctx.settings["FOLLOW_SYMLINKS"],
        "max_files": ctx.settings["MAX_FILES"],
        "max_bytes": ctx.settings["MAX_BYTES"],
        "budget": max(0.001, ctx.deadline - time.monotonic()),
        "max_total_bytes": ctx.settings.get("MAX_TOTAL_BYTES", 10485760),
        "max_extract_bytes": ctx.settings.get("MAX_EXTRACT_BYTES", 1048576),
        "max_members": ctx.settings.get("MAX_MEMBERS", 100),
        "archives": ctx.settings.get("ARCHIVES", False),
        "office": ctx.settings.get("OFFICE", False),
        "pdf": ctx.settings.get("PDF", False),
    }
    if ctx.settings.get("RETAIN_RAW"):
        raw = ctx.store.root / "private-raw"
        raw.mkdir(mode=0o700)
        config["raw_dir"] = str(raw)
    config_path = ctx.store.root / ".worker.json"
    write_private(config_path, json.dumps(config))
    pending = bytearray()
    pdfs = []

    def accept(chunk):
        pending.extend(chunk)
        while b"\n" in pending:
            line, _, rest = pending.partition(b"\n")
            pending[:] = rest
            record = json.loads(line)
            if record.get("error"):
                ctx.error(record["error"], record["resource"], record.get("detail", ""))
            elif record["kind"] == "pdf_candidate":
                pdfs.append(record["resource"])
            elif record["kind"] == "private_raw":
                ctx.report["evidence"].append(
                    {"id": f"raw-{len(ctx.report['evidence']) + 1}", "host": ctx.host, **record}
                )
            else:
                evidence = ctx.evidence(record, source=record.get("resource", "filesystem"))
                ctx.report["results"].append({"host": ctx.host, **record, "evidence": [evidence]})
                if record["kind"] in {
                    "credential_candidate",
                    "sensitive_filename",
                    "suid_binary",
                    "sgid_binary",
                    "writable_file",
                    "writable_directory",
                    "writable_service_executable",
                }:
                    ctx.finding(
                        record["kind"],
                        record["kind"].replace("_", " ").capitalize(),
                        record["resource"],
                        evidence=[evidence],
                        **{k: v for k, v in record.items() if k not in {"kind", "resource"}},
                    )

    result = ProcessResult()
    try:
        await run_process(
            [sys.executable, "-m", "fieldkit.core.local_worker", str(config_path)],
            timeout=config["budget"],
            max_output=ctx.settings["MAX_OUTPUT"],
            on_stdout=accept,
            result=result,
        )
    finally:
        config_path.unlink(missing_ok=True)
        ctx.report["coverage"].append(
            {"category": "filesystem", **result.metadata(), "roots": config["roots"], "mode": mode}
        )
        if result.reason != "finished" or pending:
            ctx.error(
                result.reason if result.reason != "finished" else "partial_record",
                "filesystem",
                "Partial filesystem evidence preserved",
            )
    used = sum(
        r.get("bytes_read", 0)
        for r in ctx.report["results"]
        if r.get("kind") == "filesystem_summary"
    )
    for filename in pdfs:
        remaining = config["max_total_bytes"] - used
        if remaining <= 0:
            ctx.error("byte_limit", filename, "PDF extraction total ceiling reached")
            break
        result, evidence = await ctx.command(
            "pdf_extract",
            ["pdftotext", "-layout", filename, "-"],
            max_output=min(config["max_extract_bytes"], remaining),
        )
        used += len(result.stdout)
        # Reuse the candidate detector without exposing raw extracted text in the report.
        captured = []
        candidates(Path(filename), bytes(result.stdout), config, "pdf-text", sink=captured.append)
        for record in captured:
            ctx.report["results"].append({"host": ctx.host, **record, "evidence": [evidence]})
            if record["kind"] == "credential_candidate":
                ctx.finding(
                    record["kind"],
                    "Credential-shaped PDF content",
                    record["resource"],
                    evidence=[evidence],
                    line=record["line"],
                    preview=record["preview"],
                )


def validate_roots(settings):
    if not settings["ROOTS"]:
        raise ValueError("Supply explicit --root files/directories")
    if any(not isinstance(root, str) or not root for root in settings["ROOTS"]):
        raise ValueError("ROOTS must be nonempty path strings")
    for name in ("MAX_FILES", "MAX_OUTPUT"):
        if settings[name] <= 0:
            raise ValueError(f"{name} must be positive")
    settings["ROOTS"] = [str(Path(root).expanduser().absolute()) for root in settings["ROOTS"]]


class LinuxInventory(LocalModule):
    name = "linux/inventory"
    description = "Read-only local host, permission, service, process and container evidence."
    options = LOCAL_OPTIONS + tuple(
        Option(
            o.name,
            o.kind,
            [
                "/usr/bin",
                "/usr/sbin",
                "/etc/cron.d",
                "/etc/cron.daily",
                "/etc/cron.weekly",
                "/etc/systemd/system",
                "/usr/lib/systemd/system",
            ]
            if o.name == "ROOTS"
            else o.default,
            o.description,
            o.flag,
        )
        for o in ROOT_OPTIONS
    )

    def validate(self, settings):
        validate_roots(settings)
        if sys.platform != "linux":
            raise ValueError("linux/inventory requires Linux")

    async def assess(self, ctx):
        for category, argv in (
            ("os_kernel", ["uname", "-a"]),
            ("identity", ["id"]),
            ("sudo_noninteractive", ["sudo", "-n", "-l"]),
            ("current_user_cron", ["crontab", "-l"]),
            ("systemd_units", ["systemctl", "list-units", "--all", "--no-pager", "--plain"]),
            ("systemd_unit_files", ["systemctl", "list-unit-files", "--no-pager", "--plain"]),
            ("processes", ["ps", "-eo", "pid,ppid,user,group,comm"]),
            ("listeners", ["ss", "-lntup"]),
            ("mounts", ["findmnt", "--json"]),
            ("nfs_exports", ["exportfs", "-v"]),
            ("file_capabilities", ["getcap", "-r", *ctx.settings["ROOTS"]]),
        ):
            await ctx.command(category, argv)
        # Bounded reads go through a child, including proc/mounted files that can block.
        for filename in (
            "/etc/os-release",
            "/etc/hostname",
            "/etc/machine-id",
            "/etc/passwd",
            "/etc/group",
            "/etc/crontab",
            "/proc/self/cgroup",
            "/proc/self/mountinfo",
            "/etc/exports",
        ):
            await ctx.command("host_file", ["head", "-c", str(ctx.settings["MAX_BYTES"]), filename])
        # Socket accessibility is metadata only; no daemon API call or container creation.
        code = (
            "import os,json,stat; from pathlib import Path; "
            "paths=['/var/run/docker.sock','/run/containerd/containerd.sock',"
            "'/run/podman/podman.sock','/.dockerenv','/run/.containerenv','/etc/shadow']; "
            "print(json.dumps([{'path':p,'exists':Path(p).exists(),"
            "'readable':os.access(p,os.R_OK),'writable':os.access(p,os.W_OK)} for p in paths]))"
        )
        await ctx.command("container_and_permissions", [sys.executable, "-c", code])
        await filesystem(ctx, "inventory")
        ctx.report["coverage"].append(
            {
                "category": "limitations",
                "status": "incomplete",
                "detail": "Local NSS/namespace view only; roots limit file "
                "coverage. No escalation proofs or credential validation.",
            }
        )


class ExposureAudit(LocalModule):
    name = "linux/exposure-audit"
    description = "Bounded, redacted credential/file exposure candidates under explicit roots."
    options = (
        LOCAL_OPTIONS
        + ROOT_OPTIONS
        + (
            Option(
                "MAX_TOTAL_BYTES",
                int,
                33554432,
                "Total read/extracted byte ceiling",
                "--max-total-bytes",
            ),
            Option(
                "MAX_EXTRACT_BYTES",
                int,
                1048576,
                "Extracted bytes per container",
                "--max-extract-bytes",
            ),
            Option(
                "MAX_MEMBERS", int, 100, "Maximum members per archive/document", "--max-members"
            ),
            Option(
                "ARCHIVES",
                bool,
                False,
                "Inspect ZIP/TAR/GZIP members without writing them",
                "--archives",
            ),
            Option("OFFICE", bool, False, "Inspect OOXML/ODF XML text", "--office"),
            Option("PDF", bool, False, "Extract PDFs with optional pdftotext", "--pdf"),
            Option(
                "RETAIN_RAW",
                bool,
                False,
                "Retain candidate content in private-raw (0600)",
                "--retain-raw",
            ),
        )
    )

    def validate(self, settings):
        validate_roots(settings)
        for name in ("MAX_TOTAL_BYTES", "MAX_EXTRACT_BYTES", "MAX_MEMBERS"):
            if settings[name] <= 0:
                raise ValueError(f"{name} must be positive")

    async def assess(self, ctx):
        await filesystem(ctx, "exposure")
