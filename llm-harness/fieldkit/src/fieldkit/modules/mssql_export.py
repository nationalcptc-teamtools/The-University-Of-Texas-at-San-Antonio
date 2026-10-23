"""Explicit read-only Windows-authenticated MSSQL inventory and private local export."""

import hashlib
import json
import os
import re
import shutil
import stat
import sys
import time
import zipfile
from pathlib import Path

from fieldkit.core.local import LOCAL_OPTIONS, LocalModule
from fieldkit.core.module import Option
from fieldkit.core.mssql import MSSQLError, credentials, identifier, parse_json, private_json
from fieldkit.core.process import ProcessResult, run_process


class MSSQLExport(LocalModule):
    name = "database/mssql-export"
    description = "Read-only Windows NTLM database inventory and explicitly selected local exports."
    options = LOCAL_OPTIONS + (
        Option("HOST", str, "", "Explicit MSSQL hostname or address", "--host"),
        Option("PORT", int, 1433, "Explicit MSSQL TCP port", "--port"),
        Option("DATABASES", list, [], "Explicit database name (repeat)", "--database"),
        Option("TABLES_FILE", str, "", "Private JSON table selections", "--tables-file"),
        Option("CREDENTIAL_FILE", str, "", "Private JSON Windows credentials", "--credential-file"),
        Option(
            "CREDENTIAL_ENV",
            str,
            "",
            "Environment variable name holding credential JSON",
            "--credential-env",
        ),
        Option(
            "INVENTORY_ONLY", bool, True, "Inventory without exporting rows", "--inventory-only"
        ),
        Option("DRY_RUN", bool, False, "Validate a plan without connecting", "--dry-run"),
        Option("MAX_TABLES", int, 50, "Selected/visible table ceiling (1-100)", "--max-tables"),
        Option("MAX_ROWS", int, 1000, "Maximum exported rows per table (1-100000)", "--max-rows"),
        Option("MAX_COLUMNS", int, 256, "Maximum columns per table (1-256)", "--max-columns"),
        Option(
            "MAX_VALUE_CHARS",
            int,
            4000,
            "Value conversion character cap (2-4000)",
            "--max-value-chars",
        ),
        Option(
            "MAX_TOTAL_BYTES",
            int,
            16777216,
            "Private archive ceiling (64KiB-256MiB)",
            "--max-total-bytes",
        ),
    )

    def validate(self, settings):
        host = settings["HOST"]
        if (
            not isinstance(host, str)
            or not 1 <= len(host) <= 253
            or any(ord(c) < 32 or c.isspace() or c in "/\\@" for c in host)
        ):
            raise MSSQLError(
                "HOST requires an explicit hostname/address without credentials or URL syntax"
            )
        if "://" in host or not 1 <= settings["PORT"] <= 65535:
            raise MSSQLError("MSSQL requires a hostname/address and TCP port 1-65535")
        if not isinstance(settings["DATABASES"], list) or not 1 <= len(settings["DATABASES"]) <= 16:
            raise MSSQLError("Select 1-16 explicit DATABASES; database scope never defaults to all")
        self._databases = list(dict.fromkeys(identifier(name) for name in settings["DATABASES"]))
        for name, lower, upper in (
            ("MAX_TABLES", 1, 100),
            ("MAX_ROWS", 1, 100000),
            ("MAX_COLUMNS", 1, 256),
            ("MAX_VALUE_CHARS", 2, 4000),
            ("MAX_TOTAL_BYTES", 65536, 268435456),
            ("MAX_BYTES", 1, 8388608),
        ):
            if type(settings[name]) is not int or not lower <= settings[name] <= upper:
                raise MSSQLError(f"{name} must be between {lower} and {upper}")
        self._credential = None
        if settings["CREDENTIAL_FILE"] and settings["CREDENTIAL_ENV"]:
            raise MSSQLError(
                "Select one private credential file or credential environment variable"
            )
        if settings["CREDENTIAL_FILE"]:
            self._credential = credentials(private_json(settings["CREDENTIAL_FILE"]))
        elif settings["CREDENTIAL_ENV"]:
            name = settings["CREDENTIAL_ENV"]
            if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,127}", name):
                raise MSSQLError("CREDENTIAL_ENV must name one bounded environment variable")
            value = os.environ.get(name, "")
            if not value or len(value.encode()) > 65536:
                raise MSSQLError("Credential environment variable is missing or exceeds its limit")
            self._credential = credentials(parse_json(value))
        elif not settings["DRY_RUN"]:
            raise MSSQLError(
                "Supply private Windows credentials via CREDENTIAL_FILE or CREDENTIAL_ENV"
            )
        self._tables = []
        if settings["TABLES_FILE"]:
            records = private_json(settings["TABLES_FILE"])
            if not isinstance(records, list) or not 1 <= len(records) <= settings["MAX_TABLES"]:
                raise MSSQLError("TABLES_FILE requires a bounded list of explicit table selections")
            for record in records:
                if not isinstance(record, dict) or set(record) != {"database", "schema", "table"}:
                    raise MSSQLError(
                        "Each table selection requires database, schema and table names"
                    )
                item = {key: identifier(value) for key, value in record.items()}
                if item["database"] not in self._databases:
                    raise MSSQLError("Table selection leaves the explicitly selected databases")
                if item in self._tables:
                    raise MSSQLError("Table selections must be unique")
                self._tables.append(item)
        if not settings["INVENTORY_ONLY"] and not self._tables:
            raise MSSQLError(
                "Row export requires TABLES_FILE; imported inventory never selects exports"
            )

    async def assess(self, ctx):
        if self._credential:
            ctx.secrets.extend(self._credential.values())
        if ctx.settings["DRY_RUN"]:
            ctx.report["plan"] = {
                "host": ctx.settings["HOST"],
                "port": ctx.settings["PORT"],
                "databases": self._databases,
                "selected_tables": self._tables,
                "inventory_only": ctx.settings["INVENTORY_ONLY"],
                "connections": 0,
                "read_only": True,
                "authentication": "windows_ntlm",
            }
            return
        private_root = ctx.store.root / "private-raw" / "mssql"
        private_root.mkdir(mode=0o700, parents=True)
        private_root.parent.chmod(0o700)
        reserve = max(16384, min(4194304, ctx.settings["MAX_TOTAL_BYTES"] // 4))
        config = {
            "host": ctx.settings["HOST"],
            "port": ctx.settings["PORT"],
            "databases": self._databases,
            "tables": self._tables,
            "inventory_only": ctx.settings["INVENTORY_ONLY"],
            "max_tables": ctx.settings["MAX_TABLES"],
            "max_rows": ctx.settings["MAX_ROWS"],
            "max_columns": ctx.settings["MAX_COLUMNS"],
            "max_value_chars": ctx.settings["MAX_VALUE_CHARS"],
            "max_query_bytes": ctx.settings["MAX_BYTES"],
            "max_row_bytes": ctx.settings["MAX_BYTES"],
            "data_limit": max(
                0,
                ctx.settings["MAX_TOTAL_BYTES"] - reserve - (ctx.settings["MAX_TABLES"] + 8) * 512,
            ),
            "max_metadata_bytes": reserve,
            "timeout": ctx.settings["TIMEOUT"],
            "budget": max(0.001, ctx.deadline - time.monotonic()),
        }
        path = ctx.store.root / ".mssql-worker.json"
        result = ProcessResult()
        created = False
        try:
            descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            created = True
            with os.fdopen(descriptor, "w") as stream:
                json.dump(
                    {"config": config, "credential": self._credential, "root": str(private_root)},
                    stream,
                )
            await run_process(
                [sys.executable, "-m", "fieldkit.core.mssql", str(path)],
                timeout=config["budget"],
                max_output=4096,
                result=result,
                terminate_grace=0.3,
            )
        finally:
            if created:
                path.unlink(missing_ok=True)
        ctx.report["coverage"].append({"category": "mssql", **result.metadata(), "read_only": True})
        manifest_path = private_root / "manifest.json"
        if not manifest_path.is_file():
            ctx.error("mssql_worker_failed", "mssql", "No MSSQL metadata was recovered")
            return
        state = private_json(manifest_path, reserve)
        if not ctx.settings["INVENTORY_ONLY"]:
            reconcile_exports(private_root, state, config)
        for inventory in state["inventory"]:
            ctx.report["results"].append({"kind": "mssql_inventory", **inventory})
        for table in state["tables"]:
            public_table = dict(table)
            filename = public_table.pop("file", "")
            if filename:
                public_table["archive_member"] = "tables/" + filename
            ctx.report["results"].append(
                {"kind": "mssql_table_export", **public_table, "private_rows": True}
            )
        for error in state["errors"]:
            ctx.error(error["error"], "mssql", error.get("detail", "Selected table export failed"))
        if not state["completed"] and not state["errors"]:
            ctx.error(
                "partial_export", "mssql", "Export caps prevented a complete selected-table archive"
            )
        if result.reason != "finished":
            ctx.error(result.reason, "mssql", "Partial MSSQL inventory/export preserved")
        if ctx.settings["INVENTORY_ONLY"]:
            shutil.rmtree(private_root)
            return
        try:
            archive = seal_archive(private_root, state, ctx.settings["MAX_TOTAL_BYTES"])
        except (OSError, ValueError):
            ctx.error(
                "archive_failed",
                "mssql",
                "Partial private files preserved; archive could not be sealed",
            )
            return
        digest = hashlib.sha256()
        with archive.open("rb") as stream:
            while chunk := stream.read(65536):
                digest.update(chunk)
        ctx.report["evidence"].append(
            {
                "id": "mssql-archive",
                "file": str(archive.relative_to(ctx.store.root)),
                "source": "mssql-export",
                "host": ctx.settings["HOST"],
                "private_raw": True,
                "bytes": archive.stat().st_size,
                "sha256": digest.hexdigest(),
            }
        )
        shutil.rmtree(private_root)


def export_path(root, filename):
    if not re.fullmatch(r"[A-Za-z0-9_.-]+--[0-9a-f]{16}\.jsonl", filename):
        raise MSSQLError("Unsafe archive member metadata")
    return Path(root) / filename


def reconcile_exports(root, state, config):
    """Recover only complete bounded JSONL records after an interrupted worker."""
    total, changed = 0, False
    for record in state["tables"]:
        filename = record.get("file")
        if not filename:
            continue
        count, clipped, complete_bytes, repaired = 0, 0, 0, False
        try:
            descriptor = os.open(export_path(root, filename), os.O_RDWR | os.O_NOFOLLOW)
            with os.fdopen(descriptor, "r+b") as stream:
                info = os.fstat(stream.fileno())
                if (
                    not stat.S_ISREG(info.st_mode)
                    or info.st_mode & 0o077
                    or info.st_uid != os.geteuid()
                ):
                    raise MSSQLError("Unsafe private export member")
                limit = min(config["max_rows"], record["actual_count"])
                columns = {column["name"] for column in record["columns"]}
                while encoded := stream.readline(config["max_row_bytes"] + 1):
                    if (
                        not encoded.endswith(b"\n")
                        or len(encoded) > config["max_row_bytes"]
                        or count >= limit
                        or total + complete_bytes + len(encoded) > config["data_limit"]
                    ):
                        repaired = True
                        break
                    try:
                        row = parse_json(encoded)
                        if not isinstance(row, dict) or set(row) != columns:
                            raise MSSQLError("Malformed private export row")
                    except MSSQLError:
                        repaired = True
                        break
                    count += 1
                    complete_bytes += len(encoded)
                    clipped += sum(
                        isinstance(value, dict) and value.get("truncated") is True
                        for value in row.values()
                    )
                if repaired:
                    stream.truncate(complete_bytes)
        except (OSError, ValueError, TypeError, KeyError):
            record.pop("file", None)
            record.update(status="recovery_failed", truncated=True, exported_count=0)
            state["errors"].append(
                {"error": "recovery_failed", "detail": "Private table output was unavailable"}
            )
            changed = True
            continue
        total += complete_bytes
        if repaired or count != record["exported_count"] or record["status"] == "running":
            record.update(status="partial", truncated=True)
            changed = True
        record.update(exported_count=count, truncated_cells=clipped)
    state["bytes_exported"] = total
    if changed:
        state["completed"] = False
        if not any(error["error"] == "partial_export" for error in state["errors"]):
            state["errors"].append(
                {
                    "error": "partial_export",
                    "detail": "Complete private rows recovered after interruption",
                }
            )


def seal_archive(root, state, maximum):
    root = Path(root)
    target = root.parent / "mssql-export.zip"
    descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    written = 0
    try:
        with (
            os.fdopen(descriptor, "w+b") as stream,
            zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_STORED) as archive,
        ):
            manifest = json.dumps(state, ensure_ascii=True, allow_nan=False, indent=2).encode()
            archive.writestr(zip_member("manifest.json"), manifest)
            written += len(manifest)
            for record in state["tables"]:
                filename = record.get("file")
                if not filename:
                    continue
                path = export_path(root, filename)
                if path.is_symlink() or not path.is_file() or not stat.S_ISREG(path.stat().st_mode):
                    raise MSSQLError("Private export member is unavailable")
                with (
                    path.open("rb") as source,
                    archive.open(zip_member("tables/" + filename), "w") as sink,
                ):
                    while chunk := source.read(65536):
                        written += len(chunk)
                        if written > maximum:
                            raise MSSQLError("Private archive byte limit reached")
                        sink.write(chunk)
        if target.stat().st_size > maximum:
            raise MSSQLError("Private archive byte limit reached")
        return target
    except BaseException:
        target.unlink(missing_ok=True)
        raise


def zip_member(name):
    member = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
    member.external_attr = (stat.S_IFREG | 0o600) << 16
    return member
