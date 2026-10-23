"""Read-only, bounded MSSQL export worker; credentials never enter argv or diagnostics.

Impacket's official tds.py login API takes useWindowsAuth as its sixth argument.
Older supported releases return ambiguous NULL/text and binary/decimal values, so
data projections carry explicit NULL flags and bounded server-side conversions.
"""

import base64
import contextlib
import hashlib
import inspect
import json
import logging
import math
import os
import re
import signal
import socket
import stat
import sys
import time
from datetime import date, datetime
from datetime import time as datetime_time
from decimal import Decimal
from pathlib import Path

from fieldkit.core.assessment import write_private
from fieldkit.core.storage import safe_label


class MSSQLError(ValueError):
    """Only fixed diagnostics are exposed to the caller."""


class QueryLimit(MSSQLError):
    pass


class ResponseLimit(QueryLimit):
    pass


class DependencyUnavailable(MSSQLError):
    pass


def private_json(filename, maximum=65536):
    try:
        descriptor = os.open(
            Path(filename).expanduser(), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
        )
        with os.fdopen(descriptor, "rb") as stream:
            info = os.fstat(stream.fileno())
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_mode & 0o077
                or info.st_uid != os.geteuid()
            ):
                raise MSSQLError("MSSQL input files must be owner-only regular files (chmod 600)")
            content = stream.read(maximum + 1)
        if len(content) > maximum:
            raise MSSQLError("MSSQL input file exceeds its limit")
        return parse_json(content)
    except OSError as exc:
        raise MSSQLError("Cannot safely read the private MSSQL input file") from exc


def parse_json(content):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise MSSQLError("Duplicate MSSQL input member")
            result[key] = value
        return result

    try:
        return json.loads(content, object_pairs_hook=pairs)
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise MSSQLError("Invalid private MSSQL JSON input") from exc


def identifier(value):
    if not isinstance(value, str) or not 1 <= len(value) <= 128 or any(ord(c) < 32 for c in value):
        raise MSSQLError("MSSQL identifiers must be nonempty bounded strings without controls")
    return value


def quote_identifier(value):
    return "[" + identifier(value).replace("]", "]]") + "]"


def literal(value):
    return "N'" + identifier(value).replace("'", "''") + "'"


def credentials(value):
    if not isinstance(value, dict) or set(value) - {"domain", "username", "password", "hashes"}:
        raise MSSQLError("Credentials support domain, username and password or NTLM hashes")
    if not isinstance(value.get("username"), str) or not 1 <= len(value["username"]) <= 256:
        raise MSSQLError("Private MSSQL credentials require a bounded username")
    if not isinstance(value.get("domain", ""), str) or len(value.get("domain", "")) > 256:
        raise MSSQLError("Private MSSQL domain must be a bounded string")
    if ("password" in value) == ("hashes" in value):
        raise MSSQLError("Supply exactly one private password or NTLM hash pair")
    if "password" in value and (
        not isinstance(value["password"], str) or len(value["password"]) > 4096
    ):
        raise MSSQLError("Private MSSQL password exceeds its limit")
    if "hashes" in value and (
        not isinstance(value["hashes"], str)
        or not re.fullmatch(r"[a-fA-F0-9]{0,32}:[a-fA-F0-9]{32}", value["hashes"])
        or len(value["hashes"].partition(":")[0]) not in {0, 32}
    ):
        raise MSSQLError("Private NTLM hashes require LMHASH:NTHASH hexadecimal format")
    return value


def scalar(value):
    """Lossless native values for fake/future adapters, never a string repr fallback."""
    if value is None or type(value) in {str, int, bool}:
        return value
    if isinstance(value, (bytes, bytearray, memoryview)):
        return {"type": "binary", "base64": base64.b64encode(bytes(value)).decode()}
    if isinstance(value, Decimal):
        if not value.is_finite():
            raise MSSQLError("Unsupported nonfinite database value")
        return {"type": "decimal", "value": str(value)}
    if isinstance(value, (datetime, date, datetime_time)):
        return {"type": type(value).__name__, "value": value.isoformat()}
    if type(value) is float and math.isfinite(value):
        return {"type": "float", "value": repr(value)}
    raise MSSQLError("Unsupported database value type")


def converted_value(value, sql_type):
    if isinstance(value, bytes):
        value = value.decode("utf-8", errors="strict")
    if not isinstance(value, str):
        return scalar(value)
    if sql_type in {"binary", "varbinary", "image", "timestamp", "rowversion"}:
        try:
            return {"type": "binary", "base64": base64.b64encode(bytes.fromhex(value)).decode()}
        except ValueError as exc:
            raise MSSQLError("Malformed converted binary value") from exc
    if sql_type in {"bigint", "int", "smallint", "tinyint"}:
        return int(value)
    if sql_type == "bit":
        if value not in {"0", "1"}:
            raise MSSQLError("Malformed converted boolean value")
        return value == "1"
    if sql_type in {
        "decimal",
        "numeric",
        "money",
        "smallmoney",
        "float",
        "real",
        "date",
        "datetime",
        "smalldatetime",
        "datetime2",
        "datetimeoffset",
        "time",
    }:
        return {"type": sql_type, "value": value}
    return value


def projection(columns, maximum):
    expressions = []
    for index, column in enumerate(columns):
        name, sql_type = quote_identifier(column["name"]), column["type"].lower()
        width = maximum
        if sql_type in {"binary", "varbinary", "image", "timestamp", "rowversion"}:
            source = f"CONVERT(varchar(max), CONVERT(varbinary(max), {name}), 2)"
            width -= width % 2
        elif sql_type in {
            "date",
            "datetime",
            "smalldatetime",
            "datetime2",
            "datetimeoffset",
            "time",
        }:
            source = f"CONVERT(nvarchar(64), {name}, 127)"
        elif sql_type in {"float", "real"}:
            source = f"CONVERT(nvarchar(64), {name}, 3)"
        elif sql_type in {"money", "smallmoney"}:
            source = f"CONVERT(nvarchar(64), {name}, 2)"
        else:
            source = f"CONVERT(nvarchar(max), {name})"
        expressions.extend(
            [
                f"CONVERT(nvarchar({maximum}), LEFT({source}, {width})) AS [fk_v{index:03d}]",
                f"CASE WHEN {name} IS NULL THEN 1 ELSE 0 END AS [fk_n{index:03d}]",
                f"CASE WHEN DATALENGTH(CONVERT(nvarchar(max), {source})) > {width * 2} "
                f"THEN 1 ELSE 0 END AS [fk_t{index:03d}]",
            ]
        )
    return ", ".join(expressions)


def decode_row(row, columns):
    if not isinstance(row, dict):
        raise MSSQLError("Unsupported database row layout")
    output, truncated = {}, 0
    for index, column in enumerate(columns):
        null, clipped = row[f"fk_n{index:03d}"], row[f"fk_t{index:03d}"]
        if null not in {0, 1} or clipped not in {0, 1}:
            raise MSSQLError("Malformed database value flags")
        value = None if null else converted_value(row[f"fk_v{index:03d}"], column["type"].lower())
        if clipped:
            value = {"value": value, "truncated": True}
            truncated += 1
        output[column["name"]] = value
    return output, truncated


class ImpacketAdapter:
    def __init__(self, config, credential, factory=None):
        if factory is None:
            try:
                from impacket.tds import MSSQL
            except ImportError as exc:
                raise DependencyUnavailable(
                    "Optional MSSQL dependency unavailable; install Fieldkit's mssql extra"
                ) from exc
            factory = MSSQL
        self.config, self.credential = config, credential
        self.client = factory(config["host"], port=config["port"])
        self.received = 0
        if hasattr(self.client, "socketRecv"):
            original = self.client.socketRecv

            def bounded_receive(size):
                result = original(min(size, 65536))
                self.received += len(result)
                if self.received > config["max_query_bytes"]:
                    raise ResponseLimit("MSSQL query response byte limit reached")
                return result

            self.client.socketRecv = bounded_receive

    def connect(self):
        socket.setdefaulttimeout(self.config["timeout"])
        if "timeout" in inspect.signature(self.client.connect).parameters:
            self.client.connect(timeout=self.config["timeout"])
        else:
            self.client.connect()
        if getattr(self.client, "socket", None):
            self.client.socket.settimeout(self.config["timeout"])
        # Compatible with official Impacket 0.12 and later; sixth argument is Windows auth.
        if not self.client.login(
            self.config["databases"][0],
            self.credential["username"],
            self.credential.get("password", ""),
            self.credential.get("domain", ""),
            self.credential.get("hashes"),
            True,
        ):
            raise MSSQLError("MSSQL Windows authentication failed")

    def query(self, query):
        if not query.startswith("SELECT "):
            raise MSSQLError("Only generated read-only SELECT statements are supported")
        self.received = 0
        rows = self.client.sql_query(query)
        # 0.12 sets lastError only in printReplies; inspect ERROR tokens without printing.
        if getattr(self.client, "lastError", False) or 0xAA in (
            getattr(self.client, "replies", {}) or {}
        ):
            raise MSSQLError("MSSQL read-only query failed")
        if not isinstance(rows, list):
            raise MSSQLError("MSSQL returned an unsupported result")
        return rows

    def close(self):
        self.client.disconnect()


def execute_export(config, credential, root, adapter_factory=ImpacketAdapter, clock=time.monotonic):
    """Persist metadata checkpoints and private JSONL; the parent seals the archive."""
    root = Path(root)
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    deadline = clock() + config["budget"]
    state = {
        "schema_version": 1,
        "authentication": "windows_ntlm",
        "inventory": [],
        "tables": [],
        "errors": [],
        "bytes_exported": 0,
        "completed": False,
        "row_selection": "unordered sample; concurrent changes possible; bounded by observed count",
    }
    state_path = root / "manifest.json"

    def save():
        encoded = json.dumps(state, ensure_ascii=True, allow_nan=False).encode()
        if len(encoded) > config["max_metadata_bytes"]:
            raise QueryLimit("MSSQL metadata byte limit reached")
        temporary = root / ".manifest.tmp"
        write_private(temporary, encoded)
        temporary.replace(state_path)

    def query(sql):
        if clock() >= deadline:
            raise TimeoutError("MSSQL worker deadline reached")
        rows = adapter.query(sql)
        if clock() >= deadline:
            raise TimeoutError("MSSQL worker deadline reached")
        return rows

    adapter = None
    try:
        save()
        adapter = adapter_factory(config, credential)
        adapter.connect()
        databases = query(
            "SELECT name FROM sys.databases WHERE state = 0 AND name IN ("
            + ", ".join(literal(name) for name in config["databases"])
            + ") ORDER BY name"
        )
        known = {identifier(row["name"]) for row in databases}
        if set(config["databases"]) - known:
            raise MSSQLError("Selected database is absent from accessible database inventory")
        known_tables = {}
        for database in config["databases"]:
            base = quote_identifier(database)
            schemas = query(
                f"SELECT TOP ({config['max_tables'] + 1}) name "
                f"FROM {base}.sys.schemas ORDER BY name"
            )
            wanted = [item for item in config["tables"] if item["database"] == database]
            where = ""
            if wanted and not config["inventory_only"]:
                where = (
                    " AND ("
                    + " OR ".join(
                        f"(s.name = {literal(item['schema'])} "
                        f"AND t.name = {literal(item['table'])})"
                        for item in wanted
                    )
                    + ")"
                )
            tables = query(
                f"SELECT TOP ({config['max_tables'] + 1}) s.name AS schema_name, "
                f"t.name AS table_name, t.object_id FROM {base}.sys.tables AS t "
                f"JOIN {base}.sys.schemas AS s ON s.schema_id = t.schema_id "
                f"WHERE t.is_ms_shipped = 0{where} ORDER BY s.name, t.name"
            )
            inventory = {
                "database": database,
                "schemas": [identifier(row["name"]) for row in schemas[: config["max_tables"]]],
                "schemas_truncated": len(schemas) > config["max_tables"],
                "tables": [],
                "tables_truncated": len(tables) > config["max_tables"],
            }
            for row in tables[: config["max_tables"]]:
                schema, table = identifier(row["schema_name"]), identifier(row["table_name"])
                object_id = row["object_id"]
                if type(object_id) is not int or not 1 <= object_id <= 2147483647:
                    raise MSSQLError("Malformed table inventory identifier")
                known_tables[(database, schema, table)] = object_id
                inventory["tables"].append({"schema": schema, "table": table})
            state["inventory"].append(inventory)
            save()
        if config["inventory_only"]:
            state["completed"] = True
            return state
        if any(
            (item["database"], item["schema"], item["table"]) not in known_tables
            for item in config["tables"]
        ):
            raise MSSQLError("Selected table is absent from validated database inventory")
        for item in config["tables"]:
            database, schema, table = item["database"], item["schema"], item["table"]
            record = {
                **item,
                "actual_count": None,
                "exported_count": 0,
                "columns": [],
                "truncated": False,
                "truncated_cells": 0,
                "status": "running",
            }
            state["tables"].append(record)
            save()
            try:
                base = quote_identifier(database)
                object_id = known_tables[(database, schema, table)]
                columns = query(
                    f"SELECT TOP ({config['max_columns'] + 1}) c.name AS column_name, "
                    f"ty.name AS type_name, c.column_id, "
                    f"CONVERT(int, c.is_nullable) AS is_nullable FROM {base}.sys.columns AS c "
                    f"JOIN {base}.sys.types AS ty ON c.user_type_id = ty.user_type_id "
                    f"WHERE c.object_id = {object_id} ORDER BY c.column_id"
                )
                if not columns or len(columns) > config["max_columns"]:
                    raise QueryLimit("MSSQL column limit reached")
                record["columns"] = [
                    {
                        "name": identifier(row["column_name"]),
                        "type": identifier(row["type_name"]),
                        "nullable": bool(row["is_nullable"]),
                    }
                    for row in columns
                ]
                if len({column["name"] for column in record["columns"]}) != len(columns):
                    raise MSSQLError("Ambiguous exported column names")
                qualified = ".".join(quote_identifier(value) for value in (database, schema, table))
                count_rows = query(f"SELECT COUNT_BIG(*) AS row_count FROM {qualified}")
                count = count_rows[0]["row_count"] if len(count_rows) == 1 else None
                if type(count) is not int or count < 0:
                    raise MSSQLError("Malformed COUNT_BIG result")
                record["actual_count"] = count
                limit = min(config["max_rows"], count)
                record["truncated"] = count > limit
                fingerprint = hashlib.sha256(
                    json.dumps([database, schema, table]).encode()
                ).hexdigest()[:16]
                filename = safe_label(schema + "_" + table, 48) + "--" + fingerprint + ".jsonl"
                record["file"] = filename
                descriptor = os.open(
                    root / filename, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600
                )
                with os.fdopen(descriptor, "wb") as stream:
                    save()
                    rows = (
                        query(
                            f"SELECT TOP ({limit}) "
                            f"{projection(record['columns'], config['max_value_chars'])} "
                            f"FROM {qualified}"
                        )
                        if limit
                        else []
                    )
                    for row in rows[:limit]:
                        if clock() >= deadline:
                            raise TimeoutError("MSSQL worker deadline reached")
                        value, clipped = decode_row(row, record["columns"])
                        encoded = (
                            json.dumps(
                                value, ensure_ascii=True, allow_nan=False, separators=(",", ":")
                            ).encode()
                            + b"\n"
                        )
                        if (
                            len(encoded) > config["max_row_bytes"]
                            or state["bytes_exported"] + len(encoded) > config["data_limit"]
                        ):
                            record.update(truncated=True, status="byte_limit")
                            break
                        stream.write(encoded)
                        stream.flush()
                        record["exported_count"] += 1
                        record["truncated_cells"] += clipped
                        state["bytes_exported"] += len(encoded)
                        save()
                record["truncated"] |= record["exported_count"] < count or bool(
                    record["truncated_cells"]
                )
                if record["status"] == "running":
                    record["status"] = "exported"
            except (TimeoutError, KeyboardInterrupt):
                record.update(status="deadline", truncated=True)
                raise
            except ResponseLimit:
                record.update(status="response_limit", truncated=True)
                raise
            except QueryLimit:
                record.update(status="limit", truncated=True)
                state["errors"].append({"error": "table_limit", "table": dict(item)})
            except Exception:
                record.update(status="failed", truncated=True)
                state["errors"].append({"error": "table_export_failed", "table": dict(item)})
            save()
        state["completed"] = not state["errors"] and all(
            record["status"] == "exported" for record in state["tables"]
        )
    except (TimeoutError, KeyboardInterrupt):
        state["errors"].append(
            {"error": "deadline", "detail": "Partial MSSQL inventory/export preserved"}
        )
    except DependencyUnavailable:
        state["errors"].append(
            {
                "error": "dependency_unavailable",
                "detail": "Optional MSSQL dependency unavailable; install Fieldkit's mssql extra",
            }
        )
    except MSSQLError:
        state["errors"].append(
            {
                "error": "mssql_validation_or_permission",
                "detail": "MSSQL input, permission, byte-limit or result validation failed",
            }
        )
    except Exception:
        state["errors"].append(
            {
                "error": "mssql_connection_or_inventory",
                "detail": "MSSQL connection or read-only inventory failed",
            }
        )
    finally:
        if adapter:
            try:
                adapter.close()
            except Exception:
                pass
        save()
    return state


def main():
    if len(sys.argv) != 2:
        return 2
    # Driver logging/tracebacks can contain data or credentials. This isolated worker is silent.
    logging.disable(logging.CRITICAL)
    with (
        open(os.devnull, "w") as sink,
        contextlib.redirect_stdout(sink),
        contextlib.redirect_stderr(sink),
    ):
        try:
            configuration = private_json(sys.argv[1], 262144)

            def terminate(_signum, _frame):
                raise KeyboardInterrupt

            signal.signal(signal.SIGTERM, terminate)
            state = execute_export(
                configuration["config"],
                credentials(configuration["credential"]),
                configuration["root"],
            )
            return 0 if state["completed"] else 1
        except BaseException:
            return 1


if __name__ == "__main__":
    raise SystemExit(main())
