"""Read-only SQL contracts, independent fake driver, private archives and deadlines."""

import base64
import io
import json
import os
import stat
import time
import zipfile
from datetime import date, datetime
from datetime import time as datetime_time
from decimal import Decimal

import pytest
from rich.console import Console

from fieldkit.core.mssql import (
    ImpacketAdapter,
    MSSQLError,
    ResponseLimit,
    credentials,
    decode_row,
    execute_export,
    private_json,
    projection,
    quote_identifier,
    scalar,
)
from fieldkit.modules.mssql_export import MSSQLExport, seal_archive

PASSWORD = "private-mssql-password-927351"
USER = "private-mssql-user-81234"
HASHES = "a" * 32 + ":" + "b" * 32
ROW_SECRET = "private-database-row-726341"


def private_file(tmp_path, name, value):
    path = tmp_path / name
    path.write_text(json.dumps(value))
    path.chmod(0o600)
    return str(path)


def configuration(**overrides):
    return {
        "host": "sql.fixture.test",
        "port": 1433,
        "databases": ["App"],
        "tables": [{"database": "App", "schema": "dbo", "table": "Customers"}],
        "inventory_only": False,
        "max_tables": 5,
        "max_rows": 2,
        "max_columns": 10,
        "max_value_chars": 4000,
        "max_query_bytes": 1048576,
        "max_row_bytes": 65536,
        "data_limit": 1048576,
        "max_metadata_bytes": 65536,
        "timeout": 2,
        "budget": 20,
        **overrides,
    }


def credential(**overrides):
    return {"domain": "LAB", "username": USER, "password": PASSWORD, **overrides}


class FakeSQL:
    def __init__(self, config, credential, *, fail_table="", clock=None):
        self.config, self.credential = config, credential
        self.sql, self.closed, self.connected = [], False, False
        self.fail_table, self.clock = fail_table, clock

    def connect(self):
        self.connected = True

    def close(self):
        self.closed = True

    def query(self, sql):
        self.sql.append(sql)
        assert sql.startswith("SELECT ")
        if "FROM sys.databases" in sql:
            return [{"name": name} for name in self.config["databases"]]
        if ".sys.schemas ORDER" in sql:
            return [{"name": "dbo"}]
        if ".sys.tables AS" in sql:
            return [
                {
                    "schema_name": item["schema"],
                    "table_name": item["table"],
                    "object_id": 100 + index,
                }
                for index, item in enumerate(self.config["tables"])
            ]
        if ".sys.columns AS" in sql:
            return [
                {"column_name": "id", "type_name": "int", "column_id": 1, "is_nullable": 0},
                {"column_name": "name", "type_name": "nvarchar", "column_id": 2, "is_nullable": 1},
                {"column_name": "amount", "type_name": "decimal", "column_id": 3, "is_nullable": 0},
                {"column_name": "blob", "type_name": "varbinary", "column_id": 4, "is_nullable": 0},
            ]
        if "COUNT_BIG" in sql:
            if self.fail_table and quote_identifier(self.fail_table) in sql:
                raise RuntimeError("Driver failure " + PASSWORD + " " + ROW_SECRET)
            return [{"row_count": 7}]
        if "[fk_v000]" in sql:
            if self.clock is not None:
                self.clock[0] += 100
            rows = []
            for index in range(4):
                values = [
                    str(index),
                    ROW_SECRET if index == 0 else "NULL",
                    "1234567890.123456789",
                    "00ff",
                ]
                row = {}
                for column_index, value in enumerate(values):
                    row[f"fk_v{column_index:03d}"] = value
                    row[f"fk_n{column_index:03d}"] = int(column_index == 1 and index == 2)
                    row[f"fk_t{column_index:03d}"] = 0
                rows.append(row)
            return rows
        raise AssertionError("Unexpected generated SQL")


def test_engine_count_big_caps_types_and_selected_read_only_queries(tmp_path):
    config = configuration()
    fake = FakeSQL(config, credential())
    state = execute_export(config, credential(), tmp_path, lambda *_args: fake)
    assert fake.connected and fake.closed and state["completed"]
    table = state["tables"][0]
    assert table["actual_count"] == 7 and table["exported_count"] == 2 and table["truncated"]
    rows = [json.loads(line) for line in (tmp_path / table["file"]).read_text().splitlines()]
    assert rows[0]["id"] == 0 and rows[0]["name"] == ROW_SECRET
    assert rows[1]["name"] == "NULL"  # Literal text is not confused with TDS0.12 NULL sentinels.
    assert rows[0]["amount"] == {"type": "decimal", "value": "1234567890.123456789"}
    assert base64.b64decode(rows[0]["blob"]["base64"]) == b"\0\xff"
    assert all(sql.startswith("SELECT ") for sql in fake.sql)
    assert not any(PASSWORD in sql or USER in sql for sql in fake.sql)
    assert "TOP (2)" in fake.sql[-1]
    assert stat.S_IMODE((tmp_path / table["file"]).stat().st_mode) == 0o600


def test_inventory_only_never_queries_counts_or_rows(tmp_path):
    config = configuration(inventory_only=True)
    fake = FakeSQL(config, credential())
    state = execute_export(config, credential(), tmp_path, lambda *_args: fake)
    assert state["completed"] and state["inventory"][0]["tables"]
    assert not state["tables"] and not list(tmp_path.glob("*.jsonl"))
    assert not any("COUNT_BIG" in sql or "fk_v" in sql for sql in fake.sql)


def test_sql_identifier_quoting_and_inventory_validation(tmp_path):
    database, schema, table = "App]; DROP TABLE x;--", "d'bo", "user]data"
    config = configuration(
        databases=[database], tables=[{"database": database, "schema": schema, "table": table}]
    )
    fake = FakeSQL(config, credential())
    state = execute_export(config, credential(), tmp_path, lambda *_args: fake)
    assert state["completed"]
    assert quote_identifier(database) == "[App]]; DROP TABLE x;--]"
    assert "s.name = N'd''bo'" in fake.sql[2]
    assert ".[d'bo].[user]]data]" in fake.sql[-1]
    assert "/" not in state["tables"][0]["file"]
    fake = FakeSQL(config, credential())
    original = fake.query
    fake.query = lambda sql: [] if "sys.tables AS" in sql else original(sql)
    state = execute_export(config, credential(), tmp_path / "unknown", lambda *_args: fake)
    assert not state["completed"] and not state["tables"]
    assert not any("COUNT_BIG" in sql for sql in fake.sql)


def test_failed_table_still_seals_partial_archive_without_error_contents(tmp_path):
    tables = [{"database": "App", "schema": "dbo", "table": name} for name in ("Good", "Bad")]
    config = configuration(tables=tables)
    fake = FakeSQL(config, credential(), fail_table="Bad")
    state = execute_export(config, credential(), tmp_path / "data", lambda *_args: fake)
    assert not state["completed"] and [item["status"] for item in state["tables"]] == [
        "exported",
        "failed",
    ]
    archive = seal_archive(tmp_path / "data", state, 1048576)
    assert stat.S_IMODE(archive.stat().st_mode) == 0o600
    with zipfile.ZipFile(archive) as zipped:
        assert len(zipped.namelist()) == 2
        manifest = json.loads(zipped.read("manifest.json"))
        assert manifest["tables"][0]["exported_count"] == 2
        assert PASSWORD not in zipped.read("manifest.json").decode()
        assert ROW_SECRET not in zipped.read("manifest.json").decode()
        assert all(info.date_time == (1980, 1, 1, 0, 0, 0) for info in zipped.infolist())


def test_byte_and_deadline_caps_preserve_manifest(tmp_path):
    config = configuration(data_limit=1)
    fake = FakeSQL(config, credential())
    state = execute_export(config, credential(), tmp_path / "bytes", lambda *_args: fake)
    assert state["tables"][0]["status"] == "byte_limit"
    assert state["bytes_exported"] == 0 and state["tables"][0]["exported_count"] == 0
    clock = [0]
    config = configuration(budget=1)
    fake = FakeSQL(config, credential(), clock=clock)
    state = execute_export(
        config, credential(), tmp_path / "time", lambda *_args: fake, clock=lambda: clock[0]
    )
    assert fake.closed and state["tables"][0]["status"] == "deadline"
    assert state["tables"][0]["actual_count"] == 7
    assert private_json(tmp_path / "time" / "manifest.json")["errors"][0]["error"] == "deadline"


class FakeTDS:
    def __init__(self, address, port):
        self.address, self.port, self.calls = address, port, []
        self.socket = None
        self.replies, self.lastError = {}, False

    def connect(self):
        self.calls.append(("connect",))

    def login(self, *args):
        self.calls.append(("login", *args))
        return True

    def sql_query(self, query):
        self.calls.append(("query", query))
        return []

    def socketRecv(self, size):
        return b"x" * size

    def disconnect(self):
        self.calls.append(("close",))


@pytest.mark.parametrize(
    "auth", [credential(), {"domain": "LAB", "username": USER, "hashes": HASHES}]
)
def test_impacket_windows_auth_flag_hashes_and_error_tokens(auth):
    before_timeout = __import__("socket").getdefaulttimeout()
    try:
        adapter = ImpacketAdapter(configuration(max_query_bytes=32), auth, FakeTDS)
        adapter.connect()
        login = adapter.client.calls[1]
        assert login[-1] is True
        assert login[1:3] == ("App", USER)
        assert login[5] == auth.get("hashes")
        assert login[3] == auth.get("password", "")
        adapter.query("SELECT 1")
        adapter.client.replies = {0xAA: [{"MsgText": PASSWORD}]}
        with pytest.raises(MSSQLError, match="query failed"):
            adapter.query("SELECT 1")
        with pytest.raises(MSSQLError, match="read-only"):
            adapter.query("EXEC xp_cmdshell 'whoami'")
        with pytest.raises(ResponseLimit):
            adapter.client.socketRecv(64)
        adapter.close()
    finally:
        __import__("socket").setdefaulttimeout(before_timeout)


def test_native_serialization_and_null_flags():
    assert scalar(None) is None
    assert scalar(Decimal("12.3456789")) == {"type": "decimal", "value": "12.3456789"}
    for value in (date(2026, 10, 9), datetime(2026, 10, 9, 1, 2), datetime_time(1, 2, 3)):
        assert scalar(value)["value"] == value.isoformat()
    with pytest.raises(MSSQLError):
        scalar(object())
    columns = [{"name": "text", "type": "nvarchar"}, {"name": "data", "type": "varbinary"}]
    values, clipped = decode_row(
        {
            "fk_v000": "NULL",
            "fk_n000": 1,
            "fk_t000": 0,
            "fk_v001": "ff00",
            "fk_n001": 0,
            "fk_t001": 1,
        },
        columns,
    )
    assert values["text"] is None and clipped == 1
    assert base64.b64decode(values["data"]["value"]["base64"]) == b"\xff\0"
    sql = projection(columns, 3)
    assert "LEFT(CONVERT(varchar(max)" in sql and ", 2)) AS [fk_v001]" in sql


def module_settings(tmp_path, **overrides):
    return {
        **MSSQLExport().defaults(),
        "HOST": "sql.fixture.test",
        "DATABASES": ["App"],
        "OUTPUT": str(tmp_path / "runs"),
        "CREDENTIAL_FILE": private_file(tmp_path, "credentials.json", credential()),
        "TABLES_FILE": private_file(tmp_path, "tables.json", configuration()["tables"]),
        "INVENTORY_ONLY": False,
        "MAX_ROWS": 2,
        **overrides,
    }


def test_module_private_worker_config_archive_and_public_privacy(tmp_path, monkeypatch):
    seen = []

    async def fake_worker(argv, **kwargs):
        seen.extend(argv)
        settings = private_json(argv[-1], 262144)
        assert stat.S_IMODE(os.stat(argv[-1]).st_mode) == 0o600
        fake = FakeSQL(settings["config"], settings["credential"])
        state = execute_export(
            settings["config"], settings["credential"], settings["root"], lambda *_args: fake
        )
        kwargs["result"].reason = "finished"
        kwargs["result"].returncode = 0 if state["completed"] else 1

    monkeypatch.setattr("fieldkit.modules.mssql_export.run_process", fake_worker)
    output = io.StringIO()
    assert MSSQLExport().run(module_settings(tmp_path), Console(file=output)) == 0
    run = next((tmp_path / "runs").iterdir())
    report = json.loads((run / "report.json").read_text())
    assert report["completed"] and report["evidence"][0]["private_raw"]
    assert not (run / ".mssql-worker.json").exists()
    archive = run / report["evidence"][0]["file"]
    assert archive.is_file() and not (run / "private-raw" / "mssql").exists()
    public = output.getvalue() + (run / "report.json").read_text() + " ".join(seen)
    assert all(secret not in public for secret in (PASSWORD, USER, ROW_SECRET, HASHES))
    with zipfile.ZipFile(archive) as zipped:
        assert ROW_SECRET in zipped.read(zipped.namelist()[1]).decode()


@pytest.mark.parametrize("failure, expected_code", [(OSError, 1), (KeyboardInterrupt, 130)])
def test_partial_worker_config_is_deleted_when_serialization_fails(
    tmp_path, monkeypatch, failure, expected_code
):
    def interrupted_write(value, stream, *args, **kwargs):
        stream.write('{"credential":' + json.dumps(value["credential"]))
        stream.flush()
        config_path = next((tmp_path / "runs").glob("*/.mssql-worker.json"))
        assert PASSWORD in config_path.read_text()
        raise failure("Interrupted private configuration write")

    async def forbidden(*_args, **_kwargs):
        pytest.fail("Incomplete credential configuration started a worker")

    monkeypatch.setattr("fieldkit.modules.mssql_export.json.dump", interrupted_write)
    monkeypatch.setattr("fieldkit.modules.mssql_export.run_process", forbidden)
    code = MSSQLExport().run(module_settings(tmp_path), Console(file=io.StringIO()))
    assert code == expected_code
    run = next((tmp_path / "runs").iterdir())
    assert not (run / ".mssql-worker.json").exists()
    report = json.loads((run / "report.json").read_text())
    assert not report["completed"] and report["errors"]
    assert PASSWORD not in json.dumps(report)


def test_dry_run_credential_env_and_private_file_guards(tmp_path, monkeypatch):
    async def forbidden(*_args, **_kwargs):
        pytest.fail("Dry-run started a worker")

    monkeypatch.setattr("fieldkit.modules.mssql_export.run_process", forbidden)
    settings = module_settings(tmp_path, DRY_RUN=True, CREDENTIAL_FILE="")
    monkeypatch.setenv("MSSQL_PRIVATE", json.dumps(credential()))
    settings["CREDENTIAL_ENV"] = "MSSQL_PRIVATE"
    assert MSSQLExport().run(settings, Console(file=io.StringIO())) == 0
    report = json.loads(next((tmp_path / "runs").glob("*/report.json")).read_text())
    assert report["plan"]["connections"] == 0 and PASSWORD not in json.dumps(report)
    path = private_file(tmp_path, "public.json", credential())
    os.chmod(path, 0o644)
    with pytest.raises(MSSQLError, match="owner-only"):
        private_json(path)
    os.chmod(path, 0o600)
    (tmp_path / "link.json").symlink_to(path)
    with pytest.raises(MSSQLError, match="safely"):
        private_json(tmp_path / "link.json")


@pytest.mark.parametrize(
    "overrides",
    [
        {"HOST": "http://sql.test"},
        {"HOST": "user:pass@sql.test"},
        {"DATABASES": []},
        {"MAX_ROWS": 0},
        {"MAX_TABLES": 101},
        {"MAX_VALUE_CHARS": 4001},
        {"MAX_TOTAL_BYTES": 1024},
        {"TABLES_FILE": ""},
        {"CREDENTIAL_FILE": ""},
    ],
)
def test_module_requires_explicit_bounded_inputs(tmp_path, overrides):
    with pytest.raises(MSSQLError):
        MSSQLExport().validate(module_settings(tmp_path, **overrides))


def test_credentials_reject_literals_unknown_auth_and_ambiguous_sources():
    for value in (
        {"username": USER},
        {**credential(), "hashes": HASHES},
        {"username": USER, "hashes": "bad"},
        {**credential(), "kerberos": True},
    ):
        with pytest.raises(MSSQLError):
            credentials(value)


def test_installed_impacket_constructs_without_connecting():
    pytest.importorskip("impacket.tds")
    adapter = ImpacketAdapter(configuration(), credential())
    assert adapter.client.server == "sql.fixture.test"
    assert adapter.client.socket == 0


def test_real_worker_deadline_stops_blocking_driver_and_deletes_credentials(tmp_path, monkeypatch):
    package = tmp_path / "fake" / "impacket"
    package.mkdir(parents=True)
    (package / "__init__.py").write_text("")
    (package / "tds.py").write_text(
        "import time\nclass MSSQL:\n"
        " def __init__(self,*a,**k): self.socket=0\n"
        " def connect(self): time.sleep(60)\n"
        " def disconnect(self): pass\n"
    )
    source = str(__import__("pathlib").Path(__file__).resolve().parents[1] / "src")
    monkeypatch.setenv("PYTHONPATH", str(package.parent) + os.pathsep + source)
    started = time.monotonic()
    code = MSSQLExport().run(module_settings(tmp_path, BUDGET=0.3), Console(file=io.StringIO()))
    assert code == 1 and time.monotonic() - started < 3
    run = next((tmp_path / "runs").iterdir())
    assert not (run / ".mssql-worker.json").exists()
    report = json.loads((run / "report.json").read_text())
    assert not report["completed"] and report["errors"]
    assert PASSWORD not in json.dumps(report)
