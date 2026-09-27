"""Additive metadata must not change historical reservation charges or policy hashes."""
import json
import sqlite3
from dataclasses import asdict
import pytest
from cptc_harness.contracts import Bounds, BudgetLimit, PolicyError, PolicySnapshot, ScopeSpec, digest
from cptc_harness.migrations import _PROFILE_CONTINUATION_DDL, ensure_ledger_schema
from cptc_harness.policy import parse_policy, policy_hash


def old_database():
    db = sqlite3.connect(':memory:', isolation_level=None)
    db.execute('CREATE TABLE reservations(engagement,device,request_id,workspace,target,realm,workflow,bounds,state,usage)')
    legacy = asdict(Bounds(request_limit=2,auth_posts=1))
    for key in ('tcp_connects','udp_datagrams','protocol_requests','tx_bytes','rx_bytes'):
        legacy.pop(key)
    db.execute('INSERT INTO reservations VALUES (?,?,?,?,?,?,?,?,?,?)',
               ('e','d','old-action','w','https://192.0.2.10:443','realm','flow',json.dumps(legacy),'complete','{}'))
    return db


def test_additive_migration_is_idempotent_and_preserves_old_rows():
    db = old_database(); before = db.execute('SELECT * FROM reservations').fetchall()
    ensure_ledger_schema(db)
    scopes = db.execute('SELECT * FROM reservation_scopes ORDER BY scope_kind,counter').fetchall()
    assert len(scopes) == 66
    assert db.execute("SELECT reserved,ceiling FROM reservation_scopes WHERE scope_kind='realm' AND counter='auth_posts'").fetchone() == (1,None)
    assert db.execute("SELECT reserved FROM reservation_scopes WHERE scope_kind='target' AND counter='request_limit'").fetchone() == (2,)
    ensure_ledger_schema(db)
    assert db.execute('SELECT * FROM reservations').fetchall() == before
    assert db.execute('SELECT * FROM reservation_scopes ORDER BY scope_kind,counter').fetchall() == scopes
    assert db.execute('SELECT COUNT(*) FROM ledger_schema_migrations').fetchone() == (5,)
    attempt_columns = {row[1] for row in db.execute('PRAGMA table_info(reservation_attempt_events)')}
    assert {'tcp_connects','udp_datagrams','request_count'} <= attempt_columns


def test_schema_one_attempt_rows_gain_zeroed_transport_columns():
    db = old_database()
    ensure_ledger_schema(db)
    db.executescript('''
        DROP TABLE reservation_attempt_events;
        DROP TABLE reservation_attempts;
        CREATE TABLE reservation_attempts(
            engagement TEXT NOT NULL, device TEXT NOT NULL, request_id TEXT NOT NULL, attempt_id TEXT NOT NULL,
            request_count INTEGER NOT NULL, request_bytes INTEGER NOT NULL, response_bytes INTEGER NOT NULL,
            elapsed_ms INTEGER NOT NULL, deadline_ns INTEGER NOT NULL, started_ns INTEGER NOT NULL,
            deadline_exceeded INTEGER NOT NULL, state TEXT NOT NULL,
            PRIMARY KEY(engagement,device,request_id,attempt_id));
        CREATE TABLE reservation_attempt_events(
            engagement TEXT NOT NULL, device TEXT NOT NULL, request_id TEXT NOT NULL,
            attempt_id TEXT NOT NULL, event_id TEXT NOT NULL, request_bytes INTEGER NOT NULL,
            response_bytes INTEGER NOT NULL,
            PRIMARY KEY(engagement,device,request_id,attempt_id,event_id));
        DROP TABLE profile_reconciliations;
        DROP TABLE profile_continuations;
        DELETE FROM ledger_schema_migrations WHERE version>=2;
    ''')
    db.execute('INSERT INTO reservation_attempts VALUES (?,?,?,?,?,?,?,?,?,?,?,?)',
               ('e','d','old-action','attempt',1,12,34,5,100,10,0,'complete'))
    db.execute('INSERT INTO reservation_attempt_events VALUES (?,?,?,?,?,?,?)',
               ('e','d','old-action','attempt','event',12,34))

    ensure_ledger_schema(db)

    assert db.execute(
        'SELECT tcp_connects,udp_datagrams,request_count,request_bytes,response_bytes '
        'FROM reservation_attempts WHERE attempt_id="attempt"'
    ).fetchone() == (0, 0, 1, 12, 34)
    assert db.execute(
        'SELECT tcp_connects,udp_datagrams,request_count,request_bytes,response_bytes '
        'FROM reservation_attempt_events WHERE event_id="event"'
    ).fetchone() == (0, 0, 0, 12, 34)
    assert db.execute('SELECT version FROM ledger_schema_migrations ORDER BY version').fetchall() == [(1,), (2,), (3,), (4,), (5,)]


def test_schema_two_gains_additive_profile_metadata_tables():
    db = old_database()
    ensure_ledger_schema(db)
    before = db.execute('SELECT * FROM reservations').fetchall()
    db.execute('DELETE FROM ledger_schema_migrations WHERE version>=3')
    db.execute('DROP TABLE profile_reconciliations')
    db.execute('DROP TABLE profile_continuations')

    ensure_ledger_schema(db)

    assert db.execute('SELECT * FROM reservations').fetchall() == before
    assert db.execute(
        'SELECT version FROM ledger_schema_migrations ORDER BY version'
    ).fetchall() == [(1,), (2,), (3,), (4,), (5,)]
    columns = {
        row[1] for row in db.execute('PRAGMA table_info(profile_reconciliations)')
    }
    assert columns == {
        'engagement', 'device', 'predecessor_action_id', 'predecessor_plan_id',
        'predecessor_plan_sha256', 'successor_action_id', 'successor_plan_id',
        'successor_plan_sha256', 'reconciliation_sha256', 'reason_code',
        'reservation_absent', 'attempt_absent', 'target_traffic_absent',
        'reconciled_at', 'reconciled_monotonic_ns',
    }


def test_schema_three_gains_only_the_additive_profile_continuation_table():
    db = old_database()
    ensure_ledger_schema(db)
    db.execute('CREATE TABLE stops(engagement TEXT PRIMARY KEY, reason TEXT NOT NULL)')
    db.execute(
        "UPDATE reservations SET state='uncertain',usage='{}' WHERE request_id='old-action'"
    )
    db.execute(
        """INSERT INTO reservation_attempts(
               engagement,device,request_id,attempt_id,tcp_connects,
               udp_datagrams,request_count,request_bytes,response_bytes,
               elapsed_ms,deadline_ns,started_ns,deadline_exceeded,state)
           VALUES ('e','d','old-action','attempt',0,0,0,0,0,1,2,1,0,'uncertain')"""
    )
    db.execute("INSERT INTO stops VALUES ('e','transport outcome uncertain')")
    db.execute(
        """INSERT INTO profile_reconciliations(
               engagement,device,predecessor_action_id,predecessor_plan_id,
               predecessor_plan_sha256,successor_action_id,successor_plan_id,
               successor_plan_sha256,reconciliation_sha256,reason_code,
               reservation_absent,attempt_absent,target_traffic_absent,
               reconciled_at,reconciled_monotonic_ns)
           VALUES ('e','d','spent-action','plan-v1',?, 'old-action','plan-v2',
                   ?,?,'clock-source-unavailable',1,1,1,
                   '2026-09-10T00:00:00.000000Z',1)""",
        ('1' * 64, '2' * 64, '3' * 64),
    )
    preserved_tables = (
        'reservations',
        'reservation_scopes',
        'reservation_attempts',
        'reservation_attempt_events',
        'profile_reconciliations',
        'stops',
    )
    before = {
        table: db.execute(f'SELECT * FROM {table} ORDER BY rowid').fetchall()
        for table in preserved_tables
    }
    db.execute('DELETE FROM ledger_schema_migrations WHERE version>=4')
    db.execute('DROP TABLE profile_continuations')

    ensure_ledger_schema(db)

    after = {
        table: db.execute(f'SELECT * FROM {table} ORDER BY rowid').fetchall()
        for table in preserved_tables
    }
    assert after == before
    assert db.execute(
        'SELECT version FROM ledger_schema_migrations ORDER BY version'
    ).fetchall() == [(1,), (2,), (3,), (4,), (5,)]
    columns = {
        row[1] for row in db.execute('PRAGMA table_info(profile_continuations)')
    }
    assert columns == {
        'predecessor_engagement', 'predecessor_device',
        'predecessor_reconciled_action_id',
        'predecessor_action_id',
        'predecessor_plan_id', 'predecessor_plan_sha256',
        'predecessor_release_manifest_sha256',
        'predecessor_profile_worker_sha256',
        'predecessor_broker_worker_sha256',
        'predecessor_audit_chain_tail_sha256',
        'predecessor_audit_snapshot_sha256',
        'predecessor_reconciliation_sha256',
        'predecessor_reconciliation_reason',
        'predecessor_raw_failure_stage', 'predecessor_stage',
        'predecessor_attempt_count', 'predecessor_observed_tcp_connects',
        'predecessor_possible_tcp_connects',
        'predecessor_charged_tcp_connects',
        'predecessor_observed_udp_datagrams',
        'predecessor_charged_udp_datagrams',
        'predecessor_observed_protocol_requests',
        'predecessor_charged_protocol_requests',
        'predecessor_observed_tx_bytes', 'predecessor_charged_tx_bytes',
        'predecessor_observed_rx_bytes', 'predecessor_charged_rx_bytes',
        'predecessor_evidence_bytes', 'predecessor_first_byte_at',
        'predecessor_wire_event_count', 'predecessor_outcome',
        'predecessor_cleanup_status', 'predecessor_stop_reason',
        'successor_engagement',
        'successor_device', 'successor_workspace', 'successor_target',
        'successor_workflow', 'successor_action_id', 'successor_plan_id',
        'successor_plan_sha256', 'predecessor_proof_sha256', 'created_at',
    }


def _presplit_v4_ddl() -> str:
    return (
        _PROFILE_CONTINUATION_DDL.replace(
            "        predecessor_reconciled_action_id TEXT NOT NULL,\n", ""
        )
        .replace(
            "        predecessor_profile_worker_sha256 TEXT NOT NULL,\n"
            "        predecessor_broker_worker_sha256 TEXT NOT NULL,\n",
            "        predecessor_worker_sha256 TEXT NOT NULL,\n",
        )
    )


def test_empty_presplit_v4_table_is_rebuilt_by_additive_v5_migration():
    db = old_database()
    ensure_ledger_schema(db)
    db.execute("DELETE FROM ledger_schema_migrations WHERE version=5")
    db.execute("DROP TABLE profile_continuations")
    db.execute(_presplit_v4_ddl())

    ensure_ledger_schema(db)

    columns = {
        row[1] for row in db.execute("PRAGMA table_info(profile_continuations)")
    }
    assert "predecessor_worker_sha256" not in columns
    assert {
        "predecessor_reconciled_action_id",
        "predecessor_profile_worker_sha256",
        "predecessor_broker_worker_sha256",
    } <= columns
    assert db.execute(
        "SELECT version FROM ledger_schema_migrations ORDER BY version"
    ).fetchall() == [(1,), (2,), (3,), (4,), (5,)]


@pytest.mark.parametrize("schema_version", (4, 5))
@pytest.mark.parametrize(
    "old,new",
    (
        ("predecessor_attempt_count INTEGER NOT NULL", "predecessor_attempt_count TEXT NOT NULL"),
        ("CHECK(predecessor_attempt_count = 1)", "CHECK(predecessor_attempt_count >= 0)"),
        (
            "PRIMARY KEY(predecessor_engagement,predecessor_action_id)",
            "PRIMARY KEY(predecessor_action_id,predecessor_engagement)",
        ),
        (
            "UNIQUE(successor_engagement,successor_action_id)",
            "UNIQUE(successor_engagement,predecessor_action_id)",
        ),
    ),
)
def test_v5_migration_rejects_malformed_schema_lookalikes_without_advancing_history(
    schema_version, old, new
):
    db = old_database()
    ensure_ledger_schema(db)
    db.execute("DELETE FROM ledger_schema_migrations WHERE version=5")
    db.execute("DROP TABLE profile_continuations")
    ddl = _presplit_v4_ddl() if schema_version == 4 else _PROFILE_CONTINUATION_DDL
    malformed = ddl.replace(old, new)
    assert malformed != ddl
    db.execute(malformed)
    before_sql = db.execute(
        "SELECT sql FROM sqlite_schema WHERE name='profile_continuations'"
    ).fetchone()[0]

    with pytest.raises(PolicyError, match="schema requires reviewed migration"):
        ensure_ledger_schema(db)

    assert db.execute(
        "SELECT version FROM ledger_schema_migrations ORDER BY version"
    ).fetchall() == [(1,), (2,), (3,), (4,)]
    assert db.execute(
        "SELECT sql FROM sqlite_schema WHERE name='profile_continuations'"
    ).fetchone()[0] == before_sql


def test_nonempty_presplit_v4_table_fails_closed_without_changing_history():
    db = old_database()
    ensure_ledger_schema(db)
    db.execute("DELETE FROM ledger_schema_migrations WHERE version=5")
    db.execute("DROP TABLE profile_continuations")
    db.execute(_presplit_v4_ddl())
    columns = [row[1] for row in db.execute("PRAGMA table_info(profile_continuations)")]
    values = {name: "value" for name in columns}
    for name in columns:
        if name.endswith("sha256"):
            values[name] = "a" * 64
    values.update(
        predecessor_raw_failure_stage=None,
        predecessor_stage="legacy_target_open_unacknowledged",
        predecessor_attempt_count=1,
        predecessor_observed_tcp_connects=0,
        predecessor_possible_tcp_connects=1,
        predecessor_charged_tcp_connects=1,
        predecessor_observed_udp_datagrams=0,
        predecessor_charged_udp_datagrams=0,
        predecessor_observed_protocol_requests=0,
        predecessor_charged_protocol_requests=0,
        predecessor_observed_tx_bytes=0,
        predecessor_charged_tx_bytes=0,
        predecessor_observed_rx_bytes=0,
        predecessor_charged_rx_bytes=0,
        predecessor_evidence_bytes=0,
        predecessor_first_byte_at=None,
        predecessor_wire_event_count=0,
        predecessor_outcome="uncertain",
        predecessor_cleanup_status="passed",
        predecessor_stop_reason="transport outcome uncertain",
    )
    placeholders = ",".join("?" for _ in columns)
    db.execute(
        f"INSERT INTO profile_continuations({','.join(columns)}) VALUES ({placeholders})",
        tuple(values[name] for name in columns),
    )
    before = db.execute("SELECT * FROM profile_continuations").fetchall()

    with pytest.raises(PolicyError, match="requires reviewed migration"):
        ensure_ledger_schema(db)

    assert db.execute("SELECT * FROM profile_continuations").fetchall() == before
    assert db.execute(
        "SELECT version FROM ledger_schema_migrations ORDER BY version"
    ).fetchall() == [(1,), (2,), (3,), (4,)]


def test_corrupt_historical_bounds_roll_back_the_entire_migration():
    db = old_database(); db.execute("UPDATE reservations SET bounds=?", ('{"request_limit":-1}',))
    before = db.execute('SELECT * FROM reservations').fetchall()
    with pytest.raises(PolicyError): ensure_ledger_schema(db)
    assert db.execute('SELECT * FROM reservations').fetchall() == before
    assert not db.execute("SELECT name FROM sqlite_master WHERE name='assessment_waves'").fetchall()


def test_policy_budget_validation_and_empty_policy_hash_compatibility():
    policy = PolicySnapshot('e','r','w','d','o',ScopeSpec())
    old = asdict(policy); old.pop('budget_limits')
    assert policy_hash(parse_policy(old)) == digest(old)
    value = asdict(policy)
    value['budget_limits'] = [asdict(BudgetLimit('device','d','auth_posts',2))]
    assert parse_policy(value).budget_limits[0].ceiling == 2
    value['budget_limits'] *= 2
    with pytest.raises(PolicyError): parse_policy(value)
    for scope,counter,ceiling in [('arbitrary','actions',1),('device','unknown',1),('device','actions',True),('realm','auth_posts',-1)]:
        with pytest.raises(PolicyError): BudgetLimit(scope,'d',counter,ceiling)
