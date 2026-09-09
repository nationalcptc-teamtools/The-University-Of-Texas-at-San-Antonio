"""Additive metadata must not change historical reservation charges or policy hashes."""
import json
import sqlite3
from dataclasses import asdict
import pytest
from cptc_harness.contracts import Bounds, BudgetLimit, PolicyError, PolicySnapshot, ScopeSpec, digest
from cptc_harness.migrations import ensure_ledger_schema
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
    assert db.execute('SELECT COUNT(*) FROM ledger_schema_migrations').fetchone() == (2,)
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
        DELETE FROM ledger_schema_migrations WHERE version=2;
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
    assert db.execute('SELECT version FROM ledger_schema_migrations ORDER BY version').fetchall() == [(1,), (2,)]


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
