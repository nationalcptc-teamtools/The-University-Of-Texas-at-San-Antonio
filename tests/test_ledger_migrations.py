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
    db.execute('INSERT INTO reservations VALUES (?,?,?,?,?,?,?,?,?,?)',
               ('e','d','old-action','w','https://192.0.2.10:443','realm','flow',json.dumps(asdict(Bounds(request_limit=2,auth_posts=1))),'complete','{}'))
    return db


def test_additive_migration_is_idempotent_and_preserves_old_rows():
    db = old_database(); before = db.execute('SELECT * FROM reservations').fetchall()
    ensure_ledger_schema(db)
    scopes = db.execute('SELECT * FROM reservation_scopes ORDER BY scope_kind,counter').fetchall()
    assert len(scopes) == 36
    assert db.execute("SELECT reserved,ceiling FROM reservation_scopes WHERE scope_kind='realm' AND counter='auth_posts'").fetchone() == (1,None)
    assert db.execute("SELECT reserved FROM reservation_scopes WHERE scope_kind='target' AND counter='request_limit'").fetchone() == (2,)
    ensure_ledger_schema(db)
    assert db.execute('SELECT * FROM reservations').fetchall() == before
    assert db.execute('SELECT * FROM reservation_scopes ORDER BY scope_kind,counter').fetchall() == scopes
    assert db.execute('SELECT COUNT(*) FROM ledger_schema_migrations').fetchone() == (1,)


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
