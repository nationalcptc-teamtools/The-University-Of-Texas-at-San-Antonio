"""Scope limits must fail for consumed allowances, not incidental in-flight locks."""
from dataclasses import asdict
import json
import threading
import pytest
from cptc_harness.contracts import Bounds, BudgetLimit, PolicyError, RESOURCE_COUNTERS
from cptc_harness.ledger import Ledger


def ledger(tmp_path):
    tmp_path.mkdir(exist_ok=True); tmp_path.chmod(0o700)
    return Ledger(tmp_path, 'eng', 'device', policy_revision='v1')


def reserve(store, request, *, workspace='ws', target='target', realm='realm', workflow='flow', budgets=(), counter='request_limit'):
    values = {key: 0 for key in RESOURCE_COUNTERS}; values[counter] = 1
    return store.reserve(request, Bounds(**values), workspace_id=workspace, target_id=target,
                         auth_realm=realm, workflow_id=workflow, budget_limits=budgets)


def spent(store, scope, key, counter='request_limit'):
    return store._db.execute('SELECT COALESCE(SUM(reserved),0) FROM reservation_scopes WHERE scope_kind=? AND scope_key=? AND counter=?', (scope, key, counter)).fetchone()[0]


@pytest.mark.parametrize('scope,key,second', [
    ('target', 'target', {'workflow': 'other'}),
    ('realm', 'realm', {'target': 'other'}),
    ('workflow', 'flow', {'target': 'other', 'realm': 'other'}),
    ('workspace', 'ws', {'target': 'other', 'realm': 'other', 'workflow': 'other'}),
    ('device', 'device', {'target': 'other', 'realm': 'other', 'workspace': 'other', 'workflow': 'other'}),
    ('engagement', 'eng', {'target': 'other', 'realm': 'other', 'workspace': 'other', 'workflow': 'other'}),
])
@pytest.mark.parametrize('counter', RESOURCE_COUNTERS)
def test_scopes_charge_every_counter_across_finished_actions(tmp_path, scope, key, second, counter):
    store = ledger(tmp_path); limit = BudgetLimit(scope, key, counter, 1)
    reserve(store, 'one', budgets=(limit,), counter=counter); store.finish('one')
    before = store._db.execute('SELECT * FROM assignments').fetchall()
    with pytest.raises(PolicyError, match='durable scoped budget exhausted'):
        reserve(store, 'two', budgets=(limit,), counter=counter, **second)
    assert spent(store, scope, key, counter) == 1
    assert store._db.execute('SELECT COUNT(*) FROM reservations').fetchone()[0] == 1
    assert store._db.execute('SELECT COUNT(*) FROM reservation_scopes').fetchone()[0] == 6 * len(RESOURCE_COUNTERS)
    assert store._db.execute('SELECT * FROM assignments').fetchall() == before


@pytest.mark.parametrize('new_limits', [(), (BudgetLimit('device', 'device', 'request_limit', 9),)])
def test_persisted_ceiling_cannot_be_removed_or_widened(tmp_path, new_limits):
    store = ledger(tmp_path)
    reserve(store, 'one', budgets=(BudgetLimit('device', 'device', 'request_limit', 1),)); store.finish('one')
    store._db.close(); store = ledger(tmp_path)
    with pytest.raises(PolicyError, match='scoped budget'):
        reserve(store, 'two', workspace='new', target='new', realm='new', budgets=new_limits)
    assert spent(store, 'device', 'device') == 1


def test_independent_connections_reserve_atomically_without_incidental_locks(tmp_path):
    first, second = ledger(tmp_path), ledger(tmp_path)
    gate = threading.Barrier(2); outcomes = []; errors = []
    def run(store, key):
        try:
            gate.wait()
            reserve(store, key, workspace=key, target=key, realm=key, budgets=(BudgetLimit('device', 'device', 'request_limit', 1),))
            store.finish(key); outcomes.append('reserved')
        except PolicyError as exc:
            outcomes.append(str(exc))
        except BaseException as exc:
            errors.append(exc)
    threads = [threading.Thread(target=run, args=(store, str(i))) for i, store in enumerate((first, second))]
    for thread in threads: thread.start()
    for thread in threads: thread.join(timeout=10)
    assert not errors and not any(t.is_alive() for t in threads)
    assert sorted(outcomes) == ['durable scoped budget exhausted', 'reserved']
    assert spent(first, 'device', 'device') == 1


def historical(store, *, auth_posts=0, realm='realm'):
    values = asdict(Bounds(request_limit=1, auth_posts=auth_posts, output_bytes=0, process_limit=0))
    store._db.execute('INSERT INTO reservations VALUES (?,?,?,?,?,?,?,?,?,?)', ('eng', 'source-device', 'legacy', 'ws', 'target', realm, 'flow', json.dumps(values), 'complete', '{}'))


def test_same_connection_legacy_charges_are_backfilled_before_new_reservation(tmp_path):
    store = ledger(tmp_path); historical(store)
    with pytest.raises(PolicyError, match='scoped budget'):
        reserve(store, 'new', budgets=(BudgetLimit('target', 'target', 'request_limit', 1),))
    assert store.usage()['request_limit'] == 1
    reserve(store, 'allowed', target='other', realm='other', budgets=(BudgetLimit('engagement', 'eng', 'request_limit', 2),))
    assert spent(store, 'engagement', 'eng') == 2
    assert spent(store, 'target', 'target') == 1


def test_unattributed_legacy_authentication_blocks_new_realm_authentication(tmp_path):
    store = ledger(tmp_path); historical(store, auth_posts=1, realm='')
    with pytest.raises(PolicyError, match='unattributed historical authentication'):
        reserve(store, 'auth', target='other', realm='known', counter='auth_posts', budgets=(BudgetLimit('realm', 'known', 'auth_posts', 2),))
    assert store.usage()['auth_posts'] == 1
    reserve(store, 'observation', target='other', realm='known')
    assert spent(store, 'realm', '-', 'auth_posts') == 1


def test_duplicate_id_never_creates_another_charge(tmp_path):
    store = ledger(tmp_path); reserve(store, 'one'); store.finish('one')
    with pytest.raises(PolicyError, match='already reserved'): reserve(store, 'one')
    assert spent(store, 'engagement', 'eng') == 1


def test_model_charges_are_bound_to_workspace_scopes(tmp_path):
    store = ledger(tmp_path); limit = BudgetLimit('workspace', 'ws', 'model_calls', 1)
    store.charge('one', 'model_calls', 1, workspace_id='ws', budget_limits=(limit,))
    with pytest.raises(PolicyError, match='scoped budget'):
        store.charge('two', 'model_calls', 1, workspace_id='ws', workflow_id='other')
    assert spent(store, 'workspace', 'ws', 'model_calls') == 1


def test_transport_remaining_uses_the_target_scope_across_workflows(tmp_path):
    store = Ledger(tmp_path, 'eng', 'device', policy_revision='v1', limits={'tcp_connects': 2})
    first = reserve(store, 'one', workflow='first', counter='tcp_connects')
    assert first.remaining['tcp_connects'] == 1
    store.finish('one')

    second = reserve(store, 'two', workflow='second', counter='tcp_connects')
    assert second.remaining['tcp_connects'] == 0


def test_v2_handover_refuses_to_lose_new_scope_ceilings(tmp_path):
    store = ledger(tmp_path)
    reserve(store, 'one', budgets=(BudgetLimit('device', 'device', 'request_limit', 2),)); store.finish('one'); store.stop()
    with pytest.raises(PolicyError, match='cannot preserve scoped ceilings'):
        store.seal_for_handover('another-device', 'a' * 64)
    assert store._db.execute('SELECT COUNT(*) FROM handover_seals').fetchone()[0] == 0


@pytest.mark.parametrize('scope,key', [('device', 'wrong'), ('engagement', 'wrong')])
def test_mismatched_fixed_scope_identity_is_rejected(tmp_path, scope, key):
    store = ledger(tmp_path)
    with pytest.raises(PolicyError, match='scope.*identity'):
        reserve(store, 'one', budgets=(BudgetLimit(scope, key, 'request_limit', 0),))
    assert store.usage()['request_limit'] == 0
