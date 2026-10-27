import { test } from 'node:test';
import { strict as assert } from 'node:assert';
import { makeRecipe } from '../../packages/core/src/recipes/recipe.js';
import { DashboardBroker, type DashboardPort } from '../../apps/controller/src/worker/dashboard.js';

test('independent broker denies interpreter attempts and withholds observations', async () => {
    const calls: string[] = [];
    const port: DashboardPort = { async perform(action, target) { calls.push(`${action}:${target}`); }, async captureToMappedStore(destination, target) { calls.push(`${destination}:${target}`); }, async sealProfile(account) { calls.push(`seal:${account}`); }, async restoreProfile(account) { calls.push(`restore:${account}`); } };
    const recipe = makeRecipe({ id: 'vendor', version: '1', accountId: 'account', destinationId: 'store', steps: [{ action: 'open', targetId: 'credentials', checkpoint: 'none' }, { action: 'capture', targetId: 'key', checkpoint: 'none' }] });
    const broker = new DashboardBroker(recipe, port, async () => { calls.push('fresh-authority'); });
    for (const kind of ['host-file', 'vault-admin', 'other-profile', 'network', 'shell']) assert.equal(await broker.dispatch({ kind, accountId: 'account' }), 'denied');
    assert.deepEqual(broker.observe({ kind: 'status', value: 'completed', secret: 'synthetic-secret' }), { kind: 'withheld' });
    assert.deepEqual(broker.observe({ kind: 'secret-subtree', value: 'synthetic-secret' }), { kind: 'withheld' });
    assert.equal(await broker.dispatch({ kind: 'step', accountId: 'account', destinationId: 'store', action: 'open', targetId: 'credentials', signal: 'expected' }), 'ok');
    assert.equal(await broker.dispatch({ kind: 'step', accountId: 'account', destinationId: 'store', action: 'capture', targetId: 'key', signal: 'expected' }), 'ok');
    assert.deepEqual(calls, ['open:credentials', 'fresh-authority', 'store:key']);
    for (const signal of ['destination-changed', 'unexpected-mfa', 'passkey', 'privilege-instruction']) {
        const other = new DashboardBroker(recipe, port, async () => {});
        assert.equal(await other.dispatch({ kind: 'step', accountId: 'account', destinationId: 'store', action: 'open', targetId: 'credentials', signal }), 'pause-guided');
    }
    const wrongAction = new DashboardBroker(recipe, port, async () => {});
    assert.equal(await wrongAction.dispatch({ kind: 'step', accountId: 'account', destinationId: 'store', action: 'select', targetId: 'credentials', signal: 'expected' }), 'pause-guided');
    const wrong = new DashboardBroker(recipe, port, async () => {});
    assert.equal(await wrong.dispatch({ kind: 'step', accountId: 'account', destinationId: 'other', action: 'open', targetId: 'credentials', signal: 'expected' }), 'pause-guided');
    assert.equal(await wrong.dispatch({ kind: 'step', accountId: 'account', destinationId: 'store', action: 'open', targetId: 'credentials', signal: 'expected' }), 'pause-guided');
});
