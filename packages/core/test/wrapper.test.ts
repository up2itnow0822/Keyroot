import test from 'node:test';
import assert from 'node:assert/strict';
import { GraceLease, launchManagedWorkload, type WrapperDescriptor } from '../src/wrapper.js';
import { contentDigest, deepFreeze } from '../src/manifest.js';
import type { EffectContext } from '../src/engine.js';
import type { AuthorizedIntent } from '../src/journal.js';

test('grace validates 15–30 minutes, uses monotonic time and never extends issuer expiry', () => { let now = 0; const clock = () => now; assert.throws(() => new GraceLease({ graceSeconds: 899, issuerRemainingMs: 1e9, monotonic: clock })); assert.throws(() => new GraceLease({ graceSeconds: 1801, issuerRemainingMs: 1e9, monotonic: clock })); const lease = new GraceLease({ graceSeconds: 900, issuerRemainingMs: 1000, monotonic: clock }); now = 400; assert.equal(lease.remainingMs(), 600); lease.renew(); now = 1000; assert.equal(lease.remainingMs(), 0); assert.throws(() => lease.renew()); const box = new GraceLease({ graceSeconds: 900, issuerRemainingMs: 1e9, monotonic: clock }); now += 100; box.renew(); now += 900001; assert.equal(box.remainingMs(), 0); });
function setup(overrides: Partial<WrapperDescriptor> = {}) { const descriptor: WrapperDescriptor = { driver: 'wrapper', consumerId: 'consumer', destinationId: 'machine', revision: 'revision', consumerMapRevision: 'map', generation: 2, handleId: 'mapped', version: 1, mappingTokenFingerprint: contentDigest('mapped-token'), workloadId: 'fixture', variable: 'API_KEY', command: process.execPath, args: ['-e', 'setInterval(()=>{},1000)'], environmentKeys: ['PATH', 'KEYROOT_TOKEN', 'STORE_TOKEN', 'CONTROLLER_TOKEN', 'ADMIN_TOKEN', 'NODE_OPTIONS'], graceSeconds: 900, issuerExpiresAt: Date.now() + 300, ...overrides }; const intent: AuthorizedIntent = deepFreeze({ intentId: 'intent', idempotencyRef: 'idem', operationId: 'op', actionId: 'deliver', grantId: 'grant', kind: 'deliver', state: 'pending', parameters: { consumerId: descriptor.consumerId, destinationId: descriptor.destinationId, handleId: descriptor.handleId, generation: descriptor.generation, expectedRevision: descriptor.revision, configurationHash: contentDigest(descriptor) } }); const context: EffectContext = { subject: { operationId: 'op', lineageId: 'lineage', accountId: 'account', generation: 2, resourceId: 'issuer', handleId: 'mapped', consumerMapRevision: 'map', consumerId: 'consumer', revision: 'revision' }, signal: new AbortController().signal }; return { descriptor, intent, context, environment: { PATH: '/usr/bin:/bin', KEYROOT_TOKEN: 'admin', STORE_TOKEN: 'store', CONTROLLER_TOKEN: 'controller', ADMIN_TOKEN: 'admin', NODE_OPTIONS: '--inspect' } }; }

test('managed launch strips administration env and resolves only exact mapping', async () => { const x = setup({ args: ['-e', `if(process.env.API_KEY!=='synthetic-secret'||Object.keys(process.env).some(k=>/TOKEN|NODE_OPTIONS/.test(k)))process.exit(7);setInterval(()=>{},1000)`] }); const calls: [string, number][] = []; const managed = await launchManagedWorkload({ ...x, store: { async withValue(handle, version, fn) { calls.push([handle, version]); await fn('synthetic-secret'); return { status: 'resolved' }; } }, trust: { beforeEffect: async () => {}, quarantine: async () => 'clear' }, heartbeat: { assertHealthy: async () => {} } }); assert.deepEqual(calls, [['mapped', 1]]); assert.equal(managed.receipt.outcome, 'delivery-accepted'); assert.equal(await managed.exited, 'issuer-expired'); assert.ok(!JSON.stringify(managed.receipt).includes('synthetic-secret')); });
test('expired or unmapped launches fail closed without exposing values', async () => { const x = setup({ issuerExpiresAt: Date.now() - 1 }); await assert.rejects(launchManagedWorkload({ ...x, store: { async withValue() { return { status: 'denied' }; } }, trust: { beforeEffect: async () => {}, quarantine: async () => 'clear' }, heartbeat: { assertHealthy: async () => {} } }), /Managed workload refused/); });
test('untrusted heartbeat cannot renew and quarantine/unmapped ports cannot launch', async () => {
  const x = setup({ issuerExpiresAt: Date.now() + 700 }); let healthy = true;
  const managed = await launchManagedWorkload({ ...x, store: { async withValue(_h, _v, use) { await use('synthetic-secret'); return { status: 'resolved' }; } }, trust: { beforeEffect: async () => {}, quarantine: async () => 'clear' }, heartbeat: { assertHealthy: async () => { if (!healthy) throw Error('synthetic-secret'); } } });
  healthy = false; assert.equal(await managed.renew(), false); await managed.stop();
  for (const quarantined of [true, false]) {
    await assert.rejects(launchManagedWorkload({ ...setup({ issuerExpiresAt: Date.now() + 60000 }), store: { async withValue() { return { status: 'denied' }; } }, trust: { beforeEffect: async () => {}, quarantine: async () => quarantined ? 'quarantined' : 'clear' }, heartbeat: { assertHealthy: async () => {} } }), /Managed workload refused/);
  }
});

test('mapped values cannot become loader configuration or administration environment', async () => {
  for (const variable of ['KEYROOT_TOKEN', 'STORE_TOKEN', 'CONTROLLER_TOKEN', 'ADMIN_TOKEN', 'NODE_OPTIONS', 'LD_PRELOAD', 'DYLD_INSERT_LIBRARIES', 'BASH_ENV']) {
    let resolved = false;
    await assert.rejects(launchManagedWorkload({ ...setup({ variable, issuerExpiresAt: Date.now() + 60000 }), store: { async withValue() { resolved = true; return { status: 'denied' }; } }, trust: { beforeEffect: async () => {}, quarantine: async () => 'clear' }, heartbeat: { assertHealthy: async () => {} } }), /Managed workload refused/);
    assert.equal(resolved, false);
  }
});

test('abort after store callback but before resolution refuses delivery and cleans startup', async () => {
  const controller = new AbortController(); const x = setup({ issuerExpiresAt: Date.now() + 60000 });
  let accidentallyReturned: Awaited<ReturnType<typeof launchManagedWorkload>> | undefined;
  try {
    await assert.rejects(async () => { accidentallyReturned = await launchManagedWorkload({ ...x, context: { ...x.context, signal: controller.signal }, store: { async withValue(_h, _v, use) { await use('synthetic-secret'); controller.abort(); return { status: 'resolved' }; } }, trust: { beforeEffect: async () => {}, quarantine: async () => 'clear' }, heartbeat: { assertHealthy: async () => {} } }); }, /Managed workload refused/);
  } finally { await accidentallyReturned?.stop(); }
});
