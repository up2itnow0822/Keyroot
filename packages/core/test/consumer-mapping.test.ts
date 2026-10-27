import { test } from 'node:test';
import { strict as assert } from 'node:assert';
import { generateKeyPairSync, sign } from 'node:crypto';
import { Journal } from '../src/journal.js';
import { ApprovalService, createLocalBootstrapContext, publicKeyFingerprint } from '../src/approval.js';
import { canonicalizeManifest, contentDigest, parseCanonicalManifest, snapshotDigest, type ApprovalManifest } from '../src/manifest.js';
import { LifecycleEngine, type LifecycleDrivers } from '../src/engine.js';
import type { LifecycleReceipt, ReceiptSubject } from '../src/receipts.js';

function manifest(sharedConsumer = false): ApprovalManifest {
  const entries = ['a', 'b'].map(suffix => ({ lineageId: `lineage-${suffix}`, consumerId: sharedConsumer ? 'workload' : `consumer-${suffix}`, resourceId: `destination-${suffix}`, revision: `revision-${suffix}` }));
  return {
    version: 1, domain: 'keyroot.approval.v1', algorithm: 'ECDSA-P256-SHA256', audience: 'keyroot-controller', installationId: 'installation', bootId: 'boot', signerId: 'phone', role: 'routine', nonce: 'grant', notBefore: 1000, expiresAt: 10000,
    budgets: { effects: 10, newCredentials: 2, restarts: 0, executions: 2 },
    operations: entries.map((entry, index) => {
      const suffix = index === 0 ? 'a' : 'b'; const operationId = `op-${suffix}`;
      return { operationId, lineageId: entry.lineageId, accountId: `account-${suffix}`, fromGeneration: 1, toGeneration: 2, actions: [
        { id: 'create', kind: 'create', parameters: { resourceId: `issuer-${suffix}`, adapterId: 'synthetic', generation: 2, handleId: `handle-${suffix}`, destinationId: 'vault' }, budgetCost: { effects: 2, newCredentials: 1, restarts: 0 } },
        { id: 'validate', kind: 'validate', parameters: { resourceId: `created:${operationId}`, handleId: `handle-${suffix}`, generation: 2 }, budgetCost: { effects: 1, newCredentials: 0, restarts: 0 } },
        { id: 'deliver', kind: 'deliver', parameters: { consumerId: entry.consumerId, destinationId: entry.resourceId, handleId: `handle-${suffix}`, generation: 2, expectedRevision: entry.revision }, budgetCost: { effects: 1, newCredentials: 0, restarts: 0 } },
        { id: 'revoke', kind: 'revoke', parameters: { resourceId: `old-${suffix}`, handleId: `old-handle-${suffix}`, generation: 1 }, budgetCost: { effects: 1, newCredentials: 0, restarts: 0 } }
      ] };
    }),
    consumerMap: { revision: 'map-2', hash: contentDigest(entries), entries }, recipes: [], adoptionThreshold: 'direct-use-every-consumer', overlapPolicy: 'required', deadline: { at: 9000, outcome: 'hold' }, outage: { permitted: false, consequence: 'none' }, graceSeconds: 900
  };
}

function fixture(sharedConsumer = false, change?: (m: ApprovalManifest) => void) {
  const m = manifest(sharedConsumer); change?.(m); const journal = new Journal(':memory:', { installationId: 'installation', bootId: 'boot' });
  const keys = generateKeyPairSync('ec', { namedCurve: 'prime256v1' }); const publicKey = keys.publicKey.export({ format: 'jwk' });
  const approvals = new ApprovalService(journal, { mode: 'synthetic', clock: () => 2000 });
  approvals.bootstrapApprover({ signerId: 'phone', role: 'routine', publicKey, localBootstrap: createLocalBootstrapContext(), confirmedFingerprint: publicKeyFingerprint(publicKey) });
  const raw = canonicalizeManifest(m); const signature = sign('sha256', Buffer.from(raw), { key: keys.privateKey, dsaEncoding: 'ieee-p1363' }).toString('base64url'); approvals.registerGrant(raw, signature, 2000);
  let sequence = 0; const calls: string[] = []; const observed: ReceiptSubject[] = [];
  const receipt = (subject: ReceiptSubject, kind: LifecycleReceipt['kind'], outcome: LifecycleReceipt['outcome']): LifecycleReceipt => ({ receiptId: `receipt-${++sequence}`, subject: { ...subject }, kind, outcome, observedAt: 2000, observerId: 'synthetic', evidenceHash: 'sha256:synthetic', limitationCodes: ['synthetic-only'] });
  const drivers: LifecycleDrivers = {
    async create(_intent, context) { await context.beforeStore(); const subject = { ...context.subject, resourceId: `new-${context.subject.lineageId}` }; return { ...receipt(subject, 'create', 'stored'), storeBinding: { operationId: subject.operationId, lineageId: subject.lineageId, accountId: subject.accountId, generation: subject.generation, issuerId: subject.resourceId, handleId: subject.handleId, destinationId: context.storeTarget.destinationId, version: 1 } }; },
    async validate(_intent, context) { return receipt(context.subject, 'validate', 'validated'); },
    async deliver(intent, context) { calls.push(`deliver:${context.subject.lineageId}:${intent.parameters.destinationId}:${context.subject.revision}`); return receipt(context.subject, 'deliver', 'delivery-accepted'); },
    async revoke(_intent, context) { calls.push(`revoke:${context.subject.lineageId}`); return receipt(context.subject, 'revoke', 'issuer-acknowledged'); },
    async reconcile(_intent, context) { return receipt(context.subject, 'create', 'unknown'); },
    async observeConsumer(subject) { observed.push({ ...subject }); return receipt(subject, 'consumer-use', 'direct-use'); },
    async observeOldUse(subject) { return receipt(subject, 'old-use', 'none-observed'); },
    async observeIssuer(subject) { return receipt(subject, 'issuer', 'confirmed-revoked'); },
    async probeOld(subject) { return receipt(subject, 'probe', 'rejected'); }
  };
  const engine = new LifecycleEngine(journal, approvals, drivers, { currentSnapshot: () => m, clock: () => 2000 });
  return { m, journal, engine, drivers, calls, observed, receipt, signature, run: (operationId: string) => engine.run({ operationId, grantId: m.nonce, signature }) };
}

for (const sharedConsumer of [false, true]) {
  test(`signed two-lineage batch only requires each lineage's consumers (${sharedConsumer ? 'same workload, distinct targets' : 'distinct workloads'})`, async () => {
    const f = fixture(sharedConsumer);
    try {
      assert.equal((await f.run('op-a')).state, 'completed'); assert.equal((await f.run('op-b')).state, 'completed');
      assert.deepEqual(f.calls, ['deliver:lineage-a:destination-a:revision-a', 'revoke:lineage-a', 'deliver:lineage-b:destination-b:revision-b', 'revoke:lineage-b']);
      assert.deepEqual(f.observed.map(s => [s.lineageId, s.consumerId, s.revision]), [['lineage-a', sharedConsumer ? 'workload' : 'consumer-a', 'revision-a'], ['lineage-b', sharedConsumer ? 'workload' : 'consumer-b', 'revision-b']]);
    } finally { f.journal.close(); }
  });
}

test('other lineage receipt cannot clear direct-use hold or enter another operation callback', async () => {
  const f = fixture(true); const observe = f.drivers.observeConsumer;
  f.drivers.observeConsumer = async subject => subject.lineageId === 'lineage-a' ? f.receipt({ ...subject, lineageId: 'lineage-b', operationId: 'op-b', revision: 'revision-b' }, 'consumer-use', 'direct-use') : observe(subject);
  try {
    const a = await f.run('op-a'); assert.equal(a.state, 'held'); assert.ok(a.holds.includes('consumer-use-unverified:workload')); assert.ok(!f.calls.includes('revoke:lineage-a'));
    assert.equal((await f.run('op-b')).state, 'completed');
    const b = f.engine.inspect('op-b').receipts.find(r => r.kind === 'consumer-use')!;
    assert.throws(() => f.engine.recordObservation('op-a', b), /Receipt subject mismatch/);
    assert.equal(f.engine.inspect('op-a').state, 'held');
  } finally { f.journal.close(); }
});

test('delivery cannot borrow a consumer mapped only to another signed lineage', async () => {
  const f = fixture(false, m => {
    const delivery = m.operations[0]!.actions.find(a => a.kind === 'deliver')!;
    delivery.parameters = { ...delivery.parameters, consumerId: 'consumer-b', destinationId: 'destination-b', expectedRevision: 'revision-b' };
  });
  try {
    await assert.rejects(f.run('op-a'), /Delivery outside exact consumer mapping/);
    assert.equal(f.journal.listIntents('op-a').some(i => i.kind === 'deliver'), false);
    assert.equal(f.calls.length, 0);
  } finally { f.journal.close(); }
});

test('signed explicit consumer with correct revision cannot deliver to a different target', async () => {
  const f = fixture(true, m => { m.operations[0]!.actions.find(a => a.kind === 'deliver')!.parameters.destinationId = 'different-target'; });
  try {
    await assert.rejects(f.run('op-a'), /Delivery outside exact consumer mapping/);
    assert.equal(f.journal.listIntents('op-a').some(i => i.kind === 'deliver'), false);
    assert.equal(f.calls.length, 0);
  } finally { f.journal.close(); }
});

test('real admission preflights explicit delivery mapping before any effect or trusted callback', async () => {
  for (const variant of ['explicit', 'legacy', 'empty', 'wrong-target'] as const) {
    const f = fixture(false, m => {
      if (variant === 'legacy') m.consumerMap.entries = m.consumerMap.entries.map(e => ({ consumerId: e.consumerId, resourceId: e.resourceId, revision: e.revision }));
      if (variant === 'empty') m.consumerMap.entries = [];
      if (variant === 'wrong-target') m.operations[0]!.actions.find(a => a.kind === 'deliver')!.parameters.destinationId = 'different-target';
      m.consumerMap.hash = contentDigest(m.consumerMap.entries);
    });
    let callbacks = 0;
    const approvals = new ApprovalService(f.journal, { mode: 'real', clock: () => 2000, assertRealAdmission: async () => { callbacks++; } });
    const request = { grantId: f.m.nonce, operationId: 'op-a', actionId: 'create', signature: f.signature, currentSnapshotDigest: snapshotDigest(f.m), now: 2000 };
    try {
      if (variant === 'explicit') { await approvals.authorizeEffect(request); assert.equal(callbacks, 1); }
      else { await assert.rejects(approvals.authorizeEffect(request), /Real delivery requires explicit lineage consumer mapping/); assert.equal(callbacks, 0); assert.equal(f.journal.listIntents('op-a').length, 0); }
    } finally { f.journal.close(); }
  }
});

test('legacy global map still requires every mapped consumer for each operation', async () => {
  const f = fixture(false, m => {
    m.consumerMap.entries = m.consumerMap.entries.map(entry => ({ consumerId: entry.consumerId, resourceId: entry.resourceId, revision: entry.revision }));
    m.consumerMap.hash = contentDigest(m.consumerMap.entries); m.budgets.effects = 12;
    for (const op of m.operations) {
      const template = op.actions.find(a => a.kind === 'deliver')!;
      op.actions = [...op.actions.filter(a => a.kind === 'create' || a.kind === 'validate'), ...m.consumerMap.entries.map(entry => ({ ...template, id: `deliver-${entry.consumerId}`, parameters: { ...template.parameters, consumerId: entry.consumerId, destinationId: entry.resourceId, expectedRevision: entry.revision } })), ...op.actions.filter(a => a.kind === 'revoke')];
    }
  });
  try {
    assert.equal((await f.run('op-a')).state, 'completed'); assert.equal((await f.run('op-b')).state, 'completed');
    assert.deepEqual(f.observed.map(s => [s.lineageId, s.consumerId]), [['lineage-a', 'consumer-a'], ['lineage-a', 'consumer-b'], ['lineage-b', 'consumer-a'], ['lineage-b', 'consumer-b']]);
  } finally { f.journal.close(); }
});

test('mapping validation rejects duplicate lineage consumer, unknown lineage and ambiguous legacy entries', () => {
  for (const variant of ['duplicate', 'unknown-lineage', 'ambiguous-global', 'duplicate-global'] as const) {
    const m = manifest(true); const first = m.consumerMap.entries[0]!;
    if (variant === 'duplicate') m.consumerMap.entries.push({ ...first, resourceId: 'another-target' });
    if (variant === 'unknown-lineage') Object.assign(first, { lineageId: 'absent-lineage' });
    if (variant === 'ambiguous-global' || variant === 'duplicate-global') m.consumerMap.entries.push({ consumerId: first.consumerId, resourceId: 'global-target', revision: 'legacy-revision' });
    if (variant === 'duplicate-global') m.consumerMap.entries = m.consumerMap.entries.slice(2).concat(m.consumerMap.entries.slice(2));
    m.consumerMap.hash = contentDigest(m.consumerMap.entries);
    assert.throws(() => canonicalizeManifest(m), /Duplicate manifest identity|Consumer map lineage outside signed operations|Ambiguous global consumer mapping/, variant);
  }
});

test('lineage-specific mapping stays in the complete canonical hash and scope digest', () => {
  const m = manifest(true); const raw = canonicalizeManifest(m); const digest = snapshotDigest(m);
  assert.deepEqual(parseCanonicalManifest(raw), m);
  m.consumerMap.entries[1]!.revision = 'changed';
  assert.notEqual(snapshotDigest(m), digest);
  assert.throws(() => canonicalizeManifest(m), /Consumer map hash mismatch/);
});
