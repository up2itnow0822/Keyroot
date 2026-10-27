import { test } from 'node:test';
import { strict as assert } from 'node:assert';
import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import { isoCBOR } from '@simplewebauthn/server/helpers';
import { EmergencyWebAuthn, emergencyEnrollmentFingerprint } from '../src/emergency-webauthn.js';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Journal, type AuthorizedIntent } from '../src/journal.js';
import { ApprovalService, createLocalBootstrapContext, publicKeyFingerprint } from '../src/approval.js';
import { canonicalizeManifest, contentDigest, snapshotDigest, type ApprovalManifest } from '../src/manifest.js';
import { LifecycleEngine, type LifecycleDrivers } from '../src/engine.js';
import type { LifecycleReceipt, ReceiptSubject } from '../src/receipts.js';

function fixture(change?: (m: ApprovalManifest) => void) {
  const entries = [{ consumerId: 'deployment', resourceId: 'app', revision: 'deploy-2' }, { consumerId: 'ci', resourceId: 'job', revision: 'job-2' }];
  const m: ApprovalManifest = {
    version: 1, domain: 'keyroot.approval.v1', algorithm: 'ECDSA-P256-SHA256', audience: 'keyroot-controller', installationId: 'installation', bootId: 'boot', signerId: 'phone', role: 'routine', nonce: 'grant', notBefore: 1000, expiresAt: 10000,
    budgets: { effects: 6, newCredentials: 1, restarts: 0, executions: 1 },
    operations: [{ operationId: 'op', lineageId: 'lineage', accountId: 'account', fromGeneration: 1, toGeneration: 2, actions: [
      { id: 'create', kind: 'create', parameters: { resourceId: 'issuer-scope', adapterId: 'synthetic', generation: 2, handleId: 'vault-handle', destinationId: 'vault' }, budgetCost: { effects: 2, newCredentials: 1, restarts: 0 } },
      { id: 'validate', kind: 'validate', parameters: { resourceId: 'created:op', handleId: 'vault-handle', generation: 2 }, budgetCost: { effects: 1, newCredentials: 0, restarts: 0 } },
      { id: 'delivery', kind: 'deliver', parameters: { consumerId: 'deployment', destinationId: 'host', handleId: 'vault-handle', generation: 2, expectedRevision: 'deploy-2' }, budgetCost: { effects: 1, newCredentials: 0, restarts: 0 } },
      { id: 'ci-delivery', kind: 'deliver', parameters: { consumerId: 'ci', destinationId: 'ci-host', handleId: 'vault-handle', generation: 2, expectedRevision: 'job-2' }, budgetCost: { effects: 1, newCredentials: 0, restarts: 0 } },
      { id: 'revoke', kind: 'revoke', parameters: { resourceId: 'old-key', handleId: 'old-handle', generation: 1 }, budgetCost: { effects: 1, newCredentials: 0, restarts: 0 } }
    ] }], consumerMap: { revision: 'map-2', hash: contentDigest(entries), entries }, recipes: [], adoptionThreshold: 'direct-use-every-consumer', overlapPolicy: 'required', deadline: { at: 9000, outcome: 'hold' }, outage: { permitted: false, consequence: 'none' }, graceSeconds: 900
  };
  change?.(m);
  const file = join(mkdtempSync(join(tmpdir(), 'keyroot-u4-')), 'journal.sqlite');
  const journal = new Journal(file, { installationId: 'installation', bootId: 'boot' });
  const keys = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const publicKey = keys.publicKey.export({ format: 'jwk' });
  let now = 2000;
  const approvals = new ApprovalService(journal, { mode: 'synthetic', clock: () => now });
  approvals.bootstrapApprover({ signerId: 'phone', role: 'routine', publicKey, localBootstrap: createLocalBootstrapContext(), confirmedFingerprint: publicKeyFingerprint(publicKey) });
  function grant(manifest = m) {
    const raw = canonicalizeManifest(manifest);
    const signature = sign('sha256', Buffer.from(raw), { key: keys.privateKey, dsaEncoding: 'ieee-p1363' }).toString('base64url');
    approvals.registerGrant(raw, signature, 2000);
    return { operationId: 'op', grantId: manifest.nonce, signature };
  }
  const input = grant(); let sequence = 0;
  const calls: string[] = [];
  const receipt = (subject: ReceiptSubject, kind: LifecycleReceipt['kind'], outcome: LifecycleReceipt['outcome']): LifecycleReceipt => ({ receiptId: `receipt-${++sequence}`, subject, kind, outcome, observedAt: now, observerId: 'synthetic-driver', evidenceHash: 'sha256:synthetic', limitationCodes: ['synthetic-only'] });
  const drivers: LifecycleDrivers = {
    async create(intent, context) {
      calls.push('create'); assert.ok(Object.isFrozen(intent)); assert.equal(journal.listIntents('op').at(-1)?.intentId, intent.intentId);
      await context.beforeStore(); calls.push('store');
      return { ...receipt({ ...context.subject, resourceId: 'new-key' }, 'create', 'stored'), storeBinding: { operationId: 'op', lineageId: 'lineage', accountId: 'account', generation: 2, issuerId: 'new-key', handleId: 'vault-handle', destinationId: 'vault', version: 1 } };
    },
    async validate(intent, context) { calls.push('validate'); assert.equal(intent.parameters.resourceId, 'created:op'); assert.equal(context.subject.resourceId, 'new-key'); return receipt(context.subject, 'validate', 'validated'); },
    async deliver(_intent, context) { calls.push('deliver'); return receipt(context.subject, 'deliver', 'delivery-accepted'); },
    async revoke(_intent, context) { calls.push('revoke'); return receipt(context.subject, 'revoke', 'issuer-acknowledged'); },
    async reconcile(_intent, context) { calls.push('reconcile'); return receipt(context.subject, 'create', 'unknown'); },
    async observeConsumer(subject) { return receipt(subject, 'consumer-use', 'direct-use'); },
    async observeOldUse(subject) { return receipt(subject, 'old-use', 'none-observed'); },
    async observeIssuer(subject) { return receipt(subject, 'issuer', 'confirmed-revoked'); },
    async probeOld(subject) { return receipt(subject, 'probe', 'rejected'); }
  };
  const engine = () => new LifecycleEngine(journal, approvals, drivers, { currentSnapshot: () => m, clock: () => now });
  return { journal, approvals, m, input, calls, drivers, receipt, engine, file, grant, keys, setNow: (value: number) => { now = value; } };
}

test('U4 real P-256 authority drives stored replacement, validation, delivery, direct adoption and two-plane terminal proof', async () => {
  const f = fixture(); const result = await f.engine().run(f.input);
  assert.equal(result.state, 'completed'); assert.deepEqual(f.calls, ['create', 'store', 'validate', 'deliver', 'deliver', 'revoke']);
  assert.equal(result.issuer, 'confirmed-revoked'); assert.equal(result.probe, 'rejected');
  assert.equal(f.journal.listIntents('op').length, 5); assert.equal(f.journal.listReceipts('op').filter(r => r.kind === 'storage').length, 1);
  const stored = f.journal.listReceipts('op').find(r => r.kind === 'storage')!;
  assert.equal(stored.accountId, 'account'); assert.equal(stored.parentResourceId, 'issuer-scope'); assert.equal(stored.resourceId, 'new-key'); assert.equal(stored.handleId, 'vault-handle'); assert.equal(stored.destinationId, 'vault'); assert.equal(stored.storeVersion, 1);
  assert.equal((await f.engine().run(f.input)).state, 'completed'); assert.equal(f.calls.filter(c => c === 'create').length, 1);
  f.journal.close();
});

test('U4 generic health, queued CI, inference, failures, stale generation/revision and observer exceptions never fabricate adoption', async () => {
  for (const variant of ['generic-health', 'queued', 'inferred-use', 'failed', 'unknown', 'throws', 'old-generation', 'wrong-revision', 'stale'] as const) {
    const f = fixture();
    f.drivers.observeConsumer = async subject => {
      if (subject.consumerId !== 'ci') return f.receipt(subject, 'consumer-use', 'direct-use');
      if (variant === 'throws') throw new Error('PRIVATE-provider-payload');
      const r = f.receipt(subject, 'consumer-use', ['old-generation', 'wrong-revision', 'stale'].includes(variant) ? 'direct-use' : variant as LifecycleReceipt['outcome']);
      if (variant === 'old-generation') r.subject = { ...subject, generation: 1 };
      if (variant === 'wrong-revision') r.subject = { ...subject, revision: 'job-1' };
      if (variant === 'stale') r.observedAt = 0;
      return r;
    };
    const result = await f.engine().run(f.input);
    assert.equal(result.state, 'held', variant); assert.ok(result.holds.some(h => h.includes('ci')), variant); assert.ok(!f.calls.includes('revoke'));
    assert.ok(!JSON.stringify(result).includes('PRIVATE')); f.journal.close();
  }
});

test('U4 positive old use holds despite new direct receipts; issuer acceptance after ack alerts and retains lock', async () => {
  const f = fixture(); f.drivers.observeOldUse = async subject => f.receipt(subject, 'old-use', 'positive-use');
  assert.equal((await f.engine().run(f.input)).state, 'held'); assert.ok(!f.calls.includes('revoke')); f.journal.close();
  const g = fixture(); g.drivers.probeOld = async subject => g.receipt(subject, 'probe', 'accepted');
  const result = await g.engine().run(g.input); assert.equal(result.state, 'held'); assert.equal(result.probe, 'accepted'); assert.ok(result.holds.includes('old-key-accepted'));
  assert.throws(() => g.journal.createOperation({ operationId: 'second', lineageId: 'lineage', accountId: 'account', fromGeneration: 2, toGeneration: 3 }), /predecessor/); g.journal.close();
});

test('U4 routine overdue exposure holds while signed hard deadline declares outage and bypasses missing adoption', async () => {
  for (const hard of [false, true]) {
    const f = fixture(m => { if (hard) { m.deadline.outcome = 'hard-revoke'; m.outage = { permitted: true, consequence: 'declared-interruption' }; } });
    f.setNow(9500); f.drivers.observeConsumer = async subject => f.receipt(subject, 'consumer-use', 'queued');
    const result = await f.engine().run(f.input); assert.equal(f.calls.includes('revoke'), hard); assert.equal(result.deadline, hard ? 'hard-outage' : 'overdue-exposure');
    assert.equal(result.state, hard ? 'completed' : 'held'); f.journal.close();
  }
});

test('U4 cancelled grant after validation stops optional delivery and compound store rechecks immediately', async () => {
  const f = fixture(); const validate = f.drivers.validate;
  f.drivers.validate = async (intent, context) => { const r = await validate(intent, context); f.approvals.cancelGrant(f.m.nonce); return r; };
  await assert.rejects(f.engine().run(f.input), /Cancelled/); assert.ok(!f.calls.includes('deliver')); f.journal.close();
  const g = fixture(); g.drivers.create = async (_intent, context) => { g.calls.push('create'); g.approvals.cancelGrant(g.m.nonce); await context.beforeStore(); throw new Error('unreachable'); };
  const result = await g.engine().run(g.input); assert.equal(result.state, 'reconcile-required'); assert.ok(!g.calls.includes('store')); assert.equal(g.journal.listIntents('op')[0]?.state, 'unknown'); g.journal.close();
});

test('U4 signed one-effect create, changed trusted snapshot and raw/mismatched driver metadata never dispatch unsafe store/delivery', async () => {
  const f = fixture(m => { m.operations[0]!.actions[0]!.budgetCost.effects = 1; });
  await assert.rejects(f.engine().run(f.input), /two effects/); assert.equal(f.calls.length, 0); f.journal.close();
  const g = fixture(); g.m.consumerMap.revision = 'changed'; await assert.rejects(g.engine().run(g.input), /scope or policy/); assert.equal(g.calls.length, 0); g.journal.close();
  for (const variant of ['account', 'binding', 'raw']) {
    const h = fixture(); const create = h.drivers.create;
    h.drivers.create = async (i, c) => { const r = await create(i, c); if (variant === 'account') r.subject = { ...r.subject, accountId: 'other' }; if (variant === 'binding') r.storeBinding!.generation = 9; if (variant === 'raw') (r as unknown as Record<string, unknown>).rawValue = 'PRIVATE'; return r; };
    const result = await h.engine().run(h.input); assert.equal(result.state, 'reconcile-required'); assert.ok(!h.calls.includes('deliver')); assert.ok(!JSON.stringify(result).includes('PRIVATE')); h.journal.close();
  }
});

test('U4 crashes at create/store/delivery/revoke persist intent; resume reconciles and never repeats effects', async () => {
  for (const stage of ['create', 'store', 'deliver', 'revoke'] as const) {
    const f = fixture(); let saved: LifecycleReceipt | undefined; let pending: AuthorizedIntent | undefined;
    if (stage === 'create' || stage === 'store') {
      const create = f.drivers.create;
      f.drivers.create = async (i, c) => { pending = i; if (stage === 'store') saved = await create(i, c); else f.calls.push('create'); throw new Error('process-response-lost'); };
    } else {
      const original = f.drivers[stage];
      f.drivers[stage] = async (i, c) => { if (pending) return original(i, c); pending = i; saved = await original(i, c); throw new Error('process-response-lost'); };
    }
    assert.equal((await f.engine().run(f.input)).state, 'reconcile-required'); assert.ok(pending);
    f.drivers.reconcile = async (_i, context) => saved ?? f.receipt({ ...context.subject, resourceId: 'new-key' }, 'create', 'created-unrecoverable');
    const result = await f.engine().run(f.input);
    assert.equal(result.state, stage === 'create' ? 'held' : 'completed', stage);
    assert.equal(f.calls.filter(c => c === stage).length, stage === 'deliver' ? 2 : 1, stage);
    f.journal.close();
  }
});

test('U4 reboot reconciles matching durable store receipt under expired authority, then needs fresh grant for further effects', async () => {
  const f = fixture(); let saved: LifecycleReceipt | undefined;
  const create = f.drivers.create; f.drivers.create = async (i, c) => { saved = await create(i, c); throw new Error('lost-response'); };
  await f.engine().run(f.input); f.journal.close();
  const restored = new Journal(f.file, { installationId: 'installation', bootId: 'new-boot' });
  const approvals = new ApprovalService(restored, { mode: 'synthetic', clock: () => 20000 });
  f.drivers.reconcile = async () => saved!;
  const engine = new LifecycleEngine(restored, approvals, f.drivers, { currentSnapshot: () => f.m, clock: () => 20000 });
  const result = await engine.reconcile('op'); assert.equal(result.replacement, 'stored'); assert.equal(f.calls.filter(c => c === 'create').length, 1);
  const receipts = restored.listReceipts('op'); const reconciled = receipts.find(r => r.kind === 'reconciliation')!;
  assert.ok(reconciled.reconcilesReceiptIds?.includes(receipts.find(r => r.outcome === 'unknown')!.receiptId)); assert.equal(reconciled.accountId, 'account'); assert.equal(reconciled.storeVersion, 1);
  await assert.rejects(engine.run(f.input)); assert.ok(!f.calls.includes('deliver')); restored.close();
});

test('U4 consumer callbacks replay idempotently and concurrent second rotation cannot create', async () => {
  const f = fixture(); f.drivers.observeConsumer = async subject => f.receipt(subject, 'consumer-use', 'inferred-use');
  await f.engine().run(f.input); const engine = f.engine();
  const subject: ReceiptSubject = { operationId: 'op', lineageId: 'lineage', accountId: 'account', generation: 2, resourceId: 'new-key', handleId: 'vault-handle', consumerMapRevision: 'map-2', consumerId: 'ci', revision: 'job-2' };
  const r = f.receipt(subject, 'consumer-use', 'direct-use'); engine.recordObservation('op', r); engine.recordObservation('op', structuredClone(r));
  assert.equal(engine.inspect('op').receipts.filter(item => item.receiptId === r.receiptId).length, 1);
  assert.throws(() => engine.recordObservation('op', { ...r, outcome: 'failed' }), /conflicting/);
  const other = structuredClone(f.m); other.nonce = 'other-grant'; other.operations[0]!.operationId = 'second';
  const input = { ...f.grant(other), operationId: 'second' }; const secondEngine = new LifecycleEngine(f.journal, f.approvals, f.drivers, { currentSnapshot: () => other, clock: () => 2000 });
  await assert.rejects(secondEngine.run(input), /predecessor/); assert.equal(f.calls.filter(c => c === 'create').length, 1); f.journal.close();
});

test('U4 explicit informed override allows inference but never failed/unknown observers', async () => {
  for (const outcome of ['inferred-use', 'failed', 'unknown'] as const) {
    const f = fixture(m => { m.adoptionThreshold = 'informed-override'; }); f.drivers.observeConsumer = async subject => f.receipt(subject, 'consumer-use', outcome);
    const result = await f.engine().run(f.input); assert.equal(result.state, outcome === 'inferred-use' ? 'completed' : 'held'); f.journal.close();
  }
});

test('U4 absent/ambiguous create metadata stays uncertain on repeated resume and no blind create repeats', async () => {
  for (const outcome of ['unknown', 'orphan-unresolved'] as const) {
    const f = fixture(); f.drivers.create = async () => { f.calls.push('create'); throw new Error('response-lost'); };
    f.drivers.reconcile = async (_intent, context) => f.receipt(context.subject, 'create', outcome);
    await f.engine().run(f.input); await f.engine().run(f.input);
    const result = await f.engine().run(f.input); assert.equal(result.state, 'reconcile-required'); assert.equal(f.calls.filter(c => c === 'create').length, 1); assert.ok(!f.calls.includes('deliver'));
    assert.throws(() => f.journal.createOperation({ operationId: 'next', lineageId: 'lineage', accountId: 'account', fromGeneration: 1, toGeneration: 2 })); f.journal.close();
  }
});

test('U4 issuer acknowledgment, confirmed active/revoked and accepted/rejected/confounded/unknown probes remain separate', async () => {
  for (const issuer of ['confirmed-active', 'unverified', 'confirmed-revoked'] as const) {
    for (const probe of ['accepted', 'rejected', 'confounded', 'unknown'] as const) {
      const f = fixture(); f.drivers.observeIssuer = async subject => f.receipt(subject, 'issuer', issuer);
      f.drivers.probeOld = async subject => ({ ...f.receipt(subject, 'probe', probe), limitationCodes: probe === 'confounded' ? ['scope-error', 'rate-limit'] : ['synthetic-only'] });
      const result = await f.engine().run(f.input); assert.equal(result.issuer, issuer); assert.equal(result.probe, probe); assert.equal(result.state, issuer === 'confirmed-revoked' && probe === 'rejected' ? 'completed' : 'held');
      assert.equal(result.receipts.find(r => r.kind === 'revoke')?.outcome, 'issuer-acknowledged'); f.journal.close();
    }
  }
});

test('U4 stale terminal evidence and probe timeout cannot safely terminate a lineage', async () => {
  for (const variant of ['stale', 'timeout'] as const) {
    const f = fixture();
    f.drivers.probeOld = async subject => { if (variant === 'timeout') throw new Error('PRIVATE-request'); return { ...f.receipt(subject, 'probe', 'rejected'), observedAt: 0 }; };
    const result = await f.engine().run(f.input); assert.equal(result.state, 'held'); assert.ok(!JSON.stringify(result).includes('PRIVATE')); f.journal.close();
  }
});

test('U4 rejected creation/validation/delivery never counts as success or permits the next effect', async () => {
  for (const stage of ['create', 'validate', 'deliver'] as const) {
    const f = fixture();
    if (stage === 'create') f.drivers.create = async (_intent, c) => f.receipt(c.subject, 'create', 'rejected');
    else if (stage === 'validate') f.drivers.validate = async (_intent, c) => f.receipt(c.subject, 'validate', 'rejected');
    else f.drivers.deliver = async (_intent, c) => f.receipt(c.subject, 'deliver', 'rejected');
    const result = await f.engine().run(f.input); assert.equal(result.state, 'held'); assert.ok(!f.calls.includes('revoke'));
    await f.engine().run(f.input); assert.equal(f.calls.filter(c => c === 'create').length, stage === 'create' ? 0 : 1); f.journal.close();
  }
});

test('U4 duplicate concurrent runs serialize dispatch; an in-flight intent cannot be reconciled by another callback', async () => {
  const f = fixture(); let release!: () => void; let started!: () => void;
  const pending = new Promise<void>(resolve => { release = resolve; }); const entered = new Promise<void>(resolve => { started = resolve; });
  const create = f.drivers.create; f.drivers.create = async (i, c) => { started(); await pending; return create(i, c); };
  const run = f.engine().run(f.input); await entered;
  await assert.rejects(f.engine().run(f.input), /busy/); await assert.rejects(f.engine().reconcile('op'), /in flight/);
  assert.equal(f.journal.listIntents('op')[0]?.state, 'pending'); release(); assert.equal((await run).state, 'completed'); assert.equal(f.calls.filter(c => c === 'create').length, 1); f.journal.close();
});

test('U4 restart resumes the same lineage with a fresh signed grant after read-only store reconciliation', async () => {
  const f = fixture(); let saved: LifecycleReceipt | undefined; const create = f.drivers.create;
  f.drivers.create = async (i, c) => { saved = await create(i, c); throw new Error('lost-response'); };
  await f.engine().run(f.input); f.journal.close();
  const restored = new Journal(f.file, { installationId: 'installation', bootId: 'new-boot' }); const approvals = new ApprovalService(restored, { mode: 'synthetic', clock: () => 20000 });
  const fresh = structuredClone(f.m); fresh.bootId = 'new-boot'; fresh.nonce = 'fresh-grant'; fresh.expiresAt = 50000;
  const raw = canonicalizeManifest(fresh); const signature = sign('sha256', Buffer.from(raw), { key: f.keys.privateKey, dsaEncoding: 'ieee-p1363' }).toString('base64url'); approvals.registerGrant(raw, signature, 20000); f.setNow(20000);
  f.drivers.reconcile = async () => saved!;
  const engine = new LifecycleEngine(restored, approvals, f.drivers, { currentSnapshot: () => fresh, clock: () => 20000 });
  assert.equal((await engine.run({ operationId: 'op', grantId: fresh.nonce, signature })).state, 'completed');
  assert.equal(f.calls.filter(c => c === 'create').length, 1); assert.equal(restored.listOperations().length, 1); restored.close();
});

test('U4 matching callback IDs cannot be repurposed and fresh grants cannot reinterpret consumed action/operation identity', async () => {
  for (const variant of ['action', 'operation'] as const) {
    const f = fixture(); f.drivers.observeConsumer = async subject => f.receipt(subject, 'consumer-use', 'queued'); await f.engine().run(f.input);
    const next = structuredClone(f.m); next.nonce = 'next-grant'; if (variant === 'action') next.operations[0]!.actions[0]!.parameters.destinationId = 'other-vault'; else next.operations[0]!.accountId = 'other-account';
    const input = f.grant(next); const engine = new LifecycleEngine(f.journal, f.approvals, f.drivers, { currentSnapshot: () => next, clock: () => 2000 });
    await assert.rejects(engine.run(input), /identity/); assert.equal(f.calls.filter(c => c === 'create').length, 1); f.journal.close();
  }
});

test('U4 orphan cleanup needs a separate fresh signed exact target and never delivers an unrecoverable successor', async () => {
  const f = fixture(); f.drivers.create = async (_intent, c) => f.receipt({ ...c.subject, resourceId: 'orphan-key' }, 'create', 'created-unrecoverable');
  assert.equal((await f.engine().run(f.input)).replacement, 'created-unrecoverable');
  assert.ok(f.journal.listReceipts('op').every(r => r.kind !== 'creation' || r.outcome !== 'confirmed'));
  const next = structuredClone(f.m); next.nonce = 'cleanup-grant'; next.operations[0]!.actions = [{ id: 'cleanup-orphan', kind: 'cleanup', parameters: { resourceId: 'orphan-key', handleId: 'vault-handle', generation: 2 }, budgetCost: { effects: 1, newCredentials: 0, restarts: 0 } }];
  f.drivers.cleanup = async (intent, c) => { assert.equal(intent.parameters.resourceId, 'orphan-key'); f.calls.push('cleanup'); return f.receipt(c.subject, 'cleanup', 'issuer-acknowledged'); };
  const engine = new LifecycleEngine(f.journal, f.approvals, f.drivers, { currentSnapshot: () => next, clock: () => 2000 });
  const result = await engine.run(f.grant(next)); assert.equal(result.state, 'held'); assert.ok(f.calls.includes('cleanup')); assert.ok(!f.calls.includes('deliver')); f.journal.close();
});

test('U4 a fresh grant cannot repeat a stored creation by renaming its action', async () => {
  const f = fixture(); f.drivers.observeConsumer = async subject => f.receipt(subject, 'consumer-use', 'queued'); await f.engine().run(f.input);
  const next = structuredClone(f.m); next.nonce = 'renamed-create-grant'; next.operations[0]!.actions[0]!.id = 'create-again';
  const engine = new LifecycleEngine(f.journal, f.approvals, f.drivers, { currentSnapshot: () => next, clock: () => 2000 });
  await assert.rejects(engine.run(f.grant(next)), /already attempted/); assert.equal(f.calls.filter(c => c === 'create').length, 1); f.journal.close();
});

test('U4 verified emergency takeover cancels optional work and preserves residual ambiguous creation', async () => {
  for (const boundary of ['validation', 'pending-create']) {
  const f = fixture();
  const emergencyKeys = generateKeyPairSync('ec', { namedCurve: 'prime256v1' }); const jwk = emergencyKeys.publicKey.export({ format: 'jwk' });
  const enrollment = { signerId: 'emergency', credentialId: Buffer.from('synthetic-emergency-key').toString('base64url'), cosePublicKey: isoCBOR.encode(new Map<number, number | Uint8Array>([[1, 2], [3, -7], [-1, 1], [-2, Buffer.from(jwk.x!, 'base64url')], [-3, Buffer.from(jwk.y!, 'base64url')]])), rpId: 'approve.keyroot.test', origin: 'https://approve.keyroot.test' };
  const enroll = structuredClone(f.m); enroll.nonce = 'enroll-emergency'; enroll.operations = [{ operationId: 'enroll-op', lineageId: 'owner-lineage', accountId: 'account', fromGeneration: 0, toGeneration: 1, actions: [{ id: 'enroll', kind: 'admin', parameters: { resourceId: 'emergency-approver', destinationId: 'emergency', authorityFingerprint: emergencyEnrollmentFingerprint(enrollment) }, budgetCost: { effects: 1, newCredentials: 0, restarts: 0 } }] }];
  const enrollmentInput = f.grant(enroll);
  const intent = await f.approvals.authorizeEffect({ ...enrollmentInput, operationId: 'enroll-op', actionId: 'enroll', currentSnapshotDigest: snapshotDigest(enroll), now: 2000 });
  const emergency = new EmergencyWebAuthn(f.journal, { clock: () => 2000 }); emergency.enrollCredential({ ...enrollment, authorizationIntentId: intent.intentId, now: 2000, confirmedFingerprint: publicKeyFingerprint(jwk) });
  const containment = structuredClone(f.m); containment.role = 'emergency'; containment.signerId = 'emergency'; containment.nonce = 'containment'; containment.operations[0]!.actions = [{ id: 'contain', kind: 'revoke', parameters: { resourceId: 'old-key', handleId: 'old-handle', generation: 1 }, budgetCost: { effects: 1, newCredentials: 0, restarts: 0 } }];
  f.approvals.registerEmergencyGrant(canonicalizeManifest(containment), 2000);
  let proofId = '';
  const takeOver = async () => {
    const challenge = emergency.createChallenge({ grantId: containment.nonce, operationId: 'op', actionId: 'contain', now: 2000 });
    const client = Buffer.from(JSON.stringify({ type: 'webauthn.get', challenge: challenge.challenge, origin: enrollment.origin, crossOrigin: false })); const counter = Buffer.alloc(4); counter.writeUInt32BE(1);
    const auth = Buffer.concat([createHash('sha256').update(enrollment.rpId).digest(), Buffer.from([5]), counter]);
    const signed = Buffer.concat([auth, createHash('sha256').update(client).digest()]);
    proofId = await emergency.verifyAssertion({ challengeId: challenge.challengeId, operationId: 'op', actionId: 'contain', now: 2000, response: { id: enrollment.credentialId, rawId: enrollment.credentialId, type: 'public-key', clientExtensionResults: {}, response: { clientDataJSON: client.toString('base64url'), authenticatorData: auth.toString('base64url'), signature: sign('sha256', signed, emergencyKeys.privateKey).toString('base64url') } } });
  };
  if (boundary === 'validation') {
    const validate = f.drivers.validate; f.drivers.validate = async (i, c) => { const r = await validate(i, c); await takeOver(); return r; };
    await assert.rejects(f.engine().run(f.input), /Cancelled|reservation/);
  } else {
    f.drivers.create = async () => { f.calls.push('create'); await takeOver(); throw new Error('issuer-success-store-unresolved'); };
    assert.equal((await f.engine().run(f.input)).state, 'reconcile-required');
    const emergencyEngine = new LifecycleEngine(f.journal, f.approvals, f.drivers, { currentSnapshot: () => containment, clock: () => 2000 });
    const result = await emergencyEngine.run({ operationId: 'op', grantId: containment.nonce, emergencyProofs: { contain: proofId } });
    assert.equal(result.state, 'reconcile-required'); assert.ok(result.holds.includes('residual-pending-effect')); assert.equal(result.issuer, 'confirmed-revoked');
    assert.equal(f.journal.listIntents('op').find(i => i.kind === 'create')?.state, 'unknown');
  }
  assert.ok(!f.calls.includes('deliver')); assert.equal(f.journal.listIntents('op').filter(i => i.kind === 'create').length, 1); f.journal.close();
  }
});

test('U4 bounded hung create/consumer waits record uncertainty, abort cooperatively and deny late store continuation', async () => {
  const f = fixture(); let continuation: (() => Promise<AuthorizedIntent>) | undefined; let signal: AbortSignal | undefined;
  f.drivers.create = async (_intent, context) => { f.calls.push('create'); continuation = context.beforeStore; signal = context.signal; return new Promise<LifecycleReceipt>(() => {}); };
  const engine = new LifecycleEngine(f.journal, f.approvals, f.drivers, { currentSnapshot: () => f.m, clock: () => 2000, timeoutMs: 10 });
  const result = await engine.run(f.input); assert.equal(result.state, 'reconcile-required'); assert.equal(f.journal.listIntents('op')[0]?.state, 'unknown'); assert.equal(signal?.aborted, true);
  assert.ok(continuation); await assert.rejects(continuation(), /timed out/); assert.equal((await engine.run(f.input)).state, 'reconcile-required'); assert.equal(f.calls.filter(c => c === 'create').length, 1); f.journal.close();
  const g = fixture(); let observerSignal: AbortSignal | undefined;
  g.drivers.observeConsumer = async (subject, currentSignal) => { if (subject.consumerId !== 'ci') return g.receipt(subject, 'consumer-use', 'direct-use'); observerSignal = currentSignal; return new Promise<LifecycleReceipt>(() => {}); };
  const observerEngine = new LifecycleEngine(g.journal, g.approvals, g.drivers, { currentSnapshot: () => g.m, clock: () => 2000, timeoutMs: 10 });
  const observed = await observerEngine.run(g.input); assert.equal(observed.state, 'held'); assert.ok(observed.holds.includes('consumer-use-unverified:ci')); assert.equal(observerSignal?.aborted, true); assert.ok(!g.calls.includes('revoke'));
  for (const timeoutMs of [0, -1, Infinity, NaN, 120001]) assert.throws(() => new LifecycleEngine(g.journal, g.approvals, g.drivers, { currentSnapshot: () => g.m, timeoutMs }), /timeout/);
  g.journal.close();
});

test('U4 separately signed hard deadline can eliminate a known old credential when no replacement exists', async () => {
  const f = fixture(m => { m.deadline.outcome = 'hard-revoke'; m.outage = { permitted: true, consequence: 'declared-interruption' }; m.operations[0]!.actions = [m.operations[0]!.actions.at(-1)!]; });
  f.setNow(9500); const result = await f.engine().run(f.input);
  assert.equal(result.state, 'completed'); assert.equal(result.replacement, 'not-created'); assert.equal(result.deadline, 'hard-outage'); assert.deepEqual(f.calls, ['revoke']); f.journal.close();
});
