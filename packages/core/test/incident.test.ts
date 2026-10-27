import { test } from 'node:test';
import { strict as assert } from 'node:assert';
import { Journal } from '../src/journal.js';
import { MutationInterlock } from '../src/notifier.js';
import { QuarantineStore } from '../src/incident.js';

test('failed push latches the effect fence and retains prepared notification until explicit retry', async () => {
  const j = new Journal(':memory:', { installationId: 'i', bootId: 'b' }); let fail = true;
  const gate = new MutationInterlock(j, async () => { if (fail) throw new Error('transport down'); });
  gate.prepare('n1', 'operation-pending', 'op');
  await assert.rejects(gate.checkEffectFence(), /notification/);
  assert.equal(gate.list()[0]?.status, 'prepared'); assert.equal(gate.alarms().length, 1);
  fail = false; await assert.rejects(gate.checkEffectFence(), /notification/);
  await gate.retry(); assert.equal(gate.list()[0]?.status, 'delivered'); await gate.checkEffectFence(); j.close();
});

test('quarantine read defaults to clear', async () => {
  const j = new Journal(':memory:', { installationId: 'i', bootId: 'b' });
  assert.equal(await new QuarantineStore(j).check('ci', 'host'), 'clear'); j.close();
});

import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import { isoCBOR } from '@simplewebauthn/server/helpers';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { EmergencyWebAuthn, emergencyEnrollmentFingerprint } from '../src/emergency-webauthn.js';
import { ApprovalService, createLocalBootstrapContext, publicKeyFingerprint } from '../src/approval.js';
import { canonicalizeManifest, contentDigest, snapshotDigest, type ApprovalManifest } from '../src/manifest.js';
import { LifecycleEngine, type LifecycleDrivers } from '../src/engine.js';
import type { LifecycleReceipt, ReceiptSubject } from '../src/receipts.js';
import { IncidentCoordinator } from '../src/incident.js';
import { createScheduledEngine, Scheduler } from '../src/schedule.js';

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


test('verified five-lineage takeover reserves whole set before an interleaved routine tick', async () => {
  const f = fixture(m => {
    const first = m.operations[0]!;
    m.operations = Array.from({ length: 5 }, (_, i) => ({ ...structuredClone(first), operationId: `op${i}`, lineageId: `lineage${i}` }));
    m.budgets = { effects: 30, newCredentials: 5, restarts: 0, executions: 5 };
  });
  const keys = generateKeyPairSync('ec', { namedCurve: 'prime256v1' }); const jwk = keys.publicKey.export({ format: 'jwk' });
  const enrollment = { signerId: 'emergency', credentialId: Buffer.from('emergency-key').toString('base64url'), cosePublicKey: isoCBOR.encode(new Map<number, number | Uint8Array>([[1, 2], [3, -7], [-1, 1], [-2, Buffer.from(jwk.x!, 'base64url')], [-3, Buffer.from(jwk.y!, 'base64url')]])), rpId: 'approve.keyroot.test', origin: 'https://approve.keyroot.test' };
  const enroll = structuredClone(f.m); enroll.nonce = 'enroll-emergency'; enroll.operations = [{ operationId: 'enroll-op', lineageId: 'owner', accountId: 'account', fromGeneration: 0, toGeneration: 1, actions: [{ id: 'enroll', kind: 'admin', parameters: { resourceId: 'emergency-approver', destinationId: 'emergency', authorityFingerprint: emergencyEnrollmentFingerprint(enrollment) }, budgetCost: { effects: 1, newCredentials: 0, restarts: 0 } }] }];
  const signed = f.grant(enroll);
  const intent = await f.approvals.authorizeEffect({ ...signed, operationId: 'enroll-op', actionId: 'enroll', currentSnapshotDigest: snapshotDigest(enroll), now: 2000 });
  const web = new EmergencyWebAuthn(f.journal, { clock: () => 2000 });
  web.enrollCredential({ ...enrollment, authorizationIntentId: intent.intentId, now: 2000, confirmedFingerprint: publicKeyFingerprint(jwk) });
  const emergency = structuredClone(f.m); emergency.role = 'emergency'; emergency.signerId = 'emergency'; emergency.nonce = 'incident'; emergency.budgets = { effects: 5, newCredentials: 0, restarts: 0, executions: 5 };
  emergency.operations.forEach((op, i) => { op.actions = [{ id: 'contain', kind: 'revoke', parameters: { resourceId: `old${i}`, handleId: `handle${i}`, generation: 1 }, budgetCost: { effects: 1, newCredentials: 0, restarts: 0 } }]; });
  f.approvals.registerEmergencyGrant(canonicalizeManifest(emergency), 2000);
  const gate = new MutationInterlock(f.journal); const wired = createScheduledEngine(f.journal, gate, f.drivers, { mode: 'synthetic', clock: () => 2000 }, { currentSnapshot: () => emergency, clock: () => 2000 });
  const incident = new IncidentCoordinator(wired.engine, gate, () => 2000); const proofs: Record<string, Record<string, string>> = {};
  assert.throws(() => incident.prepare('incident', 'fabricated', []), /verified emergency assertion/);
  await assert.rejects(incident.execute('incident', {}), /prepared/);
  for (const [i, op] of emergency.operations.entries()) {
    const challenge = web.createChallenge({ grantId: 'incident', operationId: op.operationId, actionId: 'contain', now: 2000 });
    const client = Buffer.from(JSON.stringify({ type: 'webauthn.get', challenge: challenge.challenge, origin: enrollment.origin, crossOrigin: false }));
    const counter = Buffer.alloc(4); counter.writeUInt32BE(i + 1); const auth = Buffer.concat([createHash('sha256').update(enrollment.rpId).digest(), Buffer.from([5]), counter]);
    const payload = Buffer.concat([auth, createHash('sha256').update(client).digest()]);
    const proof = await web.verifyAssertion({ challengeId: challenge.challengeId, operationId: op.operationId, actionId: 'contain', now: 2000, response: { id: enrollment.credentialId, rawId: enrollment.credentialId, type: 'public-key', clientExtensionResults: {}, response: { clientDataJSON: client.toString('base64url'), authenticatorData: auth.toString('base64url'), signature: sign('sha256', payload, keys.privateKey).toString('base64url') } } });
    proofs[op.operationId] = { contain: proof };
    if (i === 0) {
      assert.equal(f.journal.read(db => db.prepare('SELECT COUNT(*) AS n FROM emergency_reservation WHERE grant_id=?').get('incident')?.n), 5);
      incident.prepare('incident', proof, [{ consumerId: 'ci', destinationId: 'job' }]);
      assert.equal(await new QuarantineStore(f.journal).check('ci', 'job'), 'quarantined');
      assert.deepEqual(await new Scheduler(wired.engine, gate, { clock: () => 2000 }).tick('grant'), []);
      assert.equal(f.calls.length, 0);
    }
  }
  const result = await incident.execute('incident', proofs);
  assert.equal(result.length, 5); assert.equal(f.calls.filter(c => c === 'revoke').length, 5);
  assert.ok(result.every(item => item.containment === 'confirmed-revoked' && item.residualTokenValidity === 'rejected'));
  const routine = structuredClone(f.m); routine.nonce = 'after-incident'; routine.operations = [structuredClone(f.m.operations[0]!)];
  const op = routine.operations[0]!; op.operationId = 'op'; op.lineageId = 'lineage';
  routine.consumerMap.entries = [routine.consumerMap.entries.find(e => e.consumerId === 'ci')!]; routine.consumerMap.hash = contentDigest(routine.consumerMap.entries);
  op.actions = op.actions.filter(action => action.id !== 'delivery');
  op.actions.find(action => action.id === 'validate')!.parameters.resourceId = 'created:op';
  const descriptor = { driver: 'vercel' as const, consumerId: 'ci', destinationId: 'job', revision: 'job-2', consumerMapRevision: 'map-2', generation: 2, handleId: 'vault-handle', version: 1, mappingTokenFingerprint: contentDigest('mapping'), projectId: 'project', teamId: 'team', environment: 'production' as const, variable: 'API_KEY', accountId: 'account', pushTokenFingerprint: credentialFingerprint('synthetic-push') };
  const delivery = op.actions.find(action => action.kind === 'deliver')!; delivery.parameters.destinationId = 'job'; delivery.parameters.configurationHash = contentDigest(descriptor);
  const routineInput = f.grant(routine); let networkCalls = 0; let pushCalls = 0;
  const another = createScheduledEngine(f.journal, gate, f.drivers, { mode: 'synthetic', clock: () => 2000 }, { currentSnapshot: () => routine, clock: () => 2000 });
  const consumer = createVercelConsumer({ descriptor, store: { async withValue(_h, _v, fn) { await fn('synthetic-secret'); return { status: 'resolved' as const }; } }, trust: { clock: () => 2000, quarantine: (consumerId, destinationId) => new QuarantineStore(f.journal).check(consumerId, destinationId), beforeEffect: async intent => { await another.approvals.assertReservedIntentAuthority({ ...routineInput, actionId: intent.actionId, intentId: intent.intentId, currentSnapshotDigest: snapshotDigest(routine), now: 2000 }); } }, transport: async (_url, init) => { networkCalls++; if (init?.method === 'POST') pushCalls++; return new Response(JSON.stringify({ id: 'project', accountId: 'team' }), { status: 200 }); }, pushToken: 'synthetic-push', admission: { assertAdmitted: async () => {} } });
  f.drivers.deliver = (intent, context) => consumer.deliver(intent, context);
  const held = await another.engine.run(routineInput);
  assert.equal(held.state, 'held', JSON.stringify(held)); assert.ok(held.holds.includes('deliver-rejected')); assert.equal(networkCalls, 1); assert.equal(pushCalls, 0);
  f.journal.close();
});

test('notification failure stops the next real engine effect while retaining the completed creation', async () => {
  const f = fixture(); const gate = new MutationInterlock(f.journal, async () => { throw new Error('unavailable'); });
  const original = f.drivers.create;
  f.drivers.create = async (intent, context) => { const receipt = await original(intent, context); gate.prepare('created-notice', 'created', 'op'); return receipt; };
  const wired = createScheduledEngine(f.journal, gate, f.drivers, { mode: 'synthetic', clock: () => 2000 }, { currentSnapshot: () => f.m, clock: () => 2000 });
  await assert.rejects(wired.engine.run(f.input), /notification/);
  assert.deepEqual(f.calls, ['create', 'store']); assert.equal(f.journal.listIntents('op').length, 1);
  assert.equal(f.journal.listIntents('op')[0]?.state, 'observed'); assert.equal(gate.alarms().length, 1); f.journal.close();
});

import { createVercelConsumer } from '../src/consumers/vercel.js';
import { credentialFingerprint } from '../src/consumers/consumer.js';

test('scheduler bounds validity reads, preserves unknown, records cadence and alerts verified unexpected revocation', async () => {
  const f = fixture(); let now = 2000; const gate = new MutationInterlock(f.journal);
  const wired = createScheduledEngine(f.journal, gate, f.drivers, { mode: 'synthetic', clock: () => now }, { currentSnapshot: () => f.m, clock: () => now });
  const scheduler = new Scheduler(wired.engine, gate, { clock: () => now, timeoutMs: 5 }); let calls = 0;
  assert.equal(await scheduler.validity('lineage', 10, async () => { calls++; throw new Error('network'); }), 'unverified');
  assert.equal(await scheduler.validity('lineage', 10, async () => { calls++; return 'confirmed-revoked'; }), 'unverified'); assert.equal(calls, 1);
  now += 10; assert.equal(await scheduler.validity('lineage', 10, async () => 'confirmed-revoked'), 'confirmed-revoked');
  assert.equal(gate.list()[0]?.kind, 'unexpected-revocation-offer-replacement');
  now += 10; assert.equal(await scheduler.validity('other', 10, async () => new Promise(() => {})), 'unverified');
  f.approvals.cancelGrant('grant'); assert.deepEqual(await scheduler.tick('grant'), []); assert.equal(f.calls.length, 0); f.journal.close();
});

async function exerciseMixed(variant: 'verified' | 'unknown' | 'active' | 'probe-accepted' | 'unmarked') {
  const f = fixture(); const keys = generateKeyPairSync('ec', { namedCurve: 'prime256v1' }); const jwk = keys.publicKey.export({ format: 'jwk' });
  const enrollment = { signerId: 'emergency', credentialId: Buffer.from('revoke-first-key').toString('base64url'), cosePublicKey: isoCBOR.encode(new Map<number, number | Uint8Array>([[1, 2], [3, -7], [-1, 1], [-2, Buffer.from(jwk.x!, 'base64url')], [-3, Buffer.from(jwk.y!, 'base64url')]])), rpId: 'approve.keyroot.test', origin: 'https://approve.keyroot.test' };
  const enroll = structuredClone(f.m); enroll.nonce = 'enroll-mixed'; enroll.operations = [{ operationId: 'enroll-op', lineageId: 'owner', accountId: 'account', fromGeneration: 0, toGeneration: 1, actions: [{ id: 'enroll', kind: 'admin', parameters: { resourceId: 'emergency-approver', destinationId: 'emergency', authorityFingerprint: emergencyEnrollmentFingerprint(enrollment) }, budgetCost: { effects: 1, newCredentials: 0, restarts: 0 } }] }];
  const signed = f.grant(enroll); const intent = await f.approvals.authorizeEffect({ ...signed, operationId: 'enroll-op', actionId: 'enroll', currentSnapshotDigest: snapshotDigest(enroll), now: 2000 });
  const web = new EmergencyWebAuthn(f.journal, { clock: () => 2000 }); web.enrollCredential({ ...enrollment, authorizationIntentId: intent.intentId, now: 2000, confirmedFingerprint: publicKeyFingerprint(jwk) });
  const m = structuredClone(f.m); m.role = 'emergency'; m.signerId = 'emergency'; m.nonce = 'mixed'; if (variant !== 'unmarked') m.outage = { permitted: true, consequence: 'declared-interruption' };
  const actions = m.operations[0]!.actions; const revoke = actions.pop()!; if (variant !== 'unmarked') revoke.parameters.reasonCode = 'incident-revoke-first'; actions.unshift(revoke);
  f.approvals.registerEmergencyGrant(canonicalizeManifest(m), 2000);
  const gate = new MutationInterlock(f.journal); const wired = createScheduledEngine(f.journal, gate, f.drivers, { mode: 'synthetic', clock: () => 2000 }, { currentSnapshot: () => m, clock: () => 2000 });
  const coordinator = new IncidentCoordinator(wired.engine, gate, () => 2000); const proofMap: Record<string, string> = {};
  for (const [i, action] of actions.entries()) {
    const c = web.createChallenge({ grantId: 'mixed', operationId: 'op', actionId: action.id, now: 2000 }); const client = Buffer.from(JSON.stringify({ type: 'webauthn.get', challenge: c.challenge, origin: enrollment.origin, crossOrigin: false }));
    const counter = Buffer.alloc(4); counter.writeUInt32BE(i + 1); const auth = Buffer.concat([createHash('sha256').update(enrollment.rpId).digest(), Buffer.from([5]), counter]); const data = Buffer.concat([auth, createHash('sha256').update(client).digest()]);
    const proof = await web.verifyAssertion({ challengeId: c.challengeId, operationId: 'op', actionId: action.id, now: 2000, response: { id: enrollment.credentialId, rawId: enrollment.credentialId, type: 'public-key', clientExtensionResults: {}, response: { clientDataJSON: client.toString('base64url'), authenticatorData: auth.toString('base64url'), signature: sign('sha256', data, keys.privateKey).toString('base64url') } } });
    proofMap[action.id] = proof; if (i === 0 && variant !== 'unmarked') coordinator.prepare('mixed', proof, []);
  }
  const issuer = f.drivers.observeIssuer; const probe = f.drivers.probeOld;
  f.drivers.observeIssuer = async (...args) => { f.calls.push('issuer'); return variant === 'unknown' ? f.receipt(args[0], 'issuer', 'unverified') : variant === 'active' ? f.receipt(args[0], 'issuer', 'confirmed-active') : issuer(...args); };
  f.drivers.probeOld = async (...args) => { f.calls.push('probe'); return variant === 'probe-accepted' ? f.receipt(args[0], 'probe', 'accepted') : probe(...args); };
  if (variant === 'unmarked') {
    await assert.rejects(wired.engine.run({ grantId: 'mixed', operationId: 'op', emergencyProofs: proofMap }), /replacement binding/); assert.equal(f.calls.length, 0);
  } else {
    const report = await coordinator.execute('mixed', { op: proofMap });
    if (variant !== 'verified') { assert.equal(report[0]?.containment, variant === 'active' ? 'confirmed-active' : variant === 'probe-accepted' ? 'confirmed-revoked' : 'unverified'); assert.ok(!f.calls.includes('create')); assert.deepEqual(f.calls.slice(0, 3), ['revoke', 'issuer', 'probe']); }
    else { assert.equal(report[0]?.containment, 'confirmed-revoked'); assert.deepEqual(f.calls.slice(0, 5), ['revoke', 'issuer', 'probe', 'create', 'store']); assert.ok(f.calls.includes('validate')); assert.ok(f.calls.includes('deliver')); }
  }
  f.journal.close();
}
test('signed emergency revoke-first waits for fresh terminal evidence before creating a successor', async () => exerciseMixed('verified'));
test('unverified emergency revocation holds before creating a successor', async () => exerciseMixed('unknown'));
test('confirmed active issuer holds before creating a successor', async () => exerciseMixed('active'));
test('accepted old-key probe holds before creating a successor', async () => exerciseMixed('probe-accepted'));
test('unmarked emergency work cannot bypass ordinary adoption', async () => exerciseMixed('unmarked'));

test('journal receipt failure stops the scheduler before any later real effect', async () => {
  const f = fixture(); const gate = new MutationInterlock(f.journal);
  const wired = createScheduledEngine(f.journal, gate, f.drivers, { mode: 'synthetic', clock: () => 2000 }, { currentSnapshot: () => f.m, clock: () => 2000 });
  f.journal.transaction(db => db.exec("CREATE TRIGGER fail_receipt BEFORE INSERT ON engine_receipt BEGIN SELECT RAISE(ABORT,'synthetic-journal-failure'); END"));
  await assert.rejects(new Scheduler(wired.engine, gate, { clock: () => 2000 }).tick('grant'), /synthetic-journal-failure/);
  assert.deepEqual(f.calls, ['create', 'store']); assert.equal(f.journal.listIntents('op')[0]?.state, 'pending'); assert.equal(gate.alarms()[0]?.kind, 'journal-failed'); await assert.rejects(gate.checkEffectFence(), /interlock/); f.journal.close();
});

test('expired signed windows permit reconciliation but no new engine effects', async () => {
  const f = fixture(); let now = 2000; const gate = new MutationInterlock(f.journal);
  f.drivers.create = async (_intent, context) => { f.calls.push('create'); return f.receipt(context.subject, 'create', 'unknown'); };
  const wired = createScheduledEngine(f.journal, gate, f.drivers, { mode: 'synthetic', clock: () => now }, { currentSnapshot: () => f.m, clock: () => now });
  assert.equal((await wired.engine.run(f.input)).state, 'reconcile-required'); now = 10000; f.setNow(now);
  const result = await new Scheduler(wired.engine, gate, { clock: () => now }).tick('grant');
  assert.equal(result[0]?.snapshot?.state, 'reconcile-required'); assert.deepEqual(f.calls, ['create', 'reconcile']);
  assert.equal(f.journal.listIntents('op').length, 1); f.journal.close();
});

test('scheduler retains a failed credential while dispatching its signed peer once', async () => {
  const f = fixture(m => {
    const op = m.operations[0]!; const create = op.actions[0]!;
    m.operations = ['first', 'second'].map(name => ({ ...structuredClone(op), operationId: name, lineageId: name, actions: [structuredClone(create)] }));
    m.budgets = { effects: 4, newCredentials: 2, restarts: 0, executions: 2 };
  });
  f.drivers.create = async (_intent, context) => {
    f.calls.push(context.subject.operationId);
    if (context.subject.operationId === 'first') return f.receipt(context.subject, 'create', 'rejected');
    await context.beforeStore(); return { ...f.receipt({ ...context.subject, resourceId: 'new-key' }, 'create', 'stored'), storeBinding: { operationId: 'second', lineageId: 'second', accountId: 'account', generation: 2, issuerId: 'new-key', handleId: 'vault-handle', destinationId: 'vault', version: 1 } };
  };
  const gate = new MutationInterlock(f.journal); const wired = createScheduledEngine(f.journal, gate, f.drivers, { mode: 'synthetic', clock: () => 2000 }, { currentSnapshot: () => f.m, clock: () => 2000 });
  const scheduler = new Scheduler(wired.engine, gate, { clock: () => 2000 }); const results = await scheduler.tick('grant');
  assert.deepEqual(results.map(r => r.snapshot?.replacement), ['rejected', 'stored']); assert.deepEqual(f.calls, ['first', 'second']);
  await scheduler.tick('grant'); assert.deepEqual(f.calls, ['first', 'second']); f.journal.close();
});

test('effect fence rechecks a journal alarm raised while the composed fence is paused', async () => {
  const f = fixture(); const gate = new MutationInterlock(f.journal); let fenceCalls = 0;
  let release!: () => void; let signal!: () => void;
  const blocked = new Promise<void>(resolve => { release = resolve; });
  const entered = new Promise<void>(resolve => { signal = resolve; });
  const wired = createScheduledEngine(f.journal, gate, f.drivers, { mode: 'synthetic', clock: () => 2000, checkEffectFence: async () => { if (++fenceCalls === 3) { signal(); await blocked; } } }, { currentSnapshot: () => f.m, clock: () => 2000 });
  const run = wired.engine.run(f.input); await entered; gate.journalFailed('concurrent-failure'); release();
  await assert.rejects(run, /interlock/);
  assert.deepEqual(f.calls, ['create', 'store']); assert.equal(f.journal.listIntents('op')[0]?.state, 'observed'); assert.equal(f.journal.listIntents('op').length, 1); f.journal.close();
});

test('effect fence rechecks a journal alarm raised during deferred notification delivery', async () => {
  const f = fixture(); let release!: () => void; let signal!: () => void;
  const blocked = new Promise<void>(resolve => { release = resolve; });
  const entered = new Promise<void>(resolve => { signal = resolve; });
  const gate = new MutationInterlock(f.journal, async () => { signal(); await blocked; });
  const create = f.drivers.create;
  f.drivers.create = async (intent, context) => { const result = await create(intent, context); gate.prepare('notice', 'creation', 'op'); return result; };
  const wired = createScheduledEngine(f.journal, gate, f.drivers, { mode: 'synthetic', clock: () => 2000 }, { currentSnapshot: () => f.m, clock: () => 2000 });
  const run = wired.engine.run(f.input); await entered; gate.journalFailed('concurrent-failure'); release();
  await assert.rejects(run, /interlock/);
  assert.deepEqual(f.calls, ['create', 'store']); assert.equal(f.journal.listIntents('op')[0]?.state, 'observed'); assert.equal(f.journal.listIntents('op').length, 1); f.journal.close();
});

test('failed journal alarm write cannot be cleared by notification retry before reconciliation', async () => {
  const f = fixture(); const gate = new MutationInterlock(f.journal); let current = f.m;
  f.drivers.create = async (_intent, context) => { f.calls.push(context.subject.operationId); return f.receipt(context.subject, 'create', 'unknown'); };
  const wired = createScheduledEngine(f.journal, gate, f.drivers, { mode: 'synthetic', clock: () => 2000 }, { currentSnapshot: () => current, clock: () => 2000 });
  assert.equal((await wired.engine.run(f.input)).state, 'reconcile-required');
  f.journal.transaction(db => db.exec("CREATE TRIGGER fail_alarm BEFORE INSERT ON schedule_alarm BEGIN SELECT RAISE(ABORT,'alarm-unavailable'); END"));
  gate.journalFailed('lost-journal-alarm');
  f.journal.transaction(db => db.exec('DROP TRIGGER fail_alarm'));
  const next = structuredClone(f.m); next.nonce = 'next-safe'; next.operations[0]!.operationId = 'op2'; next.operations[0]!.lineageId = 'lineage2'; next.operations[0]!.actions = [next.operations[0]!.actions[0]!];
  const signed = f.grant(next); current = next;
  await assert.rejects(gate.retry(), /interlock/);
  await assert.rejects(wired.engine.run({ ...signed, operationId: 'op2' }), /interlock/);
  assert.deepEqual(f.calls, ['op']);
  assert.throws(() => gate.acknowledgeJournalRecovery(), /interlock/);
  f.drivers.reconcile = async (_intent, context) => f.receipt(context.subject, 'create', 'rejected');
  await wired.engine.reconcile('op'); gate.acknowledgeJournalRecovery();
  f.drivers.create = async (_intent, context) => { f.calls.push(context.subject.operationId); return f.receipt(context.subject, 'create', 'rejected'); };
  await wired.engine.run({ ...signed, operationId: 'op2' }); assert.deepEqual(f.calls, ['op', 'op2']); f.journal.close();
});
