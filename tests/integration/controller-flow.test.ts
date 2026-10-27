import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { generateKeyPairSync, sign, verify, createPublicKey } from 'node:crypto';
import { startController } from '../../apps/controller/src/server.js';
import { localCommand, ownerRequest } from '../../apps/controller/src/cli.js';
import { canonicalJSON, parseCanonicalManifest, contentDigest } from '../../packages/core/src/manifest.js';
import { validateControllerRow, type ControllerTable } from '../../apps/controller/src/metadata.js';
import { createDemoPorts } from '../../apps/controller/src/demo.js';
import type { PreparedBatch } from '../../apps/controller/src/service.js';
async function fixture(t: { after(fn: () => Promise<void>): void }, clock?: () => number, ports?: import('../../apps/controller/src/service.js').TrustedControllerPorts) {
  const directory = await mkdtemp(join(tmpdir(), 'kr-flow-'));
  // Configured-port acceptance runs an explicit REAL authority boundary over hermetic fixture transports.
  // These trusted test assertions establish no actual owner account/store/custody/isolation readiness.
  const hermetic = ports ? createDemoPorts(clock) : undefined;
  const unavailable = async (): Promise<never> => { throw new Error('Hermetic fixture has no configured consumer'); };
  const consumers = ports?.consumers ?? { deliver: unavailable, observeConsumer: unavailable, observeOldUse: unavailable };
  const testAdmission = async () => { assert.ok(hermetic, 'hermetic test admission only'); };
  const realFixturePorts = ports && hermetic ? { ...ports, issuerConfiguration: ports.issuerConfiguration ?? hermetic.configuration, lineageTargets: ports.lineageTargets ?? hermetic.target, lifecycleDrivers: ports.lifecycleDrivers ?? ((configuration, authority) => hermetic.drivers(configuration, authority, consumers)), liveGates: { account: testAdmission, store: testAdmission, phoneCustody: testAdmission, origin: testAdmission, isolation: testAdmission, recovery: testAdmission }, assertLiveAdmission: async context => { assert.ok(context.action.parameters.configurationHash); await testAdmission(); } } satisfies import('../../apps/controller/src/service.js').TrustedControllerPorts : undefined;
  const app = realFixturePorts
    ? await startController({ directory, port: 0, mode: 'real', phoneOrigin: 'https://phone.fixture.invalid', ports: realFixturePorts, ...(clock ? { clock } : {}) })
    : await startController({ directory, port: 0, mode: 'demo', phoneOrigin: 'https://phone.fixture.invalid', ...(clock ? { clock } : {}) });
  if (realFixturePorts) { assert.equal((await fetch(app.origin + '/api/session/demo', { method:'POST',headers:{Origin:app.origin} })).status,404); const inventory = app.service.inventory(); inventory.lineages.push({ id:'demo-lineage',issuerId:'openai-service-account',accountId:'demo-account',credentialType:'service-account-key',grantType:'static-key' }); app.service.journal.transaction(db => db.prepare("UPDATE controller_inventory SET metadata=? WHERE id='inventory'").run(canonicalJSON(inventory))); }
  t.after(async () => { try { for (const [table, rows] of Object.entries(app.service.metadata.exportRows())) for (const row of rows as Record<string, unknown>[]) validateControllerRow(table as ControllerTable, row); } finally { await app.close(); await rm(directory, { recursive: true, force: true }); } });
  const headers = { Origin: app.phoneOrigin, 'Content-Type': 'application/json' }; const keys = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const signature = (value: string) => sign('sha256', Buffer.from(value), { key: keys.privateKey, dsaEncoding: 'ieee-p1363' }).toString('base64url');
  const post = (path: string, body: unknown) => fetch(app.origin + path, { method: 'POST', headers, body: JSON.stringify(body) });
  const pairing = await post('/api/pairing/requests', { signerId: 'phone', role: 'routine', publicKey: keys.publicKey.export({ format: 'jwk' }) });
  assert.equal(pairing.status, 201); const pair = await pairing.json() as { requestId: string; fingerprint: string; challenge: unknown };
  await assert.rejects(localCommand(directory, { command: 'pair-confirm', requestId: pair.requestId, fingerprint: pair.fingerprint }));
  assert.equal((await post(`/api/pairing/requests/${pair.requestId}/proof`, { signature: signature('keyroot.pairing-possession.v1\0' + canonicalJSON(pair.challenge)) })).status, 200);
  assert.equal((await localCommand(directory, { command: 'pair-confirm', requestId: pair.requestId, fingerprint: pair.fingerprint })).outcome, 'paired');
  const owner = (path: string, method = 'GET', body?: unknown) => ownerRequest(directory, path, method, body);
  async function prepare(purpose?: string, targetId?: string, policy?: unknown) {
    return await owner('/api/batches/prepare', 'POST', { signerId: 'phone', lineageIds: ['demo-lineage'], ...(purpose ? { purpose, targetId, ...(policy ? { policy } : {}) } : {}) }) as PreparedBatch;
  }
  async function approve(batch: PreparedBatch) {
    const response = await post('/api/approvals', { batchId: batch.batchId, rawManifest: batch.rawManifest, signature: signature(batch.rawManifest) }); assert.equal(response.status, 201); return await response.json() as { grantId: string; digest: string };
  }
  return { app, directory, headers, keys, signature, post, owner, prepare, approve, pair };
}

test('actual HTTP paired P256 approval drives scheduled engine and issuer/KV2 protocols without false completion', async t => {
  const f = await fixture(t); const batch = await f.prepare(); const manifest = parseCanonicalManifest(batch.rawManifest);
  for (const hash of batch.configurationHashes) { const descriptor = await f.owner('/api/configurations/' + hash) as { hash: string; descriptor: unknown }; assert.equal(contentDigest(descriptor.descriptor), hash); }
  const grant = await f.approve(batch); assert.equal(grant.digest, batch.digest);
  assert.equal((await f.post('/api/approvals', { batchId: batch.batchId, rawManifest: batch.rawManifest, signature: f.signature(batch.rawManifest) })).status, 409);
  const result = await f.owner('/api/operations/run', 'POST', { grantId: grant.grantId, operationId: manifest.operations[0]!.operationId }) as { state: string; replacement: string; receipts: Array<{ kind: string; outcome: string }> };
  assert.equal(result.replacement, 'stored'); assert.equal(result.receipts.find(r => r.kind === 'validate')?.outcome, 'validated'); assert.equal(result.state, 'held');
  assert.equal(JSON.stringify(result).includes('synthetic-one-time'), false);
  const boot = f.app.service.journal.bootId; await f.owner('/api/overview'); assert.equal(f.app.service.journal.bootId, boot);
});

test('phone metadata requires one-use bound read signature and verifies pinned identity response', async t => {
  const f = await fixture(t); const challengeResponse = await f.post('/api/phone/challenge', { signerId: 'phone', method: 'GET', path: '/api/batches' });
  const challenge = await challengeResponse.json() as { nonce: string };
  const headers = { Origin: f.app.phoneOrigin, 'X-Keyroot-Nonce': challenge.nonce, 'X-Keyroot-Signature': f.signature('keyroot.phone-read.v1\0' + canonicalJSON(challenge)) };
  const response = await fetch(f.app.origin + '/api/batches', { headers }); assert.equal(response.status, 200);
  const envelope = await response.json() as { payload: { requestNonce: string; data: unknown }; signature: string };
  assert.equal(envelope.payload.requestNonce, challenge.nonce);
  assert.ok(verify('sha256', Buffer.from('keyroot.controller-response.v1\0' + canonicalJSON(envelope.payload)), { key: createPublicKey({ key: f.app.identity.publicKey, format: 'jwk' }), dsaEncoding: 'ieee-p1363' }, Buffer.from(envelope.signature, 'base64url')));
  assert.equal((await fetch(f.app.origin + '/api/batches', { headers })).status, 401);
});

for (const kind of ['key-policy', 'retire', 'approver-removal'] as const) test(`HTTP ${kind} action requires distinct signed nonreplayed intent`, async t => {
  const f = await fixture(t); const batch = await f.prepare(kind, kind === 'approver-removal' ? 'phone' : 'demo-lineage', kind === 'key-policy' ? { rotationDays: 7 } : undefined); const manifest = parseCanonicalManifest(batch.rawManifest); const grant = await f.approve(batch);
  const request = { grantId: grant.grantId, operationId: manifest.operations[0]!.operationId, actionId: kind };
  await assert.rejects(f.owner('/api/actions/cancel', 'POST', request));
  const result = await f.owner('/api/actions/' + kind, 'POST', request) as { outcome: string }; assert.equal(result.outcome, 'recorded');
  await assert.rejects(f.owner('/api/actions/' + kind, 'POST', request));
  if (kind === 'retire') await assert.rejects(f.prepare());
});

test('HTTP rejects private key fields, changed manifests, forged proof objects, foreign origins, demo-to-real bypass', async t => {
  const f = await fixture(t);
  assert.equal((await f.post('/api/pairing/requests', { signerId: 'attack', role: 'routine', publicKey: f.keys.privateKey.export({ format: 'jwk' }) })).status, 400);
  const batch = await f.prepare(); const changed = batch.rawManifest.replace('demo-account', 'other-account');
  assert.equal((await f.post('/api/approvals', { batchId: batch.batchId, rawManifest: changed, signature: f.signature(changed) })).status, 409);
  assert.equal((await f.post('/api/emergency/assertion', { challengeId: 'made-up', operationId: 'op', actionId: 'revoke', verified: true })).status, 400);
  assert.equal((await fetch(f.app.origin + '/api/pairing/requests', { method: 'POST', headers: { ...f.headers, Origin: 'https://evil.invalid' }, body: '{}' })).status, 403);
  const unknown = await fetch(f.app.origin + '/api/secret-token-example'); assert.equal(unknown.status, 404); assert.deepEqual(await unknown.json(), { error: 'not_found' });
});

import { createHash } from 'node:crypto';
import { isoCBOR } from '@simplewebauthn/server/helpers';
import { writeFile } from 'node:fs/promises';

test('public HTTP maintained registration and signed enrollment permit fresh incremental emergency gestures', async t => {
  let now = Date.now(); const f = await fixture(t, () => now); const emergency = generateKeyPairSync('ec', { namedCurve: 'prime256v1' }); const jwk = emergency.publicKey.export({ format: 'jwk' });
  const rpId = new URL(f.app.phoneOrigin).hostname; const credential = Buffer.from('synthetic-emergency-hardware-id'); const credentialId = credential.toString('base64url');
  const cose = isoCBOR.encode(new Map<number, number | Uint8Array>([[1, 2], [3, -7], [-1, 1], [-2, Buffer.from(jwk.x!, 'base64url')], [-3, Buffer.from(jwk.y!, 'base64url')]]));
  const registrationChallenge = await f.post('/api/emergency/enrollment/challenge', { signerId: 'emergency' }); assert.equal(registrationChallenge.status, 200);
  const registration = await registrationChallenge.json() as { requestId: string; options: { challenge: string } };
  const length = Buffer.alloc(2); length.writeUInt16BE(credential.length);
  const authData = Buffer.concat([createHash('sha256').update(rpId).digest(), Buffer.from([0x45]), Buffer.alloc(4), Buffer.alloc(16), length, credential, Buffer.from(cose)]);
  const attestation = isoCBOR.encode(new Map<string, string | Map<string, string> | Uint8Array>([['fmt', 'none'], ['attStmt', new Map<string, string>()], ['authData', authData]]));
  const response = { id: credentialId, rawId: credentialId, type: 'public-key', clientExtensionResults: {}, response: { attestationObject: Buffer.from(attestation).toString('base64url'), clientDataJSON: Buffer.from(JSON.stringify({ type: 'webauthn.create', challenge: registration.options.challenge, origin: f.app.phoneOrigin, crossOrigin: false })).toString('base64url'), transports: ['usb'] } };
  const verifiedResponse = await f.post('/api/emergency/enrollment/verify', { requestId: registration.requestId, response }); assert.equal(verifiedResponse.status, 200); const verified = await verifiedResponse.json() as { requestId: string };
  const inventory = await f.owner('/api/inventory') as import('../../apps/controller/src/service.js').Inventory;
  inventory.lineages.push({ ...inventory.lineages[0]!, id: 'second-lineage' }); inventory.consumerMap.revision++;
  inventory.consumerMap.bindings = inventory.lineages.map((lineage, index) => ({ id: 'incident-binding-' + index, lineageId: lineage.id, consumerId: 'machine-1', destinationId: index === 0 ? 'affected-destination' : 'healthy-destination', consumerRevision: 'incident-revision-' + index, association: { kind: 'declared', source: 'owner-synthetic-fixture', observedAt: new Date(now).toISOString() } }));
  const declaration = await f.owner('/api/batches/prepare', 'POST', { signerId: 'phone', lineageIds: ['demo-lineage'], purpose: 'inventory-update', targetId: 'inventory', inventory }) as PreparedBatch;
  const declarationGrant = await f.approve(declaration); await f.owner('/api/actions/inventory-update', 'POST', { grantId: declarationGrant.grantId, operationId: parseCanonicalManifest(declaration.rawManifest).operations[0]!.operationId, actionId: 'inventory-update' });
  const enrollmentBatch = await f.prepare('emergency-enrollment', verified.requestId); const enrollmentGrant = await f.approve(enrollmentBatch); const enrollmentManifest = parseCanonicalManifest(enrollmentBatch.rawManifest);
  await f.owner('/api/actions/emergency-enrollment', 'POST', { grantId: enrollmentGrant.grantId, operationId: enrollmentManifest.operations[0]!.operationId, actionId: 'emergency-enrollment' });
  const batch = await f.owner('/api/batches/prepare', 'POST', { signerId: 'emergency', role: 'emergency', lineageIds: ['demo-lineage', 'second-lineage'], incident: { policy: 'revoke-first', quarantineDestinations: [{ consumerId: 'machine-1', destinationId: 'affected-destination' }], outage: { permitted: true, consequence: 'declared-interruption' } } }) as PreparedBatch;
  const manifest = parseCanonicalManifest(batch.rawManifest); assert.deepEqual(manifest.operations[0]!.actions.map(a => a.kind), ['revoke']);
  const planHash = manifest.operations[0]!.actions[0]!.parameters.incidentPlanHash!; assert.ok(batch.configurationHashes.includes(planHash));
  const planDescriptor = await f.owner('/api/configurations/' + planHash) as { descriptor: { policy: string; quarantineDestinations: unknown[]; affectedLineages: string[] } }; assert.equal(planDescriptor.descriptor.policy, 'revoke-first'); assert.deepEqual(planDescriptor.descriptor.quarantineDestinations, [{ consumerId: 'machine-1', destinationId: 'affected-destination' }]); assert.deepEqual(planDescriptor.descriptor.affectedLineages, ['demo-lineage','second-lineage']);
  await assert.rejects(f.owner('/api/incidents/prepare', 'POST', { grantId: batch.batchId, proofId: 'unverified', destinations: [{ consumerId: 'machine-1', destinationId: 'healthy-destination' }] }));
  assert.equal((await f.post('/api/approvals', { batchId: batch.batchId, rawManifest: batch.rawManifest })).status, 201);
  const originalRaw = batch.rawManifest; let count = 0;
  for (const op of manifest.operations) {
    if (count > 0) now += 35000; // Whole ceremony exceeds proof TTL, each immediate gesture remains fresh.
    const challengeResponse = await f.post('/api/emergency/challenge', { grantId: batch.batchId, operationId: op.operationId, actionId: 'revoke' });
    const challenge = await challengeResponse.json() as { challengeId: string; challenge: string; binding: import('../../packages/core/src/emergency-webauthn.js').EmergencyChallengeBinding };
    assert.equal(challenge.binding.digest,batch.digest); assert.equal(challenge.binding.role,'emergency'); assert.equal(challenge.binding.operationId,op.operationId); assert.equal(challenge.binding.actionId,'revoke'); assert.equal(challenge.binding.domain,'keyroot.emergency.webauthn.v1'); assert.equal(challenge.challenge,Buffer.from(contentDigest(challenge.binding),'utf8').toString('base64url'));
    const client = Buffer.from(JSON.stringify({ type: 'webauthn.get', challenge: challenge.challenge, origin: f.app.phoneOrigin, crossOrigin: false }));
    const counter = Buffer.alloc(4); counter.writeUInt32BE(++count); const authenticator = Buffer.concat([createHash('sha256').update(rpId).digest(), Buffer.from([5]), counter]);
    const assertionResponse = { id: credentialId, rawId: credentialId, type: 'public-key', clientExtensionResults: {}, response: { clientDataJSON: client.toString('base64url'), authenticatorData: authenticator.toString('base64url'), signature: sign('sha256', Buffer.concat([authenticator, createHash('sha256').update(client).digest()]), emergency.privateKey).toString('base64url') } };
    const assertion = await f.post('/api/emergency/assertion', { challengeId: challenge.challengeId, operationId: op.operationId, actionId: 'revoke', response: assertionResponse }); assert.equal(assertion.status, 200); const proof = await assertion.json() as { proofId: string };
    const executed = await f.post('/api/emergency/execute', { grantId: batch.batchId, proofs: { [op.operationId]: { revoke: proof.proofId } } }); assert.equal(executed.status, 200);
    const reports = await executed.json() as Array<{ serviceRestoration: string; containment: string; residualTokenValidity: string }>; assert.equal(reports[0]!.serviceRestoration, 'not-started'); assert.equal(reports[0]!.containment, 'unverified');
    const progress = await f.owner('/api/batches/' + batch.batchId) as PreparedBatch; assert.equal(progress.rawManifest, originalRaw); assert.equal(progress.progress.filter(p => p.dispatchComplete).length, count); assert.equal(await f.app.service.quarantine.check('machine-1','affected-destination'), 'quarantined'); assert.equal(await f.app.service.quarantine.check('machine-1','healthy-destination'), 'clear');
    assert.equal((await f.post('/api/emergency/execute', { grantId: batch.batchId, proofs: { [op.operationId]: { revoke: proof.proofId } } })).status, 403);
  }
});

test('permanent recovery mode marker rejects demo before metadata and public demo sessions are opened', async t => {
  const directory = await mkdtemp(join(tmpdir(), 'kr-real-import-')); t.after(() => rm(directory, { recursive: true, force: true }));
  await writeFile(join(directory, 'runtime-mode'), 'real\n', { mode: 0o600 });
  await assert.rejects(startController({ directory, port: 0, mode: 'demo' }), /Runtime mode excludes demo/);
});

test('hermetic REAL fixture distinct signed callers reach configured native, discovery, guided and OAuth cores; replay never reruns ports', async t => {
  const calls: string[] = []; const evidenceHash = contentDigest({ evidence: 'synthetic-port-only' });
  const recipe = { id: 'guided-demo', version: 'v1', accountId: 'demo-account', destinationId: 'demo-vault', steps: [{ action: 'confirm' as const, targetId: 'mapped-store', checkpoint: 'none' as const }] };
  const f = await fixture(t, undefined, { native: { execute: async action => { calls.push(action); } }, platforms: [{ id: 'configured-platform', scan: async () => { calls.push('platform-scan'); return { bindings: [{ sourceId: 'configured-platform', name: 'NAMED_VALUE', consumerId: 'machine-1', provenance: 'observed' }], gaps: [{ sourceId: 'encrypted-values', status: 'unscanned', reason: 'opaque' }] }; } }], recipes: [recipe], oauth: {
    refresh: async () => { throw new Error('Not selected'); }, revoke: async () => ({ outcome: 'unknown', evidenceHash }), reconcile: async () => 'unknown',
    consent: async input => { calls.push('oauth-consent'); await input.beforeStore(); return { outcome: 'completed', evidenceHash }; },
  } });
  const invoke = async (kind: string, targetId: string) => { const batch = await f.prepare(kind, targetId); const grant = await f.approve(batch); const manifest = parseCanonicalManifest(batch.rawManifest); const request = { grantId: grant.grantId, operationId: manifest.operations[0]!.operationId, actionId: kind }; const result = await f.owner('/api/actions/' + kind, 'POST', request); await assert.rejects(f.owner('/api/actions/' + kind, 'POST', request)); return result; };
  const native = await invoke('native-sign-out', 'codex') as { remoteSession: string }; assert.equal(native.remoteSession, 'unverified');
  const discovery = await invoke('platform-discovery', 'configured-platform') as { bindings: unknown[]; gaps: unknown[] }; assert.equal(discovery.bindings.length, 1); assert.equal(discovery.gaps.length, 1);
  await f.owner('/api/guided/guided-demo'); await f.owner('/api/guided/guided-demo/step', 'POST', { targetId: 'mapped-store', checkpointAcknowledged: false });
  const guided = await invoke('guided-completion', 'guided-demo') as { limitation: string }; assert.match(guided.limitation, /attestation/);
  f.app.service.oauth!.registerLocal({ grantId: 'oauth-grant', familyId: 'refresh-family', ownerId: 'controller-owner', version: 1, accessExpiresAt: Date.now() + 3600000 });
  // Trusted fixture starts from a previously verified revocation, never from HTTP proof flags.
  f.app.service.journal.transaction(db => db.prepare("UPDATE oauth_family SET state='revoked' WHERE grant_id='oauth-grant'").run());
  const oauth = await invoke('oauth-consent', 'oauth-grant') as { outcome: string }; assert.equal(oauth.outcome, 'completed');
  assert.deepEqual(calls, ['codex-local-sign-out', 'platform-scan', 'oauth-consent']);
});

test('signed cancellation invalidates a different grant; schedules and owner-time intervals have actual HTTP callers', async t => {
  const f = await fixture(t); const pending = await f.prepare(); const target = await f.approve(pending); const cancel = await f.prepare('cancel', target.grantId); const signed = await f.approve(cancel); const m = parseCanonicalManifest(cancel.rawManifest);
  await f.owner('/api/actions/cancel', 'POST', { grantId: signed.grantId, operationId: m.operations[0]!.operationId, actionId: 'cancel' });
  await assert.rejects(f.owner('/api/operations/run', 'POST', { grantId: target.grantId, operationId: parseCanonicalManifest(pending.rawManifest).operations[0]!.operationId }));
  const forecast = await f.owner('/api/schedules/forecast', 'POST', { lineageId: 'demo-lineage', policyAt: Date.now() + 3600000, intervalDays: 7, mfaRequired: false, restartBudget: 0, executionBudget: 1 }) as { intervalDays: number }; assert.equal(forecast.intervalDays, 7);
  const interval = await f.owner('/api/metrics/begin', 'POST', { caseId: 'study', kind: 'review' }) as { intervalId: string }; await f.owner('/api/metrics/end', 'POST', { intervalId: interval.intervalId });
  const metrics = await f.owner('/api/metrics/study') as { openIntervals: number; activeMs: number }; assert.equal(metrics.openIntervals, 0); assert.ok(metrics.activeMs >= 0);
  const schedules = await f.owner('/api/schedules') as { forecasts: unknown[] }; assert.equal(schedules.forecasts.length, 1);
});

import { randomUUID } from 'node:crypto';
import type { LifecycleReceipt, ReceiptSubject } from '../../packages/core/src/receipts.js';

test('hermetic REAL fixture HTTP batch binds same consumer independently to each selected lineage and scopes actual engine observations', async t => {
  const delivered = new Set<string>(); const observed: string[] = [];
  const receipt = (subject: ReceiptSubject, kind: LifecycleReceipt['kind'], outcome: LifecycleReceipt['outcome']): LifecycleReceipt => ({ receiptId: randomUUID(), subject: { ...subject }, kind, outcome, observedAt: Date.now(), observerId: 'synthetic-registered-consumer', evidenceHash: contentDigest({ subject, kind, outcome }), limitationCodes: ['synthetic-only'] });
  const f = await fixture(t, undefined, {
    consumers: { deliver: async (_intent, context) => { delivered.add(context.subject.operationId + ':' + context.subject.consumerId); return receipt(context.subject, 'deliver', 'delivery-accepted'); }, observeConsumer: async subject => { observed.push(subject.lineageId + ':' + subject.revision); return receipt(subject, 'consumer-use', delivered.has(subject.operationId + ':' + subject.consumerId) ? 'direct-use' : 'unverified'); }, observeOldUse: async subject => receipt(subject, 'old-use', 'none-observed') },
    deliveryActions: (operationId, lineageId, generation) => [{ action: { id: 'deliver-machine', kind: 'deliver', parameters: { resourceId: 'created:' + operationId, consumerId: 'machine-1', destinationId: 'destination-' + lineageId, handleId: 'operations/' + operationId, generation, expectedRevision: 'revision-' + lineageId }, budgetCost: { effects: 1, newCredentials: 0, restarts: 0 } }, descriptor: { driver: 'wrapper', consumerId: 'machine-1', destinationId: 'destination-' + lineageId, handleId: 'operations/' + operationId, generation, revision: 'revision-' + lineageId, consumerMapRevision: 'map-2', version: 1, mappingTokenFingerprint: 'sha256:' + 'a'.repeat(64) } }],
  });
  const inventory = await f.owner('/api/inventory') as import('../../apps/controller/src/service.js').Inventory;
  inventory.lineages.push({ ...inventory.lineages[0]!, id: 'second-lineage' }); inventory.consumerMap.revision = 2;
  inventory.consumerMap.bindings = inventory.lineages.map(lineage => ({ id: 'binding-' + lineage.id, lineageId: lineage.id, consumerId: 'machine-1', destinationId: 'destination-' + lineage.id, consumerRevision: 'revision-' + lineage.id, association: { kind: 'declared', source: 'owner-declaration', observedAt: new Date().toISOString() } }));
  const declaration = await f.owner('/api/batches/prepare', 'POST', { signerId: 'phone', lineageIds: ['demo-lineage'], purpose: 'inventory-update', targetId: 'inventory', inventory }) as PreparedBatch; const declarationGrant = await f.approve(declaration);
  await f.owner('/api/actions/inventory-update', 'POST', { grantId: declarationGrant.grantId, operationId: parseCanonicalManifest(declaration.rawManifest).operations[0]!.operationId, actionId: 'inventory-update' });
  const batch = await f.owner('/api/batches/prepare', 'POST', { signerId: 'phone', lineageIds: ['demo-lineage', 'second-lineage'] }) as PreparedBatch;
  const manifest = parseCanonicalManifest(batch.rawManifest); assert.equal(manifest.consumerMap.entries.length, 2);
  assert.deepEqual(manifest.consumerMap.entries.map(entry => [entry.consumerId, entry.lineageId, entry.resourceId, entry.revision]), [['machine-1', 'demo-lineage', 'destination-demo-lineage', 'revision-demo-lineage'], ['machine-1', 'second-lineage', 'destination-second-lineage', 'revision-second-lineage']]);
  const grant = await f.approve(batch); await f.owner('/api/operations/run', 'POST', { grantId: grant.grantId, operationId: manifest.operations[0]!.operationId });
  assert.deepEqual(observed, ['demo-lineage:revision-demo-lineage']); assert.equal(delivered.size, 1);
});

import { readFile, realpath, chmod } from 'node:fs/promises';
import { fileDigest } from '../../packages/core/src/consumers/env-file.js';

test('hermetic REAL fixture signed HTTP env dry-run and rollback reach actual configured U6 file/vault executor without claiming successor adoption', async t => {
  const root = await realpath(await mkdtemp(join(tmpdir(), 'kr-env-http-'))); await chmod(root, 0o700); const path = join(root, '.env'); const original = Buffer.from('API_KEY=synthetic-old\nUNRELATED=keep\n'); const current = Buffer.from('API_KEY=synthetic-current\nUNRELATED=keep\n'); await writeFile(path, current, { mode: 0o600 });
  t.after(() => rm(root, { recursive: true, force: true }));
  const descriptor = { driver: 'env-file' as const, mode: 'rollback' as const, envFormat: 'node-env' as const, consumerId: 'machine-1', destinationId: 'local-env', revision: 'env-v2', consumerMapRevision: 'map-1', generation: 2, handleId: 'mapped-successor', version: 1, mappingTokenFingerprint: 'sha256:' + 'a'.repeat(64), rootId: 'fixture', relativePath: '.env', variable: 'API_KEY', expectedFileHash: fileDigest(current), backupHandle: 'backup', backupExpectedVersion: 0, backupVersion: 1, backupFileHash: fileDigest(original) };
  let backupReads = 0; const f = await fixture(t, undefined, { envTargets: [{ id: 'registered-env', descriptor, roots: { fixture: root }, store: { withValue: async () => ({ status: 'denied' }) }, backup: { write: async () => ({ status: 'denied' }), withValue: async (handle, version, execute) => { assert.equal(handle, 'backup'); assert.equal(version, 1); backupReads++; await execute(original.toString('base64')); return { status: 'resolved' }; } } }] });
  const invoke = async (kind: string) => { const batch = await f.prepare(kind, 'registered-env'); const grant = await f.approve(batch); const m = parseCanonicalManifest(batch.rawManifest); return { batch, grant, m, result: await f.owner('/api/actions/' + kind, 'POST', { grantId: grant.grantId, operationId: m.operations[0]!.operationId, actionId: kind }) as { outcome: string; limitationCodes: string[] } }; };
  const dry = await invoke('env-dry-run'); assert.equal(dry.result.outcome, 'matched'); assert.equal(backupReads, 0); assert.deepEqual(await readFile(path), current);
  const rollback = await invoke('env-rollback'); assert.equal(rollback.result.outcome, 'unknown'); assert.ok(rollback.result.limitationCodes.includes('authorized-rollback-applied')); assert.deepEqual(await readFile(path), original); assert.equal(backupReads, 1);
  assert.equal(f.app.service.inspect(rollback.m.operations[0]!.operationId).operation!.state, 'reconcile-required');
  assert.equal(JSON.stringify(rollback.result).includes('synthetic-old'), false);
});

test('policy changes and trusted-clock expiry invalidate previously signed HTTP grants before effect dispatch', async t => {
  let now = Date.now(); const f = await fixture(t, () => now); const stale = await f.prepare(); const oldGrant = await f.approve(stale);
  const policy = await f.prepare('key-policy', 'demo-lineage', { rotationDays: 7 }); const grant = await f.approve(policy); const policyManifest = parseCanonicalManifest(policy.rawManifest);
  await f.owner('/api/actions/key-policy', 'POST', { grantId: grant.grantId, operationId: policyManifest.operations[0]!.operationId, actionId: 'key-policy' });
  await assert.rejects(f.owner('/api/operations/run', 'POST', { grantId: oldGrant.grantId, operationId: parseCanonicalManifest(stale.rawManifest).operations[0]!.operationId }));
  const fresh = await f.prepare(); now += 300001; assert.equal((await f.post('/api/approvals', { batchId: fresh.batchId, rawManifest: fresh.rawManifest, signature: f.signature(fresh.rawManifest) })).status, 409);
});

test('hermetic REAL fixture failed native executable stays unverified and does not report confirmed sign-out', async t => {
  const f = await fixture(t, undefined, { native: { execute: async () => { throw new Error('synthetic-sensitive-error-redacted'); } } });
  const batch = await f.prepare('native-sign-out', 'codex'); const grant = await f.approve(batch); const manifest = parseCanonicalManifest(batch.rawManifest);
  const result = await f.owner('/api/actions/native-sign-out', 'POST', { grantId: grant.grantId, operationId: manifest.operations[0]!.operationId, actionId: 'native-sign-out' }) as { outcome: string; remoteSession: string };
  assert.equal(result.outcome, 'unverified'); assert.equal(result.remoteSession, 'unverified'); assert.equal(JSON.stringify(result).includes('sensitive'), false);
});

test('existing-trust routine key rotation requires new-key possession plus a distinct existing routine signed admin intent', async t => {
  const f = await fixture(t); const replacement = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const requested = await f.post('/api/pairing/requests', { signerId: 'replacement-phone', role: 'routine', publicKey: replacement.publicKey.export({ format: 'jwk' }) }); assert.equal(requested.status, 201);
  const pair = await requested.json() as { requestId: string; fingerprint: string; challenge: unknown };
  const signature = sign('sha256', Buffer.from('keyroot.pairing-possession.v1\0' + canonicalJSON(pair.challenge)), { key: replacement.privateKey, dsaEncoding: 'ieee-p1363' }).toString('base64url');
  assert.equal((await f.post(`/api/pairing/requests/${pair.requestId}/proof`, { signature })).status, 200);
  await assert.rejects(localCommand(f.directory, { command: 'pair-confirm', requestId: pair.requestId, fingerprint: pair.fingerprint }));
  assert.equal((await f.post('/api/phone/challenge', { signerId: 'replacement-phone', method: 'GET', path: '/api/inventory' })).status, 401);
  const batch = await f.prepare('approver-enrollment', pair.requestId); const approved = await f.approve(batch); const manifest = parseCanonicalManifest(batch.rawManifest);
  await f.owner('/api/actions/approver-enrollment', 'POST', { grantId: approved.grantId, operationId: manifest.operations[0]!.operationId, actionId: 'approver-enrollment' });
  assert.equal((await f.post('/api/phone/challenge', { signerId: 'replacement-phone', method: 'GET', path: '/api/inventory' })).status, 200);
});

test('actual scheduler tick caller cannot dispatch a cancelled or expired routine scope', async t => {
  const f = await fixture(t); const batch = await f.prepare(); const approved = await f.approve(batch); const result = await f.owner('/api/schedules/tick', 'POST', { grantId: approved.grantId }) as Array<{ snapshot: { replacement: string; state: string } }>;
  assert.equal(result.length, 1); assert.equal(result[0]!.snapshot.replacement, 'stored'); assert.equal(result[0]!.snapshot.state, 'held');
  const count = f.app.service.journal.listIntents(parseCanonicalManifest(batch.rawManifest).operations[0]!.operationId).length; const cancellation = await f.prepare('cancel', approved.grantId); const cancelGrant = await f.approve(cancellation); await f.owner('/api/actions/cancel', 'POST', { grantId: cancelGrant.grantId, operationId: parseCanonicalManifest(cancellation.rawManifest).operations[0]!.operationId, actionId: 'cancel' });
  await f.owner('/api/schedules/tick', 'POST', { grantId: approved.grantId }); assert.equal(f.app.service.journal.listIntents(parseCanonicalManifest(batch.rawManifest).operations[0]!.operationId).length, count);
});
