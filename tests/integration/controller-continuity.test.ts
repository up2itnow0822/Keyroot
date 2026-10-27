import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { startController } from '../../apps/controller/src/server.js';

test('demo durable state rejects a real restart without changing identity or inventory', async t => {
  const directory = await mkdtemp(join(tmpdir(), 'kr-mode-')); t.after(() => rm(directory, { recursive: true, force: true }));
  const app = await startController({ directory, port: 0, mode: 'demo' }); const inventory = app.service.inventory(); const identity = app.identity; const keys = generateKeyPairSync('ec', { namedCurve: 'prime256v1' }); const pair = app.service.pairing({ signerId: 'phone', role: 'routine', publicKey: keys.publicKey.export({ format: 'jwk' }) }); const signature = sign('sha256', Buffer.from('keyroot.pairing-possession.v1\0' + canonicalJSON(pair.challenge)), { key: keys.privateKey, dsaEncoding: 'ieee-p1363' }).toString('base64url'); app.service.pairingProof(pair.requestId, { signature }); app.service.confirmLocalPairing(pair.requestId, pair.fingerprint); const approvers = app.service.overview().approvers; await app.close();
  await assert.rejects(startController({ directory, port: 0, mode: 'real', phoneOrigin: 'https://phone.fixture.invalid' }));
  assert.equal(await readFile(join(directory, 'runtime-mode'), 'utf8'), 'demo\n');
  const again = await startController({ directory, port: 0, mode: 'demo' }); t.after(() => again.close());
  assert.equal(again.identity.installationId, identity.installationId); assert.deepEqual(again.service.inventory(), inventory); assert.deepEqual(again.service.overview().approvers, approvers);
});

test('incident status only restores the exact current emergency registration', async t => {
  let now = 1000000; const directory = await mkdtemp(join(tmpdir(), 'kr-incident-status-'));
  const app = await startController({ directory, port: 0, mode: 'demo', clock: () => now }); t.after(async () => { await app.close(); await rm(directory, { recursive: true, force: true }); });
  const { generateKeyPairSync } = await import('node:crypto'); const key = generateKeyPairSync('ec', { namedCurve: 'prime256v1' }).publicKey.export({ format: 'jwk' });
  app.service.journal.transaction(db => db.prepare("INSERT INTO approver(signer_id,role,public_key,fingerprint) VALUES('emergency','emergency',?,'fixture')").run(JSON.stringify(key)));
  const batch = app.service.prepare({ signerId: 'emergency', lineageIds: ['demo-lineage'], role: 'emergency', incident: { policy: 'continuity-first', quarantineDestinations: [], outage: { permitted: false, consequence: 'none' } } });
  assert.equal(batch.emergencyRegistration, null); app.service.approvals.registerEmergencyGrant(batch.rawManifest, now);
  assert.deepEqual(app.service.batch(batch.batchId).emergencyRegistration, { grantId: batch.batchId, digest: batch.digest });
  const mutate = (sql: string) => app.service.journal.transaction(db => db.exec(sql));
  mutate("UPDATE approval_grant SET digest='altered'"); assert.equal(app.service.batch(batch.batchId).emergencyRegistration, null);
  app.service.journal.transaction(db => db.prepare('UPDATE approval_grant SET digest=?').run(batch.digest));
  mutate("UPDATE approval_grant SET boot_id='other'"); assert.equal(app.service.batch(batch.batchId).emergencyRegistration, null);
  app.service.journal.transaction(db => db.prepare('UPDATE approval_grant SET boot_id=?').run(app.service.journal.bootId));
  mutate('UPDATE approver SET revoked=1'); assert.equal(app.service.batch(batch.batchId).emergencyRegistration, null); mutate('UPDATE approver SET revoked=0');
  mutate('UPDATE approval_grant SET cancelled=1'); assert.equal(app.service.batch(batch.batchId).emergencyRegistration, null); mutate('UPDATE approval_grant SET cancelled=0');
  now = batch.summary.expiresAt; assert.equal(app.service.batch(batch.batchId).emergencyRegistration, null);
});

import { generateKeyPairSync, sign, createHash } from 'node:crypto';
import { isoCBOR } from '@simplewebauthn/server/helpers';
import { localCommand, ownerRequest } from '../../apps/controller/src/cli.js';
import { canonicalJSON, parseCanonicalManifest } from '../../packages/core/src/manifest.js';
import { validateControllerRow, type ControllerTable } from '../../apps/controller/src/metadata.js';
import { createDemoPorts } from '../../apps/controller/src/demo.js';
import type { PreparedBatch } from '../../apps/controller/src/service.js';
async function continuityFixture(t: { after(fn: () => Promise<void>): void }, clock?: () => number, ports?: import('../../apps/controller/src/service.js').TrustedControllerPorts) {
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


test('signed current cancellation releases a stale emergency reservation after a policy change', async t => {
  const now = Date.now(); const f = await continuityFixture(t, () => now); const emergency = generateKeyPairSync('ec', { namedCurve: 'prime256v1' }); const jwk = emergency.publicKey.export({ format: 'jwk' });
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
  const op = manifest.operations[0]!;
  const challengeResponse = await f.post('/api/emergency/challenge', { grantId: batch.batchId, operationId: op.operationId, actionId: 'revoke' });
  const challenge = await challengeResponse.json() as { challengeId: string; challenge: string };
  const client = Buffer.from(JSON.stringify({ type: 'webauthn.get', challenge: challenge.challenge, origin: f.app.phoneOrigin, crossOrigin: false }));
  const counter = Buffer.alloc(4); counter.writeUInt32BE(1); const authenticator = Buffer.concat([createHash('sha256').update(rpId).digest(), Buffer.from([5]), counter]);
  const assertionResponse = { id: credentialId, rawId: credentialId, type: 'public-key', clientExtensionResults: {}, response: { clientDataJSON: client.toString('base64url'), authenticatorData: authenticator.toString('base64url'), signature: sign('sha256', Buffer.concat([authenticator, createHash('sha256').update(client).digest()]), emergency.privateKey).toString('base64url') } };
  assert.equal((await f.post('/api/emergency/assertion', { challengeId: challenge.challengeId, operationId: op.operationId, actionId: 'revoke', response: assertionResponse })).status, 200);
  assert.ok(f.app.service.journal.read(db => db.prepare('SELECT 1 FROM emergency_reservation WHERE grant_id=?').get(batch.batchId)));
  const policy = await f.prepare('key-policy', 'demo-lineage', { rotationDays: 7 }); const policyGrant = await f.approve(policy);
  await f.owner('/api/actions/key-policy', 'POST', { grantId: policyGrant.grantId, operationId: parseCanonicalManifest(policy.rawManifest).operations[0]!.operationId, actionId: 'key-policy' });
  assert.equal(f.app.service.batch(batch.batchId).emergencyRegistration, null);
  const routine = await f.prepare(); const routineGrant = await f.approve(routine); const routineRequest = { grantId: routineGrant.grantId, operationId: parseCanonicalManifest(routine.rawManifest).operations[0]!.operationId };
  await assert.rejects(f.owner('/api/operations/run', 'POST', routineRequest));
  const cancellation = await f.prepare('cancel', batch.batchId); const cancellationGrant = await f.approve(cancellation);
  await f.owner('/api/actions/cancel', 'POST', { grantId: cancellationGrant.grantId, operationId: parseCanonicalManifest(cancellation.rawManifest).operations[0]!.operationId, actionId: 'cancel' });
  assert.equal(f.app.service.journal.read(db => db.prepare('SELECT cancelled FROM approval_grant WHERE grant_id=?').get(batch.batchId))!.cancelled, 1);
  const resumed = await f.owner('/api/operations/run', 'POST', routineRequest) as { state: string }; assert.equal(resumed.state, 'held');
});

test('signed cancellation preserves an unknown dispatched emergency effect and its budget', async t => {
  const now = Date.now(); const synthetic = createDemoPorts(() => now); const unavailable = async (): Promise<never> => { throw new Error('synthetic observer unavailable'); };
  const f = await continuityFixture(t, () => now, { lifecycleDrivers: async (configuration, authority) => { const drivers = await synthetic.drivers(configuration, authority, { deliver: unavailable, observeConsumer: unavailable, observeOldUse: unavailable }); return { ...drivers, revoke: async () => { throw new Error('synthetic external result lost'); } }; } }); const emergency = generateKeyPairSync('ec', { namedCurve: 'prime256v1' }); const jwk = emergency.publicKey.export({ format: 'jwk' });
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
  const op = manifest.operations[0]!;
  const challengeResponse = await f.post('/api/emergency/challenge', { grantId: batch.batchId, operationId: op.operationId, actionId: 'revoke' });
  const challenge = await challengeResponse.json() as { challengeId: string; challenge: string };
  const client = Buffer.from(JSON.stringify({ type: 'webauthn.get', challenge: challenge.challenge, origin: f.app.phoneOrigin, crossOrigin: false }));
  const counter = Buffer.alloc(4); counter.writeUInt32BE(1); const authenticator = Buffer.concat([createHash('sha256').update(rpId).digest(), Buffer.from([5]), counter]);
  const assertionResponse = { id: credentialId, rawId: credentialId, type: 'public-key', clientExtensionResults: {}, response: { clientDataJSON: client.toString('base64url'), authenticatorData: authenticator.toString('base64url'), signature: sign('sha256', Buffer.concat([authenticator, createHash('sha256').update(client).digest()]), emergency.privateKey).toString('base64url') } };
  const assertion = await f.post('/api/emergency/assertion', { challengeId: challenge.challengeId, operationId: op.operationId, actionId: 'revoke', response: assertionResponse }); assert.equal(assertion.status, 200); const proof = await assertion.json() as { proofId: string };
  const dispatched = await f.post('/api/emergency/execute', { grantId: batch.batchId, proofs: { [op.operationId]: { revoke: proof.proofId } } }); assert.equal(dispatched.status, 200);
  const journal = f.app.service.journal; const intents = journal.listIntents(op.operationId); assert.equal(intents.length, 1); assert.equal(intents[0]!.state, 'unknown');
  const receipts = journal.listReceipts(op.operationId); assert.ok(receipts.some(receipt => receipt.outcome === 'unknown')); assert.ok(receipts.every(receipt => receipt.outcome !== 'confirmed'));
  const snapshot = f.app.service.engine.inspect(op.operationId); assert.equal(snapshot.state, 'reconcile-required'); assert.ok(snapshot.holds.length > 0);
  const budget = journal.read(db => db.prepare('SELECT executions,effects,new_credentials,restarts FROM approval_grant WHERE grant_id=?').get(batch.batchId)); assert.ok(Number(budget!.effects) > 0);
  const policy = await f.prepare('key-policy', 'demo-lineage', { rotationDays: 7 }); const policyGrant = await f.approve(policy);
  await f.owner('/api/actions/key-policy', 'POST', { grantId: policyGrant.grantId, operationId: parseCanonicalManifest(policy.rawManifest).operations[0]!.operationId, actionId: 'key-policy' });
  assert.equal(f.app.service.batch(batch.batchId).emergencyRegistration, null);
  const cancellation = await f.prepare('cancel', batch.batchId); const cancellationGrant = await f.approve(cancellation);
  await f.owner('/api/actions/cancel', 'POST', { grantId: cancellationGrant.grantId, operationId: parseCanonicalManifest(cancellation.rawManifest).operations[0]!.operationId, actionId: 'cancel' });
  assert.equal(journal.read(db => db.prepare('SELECT cancelled FROM approval_grant WHERE grant_id=?').get(batch.batchId))!.cancelled, 1);
  assert.deepEqual(journal.listIntents(op.operationId), intents); assert.deepEqual(journal.listReceipts(op.operationId), receipts);
  assert.deepEqual(journal.read(db => db.prepare('SELECT executions,effects,new_credentials,restarts FROM approval_grant WHERE grant_id=?').get(batch.batchId)), budget);
  const held = f.app.service.engine.inspect(op.operationId); assert.equal(held.state, 'reconcile-required'); assert.deepEqual(held.holds, snapshot.holds);
  const routine = await f.prepare(); const routineGrant = await f.approve(routine); await assert.rejects(f.owner('/api/operations/run', 'POST', { grantId: routineGrant.grantId, operationId: parseCanonicalManifest(routine.rawManifest).operations[0]!.operationId }));
});

test('direct construction rejects mode mismatch before metadata changes', async t => {
  const { ControllerService } = await import('../../apps/controller/src/service.js');
  const directory = await mkdtemp(join(tmpdir(), 'kr-direct-mode-')); const app = await startController({ directory, port: 0, mode: 'demo' });
  t.after(async () => { await app.close(); await rm(directory, { recursive: true, force: true }); });
  assert.throws(() => new ControllerService(app.service.journal, 'real'), /Demo metadata/);
  assert.equal(app.service.overview().mode, 'demo');
  assert.equal(app.service.journal.read(db => db.prepare("SELECT metadata FROM controller_runtime WHERE id='runtime'").get())!.metadata, '{"mode":"demo"}');
});
