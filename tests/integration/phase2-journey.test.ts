import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, randomUUID, sign } from 'node:crypto';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { startController } from '../../apps/controller/src/server.js';
import { localCommand, ownerRequest } from '../../apps/controller/src/cli.js';
import { createDemoPorts } from '../../apps/controller/src/demo.js';
import type { Inventory, PreparedBatch, TrustedControllerPorts } from '../../apps/controller/src/service.js';
import { canonicalJSON, contentDigest, parseCanonicalManifest } from '../../packages/core/src/manifest.js';
import { verifyConsumerUse } from '../../packages/core/src/consumer-receipt.js';
import type { LifecycleReceipt, ReceiptSubject } from '../../packages/core/src/receipts.js';

test('U13 synthetic five-lineage signed batch preserves adoption and old-use holds alongside guided limitations', async t => {
  const directory = await mkdtemp(join(tmpdir(), 'kr-u13-'));
  const now = Date.now(); const clock = () => now;
  const protocol = createDemoPorts(clock); const runtimeKey = generateKeyPairSync('ed25519');
  const delivered = new Set<string>();
  const receipt = (subject: ReceiptSubject, kind: LifecycleReceipt['kind'], outcome: LifecycleReceipt['outcome']): LifecycleReceipt => ({ receiptId: randomUUID(), subject: { ...subject }, kind, outcome, observedAt: now, observerId: 'synthetic-observer', evidenceHash: contentDigest({ subject, kind, outcome }), limitationCodes: ['synthetic-only'] });
  const consumers: NonNullable<TrustedControllerPorts['consumers']> = {
    deliver: async (_intent, context) => { delivered.add(context.subject.operationId); return receipt(context.subject, 'deliver', 'delivery-accepted'); },
    observeConsumer: async subject => {
      if (subject.lineageId === 'lineage-2') throw new Error('synthetic offline consumer');
      assert.ok(delivered.has(subject.operationId));
      const observation = { version: 1 as const, consumerIdentity: 'fixture-runtime', subject: { ...subject }, processId: 'fixture-process', runId: 'fixture-run', observedAt: now, method: 'authenticated-runtime-use' as const, limitationCodes: ['synthetic-only'] };
      const signature = sign(null, Buffer.from(canonicalJSON(observation)), runtimeKey.privateKey).toString('base64');
      return verifyConsumerUse({ observation, signature }, subject, { identities: new Map([['fixture-runtime', { consumerId: 'machine-1', publicKey: runtimeKey.publicKey }]]), clock, maxAgeMs: 1000 });
    },
    observeOldUse: async subject => receipt(subject, 'old-use', subject.lineageId === 'lineage-3' ? 'positive-use' : 'none-observed'),
  };
  const hermeticTestAdmission = async () => { assert.ok(protocol, 'trusted hermetic-test admission only'); };
  const ports: TrustedControllerPorts = {
    consumers, issuerConfiguration: protocol.configuration, lineageTargets: protocol.target,
    lifecycleDrivers: (config, authority) => protocol.drivers(config, authority, consumers),
    liveGates: { account: hermeticTestAdmission, store: hermeticTestAdmission, phoneCustody: hermeticTestAdmission, origin: hermeticTestAdmission, isolation: hermeticTestAdmission, recovery: hermeticTestAdmission },
    assertLiveAdmission: async context => { assert.ok(context.action.parameters.configurationHash); await hermeticTestAdmission(); },
    recipes: [{ id: 'guided-fixture', version: 'v1', accountId: 'demo-account', destinationId: 'demo-vault', steps: [{ action: 'confirm', targetId: 'mapped-store', checkpoint: 'none' }] }],
    deliveryActions: (operationId, lineageId, generation) => [{ action: { id: 'deliver-machine', kind: 'deliver', parameters: { resourceId: 'created:' + operationId, consumerId: 'machine-1', destinationId: 'destination-' + lineageId, handleId: 'operations/' + operationId, generation, expectedRevision: 'revision-' + lineageId }, budgetCost: { effects: 1, newCredentials: 0, restarts: 0 } }, descriptor: { driver: 'wrapper', consumerId: 'machine-1', destinationId: 'destination-' + lineageId, handleId: 'operations/' + operationId, generation, revision: 'revision-' + lineageId, consumerMapRevision: 'map-2', version: 1, mappingTokenFingerprint: 'sha256:' + 'a'.repeat(64) } }],
  };
  const app = await startController({ directory, port: 0, mode: 'real', phoneOrigin: 'https://phone.fixture.invalid', ports, clock });
  t.after(async () => { await app.close(); await rm(directory, { recursive: true, force: true }); });
  assert.equal((await fetch(app.origin + '/api/session/demo', { method: 'POST', headers: { Origin: app.origin } })).status, 404);
  // Seed only the initial synthetic enrollment; subsequent inventory changes require signed owner intent.
  const initial = app.service.inventory();
  initial.lineages.push({ id: 'lineage-1', issuerId: 'openai-service-account', accountId: 'demo-account', credentialType: 'service-account-key', grantType: 'static-key' });
  app.service.journal.transaction(db => db.prepare("UPDATE controller_inventory SET metadata=? WHERE id='inventory'").run(canonicalJSON(initial)));
  const phone = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const phoneSign = (value: string) => sign('sha256', Buffer.from(value), { key: phone.privateKey, dsaEncoding: 'ieee-p1363' }).toString('base64url');
  const post = (path: string, body: unknown) => fetch(app.origin + path, { method: 'POST', headers: { Origin: app.phoneOrigin, 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
  const pairResponse = await post('/api/pairing/requests', { signerId: 'phone', role: 'routine', publicKey: phone.publicKey.export({ format: 'jwk' }) }); assert.equal(pairResponse.status, 201);
  const pair = await pairResponse.json() as { requestId: string; fingerprint: string; challenge: unknown };
  assert.equal((await post(`/api/pairing/requests/${pair.requestId}/proof`, { signature: phoneSign('keyroot.pairing-possession.v1\0' + canonicalJSON(pair.challenge)) })).status, 200);
  assert.equal((await localCommand(directory, { command: 'pair-confirm', requestId: pair.requestId, fingerprint: pair.fingerprint })).outcome, 'paired');
  const owner = (path: string, method = 'GET', body?: unknown) => ownerRequest(directory, path, method, body);
  const approve = async (batch: PreparedBatch) => { const response = await post('/api/approvals', { batchId: batch.batchId, rawManifest: batch.rawManifest, signature: phoneSign(batch.rawManifest) }); assert.equal(response.status, 201); return await response.json() as { grantId: string }; };
  const inventory = await owner('/api/inventory') as Inventory;
  for (let i = 2; i <= 5; i++) inventory.lineages.push({ ...inventory.lineages[0]!, id: 'lineage-' + i });
  inventory.consumerMap.revision = 2;
  inventory.consumerMap.bindings = inventory.lineages.map(lineage => ({ id: 'binding-' + lineage.id, lineageId: lineage.id, consumerId: 'machine-1', destinationId: 'destination-' + lineage.id, consumerRevision: 'revision-' + lineage.id, association: { kind: 'declared', source: 'owner-fixture', observedAt: new Date(now).toISOString() } }));
  const declaration = await owner('/api/batches/prepare', 'POST', { signerId: 'phone', lineageIds: ['lineage-1'], purpose: 'inventory-update', targetId: 'inventory', inventory }) as PreparedBatch;
  const declarationGrant = await approve(declaration);
  await owner('/api/actions/inventory-update', 'POST', { grantId: declarationGrant.grantId, operationId: parseCanonicalManifest(declaration.rawManifest).operations[0]!.operationId, actionId: 'inventory-update' });
  const batch = await owner('/api/batches/prepare', 'POST', { signerId: 'phone', lineageIds: inventory.lineages.map(lineage => lineage.id) }) as PreparedBatch;
  const manifest = parseCanonicalManifest(batch.rawManifest); assert.equal(manifest.operations.length, 5); assert.equal(manifest.consumerMap.entries.length, 5);
  const grant = await approve(batch);
  assert.equal((await post('/api/approvals', { batchId: batch.batchId, rawManifest: batch.rawManifest, signature: phoneSign(batch.rawManifest) })).status, 409);
  const snapshots: Array<{ operationId: string; state: string; replacement: string; issuer: string; probe: string; holds: string[]; receipts: LifecycleReceipt[] }> = [];
  for (const operation of manifest.operations) snapshots.push(await owner('/api/operations/run', 'POST', { grantId: grant.grantId, operationId: operation.operationId }) as { operationId: string; state: string; replacement: string; issuer: string; probe: string; holds: string[]; receipts: LifecycleReceipt[] });
  assert.ok(snapshots.every(snapshot => snapshot.replacement === 'stored'));
  const byLineage = (lineage: string) => snapshots[manifest.operations.findIndex(op => op.lineageId === lineage)]!;
  const offline = byLineage('lineage-2'); assert.equal(offline.state, 'held'); assert.ok(offline.holds.includes('consumer-use-unverified:machine-1')); assert.equal(offline.receipts.some(r => r.kind === 'revoke'), false);
  const oldUse = byLineage('lineage-3'); assert.equal(oldUse.state, 'held'); assert.ok(oldUse.holds.includes('positive-old-generation-use')); assert.equal(oldUse.receipts.some(r => r.kind === 'revoke'), false);
  const acknowledged = byLineage('lineage-1'); assert.equal(acknowledged.state, 'held'); assert.equal(acknowledged.issuer, 'unverified'); assert.equal(acknowledged.probe, 'unknown');
  assert.ok(acknowledged.receipts.some(r => r.kind === 'consumer-use' && r.outcome === 'direct-use')); assert.ok(acknowledged.receipts.some(r => r.kind === 'revoke' && r.outcome === 'issuer-acknowledged')); assert.ok(acknowledged.receipts.some(r => r.kind === 'issuer' && r.outcome === 'unverified')); assert.ok(acknowledged.receipts.some(r => r.kind === 'probe' && r.outcome === 'unknown'));
  await owner('/api/guided/guided-fixture'); await owner('/api/guided/guided-fixture/step', 'POST', { targetId: 'mapped-store', checkpointAcknowledged: false });
  const guided = await owner('/api/batches/prepare', 'POST', { signerId: 'phone', lineageIds: ['lineage-1'], purpose: 'guided-completion', targetId: 'guided-fixture' }) as PreparedBatch; const guidedGrant = await approve(guided);
  const result = await owner('/api/actions/guided-completion', 'POST', { grantId: guidedGrant.grantId, operationId: parseCanonicalManifest(guided.rawManifest).operations[0]!.operationId, actionId: 'guided-completion' }) as { limitation: string };
  assert.match(result.limitation, /attestation/); assert.equal(JSON.stringify(snapshots).includes('synthetic-old-'), false);
});
