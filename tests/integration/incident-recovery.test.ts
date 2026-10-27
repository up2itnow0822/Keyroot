import { test } from 'node:test';
import { strict as assert } from 'node:assert';
import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import { existsSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Decrypter, Encrypter, generateX25519Identity, identityToRecipient } from 'age-encryption';
import { isoCBOR } from '@simplewebauthn/server/helpers';
import { EmergencyWebAuthn } from '../../packages/core/src/emergency-webauthn.js';
import { Journal } from '../../packages/core/src/journal.js';
import { ApprovalService, createLocalBootstrapContext, publicKeyFingerprint } from '../../packages/core/src/approval.js';
import { canonicalJSON, canonicalizeManifest, contentDigest, snapshotDigest, type ApprovalManifest } from '../../packages/core/src/manifest.js';
import { exportRecoveryArchive, openRecoveryArchive } from '../../packages/core/src/recovery/export.js';
import { assertImportedRecovery, importRecoveryArchive, reauthenticateImportedRecovery } from '../../packages/core/src/recovery/import.js';

async function fixture() {
  const dir = mkdtempSync(join(tmpdir(), 'keyroot-incident-recovery-'));
  const source = new Journal(join(dir, 'source.sqlite'), { installationId: 'predecessor', bootId: 'old-boot' });
  const keys = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const publicKey = keys.publicKey.export({ format: 'jwk' });
  const pin = { publicKey, fingerprint: publicKeyFingerprint(publicKey) };
  const approval = new ApprovalService(source, { mode: 'synthetic', clock: () => 2000 });
  approval.bootstrapApprover({ signerId: 'phone', role: 'routine', publicKey, localBootstrap: createLocalBootstrapContext(), confirmedFingerprint: pin.fingerprint });
  const incidentPlanHash = contentDigest({ incident: 'synthetic-plan' });
  const manifest: ApprovalManifest = { version: 1, domain: 'keyroot.approval.v1', algorithm: 'ECDSA-P256-SHA256', audience: 'keyroot-controller', installationId: source.installationId, bootId: source.bootId, signerId: 'phone', role: 'routine', nonce: 'incident-grant', notBefore: 1000, expiresAt: 10000, budgets: { executions: 1, newCredentials: 1, restarts: 0, effects: 1 }, operations: [{ operationId: 'incident-op', accountId: 'account', lineageId: 'lineage', fromGeneration: 1, toGeneration: 2, actions: [{ id: 'create', kind: 'create', parameters: { resourceId: 'resource', adapterId: 'fixture', generation: 2, handleId: 'handle', destinationId: 'destination', incidentPlanHash }, budgetCost: { effects: 1, newCredentials: 1, restarts: 0 } }] }], consumerMap: { revision: '1', hash: contentDigest([]), entries: [] }, recipes: [], adoptionThreshold: 'direct-use-every-consumer', overlapPolicy: 'required', deadline: { at: 9000, outcome: 'hold' }, outage: { permitted: false, consequence: 'none' }, graceSeconds: 900 };
  const raw = canonicalizeManifest(manifest);
  const signature = sign('sha256', Buffer.from(raw), { key: keys.privateKey, dsaEncoding: 'ieee-p1363' }).toString('base64url');
  approval.registerGrant(raw, signature, 2000);
  await approval.authorizeEffect({ grantId: manifest.nonce, signature, operationId: 'incident-op', actionId: 'create', currentSnapshotDigest: snapshotDigest(manifest) });
  const identity = await generateX25519Identity();
  const recipient = await identityToRecipient(identity);
  const archive = await exportRecoveryArchive({ journal: source, recipient, now: 2000, signerFingerprint: pin.fingerprint, sign: async data => sign('sha256', data, { key: keys.privateKey, dsaEncoding: 'ieee-p1363' }).toString('base64url') });
  return { dir, source, keys, pin, manifest, raw, signature, incidentPlanHash, identity, recipient, archive };
}

test('authorized incident survives encrypted recovery and fresh offline reauthentication while authority stays held', async () => {
  const f = await fixture();
  let restored: Journal | undefined;
  try {
    const opened = await openRecoveryArchive({ archive: f.archive, identity: f.identity, verification: f.pin, now: 3000 });
    const row = opened.metadata.tables.intent[0]!;
    assert.equal(JSON.parse(String(row.parameters)).incidentPlanHash, f.incidentPlanHash);
    assert.equal(JSON.parse(String(opened.metadata.tables.approval_grant[0]!.raw_manifest)).operations[0].actions[0].parameters.incidentPlanHash, f.incidentPlanHash);
    const path = join(f.dir, 'restored.sqlite');
    const imported = importRecoveryArchive({ opened, destination: path });
    restored = imported.journal;
    const installationId = restored.installationId;
    const bootId = restored.bootId;
    assert.equal(imported.report.recoveryHeld, true);
    assert.equal(imported.report.unresolvedIntentIds.length, 1);
    assert.equal(restored.listIntents('incident-op')[0]!.state, 'unknown');
    assert.equal(restored.listIntents('incident-op')[0]!.parameters.incidentPlanHash, f.incidentPlanHash);
    assert.equal(restored.inspectOperation('incident-op')!.state, 'reconcile-required');
    assert.equal(restored.read(db => db.prepare('SELECT revoked FROM approver').get()!.revoked), 1);
    assert.equal(restored.read(db => db.prepare('SELECT cancelled FROM approval_grant').get()!.cancelled), 1);
    assert.throws(() => new ApprovalService(restored!, { mode: 'synthetic', clock: () => 3000 }).registerGrant(f.raw, f.signature, 3000));
    const provenance = { domain: 'keyroot.recovery-imported.v1' as const, version: 1 as const, installationId, sourceInstallationId: opened.statement.installationId, metadataHash: opened.statement.metadataHash, coverageComplete: imported.report.coverageComplete, excludedTables: imported.report.excludedTables, importedAt: 3000 };
    restored.close();
    restored = new Journal(path, { installationId, bootId });
    assert.throws(() => assertImportedRecovery({ journal: restored!, opened, report: imported.report }), /offline decryption/);
    const freshOpened = await openRecoveryArchive({ archive: f.archive, identity: f.identity, verification: f.pin, now: 3000 });
    const fresh = await reauthenticateImportedRecovery({ opened: freshOpened, journal: restored, provenance });
    assertImportedRecovery(fresh);
    assert.equal(fresh.report.recoveryHeld, true);
    assert.equal(fresh.report.unresolvedIntentIds.length, 1);
    assert.equal(restored.listIntents('incident-op')[0]!.parameters.incidentPlanHash, f.incidentPlanHash);
    assert.equal(restored.listIntents('incident-op')[0]!.state, 'unknown');
  } finally { restored?.close(); f.source.close(); rmSync(f.dir, { recursive: true, force: true }); }
});

test('signed malformed incident hashes and unknown parameters are rejected before any target write', async () => {
  const f = await fixture();
  try {
    const decrypt = new Decrypter(); decrypt.addIdentity(f.identity);
    const plaintext = await decrypt.decrypt(f.archive, 'text');
    for (const fault of ['short', 'uppercase', 'unknown'] as const) {
      const envelope = JSON.parse(plaintext) as { metadata: { tables: Record<string, Record<string, unknown>[]> }; statement: Record<string, unknown>; signature: string };
      const row = envelope.metadata.tables.intent![0]!;
      const parameters = JSON.parse(String(row.parameters)) as Record<string, unknown>;
      if (fault === 'short') parameters.incidentPlanHash = 'sha256:1234';
      if (fault === 'uppercase') parameters.incidentPlanHash = 'sha256:' + 'A'.repeat(64);
      if (fault === 'unknown') parameters.secretValue = 'not-allowed';
      row.parameters = canonicalJSON(parameters);
      envelope.statement.metadataHash = contentDigest(envelope.metadata);
      envelope.signature = sign('sha256', Buffer.from(canonicalJSON(envelope.statement)), { key: f.keys.privateKey, dsaEncoding: 'ieee-p1363' }).toString('base64url');
      const encrypt = new Encrypter(); encrypt.addRecipient(f.recipient);
      const archive = await encrypt.encrypt(canonicalJSON(envelope));
      const destination = join(f.dir, 'invalid-' + fault, 'target.sqlite');
      await assert.rejects(async () => { const opened = await openRecoveryArchive({ archive, identity: f.identity, verification: f.pin, now: 3000 }); importRecoveryArchive({ opened, destination }); });
      assert.equal(existsSync(join(f.dir, 'invalid-' + fault)), false);
    }
  } finally { f.source.close(); rmSync(f.dir, { recursive: true, force: true }); }
});


test('emergency WebAuthn authorized incident action also survives encrypted held recovery', async () => {
  const f = await fixture();
  let restored: Journal | undefined;
  const source = new Journal(join(f.dir, 'emergency-source.sqlite'), { installationId: 'emergency-source', bootId: 'emergency-boot' });
  try {
    const keys = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    const jwk = keys.publicKey.export({ format: 'jwk' });
    const cosePublicKey = isoCBOR.encode(new Map<number, number | Uint8Array>([[1, 2], [3, -7], [-1, 1], [-2, Buffer.from(jwk.x!, 'base64url')], [-3, Buffer.from(jwk.y!, 'base64url')]]));
    const credentialId = Buffer.from('synthetic-emergency-key').toString('base64url');
    const emergency = new EmergencyWebAuthn(source, { clock: () => 2001 });
    emergency.bootstrapCredential({ signerId: 'emergency', credentialId, cosePublicKey, rpId: 'approve.keyroot.test', origin: 'https://approve.keyroot.test', localBootstrap: createLocalBootstrapContext(), confirmedFingerprint: publicKeyFingerprint(jwk) });
    const manifest = structuredClone(f.manifest);
    manifest.installationId = source.installationId; manifest.bootId = source.bootId;
    manifest.role = 'emergency'; manifest.signerId = 'emergency'; manifest.nonce = 'emergency-incident';
    manifest.operations[0]!.operationId = 'emergency-op'; manifest.operations[0]!.lineageId = 'emergency-lineage';
    const approvals = new ApprovalService(source, { mode: 'synthetic', clock: () => 2002 });
    approvals.registerEmergencyGrant(canonicalizeManifest(manifest), 2000);
    const challenge = emergency.createChallenge({ grantId: manifest.nonce, operationId: 'emergency-op', actionId: 'create', now: 2000 });
    const client = Buffer.from(JSON.stringify({ type: 'webauthn.get', challenge: challenge.challenge, origin: 'https://approve.keyroot.test', crossOrigin: false }));
    const auth = Buffer.alloc(37); createHash('sha256').update('approve.keyroot.test').digest().copy(auth); auth[32] = 5; auth.writeUInt32BE(1, 33);
    const response = { id: credentialId, rawId: credentialId, type: 'public-key' as const, clientExtensionResults: {}, response: { clientDataJSON: client.toString('base64url'), authenticatorData: auth.toString('base64url'), signature: sign('sha256', Buffer.concat([auth, createHash('sha256').update(client).digest()]), keys.privateKey).toString('base64url') } };
    const proof = await emergency.verifyAssertion({ challengeId: challenge.challengeId, operationId: 'emergency-op', actionId: 'create', response, now: 2001 });
    await approvals.authorizeEffect({ grantId: manifest.nonce, operationId: 'emergency-op', actionId: 'create', currentSnapshotDigest: snapshotDigest(manifest), emergencyProofId: proof, now: 2002 });
    const archive = await exportRecoveryArchive({ journal: source, recipient: f.recipient, now: 2002, signerFingerprint: f.pin.fingerprint, sign: async data => sign('sha256', data, { key: f.keys.privateKey, dsaEncoding: 'ieee-p1363' }).toString('base64url') });
    const opened = await openRecoveryArchive({ archive, identity: f.identity, verification: f.pin, now: 3000 });
    const imported = importRecoveryArchive({ opened, destination: join(f.dir, 'emergency-restored.sqlite') }); restored = imported.journal;
    assert.equal(restored.listIntents('emergency-op')[0]!.parameters.incidentPlanHash, f.incidentPlanHash);
    assert.equal(restored.listIntents('emergency-op')[0]!.state, 'unknown');
    assert.equal(restored.read(db => db.prepare("SELECT cancelled FROM approval_grant WHERE grant_id='emergency-incident'").get()!.cancelled), 1);
    assert.equal(imported.report.recoveryHeld, true);
    const archivedGrant = opened.metadata.tables.approval_grant.find(row => row.grant_id === manifest.nonce)!;
    assert.equal(JSON.parse(String(archivedGrant.raw_manifest)).operations[0].actions[0].parameters.incidentPlanHash, f.incidentPlanHash);
    const installationId = restored.installationId; const bootId = restored.bootId;
    const provenance = { domain: 'keyroot.recovery-imported.v1' as const, version: 1 as const, installationId, sourceInstallationId: opened.statement.installationId, metadataHash: opened.statement.metadataHash, coverageComplete: imported.report.coverageComplete, excludedTables: imported.report.excludedTables, importedAt: 3000 };
    restored.close(); restored = new Journal(join(f.dir, 'emergency-restored.sqlite'), { installationId, bootId });
    assert.throws(() => assertImportedRecovery({ journal: restored!, opened, report: imported.report }), /offline decryption/);
    const freshOpened = await openRecoveryArchive({ archive, identity: f.identity, verification: f.pin, now: 3000 });
    const fresh = await reauthenticateImportedRecovery({ opened: freshOpened, journal: restored, provenance });
    assertImportedRecovery(fresh);
    assert.equal(fresh.report.recoveryHeld, true);
    assert.equal(restored.listIntents('emergency-op')[0]!.parameters.incidentPlanHash, f.incidentPlanHash);
    assert.equal(restored.listIntents('emergency-op')[0]!.state, 'unknown');
    assert.equal(restored.read(db => db.prepare("SELECT cancelled FROM approval_grant WHERE grant_id='emergency-incident'").get()!.cancelled), 1);
  } finally { restored?.close(); source.close(); f.source.close(); rmSync(f.dir, { recursive: true, force: true }); }
});
