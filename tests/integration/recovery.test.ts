import { test } from 'node:test';
import { strict as assert } from 'node:assert';
import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { generateX25519Identity, identityToRecipient } from 'age-encryption';
import { isoCBOR } from '@simplewebauthn/server/helpers';
import type { AuthenticationResponseJSON } from '@simplewebauthn/server';
import { Journal } from '../../packages/core/src/journal.js';
import { ApprovalService, createLocalBootstrapContext, publicKeyFingerprint } from '../../packages/core/src/approval.js';
import { canonicalizeManifest, contentDigest, snapshotDigest, type ApprovalManifest } from '../../packages/core/src/manifest.js';
import type { EpochRecord, InstallationEpochStore } from '../../packages/core/src/installation-epoch.js';
import { exportRecoveryArchive, openRecoveryArchive } from '../../packages/core/src/recovery/export.js';
import { importRecoveryArchive } from '../../packages/core/src/recovery/import.js';
import { RecoveryCoordinator, type RecoveryObservation, type RecoveryRequirement, type RecoveryScenario } from '../../packages/core/src/recovery/drill.js';

class MemoryEpoch implements InstallationEpochStore {
  current: EpochRecord = { installationId: 'predecessor', ownerId: 'predecessor-owner', version: 1 };
  casCount = 0;
  async read() { return { ...this.current }; }
  async compareAndSet(expected: number | undefined, next: Omit<EpochRecord, 'version'>) {
    this.casCount++;
    if (expected !== this.current.version) return undefined;
    this.current = { ...next, version: this.current.version + 1 };
    return { ...this.current };
  }
}
async function setup(pending = false, excluded = false) {
  const dir = mkdtempSync(join(tmpdir(), 'kr-u12-integration-'));
  const source = new Journal(join(dir, 'source.sqlite'), { installationId: 'predecessor', bootId: 'before-loss' });
  const owner = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const jwk = owner.publicKey.export({ format: 'jwk' });
  const pin = { publicKey: jwk, fingerprint: publicKeyFingerprint(jwk) };
  const approval = new ApprovalService(source, { mode: 'synthetic', clock: () => 2000 });
  approval.bootstrapApprover({ signerId: 'lost-phone', role: 'routine', publicKey: jwk, localBootstrap: createLocalBootstrapContext(), confirmedFingerprint: pin.fingerprint });
  source.registerSession('old-dashboard-and-read-session');
  const manifest: ApprovalManifest = { version: 1, domain: 'keyroot.approval.v1', algorithm: 'ECDSA-P256-SHA256', audience: 'keyroot-controller', installationId: source.installationId, bootId: source.bootId, signerId: 'lost-phone', role: 'routine', nonce: 'old-approval', notBefore: 1000, expiresAt: 100000, budgets: { executions: 1, newCredentials: 1, restarts: 0, effects: 1 }, operations: [{ operationId: 'pending-op', lineageId: 'lineage', accountId: 'account', fromGeneration: 1, toGeneration: 2, actions: [{ id: 'create', kind: 'create', parameters: { resourceId: 'issuer-parent', adapterId: 'synthetic-adapter', generation: 2, handleId: 'store-handle', destinationId: 'vault-target' }, budgetCost: { effects: 1, newCredentials: 1, restarts: 0 } }] }], consumerMap: { revision: '1', hash: contentDigest([]), entries: [] }, recipes: [], adoptionThreshold: 'direct-use-every-consumer', overlapPolicy: 'required', deadline: { at: 9000, outcome: 'hold' }, outage: { permitted: false, consequence: 'none' }, graceSeconds: 900 };
  const raw = canonicalizeManifest(manifest);
  const signature = sign('sha256', Buffer.from(raw), { key: owner.privateKey, dsaEncoding: 'ieee-p1363' }).toString('base64url');
  approval.registerGrant(raw, signature, 2000);
  if (pending) await approval.authorizeEffect({ grantId: manifest.nonce, signature, operationId: 'pending-op', actionId: 'create', currentSnapshotDigest: snapshotDigest(manifest) });
  source.transaction(db => {
    db.exec("CREATE TABLE oauth_family (grant_id TEXT PRIMARY KEY, family_id TEXT, owner_id TEXT, version INTEGER, state TEXT, boot_id TEXT, access_expires_at INTEGER, pending_intent_id TEXT, pending_operation_id TEXT)");
    db.prepare("INSERT INTO oauth_family VALUES('oauth-grant','local-family','local-owner',2,'active',?,100000,NULL,NULL)").run(source.bootId);
  });
  if (pending) source.transaction(db => {
    db.exec('CREATE TABLE engine_schema (singleton INTEGER PRIMARY KEY, version INTEGER); INSERT INTO engine_schema VALUES(1,1); CREATE TABLE engine_operation (operation_id TEXT PRIMARY KEY, holds TEXT, deadline TEXT); CREATE TABLE engine_receipt (receipt_id TEXT PRIMARY KEY, operation_id TEXT, intent_id TEXT, metadata TEXT);');
    db.prepare('INSERT INTO engine_operation VALUES(?,?,?)').run('pending-op', JSON.stringify(['create-outcome-unknown']), 'within-window');
    const receipt = { receiptId: 'engine-unknown', subject: { operationId: 'pending-op', lineageId: 'lineage', accountId: 'account', generation: 2, resourceId: 'issuer-parent', handleId: 'store-handle', consumerMapRevision: '1' }, kind: 'create', outcome: 'unknown', observedAt: 2000, observerId: 'synthetic-driver', evidenceHash: contentDigest('unknown-upstream-outcome'), limitationCodes: ['synthetic-only'] };
    db.prepare('INSERT INTO engine_receipt VALUES(?,?,?,?)').run(receipt.receiptId, 'pending-op', source.listIntents('pending-op')[0]!.intentId, JSON.stringify(receipt));
  });
  if (excluded) source.transaction(db => db.exec('CREATE TABLE schedule_quarantine (consumer_id TEXT PRIMARY KEY, metadata TEXT);'));
  const identity = await generateX25519Identity();
  const recipient = await identityToRecipient(identity);
  const archive = await exportRecoveryArchive({ journal: source, recipient, now: 2000, signerFingerprint: pin.fingerprint, sign: async bytes => sign('sha256', bytes, { key: owner.privateKey, dsaEncoding: 'ieee-p1363' }).toString('base64url') });
  const opened = await openRecoveryArchive({ archive, identity, verification: pin, now: 3000 });
  const imported = importRecoveryArchive({ opened, destination: join(dir, 'clean-host', 'restored.sqlite') });
  const store = new MemoryEpoch();
  const predecessor = { ...store.current };
  const requirements: RecoveryRequirement[] = ['store-value-backup', 'issuer-native-access', 'predecessor-quiesced', 'management-authority-invalidated', 'issuer-inflight-reconciliation', 'clean-issuer-administration', 'management-authority-replaced', 'trusted-rebuild', 'provider-session-invalidation'];
  const resources = Object.fromEntries(requirements.map(r => [r, 'synthetic-resource:' + r])) as Record<RecoveryRequirement, string>;
  let now = 3000;
  const observations: RecoveryObservation[] = [];
  const outcomes: Partial<Record<RecoveryRequirement, RecoveryObservation['outcome']>> = {};
  const observer = { observe: async (request: { requirement: RecoveryRequirement; predecessor: Readonly<EpochRecord>; metadataHash: string; resourceId: string }): Promise<RecoveryObservation> => {
    assert.equal(imported.journal.read(db => db.prepare('SELECT recovery_hold FROM controller').get()!.recovery_hold), 1);
    const proof = { ...request, predecessor: { ...request.predecessor }, method: 'synthetic-read-only-observer', observerId: 'synthetic-clean-device', evidenceHash: contentDigest(request), observedAt: now, expiresAt: now + 60000, outcome: outcomes[request.requirement] ?? 'confirmed' };
    observations.push(proof); return proof;
  } };
  const coordinator = (scenario: RecoveryScenario = 'box-loss', emergency?: ReturnType<typeof emergencyFixture>['pin']) => new RecoveryCoordinator({ imported, scenario, observedPredecessor: predecessor, epochStore: store, resources, observer, clock: () => now, ...(emergency ? { emergency } : {}) });
  return { dir, source, imported, store, predecessor, coordinator, outcomes, observations, observer, resources, manifest, raw, signature, now: () => now, setNow: (value: number) => { now = value; }, cleanup: () => { source.close(); imported.journal.close(); rmSync(dir, { recursive: true, force: true }); } };
}
function emergencyFixture() {
  const keys = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const jwk = keys.publicKey.export({ format: 'jwk' });
  return { keys, pin: { credentialId: Buffer.from('synthetic-offline-key').toString('base64url'), cosePublicKey: isoCBOR.encode(new Map<number, number | Uint8Array>([[1, 2], [3, -7], [-1, 1], [-2, Buffer.from(jwk.x!, 'base64url')], [-3, Buffer.from(jwk.y!, 'base64url')]])), fingerprint: publicKeyFingerprint(jwk), rpId: 'approve.keyroot.test', origin: 'https://approve.keyroot.test', counter: 0 } };
}
function assertion(emergency: ReturnType<typeof emergencyFixture>, challenge: string): AuthenticationResponseJSON {
  const client = Buffer.from(JSON.stringify({ type: 'webauthn.get', challenge, origin: emergency.pin.origin, crossOrigin: false }));
  const auth = Buffer.alloc(37); createHash('sha256').update(emergency.pin.rpId).digest().copy(auth); auth[32] = 0x05; auth.writeUInt32BE(1, 33);
  const signature = sign('sha256', Buffer.concat([auth, createHash('sha256').update(client).digest()]), emergency.keys.privateKey);
  return { id: emergency.pin.credentialId, rawId: emergency.pin.credentialId, type: 'public-key', response: { clientDataJSON: client.toString('base64url'), authenticatorData: auth.toString('base64url'), signature: signature.toString('base64url') }, clientExtensionResults: {} };
}
function ceremony() {
  const keys = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const publicKey = keys.publicKey.export({ format: 'jwk' });
  return { oldSignerId: 'lost-phone', replacement: { signerId: 'replacement-phone', verification: { publicKey, fingerprint: publicKeyFingerprint(publicKey) } }, custody: { operatorId: 'synthetic-owner', evidenceHash: contentDigest('synthetic-custody-attestation'), observedAt: 3000 } };
}

test('U12 older backup invalidates signatures, sessions and OAuth while preserving ambiguous pending create', async () => {
  const f = await setup(true);
  try {
    const j = f.imported.journal;
    assert.equal(j.read(db => db.prepare('SELECT holds FROM engine_operation').get()!.holds), JSON.stringify(['create-outcome-unknown']));
    assert.equal(j.read(db => JSON.parse(String(db.prepare('SELECT metadata FROM engine_receipt').get()!.metadata)).outcome), 'unknown');
    assert.equal(j.listIntents('pending-op')[0]!.state, 'unknown');
    assert.equal(j.inspectOperation('pending-op')!.state, 'reconcile-required');
    assert.equal(j.sessionActive('old-dashboard-and-read-session'), false);
    assert.equal(j.read(db => db.prepare('SELECT revoked FROM approver').get()!.revoked), 1);
    assert.equal(j.read(db => db.prepare('SELECT cancelled FROM approval_grant').get()!.cancelled), 1);
    assert.equal(j.read(db => db.prepare('SELECT state FROM oauth_family').get()!.state), 'reconcile-required');
    const approval = new ApprovalService(j, { mode: 'synthetic', clock: () => 3000 });
    assert.throws(() => approval.registerGrant(f.raw, f.signature, 3000));
    const report = await f.coordinator().recover();
    assert.equal(report.recoveryHeld, true); assert.equal(report.unresolvedIntentIds.length, 1); assert.equal(f.store.casCount, 0);
  } finally { f.cleanup(); }
});

test('U12 partial store capsule and paused predecessor remain held without CAS or effects', async () => {
  for (const [requirement, outcome] of [['store-value-backup', 'partial'], ['predecessor-quiesced', 'unknown'], ['issuer-inflight-reconciliation', 'unknown']] as const) {
    const f = await setup();
    try {
      f.outcomes[requirement] = outcome;
      const report = await f.coordinator().recover();
      assert.equal(report.recoveryHeld, true); assert.equal(f.store.casCount, 0);
      assert.ok(report.limitations.includes(requirement + '-' + outcome));
    } finally { f.cleanup(); }
  }
});

test('U12 exact predecessor prevents third controller takeover using stale observations', async () => {
  const f = await setup();
  try {
    const b = f.coordinator();
    f.store.current = { installationId: 'third-controller', ownerId: 'third-owner', version: 2 };
    const report = await b.recover();
    assert.equal(report.recoveryHeld, true); assert.equal(f.store.casCount, 0); assert.equal(f.store.current.ownerId, 'third-owner');
  } finally { f.cleanup(); }
});

test('U12 scoped read-only evidence plus exact shared epoch releases synthetic box recovery only', async () => {
  const f = await setup();
  try {
    const c = f.coordinator();
    const report = await c.recover();
    assert.equal(report.recoveryHeld, false); assert.equal(f.store.casCount, 1);
    assert.equal(f.store.current.installationId, f.imported.journal.installationId);
    assert.ok(report.limitations.includes('physical-four-machine-recovery-unverified'));
    await c.assertBeforeEffect();
  } finally { f.cleanup(); }
});

test('U12 lost phone cannot trust archived approver or replacement fingerprint alone; emergency needs offline capsule', async () => {
  const f = await setup();
  try {
    const c = f.coordinator('lost-phone');
    assert.throws(() => c.createPhoneChallenge(ceremony()), /independent emergency/);
    const report = await c.recover();
    assert.equal(report.recoveryHeld, true); assert.equal(f.store.casCount, 0);
    assert.equal(f.imported.journal.read(db => db.prepare('SELECT revoked FROM approver').get()!.revoked), 1);
    assert.throws(() => new RecoveryCoordinator({ imported: { ...f.imported, opened: structuredClone(f.imported.opened) }, scenario: 'lost-phone', observedPredecessor: f.predecessor, epochStore: f.store, observer: f.observer, resources: f.resources, clock: f.now, emergency: emergencyFixture().pin }), /offline decryption/);
  } finally { f.cleanup(); }
});

test('U12 synthetic full offline capsule + actual WebAuthn signature + custody ceremony replaces old signer', async () => {
  const f = await setup();
  try {
    const e = emergencyFixture(); const c = f.coordinator('lost-phone', e.pin); const enrollment = ceremony();
    const challenge = c.createPhoneChallenge(enrollment);
    await c.verifyPhoneAssertion({ challengeId: challenge.challengeId, response: assertion(e, challenge.challenge) });
    await assert.rejects(c.verifyPhoneAssertion({ challengeId: challenge.challengeId, response: assertion(e, challenge.challenge) }), /consumed/);
    const report = await c.recover({ ceremonyChallengeId: challenge.challengeId });
    assert.equal(report.recoveryHeld, false);
    assert.equal(f.imported.journal.read(db => db.prepare("SELECT revoked FROM approver WHERE signer_id='lost-phone'").get()!.revoked), 1);
    assert.equal(f.imported.journal.read(db => db.prepare("SELECT fingerprint FROM approver WHERE signer_id='replacement-phone' AND revoked=0").get()!.fingerprint), enrollment.replacement.verification.fingerprint);
    assert.ok(report.limitations.includes('operator-custody-attestation-not-independent-hardware-proof'));
  } finally { f.cleanup(); }
});

test('U12 root compromise refuses old trust and reports unsupported provider-session invalidation', async () => {
  const f = await setup();
  try {
    f.outcomes['provider-session-invalidation'] = 'unsupported';
    const report = await f.coordinator('root-compromise', emergencyFixture().pin).recover();
    assert.equal(report.recoveryHeld, true); assert.equal(f.store.casCount, 0);
    assert.ok(report.limitations.includes('provider-session-invalidation-unsupported'));
    assert.ok(f.observations.some(o => o.requirement === 'clean-issuer-administration'));
    assert.ok(f.observations.some(o => o.requirement === 'management-authority-replaced'));
    assert.equal(f.imported.journal.read(db => db.prepare('SELECT revoked FROM approver').get()!.revoked), 1);
  } finally { f.cleanup(); }
});


test('U12 signed unknown security table inventory cannot be overridden by otherwise successful observations', async () => {
  const f = await setup(false, true);
  try {
    assert.equal(f.imported.report.coverageComplete, false);
    assert.deepEqual(f.imported.report.excludedTables, ['schedule_quarantine']);
    const report = await f.coordinator().recover();
    assert.equal(report.recoveryHeld, true); assert.equal(f.store.casCount, 0); assert.equal(f.observations.length, 0);
    assert.ok(report.limitations.includes('excluded-security-metadata:schedule_quarantine'));
  } finally { f.cleanup(); }
});

test('U12 forged observation scope/freshness and expiry during shared CAS retain the durable hold', async () => {
  for (const fault of ['wrong-resource', 'wrong-predecessor', 'stale', 'expiry-during-cas'] as const) {
    const f = await setup();
    try {
      if (fault === 'expiry-during-cas') {
        const originalCAS = f.store.compareAndSet.bind(f.store);
        f.store.compareAndSet = async (version, next) => { const result = await originalCAS(version, next); f.setNow(1000000); return result; };
      } else {
        const originalObserve = f.observer.observe;
        f.observer.observe = async request => {
          const proof = await originalObserve(request);
          if (fault === 'wrong-resource') proof.resourceId = 'another-resource';
          if (fault === 'wrong-predecessor') proof.predecessor.ownerId = 'another-owner';
          if (fault === 'stale') { proof.observedAt = 0; proof.expiresAt = 1; }
          return proof;
        };
      }
      const report = await f.coordinator().recover();
      assert.equal(report.recoveryHeld, true);
      assert.equal(f.imported.journal.read(db => db.prepare('SELECT recovery_hold FROM controller').get()!.recovery_hold), 1);
    } finally { f.cleanup(); }
  }
});

test('U12 recovery WebAuthn rejects forged assertion and a verified ceremony cannot cross recovery contexts', async () => {
  const f = await setup();
  try {
    const e = emergencyFixture(); const lost = f.coordinator('lost-phone', e.pin);
    const first = lost.createPhoneChallenge(ceremony());
    const fake = assertion(emergencyFixture(), first.challenge); fake.id = e.pin.credentialId; fake.rawId = e.pin.credentialId;
    await assert.rejects(lost.verifyPhoneAssertion({ challengeId: first.challengeId, response: fake }));
    const challenge = lost.createPhoneChallenge(ceremony());
    await lost.verifyPhoneAssertion({ challengeId: challenge.challengeId, response: assertion(e, challenge.challenge) });
    const root = f.coordinator('root-compromise', e.pin);
    const report = await root.recover({ ceremonyChallengeId: challenge.challengeId });
    assert.equal(report.recoveryHeld, true); assert.equal(f.store.casCount, 0);
    assert.ok(report.limitations.includes('emergency-ceremony-context-mismatch'));
  } finally { f.cleanup(); }
});
