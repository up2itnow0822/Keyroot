import { test } from 'node:test';
import { strict as assert } from 'node:assert';
import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import { mkdtempSync, rmSync, writeFileSync, chmodSync, existsSync, readFileSync, readdirSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { generateX25519Identity, identityToRecipient, Decrypter, Encrypter } from 'age-encryption';
import { isoCBOR } from '@simplewebauthn/server/helpers';
import type { AuthenticationResponseJSON } from '@simplewebauthn/server';
import { Journal } from '../../packages/core/src/journal.js';
import { ApprovalService, createLocalBootstrapContext, publicKeyFingerprint } from '../../packages/core/src/approval.js';
import { spawnSync } from 'node:child_process';
import { canonicalJSON, canonicalizeManifest, contentDigest, snapshotDigest, type ApprovalManifest } from '../../packages/core/src/manifest.js';
import type { EpochRecord, InstallationEpochStore } from '../../packages/core/src/installation-epoch.js';
import { exportRecoveryArchive, openRecoveryArchive } from '../../packages/core/src/recovery/export.js';
import { importRecoveryArchive } from '../../packages/core/src/recovery/import.js';
import { recoverFromFiles, runRecoverCLI, exportFromFiles, runBackupCLI, openExistingHeldRecovery, runResumeCLI, controllerRecoverySchemaRegistry, RECOVERY_IMPORTED_MARKER } from '../../apps/controller/src/commands/recover.js';
import { initializeScheduleSchema, ForecastStore } from '../../packages/core/src/schedule.js';
import { OwnerMetrics } from '../../packages/core/src/metrics.js';
import { MutationInterlock } from '../../packages/core/src/notifier.js';
import { type Recipe } from '../../packages/core/src/recipes/recipe.js';
import { controllerMetadataAdapter } from '../../apps/controller/src/metadata.js';
import { startController } from '../../apps/controller/src/server.js';
import { ControllerService } from '../../apps/controller/src/service.js';
import { BootFence } from '../../packages/core/src/boot-fence.js';
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
async function setup(pending = false, excluded = false, full = false) {
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
  if (excluded) source.transaction(db => db.exec('CREATE TABLE future_security_quarantine (consumer_id TEXT PRIMARY KEY, metadata TEXT);'));
  if (full) {
    initializeScheduleSchema(source);
    new ForecastStore(source).save({ lineageId: 'lineage', policyAt: 4000, intervalDays: 7, mfaRequired: true, restartBudget: 1, executionBudget: 2 });
    const interlock = new MutationInterlock(source); interlock.prepare('outbox-pending', 'quarantine-notice', 'consumer-id'); interlock.journalFailed('pending-op');
    const metrics = new OwnerMetrics(source, () => 2000); metrics.createCase('incident', ['lineage'], ['provider-unverified']); metrics.begin('owner-review', 'incident', 'review');
    source.transaction(db => {
      db.prepare('INSERT INTO schedule_quarantine VALUES(?,?,?)').run('consumer-id', 'destination-id', manifest.nonce);
      db.prepare('INSERT INTO schedule_validity VALUES(?,?,?,?)').run('lineage', 2000, 'unverified', 60000);
      db.prepare('INSERT INTO schedule_incident VALUES(?,?,?)').run(manifest.nonce, contentDigest(manifest), 'continuity-first');
    });
    const recipe: Recipe = { id: 'guided-recipe', version: '1', accountId: 'account', destinationId: 'store-target', steps: [{ action: 'open', targetId: 'dashboard', checkpoint: 'none' }, { action: 'confirm', targetId: 'complete', checkpoint: 'mfa' }] };
    // Hermetic REAL composition exercises controller metadata; these callbacks never admit an effect
    // or claim actual owner account/store/phone/isolation readiness. Demo never accepts injected ports.
    const refuseEffect = async (): Promise<never> => { assert.fail('Metadata-only recovery fixture cannot dispatch effects'); };
    const service = new ControllerService(source, 'real', { recipes: [recipe], assertLiveAdmission: refuseEffect, lifecycleDrivers: refuseEffect, liveGates: { account: refuseEffect, store: refuseEffect, phoneCustody: refuseEffect, origin: refuseEffect, isolation: refuseEffect, recovery: refuseEffect } }, () => 2000);
    service.configurePhoneOrigin('https://recovery-phone.fixture.invalid');
    const controller = controllerMetadataAdapter(source);
    const inventory = service.inventory();
    inventory.lineages.push({ id: 'demo-lineage', issuerId: 'synthetic-issuer', accountId: 'account', credentialType: 'metadata-only-recovery-fixture', grantType: 'static-key' });
    const inventoryRow = { id: 'inventory', metadata: canonicalJSON(inventory) }; controller.validateRow('controller_inventory', inventoryRow);
    source.transaction(db => db.prepare("UPDATE controller_inventory SET metadata=? WHERE id='inventory'").run(inventoryRow.metadata));
    service.guided(recipe.id, 'dashboard');
    service.prepare({ signerId: 'lost-phone', lineageIds: ['demo-lineage'], purpose: 'key-policy', targetId: 'demo-lineage', policy: { rotationDays: 7 } });
    controller.importRows({
      controller_policy: [{ id: 'demo-lineage', metadata: JSON.stringify({ rotationDays: 7 }) }],
      controller_guided: [{ id: recipe.id, metadata: JSON.stringify({ recipeId: recipe.id, recipeHash: contentDigest(recipe), accountId: recipe.accountId, destinationId: recipe.destinationId, stepIndex: 1, completed: false }) }],
    });
  }
  const identity = await generateX25519Identity();
  const recipient = await identityToRecipient(identity);
  const archive = await exportRecoveryArchive({ journal: source, recipient, now: 2000, signerFingerprint: pin.fingerprint, ...(full ? { additionalSchemaRegistry: controllerRecoverySchemaRegistry } : {}), sign: async bytes => sign('sha256', bytes, { key: owner.privateKey, dsaEncoding: 'ieee-p1363' }).toString('base64url') });
  const opened = await openRecoveryArchive({ archive, identity, verification: pin, now: 3000, ...(full ? { additionalSchemaRegistry: controllerRecoverySchemaRegistry } : {}) });
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
  return { dir, source, imported, store, predecessor, archive, identity, pin, owner, recipient, coordinator, outcomes, observations, observer, resources, manifest, raw, signature, now: () => now, setNow: (value: number) => { now = value; }, cleanup: () => { source.close(); imported.journal.close(); rmSync(dir, { recursive: true, force: true }); } };
}
function emergencyFixture() {
  const keys = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const jwk = keys.publicKey.export({ format: 'jwk' });
  return { keys, pin: { credentialId: Buffer.from('synthetic-offline-key').toString('base64url'), cosePublicKey: isoCBOR.encode(new Map<number, number | Uint8Array>([[1, 2], [3, -7], [-1, 1], [-2, Buffer.from(jwk.x!, 'base64url')], [-3, Buffer.from(jwk.y!, 'base64url')]])), fingerprint: publicKeyFingerprint(jwk), rpId: 'approve.keyroot.test', origin: 'https://approve.keyroot.test', counter: 0 } };
}
function assertion(emergency: ReturnType<typeof emergencyFixture>, challenge: string, counter = 1): AuthenticationResponseJSON {
  const client = Buffer.from(JSON.stringify({ type: 'webauthn.get', challenge, origin: emergency.pin.origin, crossOrigin: false }));
  const auth = Buffer.alloc(37); createHash('sha256').update(emergency.pin.rpId).digest().copy(auth); auth[32] = 0x05; auth.writeUInt32BE(counter, 33);
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
    assert.deepEqual(f.imported.report.excludedTables, ['future_security_quarantine']);
    const report = await f.coordinator().recover();
    assert.equal(report.recoveryHeld, true); assert.equal(f.store.casCount, 0); assert.equal(f.observations.length, 0);
    assert.ok(report.limitations.includes('excluded-security-metadata:future_security_quarantine'));
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


function recoveryFiles(f: Awaited<ReturnType<typeof setup>>, suffix = 'operator') {
  const archivePath = join(f.dir, 'metadata.age'); const identityPath = join(f.dir, 'offline-identity'); const verificationPinPath = join(f.dir, 'independent-public-pin.json');
  writeFileSync(archivePath, f.archive, { mode: 0o600 }); writeFileSync(identityPath, f.identity + '\n', { mode: 0o600 }); writeFileSync(verificationPinPath, JSON.stringify(f.pin), { mode: 0o600 });
  return { archivePath, identityPath, verificationPinPath, destinationDirectory: join(f.dir, suffix), controllerSocketPath: join(f.dir, 'boot.sock'), clock: f.now };
}

test('U12b full schema roundtrip preserves quarantine, alarm, outbox, guided progress and controller rows while invalidating authority', async () => {
  const f = await setup(true, false, true);
  try {
    assert.equal(f.imported.report.coverageComplete, true);
    const j = f.imported.journal;
    assert.deepEqual(j.read(db => JSON.parse(String(db.prepare('SELECT metadata FROM controller_runtime').get()!.metadata))), { mode: 'real' });
    assert.equal(j.read(db => db.prepare('SELECT grant_id FROM schedule_quarantine').get()!.grant_id), 'old-approval');
    assert.equal(j.read(db => db.prepare('SELECT status FROM schedule_outbox').get()!.status), 'prepared');
    assert.equal(j.read(db => db.prepare('SELECT resolved FROM schedule_alarm').get()!.resolved), 0);
    assert.equal(j.read(db => db.prepare('SELECT step_index FROM guided_draft').get()!.step_index), 1);
    assert.equal(j.read(db => db.prepare('SELECT completed FROM guided_draft').get()!.completed), 0);
    assert.equal(j.read(db => db.prepare('SELECT ended_at FROM owner_interval').get()!.ended_at), null);
    assert.equal(j.read(db => db.prepare('SELECT count(*) AS n FROM controller_batch').get()!.n), 1);
    assert.equal(j.read(db => db.prepare('SELECT count(*) AS n FROM controller_batch_context').get()!.n), 1);
    assert.equal(j.read(db => JSON.parse(String(db.prepare('SELECT metadata FROM controller_descriptor').get()!.metadata)).purpose), 'key-policy');
    assert.equal(j.read(db => db.prepare('SELECT cancelled FROM approval_grant').get()!.cancelled), 1);
    assert.equal(j.read(db => db.prepare('SELECT revoked FROM approver').get()!.revoked), 1);
    const report = await f.coordinator().recover(); assert.equal(report.recoveryHeld, true);
  } finally { f.cleanup(); }
});

test('U12b operator recovery reads private offline files and emits only a held metadata report', async () => {
  const f = await setup(false, false, true);
  try {
    const files = recoveryFiles(f);
    const report = await recoverFromFiles(files);
    assert.equal(report.recoveryHeld, true); assert.equal(report.coverageComplete, true); assert.ok(existsSync(files.destinationDirectory));
    assert.notEqual(report.installationId, f.source.installationId);
    assert.ok(!JSON.stringify(report).includes(f.identity));
    const restored = new Journal(join(files.destinationDirectory, 'journal.sqlite'), { installationId: report.installationId, bootId: report.bootId });
    try { assert.equal(restored.read(db => db.prepare('SELECT recovery_hold FROM controller').get()!.recovery_hold), 1); assert.equal(restored.read(db => db.prepare('SELECT count(*) AS n FROM schedule_quarantine').get()!.n), 1); }
    finally { restored.close(); }
    const output: string[] = []; const errors: string[] = [];
    const second = recoveryFiles(f, 'operator-cli');
    const code = await runRecoverCLI(['--archive', second.archivePath, '--identity-file', second.identityPath, '--verification-pin-file', second.verificationPinPath, '--destination-directory', second.destinationDirectory, '--controller-socket', second.controllerSocketPath], { write: text => output.push(text), error: text => errors.push(text) });
    assert.equal(code, 0); assert.equal(errors.length, 0); assert.equal(JSON.parse(output[0]!).status, 'imported-held');
    assert.ok(!output.join('').includes(f.identity));
  } finally { f.cleanup(); }
});

test('U12b operator rejects wrong identity, loose permissions, live singleton and existing target without leaking offline material', async () => {
  for (const fault of ['wrong-identity', 'permissions', 'live-controller', 'existing-target'] as const) {
    const f = await setup(false, false, true); let fence: BootFence | undefined;
    try {
      const files = recoveryFiles(f);
      if (fault === 'wrong-identity') writeFileSync(files.identityPath, await generateX25519Identity(), { mode: 0o600 });
      if (fault === 'permissions') chmodSync(files.identityPath, 0o644);
      if (fault === 'live-controller') fence = await BootFence.acquire(files.controllerSocketPath);
      if (fault === 'existing-target') files.destinationDirectory = f.dir;
      const errors: string[] = [];
      await assert.rejects(recoverFromFiles(files), error => { errors.push(String(error)); return (error as { code?: string }).code === 'RECOVERY_IMPORT_DENIED'; });
      assert.ok(!errors.join('').includes(f.identity));
      assert.ok(!errors.join('').includes(files.identityPath));
      if (fault !== 'existing-target') assert.equal(existsSync(files.destinationDirectory), false);
      assert.equal(f.source.read(db => db.prepare('SELECT installation_id FROM controller').get()!.installation_id), 'predecessor');
    } finally { await fence?.release(); f.cleanup(); }
  }
});


test('U12b authentically signed malformed security rows and schema fingerprints are rejected before import', async () => {
  const f = await setup(false, false, true);
  try {
    const d = new Decrypter(); d.addIdentity(f.identity); const raw = await d.decrypt(f.archive, 'text');
    for (const fault of ['quarantine', 'outbox', 'forecast', 'guided', 'controller-policy', 'table-schema', 'registry-schema'] as const) {
      const envelope = JSON.parse(raw) as { metadata: { tables: Record<string, Record<string, unknown>[]>; additionalTables: Record<string, Record<string, unknown>[]>; tableInventory: { name: string; schemaHash: string }[]; additionalSchemaHash: string }; statement: Record<string, unknown>; signature: string };
      if (fault === 'quarantine') envelope.metadata.tables.schedule_quarantine![0]!.grant_id = '';
      if (fault === 'outbox') envelope.metadata.tables.schedule_outbox![0]!.status = 'run-now';
      if (fault === 'forecast') { const metadata = JSON.parse(String(envelope.metadata.tables.schedule_forecast![0]!.metadata)) as Record<string, unknown>; metadata.promptAt = 1; envelope.metadata.tables.schedule_forecast![0]!.metadata = JSON.stringify(metadata); }
      if (fault === 'guided') envelope.metadata.tables.guided_draft![0]!.step_index = 33;
      if (fault === 'controller-policy') envelope.metadata.additionalTables.controller_policy![0]!.metadata = JSON.stringify({ rotationDays: 0 });
      if (fault === 'table-schema') envelope.metadata.tableInventory.find(table => table.name === 'schedule_quarantine')!.schemaHash = contentDigest('different-schema');
      if (fault === 'registry-schema') envelope.metadata.additionalSchemaHash = contentDigest('unregistered-schema');
      envelope.statement.metadataHash = contentDigest(envelope.metadata);
      envelope.signature = sign('sha256', Buffer.from(canonicalJSON(envelope.statement)), { key: f.owner.privateKey, dsaEncoding: 'ieee-p1363' }).toString('base64url');
      const e = new Encrypter(); e.addRecipient(f.recipient);
      await assert.rejects(openRecoveryArchive({ archive: await e.encrypt(canonicalJSON(envelope)), identity: f.identity, verification: f.pin, now: 3000, additionalSchemaRegistry: controllerRecoverySchemaRegistry }));
    }
  } finally { f.cleanup(); }
});

test('U12b actual Node CLI accepts file paths and prints a metadata-only held report', async () => {
  const f = await setup(false, false, true);
  try {
    const files = recoveryFiles(f, 'node-cli');
    const result = spawnSync(process.execPath, ['--import', 'tsx', resolve('apps/controller/src/commands/recover.ts'), '--archive', files.archivePath, '--identity-file', files.identityPath, '--verification-pin-file', files.verificationPinPath, '--destination-directory', files.destinationDirectory, '--controller-socket', files.controllerSocketPath], { cwd: process.cwd(), encoding: 'utf8', timeout: 10000, maxBuffer: 65536 });
    assert.equal(result.status, 0); assert.equal(JSON.parse(result.stdout).status, 'imported-held');
    assert.equal(JSON.parse(result.stdout).report.recoveryHeld, true); assert.ok(!result.stdout.includes(f.identity)); assert.ok(!result.stderr.includes(f.identity));
    const denied = spawnSync(process.execPath, ['--import', 'tsx', resolve('apps/controller/src/commands/recover.ts'), '--identity-file', files.identityPath], { cwd: process.cwd(), encoding: 'utf8', timeout: 10000, maxBuffer: 65536 });
    assert.equal(denied.status, 1); assert.deepEqual(JSON.parse(denied.stderr), { status: 'denied', code: 'RECOVERY_IMPORT_DENIED' });
  } finally { f.cleanup(); }
});


test('U12b published installation boots held with matching identity, private modes and permanent real-mode markers', async () => {
  const f = await setup(false, false, true);
  try {
    const files = recoveryFiles(f, 'bootable-stage'); const report = await recoverFromFiles(files);
    const installationId = readFileSync(join(files.destinationDirectory, 'installation-id'), 'utf8').trim();
    assert.equal(installationId, report.installationId);
    assert.equal(readFileSync(join(files.destinationDirectory, 'runtime-mode'), 'utf8'), 'real\n');
    const marker = JSON.parse(readFileSync(join(files.destinationDirectory, RECOVERY_IMPORTED_MARKER), 'utf8')) as Record<string, unknown>;
    assert.equal(marker.domain, 'keyroot.recovery-imported.v1'); assert.equal(marker.installationId, installationId); assert.equal(marker.metadataHash, report.metadataHash);
    assert.equal(statSync(files.destinationDirectory).mode & 0o777, 0o700);
    for (const name of ['journal.sqlite', 'installation-id', 'runtime-mode', RECOVERY_IMPORTED_MARKER]) assert.equal(statSync(join(files.destinationDirectory, name)).mode & 0o777, 0o600);
    assert.equal(existsSync(join(files.destinationDirectory, 'identity.pem')), false);
    const journal = new Journal(join(files.destinationDirectory, 'journal.sqlite'), { installationId, bootId: 'fresh-controller-recovery-boot' });
    try {
      assert.equal(journal.read(db => db.prepare('SELECT recovery_hold FROM controller').get()!.recovery_hold), 1);
      assert.equal(journal.read(db => db.prepare('SELECT revoked FROM approver').get()!.revoked), 1);
      assert.equal(journal.sessionActive('old-dashboard-and-read-session'), false);
      journal.releaseRecoveryHold();
      assert.equal(readFileSync(join(files.destinationDirectory, 'runtime-mode'), 'utf8'), 'real\n');
      assert.ok(existsSync(join(files.destinationDirectory, RECOVERY_IMPORTED_MARKER)));
    } finally { journal.close(); }
    assert.equal(readdirSync(f.dir).some(name => name.startsWith('.keyroot-recovery-')), false);
  } finally { f.cleanup(); }
});

test('U12b failed foreign-key restore removes only its unpublished staging installation', async () => {
  const f = await setup(false, false, true);
  try {
    const files = recoveryFiles(f, 'never-published');
    const sentinel = join(f.dir, 'unrelated-file'); writeFileSync(sentinel, 'keep', { mode: 0o600 });
    const d = new Decrypter(); d.addIdentity(f.identity);
    const envelope = JSON.parse(await d.decrypt(f.archive, 'text')) as { metadata: { tables: Record<string, unknown[]> }; statement: Record<string, unknown>; signature: string };
    envelope.metadata.tables.lineage_lock = [{ lineage_id: 'unresolved-lineage', operation_id: 'missing-operation', fence: 'synthetic-fence' }];
    envelope.statement.metadataHash = contentDigest(envelope.metadata); envelope.signature = sign('sha256', Buffer.from(canonicalJSON(envelope.statement)), { key: f.owner.privateKey, dsaEncoding: 'ieee-p1363' }).toString('base64url');
    const e = new Encrypter(); e.addRecipient(f.recipient); writeFileSync(files.archivePath, await e.encrypt(canonicalJSON(envelope)), { mode: 0o600 });
    await assert.rejects(recoverFromFiles(files), /Recovery import denied/);
    assert.equal(existsSync(files.destinationDirectory), false); assert.equal(readdirSync(f.dir).some(name => name.startsWith('.keyroot-recovery-')), false);
    assert.equal(readFileSync(sentinel, 'utf8'), 'keep'); assert.equal(f.source.installationId, 'predecessor');
  } finally { f.cleanup(); }
});


test('U12b actual controller factory opens recovered installation in real held mode and denies public demo access', async () => {
  const f = await setup(false, false, true); let controller: Awaited<ReturnType<typeof startController>> | undefined;
  try {
    const files = recoveryFiles(f, 'factory-stage'); const report = await recoverFromFiles(files);
    await assert.rejects(startController({ directory: files.destinationDirectory, port: 0, mode: 'demo' }), /Runtime mode excludes demo/);
    controller = await startController({ directory: files.destinationDirectory, port: 0, mode: 'real', phoneOrigin: 'https://approve.keyroot.test', clock: f.now });
    assert.equal(controller.identity.installationId, report.installationId); assert.equal(controller.service.mode, 'real');
    assert.equal(controller.service.journal.read(db => db.prepare('SELECT recovery_hold FROM controller').get()!.recovery_hold), 1);
    assert.equal(controller.service.journal.read(db => db.prepare('SELECT revoked FROM approver').get()!.revoked), 1);
    assert.equal(await controller.service.quarantine.check('consumer-id', 'destination-id'), 'quarantined');
    const demo = await fetch(controller.origin + '/api/session/demo', { method: 'POST', headers: { Origin: controller.origin } });
    assert.equal(demo.status, 404);
    const inventory = await fetch(controller.origin + '/api/inventory'); assert.equal(inventory.status, 401);
    controller.service.journal.releaseRecoveryHold();
    assert.throws(() => new ControllerService(controller!.service.journal, 'demo'), /Real metadata cannot enter demo runtime/);
  } finally { await controller?.close(); f.cleanup(); }
});


test('U12 operator backup and fresh-process held resumption have actual callable entry points', () => {
  assert.equal(typeof exportFromFiles, 'function'); assert.equal(typeof runBackupCLI, 'function');
  assert.equal(typeof openExistingHeldRecovery, 'function'); assert.equal(typeof runResumeCLI, 'function');
});


function resumeFiles(files: ReturnType<typeof recoveryFiles>, f: Awaited<ReturnType<typeof setup>>) {
  return { archivePath: files.archivePath, identityPath: files.identityPath, verificationPinPath: files.verificationPinPath, directory: files.destinationDirectory, clock: f.now, epochStore: f.store };
}
test('U12 offline operator backup signs and encrypts a consistent existing boot without rotating source authority', async () => {
  const f = await setup(false, false, true);
  try {
    const files = recoveryFiles(f, 'backup-source'); const original = await recoverFromFiles(files);
    const recipientPath = join(f.dir, 'offline-recipient'); const signingKeyPath = join(f.dir, 'offline-owner-signing.pem'); const archiveOutputPath = join(f.dir, 'operator-backup.age');
    writeFileSync(recipientPath, f.recipient + '\n', { mode: 0o600 }); writeFileSync(signingKeyPath, f.owner.privateKey.export({ format: 'pem', type: 'pkcs8' }), { mode: 0o600 });
    const report = await exportFromFiles({ sourceDirectory: files.destinationDirectory, recipientPath, signingKeyPath, archiveOutputPath, clock: f.now });
    assert.equal(report.sourceInstallationId, original.installationId); assert.equal(report.sourceBootId, original.bootId);
    assert.equal(statSync(archiveOutputPath).mode & 0o777, 0o600); assert.equal(readFileSync(join(files.destinationDirectory, 'installation-id'), 'utf8').trim(), original.installationId);
    const opened = await openRecoveryArchive({ archive: readFileSync(archiveOutputPath), identity: f.identity, verification: f.pin, now: 3000, additionalSchemaRegistry: controllerRecoverySchemaRegistry });
    assert.equal(opened.statement.bootId, original.bootId); assert.equal(opened.metadata.tables.schedule_quarantine.length, 1);
    const outputs: string[] = []; const errors: string[] = [];
    const code = await runBackupCLI(['--source-directory', files.destinationDirectory, '--recipient-file', recipientPath, '--signing-key-file', signingKeyPath, '--output', join(f.dir, 'second-backup.age')], { write: text => outputs.push(text), error: text => errors.push(text) });
    assert.equal(code, 0); assert.equal(errors.length, 0); assert.equal(JSON.parse(outputs[0]!).status, 'backup-exported'); assert.ok(!outputs.join('').includes('PRIVATE KEY'));
    const child = spawnSync(process.execPath, ['--import', 'tsx', resolve('apps/controller/src/commands/recover.ts'), 'backup', '--source-directory', files.destinationDirectory, '--recipient-file', recipientPath, '--signing-key-file', signingKeyPath, '--output', join(f.dir, 'child-backup.age')], { cwd: process.cwd(), encoding: 'utf8', timeout: 10000, maxBuffer: 65536 });
    assert.equal(child.status, 0); assert.equal(JSON.parse(child.stdout).status, 'backup-exported'); assert.ok(!child.stdout.includes('PRIVATE KEY'));
    await assert.rejects(exportFromFiles({ sourceDirectory: files.destinationDirectory, recipientPath, signingKeyPath, archiveOutputPath }), /Recovery backup denied/);
    const fence = await BootFence.acquire(join(files.destinationDirectory, 'boot.sock'));
    try { await assert.rejects(exportFromFiles({ sourceDirectory: files.destinationDirectory, recipientPath, signingKeyPath, archiveOutputPath: join(f.dir, 'live-denied.age') })); assert.equal(existsSync(join(f.dir, 'live-denied.age')), false); } finally { await fence.release(); }
    const forbiddenKey = join(files.destinationDirectory, 'controller-private.pem'); writeFileSync(forbiddenKey, f.owner.privateKey.export({ format: 'pem', type: 'pkcs8' }), { mode: 0o600 });
    await assert.rejects(exportFromFiles({ sourceDirectory: files.destinationDirectory, recipientPath, signingKeyPath: forbiddenKey, archiveOutputPath: join(f.dir, 'controller-key-denied.age') }));
  } finally { f.cleanup(); }
});

test('U12 each resumed session decrypts again and issues a new process-local held capability for the same database', async () => {
  const f = await setup(false, false, true);
  try {
    const files = recoveryFiles(f, 'resume-target'); const original = await recoverFromFiles(files);
    const session = await openExistingHeldRecovery(resumeFiles(files, f));
    assert.equal(session.imported.journal.installationId, original.installationId); assert.equal(session.imported.report.recoveryHeld, true);
    const serialized = JSON.parse(JSON.stringify({ opened: session.imported.opened, report: session.imported.report })) as { opened: typeof session.imported.opened; report: typeof session.imported.report };
    assert.throws(() => new RecoveryCoordinator({ imported: { journal: session.imported.journal, ...serialized }, scenario: 'box-loss', observedPredecessor: f.predecessor, epochStore: f.store, observer: f.observer, resources: f.resources, clock: f.now }), /offline decryption/);
    await session.close();
    const outputs: string[] = []; const errors: string[] = [];
    const code = await runResumeCLI(['--archive', files.archivePath, '--identity-file', files.identityPath, '--verification-pin-file', files.verificationPinPath, '--directory', files.destinationDirectory], { write: text => outputs.push(text), error: text => errors.push(text) });
    assert.equal(code, 0); assert.equal(errors.length, 0); assert.equal(JSON.parse(outputs[0]!).status, 'reauthenticated-held'); assert.ok(!outputs.join('').includes(f.identity));
    const child = spawnSync(process.execPath, ['--import', 'tsx', resolve('apps/controller/src/commands/recover.ts'), 'resume', '--archive', files.archivePath, '--identity-file', files.identityPath, '--verification-pin-file', files.verificationPinPath, '--directory', files.destinationDirectory], { cwd: process.cwd(), encoding: 'utf8', timeout: 10000, maxBuffer: 65536 });
    assert.equal(child.status, 0); assert.equal(JSON.parse(child.stdout).status, 'reauthenticated-held'); assert.equal(JSON.parse(child.stdout).report.recoveryHeld, true);
    assert.ok(!child.stdout.includes(f.identity));
  } finally { f.cleanup(); }
});

test('U12 held resume rejects corrupt or wrong offline material, DB scope tampering, wrong epoch, source identity and live runtime', async () => {
  for (const fault of ['wrong-identity', 'wrong-pin', 'corrupt', 'db-tamper', 'epoch', 'source-identity', 'live-controller', 'mode'] as const) {
    const f = await setup(false, false, true); let fence: BootFence | undefined;
    try {
      const files = recoveryFiles(f, 'rejected-resume'); const original = await recoverFromFiles(files);
      if (fault === 'wrong-identity') writeFileSync(files.identityPath, await generateX25519Identity(), { mode: 0o600 });
      if (fault === 'corrupt') { const bytes = readFileSync(files.archivePath); bytes[bytes.length - 1]! ^= 1; writeFileSync(files.archivePath, bytes, { mode: 0o600 }); }
      if (fault === 'wrong-pin') { const key = generateKeyPairSync('ec', { namedCurve: 'prime256v1' }).publicKey.export({ format: 'jwk' }); writeFileSync(files.verificationPinPath, JSON.stringify({ publicKey: key, fingerprint: publicKeyFingerprint(key) }), { mode: 0o600 }); }
      if (fault === 'epoch') f.store.current = { installationId: 'unrelated-controller', ownerId: 'other-owner', version: 10 };
      if (fault === 'mode') writeFileSync(join(files.destinationDirectory, 'runtime-mode'), 'demo\n', { mode: 0o600 });
      if (fault === 'live-controller') fence = await BootFence.acquire(join(files.destinationDirectory, 'boot.sock'));
      if (fault === 'db-tamper' || fault === 'source-identity') {
        const j = new Journal(join(files.destinationDirectory, 'journal.sqlite'), { installationId: original.installationId, bootId: original.bootId });
        try { j.transaction(db => { if (fault === 'db-tamper') db.prepare("UPDATE approver SET revoked=0 WHERE signer_id='lost-phone'").run(); else db.prepare('UPDATE controller SET installation_id=?').run(f.source.installationId); }); } finally { j.close(); }
        if (fault === 'source-identity') { writeFileSync(join(files.destinationDirectory, 'installation-id'), f.source.installationId + '\n', { mode: 0o600 }); const path = join(files.destinationDirectory, RECOVERY_IMPORTED_MARKER); const marker = JSON.parse(readFileSync(path, 'utf8')) as Record<string, unknown>; marker.installationId = f.source.installationId; writeFileSync(path, JSON.stringify(marker), { mode: 0o600 }); }
      }
      await assert.rejects(openExistingHeldRecovery(resumeFiles(files, f)), /Recovery import denied/);
      assert.ok(existsSync(join(files.destinationDirectory, 'journal.sqlite'))); assert.equal(f.source.installationId, 'predecessor');
    } finally { await fence?.release(); f.cleanup(); }
  }
});

test('U12 fresh reauthentication invalidates persisted ceremony flags and permits a new actual emergency ceremony to progress', async () => {
  const f = await setup(false, false, true); const e = emergencyFixture();
  let first: Awaited<ReturnType<typeof openExistingHeldRecovery>> | undefined, second: Awaited<ReturnType<typeof openExistingHeldRecovery>> | undefined;
  try {
    const files = recoveryFiles(f, 'ceremony-resume'); await recoverFromFiles(files);
    const make = (imported: NonNullable<typeof first>['imported']) => new RecoveryCoordinator({ imported, scenario: 'lost-phone', observedPredecessor: f.predecessor, epochStore: f.store, observer: { observe: request => f.observer.observe(request) }, resources: f.resources, clock: f.now, emergency: e.pin });
    first = await openExistingHeldRecovery(resumeFiles(files, f)); const old = make(first.imported); const challenge = old.createPhoneChallenge(ceremony()); await old.verifyPhoneAssertion({ challengeId: challenge.challengeId, response: assertion(e, challenge.challenge) });
    await first.close(); first = undefined;
    second = await openExistingHeldRecovery(resumeFiles(files, f)); const fresh = make(second.imported);
    const denied = await fresh.recover({ ceremonyChallengeId: challenge.challengeId }); assert.equal(denied.recoveryHeld, true); assert.equal(f.store.casCount, 0);
    const next = fresh.createPhoneChallenge(ceremony()); await fresh.verifyPhoneAssertion({ challengeId: next.challengeId, response: assertion(e, next.challenge, 2) });
    const report = await fresh.recover({ ceremonyChallengeId: next.challengeId }); assert.equal(report.recoveryHeld, false); assert.equal(f.store.casCount, 1);
    assert.equal(second.imported.journal.read(db => db.prepare("SELECT revoked FROM approver WHERE signer_id='lost-phone'").get()!.revoked), 1);
  } finally { await first?.close(); await second?.close(); f.cleanup(); }
});
