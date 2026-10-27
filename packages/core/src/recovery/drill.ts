import { randomBytes, randomUUID } from 'node:crypto';
import { verifyAuthenticationResponse, type AuthenticationResponseJSON } from '@simplewebauthn/server';
import { decodeClientDataJSON, isoCBOR } from '@simplewebauthn/server/helpers';
import { InstallationEpoch, type EpochRecord, type InstallationEpochStore } from '../installation-epoch.js';
import { publicKeyFingerprint } from '../approval.js';
import { canonicalJSON, contentDigest, deepFreeze } from '../manifest.js';
import { assertOpenedArchive, exactKeys, recoveryHash, recoveryId, validatePublicPin, uncoveredRecoveryTables, type VerificationPin } from './export.js';
import { assertImportedRecovery, type ImportedRecovery, type RecoveryReport } from './import.js';

export type RecoveryScenario = 'box-loss' | 'lost-phone' | 'root-compromise';
export type RecoveryRequirement = 'store-value-backup' | 'issuer-native-access' | 'predecessor-quiesced' | 'management-authority-invalidated' | 'issuer-inflight-reconciliation' | 'clean-issuer-administration' | 'management-authority-replaced' | 'trusted-rebuild' | 'provider-session-invalidation';
/** These are trusted executor observations, never archive/HTTP claims. Unknown/partial outcomes retain the hold. */
export interface RecoveryObservation {
  requirement: RecoveryRequirement; predecessor: EpochRecord; metadataHash: string; resourceId: string; method: string; observerId: string;
  evidenceHash: string; observedAt: number; expiresAt: number; outcome: 'confirmed' | 'unknown' | 'unsupported' | 'partial';
}
export interface RecoveryObserver {
  /** Must perform an actual read-only store/issuer/process observation. The coordinator never executes credential effects. */
  observe(request: { requirement: RecoveryRequirement; predecessor: Readonly<EpochRecord>; metadataHash: string; resourceId: string }): Promise<RecoveryObservation>;
}
export interface RecoveryEmergencyPin {
  credentialId: string; cosePublicKey: Uint8Array; fingerprint: string; rpId: string; origin: string; counter: number;
}
export interface ReplacementPhone { signerId: string; verification: VerificationPin }
export interface CustodyAttestation { operatorId: string; evidenceHash: string; observedAt: number }
interface Ceremony { oldSignerId: string; replacement: ReplacementPhone; custody: CustodyAttestation }
const sameEpoch = (a: EpochRecord, b: EpochRecord) => a.installationId === b.installationId && a.ownerId === b.ownerId && a.version === b.version;

/** Independent offline capsule + maintained WebAuthn verification. Emergency hardware is not an archive encryption key. */
export class RecoveryCoordinator {
  private readonly epoch: InstallationEpoch;
  private readonly predecessor: Readonly<EpochRecord>;
  private readonly emergency?: RecoveryEmergencyPin;
  private completed = false;
  private casGuard: (() => void) | undefined;
  constructor(private readonly input: {
    imported: ImportedRecovery; scenario: RecoveryScenario; observedPredecessor: EpochRecord;
    epochStore: InstallationEpochStore; observer: RecoveryObserver;
    /** Explicit resources chosen by the clean owning executor, outside the archive. */
    resources: Readonly<Record<RecoveryRequirement, string>>;
    clock: () => number; emergency?: RecoveryEmergencyPin;
    predecessorResolution?: 'quiesced' | 'management-authority-invalidated';
  }) {
    assertImportedRecovery(input.imported);
    assertOpenedArchive(input.imported.opened);
    const j = input.imported.journal;
    j.setRecoveryHold(); // Durable before any observer/CAS/ceremony.
    const p = input.observedPredecessor;
    recoveryId(p.installationId); recoveryId(p.ownerId);
    if (!Number.isSafeInteger(p.version) || p.version < 1) throw new Error('Exact predecessor epoch required');
    this.predecessor = deepFreeze({ ...p });
    input.resources = deepFreeze({ ...input.resources });
    this.epoch = new InstallationEpoch(j.installationId, {
      read: () => input.epochStore.read(),
      compareAndSet: async (version, next) => {
        this.assertHeld();
        if (!this.casGuard) throw new Error('Scoped recovery observations required before CAS');
        this.casGuard();
        const result = await input.epochStore.compareAndSet(version, next);
        this.casGuard();
        return result;
      },
    }, j);
    for (const resource of Object.values(input.resources)) recoveryId(resource);
    if (input.emergency) {
      const e = input.emergency;
      const cose = isoCBOR.decodeFirst<Map<number, unknown>>(new Uint8Array(e.cosePublicKey));
      const x = cose.get(-2), y = cose.get(-3);
      if (cose.get(1) !== 2 || cose.get(3) !== -7 || cose.get(-1) !== 1 || !(x instanceof Uint8Array) || !(y instanceof Uint8Array) || x.length !== 32 || y.length !== 32) throw new Error('Independently pinned ES256 emergency key required');
      const key = { kty: 'EC', crv: 'P-256', x: Buffer.from(x).toString('base64url'), y: Buffer.from(y).toString('base64url') };
      validatePublicPin({ publicKey: key, fingerprint: e.fingerprint });
      const origin = new URL(e.origin);
      if (origin.protocol !== 'https:' || origin.origin !== e.origin || !(origin.hostname === e.rpId || origin.hostname.endsWith('.' + e.rpId)) || !/^[a-zA-Z0-9_-]{1,1024}$/.test(e.credentialId) || !Number.isSafeInteger(e.counter) || e.counter < 0) throw new Error('Invalid independent emergency enrollment');
      this.emergency = { ...e, cosePublicKey: new Uint8Array(e.cosePublicKey) };
    }
    j.transaction(db => db.exec('CREATE TABLE IF NOT EXISTS recovery_observation (id TEXT PRIMARY KEY, metadata TEXT NOT NULL); CREATE TABLE IF NOT EXISTS recovery_ceremony (challenge_id TEXT PRIMARY KEY, challenge TEXT NOT NULL, binding TEXT NOT NULL, expires_at INTEGER NOT NULL, used INTEGER NOT NULL DEFAULT 0, verified INTEGER NOT NULL DEFAULT 0); CREATE TABLE IF NOT EXISTS recovery_emergency_counter (fingerprint TEXT PRIMARY KEY, counter INTEGER NOT NULL);'));
  }
  private assertHeld(): void {
    if (this.completed || this.input.imported.journal.read(db => db.prepare('SELECT recovery_hold FROM controller WHERE singleton=1').get()?.recovery_hold) !== 1) throw new Error('Recovery workflow is no longer held');
  }
  async assertBeforeEffect(): Promise<void> { await this.epoch.assertBeforeEffect(); }
  private ceremonyBinding(ceremony: Ceremony) {
    return { ceremony, predecessor: this.predecessor, metadataHash: this.input.imported.opened.statement.metadataHash, installationId: this.input.imported.journal.installationId, bootId: this.input.imported.journal.bootId, scenario: this.input.scenario, emergencyFingerprint: this.emergency?.fingerprint };
  }
  private boundCeremony(raw: string): Ceremony {
    const binding = JSON.parse(raw) as ReturnType<RecoveryCoordinator['ceremonyBinding']>;
    if (canonicalJSON(binding) !== canonicalJSON(this.ceremonyBinding(binding.ceremony))) throw new Error('Emergency ceremony belongs to another recovery context');
    return binding.ceremony;
  }
  createPhoneChallenge(ceremony: Ceremony): { challengeId: string; challenge: string; rpId: string; credentialId: string; expiresAt: number } {
    this.assertHeld();
    if (!this.emergency || this.input.scenario === 'box-loss') throw new Error('Lost-phone/root ceremony requires independent emergency enrollment and offline capsule');
    recoveryId(ceremony.oldSignerId); recoveryId(ceremony.replacement.signerId); recoveryId(ceremony.custody.operatorId);
    validatePublicPin(ceremony.replacement.verification); recoveryHash(ceremony.custody.evidenceHash);
    const now = this.input.clock();
    if (ceremony.oldSignerId === ceremony.replacement.signerId || ceremony.custody.observedAt > now || ceremony.custody.observedAt < now - 300000) throw new Error('Fresh operator custody attestation and new signer identity required');
    const old = this.input.imported.journal.read(db => db.prepare("SELECT fingerprint FROM approver WHERE signer_id=? AND role='routine'").get(ceremony.oldSignerId));
    if (!old || old.fingerprint === ceremony.replacement.verification.fingerprint) throw new Error('Distinct replacement phone fingerprint required');
    const challengeId = randomUUID();
    const challenge = Buffer.from(contentDigest({ domain: 'keyroot.offline-phone-recovery.v1', metadataHash: this.input.imported.opened.statement.metadataHash, installationId: this.input.imported.journal.installationId, bootId: this.input.imported.journal.bootId, predecessor: this.predecessor, ceremony, nonce: randomBytes(32).toString('base64url') })).toString('base64url');
    const expiresAt = now + 60000;
    this.input.imported.journal.transaction(db => db.prepare('INSERT INTO recovery_ceremony VALUES(?,?,?,?,0,0)').run(challengeId, challenge, canonicalJSON(this.ceremonyBinding(ceremony)), expiresAt));
    return { challengeId, challenge, rpId: this.emergency.rpId, credentialId: this.emergency.credentialId, expiresAt };
  }
  async verifyPhoneAssertion(input: { challengeId: string; response: AuthenticationResponseJSON }): Promise<void> {
    this.assertHeld();
    const e = this.emergency;
    if (!e) throw new Error('Independent emergency enrollment required');
    const j = this.input.imported.journal;
    const saved = j.transaction(db => {
      const row = db.prepare('SELECT * FROM recovery_ceremony WHERE challenge_id=? AND used=0').get(input.challengeId);
      if (!row || Number(row.expires_at) <= this.input.clock()) throw new Error('Recovery challenge expired or consumed');
      this.boundCeremony(String(row.binding));
      db.prepare('UPDATE recovery_ceremony SET used=1 WHERE challenge_id=?').run(input.challengeId);
      const localCounter = db.prepare('SELECT counter FROM recovery_emergency_counter WHERE fingerprint=?').get(e.fingerprint);
      return { challenge: String(row.challenge), expiresAt: Number(row.expires_at), counter: Math.max(e.counter, Number(localCounter?.counter ?? 0)) };
    });
    if (input.response.id !== e.credentialId || input.response.rawId !== e.credentialId || decodeClientDataJSON(input.response.response.clientDataJSON).crossOrigin) throw new Error('Emergency assertion identity/origin mismatch');
    const result = await verifyAuthenticationResponse({ response: input.response, expectedChallenge: saved.challenge, expectedOrigin: e.origin, expectedRPID: e.rpId, requireUserVerification: true, credential: { id: e.credentialId, publicKey: new Uint8Array(e.cosePublicKey), counter: saved.counter } });
    this.assertHeld();
    if (!result.verified || !result.authenticationInfo.userVerified || result.authenticationInfo.credentialDeviceType !== 'singleDevice' || result.authenticationInfo.credentialBackedUp || this.input.clock() >= saved.expiresAt) throw new Error('Fresh present verified single-device emergency assertion required');
    j.transaction(db => {
      const current = db.prepare('SELECT counter FROM recovery_emergency_counter WHERE fingerprint=?').get(e.fingerprint);
      if (Math.max(e.counter, Number(current?.counter ?? 0)) !== saved.counter) throw new Error('Emergency counter raced');
      db.prepare('INSERT INTO recovery_emergency_counter VALUES(?,?) ON CONFLICT(fingerprint) DO UPDATE SET counter=excluded.counter').run(e.fingerprint, result.authenticationInfo.newCounter);
      db.prepare('UPDATE recovery_ceremony SET verified=1 WHERE challenge_id=?').run(input.challengeId);
      j.audit(db, 'offline-emergency-assertion-verified', null, input.challengeId);
    });
  }
  /** Read-only reconciliation may append scoped observations while the durable hold remains set. */
  async observe(requirement: RecoveryRequirement): Promise<RecoveryObservation> {
    this.assertHeld();
    const resourceId = this.input.resources[requirement];
    recoveryId(resourceId);
    const observation = await this.input.observer.observe({ requirement, predecessor: this.predecessor, metadataHash: this.input.imported.opened.statement.metadataHash, resourceId });
    this.assertHeld();
    const now = this.input.clock();
    exactKeys(observation, ['requirement', 'predecessor', 'metadataHash', 'resourceId', 'method', 'observerId', 'evidenceHash', 'observedAt', 'expiresAt', 'outcome']);
    exactKeys(observation.predecessor, ['installationId', 'ownerId', 'version']);
    if (observation.metadataHash !== this.input.imported.opened.statement.metadataHash || observation.requirement !== requirement || observation.resourceId !== resourceId || !sameEpoch(observation.predecessor, this.predecessor) || !Number.isSafeInteger(observation.observedAt) || !Number.isSafeInteger(observation.expiresAt) || observation.observedAt > now || observation.observedAt < now - 300000 || observation.expiresAt <= now || observation.expiresAt > observation.observedAt + 300000 || !['confirmed', 'unknown', 'unsupported', 'partial'].includes(observation.outcome)) throw new Error('Recovery observation scope, predecessor or freshness invalid');
    recoveryId(observation.method); recoveryId(observation.observerId); recoveryHash(observation.evidenceHash);
    const copy = deepFreeze(structuredClone(observation));
    this.input.imported.journal.transaction(db => db.prepare('INSERT INTO recovery_observation VALUES(?,?)').run(randomUUID(), canonicalJSON(copy)));
    return copy;
  }
  async recover(input: { ceremonyChallengeId?: string } = {}): Promise<RecoveryReport> {
    this.assertHeld();
    const j = this.input.imported.journal;
    const report: RecoveryReport = { ...this.input.imported.report, limitations: [...this.input.imported.report.limitations], unresolvedIntentIds: j.read(db => db.prepare("SELECT intent_id FROM intent WHERE state!='observed'").all().map(row => String(row.intent_id))) };
    const uncovered = uncoveredRecoveryTables(this.input.imported.opened);
    if (uncovered.length) {
      report.limitations.push(...uncovered.map(table => 'excluded-security-metadata:' + table));
      return report;
    }
    const requirements: RecoveryRequirement[] = ['store-value-backup', 'issuer-native-access', 'issuer-inflight-reconciliation', this.input.scenario === 'root-compromise' || this.input.predecessorResolution === 'management-authority-invalidated' ? 'management-authority-invalidated' : 'predecessor-quiesced'];
    if (this.input.scenario === 'root-compromise') requirements.push('clean-issuer-administration', 'management-authority-replaced', 'trusted-rebuild', 'provider-session-invalidation');
    const proofs: RecoveryObservation[] = [];
    for (const requirement of requirements) {
      try { proofs.push(await this.observe(requirement)); }
      catch { report.limitations.push('missing-or-invalid-' + requirement); return report; }
    }
    for (const proof of proofs) if (proof.outcome !== 'confirmed') report.limitations.push(proof.requirement + '-' + proof.outcome);
    if (proofs.some(proof => proof.outcome !== 'confirmed') || report.unresolvedIntentIds.length) return report;
    let ceremony: Ceremony | undefined;
    if (this.input.scenario !== 'box-loss') {
      const row = j.read(db => db.prepare('SELECT * FROM recovery_ceremony WHERE challenge_id=? AND verified=1 AND used=1').get(input.ceremonyChallengeId ?? ''));
      if (!row || Number(row.expires_at) <= this.input.clock()) { report.limitations.push('independent-emergency-phone-ceremony-required'); return report; }
      try { ceremony = this.boundCeremony(String(row.binding)); }
      catch { report.limitations.push('emergency-ceremony-context-mismatch'); return report; }
    }
    // Expiry is checked after all asynchronous observations; old proofs never survive an observer delay.
    if (proofs.some(proof => proof.expiresAt <= this.input.clock())) { report.limitations.push('recovery-observations-expired'); return report; }
    this.casGuard = () => {
      if (proofs.some(proof => proof.expiresAt <= this.input.clock())) throw new Error('Recovery observations expired during CAS');
      if (ceremony) {
        const row = j.read(db => db.prepare('SELECT expires_at,verified FROM recovery_ceremony WHERE challenge_id=?').get(input.ceremonyChallengeId!));
        if (!row || row.verified !== 1 || Number(row.expires_at) <= this.input.clock()) throw new Error('Phone ceremony expired during CAS');
      }
    };
    const fence = proofs.find(proof => proof.requirement === 'predecessor-quiesced' || proof.requirement === 'management-authority-invalidated')!;
    try {
      await this.epoch.recover({ predecessor: fence.requirement === 'predecessor-quiesced' ? 'quiesced' : 'management-authority-invalidated', observedPredecessor: { ...this.predecessor }, evidenceHash: contentDigest(proofs), inFlightOutcomes: 'reconciled' });
      if (ceremony) {
        const c = ceremony;
        j.transaction(db => {
          j.assertCurrent(db);
          if (db.prepare('SELECT 1 FROM approver WHERE signer_id=?').get(c.replacement.signerId)) throw new Error('Replacement signer identity already exists');
          db.exec('UPDATE approver SET revoked=1; UPDATE approval_grant SET cancelled=1; UPDATE session_revocation SET revoked=1;');
          db.prepare('INSERT INTO approver VALUES(?,?,?,?,0)').run(c.replacement.signerId, 'routine', JSON.stringify(c.replacement.verification.publicKey), publicKeyFingerprint(c.replacement.verification.publicKey));
          db.prepare('UPDATE recovery_ceremony SET verified=0 WHERE challenge_id=?').run(input.ceremonyChallengeId!);
          j.audit(db, 'replacement-phone-operator-custody-attested', null, c.custody.evidenceHash);
        });
        report.limitations.push('operator-custody-attestation-not-independent-hardware-proof');
      }
      this.completed = true;
      report.recoveryHeld = false;
    } catch { j.setRecoveryHold(); report.limitations.push('epoch-or-ceremony-recovery-failed'); }
    return report;
  }
}
