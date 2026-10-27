import { randomUUID } from 'node:crypto';
import { Journal } from './journal.js';
import { LifecycleEngine, type LifecycleSnapshot } from './engine.js';
import { parseCanonicalManifest, type ApprovalManifest } from './manifest.js';
import { assertWiredEngine, initializeScheduleSchema } from './schedule.js';
import { MutationInterlock, NotificationFailure } from './notifier.js';
export interface Destination { consumerId: string; destinationId: string }
export class QuarantineStore {
  constructor(private readonly journal: Journal) { initializeScheduleSchema(journal); }
  async check(consumerId: string, destinationId: string): Promise<'clear' | 'quarantined' | 'unknown'> {
    try { return this.journal.read(db => db.prepare('SELECT 1 FROM schedule_quarantine WHERE consumer_id=? AND destination_id=?').get(consumerId, destinationId)) ? 'quarantined' : 'clear'; }
    catch { return 'unknown'; }
  }
}
export interface IncidentReport { operationId: string; containment: LifecycleSnapshot['issuer']; residualTokenValidity: LifecycleSnapshot['probe']; replacement: LifecycleSnapshot['replacement']; serviceRestoration: 'not-started' | 'unverified' | 'direct-use-observed'; ownerAction: string[] }
/** Uses the verifier's persisted proof/reservations and the engine, not caller verification flags. */
export class IncidentCoordinator {
  constructor(private readonly engine: LifecycleEngine, private readonly interlock: MutationInterlock, private readonly clock: () => number = Date.now) { assertWiredEngine(engine, interlock); initializeScheduleSchema(engine.journal); }
  prepare(grantId: string, proofId: string, destinations: readonly Destination[]): { manifest: ApprovalManifest; policy: 'continuity-first' | 'revoke-first' } {
    return this.engine.journal.transaction(db => {
      this.engine.journal.assertCurrent(db); const now = this.clock();
      if (!Number.isSafeInteger(now) || now < 0) throw new Error('Invalid trusted clock');
      const grant = db.prepare("SELECT * FROM approval_grant WHERE grant_id=? AND role='emergency' AND cancelled=0").get(grantId);
      if (!grant || grant.boot_id !== this.engine.journal.bootId) throw new Error('Emergency grant missing');
      const manifest = parseCanonicalManifest(String(grant.raw_manifest));
      if (now < manifest.notBefore || now >= manifest.expiresAt) throw new Error('Emergency grant expired');
      const proof = db.prepare('SELECT * FROM emergency_proof WHERE proof_id=? AND grant_id=? AND digest=? AND used=0 AND expires_at>?').get(proofId, grantId, String(grant.digest), now);
      if (!proof) throw new Error('Fresh verified emergency assertion required');
      if (new Set(manifest.operations.map(op => op.lineageId)).size !== manifest.operations.length) throw new Error('One operation per affected lineage required');
      if (manifest.operations.some(op => !db.prepare('SELECT 1 FROM emergency_reservation WHERE grant_id=? AND lineage_id=?').get(grantId, op.lineageId))) throw new Error('Complete verified reservation required');
      const sequences = manifest.operations.map(op => {
        const revoke = op.actions.findIndex(a => a.kind === 'revoke'); const create = op.actions.findIndex(a => a.kind === 'create');
        if (revoke < 0) throw new Error('Every incident lineage needs signed old-generation revoke');
        if (op.actions.some(a => a.kind === 'create' && a.parameters.generation !== op.toGeneration)) throw new Error('Leaked generation reuse');
        if (create >= 0 && revoke < create && (revoke !== 0 || !manifest.outage.permitted || op.actions[revoke]!.parameters.reasonCode !== 'incident-revoke-first')) throw new Error('Revoke-first requires signed outage and explicit reason');
        return create < 0 || revoke < create ? 'revoke-first' : 'continuity-first';
      });
      if (new Set(sequences).size !== 1) throw new Error('Incident policy must cover the complete signed set');
      const policy = sequences[0];
      if (policy === undefined) throw new Error('Incident affected set is empty');
      for (const destination of destinations) {
        const bound = manifest.consumerMap.entries.some(e => e.consumerId === destination.consumerId && e.resourceId === destination.destinationId) || manifest.operations.some(op => op.actions.some(a => a.kind === 'deliver' && a.parameters.consumerId === destination.consumerId && a.parameters.destinationId === destination.destinationId));
        if (!bound) throw new Error('Quarantine outside signed scope');
        db.prepare('INSERT INTO schedule_quarantine VALUES(?,?,?) ON CONFLICT(consumer_id,destination_id) DO UPDATE SET grant_id=excluded.grant_id').run(destination.consumerId, destination.destinationId, grantId);
      }
      db.prepare('INSERT INTO schedule_incident VALUES(?,?,?) ON CONFLICT(grant_id) DO UPDATE SET digest=excluded.digest,policy=excluded.policy').run(grantId, String(grant.digest), policy);
      this.engine.journal.audit(db, 'incident-quarantine', null, grantId);
      return { manifest, policy };
    });
  }
  async execute(grantId: string, proofs: Readonly<Record<string, Readonly<Record<string, string>>>>): Promise<IncidentReport[]> {
    const row = this.engine.journal.read(db => db.prepare("SELECT * FROM approval_grant WHERE grant_id=? AND role='emergency' AND cancelled=0").get(grantId));
    if (!row) throw new Error('Emergency grant missing');
    const prepared = this.engine.journal.read(db => db.prepare('SELECT 1 FROM schedule_incident WHERE grant_id=? AND digest=?').get(grantId, String(row.digest)));
    if (!prepared) throw new Error('Incident must be prepared under verified assertion');
    const manifest = parseCanonicalManifest(String(row.raw_manifest));
    const reserved = this.engine.journal.read(db => manifest.operations.every(op => !!db.prepare('SELECT 1 FROM emergency_reservation WHERE grant_id=? AND lineage_id=?').get(grantId, op.lineageId)));
    if (!reserved) throw new Error('Complete verified reservation required');
    const result: IncidentReport[] = [];
    for (const op of manifest.operations) {
      await this.interlock.checkEffectFence();
      try {
        const emergencyProofs = proofs[op.operationId];
        const snapshot = await this.engine.run({ grantId, operationId: op.operationId, ...(emergencyProofs ? { emergencyProofs } : {}) });
        const used = manifest.consumerMap.entries.length > 0 && manifest.consumerMap.entries.every(entry => {
          const delivered = snapshot.receipts.filter(r => r.kind === 'deliver' && r.outcome === 'delivery-accepted' && r.subject.consumerId === entry.consumerId && r.subject.revision === entry.revision && r.subject.consumerMapRevision === manifest.consumerMap.revision && r.subject.generation === op.toGeneration).at(-1);
          return !!delivered && snapshot.receipts.some(r => r.kind === 'consumer-use' && r.outcome === 'direct-use' && r.subject.consumerId === entry.consumerId && r.subject.revision === entry.revision && r.subject.consumerMapRevision === manifest.consumerMap.revision && r.subject.generation === op.toGeneration && r.subject.resourceId === delivered.subject.resourceId && r.observedAt >= delivered.observedAt);
        });
        result.push({ operationId: op.operationId, containment: snapshot.issuer, residualTokenValidity: snapshot.probe, replacement: snapshot.replacement, serviceRestoration: used ? 'direct-use-observed' : snapshot.replacement === 'not-created' ? 'not-started' : 'unverified', ownerAction: snapshot.holds });
        this.interlock.prepare(randomUUID(), 'incident-action-recorded', op.operationId);
      } catch (error) {
        if (error instanceof NotificationFailure) throw error;
          if (typeof error === 'object' && error !== null && 'code' in error && String(error.code).includes('SQLITE')) { this.interlock.journalFailed(op.operationId); throw error; }
        await this.interlock.checkEffectFence();
        if (!(error instanceof Error) || !/predecessor|Lineage busy|Cancelled or unknown approval|outside validity|Current scope or policy changed|budget exhausted|reconcil/i.test(error.message)) throw error;
        const prior = this.engine.journal.inspectOperation(op.operationId) ? this.engine.inspect(op.operationId) : undefined;
        result.push({ operationId: op.operationId, containment: prior?.issuer ?? 'unverified', residualTokenValidity: prior?.probe ?? 'unknown', replacement: prior?.replacement ?? 'not-created', serviceRestoration: prior?.replacement === 'stored' ? 'unverified' : 'not-started', ownerAction: ['credential-held', ...(prior?.holds ?? [])] });
      }
    }
    return result;
  }
}
