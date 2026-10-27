import { randomUUID } from 'node:crypto';
import { ApprovalService, type AuthorizeEffectRequest } from './approval.js';
import { Journal, type AuthorizedIntent, type MetadataReceipt } from './journal.js';
import { applicableConsumers, canonicalJSON, deepFreeze, parseCanonicalManifest, snapshotDigest, type ApprovalManifest, type ManifestAction, type ManifestOperation } from './manifest.js';
import { deadlineDisposition, type DeadlineDisposition } from './deadline.js';
import { assertReceiptSubject, safeReceipt, type LifecycleReceipt, type LifecycleReceiptKind, type ReceiptSubject } from './receipts.js';
import { resolveCreatedReference } from './reconciliation.js';

export interface EffectContext { readonly subject: Readonly<ReceiptSubject>; readonly signal: AbortSignal }
export interface CompoundCreateContext extends EffectContext {
  readonly storeTarget: Readonly<{ destinationId: string; handleId: string; expectedVersion: number }>;
  /** Trusted driver calls once, immediately before the exact prebound store CAS. No secret returns to the engine. */
  beforeStore(): Promise<AuthorizedIntent>;
}
export interface LifecycleDrivers {
  create(intent: AuthorizedIntent, context: CompoundCreateContext): Promise<LifecycleReceipt>;
  validate(intent: AuthorizedIntent, context: EffectContext): Promise<LifecycleReceipt>;
  deliver(intent: AuthorizedIntent, context: EffectContext): Promise<LifecycleReceipt>;
  revoke(intent: AuthorizedIntent, context: EffectContext): Promise<LifecycleReceipt>;
  cleanup?(intent: AuthorizedIntent, context: EffectContext): Promise<LifecycleReceipt>;
  /** Read-only issuer AND store/consumer queries by stable intent reference; never retry an effect here. */
  reconcile(intent: AuthorizedIntent, context: EffectContext): Promise<LifecycleReceipt>;
  observeConsumer(subject: Readonly<ReceiptSubject>, signal?: AbortSignal): Promise<LifecycleReceipt>;
  observeOldUse(subject: Readonly<ReceiptSubject>, signal?: AbortSignal): Promise<LifecycleReceipt>;
  observeIssuer(subject: Readonly<ReceiptSubject>, signal?: AbortSignal): Promise<LifecycleReceipt>;
  probeOld(subject: Readonly<ReceiptSubject>, signal?: AbortSignal): Promise<LifecycleReceipt>;
}
export interface LifecycleRequest { operationId: string; grantId: string; signature?: string; emergencyProofs?: Readonly<Record<string, string>> }
export interface LifecycleSnapshot {
  operationId: string;
  state: 'active' | 'held' | 'reconcile-required' | 'completed';
  replacement: 'not-created' | 'unknown' | 'stored' | 'rejected' | 'created-unrecoverable' | 'orphan-unresolved';
  issuer: 'issuer-acknowledged' | 'confirmed-revoked' | 'confirmed-active' | 'unverified';
  probe: 'accepted' | 'rejected' | 'confounded' | 'unknown';
  deadline: DeadlineDisposition;
  holds: string[];
  receipts: LifecycleReceipt[];
}
interface EngineRow { operation_id: string; holds: string; deadline: DeadlineDisposition }
const effectKinds: readonly string[] = ['create', 'validate', 'deliver', 'revoke', 'cleanup'];
const successful: Partial<Record<LifecycleReceiptKind, readonly string[]>> = { create: ['stored'], validate: ['validated'], deliver: ['delivery-accepted'], revoke: ['issuer-acknowledged', 'confirmed-revoked', 'confirmed-active', 'unverified'], cleanup: ['issuer-acknowledged', 'confirmed-revoked', 'confirmed-active', 'unverified'] };
const isUncertain = (r: LifecycleReceipt) => r.outcome === 'unknown' || r.outcome === 'orphan-unresolved' || (r.kind === 'revoke' || r.kind === 'cleanup') && r.outcome === 'unverified';
const dispatching = new Set<string>();

/** Trusted controller integration. Constructor ports, clocks and snapshots must never come from owner JSON. */
export class LifecycleEngine {
  constructor(readonly journal: Journal, readonly approvals: ApprovalService, private readonly drivers: LifecycleDrivers, private readonly trusted: {
    currentSnapshot: () => ApprovalManifest | Promise<ApprovalManifest>;
    clock?: () => number;
    maxEvidenceAgeMs?: number;
    timeoutMs?: number;
  }) {
    if (approvals.journal !== journal) throw new Error('Approval and engine journal must match');
    if (trusted.maxEvidenceAgeMs !== undefined && (!Number.isSafeInteger(trusted.maxEvidenceAgeMs) || trusted.maxEvidenceAgeMs < 1)) throw new Error('Invalid evidence age');
    if (trusted.timeoutMs !== undefined && (!Number.isSafeInteger(trusted.timeoutMs) || trusted.timeoutMs < 1 || trusted.timeoutMs > 120_000)) throw new Error('Invalid driver timeout');
    journal.transaction(db => {
      db.exec('CREATE TABLE IF NOT EXISTS engine_schema (singleton INTEGER PRIMARY KEY CHECK(singleton=1), version INTEGER NOT NULL);');
      const version = db.prepare('SELECT version FROM engine_schema WHERE singleton=1').get();
      if (!version) {
        db.exec(`CREATE TABLE engine_receipt (receipt_id TEXT PRIMARY KEY, operation_id TEXT NOT NULL REFERENCES operation(operation_id), intent_id TEXT REFERENCES intent(intent_id), metadata TEXT NOT NULL);
CREATE TABLE engine_operation (operation_id TEXT PRIMARY KEY REFERENCES operation(operation_id), holds TEXT NOT NULL, deadline TEXT NOT NULL);
INSERT INTO engine_schema VALUES(1,1);`);
      } else if (version.version !== 1) throw new Error('Unsupported engine schema');
    });
  }
  private now() { return this.trusted.clock?.() ?? Date.now(); }
  /** Timeout bounds controller work; abort is advisory and cannot undo an upstream effect. */
  private async bounded<T>(execute: (signal: AbortSignal) => Promise<T>): Promise<T> {
    const controller = new AbortController(); let timer: ReturnType<typeof setTimeout> | undefined;
    try {
      return await Promise.race([
        execute(controller.signal),
        new Promise<never>((_resolve, reject) => { timer = setTimeout(() => { controller.abort(); reject(new Error('Driver observation timed out')); }, this.trusted.timeoutMs ?? 30_000); })
      ]);
    } finally { if (timer !== undefined) clearTimeout(timer); }
  }
  private grant(grantId: string): ApprovalManifest {
    const raw = this.journal.read(db => db.prepare('SELECT raw_manifest FROM approval_grant WHERE grant_id=?').get(grantId));
    if (!raw) throw new Error('Unknown signed grant');
    return parseCanonicalManifest(String(raw.raw_manifest));
  }
  private operation(manifest: ApprovalManifest, id: string): ManifestOperation {
    const op = manifest.operations.find(o => o.operationId === id);
    if (!op) throw new Error('Operation outside signed grant');
    return op;
  }
  private operationManifest(id: string): ApprovalManifest {
    const row = this.journal.read(db => db.prepare('SELECT g.raw_manifest FROM approval_grant g JOIN intent i ON i.grant_id=g.grant_id WHERE i.operation_id=? ORDER BY i.rowid DESC LIMIT 1').get(id));
    if (!row) throw new Error('Unknown lifecycle operation');
    return parseCanonicalManifest(String(row.raw_manifest));
  }
  private receipts(id: string): LifecycleReceipt[] {
    return this.journal.read(db => db.prepare('SELECT metadata FROM engine_receipt WHERE operation_id=? ORDER BY rowid').all(id).map(r => safeReceipt(JSON.parse(String(r.metadata)) as LifecycleReceipt)));
  }
  private receiptsFor(intent: AuthorizedIntent): LifecycleReceipt[] {
    return this.journal.read(db => db.prepare('SELECT metadata FROM engine_receipt WHERE intent_id=? ORDER BY rowid').all(intent.intentId).map(r => safeReceipt(JSON.parse(String(r.metadata)) as LifecycleReceipt)));
  }
  private subject(op: ManifestOperation, action: ManifestAction, manifest: ApprovalManifest): ReceiptSubject {
    const generation = Number(action.parameters.generation);
    let reference = action.parameters.resourceId;
    if (!reference && (action.kind === 'deliver' || action.kind === 'validate')) reference = `created:${op.operationId}`;
    if (!reference) throw new Error('Missing bound resource');
    const subject: ReceiptSubject = { operationId: op.operationId, lineageId: op.lineageId, accountId: op.accountId, generation, resourceId: resolveCreatedReference(reference, op, this.receipts(op.operationId)), handleId: String(action.parameters.handleId), consumerMapRevision: manifest.consumerMap.revision };
    if (action.parameters.consumerId) {
      const entry = applicableConsumers(manifest, op).find(e => e.consumerId === action.parameters.consumerId);
      if (!entry || action.parameters.expectedRevision !== entry.revision || action.kind === 'deliver' && entry.lineageId !== undefined && action.parameters.destinationId !== entry.resourceId) throw new Error('Delivery outside exact consumer mapping');
      subject.consumerId = entry.consumerId; subject.revision = entry.revision;
    }
    return deepFreeze(subject);
  }
  private expectedKind(intent: AuthorizedIntent): LifecycleReceiptKind {
    if (!effectKinds.includes(intent.kind)) throw new Error('Unsupported lifecycle effect');
    return intent.kind as LifecycleReceiptKind;
  }
  private expectedStoreVersion(parameters: AuthorizedIntent['parameters']): number {
    const revision = parameters.expectedRevision ?? '0';
    if (typeof revision !== 'string' || !/^(0|[1-9][0-9]*)$/.test(revision) || !Number.isSafeInteger(Number(revision)) || Number(revision) >= Number.MAX_SAFE_INTEGER) throw new Error('Create requires an exact store CAS revision');
    return Number(revision);
  }
  private acceptEffect(intent: AuthorizedIntent, receipt: LifecycleReceipt, expected: ReceiptSubject, destinationId?: string): void {
    if (receipt.kind !== this.expectedKind(intent)) throw new Error('Receipt effect mismatch');
    assertReceiptSubject(receipt, expected, { createdResource: intent.kind === 'create', ...(destinationId !== undefined ? { destinationId } : {}) });
    if (receipt.observedAt > this.now()) throw new Error('Future effect observation');
    if (intent.kind === 'create' && receipt.outcome === 'stored' && receipt.subject.resourceId.startsWith('created:')) throw new Error('Unresolved issuer identity');
    if (intent.kind === 'create' && receipt.outcome === 'stored' && receipt.storeBinding!.version !== this.expectedStoreVersion(intent.parameters) + 1) throw new Error('Creation store CAS version mismatch');
    this.persist(receipt, intent);
  }
  private persist(receipt: LifecycleReceipt, intent?: AuthorizedIntent): void {
    const r = safeReceipt(receipt); const raw = canonicalJSON(r);
    this.journal.transaction(db => {
      const prior = db.prepare('SELECT operation_id,intent_id,metadata FROM engine_receipt WHERE receipt_id=?').get(r.receiptId);
      if (prior) {
        if (prior.metadata !== raw || prior.operation_id !== r.subject.operationId || prior.intent_id !== (intent?.intentId ?? null)) throw new Error('Receipt callback conflicting replay');
        return;
      }
      db.prepare('INSERT INTO engine_receipt VALUES(?,?,?,?)').run(r.receiptId, r.subject.operationId, intent?.intentId ?? null, raw);
      if (!intent) return;
      const kind: MetadataReceipt['kind'] = r.kind === 'create' ? 'creation' : r.kind === 'validate' ? 'validation' : r.kind === 'deliver' ? 'delivery-accepted' : 'issuer-revocation';
      // A known orphan is a resolved failed stage, never a confirmed successor in generic receipt queries.
      const outcome: MetadataReceipt['outcome'] = isUncertain(r) || r.outcome === 'created-unrecoverable' ? 'unknown' : ['rejected', 'failed'].includes(r.outcome) ? 'rejected' : 'confirmed';
      const metadata: MetadataReceipt = { receiptId: r.receiptId, intentId: intent.intentId, kind, outcome, accountId: r.subject.accountId, generation: r.subject.generation, observedAt: r.observedAt, observerId: r.observerId, evidenceHash: r.evidenceHash, resourceId: r.subject.resourceId, handleId: r.subject.handleId, limitationCodes: [...r.limitationCodes, ...(r.outcome === 'created-unrecoverable' ? ['created-unrecoverable'] : [])], ...(r.subject.consumerId ? { consumerId: r.subject.consumerId } : {}), ...(r.subject.revision ? { revision: r.subject.revision } : {}), ...(intent.kind === 'create' ? { parentResourceId: String(intent.parameters.resourceId) } : {}), ...(intent.parameters.destinationId ? { destinationId: String(intent.parameters.destinationId) } : {}), ...(r.storeBinding ? { storeVersion: r.storeBinding.version } : {}) };
      const priorUnknowns = db.prepare('SELECT metadata FROM receipt WHERE intent_id=? ORDER BY rowid').all(intent.intentId).map(row => JSON.parse(String(row.metadata)) as MetadataReceipt).filter(item => item.outcome === 'unknown').map(item => item.receiptId);
      db.prepare('INSERT INTO receipt VALUES(?,?,?)').run(metadata.receiptId, intent.intentId, canonicalJSON(metadata));
      if (r.kind === 'create' && r.outcome === 'stored') {
        const stored: MetadataReceipt = { ...metadata, receiptId: r.receiptId + '.storage', kind: 'storage', revision: String(r.storeBinding!.version) };
        db.prepare('INSERT INTO receipt VALUES(?,?,?)').run(stored.receiptId, intent.intentId, canonicalJSON(stored));
      }
      if (!isUncertain(r) && r.outcome !== 'created-unrecoverable' && priorUnknowns.length) {
        const reconciled: MetadataReceipt = { ...metadata, receiptId: r.receiptId + '.reconciled', kind: 'reconciliation', reconcilesReceiptIds: priorUnknowns };
        db.prepare('INSERT INTO receipt VALUES(?,?,?)').run(reconciled.receiptId, intent.intentId, canonicalJSON(reconciled));
      }
      // A compound stage resolves only after the exact issuer/store binding passes acceptEffect.
      db.prepare('UPDATE intent SET state=? WHERE intent_id=?').run(isUncertain(r) ? 'unknown' : 'observed', intent.intentId);
      this.journal.audit(db, 'lifecycle-evidence', intent.operationId, r.receiptId);
    });
  }
  private unknown(subject: ReceiptSubject, kind: LifecycleReceiptKind): LifecycleReceipt {
    return { receiptId: randomUUID(), subject: { ...subject }, kind, outcome: 'unknown', observedAt: this.now(), observerId: 'keyroot-engine', evidenceHash: 'sha256:observer-unavailable', limitationCodes: ['observer-unavailable'] };
  }
  private status(id: string, holds: string[], deadline: DeadlineDisposition): LifecycleSnapshot {
    this.journal.transaction(db => db.prepare('INSERT INTO engine_operation VALUES(?,?,?) ON CONFLICT(operation_id) DO UPDATE SET holds=excluded.holds,deadline=excluded.deadline').run(id, canonicalJSON(holds), deadline));
    return this.inspect(id);
  }
  inspect(id: string): LifecycleSnapshot {
    const operation = this.journal.inspectOperation(id);
    if (!operation) throw new Error('Unknown lifecycle operation');
    const receipts = this.receipts(id);
    const row = this.journal.read(db => db.prepare('SELECT * FROM engine_operation WHERE operation_id=?').get(id)) as EngineRow | undefined;
    const holds: string[] = row ? JSON.parse(row.holds) as string[] : [];
    const creation = receipts.filter(r => r.kind === 'create').at(-1);
    const replacement = creation ? (creation.outcome === 'stored' || creation.outcome === 'rejected' || creation.outcome === 'created-unrecoverable' || creation.outcome === 'orphan-unresolved' ? creation.outcome : 'unknown') : 'not-created';
    const issuerReceipt = receipts.filter(r => r.kind === 'issuer' || r.kind === 'revoke').at(-1);
    const issuer = issuerReceipt && ['issuer-acknowledged', 'confirmed-revoked', 'confirmed-active'].includes(issuerReceipt.outcome) ? issuerReceipt.outcome as LifecycleSnapshot['issuer'] : 'unverified';
    const probeReceipt = receipts.filter(r => r.kind === 'probe').at(-1);
    const probe = probeReceipt ? probeReceipt.outcome as LifecycleSnapshot['probe'] : 'unknown';
    const uncertain = this.journal.listIntents(id).some(i => i.state !== 'observed');
    const state = operation.state === 'completed' ? 'completed' : uncertain ? 'reconcile-required' : holds.length ? 'held' : 'active';
    return deepFreeze({ operationId: id, state, replacement, issuer, probe, deadline: row?.deadline ?? 'within-window', holds, receipts });
  }
  /** Read-only external reconciliation is allowed after authority expiry or boot invalidation. */
  async reconcile(id: string): Promise<LifecycleSnapshot> {
    const op = this.journal.inspectOperation(id);
    if (op && dispatching.has(`${this.journal.installationId}/${this.journal.bootId}/${op.lineageId}`)) throw new Error('Lineage dispatch still in flight');
    return this.reconcilePending(id);
  }
  private async reconcilePending(id: string): Promise<LifecycleSnapshot> {
    const manifest = this.operationManifest(id); const op = this.operation(manifest, id);
    for (const intent of this.journal.listIntents(id).filter(i => i.state !== 'observed')) {
      const action = this.operation(this.grant(intent.grantId), id).actions.find(a => a.id === intent.actionId)!;
      const subject = this.subject(op, action, manifest);
      let receipt: LifecycleReceipt;
      try { receipt = await this.bounded(signal => this.drivers.reconcile(intent, { subject, signal })); this.acceptEffect(intent, receipt, subject, action.parameters.destinationId); }
      catch { receipt = this.unknown(subject, this.expectedKind(intent)); this.persist(receipt, intent); }
    }
    if (this.journal.listIntents(id).every(i => i.state === 'observed') && this.journal.inspectOperation(id)?.state === 'reconcile-required') this.journal.reconcileOperation(id);
    const created = this.receipts(id).filter(r => r.kind === 'create').at(-1);
    return this.status(id, created?.outcome === 'created-unrecoverable' ? ['created-unrecoverable-cleanup-needs-fresh-authority'] : created?.outcome === 'orphan-unresolved' ? ['orphan-unresolved'] : [], deadlineDisposition(manifest, this.now()));
  }
  private async authority(input: LifecycleRequest, actionId: string): Promise<AuthorizeEffectRequest> {
    const current = await this.trusted.currentSnapshot();
    return { grantId: input.grantId, operationId: input.operationId, actionId, currentSnapshotDigest: snapshotDigest(current), now: this.now(), ...(input.signature ? { signature: input.signature } : {}), ...(input.emergencyProofs?.[actionId] ? { emergencyProofId: input.emergencyProofs[actionId] } : {}) };
  }
  private replacementValidated(id: string, op: ManifestOperation): boolean {
    const receipts = this.receipts(id);
    let resource: string;
    try { resource = resolveCreatedReference(`created:${id}`, op, receipts); } catch { return false; }
    return receipts.some(r => r.kind === 'validate' && r.outcome === 'validated' && r.subject.resourceId === resource && r.subject.generation === op.toGeneration);
  }
  private oldAction(op: ManifestOperation): ManifestAction {
    const action = op.actions.find(a => a.kind === 'revoke' && a.parameters.generation === op.fromGeneration);
    if (!action) throw new Error('Named old-generation revoke required');
    return action;
  }
  private consumerSubject(op: ManifestOperation, manifest: ApprovalManifest, consumerId: string): ReceiptSubject {
    const entry = applicableConsumers(manifest, op).find(e => e.consumerId === consumerId);
    const created = this.receipts(op.operationId).find(r => r.kind === 'create' && r.outcome === 'stored');
    if (!entry || !created) throw new Error('Consumer replacement binding missing');
    return deepFreeze({ ...created.subject, consumerMapRevision: manifest.consumerMap.revision, consumerId, revision: entry.revision });
  }
  /** Authenticated executor callbacks only; imported owner flags are not observation evidence. */
  recordObservation(id: string, receipt: LifecycleReceipt): void {
    const manifest = this.operationManifest(id); const op = this.operation(manifest, id);
    if (!['consumer-use', 'old-use', 'issuer', 'probe'].includes(receipt.kind)) throw new Error('Not a read-only observation');
    const expected = receipt.kind === 'consumer-use' ? this.consumerSubject(op, manifest, receipt.subject.consumerId ?? '') : this.subject(op, this.oldAction(op), manifest);
    assertReceiptSubject(receipt, expected);
    if (receipt.observedAt > this.now()) throw new Error('Future observation');
    this.persist(receipt);
  }
  private async observe(id: string, subject: ReceiptSubject, kind: LifecycleReceiptKind, observer: (subject: Readonly<ReceiptSubject>, signal: AbortSignal) => Promise<LifecycleReceipt>): Promise<void> {
    try {
      const receipt = await this.bounded(signal => observer(subject, signal));
      if (receipt.kind !== kind) throw new Error('Observation kind mismatch');
      assertReceiptSubject(receipt, subject);
      if (receipt.observedAt > this.now()) throw new Error('Future observation');
      this.persist(receipt);
    } catch { this.persist(this.unknown(subject, kind)); }
    void id;
  }
  private fresh(receipt: LifecycleReceipt | undefined): receipt is LifecycleReceipt { return !!receipt && receipt.observedAt <= this.now() && this.now() - receipt.observedAt <= (this.trusted.maxEvidenceAgeMs ?? 300_000); }
  private async revokeHolds(op: ManifestOperation, manifest: ApprovalManifest, hard: boolean): Promise<string[]> {
    const id = op.operationId;
    if (hard) return [];
    for (const entry of applicableConsumers(manifest, op)) await this.observe(id, this.consumerSubject(op, manifest, entry.consumerId), 'consumer-use', (subject, signal) => this.drivers.observeConsumer(subject, signal));
    const old = this.subject(op, this.oldAction(op), manifest);
    await this.observe(id, old, 'old-use', (subject, signal) => this.drivers.observeOldUse(subject, signal));
    const receipts = this.receipts(id); const holds: string[] = [];
    if (!this.replacementValidated(id, op)) holds.push('replacement-not-validated');
    for (const entry of applicableConsumers(manifest, op)) {
      const delivery = receipts.filter(r => r.kind === 'deliver' && r.subject.consumerId === entry.consumerId && r.subject.revision === entry.revision && r.subject.consumerMapRevision === manifest.consumerMap.revision && r.subject.generation === op.toGeneration && r.outcome === 'delivery-accepted').at(-1);
      if (!delivery) holds.push(`delivery-unverified:${entry.consumerId}`);
      const use = receipts.filter(r => r.kind === 'consumer-use' && r.subject.consumerId === entry.consumerId && r.subject.revision === entry.revision && r.subject.consumerMapRevision === manifest.consumerMap.revision && r.subject.generation === op.toGeneration).at(-1);
      const accepted = use?.outcome === 'direct-use' || manifest.adoptionThreshold === 'informed-override' && use?.outcome === 'inferred-use';
      if (!this.fresh(use) || !delivery || use.observedAt < delivery.observedAt || !accepted) holds.push(`consumer-use-unverified:${entry.consumerId}`);
    }
    const oldUse = receipts.filter(r => r.kind === 'old-use').at(-1);
    if (receipts.some(r => r.kind === 'old-use' && r.outcome === 'positive-use')) holds.push('positive-old-generation-use');
    if (!this.fresh(oldUse) || oldUse.outcome !== 'none-observed') holds.push('old-generation-use-unverified');
    return holds;
  }
  private async finish(op: ManifestOperation, manifest: ApprovalManifest, deadline: DeadlineDisposition): Promise<LifecycleSnapshot> {
    const old = this.subject(op, this.oldAction(op), manifest);
    await this.observe(op.operationId, old, 'issuer', (s, signal) => this.drivers.observeIssuer(s, signal));
    await this.observe(op.operationId, old, 'probe', (s, signal) => this.drivers.probeOld(s, signal));
    const state = this.inspect(op.operationId); const holds: string[] = [];
    const revoked = state.receipts.filter(r => r.kind === 'revoke').at(-1);
    const issuer = state.receipts.filter(r => r.kind === 'issuer').at(-1);
    const probe = state.receipts.filter(r => r.kind === 'probe').at(-1);
    if (state.issuer !== 'confirmed-revoked' || !this.fresh(issuer) || !revoked || issuer.observedAt < revoked.observedAt) holds.push(`issuer-${state.issuer === 'confirmed-revoked' ? 'stale-evidence' : state.issuer}`);
    if (state.probe !== 'rejected' || !this.fresh(probe) || !revoked || probe.observedAt < revoked.observedAt) holds.push(state.probe === 'accepted' ? 'old-key-accepted' : `old-probe-${state.probe === 'rejected' ? 'stale-evidence' : state.probe}`);
    if (this.journal.listIntents(op.operationId).some(i => i.state !== 'observed')) holds.push('residual-pending-effect');
    if (!holds.length) this.journal.completeOperation(op.operationId);
    return this.status(op.operationId, holds, deadline);
  }
  async run(input: LifecycleRequest): Promise<LifecycleSnapshot> {
    const manifest = this.grant(input.grantId); const op = this.operation(manifest, input.operationId);
    const key = `${this.journal.installationId}/${this.journal.bootId}/${op.lineageId}`;
    if (dispatching.has(key)) throw new Error('Lineage busy with live predecessor dispatch');
    dispatching.add(key);
    try { return await this.execute(input, manifest, op); } finally { dispatching.delete(key); }
  }
  private async execute(input: LifecycleRequest, manifest: ApprovalManifest, op: ManifestOperation): Promise<LifecycleSnapshot> {
    const before = this.journal.inspectOperation(op.operationId);
    if (before && (before.lineageId !== op.lineageId || before.accountId !== op.accountId || before.fromGeneration !== op.fromGeneration || before.toGeneration !== op.toGeneration)) throw new Error('Stable operation identity mismatch');
    if (before?.state === 'completed') return this.inspect(op.operationId);
    const emergencyContainment = manifest.role === 'emergency' && op.actions.every(a => a.kind === 'revoke' && a.parameters.generation === op.fromGeneration && !a.parameters.resourceId?.startsWith('created:'));
    const first = op.actions[0];
    const revokeFirst = manifest.role === 'emergency' && manifest.outage.permitted && first?.kind === 'revoke' && first.parameters.reasonCode === 'incident-revoke-first' && first.parameters.generation === op.fromGeneration && !!first.parameters.resourceId && !first.parameters.resourceId.startsWith('created:');
    const pendingContainment = revokeFirst && !this.journal.listIntents(op.operationId).some(i => i.actionId === first.id);
    if (!emergencyContainment && !pendingContainment && this.journal.listIntents(op.operationId).some(i => i.state !== 'observed')) {
      const state = await this.reconcilePending(op.operationId);
      if (state.state === 'reconcile-required' || state.holds.length) return state;
    }
    let deadline = deadlineDisposition(manifest, this.now());
    for (const action of op.actions) {
      if (!effectKinds.includes(action.kind)) throw new Error('Unsupported lifecycle effect');
      const prior = this.journal.listIntents(op.operationId).find(i => i.actionId === action.id);
      if (prior) {
        if (prior.kind !== action.kind || canonicalJSON(prior.parameters) !== canonicalJSON(action.parameters)) throw new Error('Consumed action identity changed');
        const receipt = this.receiptsFor(prior).at(-1);
        if (!receipt || !successful[receipt.kind]?.includes(receipt.outcome)) return this.status(op.operationId, [receipt?.outcome === 'created-unrecoverable' ? 'created-unrecoverable-cleanup-needs-fresh-authority' : `${action.kind}-${receipt?.outcome ?? 'unknown'}`], deadline);
        continue;
      }
      if (action.kind === 'create' && (action.budgetCost.effects < 2 || action.budgetCost.newCredentials < 1)) throw new Error('Compound create/store requires two effects and one new credential');
      if (action.kind === 'create' && this.journal.listIntents(op.operationId).some(i => i.kind === 'create')) throw new Error('Creation already attempted for stable operation; reconcile it');
      if (action.kind === 'create') this.expectedStoreVersion(action.parameters as AuthorizedIntent['parameters']);
      if (revokeFirst && ['create', 'validate', 'deliver'].includes(action.kind)) {
        const old = this.subject(op, first, manifest);
        await this.observe(op.operationId, old, 'issuer', (s, signal) => this.drivers.observeIssuer(s, signal));
        await this.observe(op.operationId, old, 'probe', (s, signal) => this.drivers.probeOld(s, signal));
        const state = this.inspect(op.operationId);
        const revoked = state.receipts.filter(r => r.kind === 'revoke').at(-1);
        const issuer = state.receipts.filter(r => r.kind === 'issuer').at(-1);
        const probe = state.receipts.filter(r => r.kind === 'probe').at(-1);
        if (!revoked || state.issuer !== 'confirmed-revoked' || state.probe !== 'rejected' || !this.fresh(issuer) || !this.fresh(probe) || issuer.observedAt < revoked.observedAt || probe.observedAt < revoked.observedAt) return this.status(op.operationId, ['revoke-first-containment-unverified'], deadline);
      }
      if (['validate', 'deliver'].includes(action.kind) && this.receipts(op.operationId).every(r => r.kind !== 'create' || r.outcome !== 'stored')) throw new Error('Replacement not stored');
      if (action.kind === 'deliver' && !this.replacementValidated(op.operationId, op)) return this.status(op.operationId, ['replacement-not-validated'], deadline);
      if (action.kind === 'revoke') {
        deadline = deadlineDisposition(manifest, this.now());
        if (action.parameters.generation !== op.fromGeneration || action.parameters.resourceId?.startsWith('created:')) throw new Error('Ordinary revoke must name old generation');
        const holds = emergencyContainment || revokeFirst && action.id === first.id ? [] : await this.revokeHolds(op, manifest, deadline === 'hard-outage');
        if (holds.length) return this.status(op.operationId, [...holds, ...(deadline === 'overdue-exposure' ? ['overdue-exposure'] : [])], deadline);
      }
      if (action.kind === 'cleanup') {
        if (!this.drivers.cleanup || !this.receipts(op.operationId).some(r => r.kind === 'create' && r.outcome === 'created-unrecoverable' && r.subject.resourceId === action.parameters.resourceId && r.subject.generation === action.parameters.generation && r.subject.handleId === action.parameters.handleId)) throw new Error('Fresh, exact orphan cleanup authority required');
        if (this.journal.listIntents(op.operationId).some(i => i.kind === 'create' && i.grantId === input.grantId)) throw new Error('Orphan cleanup needs a separate fresh grant');
      }
      const subject = this.subject(op, action, manifest);
      const intent = await this.approvals.authorizeEffect(await this.authority(input, action.id));
      let receipt: LifecycleReceipt;
      try {
        receipt = await this.bounded(async signal => {
        const context: EffectContext = Object.freeze({ subject, signal });
        let result: LifecycleReceipt;
        if (action.kind === 'create') {
          let storeChecked = false;
          result = await this.drivers.create(intent, Object.freeze({ subject, signal, storeTarget: Object.freeze({ destinationId: String(intent.parameters.destinationId), handleId: String(intent.parameters.handleId), expectedVersion: this.expectedStoreVersion(intent.parameters) }), beforeStore: async () => {
            if (signal.aborted) throw new Error('Compound continuation timed out');
            if (storeChecked) throw new Error('Compound store already dispatched');
            storeChecked = true;
            const current = await this.approvals.assertCurrentAuthority({ ...await this.authority(input, action.id), intentId: intent.intentId });
            if (signal.aborted) throw new Error('Compound continuation timed out');
            return current;
          } }));
          if (result.outcome === 'stored' && !storeChecked) throw new Error('Compound store authority was not rechecked');
        } else if (action.kind === 'validate') result = await this.drivers.validate(intent, context);
        else if (action.kind === 'deliver') result = await this.drivers.deliver(intent, context);
        else if (action.kind === 'cleanup') result = await this.drivers.cleanup!(intent, context);
        else result = await this.drivers.revoke(intent, context);
        return result;
        });
        this.acceptEffect(intent, receipt, subject, action.parameters.destinationId);
      } catch { receipt = this.unknown(subject, this.expectedKind(intent)); this.persist(receipt, intent); }
      if (isUncertain(receipt)) return this.status(op.operationId, [`${action.kind}-outcome-unknown`], deadline);
      if (!successful[receipt.kind]?.includes(receipt.outcome)) return this.status(op.operationId, [receipt.outcome === 'created-unrecoverable' ? 'created-unrecoverable-cleanup-needs-fresh-authority' : `${action.kind}-${receipt.outcome}`], deadline);
    }
    if (op.actions.some(a => a.kind === 'revoke')) return this.finish(op, manifest, deadline);
    return this.status(op.operationId, ['old-generation-not-proven-terminal'], deadline);
  }
}
