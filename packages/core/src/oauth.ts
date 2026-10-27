import { createHash, randomUUID } from 'node:crypto';
import { ApprovalService, type AuthorizeEffectRequest } from './approval.js';
import { Journal, type AuthorizedIntent } from './journal.js';

export type OAuthOwner = 'keyroot-local' | 'production' | 'third-party';
/** OAuth objects have distinct lifetimes and revocation boundaries; only identifiers and expiry are represented. */
export type OAuthObject =
  | { kind: 'app-secret'; resourceId: string }
  | { kind: 'access-token'; resourceId: string; expiresAt: number }
  | { kind: 'refresh-family'; resourceId: string; owner: OAuthOwner; version: number }
  | { kind: 'grant'; resourceId: string }
  | { kind: 'native-session'; resourceId: string; client: 'claude-code' | 'codex' };
export interface OAuthFamily { grantId: string; familyId: string; ownerId: string; version: number; state: 'active' | 'refreshing' | 'reconcile-required' | 'revoking' | 'revoked' | 'consenting' | 'reconciling'; bootId: string; accessExpiresAt: number; pendingIntentId?: string; pendingOperationId?: string }
export interface OAuthExecutor {
  /** Resolve and update token values entirely inside this trusted boundary. */
  refresh(input: { grantId: string; familyId: string; ownerId: string; version: number; beforeStore: () => Promise<void> }): Promise<{ accessExpiresAt: number; evidenceHash: string }>;
  revoke(input: { grantId: string; familyId: string }): Promise<{ outcome: 'confirmed' | 'unknown'; evidenceHash: string }>;
  consent(input: { grantId: string; familyId: string; beforeStore: () => Promise<void> }): Promise<{ outcome: 'completed' | 'cancelled' | 'unknown'; evidenceHash: string }>;
  reconcile(input: { grantId: string; familyId: string; version: number; priorState: OAuthFamily['state'] }): Promise<{ state: 'active' | 'revoked'; version: number; issuerEvidenceHash: string; storeEvidenceHash: string; effect: 'applied' | 'not-applied' | 'unknown' } | 'unknown'>;
}
const id = (value: string) => { if (!/^[a-zA-Z0-9_.:@/-]{1,256}$/.test(value)) throw new Error('Invalid OAuth metadata identifier'); };
const validHash = (value: string) => /^sha256:[a-f0-9]{64}$/.test(value);
const number = (value: number) => { if (!Number.isSafeInteger(value) || value < 0) throw new Error('Invalid OAuth metadata number'); };
function row(record: Record<string, unknown>): OAuthFamily { return { grantId: String(record.grant_id), familyId: String(record.family_id), ownerId: String(record.owner_id), version: Number(record.version), state: record.state as OAuthFamily['state'], bootId: String(record.boot_id), accessExpiresAt: Number(record.access_expires_at), ...(record.pending_intent_id ? { pendingIntentId: String(record.pending_intent_id), pendingOperationId: String(record.pending_operation_id) } : {}) }; }

/** Trusted controller integration. Values never enter this API or its journal. */
export class OAuthCoordinator {
  constructor(readonly journal: Journal, readonly approval: ApprovalService, readonly executor: OAuthExecutor) {
    if (approval.journal !== journal) throw new Error('Approval and OAuth journal must match');
    journal.transaction(db => {
      journal.assertCurrent(db);
      db.exec('CREATE TABLE IF NOT EXISTS oauth_schema (singleton INTEGER PRIMARY KEY CHECK(singleton=1), version INTEGER NOT NULL);');
      const schema = db.prepare('SELECT version FROM oauth_schema WHERE singleton=1').get();
      if (!schema) {
        db.exec("CREATE TABLE oauth_family (grant_id TEXT PRIMARY KEY, family_id TEXT NOT NULL UNIQUE, owner_id TEXT NOT NULL, version INTEGER NOT NULL, state TEXT NOT NULL CHECK(state IN ('active','refreshing','reconcile-required','revoking','revoked','consenting','reconciling')), boot_id TEXT NOT NULL, access_expires_at INTEGER NOT NULL, pending_intent_id TEXT, pending_operation_id TEXT); INSERT INTO oauth_schema VALUES(1,2);");
      } else if (schema.version === 1) { db.exec("ALTER TABLE oauth_family ADD COLUMN pending_intent_id TEXT; ALTER TABLE oauth_family ADD COLUMN pending_operation_id TEXT; UPDATE oauth_family SET state='reconcile-required' WHERE state IN ('refreshing','revoking','consenting','reconciling'); UPDATE oauth_schema SET version=2 WHERE singleton=1;"); } else if (schema.version !== 2) throw new Error('Unsupported OAuth schema');
    });
  }
  registerLocal(input: { grantId: string; familyId: string; ownerId: string; version: number; accessExpiresAt: number }): void {
    id(input.grantId); id(input.familyId); id(input.ownerId); number(input.version); number(input.accessExpiresAt);
    this.journal.transaction(db => { this.journal.assertCurrent(db); db.prepare("INSERT INTO oauth_family VALUES(?,?,?,?,'active',?,?,NULL,NULL)").run(input.grantId, input.familyId, input.ownerId, input.version, this.journal.bootId, input.accessExpiresAt); });
  }
  inspect(grantId: string): OAuthFamily | undefined { id(grantId); return this.journal.read(db => { const found = db.prepare('SELECT * FROM oauth_family WHERE grant_id=?').get(grantId); return found ? row(found) : undefined; }); }
  private async authorize(request: AuthorizeEffectRequest, expected: { kind: 'admin' | 'revoke'; grantId: string; familyId: string; ownerId: string; version: number; reason: string }): Promise<AuthorizedIntent> {
    const intent = await this.approval.authorizeEffect(request);
    const p = intent.parameters;
    if (intent.kind !== expected.kind || p.resourceId !== expected.grantId || p.handleId !== expected.familyId || p.destinationId !== expected.ownerId || p.expectedRevision !== String(expected.version) || p.reasonCode !== expected.reason) throw new Error('OAuth action differs from signed scope');
    return intent;
  }
  private receipt(intent: AuthorizedIntent, outcome: 'confirmed' | 'unknown', now: number, sourceHash?: string, reconciliationOf?: string[], limitation = 'executor-metadata'): string {
    const operation = this.journal.inspectOperation(intent.operationId);
    if (!operation) throw new Error('OAuth operation missing');
    const p = intent.parameters;
    const hash = sourceHash && validHash(sourceHash) ? sourceHash : 'sha256:' + createHash('sha256').update(JSON.stringify({ intentId: intent.intentId, outcome, resourceId: p.resourceId, handleId: p.handleId, at: now })).digest('hex');
    const receiptId = randomUUID();
    this.journal.appendReceipt({ receiptId, intentId: intent.intentId, kind: reconciliationOf ? 'reconciliation' : intent.kind === 'revoke' ? 'issuer-revocation' : 'administration', outcome, generation: Number(p.generation ?? operation.toGeneration), observedAt: now, observerId: reconciliationOf ? 'oauth-observer' : 'oauth-executor', evidenceHash: hash, accountId: operation.accountId, ...(typeof p.resourceId === 'string' ? { resourceId: p.resourceId } : {}), ...(typeof p.handleId === 'string' ? { handleId: p.handleId } : {}), ...(typeof p.destinationId === 'string' ? { destinationId: p.destinationId } : {}), ...(typeof p.expectedRevision === 'string' ? { revision: p.expectedRevision } : {}), ...(reconciliationOf ? { reconcilesReceiptIds: reconciliationOf } : {}), limitationCodes: [limitation] });
    if (outcome === 'confirmed' && !reconciliationOf) this.journal.resolveIntent({ intentId: intent.intentId, receiptIds: [receiptId] });
    return receiptId;
  }
  private resolveObserved(intent: AuthorizedIntent, family: OAuthFamily, observation: { state: 'active' | 'revoked'; version: number; issuerEvidenceHash: string; storeEvidenceHash: string; effect: 'applied' | 'not-applied' | 'unknown' }): void {
    if (observation.effect !== 'applied' || (intent.kind === 'revoke' ? observation.state !== 'revoked' : observation.state !== 'active')) throw new Error('Original OAuth effect not confirmed');
    if (intent.state === 'observed') { if (this.journal.inspectOperation(intent.operationId)?.state === 'reconcile-required') this.journal.reconcileOperation(intent.operationId); return; }
    const hash = 'sha256:' + createHash('sha256').update(JSON.stringify({ grantId: family.grantId, familyId: family.familyId, ownerId: family.ownerId, version: observation.version, state: observation.state, issuer: observation.issuerEvidenceHash, store: observation.storeEvidenceHash })).digest('hex');
    const operation = this.journal.inspectOperation(intent.operationId);
    if (!operation) throw new Error('Original OAuth operation missing');
    const p = intent.parameters; const now = Date.now(); const confirmedId = randomUUID();
    const subject = { accountId: operation.accountId, generation: Number(p.generation ?? operation.toGeneration), ...(typeof p.resourceId === 'string' ? { resourceId: p.resourceId } : {}), ...(typeof p.handleId === 'string' ? { handleId: p.handleId } : {}), ...(typeof p.destinationId === 'string' ? { destinationId: p.destinationId } : {}), ...(typeof p.expectedRevision === 'string' ? { revision: p.expectedRevision } : {}) };
    this.journal.appendReceipt({ receiptId: confirmedId, intentId: intent.intentId, kind: intent.kind === 'revoke' ? 'issuer-revocation' : 'administration', outcome: 'confirmed', observedAt: now, observerId: 'oauth-observer', evidenceHash: hash, ...subject, limitationCodes: ['issuer-and-store-observation'] });
    const unknowns = this.journal.listReceipts(intent.operationId).filter(r => r.intentId === intent.intentId && r.outcome === 'unknown').map(r => r.receiptId);
    const marker = randomUUID();
    this.journal.appendReceipt({ receiptId: marker, intentId: intent.intentId, kind: 'reconciliation', outcome: 'confirmed', observedAt: now, observerId: 'oauth-observer', evidenceHash: hash, ...subject, reconcilesReceiptIds: unknowns, limitationCodes: ['issuer-and-store-observation'] });
    this.journal.resolveIntent({ intentId: intent.intentId, receiptIds: [confirmedId], reconciliationReceiptId: marker });
    if (this.journal.inspectOperation(intent.operationId)?.state === 'reconcile-required') this.journal.reconcileOperation(intent.operationId);
  }
  private begin(input: { grantId: string; familyId: string; ownerId: string; version: number }, allowed: OAuthFamily['state'], next: OAuthFamily['state'], requireBoot: boolean, intent?: AuthorizedIntent): OAuthFamily {
    return this.journal.transaction(db => {
      this.journal.assertCurrent(db);
      const found = db.prepare('SELECT * FROM oauth_family WHERE grant_id=?').get(input.grantId);
      if (!found) throw new Error('Unknown OAuth family');
      const f = row(found);
      if (f.familyId !== input.familyId || f.ownerId !== input.ownerId || f.version !== input.version || f.state !== allowed) throw new Error('OAuth owner, version or state mismatch');
      if (requireBoot && f.bootId !== this.journal.bootId) throw new Error('Restored OAuth family requires reconciliation or consent');
      const update = db.prepare('UPDATE oauth_family SET state=?, pending_intent_id=COALESCE(?,pending_intent_id), pending_operation_id=COALESCE(?,pending_operation_id) WHERE grant_id=? AND family_id=? AND owner_id=? AND version=? AND state=? AND boot_id=?').run(next, intent?.intentId ?? null, intent?.operationId ?? null, f.grantId, f.familyId, f.ownerId, f.version, f.state, f.bootId);
      if (Number(update.changes) !== 1) throw new Error('OAuth family fence moved');
      return f;
    });
  }
  private finish(input: OAuthFamily, pending: OAuthFamily['state'], next: OAuthFamily['state'], version: number, expires: number, bootId = input.bootId): void {
    this.journal.transaction(db => {
      this.journal.assertCurrent(db);
      const changed = db.prepare('UPDATE oauth_family SET state=?, version=?, access_expires_at=?, boot_id=?, pending_intent_id=CASE WHEN ? THEN NULL ELSE pending_intent_id END, pending_operation_id=CASE WHEN ? THEN NULL ELSE pending_operation_id END WHERE grant_id=? AND family_id=? AND owner_id=? AND version=? AND state=? AND boot_id=?').run(next, version, expires, bootId, next === 'active' || next === 'revoked' ? 1 : 0, next === 'active' || next === 'revoked' ? 1 : 0, input.grantId, input.familyId, input.ownerId, input.version, pending, input.bootId);
      if (Number(changed.changes) !== 1) throw new Error('OAuth family fence moved');
    });
  }
  async refresh(input: { owner: OAuthOwner; grantId: string; familyId: string; ownerId: string; version: number; request: AuthorizeEffectRequest }): Promise<'refreshed' | 'external' | 'unknown'> {
    if (input.owner !== 'keyroot-local') return 'external';
    const current = this.inspect(input.grantId);
    if (!current || current.familyId !== input.familyId || current.ownerId !== input.ownerId || current.version !== input.version || current.state !== 'active') throw new Error('OAuth owner, version or state mismatch');
    if (current.bootId !== this.journal.bootId) throw new Error('Restored OAuth family requires reconciliation or consent');
    const intent = await this.authorize(input.request, { ...input, kind: 'admin', reason: 'oauth-refresh' });
    const family = this.begin(input, 'active', 'refreshing', true, intent);
    if (family.version === Number.MAX_SAFE_INTEGER) { this.finish(family, 'refreshing', 'reconcile-required', family.version, family.accessExpiresAt); throw new Error('OAuth family version exhausted'); }
    let expires: number; let evidenceHash: string; let guarded = false;
    const beforeStore = async () => { await this.approval.assertReservedIntentAuthority({ ...input.request, intentId: intent.intentId }); guarded = true; };
    try { const result = await this.executor.refresh({ grantId: family.grantId, familyId: family.familyId, ownerId: family.ownerId, version: family.version, beforeStore }); expires = result.accessExpiresAt; evidenceHash = result.evidenceHash; number(expires); if (!guarded || !validHash(evidenceHash)) throw new Error('Refresh continuation evidence missing'); }
    catch { this.receipt(intent, 'unknown', Date.now()); this.finish(family, 'refreshing', 'reconcile-required', family.version, family.accessExpiresAt); return 'unknown'; }
    this.receipt(intent, 'confirmed', Date.now(), evidenceHash);
    this.finish(family, 'refreshing', 'active', family.version + 1, expires);
    return 'refreshed';
  }
  async revoke(input: { owner: OAuthOwner; grantId: string; familyId: string; ownerId: string; version: number; request: AuthorizeEffectRequest }): Promise<{ outcome: 'confirmed' | 'unknown' | 'external'; accessExpiresAt?: number }> {
    if (input.owner !== 'keyroot-local') return { outcome: 'external' };
    const intent = await this.authorize(input.request, { ...input, kind: 'revoke', reason: 'oauth-revoke' });
    const current = this.inspect(input.grantId);
    if (!current || current.state !== 'active') throw new Error('Grant cannot be revoked from this state');
    const family = this.begin(input, current.state, 'revoking', false, intent);
    let result: 'confirmed' | 'unknown'; let evidenceHash: string | undefined;
    try { const observed = await this.executor.revoke({ grantId: family.grantId, familyId: family.familyId }); result = observed.outcome; evidenceHash = observed.evidenceHash; if (result !== 'confirmed' || !validHash(evidenceHash)) result = 'unknown'; } catch { result = 'unknown'; }
    this.receipt(intent, result, Date.now(), evidenceHash);
    this.finish(family, 'revoking', result === 'confirmed' ? 'revoked' : 'reconcile-required', family.version, family.accessExpiresAt);
    return { outcome: result, accessExpiresAt: family.accessExpiresAt };
  }
  async consent(input: { grantId: string; familyId: string; ownerId: string; version: number; request: AuthorizeEffectRequest }): Promise<'completed' | 'cancelled' | 'unknown'> {
    const current = this.inspect(input.grantId);
    if (!current || current.familyId !== input.familyId || current.ownerId !== input.ownerId || current.version !== input.version || current.state !== 'revoked' || current.pendingIntentId) throw new Error('Confirmed revocation required before consent');
    const intent = await this.authorize(input.request, { ...input, kind: 'admin', reason: 'oauth-consent' });
    const family = this.begin(input, 'revoked', 'consenting', false, intent);
    if (family.version === Number.MAX_SAFE_INTEGER) { this.finish(family, 'consenting', 'revoked', family.version, family.accessExpiresAt); throw new Error('OAuth family version exhausted'); }
    let result: 'completed' | 'cancelled' | 'unknown'; let evidenceHash: string | undefined; let guarded = false;
    const beforeStore = async () => { await this.approval.assertReservedIntentAuthority({ ...input.request, intentId: intent.intentId }); guarded = true; };
    try { const observed = await this.executor.consent({ grantId: family.grantId, familyId: family.familyId, beforeStore }); result = observed.outcome; evidenceHash = observed.evidenceHash; if (!['completed', 'cancelled'].includes(result) || !validHash(evidenceHash) || (result === 'completed' && !guarded)) result = 'unknown'; } catch { result = 'unknown'; }
    this.receipt(intent, result === 'unknown' ? 'unknown' : 'confirmed', Date.now(), evidenceHash, undefined, result === 'cancelled' ? 'consent-cancelled' : 'executor-metadata');
    this.finish(family, 'consenting', result === 'completed' ? 'active' : result === 'cancelled' ? 'revoked' : 'reconcile-required', result === 'completed' ? family.version + 1 : family.version, family.accessExpiresAt, result === 'completed' ? this.journal.bootId : family.bootId);
    return result;
  }
  async reconcile(input: { grantId: string; familyId: string; ownerId: string; version: number }): Promise<'confirmed' | 'unknown'> {
    const current = this.inspect(input.grantId);
    if (!current) throw new Error('Unknown OAuth family');
    if (current.state !== 'reconcile-required' && !(current.bootId !== this.journal.bootId && ['active', 'refreshing', 'revoking', 'consenting', 'reconciling'].includes(current.state))) throw new Error('Reconciliation not required');
    if (current.state !== 'active' && !current.pendingIntentId) throw new Error('Legacy family lacks original intent; manual U3 recovery required');
    const family = this.begin(input, current.state, 'reconciling', false);
    let result: { state: 'active' | 'revoked'; version: number; issuerEvidenceHash: string; storeEvidenceHash: string; effect: 'applied' | 'not-applied' | 'unknown' } | 'unknown';
    try {
      result = await this.executor.reconcile({ grantId: family.grantId, familyId: family.familyId, version: family.version, priorState: current.state });
      if (result !== 'unknown') { number(result.version); if (!['active', 'revoked'].includes(result.state) || result.version < family.version || !validHash(result.issuerEvidenceHash) || !validHash(result.storeEvidenceHash)) result = 'unknown'; }
    } catch { result = 'unknown'; }
    if (result !== 'unknown' && family.pendingIntentId && family.pendingOperationId) {
      const intent = this.journal.listIntents(family.pendingOperationId).find(item => item.intentId === family.pendingIntentId);
      if (!intent) throw new Error('Original OAuth intent missing');
      try { this.resolveObserved(intent, family, result); } catch { this.finish(family, 'reconciling', 'reconcile-required', family.version, family.accessExpiresAt); return 'unknown'; }
    }
    this.finish(family, 'reconciling', result === 'unknown' ? 'reconcile-required' : result.state, result === 'unknown' ? family.version : result.version, family.accessExpiresAt, result === 'unknown' ? family.bootId : this.journal.bootId);
    return result === 'unknown' ? 'unknown' : 'confirmed';
  }
}
