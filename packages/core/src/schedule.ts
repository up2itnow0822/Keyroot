import { Journal } from './journal.js';

export interface ForecastInput {
  lineageId: string; policyAt: number; issuerExpiryAt?: number; reauthorizationAt?: number;
  intervalDays: number; mfaRequired: boolean; restartBudget: number; executionBudget: number;
}
export interface Forecast extends ForecastInput { promptAt: number; warnings: string[] }
function integer(value: number, min = 0): void {
  if (!Number.isSafeInteger(value) || value < min) throw new Error('Invalid forecast value');
}
export function forecast(input: ForecastInput): Forecast {
  if (!/^[-a-zA-Z0-9_.:@/]+$/.test(input.lineageId) || input.lineageId.length > 256 || typeof input.mfaRequired !== 'boolean') throw new Error('Invalid forecast metadata');
  integer(input.policyAt); integer(input.intervalDays, 1); integer(input.restartBudget); integer(input.executionBudget, 1);
  if (input.issuerExpiryAt !== undefined) integer(input.issuerExpiryAt);
  if (input.reauthorizationAt !== undefined) integer(input.reauthorizationAt);
  return { ...input, promptAt: Math.min(input.policyAt, input.issuerExpiryAt ?? Infinity, input.reauthorizationAt ?? Infinity), warnings: input.intervalDays > 90 ? ['interval-over-90-days'] : [] };
}
export function initializeScheduleSchema(journal: Journal): void {
    journal.transaction(db => {
      db.exec('CREATE TABLE IF NOT EXISTS schedule_schema (singleton INTEGER PRIMARY KEY CHECK(singleton=1), version INTEGER NOT NULL);');
      const row = db.prepare('SELECT version FROM schedule_schema WHERE singleton=1').get();
      if (!row) db.exec('CREATE TABLE schedule_forecast (lineage_id TEXT PRIMARY KEY, metadata TEXT NOT NULL); CREATE TABLE owner_interval (id TEXT PRIMARY KEY, case_id TEXT NOT NULL, kind TEXT NOT NULL, started_at INTEGER NOT NULL, ended_at INTEGER); CREATE TABLE schedule_outbox (id TEXT PRIMARY KEY, kind TEXT NOT NULL, subject TEXT NOT NULL, status TEXT NOT NULL); CREATE TABLE schedule_alarm (id INTEGER PRIMARY KEY AUTOINCREMENT, kind TEXT NOT NULL, subject TEXT NOT NULL, resolved INTEGER NOT NULL DEFAULT 0); CREATE TABLE schedule_quarantine (consumer_id TEXT NOT NULL, destination_id TEXT NOT NULL, grant_id TEXT NOT NULL, PRIMARY KEY(consumer_id,destination_id)); CREATE TABLE schedule_validity (lineage_id TEXT PRIMARY KEY, checked_at INTEGER NOT NULL, outcome TEXT NOT NULL, cadence_ms INTEGER NOT NULL); CREATE TABLE schedule_incident (grant_id TEXT PRIMARY KEY, digest TEXT NOT NULL, policy TEXT NOT NULL); CREATE TABLE metric_case (id TEXT PRIMARY KEY, affected TEXT NOT NULL, started_at INTEGER NOT NULL, contained_at INTEGER, restored_at INTEGER, coverage TEXT NOT NULL); INSERT INTO schedule_schema VALUES(1,1);');
      else if (row.version !== 1) throw new Error('Unsupported schedule schema');
    });
}
/** Forecast metadata is durable; it confers no approval or effect authority. */
export class ForecastStore {
  constructor(private readonly journal: Journal) { initializeScheduleSchema(journal); }
  save(input: ForecastInput): Forecast {
    const result = forecast(input);
    this.journal.transaction(db => { this.journal.assertCurrent(db); db.prepare('INSERT INTO schedule_forecast VALUES(?,?) ON CONFLICT(lineage_id) DO UPDATE SET metadata=excluded.metadata').run(result.lineageId, JSON.stringify(result)); });
    return result;
  }
  list(): Forecast[] { return this.journal.read(db => db.prepare('SELECT metadata FROM schedule_forecast ORDER BY lineage_id').all().map(row => JSON.parse(String(row.metadata)) as Forecast)); }
}

import { randomUUID } from 'node:crypto';
import { ApprovalService } from './approval.js';
import { LifecycleEngine, type LifecycleDrivers, type LifecycleSnapshot } from './engine.js';
import { parseCanonicalManifest, type ApprovalManifest } from './manifest.js';
import { MutationInterlock, NotificationFailure } from './notifier.js';

const wiredEngines = new WeakMap<LifecycleEngine, MutationInterlock>();
export function assertWiredEngine(engine: LifecycleEngine, interlock: MutationInterlock): void { if (wiredEngines.get(engine) !== interlock) throw new Error('Engine requires the installed notification effect fence'); }
/** Construct both ports together so every U3 effect and continuation uses the same fence. */
export function createScheduledEngine(journal: Journal, interlock: MutationInterlock, drivers: LifecycleDrivers, approvalOptions: ConstructorParameters<typeof ApprovalService>[1], engineOptions: ConstructorParameters<typeof LifecycleEngine>[3]): { approvals: ApprovalService; engine: LifecycleEngine } {
  if (interlock.journal !== journal) throw new Error('Interlock and engine journal must match');
  const previous = approvalOptions.checkEffectFence;
  const approvals = new ApprovalService(journal, { ...approvalOptions, checkEffectFence: async () => { await interlock.checkEffectFence(); await previous?.(); await interlock.checkEffectFence(); } });
  const engine = new LifecycleEngine(journal, approvals, drivers, engineOptions); wiredEngines.set(engine, interlock); return { approvals, engine };
}
export type Validity = 'confirmed-active' | 'confirmed-revoked' | 'unverified';
export class Scheduler {
  private running = false;
  constructor(private readonly engine: LifecycleEngine, private readonly interlock: MutationInterlock, private readonly options: { clock?: () => number; timeoutMs?: number }) {
    assertWiredEngine(engine, interlock); if (engine.approvals.journal !== engine.journal) throw new Error('Journal mismatch');
    if (options.timeoutMs !== undefined && (!Number.isSafeInteger(options.timeoutMs) || options.timeoutMs < 1 || options.timeoutMs > 120000)) throw new Error('Invalid timeout');
    initializeScheduleSchema(engine.journal);
  }
  private now(): number { const now = this.options.clock?.() ?? Date.now(); if (!Number.isSafeInteger(now) || now < 0) throw new Error('Invalid clock'); return now; }
  async validity(lineageId: string, cadenceMs: number, read: (signal: AbortSignal) => Promise<Validity>): Promise<Validity> {
    if (!/^[-a-zA-Z0-9_.:@/]{1,256}$/.test(lineageId)) throw new Error('Invalid lineage'); integer(cadenceMs, 1); const now = this.now();
    const previous = this.engine.journal.read(db => db.prepare('SELECT * FROM schedule_validity WHERE lineage_id=?').get(lineageId));
    if (previous && now < Number(previous.checked_at)) throw new Error('Clock moved backwards');
    if (previous && now - Number(previous.checked_at) < Number(previous.cadence_ms)) return String(previous.outcome) as Validity;
    const abort = new AbortController(); let timer: ReturnType<typeof setTimeout> | undefined; let result: Validity = 'unverified';
    try {
      const observed = await Promise.race([read(abort.signal), new Promise<Validity>(resolve => { timer = setTimeout(() => { abort.abort(); resolve('unverified'); }, this.options.timeoutMs ?? 30000); })]);
      if (observed === 'confirmed-active' || observed === 'confirmed-revoked') result = observed;
    } catch { result = 'unverified'; } finally { if (timer) clearTimeout(timer); }
    this.engine.journal.transaction(db => { this.engine.journal.assertCurrent(db); db.prepare('INSERT INTO schedule_validity VALUES(?,?,?,?) ON CONFLICT(lineage_id) DO UPDATE SET checked_at=excluded.checked_at,outcome=excluded.outcome,cadence_ms=excluded.cadence_ms').run(lineageId, this.now(), result, cadenceMs); });
    if (result === 'confirmed-revoked' && previous?.outcome !== 'confirmed-revoked') this.interlock.prepare(randomUUID(), 'unexpected-revocation-offer-replacement', lineageId);
    return result;
  }
  /** Processes only the immutable persisted manifest; expired/cancelled grants reconcile existing intents. */
  async tick(grantId: string): Promise<Array<{ operationId: string; snapshot?: LifecycleSnapshot; error?: string }>> {
    if (this.running) throw new Error('Scheduler tick already running'); this.running = true;
    try {
      const row = this.engine.journal.read(db => db.prepare('SELECT * FROM approval_grant WHERE grant_id=?').get(grantId));
      if (!row || row.role !== 'routine') throw new Error('Unknown routine grant');
      const manifest: ApprovalManifest = parseCanonicalManifest(String(row.raw_manifest));
      const active = !row.cancelled && row.boot_id === this.engine.journal.bootId && this.now() >= manifest.notBefore && this.now() < manifest.expiresAt;
      const output: Array<{ operationId: string; snapshot?: LifecycleSnapshot; error?: string }> = [];
      for (const op of manifest.operations) {
        if (!active) {
          if (this.engine.journal.listIntents(op.operationId).length) output.push({ operationId: op.operationId, snapshot: await this.engine.reconcile(op.operationId) });
          continue;
        }
        await this.interlock.checkEffectFence();
        try { output.push({ operationId: op.operationId, snapshot: await this.engine.run({ operationId: op.operationId, grantId, signature: String(row.signature) }) }); }
        catch (error) {
          if (error instanceof NotificationFailure) throw error;
          if (typeof error === 'object' && error !== null && 'code' in error && String(error.code).includes('SQLITE')) { this.interlock.journalFailed(op.operationId); throw error; }
          await this.interlock.checkEffectFence();
          // Known per-credential fencing and approval failures do not erase peers. Unknown storage failures stop the batch.
          const message = error instanceof Error ? error.message : '';
          if (!/predecessor|Lineage busy|Cancelled or unknown approval|outside validity|Current scope or policy changed|budget exhausted|reconcil/i.test(message)) throw error;
          output.push({ operationId: op.operationId, error: 'credential-held' });
        }
      }
      return output;
    } finally { this.running = false; }
  }
}
