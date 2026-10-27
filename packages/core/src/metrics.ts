import { Journal } from './journal.js';
import { initializeScheduleSchema } from './schedule.js';

export type OwnerAction = 'mfa' | 'guided' | 'troubleshooting' | 'review' | 'approval' | 'other';
const kinds: OwnerAction[] = ['mfa', 'guided', 'troubleshooting', 'review', 'approval', 'other'];
function metadataId(value: string): void { if (!/^[-a-zA-Z0-9_.:@/]+$/.test(value) || value.length > 256) throw new Error('Invalid metadata identifier'); }
interface Interval { id: string; case_id: string; kind: OwnerAction; started_at: number; ended_at: number | null }
function union(intervals: Array<[number, number]>): number {
  intervals.sort((a, b) => a[0] - b[0]); let sum = 0; let start = 0; let end = 0; let first = true;
  for (const [a, b] of intervals) { if (first) { start = a; end = b; first = false; } else if (a <= end) end = Math.max(end, b); else { sum += end - start; start = a; end = b; } }
  return first ? 0 : sum + end - start;
}
/** Clock and calls belong to the authenticated controller, never client-supplied timestamps. */
export class OwnerMetrics {
  constructor(private readonly journal: Journal, private readonly clock: () => number = Date.now) {
    initializeScheduleSchema(journal);
  }
  private now(): number { const n = this.clock(); if (!Number.isSafeInteger(n) || n < 0) throw new Error('Invalid trusted clock'); return n; }
  begin(id: string, caseId: string, kind: OwnerAction): void {
    metadataId(id); metadataId(caseId); if (!kinds.includes(kind)) throw new Error('Invalid owner action'); const now = this.now();
    this.journal.transaction(db => { this.journal.assertCurrent(db); const last = db.prepare('SELECT MAX(COALESCE(ended_at,started_at)) AS at FROM owner_interval WHERE case_id=?').get(caseId); if (last?.at !== null && last?.at !== undefined && now < Number(last.at)) throw new Error('Clock moved backwards'); db.prepare('INSERT INTO owner_interval VALUES(?,?,?,?,NULL)').run(id, caseId, kind, now); });
  }
  end(id: string): void {
    metadataId(id); const now = this.now();
    this.journal.transaction(db => { this.journal.assertCurrent(db); const row = db.prepare('SELECT * FROM owner_interval WHERE id=?').get(id) as unknown as Interval | undefined; if (!row || row.ended_at !== null || now < row.started_at) throw new Error('Unknown, ended, or invalid interval'); const last = db.prepare('SELECT MAX(COALESCE(ended_at,started_at)) AS at FROM owner_interval WHERE case_id=?').get(row.case_id); if (now < Number(last?.at ?? 0)) throw new Error('Clock moved backwards'); db.prepare('UPDATE owner_interval SET ended_at=? WHERE id=?').run(now, id); });
  }
  createCase(caseId: string, affected: string[], coverageLimitations: string[]): void {
    metadataId(caseId); if (!affected.length || new Set(affected).size !== affected.length) throw new Error('Finite unique affected set required');
    affected.forEach(metadataId); coverageLimitations.forEach(metadataId); const now = this.now();
    this.journal.transaction(db => { this.journal.assertCurrent(db); db.prepare('INSERT INTO metric_case VALUES(?,?,?,NULL,NULL,?)').run(caseId, JSON.stringify([...affected].sort()), now, JSON.stringify([...new Set(coverageLimitations)].sort())); });
  }
  mark(caseId: string, milestone: 'contained' | 'restored'): void {
    metadataId(caseId); if (milestone !== 'contained' && milestone !== 'restored') throw new Error('Invalid milestone'); const now = this.now();
    this.journal.transaction(db => {
      this.journal.assertCurrent(db); const row = db.prepare('SELECT * FROM metric_case WHERE id=?').get(caseId);
      if (!row || now < Number(row.started_at) || (row.contained_at !== null && now < Number(row.contained_at)) || (row.restored_at !== null && now < Number(row.restored_at))) throw new Error('Invalid milestone time');
      const column = milestone === 'contained' ? 'contained_at' : 'restored_at'; if (row[column] !== null) throw new Error('Milestone replay');
      db.prepare(`UPDATE metric_case SET ${column}=? WHERE id=?`).run(now, caseId);
    });
  }
  compare(caseId: string, baselineId: string, maintenanceId: string): { activeMs: number; baselineActiveMs: number; maintenanceActiveMs: number; elapsedContainmentMs: number | null; elapsedRestorationMs: number | null; unattendedWaitMs: number | null; coverageLimitations: string[] } {
    const cases = [caseId, baselineId, maintenanceId].map(id => { metadataId(id); return this.journal.read(db => db.prepare('SELECT * FROM metric_case WHERE id=?').get(id)); });
    if (cases.some(row => !row)) throw new Error('Unknown comparison case');
    if (cases.some(row => row!.affected !== cases[0]!.affected)) throw new Error('Comparison requires same affected set');
    const row = cases[0]!; const report = this.report(caseId); const base = this.report(baselineId); const maintenance = this.report(maintenanceId);
    const elapsedContainmentMs = row.contained_at === null ? null : Number(row.contained_at) - Number(row.started_at);
    const elapsedRestorationMs = row.restored_at === null ? null : Number(row.restored_at) - Number(row.started_at);
    const clipped = elapsedRestorationMs === null ? [] : this.journal.read(db => db.prepare('SELECT started_at,ended_at FROM owner_interval WHERE case_id=? AND ended_at IS NOT NULL').all(caseId)).map(r => [Math.max(Number(row.started_at), Number(r.started_at)), Math.min(Number(row.restored_at), Number(r.ended_at))] as [number, number]).filter(([a,b]) => b > a);
    const limitations = new Set(cases.flatMap(item => JSON.parse(String(item!.coverage)) as string[]));
    if (report.openIntervals || base.openIntervals || maintenance.openIntervals) limitations.add('open-owner-intervals');
    if (elapsedContainmentMs === null) limitations.add('containment-unmeasured');
    if (elapsedRestorationMs === null) limitations.add('restoration-unmeasured');
    return { activeMs: report.activeMs, baselineActiveMs: base.activeMs, maintenanceActiveMs: maintenance.activeMs, elapsedContainmentMs, elapsedRestorationMs, unattendedWaitMs: elapsedRestorationMs === null ? null : elapsedRestorationMs - union(clipped), coverageLimitations: [...limitations].sort() };
  }
  report(caseId: string): { activeMs: number; byKind: Record<OwnerAction, number>; openIntervals: number } {
    metadataId(caseId); const rows = this.journal.read(db => db.prepare('SELECT * FROM owner_interval WHERE case_id=? ORDER BY started_at,id').all(caseId)) as unknown as Interval[];
    const completed = rows.filter((r): r is Interval & { ended_at: number } => r.ended_at !== null);
    const byKind = Object.fromEntries(kinds.map(kind => [kind, union(completed.filter(r => r.kind === kind).map(r => [r.started_at, r.ended_at]))])) as Record<OwnerAction, number>;
    return { activeMs: union(completed.map(r => [r.started_at, r.ended_at])), byKind, openIntervals: rows.length - completed.length };
  }
}
