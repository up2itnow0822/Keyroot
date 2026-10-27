import { canonicalJSON } from '../manifest.js';
import { forecast } from '../schedule.js';

export const scheduleRecoveryTables = {
  schedule_schema: ['singleton', 'version'],
  schedule_forecast: ['lineage_id', 'metadata'],
  schedule_outbox: ['id', 'kind', 'subject', 'status'],
  schedule_alarm: ['id', 'kind', 'subject', 'resolved'],
  schedule_quarantine: ['consumer_id', 'destination_id', 'grant_id'],
  schedule_validity: ['lineage_id', 'checked_at', 'outcome', 'cadence_ms'],
  schedule_incident: ['grant_id', 'digest', 'policy'],
  owner_interval: ['id', 'case_id', 'kind', 'started_at', 'ended_at'],
  metric_case: ['id', 'affected', 'started_at', 'contained_at', 'restored_at', 'coverage'],
  guided_draft: ['procedure_id', 'recipe_hash', 'account_id', 'destination_id', 'step_index', 'completed'],
} as const;
export type ScheduleRecoveryTable = keyof typeof scheduleRecoveryTables;
const identifier = (v: unknown) => { if (typeof v !== 'string' || !/^[-A-Za-z0-9_.:@/]{1,256}$/.test(v) || v.split('/').includes('..')) throw new Error('Invalid scheduling metadata identifier'); };
const integer = (v: unknown, min = 0) => { if (typeof v !== 'number' || !Number.isSafeInteger(v) || v < min) throw new Error('Invalid scheduling metadata integer'); };
const choice = (v: unknown, choices: readonly unknown[]) => { if (!choices.includes(v)) throw new Error('Invalid scheduling metadata choice'); };
const list = (v: unknown) => { if (!Array.isArray(v) || v.length > 1000 || new Set(v).size !== v.length) throw new Error('Invalid scheduling metadata list'); v.forEach(identifier); };
const hash = (v: unknown) => { if (typeof v !== 'string' || !/^sha256:[a-f0-9]{64}$/.test(v)) throw new Error('Invalid scheduling metadata hash'); };
function interval(row: Record<string, unknown>, end: string) { integer(row.started_at); if (row[end] !== null) { integer(row[end]); if (Number(row[end]) < Number(row.started_at)) throw new Error('Invalid scheduling interval'); } }
/** Existing owner workflows define these fields; their flags never reconstitute approval authority. */
export function validateScheduleRecoveryRow(table: ScheduleRecoveryTable, row: Record<string, unknown>): void {
  const columns: readonly string[] = scheduleRecoveryTables[table];
  if (Object.keys(row).sort().join('|') !== [...columns].sort().join('|')) throw new Error('Unknown scheduling metadata column');
  if (table === 'schedule_schema') { choice(row.singleton, [1]); choice(row.version, [1]); }
  else if (table === 'schedule_forecast') {
    identifier(row.lineage_id);
    const parsed: unknown = JSON.parse(String(row.metadata));
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) throw new Error('Invalid archived forecast');
    const metadata = parsed as Parameters<typeof forecast>[0] & { promptAt: number; warnings: string[] };
    const { promptAt, warnings, ...input } = metadata;
    const allowed = ['lineageId', 'policyAt', 'issuerExpiryAt', 'reauthorizationAt', 'intervalDays', 'mfaRequired', 'restartBudget', 'executionBudget'];
    if (Object.keys(input).some(key => !allowed.includes(key)) || metadata.lineageId !== row.lineage_id || canonicalJSON({ ...input, promptAt, warnings }) !== canonicalJSON(forecast(input))) throw new Error('Archived forecast semantics invalid');
  } else if (table === 'schedule_outbox') {
    identifier(row.id); identifier(row.kind); identifier(row.subject); choice(row.status, ['prepared', 'delivered', 'acknowledged']);
  } else if (table === 'schedule_alarm') {
    integer(row.id, 1); identifier(row.kind); identifier(row.subject); choice(row.resolved, [0, 1]);
  } else if (table === 'schedule_quarantine') { identifier(row.consumer_id); identifier(row.destination_id); identifier(row.grant_id); }
  else if (table === 'schedule_validity') {
    identifier(row.lineage_id); integer(row.checked_at); integer(row.cadence_ms, 1); choice(row.outcome, ['confirmed-active', 'confirmed-revoked', 'unverified']);
  } else if (table === 'schedule_incident') {
    identifier(row.grant_id); hash(row.digest); choice(row.policy, ['continuity-first', 'revoke-first']);
  } else if (table === 'owner_interval') {
    identifier(row.id); identifier(row.case_id); choice(row.kind, ['mfa', 'guided', 'troubleshooting', 'review', 'approval', 'other']); interval(row, 'ended_at');
  } else if (table === 'metric_case') {
    identifier(row.id); list(JSON.parse(String(row.affected))); if (!(JSON.parse(String(row.affected)) as unknown[]).length) throw new Error('Empty affected set');
    list(JSON.parse(String(row.coverage))); interval(row, 'contained_at'); interval(row, 'restored_at');
    if (row.contained_at !== null && row.restored_at !== null && Number(row.restored_at) < Number(row.contained_at)) throw new Error('Restoration predates containment');
  } else if (table === 'guided_draft') {
    for (const field of ['procedure_id', 'account_id', 'destination_id']) identifier(row[field]);
    hash(row.recipe_hash); integer(row.step_index); if (Number(row.step_index) > 32) throw new Error('Guided draft exceeds recipe bounds'); choice(row.completed, [0, 1]);
  }
}
