export class ApiError extends Error {
  constructor(public readonly status: number, public readonly code: string) { super(code); }
}
type Obj = Record<string, unknown>;
function object(value: unknown): Obj { if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('Invalid controller response'); return value as Obj; }
function string(value: unknown): string { if (typeof value !== 'string') throw new Error('Invalid controller response'); return value; }
function array(value: unknown): unknown[] { if (!Array.isArray(value)) throw new Error('Invalid controller response'); return value; }
function number(value: unknown): number { if (typeof value !== 'number' || !Number.isFinite(value)) throw new Error('Invalid controller response'); return value; }
export interface Lineage { id: string; issuerId: string; accountId: string; credentialType: string; grantType: string; grantId?: string }
export interface Overview {
  mode: 'demo' | 'real'; approvers: Array<{ signerId: string; role: 'routine' | 'emergency'; fingerprint: string }>; revision: number; lineages: Lineage[]; consumers: Array<{ id: string; name: string; kind: string }>;
  bindings: Array<{ id: string; lineageId: string; consumerId: string; generationId?: string; destinationId?: string; consumerRevision?: string; association: { kind: string; source: string; observedAt: string } }>;
  gaps: Array<{ kind: string; source: string; detail?: string }>; native: Array<{ client: string; storage: string; remoteSignOut: string; sessionTelemetry: string }>;
  batches: Batch[]; operations: Array<{ operationId: string; state: string; lineageId: string }>;
  coverage: Record<string, string>; liveAdmission: string; policies: Array<{ id: string; policy: unknown }>; outboxCount: number; alarmCount: number;
}
export interface Batch { batchId: string; digest: string; configurationHashes: string[]; summary: { lineages: string[]; effects: number; expiresAt: number; mode: string; role: 'routine' | 'emergency' }; progress: Array<{ operationId: string; state: string; actions: Array<{ actionId: string; kind: string; state: string }>; nextActionId: string | null; outcome: { issuer: string; probe: string; replacement: string; deadline: string; holds: string[] } | null }> }
export function parseBatch(value: unknown): Batch {
  const b = object(value), s = object(b.summary), manifest = object(JSON.parse(string(b.rawManifest)) as unknown);
  if (manifest.role !== 'routine' && manifest.role !== 'emergency') throw new Error('Invalid batch role');
  return { batchId: string(b.batchId), digest: string(b.digest), configurationHashes: array(b.configurationHashes).map(string), summary: { lineages: array(s.lineages).map(string), effects: number(s.effects), expiresAt: number(s.expiresAt), mode: string(s.mode), role: manifest.role }, progress: array(b.progress).map(v => { const p = object(v); const o = p.outcome === null ? null : object(p.outcome); return { operationId: string(p.operationId), state: string(p.state), actions: array(p.actions).map(v => { const a = object(v); return { actionId: string(a.actionId), kind: string(a.kind), state: string(a.state) }; }), nextActionId: p.nextActionId === null ? null : string(p.nextActionId), outcome: o ? { issuer: string(o.issuer), probe: string(o.probe), replacement: string(o.replacement), deadline: string(o.deadline), holds: array(o.holds).map(string) } : null }; }) };
}
export function parseOverview(value: unknown): Overview {
  const o = object(value), i = object(o.inventory), m = object(i.consumerMap), c = object(o.coverage);
  if (o.mode !== 'demo' && o.mode !== 'real') throw new Error('Invalid controller mode');
  return { mode: o.mode, approvers: array(o.approvers).map(v => { const a = object(v); if (a.role !== 'routine' && a.role !== 'emergency') throw new Error('Invalid approver role'); return { signerId: string(a.signerId), role: a.role, fingerprint: string(a.fingerprint) }; }), revision: number(m.revision), lineages: array(i.lineages).map(v => { const l = object(v); return { id: string(l.id), issuerId: string(l.issuerId), accountId: string(l.accountId), credentialType: string(l.credentialType), grantType: string(l.grantType), ...(l.grantId === undefined ? {} : { grantId: string(l.grantId) }) }; }), consumers: array(i.consumers).map(v => { const x = object(v); return { id: string(x.id), name: string(x.name), kind: string(x.kind) }; }), bindings: array(m.bindings).map(v => { const b = object(v), a = object(b.association); return { id: string(b.id), lineageId: string(b.lineageId), consumerId: string(b.consumerId), ...(b.generationId === undefined ? {} : { generationId: string(b.generationId) }), ...(b.destinationId === undefined ? {} : { destinationId: string(b.destinationId) }), ...(b.consumerRevision === undefined ? {} : { consumerRevision: string(b.consumerRevision) }), association: { kind: string(a.kind), source: string(a.source), observedAt: string(a.observedAt) } }; }), gaps: array(m.gaps).map(v => { const g = object(v); return { kind: string(g.kind), source: string(g.source), ...(g.detail === undefined ? {} : { detail: string(g.detail) }) }; }), native: array(i.native).map(v => { const n = object(v); return { client: string(n.client), storage: string(n.storage), remoteSignOut: string(n.remoteSignOut), sessionTelemetry: string(n.sessionTelemetry) }; }), batches: array(o.batches).map(parseBatch), operations: array(o.operations).map(v => { const p = object(v); return { operationId: string(p.operation_id), state: string(p.state), lineageId: string(p.lineage_id) }; }), coverage: Object.fromEntries(Object.entries(c).map(([k,v]) => [k, string(v)])), liveAdmission: string(o.liveAdmission), policies: array(o.policies).map(v => { const p = object(v); return { id: string(p.id), policy: p.policy }; }), outboxCount: array(o.outbox).length, alarmCount: array(o.alarms).length };
}
export type Purpose = 'cancel' | 'retire' | 'key-policy' | 'approver-removal' | 'oauth-consent' | 'oauth-reconcile' | 'native-sign-out' | 'env-dry-run' | 'env-rollback' | 'platform-discovery' | 'guided-completion' | 'quarantine' | 'emergency-enrollment' | 'inventory-update';
export interface Prepare { signerId: string; lineageIds: string[]; role?: 'routine' | 'emergency'; purpose?: Purpose; targetId?: string; policy?: { rotationDays: number }; incident?: { policy: 'continuity-first' | 'revoke-first'; quarantineDestinations: Array<{ consumerId: string; destinationId: string }>; outage: { permitted: boolean; consequence: 'none' | 'declared-interruption' } }; inventory?: { lineages: Overview['lineages']; consumers: Overview['consumers']; consumerMap: { revision: number; bindings: Overview['bindings']; gaps: Overview['gaps'] }; native: Overview['native'] } }
export class OwnerApi {
  private csrf: string | null = null;
  get canWrite(): boolean { return this.csrf !== null; }
  constructor(private readonly fetcher: typeof fetch = globalThis.fetch.bind(globalThis)) {}
  private async request(path: string, body?: unknown, protectedWrite = false): Promise<unknown> {
    if (protectedWrite && !this.csrf) throw new ApiError(401, 'session_required');
    const headers: Record<string,string> = {}; if (body !== undefined) headers['Content-Type'] = 'application/json'; if (protectedWrite && this.csrf) headers['X-Keyroot-CSRF'] = this.csrf;
    const response = await this.fetcher(path, { method: body === undefined ? 'GET' : 'POST', credentials: 'same-origin', headers, ...(body === undefined ? {} : { body: JSON.stringify(body) }) });
    const data: unknown = await response.json(); if (!response.ok) { const e = object(data); throw new ApiError(response.status, typeof e.error === 'string' ? e.error : 'request_failed'); } return data;
  }
  async mode(): Promise<'demo' | 'real'> { const m = object(await this.request('/api/identity')).mode; if (m !== 'demo' && m !== 'real') throw new Error('Invalid controller mode'); return m; }
  private async session(path: string, body: unknown): Promise<void> { const s = object(await this.request(path, body)); this.csrf = string(s.csrfToken); number(s.expiresAt); }
  async exchange(code: string): Promise<void> { await this.session('/api/session/exchange', { code }); }
  async demo(): Promise<void> { await this.session('/api/session/demo', {}); }
  async overview(): Promise<Overview> { return parseOverview(await this.request('/api/overview')); }
  async prepare(body: Prepare): Promise<Batch> { return parseBatch(await this.request('/api/batches/prepare', body, true)); }
  async batch(id: string): Promise<Batch> { return parseBatch(await this.request(`/api/batches/${encodeURIComponent(id)}`)); }
  async run(grantId: string, operationId: string): Promise<void> { await this.request('/api/operations/run', { grantId, operationId }, true); }
  async inspect(operationId: string): Promise<Array<{ kind: string; outcome: string; limitationCodes: string[]; consumerId?: string; journalInterpretation?: { kind: string; outcome: string } }>> {
    const result = object(await this.request(`/api/operations/${encodeURIComponent(operationId)}`));
    const snapshot = result.snapshot === null || result.snapshot === undefined ? null : object(result.snapshot);
    const merged: Array<{ id?: string; kind: string; outcome: string; limitationCodes: string[]; consumerId?: string; journalInterpretation?: { kind: string; outcome: string } }> = [];
    for (const value of [...(snapshot ? array(snapshot.receipts) : []), ...array(result.receipts)]) {
      const receipt = object(value), subject = receipt.subject === undefined ? receipt : object(receipt.subject);
      const item = { ...(receipt.receiptId === undefined ? {} : { id: string(receipt.receiptId) }), kind: string(receipt.kind), outcome: string(receipt.outcome), limitationCodes: array(receipt.limitationCodes).map(string), ...(subject.consumerId === undefined ? {} : { consumerId: string(subject.consumerId) }) };
      const prior = item.id ? merged.find(r => r.id === item.id) : undefined;
      if (prior) { if (prior.kind !== item.kind || prior.outcome !== item.outcome) prior.journalInterpretation = { kind: item.kind, outcome: item.outcome }; prior.limitationCodes = [...new Set([...prior.limitationCodes, ...item.limitationCodes])]; if (!prior.consumerId && item.consumerId) prior.consumerId = item.consumerId; }
      else merged.push(item);
    }
    return merged;

  }
  async reconcile(operationId: string): Promise<void> { await this.request('/api/operations/reconcile', { operationId }, true); }
  async action(kind: Purpose, grantId: string, operationId: string): Promise<void> { await this.request(`/api/actions/${kind}`, { grantId, operationId, actionId: kind }, true); }
  async pairing(id: string): Promise<{ requestId: string; status: string; signerId: string; fingerprint: string; expiresAt: number }> { const p = object(await this.request(`/api/pairing/owner/${encodeURIComponent(id)}`)); return { requestId: string(p.requestId), status: string(p.status), signerId: string(p.signerId), fingerprint: string(p.fingerprint), expiresAt: number(p.expiresAt) }; }
  async enrollment(id: string): Promise<{ requestId: string; signerId: string; publicFingerprint: string; enrollmentFingerprint: string; rpId: string; origin: string }> { const e = object(await this.request(`/api/emergency/enrollment/${encodeURIComponent(id)}`)); if (e.purpose !== 'emergency-enrollment') throw new Error('Invalid enrollment descriptor'); return { requestId: string(e.requestId), signerId: string(e.signerId), publicFingerprint: string(e.publicFingerprint), enrollmentFingerprint: string(e.enrollmentFingerprint), rpId: string(e.rpId), origin: string(e.origin) }; }
  async guided(id: string): Promise<string> { return parseGuided(await this.request(`/api/guided/${encodeURIComponent(id)}`)); }
  async guidedStep(id: string, targetId: string): Promise<string> { return parseGuided(await this.request(`/api/guided/${encodeURIComponent(id)}/step`, { targetId, checkpointAcknowledged: true }, true)); }
}

function parseGuided(value: unknown): string { const data = object(value), recipe = object(data.recipe); const id = string(recipe.id), version = string(recipe.version); if (data.current === null) return `Recipe ${id} (${version}): steps complete; prepare guided-completion for phone approval.`; const step = object(data.current); return `Recipe ${id} (${version}): ${string(step.action)} ${string(step.targetId)}; checkpoint ${string(step.checkpoint)}. ${string(step.captureRule)}`; }

export const credentialTypes = ['api-key', 'oauth-token', 'workload-identity', 'native-session', 'other', 'unknown'] as const;
export const grantTypes = ['static-key', 'oauth', 'workload-identity', 'native-session', 'other', 'unknown'] as const;
export interface CredentialDraft { id: string; issuerId: string; accountId: string; credentialType: typeof credentialTypes[number]; grantType: typeof grantTypes[number] }
/** Prepare a complete metadata snapshot; this does not write the inventory or confer authority. */
export function buildCredentialProposal(overview: Overview, draft: CredentialDraft, signerId: string): Prepare {
  const identifier = /^[-a-zA-Z0-9_.:@/]{1,256}$/;
  if (![draft.id, draft.issuerId, draft.accountId].every(value => identifier.test(value))) throw new Error('Use nonsecret identifiers with letters, numbers and . _ : @ / - only.');
  if (!credentialTypes.includes(draft.credentialType) || !grantTypes.includes(draft.grantType)) throw new Error('Choose a credential and grant type.');
  if (overview.lineages.some(lineage => lineage.id === draft.id)) throw new Error('That lineage ID already exists.');
  if (!overview.approvers.some(approver => approver.role === 'routine' && approver.signerId === signerId)) throw new Error('Choose an existing paired routine phone.');
  if (!Number.isSafeInteger(overview.revision) || overview.revision < 0 || overview.revision >= Number.MAX_SAFE_INTEGER) throw new Error('Inventory revision is invalid. Refresh before continuing.');
  return { signerId, role: 'routine', lineageIds: [draft.id], purpose: 'inventory-update', targetId: 'inventory', inventory: { lineages: [...structuredClone(overview.lineages), { ...draft }], consumers: structuredClone(overview.consumers), native: structuredClone(overview.native), consumerMap: { revision: overview.revision + 1, bindings: structuredClone(overview.bindings), gaps: structuredClone(overview.gaps) } } };
}
