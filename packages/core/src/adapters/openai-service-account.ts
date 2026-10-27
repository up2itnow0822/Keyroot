import { validStoreBinding } from './store.js';
import type { ExistingStore, StoreBinding } from './store.js';

type Fetch = typeof globalThis.fetch;
export type RevocationObservation = 'confirmed-revoked' | 'confirmed-active' | 'unverified';
type ProbeOutcome = 'accepted' | 'rejected' | 'confounded' | 'unknown';
type SafeKey = { id: string; name: string; serviceAccountId: string };
type Result<T> = { status: 'ok'; value: T } | { status: 'unknown' | 'denied' | 'schema-error' };
interface Config { kind: 'synthetic' | 'live'; accountId: string; projectId: string; serviceAccountId: string; adminToken: string; fetch: Fetch; store: ExistingStore; timeoutMs?: number }
export interface LiveAssessmentHook { assess(scope: { accountId: string; projectId: string; serviceAccountId: string; action: 'create' | 'list' | 'revoke' | 'probe' }): Promise<{ admitted: boolean; limitations: readonly string[] }> }
const idPattern = /^[A-Za-z0-9_-]{1,128}$/;
function validId(value: unknown): value is string { return typeof value === 'string' && idPattern.test(value); }
function object(value: unknown): Record<string, unknown> | undefined { return value !== null && typeof value === 'object' && !Array.isArray(value) ? value as Record<string, unknown> : undefined; }
function key(value: unknown, owner: string): SafeKey | undefined {
  const o = object(value); const ownership = object(o?.owner); const account = object(ownership?.service_account);
  if (o?.object !== 'organization.project.api_key' || !validId(o.id) || typeof o.name !== 'string' || ownership?.type !== 'service_account' || account?.id !== owner) return undefined;
  return { id: o.id, name: o.name, serviceAccountId: owner };
}
export function createOpenAIServiceAccountAdapter(config: Config) {
  if (![config.accountId, config.projectId, config.serviceAccountId].every(validId)) throw new Error('Invalid account scope');
  if (config.kind !== 'synthetic' || config.fetch === globalThis.fetch) throw new Error('Live account admission is unavailable');
  const root = `https://api.openai.com/v1/organization/projects/${encodeURIComponent(config.projectId)}`;
  const attempted = new Set<string>();
  const timeoutMs = config.timeoutMs ?? 10_000;
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 120_000) throw new Error('Invalid timeout');
  async function request(path: string, init: RequestInit): Promise<{ status: number; body: unknown } | undefined> {
    const controller = new AbortController();
    let timer: ReturnType<typeof setTimeout> | undefined;
    try {
      return await Promise.race([
        (async () => {
          const response = await config.fetch(`${root}${path}`, { ...init, signal: controller.signal, headers: { Authorization: `Bearer ${config.adminToken}`, 'Content-Type': 'application/json' } });
          let body: unknown; try { body = await response.json(); } catch { body = undefined; }
          return { status: response.status, body };
        })(),
        new Promise<undefined>((resolve) => { timer = setTimeout(() => { controller.abort(); resolve(undefined); }, timeoutMs); })
      ]);
    } catch { return undefined; } finally { if (timer !== undefined) clearTimeout(timer); }
  }
  function failure(status: number | undefined): 'unknown' | 'denied' { return status === 401 || status === 403 ? 'denied' : 'unknown'; }
  async function list(): Promise<Result<SafeKey[]>> {
    const values: SafeKey[] = []; let after: string | undefined; const cursors = new Set<string>(); let more = true;
    do {
      const params = new URLSearchParams({ limit: '100', owner_project_access: 'any' }); if (after) params.set('after', after);
      const response = await request(`/api_keys?${params}`, { method: 'GET' });
      if (!response || response.status < 200 || response.status >= 300) return { status: failure(response?.status) };
      const body = object(response.body);
      if (body?.object !== 'list' || !Array.isArray(body.data) || typeof body.has_more !== 'boolean') return { status: 'schema-error' };
      for (const item of body.data) {
        const entry = object(item); const ownership = object(entry?.owner); const service = object(ownership?.service_account);
        if (entry?.object !== 'organization.project.api_key' || !validId(entry.id) || typeof entry.name !== 'string' || (ownership?.type !== 'user' && ownership?.type !== 'service_account')) return { status: 'schema-error' };
        if (ownership.type === 'service_account') {
          if (!validId(service?.id)) return { status: 'schema-error' };
          if (service.id === config.serviceAccountId) { const safe = key(item, config.serviceAccountId); if (!safe) return { status: 'schema-error' }; values.push(safe); }
        }
      }
      more = body.has_more;
      if (!more) break;
      if (!validId(body.last_id) || cursors.has(body.last_id)) return { status: 'schema-error' };
      after = body.last_id; cursors.add(after);
    } while (more);
    return { status: 'ok', value: values };
  }
  return {
    capabilities: Object.freeze({ trust: 'synthetic' as const, liveAdmitted: false, arbitraryProjectKeyCreate: false, limitations: ['Account permissions, overlap and data-plane probes require live assessment', 'Correlation names are not idempotency keys'] }),
    async create(input: { operationId: string; scopes: string[]; expiresInSeconds: number }) {
      if (!validId(input.operationId) || !Array.isArray(input.scopes) || input.scopes.some((s) => typeof s !== 'string' || !s.trim()) || !Number.isSafeInteger(input.expiresInSeconds) || input.expiresInSeconds <= 0) throw new Error('Invalid create request');
      if (attempted.has(input.operationId)) return { status: 'reconciliation-required' as const };
      attempted.add(input.operationId);
      const name = `keyroot-${input.operationId}`; const handle = `operations/${input.operationId}`;
      const response = await request(`/service_accounts/${encodeURIComponent(config.serviceAccountId)}/api_keys`, { method: 'POST', body: JSON.stringify({ name, scopes: input.scopes, expires_in_seconds: input.expiresInSeconds }) });
      if (!response || response.status < 200 || response.status >= 300) return { status: 'unknown' as const };
      const body = object(response.body);
      if (body?.object !== 'organization.project.service_account.api_key' || !validId(body.id) || body.name !== name || typeof body.value !== 'string' || !body.value) return { status: 'unknown' as const };
      const binding: StoreBinding = { operationId: input.operationId, issuerId: body.id, accountId: config.accountId, projectId: config.projectId, serviceAccountId: config.serviceAccountId };
      let saved; try { saved = await config.store.write(handle, 0, body.value, binding); } catch { return { status: 'store-outcome-unknown' as const, issuerId: body.id, handle }; }
      if (saved.status === 'unknown' || saved.status === 'schema-error') return { status: 'store-outcome-unknown' as const, issuerId: body.id, handle };
      if (saved.status !== 'written') return { status: 'created-unrecoverable' as const, issuerId: body.id, handle };
      return { status: 'created' as const, issuerId: body.id, handle, version: saved.version };
    },
    list,
    async reconcile(operationId: string) {
      if (!validId(operationId)) throw new Error('Invalid operation');
      const found = await list(); if (found.status !== 'ok') return { status: 'unknown' as const };
      const matches = found.value.filter((item) => item.name === `keyroot-${operationId}`);
      if (matches.length !== 1) return { status: 'ambiguous' as const, matches: matches.length };
      const item = matches[0]; if (!item) return { status: 'unknown' as const };
      const handle = `operations/${operationId}`;
      let current; let pinned;
      try { current = await config.store.metadata(handle); } catch { return { status: 'unknown' as const }; }
      if (current.status === 'not-found') return { status: 'created-unrecoverable' as const, issuerId: item.id };
      if (current.status !== 'found') return { status: 'unknown' as const };
      if (current.version !== 1) return { status: 'ambiguous' as const, matches: 1 };
      try { pinned = await config.store.metadata(handle, 1); } catch { return { status: 'unknown' as const }; }
      if (pinned.status !== 'found' || pinned.version !== 1 || !validStoreBinding(pinned.binding)) return { status: 'unknown' as const };
      const expected: StoreBinding = { operationId, issuerId: item.id, accountId: config.accountId, projectId: config.projectId, serviceAccountId: config.serviceAccountId };
      if ((Object.keys(expected) as (keyof StoreBinding)[]).some((k) => pinned.binding?.[k] !== expected[k])) return { status: 'ambiguous' as const, matches: 1 };
      return { status: 'stored-candidate' as const, issuerId: item.id, version: 1 };
    },
    async revoke(issuerId: string) {
      if (!validId(issuerId)) throw new Error('Invalid issuer id');
      const found = await list(); if (found.status !== 'ok' || !found.value.some((item) => item.id === issuerId)) return { status: 'unverified' as const };
      const response = await request(`/api_keys/${encodeURIComponent(issuerId)}`, { method: 'DELETE' });
      if (!response || response.status < 200 || response.status >= 300) return { status: 'unverified' as const };
      const body = object(response.body);
      return body?.object === 'organization.project.api_key.deleted' && body.id === issuerId && body.deleted === true ? { status: 'acknowledged' as const } : { status: 'unverified' as const };
    },
    async observe(issuerId: string) {
      if (!validId(issuerId)) throw new Error('Invalid issuer id');
      const response = await request(`/api_keys/${encodeURIComponent(issuerId)}`, { method: 'GET' });
      if (!response || response.status < 200 || response.status >= 300) return { status: 'unverified' as const };
      const found = key(response.body, config.serviceAccountId);
      return found?.id === issuerId ? { status: 'confirmed-active' as const } : { status: 'unverified' as const };
    },
    async probe(port: { withValue: (execute: (value: string) => Promise<void>) => Promise<{ status: string }> }, callback: (value: string) => Promise<ProbeOutcome>) {
      let outcome: ProbeOutcome = 'unknown';
      try { const resolved = await port.withValue(async (value) => { outcome = await callback(value); }); if (resolved.status !== 'resolved') return { status: 'unknown' as const }; } catch { return { status: 'unknown' as const }; }
      return { status: (['accepted', 'rejected', 'confounded', 'unknown'] as readonly string[]).includes(outcome) ? outcome : 'unknown' as const };
    }
  };
}
