import { validStoreBinding } from './store.js';
import type { ExistingStore, StoreStatus, StoreResolveResult } from './store.js';

type Fetch = typeof globalThis.fetch;
interface Options { baseUrl: string; mount: string; token: string; fetch: Fetch; syntheticLoopback?: boolean; timeoutMs?: number }
const segment = /^[A-Za-z0-9_-]+$/;
function path(value: string): string {
  const parts = value.split('/');
  if (!parts.length || parts.some((p) => !segment.test(p))) throw new Error('Invalid store path');
  return parts.map(encodeURIComponent).join('/');
}
function obj(value: unknown): Record<string, unknown> | undefined { return value !== null && typeof value === 'object' && !Array.isArray(value) ? value as Record<string, unknown> : undefined; }
function version(value: unknown): value is number { return Number.isSafeInteger(value) && (value as number) > 0; }
export function createOpenBaoStore(options: Options): ExistingStore {
  let base: URL;
  try { base = new URL(options.baseUrl); } catch { throw new Error('Invalid store endpoint'); }
  if (base.username || base.password || base.search || base.hash || base.pathname !== '/' || !(base.protocol === 'https:' || (options.syntheticLoopback === true && base.protocol === 'http:' && ['localhost', '127.0.0.1', '[::1]'].includes(base.hostname)))) throw new Error('Invalid store endpoint');
  const mount = path(options.mount);
  const timeoutMs = options.timeoutMs ?? 10_000;
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 120_000) throw new Error('Invalid timeout');
  async function request(kind: 'data' | 'metadata', handle: string, init: RequestInit, requestedVersion?: number): Promise<{ status: number; body: unknown } | undefined> {
    const target = `${base.origin}/v1/${mount}/${kind}/${path(handle)}${requestedVersion === undefined ? '' : `?version=${requestedVersion}`}`;
    const controller = new AbortController();
    let timer: ReturnType<typeof setTimeout> | undefined;
    try {
      return await Promise.race([
        (async () => {
          const response = await options.fetch(target, { ...init, signal: controller.signal, headers: { 'X-Vault-Token': options.token, 'Content-Type': 'application/json' } });
          let body: unknown; try { body = await response.json(); } catch { body = undefined; }
          return { status: response.status, body };
        })(),
        new Promise<undefined>((resolve) => { timer = setTimeout(() => { controller.abort(); resolve(undefined); }, timeoutMs); })
      ]);
    } catch { return undefined; } finally { if (timer !== undefined) clearTimeout(timer); }
  }
  function error(status: number | undefined): StoreStatus {
    if (status === 404) return 'not-found';
    if (status === 401 || status === 403) return 'denied';
    return 'unknown';
  }
  return {
    async write(handle, expectedVersion, value, binding) {
      if (!Number.isSafeInteger(expectedVersion) || expectedVersion < 0 || typeof value !== 'string') throw new Error('Invalid store write');
      if (binding !== undefined && !validStoreBinding(binding)) throw new Error('Invalid store binding');
      const response = await request('data', handle, { method: 'POST', body: JSON.stringify({ options: { cas: expectedVersion }, data: { value, ...(binding ? { binding } : {}) } }) });
      if (response?.status === 400) {
        const errors = obj(response.body)?.errors;
        if (Array.isArray(errors) && errors.some((x: unknown) => typeof x === 'string' && x.includes('check-and-set parameter did not match'))) return { status: 'conflict' };
        return { status: 'schema-error' };
      }
      if (!response || response.status < 200 || response.status >= 300) return { status: error(response?.status) };
      const actual = obj(obj(response.body)?.data)?.version;
      return version(actual) && actual === expectedVersion + 1 ? { status: 'written', version: actual } : { status: 'schema-error' };
    },
    async metadata(handle, requestedVersion) {
      if (requestedVersion !== undefined && !version(requestedVersion)) throw new Error('Invalid store version');
      const response = await request('data', handle, { method: 'GET' }, requestedVersion);
      if (!response || response.status < 200 || response.status >= 300) return { status: error(response?.status) };
      const envelope = obj(obj(response.body)?.data); const actual = obj(envelope?.metadata)?.version; const data = obj(envelope?.data);
      if (!version(actual) || (requestedVersion !== undefined && actual !== requestedVersion) || !data || typeof data.value !== 'string') return { status: 'schema-error' };
      if (data.binding === undefined) return { status: 'found', version: actual };
      if (!validStoreBinding(data.binding)) return { status: 'schema-error' };
      const { operationId, issuerId, accountId, projectId, serviceAccountId } = data.binding;
      return { status: 'found', version: actual, binding: { operationId, issuerId, accountId, projectId, serviceAccountId } };
    },
    consumer(allowedHandles) {
      const allowed = new Set(allowedHandles.map((h) => { path(h); return h; }));
      return { async withValue(handle, requestedVersion, execute): Promise<StoreResolveResult> {
        if (!allowed.has(handle)) return { status: 'denied' };
        if (!version(requestedVersion)) throw new Error('Invalid store version');
        const response = await request('data', handle, { method: 'GET' }, requestedVersion);
        if (!response || response.status < 200 || response.status >= 300) return { status: error(response?.status) };
        const data = obj(obj(response.body)?.data); const metadata = obj(data?.metadata); const value = obj(data?.data)?.value;
        if (metadata?.version !== requestedVersion || typeof value !== 'string') return { status: 'schema-error' };
        try { await execute(value); } catch { return { status: 'unknown' }; }
        return { status: 'resolved' };
      } };
    }
  };
}
