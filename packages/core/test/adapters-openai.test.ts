import { test } from 'node:test';
import { strict as assert } from 'node:assert';
import { createOpenAIServiceAccountAdapter } from '../src/adapters/openai-service-account.js';
import type { ExistingStore } from '../src/adapters/store.js';

const store = (status: 'written' | 'conflict' = 'written'): ExistingStore => ({ write: async () => status === 'written' ? { status, version: 1 } : { status }, metadata: async () => ({ status: 'not-found' }), consumer: () => ({ withValue: async () => ({ status: 'not-found' }) }) });
const config = { kind: 'synthetic' as const, accountId: 'org-a', projectId: 'proj-a', serviceAccountId: 'sa-a', adminToken: 'admin-secret' };
test('create stores one-time secret and returns only metadata', async () => {
  let request: { url: string; body: unknown; redirect: RequestRedirect | undefined } | undefined;
  const adapter = createOpenAIServiceAccountAdapter({ ...config, store: store(), fetch: async (url, init) => { request = { url: String(url), body: JSON.parse(String(init?.body)), redirect: init?.redirect }; return Response.json({ object: 'organization.project.service_account.api_key', id: 'key-a', name: 'keyroot-op-1', value: 'sentinel-secret' }); } });
  const result = await adapter.create({ operationId: 'op-1', scopes: ['api.read'], expiresInSeconds: 3600 });
  assert.equal(request?.url, 'https://api.openai.com/v1/organization/projects/proj-a/service_accounts/sa-a/api_keys');
  assert.deepEqual(request?.body, { name: 'keyroot-op-1', scopes: ['api.read'], expires_in_seconds: 3600 });
  assert.equal(request?.redirect, 'error');
  assert.equal(result.status, 'created');
  assert.equal(JSON.stringify(result).includes('sentinel-secret'), false);
});
test('created but store failure and lost response never retry', async () => {
  let calls = 0;
  const adapter = createOpenAIServiceAccountAdapter({ ...config, store: store('conflict'), fetch: async () => { calls++; return Response.json({ object: 'organization.project.service_account.api_key', id: 'key-a', name: 'keyroot-op-1', value: 'sentinel-secret' }); } });
  assert.equal((await adapter.create({ operationId: 'op-1', scopes: [], expiresInSeconds: 1 })).status, 'created-unrecoverable');
  assert.equal(calls, 1);
  const lost = createOpenAIServiceAccountAdapter({ ...config, store: store(), fetch: async () => { throw new Error('sentinel-secret'); } });
  const result = await lost.create({ operationId: 'op-1', scopes: [], expiresInSeconds: 1 });
  assert.equal(result.status, 'unknown'); assert.equal(JSON.stringify(result).includes('sentinel-secret'), false);
});
const item = (id: string, name: string, owner = 'sa-a') => ({ object: 'organization.project.api_key', id, name, owner: { type: 'service_account', service_account: { id: owner } }, redacted_value: 'sentinel-secret' });
test('paginates, excludes other accounts, and holds duplicate correlations', async () => {
  const urls: string[] = [];
  const adapter = createOpenAIServiceAccountAdapter({ ...config, store: store(), fetch: async (url) => { urls.push(String(url)); return urls.length === 1 ? Response.json({ object: 'list', data: [item('key-1', 'keyroot-op-1'), item('foreign', 'keyroot-op-1', 'sa-b')], has_more: true, last_id: 'key-1' }) : Response.json({ object: 'list', data: [item('key-2', 'keyroot-op-1')], has_more: false }); } });
  assert.deepEqual(await adapter.reconcile('op-1'), { status: 'ambiguous', matches: 2 });
  assert.match(urls[0] ?? '', /owner_project_access=any/); assert.match(urls[1] ?? '', /after=key-1/);
  assert.equal(JSON.stringify(await adapter.observe('foreign')).includes('sentinel-secret'), false);
});
test('deletes only an owned key and treats failure as unverified', async () => {
  let deletes = 0; let fail = false;
  const adapter = createOpenAIServiceAccountAdapter({ ...config, store: store(), fetch: async (_url, init) => { if (init?.method === 'DELETE') { deletes++; return fail ? new Response('', { status: 503 }) : Response.json({ object: 'organization.project.api_key.deleted', id: 'key-1', deleted: true }); } return Response.json({ object: 'list', data: [item('key-1', 'name'), item('foreign', 'name', 'sa-b')], has_more: false }); } });
  assert.equal((await adapter.revoke('foreign')).status, 'unverified'); assert.equal(deletes, 0);
  assert.equal((await adapter.revoke('key-1')).status, 'acknowledged');
  fail = true; assert.equal((await adapter.revoke('key-1')).status, 'unverified');
});
test('probe preserves confounded and safely handles exceptions', async () => {
  const adapter = createOpenAIServiceAccountAdapter({ ...config, store: store(), fetch: async () => new Response('', { status: 500 }) });
  const port = { withValue: async (execute: (value: string) => Promise<void>) => { await execute('sentinel-secret'); return { status: 'resolved' }; } };
  assert.deepEqual(await adapter.probe(port, async () => 'confounded'), { status: 'confounded' });
  const outcome = await adapter.probe(port, async () => { throw new Error('sentinel-secret'); });
  assert.deepEqual(outcome, { status: 'unknown' });
  assert.throws(() => createOpenAIServiceAccountAdapter({ ...config, kind: 'live', store: store(), fetch }));
});
test('lost store acknowledgement and repeated create require reconciliation', async () => {
  let calls = 0;
  const unknownStore: ExistingStore = { ...store(), write: async () => ({ status: 'unknown' }) };
  const adapter = createOpenAIServiceAccountAdapter({ ...config, store: unknownStore, fetch: async () => { calls++; return Response.json({ object: 'organization.project.service_account.api_key', id: 'key-a', name: 'keyroot-op-1', value: 'sentinel-secret' }); } });
  assert.equal((await adapter.create({ operationId: 'op-1', scopes: [], expiresInSeconds: 1 })).status, 'store-outcome-unknown');
  assert.equal((await adapter.create({ operationId: 'op-1', scopes: [], expiresInSeconds: 1 })).status, 'reconciliation-required'); assert.equal(calls, 1);
});
test('active observation requires matching ownership and id', async () => {
  let response: unknown = item('key-1', 'name');
  const adapter = createOpenAIServiceAccountAdapter({ ...config, store: store(), fetch: async () => Response.json(response) });
  assert.equal((await adapter.observe('key-1')).status, 'confirmed-active');
  response = item('key-1', 'name', 'sa-b'); assert.equal((await adapter.observe('key-1')).status, 'unverified');
  response = item('key-2', 'name'); assert.equal((await adapter.observe('key-1')).status, 'unverified');
});
test('timeout aborts provider call and exposes no secret', async () => {
  let signal: AbortSignal | null | undefined;
  const adapter = createOpenAIServiceAccountAdapter({ ...config, timeoutMs: 5, store: store(), fetch: async (_url, init) => { signal = init?.signal; return new Promise(() => {}); } });
  const result = await adapter.create({ operationId: 'op-1', scopes: [], expiresInSeconds: 1 });
  assert.equal(result.status, 'unknown'); assert.equal(signal?.aborted, true);
});
test('reconciliation requires exact binding and unchanged current version', async () => {
  const binding = { operationId: 'op-1', issuerId: 'key-1', accountId: 'org-a', projectId: 'proj-a', serviceAccountId: 'sa-a' };
  let current = 1; let actual: typeof binding | undefined = binding;
  const boundStore: ExistingStore = { ...store(), metadata: async (_handle, version) => ({ status: 'found', version: version ?? current, ...(actual ? { binding: actual } : {}) }) };
  const adapter = createOpenAIServiceAccountAdapter({ ...config, store: boundStore, fetch: async () => Response.json({ object: 'list', data: [item('key-1', 'keyroot-op-1')], has_more: false }) });
  assert.equal((await adapter.reconcile('op-1')).status, 'stored-candidate');
  actual = { ...binding, issuerId: 'key-other' }; assert.notEqual((await adapter.reconcile('op-1')).status, 'stored-candidate');
  actual = undefined; assert.notEqual((await adapter.reconcile('op-1')).status, 'stored-candidate');
  actual = binding; current = 2; assert.notEqual((await adapter.reconcile('op-1')).status, 'stored-candidate');
});
test('create passes account-scoped binding into the same CAS write', async () => {
  let writeArgs: unknown[] = [];
  const boundStore: ExistingStore = { ...store(), write: async (...args) => { writeArgs = args; return { status: 'written', version: 1 }; } };
  const adapter = createOpenAIServiceAccountAdapter({ ...config, store: boundStore, fetch: async () => Response.json({ object: 'organization.project.service_account.api_key', id: 'key-1', name: 'keyroot-op-1', value: 'sentinel-secret' }) });
  const receipt = await adapter.create({ operationId: 'op-1', scopes: [], expiresInSeconds: 1 });
  assert.deepEqual(writeArgs, ['operations/op-1', 0, 'sentinel-secret', { operationId: 'op-1', issuerId: 'key-1', accountId: 'org-a', projectId: 'proj-a', serviceAccountId: 'sa-a' }]);
  assert.equal(JSON.stringify(receipt).includes('sentinel-secret'), false);
  assert.throws(() => createOpenAIServiceAccountAdapter({ ...config, store: store(), timeoutMs: 0, fetch: async () => new Response() }));
});
