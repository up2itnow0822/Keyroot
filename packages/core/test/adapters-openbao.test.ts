import { test } from 'node:test';
import { strict as assert } from 'node:assert';
import { createOpenBaoStore } from '../src/adapters/openbao-kv2.js';

test('CAS uses KV2 wire format and exposes a narrow consumer port', async () => {
  const calls: { url: string; init?: RequestInit }[] = [];
  const store = createOpenBaoStore({ baseUrl: 'http://127.0.0.1:8200', mount: 'secret', token: 'synthetic-token', syntheticLoopback: true, fetch: async (url, init) => { calls.push({ url: String(url), ...(init ? { init } : {}) }); return Response.json({ data: { version: 1 } }); } });
  assert.deepEqual(await store.write('ops/op-1', 0, 'sentinel-secret'), { status: 'written', version: 1 });
  assert.equal(calls[0]?.url, 'http://127.0.0.1:8200/v1/secret/data/ops/op-1');
  assert.deepEqual(JSON.parse(String(calls[0]?.init?.body)), { options: { cas: 0 }, data: { value: 'sentinel-secret' } });
  const consumer = store.consumer(['ops/op-1']);
  assert.equal('write' in consumer, false);
  assert.equal('metadata' in consumer, false);
});
test('CAS conflicts, malformed replies and transport uncertainty stay distinct', async () => {
  let response = Response.json({ errors: ['check-and-set parameter did not match the current version'] }, { status: 400 });
  const store = createOpenBaoStore({ baseUrl: 'https://bao.example', mount: 'secret', token: 'x', fetch: async () => response });
  assert.equal((await store.write('x', 2, 'secret')).status, 'conflict');
  response = Response.json({ data: {} });
  assert.equal((await store.write('x', 2, 'secret')).status, 'schema-error');
  response = new Response('', { status: 503 });
  assert.equal((await store.write('x', 2, 'secret')).status, 'unknown');
  assert.throws(() => createOpenBaoStore({ baseUrl: 'http://bao.example', mount: 'secret', token: 'x', fetch }));
});
test('resolves an authorized exact version without exposing values', async () => {
  let target = '';
  const store = createOpenBaoStore({ baseUrl: 'https://bao.example', mount: 'secret', token: 'x', fetch: async (url) => { target = String(url); return Response.json({ data: { metadata: { version: 3 }, data: { value: 'sentinel-secret' } } }); } });
  const port = store.consumer(['ops/a']); let used = false;
  assert.deepEqual(await port.withValue('ops/a', 3, async (value) => { used = value === 'sentinel-secret'; }), { status: 'resolved' });
  assert.equal(used, true); assert.match(target, /ops\/a\?version=3$/);
  assert.equal((await port.withValue('ops/b', 3, async () => {})).status, 'denied');
});
test('versioned update and metadata return only strict version information', async () => {
  let init: RequestInit | undefined;
  const store = createOpenBaoStore({ baseUrl: 'https://bao.example', mount: 'secret', token: 'x', fetch: async (_url, request) => { init = request; return request?.method === 'GET' ? Response.json({ data: { metadata: { version: 4 }, data: { value: 'sentinel-secret' } } }) : Response.json({ data: { version: 5 } }); } });
  assert.deepEqual(await store.metadata('ops/a'), { status: 'found', version: 4 });
  assert.deepEqual(await store.write('ops/a', 4, 'sentinel-secret'), { status: 'written', version: 5 });
  assert.equal(JSON.parse(String(init?.body)).options.cas, 4);
});
test('bounded timeout aborts requests and reports unknown', async () => {
  let signal: AbortSignal | null | undefined;
  const store = createOpenBaoStore({ baseUrl: 'https://bao.example', mount: 'secret', token: 'x', timeoutMs: 5, fetch: async (_url, init) => { signal = init?.signal; return new Promise(() => {}); } });
  assert.equal((await store.write('a', 0, 'sentinel-secret')).status, 'unknown');
  assert.equal(signal?.aborted, true);
});
test('versioned envelope returns validated binding without the value', async () => {
  const binding = { operationId: 'op-1', issuerId: 'key-1', accountId: 'org-a', projectId: 'proj-a', serviceAccountId: 'sa-a' };
  const store = createOpenBaoStore({ baseUrl: 'https://bao.example', mount: 'secret', token: 'x', fetch: async () => Response.json({ data: { metadata: { version: 1 }, data: { value: 'sentinel-secret', binding } } }) });
  const result = await store.metadata('ops/a', 1);
  assert.deepEqual(result, { status: 'found', version: 1, binding });
  assert.equal(JSON.stringify(result).includes('sentinel-secret'), false);
});
test('CAS writes binding atomically and rejects invalid envelope bindings', async () => {
  const binding = { operationId: 'op-1', issuerId: 'key-1', accountId: 'org-a', projectId: 'proj-a', serviceAccountId: 'sa-a' };
  let payload: unknown;
  const store = createOpenBaoStore({ baseUrl: 'https://bao.example', mount: 'secret', token: 'x', fetch: async (_url, init) => { if (init?.method === 'POST') { payload = JSON.parse(String(init.body)); return Response.json({ data: { version: 1 } }); } return Response.json({ data: { metadata: { version: 1 }, data: { value: 'sentinel-secret', binding: { ...binding, extra: 'secret' } } } }); } });
  assert.equal((await store.write('ops/a', 0, 'sentinel-secret', binding)).status, 'written');
  assert.deepEqual(payload, { options: { cas: 0 }, data: { value: 'sentinel-secret', binding } });
  const result = await store.metadata('ops/a', 1); assert.equal(result.status, 'schema-error'); assert.equal(JSON.stringify(result).includes('sentinel-secret'), false);
  assert.throws(() => createOpenBaoStore({ baseUrl: 'https://bao.example', mount: 'secret', token: 'x', timeoutMs: 120_001, fetch }));
});
