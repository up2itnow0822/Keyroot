import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { setTimeout as delay } from 'node:timers/promises';
import { test } from 'node:test';
import { createOpenBaoStore } from '../../packages/core/src/adapters/openbao-kv2.js';

// Official 2.7.2 multi-platform digest. This disposable dev server contains only synthetic values.
const image = 'openbao/openbao@sha256:5046911075e137e154ce49ab051502f4ec7cf367d484ae4a4dce665d9b90561f';
const fixtureToken = 'keyroot-disposable-fixture-only';

test('actual OpenBao KV2 enforces CAS, pinned bindings and server-side consumer scope', { timeout: 120000 }, async t => {
  const name = `keyroot-test-${randomUUID()}`;
  const docker = (args: string[]) => execFileSync('docker', args, { encoding: 'utf8', timeout: 90000, stdio: ['ignore', 'pipe', 'pipe'] }).trim();
  try { docker(['version', '--format', '{{.Server.Version}}']); }
  catch { assert.fail('A running Docker server is required for the actual OpenBao gate.'); }
  let started = false;
  t.after(() => { if (started) docker(['rm', '--force', name]); });
  try {
    docker(['run', '--detach', '--rm', '--name', name, '--read-only', '--cap-drop', 'ALL',
      '--security-opt', 'no-new-privileges', '--tmpfs', '/tmp:rw,noexec,nosuid,size=16m',
      '--tmpfs', '/openbao/file:rw,noexec,nosuid,size=16m,uid=100,gid=1000', '--publish', '127.0.0.1::8200',
      '--env', `BAO_DEV_ROOT_TOKEN_ID=${fixtureToken}`, '--env', 'BAO_DEV_LISTEN_ADDRESS=0.0.0.0:8200', image]);
    started = true;
  } catch { assert.fail('Could not start the official isolated synthetic OpenBao fixture.'); }
  const mapping = docker(['port', name, '8200/tcp']);
  assert.match(mapping, /^127\.0\.0\.1:\d+$/);
  const baseUrl = `http://${mapping}`;
  let ready = false;
  for (let i = 0; i < 80; i++) {
    try {
      ready = (await fetch(`${baseUrl}/v1/sys/health`, { signal: AbortSignal.timeout(500) })).status === 200;
      if (ready) break;
    } catch { /* Starting the disposable fixture is not issuer evidence. */ }
    await delay(50);
  }
  assert.equal(ready, true, 'Synthetic store did not become ready.');
  async function admin(path: string, body: unknown) {
    const response = await fetch(`${baseUrl}/v1/${path}`, { method: 'POST', headers: { 'X-Vault-Token': fixtureToken, 'Content-Type': 'application/json' }, body: JSON.stringify(body), signal: AbortSignal.timeout(5000) });
    assert.ok(response.ok, `Synthetic fixture setup returned HTTP ${response.status}`);
    return response;
  }
  await admin('sys/mounts/keyroot', { type: 'kv', options: { version: '2' } });
  const store = createOpenBaoStore({ baseUrl, mount: 'keyroot', token: fixtureToken, fetch, syntheticLoopback: true });
  const binding = { operationId: 'test-operation', issuerId: 'test-key', accountId: 'test-account', projectId: 'test-project', serviceAccountId: 'test-service-account' };
  const sentinel = 'SYNTHETIC_VALUE_NEVER_IN_METADATA';
  assert.deepEqual(await store.write('operations/test-operation', 0, sentinel, binding), { status: 'written', version: 1 });
  assert.deepEqual(await store.write('operations/test-operation', 0, sentinel, binding), { status: 'conflict' });
  assert.deepEqual(await store.metadata('operations/test-operation', 1), { status: 'found', version: 1, binding });
  assert.deepEqual(await store.write('operations/test-operation', 1, 'SYNTHETIC_SECOND_GENERATION', binding), { status: 'written', version: 2 });
  assert.deepEqual(await store.metadata('operations/test-operation'), { status: 'found', version: 2, binding });
  assert.deepEqual(await store.metadata('operations/test-operation', 1), { status: 'found', version: 1, binding });
  let seen = false;
  const port = store.consumer(['operations/test-operation']);
  assert.deepEqual(await port.withValue('operations/test-operation', 1, async value => { assert.equal(value, sentinel); seen = true; }), { status: 'resolved' });
  assert.equal(seen, true);
  assert.deepEqual(await port.withValue('operations/unmapped', 1, async () => { assert.fail('Unmapped executor called'); }), { status: 'denied' });

  await admin('sys/policies/acl/keyroot-consumer-test', { policy: 'path "keyroot/data/operations/test-operation" { capabilities = ["read"] }' });
  const response = await admin('auth/token/create', { policies: ['keyroot-consumer-test'], no_default_policy: true, ttl: '60s', renewable: false });
  const tokenResponse = await response.json() as { auth: { client_token: string } };
  assert.equal(typeof tokenResponse.auth.client_token, 'string');
  const limited = createOpenBaoStore({ baseUrl, mount: 'keyroot', token: tokenResponse.auth.client_token, fetch, syntheticLoopback: true });
  assert.deepEqual(await limited.consumer(['operations/test-operation']).withValue('operations/test-operation', 1, async value => { assert.equal(value, sentinel); }), { status: 'resolved' });
  assert.deepEqual(await limited.write('operations/test-operation', 2, 'SYNTHETIC_FORBIDDEN_WRITE', binding), { status: 'denied' });
  assert.deepEqual(await limited.consumer(['operations/unmapped']).withValue('operations/unmapped', 1, async () => { assert.fail('Server-scope violation'); }), { status: 'denied' });
  const metadata = JSON.stringify(await store.metadata('operations/test-operation', 1));
  assert.equal(metadata.includes(sentinel), false);
  assert.equal(metadata.includes(fixtureToken), false);
  assert.equal(metadata.includes(tokenResponse.auth.client_token), false);
});
