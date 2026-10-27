import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, writeFile, stat, rm, symlink, realpath } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import sodium from 'libsodium-wrappers';
import { generateKeyPairSync, sign } from 'node:crypto';
import { canonicalJSON, contentDigest, deepFreeze } from '../src/manifest.js';
import { fileDigest, createEnvFileConsumer, type EnvFileDescriptor } from '../src/consumers/env-file.js';
import { createGitHubActionsConsumer } from '../src/consumers/github-actions.js';
import { createVercelConsumer } from '../src/consumers/vercel.js';
import { verifyConsumerUse } from '../src/consumer-receipt.js';
import type { AuthorizedIntent } from '../src/journal.js';
import type { EffectContext } from '../src/engine.js';
import { credentialFingerprint, type ConsumerDescriptor, type ConsumerTrust } from '../src/consumers/consumer.js';

const original = '# fixture\nUNRELATED=keep\nAPI_KEY=old\n';
const subject = { operationId: 'op', lineageId: 'lineage', accountId: 'account', generation: 2, resourceId: 'issuer', handleId: 'mapped', consumerMapRevision: 'map-v1', consumerId: 'consumer', revision: 'revision' };
const context: EffectContext = { subject, signal: new AbortController().signal };
function intent(d: ConsumerDescriptor): AuthorizedIntent { return deepFreeze({ intentId: 'intent', idempotencyRef: 'idem', operationId: 'op', actionId: 'deliver', grantId: 'grant', kind: 'deliver', state: 'pending', parameters: { consumerId: d.consumerId, destinationId: d.destinationId, handleId: d.handleId, generation: d.generation, expectedRevision: d.revision, configurationHash: contentDigest(d) } }); }
const trust = (guard: ConsumerTrust['beforeEffect'] = async () => {}): ConsumerTrust => ({ beforeEffect: guard, quarantine: async () => 'clear', clock: () => 100 });
const base = { consumerId: 'consumer', destinationId: 'destination', revision: 'revision', consumerMapRevision: 'map-v1', generation: 2, handleId: 'mapped', version: 1, mappingTokenFingerprint: contentDigest('mapped-token') };
async function fixture() { const root = await realpath(await mkdtemp(join(tmpdir(), 'keyroot-consumer-'))); const path = join(root, '.env'); await writeFile(path, original); const d: EnvFileDescriptor = { ...base, driver: 'env-file', envFormat: 'node-env', mode: 'deliver', rootId: 'fixture-root', relativePath: '.env', variable: 'API_KEY', expectedFileHash: fileDigest(Buffer.from(original)), backupHandle: 'backup', backupExpectedVersion: 0, backupVersion: 1 }; let backup: string | undefined; const vault = { async write(handle: string, version: number, value: string) { assert.equal(handle, 'backup'); assert.equal(version, 0); backup = value; return { status: 'written' as const, version: 1 }; }, async withValue(handle: string, version: number, fn: (value: string) => Promise<void>) { assert.equal(handle, 'backup'); assert.equal(version, 1); assert.ok(backup); await fn(backup); return { status: 'resolved' as const }; } }; const store = { async withValue(handle: string, version: number, fn: (value: string) => Promise<void>) { assert.equal(handle, 'mapped'); assert.equal(version, 1); await fn('synthetic-secret'); return { status: 'resolved' as const }; } }; return { root, path, d, vault, store }; }

test('env delivery preserves unrelated entries and restrictive permissions; rollback needs separate signed exact binding', async () => { const f = await fixture(); try { const c = createEnvFileConsumer({ descriptor: f.d, roots: { 'fixture-root': f.root }, store: f.store, backup: f.vault, trust: trust() }); const receipt = await c.deliver(intent(f.d), context); assert.equal(receipt.outcome, 'delivery-accepted'); assert.ok(!JSON.stringify(receipt).includes('synthetic-secret')); const updated = await readFile(f.path); assert.match(updated.toString(), /UNRELATED=keep/); assert.match(updated.toString(), /API_KEY="synthetic-secret"/); assert.equal((await stat(f.path)).mode & 0o777, 0o600); const rollback = { ...f.d, mode: 'rollback' as const, expectedFileHash: fileDigest(updated), backupFileHash: fileDigest(Buffer.from(original)) }; const r = createEnvFileConsumer({ descriptor: rollback, roots: { 'fixture-root': f.root }, store: f.store, backup: f.vault, trust: trust() }); assert.equal((await r.deliver(intent(f.d), context)).outcome, 'rejected'); const restored = await r.deliver(intent(rollback), context); assert.equal(restored.outcome, 'unknown'); assert.ok(restored.limitationCodes.includes('authorized-rollback-applied')); assert.ok(restored.limitationCodes.includes('backup')); assert.ok(restored.limitationCodes.includes('restored-backup-version:1')); assert.ok(restored.limitationCodes.includes('successor-delivery-unverified')); assert.equal((await readFile(f.path)).toString(), original); } finally { await rm(f.root, { recursive: true, force: true }); } });
test('quarantine, mismatched file, mutable intent and symlink fail before replacement delivery', async () => { const f = await fixture(); try { const c = (t: ConsumerTrust) => createEnvFileConsumer({ descriptor: f.d, roots: { 'fixture-root': f.root }, store: f.store, backup: f.vault, trust: t }); assert.equal((await c({ ...trust(), quarantine: async () => 'quarantined' }).deliver(intent(f.d), context)).outcome, 'rejected'); assert.equal((await c(trust()).deliver({ ...intent(f.d) }, context)).outcome, 'rejected'); await writeFile(f.path, 'changed'); assert.equal((await c(trust()).deliver(intent(f.d), context)).outcome, 'rejected'); await rm(f.path); await symlink(join(f.root, 'outside'), f.path); assert.equal((await c(trust()).deliver(intent(f.d), context)).outcome, 'rejected'); } finally { await rm(f.root, { recursive: true, force: true }); } });
test('failed pre-rename guard leaves original bytes and never emits a raw error', async () => { const f = await fixture(); try { const c = createEnvFileConsumer({ descriptor: f.d, roots: { 'fixture-root': f.root }, store: f.store, backup: f.vault, trust: trust(async (_i, boundary) => { if (boundary === 'env-rename') throw Error('synthetic-secret'); }) }); const receipt = await c.deliver(intent(f.d), context); assert.equal(receipt.outcome, 'rejected'); assert.equal((await readFile(f.path)).toString(), original); assert.ok(!JSON.stringify(receipt).includes('synthetic-secret')); } finally { await rm(f.root, { recursive: true, force: true }); } });
test('signed consumer run proof binds generation, revision and named runtime; imported status cannot prove use', async () => { const keys = generateKeyPairSync('ed25519'); const observation = { version: 1 as const, consumerIdentity: 'runtime', subject, processId: 'process', deploymentId: 'deployment', jobId: 'job', runId: 'run', observedAt: 100, method: 'authenticated-runtime-use' as const, limitationCodes: ['unmanaged-copies-uncontrolled'] }; const signature = sign(null, Buffer.from(canonicalJSON(observation)), keys.privateKey).toString('base64'); const config = { identities: new Map([['runtime', { consumerId: 'consumer', publicKey: keys.publicKey }]]), clock: () => 100, maxAgeMs: 1000 }; assert.equal(verifyConsumerUse({ observation, signature }, subject, config).outcome, 'direct-use'); assert.throws(() => verifyConsumerUse({ observation: { ...observation, subject: { ...subject, generation: 1 } }, signature }, subject, config)); assert.throws(() => verifyConsumerUse({ observation: { ...observation, method: 'generic-health' as never }, signature }, subject, config)); });
test('official platform paths yield delivery only and trusted admission/quarantine are mandatory', async () => { await sodium.ready; const pair = sodium.crypto_box_keypair(); const calls: string[] = []; const store = { async withValue(_h: string, _v: number, fn: (value: string) => Promise<void>) { await fn('synthetic-secret'); return { status: 'resolved' as const }; } }; const transport: typeof fetch = async (url, init) => { calls.push(String(url)); assert.equal(init?.redirect, 'error'); if (String(url).endsWith('/public-key')) return new Response(JSON.stringify({ key_id: 'key', key: Buffer.from(pair.publicKey).toString('base64') })); if (init?.method === 'PUT') { assert.ok(!String(init.body).includes('synthetic-secret')); const payload = JSON.parse(String(init.body)) as { encrypted_value: string }; assert.equal(Buffer.from(sodium.crypto_box_seal_open(Buffer.from(payload.encrypted_value, 'base64'), pair.publicKey, pair.privateKey)).toString(), 'synthetic-secret'); return new Response(null, { status: 204 }); } if (init?.method === 'GET') return new Response(JSON.stringify({ id: 'project', accountId: 'team' })); return new Response(JSON.stringify({ created: [{ id: 'env_fixture', key: 'API_KEY', target: ['production'], type: 'encrypted' }], failed: [], skipped: [] }), { status: 201 }); }; const gh = { ...base, driver: 'github-actions' as const, owner: 'owner', repository: 'repo', secretName: 'API_KEY', accountId: 'account', pushTokenFingerprint: credentialFingerprint('synthetic-push') }; const c = createGitHubActionsConsumer({ descriptor: gh, store, trust: trust(), transport, pushToken: 'synthetic-push', admission: { assertAdmitted: async () => {} } }); assert.equal((await c.deliver(intent(gh), context)).outcome, 'delivery-accepted'); assert.ok(calls.every(url => url.startsWith('https://api.github.com/repos/owner/repo/'))); const v = { ...base, driver: 'vercel' as const, projectId: 'project', teamId: 'team', environment: 'production' as const, variable: 'API_KEY', accountId: 'account', pushTokenFingerprint: credentialFingerprint('synthetic-push') }; const vc = createVercelConsumer({ descriptor: v, store, trust: trust(), transport, pushToken: 'synthetic-push', admission: { assertAdmitted: async () => {} } }); assert.equal((await vc.deliver(intent(v), context)).outcome, 'delivery-accepted'); const denied = createVercelConsumer({ descriptor: v, store, trust: trust(), transport, pushToken: 'synthetic-push', admission: { assertAdmitted: async () => { throw Error('not admitted'); } } }); const count = calls.length; assert.equal((await denied.deliver(intent(v), context)).outcome, 'rejected'); assert.equal(calls.length, count); });

test('env grammar preserves mixed newlines and unrelated multiline entries while supporting literal token punctuation', async () => {
  const f = await fixture();
  try {
    const input = '# mixed\r\nUNRELATED="line one\nAPI_KEY=not-an-assignment\nline three"\r\nAPI_KEY="old\nmultiline"\nLAST=unchanged';
    await writeFile(f.path, input);
    const descriptor = { ...f.d, expectedFileHash: fileDigest(Buffer.from(input)) };
    const token = 'cash$dollar\\slash"quote';
    const store = { async withValue(_handle: string, _version: number, use: (value: string) => Promise<void>) { await use(token); return { status: 'resolved' as const }; } };
    const receipt = await createEnvFileConsumer({ descriptor, roots: { 'fixture-root': f.root }, store, backup: f.vault, trust: trust() }).deliver(intent(descriptor), context);
    assert.equal(receipt.outcome, 'delivery-accepted');
    const output = await readFile(f.path, 'utf8');
    assert.ok(output.startsWith('# mixed\r\nUNRELATED="line one\nAPI_KEY=not-an-assignment\nline three"\r\n'));
    assert.ok(output.endsWith('\nLAST=unchanged'));
    assert.ok(!output.includes('old\nmultiline'));
    const { parseEnv } = await import('node:util'); assert.equal(parseEnv(output).API_KEY, token);
  } finally { await rm(f.root, { recursive: true, force: true }); }
});
test('post-rename failure reports partial delivery and never performs unsigned rollback', async () => {
  const f = await fixture(); let ticks = 0;
  try {
    const receipt = await createEnvFileConsumer({ descriptor: f.d, roots: { 'fixture-root': f.root }, store: f.store, backup: f.vault, trust: { ...trust(), clock: () => { if (++ticks === 1) throw Error('synthetic-secret'); return 100; } } }).deliver(intent(f.d), context);
    assert.equal(receipt.outcome, 'unknown'); assert.ok(receipt.limitationCodes.includes('fresh-rollback-authority-required'));
    assert.notEqual((await readFile(f.path)).toString(), original); assert.ok(!JSON.stringify(receipt).includes('synthetic-secret'));
  } finally { await rm(f.root, { recursive: true, force: true }); }
});
test('exact descriptor substitution and quarantine immediately before rename refuse delivery', async () => {
  const f = await fixture(); let quarantined = false;
  try {
    const substitute = { ...f.d, variable: 'OTHER_KEY' };
    assert.equal((await createEnvFileConsumer({ descriptor: substitute, roots: { 'fixture-root': f.root }, store: f.store, backup: f.vault, trust: trust() }).deliver(intent(f.d), context)).outcome, 'rejected');
    const t: ConsumerTrust = { beforeEffect: async (_i, boundary) => { if (boundary === 'env-temp-write') quarantined = true; }, quarantine: async () => quarantined ? 'quarantined' : 'clear' };
    assert.equal((await createEnvFileConsumer({ descriptor: f.d, roots: { 'fixture-root': f.root }, store: f.store, backup: f.vault, trust: t }).deliver(intent(f.d), context)).outcome, 'rejected');
    assert.equal((await readFile(f.path)).toString(), original);
  } finally { await rm(f.root, { recursive: true, force: true }); }
});
test('remote timeout/redirect/schema confusion never claims delivery or adoption', async () => {
  const d = { ...base, driver: 'vercel' as const, projectId: 'project', teamId: 'team', environment: 'production' as const, variable: 'API_KEY', accountId: 'account', pushTokenFingerprint: credentialFingerprint('synthetic-push') };
  const store = { async withValue(_h: string, _v: number, use: (value: string) => Promise<void>) { await use('synthetic-secret'); return { status: 'resolved' as const }; } };
  for (const mode of ['timeout', 'redirect', 'wrong-project', 'push-failure', 'failed-200'] as const) {
    const transport: typeof fetch = async (_url, request) => {
      if (request?.method === 'GET') return new Response(JSON.stringify({ id: mode === 'wrong-project' ? 'other' : 'project', accountId: 'team' }));
      if (mode === 'timeout') return new Promise(() => {});
      if (mode === 'failed-200') return new Response(JSON.stringify({ created: [], failed: [{ error: 'failure' }] }));
      if (mode === 'redirect') return new Response(null, { status: 307, headers: { Location: 'https://untrusted.invalid' } });
      throw Error('synthetic-secret');
    };
    const c = createVercelConsumer({ descriptor: d, store, trust: trust(), transport, pushToken: 'synthetic-push', admission: { assertAdmitted: async () => {} }, timeoutMs: 10 });
    const receipt = await c.deliver(intent(d), context);
    assert.equal(receipt.outcome, mode === 'wrong-project' ? 'rejected' : 'unknown'); assert.ok(!JSON.stringify(receipt).includes('synthetic-secret'));
  }
});
test('consumer identity, timestamp, method and signature must all verify independently', async () => {
  const keys = generateKeyPairSync('ed25519');
  const observation = { version: 1 as const, consumerIdentity: 'runtime', subject, processId: 'process', deploymentId: 'deployment', jobId: 'job', runId: 'run', observedAt: 100, method: 'authenticated-runtime-use' as const, limitationCodes: [] };
  const signature = sign(null, Buffer.from(canonicalJSON(observation)), keys.privateKey).toString('base64');
  const config = { identities: new Map([['runtime', { consumerId: 'consumer', publicKey: keys.publicKey }]]), clock: () => 100, maxAgeMs: 10 };
  assert.throws(() => verifyConsumerUse({ observation, signature: Buffer.alloc(64).toString('base64') }, subject, config));
  assert.throws(() => verifyConsumerUse({ observation, signature }, subject, { ...config, identities: new Map([['runtime', { consumerId: 'other-consumer', publicKey: keys.publicKey }]]) }));
  assert.throws(() => verifyConsumerUse({ observation, signature }, subject, { ...config, clock: () => 200 }));
  assert.throws(() => verifyConsumerUse({ observation, signature }, subject, { ...config, clock: () => 99 }));
  for (const method of ['generic-health', 'queued-ci', 'callback-import']) {
    const fake = { ...observation, method: method as never }; const sig = sign(null, Buffer.from(canonicalJSON(fake)), keys.privateKey).toString('base64');
    assert.throws(() => verifyConsumerUse({ observation: fake, signature: sig }, subject, config));
  }
});

test('quarantine activated while the authority fence waits prevents destination push', async () => {
  const d = { ...base, driver: 'vercel' as const, projectId: 'project', teamId: 'team', environment: 'production' as const, variable: 'API_KEY', accountId: 'account', pushTokenFingerprint: credentialFingerprint('synthetic-push') };
  let release!: () => void; let entered!: () => void; let quarantined = false; let pushes = 0;
  const fence = new Promise<void>(resolve => { release = resolve; }); const reached = new Promise<void>(resolve => { entered = resolve; });
  const consumer = createVercelConsumer({ descriptor: d, pushToken: 'synthetic-push', admission: { assertAdmitted: async () => {} }, store: { async withValue(_h, _v, use) { await use('synthetic-secret'); return { status: 'resolved' }; } }, trust: { quarantine: async () => quarantined ? 'quarantined' : 'clear', beforeEffect: async () => { entered(); await fence; } }, transport: async (_url, request) => { if (request?.method === 'POST') { pushes++; return new Response(JSON.stringify({ id: 'env_fixture', key: 'API_KEY', type: 'encrypted', target: ['production'] })); } return new Response(JSON.stringify({ id: 'project', accountId: 'team' })); } });
  const pending = consumer.deliver(intent(d), context); await reached; quarantined = true; release(); const result = await pending;
  assert.equal(pushes, 0); assert.equal(result.outcome, 'rejected');
});
