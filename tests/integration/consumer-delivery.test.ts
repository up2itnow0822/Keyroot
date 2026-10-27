import test from 'node:test';
import assert from 'node:assert/strict';
import childProcess, { spawn, type ChildProcess, type SpawnOptions } from 'node:child_process';
import { syncBuiltinESMExports } from 'node:module';
import type { Readable, Writable } from 'node:stream';
import { createCipheriv, createDecipheriv, generateKeyPairSync, randomBytes, sign } from 'node:crypto';
import { mkdtemp, readFile, realpath, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { ApprovalService, createLocalBootstrapContext, publicKeyFingerprint } from '../../packages/core/src/approval.js';
import { Journal, type AuthorizedIntent } from '../../packages/core/src/journal.js';
import { canonicalizeManifest, contentDigest, snapshotDigest, deepFreeze, type ApprovalManifest } from '../../packages/core/src/manifest.js';
import { createEnvFileConsumer, fileDigest, type EnvFileDescriptor } from '../../packages/core/src/consumers/env-file.js';
import type { ConsumerDescriptor, ConsumerTrust } from '../../packages/core/src/consumers/consumer.js';
import type { EffectContext } from '../../packages/core/src/engine.js';
import { launchManagedWorkload, type WrapperDescriptor } from '../../packages/core/src/wrapper.js';
const base = { consumerId: 'consumer', destinationId: 'destination', revision: 'revision', consumerMapRevision: 'map', generation: 2, handleId: 'mapped', version: 1, mappingTokenFingerprint: contentDigest('mapped-token') };
const context: EffectContext = { subject: { operationId: 'op', lineageId: 'lineage', accountId: 'account', generation: 2, resourceId: 'resource', handleId: 'mapped', consumerMapRevision: 'map', consumerId: 'consumer', revision: 'revision' }, signal: new AbortController().signal };
function signedAuthority(d: ConsumerDescriptor) {
  const keys = generateKeyPairSync('ec', { namedCurve: 'prime256v1' }); const journal = new Journal(':memory:', { installationId: 'installation', bootId: 'boot' });
  const approvals = new ApprovalService(journal, { mode: 'synthetic', clock: () => 2000 }); const publicKey = keys.publicKey.export({ format: 'jwk' });
  approvals.bootstrapApprover({ signerId: 'phone', role: 'routine', publicKey, localBootstrap: createLocalBootstrapContext(), confirmedFingerprint: publicKeyFingerprint(publicKey) });
  const entries = [{ consumerId: 'consumer', resourceId: 'resource', revision: 'revision' }];
  const m: ApprovalManifest = { version: 1, domain: 'keyroot.approval.v1', algorithm: 'ECDSA-P256-SHA256', audience: 'keyroot-controller', installationId: 'installation', bootId: 'boot', signerId: 'phone', role: 'routine', nonce: 'nonce', notBefore: 1000, expiresAt: 10000, budgets: { executions: 1, effects: 1, restarts: 0, newCredentials: 0 }, operations: [{ operationId: 'op', lineageId: 'lineage', accountId: 'account', fromGeneration: 1, toGeneration: 2, actions: [{ id: 'deliver', kind: 'deliver', parameters: { consumerId: d.consumerId, destinationId: d.destinationId, handleId: d.handleId, generation: d.generation, expectedRevision: d.revision, configurationHash: contentDigest(d) }, budgetCost: { effects: 1, newCredentials: 0, restarts: 0 } }] }], consumerMap: { revision: 'map', hash: contentDigest(entries), entries }, recipes: [], adoptionThreshold: 'direct-use-every-consumer', overlapPolicy: 'required', deadline: { at: 9000, outcome: 'hold' }, outage: { permitted: false, consequence: 'none' }, graceSeconds: 900 };
  const raw = canonicalizeManifest(m); const signature = sign('sha256', Buffer.from(raw), { key: keys.privateKey, dsaEncoding: 'ieee-p1363' }).toString('base64url'); approvals.registerGrant(raw, signature, 2000);
  const request = { grantId: 'nonce', signature, operationId: 'op', actionId: 'deliver', currentSnapshotDigest: snapshotDigest(m), now: 2000 };
  const trust: ConsumerTrust = { quarantine: async () => 'clear', beforeEffect: async intent => { await approvals.assertReservedIntentAuthority({ ...request, intentId: intent.intentId }); } };
  return { journal, approvals, trust, authorize: () => approvals.authorizeEffect(request) };
}
function encryptedVault() {
  const key = randomBytes(32); let stored: Buffer | undefined; let nonce: Buffer | undefined; let tag: Buffer | undefined;
  return { get ciphertext() { return stored; }, async write(handle: string, version: number, value: string) { assert.equal(handle, 'backup'); assert.equal(version, 0); nonce = randomBytes(12); const cipher = createCipheriv('aes-256-gcm', key, nonce); stored = Buffer.concat([cipher.update(value), cipher.final()]); tag = cipher.getAuthTag(); return { status: 'written' as const, version: 1 }; }, async withValue(handle: string, version: number, use: (value: string) => Promise<void>) { assert.equal(handle, 'backup'); assert.equal(version, 1); assert.ok(stored && nonce && tag); const decipher = createDecipheriv('aes-256-gcm', key, nonce); decipher.setAuthTag(tag); const clear = Buffer.concat([decipher.update(stored), decipher.final()]); try { await use(clear.toString()); } finally { clear.fill(0); } return { status: 'resolved' as const }; } };
}
test('actual atomic file delivery + encrypted-vault rollback uses fresh signed U3 authority; cancellation preserves original', async () => {
  const root = await realpath(await mkdtemp(join(tmpdir(), 'keyroot-delivery-integration-'))); const path = join(root, '.env'); const original = Buffer.from('# fixture\nUNRELATED=unchanged\nAPI_KEY=old\n'); const vault = encryptedVault();
  const store = { async withValue(h: string, v: number, use: (value: string) => Promise<void>) { assert.equal(h, 'mapped'); assert.equal(v, 1); await use('synthetic-replacement'); return { status: 'resolved' as const }; } };
  const d: EnvFileDescriptor = { ...base, driver: 'env-file', envFormat: 'node-env', mode: 'deliver', rootId: 'fixture', relativePath: '.env', variable: 'API_KEY', expectedFileHash: fileDigest(original), backupHandle: 'backup', backupExpectedVersion: 0, backupVersion: 1 };
  let authority = signedAuthority(d);
  try {
    await writeFile(path, original);
    let intent = await authority.authorize();
    const failTrust: ConsumerTrust = { ...authority.trust, beforeEffect: async (i, boundary) => { if (boundary === 'env-rename') authority.approvals.cancelGrant('nonce'); await authority.trust.beforeEffect(i, boundary); } };
    const failed = await createEnvFileConsumer({ descriptor: d, roots: { fixture: root }, store, backup: vault, trust: failTrust }).deliver(intent, context);
    assert.equal(failed.outcome, 'rejected'); assert.deepEqual(await readFile(path), original); assert.ok(vault.ciphertext); assert.ok(!vault.ciphertext.includes(original));
    authority.journal.close(); authority = signedAuthority(d); intent = await authority.authorize();
    const delivered = await createEnvFileConsumer({ descriptor: d, roots: { fixture: root }, store, backup: vault, trust: authority.trust }).deliver(intent, context);
    assert.equal(delivered.outcome, 'delivery-accepted'); const updated = await readFile(path); assert.match(updated.toString(), /UNRELATED=unchanged/);
    const rollback: EnvFileDescriptor = { ...d, mode: 'rollback', expectedFileHash: fileDigest(updated), backupFileHash: fileDigest(original) };
    assert.equal((await createEnvFileConsumer({ descriptor: rollback, roots: { fixture: root }, store, backup: vault, trust: authority.trust }).deliver(intent, context)).outcome, 'rejected');
    authority.journal.close(); authority = signedAuthority(rollback); intent = await authority.authorize();
    const restored = await createEnvFileConsumer({ descriptor: rollback, roots: { fixture: root }, store, backup: vault, trust: authority.trust }).deliver(intent, context); assert.equal(restored.outcome, 'unknown'); assert.ok(restored.limitationCodes.includes('authorized-rollback-applied')); assert.ok(restored.limitationCodes.includes('backup')); assert.ok(restored.limitationCodes.includes('restored-backup-version:1')); assert.ok(restored.limitationCodes.includes('successor-delivery-unverified'));
    assert.deepEqual(await readFile(path), original);
  } finally { authority.journal.close(); await rm(root, { recursive: true, force: true }); }
});
async function eventually<T>(check: () => Promise<T | undefined>, timeoutMs = 5000): Promise<T> { const until = Date.now() + timeoutMs; while (Date.now() < until) { const result = await check(); if (result !== undefined) return result; await new Promise(resolve => setTimeout(resolve, 20)); } throw Error('Fixture observation timed out'); }
function alive(pid: number): boolean { try { process.kill(pid, 0); return true; } catch { return false; } }
async function gone(pid: number) { await eventually(async () => alive(pid) ? undefined : true); }
async function pids(path: string): Promise<{ child: number; grandchild: number }> { return eventually(async () => { try { return JSON.parse(await readFile(path, 'utf8')) as { child: number; grandchild: number }; } catch { return undefined; } }); }
function cleanup(pid: number | undefined, group = false) { if (pid) { try { process.kill(group ? -pid : pid, 'SIGKILL'); } catch { /* Only fixture-owned processes. */ } } }
const treeScript = `const {spawn}=require('node:child_process');const fs=require('node:fs');const child=spawn(process.execPath,['-e', 'process.on("SIGTERM",()=>{});setInterval(()=>{},1000)'],{stdio:'ignore'});fs.writeFileSync(process.argv[1],JSON.stringify({child:process.pid,grandchild:child.pid}));setInterval(()=>{},1000);`;
function wrapper(path: string, expiry: number): WrapperDescriptor { return { ...base, driver: 'wrapper', workloadId: 'fixture-tree', variable: 'API_KEY', command: process.execPath, args: ['-e', treeScript, path], environmentKeys: [], graceSeconds: 900, issuerExpiresAt: expiry }; }

test('actual managed child + TERM-resistant grandchild terminate at issuer expiry', async () => { const root = await mkdtemp(join(tmpdir(), 'keyroot-process-expiry-')); const d = wrapper(join(root, 'pids'), Date.now() + 700); const authority = signedAuthority(d); const unmanaged = spawn(process.execPath, ['-e', 'setInterval(()=>{},1000)'], { env: { API_KEY: 'synthetic-unmanaged-copy' }, stdio: 'ignore', detached: true }); let child: number | undefined; let supervisor: number | undefined; try { const managed = await launchManagedWorkload({ descriptor: d, intent: await authority.authorize(), context, store: { async withValue(_h, _v, use) { await use('synthetic-process-secret'); return { status: 'resolved' }; } }, trust: authority.trust, heartbeat: { assertHealthy: async () => {} } }); child = managed.childPid; supervisor = managed.supervisorPid; const tree = await pids(join(root, 'pids')); assert.equal(tree.child, child); assert.equal(await managed.exited, 'issuer-expired'); await gone(tree.child); await gone(tree.grandchild); await gone(managed.supervisorPid); assert.ok(unmanaged.pid && alive(unmanaged.pid)); assert.ok(managed.receipt.limitationCodes.includes('unmanaged-copies-uncontrolled')); } finally { cleanup(unmanaged.pid, true); await new Promise<void>(resolve => { if (unmanaged.exitCode !== null || unmanaged.signalCode !== null) resolve(); else unmanaged.once('exit', () => resolve()); }); cleanup(child, true); cleanup(supervisor); authority.journal.close(); await rm(root, { recursive: true, force: true }); } });

test('independent supervisor survives SIGKILL launcher loss long enough to terminate the real process group', async () => {
  const root = await mkdtemp(join(tmpdir(), 'keyroot-launcher-loss-')); const file = join(root, 'pids'); const ready = join(root, 'ready'); const d = wrapper(file, Date.now() + 60000);
  const parameters = { consumerId: d.consumerId, destinationId: d.destinationId, handleId: d.handleId, generation: d.generation, expectedRevision: d.revision, configurationHash: contentDigest(d) };
  const intent: AuthorizedIntent = deepFreeze({ intentId: 'intent', idempotencyRef: 'idem', operationId: 'op', actionId: 'deliver', grantId: 'grant', kind: 'deliver', state: 'pending', parameters });
  const source = `import{launchManagedWorkload}from${JSON.stringify(new URL('../../packages/core/src/wrapper.ts', import.meta.url).href)};import{deepFreeze}from${JSON.stringify(new URL('../../packages/core/src/manifest.ts', import.meta.url).href)};import{writeFileSync}from'node:fs';const d=${JSON.stringify(d)};const m=await launchManagedWorkload({descriptor:d,intent:deepFreeze(${JSON.stringify(intent)}),context:{subject:${JSON.stringify(context.subject)},signal:new AbortController().signal},store:{async withValue(h,v,use){await use('synthetic-secret');return{status:'resolved'}}},trust:{beforeEffect:async()=>{},quarantine:async()=>'clear'},heartbeat:{assertHealthy:async()=>{}}});writeFileSync(${JSON.stringify(ready)},JSON.stringify({supervisor:m.supervisorPid,child:m.childPid}));await m.exited;`;
  const launcher = spawn(process.execPath, ['--import', 'tsx', '--input-type=module', '-e', source], { stdio: 'ignore', env: {}, detached: true }); let managed: { supervisor: number; child: number } | undefined;
  try { managed = await eventually(async () => { try { return JSON.parse(await readFile(ready, 'utf8')) as typeof managed; } catch { return undefined; } }); assert.ok(managed); const tree = await pids(file); assert.ok(alive(managed.supervisor)); launcher.kill('SIGKILL'); await gone(tree.child); await gone(tree.grandchild); await gone(managed.supervisor); } finally { cleanup(launcher.pid, true); cleanup(managed?.child, true); cleanup(managed?.supervisor); await rm(root, { recursive: true, force: true }); }
});

test('closed launcher FD and supervisor SIGHUP/SIGQUIT/TERM clean managed groups', async () => {
  const root = await mkdtemp(join(tmpdir(), 'keyroot-signal-cleanup-'));
  try { for (const signal of ['fd-close', 'SIGHUP', 'SIGQUIT', 'SIGTERM'] as const) { const d = wrapper(join(root, signal), Date.now() + 60000); const authority = signedAuthority(d); let child: number | undefined; let supervisor: number | undefined; try { const m = await launchManagedWorkload({ descriptor: d, intent: await authority.authorize(), context, store: { async withValue(_h, _v, use) { await use('synthetic-secret'); return { status: 'resolved' }; } }, trust: authority.trust, heartbeat: { assertHealthy: async () => {} } }); child = m.childPid; supervisor = m.supervisorPid; const tree = await pids(join(root, signal)); if (signal === 'fd-close') m.releaseLauncher(); else process.kill(m.supervisorPid, signal); await m.exited; await gone(tree.child); await gone(tree.grandchild); await gone(m.supervisorPid); } finally { cleanup(child, true); cleanup(supervisor); authority.journal.close(); } } } finally { await rm(root, { recursive: true, force: true }); }
});

test('launcher cleans the known group after supervisor SIGKILL, including TERM-resistant grandchild', async () => {
  const root = await mkdtemp(join(tmpdir(), 'keyroot-supervisor-loss-')); const d = wrapper(join(root, 'pids'), Date.now() + 60000); const authority = signedAuthority(d);
  let child: number | undefined; let supervisor: number | undefined;
  try {
    const m = await launchManagedWorkload({ descriptor: d, intent: await authority.authorize(), context, store: { async withValue(_h, _v, use) { await use('synthetic-secret'); return { status: 'resolved' }; } }, trust: authority.trust, heartbeat: { assertHealthy: async () => {} } }); child = m.childPid; supervisor = m.supervisorPid;
    const tree = await pids(join(root, 'pids')); process.kill(m.supervisorPid, 'SIGKILL'); assert.equal(await m.exited, 'supervisor-lost');
    await gone(tree.child); await gone(tree.grandchild); await gone(m.supervisorPid);
  } finally { cleanup(child, true); cleanup(supervisor); authority.journal.close(); await rm(root, { recursive: true, force: true }); }
});


test('abort after await use but before store resolution cleans the actual child and grandchild', async () => {
  const root = await mkdtemp(join(tmpdir(), 'keyroot-startup-abort-')); const d = wrapper(join(root, 'pids'), Date.now() + 60000); const authority = signedAuthority(d); const controller = new AbortController();
  let tree: { child: number; grandchild: number } | undefined;
  try {
    await assert.rejects(launchManagedWorkload({ descriptor: d, intent: await authority.authorize(), context: { ...context, signal: controller.signal }, store: { async withValue(_h, _v, use) { await use('synthetic-secret'); tree = await pids(join(root, 'pids')); controller.abort(); return { status: 'resolved' }; } }, trust: authority.trust, heartbeat: { assertHealthy: async () => {} } }), /Managed workload refused/);
    assert.ok(tree); await gone(tree.child); await gone(tree.grandchild);
  } finally { cleanup(tree?.child, true); authority.journal.close(); await rm(root, { recursive: true, force: true }); }
});

for (const failure of ['abort-before-ready', 'supervisor-killed-before-commit', 'supervisor-killed-before-pid-report'] as const) {
  test(`startup PGID handshake fails closed: ${failure}`, async t => {
    const root = await mkdtemp(join(tmpdir(), 'keyroot-startup-handshake-')); const file = join(root, 'pids'); const d = wrapper(file, Date.now() + 60000); const authority = signedAuthority(d); const controller = new AbortController();
    let managedPid: number | undefined; let supervisorPid: number | undefined;
    const originalSpawn = childProcess.spawn;
    t.mock.method(childProcess, 'spawn', (command: string, args: readonly string[], options: SpawnOptions): ChildProcess => {
      const child = originalSpawn(command, args, options);
      if (command === process.execPath && args[0] === '-e' && args[1]?.includes('const gateSource=')) {
        supervisorPid = child.pid;
        if (failure === 'supervisor-killed-before-pid-report') {
          const output = child.stdio[4] as Readable; const emit = output.emit.bind(output);
          t.mock.method(output, 'emit', (event: string | symbol, ...events: unknown[]) => {
            if (event === 'data') {
              const message = JSON.parse(String(events[0])) as { type: string; pid?: number };
              if (message.type === 'prepared') { managedPid = message.pid; child.kill('SIGKILL'); return true; }
            }
            return emit(event, ...events);
          });
        }
        const input = child.stdio[3] as Writable; const write = input.write.bind(input);
        t.mock.method(input, 'write', (chunk: string) => {
          const message = JSON.parse(chunk) as { type: string; pid?: number };
          if (message.type === 'commit') {
            managedPid = message.pid;
            if (failure === 'abort-before-ready') controller.abort(); else child.kill('SIGKILL');
            return true;
          }
          return write(chunk);
        });
      }
      return child;
    });
    syncBuiltinESMExports();
    try {
      await assert.rejects(launchManagedWorkload({ descriptor: d, intent: await authority.authorize(), context: { ...context, signal: controller.signal }, store: { async withValue(_h, _v, use) { await use('synthetic-secret'); return { status: 'resolved' }; } }, trust: authority.trust, heartbeat: { assertHealthy: async () => {} } }), /Managed workload refused/);
      assert.ok(managedPid && supervisorPid); await gone(managedPid); await gone(supervisorPid);
      await assert.rejects(readFile(file), { code: 'ENOENT' });
    } finally { t.mock.restoreAll(); syncBuiltinESMExports(); cleanup(managedPid, true); cleanup(supervisorPid); authority.journal.close(); await rm(root, { recursive: true, force: true }); }
  });
}
