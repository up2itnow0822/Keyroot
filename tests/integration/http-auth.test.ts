import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { startController } from '../../apps/controller/src/server.js';

test('owner metadata requires one-use local exchange and exact origin; read session cannot bootstrap', async t => {
  const directory = await mkdtemp(join(tmpdir(), 'kr-http-'));
  const app = await startController({ directory, port: 0, mode: 'demo' });
  t.after(async () => { await app.close(); await rm(directory, { recursive: true, force: true }); });
  const headers = { Origin: app.origin, 'Content-Type': 'application/json' };
  assert.equal((await fetch(app.origin + '/api/inventory', { headers })).status, 401);
  const code = app.auth.issueExchangeCode();
  const exchange = await fetch(app.origin + '/api/session/exchange', { method: 'POST', headers, body: JSON.stringify({ code }) });
  assert.equal(exchange.status, 200);
  const cookie = exchange.headers.get('set-cookie')!.split(';')[0]!;
  const { csrfToken } = await exchange.json() as { csrfToken: string };
  assert.equal((await fetch(app.origin + '/api/session/exchange', { method: 'POST', headers, body: JSON.stringify({ code }) })).status, 401);
  assert.equal((await fetch(app.origin + '/api/inventory', { headers: { ...headers, Cookie: cookie } })).status, 200);
  assert.equal((await fetch(app.origin + '/api/inventory', { headers: { ...headers, Origin: 'https://evil.invalid', Cookie: cookie } })).status, 403);
  assert.equal((await fetch(app.origin + '/api/approvers', { method: 'POST', headers: { ...headers, Cookie: cookie, 'X-Keyroot-CSRF': csrfToken }, body: '{}' })).status, 404);
  assert.equal((await fetch(app.origin + '/api/batches/prepare', { method: 'POST', headers: { ...headers, Cookie: cookie }, body: '{}' })).status, 403);
});

import { request as httpRequest } from 'node:http';
import { generateKeyPairSync } from 'node:crypto';
import { writeFile } from 'node:fs/promises';
import { validateControllerRow } from '../../apps/controller/src/metadata.js';

test('all owner metadata reads deny unauthenticated access, exact host, stale cookie and non-CSRF writes', async t => {
  let now = Date.now(); const directory = await mkdtemp(join(tmpdir(), 'kr-auth-all-'));
  const app = await startController({ directory, port: 0, mode: 'demo', clock: () => now }); t.after(async () => { await app.close(); await rm(directory, { recursive: true, force: true }); });
  for (const path of ['/api/inventory', '/api/overview', '/api/batches', '/api/batches/unknown', '/api/configurations/sha256:' + 'a'.repeat(64), '/api/schedules', '/api/operations/unknown', '/api/metrics/unknown', '/api/guided/unknown', '/api/owner/pairing/requests/unknown', '/api/owner/emergency/registrations/unknown']) assert.equal((await fetch(app.origin + path)).status, 401, path);
  const status = await new Promise<number>((resolve, reject) => { const req = httpRequest(app.origin + '/api/identity', { headers: { Host: 'evil.invalid' } }, response => { response.resume(); resolve(response.statusCode!); }); req.on('error', reject); req.end(); }); assert.equal(status, 403);
  const demo = await fetch(app.origin + '/api/session/demo', { method: 'POST', headers: { Origin: app.origin } }); const cookie = demo.headers.get('set-cookie')!.split(';')[0]!; const session = await demo.json() as { csrfToken: string };
  for (const path of ['/api/actions/retire', '/api/actions/key-policy', '/api/actions/approver-removal', '/api/actions/oauth-consent', '/api/actions/env-rollback', '/api/actions/platform-discovery']) assert.equal((await fetch(app.origin + path, { method: 'POST', headers: { Origin: app.origin, Cookie: cookie, 'Content-Type': 'application/json', 'X-Keyroot-CSRF': session.csrfToken }, body: '{}' })).status, 400, path);
  now += 600001; assert.equal((await fetch(app.origin + '/api/inventory', { headers: { Cookie: cookie } })).status, 401);
});

test('pairing rejects private fields before trust, wrong comparison and a second controller before boot change', async t => {
  const directory = await mkdtemp(join(tmpdir(), 'kr-pair-empty-')); const app = await startController({ directory, port: 0, mode: 'demo' }); t.after(async () => { await app.close(); await rm(directory, { recursive: true, force: true }); });
  const keys = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  assert.equal((await fetch(app.origin + '/api/pairing/requests', { method: 'POST', headers: { Origin: app.origin, 'Content-Type': 'application/json' }, body: JSON.stringify({ signerId: 'phone', role: 'routine', publicKey: keys.privateKey.export({ format: 'jwk' }) }) })).status, 400);
  const bootId = app.service.journal.bootId; await assert.rejects(startController({ directory, port: 0, mode: 'demo' }), /Singleton/); assert.equal(app.service.journal.bootId, bootId);
});

test('real runtime exposes no public demo session and missing live executor coverage stays unavailable', async t => {
  const directory = await mkdtemp(join(tmpdir(), 'kr-real-http-')); const app = await startController({ directory, port: 0, mode: 'real', phoneOrigin: 'https://phone.fixture.invalid' }); t.after(async () => { await app.close(); await rm(directory, { recursive: true, force: true }); });
  assert.equal((await fetch(app.origin + '/api/session/demo', { method: 'POST', headers: { Origin: app.origin } })).status, 404);
  assert.equal(app.service.overview().liveAdmission, 'unavailable');
  await app.close(); await writeFile(join(directory, 'runtime-mode'), 'demo\n', { mode: 0o600 }); // Even losing the file marker cannot downgrade persisted real journal mode.
  await assert.rejects(startController({ directory, port: 0, mode: 'demo' }), /Real metadata cannot enter demo/);
});

test('recovery controller metadata validators reject authority-shaped and malformed domain rows', () => {
  assert.throws(() => validateControllerRow('controller_inventory', { id: 'inventory', metadata: JSON.stringify({ verified: true }) }));
  assert.throws(() => validateControllerRow('controller_policy', { id: 'lineage', metadata: JSON.stringify({ rotationDays: -1 }) }));
  assert.throws(() => validateControllerRow('controller_policy', { id: 'lineage', metadata: JSON.stringify({ rotationDays: 7, admission: true }) }));
  assert.throws(() => validateControllerRow('controller_guided', { id: 'guide', metadata: JSON.stringify({ recipeId: 'recipe', recipeHash: 'sha256:' + 'a'.repeat(64), accountId: 'account', destinationId: 'vault', stepIndex: 999, completed: true }) }));
});

test('default and explicit demo reject every external port before filesystem, listeners or provider work', async t => {
  const directory = await mkdtemp(join(tmpdir(), 'kr-demo-port-denial-')); t.after(() => rm(directory, { recursive: true, force: true })); let calls = 0;
  const externalPorts = [
    { native: { execute: async () => { calls++; } } },
    { oauth: { refresh: async () => { calls++; throw new Error('unavailable'); }, revoke: async () => { calls++; throw new Error('unavailable'); }, consent: async () => { calls++; throw new Error('unavailable'); }, reconcile: async () => { calls++; return 'unknown' as const; } } },
    { envTargets: [] }, { consumers: {} }, { platforms: [] }, { validity: async () => { calls++; return 'unverified' as const; } }, { recipes: [] }, { native: undefined }, Object.create({ native: { execute: async () => { calls++; } } }),
  ] as import('../../apps/controller/src/service.js').TrustedControllerPorts[];
  for (const mode of [undefined, 'demo'] as const) for (const ports of externalPorts) {
    let unexpected: Awaited<ReturnType<typeof startController>> | undefined;
    await assert.rejects(async () => { unexpected = await startController({ directory: join(directory, 'must-not-exist'), port: 0, phoneOrigin: 'https://phone.fixture.invalid', ...(mode ? { mode } : {}), ports }); }, /Demo runtime rejects external ports/).finally(async () => { await unexpected?.close(); });
  }
  const { access } = await import('node:fs/promises'); await assert.rejects(access(join(directory, 'must-not-exist'))); assert.equal(calls, 0);
});

import { EmergencyEnrollmentController } from '../../apps/controller/src/http/enrollment.js';
import { _generateChallengeInternals, isoCBOR } from '@simplewebauthn/server/helpers';
import { createHash } from 'node:crypto';

test('enrollment reserves all eight creation slots before deferred challenge generation', async t => {
  const enrollment = new EmergencyEnrollmentController('https://phone.fixture.invalid'); let release!: () => void; const blocked = new Promise<void>(resolve => { release = resolve; }); let entered = 0;
  t.mock.method(_generateChallengeInternals, 'stubThis', (bytes: Parameters<typeof _generateChallengeInternals.stubThis>[0]) => { entered++; return blocked.then(() => bytes) as unknown as typeof bytes; });
  const pending = Array.from({ length: 8 }, (_, i) => enrollment.challenge({ signerId: 'emergency-' + i }));
  try { let rejection: unknown; const ninth = enrollment.challenge({ signerId: 'ninth' }); void ninth.catch(error => { rejection = error; }); await Promise.resolve(); await Promise.resolve(); assert.ok(rejection instanceof Error && /enrollment_limit/.test(rejection.message), 'ninth creation must reject before generators resume'); assert.ok(entered <= 8); }
  finally { release(); await Promise.allSettled(pending); }
});

function syntheticRegistrationResponse(registration: { options: { challenge: string } }, i: number) {
  const rpId = 'phone.fixture.invalid'; const keys = generateKeyPairSync('ec', { namedCurve: 'prime256v1' }); const jwk = keys.publicKey.export({ format: 'jwk' });
    const credential = Buffer.from('synthetic-enrollment-' + i); const credentialId = credential.toString('base64url'); const length = Buffer.alloc(2); length.writeUInt16BE(credential.length);
    const cose = isoCBOR.encode(new Map<number, number | Uint8Array>([[1,2],[3,-7],[-1,1],[-2,Buffer.from(jwk.x!,'base64url')],[-3,Buffer.from(jwk.y!,'base64url')]]));
    const authenticator = Buffer.concat([createHash('sha256').update(rpId).digest(),Buffer.from([0x45]),Buffer.alloc(4),Buffer.alloc(16),length,credential,Buffer.from(cose)]);
    const attestation = isoCBOR.encode(new Map<string,string | Map<string,string> | Uint8Array>([['fmt','none'],['attStmt',new Map<string,string>()],['authData',authenticator]]));
    return { id:credentialId,rawId:credentialId,type:'public-key',clientExtensionResults:{},response:{attestationObject:Buffer.from(attestation).toString('base64url'),clientDataJSON:Buffer.from(JSON.stringify({type:'webauthn.create',challenge:registration.options.challenge,origin:'https://phone.fixture.invalid',crossOrigin:false})).toString('base64url'),transports:['usb']} };
}

test('parallel registration verification retains occupancy until failure, expiry or one-time consumption', async t => {
  const enrollment = new EmergencyEnrollmentController('https://phone.fixture.invalid');
  const registrations = await Promise.all(Array.from({ length: 8 }, (_, i) => enrollment.challenge({ signerId: 'emergency-' + i })));
  let release!: () => void; const blocked = new Promise<void>(resolve => { release = resolve; }); const originalDigest = crypto.subtle.digest.bind(crypto.subtle);
  t.mock.method(crypto.subtle,'digest',async (algorithm: Parameters<typeof originalDigest>[0],data: Parameters<typeof originalDigest>[1]) => { await blocked; return originalDigest(algorithm,data); });
  const verifications = registrations.map((registration,i) => enrollment.verify({ requestId:registration.requestId,response:syntheticRegistrationResponse(registration,i) }));
  try {
    await assert.rejects(enrollment.challenge({ signerId:'ninth' }), /enrollment_limit/);
    await assert.rejects(enrollment.verify({ requestId:registrations[0]!.requestId,response:syntheticRegistrationResponse(registrations[0]!,0) }), /enrollment_challenge_expired/);
    await assert.rejects(enrollment.challenge({ signerId:'still-ninth' }), /enrollment_limit/);
  } finally { release(); await Promise.allSettled(verifications); }
  const result = await Promise.all(verifications); assert.equal(result.length,8);
  await assert.rejects(enrollment.challenge({ signerId:'verified-ninth' }), /enrollment_limit/);
  enrollment.consume(registrations[0]!.requestId); assert.ok(await enrollment.challenge({ signerId:'after-consumption' }));
});

import { Journal } from '../../packages/core/src/journal.js';
import { ControllerService, type TrustedControllerPorts } from '../../apps/controller/src/service.js';

test('direct demo construction rejects external ports before controller schema changes and freezes accepted empty composition', async t => {
  let effects = 0; const journal = new Journal(':memory:', { installationId:'direct-demo-test',bootId:'direct-demo-boot' }); t.after(() => journal.close());
  assert.throws(() => new ControllerService(journal,'demo',{ native:{execute:async () => { effects++; }} }),/Demo runtime rejects external ports/);
  assert.equal(journal.read(db => db.prepare("SELECT 1 FROM sqlite_master WHERE name='controller_inventory'").get()),undefined); assert.equal(effects,0);
  const directory = await mkdtemp(join(tmpdir(),'kr-empty-demo-')); const ports: TrustedControllerPorts = {}; const app = await startController({ directory,port:0,mode:'demo',ports }); t.after(async () => { await app.close(); await rm(directory,{recursive:true,force:true}); });
  ports.native = { execute:async () => { effects++; } }; assert.equal(app.service.overview().coverage.native,'unavailable'); assert.equal(effects,0);
});

test('expired in-flight enrollment results never reclaim released slots or resurrect verified records', async t => {
  let now = Date.now(); const enrollment = new EmergencyEnrollmentController('https://phone.fixture.invalid',() => now);
  const registrations = await Promise.all(Array.from({length:8},(_,i) => enrollment.challenge({signerId:'expiring-'+i})));
  let release!: () => void; const blocked = new Promise<void>(resolve => { release=resolve; }); const originalDigest = crypto.subtle.digest.bind(crypto.subtle);
  t.mock.method(crypto.subtle,'digest',async (algorithm: Parameters<typeof originalDigest>[0],data: Parameters<typeof originalDigest>[1]) => { await blocked; return originalDigest(algorithm,data); });
  const verifications = registrations.map((registration,i) => enrollment.verify({requestId:registration.requestId,response:syntheticRegistrationResponse(registration,i)}));
  const results = Promise.allSettled(verifications); now += 60001;
  const replacements = await Promise.all(Array.from({length:8},(_,i) => enrollment.challenge({signerId:'replacement-'+i})));
  release(); assert.ok((await results).every(result => result.status === 'rejected'));
  for (const registration of registrations) assert.throws(() => enrollment.metadata(registration.requestId),/registration_not_found/);
  for (const replacement of replacements) assert.equal(enrollment.metadata(replacement.requestId).status,'pending');
  await assert.rejects(enrollment.challenge({signerId:'ninth-after-old-verification'}),/enrollment_limit/);
  await assert.rejects(enrollment.verify({requestId:replacements[0]!.requestId,response:{}}));
  await assert.rejects(enrollment.verify({requestId:replacements[0]!.requestId,response:{}}),/enrollment_challenge_expired/);
  assert.ok(await enrollment.challenge({signerId:'slot-released-after-failure'}));
});
