import { test } from 'node:test';
import assert from 'node:assert/strict';
import { webcrypto, createPublicKey, verify } from 'node:crypto';
import { generatePhoneKey, fingerprint, signBytes, base64url } from '../../apps/review/src/phone/signing.js';
import { publicKeyFingerprint } from '../../packages/core/src/approval.js';

test('phone key is nonextractable and signatures interoperate with Node', async () => {
  const key = await generatePhoneKey(webcrypto as Crypto);
  assert.equal(key.privateKey.extractable, false);
  await assert.rejects(webcrypto.subtle.exportKey('pkcs8', key.privateKey));
  const jwk = await webcrypto.subtle.exportKey('jwk', key.publicKey);
  assert.equal(await fingerprint(key.publicKey, webcrypto as Crypto), publicKeyFingerprint(jwk));
  const bytes = new TextEncoder().encode('synthetic');
  const signature = await signBytes(key.privateKey, bytes, webcrypto as Crypto);
  assert.equal(Buffer.from(signature, 'base64url').length, 64);
  assert.ok(verify('sha256', bytes, { key: createPublicKey({ key: jwk as import('node:crypto').JsonWebKey, format: 'jwk' }), dsaEncoding: 'ieee-p1363' }, Buffer.from(signature, 'base64url')));
  assert.equal(base64url(new Uint8Array([255, 254])), '__4');
});

import { canonicalJSON } from '../../apps/review/src/phone/manifest.js';
import { contentHash, manifestDigest, parseManifest, validateReview, verifyDescriptor } from '../../apps/review/src/phone/signing.js';

test('canonical review rejects duplicate fields, unknown fields, drift, expiry, and absent independent trust', async () => {
  const map: never[] = [];
  const value = { version: 1, domain: 'keyroot.approval.v1', algorithm: 'ECDSA-P256-SHA256', audience: 'keyroot-controller', installationId: 'install', bootId: 'boot', signerId: 'phone', role: 'routine', nonce: 'nonce', notBefore: 1, expiresAt: 1000, budgets: { effects: 1, newCredentials: 0, restarts: 0, executions: 1 }, operations: [{ operationId: 'op', lineageId: 'line', accountId: 'account', fromGeneration: 1, toGeneration: 2, actions: [{ id: 'a', kind: 'disable', parameters: { resourceId: 'resource' }, budgetCost: { effects: 1, newCredentials: 0, restarts: 0 } }] }], consumerMap: { revision: 'r1', hash: await contentHash(map), entries: map }, recipes: [], adoptionThreshold: 'direct-use-every-consumer', overlapPolicy: 'required', deadline: { at: 900, outcome: 'hold' }, outage: { permitted: false, consequence: 'none' }, graceSeconds: 0 };
  const raw = canonicalJSON(value); const digest = await manifestDigest(raw);
  assert.equal((await parseManifest(raw)).nonce, 'nonce');
  await assert.rejects(parseManifest(raw.replace('"version":1', '"version":1,"version":1')));
  await assert.rejects(parseManifest(canonicalJSON({ ...value, unknown: true })));
  const descriptor = { scopes: ['read'], ttl: 60 }; const hash = await contentHash(descriptor);
  await verifyDescriptor(hash, descriptor); await assert.rejects(verifyDescriptor(hash, { ...descriptor, ttl: 61 }));
  const guard = { origin: 'https://phone.example', controllerOrigin: 'https://controller.example', pinnedFingerprint: 'sha256:pin', actualFingerprint: 'sha256:pin', reviewedBundle: true, demo: false, expectedDigest: digest, now: 10 };
  await validateReview(raw, guard);
  await assert.rejects(validateReview(raw, { ...guard, now: 1000 }));
  await assert.rejects(validateReview(raw, { ...guard, expectedDigest: 'wrong' }));
  await assert.rejects(validateReview(raw, { ...guard, actualFingerprint: 'wrong' }));
  await assert.rejects(validateReview(raw, { ...guard, origin: guard.controllerOrigin }));
  await assert.rejects(validateReview(raw, { ...guard, reviewedBundle: false }));
});

import { canonicalizeManifest, parseCanonicalManifest, contentDigest, type ApprovalManifest } from '../../packages/core/src/manifest.js';
import { Journal } from '../../packages/core/src/journal.js';
import { ApprovalService, createLocalBootstrapContext } from '../../packages/core/src/approval.js';
import { validateKeyPair } from '../../apps/review/src/phone/pairing.js';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

function coreFixture(): ApprovalManifest {
  const entries = [{ consumerId: 'consumer', resourceId: 'resource', revision: 'r1' }];
  return { version: 1, domain: 'keyroot.approval.v1', algorithm: 'ECDSA-P256-SHA256', audience: 'keyroot-controller', installationId: 'installation', bootId: 'boot', signerId: 'phone', role: 'routine', nonce: 'nonce', notBefore: 1000, expiresAt: 10000, budgets: { effects: 1, newCredentials: 0, restarts: 0, executions: 1 }, operations: [{ operationId: 'op', lineageId: 'lineage', accountId: 'account', fromGeneration: 1, toGeneration: 2, actions: [{ id: 'action', kind: 'disable', parameters: { resourceId: 'resource', configurationHash: contentDigest({ scopes: ['read'], ttl: 60 }) }, budgetCost: { effects: 1, newCredentials: 0, restarts: 0 } }] }], consumerMap: { revision: 'r1', entries, hash: contentDigest(entries) }, recipes: [{ id: 'recipe', version: '1', steps: [{ action: 'disable', resourceId: 'resource' }], hash: contentDigest([{ action: 'disable', resourceId: 'resource' }]) }], adoptionThreshold: 'direct-use-every-consumer', overlapPolicy: 'required', deadline: { at: 9000, outcome: 'hold' }, outage: { permitted: false, consequence: 'none' }, graceSeconds: 30 };
}
test('browser parser agrees with core across valid and invalid signed scope', async () => {
  const valid = coreFixture();
  for (const m of [valid, { ...valid, role: 'emergency' as const }, { ...valid, recipes: [] }]) {
    const raw = canonicalizeManifest(m); assert.deepEqual(await parseManifest(raw), parseCanonicalManifest(raw));
  }
  const mutated = (fn: (m: ApprovalManifest) => void) => { const m = structuredClone(valid); fn(m); return canonicalJSON(m); };
  const raw = canonicalizeManifest(valid);
  const cases = [raw.replace('"version":1', '"version":1,"version":1'), mutated(m => { (m as unknown as Record<string, unknown>).extra = true; }), mutated(m => { m.role = 'other' as 'routine'; }), mutated(m => { m.operations[0]!.actions[0]!.budgetCost.effects = 0; }), mutated(m => { m.consumerMap.hash = 'bad'; }), mutated(m => { m.recipes[0]!.hash = 'bad'; }), mutated(m => { m.operations[0]!.toGeneration = 4; }), mutated(m => { m.operations[0]!.fromGeneration = Number.MAX_SAFE_INTEGER + 1; }), mutated(m => { delete m.operations[0]!.actions[0]!.parameters.resourceId; }), mutated(m => { m.operations[0]!.actions[0]!.parameters.configurationHash = 'sha256:bad'; })];
  for (const invalid of cases) { assert.throws(() => parseCanonicalManifest(invalid)); await assert.rejects(parseManifest(invalid)); }
});
test('browser signature registers with actual core approval service', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'phone-approval-')); const journal = new Journal(join(dir, 'journal.sqlite'), { installationId: 'installation', bootId: 'boot' });
  try {
    const key = await generatePhoneKey(); const publicKey = await crypto.subtle.exportKey('jwk', key.publicKey);
    const approval = new ApprovalService(journal, { mode: 'synthetic', clock: () => 2000 });
    approval.bootstrapApprover({ signerId: 'phone', role: 'routine', publicKey, localBootstrap: createLocalBootstrapContext(), confirmedFingerprint: await fingerprint(key.publicKey) });
    const raw = canonicalizeManifest(coreFixture()); const signature = await signBytes(key.privateKey, new TextEncoder().encode(raw));
    assert.equal(approval.registerGrant(raw, signature, 2000), 'nonce');
    assert.throws(() => approval.registerGrant(raw.replace('"account"', '"another"'), signature, 2000));
  } finally { journal.close(); rmSync(dir, { recursive: true, force: true }); }
});
test('stored key mismatch and extractable private key fail validation', async () => {
  const first = await generatePhoneKey(); const second = await generatePhoneKey();
  await validateKeyPair(first);
  await assert.rejects(validateKeyPair({ privateKey: first.privateKey, publicKey: second.publicKey }));
  const extractable = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
  await assert.rejects(validateKeyPair(extractable));
});

import { read, approve, type Batch } from '../../apps/review/src/phone/client.js';
test('authenticated reads reject a mismatched nonce, forged response and expired response', async () => {
  const phone = await generatePhoneKey(); const controllerKeys = await generatePhoneKey();
  const controller = { data: { installationId: 'installation', bootId: 'boot', publicKey: await crypto.subtle.exportKey('jwk', controllerKeys.publicKey), fingerprint: await fingerprint(controllerKeys.publicKey), mode: 'demo' }, key: controllerKeys.publicKey };
  const originalFetch = globalThis.fetch; const originalNow = Date.now; let variant = 'valid';
  const expiresAt = Date.now() + 30000; const path = '/api/batches';
  globalThis.fetch = async (input) => {
    const url = String(input);
    if (url.endsWith('/api/phone/challenge')) return Response.json({ nonce: 'nonce', installationId: 'installation', signerId: 'phone', method: 'GET', path, expiresAt });
    if (variant === 'late') Date.now = () => expiresAt + 1;
    const payload = { requestNonce: variant === 'nonce' ? 'other' : 'nonce', method: 'GET', path, installationId: 'installation', expiresAt: variant === 'expired' ? 1 : expiresAt, data: { batches: [] } };
    const signature = await signBytes(variant === 'forged' ? phone.privateKey : controllerKeys.privateKey, new TextEncoder().encode('keyroot.controller-response.v1\0' + canonicalJSON(payload)));
    return Response.json({ payload, signature });
  };
  try {
    assert.deepEqual(await read(path, 'phone', phone, controller), { batches: [] });
    for (variant of ['nonce', 'forged', 'expired', 'late']) await assert.rejects(read(path, 'phone', phone, controller));
  } finally { globalThis.fetch = originalFetch; Date.now = originalNow; }
});
test('changed batch is refused before approval dispatch', async () => {
  const phone = await generatePhoneKey(); const controllerKeys = await generatePhoneKey();
  const controller = { data: { installationId: 'installation', bootId: 'boot', publicKey: await crypto.subtle.exportKey('jwk', controllerKeys.publicKey), fingerprint: await fingerprint(controllerKeys.publicKey), mode: 'demo' }, key: controllerKeys.publicKey };
  const raw = canonicalizeManifest(coreFixture()); const batch: Batch = { batchId: 'batch', rawManifest: raw, digest: await manifestDigest(raw), configurationHashes: [] };
  const originalFetch = globalThis.fetch; const expiresAt = Date.now() + 30000; const path = '/api/batches/batch'; let posted = false;
  globalThis.fetch = async input => {
    const url = String(input); if (url.endsWith('/api/approvals')) { posted = true; throw new Error('unexpected approval'); }
    if (url.endsWith('/api/phone/challenge')) return Response.json({ nonce: 'nonce', installationId: 'installation', signerId: 'phone', method: 'GET', path, expiresAt });
    const payload = { requestNonce: 'nonce', method: 'GET', path, installationId: 'installation', expiresAt, data: { ...batch, rawManifest: raw.replace('"account"', '"different"') } };
    return Response.json({ payload, signature: await signBytes(controllerKeys.privateKey, new TextEncoder().encode('keyroot.controller-response.v1\0' + canonicalJSON(payload))) });
  };
  try { await assert.rejects(approve(batch, 'phone', phone, controller), /changed/); assert.equal(posted, false); } finally { globalThis.fetch = originalFetch; }
});

import { EmergencyWebAuthn } from '../../packages/core/src/emergency-webauthn.js';
import { isoCBOR } from '@simplewebauthn/server/helpers';
import { emergencyProof, requestPairing } from '../../apps/review/src/phone/client.js';
test('pairing proof signs controller challenge before local confirmation', async () => {
  const phone = await generatePhoneKey(); const controllerKey = await generatePhoneKey();
  const controller = { data: { installationId: 'installation', bootId: 'boot', publicKey: await crypto.subtle.exportKey('jwk', controllerKey.publicKey), fingerprint: await fingerprint(controllerKey.publicKey), mode: 'demo' }, key: controllerKey.publicKey };
  const publicKey = await crypto.subtle.exportKey('jwk', phone.publicKey); const phoneFingerprint = await fingerprint(phone.publicKey); const expiresAt = Date.now() + 30000;
  const challenge = { requestId: 'request', nonce: 'random', installationId: 'installation', signerId: 'phone', fingerprint: phoneFingerprint, expiresAt }; const originalFetch = globalThis.fetch; let proofSent = false;
  globalThis.fetch = async (input, init) => {
    if (String(input).endsWith('/proof')) {
      const body = JSON.parse(String(init?.body)) as { signature: string }; const signature = Buffer.from(body.signature, 'base64url');
      assert.ok(verify('sha256', Buffer.from('keyroot.pairing-possession.v1\0' + canonicalJSON(challenge)), { key: createPublicKey({ key: publicKey as import('node:crypto').JsonWebKey, format: 'jwk' }), dsaEncoding: 'ieee-p1363' }, signature));
      proofSent = true; return Response.json({ status: 'proved' });
    }
    return Response.json({ requestId: 'request', fingerprint: phoneFingerprint, expiresAt, challenge });
  };
  try { await requestPairing('phone', phone, controller); assert.equal(proofSent, true); } finally { globalThis.fetch = originalFetch; }
});
test('emergency gesture accepts core-issued exact binding and rejects altered intent before authenticator', async () => {
  const originalFetch = globalThis.fetch; const navigatorDescriptor = Object.getOwnPropertyDescriptor(globalThis, 'navigator'); const assertionDescriptor = Object.getOwnPropertyDescriptor(globalThis, 'AuthenticatorAssertionResponse');
  const dir = mkdtempSync(join(tmpdir(), 'phone-emergency-')); const journal = new Journal(join(dir, 'journal.sqlite'), { installationId: 'installation', bootId: 'boot' });
  const key = await generatePhoneKey(); const publicKey = await crypto.subtle.exportKey('jwk', key.publicKey); const cose = isoCBOR.encode(new Map<number, number | Uint8Array>([[1, 2], [3, -7], [-1, 1], [-2, Buffer.from(publicKey.x!, 'base64url')], [-3, Buffer.from(publicKey.y!, 'base64url')]]));
  const now = Date.now(); const emergency = new EmergencyWebAuthn(journal, { clock: () => now });
  emergency.bootstrapCredential({ signerId: 'hardware', credentialId: 'Bw', cosePublicKey: cose, rpId: 'localhost', origin: 'https://localhost', localBootstrap: createLocalBootstrapContext(), confirmedFingerprint: publicKeyFingerprint(publicKey) });
  const fixture = coreFixture(); fixture.role = 'emergency'; fixture.signerId = 'hardware'; fixture.notBefore = now - 100; fixture.expiresAt = now + 120000; fixture.deadline.at = now + 60000;
  const raw = canonicalizeManifest(fixture); const batch = { batchId: 'batch', rawManifest: raw, digest: await manifestDigest(raw), configurationHashes: [] };
  new ApprovalService(journal, { mode: 'synthetic', clock: () => now }).registerEmergencyGrant(raw, now);
  const issued = emergency.createChallenge({ grantId: 'nonce', operationId: 'op', actionId: 'action', now });
  class Assertion { authenticatorData = new Uint8Array([1, 2]).buffer; clientDataJSON = new Uint8Array([3]).buffer; signature = new Uint8Array([4]).buffer; userHandle = null; }
  Object.defineProperty(globalThis, 'AuthenticatorAssertionResponse', { configurable: true, value: Assertion });
  let gestures = 0; Object.defineProperty(globalThis, 'navigator', { configurable: true, value: { credentials: { get: async (options: CredentialRequestOptions) => { gestures++; assert.deepEqual(Buffer.from(options.publicKey!.challenge as ArrayBuffer), Buffer.from(issued.challenge, 'base64url')); assert.deepEqual([...new Uint8Array(options.publicKey!.allowCredentials![0]!.id as ArrayBuffer)], [7]); return { id: 'Bw', rawId: new Uint8Array([7]).buffer, type: 'public-key', authenticatorAttachment: 'cross-platform', getClientExtensionResults: () => ({}), response: new Assertion() }; } } } });
  let responseChallenge: unknown = issued; let assertions = 0;
  globalThis.fetch = async (input, init) => {
    if (String(input).endsWith('/challenge')) return Response.json(responseChallenge);
    const body = JSON.parse(String(init?.body)) as { challengeId: string; operationId: string; actionId: string; response: { rawId: string; response: { authenticatorData: string; signature: string } } };
    assert.equal(body.challengeId, issued.challengeId); assert.equal(body.operationId, 'op'); assert.equal(body.actionId, 'action'); assert.equal(body.response.rawId, 'Bw'); assert.equal(body.response.response.authenticatorData, 'AQI'); assert.equal(body.response.response.signature, 'BA'); assertions++; return Response.json({ proofId: 'proof' });
  };
  try {
    const forged = (patch: Record<string, unknown>) => { const binding = { ...issued.binding, ...patch }; return { ...issued, binding, challenge: Buffer.from(contentDigest(binding)).toString('base64url') }; };
    for (const bad of [{ ...issued, challenge: 'BQY' }, { ...issued, binding: { ...issued.binding, nonce: base64url(new Uint8Array(32)) } }, forged({ digest: 'sha256:' + '0'.repeat(64) }), forged({ actionId: 'other' }), forged({ operationId: 'other' }), forged({ nonce: 'invalid' }), forged({ domain: 'other' }), forged({ extra: true }), { ...issued, expiresAt: Number.MAX_SAFE_INTEGER }]) { responseChallenge = bad; await assert.rejects(emergencyProof(batch, 'nonce', 'op', 'action')); assert.equal(gestures, 0); }
    await assert.rejects(emergencyProof(batch, 'nonce', 'op', 'other')); assert.equal(gestures, 0);
    responseChallenge = issued; assert.equal((await emergencyProof(batch, 'nonce', 'op', 'action')).id, 'proof'); assert.equal(gestures, 1); assert.equal(assertions, 1);
  } finally {
    globalThis.fetch = originalFetch; journal.close(); rmSync(dir, { recursive: true, force: true });
    if (navigatorDescriptor) Object.defineProperty(globalThis, 'navigator', navigatorDescriptor); else Reflect.deleteProperty(globalThis, 'navigator');
    if (assertionDescriptor) Object.defineProperty(globalThis, 'AuthenticatorAssertionResponse', assertionDescriptor); else Reflect.deleteProperty(globalThis, 'AuthenticatorAssertionResponse');
  }
});

test('descriptor drift is rejected before review becomes available', async () => {
  const phone = await generatePhoneKey(); const controllerKey = await generatePhoneKey();
  const controller = { data: { installationId: 'installation', bootId: 'boot', publicKey: await crypto.subtle.exportKey('jwk', controllerKey.publicKey), fingerprint: await fingerprint(controllerKey.publicKey), mode: 'demo' }, key: controllerKey.publicKey };
  const fixture = coreFixture(); fixture.notBefore = Date.now() - 1000; fixture.expiresAt = Date.now() + 30000; fixture.deadline.at = fixture.expiresAt - 1000;
  const hash = fixture.operations[0]!.actions[0]!.parameters.configurationHash!; const raw = canonicalizeManifest(fixture); const batch = { batchId: 'batch', rawManifest: raw, digest: await manifestDigest(raw), configurationHashes: [hash] };
  const path = '/api/configurations/' + hash; const expiry = Date.now() + 10000; const originalFetch = globalThis.fetch; const locationDescriptor = Object.getOwnPropertyDescriptor(globalThis, 'location');
  Object.defineProperty(globalThis, 'location', { configurable: true, value: { origin: 'http://localhost:4173' } });
  globalThis.fetch = async input => {
    if (String(input).endsWith('/api/phone/challenge')) return Response.json({ nonce: 'nonce', installationId: 'installation', signerId: 'phone', method: 'GET', path, expiresAt: expiry });
    const payload = { requestNonce: 'nonce', method: 'GET', path, installationId: 'installation', expiresAt: expiry, data: { hash, descriptor: { scopes: ['write'], ttl: 60 } } };
    return Response.json({ payload, signature: await signBytes(controllerKey.privateKey, new TextEncoder().encode('keyroot.controller-response.v1\0' + canonicalJSON(payload))) });
  };
  try { const { loadReview } = await import('../../apps/review/src/phone/client.js'); await assert.rejects(loadReview(batch, 'phone', phone, controller), /descriptor changed/); } finally { globalThis.fetch = originalFetch; if (locationDescriptor) Object.defineProperty(globalThis, 'location', locationDescriptor); else Reflect.deleteProperty(globalThis, 'location'); }
});

test('emergency queue retains full scope across fresh steps more than 30 seconds apart', async () => {
  const phone = await generatePhoneKey(); const controllerKey = await generatePhoneKey();
  const controller = { data: { installationId: 'installation', bootId: 'boot', publicKey: await crypto.subtle.exportKey('jwk', controllerKey.publicKey), fingerprint: await fingerprint(controllerKey.publicKey), mode: 'demo' }, key: controllerKey.publicKey };
  const originalNow = Date.now; let now = originalNow(); Date.now = () => now;
  const fixture = coreFixture(); fixture.notBefore = now - 100; fixture.expiresAt = now + 120000; fixture.deadline.at = fixture.expiresAt - 1000; fixture.role = 'emergency'; fixture.signerId = 'hardware'; delete fixture.operations[0]!.actions[0]!.parameters.configurationHash;
  fixture.operations.push({ ...structuredClone(fixture.operations[0]!), operationId: 'op2', lineageId: 'lineage2', accountId: 'account2' });
  const raw = canonicalizeManifest(fixture); const batch = { batchId: 'nonce', rawManifest: raw, digest: await manifestDigest(raw), configurationHashes: [] }; const path = '/api/batches/nonce';
  const originalFetch = globalThis.fetch; const locationDescriptor = Object.getOwnPropertyDescriptor(globalThis, 'location'); let posts = 0;
  const progress = fixture.operations.map(op => ({ operationId: op.operationId, state: 'not-started', actions: [{ actionId: 'action', kind: 'disable', state: 'not-started' }], nextActionId: 'action' as string | null, dispatchComplete: false, outcome: null as null | { issuer: string; probe: string; replacement: string; holds: string[] } }));
  Object.defineProperty(globalThis, 'location', { configurable: true, value: { origin: 'http://localhost:4173' } });
  globalThis.fetch = async (input, init) => {
    const expiry = now + 10000;
    if (String(input).endsWith('/api/phone/challenge')) return Response.json({ nonce: 'nonce', installationId: 'installation', signerId: 'phone', method: 'GET', path, expiresAt: expiry });
    if (String(input).endsWith('/api/emergency/execute')) { posts++; assert.deepEqual(JSON.parse(String(init?.body)), { grantId: 'nonce', proofs: posts === 1 ? { op: { action: 'proof1' } } : { op2: { action: 'proof2' } } }); return Response.json([{ containment: 'unverified', replacement: 'not-created' }]); }
    const payload = { requestNonce: 'nonce', method: 'GET', path, installationId: 'installation', expiresAt: expiry, data: { ...batch, emergencyRegistration: { grantId: 'nonce', digest: batch.digest }, progress } };
    return Response.json({ payload, signature: await signBytes(controllerKey.privateKey, new TextEncoder().encode('keyroot.controller-response.v1\0' + canonicalJSON(payload))) });
  };
  try {
    const { executeEmergency, refreshEmergency, nextEmergencyAction } = await import('../../apps/review/src/phone/client.js');
    const first = { operationId: 'op', actionId: 'action' }; const second = { operationId: 'op2', actionId: 'action' };
    await assert.rejects(executeEmergency(batch, 'phone', phone, controller, first, { id: 'expired', expiresAt: now - 1 }), /Fresh/);
    await assert.rejects(executeEmergency(batch, 'phone', phone, controller, second, { id: 'wrong', expiresAt: now + 10000 }), /progress changed/);
    const firstProof = { id: 'proof1', expiresAt: now + 10000 }; await executeEmergency(batch, 'phone', phone, controller, first, firstProof);
    await assert.rejects(executeEmergency(batch, 'phone', phone, controller, first, firstProof), /reused/);
    progress[0]!.actions[0]!.state = 'observed'; progress[0]!.nextActionId = null; progress[0]!.dispatchComplete = true; progress[0]!.outcome = { issuer: 'unverified', probe: 'unknown', replacement: 'not-created', holds: [] };
    now += 31000;
    const refreshed = await refreshEmergency(batch, 'phone', phone, controller); assert.equal(refreshed.length, 2); assert.equal(refreshed[1]!.actions[0]!.state, 'not-started'); assert.deepEqual(nextEmergencyAction(refreshed), second);
    await executeEmergency(batch, 'phone', phone, controller, second, { id: 'proof2', expiresAt: now + 10000 }); assert.equal(posts, 2); assert.equal(batch.rawManifest, raw);
    progress[0]!.outcome!.holds = ['reconcile']; assert.equal(nextEmergencyAction(await refreshEmergency(batch, 'phone', phone, controller)), null); progress[0]!.outcome!.holds = [];
    progress[1]!.actions[0]!.state = 'unknown'; progress[1]!.nextActionId = null;
    assert.equal(nextEmergencyAction(await refreshEmergency(batch, 'phone', phone, controller)), null);
    fixture.role = 'routine'; fixture.signerId = 'phone'; batch.rawManifest = canonicalizeManifest(fixture); batch.digest = await manifestDigest(batch.rawManifest); await assert.rejects(executeEmergency(batch, 'phone', phone, controller, second, { id: 'wrong-role', expiresAt: now + 10000 }), /registered emergency scope required|does not match/); assert.equal(posts, 2);
  } finally { Date.now = originalNow; globalThis.fetch = originalFetch; if (locationDescriptor) Object.defineProperty(globalThis, 'location', locationDescriptor); else Reflect.deleteProperty(globalThis, 'location'); }
});

test('security-key registration converts options and sends attestation for verification', async () => {
  const originalFetch = globalThis.fetch; const nav = Object.getOwnPropertyDescriptor(globalThis, 'navigator'); const attestationDescriptor = Object.getOwnPropertyDescriptor(globalThis, 'AuthenticatorAttestationResponse');
  class Attestation { attestationObject = new Uint8Array([8, 9]).buffer; clientDataJSON = new Uint8Array([3]).buffer; getTransports() { return ['usb']; } }
  Object.defineProperty(globalThis, 'AuthenticatorAttestationResponse', { configurable: true, value: Attestation });
  Object.defineProperty(globalThis, 'navigator', { configurable: true, value: { credentials: { create: async (request: CredentialCreationOptions) => { const options = request.publicKey!; assert.deepEqual([...new Uint8Array(options.challenge as ArrayBuffer)], [5, 6]); assert.deepEqual([...new Uint8Array(options.user.id as ArrayBuffer)], [7]); return { id: 'Cg', rawId: new Uint8Array([10]).buffer, type: 'public-key', authenticatorAttachment: 'cross-platform', getClientExtensionResults: () => ({}), response: new Attestation() }; } } } });
  globalThis.fetch = async (input, init) => {
    if (String(input).endsWith('/challenge')) return Response.json({ requestId: 'request', expiresAt: Date.now() + 30000, options: { challenge: 'BQY', user: { id: 'Bw', name: 'emergency', displayName: 'emergency' }, rp: { name: 'Keyroot', id: 'localhost' }, pubKeyCredParams: [{ type: 'public-key', alg: -7 }] } });
    const body = JSON.parse(String(init?.body)) as { requestId: string; response: { rawId: string; response: { attestationObject: string; transports: string[] } } }; assert.equal(body.requestId, 'request'); assert.equal(body.response.rawId, 'Cg'); assert.equal(body.response.response.attestationObject, 'CAk'); assert.deepEqual(body.response.response.transports, ['usb']);
    return Response.json({ requestId: 'request', fingerprint: 'public', enrollmentFingerprint: 'binding', expiresAt: Date.now() + 30000, limitation: 'unverified' });
  };
  try { const { registerEmergencyKey } = await import('../../apps/review/src/phone/client.js'); assert.equal((await registerEmergencyKey('emergency')).enrollmentFingerprint, 'binding'); } finally { globalThis.fetch = originalFetch; if (nav) Object.defineProperty(globalThis, 'navigator', nav); else Reflect.deleteProperty(globalThis, 'navigator'); if (attestationDescriptor) Object.defineProperty(globalThis, 'AuthenticatorAttestationResponse', attestationDescriptor); else Reflect.deleteProperty(globalThis, 'AuthenticatorAttestationResponse'); }
});

test('phone sources do not import Node-only crypto or core implementation', async () => {
  const { readdir, readFile } = await import('node:fs/promises');
  const dir = new URL('../../apps/review/src/phone/', import.meta.url);
  for (const file of await readdir(dir)) {
    if (!/\.(?:ts|tsx)$/.test(file)) continue;
    const source = await readFile(new URL(file, dir), 'utf8');
    assert.doesNotMatch(source, /(?:from\s*|import\s*\()\s*['"](?:node:|.*packages\/core)/, file);
  }
});

test('browser and core agree on lineage-scoped shared consumer bindings', async () => {
  const value = coreFixture(); value.operations.push({ ...structuredClone(value.operations[0]!), operationId: 'op2', lineageId: 'lineage2' });
  const entries = [{ lineageId: 'lineage', consumerId: 'shared', resourceId: 'destination-a', revision: 'rev-a' }, { lineageId: 'lineage2', consumerId: 'shared', resourceId: 'destination-b', revision: 'rev-b' }];
  value.consumerMap.entries = entries; value.consumerMap.hash = contentDigest(entries);
  const valid = canonicalizeManifest(value); assert.deepEqual(await parseManifest(valid), parseCanonicalManifest(valid));
  const invalid = (map: typeof entries | Array<{ consumerId: string; resourceId: string; revision: string; lineageId?: string }>) => canonicalJSON({ ...value, consumerMap: { ...value.consumerMap, entries: map, hash: contentDigest(map) } });
  for (const raw of [invalid([{ ...entries[0]!, lineageId: 'unknown' }]), invalid([entries[0]!, { ...entries[0]!, resourceId: 'other' }]), invalid([entries[0]!, { consumerId: 'shared', resourceId: 'global', revision: 'r' }])]) { assert.throws(() => parseCanonicalManifest(raw)); await assert.rejects(parseManifest(raw)); }
});

test('incident plan hash is validated by core and browser', async () => {
  const value = coreFixture(); const plan = { type: 'incident-plan', version: 1, policy: 'revoke-first', affectedLineages: ['lineage'], quarantineDestinations: [{ consumerId: 'consumer', destinationId: 'resource' }], outage: { permitted: true, consequence: 'declared-interruption' } };
  value.operations[0]!.actions[0]!.parameters.incidentPlanHash = contentDigest(plan);
  const raw = canonicalizeManifest(value); assert.deepEqual(await parseManifest(raw), parseCanonicalManifest(raw));
  value.operations[0]!.actions[0]!.parameters.incidentPlanHash = 'sha256:invalid'; const bad = canonicalJSON(value);
  assert.throws(() => parseCanonicalManifest(bad)); await assert.rejects(parseManifest(bad));
});

test('incident review verifies exact sidecar set and rejects changed quarantine plan before approval', async () => {
  const phone = await generatePhoneKey(); const controllerKey = await generatePhoneKey();
  const controller = { data: { installationId: 'installation', bootId: 'boot', publicKey: await crypto.subtle.exportKey('jwk', controllerKey.publicKey), fingerprint: await fingerprint(controllerKey.publicKey), mode: 'demo' }, key: controllerKey.publicKey };
  const plan = { type: 'incident-plan', version: 1, policy: 'revoke-first', affectedLineages: ['lineage'], quarantineDestinations: [{ consumerId: 'consumer', destinationId: 'resource' }], outage: { permitted: true, consequence: 'declared-interruption' } };
  const config = { scopes: ['read'], ttl: 60 }; const configHash = contentDigest(config); const planHash = contentDigest(plan);
  const fixture = coreFixture(); fixture.notBefore = Date.now() - 100; fixture.expiresAt = Date.now() + 60000; fixture.deadline.at = fixture.expiresAt - 100; fixture.role = 'emergency'; fixture.signerId = 'hardware'; fixture.operations[0]!.actions[0]!.parameters.incidentPlanHash = planHash;
  const raw = canonicalizeManifest(fixture); const batch = { batchId: 'batch', rawManifest: raw, digest: await manifestDigest(raw), configurationHashes: [configHash, planHash] }; const originalFetch = globalThis.fetch; const locationDescriptor = Object.getOwnPropertyDescriptor(globalThis, 'location'); let requestedPath = ''; let drift = false; let posted = false; const fetched: string[] = []; let remoteBatch = batch; let expiresAt = Date.now() + 10000;
  Object.defineProperty(globalThis, 'location', { configurable: true, value: { origin: 'http://localhost:4173' } });
  globalThis.fetch = async (input, init) => {
    const url = String(input);
    if (url.endsWith('/api/approvals')) { posted = true; throw new Error('unexpected approval'); }
    if (url.endsWith('/api/phone/challenge')) { expiresAt = Date.now() + 10000; const body = JSON.parse(String(init?.body)) as { path: string }; requestedPath = body.path; return Response.json({ nonce: 'nonce', installationId: 'installation', signerId: 'phone', method: 'GET', path: requestedPath, expiresAt }); }
    const hash = requestedPath.slice('/api/configurations/'.length); if (requestedPath.startsWith('/api/configurations/')) fetched.push(hash);
    const descriptor = hash === planHash ? (drift ? { ...plan, quarantineDestinations: [] } : plan) : config;
    const payload = { requestNonce: 'nonce', method: 'GET', path: requestedPath, installationId: 'installation', expiresAt, data: requestedPath === '/api/batches/batch' ? remoteBatch : { hash, descriptor } };
    return Response.json({ payload, signature: await signBytes(controllerKey.privateKey, new TextEncoder().encode('keyroot.controller-response.v1\0' + canonicalJSON(payload))) });
  };
  try {
    const { loadReview } = await import('../../apps/review/src/phone/client.js');
    const review = await loadReview(batch, 'phone', phone, controller); assert.deepEqual(review.descriptors[planHash], plan); assert.deepEqual(new Set(fetched), new Set([configHash, planHash]));
    await assert.rejects(loadReview({ ...batch, configurationHashes: [configHash] }, 'phone', phone, controller), /Configuration list/);
    await assert.rejects(loadReview({ ...batch, configurationHashes: [configHash, planHash, 'sha256:' + '0'.repeat(64)] }, 'phone', phone, controller), /Configuration list/);
    drift = true; await assert.rejects(loadReview(batch, 'phone', phone, controller), /descriptor changed/); await assert.rejects(approve(batch, 'phone', phone, controller), /descriptor changed/); assert.equal(posted, false);
    const changed = structuredClone(fixture); changed.operations[0]!.actions[0]!.parameters.incidentPlanHash = contentDigest({ ...plan, quarantineDestinations: [] }); const changedRaw = canonicalizeManifest(changed); assert.notEqual(await manifestDigest(changedRaw), batch.digest);
    remoteBatch = { ...batch, rawManifest: changedRaw, digest: await manifestDigest(changedRaw) }; const { refreshEmergency } = await import('../../apps/review/src/phone/client.js'); await assert.rejects(refreshEmergency(batch, 'phone', phone, controller), /scope changed/); assert.equal(posted, false);
  } finally { globalThis.fetch = originalFetch; if (locationDescriptor) Object.defineProperty(globalThis, 'location', locationDescriptor); else Reflect.deleteProperty(globalThis, 'location'); }
});

test('registered scope restoration binds current manifest id, digest, and validity', async () => {
  const { registeredEmergency } = await import('../../apps/review/src/phone/client.js');
  const fixture = coreFixture(); fixture.role = 'emergency'; fixture.signerId = 'hardware'; fixture.notBefore = Date.now() - 100; fixture.expiresAt = Date.now() + 30000; fixture.deadline.at = fixture.expiresAt - 1000;
  const raw = canonicalizeManifest(fixture); const digest = await manifestDigest(raw); const batch = { batchId: fixture.nonce, rawManifest: raw, digest, configurationHashes: [], emergencyRegistration: { grantId: fixture.nonce, digest } };
  assert.equal(await registeredEmergency(batch, fixture), fixture.nonce);
  assert.equal(await registeredEmergency({ ...batch, emergencyRegistration: null }, fixture), null);
  await assert.rejects(registeredEmergency({ ...batch, emergencyRegistration: { grantId: 'wrong', digest } }, fixture));
  await assert.rejects(registeredEmergency({ ...batch, emergencyRegistration: { grantId: fixture.nonce, digest: 'wrong' } }, fixture));
  await assert.rejects(registeredEmergency({ ...batch, batchId: 'wrong' }, fixture));
  await assert.rejects(registeredEmergency(batch, { ...fixture, expiresAt: Date.now() - 1 }));
});
