import { test } from 'node:test';
import { strict as assert } from 'node:assert';
import { issuerConfigurationHash, issuerConfigurationDescriptor, assertIssuerConfigurationHash, assertIssuerConfigurationDescriptor } from '../src/adapters/issuer-drivers.js';
import { validateManifest } from '../src/manifest.js';

test('configuration descriptor binds metadata with an exact content digest', () => {
  const descriptor = issuerConfigurationDescriptor({ accountId: 'org-a', projectId: 'proj-a', serviceAccountId: 'sa-a', adapterVersion: '1', scopeIds: ['api.read'], expiresInSeconds: 3600, probeMethod: 'models-list', probeEndpointId: 'models-list-v1', destinationId: 'vault', handleId: 'operations/op', expectedVersion: 0, issuerAuthorityFingerprint: 'issuer-admin', storeAuthorityFingerprint: 'store-admin' });
  const hash = issuerConfigurationHash(descriptor);
  assert.match(hash, /^sha256:[a-f0-9]{64}$/);
  assert.doesNotThrow(() => assertIssuerConfigurationHash(hash, descriptor));
  assert.throws(() => assertIssuerConfigurationHash(hash, { ...descriptor, expiresInSeconds: 1 }), /configuration/i);
  assert.equal(JSON.stringify(descriptor).includes('adminToken'), false);
  assert.throws(() => validateManifest({ operations: [] }));
});

import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { generateKeyPairSync, sign } from 'node:crypto';
import { Journal, type AuthorizedIntent } from '../src/journal.js';
import { ApprovalService, createLocalBootstrapContext, publicKeyFingerprint, type RealAdmissionContext } from '../src/approval.js';
import { canonicalizeManifest, snapshotDigest, contentDigest, type ApprovalManifest, type ManifestAction } from '../src/manifest.js';
import { LifecycleEngine } from '../src/engine.js';
import { createOpenBaoStore } from '../src/adapters/openbao-kv2.js';
import { createOpenAIServiceAccountAdapter } from '../src/adapters/openai-service-account.js';
import { createAccountAssessmentWorkflow } from '../src/adapters/account-assessment.js';
import { createIssuerLifecycleDrivers, issuerActionConfigurationDescriptor, type IssuerConfigurationMetadata } from '../src/adapters/issuer-drivers.js';
import type { StoreBinding } from '../src/adapters/store.js';

/** In-memory HTTP fixture: exercises both actual transports without a server or vendor account. */
function httpFixture() {
  const keys = new Map<string, { name: string; value: string }>();
  const stored = new Map<string, { version: number; value: string; binding: StoreBinding }>();
  const state = { creates: 0, writes: 0, deletes: 0, loseCreateResponse: false, loseStoreResponse: false, storeConflict: false, beforeCreateResponse: undefined as (() => void) | undefined, beforeDelete: undefined as (() => void) | undefined, beforeListResponse: undefined as (() => void) | undefined, rejectProbe: false, confoundProbe: false };
  const request: typeof fetch = async (url, init) => {
    const target = new URL(String(url));
    if (target.hostname === 'account.fixture.invalid') return Response.json({ permission: 'validate', methodCapability: 'admitted' });
    if (target.hostname === 'data.fixture.invalid') {
      if (state.confoundProbe) return new Response(null, { status: 429 });
      return new Response(null, { status: state.rejectProbe ? 401 : 200 });
    }
    if (target.hostname === 'vault.fixture.invalid') {
      assert.equal((init?.headers as Record<string, string>)['X-Vault-Token'], 'fixture-store-admin');
      const handle = target.pathname.split('/data/')[1]!;
      if (init?.method === 'POST') {
        state.writes++;
        const body = JSON.parse(String(init.body)) as { options: { cas: number }; data: { value: string; binding: StoreBinding } };
        if (state.storeConflict || body.options.cas !== (stored.get(handle)?.version ?? 0)) return Response.json({ errors: ['check-and-set parameter did not match'] }, { status: 400 });
        stored.set(handle, { ...body.data, version: body.options.cas + 1 });
        if (state.loseStoreResponse) throw new Error('fixture response lost');
        return Response.json({ data: { version: body.options.cas + 1 } });
      }
      const record = stored.get(handle); if (!record) return new Response(null, { status: 404 });
      if (target.searchParams.has('version') && Number(target.searchParams.get('version')) !== record.version) return new Response(null, { status: 404 });
      return Response.json({ data: { data: { value: record.value, binding: record.binding }, metadata: { version: record.version } } });
    }
    assert.equal(target.hostname, 'api.openai.com');
    assert.equal((init?.headers as Record<string, string>).Authorization, 'Bearer fixture-issuer-admin');
    if (init?.method === 'POST') {
      state.creates++; const body = JSON.parse(String(init.body)) as { name: string; scopes: string[]; expires_in_seconds: number };
      assert.deepEqual(body.scopes, ['api.read']); assert.equal(body.expires_in_seconds, 3600);
      const resource = `key-${state.creates}`; keys.set(resource, { name: body.name, value: 'fixture-one-time-value' });
      state.beforeCreateResponse?.();
      if (state.loseCreateResponse) throw new Error('fixture response lost');
      return Response.json({ object: 'organization.project.service_account.api_key', id: resource, name: body.name, value: 'fixture-one-time-value' });
    }
    const keyId = target.pathname.split('/').at(-1)!;
    if (init?.method === 'DELETE') { state.beforeDelete?.(); state.deletes++; keys.delete(keyId); return Response.json({ object: 'organization.project.api_key.deleted', id: keyId, deleted: true }); }
    const item = (keyId: string, name: string) => ({ object: 'organization.project.api_key', id: keyId, name, owner: { type: 'service_account', service_account: { id: 'sa-a' } } });
    if (keyId === 'api_keys') { state.beforeListResponse?.(); return Response.json({ object: 'list', data: [...keys].map(([keyId, key]) => item(keyId, key.name)), has_more: false }); }
    const found = keys.get(keyId); return found ? Response.json(item(keyId, found.name)) : new Response(null, { status: 404 });
  };
  return { request, state, stored, keys };
}
const configuration = (): IssuerConfigurationMetadata => ({ accountId: 'org-a', projectId: 'proj-a', serviceAccountId: 'sa-a', adapterVersion: '1', scopeIds: ['api.read'], expiresInSeconds: 3600, probeMethod: 'fixture-cheap-v1', probeEndpointId: 'fixture-cheap', destinationId: 'vault', handleId: 'operations/op', expectedVersion: 0, issuerAuthorityFingerprint: 'issuer-authority', storeAuthorityFingerprint: 'store-authority' });
async function integratedFixture(t: { after: (fn: () => void) => void }, approvalMode: 'synthetic' | 'real' = 'synthetic', admission?: (context: Readonly<RealAdmissionContext>) => Promise<void>) {
  const http = httpFixture(); const config = configuration(); let currentConfig = structuredClone(config); let now = 2000;
  const directory = mkdtempSync(join(tmpdir(), 'keyroot-u5b-')); const file = join(directory, 'journal.sqlite');
  let journal = new Journal(file, { installationId: 'installation', bootId: 'boot' });
  const key = generateKeyPairSync('ec', { namedCurve: 'prime256v1' }); const publicKey = key.publicKey.export({ format: 'jwk' });
  let approvals = new ApprovalService(journal, { mode: approvalMode, clock: () => now, ...(admission ? { assertRealAdmission: admission } : {}) });
  approvals.bootstrapApprover({ signerId: 'phone', role: 'routine', publicKey, confirmedFingerprint: publicKeyFingerprint(publicKey), localBootstrap: createLocalBootstrapContext() });
  const actions: ManifestAction[] = [
    { id: 'create', kind: 'create', parameters: { resourceId: 'proj-a:sa-a', adapterId: 'openai-service-account', handleId: config.handleId, destinationId: config.destinationId, generation: 2, expectedRevision: '0' }, budgetCost: { effects: 2, newCredentials: 1, restarts: 0 } },
    { id: 'validate', kind: 'validate', parameters: { resourceId: 'created:op', handleId: config.handleId, generation: 2 }, budgetCost: { effects: 1, newCredentials: 0, restarts: 0 } }
  ];
  let m: ApprovalManifest = { version: 1, domain: 'keyroot.approval.v1', algorithm: 'ECDSA-P256-SHA256', audience: 'keyroot-controller', installationId: 'installation', bootId: 'boot', signerId: 'phone', role: 'routine', nonce: 'grant', notBefore: 1000, expiresAt: 10000, budgets: { executions: 1, effects: 3, newCredentials: 1, restarts: 0 }, operations: [{ operationId: 'op', lineageId: 'lineage', accountId: config.accountId, fromGeneration: 1, toGeneration: 2, actions }], consumerMap: { revision: 'map-1', entries: [], hash: contentDigest([]) }, recipes: [], adoptionThreshold: 'direct-use-every-consumer', overlapPolicy: 'required', deadline: { at: 9000, outcome: 'hold' }, outage: { permitted: false, consequence: 'none' }, graceSeconds: 900 };
  const signatures = new Map<string, string>();
  function register(manifest = m) {
    for (const action of manifest.operations[0]!.actions) action.parameters.configurationHash = issuerConfigurationHash(issuerActionConfigurationDescriptor(config, { operationId: 'op', actionId: action.id, kind: action.kind, parameters: action.parameters }));
    const raw = canonicalizeManifest(manifest); const signature = sign('sha256', Buffer.from(raw), { key: key.privateKey, dsaEncoding: 'ieee-p1363' }).toString('base64url');
    approvals.registerGrant(raw, signature, now); signatures.set(manifest.nonce, signature); m = manifest;
    return { operationId: 'op', grantId: manifest.nonce, signature };
  }
  const input = register();
  const store = createOpenBaoStore({ baseUrl: 'https://vault.fixture.invalid', mount: 'secret', token: 'fixture-store-admin', fetch: http.request });
  const transport = { kind: 'synthetic' as const, accountId: config.accountId, projectId: config.projectId, serviceAccountId: config.serviceAccountId, adminToken: 'fixture-issuer-admin', fetch: http.request, store };
  const assessment = createAccountAssessmentWorkflow({ trustDomain: 'synthetic', observerId: 'account-fixture', methodId: config.probeMethod, lifetimeMs: 20_000, timeoutMs: 100, clock: () => now, verifier: async request => { const response = await http.request('https://account.fixture.invalid/permissions', { signal: request.signal }); const evidence = await response.json() as { permission: string; methodCapability: string }; return { challenge: request.challenge, scope: request.scope, outcome: response.ok ? 'verified' : 'unverified', evidence, limitations: ['synthetic-only'], invalidationTriggers: ['permissions-changed'] }; } });
  await assessment.assess({ accountId: config.accountId, resourceId: 'proj-a:sa-a', action: 'validate', adapter: 'openai-service-account', adapterVersion: config.adapterVersion, authorityFingerprint: config.issuerAuthorityFingerprint, configurationHash: issuerConfigurationHash(issuerConfigurationDescriptor(config)) });
  const makeDrivers = () => createIssuerLifecycleDrivers({ transport, configuration: config, currentConfiguration: () => currentConfig, observerId: 'issuer-fixture', clock: () => now, assertAuthority: intent => approvals.assertReservedIntentAuthority({ grantId: intent.grantId, operationId: intent.operationId, actionId: intent.actionId, intentId: intent.intentId, signature: signatures.get(intent.grantId)!, currentSnapshotDigest: snapshotDigest(m) }), probe: { methodId: config.probeMethod, endpointId: config.probeEndpointId, cost: 'no-paid-work', assessment, execute: async (value, context) => { const response = await http.request('https://data.fixture.invalid/cheap', { headers: { Authorization: `Bearer ${value}` }, ...(context.signal ? { signal: context.signal } : {}) }); return { outcome: response.status === 200 ? 'accepted' : response.status === 401 ? 'rejected' : 'confounded', confounders: response.status === 429 ? ['rate-limit'] : [] }; } }, consumers: { deliver: async () => { throw new Error('U6 not installed'); }, observeConsumer: async () => { throw new Error('U6 not installed'); }, observeOldUse: async () => { throw new Error('U6 not installed'); } } });
  let drivers = makeDrivers();
  const engine = () => new LifecycleEngine(journal, approvals, drivers, { currentSnapshot: () => m, clock: () => now });
  const request = (intent: AuthorizedIntent) => ({ grantId: intent.grantId, operationId: intent.operationId, actionId: intent.actionId, intentId: intent.intentId, signature: signatures.get(intent.grantId)!, currentSnapshotDigest: snapshotDigest(m) });
  t.after(() => { journal.close(); rmSync(directory, { recursive: true, force: true }); });
  return { ...http, config, store, transport, input, engine, register, request, get journal() { return journal; }, get approvals() { return approvals; }, get manifest() { return m; }, get drivers() { return drivers; }, setNow: (value: number) => { now = value; }, driftConfig: () => { currentConfig = { ...currentConfig, scopeIds: ['api.write'] }; }, restart: () => { journal.close(); journal = new Journal(file, { installationId: 'installation', bootId: 'new-boot' }); approvals = new ApprovalService(journal, { mode: 'synthetic', clock: () => now }); drivers = makeDrivers(); } };
}

test('actual issuer and KV2 transports drive a real signed engine create and admitted cheap validation', async t => {
  const f = await integratedFixture(t); const result = await f.engine().run(f.input);
  assert.equal(result.replacement, 'stored'); assert.equal(result.receipts.find(r => r.kind === 'validate')?.outcome, 'validated');
  assert.equal(result.state, 'held'); assert.equal(f.state.creates, 1); assert.equal(f.state.writes, 1);
  assert.deepEqual(result.receipts.find(r => r.kind === 'create')?.storeBinding, { operationId: 'op', lineageId: 'lineage', accountId: 'org-a', generation: 2, issuerId: 'key-1', handleId: 'operations/op', destinationId: 'vault', version: 1 });
  assert.equal(JSON.stringify(result).includes('fixture-one-time-value'), false);
  assert.equal(JSON.stringify(f.journal.listReceipts('op')).includes('fixture-one-time-value'), false);
  await f.engine().run(f.input); assert.equal(f.state.creates, 1);
});

for (const fault of ['cancel', 'expiry', 'snapshot', 'configuration'] as const) test(`create continuation ${fault} denies exact CAS after provider success`, async t => {
  const f = await integratedFixture(t);
  f.state.beforeCreateResponse = () => {
    if (fault === 'cancel') f.approvals.cancelGrant(f.input.grantId);
    if (fault === 'expiry') f.setNow(10000);
    if (fault === 'snapshot') f.manifest.consumerMap.revision = 'changed';
    if (fault === 'configuration') f.driftConfig();
  };
  const result = await f.engine().run(f.input);
  assert.equal(result.replacement, 'created-unrecoverable'); assert.equal(f.state.creates, 1); assert.equal(f.state.writes, 0);
  assert.equal(result.receipts[0]?.subject.resourceId, 'key-1');
});

test('lost CAS acknowledgment resumes after restart by exact issuer and pinned store without recreation', async t => {
  const f = await integratedFixture(t); f.state.loseStoreResponse = true;
  assert.equal((await f.engine().run(f.input)).replacement, 'unknown');
  assert.equal(f.state.creates, 1); assert.equal(f.state.writes, 1); f.restart();
  const result = await f.engine().reconcile('op');
  assert.equal(result.replacement, 'stored'); assert.equal(f.state.creates, 1); assert.equal(f.state.writes, 1);
});

test('lost create response reconciles orphan without blind retry', async t => {
  const f = await integratedFixture(t); f.state.loseCreateResponse = true;
  assert.equal((await f.engine().run(f.input)).replacement, 'unknown'); f.restart();
  const result = await f.engine().reconcile('op'); assert.equal(result.replacement, 'created-unrecoverable');
  assert.equal(f.state.creates, 1); assert.equal(f.state.writes, 0);
});

test('store binding mismatch cannot turn a lost response into stored success', async t => {
  const f = await integratedFixture(t); f.state.loseStoreResponse = true;
  await f.engine().run(f.input); const record = f.stored.get('operations/op')!; record.binding = { ...record.binding, issuerId: 'foreign' }; f.restart();
  const result = await f.engine().reconcile('op'); assert.equal(result.replacement, 'orphan-unresolved'); assert.equal(f.state.creates, 1);
});

test('factory and exact action digest deny changed target, expiry and scope configuration', async t => {
  const f = await integratedFixture(t);
  const action = f.manifest.operations[0]!.actions[0]!; const intent = await f.approvals.authorizeEffect({ ...f.request({ grantId: f.input.grantId, operationId: 'op', actionId: 'create', intentId: '', idempotencyRef: '', kind: 'create', parameters: action.parameters as Readonly<Record<string, string | number>>, state: 'pending' }) });
  const context = { subject: { operationId: 'op', lineageId: 'lineage', accountId: 'org-a', generation: 2, resourceId: 'proj-a:sa-a', handleId: 'operations/op', consumerMapRevision: 'map-1' }, signal: new AbortController().signal, storeTarget: { destinationId: 'vault', handleId: 'operations/op', expectedVersion: 0 }, beforeStore: () => f.approvals.assertCurrentAuthority(f.request(intent)) };
  await assert.rejects(f.drivers.create({ ...intent, parameters: { ...intent.parameters, expectedRevision: '1' } }, context), /configuration/);
  await assert.rejects(f.drivers.create(intent, { ...context, storeTarget: { ...context.storeTarget, handleId: 'foreign' } }), /target/);
  const forged = { ...intent, parameters: { ...intent.parameters, reasonCode: 'not-signed' } as Record<string, string | number> };
  forged.parameters.configurationHash = issuerConfigurationHash(issuerActionConfigurationDescriptor(f.config, forged));
  await assert.rejects(f.drivers.create(forged, context), /authorized issuer intent/);
  f.driftConfig(); await assert.rejects(f.drivers.create(intent, context), /drift/); assert.equal(f.state.creates, 0);
});

test('rate limit never validates a replacement and metadata 404 never confirms revocation', async t => {
  const f = await integratedFixture(t); f.state.confoundProbe = true;
  const result = await f.engine().run(f.input); assert.equal(result.receipts.find(r => r.kind === 'validate')?.outcome, 'unknown');
  const subject = { operationId: 'op', lineageId: 'lineage', accountId: 'org-a', generation: 1, resourceId: 'missing', handleId: 'old-handle', consumerMapRevision: 'map-1' };
  assert.equal((await f.drivers.observeIssuer(subject)).outcome, 'unverified');
  assert.equal((await f.drivers.probeOld(subject)).outcome, 'unknown');
});

test('real approval remains denied without owning proof; trusted admission port runs for dispatch and CAS continuation', async t => {
  const denied = await integratedFixture(t, 'real'); await assert.rejects(denied.engine().run(denied.input), /Real mutation/); assert.equal(denied.state.creates, 0);
  const contexts: Readonly<RealAdmissionContext>[] = [];
  const f = await integratedFixture(t, 'real', async context => { contexts.push(context); });
  const result = await f.engine().run(f.input); assert.equal(result.replacement, 'stored');
  assert.ok(contexts.some(c => c.phase === 'dispatch' && c.action.kind === 'create')); assert.ok(contexts.some(c => c.phase === 'continuation' && c.action.kind === 'create'));
  assert.equal(contexts[0]?.operation.accountId, 'org-a'); assert.match(contexts[0]?.action.parameters.configurationHash ?? '', /^sha256:/);
  // This callback is a test integration boundary, not owner phone/isolation/recovery proof.
});

test('orphan cleanup uses a separate signed fresh grant and rechecks authority before DELETE', async t => {
  const f = await integratedFixture(t); f.state.storeConflict = true;
  assert.equal((await f.engine().run(f.input)).replacement, 'created-unrecoverable');
  assert.equal(f.state.deletes, 0);
  const cleanup = structuredClone(f.manifest); cleanup.nonce = 'cleanup-grant'; cleanup.budgets = { executions: 1, effects: 1, newCredentials: 0, restarts: 0 };
  cleanup.operations[0]!.actions = [{ id: 'cleanup', kind: 'cleanup', parameters: { resourceId: 'key-1', handleId: 'operations/op', generation: 2 }, budgetCost: { effects: 1, newCredentials: 0, restarts: 0 } }];
  const fresh = f.register(cleanup);
  const result = await f.engine().run(fresh);
  assert.equal(result.receipts.find(r => r.kind === 'cleanup')?.outcome, 'issuer-acknowledged'); assert.equal(f.state.deletes, 1); assert.equal(f.state.creates, 1);
});

test('cancelled cleanup grant cannot dispatch DELETE', async t => {
  const f = await integratedFixture(t); f.state.storeConflict = true; await f.engine().run(f.input);
  const cleanup = structuredClone(f.manifest); cleanup.nonce = 'cleanup-grant'; cleanup.budgets = { executions: 1, effects: 1, newCredentials: 0, restarts: 0 };
  cleanup.operations[0]!.actions = [{ id: 'cleanup', kind: 'cleanup', parameters: { resourceId: 'key-1', handleId: 'operations/op', generation: 2 }, budgetCost: { effects: 1, newCredentials: 0, restarts: 0 } }];
  const fresh = f.register(cleanup); f.approvals.cancelGrant(fresh.grantId);
  await assert.rejects(f.engine().run(fresh), /Cancelled/); assert.equal(f.state.deletes, 0);
});

test('manifest strictly validates configurationHash and P-256 rejects post-signature descriptor changes', async t => {
  const f = await integratedFixture(t); const malformed = structuredClone(f.manifest); malformed.operations[0]!.actions[0]!.parameters.configurationHash = 'sha256:invented';
  assert.throws(() => canonicalizeManifest(malformed), /configuration hash/);
  const changed = structuredClone(f.manifest); changed.operations[0]!.actions[0]!.parameters.configurationHash = issuerConfigurationHash(issuerActionConfigurationDescriptor({ ...f.config, expiresInSeconds: 1 }, { operationId: 'op', actionId: 'create', kind: 'create', parameters: changed.operations[0]!.actions[0]!.parameters }));
  assert.throws(() => f.approvals.registerGrant(canonicalizeManifest(changed), f.input.signature, 2000), /signature/);
});

test('live transport accepts only an owning evaluator and fresh exact account configuration proof', async () => {
  const http = httpFixture(); const config = configuration(); const store = createOpenBaoStore({ baseUrl: 'https://vault.fixture.invalid', mount: 'secret', token: 'fixture-store-admin', fetch: http.request });
  let now = 2000; let verified = 0;
  // This installs a hermetic verifier to test the trusted port; no real account evidence is claimed.
  const workflow = createAccountAssessmentWorkflow({ trustDomain: 'live', observerId: 'owning-workflow-fixture', methodId: 'permission-overlap-fixture', lifetimeMs: 1000, timeoutMs: 100, clock: () => now, verifier: async request => { verified++; return { challenge: request.challenge, scope: request.scope, outcome: 'verified', evidence: { permission: request.scope.action, overlap: 'present' }, limitations: ['hermetic-verifier-fixture'], invalidationTriggers: ['permissions-changed'] }; } });
  const transport = { kind: 'live' as const, accountId: 'org-a', projectId: 'proj-a', serviceAccountId: 'sa-a', adminToken: 'fixture-issuer-admin', fetch: http.request, store, adapterVersion: '1', authorityFingerprint: config.issuerAuthorityFingerprint, configurationHash: issuerConfigurationHash(issuerConfigurationDescriptor(config)), assessment: workflow };
  assert.throws(() => createOpenAIServiceAccountAdapter({ ...transport, assessment: { ...workflow } }), /admission/);
  const adapter = createOpenAIServiceAccountAdapter(transport); assert.equal(adapter.capabilities.liveAdmitted, false);
  await assert.rejects(adapter.create({ operationId: 'op', scopes: ['api.read'], expiresInSeconds: 3600, beforeStore: async () => {} }), /evidence/); assert.equal(http.state.creates, 0);
  for (const action of ['create', 'observe', 'validate', 'revoke'] as const) await workflow.assess({ accountId: 'org-a', resourceId: 'proj-a:sa-a', action, adapter: 'openai-service-account', adapterVersion: '1', authorityFingerprint: config.issuerAuthorityFingerprint, configurationHash: transport.configurationHash });
  assert.equal(verified, 4); assert.equal(adapter.capabilities.liveAdmitted, true);
  assert.equal((await adapter.create({ operationId: 'op', scopes: ['api.read'], expiresInSeconds: 3600, beforeStore: async () => {} })).status, 'created');
  now = 3000; assert.equal(adapter.capabilities.liveAdmitted, false);
  await assert.rejects(adapter.create({ operationId: 'op-2', scopes: ['api.read'], expiresInSeconds: 3600, beforeStore: async () => {} }), /evidence/); assert.equal(http.state.creates, 1);
});

test('cleanup cancellation during ownership listing is rechecked immediately before DELETE', async t => {
  const f = await integratedFixture(t); f.state.storeConflict = true; await f.engine().run(f.input);
  const cleanup = structuredClone(f.manifest); cleanup.nonce = 'cleanup-grant'; cleanup.budgets = { executions: 1, effects: 1, newCredentials: 0, restarts: 0 };
  cleanup.operations[0]!.actions = [{ id: 'cleanup', kind: 'cleanup', parameters: { resourceId: 'key-1', handleId: 'operations/op', generation: 2 }, budgetCost: { effects: 1, newCredentials: 0, restarts: 0 } }];
  const fresh = f.register(cleanup); f.state.beforeListResponse = () => f.approvals.cancelGrant(fresh.grantId);
  const result = await f.engine().run(fresh); assert.equal(result.receipts.find(r => r.kind === 'cleanup')?.outcome, 'unknown'); assert.equal(f.state.deletes, 0);
});

test('fetched descriptors reject secret-bearing fields, unknown actions and recursive hashes before phone display', () => {
  const metadata = configuration(); const descriptor = issuerConfigurationDescriptor(metadata);
  assert.throws(() => assertIssuerConfigurationDescriptor({ ...descriptor, value: 'not-display-material' }), /configuration/);
  assert.throws(() => issuerActionConfigurationDescriptor(metadata, { operationId: 'op', actionId: 'create', kind: 'create', parameters: { adminToken: 'not-display-material' } }), /binding/);
  assert.throws(() => assertIssuerConfigurationDescriptor({ ...descriptor, action: { operationId: 'op', actionId: 'create', kind: 'create', parameters: { configurationHash: contentDigest({}) } } }), /parameters/);
  assert.throws(() => issuerActionConfigurationDescriptor(metadata, { operationId: 'op', actionId: 'admin', kind: 'admin', parameters: {} }), /binding/);
});

test('trusted real admission continuation cannot preserve expired authority by an earlier request clock', async t => {
  let continuations = 0;
  const f = await integratedFixture(t, 'real', async context => { if (context.phase === 'continuation' && context.action.kind === 'create' && ++continuations === 2) f.setNow(10000); });
  const result = await f.engine().run(f.input); assert.equal(result.replacement, 'created-unrecoverable'); assert.equal(f.state.writes, 0);
});
