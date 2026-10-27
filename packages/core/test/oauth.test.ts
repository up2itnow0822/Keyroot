import { test } from 'node:test';
import { strict as assert } from 'node:assert';
import { generateKeyPairSync, sign } from 'node:crypto';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { OAuthCoordinator, type OAuthExecutor } from '../src/oauth.js';
import { Journal } from '../src/journal.js';
import { ApprovalService, createLocalBootstrapContext, publicKeyFingerprint } from '../src/approval.js';
import { canonicalizeManifest, contentDigest, snapshotDigest, type ApprovalManifest } from '../src/manifest.js';

function fixture() {
  const dir = mkdtempSync(join(tmpdir(), 'oauth-')); const path = join(dir, 'journal.sqlite');
  const keys = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  let clockTime = 2000;
  let journal = new Journal(path, { installationId: 'installation', bootId: 'boot' });
  let approval = new ApprovalService(journal, { mode: 'synthetic', clock: () => clockTime });
  const publicKey = keys.publicKey.export({ format: 'jwk' });
  approval.bootstrapApprover({ signerId: 'phone', role: 'routine', publicKey, localBootstrap: createLocalBootstrapContext(), confirmedFingerprint: publicKeyFingerprint(publicKey) });
  const calls: string[] = []; let refreshGate: Promise<void> | undefined; let consentGate: Promise<void> | undefined; let refreshOutcome: 'ok' | 'lost' = 'ok'; let consentOutcome: 'completed' | 'cancelled' = 'cancelled';
  const executor: OAuthExecutor = { refresh: async ({ beforeStore }) => { calls.push('refresh'); await refreshGate; if (refreshOutcome === 'lost') throw new Error('sentinel-secret'); await beforeStore(); return { accessExpiresAt: 15000, evidenceHash: 'sha256:' + 'a'.repeat(64) }; }, revoke: async () => { calls.push('revoke'); return { outcome: 'confirmed', evidenceHash: 'sha256:' + 'b'.repeat(64) }; }, consent: async ({ beforeStore }) => { calls.push('consent'); await consentGate; if (consentOutcome === 'completed') await beforeStore(); return { outcome: consentOutcome, evidenceHash: 'sha256:' + 'c'.repeat(64) }; }, reconcile: async ({ version }) => { calls.push('reconcile'); return { state: 'active', version, effect: 'applied', issuerEvidenceHash: 'sha256:' + 'd'.repeat(64), storeEvidenceHash: 'sha256:' + 'e'.repeat(64) }; } };
  let coordinator = new OAuthCoordinator(journal, approval, executor);
  coordinator.registerLocal({ grantId: 'grant', familyId: 'family', ownerId: 'owner', version: 1, accessExpiresAt: 12000 });
  let seq = 0;
  const request = (reason: string, version = 1, owner = 'owner', signatureOverride?: string, sameOperation?: number) => {
    seq++; const kind = reason === 'oauth-revoke' ? 'revoke' : 'admin'; const op = `op-${sameOperation ?? seq}`; const action = `action-${seq}`;
    const value: ApprovalManifest = { version: 1, domain: 'keyroot.approval.v1', algorithm: 'ECDSA-P256-SHA256', audience: 'keyroot-controller', installationId: 'installation', bootId: journal.bootId, signerId: 'phone', role: 'routine', nonce: `grant-${seq}`, notBefore: 1000, expiresAt: 10000, budgets: { executions: 1, newCredentials: 0, restarts: 0, effects: 1 }, operations: [{ operationId: op, accountId: 'account', lineageId: `lineage-${sameOperation ?? seq}`, fromGeneration: 1, toGeneration: 2, actions: [{ id: action, kind, parameters: { resourceId: 'grant', handleId: 'family', destinationId: owner, expectedRevision: String(version), reasonCode: reason, ...(kind === 'admin' ? { authorityFingerprint: 'issuer' } : { generation: 1 }) }, budgetCost: { effects: 1, newCredentials: 0, restarts: 0 } }] }], consumerMap: { revision: '1', hash: contentDigest([]), entries: [] }, recipes: [], adoptionThreshold: 'direct-use-every-consumer', overlapPolicy: 'required', deadline: { at: 9000, outcome: 'hold' }, outage: { permitted: false, consequence: 'none' }, graceSeconds: 900 };
    const raw = canonicalizeManifest(value); const signature = sign('sha256', Buffer.from(raw), { key: keys.privateKey, dsaEncoding: 'ieee-p1363' }).toString('base64url');
    approval.registerGrant(raw, signature, 2000);
    return { grantId: value.nonce, operationId: op, actionId: action, signature: signatureOverride ?? signature, currentSnapshotDigest: snapshotDigest(value), now: 2000 };
  };
  const target = { grantId: 'grant', familyId: 'family', ownerId: 'owner', version: 1 };
  return { target, get coordinator() { return coordinator; }, get calls() { return calls; }, request, history(operationId: string) { return { intents: journal.listIntents(operationId), receipts: journal.listReceipts(operationId) }; }, advanceClock(time: number) { clockTime = time; }, cancel(grantId: string) { approval.cancelGrant(grantId); }, gateRefresh(gate: Promise<void>) { refreshGate = gate; }, gateConsent(gate: Promise<void>) { consentGate = gate; }, lost() { refreshOutcome = 'lost'; }, restoreRefresh() { refreshOutcome = 'ok'; }, completeConsent() { consentOutcome = 'completed'; }, reboot() { journal.close(); journal = new Journal(path, { installationId: 'installation', bootId: 'boot2' }); approval = new ApprovalService(journal, { mode: 'synthetic', clock: () => clockTime }); coordinator = new OAuthCoordinator(journal, approval, executor); }, close() { journal.close(); rmSync(dir, { recursive: true, force: true }); } };
}

test('local refresh persists version and competing owner cannot dispatch; production remains external', async () => {
  const f = fixture(); try {
    assert.equal(await f.coordinator.refresh({ ...f.target, owner: 'production', request: f.request('oauth-refresh') }), 'external');
    assert.deepEqual(f.calls, []);
    assert.equal(await f.coordinator.refresh({ ...f.target, owner: 'keyroot-local', request: f.request('oauth-refresh') }), 'refreshed');
    assert.equal(f.coordinator.inspect('grant')?.version, 2);
    await assert.rejects(f.coordinator.refresh({ ...f.target, ownerId: 'other', version: 2, owner: 'keyroot-local', request: f.request('oauth-refresh', 2, 'other') }), /owner, version or state/);
    assert.deepEqual(f.calls, ['refresh']);
  } finally { f.close(); }
});

test('restored family blocks refresh until issuer reconciliation', async () => {
  const f = fixture(); try {
    f.reboot();
    await assert.rejects(f.coordinator.refresh({ ...f.target, owner: 'keyroot-local', request: f.request('oauth-refresh') }), /Restored/);
    assert.deepEqual(f.calls, []);
    assert.equal(await f.coordinator.reconcile({ ...f.target }), 'confirmed');
    assert.equal(await f.coordinator.refresh({ ...f.target, owner: 'keyroot-local', request: f.request('oauth-refresh') }), 'refreshed');
  } finally { f.close(); }
});

test('lost refresh response holds family without retry or leaking error', async () => {
  const f = fixture(); try {
    f.lost(); assert.equal(await f.coordinator.refresh({ ...f.target, owner: 'keyroot-local', request: f.request('oauth-refresh') }), 'unknown');
    assert.equal(f.coordinator.inspect('grant')?.state, 'reconcile-required');
    await assert.rejects(f.coordinator.refresh({ ...f.target, owner: 'keyroot-local', request: f.request('oauth-refresh') }));
    assert.deepEqual(f.calls, ['refresh']);
    assert.ok(!JSON.stringify(f.coordinator.inspect('grant')).includes('sentinel-secret'));
  } finally { f.close(); }
});

test('revoke precedes signed consent, reports residual lifetime, and cancelled consent stays revoked', async () => {
  const f = fixture(); try {
    await assert.rejects(f.coordinator.consent({ ...f.target, request: f.request('oauth-consent') }));
    assert.deepEqual(f.calls, []);
    assert.deepEqual(await f.coordinator.revoke({ ...f.target, owner: 'keyroot-local', request: f.request('oauth-revoke') }), { outcome: 'confirmed', accessExpiresAt: 12000 });
    await assert.rejects(f.coordinator.consent({ ...f.target, request: f.request('oauth-consent', 1, 'owner', 'wrong') }));
    assert.equal(await f.coordinator.consent({ ...f.target, request: f.request('oauth-consent') }), 'cancelled');
    assert.equal(f.coordinator.inspect('grant')?.state, 'revoked');
    f.completeConsent();
    assert.equal(await f.coordinator.consent({ ...f.target, request: f.request('oauth-consent') }), 'completed');
    assert.deepEqual(f.calls, ['revoke', 'consent', 'consent']);
    assert.equal(f.coordinator.inspect('grant')?.version, 2);
  } finally { f.close(); }
});


test('concurrent refreshes reserve a single owner and family version before execution', async () => {
  const f = fixture(); try {
    let release!: () => void; const gate = new Promise<void>(resolve => { release = resolve; }); f.gateRefresh(gate);
    const first = f.coordinator.refresh({ ...f.target, owner: 'keyroot-local', request: f.request('oauth-refresh') });
    await new Promise<void>(resolve => setImmediate(resolve));
    await assert.rejects(f.coordinator.refresh({ ...f.target, owner: 'keyroot-local', request: f.request('oauth-refresh') }), /owner, version or state/);
    release(); assert.equal(await first, 'refreshed');
    assert.deepEqual(f.calls, ['refresh']);
  } finally { f.close(); }
});


test('unknown refresh reconciles same operation by read-only observation before a fresh action', async () => {
  const f = fixture(); try {
    f.lost();
    const request = f.request('oauth-refresh');
    assert.equal(await f.coordinator.refresh({ ...f.target, owner: 'keyroot-local', request }), 'unknown');
    f.reboot();
    assert.equal(f.history(request.operationId).intents[0]?.state, 'unknown');
    assert.equal(await f.coordinator.reconcile({ ...f.target }), 'confirmed');
    const history = f.history(request.operationId);
    assert.equal(history.intents[0]?.state, 'observed');
    const unknown = history.receipts.find(receipt => receipt.outcome === 'unknown');
    const marker = history.receipts.find(receipt => receipt.kind === 'reconciliation');
    assert.ok(unknown && marker?.reconcilesReceiptIds?.includes(unknown.receiptId));
    assert.ok(!JSON.stringify(history).includes('sentinel-secret'));
    assert.equal(f.coordinator.inspect('grant')?.state, 'active');
    f.restoreRefresh();
    assert.equal(await f.coordinator.refresh({ ...f.target, owner: 'keyroot-local', request: f.request('oauth-refresh', 1, 'owner', undefined, 1) }), 'refreshed');
  } finally { f.close(); }
});

test('cancelled authority during refresh prevents token-store continuation', async () => {
  const f = fixture(); try {
    let release!: () => void; const gate = new Promise<void>(resolve => { release = resolve; }); f.gateRefresh(gate);
    const request = f.request('oauth-refresh');
    const pending = f.coordinator.refresh({ ...f.target, owner: 'keyroot-local', request });
    await new Promise<void>(resolve => setImmediate(resolve));
    f.cancel(request.grantId);
    release();
    assert.equal(await pending, 'unknown');
    assert.equal(f.coordinator.inspect('grant')?.state, 'reconcile-required');
  } finally { f.close(); }
});


test('cancelled approval cannot complete consent after a long wait', async () => {
  const f = fixture(); try {
    await f.coordinator.revoke({ ...f.target, owner: 'keyroot-local', request: f.request('oauth-revoke') });
    f.completeConsent();
    let release!: () => void; const gate = new Promise<void>(resolve => { release = resolve; }); f.gateConsent(gate);
    const request = f.request('oauth-consent');
    const pending = f.coordinator.consent({ ...f.target, request });
    await new Promise<void>(resolve => setImmediate(resolve));
    f.cancel(request.grantId); release();
    assert.equal(await pending, 'unknown');
    assert.equal(f.coordinator.inspect('grant')?.state, 'reconcile-required');
  } finally { f.close(); }
});


test('expired authority cannot cross the refresh store boundary', async () => {
  const f = fixture(); try {
    let release!: () => void; const gate = new Promise<void>(resolve => { release = resolve; }); f.gateRefresh(gate);
    const request = f.request('oauth-refresh');
    const pending = f.coordinator.refresh({ ...f.target, owner: 'keyroot-local', request });
    await new Promise<void>(resolve => setImmediate(resolve));
    f.advanceClock(10000); release();
    assert.equal(await pending, 'unknown');
    assert.equal(f.coordinator.inspect('grant')?.state, 'reconcile-required');
  } finally { f.close(); }
});
