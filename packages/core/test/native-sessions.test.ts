import { test } from 'node:test';
import { strict as assert } from 'node:assert';
import { describeNativeCoverage, newPlaceAlert } from '../src/native-sessions.js';

test('native storage, remote logout, and telemetry remain separate', () => {
  assert.deepEqual(describeNativeCoverage({ client: 'codex', storage: 'plaintext-only', remoteSignOut: 'unavailable', sessionTelemetry: 'unknown' }), { client: 'codex', storage: 'plaintext-only', remoteSignOut: 'unavailable', sessionTelemetry: 'unknown' });
  const alert = newPlaceAlert({ provider: 'provider-a', accountId: 'account', placeId: 'place', observedAt: '2026-10-26T00:00:00Z', kind: 'new-place' });
  assert.equal(alert.provider, 'provider-a');
  assert.ok(!JSON.stringify(alert).includes('provider-b'));
});

test('native sign-out requires a fresh signed U3 action and dispatches only its fixed action', async () => {
  const { generateKeyPairSync, sign } = await import('node:crypto');
  const { Journal } = await import('../src/journal.js');
  const { ApprovalService, createLocalBootstrapContext, publicKeyFingerprint } = await import('../src/approval.js');
  const { canonicalizeManifest, contentDigest, snapshotDigest } = await import('../src/manifest.js');
  const { signOutNative } = await import('../src/native-sessions.js');
  const journal = new Journal(':memory:', { installationId: 'installation', bootId: 'boot' });
  try {
    const keys = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    const publicKey = keys.publicKey.export({ format: 'jwk' });
    const approval = new ApprovalService(journal, { mode: 'synthetic', clock: () => 2000 });
    approval.bootstrapApprover({ signerId: 'phone', role: 'routine', publicKey, localBootstrap: createLocalBootstrapContext(), confirmedFingerprint: publicKeyFingerprint(publicKey) });
    const value: import('../src/manifest.js').ApprovalManifest = { version: 1, domain: 'keyroot.approval.v1', algorithm: 'ECDSA-P256-SHA256', audience: 'keyroot-controller', installationId: 'installation', bootId: 'boot', signerId: 'phone', role: 'routine', nonce: 'native-grant', notBefore: 1000, expiresAt: 10000, budgets: { executions: 1, newCredentials: 0, restarts: 0, effects: 1 }, operations: [{ operationId: 'op', accountId: 'account', lineageId: 'native', fromGeneration: 1, toGeneration: 2, actions: [{ id: 'logout', kind: 'sign-out', parameters: { resourceId: 'native:codex:local', generation: 1 }, budgetCost: { effects: 1, newCredentials: 0, restarts: 0 } }] }], consumerMap: { revision: '1', hash: contentDigest([]), entries: [] }, recipes: [], adoptionThreshold: 'direct-use-every-consumer', overlapPolicy: 'required', deadline: { at: 9000, outcome: 'hold' }, outage: { permitted: false, consequence: 'none' }, graceSeconds: 900 };
    const raw = canonicalizeManifest(value); const signature = sign('sha256', Buffer.from(raw), { key: keys.privateKey, dsaEncoding: 'ieee-p1363' }).toString('base64url');
    approval.registerGrant(raw, signature, 2000);
    const request = { grantId: value.nonce, signature, operationId: 'op', actionId: 'logout', currentSnapshotDigest: snapshotDigest(value), now: 2000 };
    const calls: string[] = [];
    const executor = { execute: async (action: 'claude-code-local-sign-out' | 'codex-local-sign-out') => { calls.push(action); } };
    await assert.rejects(signOutNative({ client: 'codex', approval, request: { ...request, signature: 'wrong' }, executor }));
    await signOutNative({ client: 'codex', approval, request, executor });
    assert.deepEqual(calls, ['codex-local-sign-out']);
    assert.equal(journal.listIntents('op')[0]?.state, 'observed');
    assert.equal(journal.listReceipts('op')[0]?.kind, 'sign-out');
    assert.ok(journal.listReceipts('op')[0]?.limitationCodes.includes('local-command-only-remote-session-unverified'));
    await assert.rejects(signOutNative({ client: 'codex', approval, request, executor }));
  } finally { journal.close(); }
});

test('native executor failures retain unknown evidence and redact errors', async () => {
  const { generateKeyPairSync, sign } = await import('node:crypto');
  const { Journal } = await import('../src/journal.js');
  const { ApprovalService, createLocalBootstrapContext, publicKeyFingerprint } = await import('../src/approval.js');
  const { canonicalizeManifest, contentDigest, snapshotDigest } = await import('../src/manifest.js');
  const { signOutNative } = await import('../src/native-sessions.js');
  const journal = new Journal(':memory:', { installationId: 'installation', bootId: 'boot' });
  try {
    const keys = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    const publicKey = keys.publicKey.export({ format: 'jwk' });
    const approval = new ApprovalService(journal, { mode: 'synthetic', clock: () => 2000 });
    approval.bootstrapApprover({ signerId: 'phone', role: 'routine', publicKey, localBootstrap: createLocalBootstrapContext(), confirmedFingerprint: publicKeyFingerprint(publicKey) });
    const value: import('../src/manifest.js').ApprovalManifest = { version: 1, domain: 'keyroot.approval.v1', algorithm: 'ECDSA-P256-SHA256', audience: 'keyroot-controller', installationId: 'installation', bootId: 'boot', signerId: 'phone', role: 'routine', nonce: 'native-grant', notBefore: 1000, expiresAt: 10000, budgets: { executions: 1, newCredentials: 0, restarts: 0, effects: 1 }, operations: [{ operationId: 'op', accountId: 'account', lineageId: 'native', fromGeneration: 1, toGeneration: 2, actions: [{ id: 'logout', kind: 'sign-out', parameters: { resourceId: 'native:codex:local', generation: 1 }, budgetCost: { effects: 1, newCredentials: 0, restarts: 0 } }] }], consumerMap: { revision: '1', hash: contentDigest([]), entries: [] }, recipes: [], adoptionThreshold: 'direct-use-every-consumer', overlapPolicy: 'required', deadline: { at: 9000, outcome: 'hold' }, outage: { permitted: false, consequence: 'none' }, graceSeconds: 900 };
    const raw = canonicalizeManifest(value); const signature = sign('sha256', Buffer.from(raw), { key: keys.privateKey, dsaEncoding: 'ieee-p1363' }).toString('base64url');
    approval.registerGrant(raw, signature, 2000);
    const request = { grantId: value.nonce, signature, operationId: 'op', actionId: 'logout', currentSnapshotDigest: snapshotDigest(value), now: 2000 };
    const executor = { execute: async () => { throw new Error('sentinel-secret'); } };
    await assert.rejects(signOutNative({ client: 'codex', approval, request, executor }), /outcome unknown/);
    assert.equal(journal.listIntents('op')[0]?.state, 'pending');
    const receipts = journal.listReceipts('op');
    assert.equal(receipts[0]?.outcome, 'unknown');
    assert.equal(receipts[0]?.kind, 'sign-out');
    assert.ok(!JSON.stringify(receipts).includes('sentinel-secret'));
    await assert.rejects(signOutNative({ client: 'codex', approval, request, executor }));
  } finally { journal.close(); }
});
