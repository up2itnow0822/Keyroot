import { test } from 'node:test';
import { strict as assert } from 'node:assert';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { generateKeyPairSync, sign } from 'node:crypto';
import { canonicalizeManifest, parseCanonicalManifest, snapshotDigest, contentDigest, type ApprovalManifest } from '../src/manifest.js';
import { Journal } from '../src/journal.js';
import { ApprovalService, publicKeyFingerprint, createLocalBootstrapContext } from '../src/approval.js';
export function manifest(): ApprovalManifest {
    return { version: 1, domain: 'keyroot.approval.v1', algorithm: 'ECDSA-P256-SHA256', audience: 'keyroot-controller', installationId: 'installation', bootId: 'boot', signerId: 'phone', role: 'routine', nonce: 'nonce-unique', notBefore: 1000, expiresAt: 10000, budgets: { executions: 1, newCredentials: 1, restarts: 1, effects: 3 }, operations: [{ operationId: 'op', accountId: 'account', lineageId: 'lineage', fromGeneration: 1, toGeneration: 2, actions: [{ id: 'create', kind: 'create', parameters: { resourceId: 'resource', adapterId: 'fixture', generation: 2, handleId: 'store-handle', destinationId: 'vault-target' }, budgetCost: { effects: 1, newCredentials: 1, restarts: 0 } }, { id: 'deliver', kind: 'deliver', parameters: { consumerId: 'consumer', destinationId: 'host-path-id', handleId: 'store-handle', generation: 2 }, budgetCost: { effects: 1, newCredentials: 0, restarts: 0 } }] }], consumerMap: { revision: '1', hash: contentDigest([{ consumerId: 'consumer', resourceId: 'resource', revision: '1' }]), entries: [{ consumerId: 'consumer', resourceId: 'resource', revision: '1' }] }, recipes: [], adoptionThreshold: 'direct-use-every-consumer', overlapPolicy: 'required', deadline: { at: 9000, outcome: 'hold' }, outage: { permitted: false, consequence: 'none' }, graceSeconds: 900 };
}
export function fixture(file = join(mkdtempSync(join(tmpdir(), 'keyroot-u3-')), 'journal.sqlite')) {
    const journal = new Journal(file, { installationId: 'installation', bootId: 'boot' });
    const keys = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    const jwk = keys.publicKey.export({ format: 'jwk' });
    const approvals = new ApprovalService(journal, { mode: 'synthetic' });
    approvals.bootstrapApprover({ signerId: 'phone', role: 'routine', publicKey: jwk, localBootstrap: createLocalBootstrapContext(), confirmedFingerprint: publicKeyFingerprint(jwk) });
    const value = manifest();
    const raw = canonicalizeManifest(value);
    const signature = sign('sha256', Buffer.from(raw), { key: keys.privateKey, dsaEncoding: 'ieee-p1363' }).toString('base64url');
    approvals.registerGrant(raw, signature, 2000);
    return { journal, approvals, value, raw, signature, file, keys };
}
test('U3 canonical manifest rejects duplicate, unknown, unsafe and policy tampering before signature', () => {
    const raw = canonicalizeManifest(manifest());
    assert.deepEqual(parseCanonicalManifest(raw), manifest());
    assert.throws(() => parseCanonicalManifest(raw.replace('"version":1', '"version":1,"version":1')));
    assert.throws(() => parseCanonicalManifest(raw.replace('"version":1', '"unknown":true,"version":1')));
    assert.throws(() => parseCanonicalManifest(raw.replace('"graceSeconds":900', '"graceSeconds":9007199254740992')));
    const f = fixture();
    assert.throws(() => f.approvals.registerGrant(canonicalizeManifest({ ...f.value, adoptionThreshold: 'informed-override' }), f.signature, 2000));
    f.journal.close();
});
test('U3 admission once, stable intent before effect, bounded steps and cancellation', async () => {
    const f = fixture();
    const request = { grantId: f.value.nonce, signature: f.signature, operationId: 'op', actionId: 'create', currentSnapshotDigest: snapshotDigest(f.value), now: 2000 };
    const intent = await f.approvals.authorizeEffect(request);
    assert.equal(Object.isFrozen(intent), true);
    assert.equal(f.journal.listIntents('op').length, 1);
    await assert.rejects(f.approvals.authorizeEffect(request));
    f.journal.appendReceipt({ receiptId: 'receipt-create', intentId: intent.intentId, kind: 'creation', outcome: 'confirmed', generation: 2, observedAt: 2001, observerId: 'synthetic', evidenceHash: 'sha256:synthetic', limitationCodes: ['synthetic-only'] });
    const next = await f.approvals.authorizeEffect({ ...request, actionId: 'deliver' });
    assert.equal(next.operationId, 'op');
    f.approvals.cancelGrant(f.value.nonce);
    await assert.rejects(f.approvals.authorizeEffect({ ...request, actionId: 'deliver' }));
    f.journal.close();
});
test('U3 two connections cannot consume same instance or forget live lineage', async () => {
    const f = fixture();
    const second = new Journal(f.file, { installationId: 'installation', bootId: 'boot' });
    const approvals = new ApprovalService(second, { mode: 'synthetic' });
    const req = { grantId: f.value.nonce, signature: f.signature, operationId: 'op', actionId: 'create', currentSnapshotDigest: snapshotDigest(f.value), now: 2000 };
    const results = await Promise.allSettled([f.approvals.authorizeEffect(req), approvals.authorizeEffect(req)]);
    assert.equal(results.filter(r => r.status === 'fulfilled').length, 1);
    assert.throws(() => second.createOperation({ operationId: 'other', lineageId: 'lineage', accountId: 'account', fromGeneration: 1, toGeneration: 2 }));
    second.close();
    f.journal.close();
});
test('U3 restart invalidates grants, retains intent and requires reconciliation', async () => {
    const f = fixture();
    await f.approvals.authorizeEffect({ grantId: f.value.nonce, signature: f.signature, operationId: 'op', actionId: 'create', currentSnapshotDigest: snapshotDigest(f.value), now: 2000 });
    f.journal.close();
    const restored = new Journal(f.file, { installationId: 'installation', bootId: 'new-boot' });
    assert.equal(restored.inspectOperation('op')?.state, 'reconcile-required');
    assert.equal(restored.listIntents('op').length, 1);
    await assert.rejects(new ApprovalService(restored, { mode: 'synthetic' }).authorizeEffect({ grantId: f.value.nonce, signature: f.signature, operationId: 'op', actionId: 'deliver', currentSnapshotDigest: snapshotDigest(f.value), now: 2000 }));
    restored.close();
});
test('U3 budgets derive minimum create/restart costs and cannot be bypassed with signed zero', () => {
    const m = manifest();
    m.operations[0]!.actions[0]!.budgetCost.newCredentials = 0;
    assert.throws(() => canonicalizeManifest(m), /understates/);
    const restart = manifest();
    restart.operations[0]!.actions[0] = { id: 'restart', kind: 'restart', parameters: { resourceId: 'resource', consumerId: 'consumer', generation: 2 }, budgetCost: { effects: 1, newCredentials: 0, restarts: 0 } };
    assert.throws(() => canonicalizeManifest(restart), /understates/);
});
test('U3 cancellation, expiry, changed snapshot, wrong signature and wrong role fail closed', async () => {
    for (const variant of ['cancel', 'expire', 'snapshot', 'signature', 'role'] as const) {
        const f = fixture();
        if (variant === 'cancel')
            f.approvals.cancelGrant(f.value.nonce);
        if (variant === 'role')
            f.journal.transaction(db => {
                db.prepare("UPDATE approver SET role='emergency'").run();
            });
        await assert.rejects(f.approvals.authorizeEffect({ grantId: f.value.nonce, signature: variant === 'signature' ? 'wrong' : f.signature, operationId: 'op', actionId: 'create', currentSnapshotDigest: variant === 'snapshot' ? 'changed' : snapshotDigest(f.value), now: variant === 'expire' ? 10000 : 2000 }));
        assert.equal(f.journal.listIntents('op').length, 0);
        f.journal.close();
    }
});
test('U3 budget exhaustion is transactional and no second operation is admitted', async () => {
    const f = fixture();
    f.approvals.cancelGrant(f.value.nonce);
    const value = manifest();
    value.nonce = 'one-effect';
    value.budgets.effects = 1;
    value.operations[0]!.actions[0]!.budgetCost.newCredentials = 1;
    const raw = canonicalizeManifest(value);
    const signature = sign('sha256', Buffer.from(raw), { key: f.keys.privateKey, dsaEncoding: 'ieee-p1363' }).toString('base64url');
    f.approvals.registerGrant(raw, signature, 2000);
    const req = { grantId: value.nonce, signature, operationId: 'op', actionId: 'create', currentSnapshotDigest: snapshotDigest(value), now: 2000 };
    const intent = await f.approvals.authorizeEffect(req);
    f.journal.appendReceipt({ receiptId: 'created', intentId: intent.intentId, kind: 'creation', outcome: 'confirmed', generation: 2, observedAt: 2001, observerId: 'fixture', evidenceHash: 'sha256:fixture', limitationCodes: ['synthetic-only'] });
    await assert.rejects(f.approvals.authorizeEffect({ ...req, actionId: 'deliver' }), /budget/);
    assert.equal(f.journal.listIntents('op').length, 1);
    f.journal.close();
});
test('U3 receipt schema refuses raw payload, unknown outcome and forgetting ambiguous actions', async () => {
    const f = fixture();
    const intent = await f.approvals.authorizeEffect({ grantId: f.value.nonce, signature: f.signature, operationId: 'op', actionId: 'create', currentSnapshotDigest: snapshotDigest(f.value), now: 2000 });
    assert.throws(() => f.journal.completeOperation('op'), /ambiguous/);
    assert.throws(() => f.journal.reconcileOperation('op'), /reconciliation/);
    const receipt = { receiptId: 'created', intentId: intent.intentId, kind: 'creation' as const, outcome: 'confirmed' as const, generation: 2, observedAt: 2001, observerId: 'fixture', evidenceHash: 'sha256:fixture', limitationCodes: ['synthetic-only'] };
    assert.throws(() => f.journal.appendReceipt({ ...receipt, rawPayload: 'secret' } as typeof receipt), /payload/);
    f.journal.close();
});
test('U3 public bootstrap requires local capability, empty trust and independently compared public fingerprint', () => {
    const f = fixture();
    assert.throws(() => f.approvals.bootstrapApprover({ signerId: 'another', role: 'routine', publicKey: f.keys.publicKey.export({ format: 'jwk' }), localBootstrap: createLocalBootstrapContext(), confirmedFingerprint: publicKeyFingerprint(f.keys.publicKey.export({ format: 'jwk' })) }), /not empty/);
    assert.throws(() => f.approvals.bootstrapApprover({ signerId: 'other', role: 'routine', publicKey: f.keys.publicKey.export({ format: 'jwk' }), localBootstrap: { kind: 'local-console-bootstrap' }, confirmedFingerprint: 'made-up' }), /trusted local/);
    assert.throws(() => publicKeyFingerprint(f.keys.privateKey.export({ format: 'jwk' })), /public P-256/);
    f.journal.close();
});
test('U3 every immutable map/recipe/policy/succession/action parameter is signed', () => {
    const f = fixture();
    const mutations = [(m: ApprovalManifest) => {
            m.consumerMap.entries[0]!.revision = '2';
            m.consumerMap.hash = contentDigest(m.consumerMap.entries);
        }, (m: ApprovalManifest) => {
            m.recipes = [{ id: 'recipe', version: '1', steps: [{ action: 'deliver', resourceId: 'resource' }], hash: contentDigest([{ action: 'deliver', resourceId: 'resource' }]) }];
        }, (m: ApprovalManifest) => {
            m.overlapPolicy = 'unavailable';
            m.outage = { permitted: true, consequence: 'declared-interruption' };
        }, (m: ApprovalManifest) => {
            m.budgets.restarts = 2;
        }, (m: ApprovalManifest) => {
            m.operations[0]!.fromGeneration = 2;
            m.operations[0]!.toGeneration = 3;
            m.operations[0]!.actions.forEach(a => {
                a.parameters.generation = 3;
            });
        }, (m: ApprovalManifest) => {
            m.operations[0]!.actions[1]!.parameters.destinationId = 'another-destination';
        }];
    for (const mutate of mutations) {
        const m = structuredClone(f.value);
        mutate(m);
        assert.throws(() => f.approvals.registerGrant(canonicalizeManifest(m), f.signature, 2000), /signature/);
    }
    f.journal.close();
});
import { createHash } from 'node:crypto';
import { copyFileSync, writeFileSync } from 'node:fs';
import { isoCBOR } from '@simplewebauthn/server/helpers';
import type { AuthenticationResponseJSON } from '@simplewebauthn/server';
import { EmergencyWebAuthn, emergencyEnrollmentFingerprint } from '../src/emergency-webauthn.js';
import { InstallationEpoch, type EpochRecord, type InstallationEpochStore } from '../src/installation-epoch.js';
import { BootFence } from '../src/boot-fence.js';
function emergencyFixture() {
    const journal = new Journal(join(mkdtempSync(join(tmpdir(), 'keyroot-u3-emergency-')), 'journal.sqlite'), { installationId: 'installation', bootId: 'boot' });
    const keys = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    const jwk = keys.publicKey.export({ format: 'jwk' });
    const cose = isoCBOR.encode(new Map<number, number | Uint8Array>([[1, 2], [3, -7], [-1, 1], [-2, Buffer.from(jwk.x!, 'base64url')], [-3, Buffer.from(jwk.y!, 'base64url')]]));
    const emergency = new EmergencyWebAuthn(journal, { clock: () => 2001 });
    const credentialId = Buffer.from('synthetic-security-key').toString('base64url');
    emergency.bootstrapCredential({ signerId: 'emergency', credentialId, cosePublicKey: cose, rpId: 'approve.keyroot.test', origin: 'https://approve.keyroot.test', localBootstrap: createLocalBootstrapContext(), confirmedFingerprint: publicKeyFingerprint(jwk) });
    const approvals = new ApprovalService(journal, { mode: 'synthetic' });
    const value = manifest();
    value.role = 'emergency';
    value.signerId = 'emergency';
    value.nonce = 'emergency-nonce';
    approvals.registerEmergencyGrant(canonicalizeManifest(value), 2000);
    return { journal, keys, jwk, emergency, approvals, value, credentialId };
}
function assertion(f: ReturnType<typeof emergencyFixture>, challenge: string, options: {
    origin?: string;
    rpId?: string;
    flags?: number;
    counter?: number;
    signatureKey?: ReturnType<typeof generateKeyPairSync>['privateKey'];
} = {}): AuthenticationResponseJSON {
    const client = Buffer.from(JSON.stringify({ type: 'webauthn.get', challenge, origin: options.origin ?? 'https://approve.keyroot.test', crossOrigin: false }));
    const counter = Buffer.alloc(4);
    counter.writeUInt32BE(options.counter ?? 1);
    const authData = Buffer.concat([createHash('sha256').update(options.rpId ?? 'approve.keyroot.test').digest(), Buffer.from([options.flags ?? 5]), counter]);
    const signed = Buffer.concat([authData, createHash('sha256').update(client).digest()]);
    return { id: f.credentialId, rawId: f.credentialId, type: 'public-key', clientExtensionResults: {}, response: { clientDataJSON: client.toString('base64url'), authenticatorData: authData.toString('base64url'), signature: sign('sha256', signed, options.signatureKey ?? f.keys.privateKey).toString('base64url') } };
}
test('U3 maintained WebAuthn positive synthetic protocol verifies then consumes one exact emergency action', async () => {
    const f = emergencyFixture();
    const challenge = f.emergency.createChallenge({ grantId: f.value.nonce, operationId: 'op', actionId: 'create', now: 2000 });
    const response = assertion(f, challenge.challenge);
    const proof = await f.emergency.verifyAssertion({ challengeId: challenge.challengeId, operationId: 'op', actionId: 'create', response, now: 2001 });
    const intent = await f.approvals.authorizeEffect({ grantId: f.value.nonce, operationId: 'op', actionId: 'create', currentSnapshotDigest: snapshotDigest(f.value), emergencyProofId: proof, now: 2002 });
    assert.equal(intent.kind, 'create');
    await assert.rejects(f.emergency.verifyAssertion({ challengeId: challenge.challengeId, operationId: 'op', actionId: 'create', response, now: 2003 }), /Stale/);
    await assert.rejects(f.approvals.authorizeEffect({ grantId: f.value.nonce, operationId: 'op', actionId: 'create', currentSnapshotDigest: snapshotDigest(f.value), emergencyProofId: proof, now: 2003 }), /assertion/);
    f.journal.close();
});
test('U3 emergency denies wrong challenge, digest, RP, origin, presence, verification, credential, signature and action', async () => {
    for (const variant of ['challenge', 'digest', 'rp', 'origin', 'presence', 'verification', 'credential', 'signature', 'action', 'stale'] as const) {
        const f = emergencyFixture();
        const challenge = f.emergency.createChallenge({ grantId: f.value.nonce, operationId: 'op', actionId: 'create', now: 2000 });
        const options = variant === 'rp' ? { rpId: 'evil.test' } : variant === 'origin' ? { origin: 'https://evil.test' } : variant === 'presence' ? { flags: 4 } : variant === 'verification' ? { flags: 1 } : variant === 'signature' ? { signatureKey: generateKeyPairSync('ec', { namedCurve: 'prime256v1' }).privateKey } : {};
        const response = assertion(f, variant === 'challenge' || variant === 'digest' ? Buffer.from('another-manifest-digest').toString('base64url') : challenge.challenge, options);
        if (variant === 'credential')
            response.id = 'another-key';
        await assert.rejects(f.emergency.verifyAssertion({ challengeId: challenge.challengeId, operationId: 'op', actionId: variant === 'action' ? 'deliver' : 'create', response, now: variant === 'stale' ? 10000 : 2001 }), variant);
        assert.equal(f.journal.listIntents('op').length, 0);
        f.journal.close();
    }
});
test('U3 role separation disallows routine grant through emergency path and imported verified flags', async () => {
    const f = fixture();
    assert.throws(() => f.approvals.registerEmergencyGrant(f.raw, 2000), /role/);
    f.journal.close();
    const e = emergencyFixture();
    assert.throws(() => e.approvals.registerGrant(canonicalizeManifest(e.value), '', 2000), /WebAuthn/);
    await assert.rejects(e.approvals.authorizeEffect({ grantId: e.value.nonce, operationId: 'op', actionId: 'create', currentSnapshotDigest: snapshotDigest(e.value), now: 2000, emergencyProofId: 'verified-true' }), /assertion/);
    e.journal.close();
});
class MemoryEpoch implements InstallationEpochStore {
    current: EpochRecord | undefined;
    async read() {
        return this.current ? { ...this.current } : undefined;
    }
    async compareAndSet(expected: number | undefined, next: Omit<EpochRecord, 'version'>) {
        if (this.current?.version !== expected)
            return undefined;
        this.current = { ...next, version: (expected ?? 0) + 1 };
        return { ...this.current };
    }
}
test('U3 epoch CAS detects simultaneous clones and prevents later dispatch', async () => {
    const store = new MemoryEpoch();
    const f = fixture();
    const other = new Journal(join(mkdtempSync(join(tmpdir(), 'keyroot-u3-clone-')), 'clone.sqlite'), { installationId: 'installation', bootId: 'clone' });
    const a = new InstallationEpoch('installation', store, f.journal);
    const b = new InstallationEpoch('installation', store, other);
    const results = await Promise.allSettled([a.establishFresh(), b.establishFresh()]);
    assert.equal(results.filter(r => r.status === 'fulfilled').length, 1);
    await a.assertBeforeEffect();
    await b.recover({ predecessor: 'quiesced', evidenceHash: 'sha256:' + 'a'.repeat(64), inFlightOutcomes: 'reconciled' });
    await assert.rejects(a.assertBeforeEffect(), /epoch lost/);
    await b.assertBeforeEffect();
    f.journal.close();
    other.close();
});
test('U3 restored pending upstream work remains unknown; epoch cannot promise to cancel request', async () => {
    const f = fixture();
    const store = new MemoryEpoch();
    const original = new InstallationEpoch('installation', store, f.journal);
    await original.establishFresh();
    const intent = await f.approvals.authorizeEffect({ grantId: f.value.nonce, signature: f.signature, operationId: 'op', actionId: 'create', currentSnapshotDigest: snapshotDigest(f.value), now: 2000 });
    let finish!: () => void;
    let issuedEffects = 0;
    const upstream = new Promise<void>(resolve => {
        finish = () => {
            issuedEffects++;
            resolve();
        };
    });
    f.journal.read(db => db.exec('PRAGMA wal_checkpoint(TRUNCATE)'));
    const path = join(mkdtempSync(join(tmpdir(), 'keyroot-u3-restore-')), 'copy.sqlite');
    copyFileSync(f.file, path);
    const restored = new Journal(path, { installationId: 'installation', bootId: 'restore' });
    const epoch = new InstallationEpoch('installation', store, restored);
    await assert.rejects(epoch.establishFresh(), /recovery/);
    await assert.rejects(epoch.recover({ predecessor: 'management-authority-invalidated', evidenceHash: 'sha256:' + 'b'.repeat(64), inFlightOutcomes: 'reconciled' }), /Unreconciled/);
    finish();
    await upstream;
    assert.equal(issuedEffects, 1);
    restored.appendReceipt({ receiptId: 'external-reconciliation', intentId: intent.intentId, kind: 'reconciliation', outcome: 'confirmed', generation: 2, observedAt: 3000, observerId: 'fixture', evidenceHash: 'sha256:fixture', limitationCodes: ['synthetic-only'] });
    await epoch.recover({ predecessor: 'management-authority-invalidated', evidenceHash: 'sha256:' + 'b'.repeat(64), inFlightOutcomes: 'reconciled' });
    await epoch.assertBeforeEffect();
    await assert.rejects(original.assertBeforeEffect());
    f.journal.close();
    restored.close();
});
test('U3 OS singleton refuses live and stale sockets until explicit reconciliation', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'kr-u3-'));
    const path = join(dir, 'controller.sock');
    const fence = await BootFence.acquire(path);
    await assert.rejects(BootFence.acquire(path), /reconciliation/);
    await fence.release();
    const next = await BootFence.acquire(path);
    assert.notEqual(next.bootId, fence.bootId);
    await next.release();
    writeFileSync(path, 'stale');
    await assert.rejects(BootFence.acquire(path), /reconciliation/);
});
test('U3 each execution/new-credential/restart budget is independently enforced', async () => {
    for (const budget of ['executions', 'newCredentials', 'restarts'] as const) {
        const f = fixture();
        const m = manifest();
        m.nonce = 'budget-' + budget;
        m.budgets[budget] = 0;
        if (budget === 'restarts')
            m.operations[0]!.actions = [{ id: 'create', kind: 'restart', parameters: { consumerId: 'consumer', resourceId: 'resource', generation: 2 }, budgetCost: { effects: 1, newCredentials: 0, restarts: 1 } }];
        const raw = canonicalizeManifest(m);
        const signature = sign('sha256', Buffer.from(raw), { key: f.keys.privateKey, dsaEncoding: 'ieee-p1363' }).toString('base64url');
        f.approvals.registerGrant(raw, signature, 2000);
        await assert.rejects(f.approvals.authorizeEffect({ grantId: m.nonce, signature, operationId: 'op', actionId: 'create', currentSnapshotDigest: snapshotDigest(m), now: 2000 }), /budget/);
        assert.equal(f.journal.inspectOperation('op'), undefined);
        f.journal.close();
    }
});
test('U3 restart needs actual reconciliation AND fresh authority; stable action is never recreated', async () => {
    const f = fixture();
    const first = await f.approvals.authorizeEffect({ grantId: f.value.nonce, signature: f.signature, operationId: 'op', actionId: 'create', currentSnapshotDigest: snapshotDigest(f.value), now: 2000 });
    f.journal.registerSession('owner-session');
    assert.equal(f.journal.sessionActive('owner-session'), true);
    f.journal.close();
    const journal = new Journal(f.file, { installationId: 'installation', bootId: 'next-boot' });
    assert.equal(journal.sessionActive('owner-session'), false);
    journal.appendReceipt({ receiptId: 'reconcile-create', intentId: first.intentId, kind: 'reconciliation', outcome: 'confirmed', generation: 2, observedAt: 3000, observerId: 'fixture', evidenceHash: 'sha256:fixture', resourceId: 'created-id', handleId: 'store-handle', limitationCodes: ['synthetic-only'] });
    journal.reconcileOperation('op');
    const approvals = new ApprovalService(journal, { mode: 'synthetic' });
    const m = manifest();
    m.bootId = 'next-boot';
    m.nonce = 'fresh-grant';
    const raw = canonicalizeManifest(m);
    const signature = sign('sha256', Buffer.from(raw), { key: f.keys.privateKey, dsaEncoding: 'ieee-p1363' }).toString('base64url');
    approvals.registerGrant(raw, signature, 3000);
    await assert.rejects(approvals.authorizeEffect({ grantId: m.nonce, signature, operationId: 'op', actionId: 'create', currentSnapshotDigest: snapshotDigest(m), now: 3000 }), /consumed/);
    const next = await approvals.authorizeEffect({ grantId: m.nonce, signature, operationId: 'op', actionId: 'deliver', currentSnapshotDigest: snapshotDigest(m), now: 3000 });
    assert.equal(next.operationId, 'op');
    assert.equal(journal.listIntents('op').length, 2);
    journal.close();
});
test('U3 emergency enrollment after phone pairing requires exact signed admin intent', async () => {
    const f = fixture();
    const keys = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    const jwk = keys.publicKey.export({ format: 'jwk' });
    const enrollment = { signerId: 'yubikey', credentialId: Buffer.from('hardware-synthetic').toString('base64url'), cosePublicKey: isoCBOR.encode(new Map<number, number | Uint8Array>([[1, 2], [3, -7], [-1, 1], [-2, Buffer.from(jwk.x!, 'base64url')], [-3, Buffer.from(jwk.y!, 'base64url')]])), rpId: 'approve.keyroot.test', origin: 'https://approve.keyroot.test' };
    const m = manifest();
    m.nonce = 'enroll-key';
    m.operations[0]!.actions = [{ id: 'enroll', kind: 'admin', parameters: { resourceId: 'emergency-approver', destinationId: 'yubikey', authorityFingerprint: emergencyEnrollmentFingerprint(enrollment) }, budgetCost: { effects: 1, newCredentials: 0, restarts: 0 } }];
    const raw = canonicalizeManifest(m);
    const signature = sign('sha256', Buffer.from(raw), { key: f.keys.privateKey, dsaEncoding: 'ieee-p1363' }).toString('base64url');
    f.approvals.registerGrant(raw, signature, 2000);
    const intent = await f.approvals.authorizeEffect({ grantId: m.nonce, signature, operationId: 'op', actionId: 'enroll', currentSnapshotDigest: snapshotDigest(m), now: 2000 });
    const emergency = new EmergencyWebAuthn(f.journal, { clock: () => 2001 });
    assert.throws(() => emergency.enrollCredential({ ...enrollment, origin: 'https://evil.test', authorizationIntentId: intent.intentId, now: 2000, confirmedFingerprint: publicKeyFingerprint(jwk) }));
    emergency.enrollCredential({ ...enrollment, authorizationIntentId: intent.intentId, now: 2000, confirmedFingerprint: publicKeyFingerprint(jwk) });
    assert.equal(f.journal.listIntents('op')[0]!.state, 'observed');
    assert.throws(() => emergency.enrollCredential({ ...enrollment, authorizationIntentId: intent.intentId, now: 2000, confirmedFingerprint: publicKeyFingerprint(jwk) }), /intent required/);
    f.journal.close();
});
test('U3 compound create/store continuation rechecks exact authority without consuming another intent', async () => {
    const f = fixture();
    const m = manifest();
    m.nonce = 'compound-create';
    m.operations[0]!.actions[0]!.budgetCost.effects = 2;
    const raw = canonicalizeManifest(m);
    const signature = sign('sha256', Buffer.from(raw), { key: f.keys.privateKey, dsaEncoding: 'ieee-p1363' }).toString('base64url');
    f.approvals.registerGrant(raw, signature, 2000);
    const request = { grantId: m.nonce, signature, operationId: 'op', actionId: 'create', currentSnapshotDigest: snapshotDigest(m), now: 2000 };
    const intent = await f.approvals.authorizeEffect(request);
    const current = await f.approvals.assertCurrentAuthority({ ...request, intentId: intent.intentId });
    assert.equal(current.intentId, intent.intentId);
    assert.equal(current.parameters.handleId, 'store-handle');
    assert.equal(f.journal.listIntents('op').length, 1);
    f.approvals.cancelGrant(m.nonce);
    await assert.rejects(f.approvals.assertCurrentAuthority({ ...request, intentId: intent.intentId }), /Cancelled/);
    assert.equal(f.journal.listIntents('op').length, 1);
    f.journal.close();
});
test('U3 unsigned compound store and changed continuation snapshots are denied', async () => {
    const f = fixture();
    const request = { grantId: f.value.nonce, signature: f.signature, operationId: 'op', actionId: 'create', currentSnapshotDigest: snapshotDigest(f.value), now: 2000 };
    const intent = await f.approvals.authorizeEffect(request);
    await assert.rejects(f.approvals.assertCurrentAuthority({ ...request, intentId: intent.intentId }), /two effects/);
    await assert.rejects(f.approvals.assertCurrentAuthority({ ...request, currentSnapshotDigest: 'changed', intentId: intent.intentId }), /scope/);
    f.journal.close();
});
test('U3 pending create permits only separately authorized concrete old-resource containment in same operation', async () => {
    for (const variant of ['old-revoke', 'ambiguous-target', 'create', 'deliver', 'competing-operation'] as const) {
        const f = emergencyFixture();
        const challenge = f.emergency.createChallenge({ grantId: f.value.nonce, operationId: 'op', actionId: 'create', now: 2000 });
        const proof = await f.emergency.verifyAssertion({ challengeId: challenge.challengeId, operationId: 'op', actionId: 'create', response: assertion(f, challenge.challenge), now: 2001 });
        const first = await f.approvals.authorizeEffect({ grantId: f.value.nonce, operationId: 'op', actionId: 'create', currentSnapshotDigest: snapshotDigest(f.value), emergencyProofId: proof, now: 2002 });
        // Existing routine window is independently cancellable and must be cancelled by accepted containment.
        f.journal.transaction(db => db.prepare("INSERT INTO approval_grant(grant_id,raw_manifest,signature,digest,boot_id,role) VALUES(?,?,?,?,?,?)").run('routine-window', canonicalizeManifest(manifest()), 'unused', 'metadata-digest', 'boot', 'routine'));
        const m = manifest();
        m.role = 'emergency';
        m.signerId = 'emergency';
        m.nonce = 'contain-' + variant;
        const op = m.operations[0]!;
        if (variant === 'competing-operation')
            op.operationId = 'competing-op';
        op.actions = [variant === 'create' ? { ...f.value.operations[0]!.actions[0]!, id: 'contain' } : variant === 'deliver' ? { ...f.value.operations[0]!.actions[1]!, id: 'contain' } : { id: 'contain', kind: 'revoke', parameters: { resourceId: variant === 'ambiguous-target' ? 'resource' : 'known-old-key', handleId: 'old-handle', generation: 1 }, budgetCost: { effects: 1, newCredentials: 0, restarts: 0 } }];
        f.approvals.registerEmergencyGrant(canonicalizeManifest(m), 2002);
        const c = f.emergency.createChallenge({ grantId: m.nonce, operationId: op.operationId, actionId: 'contain', now: 2003 });
        const p = await f.emergency.verifyAssertion({ challengeId: c.challengeId, operationId: op.operationId, actionId: 'contain', response: assertion(f, c.challenge, { counter: 2 }), now: 2004 });
        const request = { grantId: m.nonce, operationId: op.operationId, actionId: 'contain', currentSnapshotDigest: snapshotDigest(m), emergencyProofId: p, now: 2005 };
        if (variant === 'old-revoke') {
            const containment = await f.approvals.authorizeEffect(request);
            assert.equal(containment.kind, 'revoke');
            assert.equal(f.journal.inspectOperation('op')!.state, 'reconcile-required');
            assert.equal(f.journal.listIntents('op').find(i => i.intentId === first.intentId)!.state, 'pending');
            assert.equal(f.journal.read(db => db.prepare('SELECT cancelled FROM approval_grant WHERE grant_id=?').get('routine-window')!.cancelled), 1);
            assert.throws(() => f.journal.completeOperation('op'));
        }
        else
            await assert.rejects(f.approvals.authorizeEffect(request));
        f.journal.close();
    }
});
async function attachEmergencyToPhone(f: ReturnType<typeof fixture>) {
    const keys = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    const jwk = keys.publicKey.export({ format: 'jwk' });
    const enrollment = { signerId: 'emergency', credentialId: Buffer.from('second-role-key').toString('base64url'), cosePublicKey: isoCBOR.encode(new Map<number, number | Uint8Array>([[1, 2], [3, -7], [-1, 1], [-2, Buffer.from(jwk.x!, 'base64url')], [-3, Buffer.from(jwk.y!, 'base64url')]])), rpId: 'approve.keyroot.test', origin: 'https://approve.keyroot.test' };
    const m = manifest();
    m.nonce = 'enroll-reservation-key';
    m.operations = [{ operationId: 'enroll-op', lineageId: 'owner-lineage', accountId: 'account', fromGeneration: 0, toGeneration: 1, actions: [{ id: 'enroll', kind: 'admin', parameters: { resourceId: 'emergency-approver', destinationId: 'emergency', authorityFingerprint: emergencyEnrollmentFingerprint(enrollment) }, budgetCost: { effects: 1, newCredentials: 0, restarts: 0 } }] }];
    const raw = canonicalizeManifest(m);
    const signature = sign('sha256', Buffer.from(raw), { key: f.keys.privateKey, dsaEncoding: 'ieee-p1363' }).toString('base64url');
    f.approvals.registerGrant(raw, signature, 2000);
    const intent = await f.approvals.authorizeEffect({ grantId: m.nonce, signature, operationId: 'enroll-op', actionId: 'enroll', currentSnapshotDigest: snapshotDigest(m), now: 2000 });
    const emergency = new EmergencyWebAuthn(f.journal, { clock: () => 2001 });
    emergency.enrollCredential({ ...enrollment, authorizationIntentId: intent.intentId, now: 2000, confirmedFingerprint: publicKeyFingerprint(jwk) });
    return { ...f, keys, jwk, emergency, credentialId: enrollment.credentialId };
}
test('U3 unsigned emergency preparation cannot reserve or cancel; verified assertion reserves all lineages before dispatch', async () => {
    const f = fixture();
    const e = await attachEmergencyToPhone(f);
    const compound = manifest();
    compound.nonce = 'routine-compound';
    compound.operations[0]!.actions[0]!.budgetCost.effects = 2;
    const raw = canonicalizeManifest(compound);
    const signature = sign('sha256', Buffer.from(raw), { key: f.keys.privateKey, dsaEncoding: 'ieee-p1363' }).toString('base64url');
    f.approvals.registerGrant(raw, signature, 2000);
    const emergency = manifest();
    emergency.role = 'emergency';
    emergency.signerId = 'emergency';
    emergency.nonce = 'multi-lineage-emergency';
    emergency.budgets.executions = 2;
    emergency.operations[0]!.actions = [{ id: 'contain', kind: 'revoke', parameters: { resourceId: 'known-old-key', handleId: 'old-handle', generation: 1 }, budgetCost: { effects: 1, newCredentials: 0, restarts: 0 } }];
    emergency.operations.push({ ...structuredClone(emergency.operations[0]!), operationId: 'second-op', lineageId: 'second-lineage' });
    f.approvals.registerEmergencyGrant(canonicalizeManifest(emergency), 2000);
    assert.equal(f.journal.read(db => db.prepare('SELECT count(*) AS n FROM emergency_reservation').get()!.n), 0);
    assert.equal(f.journal.read(db => db.prepare('SELECT cancelled FROM approval_grant WHERE grant_id=?').get(compound.nonce)!.cancelled), 0);
    const request = { grantId: compound.nonce, signature, operationId: 'op', actionId: 'create', currentSnapshotDigest: snapshotDigest(compound), now: 2000 };
    const intent = await f.approvals.authorizeEffect(request);
    await f.approvals.assertCurrentAuthority({ ...request, intentId: intent.intentId });
    const c = e.emergency.createChallenge({ grantId: emergency.nonce, operationId: 'op', actionId: 'contain', now: 2000 });
    await e.emergency.verifyAssertion({ challengeId: c.challengeId, operationId: 'op', actionId: 'contain', response: assertion({ ...e, value: emergency }, c.challenge), now: 2001 });
    assert.equal(f.journal.read(db => db.prepare('SELECT count(*) AS n FROM emergency_reservation').get()!.n), 2);
    assert.equal(f.journal.listIntents('op').length, 1);
    await assert.rejects(f.approvals.assertCurrentAuthority({ ...request, intentId: intent.intentId }), /Cancelled|reservation/);
    const future = manifest();
    future.nonce = 'post-emergency-routine';
    const futureRaw = canonicalizeManifest(future);
    const futureSignature = sign('sha256', Buffer.from(futureRaw), { key: f.keys.privateKey, dsaEncoding: 'ieee-p1363' }).toString('base64url');
    f.approvals.registerGrant(futureRaw, futureSignature, 2002);
    await assert.rejects(f.approvals.authorizeEffect({ grantId: future.nonce, signature: futureSignature, operationId: 'op', actionId: 'create', currentSnapshotDigest: snapshotDigest(future), now: 2002 }), /reservation/);
    f.journal.close();
});
test('U3 emergency proof has short expiry even while weekly authority remains valid', async () => {
    const f = emergencyFixture();
    const m = structuredClone(f.value);
    m.nonce = 'long-emergency';
    m.expiresAt = 100000;
    f.approvals.registerEmergencyGrant(canonicalizeManifest(m), 2000);
    const c = f.emergency.createChallenge({ grantId: m.nonce, operationId: 'op', actionId: 'create', now: 2000 });
    const proof = await f.emergency.verifyAssertion({ challengeId: c.challengeId, operationId: 'op', actionId: 'create', response: assertion(f, c.challenge), now: 2001 });
    await assert.rejects(f.approvals.authorizeEffect({ grantId: m.nonce, operationId: 'op', actionId: 'create', currentSnapshotDigest: snapshotDigest(m), emergencyProofId: proof, now: 32002 }), /assertion/);
    assert.equal(f.journal.listIntents('op').length, 0);
    f.journal.close();
});
test('U3 asynchronous verification rechecks trusted clock before reserving or issuing proof', async () => {
    const f = emergencyFixture();
    const c = f.emergency.createChallenge({ grantId: f.value.nonce, operationId: 'op', actionId: 'create', now: 2000 });
    const expired = new EmergencyWebAuthn(f.journal, { clock: () => 10000 });
    await assert.rejects(expired.verifyAssertion({ challengeId: c.challengeId, operationId: 'op', actionId: 'create', response: assertion(f, c.challenge), now: 2001 }), /expired during/);
    assert.equal(f.journal.read(db => db.prepare('SELECT count(*) AS n FROM emergency_reservation').get()!.n), 0);
    assert.equal(f.journal.read(db => db.prepare('SELECT count(*) AS n FROM emergency_proof').get()!.n), 0);
    f.journal.close();
});
