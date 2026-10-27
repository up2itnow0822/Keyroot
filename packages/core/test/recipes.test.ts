import { test } from 'node:test';
import { strict as assert } from 'node:assert';
import { makeRecipe, GuidedProcedure } from '../src/recipes/recipe.js';
import { proposeTrace } from '../src/recipes/trace.js';

test('guided recipe uses finite reviewed actions and sanitized proposal', () => {
    const recipe = makeRecipe({ id: 'vendor', version: '1', accountId: 'account', destinationId: 'store', steps: [{ action: 'open', targetId: 'credentials', checkpoint: 'none' }, { action: 'capture', targetId: 'new-key', checkpoint: 'mfa' }] });
    const guided = new GuidedProcedure(recipe);
    assert.equal(guided.current()?.targetId, 'credentials');
    guided.confirmStep('credentials');
    assert.equal(guided.current()?.checkpoint, 'mfa');
    assert.throws(() => guided.confirmStep('wrong'));
    assert.throws(() => makeRecipe({ ...recipe, steps: [{ action: 'open', targetId: 'https://evil', checkpoint: 'none' }] }));
    assert.throws(() => proposeTrace(recipe, [{ action: 'open', targetId: 'credentials', observation: 'token=supersecret' as 'visible' }]));
});

import { generateKeyPairSync, sign } from 'node:crypto';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Journal } from '../src/journal.js';
import { ApprovalService, createLocalBootstrapContext, publicKeyFingerprint } from '../src/approval.js';
import { canonicalizeManifest, contentDigest, snapshotDigest, type ApprovalManifest } from '../src/manifest.js';
import { recipeDescriptor } from '../src/recipes/recipe.js';
import { admissionStatus } from '../src/recipes/admission.js';

function signedFixture(recipe: ReturnType<typeof makeRecipe>, purpose: string | string[], fingerprint: string) {
    const purposes = Array.isArray(purpose) ? purpose : [purpose];
    let now = 2000;
    const journal = new Journal(join(mkdtempSync(join(tmpdir(), 'keyroot-recipe-')), 'journal.sqlite'), { installationId: 'installation', bootId: 'boot' });
    const keys = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    const publicKey = keys.publicKey.export({ format: 'jwk' });
    const approvals = new ApprovalService(journal, { mode: 'synthetic', clock: () => now });
    approvals.bootstrapApprover({ signerId: 'phone', role: 'routine', publicKey, localBootstrap: createLocalBootstrapContext(), confirmedFingerprint: publicKeyFingerprint(publicKey) });
    const manifest: ApprovalManifest = { version: 1, domain: 'keyroot.approval.v1', algorithm: 'ECDSA-P256-SHA256', audience: 'keyroot-controller', installationId: 'installation', bootId: 'boot', signerId: 'phone', role: 'routine', nonce: 'nonce', notBefore: 1000, expiresAt: 9000, budgets: { executions: 1, effects: purposes.length, newCredentials: 0, restarts: 0 }, operations: [{ operationId: 'op', accountId: recipe.accountId, lineageId: 'lineage', fromGeneration: 1, toGeneration: 2, actions: purposes.map((purpose, index) => ({ id: index === 0 ? 'admin' : `admin${index}`, kind: 'admin' as const, parameters: { resourceId: recipe.id, recipeId: recipe.id, expectedRevision: recipe.version, destinationId: recipe.destinationId, authorityFingerprint: fingerprint, configurationHash: recipeDescriptor(recipe, purpose, fingerprint) }, budgetCost: { effects: 1, newCredentials: 0, restarts: 0 } })) }], consumerMap: { revision: '1', entries: [], hash: contentDigest([]) }, recipes: [], adoptionThreshold: 'direct-use-every-consumer', overlapPolicy: 'required', deadline: { at: 8000, outcome: 'hold' }, outage: { permitted: false, consequence: 'none' }, graceSeconds: 0 };
    const raw = canonicalizeManifest(manifest);
    const signature = sign('sha256', Buffer.from(raw), { key: keys.privateKey, dsaEncoding: 'ieee-p1363' }).toString('base64url');
    approvals.registerGrant(raw, signature, 2000);
    return { journal, approvals, setNow: (value: number) => { now = value; }, request: { grantId: 'nonce', signature, operationId: 'op', actionId: 'admin', currentSnapshotDigest: snapshotDigest(manifest) } };
}
test('guided completion requires fresh signed recipe scope', async () => {
    const recipe = makeRecipe({ id: 'vendor', version: '1', accountId: 'account', destinationId: 'store', steps: [{ action: 'confirm', targetId: 'finish', checkpoint: 'consent' }] });
    const fingerprint = 'sha256:' + 'a'.repeat(64);
    const f = signedFixture(recipe, 'guided-completion', fingerprint);
    const guided = new GuidedProcedure(recipe);
    assert.throws(() => guided.confirmStep('finish'));
    guided.confirmStep('finish', true);
    await assert.rejects(guided.complete(f.approvals, { ...f.request, signature: 'invalid' }, fingerprint));
    const receipt = await guided.complete(f.approvals, f.request, fingerprint);
    assert.match(receipt.limitation, /attestation/);
    await assert.rejects(guided.complete(f.approvals, f.request, fingerprint));
    f.journal.close();
});
test('missing runtime and account proof always leaves guided-only', () => {
    const recipe = makeRecipe({ id: 'vendor', version: '1', accountId: 'account', destinationId: 'store', steps: [{ action: 'open', targetId: 'credentials', checkpoint: 'none' }] });
    assert.equal(admissionStatus().mode, 'guided-only');
    assert.equal(new GuidedProcedure(recipe).current()?.targetId, 'credentials');
});

import { admitSynthetic, rehearseSynthetic, syntheticWorker, runPurpose, type DashboardPort } from '../../../apps/controller/src/worker/dashboard.js';
import { admissionPurpose } from '../src/recipes/admission.js';
test('synthetic proof and signed admission bind broker to exact scope', async () => {
    const recipe = makeRecipe({ id: 'vendor', version: '1', accountId: 'account', destinationId: 'store', steps: [{ action: 'open', targetId: 'credentials', checkpoint: 'none' }] });
    const scope = { actorFingerprint: 'sha256:' + 'a'.repeat(64), authorityFingerprint: 'sha256:' + 'b'.repeat(64), workerFingerprint: 'sha256:' + 'c'.repeat(64), expiresAt: 7000 };
    const f = signedFixture(recipe, admissionPurpose(scope), scope.authorityFingerprint);
    await assert.rejects(rehearseSynthetic(recipe, scope, 2000, [{ kind: 'status', value: 'visible', secret: 'one-time-secret' }]));
    const proof = await rehearseSynthetic(recipe, scope, 2000, [{ kind: 'status', value: 'visible' }]);
    await assert.rejects(admitSynthetic(f.approvals, f.request, recipe, scope, { ...proof }, 2000));
    const admission = await admitSynthetic(f.approvals, f.request, recipe, scope, proof, 2000);
    let calls = 0;
    const port: DashboardPort = { async perform() { calls++; }, async captureToMappedStore() {}, async sealProfile() {}, async restoreProfile() {} };
    const runFixture = signedFixture(recipe, runPurpose('run', 0, 'step', 'open', 'credentials'), scope.authorityFingerprint);
    const run = { approvals: runFixture.approvals, runId: 'run', commands: [{ kind: 'step' as const, action: 'open' as const, targetId: 'credentials', request: runFixture.request }], clock: () => 2000, currentSnapshot: () => runFixture.request.currentSnapshotDigest };
    assert.throws(() => syntheticWorker(admission, makeRecipe({ ...recipe, version: '2' }), scope, run, port));
    assert.throws(() => syntheticWorker(admission, recipe, { ...scope, workerFingerprint: 'sha256:' + 'd'.repeat(64) }, run, port));
    assert.throws(() => syntheticWorker({ ...admission }, recipe, scope, run, port));
    const worker = syntheticWorker(admission, recipe, scope, run, port);
    assert.equal(await worker.dispatch({ kind: 'step', accountId: 'account', destinationId: 'store', action: 'open', targetId: 'credentials', signal: 'expected' }), 'ok');
    assert.equal(calls, 1);
    const replay = syntheticWorker(admission, recipe, scope, run, port);
    await assert.rejects(replay.dispatch({ kind: 'step', accountId: 'account', destinationId: 'store', action: 'open', targetId: 'credentials', signal: 'expected' }));
    assert.equal(calls, 1);
    assert.equal(f.journal.listIntents('op')[0]?.state, 'observed');
    runFixture.journal.close();
    f.journal.close();
});

test('guided drafts resume in journal and reject changed recipe', () => {
    const recipe = makeRecipe({ id: 'vendor', version: '1', accountId: 'account', destinationId: 'store', steps: [{ action: 'open', targetId: 'first', checkpoint: 'none' }, { action: 'confirm', targetId: 'last', checkpoint: 'consent' }] });
    const journal = new Journal(join(mkdtempSync(join(tmpdir(), 'keyroot-draft-')), 'journal.sqlite'), { installationId: 'installation', bootId: 'boot' });
    const first = new GuidedProcedure(recipe, { journal, procedureId: 'draft' });
    first.confirmStep('first');
    const resumed = new GuidedProcedure(recipe, { journal, procedureId: 'draft' });
    assert.equal(resumed.current()?.targetId, 'last');
    assert.throws(() => new GuidedProcedure(makeRecipe({ ...recipe, version: '2' }), { journal, procedureId: 'draft' }));
    assert.throws(() => first.confirmStep('first'));
    journal.close();
});

test('finite run rechecks cancellation, expiry and exact signed step between effects', async () => {
    for (const failure of ['cancel', 'expire', 'target', 'unknown'] as const) {
        const recipe = makeRecipe({ id: 'vendor', version: '1', accountId: 'account', destinationId: 'store', steps: [{ action: 'open', targetId: 'first', checkpoint: 'none' }, { action: 'confirm', targetId: 'second', checkpoint: 'none' }] });
        const scope = { actorFingerprint: 'sha256:' + 'a'.repeat(64), authorityFingerprint: 'sha256:' + 'b'.repeat(64), workerFingerprint: 'sha256:' + 'c'.repeat(64), expiresAt: 12000 };
        const admissionFixture = signedFixture(recipe, admissionPurpose(scope), scope.authorityFingerprint);
        const proof = await rehearseSynthetic(recipe, scope, 2000, [{ kind: 'status', value: 'visible' }]);
        const admission = await admitSynthetic(admissionFixture.approvals, admissionFixture.request, recipe, scope, proof, 2000);
        const runFixture = signedFixture(recipe, [runPurpose('run', 0, 'step', 'open', 'first'), runPurpose('run', 1, 'step', 'confirm', failure === 'target' ? 'different' : 'second')], scope.authorityFingerprint);
        const commands = [{ kind: 'step' as const, action: 'open' as const, targetId: 'first', request: runFixture.request }, { kind: 'step' as const, action: 'confirm' as const, targetId: 'second', request: { ...runFixture.request, actionId: 'admin1' } }];
        let calls = 0;
        const port: DashboardPort = { async perform() { calls++; if (failure === 'unknown' && calls === 2) throw new Error('unobserved'); }, async captureToMappedStore() {}, async sealProfile() {}, async restoreProfile() {} };
        const run = { approvals: runFixture.approvals, runId: 'run', commands, clock: () => 2000, currentSnapshot: () => runFixture.request.currentSnapshotDigest };
        const worker = syntheticWorker(admission, recipe, scope, run, port);
        assert.equal(await worker.dispatch({ kind: 'step', accountId: 'account', destinationId: 'store', action: 'open', targetId: 'first', signal: 'expected' }), 'ok');
        if (failure === 'cancel') runFixture.approvals.cancelGrant('nonce');
        if (failure === 'expire') runFixture.setNow(9000);
        await assert.rejects(worker.dispatch({ kind: 'step', accountId: 'account', destinationId: 'store', action: 'confirm', targetId: 'second', signal: 'expected' }));
        assert.equal(calls, failure === 'unknown' ? 2 : 1);
        if (failure === 'unknown') assert.equal(runFixture.journal.listIntents('op')[1]?.state, 'pending');
        runFixture.journal.close(); admissionFixture.journal.close();
    }
});
