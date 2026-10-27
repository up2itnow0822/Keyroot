import { test } from 'node:test';
import { strict as assert } from 'node:assert';
import { createAccountAssessmentWorkflow } from '../src/adapters/account-assessment.js';

test('account assessment invokes verifier and binds evidence to exact scope and clock', async () => {
  let calls = 0; let now = 2000;
  const scope = { accountId: 'account', resourceId: 'project:service', action: 'create' as const, adapter: 'openai-service-account', adapterVersion: '1', authorityFingerprint: 'issuer' };
  const workflow = createAccountAssessmentWorkflow({ trustDomain: 'synthetic', observerId: 'fixture', methodId: 'permission-and-overlap', lifetimeMs: 1000, timeoutMs: 100, clock: () => now, verifier: async (request) => { calls++; return { challenge: request.challenge, scope: request.scope, outcome: 'verified', evidence: { permission: 'create', overlap: 'present' }, limitations: [], invalidationTriggers: ['permissions-changed'] }; } });
  assert.equal(workflow.evaluate(scope).admitted, false);
  await workflow.assess(scope);
  assert.equal(calls, 1); assert.equal(workflow.evaluate(scope).admitted, true);
  assert.equal(workflow.evaluate({ ...scope, adapterVersion: '2' }).admitted, false);
  assert.equal(workflow.evaluate(scope, 'live').admitted, false);
  workflow.invalidate('permissions-changed'); assert.equal(workflow.evaluate(scope).admitted, false);
  await workflow.assess(scope); now = 3000; assert.equal(workflow.evaluate(scope).admitted, false);
});

import { mutationAllowed } from '../src/capability.js';
import { contentDigest } from '../src/manifest.js';
import { createAdmissionWorkflow } from '../src/admission.js';
import type { AdmissionScope, BoundedAdmissionVerifier } from '../src/admission.js';

const actionScope: AdmissionScope = { accountId: 'account', resourceId: 'project:service', action: 'create', adapter: 'openai-service-account', adapterVersion: '1', authorityFingerprint: 'issuer', configurationHash: contentDigest({ scopes: ['read'], ttl: 3600 }) };
const verified: BoundedAdmissionVerifier = async request => ({ challenge: request.challenge, scope: request.scope, outcome: 'verified', evidence: { permission: 'create', overlap: 'present' }, limitations: [], invalidationTriggers: ['permissions-changed'] });
const options = () => ({ trustDomain: 'synthetic' as const, observerId: 'account-fixture', methodId: 'permission-and-overlap', lifetimeMs: 1000, timeoutMs: 20, clock: () => 2000, verifier: verified });

test('owning evaluator accepts only its exact current record and rejects serialized imports, booleans and synthetic proof for live', async () => {
  const workflow = createAccountAssessmentWorkflow(options()); const record = await workflow.assess(actionScope); assert.ok(record);
  const context = { scope: actionScope, now: new Date(2000).toISOString(), evaluator: workflow };
  assert.equal(mutationAllowed({ state: 'account-tested', admission: record }, context, 'synthetic'), true);
  assert.equal(mutationAllowed({ state: 'account-tested', admission: record }, context, 'live'), false);
  assert.equal(mutationAllowed({ state: 'account-tested', admission: JSON.parse(JSON.stringify(record)) }, context, 'synthetic'), false);
  assert.equal(mutationAllowed({ state: 'account-tested', admission: { account_tested: true } }, context, 'synthetic'), false);
  assert.equal(mutationAllowed({ state: 'account-tested', admission: undefined }, context, 'synthetic'), false);
  assert.equal(mutationAllowed({ state: 'account-tested', admission: record }, { ...context, invalidations: ['permissions-changed'] }, 'synthetic'), false);
  const synthetic = createAdmissionWorkflow('synthetic').record(actionScope, { observer: 'fixture', method: 'synthetic', evidenceHash: 'sha256:synthetic', observedAt: new Date(1000).toISOString(), expiresAt: new Date(3000).toISOString(), limitations: [], invalidationTriggers: [] });
  assert.equal(mutationAllowed({ state: 'account-tested', admission: synthetic }, context, 'live'), false);
  const next = await workflow.assess(actionScope); assert.ok(next); assert.notEqual(record, next);
  assert.equal(mutationAllowed({ state: 'account-tested', admission: record }, context, 'synthetic'), false);
});

test('scope, version, authority, action and configuration proof changes require another verifier operation', async () => {
  const workflow = createAccountAssessmentWorkflow(options()); await workflow.assess(actionScope);
  for (const changed of [{ accountId: 'other' }, { resourceId: 'other' }, { action: 'revoke' as const }, { adapterVersion: '2' }, { authorityFingerprint: 'other' }, { configurationHash: contentDigest({ scopes: ['admin'] }) }]) assert.equal(workflow.evaluate({ ...actionScope, ...changed }).admitted, false);
});

for (const fault of ['challenge', 'scope', 'denied', 'unverified', 'raw-fields', 'missing-permission', 'missing-overlap', 'throw', 'timeout'] as const) test(`bounded account verifier ${fault} cannot mint admission`, async () => {
  const workflow = createAccountAssessmentWorkflow({ ...options(), timeoutMs: 5, verifier: async request => {
    if (fault === 'throw') throw new Error('fixture failure');
    if (fault === 'timeout') return new Promise(() => {});
    return { challenge: fault === 'challenge' ? 'wrong' : request.challenge, scope: fault === 'scope' ? { ...request.scope, accountId: 'other' } : request.scope, outcome: fault === 'denied' ? 'denied' : fault === 'unverified' ? 'unverified' : 'verified', evidence: fault === 'raw-fields' ? { permission: 'create', overlap: 'present', value: 'must-never-be-evidence' } : fault === 'missing-permission' ? { overlap: 'present' } : fault === 'missing-overlap' ? { permission: 'create' } : { permission: 'create', overlap: 'present' }, limitations: [], invalidationTriggers: [] };
  } });
  assert.equal(await workflow.assess(actionScope), undefined); assert.equal(workflow.evaluate(actionScope).admitted, false);
});

test('live evidence requires configuration binding and concurrent invalidation rejects in-flight proof', async () => {
  const live = createAccountAssessmentWorkflow({ ...options(), trustDomain: 'live' });
  const { configurationHash: _hash, ...unbound } = actionScope;
  assert.ok(_hash); await assert.rejects(live.assess(unbound), /scope/);
  let release: (() => void) | undefined;
  const paused = new Promise<void>(resolve => { release = resolve; });
  const workflow = createAccountAssessmentWorkflow({ ...options(), verifier: async request => { await paused; return verified(request); } });
  const pending = workflow.assess(actionScope); workflow.invalidate('permissions-changed'); release!();
  assert.equal(await pending, undefined); assert.equal(workflow.evaluate(actionScope).admitted, false);
});
