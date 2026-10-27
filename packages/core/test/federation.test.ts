import { test } from 'node:test';
import { strict as assert } from 'node:assert';
import { createAdmissionWorkflow, type AdmissionScope } from '../src/admission.js';
import { recommendFederation } from '../src/federation.js';

test('federation needs scoped admission and cannot retire active fallback', () => {
  const workflow = createAdmissionWorkflow('synthetic');
  const evidence = { observer: 'test', method: 'test', evidenceHash: 'abc', observedAt: '2026-01-01T00:00:00Z', expiresAt: '2027-01-01T00:00:00Z', limitations: [], invalidationTriggers: [] };
  const make = (resourceId: string) => { const scope: AdmissionScope = { accountId: 'account', resourceId, action: 'observe', adapter: 'test', adapterVersion: '1', authorityFingerprint: 'fp' }; return { scope, record: workflow.record(scope, evidence) }; };
  const input = { issuer: make('issuer'), entitlement: make('account'), consumer: make('consumer'), accountId: 'account', issuerId: 'issuer', consumerId: 'consumer', now: '2026-10-26T00:00:00Z', domain: 'synthetic' as const, staticFallback: 'active' as const };
  assert.deepEqual(recommendFederation(input).recommendation, 'eligible-draft');
  assert.equal(recommendFederation(input).retirement, 'blocked');
  assert.equal(recommendFederation({ ...input, issuer: { ...input.issuer, record: structuredClone(input.issuer.record) } }).recommendation, 'insufficient-evidence');
});
