import { test } from 'node:test';
import { strict as assert } from 'node:assert';
import { createAdmissionWorkflow, assessAdmission } from '../src/admission.js';

const scope = { accountId: 'account-a', resourceId: 'credential', action: 'create' as const, adapter: 'issuer', adapterVersion: '1', authorityFingerprint: 'fingerprint' };
const evidence = { observer: 'owner', method: 'account-test', evidenceHash: 'sha256:abc', observedAt: '2026-01-01T00:00:00Z', expiresAt: '2027-01-01T00:00:00Z', limitations: [], invalidationTriggers: ['authority-changed'] };
const now = '2026-06-01T00:00:00Z';
test('admission is scoped, expires and rejects imported or synthetic proof for live use', () => {
  assert.throws(() => createAdmissionWorkflow('live').record(scope, evidence));
  const workflow = createAdmissionWorkflow('synthetic');
  const record = workflow.record(scope, evidence);
  assert.equal(assessAdmission(record, scope, now, 'synthetic').admitted, true);
  assert.equal(assessAdmission(record, scope, now, 'synthetic', ['authority-changed']).admitted, false);
  assert.equal(assessAdmission({ ...record, verified: true }, scope, now, 'synthetic').admitted, false);
  assert.equal(assessAdmission(record, { ...scope, accountId: 'account-b' }, now, 'synthetic').admitted, false);
  assert.equal(assessAdmission(record, { ...scope, adapterVersion: '2' }, now, 'synthetic').admitted, false);
  assert.equal(assessAdmission(record, scope, '2028-01-01T00:00:00Z', 'synthetic').admitted, false);
  assert.equal(assessAdmission(JSON.parse(JSON.stringify(record)), scope, now, 'live').admitted, false);
  assert.equal(assessAdmission(createAdmissionWorkflow('synthetic').record(scope, evidence), scope, now, 'live').admitted, false);
});
