import { test } from 'node:test';
import assert from 'node:assert/strict';
import { canonicalJSON, contentDigest, parseCanonicalManifest } from '../src/manifest.js';

test('incident plan hash is an explicit bounded signed action parameter', () => {
  const plan = { type: 'incident-plan', version: 1, policy: 'revoke-first', affectedLineages: ['lineage'], quarantineDestinations: [], outage: { permitted: true, consequence: 'declared-interruption' } };
  const value = { version: 1, domain: 'keyroot.approval.v1', algorithm: 'ECDSA-P256-SHA256', audience: 'keyroot-controller', installationId: 'install', bootId: 'boot', signerId: 'emergency', role: 'emergency', nonce: 'incident', notBefore: 1, expiresAt: 10000, budgets: { effects: 1, newCredentials: 0, restarts: 0, executions: 1 }, operations: [{ operationId: 'op', lineageId: 'lineage', accountId: 'account', fromGeneration: 1, toGeneration: 2, actions: [{ id: 'revoke', kind: 'revoke', parameters: { resourceId: 'old-key', handleId: 'old-handle', generation: 1, incidentPlanHash: contentDigest(plan) }, budgetCost: { effects: 1, newCredentials: 0, restarts: 0 } }] }], consumerMap: { revision: 'map', hash: contentDigest([]), entries: [] }, recipes: [], adoptionThreshold: 'direct-use-every-consumer', overlapPolicy: 'required', deadline: { at: 9000, outcome: 'hold' }, outage: { permitted: true, consequence: 'declared-interruption' }, graceSeconds: 900 };
  assert.equal((parseCanonicalManifest(canonicalJSON(value)).operations[0]!.actions[0]!.parameters as Record<string, unknown>).incidentPlanHash, contentDigest(plan));
  value.operations[0]!.actions[0]!.parameters.incidentPlanHash = 'sha256:bad';
  assert.throws(() => parseCanonicalManifest(canonicalJSON(value)));
});
