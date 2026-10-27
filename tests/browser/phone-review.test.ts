import { test } from 'node:test';
import assert from 'node:assert/strict';
import { renderToStaticMarkup } from 'react-dom/server';
import { createElement } from 'react';
import { PhoneReview } from '../../apps/review/src/phone/PhoneReview.js';

test('phone begins with an explicit connection gesture and visible custody limitation', () => {
  const html = renderToStaticMarkup(createElement(PhoneReview));
  assert.match(html, /SYNTHETIC DEMO/);
  assert.match(html, /Connect and prepare phone key/);
  assert.match(html, /does not prove hardware protection or physical custody/);
  assert.doesNotMatch(html, /Approve this exact change/);
});

import { ReviewDetails } from '../../apps/review/src/phone/PhoneReview.js';
import type { ApprovalManifest } from '../../apps/review/src/phone/manifest.js';
test('review renders signed scope and verified descriptor rather than a summary', () => {
  const manifest: ApprovalManifest = { version: 1, domain: 'keyroot.approval.v1', algorithm: 'ECDSA-P256-SHA256', audience: 'keyroot-controller', installationId: 'installation', bootId: 'boot', signerId: 'phone', role: 'routine', nonce: 'nonce', notBefore: 1, expiresAt: 20000, budgets: { effects: 1, newCredentials: 0, restarts: 0, executions: 1 }, operations: [{ operationId: 'op', lineageId: 'lineage', accountId: 'account', fromGeneration: 1, toGeneration: 2, actions: [{ id: 'act', kind: 'disable', parameters: { resourceId: 'target' }, budgetCost: { effects: 1, newCredentials: 0, restarts: 0 } }] }], consumerMap: { revision: 'map1', hash: 'maphash', entries: [] }, recipes: [], adoptionThreshold: 'direct-use-every-consumer', overlapPolicy: 'required', deadline: { at: 10000, outcome: 'hold' }, outage: { permitted: false, consequence: 'none' }, graceSeconds: 30 };
  manifest.operations.push({ ...structuredClone(manifest.operations[0]!), operationId: 'op2', lineageId: 'lineage2', accountId: 'account2' });
  manifest.consumerMap.entries = [{ lineageId: 'lineage', consumerId: 'shared', resourceId: 'destination-a', revision: 'rev-a' }, { lineageId: 'lineage2', consumerId: 'shared', resourceId: 'destination-b', revision: 'rev-b' }];
  manifest.operations[0]!.actions[0]!.parameters.incidentPlanHash = 'sha256:plan';
  manifest.operations[0]!.actions[0]!.parameters.configurationHash = 'sha256:descriptor';
  const plan = { type: 'incident-plan', version: 1, policy: 'revoke-first', affectedLineages: ['lineage', 'lineage2'], quarantineDestinations: [{ consumerId: 'shared', destinationId: 'destination-a' }], outage: { permitted: true, consequence: 'declared-interruption' } };
  const html = renderToStaticMarkup(createElement(ReviewDetails, { batch: { batchId: 'batch', rawManifest: '{"exact":"bytes"}', digest: 'sha256:review', configurationHashes: ['sha256:descriptor'] }, review: { manifest, descriptors: { 'sha256:descriptor': { provider: 'openai-service-account', projectId: 'verified-project', serviceAccountId: 'verified-service', scopeIds: ['api.read'], expiresInSeconds: 3600, destinationId: 'verified-vault' }, 'sha256:plan': plan } } }));
  for (const expected of ['account', 'lineage', 'disable', 'target', 'api.read', '3600', 'map1', 'required', 'hold', 'sha256:review', 'Exact bytes to be signed']) assert.ok(html.includes(expected), expected);
  for (const expected of ['Incident plan', 'revoke-first', 'Whole affected lineage set', 'Quarantine destinations', 'Outage:', 'declared-interruption', 'sha256:plan']) assert.ok(html.includes(expected), expected);
  const advanced = html.indexOf('Advanced: exact signed scope'); const summary = html.slice(0, advanced);
  for (const expected of ['OpenAI service account', 'verified-project', 'verified-service', 'api.read', '3600 seconds', 'verified-vault', 'Executions', 'New credentials', 'Effects', 'Restarts']) assert.ok(summary.includes(expected), expected);
  assert.match(html, /<details class="phone-advanced"><summary>Advanced:/); assert.ok(html.includes('{&quot;exact&quot;:&quot;bytes&quot;}')); assert.ok(html.includes('Proposal ID:'));
  const cards = [...html.matchAll(/<article[\s\S]*?<\/article>/g)].map(match => match[0]);
  assert.equal(cards.length, 2); assert.match(cards[0]!, /shared workload, lineage-specific binding/); assert.match(cards[0]!, /destination-a.*rev-a/); assert.doesNotMatch(cards[0]!, /destination-b/); assert.match(cards[1]!, /destination-b.*rev-b/); assert.doesNotMatch(cards[1]!, /destination-a/);
});

test('empty consumer map warns that adoption is unverified', () => {
  const manifest: ApprovalManifest = { version: 1, domain: 'keyroot.approval.v1', algorithm: 'ECDSA-P256-SHA256', audience: 'keyroot-controller', installationId: 'installation', bootId: 'boot', signerId: 'phone', role: 'routine', nonce: 'nonce', notBefore: 1, expiresAt: 20000, budgets: { effects: 1, newCredentials: 0, restarts: 0, executions: 1 }, operations: [{ operationId: 'op', lineageId: 'lineage', accountId: 'account', fromGeneration: 1, toGeneration: 2, actions: [{ id: 'act', kind: 'disable', parameters: { resourceId: 'target' }, budgetCost: { effects: 1, newCredentials: 0, restarts: 0 } }] }], consumerMap: { revision: 'map1', hash: 'hash', entries: [] }, recipes: [], adoptionThreshold: 'direct-use-every-consumer', overlapPolicy: 'required', deadline: { at: 10000, outcome: 'hold' }, outage: { permitted: false, consequence: 'none' }, graceSeconds: 30 };
  const html = renderToStaticMarkup(createElement(ReviewDetails, { batch: { batchId: 'batch', rawManifest: '{}', digest: 'digest', configurationHashes: [] }, review: { manifest, descriptors: {} } }));
  assert.match(html, /No mapped consumers; this proposal provides no adoption assurance\. Unknown copies may still use the old credential\./);
});

test('administrative target, consequences, fingerprints and digest are visible before advanced details', () => {
  const manifest = { operations: [{ operationId: 'op', lineageId: 'admin:B', accountId: 'selected-A', fromGeneration: 1, toGeneration: 2, actions: [{ id: 'retire', kind: 'admin', parameters: { resourceId: 'B', reasonCode: 'retire', configurationHash: 'hash' } }] }], consumerMap: { revision: '1', hash: 'map', entries: [] }, budgets: { executions: 1, effects: 1, newCredentials: 0, restarts: 0 }, expiresAt: 20000, deadline: { at: 10000, outcome: 'hold' }, outage: { permitted: false, consequence: 'none' }, graceSeconds: 30, overlapPolicy: 'required', adoptionThreshold: 'direct-use-every-consumer' } as unknown as ApprovalManifest;
  const batch = { batchId: 'b', rawManifest: '{}', digest: 'digest-visible', configurationHashes: ['hash'] };
  const html = renderToStaticMarkup(createElement(ReviewDetails, { batch, review: { manifest, descriptors: { hash: { purpose: 'retire', targetId: 'B', lineageId: 'A' } } } }));
  const summary = html.slice(0, html.indexOf('Advanced: exact signed scope'));
  assert.match(summary, /digest-visible/); assert.match(summary, /retire/i); assert.match(summary, /Target.*B/); assert.match(summary, /retired/i); assert.doesNotMatch(summary, /Provider, scopes, TTL/);
});

test('enrollment fingerprints and full replacement inventory are disclosed in the primary review', () => {
  const action = { id: 'emergency-enrollment', kind: 'admin', parameters: { resourceId: 'emergency-approver', destinationId: 'backup', authorityFingerprint: 'enroll-fp', reasonCode: 'emergency-enrollment', configurationHash: 'hash' }, budgetCost: { effects: 1, newCredentials: 0, restarts: 0 } };
  const manifest = { operations: [{ operationId: 'op', lineageId: 'admin:req', accountId: 'selected', fromGeneration: 1, toGeneration: 2, actions: [action] }], consumerMap: { revision: '1', hash: 'map', entries: [] }, budgets: { executions: 1, effects: 1, newCredentials: 0, restarts: 0 }, expiresAt: 20000, deadline: { at: 10000, outcome: 'hold' }, outage: { permitted: false, consequence: 'none' }, graceSeconds: 30, overlapPolicy: 'required', adoptionThreshold: 'direct-use-every-consumer' } as unknown as ApprovalManifest;
  const batch = { batchId: 'b', rawManifest: '{}', digest: 'digest', configurationHashes: ['hash'] };
  const render = (descriptor: unknown) => renderToStaticMarkup(createElement(ReviewDetails, { batch, review: { manifest, descriptors: { hash: descriptor } } })).split('Advanced: exact signed scope')[0]!;
  const enrollment = render({ purpose: 'emergency-enrollment', requestId: 'req', signerId: 'backup', publicFingerprint: 'public-fp', enrollmentFingerprint: 'enroll-fp' });
  for (const text of ['public-fp', 'enroll-fp', 'backup', 'req']) assert.ok(enrollment.includes(text), text);
  action.id = 'inventory-update'; action.parameters.reasonCode = 'inventory-update'; action.parameters.resourceId = 'inventory';
  const inventory = render({ purpose: 'inventory-update', targetId: 'inventory', lineageId: 'A', inventory: { lineages: [{ id: 'B', issuerId: 'issuer-B', accountId: 'account-B', credentialType: 'key', grantType: 'static-key' }], consumers: [{ id: 'machine', name: 'Machine', kind: 'dev' }], native: [], consumerMap: { revision: 8, bindings: [{ lineageId: 'B', consumerId: 'machine', destinationId: 'vault', consumerRevision: 'v2' }], gaps: [] } } });
  for (const text of ['Replaces the complete inventory', 'revision: 8', 'issuer-B', 'account-B', 'machine', 'vault', 'v2']) assert.ok(inventory.includes(text), text);
});

test('routine approver enrollment displays its bound fingerprint and rejects mismatched action bindings', async () => {
  const { reviewRecognized } = await import('../../apps/review/src/phone/PhoneReview.js');
  const action = { id: 'approver-enrollment', kind: 'admin', parameters: { resourceId: 'routine-approver', destinationId: 'phone-new', authorityFingerprint: 'fingerprint-new', reasonCode: 'approver-enrollment', configurationHash: 'hash' }, budgetCost: { effects: 1, newCredentials: 0, restarts: 0 } };
  const manifest = { operations: [{ operationId: 'op', lineageId: 'admin:req', accountId: 'selected', fromGeneration: 1, toGeneration: 2, actions: [action] }], consumerMap: { revision: '1', hash: 'map', entries: [] }, budgets: { executions: 1, effects: 1, newCredentials: 0, restarts: 0 }, expiresAt: 20000, deadline: { at: 10000, outcome: 'hold' }, outage: { permitted: false, consequence: 'none' }, graceSeconds: 30, overlapPolicy: 'required', adoptionThreshold: 'direct-use-every-consumer' } as unknown as ApprovalManifest;
  const descriptor = { purpose: 'approver-enrollment', requestId: 'req', signerId: 'phone-new', fingerprint: 'fingerprint-new' };
  const review = { manifest, descriptors: { hash: descriptor } };
  const batch = { batchId: 'b', rawManifest: '{}', digest: 'digest', configurationHashes: ['hash'] };
  const primary = renderToStaticMarkup(createElement(ReviewDetails, { batch, review })).split('Advanced: exact signed scope')[0]!;
  assert.match(primary, /Public fingerprint:.*fingerprint-new/); assert.match(primary, /phone-new/); assert.equal(reviewRecognized(review), true);
  assert.equal(reviewRecognized({ manifest, descriptors: { hash: { ...descriptor, signerId: 'other' } } }), false);
  assert.equal(reviewRecognized({ manifest, descriptors: { hash: { ...descriptor, fingerprint: 'other' } } }), false);
});
