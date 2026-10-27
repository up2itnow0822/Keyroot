import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { ReviewApp, CredentialDraftForm, credentialsFromOverview } from '../../apps/review/src/ReviewApp.js';
import { parseOverview } from '../../apps/review/src/owner-api.js';

const overview = { mode: 'demo', approvers: [], inventory: { lineages: [{ id: 'demo-lineage', issuerId: 'openai', accountId: 'demo', credentialType: 'key', grantType: 'static-key' }], consumers: [{ id: 'machine-1', name: 'Machine 1', kind: 'dev-machine' }], consumerMap: { revision: 1, bindings: [], gaps: [{ source: 'machine-1', kind: 'unscanned' }] }, native: [] }, batches: [], operations: [], policies: [], outbox: [], alarms: [], liveAdmission: 'synthetic-only', coverage: { native: 'unavailable' } };
test('loading owner screen never renders the three-row sample', () => { const html = renderToStaticMarkup(createElement(ReviewApp)); assert.match(html, /Connecting to the local controller/); assert.doesNotMatch(html, /Demo hosting|sample data/); });
test('actual inventory preserves no bindings and visible gaps', () => { const data = parseOverview(overview); const rows = credentialsFromOverview(data); assert.equal(rows.length, 1); assert.equal(rows[0]?.consumers.length, 0); assert.match(rows[0]?.notes ?? '', /1 coverage gaps/); assert.equal(data.gaps[0]?.kind, 'unscanned'); });

test('controller service overview conforms to owner parser without starting a server', async () => {
  const { Journal } = await import('../../packages/core/src/journal.js');
  const { ControllerService } = await import('../../apps/controller/src/service.js');
  const journal = new Journal(':memory:', { installationId: 'test-installation' });
  try {
    const service = new ControllerService(journal, 'demo');
    const data = parseOverview(service.overview());
    assert.equal(data.mode, 'demo');
    assert.equal(data.lineages.length, 1);
    assert.equal(data.bindings.length, 0);
    assert.equal(data.gaps.length, 4);
    assert.equal(data.approvers.length, 0);
    assert.equal(data.coverage.native, 'unavailable');
  } finally { journal.close(); }
});

test('overview validates role and preserves typed mapping metadata', () => {
  const data = structuredClone(overview);
  const withPair = { ...data, approvers: [{ signerId: 'phone', role: 'routine', fingerprint: 'public' }], inventory: { ...data.inventory, consumerMap: { ...data.inventory.consumerMap, bindings: [{ id: 'binding', lineageId: 'demo-lineage', consumerId: 'machine-1', destinationId: 'destination', consumerRevision: 'r1', association: { kind: 'declared', source: 'owner', observedAt: '2026-10-26T00:00:00Z' } }] } } };
  const parsed = parseOverview(withPair);
  assert.equal(parsed.approvers[0]?.role, 'routine');
  assert.equal(parsed.bindings[0]?.destinationId, 'destination');
  assert.equal(parsed.bindings[0]?.consumerRevision, 'r1');
  assert.throws(() => parseOverview({ ...withPair, approvers: [{ ...withPair.approvers[0], role: 'administrator' }] }));
});

test('new credential proposal preserves empty inventory and binds nonsecret draft to paired phone', async () => {
  const { buildCredentialProposal } = await import('../../apps/review/src/owner-api.js');
  const data = parseOverview({ ...overview, approvers: [{ signerId: 'phone', role: 'routine', fingerprint: 'public' }], inventory: { ...overview.inventory, lineages: [] } });
  const draft = { id: 'service-key', issuerId: 'openai', accountId: 'account-1', credentialType: 'api-key' as const, grantType: 'static-key' as const };
  const proposal = buildCredentialProposal(data, draft, 'phone');
  assert.deepEqual(proposal.lineageIds, ['service-key']); assert.equal(proposal.purpose, 'inventory-update'); assert.equal(proposal.targetId, 'inventory'); assert.deepEqual(proposal.inventory?.lineages, [draft]);
  assert.equal(proposal.inventory?.consumerMap.revision, 2); assert.deepEqual(proposal.inventory?.consumerMap.gaps, data.gaps); assert.deepEqual(data.lineages, []);
  assert.throws(() => buildCredentialProposal(data, draft, 'unknown'));
  assert.throws(() => buildCredentialProposal({ ...data, lineages: [draft] }, draft, 'phone'));
});

test('empty inventory add form asks only for metadata and a paired routine phone', () => {
  const html = renderToStaticMarkup(createElement(CredentialDraftForm, { draft: { id: '', issuerId: '', accountId: '', credentialType: 'api-key', grantType: 'static-key' }, signer: '', signers: [], busy: false, writable: true, onDraft: () => {}, onSigner: () => {}, onSubmit: () => {}, onPair: () => {} }));
  for (const expected of ['Lineage ID', 'Issuer ID', 'Account ID', 'Credential type', 'Grant type', 'Paired routine phone', 'Do not enter a key, token or password', 'Pair a phone', 'Prepare for phone approval']) assert.ok(html.includes(expected), expected);
  assert.doesNotMatch(html, /type="password"/); assert.match(html, /<button class="button primary" disabled=""/);
  const pattern = html.match(/pattern="([^"]+)"/)?.[1]; assert.ok(pattern); const valid = new RegExp(`^(?:${pattern})$`, 'v'); assert.ok(valid.test('issuer/thing-1')); assert.equal(valid.test('with spaces'), false);
});

test('late receipt responses stay bound to their operation across both panels', async () => {
  const { putReceipts, receiptsFor } = await import('../../apps/review/src/receipt-cache.js');
  type Receipt = { kind: string; outcome: string; limitationCodes: string[] };
  let cache: Record<string, Receipt[]> = {}; let resolveA!: (v: Receipt[]) => void;
  const a = new Promise<Receipt[]>(resolve => { resolveA = resolve; }).then(value => { cache = putReceipts(cache, 'A', value); });
  cache = putReceipts(cache, 'B', [{ kind: 'issuer', outcome: 'unknown', limitationCodes: [] }]);
  resolveA([{ kind: 'sign-out', outcome: 'recorded', limitationCodes: ['local-only'] }]); await a;
  assert.equal(receiptsFor(cache, 'B')[0]?.outcome, 'unknown');
  assert.equal(receiptsFor(cache, 'A')[0]?.kind, 'sign-out');
});
