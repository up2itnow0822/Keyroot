import assert from 'node:assert/strict';
import { test } from 'node:test';
import { OwnerApi, parseOverview } from '../../apps/review/src/owner-api.js';

test('owner session keeps CSRF in memory and sends it only on writes', async () => {
  const calls: Array<{ url: string; init: RequestInit | undefined }> = [];
  const fetcher: typeof fetch = async (url, init) => { calls.push({ url: String(url), init }); return new Response(JSON.stringify(String(url).endsWith('/exchange') ? { csrfToken: 'test-csrf', expiresAt: 1 } : { batchId: 'batch', rawManifest: JSON.stringify({ role: 'routine' }), digest: 'digest', configurationHashes: [], summary: { lineages: ['lineage'], effects: 1, expiresAt: 1, mode: 'demo' }, progress: [] }), { status: 200 }); };
  const api = new OwnerApi(fetcher);
  await api.exchange('one-use');
  await api.prepare({ signerId: 'phone', lineageIds: ['lineage'] });
  assert.equal(calls[0]?.url, '/api/session/exchange');
  assert.equal(calls[1]?.url, '/api/batches/prepare');
  assert.equal((calls[1]?.init?.headers as Record<string, string>)['X-Keyroot-CSRF'], 'test-csrf');
  assert.equal(calls[1]?.init?.credentials, 'same-origin');
});

test('overview rejects malformed data instead of using a preview', () => {
  assert.throws(() => parseOverview({ mode: 'demo', inventory: {} }));
});

test('unauthorized reads surface a 401 and do not fall back to sample data', async () => {
  const api = new OwnerApi(async () => new Response(JSON.stringify({ error: 'session_required' }), { status: 401 }));
  await assert.rejects(api.overview(), (error: unknown) => error instanceof Error && 'status' in error && error.status === 401);
  assert.equal(api.canWrite, false);
});

test('owner lookups use metadata-only authenticated endpoints', async () => {
  const calls: string[] = [];
  const api = new OwnerApi(async url => {
    calls.push(String(url));
    return Response.json(String(url).includes('pairing')
      ? { requestId: 'req', status: 'proved', signerId: 'phone', fingerprint: 'public-fingerprint', expiresAt: 10 }
      : { purpose: 'emergency-enrollment', requestId: 'req', signerId: 'backup', publicFingerprint: 'public-fingerprint', enrollmentFingerprint: 'enrollment-fingerprint', rpId: 'phone.example', origin: 'https://phone.example', credentialId: 'public-id', registrationEvidenceHash: 'hash' });
  });
  assert.equal((await api.pairing('req')).status, 'proved');
  assert.equal((await api.enrollment('req')).signerId, 'backup');
  assert.deepEqual(calls, ['/api/pairing/owner/req', '/api/emergency/enrollment/req']);
});

test('operation inspection retains independent old-use and direct adoption observations', async () => {
  const api = new OwnerApi(async () => Response.json({ operation: {}, intents: [], receipts: [], snapshot: { receipts: [
    { kind: 'old-use', outcome: 'positive-use', subject: {}, limitationCodes: [] },
    { kind: 'consumer-use', outcome: 'direct-use', subject: { consumerId: 'machine-1' }, limitationCodes: ['local-only'] },
  ] } }));
  const receipts = await api.inspect('operation');
  assert.equal(receipts[0]?.outcome, 'positive-use');
  assert.equal(receipts[1]?.outcome, 'direct-use');
  assert.equal(receipts[1]?.consumerId, 'machine-1');
});

test('incident proposal sends the complete typed scope and explicit outage', async () => {
  let body: Record<string, unknown> | undefined;
  const api = new OwnerApi(async (url, init) => {
    if (String(url).endsWith('/exchange')) return Response.json({ csrfToken: 'csrf', expiresAt: 1 });
    body = JSON.parse(String(init?.body)) as Record<string, unknown>;
    return Response.json({ batchId: 'incident', rawManifest: JSON.stringify({ role: 'emergency' }), digest: 'digest', configurationHashes: [], summary: { lineages: ['a', 'b'], effects: 2, mode: 'demo', expiresAt: 1 }, progress: [] });
  });
  await api.exchange('once');
  const batch = await api.prepare({ signerId: 'emergency', role: 'emergency', lineageIds: ['a', 'b'], incident: { policy: 'revoke-first', quarantineDestinations: [{ consumerId: 'machine', destinationId: 'dest' }], outage: { permitted: true, consequence: 'declared-interruption' } } });
  assert.equal(batch.summary.role, 'emergency');
  assert.deepEqual(body?.incident, { policy: 'revoke-first', quarantineDestinations: [{ consumerId: 'machine', destinationId: 'dest' }], outage: { permitted: true, consequence: 'declared-interruption' } });
});

test('new credential prepares only a signed inventory proposal, preserving existing metadata', async () => {
  const { buildCredentialProposal } = await import('../../apps/review/src/owner-api.js');
  const overview = parseOverview({ mode: 'real', approvers: [{ signerId: 'phone', role: 'routine', fingerprint: 'public' }], inventory: { lineages: [{ id: 'old', issuerId: 'issuer', accountId: 'old-account', credentialType: 'key', grantType: 'static-key' }], consumers: [{ id: 'consumer', name: 'Consumer', kind: 'dev-machine' }], consumerMap: { revision: 7, bindings: [], gaps: [{ source: 'device', kind: 'unscanned' }] }, native: [] }, batches: [], operations: [], policies: [], outbox: [], alarms: [], liveAdmission: 'unavailable', coverage: {} });
  const payload = buildCredentialProposal(overview, { id: 'new', issuerId: 'issuer', accountId: 'account', credentialType: 'api-key', grantType: 'static-key' }, 'phone');
  assert.deepEqual(payload.inventory?.lineages.map(lineage => lineage.id), ['old', 'new']); assert.equal(payload.inventory?.consumerMap.revision, 8); assert.deepEqual(payload.inventory?.consumerMap.gaps, overview.gaps);
  const calls: Array<{ url: string; body: unknown }> = [];
  const api = new OwnerApi(async (url, init) => { calls.push({ url: String(url), body: init?.body ? JSON.parse(String(init.body)) as unknown : undefined }); return Response.json(String(url).endsWith('/exchange') ? { csrfToken: 'csrf', expiresAt: 1 } : { batchId: 'proposal', rawManifest: JSON.stringify({ role: 'routine' }), digest: 'digest', configurationHashes: [], summary: { lineages: ['new'], effects: 1, expiresAt: 1, mode: 'real' }, progress: [] }); });
  assert.equal(calls.length, 0); await assert.rejects(api.prepare(payload)); assert.equal(calls.length, 0);
  await api.exchange('once'); await api.prepare(payload); assert.deepEqual(calls.map(call => call.url), ['/api/session/exchange', '/api/batches/prepare']); assert.deepEqual(calls[1]?.body, payload);
  assert.throws(() => buildCredentialProposal(overview, { id: 'bad secret value', issuerId: 'issuer', accountId: 'account', credentialType: 'api-key', grantType: 'static-key' }, 'phone'));
});

test('inspection merges journal-only admin evidence and deduplicates lifecycle receipts by identity', async () => {
  const api = new OwnerApi(async () => Response.json({ snapshot: { receipts: [{ receiptId: 'same', kind: 'issuer', outcome: 'revoked', subject: {}, limitationCodes: ['engine'] }] }, receipts: [{ receiptId: 'same', kind: 'issuer-revocation', outcome: 'confirmed', limitationCodes: ['journal'] }, { receiptId: 'admin', kind: 'admin', outcome: 'recorded', limitationCodes: ['no-provider-validation'] }, { receiptId: 'native', kind: 'sign-out', outcome: 'unknown', limitationCodes: ['local-only'] }] }));
  const receipts = await api.inspect('operation');
  assert.equal(receipts.length, 3);
  assert.deepEqual(receipts[0]?.limitationCodes, ['engine', 'journal']);
  assert.deepEqual(receipts[0]?.journalInterpretation, { kind: 'issuer-revocation', outcome: 'confirmed' });
  assert.equal(receipts[1]?.outcome, 'recorded');
  assert.equal(receipts[2]?.outcome, 'unknown');
});
