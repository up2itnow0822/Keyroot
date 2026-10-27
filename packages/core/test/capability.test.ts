import { test } from 'node:test';
import { strict as assert } from 'node:assert';
import { mutationAllowed, consumerPath } from '../src/capability.js';

test('documentation and unavailable account access cannot unlock mutation', () => {
  assert.equal(mutationAllowed({ state: 'documented', source: 'docs' }, undefined, 'live'), false);
  assert.equal(mutationAllowed({ state: 'unavailable', reason: 'account lacks entitlement' }, undefined, 'live'), false);
  assert.equal(consumerPath({ state: 'unavailable', reason: 'no integration' }, true), 'assisted');
  assert.equal(consumerPath({ state: 'unknown' }, false), 'inventory-only');
  const forged = { state: 'account-tested' as const, admission: { verified: true } };
  const scope = { accountId: 'a', resourceId: 'r', action: 'deliver' as const, adapter: 'x', adapterVersion: '1', authorityFingerprint: 'f' };
  assert.equal(mutationAllowed(forged, { scope, now: '2026-01-01T00:00:00Z' }, 'live'), false);
  assert.equal(consumerPath(forged, true, { path: 'native', scope, now: '2026-01-01T00:00:00Z', domain: 'live' }), 'assisted');
});
