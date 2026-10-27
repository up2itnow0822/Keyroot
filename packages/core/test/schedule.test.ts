import { test } from 'node:test';
import { strict as assert } from 'node:assert';
import { forecast } from '../src/schedule.js';

test('forecast warns about long intervals and brings prompt forward for issuer expiry or reauthentication', () => {
  const result = forecast({ lineageId: 'lineage', policyAt: 120, issuerExpiryAt: 70, reauthorizationAt: 80, intervalDays: 120, mfaRequired: true, restartBudget: 2, executionBudget: 1 });
  assert.equal(result.promptAt, 70);
  assert.deepEqual(result.warnings, ['interval-over-90-days']);
  assert.equal(result.mfaRequired, true);
  assert.throws(() => forecast({ lineageId: 'x', policyAt: 1, intervalDays: -1, mfaRequired: false, restartBudget: 0, executionBudget: 1 }));
});

test('forecast persists the full finite budget and deadline metadata', async () => {
  const { Journal } = await import('../src/journal.js');
  const { ForecastStore } = await import('../src/schedule.js');
  const journal = new Journal(':memory:', { installationId: 'installation', bootId: 'boot' });
  const store = new ForecastStore(journal);
  store.save({ lineageId: 'x', policyAt: 120, reauthorizationAt: 60, intervalDays: 30, mfaRequired: true, restartBudget: 3, executionBudget: 4 });
  assert.equal(new ForecastStore(journal).list()[0]?.promptAt, 60);
  assert.equal(store.list()[0]?.executionBudget, 4);
  journal.close();
});
