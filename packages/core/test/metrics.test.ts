import { test } from 'node:test';
import { strict as assert } from 'node:assert';
import { Journal } from '../src/journal.js';
import { OwnerMetrics } from '../src/metrics.js';

test('owner intervals are server timed, persisted, replay safe and overlap counted once', () => {
  let now = 10;
  const journal = new Journal(':memory:', { installationId: 'installation', bootId: 'boot' });
  const metrics = new OwnerMetrics(journal, () => now);
  metrics.begin('a', 'incident', 'mfa'); now = 20; metrics.begin('b', 'incident', 'guided');
  now = 30; metrics.end('a'); now = 40; metrics.end('b');
  const report = metrics.report('incident');
  assert.equal(report.activeMs, 30); assert.equal(report.byKind.mfa, 20); assert.equal(report.byKind.guided, 20);
  assert.throws(() => metrics.end('a')); assert.throws(() => metrics.begin('a', 'incident', 'review'));
  journal.close();
});

test('open records remain visible and backward clock events cannot falsify measured time', () => {
  let now = 50;
  const journal = new Journal(':memory:', { installationId: 'installation', bootId: 'boot' });
  const metrics = new OwnerMetrics(journal, () => now);
  metrics.begin('open', 'case', 'troubleshooting');
  assert.equal(new OwnerMetrics(journal, () => now).report('case').openIntervals, 1);
  now = 49; assert.throws(() => metrics.end('open'), /invalid interval/);
  now = 55; metrics.end('open');
  now = 54; assert.throws(() => metrics.begin('later', 'case', 'review'), /backwards/);
  assert.equal(metrics.report('case').activeMs, 5); journal.close();
});

test('same-set baseline separates active time and elapsed milestones, and exposes coverage', () => {
  let now = 0; const journal = new Journal(':memory:', { installationId: 'i', bootId: 'b' }); const m = new OwnerMetrics(journal, () => now);
  m.createCase('coordinated', ['a', 'b'], ['vendor-guided']);
  m.begin('mfa1', 'coordinated', 'mfa'); now = 10; m.end('mfa1');
  m.begin('guided1', 'coordinated', 'guided'); now = 20; m.end('guided1');
  now = 30; m.mark('coordinated', 'contained'); now = 50; m.mark('coordinated', 'restored');
  m.createCase('baseline', ['b', 'a'], []); m.begin('baseline1', 'baseline', 'guided'); now = 90; m.end('baseline1');
  m.createCase('maintenance', ['a', 'b'], []); m.begin('maintenance1', 'maintenance', 'review'); now = 95; m.end('maintenance1');
  const result = m.compare('coordinated', 'baseline', 'maintenance');
  assert.equal(result.activeMs, 20); assert.equal(result.baselineActiveMs, 40); assert.equal(result.maintenanceActiveMs, 5);
  assert.equal(result.elapsedContainmentMs, 30); assert.equal(result.elapsedRestorationMs, 50); assert.deepEqual(result.coverageLimitations, ['vendor-guided']);
  m.createCase('wrong', ['a'], []); assert.throws(() => m.compare('coordinated', 'wrong', 'maintenance'), /same affected set/); journal.close();
});
