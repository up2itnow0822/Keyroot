import { test } from 'node:test';
import { strict as assert } from 'node:assert';
import { planAllocation, type ConsumerBinding } from '../src/inventory.js';
import { summarizeCoverage } from '../src/coverage.js';

test('coverage retains named bindings and unresolved read-only gaps', () => {
  const result = summarizeCoverage({ revision: 1, bindings: [{ id: 'binding', lineageId: 'key', consumerId: 'ci', association: { kind: 'observed', source: 'scan', observedAt: '2026-01-01T00:00:00Z' } }], gaps: [{ kind: 'inaccessible', source: 'ci secret' }, { kind: 'unplaced', source: 'local value' }, { kind: 'unscanned', source: 'other host' }] });
  assert.equal(result.bindings.length, 1);
  assert.deepEqual(JSON.parse(JSON.stringify(result)).gaps.map((gap: {kind: string}) => gap.kind), ['inaccessible', 'unplaced', 'unscanned']);
});

test('allocation reserves overlap, considers consolidation, and honors per-device selection', () => {
  const input = { externalConsumers: ['a', 'b'], devConsumers: ['d1', 'd2', 'd3', 'd4'], availableSlots: 3 };
  const draft = planAllocation(input);
  assert.equal(draft.groups.length, 3);
  assert.equal(draft.overlapReserved, false);
  assert.equal(draft.consolidationAssessment, 'evaluated');
  assert.equal(draft.nextStep, 'review-consolidation');
  assert.equal(draft.consolidationCandidate?.length, 1);
  assert.equal(planAllocation({ ...input, availableSlots: 1 }).nextStep, 'non-overlap-outage-review');
  const selected = planAllocation({ ...input, availableSlots: 7, devAllocation: 'per-device' });
  assert.equal(selected.groups.length, 6);
  assert.equal(selected.overlapReserved, true);
});

test('coverage preserves distinct consumer targets and revisions without inferring missing deployment metadata', () => {
  const association = { kind: 'observed', source: 'scan', observedAt: '2026-01-01T00:00:00Z' } as const;
  const bindings: ConsumerBinding[] = [
    { id: 'binding-a', lineageId: 'key-a', consumerId: 'workload', generationId: 'generation-a', destinationId: 'destination-a', consumerRevision: 'deployment-a', association },
    { id: 'binding-b', lineageId: 'key-b', consumerId: 'workload', generationId: 'generation-b', destinationId: 'destination-b', consumerRevision: 'deployment-b', association },
    { id: 'legacy', lineageId: 'key-c', consumerId: 'workload', generationId: 'generation-c', association }
  ];
  const result = summarizeCoverage({ revision: 1, bindings, gaps: [] });
  assert.deepEqual(result.bindings, bindings);
  assert.equal(result.bindings[2]?.destinationId, undefined);
  assert.equal(result.bindings[2]?.consumerRevision, undefined);
});
