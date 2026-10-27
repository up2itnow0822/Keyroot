import type { ConsumerMap } from './inventory.js';
/** A snapshot never asserts absence of undiscovered copies. */
export function summarizeCoverage(map: ConsumerMap): ConsumerMap & { undiscoveredCopies: 'unknown' } {
  return { revision: map.revision, bindings: map.bindings.map((binding) => ({ ...binding, association: { ...binding.association } })), gaps: map.gaps.map((gap) => ({ ...gap })), undiscoveredCopies: 'unknown' };
}
