/** Non-secret identifiers; values are resolved only inside trusted executors. */
export type Id = string;
export type Association = { kind: 'declared' | 'observed' | 'inferred'; source: string; observedAt: string };
export type GrantType = 'static-key' | 'oauth' | 'workload-identity' | 'native-session' | 'other' | 'unknown';
export interface CredentialLineage { id: Id; issuerId: Id; accountId: Id; credentialType: string; grantType: GrantType; grantId?: Id; }
export interface CredentialGeneration { id: Id; lineageId: Id; version: string; status: 'active' | 'retired' | 'unknown'; }
export interface Consumer { id: Id; name: string; kind: 'external' | 'dev-machine' | 'production' | 'ci' | 'other'; }
export interface ConsumerBinding {
  id: Id; lineageId: Id; consumerId: Id; generationId?: Id;
  /** Exact delivery target and workload revision; omitted metadata remains unknown. */
  destinationId?: Id; consumerRevision?: string;
  association: Association;
}
export interface CoverageGap { kind: 'unplaced' | 'inaccessible' | 'unscanned'; source: string; detail?: string; }
export interface ConsumerMap { revision: number; bindings: ConsumerBinding[]; gaps: CoverageGap[]; }
export type DevAllocation = 'shared' | 'per-device';
export interface AllocationInput { externalConsumers: Id[]; devConsumers: Id[]; availableSlots: number; devAllocation?: DevAllocation; }
export interface AllocationDraft { groups: Id[][]; overlapReserved: boolean; consolidationAssessment: 'evaluated' | 'not-needed'; consolidationCandidate: Id[][] | null; nextStep: 'ready' | 'review-consolidation' | 'non-overlap-outage-review'; }
/** Draft only; never performs mutation or consumes approval authority. */
export function planAllocation(input: AllocationInput): AllocationDraft {
  if (!Number.isSafeInteger(input.availableSlots) || input.availableSlots < 0) throw new RangeError('availableSlots must be a nonnegative integer');
  const groups = input.externalConsumers.map((id) => [id]);
  if (input.devAllocation === 'per-device') groups.push(...input.devConsumers.map((id) => [id]));
  else if (input.devConsumers.length) groups.push([...input.devConsumers]);
  const overlapReserved = input.availableSlots >= groups.length + 1;
  if (overlapReserved) return { groups, overlapReserved, consolidationAssessment: 'not-needed', consolidationCandidate: null, nextStep: 'ready' };
  const allConsumers = [...input.externalConsumers, ...input.devConsumers];
  const consolidationCandidate = allConsumers.length ? [allConsumers] : [];
  const canRestoreOverlap = input.availableSlots >= consolidationCandidate.length + 1;
  return { groups, overlapReserved, consolidationAssessment: 'evaluated', consolidationCandidate, nextStep: canRestoreOverlap ? 'review-consolidation' : 'non-overlap-outage-review' };
}
