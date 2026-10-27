import type { ApprovalManifest } from './manifest.js';
export type DeadlineDisposition = 'within-window' | 'overdue-exposure' | 'hard-outage';
/** This is policy interpretation only. Actual dispatch still needs a current signed action. */
export function deadlineDisposition(policy: Pick<ApprovalManifest, 'deadline' | 'outage'>, now: number): DeadlineDisposition {
  if (!Number.isSafeInteger(now) || now < 0) throw new Error('Invalid trusted time');
  if (now < policy.deadline.at) return 'within-window';
  if (policy.deadline.outcome === 'hard-revoke') {
    if (!policy.outage.permitted || policy.outage.consequence !== 'declared-interruption') throw new Error('Hard deadline requires explicit outage authority');
    return 'hard-outage';
  }
  return 'overdue-exposure';
}
