import { isAccountAssessmentEvaluator, type AccountAssessmentEvaluator } from './adapters/account-assessment.js';
import { assessAdmission } from './admission.js';
import type { AdmissionScope, CapabilityAction, TrustDomain } from './admission.js';
export type Capability = { state: 'documented'; source: string } | { state: 'account-tested'; admission: unknown } | { state: 'unavailable'; reason: string } | { state: 'unknown' };
export interface CapabilityRecord { credentialType: string; issuerAccountId: string; consumerId: string; actions: Record<CapabilityAction, Capability>; }
export function mutationAllowed(capability: Capability, context: { scope: AdmissionScope; now: string; invalidations?: readonly string[]; evaluator?: AccountAssessmentEvaluator } | undefined, domain: TrustDomain): boolean {
  return capability.state === 'account-tested' && context !== undefined && (context.evaluator && isAccountAssessmentEvaluator(context.evaluator) ? capability.admission !== undefined && context.evaluator.evaluate(context.scope, domain, capability.admission, context.invalidations).admitted : assessAdmission(capability.admission, context.scope, context.now, domain, context.invalidations).admitted);
}
export type ConsumerPath = 'native' | 'managed-delivery' | 'assisted' | 'inventory-only';
export function consumerPath(delivery: Capability, assistedAvailable: boolean, verified?: { path: 'native' | 'managed-delivery'; scope: AdmissionScope; now: string; domain: TrustDomain; invalidations?: readonly string[] }): ConsumerPath {
  if (verified && mutationAllowed(delivery, verified, verified.domain)) return verified.path;
  return assistedAvailable ? 'assisted' : 'inventory-only';
}
