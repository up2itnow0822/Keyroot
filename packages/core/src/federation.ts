import { assessAdmission, type AdmissionScope, type TrustDomain } from './admission.js';

export interface FederationEvidence { record: unknown; scope: AdmissionScope }
export interface FederationRecommendation {
  recommendation: 'eligible-draft' | 'insufficient-evidence';
  retirement: 'blocked' | 'eligible-for-review';
  reasons: string[];
}
/** Evidence must be independently scoped to issuer, account entitlement, and consumer. */
export function recommendFederation(input: {
  issuer: FederationEvidence; entitlement: FederationEvidence; consumer: FederationEvidence;
  accountId: string; issuerId: string; consumerId: string; now: string; domain: TrustDomain;
  invalidations?: readonly string[]; staticFallback: 'active' | 'inactive' | 'unknown';
}): FederationRecommendation {
  const reasons: string[] = [];
  for (const [label, evidence, resource] of [
    ['issuer', input.issuer, input.issuerId], ['entitlement', input.entitlement, input.accountId], ['consumer', input.consumer, input.consumerId],
  ] as const) {
    if (evidence.scope.accountId !== input.accountId || evidence.scope.resourceId !== resource) reasons.push(`${label} scope mismatch`);
    else if (!assessAdmission(evidence.record, evidence.scope, input.now, input.domain, input.invalidations).admitted) reasons.push(`${label} evidence unavailable`);
  }
  if (input.staticFallback !== 'inactive') reasons.push('static fallback precedence unresolved or active');
  const eligible = !reasons.some(reason => !reason.startsWith('static fallback'));
  return { recommendation: eligible ? 'eligible-draft' : 'insufficient-evidence', retirement: eligible && input.staticFallback === 'inactive' ? 'eligible-for-review' : 'blocked', reasons };
}
