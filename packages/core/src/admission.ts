export type CapabilityAction = 'create' | 'validate' | 'deliver' | 'observe' | 'revoke';
export type TrustDomain = 'synthetic' | 'live';
export interface AdmissionScope { accountId: string; resourceId: string; action: CapabilityAction; adapter: string; adapterVersion: string; authorityFingerprint: string; }
export interface AdmissionEvidence { observer: string; method: string; evidenceHash: string; observedAt: string; expiresAt: string; limitations: string[]; invalidationTriggers: string[]; }
export interface AdmissionRecord { scope: AdmissionScope; evidence: AdmissionEvidence; trustDomain: TrustDomain; }
export interface AdmissionAssessment { admitted: boolean; reason: string; }
// In-memory provenance cannot survive serialization. The trusted owning workflow must
// re-establish evidence after restart; arbitrary imports cannot acquire this identity.
const issued = new WeakSet<object>();
export function createAdmissionWorkflow(trustDomain: TrustDomain) {
  return { record(scope: AdmissionScope, evidence: AdmissionEvidence): AdmissionRecord {
    if (trustDomain === 'live') throw new Error('Live admission requires an owning account-test workflow');
    const required = [scope.accountId, scope.resourceId, scope.action, scope.adapter, scope.adapterVersion, scope.authorityFingerprint, evidence.observer, evidence.method, evidence.evidenceHash];
    const start = Date.parse(evidence.observedAt); const end = Date.parse(evidence.expiresAt);
    if (required.some((value) => !value.trim()) || !Number.isFinite(start) || !Number.isFinite(end) || end <= start) throw new Error('Invalid admission provenance');
    const record = Object.freeze({ scope: Object.freeze({ ...scope }), evidence: Object.freeze({ ...evidence, limitations: Object.freeze([...evidence.limitations]), invalidationTriggers: Object.freeze([...evidence.invalidationTriggers]) }), trustDomain }) as unknown as AdmissionRecord;
    issued.add(record);
    return record;
  } };
}
export function assessAdmission(record: unknown, expected: AdmissionScope, now: string, domain: TrustDomain, invalidations: readonly string[] = []): AdmissionAssessment {
  if (typeof record !== 'object' || record === null || !issued.has(record)) return { admitted: false, reason: 'untrusted provenance' };
  const candidate = record as AdmissionRecord;
  if (candidate.trustDomain !== domain) return { admitted: false, reason: 'trust domain mismatch' };
  const keys: (keyof AdmissionScope)[] = ['accountId', 'resourceId', 'action', 'adapter', 'adapterVersion', 'authorityFingerprint'];
  if (keys.some((key) => candidate.scope[key] !== expected[key])) return { admitted: false, reason: 'scope mismatch' };
  const time = Date.parse(now);
  if (!Number.isFinite(time) || time < Date.parse(candidate.evidence.observedAt) || time >= Date.parse(candidate.evidence.expiresAt)) return { admitted: false, reason: 'evidence outside validity period' };
  if (invalidations.some((event) => candidate.evidence.invalidationTriggers.includes(event))) return { admitted: false, reason: 'evidence invalidated' };
  return { admitted: true, reason: 'scoped evidence accepted' };
}
