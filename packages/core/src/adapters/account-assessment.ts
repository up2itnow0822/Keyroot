import { randomUUID } from 'node:crypto';
import { type AdmissionAssessment, type AdmissionRecord, type AdmissionScope, type BoundedAdmissionVerifier, type TrustDomain } from '../admission.js';
import { canonicalJSON, contentDigest, deepFreeze } from '../manifest.js';

const evaluators = new WeakSet<object>();
const records = new WeakSet<object>();
export interface AccountAssessmentEvaluator {
  readonly trustDomain: TrustDomain;
  evaluate(scope: AdmissionScope, domain?: TrustDomain, record?: unknown, invalidations?: readonly string[]): AdmissionAssessment;
}
export function isAccountAssessmentEvaluator(value: unknown): value is AccountAssessmentEvaluator {
  return typeof value === 'object' && value !== null && evaluators.has(value);
}
export interface AccountAssessmentOptions {
  trustDomain: TrustDomain;
  observerId: string;
  methodId: string;
  lifetimeMs: number;
  timeoutMs: number;
  clock?: () => number;
  /** Trusted constructor dependency. This callback alone is not evidence of a real account test. */
  verifier: BoundedAdmissionVerifier;
}
const metadata = (v: unknown): v is string => typeof v === 'string' && /^[-a-zA-Z0-9_.:@/]{1,256}$/.test(v);
function validScope(scope: AdmissionScope): boolean {
  const required = ['accountId', 'resourceId', 'action', 'adapter', 'adapterVersion', 'authorityFingerprint'];
  return required.every(key => Object.hasOwn(scope, key)) && Object.keys(scope).every(key => required.includes(key) || key === 'configurationHash') && Object.values(scope).every(metadata) && (scope.configurationHash === undefined || /^sha256:[a-f0-9]{64}$/.test(scope.configurationHash)) && ['create', 'validate', 'deliver', 'observe', 'revoke'].includes(scope.action);
}
/** Obtains fresh evidence by executing a bounded verifier; no imported-record or account_tested input exists. */
export function createAccountAssessmentWorkflow(options: AccountAssessmentOptions) {
  if (!metadata(options.observerId) || !metadata(options.methodId) || !Number.isSafeInteger(options.lifetimeMs) || options.lifetimeMs < 1 || options.lifetimeMs > 86_400_000 || !Number.isSafeInteger(options.timeoutMs) || options.timeoutMs < 1 || options.timeoutMs > 120_000 || typeof options.verifier !== 'function' || !['synthetic', 'live'].includes(options.trustDomain)) throw new Error('Invalid account assessment workflow');
  const config = { ...options };
  const current = new Map<string, AdmissionRecord>();
  const invalidated = new Set<string>();
  let invalidationVersion = 0;
  const now = () => config.clock?.() ?? Date.now();
  const evaluator = {
    trustDomain: config.trustDomain,
    evaluate(scope: AdmissionScope, domain: TrustDomain = config.trustDomain, record?: unknown, invalidations: readonly string[] = []): AdmissionAssessment {
      const candidate = current.get(canonicalJSON(scope));
      if (!candidate || !records.has(candidate) || record !== undefined && record !== candidate) return { admitted: false, reason: 'missing account verifier evidence' };
      // The record identity is private to this workflow, independently of ordinary synthetic imports.
      if (candidate.trustDomain !== domain) return { admitted: false, reason: 'trust domain mismatch' };
      if (canonicalJSON(candidate.scope) !== canonicalJSON(scope)) return { admitted: false, reason: 'scope mismatch' };
      const time = now();
      if (!Number.isSafeInteger(time) || time < Date.parse(candidate.evidence.observedAt) || time >= Date.parse(candidate.evidence.expiresAt)) return { admitted: false, reason: 'evidence outside validity period' };
      if (candidate.evidence.invalidationTriggers.some(trigger => invalidated.has(trigger) || invalidations.includes(trigger))) return { admitted: false, reason: 'evidence invalidated' };
      return { admitted: true, reason: 'bounded account verifier evidence accepted' };
    },
    async assess(scope: AdmissionScope): Promise<Readonly<AdmissionRecord> | undefined> {
      if (!validScope(scope) || config.trustDomain === 'live' && !scope.configurationHash) throw new Error('Invalid account assessment scope');
      const pinned = deepFreeze({ ...scope });
      const key = canonicalJSON(pinned);
      current.delete(key);
      const version = invalidationVersion;
      const start = now(); const challenge = randomUUID(); const controller = new AbortController();
      let timer: ReturnType<typeof setTimeout> | undefined;
      try {
        const result = await Promise.race([
          config.verifier(Object.freeze({ challenge, scope: pinned, signal: controller.signal })),
          new Promise<undefined>(resolve => { timer = setTimeout(() => { controller.abort(); resolve(undefined); }, config.timeoutMs); })
        ]);
        const end = now();
        if (!result || version !== invalidationVersion || controller.signal.aborted || result.outcome !== 'verified' || result.challenge !== challenge || canonicalJSON(result.scope) !== key || !Number.isSafeInteger(start) || !Number.isSafeInteger(end) || end < start || end - start >= config.lifetimeMs) return undefined;
        if (!result.evidence || !Object.keys(result.evidence).length || Object.keys(result.evidence).some(k => !['permission', 'overlap', 'methodCapability', 'observationHash', 'configurationHash', 'storeBindingHash'].includes(k)) || ![pinned.action, 'allowed'].includes(String(result.evidence.permission)) || pinned.action === 'create' && !['present', 'unavailable'].includes(String(result.evidence.overlap)) || Object.entries(result.evidence).some(([k, v]) => !metadata(k) || !(typeof v === 'boolean' || typeof v === 'number' && Number.isFinite(v) || metadata(v))) || !Array.isArray(result.limitations) || !Array.isArray(result.invalidationTriggers) || ![...result.limitations, ...result.invalidationTriggers].every(metadata)) return undefined;
        const record: AdmissionRecord = deepFreeze({ scope: pinned, trustDomain: config.trustDomain, evidence: { observer: config.observerId, method: config.methodId, evidenceHash: contentDigest({ challenge, scope: pinned, evidence: result.evidence }), observedAt: new Date(start).toISOString(), expiresAt: new Date(start + config.lifetimeMs).toISOString(), limitations: [...result.limitations], invalidationTriggers: [...result.invalidationTriggers] } });
        records.add(record); current.set(key, record);
        // An invalidation cannot be cleared merely by unrelated assessment. This scope is refreshed only.
        for (const trigger of result.invalidationTriggers) invalidated.delete(trigger);
        return record;
      } catch { return undefined; } finally { if (timer !== undefined) clearTimeout(timer); }
    },
    invalidate(trigger: string): void {
      if (!metadata(trigger)) throw new Error('Invalid invalidation trigger');
      invalidationVersion++;
      invalidated.add(trigger);
      for (const [key, record] of current) if (record.evidence.invalidationTriggers.includes(trigger)) current.delete(key);
    }
  };
  evaluators.add(evaluator);
  return Object.freeze(evaluator);
}
