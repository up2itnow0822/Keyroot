export interface AdmissionScope { actorFingerprint: string; authorityFingerprint: string; workerFingerprint: string; expiresAt: number }
export function admissionPurpose(scope: AdmissionScope): string {
    if (!Number.isSafeInteger(scope.expiresAt) || ![scope.actorFingerprint, scope.authorityFingerprint, scope.workerFingerprint].every(s => /^sha256:[a-f0-9]{64}$/.test(s))) throw new Error('Invalid admission scope');
    return `synthetic-admission:${scope.actorFingerprint}:${scope.workerFingerprint}:${scope.expiresAt}`;
}
export function admissionStatus(): { mode: 'guided-only'; missing: string[] } {
    return { mode: 'guided-only', missing: ['verified live runtime isolation', 'actual account guided rehearsal', 'owner signed scoped admission', 'hosted model disclosure review when applicable'] };
}
/** No hosted model transport is installed. Owner review is a prerequisite to adding one. */
export function hostedModelDisclosure(): { allowed: false; provenance: 'unreviewed'; reason: string } {
    return { allowed: false, provenance: 'unreviewed', reason: 'No hosted model disclosure review or approved observation contract is available.' };
}
/** Future trusted provider must supply verified physical isolation and account-specific rehearsal. No provider is currently installed. */
export interface LiveProofEvaluationPort { evaluate(recipeHash: string, scope: AdmissionScope): Promise<{ runtime: 'verified' | 'unverified'; accountRehearsal: 'verified' | 'unverified'; disclosure: 'reviewed' | 'not-applicable' | 'unverified' }> }
