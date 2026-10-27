import { makeRecipe, type Recipe, type RecipeAction } from '../../../../packages/core/src/recipes/recipe.js';
import { assessDrift, type PageSignal } from '../../../../packages/core/src/recipes/drift.js';

/** Trusted host implements these narrow capabilities. No file, vault-admin or cross-profile capability exists. */
export interface DashboardPort {
    perform(action: Exclude<RecipeAction, 'capture'>, targetId: string): Promise<void>;
    captureToMappedStore(destinationId: string, targetId: string): Promise<void>;
    sealProfile(accountId: string): Promise<void>;
    restoreProfile(accountId: string): Promise<void>;
}
export type WorkerCommand = { kind: 'step'; accountId: string; destinationId: string; action: RecipeAction; targetId: string; signal: PageSignal } | { kind: 'seal' | 'restore'; accountId: string };
export type Observation = { kind: 'status'; value: 'visible' | 'completed' | 'blocked' } | { kind: 'secret-subtree' };
/** The broker, not an interpreter, enforces sequence and the entire runtime capability surface. */
export class DashboardBroker {
    private index = 0;
    private paused = false;
    private readonly recipe: Recipe;
    constructor(recipe: Recipe, private readonly port: DashboardPort, private readonly authorizeCapture: (destinationId: string, targetId: string) => Promise<void>, private readonly currentScope: () => boolean = () => true) { this.recipe = makeRecipe(recipe); }
    async dispatch(command: unknown): Promise<'ok' | 'pause-guided' | 'denied'> {
        if (!this.currentScope()) { this.paused = true; return 'pause-guided'; }
        if (!command || typeof command !== 'object' || Array.isArray(command)) return 'denied';
        const c = command as Record<string, unknown>;
        if (this.paused) return 'pause-guided';
        if ((c.kind === 'seal' || c.kind === 'restore') && Object.keys(c).sort().join(',') === 'accountId,kind' && c.accountId === this.recipe.accountId) {
            if (c.kind === 'seal') await this.port.sealProfile(this.recipe.accountId); else await this.port.restoreProfile(this.recipe.accountId);
            return 'ok';
        }
        if (c.kind !== 'step' || Object.keys(c).sort().join(',') !== 'accountId,action,destinationId,kind,signal,targetId') return 'denied';
        const step = this.recipe.steps[this.index];
        if (!step || c.accountId !== this.recipe.accountId || c.destinationId !== this.recipe.destinationId || c.action !== step.action || c.targetId !== step.targetId || assessDrift(c.signal as PageSignal) !== 'continue' || step.checkpoint !== 'none') { this.paused = true; return 'pause-guided'; }
        if (step.action === 'capture') {
            await this.authorizeCapture(this.recipe.destinationId, step.targetId);
            await this.port.captureToMappedStore(this.recipe.destinationId, step.targetId);
        } else await this.port.perform(step.action, step.targetId);
        this.index++;
        return 'ok';
    }
    observe(observation: unknown): { kind: 'status'; value: 'visible' | 'completed' | 'blocked' } | { kind: 'withheld' } {
        if (!observation || typeof observation !== 'object' || Array.isArray(observation)) return { kind: 'withheld' };
        const o = observation as Record<string, unknown>;
        if (Object.keys(o).sort().join(',') === 'kind,value' && o.kind === 'status' && (o.value === 'visible' || o.value === 'completed' || o.value === 'blocked')) return { kind: 'status', value: o.value };
        return { kind: 'withheld' };
    }
    get limitation(): string { return 'Synthetic protocol only; browser isolation and real account rehearsal are unverified. Broad account sessions retain account-level blast radius.'; }
}

import type { ApprovalService, AuthorizeEffectRequest } from '../../../../packages/core/src/approval.js';
import { admissionPurpose, type AdmissionScope } from '../../../../packages/core/src/recipes/admission.js';
import { authorizeRecipeAction, recipeHash, recordRecipeAction } from '../../../../packages/core/src/recipes/recipe.js';
interface SyntheticProof { readonly kind: 'synthetic-protocol-proof' }
export interface SyntheticAdmission { readonly kind: 'synthetic-protocol-admission' }
interface Bound { hash: string; scope: AdmissionScope }
const proofs = new WeakMap<object, Bound>();
const admissions = new WeakMap<object, Bound>();
function binding(recipe: Recipe, scope: AdmissionScope): Bound { return { hash: recipeHash(recipe), scope: { ...scope } }; }
function matches(bound: Bound | undefined, recipe: Recipe, scope: AdmissionScope, now: number): boolean {
    return !!bound && Number.isSafeInteger(now) && now < scope.expiresAt && bound.hash === recipeHash(recipe) && bound.scope.actorFingerprint === scope.actorFingerprint && bound.scope.authorityFingerprint === scope.authorityFingerprint && bound.scope.workerFingerprint === scope.workerFingerprint && bound.scope.expiresAt === scope.expiresAt;
}
/** Executes the real broker in a hermetic synthetic fixture; never proves physical isolation or a vendor account. */
export async function rehearseSynthetic(recipe: Recipe, scope: AdmissionScope, now: number, observations: unknown[]): Promise<SyntheticProof> {
    const r = makeRecipe(recipe);
    admissionPurpose(scope);
    if (now >= scope.expiresAt || !Number.isSafeInteger(now)) throw new Error('Expired proof scope');
    let effects = 0;
    const port: DashboardPort = { async perform() { effects++; }, async captureToMappedStore() { effects++; }, async sealProfile() { effects++; }, async restoreProfile() { effects++; } };
    const broker = new DashboardBroker(r, port, async () => {});
    for (const kind of ['host-file', 'vault-admin', 'other-profile', 'network', 'shell']) if (await broker.dispatch({ kind, accountId: r.accountId }) !== 'denied') throw new Error('Runtime mediation failed');
    const first = r.steps[0]!;
    for (const override of [{ action: 'invalid' }, { destinationId: 'other' }, { accountId: 'other' }, { signal: 'passkey' }, { signal: 'unexpected-mfa' }, { signal: 'privilege-instruction' }]) {
        const attempt = new DashboardBroker(r, port, async () => {});
        if (await attempt.dispatch({ kind: 'step', accountId: r.accountId, destinationId: r.destinationId, action: first.action, targetId: first.targetId, signal: 'expected', ...override }) !== 'pause-guided') throw new Error('Adversarial mediation failed');
    }
    if (effects !== 0 || observations.length === 0 || observations.some(o => broker.observe(o).kind !== 'status')) throw new Error('Rehearsal observation withheld or unsafe');
    // Exercise the allowed path against the same broker; interactive checkpoints remain guided.
    for (const step of r.steps) {
        const outcome = await broker.dispatch({ kind: 'step', accountId: r.accountId, destinationId: r.destinationId, action: step.action, targetId: step.targetId, signal: 'expected' });
        if (step.checkpoint !== 'none') { if (outcome !== 'pause-guided') throw new Error('Checkpoint mediation failed'); break; }
        if (outcome !== 'ok') throw new Error('Synthetic rehearsal failed');
    }
    const proof = Object.freeze({ kind: 'synthetic-protocol-proof' as const });
    proofs.set(proof, binding(r, scope));
    return proof;
}
export async function admitSynthetic(approvals: ApprovalService, request: AuthorizeEffectRequest, recipe: Recipe, scope: AdmissionScope, proof: SyntheticProof, now: number): Promise<SyntheticAdmission> {
    if (!matches(proofs.get(proof), recipe, scope, now)) throw new Error('Scoped synthetic rehearsal proof required');
    const intentId = await authorizeRecipeAction(approvals, request, recipe, admissionPurpose(scope), scope.authorityFingerprint);
    recordRecipeAction(approvals, request, recipe, intentId, ['synthetic-only', 'live-isolation-unverified', 'actual-account-unverified']);
    proofs.delete(proof);
    const admission = Object.freeze({ kind: 'synthetic-protocol-admission' as const });
    admissions.set(admission, binding(recipe, scope));
    return admission;
}
export type RunCommand = { kind: 'step'; action: RecipeAction; targetId: string; request: AuthorizeEffectRequest } | { kind: 'seal' | 'restore'; request: AuthorizeEffectRequest };
export interface SyntheticRunAuthority { approvals: ApprovalService; runId: string; commands: RunCommand[]; clock: () => number; currentSnapshot: () => string }
export function runPurpose(runId: string, index: number, kind: string, action: string, target: string): string {
    if (!/^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$/.test(runId) || !Number.isSafeInteger(index) || index < 0) throw new Error('Invalid run scope');
    return `synthetic-run:${runId}:${index}:${kind}:${action}:${target}`;
}
/** Run context and capability port come from the trusted controller, never a page, model or JSON. */
export function syntheticWorker(admission: SyntheticAdmission, recipe: Recipe, scope: AdmissionScope, run: SyntheticRunAuthority, port: DashboardPort): DashboardBroker {
    const pinned = makeRecipe(recipe);
    if (!matches(admissions.get(admission), pinned, scope, run.clock())) throw new Error('Scoped synthetic admission required');
    let index = 0;
    let busy = false;
    async function execute(kind: 'step' | 'seal' | 'restore', action: string, target: string, effect: () => Promise<void>): Promise<void> {
        if (busy) throw new Error('Concurrent command denied');
        busy = true;
        try {
            if (!matches(admissions.get(admission), pinned, scope, run.clock())) throw new Error('Admission expired');
            const command = run.commands[index];
            if (!command || command.kind !== kind || (kind === 'step' && (command.kind !== 'step' || command.action !== action || command.targetId !== target))) throw new Error('Run command outside signed sequence');
            const request = { ...command.request, currentSnapshotDigest: run.currentSnapshot() };
            const intentId = await authorizeRecipeAction(run.approvals, request, pinned, runPurpose(run.runId, index, kind, action, target), scope.authorityFingerprint);
            // If the effect throws, its intent remains unresolved for reconciliation.
            await effect();
            recordRecipeAction(run.approvals, request, pinned, intentId, ['synthetic-only', 'provider-unverified']);
            index++;
        } finally { busy = false; }
    }
    const mediated: DashboardPort = {
        perform: (action, target) => execute('step', action, target, () => port.perform(action, target)),
        captureToMappedStore: (destination, target) => execute('step', 'capture', target, () => port.captureToMappedStore(destination, target)),
        sealProfile: account => execute('seal', 'seal', account, () => port.sealProfile(account)),
        restoreProfile: account => execute('restore', 'restore', account, () => port.restoreProfile(account))
    };
    return new DashboardBroker(pinned, mediated, async () => {}, () => matches(admissions.get(admission), pinned, scope, run.clock()));
}
