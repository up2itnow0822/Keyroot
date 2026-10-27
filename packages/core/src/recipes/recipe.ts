import { randomUUID } from 'node:crypto';
import { contentDigest, parseCanonicalManifest } from '../manifest.js';
import type { Journal } from '../journal.js';
import type { ApprovalService, AuthorizeEffectRequest } from '../approval.js';

export type RecipeAction = 'open' | 'select' | 'capture' | 'confirm';
export type Checkpoint = 'none' | 'mfa' | 'consent';
export interface RecipeStep { action: RecipeAction; targetId: string; checkpoint: Checkpoint }
export interface Recipe { id: string; version: string; accountId: string; destinationId: string; steps: RecipeStep[] }
const identifier = /^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$/;
export function makeRecipe(input: Recipe): Recipe {
    const keys = Object.keys(input).sort().join(',');
    if (keys !== 'accountId,destinationId,id,steps,version' || ![input.id, input.version, input.accountId, input.destinationId].every(x => typeof x === 'string' && identifier.test(x)) || !Array.isArray(input.steps) || input.steps.length < 1 || input.steps.length > 32) throw new Error('Invalid recipe');
    const steps = input.steps.map(s => {
        if (!s || Object.keys(s).sort().join(',') !== 'action,checkpoint,targetId' || !['open', 'select', 'capture', 'confirm'].includes(s.action) || !['none', 'mfa', 'consent'].includes(s.checkpoint) || typeof s.targetId !== 'string' || !identifier.test(s.targetId)) throw new Error('Invalid recipe step');
        return Object.freeze({ ...s });
    });
    return Object.freeze({ id: input.id, version: input.version, accountId: input.accountId, destinationId: input.destinationId, steps: Object.freeze(steps) as unknown as RecipeStep[] });
}
export function recipeHash(recipe: Recipe): string { return contentDigest(makeRecipe(recipe)); }
/** All descriptors and the recipe hash must appear in the same owner-signed action. */
export async function authorizeRecipeAction(approvals: ApprovalService, request: AuthorizeEffectRequest, recipe: Recipe, purpose: string, authorityFingerprint: string): Promise<string> {
    const validated = makeRecipe(recipe);
    const descriptor = contentDigest({ purpose, recipeHash: recipeHash(validated), accountId: validated.accountId, destinationId: validated.destinationId, authorityFingerprint });
    const raw = approvals.journal.read(db => db.prepare('SELECT raw_manifest FROM approval_grant WHERE grant_id=?').get(request.grantId)?.raw_manifest);
    if (typeof raw !== 'string') throw new Error('Missing signed grant');
    const manifest = parseCanonicalManifest(raw);
    const operation = manifest.operations.find(o => o.operationId === request.operationId);
    const action = operation?.actions.find(a => a.id === request.actionId);
    if (operation?.accountId !== validated.accountId || action?.kind !== 'admin' || action.parameters.resourceId !== validated.id || action.parameters.recipeId !== validated.id || action.parameters.expectedRevision !== validated.version || action.parameters.destinationId !== validated.destinationId || action.parameters.authorityFingerprint !== authorityFingerprint || action.parameters.configurationHash !== descriptor) throw new Error('Signed recipe scope mismatch');
    const intent = await approvals.authorizeEffect(request);
    return intent.intentId;
}
export function recipeDescriptor(recipe: Recipe, purpose: string, authorityFingerprint: string): string {
    const r = makeRecipe(recipe);
    return contentDigest({ purpose, recipeHash: recipeHash(r), accountId: r.accountId, destinationId: r.destinationId, authorityFingerprint });
}
/** Records the bounded admin action; it asserts only local execution or owner attestation. */
export function recordRecipeAction(approvals: ApprovalService, request: AuthorizeEffectRequest, recipe: Recipe, intentId: string, limitationCodes: string[]): string {
    const operation = approvals.journal.inspectOperation(request.operationId);
    if (!operation) throw new Error('Completion authority unavailable');
    const receiptId = randomUUID();
    approvals.journal.appendReceipt({ receiptId, intentId, kind: 'administration', outcome: 'confirmed', generation: operation.toGeneration, observedAt: Date.now(), observerId: 'keyroot-controller', evidenceHash: recipeHash(recipe), accountId: recipe.accountId, resourceId: recipe.id, revision: recipe.version, destinationId: recipe.destinationId, limitationCodes });
    approvals.journal.resolveIntent({ intentId, receiptIds: [receiptId] });
    return receiptId;
}
export class GuidedProcedure {
    private index = 0;
    private completed = false;
    readonly recipe: Recipe;
    constructor(recipe: Recipe, private readonly draft?: { journal: Journal; procedureId: string }) {
        this.recipe = makeRecipe(recipe);
        if (draft) {
            if (!identifier.test(draft.procedureId)) throw new Error('Invalid procedure id');
            const hash = recipeHash(this.recipe);
            this.index = draft.journal.transaction(db => {
                db.exec('CREATE TABLE IF NOT EXISTS guided_draft (procedure_id TEXT PRIMARY KEY, recipe_hash TEXT NOT NULL, account_id TEXT NOT NULL, destination_id TEXT NOT NULL, step_index INTEGER NOT NULL, completed INTEGER NOT NULL DEFAULT 0)');
                db.prepare('INSERT OR IGNORE INTO guided_draft (procedure_id,recipe_hash,account_id,destination_id,step_index) VALUES (?,?,?,?,0)').run(draft.procedureId, hash, this.recipe.accountId, this.recipe.destinationId);
                const row = db.prepare('SELECT * FROM guided_draft WHERE procedure_id=?').get(draft.procedureId);
                if (!row || row.recipe_hash !== hash || row.account_id !== this.recipe.accountId || row.destination_id !== this.recipe.destinationId || Number(row.step_index) > this.recipe.steps.length || Number(row.completed) !== 0) throw new Error('Draft scope changed or completed');
                return Number(row.step_index);
            });
        }
    }
    current(): (RecipeStep & { accountId: string; destinationId: string; captureRule: string }) | undefined {
        const step = this.recipe.steps[this.index];
        return step && { ...step, accountId: this.recipe.accountId, destinationId: this.recipe.destinationId, captureRule: 'Enter the one-time secret directly into the mapped existing store; never paste it into Keyroot, a model, or a trace.' };
    }
    confirmStep(targetId: string, checkpointAcknowledged = false): void {
        const step = this.recipe.steps[this.index];
        if (this.completed || !step || step.targetId !== targetId || (step.checkpoint !== 'none' && !checkpointAcknowledged)) throw new Error('Step or checkpoint mismatch');
        if (this.draft) this.draft.journal.transaction(db => {
            const result = db.prepare('UPDATE guided_draft SET step_index=step_index+1 WHERE procedure_id=? AND recipe_hash=? AND step_index=? AND completed=0').run(this.draft!.procedureId, recipeHash(this.recipe), this.index);
            if (result.changes !== 1) throw new Error('Draft changed concurrently');
        });
        this.index++;
    }
    async complete(approvals: ApprovalService, request: AuthorizeEffectRequest, authorityFingerprint: string): Promise<{ receiptId: string; intentId: string; recipeHash: string; grantId: string; signature: string; limitation: string }> {
        if (this.completed || this.current()) throw new Error('Guided steps incomplete');
        const intentId = await authorizeRecipeAction(approvals, request, this.recipe, 'guided-completion', authorityFingerprint);
        this.completed = true;
        if (!request.signature) throw new Error('Completion authority unavailable');
        const receiptId = recordRecipeAction(approvals, request, this.recipe, intentId, ['owner-attestation', 'provider-unverified', 'store-unverified']);
        if (this.draft) this.draft.journal.transaction(db => {
            const result = db.prepare('UPDATE guided_draft SET completed=1 WHERE procedure_id=? AND recipe_hash=? AND step_index=? AND completed=0').run(this.draft!.procedureId, recipeHash(this.recipe), this.index);
            if (result.changes !== 1) throw new Error('Draft changed concurrently');
        });
        return { receiptId, intentId, grantId: request.grantId, signature: request.signature, recipeHash: recipeHash(this.recipe), limitation: 'Owner attestation only; provider outcome and secret storage are not independently verified.' };
    }
}
