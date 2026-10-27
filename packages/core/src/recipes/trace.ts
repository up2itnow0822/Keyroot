import { makeRecipe, recipeHash, type Recipe, type RecipeAction } from './recipe.js';
export interface TraceObservation { action: RecipeAction; targetId: string; observation: 'visible' | 'completed' | 'blocked' }
export interface RecipeProposal { status: 'proposal'; basedOnHash: string; proposedVersion: string; observations: TraceObservation[] }
/** Observations are a closed vocabulary. Page/model prose never becomes recipe instructions. */
export function proposeTrace(recipe: Recipe, observations: TraceObservation[]): RecipeProposal {
    const r = makeRecipe(recipe);
    if (!Array.isArray(observations) || observations.length > 32) throw new Error('Invalid trace');
    const safe = observations.map(o => {
        if (!o || Object.keys(o).sort().join(',') !== 'action,observation,targetId' || !['visible', 'completed', 'blocked'].includes(o.observation) || !r.steps.some(s => s.action === o.action && s.targetId === o.targetId)) throw new Error('Unsafe trace observation');
        return { action: o.action, targetId: o.targetId, observation: o.observation };
    });
    return { status: 'proposal', basedOnHash: recipeHash(r), proposedVersion: `${r.version}.proposal`, observations: safe };
}
