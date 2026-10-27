import { createHash } from 'node:crypto';
export type SignerRole = 'routine' | 'emergency';
export type ActionKind = 'create' | 'validate' | 'store' | 'deliver' | 'restart' | 'revoke' | 'cleanup' | 'quarantine' | 'disable' | 'sign-out' | 'admin' | 'emergency-contain';
export interface BudgetCost {
    effects: number;
    newCredentials: number;
    restarts: number;
}
/** Identifiers and revision metadata only; never secret values, shell, URLs or request bodies. */
export interface ActionParameters {
    resourceId?: string;
    consumerId?: string;
    destinationId?: string;
    handleId?: string;
    generation?: number;
    expectedRevision?: string;
    recipeId?: string;
    adapterId?: string;
    authorityFingerprint?: string;
    reasonCode?: string;
}
export interface ManifestAction {
    id: string;
    kind: ActionKind;
    parameters: ActionParameters;
    budgetCost: BudgetCost;
}
export interface ManifestOperation {
    operationId: string;
    lineageId: string;
    accountId: string;
    fromGeneration: number;
    toGeneration: number;
    actions: ManifestAction[];
}
export interface ApprovalManifest {
    version: 1;
    domain: 'keyroot.approval.v1';
    algorithm: 'ECDSA-P256-SHA256';
    audience: 'keyroot-controller';
    installationId: string;
    bootId: string;
    signerId: string;
    role: SignerRole;
    nonce: string;
    notBefore: number;
    expiresAt: number;
    budgets: BudgetCost & {
        executions: number;
    };
    operations: ManifestOperation[];
    consumerMap: {
        revision: string;
        hash: string;
        entries: {
            consumerId: string;
            resourceId: string;
            revision: string;
        }[];
    };
    recipes: {
        id: string;
        version: string;
        hash: string;
        steps: {
            action: ActionKind;
            resourceId: string;
        }[];
    }[];
    adoptionThreshold: 'direct-use-every-consumer' | 'informed-override';
    overlapPolicy: 'required' | 'unavailable';
    deadline: {
        at: number;
        outcome: 'hold' | 'hard-revoke';
    };
    outage: {
        permitted: boolean;
        consequence: 'none' | 'declared-interruption';
    };
    graceSeconds: number;
}
function object(value: unknown, keys: string[], optional: string[] = []): asserts value is Record<string, unknown> {
    if (!value || typeof value !== 'object' || Array.isArray(value))
        throw new Error('Expected metadata object');
    const actual = Object.keys(value);
    if (keys.some(k => !actual.includes(k)) || actual.some(k => !keys.includes(k) && !optional.includes(k)))
        throw new Error('Unknown or missing manifest field');
}
function id(v: unknown): asserts v is string {
    if (typeof v !== 'string' || !v.length || v.length > 256 || !/^[-a-zA-Z0-9_.:@/]+$/.test(v))
        throw new Error('Invalid metadata identifier');
}
function integer(v: unknown, minimum = 0): asserts v is number {
    if (typeof v !== 'number' || !Number.isSafeInteger(v) || Object.is(v, -0) || v < minimum)
        throw new Error('Invalid safe integer');
}
function list(v: unknown): asserts v is unknown[] {
    if (!Array.isArray(v) || v.length > 1000)
        throw new Error('Invalid finite manifest list');
}
function choice(v: unknown, choices: readonly unknown[]) {
    if (!choices.includes(v))
        throw new Error('Invalid manifest choice');
}
const actionKinds: ActionKind[] = ['create', 'validate', 'store', 'deliver', 'restart', 'revoke', 'cleanup', 'quarantine', 'disable', 'sign-out', 'admin', 'emergency-contain'];
function costs(v: unknown, executions = false) {
    object(v, executions ? ['effects', 'newCredentials', 'restarts', 'executions'] : ['effects', 'newCredentials', 'restarts']);
    for (const n of Object.values(v))
        integer(n);
}
export function actionCost(action: Pick<ManifestAction, 'kind' | 'budgetCost'>): BudgetCost {
    const minimum = { effects: 1, newCredentials: action.kind === 'create' ? 1 : 0, restarts: action.kind === 'restart' ? 1 : 0 };
    if (action.budgetCost.effects < minimum.effects || action.budgetCost.newCredentials < minimum.newCredentials || action.budgetCost.restarts < minimum.restarts)
        throw new Error('Action understates effect budget');
    return { ...action.budgetCost };
}
function unique(values: string[]) {
    if (new Set(values).size !== values.length)
        throw new Error('Duplicate manifest identity');
}
export function validateManifest(value: unknown): asserts value is ApprovalManifest {
    object(value, ['version', 'domain', 'algorithm', 'audience', 'installationId', 'bootId', 'signerId', 'role', 'nonce', 'notBefore', 'expiresAt', 'budgets', 'operations', 'consumerMap', 'recipes', 'adoptionThreshold', 'overlapPolicy', 'deadline', 'outage', 'graceSeconds']);
    choice(value.version, [1]);
    choice(value.domain, ['keyroot.approval.v1']);
    choice(value.algorithm, ['ECDSA-P256-SHA256']);
    choice(value.audience, ['keyroot-controller']);
    choice(value.role, ['routine', 'emergency']);
    for (const key of ['installationId', 'bootId', 'signerId', 'nonce'])
        id(value[key]);
    integer(value.notBefore);
    integer(value.expiresAt);
    if (value.expiresAt <= value.notBefore)
        throw new Error('Invalid authority range');
    costs(value.budgets, true);
    list(value.operations);
    if (!value.operations.length)
        throw new Error('Empty approval');
    for (const op of value.operations) {
        object(op, ['operationId', 'lineageId', 'accountId', 'fromGeneration', 'toGeneration', 'actions']);
        id(op.operationId);
        id(op.lineageId);
        id(op.accountId);
        integer(op.fromGeneration);
        integer(op.toGeneration);
        if (op.toGeneration !== op.fromGeneration + 1)
            throw new Error('Invalid generation succession');
        list(op.actions);
        if (!op.actions.length)
            throw new Error('Empty operation');
        for (const a of op.actions) {
            object(a, ['id', 'kind', 'parameters', 'budgetCost']);
            id(a.id);
            choice(a.kind, actionKinds);
            object(a.parameters, [], ['resourceId', 'consumerId', 'destinationId', 'handleId', 'generation', 'expectedRevision', 'recipeId', 'adapterId', 'authorityFingerprint', 'reasonCode']);
            for (const [k, v] of Object.entries(a.parameters)) {
                if (k === 'generation')
                    integer(v);
                else
                    id(v);
            }
            costs(a.budgetCost);
            actionCost(a as unknown as ManifestAction);
            const required: Record<string, string[]> = { create: ['resourceId', 'adapterId', 'generation', 'handleId', 'destinationId'], validate: ['resourceId', 'handleId', 'generation'], store: ['destinationId', 'handleId', 'generation'], deliver: ['consumerId', 'destinationId', 'handleId', 'generation'], restart: ['consumerId', 'resourceId', 'generation'], revoke: ['resourceId', 'handleId', 'generation'], cleanup: ['resourceId', 'handleId', 'generation'], admin: ['resourceId', 'authorityFingerprint'], quarantine: ['resourceId', 'consumerId'], 'sign-out': ['resourceId', 'generation'] };
            for (const key of required[String(a.kind)] ?? ['resourceId'])
                if (a.parameters[key] === undefined)
                    throw new Error('Missing bound action target');
            if (a.parameters.generation !== undefined && a.parameters.generation !== op.fromGeneration && a.parameters.generation !== op.toGeneration)
                throw new Error('Action generation outside signed succession');
            if (['create', 'validate', 'store', 'deliver', 'restart'].includes(String(a.kind)) && a.parameters.generation !== op.toGeneration)
                throw new Error('Successor action generation mismatch');
        }
        unique(op.actions.map(a => (a as ManifestAction).id));
    }
    unique(value.operations.map(o => (o as ManifestOperation).operationId));
    object(value.consumerMap, ['revision', 'hash', 'entries']);
    id(value.consumerMap.revision);
    list(value.consumerMap.entries);
    for (const e of value.consumerMap.entries) {
        object(e, ['consumerId', 'resourceId', 'revision']);
        Object.values(e).forEach(id);
    }
    unique(value.consumerMap.entries.map(e => (e as {
        consumerId: string;
    }).consumerId));
    if (value.consumerMap.hash !== contentDigest(value.consumerMap.entries))
        throw new Error('Consumer map hash mismatch');
    list(value.recipes);
    for (const r of value.recipes) {
        object(r, ['id', 'version', 'hash', 'steps']);
        id(r.id);
        id(r.version);
        list(r.steps);
        for (const s of r.steps) {
            object(s, ['action', 'resourceId']);
            choice(s.action, actionKinds);
            id(s.resourceId);
        }
        if (r.hash !== contentDigest(r.steps))
            throw new Error('Recipe hash mismatch');
    }
    unique(value.recipes.map(r => (r as {
        id: string;
    }).id));
    choice(value.adoptionThreshold, ['direct-use-every-consumer', 'informed-override']);
    choice(value.overlapPolicy, ['required', 'unavailable']);
    object(value.deadline, ['at', 'outcome']);
    integer(value.deadline.at);
    choice(value.deadline.outcome, ['hold', 'hard-revoke']);
    object(value.outage, ['permitted', 'consequence']);
    choice(value.outage.permitted, [true, false]);
    choice(value.outage.consequence, ['none', 'declared-interruption']);
    integer(value.graceSeconds);
    if (value.outage.permitted !== (value.outage.consequence === 'declared-interruption'))
        throw new Error('Outage consequence required');
    if ((value.deadline.outcome === 'hard-revoke' || value.overlapPolicy === 'unavailable') && !value.outage.permitted)
        throw new Error('Outage authority required');
}
/** Deterministic key ordering; input byte equality additionally rejects duplicate keys and alternate numbers. */
export function canonicalJSON(value: unknown): string {
    if (Array.isArray(value))
        return '[' + value.map(canonicalJSON).join(',') + ']';
    if (value !== null && typeof value === 'object')
        return '{' + Object.keys(value).sort().map(k => JSON.stringify(k) + ':' + canonicalJSON((value as Record<string, unknown>)[k])).join(',') + '}';
    return JSON.stringify(value);
}
export function contentDigest(value: unknown): string {
    return 'sha256:' + createHash('sha256').update(canonicalJSON(value)).digest('hex');
}
export function canonicalizeManifest(value: ApprovalManifest): string {
    validateManifest(value);
    return canonicalJSON(value);
}
export function parseCanonicalManifest(raw: string): ApprovalManifest {
    if (Buffer.byteLength(raw) > 1024 * 1024)
        throw new Error('Manifest too large');
    const value: unknown = JSON.parse(raw);
    validateManifest(value);
    if (canonicalJSON(value) !== raw)
        throw new Error('Noncanonical or duplicate manifest fields');
    return deepFreeze(value);
}
export function manifestDigest(raw: string): string {
    parseCanonicalManifest(raw);
    return 'sha256:' + createHash('sha256').update('keyroot.manifest-digest.v1\0').update(raw).digest('hex');
}
/** Trusted engine computes this from its *current* policy and inventory, never from an HTTP assertion. */
export function snapshotDigest(m: ApprovalManifest): string {
    return contentDigest({ operations: m.operations, consumerMap: m.consumerMap, recipes: m.recipes, adoptionThreshold: m.adoptionThreshold, overlapPolicy: m.overlapPolicy, deadline: m.deadline, outage: m.outage, graceSeconds: m.graceSeconds });
}
export function deepFreeze<T>(value: T): T {
    if (value && typeof value === 'object') {
        Object.values(value).forEach(deepFreeze);
        Object.freeze(value);
    }
    return value;
}
