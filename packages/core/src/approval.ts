import type { DatabaseSync } from 'node:sqlite';
import { createHash, createPublicKey, verify, randomUUID, type JsonWebKey as NodeJsonWebKey } from 'node:crypto';
import { Journal, type AuthorizedIntent, type OperationRecord } from './journal.js';
import { actionCost, canonicalJSON, manifestDigest, parseCanonicalManifest, snapshotDigest, type ApprovalManifest, type ManifestOperation, type ManifestAction, type SignerRole } from './manifest.js';
const localBootstraps = new WeakSet<object>();
export interface LocalBootstrapContext {
    readonly kind: 'local-console-bootstrap';
}
/** Trusted local CLI only: mint after the local ceremony, never from a request body or tailnet identity. */
export function createLocalBootstrapContext(): LocalBootstrapContext {
    const context = Object.freeze({ kind: 'local-console-bootstrap' as const });
    localBootstraps.add(context);
    return context;
}
function publicKey(value: JsonWebKey) {
    if (Object.keys(value).some(k => !['kty', 'crv', 'x', 'y', 'ext', 'key_ops'].includes(k)) || value.kty !== 'EC' || value.crv !== 'P-256' || !value.x || !value.y)
        throw new Error('Only public P-256 material is accepted');
    return createPublicKey({ key: value as NodeJsonWebKey, format: 'jwk' });
}
export function publicKeyFingerprint(value: JsonWebKey): string {
    return 'sha256:' + createHash('sha256').update(publicKey(value).export({ format: 'der', type: 'spki' })).digest('hex');
}
interface GrantRow {
    grant_id: string;
    raw_manifest: string;
    signature: string;
    digest: string;
    boot_id: string;
    role: SignerRole;
    cancelled: number;
    executions: number;
    effects: number;
    new_credentials: number;
    restarts: number;
}
export interface AuthorizeEffectRequest {
    grantId: string;
    signature?: string;
    operationId: string;
    actionId: string;
    currentSnapshotDigest: string;
    /** Retained compatibility metadata; ignored for effect authority. The executor injects the trusted clock. */
    now?: number;
    emergencyProofId?: string;
}
export interface ApproverBootstrap {
    signerId: string;
    role: SignerRole;
    publicKey: JsonWebKey;
    localBootstrap: LocalBootstrapContext;
    confirmedFingerprint: string;
}
export class ApprovalService {
    constructor(readonly journal: Journal, private readonly options: {
        mode: 'synthetic' | 'real';
        clock?: () => number;
        checkEffectFence?: () => Promise<void>;
    }) {
    }
    bootstrapApprover(input: ApproverBootstrap): void {
        this.journal.transaction(db => this.bootstrapApproverInTransaction(db, input));
    }
    /** Internal local-bootstrap primitive; caller owns the transaction and any dependent credential insert. */
    bootstrapApproverInTransaction(db: DatabaseSync, input: ApproverBootstrap): void {
        if (!localBootstraps.has(input.localBootstrap))
            throw new Error('Explicit trusted local bootstrap required');
        const fingerprint = publicKeyFingerprint(input.publicKey);
        if (fingerprint !== input.confirmedFingerprint)
            throw new Error('Independent fingerprint comparison required');
        if (input.role !== 'routine' && input.role !== 'emergency')
            throw new Error('Invalid signer role');
        this.journal.assertCurrent(db);
        if (db.prepare('SELECT 1 FROM approver').get())
            throw new Error('Trust configuration is not empty');
        db.prepare('INSERT INTO approver(signer_id,role,public_key,fingerprint) VALUES(?,?,?,?)').run(input.signerId, input.role, canonicalJSON(input.publicKey), fingerprint);
        this.journal.audit(db, 'approver-local-bootstrap', null, input.signerId);
    }
    /** Enrolling the separate emergency key is itself an owner-authorized admin action in U10. */
    revokeApprover(signerId: string): void {
        this.journal.transaction(db => {
            db.prepare('UPDATE approver SET revoked=1 WHERE signer_id=?').run(signerId);
            for (const row of db.prepare('SELECT grant_id,raw_manifest FROM approval_grant').all()) {
                if (parseCanonicalManifest(String(row.raw_manifest)).signerId === signerId)
                    db.prepare('UPDATE approval_grant SET cancelled=1 WHERE grant_id=?').run(String(row.grant_id));
            }
            this.journal.audit(db, 'approver-revoked', null, signerId);
        });
    }
    private verifySignature(manifest: ApprovalManifest, raw: string, signature: string): void {
        const signer = this.journal.read(db => db.prepare('SELECT * FROM approver WHERE signer_id=? AND revoked=0').get(manifest.signerId));
        if (!signer || signer.role !== manifest.role)
            throw new Error('Unknown or wrong signer role');
        const bytes = Buffer.from(signature, 'base64url');
        if (bytes.length !== 64 || !verify('sha256', Buffer.from(raw), { key: publicKey(JSON.parse(String(signer.public_key)) as JsonWebKey), dsaEncoding: 'ieee-p1363' }, bytes))
            throw new Error('Invalid P-256 signature');
    }
    private checkManifest(manifest: ApprovalManifest, now: number) {
        if (!Number.isSafeInteger(now) || now < manifest.notBefore || now >= manifest.expiresAt)
            throw new Error('Approval outside validity range');
        if (manifest.installationId !== this.journal.installationId || manifest.bootId !== this.journal.bootId)
            throw new Error('Approval installation or boot mismatch');
    }
    registerGrant(raw: string, signature: string, now = Date.now()): string {
        const manifest = parseCanonicalManifest(raw);
        if (manifest.role !== 'routine')
            throw new Error('Emergency authority requires WebAuthn');
        this.checkManifest(manifest, now);
        this.verifySignature(manifest, raw, signature);
        return this.persistGrant(manifest, raw, signature);
    }
    /** No authority is conferred until a fresh maintained-verifier WebAuthn assertion is consumed per action. */
    registerEmergencyGrant(raw: string, now = Date.now()): string {
        const manifest = parseCanonicalManifest(raw);
        if (manifest.role !== 'emergency')
            throw new Error('Wrong emergency role');
        this.checkManifest(manifest, now);
        return this.persistGrant(manifest, raw, '');
    }
    private persistGrant(manifest: ApprovalManifest, raw: string, signature: string): string {
        this.journal.transaction(db => {
            this.journal.assertCurrent(db);
            const signer = db.prepare('SELECT role FROM approver WHERE signer_id=? AND revoked=0').get(manifest.signerId);
            if (!signer || signer.role !== manifest.role)
                throw new Error('Unknown signer role');
            db.prepare('INSERT INTO approval_grant(grant_id,raw_manifest,signature,digest,boot_id,role) VALUES(?,?,?,?,?,?)').run(manifest.nonce, raw, signature, manifestDigest(raw), manifest.bootId, manifest.role);
            this.journal.audit(db, 'grant-registered', null, manifest.nonce);
        });
        return manifest.nonce;
    }
    /** One predicate for initial admission and continuation; the reserved intent itself is excluded by the latter. */
    private isNarrowEmergencyContainment(manifest: ApprovalManifest, operation: ManifestOperation, action: ManifestAction, existing: OperationRecord | undefined, unresolved: readonly Record<string, unknown>[], reservedIntentId?: string): boolean {
        if (manifest.role !== 'emergency' || !unresolved.length || !existing || !['revoke', 'quarantine', 'sign-out'].includes(action.kind))
            return false;
        if (existing.state === 'completed' || existing.lineageId !== operation.lineageId || existing.accountId !== operation.accountId || existing.fromGeneration !== operation.fromGeneration || existing.toGeneration !== operation.toGeneration)
            throw new Error('Containment must attach to the exact predecessor');
        const target = action.parameters.resourceId;
        if (!target || target.startsWith('created:') || (action.kind !== 'quarantine' && action.parameters.generation !== operation.fromGeneration))
            throw new Error('Containment requires concrete known old resource');
        if (action.kind === 'quarantine' && !manifest.consumerMap.entries.some(e => e.consumerId === action.parameters.consumerId))
            throw new Error('Quarantine consumer outside exact signed map');
        for (const row of unresolved) {
            if (row.intent_id === reservedIntentId)
                continue;
            const params = JSON.parse(String(row.parameters)) as Record<string, unknown>;
            if ((action.kind === 'quarantine' && params.consumerId === action.parameters.consumerId) || (action.kind !== 'quarantine' && params.resourceId === target))
                throw new Error('Containment cannot target ambiguous resource');
        }
        return true;
    }
    /** Continuation of exactly the reserved action, with no new intent or additional effect authority. */
    assertReservedIntentAuthority(request: AuthorizeEffectRequest & {
        intentId: string;
    }): Promise<AuthorizedIntent> {
        return this.checkReservedIntentAuthority(request, false);
    }
    /** Compound create continuation additionally requires both effect slots and the signed store target. */
    assertCurrentAuthority(request: AuthorizeEffectRequest & {
        intentId: string;
    }): Promise<AuthorizedIntent> {
        return this.checkReservedIntentAuthority(request, true);
    }
    private async checkReservedIntentAuthority(request: AuthorizeEffectRequest & {
        intentId: string;
    }, compoundCreate: boolean): Promise<AuthorizedIntent> {
        if (this.options.mode === 'real')
            throw new Error('Real mutation remains gated pending custody, isolation and recovery admission');
        await this.options.checkEffectFence?.();
        return this.journal.transaction(db => {
            this.journal.assertCurrent(db);
            const now = this.options.clock?.() ?? Date.now();
            const grant = db.prepare('SELECT * FROM approval_grant WHERE grant_id=? AND cancelled=0').get(request.grantId) as unknown as GrantRow | undefined;
            if (!grant)
                throw new Error('Cancelled or unknown approval');
            const manifest = parseCanonicalManifest(grant.raw_manifest);
            this.checkManifest(manifest, now);
            if (manifest.role === 'routine') {
                if (request.emergencyProofId)
                    throw new Error('Emergency proof cannot authorize routine work');
                if (request.signature !== grant.signature)
                    throw new Error('Signature mismatch');
                this.verifySignature(manifest, grant.raw_manifest, request.signature);
            }
            else {
                const signer = db.prepare("SELECT 1 FROM approver WHERE signer_id=? AND role='emergency' AND revoked=0").get(manifest.signerId);
                const proof = db.prepare('SELECT * FROM emergency_proof WHERE proof_id=? AND used=1').get(request.emergencyProofId ?? '');
                if (!signer || !proof || proof.grant_id !== request.grantId || proof.digest !== grant.digest || proof.operation_id !== request.operationId || proof.action_id !== request.actionId || Number(proof.expires_at) <= (now))
                    throw new Error('Emergency continuation authority missing');
            }
            if (snapshotDigest(manifest) !== request.currentSnapshotDigest)
                throw new Error('Current scope or policy changed');
            const op = manifest.operations.find(o => o.operationId === request.operationId);
            const action = op?.actions.find(a => a.id === request.actionId);
            if (manifest.role === 'routine' && op && db.prepare("SELECT 1 FROM emergency_reservation r JOIN approval_grant g ON g.grant_id=r.grant_id WHERE r.lineage_id=? AND g.cancelled=0 AND g.boot_id=?").get(op.lineageId, this.journal.bootId))
                throw new Error('Verified emergency reservation blocks routine continuation');
            const row = db.prepare("SELECT * FROM intent WHERE intent_id=? AND operation_id=? AND action_id=? AND grant_id=? AND state='pending'").get(request.intentId, request.operationId, request.actionId, request.grantId);
            if (!op || !action || !row || row.kind !== action.kind || row.parameters !== canonicalJSON(action.parameters))
                throw new Error('Exact reserved intent missing');
            if (db.prepare('SELECT metadata FROM receipt WHERE intent_id=?').all(request.intentId).some(row => (JSON.parse(String(row.metadata)) as {
                outcome: string;
            }).outcome === 'unknown'))
                throw new Error('Reserved effect needs explicit reconciliation');
            if (compoundCreate && (action.kind !== 'create' || action.budgetCost.effects < 2 || !action.parameters.handleId || !action.parameters.destinationId))
                throw new Error('Compound create/store must reserve two effects and exact store target');
            const operation = this.journal.inspectOperation(request.operationId);
            let heldContainment = false;
            if (operation?.state === 'reconcile-required' && manifest.role === 'emergency' && !compoundCreate) {
                if (!db.prepare('SELECT 1 FROM emergency_reservation WHERE grant_id=? AND lineage_id=?').get(request.grantId, op.lineageId))
                    throw new Error('Missing emergency reservation');
                const unresolved = db.prepare("SELECT * FROM intent WHERE operation_id=? AND state!='observed'").all(op.operationId);
                heldContainment = this.isNarrowEmergencyContainment(manifest, op, action, operation, unresolved, request.intentId);
            }
            if (!operation || (operation.state !== 'active' && !heldContainment) || !db.prepare('SELECT 1 FROM lineage_lock WHERE lineage_id=? AND operation_id=?').get(op.lineageId, op.operationId))
                throw new Error('Continuation operation fenced');
            return this.journal.intentRecord(row);
        });
    }
    cancelGrant(grantId: string): void {
        this.journal.transaction(db => {
            db.prepare('UPDATE approval_grant SET cancelled=1 WHERE grant_id=?').run(grantId);
            this.journal.audit(db, 'grant-cancelled', null, grantId);
        });
    }
    async authorizeEffect(request: AuthorizeEffectRequest): Promise<AuthorizedIntent> {
        // This unit does not yet have the required independent-origin/custody/recovery admission path.
        if (this.options.mode === 'real')
            throw new Error('Real mutation remains gated pending custody, isolation and recovery admission');
        await this.options.checkEffectFence?.();
        return this.journal.transaction(db => {
            this.journal.assertCurrent(db);
            const now = this.options.clock?.() ?? Date.now();
            const grant = db.prepare('SELECT * FROM approval_grant WHERE grant_id=?').get(request.grantId) as unknown as GrantRow | undefined;
            if (!grant || grant.cancelled)
                throw new Error('Cancelled or unknown approval');
            const manifest = parseCanonicalManifest(grant.raw_manifest);
            this.checkManifest(manifest, now);
            if (grant.boot_id !== this.journal.bootId)
                throw new Error('Stale boot approval');
            if (manifest.role === 'routine') {
                if (request.emergencyProofId)
                    throw new Error('Emergency proof cannot authorize routine work');
                if (request.signature !== grant.signature)
                    throw new Error('Signature mismatch');
                this.verifySignature(manifest, grant.raw_manifest, request.signature);
            }
            else {
                const signer = db.prepare('SELECT role FROM approver WHERE signer_id=? AND revoked=0').get(manifest.signerId);
                if (signer?.role !== 'emergency')
                    throw new Error('Emergency key revoked');
                const proof = db.prepare('SELECT * FROM emergency_proof WHERE proof_id=? AND used=0').get(request.emergencyProofId ?? '');
                if (!proof || proof.grant_id !== request.grantId || proof.digest !== grant.digest || proof.operation_id !== request.operationId || proof.action_id !== request.actionId || Number(proof.expires_at) <= (now))
                    throw new Error('Fresh emergency assertion required');
                db.prepare('UPDATE emergency_proof SET used=1 WHERE proof_id=?').run(request.emergencyProofId!);
            }
            if (snapshotDigest(manifest) !== request.currentSnapshotDigest)
                throw new Error('Current scope or policy changed');
            const operation = manifest.operations.find(op => op.operationId === request.operationId);
            const action = operation?.actions.find(a => a.id === request.actionId);
            if (manifest.role === 'routine' && operation && db.prepare("SELECT 1 FROM emergency_reservation r JOIN approval_grant g ON g.grant_id=r.grant_id WHERE r.lineage_id=? AND g.cancelled=0 AND g.boot_id=?").get(operation.lineageId, this.journal.bootId))
                throw new Error('Verified emergency reservation blocks routine dispatch');
            if (!operation || !action)
                throw new Error('Action outside signed finite scope');
            const unresolved = db.prepare("SELECT * FROM intent WHERE operation_id=? AND state!='observed'").all(operation.operationId);
            const existing = this.journal.inspectOperation(operation.operationId);
            const emergencyContainment = this.isNarrowEmergencyContainment(manifest, operation, action, existing, unresolved);
            if (emergencyContainment)
                db.prepare("UPDATE operation SET state='reconcile-required' WHERE operation_id=?").run(operation.operationId);
            const record = emergencyContainment ? existing! : this.journal.ensureOperation(db, operation);
            const lock = db.prepare('SELECT * FROM lineage_lock WHERE lineage_id=? AND operation_id=?').get(record.lineageId, record.operationId);
            if (!lock)
                throw new Error('Lineage fence missing');
            if (db.prepare('SELECT 1 FROM intent WHERE operation_id=? AND action_id=?').get(record.operationId, action.id))
                throw new Error('Action already consumed');
            for (const previous of emergencyContainment ? [] : operation.actions.slice(0, operation.actions.indexOf(action))) {
                if (!db.prepare("SELECT 1 FROM intent WHERE operation_id=? AND action_id=? AND state='observed'").get(record.operationId, previous.id))
                    throw new Error('Prior effect needs observation/reconciliation');
            }
            if (!emergencyContainment && unresolved.length > 0)
                throw new Error('Unreconciled effect');
            const instance = db.prepare('SELECT 1 FROM approval_instance WHERE grant_id=? AND operation_id=?').get(request.grantId, record.operationId);
            const cost = actionCost(action);
            const executionCost = instance ? 0 : 1;
            if (grant.executions + executionCost > manifest.budgets.executions || grant.effects + cost.effects > manifest.budgets.effects || grant.new_credentials + cost.newCredentials > manifest.budgets.newCredentials || grant.restarts + cost.restarts > manifest.budgets.restarts)
                throw new Error('Approval budget exhausted');
            if (!instance)
                db.prepare('INSERT INTO approval_instance VALUES(?,?)').run(request.grantId, record.operationId);
            if (manifest.role === 'emergency') {
                if (!db.prepare('SELECT 1 FROM emergency_reservation WHERE grant_id=? AND lineage_id=?').get(request.grantId, record.lineageId))
                    throw new Error('Missing emergency reservation');
                db.prepare('UPDATE emergency_reservation SET consumed=1 WHERE grant_id=? AND lineage_id=?').run(request.grantId, record.lineageId);
                // Cancel optional routine grants for the lineage; a live/ambiguous predecessor remains locked.
                for (const row of db.prepare("SELECT grant_id,raw_manifest FROM approval_grant WHERE role='routine' AND cancelled=0").all()) {
                    if (parseCanonicalManifest(String(row.raw_manifest)).operations.some(op => op.lineageId === record.lineageId))
                        db.prepare('UPDATE approval_grant SET cancelled=1 WHERE grant_id=?').run(String(row.grant_id));
                }
            }
            db.prepare('UPDATE approval_grant SET executions=executions+?,effects=effects+?,new_credentials=new_credentials+?,restarts=restarts+? WHERE grant_id=?').run(executionCost, cost.effects, cost.newCredentials, cost.restarts, request.grantId);
            const intentId = randomUUID();
            db.prepare("INSERT INTO intent VALUES(?,?,?,?,?,?,?,'pending')").run(intentId, Journal.idempotencyRef(record.operationId, action.id), record.operationId, action.id, request.grantId, action.kind, canonicalJSON(action.parameters));
            this.journal.audit(db, 'effect-intent-consumed', record.operationId, intentId);
            return this.journal.intentRecord(db.prepare('SELECT * FROM intent WHERE intent_id=?').get(intentId)!);
        });
    }
}
