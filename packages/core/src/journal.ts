import { DatabaseSync } from 'node:sqlite';
import { createHash, randomUUID } from 'node:crypto';
import { canonicalJSON, deepFreeze, parseCanonicalManifest, type ManifestOperation, type SignerRole } from './manifest.js';
export type OperationState = 'active' | 'reconcile-required' | 'held' | 'completed';
export interface OperationRecord {
    operationId: string;
    lineageId: string;
    accountId: string;
    fromGeneration: number;
    toGeneration: number;
    state: OperationState;
    bootId: string;
}
export interface AuthorizedIntent {
    intentId: string;
    idempotencyRef: string;
    operationId: string;
    actionId: string;
    grantId: string;
    kind: string;
    parameters: Readonly<Record<string, string | number>>;
    state: 'pending' | 'observed' | 'unknown';
}
export type ReceiptKind = 'creation' | 'validation' | 'storage' | 'delivery-accepted' | 'direct-use' | 'inferred-adoption' | 'issuer-revocation' | 'issuer-rejection' | 'reconciliation' | 'unknown' | 'restart' | 'quarantine' | 'disable' | 'sign-out' | 'administration' | 'containment';
export interface MetadataReceipt {
    receiptId: string;
    intentId: string;
    kind: ReceiptKind;
    outcome: 'confirmed' | 'rejected' | 'unknown';
    generation: number;
    observedAt: number;
    observerId: string;
    evidenceHash: string;
    consumerId?: string;
    revision?: string;
    resourceId?: string;
    handleId?: string;
    accountId?: string;
    parentResourceId?: string;
    destinationId?: string;
    storeVersion?: number;
    reconcilesReceiptIds?: string[];
    limitationCodes: string[];
}
interface OperationRow {
    operation_id: string;
    lineage_id: string;
    account_id: string;
    from_generation: number;
    to_generation: number;
    state: OperationState;
    boot_id: string;
}
const migration1 = `
CREATE TABLE controller (singleton INTEGER PRIMARY KEY CHECK(singleton=1), installation_id TEXT NOT NULL, boot_id TEXT NOT NULL, recovery_hold INTEGER NOT NULL DEFAULT 0);
CREATE TABLE operation (operation_id TEXT PRIMARY KEY, lineage_id TEXT NOT NULL, account_id TEXT NOT NULL, from_generation INTEGER NOT NULL, to_generation INTEGER NOT NULL, state TEXT NOT NULL CHECK(state IN ('active','reconcile-required','held','completed')), boot_id TEXT NOT NULL);
CREATE TABLE lineage_lock (lineage_id TEXT PRIMARY KEY, operation_id TEXT NOT NULL REFERENCES operation(operation_id), fence TEXT NOT NULL UNIQUE);
CREATE TABLE approver (signer_id TEXT PRIMARY KEY, role TEXT NOT NULL CHECK(role IN ('routine','emergency')), public_key TEXT NOT NULL, fingerprint TEXT NOT NULL, revoked INTEGER NOT NULL DEFAULT 0);
CREATE TABLE approval_grant (grant_id TEXT PRIMARY KEY, raw_manifest TEXT NOT NULL, signature TEXT NOT NULL, digest TEXT NOT NULL, boot_id TEXT NOT NULL, role TEXT NOT NULL, cancelled INTEGER NOT NULL DEFAULT 0, executions INTEGER NOT NULL DEFAULT 0, effects INTEGER NOT NULL DEFAULT 0, new_credentials INTEGER NOT NULL DEFAULT 0, restarts INTEGER NOT NULL DEFAULT 0);
CREATE TABLE approval_instance (grant_id TEXT NOT NULL REFERENCES approval_grant(grant_id), operation_id TEXT NOT NULL REFERENCES operation(operation_id), PRIMARY KEY(grant_id,operation_id));
CREATE TABLE intent (intent_id TEXT PRIMARY KEY, idempotency_ref TEXT NOT NULL UNIQUE, operation_id TEXT NOT NULL REFERENCES operation(operation_id), action_id TEXT NOT NULL, grant_id TEXT NOT NULL REFERENCES approval_grant(grant_id), kind TEXT NOT NULL, parameters TEXT NOT NULL, state TEXT NOT NULL CHECK(state IN ('pending','observed','unknown')), UNIQUE(operation_id,action_id));
CREATE TABLE receipt (receipt_id TEXT PRIMARY KEY, intent_id TEXT NOT NULL REFERENCES intent(intent_id), metadata TEXT NOT NULL);
CREATE TABLE emergency_reservation (grant_id TEXT NOT NULL REFERENCES approval_grant(grant_id), lineage_id TEXT NOT NULL, consumed INTEGER NOT NULL DEFAULT 0, PRIMARY KEY(grant_id,lineage_id));
CREATE TABLE emergency_credential (signer_id TEXT PRIMARY KEY REFERENCES approver(signer_id), credential_id TEXT NOT NULL UNIQUE, public_key TEXT NOT NULL, counter INTEGER NOT NULL, rp_id TEXT NOT NULL, origin TEXT NOT NULL);
CREATE TABLE emergency_challenge (challenge_id TEXT PRIMARY KEY, signer_id TEXT NOT NULL REFERENCES emergency_credential(signer_id), grant_id TEXT NOT NULL REFERENCES approval_grant(grant_id), digest TEXT NOT NULL, operation_id TEXT NOT NULL, action_id TEXT NOT NULL, challenge TEXT NOT NULL UNIQUE, expires_at INTEGER NOT NULL, used INTEGER NOT NULL DEFAULT 0);
CREATE TABLE emergency_proof (proof_id TEXT PRIMARY KEY, grant_id TEXT NOT NULL, digest TEXT NOT NULL, operation_id TEXT NOT NULL, action_id TEXT NOT NULL, expires_at INTEGER NOT NULL, used INTEGER NOT NULL DEFAULT 0);
CREATE TABLE session_revocation (session_id TEXT PRIMARY KEY, boot_id TEXT NOT NULL, revoked INTEGER NOT NULL DEFAULT 0);
CREATE TABLE source_evidence (evidence_id TEXT PRIMARY KEY, source_id TEXT NOT NULL, evidence_hash TEXT NOT NULL, observed_at INTEGER NOT NULL);
CREATE TABLE audit (sequence INTEGER PRIMARY KEY AUTOINCREMENT, kind TEXT NOT NULL, operation_id TEXT, reference_id TEXT NOT NULL, boot_id TEXT NOT NULL);
`;
function metadataId(value: unknown): asserts value is string {
    if (typeof value !== 'string' || !/^[-a-zA-Z0-9_.:@/]+$/.test(value) || value.length > 256)
        throw new Error('Invalid metadata identifier');
}
function operationRecord(row: OperationRow): OperationRecord {
    return { operationId: row.operation_id, lineageId: row.lineage_id, accountId: row.account_id, fromGeneration: row.from_generation, toGeneration: row.to_generation, state: row.state, bootId: row.boot_id };
}
/** Trusted controller persistence boundary. SQL access is internal integration API, never an HTTP surface. */
export class Journal {
    readonly installationId: string;
    readonly bootId: string;
    private readonly db: DatabaseSync;
    constructor(path: string, options: {
        installationId: string;
        bootId?: string;
    }) {
        this.installationId = options.installationId;
        this.bootId = options.bootId ?? randomUUID();
        metadataId(this.installationId);
        metadataId(this.bootId);
        this.db = new DatabaseSync(path);
        this.db.exec('PRAGMA foreign_keys=ON; PRAGMA busy_timeout=5000; PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;');
        this.transaction(db => {
            const version = (db.prepare('PRAGMA user_version').get() as {
                user_version: number;
            }).user_version;
            if (version === 0) {
                db.exec(migration1);
                db.exec('PRAGMA user_version=1');
            }
            else if (version !== 1)
                throw new Error('Unsupported journal schema');
            const row = db.prepare('SELECT * FROM controller WHERE singleton=1').get() as {
                installation_id: string;
                boot_id: string;
            } | undefined;
            if (!row)
                db.prepare('INSERT INTO controller(singleton,installation_id,boot_id) VALUES(1,?,?)').run(this.installationId, this.bootId);
            else {
                if (row.installation_id !== this.installationId)
                    throw new Error('Installation mismatch; recovery required');
                if (row.boot_id !== this.bootId) {
                    db.prepare('UPDATE controller SET boot_id=? WHERE singleton=1').run(this.bootId);
                    db.exec("UPDATE approval_grant SET cancelled=1; UPDATE session_revocation SET revoked=1; UPDATE operation SET state='reconcile-required' WHERE state!='completed'; UPDATE intent SET state='unknown' WHERE state='pending'; UPDATE emergency_challenge SET used=1; UPDATE emergency_proof SET used=1;");
                    this.audit(db, 'boot-invalidated', null, this.bootId);
                }
            }
        });
    }
    transaction<T>(fn: (db: DatabaseSync) => T): T {
        this.db.exec('BEGIN IMMEDIATE');
        try {
            const result = fn(this.db);
            this.db.exec('COMMIT');
            return result;
        }
        catch (error) {
            this.db.exec('ROLLBACK');
            throw error;
        }
    }
    read<T>(fn: (db: DatabaseSync) => T): T {
        return fn(this.db);
    }
    audit(db: DatabaseSync, kind: string, operationId: string | null, referenceId: string) {
        db.prepare('INSERT INTO audit(kind,operation_id,reference_id,boot_id) VALUES(?,?,?,?)').run(kind, operationId, referenceId, this.bootId);
    }
    assertCurrent(db: DatabaseSync) {
        const row = db.prepare('SELECT * FROM controller WHERE singleton=1').get() as {
            boot_id: string;
            recovery_hold: number;
        };
        if (row.boot_id !== this.bootId || row.recovery_hold)
            throw new Error('Controller fenced or in recovery hold');
    }
    createOperation(operation: Omit<ManifestOperation, 'actions'>): OperationRecord {
        return this.transaction(db => this.ensureOperation(db, operation));
    }
    ensureOperation(db: DatabaseSync, operation: Omit<ManifestOperation, 'actions'>): OperationRecord {
        this.assertCurrent(db);
        for (const key of ['operationId', 'lineageId', 'accountId'] as const)
            metadataId(operation[key]);
        if (!Number.isSafeInteger(operation.fromGeneration) || operation.fromGeneration < 0 || operation.toGeneration !== operation.fromGeneration + 1)
            throw new Error('Invalid generation succession');
        const row = db.prepare('SELECT * FROM operation WHERE operation_id=?').get(operation.operationId) as unknown as OperationRow | undefined;
        if (row) {
            const found = operationRecord(row);
            for (const key of ['lineageId', 'accountId', 'fromGeneration', 'toGeneration'] as const)
                if (found[key] !== operation[key])
                    throw new Error('Operation identity mismatch');
            if (found.state !== 'active')
                throw new Error('Operation requires reconciliation or is terminal');
            return found;
        }
        const lock = db.prepare('SELECT operation_id FROM lineage_lock WHERE lineage_id=?').get(operation.lineageId);
        if (lock)
            throw new Error('Lineage has a live predecessor');
        const predecessor = db.prepare("SELECT to_generation FROM operation WHERE lineage_id=? AND state='completed' ORDER BY rowid DESC LIMIT 1").get(operation.lineageId);
        if (predecessor && predecessor.to_generation !== operation.fromGeneration)
            throw new Error('Lineage generation moved');
        db.prepare("INSERT INTO operation VALUES(?,?,?,?,?,'active',?)").run(operation.operationId, operation.lineageId, operation.accountId, operation.fromGeneration, operation.toGeneration, this.bootId);
        db.prepare('INSERT INTO lineage_lock VALUES(?,?,?)').run(operation.lineageId, operation.operationId, randomUUID());
        this.audit(db, 'operation-created', operation.operationId, operation.lineageId);
        return { ...operation, state: 'active', bootId: this.bootId };
    }
    inspectOperation(operationId: string): OperationRecord | undefined {
        return this.read(db => {
            const row = db.prepare('SELECT * FROM operation WHERE operation_id=?').get(operationId) as unknown as OperationRow | undefined;
            return row ? deepFreeze(operationRecord(row)) : undefined;
        });
    }
    listOperations(): OperationRecord[] {
        return this.read(db => (db.prepare('SELECT * FROM operation ORDER BY operation_id').all() as unknown as OperationRow[]).map(operationRecord));
    }
    listIntents(operationId: string): AuthorizedIntent[] {
        return this.read(db => db.prepare('SELECT * FROM intent WHERE operation_id=? ORDER BY rowid').all(operationId).map(row => this.intentRecord(row)));
    }
    intentRecord(row: Record<string, unknown>): AuthorizedIntent {
        return deepFreeze({ intentId: String(row.intent_id), idempotencyRef: String(row.idempotency_ref), operationId: String(row.operation_id), actionId: String(row.action_id), grantId: String(row.grant_id), kind: String(row.kind), parameters: JSON.parse(String(row.parameters)) as Record<string, string | number>, state: row.state as AuthorizedIntent['state'] });
    }
    appendReceipt(receipt: MetadataReceipt): void {
        const fields = ['receiptId', 'intentId', 'kind', 'outcome', 'generation', 'observedAt', 'observerId', 'evidenceHash', 'consumerId', 'revision', 'resourceId', 'handleId', 'accountId', 'parentResourceId', 'destinationId', 'storeVersion', 'reconcilesReceiptIds', 'limitationCodes'];
        if (Object.keys(receipt).some(k => !fields.includes(k)))
            throw new Error('Unexpected receipt payload');
        for (const key of ['receiptId', 'intentId', 'observerId', 'evidenceHash'] as const)
            metadataId(receipt[key]);
        for (const v of [receipt.consumerId, receipt.revision, receipt.resourceId, receipt.handleId, receipt.accountId, receipt.parentResourceId, receipt.destinationId, ...(receipt.reconcilesReceiptIds ?? []), ...receipt.limitationCodes])
            if (v !== undefined)
                metadataId(v);
        if (!['creation', 'validation', 'storage', 'delivery-accepted', 'direct-use', 'inferred-adoption', 'issuer-revocation', 'issuer-rejection', 'reconciliation', 'unknown', 'restart', 'quarantine', 'disable', 'sign-out', 'administration', 'containment'].includes(receipt.kind) || !['confirmed', 'rejected', 'unknown'].includes(receipt.outcome) || !Number.isSafeInteger(receipt.generation) || receipt.generation < 0 || !Number.isSafeInteger(receipt.observedAt) || receipt.observedAt < 0)
            throw new Error('Invalid receipt metadata');
        if (receipt.storeVersion !== undefined && (!Number.isSafeInteger(receipt.storeVersion) || receipt.storeVersion < 1))
            throw new Error('Invalid pinned store version');
        if (receipt.reconcilesReceiptIds !== undefined && (!Array.isArray(receipt.reconcilesReceiptIds) || new Set(receipt.reconcilesReceiptIds).size !== receipt.reconcilesReceiptIds.length))
            throw new Error('Invalid reconciliation receipt references');
        this.transaction(db => {
            db.prepare('INSERT INTO receipt VALUES(?,?,?)').run(receipt.receiptId, receipt.intentId, JSON.stringify(receipt));
            this.audit(db, 'receipt-appended', null, receipt.receiptId);
        });
    }
    /** Evidence append never resolves an effect. Only a complete, signed-subject-bound set may do so. */
    resolveIntent(input: {
        intentId: string;
        receiptIds: string[];
        reconciliationReceiptId?: string;
    }): void {
        this.transaction(db => {
            if (db.prepare('SELECT boot_id FROM controller WHERE singleton=1').get()?.boot_id !== this.bootId)
                throw new Error('Controller boot fenced');
            const intent = db.prepare('SELECT * FROM intent WHERE intent_id=?').get(input.intentId);
            if (!intent || intent.state === 'observed')
                throw new Error('Intent is missing or already resolved');
            const op = db.prepare('SELECT * FROM operation WHERE operation_id=?').get(String(intent.operation_id));
            const grant = db.prepare('SELECT raw_manifest FROM approval_grant WHERE grant_id=?').get(String(intent.grant_id));
            if (!op || !grant)
                throw new Error('Intent authority metadata missing');
            const manifest = parseCanonicalManifest(String(grant.raw_manifest));
            const operation = manifest.operations.find(o => o.operationId === intent.operation_id);
            const action = operation?.actions.find(a => a.id === intent.action_id);
            if (!operation || !action || action.kind !== intent.kind || canonicalJSON(action.parameters) !== String(intent.parameters))
                throw new Error('Intent does not match signed action');
            if (!input.receiptIds.length || new Set(input.receiptIds).size !== input.receiptIds.length)
                throw new Error('Complete distinct evidence references required');
            const history = db.prepare('SELECT rowid AS sequence,metadata FROM receipt WHERE intent_id=? ORDER BY rowid').all(input.intentId).map(row => ({ sequence: Number(row.sequence), receipt: JSON.parse(String(row.metadata)) as MetadataReceipt }));
            const selected = input.receiptIds.map(id => {
                const entry = history.find(h => h.receipt.receiptId === id);
                if (!entry)
                    throw new Error('Evidence belongs to another intent or is missing');
                return entry.receipt;
            });
            const generation = Number(action.parameters.generation ?? operation.toGeneration);
            const subject = (receipt: MetadataReceipt, expected: Record<string, string | number>) => {
                if (receipt.outcome !== 'confirmed' || receipt.accountId !== operation.accountId || receipt.generation !== generation)
                    throw new Error('Receipt outcome, account or generation mismatch');
                for (const [key, value] of Object.entries(expected))
                    if ((receipt as unknown as Record<string, unknown>)[key] !== value)
                        throw new Error('Receipt subject mismatch: ' + key);
            };
            const requireKind = (kind: ReceiptKind, expected: Record<string, string | number>) => {
                const candidates = selected.filter(r => r.kind === kind);
                if (!candidates.length)
                    throw new Error('Complete ' + kind + ' evidence required');
                for (const receipt of candidates)
                    subject(receipt, expected);
                return candidates[0]!;
            };
            let expected: Record<string, string | number> = {};
            let allowed: ReceiptKind[] = [];
            if (action.kind === 'create') {
                const created = requireKind('creation', { parentResourceId: String(action.parameters.resourceId) });
                if (!created.resourceId || created.resourceId.startsWith('created:'))
                    throw new Error('Concrete created issuer identity required');
                expected = { resourceId: created.resourceId };
                allowed = ['creation'];
                for (const receipt of selected.filter(r => r.kind === 'creation'))
                    subject(receipt, { ...expected, parentResourceId: String(action.parameters.resourceId) });
                if (action.budgetCost.effects >= 2) {
                    expected.handleId = String(action.parameters.handleId);
                    expected.destinationId = String(action.parameters.destinationId);
                    const stored = requireKind('storage', expected);
                    if (!Number.isSafeInteger(stored.storeVersion) || Number(stored.storeVersion) < 1)
                        throw new Error('Pinned storage version required');
                    expected.storeVersion = stored.storeVersion!;
                    allowed.push('storage');
                    for (const receipt of selected.filter(r => r.kind === 'storage'))
                        subject(receipt, expected);
                }
            }
            else {
                for (const [parameter, field] of [['resourceId', 'resourceId'], ['consumerId', 'consumerId'], ['handleId', 'handleId'], ['destinationId', 'destinationId'], ['expectedRevision', 'revision']] as const) {
                    const value = action.parameters[parameter];
                    if (value !== undefined)
                        expected[field] = value;
                }
                if (typeof expected.resourceId === 'string' && expected.resourceId.startsWith('created:')) {
                    if (expected.resourceId !== 'created:' + operation.operationId)
                        throw new Error('Created reference belongs to another operation');
                    const creations = db.prepare("SELECT r.metadata FROM receipt r JOIN intent i ON i.intent_id=r.intent_id WHERE i.operation_id=? AND i.kind='create' AND i.state='observed'").all(operation.operationId).map(row => JSON.parse(String(row.metadata)) as MetadataReceipt).filter(r => r.kind === 'creation' && r.outcome === 'confirmed' && r.accountId === operation.accountId && r.generation === generation);
                    const ids = new Set(creations.map(r => r.resourceId).filter((id): id is string => Boolean(id)));
                    if (ids.size !== 1)
                        throw new Error('Created issuer reference is not durably resolved');
                    expected.resourceId = [...ids][0]!;
                }
                const kinds: Record<string, ReceiptKind> = { validate: 'validation', store: 'storage', deliver: 'delivery-accepted', restart: 'restart', revoke: 'issuer-revocation', cleanup: 'issuer-revocation', quarantine: 'quarantine', disable: 'disable', 'sign-out': 'sign-out', admin: 'administration', 'emergency-contain': 'containment' };
                const kind = kinds[action.kind];
                if (!kind)
                    throw new Error('Action resolution unsupported');
                const receipt = requireKind(kind, expected);
                allowed = [kind];
                if (kind === 'storage') {
                    if (!Number.isSafeInteger(receipt.storeVersion) || Number(receipt.storeVersion) < 1)
                        throw new Error('Pinned storage version required');
                    expected.storeVersion = receipt.storeVersion!;
                    for (const stored of selected.filter(r => r.kind === 'storage'))
                        subject(stored, expected);
                }
            }
            if (selected.some(r => !allowed.includes(r.kind)))
                throw new Error('Receipt kind does not resolve this action');
            const unknowns = history.filter(h => h.receipt.outcome === 'unknown');
            if (intent.state === 'unknown' || unknowns.length || input.reconciliationReceiptId) {
                const marker = history.find(h => h.receipt.receiptId === input.reconciliationReceiptId);
                if (!marker || marker.receipt.kind !== 'reconciliation' || !Array.isArray(marker.receipt.reconcilesReceiptIds))
                    throw new Error('Explicit complete reconciliation required');
                subject(marker.receipt, expected);
                if (unknowns.some(h => !marker.receipt.reconcilesReceiptIds!.includes(h.receipt.receiptId) || h.sequence >= marker.sequence) || marker.receipt.reconcilesReceiptIds.some(id => !unknowns.some(h => h.receipt.receiptId === id)) || selected.some(r => r.observedAt > marker.receipt.observedAt || history.find(h => h.receipt.receiptId === r.receiptId)!.sequence >= marker.sequence))
                    throw new Error('Reconciliation does not cover historical uncertainty');
            }
            db.prepare("UPDATE intent SET state='observed' WHERE intent_id=?").run(input.intentId);
            this.audit(db, 'intent-explicitly-resolved', String(intent.operation_id), input.reconciliationReceiptId ?? input.receiptIds[0]!);
        });
    }
    listReceipts(operationId: string): MetadataReceipt[] {
        return this.read(db => db.prepare('SELECT r.metadata FROM receipt r JOIN intent i ON i.intent_id=r.intent_id WHERE i.operation_id=? ORDER BY r.rowid').all(operationId).map(r => deepFreeze(JSON.parse(String(r.metadata)) as MetadataReceipt)));
    }
    /** Called only by the owning reconciler after actual issuer observations; evidence cannot erase unknown intents. */
    reconcileOperation(operationId: string): void {
        this.transaction(db => {
            this.assertCurrent(db);
            const unresolved = db.prepare("SELECT 1 FROM intent WHERE operation_id=? AND state!='observed'").get(operationId);
            if (unresolved)
                throw new Error('In-flight effects require reconciliation receipts');
            const op = db.prepare('SELECT * FROM operation WHERE operation_id=?').get(operationId);
            if (!op || op.state === 'completed')
                throw new Error('Operation not reconcilable');
            db.prepare("UPDATE operation SET state='active',boot_id=? WHERE operation_id=?").run(this.bootId, operationId);
            this.audit(db, 'operation-reconciled', operationId, operationId);
        });
    }
    completeOperation(operationId: string): void {
        this.transaction(db => {
            this.assertCurrent(db);
            if (db.prepare("SELECT 1 FROM intent WHERE operation_id=? AND state!='observed'").get(operationId))
                throw new Error('Cannot forget ambiguous effect');
            const row = db.prepare('SELECT * FROM operation WHERE operation_id=?').get(operationId);
            if (!row || row.state !== 'active')
                throw new Error('Operation not active');
            db.prepare("UPDATE operation SET state='completed' WHERE operation_id=?").run(operationId);
            db.prepare('DELETE FROM lineage_lock WHERE operation_id=?').run(operationId);
            this.audit(db, 'operation-completed', operationId, operationId);
        });
    }
    setRecoveryHold(): void {
        this.transaction(db => {
            db.exec("UPDATE controller SET recovery_hold=1; UPDATE approval_grant SET cancelled=1; UPDATE session_revocation SET revoked=1; UPDATE operation SET state='reconcile-required' WHERE state!='completed'; UPDATE intent SET state='unknown' WHERE state='pending';");
            this.audit(db, 'recovery-held', null, this.bootId);
        });
    }
    /** Epoch recovery coordinator calls only after external predecessor and issuer reconciliation. */
    releaseRecoveryHold(): void {
        this.transaction(db => {
            if (db.prepare("SELECT 1 FROM intent WHERE state!='observed'").get())
                throw new Error('Unreconciled external effects');
            db.exec('UPDATE controller SET recovery_hold=0');
            this.audit(db, 'recovery-released', null, this.bootId);
        });
    }
    registerSession(sessionId: string): void {
        metadataId(sessionId);
        this.transaction(db => {
            this.assertCurrent(db);
            db.prepare('INSERT INTO session_revocation VALUES(?,?,0)').run(sessionId, this.bootId);
        });
    }
    sessionActive(sessionId: string): boolean {
        return this.read(db => Boolean(db.prepare('SELECT 1 FROM session_revocation WHERE session_id=? AND boot_id=? AND revoked=0').get(sessionId, this.bootId)));
    }
    revokeSession(sessionId: string): void {
        this.transaction(db => {
            db.prepare('UPDATE session_revocation SET revoked=1 WHERE session_id=?').run(sessionId);
        });
    }
    static idempotencyRef(operationId: string, actionId: string): string {
        return 'kr-' + createHash('sha256').update(JSON.stringify([operationId, actionId])).digest('hex');
    }
    close(): void {
        this.db.close();
    }
}
export interface RegisteredApprover {
    signerId: string;
    role: SignerRole;
    publicKey: JsonWebKey;
}
