import { randomBytes, randomUUID } from 'node:crypto';
import { verifyAuthenticationResponse, type AuthenticationResponseJSON } from '@simplewebauthn/server';
import { isoCBOR, decodeClientDataJSON } from '@simplewebauthn/server/helpers';
import { ApprovalService, publicKeyFingerprint, type LocalBootstrapContext } from './approval.js';
import { Journal } from './journal.js';
import { contentDigest, parseCanonicalManifest } from './manifest.js';
interface ChallengeRow {
    challenge_id: string;
    signer_id: string;
    grant_id: string;
    digest: string;
    operation_id: string;
    action_id: string;
    challenge: string;
    expires_at: number;
    used: number;
}
interface CredentialRow {
    credential_id: string;
    public_key: string;
    counter: number;
    rp_id: string;
    origin: string;
}
export interface EmergencyEnrollment {
    signerId: string;
    credentialId: string;
    cosePublicKey: Uint8Array;
    rpId: string;
    origin: string;
}
function enrollmentPublicKey(input: EmergencyEnrollment): JsonWebKey {
    const origin = new URL(input.origin);
    if (origin.protocol !== 'https:' || origin.origin !== input.origin || !(origin.hostname === input.rpId || origin.hostname.endsWith('.' + input.rpId)))
        throw new Error('Invalid emergency RP/origin');
    if (!/^[-a-zA-Z0-9_]+$/.test(input.credentialId) || !/^[-a-zA-Z0-9_.:]+$/.test(input.signerId))
        throw new Error('Invalid emergency credential metadata');
    const cose = isoCBOR.decodeFirst<Map<number, unknown>>(new Uint8Array(input.cosePublicKey));
    const x = cose.get(-2);
    const y = cose.get(-3);
    if (cose.get(1) !== 2 || cose.get(3) !== -7 || cose.get(-1) !== 1 || !(x instanceof Uint8Array) || !(y instanceof Uint8Array) || x.length !== 32 || y.length !== 32)
        throw new Error('Emergency key must be P-256 ES256');
    return { kty: 'EC', crv: 'P-256', x: Buffer.from(x).toString('base64url'), y: Buffer.from(y).toString('base64url') };
}
/** Bind every enrollment field to the phone-authorized admin action. */
export function emergencyEnrollmentFingerprint(input: EmergencyEnrollment): string {
    return contentDigest({ signerId: input.signerId, credentialId: input.credentialId, publicKeyFingerprint: publicKeyFingerprint(enrollmentPublicKey(input)), rpId: input.rpId, origin: input.origin });
}
/** Maintained verifier, no caller-writable `verified` flag. All inputs and outputs are credential metadata. */
export class EmergencyWebAuthn {
    constructor(readonly journal: Journal, private readonly options: {
        clock?: () => number;
    } = {}) {
    }
    bootstrapCredential(input: {
        signerId: string;
        credentialId: string;
        cosePublicKey: Uint8Array;
        rpId: string;
        origin: string;
        localBootstrap: LocalBootstrapContext;
        confirmedFingerprint: string;
    }): void {
        const jwk = enrollmentPublicKey(input);
        if (publicKeyFingerprint(jwk) !== input.confirmedFingerprint)
            throw new Error('Emergency fingerprint mismatch');
        this.journal.transaction(db => {
            new ApprovalService(this.journal, { mode: 'synthetic' }).bootstrapApproverInTransaction(db, { signerId: input.signerId, role: 'emergency', publicKey: jwk, localBootstrap: input.localBootstrap, confirmedFingerprint: input.confirmedFingerprint });
            db.prepare('INSERT INTO emergency_credential VALUES(?,?,?,?,?,?)').run(input.signerId, input.credentialId, Buffer.from(input.cosePublicKey).toString('base64url'), 0, input.rpId, input.origin);
            this.journal.audit(db, 'emergency-local-bootstrap', null, input.signerId);
        });
    }
    /** Add the emergency-only key after normal phone pairing, using one already-consumed signed admin intent. */
    enrollCredential(input: EmergencyEnrollment & {
        authorizationIntentId: string;
        now?: number;
        confirmedFingerprint: string;
    }): void {
        const jwk = enrollmentPublicKey(input);
        const fingerprint = publicKeyFingerprint(jwk);
        if (fingerprint !== input.confirmedFingerprint)
            throw new Error('Emergency fingerprint comparison required');
        const bound = emergencyEnrollmentFingerprint(input);
        this.journal.transaction(db => {
            this.journal.assertCurrent(db);
            const intent = db.prepare("SELECT * FROM intent WHERE intent_id=? AND kind='admin' AND state='pending'").get(input.authorizationIntentId);
            if (!intent)
                throw new Error('Phone-authorized enrollment intent required');
            const params = JSON.parse(String(intent.parameters)) as Record<string, unknown>;
            if (params.resourceId !== 'emergency-approver' || params.destinationId !== input.signerId || params.authorityFingerprint !== bound)
                throw new Error('Enrollment differs from signed admin action');
            const grant = db.prepare("SELECT * FROM approval_grant WHERE grant_id=? AND role='routine' AND cancelled=0").get(String(intent.grant_id));
            if (!grant || grant.boot_id !== this.journal.bootId)
                throw new Error('Phone enrollment authority expired or cancelled');
            const manifest = parseCanonicalManifest(String(grant.raw_manifest));
            const now = input.now ?? Date.now();
            if (now < manifest.notBefore || now >= manifest.expiresAt || !db.prepare("SELECT 1 FROM approver WHERE signer_id=? AND role='routine' AND revoked=0").get(manifest.signerId))
                throw new Error('Phone enrollment authority expired or revoked');
            db.prepare('INSERT INTO approver(signer_id,role,public_key,fingerprint) VALUES(?,?,?,?)').run(input.signerId, 'emergency', JSON.stringify(jwk), fingerprint);
            db.prepare('INSERT INTO emergency_credential VALUES(?,?,?,?,?,?)').run(input.signerId, input.credentialId, Buffer.from(input.cosePublicKey).toString('base64url'), 0, input.rpId, input.origin);
            const receipt = { receiptId: randomUUID(), intentId: input.authorizationIntentId, kind: 'validation', outcome: 'confirmed', generation: 0, observedAt: Date.now(), observerId: 'controller-enrollment', evidenceHash: bound, limitationCodes: ['physical-custody-unverified'] };
            db.prepare('INSERT INTO receipt VALUES(?,?,?)').run(receipt.receiptId, input.authorizationIntentId, JSON.stringify(receipt));
            db.prepare("UPDATE intent SET state='observed' WHERE intent_id=?").run(input.authorizationIntentId);
            this.journal.audit(db, 'emergency-key-enrolled', String(intent.operation_id), input.signerId);
        });
    }
    createChallenge(input: {
        grantId: string;
        operationId: string;
        actionId: string;
        now?: number;
    }): {
        challengeId: string;
        challenge: string;
        rpId: string;
        credentialId: string;
        expiresAt: number;
    } {
        const now = input.now ?? Date.now();
        return this.journal.transaction(db => {
            this.journal.assertCurrent(db);
            const grant = db.prepare("SELECT * FROM approval_grant WHERE grant_id=? AND role='emergency' AND cancelled=0").get(input.grantId);
            if (!grant)
                throw new Error('Emergency grant missing');
            const manifest = parseCanonicalManifest(String(grant.raw_manifest));
            if (now < manifest.notBefore || now >= manifest.expiresAt || manifest.bootId !== this.journal.bootId)
                throw new Error('Stale emergency grant');
            if (!manifest.operations.some(op => op.operationId === input.operationId && op.actions.some(a => a.id === input.actionId)))
                throw new Error('Emergency action outside manifest');
            const credential = db.prepare('SELECT c.* FROM emergency_credential c JOIN approver a ON a.signer_id=c.signer_id WHERE c.signer_id=? AND a.role=\'emergency\' AND a.revoked=0').get(manifest.signerId) as unknown as CredentialRow | undefined;
            if (!credential)
                throw new Error('Emergency credential missing');
            const challengeId = randomUUID();
            const challenge = Buffer.from(contentDigest({ domain: 'keyroot.emergency.webauthn.v1', digest: grant.digest, role: 'emergency', operationId: input.operationId, actionId: input.actionId, nonce: randomBytes(32).toString('base64url') })).toString('base64url');
            const expiresAt = Math.min(now + 60000, manifest.expiresAt);
            db.prepare('INSERT INTO emergency_challenge VALUES(?,?,?,?,?,?,?,?,0)').run(challengeId, manifest.signerId, input.grantId, String(grant.digest), input.operationId, input.actionId, challenge, expiresAt);
            return { challengeId, challenge, rpId: credential.rp_id, credentialId: credential.credential_id, expiresAt };
        });
    }
    async verifyAssertion(input: {
        challengeId: string;
        operationId: string;
        actionId: string;
        response: AuthenticationResponseJSON;
        now?: number;
    }): Promise<string> {
        const now = input.now ?? Date.now();
        const saved = this.journal.transaction(db => {
            this.journal.assertCurrent(db);
            const row = db.prepare('SELECT * FROM emergency_challenge WHERE challenge_id=? AND used=0').get(input.challengeId) as unknown as ChallengeRow | undefined;
            if (!row || now >= row.expires_at || row.operation_id !== input.operationId || row.action_id !== input.actionId)
                throw new Error('Stale emergency challenge');
            const grant = db.prepare("SELECT * FROM approval_grant WHERE grant_id=? AND cancelled=0 AND role='emergency'").get(row.grant_id);
            if (!grant || grant.boot_id !== this.journal.bootId || grant.digest !== row.digest)
                throw new Error('Emergency authority changed');
            const manifest = parseCanonicalManifest(String(grant.raw_manifest));
            if (now < manifest.notBefore || now >= manifest.expiresAt || !manifest.operations.some(op => op.operationId === input.operationId && op.actions.some(a => a.id === input.actionId)))
                throw new Error('Emergency action outside manifest');
            const credential = db.prepare('SELECT c.* FROM emergency_credential c JOIN approver a ON a.signer_id=c.signer_id WHERE c.signer_id=? AND a.revoked=0 AND a.role=\'emergency\'').get(row.signer_id) as unknown as CredentialRow | undefined;
            if (!credential)
                throw new Error('Unknown emergency credential');
            // Burn even a failed assertion attempt; do not allow concurrent verification to reuse it.
            db.prepare('UPDATE emergency_challenge SET used=1 WHERE challenge_id=?').run(input.challengeId);
            return { row, credential };
        });
        if (input.response.id !== saved.credential.credential_id || input.response.rawId !== saved.credential.credential_id)
            throw new Error('Emergency credential identity mismatch');
        if (decodeClientDataJSON(input.response.response.clientDataJSON).crossOrigin)
            throw new Error('Cross-origin emergency ceremony rejected');
        const result = await verifyAuthenticationResponse({ response: input.response, expectedChallenge: saved.row.challenge, expectedOrigin: saved.credential.origin, expectedRPID: saved.credential.rp_id, requireUserVerification: true, credential: { id: saved.credential.credential_id, publicKey: new Uint8Array(Buffer.from(saved.credential.public_key, 'base64url')), counter: saved.credential.counter } });
        if (!result.verified || !result.authenticationInfo.userVerified || result.authenticationInfo.credentialDeviceType !== 'singleDevice' || result.authenticationInfo.credentialBackedUp)
            throw new Error('Emergency assertion requires present, verified single-device credential');
        return this.journal.transaction(db => {
            this.journal.assertCurrent(db);
            const current = db.prepare("SELECT * FROM approval_grant WHERE grant_id=? AND cancelled=0 AND role='emergency'").get(saved.row.grant_id);
            const signer = db.prepare('SELECT 1 FROM approver WHERE signer_id=? AND revoked=0 AND role=\'emergency\'').get(saved.row.signer_id);
            if (!current || !signer || current.boot_id !== this.journal.bootId || current.digest !== saved.row.digest)
                throw new Error('Emergency authority revoked during verification');
            const manifest = parseCanonicalManifest(String(current.raw_manifest));
            const finalNow = this.options.clock?.() ?? Date.now();
            if (finalNow >= saved.row.expires_at || finalNow < manifest.notBefore || finalNow >= manifest.expiresAt)
                throw new Error('Emergency assertion expired during verification');
            for (const operation of manifest.operations)
                db.prepare('INSERT OR IGNORE INTO emergency_reservation(grant_id,lineage_id) VALUES(?,?)').run(saved.row.grant_id, operation.lineageId);
            for (const row of db.prepare("SELECT grant_id,raw_manifest FROM approval_grant WHERE role='routine' AND cancelled=0").all()) {
                if (parseCanonicalManifest(String(row.raw_manifest)).operations.some(op => manifest.operations.some(emergency => emergency.lineageId === op.lineageId)))
                    db.prepare('UPDATE approval_grant SET cancelled=1 WHERE grant_id=?').run(String(row.grant_id));
            }
            const updated = db.prepare('UPDATE emergency_credential SET counter=? WHERE signer_id=? AND counter=?').run(result.authenticationInfo.newCounter, saved.row.signer_id, saved.credential.counter);
            if (updated.changes !== 1)
                throw new Error('Emergency credential counter raced');
            const proofId = randomUUID();
            db.prepare('INSERT INTO emergency_proof VALUES(?,?,?,?,?,?,0)').run(proofId, saved.row.grant_id, saved.row.digest, input.operationId, input.actionId, Math.min(saved.row.expires_at, manifest.expiresAt, finalNow + 30000));
            this.journal.audit(db, 'emergency-assertion-verified', input.operationId, proofId);
            return proofId;
        });
    }
}
