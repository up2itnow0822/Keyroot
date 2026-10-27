import { randomUUID } from 'node:crypto';
import { generateRegistrationOptions, verifyRegistrationResponse, type RegistrationResponseJSON } from '@simplewebauthn/server';
import { decodeClientDataJSON, isoCBOR } from '@simplewebauthn/server/helpers';
import { emergencyEnrollmentFingerprint, type EmergencyEnrollment } from '../../../../packages/core/src/emergency-webauthn.js';
import { publicKeyFingerprint } from '../../../../packages/core/src/approval.js';
import { contentDigest } from '../../../../packages/core/src/manifest.js';
import { exactObject, HttpFailure, identifier } from '../auth.js';
interface Pending { signerId: string; challenge: string; expiresAt: number; state: 'creating' | 'pending' | 'verifying' | 'verified'; verified?: EmergencyEnrollment; publicFingerprint?: string }
/** Maintained registration verification precedes a separate routine-phone signed enrollment intent. */
export class EmergencyEnrollmentController {
  private readonly pending = new Map<string, Pending>();
  constructor(private readonly origin: string, private readonly clock: () => number = Date.now) {}
  async challenge(input: unknown) {
    const body = exactObject(input, ['signerId']); const signerId = identifier(body.signerId);
    const origin = new URL(this.origin); if (origin.protocol !== 'https:') throw new HttpFailure(503, 'secure_emergency_origin_required');
    for (const [id, p] of this.pending) if (p.expiresAt <= this.clock()) this.pending.delete(id);
    if (this.pending.size >= 8) throw new HttpFailure(429, 'enrollment_limit');
    // Occupancy covers creation, verification and verified-but-unconsumed records.
    const requestId = randomUUID(); const pending: Pending = { signerId, challenge: '', expiresAt: this.clock() + 60000, state: 'creating' }; this.pending.set(requestId, pending);
    try {
      const options = await generateRegistrationOptions({ rpName: 'Keyroot emergency key', rpID: origin.hostname, userName: signerId, userID: new TextEncoder().encode(signerId), timeout: 60000, attestationType: 'none', authenticatorSelection: { authenticatorAttachment: 'cross-platform', residentKey: 'discouraged', userVerification: 'required' }, supportedAlgorithmIDs: [-7], preferredAuthenticatorType: 'securityKey' });
      if (this.pending.get(requestId) !== pending || pending.expiresAt <= this.clock()) throw new HttpFailure(409, 'enrollment_challenge_expired');
      pending.challenge = options.challenge; pending.state = 'pending'; return { requestId, expiresAt: pending.expiresAt, options };
    } catch (error) { if (this.pending.get(requestId) === pending) this.pending.delete(requestId); throw error; }
  }
  async verify(input: unknown) {
    const body = exactObject(input, ['requestId', 'response']); const requestId = identifier(body.requestId); const pending = this.pending.get(requestId);
    if (!pending || pending.expiresAt <= this.clock() || pending.state !== 'pending') throw new HttpFailure(409, 'enrollment_challenge_expired');
    // Burn this attempt synchronously without releasing its capacity during maintained verification.
    pending.state = 'verifying';
    try {
      const response = body.response as RegistrationResponseJSON;
      if (decodeClientDataJSON(response.response.clientDataJSON).crossOrigin) throw new HttpFailure(403, 'cross_origin_ceremony_denied');
      const result = await verifyRegistrationResponse({ response, expectedChallenge: pending.challenge, expectedOrigin: this.origin, expectedRPID: new URL(this.origin).hostname, requireUserVerification: true, supportedAlgorithmIDs: [-7] });
      if (!result.verified || !result.registrationInfo.userVerified || result.registrationInfo.credentialDeviceType !== 'singleDevice' || result.registrationInfo.credentialBackedUp) throw new HttpFailure(403, 'single_device_emergency_key_required');
      if (this.pending.get(requestId) !== pending || pending.expiresAt <= this.clock()) throw new HttpFailure(409, 'enrollment_challenge_expired');
      const info = result.registrationInfo; const enrollment: EmergencyEnrollment = { signerId: pending.signerId, credentialId: info.credential.id, cosePublicKey: info.credential.publicKey, rpId: new URL(this.origin).hostname, origin: this.origin };
      const cose = isoCBOR.decodeFirst<Map<number, unknown>>(info.credential.publicKey); const x = cose.get(-2); const y = cose.get(-3);
      if (!(x instanceof Uint8Array) || !(y instanceof Uint8Array)) throw new HttpFailure(403, 'invalid_emergency_key');
      const publicFingerprint = publicKeyFingerprint({ kty: 'EC', crv: 'P-256', x: Buffer.from(x).toString('base64url'), y: Buffer.from(y).toString('base64url') });
      pending.verified = enrollment; pending.publicFingerprint = publicFingerprint; pending.expiresAt = this.clock() + 300000; pending.state = 'verified';
      return { requestId, fingerprint: publicFingerprint, enrollmentFingerprint: emergencyEnrollmentFingerprint(enrollment), expiresAt: pending.expiresAt, limitation: 'hardware-provenance-and-physical-custody-unverified' };
    } catch (error) { if (this.pending.get(requestId) === pending) this.pending.delete(requestId); throw error; }
  }
  metadata(requestId: string) { const pending = this.pending.get(requestId); if (!pending || pending.expiresAt <= this.clock()) throw new HttpFailure(404, 'registration_not_found'); return { requestId, signerId: pending.signerId, fingerprint: pending.publicFingerprint ?? null, status: pending.verified ? 'verified' : 'pending', expiresAt: pending.expiresAt }; }
  descriptor(requestId: string) {
    const pending = this.pending.get(requestId); if (pending?.state !== 'verified' || !pending.verified || pending.expiresAt <= this.clock()) throw new HttpFailure(409, 'verified_registration_required');
    const e = pending.verified;
    return { purpose: 'emergency-enrollment', requestId, signerId: e.signerId, credentialId: e.credentialId, rpId: e.rpId, origin: e.origin, enrollmentFingerprint: emergencyEnrollmentFingerprint(e), publicFingerprint: pending.publicFingerprint!, registrationEvidenceHash: contentDigest({ requestId, credentialId: e.credentialId, challenge: pending.challenge }) };
  }
  consume(requestId: string): EmergencyEnrollment & { confirmedFingerprint: string } {
    this.descriptor(requestId); const pending = this.pending.get(requestId)!; this.pending.delete(requestId); return { ...pending.verified!, confirmedFingerprint: pending.publicFingerprint! };
  }
}
