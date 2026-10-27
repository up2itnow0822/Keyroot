import { canonicalJSON } from './manifest.js';
import { base64url, bytes, fingerprint, signBytes, verifyDescriptor, manifestDigest, validateReview, parseManifest, contentHash } from './signing.js';

// Deployment replaces these constants as part of a reviewed immutable bundle, never through UI input.
export const TRUST = Object.freeze({ controllerOrigin: 'http://127.0.0.1:9047', phoneOrigin: 'http://localhost:4173', pin: '', reviewedBundle: false, demo: true });
interface Identity { installationId: string; bootId: string; publicKey: JsonWebKey; fingerprint: string; mode: string }
export interface OperationProgress { operationId: string; state: string; actions: Array<{ actionId: string; kind: string; state: 'not-started' | 'pending' | 'observed' | 'unknown' }>; nextActionId: string | null; dispatchComplete: boolean; outcome: null | { issuer: string; probe: string; replacement: string; holds: string[] } }
export interface Batch { batchId: string; rawManifest: string; digest: string; configurationHashes: string[]; emergencyRegistration?: { grantId: string; digest: string } | null; progress?: OperationProgress[] }
interface Envelope { payload: { requestNonce: string; method: string; path: string; installationId: string; expiresAt: number; data: unknown }; signature: string }
function decode(value: string): Uint8Array<ArrayBuffer> {
  if (!/^[A-Za-z0-9_-]+$/.test(value)) throw new Error('Invalid signature');
  const binary = atob(value.replace(/-/g, '+').replace(/_/g, '/').padEnd(Math.ceil(value.length / 4) * 4, '='));
  return Uint8Array.from(binary, c => c.charCodeAt(0));
}
async function json(path: string, init?: RequestInit): Promise<unknown> {
  const response = await fetch(TRUST.controllerOrigin + path, { ...init, credentials: 'omit', headers: { 'Content-Type': 'application/json', ...init?.headers } });
  if (!response.ok) throw new Error(`Controller request failed (${response.status}). Check pairing and try again.`);
  return response.json() as Promise<unknown>;
}
export async function identity(): Promise<{ data: Identity; key: CryptoKey }> {
  const origin = new URL(location.origin);
  const controllerOrigin = new URL(TRUST.controllerOrigin);
  if (TRUST.demo) {
    if (!['localhost', '127.0.0.1'].includes(origin.hostname) || !['localhost', '127.0.0.1'].includes(controllerOrigin.hostname)) throw new Error('Demo requires loopback origins');
  } else if (origin.origin !== TRUST.phoneOrigin || origin.protocol !== 'https:' || controllerOrigin.protocol !== 'https:' || origin.origin === controllerOrigin.origin || !TRUST.reviewedBundle || !TRUST.pin) throw new Error('Independent HTTPS origin, reviewed bundle, and controller pin required');
  const data = await json('/api/identity') as Identity;
  const key = await crypto.subtle.importKey('jwk', data.publicKey, { name: 'ECDSA', namedCurve: 'P-256' }, true, ['verify']);
  const actual = await fingerprint(key);
  if (actual !== data.fingerprint || (!TRUST.demo && actual !== TRUST.pin)) throw new Error('Controller identity does not match the installed pin');
  if (TRUST.demo && data.mode !== 'demo') throw new Error('The preview only connects to a demo controller');
  return { data, key };
}
export async function requestPairing(signerId: string, key: CryptoKeyPair, controller: Awaited<ReturnType<typeof identity>>) {
  const publicKey = await crypto.subtle.exportKey('jwk', key.publicKey);
  const expectedFingerprint = await fingerprint(key.publicKey);
  const result = await json('/api/pairing/requests', { method: 'POST', body: JSON.stringify({ signerId, publicKey, role: 'routine' }) }) as { requestId: string; fingerprint: string; expiresAt: number; challenge: { requestId: string; nonce: string; installationId: string; signerId: string; fingerprint: string; expiresAt: number } };
  const challenge = result.challenge;
  if (!challenge || challenge.requestId !== result.requestId || challenge.fingerprint !== expectedFingerprint || result.fingerprint !== expectedFingerprint || challenge.installationId !== controller.data.installationId || challenge.signerId !== signerId || challenge.expiresAt !== result.expiresAt || challenge.expiresAt <= Date.now() || !/^[A-Za-z0-9_-]+$/.test(challenge.nonce)) throw new Error('Pairing challenge does not match this phone and controller');
  const signature = await signBytes(key.privateKey, bytes('keyroot.pairing-possession.v1\0' + canonicalJSON(challenge)));
  if (challenge.expiresAt <= Date.now()) throw new Error('Pairing challenge expired; request again');
  const proof = await json('/api/pairing/requests/' + encodeURIComponent(result.requestId) + '/proof', { method: 'POST', body: JSON.stringify({ signature }) }) as { status: string };
  if (proof.status !== 'proved') throw new Error('Pairing proof was not accepted');
  return result;
}
export async function pairingStatus(requestId: string) {
  return json('/api/pairing/requests/' + encodeURIComponent(requestId)) as Promise<{ status: string }>;
}
export async function read(path: string, signerId: string, key: CryptoKeyPair, controller: Awaited<ReturnType<typeof identity>>): Promise<unknown> {
  const challenge = await json('/api/phone/challenge', { method: 'POST', body: JSON.stringify({ signerId, method: 'GET', path }) }) as { nonce: string; installationId: string; signerId: string; method: string; path: string; expiresAt: number };
  if (challenge.installationId !== controller.data.installationId || challenge.signerId !== signerId || challenge.method !== 'GET' || challenge.path !== path || challenge.expiresAt <= Date.now()) throw new Error('Invalid read challenge');
  const signature = await signBytes(key.privateKey, bytes('keyroot.phone-read.v1\0' + canonicalJSON(challenge)));
  const envelope = await json(path, { headers: { 'X-Keyroot-Nonce': challenge.nonce, 'X-Keyroot-Signature': signature } }) as Envelope;
  const payload = envelope.payload;
  if (payload.requestNonce !== challenge.nonce || payload.method !== 'GET' || payload.path !== path || payload.installationId !== controller.data.installationId || payload.expiresAt !== challenge.expiresAt || challenge.expiresAt <= Date.now()) throw new Error('Controller response does not match request');
  const valid = await crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, controller.key, decode(envelope.signature), bytes('keyroot.controller-response.v1\0' + canonicalJSON(payload)));
  if (!valid) throw new Error('Controller response signature invalid');
  return payload.data;
}
export async function loadReview(batch: Batch, signerId: string, key: CryptoKeyPair, controller: Awaited<ReturnType<typeof identity>>) {
  const manifest = await validateReview(batch.rawManifest, { origin: location.origin, controllerOrigin: TRUST.controllerOrigin, pinnedFingerprint: TRUST.pin, actualFingerprint: controller.data.fingerprint, reviewedBundle: TRUST.reviewedBundle, demo: TRUST.demo, expectedDigest: batch.digest, now: Date.now() });
  if (manifest.installationId !== controller.data.installationId || manifest.bootId !== controller.data.bootId || (manifest.role === 'routine' && manifest.signerId !== signerId)) throw new Error('Approval belongs to another controller, boot, or signer');
  const hashes = [...new Set(manifest.operations.flatMap(op => op.actions.flatMap(a => [a.parameters.configurationHash, a.parameters.incidentPlanHash]).filter((v): v is string => !!v)))];
  if (canonicalJSON([...hashes].sort()) !== canonicalJSON([...batch.configurationHashes].sort())) throw new Error('Configuration list does not match the signed actions');
  const descriptors: Record<string, unknown> = {};
  for (const hash of hashes) {
    const item = await read('/api/configurations/' + hash, signerId, key, controller) as { hash: string; descriptor: unknown };
    if (item.hash !== hash) throw new Error('Configuration address mismatch');
    await verifyDescriptor(hash, item.descriptor); descriptors[hash] = item.descriptor;
  }
  return { manifest, descriptors };
}
export async function approve(batch: Batch, signerId: string, key: CryptoKeyPair, controller: Awaited<ReturnType<typeof identity>>) {
  const current = await read('/api/batches/' + encodeURIComponent(batch.batchId), signerId, key, controller) as Batch;
  if (current.rawManifest !== batch.rawManifest || current.digest !== batch.digest || await manifestDigest(current.rawManifest) !== batch.digest) throw new Error('Approval changed. Review the new version.');
  const review = await loadReview(current, signerId, key, controller);
  if (review.manifest.role === 'emergency') return json('/api/approvals', { method: 'POST', body: JSON.stringify({ batchId: batch.batchId, rawManifest: batch.rawManifest }) });
  const signature = await signBytes(key.privateKey, bytes(batch.rawManifest));
  return json('/api/approvals', { method: 'POST', body: JSON.stringify({ batchId: batch.batchId, rawManifest: batch.rawManifest, signature }) });
}
export { base64url };

export async function emergencyProof(batch: Batch, grantId: string, operationId: string, actionId: string): Promise<{ id: string; expiresAt: number }> {
  const manifest = await parseManifest(batch.rawManifest);
  const digest = await manifestDigest(batch.rawManifest);
  if (digest !== batch.digest || manifest.role !== 'emergency' || manifest.nonce !== grantId || Date.now() < manifest.notBefore || Date.now() >= manifest.expiresAt || !manifest.operations.some(op => op.operationId === operationId && op.actions.some(action => action.id === actionId))) throw new Error('Emergency action is outside the reviewed scope');
  const challenge = await json('/api/emergency/challenge', { method: 'POST', body: JSON.stringify({ grantId, operationId, actionId }) }) as { challengeId: string; challenge: string; rpId: string; credentialId: string; expiresAt: number; binding: unknown };
  const binding = challenge.binding;
  if (!binding || typeof binding !== 'object' || Array.isArray(binding)) throw new Error('Emergency challenge binding is invalid');
  const item = binding as Record<string, unknown>;
  if (canonicalJSON(Object.keys(item).sort()) !== canonicalJSON(['actionId', 'digest', 'domain', 'nonce', 'operationId', 'role']) || item.domain !== 'keyroot.emergency.webauthn.v1' || item.role !== 'emergency' || item.digest !== digest || item.operationId !== operationId || item.actionId !== actionId || typeof item.nonce !== 'string') throw new Error('Emergency challenge does not match the reviewed action');
  const nonce = decode(item.nonce);
  if (nonce.length !== 32 || base64url(nonce) !== item.nonce || challenge.challenge !== base64url(bytes(await contentHash(item)))) throw new Error('Emergency challenge preimage is invalid');
  if (!challenge.challengeId || typeof challenge.rpId !== 'string' || !challenge.rpId || !Number.isSafeInteger(challenge.expiresAt) || challenge.expiresAt <= Date.now() || challenge.expiresAt > manifest.expiresAt) throw new Error('Emergency challenge expired or invalid');
  const credential = await navigator.credentials.get({ publicKey: { challenge: decode(challenge.challenge), rpId: challenge.rpId, allowCredentials: [{ type: 'public-key', id: decode(challenge.credentialId) }], userVerification: 'required', timeout: Math.min(60000, challenge.expiresAt - Date.now()) } }) as PublicKeyCredential | null;
  if (!credential || !(credential.response instanceof AuthenticatorAssertionResponse)) throw new Error('Security key approval was cancelled');
  if (Date.now() >= challenge.expiresAt) throw new Error('Security key challenge expired; try again');
  const assertion = credential.response;
  const response = { id: credential.id, rawId: base64url(new Uint8Array(credential.rawId)), type: credential.type, authenticatorAttachment: credential.authenticatorAttachment ?? undefined, clientExtensionResults: credential.getClientExtensionResults(), response: { authenticatorData: base64url(new Uint8Array(assertion.authenticatorData)), clientDataJSON: base64url(new Uint8Array(assertion.clientDataJSON)), signature: base64url(new Uint8Array(assertion.signature)), userHandle: assertion.userHandle ? base64url(new Uint8Array(assertion.userHandle)) : undefined } };
  const result = await json('/api/emergency/assertion', { method: 'POST', body: JSON.stringify({ challengeId: challenge.challengeId, operationId, actionId, response }) }) as { proofId: string };
  if (!result.proofId) throw new Error('Security key proof was not accepted');
  return { id: result.proofId, expiresAt: Math.min(challenge.expiresAt, Date.now() + 29000) };
}

export function validateProgress(manifest: import('./manifest.js').ApprovalManifest, progress: OperationProgress[] | undefined): OperationProgress[] {
  if (!Array.isArray(progress) || progress.length !== manifest.operations.length) throw new Error('Incomplete incident progress; reconcile before continuing');
  return manifest.operations.map(operation => {
    const matches = progress.filter(item => item.operationId === operation.operationId);
    const item = matches[0];
    if (matches.length !== 1 || !item || !Array.isArray(item.actions) || item.actions.length !== operation.actions.length) throw new Error('Incident progress does not match the reviewed scope');
    for (let i = 0; i < operation.actions.length; i++) {
      const action = operation.actions[i]!; const state = item.actions[i];
      if (!state || state.actionId !== action.id || state.kind !== action.kind || !['not-started', 'pending', 'observed', 'unknown'].includes(state.state)) throw new Error('Incident action progress is invalid');
    }
    if (typeof item.state !== 'string' || (item.outcome !== null && (!item.outcome || typeof item.outcome.issuer !== 'string' || typeof item.outcome.probe !== 'string' || typeof item.outcome.replacement !== 'string' || !Array.isArray(item.outcome.holds) || item.outcome.holds.some(hold => typeof hold !== 'string')))) throw new Error('Incident outcome is invalid');
    if (item.actions.some((action, index) => action.state === 'observed' && item.actions.slice(0, index).some(prior => prior.state !== 'observed'))) throw new Error('Incident action order is inconsistent');
    const next = item.actions.find((action, index) => action.state === 'not-started' && item.actions.slice(0, index).every(prior => prior.state === 'observed'));
    if (item.nextActionId !== (next?.actionId ?? null) || item.dispatchComplete !== item.actions.every(action => action.state === 'observed')) throw new Error('Incident progress is inconsistent');
    return item;
  });
}
export function nextEmergencyAction(progress: OperationProgress[]): { operationId: string; actionId: string } | null {
  if (progress.some(item => item.outcome?.holds.length || item.actions.some(action => action.state === 'pending' || action.state === 'unknown'))) return null;
  const item = progress.find(row => row.nextActionId !== null);
  return item?.nextActionId ? { operationId: item.operationId, actionId: item.nextActionId } : null;
}
export async function registeredEmergency(batch: Batch, manifest: import('./manifest.js').ApprovalManifest): Promise<string | null> {
  const registration = batch.emergencyRegistration;
  if (registration === null || registration === undefined) return null;
  if (!registration || typeof registration !== 'object' || typeof registration.grantId !== 'string' || typeof registration.digest !== 'string' || manifest.role !== 'emergency' || manifest.nonce !== registration.grantId || batch.batchId !== registration.grantId || batch.digest !== registration.digest || await manifestDigest(batch.rawManifest) !== registration.digest || Date.now() < manifest.notBefore || Date.now() >= manifest.expiresAt) throw new Error('Registered emergency scope does not match the reviewed manifest');
  return registration.grantId;
}
export async function refreshEmergency(batch: Batch, signerId: string, key: CryptoKeyPair, controller: Awaited<ReturnType<typeof identity>>) {
  const current = await read('/api/batches/' + encodeURIComponent(batch.batchId), signerId, key, controller) as Batch;
  if (current.batchId !== batch.batchId || current.rawManifest !== batch.rawManifest || current.digest !== batch.digest) throw new Error('Emergency scope changed. Review it again.');
  const review = await loadReview(current, signerId, key, controller);
  if (review.manifest.role !== 'emergency' || !await registeredEmergency(current, review.manifest)) throw new Error('Active registered emergency scope required');
  return validateProgress(review.manifest, current.progress);
}
const submittedProofs = new Map<string, number>();
export async function executeEmergency(batch: Batch, signerId: string, key: CryptoKeyPair, controller: Awaited<ReturnType<typeof identity>>, target: { operationId: string; actionId: string }, proof: { id: string; expiresAt: number }) {
  const progress = await refreshEmergency(batch, signerId, key, controller);
  const next = nextEmergencyAction(progress);
  if (!next || next.operationId !== target.operationId || next.actionId !== target.actionId) throw new Error('Incident progress changed or needs reconciliation');
  if (proof.expiresAt <= Date.now()) throw new Error('Fresh security key proof required');
  for (const [id, expiry] of submittedProofs) if (expiry <= Date.now()) submittedProofs.delete(id);
  if (submittedProofs.has(proof.id)) throw new Error('A security key proof cannot be reused');
  submittedProofs.set(proof.id, proof.expiresAt);
  return json('/api/emergency/execute', { method: 'POST', body: JSON.stringify({ grantId: JSON.parse(batch.rawManifest).nonce, proofs: { [target.operationId]: { [target.actionId]: proof.id } } }) });
}

interface RegistrationOptionsJSON extends Omit<PublicKeyCredentialCreationOptions, 'challenge' | 'user' | 'excludeCredentials'> {
  challenge: string;
  user: Omit<PublicKeyCredentialUserEntity, 'id'> & { id: string };
  excludeCredentials?: Array<Omit<PublicKeyCredentialDescriptor, 'id'> & { id: string }>;
}
export async function registerEmergencyKey(signerId: string) {
  const result = await json('/api/emergency/enrollment/challenge', { method: 'POST', body: JSON.stringify({ signerId }) }) as { requestId: string; expiresAt: number; options: RegistrationOptionsJSON };
  if (result.expiresAt <= Date.now()) throw new Error('Enrollment challenge expired');
  const options = result.options;
  const { challenge, user, excludeCredentials, ...rest } = options;
  const publicKey: PublicKeyCredentialCreationOptions = { ...rest, challenge: decode(challenge), user: { ...user, id: decode(user.id) }, ...(excludeCredentials ? { excludeCredentials: excludeCredentials.map(item => ({ ...item, id: decode(item.id) })) } : {}) };
  const credential = await navigator.credentials.create({ publicKey }) as PublicKeyCredential | null;
  if (!credential || !(credential.response instanceof AuthenticatorAttestationResponse)) throw new Error('Security key registration was cancelled');
  if (result.expiresAt <= Date.now()) throw new Error('Registration challenge expired; try again');
  const attestation = credential.response;
  const response = { id: credential.id, rawId: base64url(new Uint8Array(credential.rawId)), type: credential.type, authenticatorAttachment: credential.authenticatorAttachment ?? undefined, clientExtensionResults: credential.getClientExtensionResults(), response: { attestationObject: base64url(new Uint8Array(attestation.attestationObject)), clientDataJSON: base64url(new Uint8Array(attestation.clientDataJSON)), transports: attestation.getTransports() } };
  const verified = await json('/api/emergency/enrollment/verify', { method: 'POST', body: JSON.stringify({ requestId: result.requestId, response }) }) as { requestId: string; fingerprint: string; enrollmentFingerprint: string; expiresAt: number; limitation: string };
  if (verified.requestId !== result.requestId || verified.expiresAt <= Date.now()) throw new Error('Verified registration did not match the request');
  return verified;
}
