import { canonicalJSON, validateManifest, type ApprovalManifest } from './manifest.js';

const encoder = new TextEncoder();
export const base64url = (bytes: Uint8Array): string => {
  let binary = ''; for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
};
export const bytes = (value: string): Uint8Array<ArrayBuffer> => encoder.encode(value);
export async function sha256(data: Uint8Array<ArrayBuffer>, crypto: Crypto = globalThis.crypto): Promise<string> {
  const hash = await crypto.subtle.digest('SHA-256', data);
  return 'sha256:' + Array.from(new Uint8Array(hash), x => x.toString(16).padStart(2, '0')).join('');
}
export async function generatePhoneKey(crypto: Crypto = globalThis.crypto): Promise<CryptoKeyPair> {
  return crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign', 'verify']);
}
export async function fingerprint(key: CryptoKey, crypto: Crypto = globalThis.crypto): Promise<string> {
  return sha256(new Uint8Array(await crypto.subtle.exportKey('spki', key)), crypto);
}
export async function signBytes(key: CryptoKey, data: Uint8Array<ArrayBuffer>, crypto: Crypto = globalThis.crypto): Promise<string> {
  const signature = new Uint8Array(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, key, data));
  if (signature.length !== 64) throw new Error('Unsupported signature format');
  return base64url(signature);
}
export async function contentHash(value: unknown, crypto: Crypto = globalThis.crypto): Promise<string> {
  return sha256(bytes(canonicalJSON(value)), crypto);
}
export async function parseManifest(raw: string, crypto: Crypto = globalThis.crypto): Promise<ApprovalManifest> {
  if (bytes(raw).length > 1024 * 1024) throw new Error('Manifest too large');
  const value: unknown = JSON.parse(raw);
  validateManifest(value);
  if (canonicalJSON(value) !== raw) throw new Error('Noncanonical or duplicate manifest fields');
  if (value.consumerMap.hash !== await contentHash(value.consumerMap.entries, crypto)) throw new Error('Consumer map hash mismatch');
  for (const recipe of value.recipes) if (recipe.hash !== await contentHash(recipe.steps, crypto)) throw new Error('Recipe hash mismatch');
  return value;
}
export async function manifestDigest(raw: string, crypto: Crypto = globalThis.crypto): Promise<string> {
  return sha256(bytes('keyroot.manifest-digest.v1\0' + raw), crypto);
}
export async function verifyDescriptor(hash: string, descriptor: unknown, crypto: Crypto = globalThis.crypto): Promise<void> {
  if (!/^sha256:[a-f0-9]{64}$/.test(hash) || await contentHash(descriptor, crypto) !== hash) throw new Error('Configuration descriptor changed');
}
export interface ReviewGuard { origin: string; controllerOrigin: string; pinnedFingerprint: string; actualFingerprint: string; reviewedBundle: boolean; demo: boolean; expectedDigest: string; now: number; }
export async function validateReview(raw: string, guard: ReviewGuard, crypto: Crypto = globalThis.crypto): Promise<ApprovalManifest> {
  const manifest = await parseManifest(raw, crypto);
  if (await manifestDigest(raw, crypto) !== guard.expectedDigest) throw new Error('Review changed');
  if (guard.now < manifest.notBefore || guard.now >= manifest.expiresAt) throw new Error('Approval expired or not yet valid');
  const origin = new URL(guard.origin), controller = new URL(guard.controllerOrigin);
  if (!guard.demo && (origin.protocol !== 'https:' || controller.protocol !== 'https:' || origin.origin === controller.origin || !guard.reviewedBundle || !guard.pinnedFingerprint || guard.actualFingerprint !== guard.pinnedFingerprint)) throw new Error('Independent origin, reviewed bundle, and controller pin required');
  return manifest;
}
