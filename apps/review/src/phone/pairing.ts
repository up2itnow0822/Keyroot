import { fingerprint, generatePhoneKey } from './signing.js';

const DATABASE = 'keyroot-phone-v1';
export async function validateKeyPair(key: CryptoKeyPair): Promise<void> {
  if (!key?.privateKey || !key.publicKey || key.privateKey.extractable || key.privateKey.type !== 'private' || key.publicKey.type !== 'public' || key.privateKey.algorithm.name !== 'ECDSA' || key.publicKey.algorithm.name !== 'ECDSA' || (key.privateKey.algorithm as EcKeyAlgorithm).namedCurve !== 'P-256' || (key.publicKey.algorithm as EcKeyAlgorithm).namedCurve !== 'P-256' || !key.privateKey.usages.includes('sign') || !key.publicKey.usages.includes('verify')) throw new Error('Stored phone key is invalid');
  const challenge = crypto.getRandomValues(new Uint8Array(32));
  const signature = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, key.privateKey, challenge);
  if (!await crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, key.publicKey, signature, challenge)) throw new Error('Stored phone key pair does not match');
}
export async function getOrCreateKey(): Promise<CryptoKeyPair> {
  const db = await new Promise<IDBDatabase>((resolve, reject) => {
    const request = indexedDB.open(DATABASE, 1);
    request.onupgradeneeded = () => request.result.createObjectStore('keys');
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
  try {
    const existing = await new Promise<CryptoKeyPair | undefined>((resolve, reject) => {
      const request = db.transaction('keys').objectStore('keys').get('routine');
      request.onsuccess = () => resolve(request.result as CryptoKeyPair | undefined);
      request.onerror = () => reject(request.error);
    });
    if (existing) { await validateKeyPair(existing); return existing; }
    const key = await generatePhoneKey();
    await new Promise<void>((resolve, reject) => {
      const tx = db.transaction('keys', 'readwrite');
      tx.objectStore('keys').add(key, 'routine');
      tx.oncomplete = () => resolve(); tx.onerror = () => reject(tx.error); tx.onabort = () => reject(tx.error);
    });
    return key;
  } finally { db.close(); }
}
export async function publicPairing(key: CryptoKeyPair) {
  return { publicKey: await crypto.subtle.exportKey('jwk', key.publicKey), fingerprint: await fingerprint(key.publicKey) };
}
