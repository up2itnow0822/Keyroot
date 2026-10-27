import { createPublicKey, verify, type KeyObject } from 'node:crypto';
import { canonicalJSON, contentDigest } from './manifest.js';
import { safeReceipt, type LifecycleReceipt, type ReceiptSubject } from './receipts.js';

export interface SignedConsumerObservation {
  version: 1;
  consumerIdentity: string;
  subject: ReceiptSubject;
  processId?: string;
  deploymentId?: string;
  jobId?: string;
  runId: string;
  observedAt: number;
  method: 'authenticated-runtime-use';
  limitationCodes: string[];
}
/** Only installed, authenticated consumer identities can prove named new-generation use. */
export function verifyConsumerUse(proof: { observation: SignedConsumerObservation; signature: string }, expected: Readonly<ReceiptSubject>, trusted: { identities: ReadonlyMap<string, { consumerId: string; publicKey: KeyObject | string }>; clock?: () => number; maxAgeMs: number }): LifecycleReceipt {
  const deny = () => { throw new Error('Consumer-use proof refused'); };
  try {
    const o = proof.observation;
    const keys = ['version', 'consumerIdentity', 'subject', 'runId', 'observedAt', 'method', 'limitationCodes']; const runtimeKeys = ['processId', 'deploymentId', 'jobId'];
    if (Object.keys(o).some(k => !keys.includes(k) && !runtimeKeys.includes(k)) || keys.some(k => !(k in o)) || ![o.processId, o.deploymentId, o.jobId].some(id => id !== undefined) || o.version !== 1 || o.method !== 'authenticated-runtime-use' || !Number.isSafeInteger(trusted.maxAgeMs) || trusted.maxAgeMs < 1) return deny();
    if (!expected.consumerId || !expected.revision || canonicalJSON(o.subject) !== canonicalJSON(expected)) return deny();
    for (const id of [o.consumerIdentity, o.runId, ...[o.processId, o.deploymentId, o.jobId].filter(id => id !== undefined)]) if (typeof id !== 'string' || !/^[-a-zA-Z0-9_.:@/]{1,256}$/.test(id)) return deny();
    const now = trusted.clock?.() ?? Date.now();
    if (!Number.isSafeInteger(o.observedAt) || o.observedAt > now || now - o.observedAt > trusted.maxAgeMs) return deny();
    const identity = trusted.identities.get(o.consumerIdentity); if (!identity || identity.consumerId !== expected.consumerId) return deny();
    const publicKey = typeof identity.publicKey === 'string' ? createPublicKey(identity.publicKey) : identity.publicKey;
    if (publicKey.type !== 'public' || publicKey.asymmetricKeyType !== 'ed25519' || typeof proof.signature !== 'string' || !/^[A-Za-z0-9+/]{86}==$/.test(proof.signature) || !verify(null, Buffer.from(canonicalJSON(o)), publicKey, Buffer.from(proof.signature, 'base64'))) return deny();
    return safeReceipt({ receiptId: contentDigest({ observation: o, signature: proof.signature }), subject: { ...o.subject }, kind: 'consumer-use', outcome: 'direct-use', observedAt: o.observedAt, observerId: o.consumerIdentity, evidenceHash: contentDigest(o), limitationCodes: [...o.limitationCodes, 'named-run-only', 'unmanaged-copies-uncontrolled'] });
  } catch { return deny(); }
}
