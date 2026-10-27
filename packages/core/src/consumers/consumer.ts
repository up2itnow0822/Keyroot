import { createHash, randomUUID } from 'node:crypto';
import type { AuthorizedIntent } from '../journal.js';
import type { EffectContext } from '../engine.js';
import { canonicalJSON, contentDigest, deepFreeze } from '../manifest.js';
import { safeReceipt, type LifecycleReceipt } from '../receipts.js';

/** Canonical metadata signed as ActionParameters.configurationHash. Values never belong here. */
export interface ConsumerDescriptor {
  driver: 'env-file' | 'github-actions' | 'vercel' | 'wrapper';
  consumerId: string;
  destinationId: string;
  revision: string;
  consumerMapRevision: string;
  generation: number;
  handleId: string;
  version: number;
  mappingTokenFingerprint: string;
}
export interface ConsumerTrust {
  /** Installed executor closure must call U3's current authority/boot fence. Never accept from owner JSON. */
  beforeEffect(intent: AuthorizedIntent, boundary: string): Promise<void>;
  /** Read current inventory at the effect boundary, including during emergencies. Unknown fails closed. */
  quarantine(consumerId: string, destinationId: string): Promise<'clear' | 'quarantined' | 'unknown'>;
  clock?: () => number;
}
export interface ConsumerDriver { deliver(intent: AuthorizedIntent, context: EffectContext): Promise<LifecycleReceipt> }
export interface PlatformAdmission {
  /** Installed account-test registry must check exact descriptor scope; a push response is never admission. */
  assertAdmitted(descriptor: Readonly<ConsumerDescriptor>): Promise<void>;
}
export class ConsumerRefusal extends Error { constructor() { super('Consumer effect refused'); } }
export function pinDescriptor<T extends ConsumerDescriptor>(descriptor: T, extraFields: readonly string[]): Readonly<T> {
  const base = ['driver', 'consumerId', 'destinationId', 'revision', 'consumerMapRevision', 'generation', 'handleId', 'version', 'mappingTokenFingerprint'];
  if (Object.keys(descriptor).some(k => !base.includes(k) && !extraFields.includes(k)) || base.some(k => !(k in descriptor))) throw new ConsumerRefusal();
  for (const key of ['consumerId', 'destinationId', 'revision', 'consumerMapRevision', 'handleId', 'mappingTokenFingerprint'] as const) if (typeof descriptor[key] !== 'string' || !/^[-a-zA-Z0-9_.:@/]{1,256}$/.test(descriptor[key])) throw new ConsumerRefusal();
  if (!/^sha256:[a-f0-9]{64}$/.test(descriptor.mappingTokenFingerprint)) throw new ConsumerRefusal();
  if (!Number.isSafeInteger(descriptor.generation) || descriptor.generation < 0 || !Number.isSafeInteger(descriptor.version) || descriptor.version < 1) throw new ConsumerRefusal();
  return deepFreeze(JSON.parse(canonicalJSON(descriptor)) as T);
}
export function assertConsumerIntent(intent: AuthorizedIntent, d: Readonly<ConsumerDescriptor>, context: EffectContext): void {
  const p = intent.parameters; const s = context.subject;
  if (!Object.isFrozen(intent) || !Object.isFrozen(p) || intent.kind !== 'deliver' || intent.state !== 'pending' || intent.operationId !== s.operationId || p.configurationHash !== contentDigest(d) || p.consumerId !== d.consumerId || p.destinationId !== d.destinationId || p.handleId !== d.handleId || p.generation !== d.generation || p.expectedRevision !== d.revision || s.consumerId !== d.consumerId || s.handleId !== d.handleId || s.generation !== d.generation || s.revision !== d.revision || s.consumerMapRevision !== d.consumerMapRevision || context.signal.aborted) throw new ConsumerRefusal();
}
export async function beforeConsumerEffect(intent: AuthorizedIntent, d: Readonly<ConsumerDescriptor>, context: EffectContext, trust: ConsumerTrust, boundary: string): Promise<void> {
  assertConsumerIntent(intent, d, context);
  try {
    if (await trust.quarantine(d.consumerId, d.destinationId) !== 'clear') throw new ConsumerRefusal();
    await trust.beforeEffect(intent, boundary);
    assertConsumerIntent(intent, d, context);
  } catch { throw new ConsumerRefusal(); }
}
export function deliveryReceipt(context: EffectContext, trust: ConsumerTrust, d: ConsumerDescriptor, outcome: 'delivery-accepted' | 'rejected' | 'unknown', limitations: string[] = []): LifecycleReceipt {
  return safeReceipt({ receiptId: randomUUID(), subject: { ...context.subject }, kind: 'deliver', outcome, observedAt: trust.clock?.() ?? Date.now(), observerId: `consumer:${d.driver}`, evidenceHash: contentDigest({ descriptor: d, outcome, limitations }), limitationCodes: ['delivery-is-not-adoption', ...limitations] });
}
/** Bounded HTTPS transport; redirects and raw errors never escape the installed driver. */
export async function platformRequest(transport: typeof fetch, url: string, token: string, init: RequestInit, timeoutMs: number, parentSignal: AbortSignal, readResponseMetadata = false): Promise<{ status: number; body?: unknown } | undefined> {
  const controller = new AbortController(); const abort = () => controller.abort(); parentSignal.addEventListener('abort', abort, { once: true });
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    if (parentSignal.aborted) return undefined;
    return await Promise.race([
      (async () => { const response = await transport(url, { ...init, redirect: 'error', signal: controller.signal, headers: { Accept: 'application/json', ...init.headers, Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' } }); let body: unknown; if (init.method === 'GET' || readResponseMetadata) { const length = response.headers.get('content-length'); if (length !== null && Number(length) > 65536) return undefined; const reader = response.body?.getReader(); if (reader) { let bytes = 0; const chunks: Uint8Array[] = []; try { for (;;) { const chunk = await reader.read(); if (chunk.done) break; bytes += chunk.value.length; if (bytes > 65536) { await reader.cancel(); return undefined; } chunks.push(chunk.value); } body = JSON.parse(Buffer.concat(chunks).toString('utf8')) as unknown; } catch { return undefined; } finally { reader.releaseLock(); } } } else await response.body?.cancel(); return { status: response.status, body }; })(),
      new Promise<undefined>(resolve => { timer = setTimeout(() => { controller.abort(); resolve(undefined); }, timeoutMs); })
    ]);
  } catch { return undefined; } finally { if (timer !== undefined) clearTimeout(timer); parentSignal.removeEventListener('abort', abort); }
}
export function platformTimeout(value = 10000): number { if (!Number.isSafeInteger(value) || value < 1 || value > 120000) throw new ConsumerRefusal(); return value; }
export function credentialFingerprint(value: string): string { return `sha256:${createHash('sha256').update(value).digest('hex')}`; }
export function platformId(value: string): boolean { return /^[a-zA-Z0-9_-]{1,128}$/.test(value); }
