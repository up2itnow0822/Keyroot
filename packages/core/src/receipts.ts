import { canonicalJSON, deepFreeze } from './manifest.js';

/** Metadata returned only by installed, trusted executors. No credential material crosses this port. */
export interface ReceiptSubject {
  operationId: string;
  lineageId: string;
  accountId: string;
  generation: number;
  resourceId: string;
  handleId: string;
  consumerMapRevision: string;
  consumerId?: string;
  revision?: string;
}
export interface CreationStoreBinding {
  operationId: string;
  lineageId: string;
  accountId: string;
  generation: number;
  issuerId: string;
  handleId: string;
  destinationId: string;
  version: number;
}
export type LifecycleReceiptKind = 'create' | 'validate' | 'deliver' | 'revoke' | 'cleanup' | 'consumer-use' | 'old-use' | 'issuer' | 'probe';
export type LifecycleOutcome = 'stored' | 'rejected' | 'unknown' | 'created-unrecoverable' | 'orphan-unresolved' | 'validated' | 'delivery-accepted' | 'issuer-acknowledged' | 'confirmed-revoked' | 'confirmed-active' | 'unverified' | 'direct-use' | 'inferred-use' | 'generic-health' | 'queued' | 'failed' | 'positive-use' | 'none-observed' | 'accepted' | 'confounded';
export interface LifecycleReceipt {
  receiptId: string;
  subject: ReceiptSubject;
  kind: LifecycleReceiptKind;
  outcome: LifecycleOutcome;
  observedAt: number;
  observerId: string;
  evidenceHash: string;
  limitationCodes: string[];
  storeBinding?: CreationStoreBinding;
}
const outcomes: Record<LifecycleReceiptKind, readonly LifecycleOutcome[]> = {
  create: ['stored', 'rejected', 'unknown', 'created-unrecoverable', 'orphan-unresolved'],
  validate: ['validated', 'rejected', 'unknown'],
  deliver: ['delivery-accepted', 'rejected', 'unknown'],
  revoke: ['issuer-acknowledged', 'confirmed-revoked', 'confirmed-active', 'unverified', 'rejected', 'unknown'],
  cleanup: ['issuer-acknowledged', 'confirmed-revoked', 'confirmed-active', 'unverified', 'rejected', 'unknown'],
  'consumer-use': ['direct-use', 'inferred-use', 'generic-health', 'queued', 'failed', 'unknown'],
  'old-use': ['positive-use', 'none-observed', 'unknown'],
  issuer: ['confirmed-revoked', 'confirmed-active', 'unverified', 'unknown'],
  probe: ['accepted', 'rejected', 'confounded', 'unknown']
};
function object(value: unknown, required: string[], optional: string[] = []): asserts value is Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value) || required.some(k => !(k in value)) || Object.keys(value).some(k => !required.includes(k) && !optional.includes(k))) throw new Error('Invalid safe receipt fields');
}
function id(value: unknown): asserts value is string {
  if (typeof value !== 'string' || !/^[-a-zA-Z0-9_.:@/]+$/.test(value) || value.length > 256) throw new Error('Invalid safe receipt identifier');
}
function integer(value: unknown, min = 0): asserts value is number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < min) throw new Error('Invalid safe receipt integer');
}
export function validateStoreBinding(value: unknown): asserts value is CreationStoreBinding {
  object(value, ['operationId', 'lineageId', 'accountId', 'generation', 'issuerId', 'handleId', 'destinationId', 'version']);
  for (const [key, v] of Object.entries(value)) { if (key === 'generation' || key === 'version') integer(v, key === 'version' ? 1 : 0); else id(v); }
}
export function validateReceipt(value: unknown): asserts value is LifecycleReceipt {
  object(value, ['receiptId', 'subject', 'kind', 'outcome', 'observedAt', 'observerId', 'evidenceHash', 'limitationCodes'], ['storeBinding']);
  for (const key of ['receiptId', 'observerId', 'evidenceHash']) id(value[key]);
  integer(value.observedAt);
  object(value.subject, ['operationId', 'lineageId', 'accountId', 'generation', 'resourceId', 'handleId', 'consumerMapRevision'], ['consumerId', 'revision']);
  for (const [key, v] of Object.entries(value.subject)) { if (key === 'generation') integer(v); else id(v); }
  if (typeof value.kind !== 'string' || !Object.hasOwn(outcomes, value.kind) || !outcomes[value.kind as LifecycleReceiptKind].includes(value.outcome as LifecycleOutcome)) throw new Error('Invalid receipt kind or outcome');
  if (!Array.isArray(value.limitationCodes) || value.limitationCodes.length > 100) throw new Error('Invalid receipt limitations');
  value.limitationCodes.forEach(id);
  if (value.storeBinding !== undefined) validateStoreBinding(value.storeBinding);
  if (value.outcome === 'stored' && (value.kind !== 'create' || value.storeBinding === undefined)) throw new Error('Stored creation needs exact store binding');
  if (value.storeBinding !== undefined && value.kind !== 'create') throw new Error('Unexpected store binding');
}
export function assertReceiptSubject(receipt: LifecycleReceipt, expected: ReceiptSubject, options: { createdResource?: boolean; destinationId?: string } = {}): void {
  validateReceipt(receipt);
  for (const key of Object.keys(expected) as (keyof ReceiptSubject)[]) {
    if (key === 'resourceId' && options.createdResource) continue;
    if (receipt.subject[key] !== expected[key]) throw new Error('Receipt subject mismatch');
  }
  for (const key of ['consumerId', 'revision'] as const) if (receipt.subject[key] !== expected[key]) throw new Error('Receipt consumer binding mismatch');
  if (receipt.storeBinding) {
    const b = receipt.storeBinding;
    for (const key of ['operationId', 'lineageId', 'accountId', 'generation', 'handleId'] as const) if (b[key] !== expected[key]) throw new Error('Creation store binding mismatch');
    if (b.issuerId !== receipt.subject.resourceId || (options.destinationId !== undefined && b.destinationId !== options.destinationId)) throw new Error('Creation store target mismatch');
  }
}
export function safeReceipt(receipt: LifecycleReceipt): Readonly<LifecycleReceipt> {
  validateReceipt(receipt);
  return deepFreeze(JSON.parse(canonicalJSON(receipt)) as LifecycleReceipt);
}
