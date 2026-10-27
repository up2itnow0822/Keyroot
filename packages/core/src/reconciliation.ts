import type { ManifestOperation } from './manifest.js';
import { validateReceipt, validateStoreBinding, type CreationStoreBinding, type LifecycleReceipt } from './receipts.js';

export type CreationReconciliation =
  | { outcome: 'stored'; resourceId: string; storeBinding: CreationStoreBinding }
  | { outcome: 'created-unrecoverable'; resourceId: string }
  | { outcome: 'orphan-unresolved' };
export type IssuerCreationObservation = { status: 'found'; operationId: string; accountId: string; lineageId: string; generation: number; resourceId: string } | { status: 'not-found' | 'unknown' | 'ambiguous' };
export type StoreCreationObservation = { status: 'found'; binding: CreationStoreBinding } | { status: 'not-found' | 'unknown' };
/** Absence of issuer metadata is never evidence that an ambiguous create did not happen. */
export function reconcileCreation(operation: Omit<ManifestOperation, 'actions'>, target: { handleId: string; destinationId: string; expectedVersion?: number }, issuer: IssuerCreationObservation, store: StoreCreationObservation): CreationReconciliation {
  if (issuer.status !== 'found') return { outcome: 'orphan-unresolved' };
  if (issuer.operationId !== operation.operationId || issuer.accountId !== operation.accountId || issuer.lineageId !== operation.lineageId || issuer.generation !== operation.toGeneration) return { outcome: 'orphan-unresolved' };
  if (store.status === 'not-found') return { outcome: 'created-unrecoverable', resourceId: issuer.resourceId };
  if (store.status !== 'found') return { outcome: 'orphan-unresolved' };
  try { validateStoreBinding(store.binding); } catch { return { outcome: 'orphan-unresolved' }; }
  const b = store.binding;
  if (b.operationId !== operation.operationId || b.lineageId !== operation.lineageId || b.accountId !== operation.accountId || b.generation !== operation.toGeneration || b.issuerId !== issuer.resourceId || b.handleId !== target.handleId || b.destinationId !== target.destinationId || b.version !== (target.expectedVersion ?? 0) + 1) return { outcome: 'orphan-unresolved' };
  return { outcome: 'stored', resourceId: issuer.resourceId, storeBinding: { ...b } };
}
/** Resolve references through durable, validated metadata without modifying the signed manifest. */
export function resolveCreatedReference(reference: string, operation: Omit<ManifestOperation, 'actions'>, receipts: readonly LifecycleReceipt[]): string {
  if (!reference.startsWith('created:')) return reference;
  if (reference !== `created:${operation.operationId}`) throw new Error('Created reference outside operation');
  const matches = receipts.filter(r => r.kind === 'create' && r.outcome === 'stored' && r.subject.operationId === operation.operationId);
  const resources = new Set<string>();
  for (const r of matches) {
    validateReceipt(r); const b = r.storeBinding!;
    if (r.subject.accountId !== operation.accountId || r.subject.lineageId !== operation.lineageId || r.subject.generation !== operation.toGeneration || b.accountId !== operation.accountId || b.lineageId !== operation.lineageId || b.operationId !== operation.operationId || b.generation !== operation.toGeneration || b.issuerId !== r.subject.resourceId || b.handleId !== r.subject.handleId) throw new Error('Invalid durable creation binding');
    resources.add(r.subject.resourceId);
  }
  if (resources.size !== 1) throw new Error('Durable matching creation/store receipt required');
  return [...resources][0]!;
}
