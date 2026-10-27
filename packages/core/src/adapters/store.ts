/** Privileged port: callers must be trusted executors, never owner or UI code. */
export type StoreStatus = 'not-found' | 'conflict' | 'unknown' | 'denied' | 'schema-error';
export type StoreWriteResult = { status: 'written'; version: number } | { status: StoreStatus };
export interface StoreBinding { operationId: string; issuerId: string; accountId: string; projectId: string; serviceAccountId: string }
export function validStoreBinding(value: unknown): value is StoreBinding {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const candidate = value as Record<string, unknown>;
  const keys = ['operationId', 'issuerId', 'accountId', 'projectId', 'serviceAccountId'];
  return Object.keys(candidate).length === keys.length && keys.every((k) => typeof candidate[k] === 'string' && /^[A-Za-z0-9_-]{1,128}$/.test(candidate[k] as string));
}
export type StoreMetadataResult = { status: 'found'; version: number; binding?: StoreBinding } | { status: StoreStatus };
export type StoreResolveResult = { status: 'resolved' } | { status: StoreStatus };
export interface ConsumerStorePort {
  withValue(handle: string, version: number, execute: (value: string) => Promise<void>): Promise<StoreResolveResult>;
}
export interface ExistingStore {
  write(handle: string, expectedVersion: number, value: string, binding?: StoreBinding): Promise<StoreWriteResult>;
  metadata(handle: string, version?: number): Promise<StoreMetadataResult>;
  consumer(allowedHandles: readonly string[]): ConsumerStorePort;
}
