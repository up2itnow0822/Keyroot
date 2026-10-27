import { createHash, randomUUID } from 'node:crypto';
import type { ApprovalService, AuthorizeEffectRequest } from './approval.js';

export type NativeClient = 'claude-code' | 'codex';
export interface NativeCoverage {
  client: NativeClient;
  storage: 'supported-os-credential-store' | 'plaintext-only' | 'unknown';
  remoteSignOut: 'available' | 'unavailable' | 'unknown';
  sessionTelemetry: 'available' | 'unavailable' | 'unknown';
}
/** Metadata only; no inspection of login files or token material. */
export function describeNativeCoverage(coverage: NativeCoverage): NativeCoverage { return { ...coverage }; }
export interface SessionEvent { provider: string; accountId: string; placeId: string; observedAt: string; kind: 'new-place' }
/** A trusted provider telemetry adapter supplies actual events; unknown providers make no cross-provider claim. */
export function newPlaceAlert(event: SessionEvent): { provider: string; accountId: string; placeId: string; observedAt: string; message: string } {
  if (!event.provider || !event.accountId || !event.placeId || !Number.isFinite(Date.parse(event.observedAt)) || event.kind !== 'new-place') throw new Error('Invalid session event');
  return { provider: event.provider, accountId: event.accountId, placeId: event.placeId, observedAt: event.observedAt, message: 'New place reported by this provider' };
}
/** Executor is a trusted integration selecting a fixed documented action; no command or arguments come from the caller. */
export interface NativeSignOutExecutor { execute(action: 'claude-code-local-sign-out' | 'codex-local-sign-out'): Promise<void> }
export async function signOutNative(input: { client: NativeClient; approval: ApprovalService; request: AuthorizeEffectRequest; executor: NativeSignOutExecutor }): Promise<void> {
  const intent = await input.approval.authorizeEffect(input.request);
  const resource = `native:${input.client}:local`;
  if (intent.kind !== 'sign-out' || intent.parameters.resourceId !== resource) throw new Error('Signed action does not authorize this native sign-out');
  const action = input.client === 'codex' ? 'codex-local-sign-out' : 'claude-code-local-sign-out';
  const operation = input.approval.journal.inspectOperation(intent.operationId);
  if (!operation) throw new Error('Native sign-out operation missing');
  let outcome: 'confirmed' | 'unknown' = 'confirmed';
  try { await input.executor.execute(action); } catch { outcome = 'unknown'; }
  const observedAt = Date.now();
  const receiptId = randomUUID();
  const p = intent.parameters;
  const evidenceHash = 'sha256:' + createHash('sha256').update(JSON.stringify({ method: action, intentId: intent.intentId, resource, outcome, observedAt })).digest('hex');
  input.approval.journal.appendReceipt({ receiptId, intentId: intent.intentId, kind: 'sign-out', outcome, accountId: operation.accountId, generation: Number(p.generation ?? operation.toGeneration), resourceId: resource, ...(typeof p.consumerId === 'string' ? { consumerId: p.consumerId } : {}), ...(typeof p.handleId === 'string' ? { handleId: p.handleId } : {}), ...(typeof p.destinationId === 'string' ? { destinationId: p.destinationId } : {}), ...(typeof p.expectedRevision === 'string' ? { revision: p.expectedRevision } : {}), observedAt, observerId: 'native-local-command', evidenceHash, limitationCodes: ['local-command-only-remote-session-unverified'] });
  if (outcome === 'unknown') throw new Error('Native local sign-out outcome unknown');
  input.approval.journal.resolveIntent({ intentId: intent.intentId, receiptIds: [receiptId] });
}
