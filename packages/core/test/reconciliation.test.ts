import { test } from 'node:test';
import { strict as assert } from 'node:assert';
import { reconcileCreation, resolveCreatedReference, type IssuerCreationObservation, type StoreCreationObservation } from '../src/reconciliation.js';
import { assertReceiptSubject, validateReceipt, type CreationStoreBinding, type LifecycleReceipt } from '../src/receipts.js';
import { deadlineDisposition } from '../src/deadline.js';

const op = { operationId: 'op', lineageId: 'lineage', accountId: 'account', fromGeneration: 1, toGeneration: 2 };
const target = { handleId: 'handle', destinationId: 'vault' };
const issuer: IssuerCreationObservation = { status: 'found', operationId: 'op', lineageId: 'lineage', accountId: 'account', generation: 2, resourceId: 'new-key' };
const binding: CreationStoreBinding = { operationId: 'op', lineageId: 'lineage', accountId: 'account', generation: 2, issuerId: 'new-key', handleId: 'handle', destinationId: 'vault', version: 1 };
function receipt(): LifecycleReceipt { return { receiptId: 'receipt', kind: 'create', outcome: 'stored', subject: { operationId: op.operationId, lineageId: op.lineageId, accountId: op.accountId, generation: 2, resourceId: 'new-key', handleId: 'handle', consumerMapRevision: 'map' }, storeBinding: binding, observedAt: 1000, observerId: 'synthetic', evidenceHash: 'sha256:synthetic', limitationCodes: ['synthetic-only'] }; }

test('U4 reconciliation requires exact issuer AND operation-bound pinned store metadata; absence cannot authorize retry', () => {
  assert.equal(reconcileCreation(op, target, issuer, { status: 'found', binding }).outcome, 'stored');
  for (const status of ['unknown', 'not-found', 'ambiguous'] as const) assert.equal(reconcileCreation(op, target, { status }, { status: 'not-found' }).outcome, 'orphan-unresolved');
  assert.equal(reconcileCreation(op, target, issuer, { status: 'not-found' }).outcome, 'created-unrecoverable');
  assert.equal(reconcileCreation(op, target, issuer, { status: 'unknown' }).outcome, 'orphan-unresolved');
  for (const [field, value] of Object.entries({ operationId: 'other', lineageId: 'other', accountId: 'other', generation: 3, issuerId: 'other', handleId: 'other', destinationId: 'other', version: 0 })) {
    const store = { status: 'found', binding: { ...binding, [field]: value } } as StoreCreationObservation;
    assert.equal(reconcileCreation(op, target, issuer, store).outcome, 'orphan-unresolved', field);
  }
  assert.equal(reconcileCreation(op, target, { ...issuer, accountId: 'other' }, { status: 'found', binding }).outcome, 'orphan-unresolved');
});

test('U4 created references resolve only from complete matching durable creation/store bindings without manifest rewrites', () => {
  const r = receipt();
  const ref = 'created:op'; assert.equal(resolveCreatedReference(ref, op, [r]), 'new-key'); assert.equal(ref, 'created:op');
  assert.throws(() => resolveCreatedReference(ref, op, []));
  assert.throws(() => resolveCreatedReference('created:another', op, [r]));
  assert.throws(() => resolveCreatedReference(ref, op, [{ ...r, subject: { ...r.subject, accountId: 'other' } }]));
  assert.throws(() => resolveCreatedReference(ref, op, [{ ...r, storeBinding: { ...binding, generation: 7 } }]));
  assert.throws(() => resolveCreatedReference(ref, op, [r, { ...r, receiptId: 'second', subject: { ...r.subject, resourceId: 'second-key' }, storeBinding: { ...binding, issuerId: 'second-key' } }]));
  assert.equal(resolveCreatedReference('known-old-key', op, []), 'known-old-key');
});

test('U4 safe receipt schema refuses raw payloads and matching booleans, checks actual identity and outcome semantics', () => {
  const r = receipt();
  validateReceipt(r); assertReceiptSubject(r, r.subject, { createdResource: true, destinationId: 'vault' });
  for (const field of ['rawValue', 'payload', 'error', 'matching', 'sameGeneration']) assert.throws(() => validateReceipt({ ...r, [field]: field === 'matching' ? true : 'PRIVATE' }));
  assert.throws(() => assertReceiptSubject({ ...r, subject: { ...r.subject, consumerMapRevision: 'wrong' } }, r.subject));
  assert.throws(() => validateReceipt({ ...r, kind: 'consumer-use', outcome: 'stored' }));
  assert.throws(() => validateReceipt({ ...r, outcome: 'stored', storeBinding: undefined }));
  assert.throws(() => validateReceipt({ ...r, observerId: 'raw secret with spaces' }));
});

test('U4 routine and hard deadlines preserve signed outage consequences independently from authority lifetime', () => {
  const routine = { deadline: { at: 10, outcome: 'hold' as const }, outage: { permitted: false, consequence: 'none' as const } };
  assert.equal(deadlineDisposition(routine, 9), 'within-window'); assert.equal(deadlineDisposition(routine, 10), 'overdue-exposure');
  assert.throws(() => deadlineDisposition({ ...routine, deadline: { at: 10, outcome: 'hard-revoke' } }, 10));
  assert.equal(deadlineDisposition({ deadline: { at: 10, outcome: 'hard-revoke' }, outage: { permitted: true, consequence: 'declared-interruption' } }, 10), 'hard-outage');
});
