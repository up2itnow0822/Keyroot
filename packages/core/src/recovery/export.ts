import { createPublicKey, verify, type JsonWebKey as CryptoJsonWebKey } from 'node:crypto';
import type { SQLInputValue } from 'node:sqlite';
import { Encrypter, Decrypter } from 'age-encryption';
import type { Journal } from '../journal.js';
import { canonicalJSON, contentDigest, deepFreeze, parseCanonicalManifest } from '../manifest.js';
import { validateReceipt } from '../receipts.js';
import { publicKeyFingerprint } from '../approval.js';

const MAX_BYTES = 8 * 1024 * 1024;
const MAX_ROWS = 10000;
/** Fixed known metadata projections. SQL identifiers never originate in an archive. */
export const recoveryTables = deepFreeze({
  operation: ['operation_id', 'lineage_id', 'account_id', 'from_generation', 'to_generation', 'state', 'boot_id'],
  lineage_lock: ['lineage_id', 'operation_id', 'fence'],
  approver: ['signer_id', 'role', 'public_key', 'fingerprint', 'revoked'],
  approval_grant: ['grant_id', 'raw_manifest', 'signature', 'digest', 'boot_id', 'role', 'cancelled', 'executions', 'effects', 'new_credentials', 'restarts'],
  approval_instance: ['grant_id', 'operation_id'],
  intent: ['intent_id', 'idempotency_ref', 'operation_id', 'action_id', 'grant_id', 'kind', 'parameters', 'state'],
  receipt: ['receipt_id', 'intent_id', 'metadata'],
  session_revocation: ['session_id', 'boot_id', 'revoked'],
  source_evidence: ['evidence_id', 'source_id', 'evidence_hash', 'observed_at'],
  audit: ['sequence', 'kind', 'operation_id', 'reference_id', 'boot_id'],
  engine_operation: ['operation_id', 'holds', 'deadline'],
  engine_receipt: ['receipt_id', 'operation_id', 'intent_id', 'metadata'],
  oauth_family: ['grant_id', 'family_id', 'owner_id', 'version', 'state', 'boot_id', 'access_expires_at', 'pending_intent_id', 'pending_operation_id'],
} as const);
export type RecoveryTable = keyof typeof recoveryTables;
export type MetadataRow = Record<string, SQLInputValue>;
export interface RecoveryMetadata { coverage: 'U3-U4-U7-only'; tableInventory: { name: string; schemaHash: string }[]; tables: Record<RecoveryTable, MetadataRow[]> }
export interface ArchiveStatement {
  domain: 'keyroot.recovery-export.v1'; version: 1; schema: 1;
  installationId: string; bootId: string; createdAt: number; metadataHash: string;
  signerFingerprint: string; recipient: string;
}
export interface OpenedRecoveryArchive { readonly statement: ArchiveStatement; readonly metadata: RecoveryMetadata }
export interface VerificationPin { publicKey: JsonWebKey; fingerprint: string }
const openedArchives = new WeakSet<OpenedRecoveryArchive>();
export function uncoveredRecoveryTables(opened: OpenedRecoveryArchive): string[] {
  const intentionallyInvalidated = new Set(['controller', 'emergency_reservation', 'emergency_credential', 'emergency_challenge', 'emergency_proof', 'engine_schema', 'oauth_schema', 'sqlite_sequence']);
  return opened.metadata.tableInventory.map(entry => entry.name).filter(name => !Object.hasOwn(recoveryTables, name) && !intentionallyInvalidated.has(name));
}
export function assertOpenedArchive(opened: OpenedRecoveryArchive): void {
  if (!openedArchives.has(opened)) throw new Error('Independent offline decryption and authenticated archive required');
}
export function recoveryId(value: unknown): asserts value is string {
  if (typeof value !== 'string' || !/^[-a-zA-Z0-9_.:@/]{1,256}$/.test(value) || value.split('/').includes('..')) throw new Error('Invalid recovery metadata identifier');
}
export function recoveryHash(value: unknown): asserts value is string {
  if (typeof value !== 'string' || !/^sha256:[a-f0-9]{64}$/.test(value)) throw new Error('Invalid recovery evidence hash');
}
export function exactKeys(value: unknown, keys: readonly string[]): asserts value is Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value) || Object.keys(value).sort().join('|') !== [...keys].sort().join('|')) throw new Error('Unknown or missing recovery field');
}
export function validatePublicPin(pin: VerificationPin): void {
  exactKeys(pin.publicKey, ['kty', 'crv', 'x', 'y', ...('ext' in pin.publicKey ? ['ext'] : []), ...('key_ops' in pin.publicKey ? ['key_ops'] : [])]);
  if (pin.publicKey.ext !== undefined && typeof pin.publicKey.ext !== 'boolean' || pin.publicKey.key_ops !== undefined && (!Array.isArray(pin.publicKey.key_ops) || pin.publicKey.key_ops.length !== 1 || pin.publicKey.key_ops[0] !== 'verify')) throw new Error('Invalid public verification key usage');
  if (pin.publicKey.kty !== 'EC' || pin.publicKey.crv !== 'P-256' || publicKeyFingerprint(pin.publicKey) !== pin.fingerprint) throw new Error('Independent P256 verification pin required');
  createPublicKey({ key: pin.publicKey, format: 'jwk' });
}
function validateMetadata(value: unknown): asserts value is RecoveryMetadata {
  exactKeys(value, ['coverage', 'tableInventory', 'tables']);
  if (value.coverage !== 'U3-U4-U7-only') throw new Error('Unsupported archive coverage');
  if (!Array.isArray(value.tableInventory) || value.tableInventory.length > 1000) throw new Error('Invalid metadata table inventory');
  const names = new Set<string>();
  for (const entry of value.tableInventory) {
    exactKeys(entry, ['name', 'schemaHash']); recoveryId(entry.name); recoveryHash(entry.schemaHash);
    if (names.has(entry.name)) throw new Error('Duplicate metadata table inventory');
    names.add(entry.name);
  }
  exactKeys(value.tables, Object.keys(recoveryTables));
  let count = 0;
  for (const table of Object.keys(recoveryTables) as RecoveryTable[]) {
    const rows = value.tables[table];
    if (!Array.isArray(rows) || (count += rows.length) > MAX_ROWS) throw new Error('Recovery table bounds exceeded');
    for (const row of rows) {
      exactKeys(row, recoveryTables[table]);
      for (const [field, item] of Object.entries(row)) {
        if (item === null && ['operation_id', 'intent_id', 'pending_intent_id', 'pending_operation_id'].includes(field)) continue;
        if (['from_generation', 'to_generation', 'revoked', 'cancelled', 'executions', 'effects', 'new_credentials', 'restarts', 'sequence', 'observed_at', 'version', 'access_expires_at'].includes(field)) {
          if (typeof item !== 'number' || !Number.isSafeInteger(item) || item < 0) throw new Error('Invalid recovery integer');
        } else if (field === 'raw_manifest') parseCanonicalManifest(String(item));
        else if (field === 'public_key') {
          const jwk: JsonWebKey = JSON.parse(String(item)); validatePublicPin({ publicKey: jwk, fingerprint: String(row.fingerprint) });
        } else if (field === 'parameters') {
          const params: unknown = JSON.parse(String(item));
          if (!params || typeof params !== 'object' || Array.isArray(params)) throw new Error('Invalid archived intent parameters');
          const allowed = ['resourceId', 'consumerId', 'destinationId', 'handleId', 'generation', 'expectedRevision', 'recipeId', 'adapterId', 'authorityFingerprint', 'reasonCode', 'configurationHash'];
          for (const [key, v] of Object.entries(params)) {
            if (!allowed.includes(key)) throw new Error('Unexpected archived parameter');
            if (key === 'generation') { if (!Number.isSafeInteger(v) || Number(v) < 0) throw new Error('Invalid generation'); }
            else recoveryId(v);
          }
        } else if (field === 'holds') {
          const holds: unknown = JSON.parse(String(item));
          if (!Array.isArray(holds) || holds.length > 1000) throw new Error('Invalid lifecycle holds');
          holds.forEach(recoveryId);
        } else if (field === 'metadata' && table === 'engine_receipt') {
          validateReceipt(JSON.parse(String(item)));
        } else if (field === 'metadata') {
          const receipt: unknown = JSON.parse(String(item));
          if (!receipt || typeof receipt !== 'object' || Array.isArray(receipt)) throw new Error('Invalid receipt metadata');
          const allowed = ['receiptId', 'intentId', 'kind', 'outcome', 'generation', 'observedAt', 'observerId', 'evidenceHash', 'consumerId', 'revision', 'resourceId', 'handleId', 'accountId', 'parentResourceId', 'destinationId', 'storeVersion', 'reconcilesReceiptIds', 'limitationCodes'];
          for (const [key, v] of Object.entries(receipt)) {
            if (!allowed.includes(key)) throw new Error('Unexpected receipt metadata');
            if (['generation', 'observedAt', 'storeVersion'].includes(key)) { if (!Number.isSafeInteger(v) || Number(v) < 0) throw new Error('Invalid receipt number'); }
            else if (['reconcilesReceiptIds', 'limitationCodes'].includes(key)) { if (!Array.isArray(v) || v.length > 1000) throw new Error('Invalid receipt list'); v.forEach(recoveryId); }
            else recoveryId(v);
          }
        } else if (field === 'signature') {
          if (typeof item !== 'string' || !/^[a-zA-Z0-9_-]{0,256}$/.test(item)) throw new Error('Invalid archived signature');
        } else recoveryId(item);
      }
    }
  }
}

/** Returns bytes only. Caller supplies the owner/phone signer; private keys never enter metadata. */
export async function exportRecoveryArchive(input: { journal: Journal; recipient: string; now: number; signerFingerprint: string; sign: (statement: Buffer) => Promise<string> }): Promise<Uint8Array> {
  if (!/^age1[ac-hj-np-z02-9]{58}$/.test(input.recipient) || !Number.isSafeInteger(input.now) || input.now < 0) throw new Error('Standard offline X25519 recipient and export time required');
  recoveryHash(input.signerFingerprint);
  const metadata = input.journal.read(db => {
    // BEGIN pins one SQLite read snapshot across all table projections, including WAL writers.
    db.exec('BEGIN');
    try {
      const controller = db.prepare('SELECT installation_id,boot_id FROM controller WHERE singleton=1').get();
      if (!controller || controller.installation_id !== input.journal.installationId || controller.boot_id !== input.journal.bootId || db.prepare('PRAGMA user_version').get()?.user_version !== 1) throw new Error('Stale controller or unsupported journal schema');
      for (const [schema, expected] of [['engine_schema', 1], ['oauth_schema', 2]] as const) {
        if (db.prepare("SELECT 1 FROM sqlite_schema WHERE type='table' AND name=?").get(schema) && db.prepare(`SELECT version FROM ${schema} WHERE singleton=1`).get()?.version !== expected) throw new Error('Unsupported metadata extension schema');
      }
      const tableInventory = db.prepare("SELECT name,sql FROM sqlite_schema WHERE type='table' ORDER BY name").all().map(row => ({ name: String(row.name), schemaHash: contentDigest(String(row.sql)) }));
      const tables = {} as Record<RecoveryTable, MetadataRow[]>;
      for (const table of Object.keys(recoveryTables) as RecoveryTable[]) {
        const exists = db.prepare("SELECT 1 FROM sqlite_schema WHERE type='table' AND name=?").get(table);
        if (exists) {
          const actual = db.prepare(`PRAGMA table_info(${table})`).all().map(row => String(row.name));
          if (actual.join('|') !== recoveryTables[table].join('|')) throw new Error('Unsupported metadata table columns');
        }
        tables[table] = exists ? db.prepare(`SELECT ${recoveryTables[table].join(',')} FROM ${table} ORDER BY rowid LIMIT ${MAX_ROWS + 1}`).all() as MetadataRow[] : [];
      }
      db.exec('COMMIT'); return { coverage: 'U3-U4-U7-only' as const, tableInventory, tables };
    } catch (error) { db.exec('ROLLBACK'); throw error; }
  });
  validateMetadata(metadata);
  const statement: ArchiveStatement = { domain: 'keyroot.recovery-export.v1', version: 1, schema: 1, installationId: input.journal.installationId, bootId: input.journal.bootId, createdAt: input.now, metadataHash: contentDigest(metadata), signerFingerprint: input.signerFingerprint, recipient: input.recipient };
  const signature = await input.sign(Buffer.from(canonicalJSON(statement)));
  if (!/^[A-Za-z0-9_-]{86}$/.test(signature)) throw new Error('P256 detached export signature required');
  const envelope = canonicalJSON({ statement, metadata, signature });
  if (Buffer.byteLength(envelope) > MAX_BYTES) throw new Error('Recovery archive bounds exceeded');
  const encrypter = new Encrypter(); encrypter.addRecipient(input.recipient);
  return encrypter.encrypt(envelope);
}

/** A supplied public recipient is not sender authentication. Only the independently held pin authenticates this content. */
export async function openRecoveryArchive(input: { archive: Uint8Array; identity: string; verification: VerificationPin; now: number; minimumCreatedAt?: number }): Promise<OpenedRecoveryArchive> {
  try {
    if (!(input.archive instanceof Uint8Array) || input.archive.byteLength > MAX_BYTES + 65536 || !/^AGE-SECRET-KEY-1[0-9A-Z]+$/.test(input.identity)) throw new Error('Invalid offline archive');
    const verification = structuredClone(input.verification);
    validatePublicPin(verification);
    const decrypter = new Decrypter(); decrypter.addIdentity(input.identity);
    const raw = await decrypter.decrypt(input.archive, 'text');
    if (Buffer.byteLength(raw) > MAX_BYTES) throw new Error('Archive bounds');
    const envelope: unknown = JSON.parse(raw);
    exactKeys(envelope, ['statement', 'metadata', 'signature']);
    if (canonicalJSON(envelope) !== raw) throw new Error('Noncanonical archive');
    const s = envelope.statement;
    exactKeys(s, ['domain', 'version', 'schema', 'installationId', 'bootId', 'createdAt', 'metadataHash', 'signerFingerprint', 'recipient']);
    if (s.domain !== 'keyroot.recovery-export.v1' || s.version !== 1 || s.schema !== 1) throw new Error('Unsupported archive version/schema');
    recoveryId(s.installationId); recoveryId(s.bootId); recoveryHash(s.metadataHash);
    if (!Number.isSafeInteger(input.now) || !Number.isSafeInteger(s.createdAt) || Number(s.createdAt) < (input.minimumCreatedAt ?? 0) || Number(s.createdAt) > input.now) throw new Error('Archive time outside independent policy');
    if (s.signerFingerprint !== verification.fingerprint || typeof envelope.signature !== 'string' || !/^[A-Za-z0-9_-]{86}$/.test(envelope.signature) || !verify('sha256', Buffer.from(canonicalJSON(s)), { key: createPublicKey({ key: verification.publicKey as CryptoJsonWebKey, format: 'jwk' }), dsaEncoding: 'ieee-p1363' }, Buffer.from(envelope.signature, 'base64url'))) throw new Error('Archive signature failed');
    validateMetadata(envelope.metadata);
    if (contentDigest(envelope.metadata) !== s.metadataHash) throw new Error('Archive metadata integrity failed');
    const opened = deepFreeze({ statement: s as unknown as ArchiveStatement, metadata: envelope.metadata });
    openedArchives.add(opened); return opened;
  } catch { throw new Error('Recovery archive rejected: decryption, signature, schema or integrity invalid'); }
}
