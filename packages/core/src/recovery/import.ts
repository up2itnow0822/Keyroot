import { randomUUID } from 'node:crypto';
import { chmodSync, closeSync, mkdirSync, openSync, rmSync } from 'node:fs';
import { dirname, isAbsolute } from 'node:path';
import { canonicalJSON, contentDigest, deepFreeze } from '../manifest.js';
import { initializeScheduleSchema } from '../schedule.js';
import { Journal } from '../journal.js';
import { assertOpenedArchive, recoveryTables, uncoveredRecoveryTables, openedArchiveRegistry, exactKeys, recoveryId, snapshotRecoveryMetadata, type OpenedRecoveryArchive, type RecoveryTable } from './export.js';

export interface RecoveryReport {
  installationId: string; bootId: string; sourceInstallationId: string; metadataHash: string;
  coverageComplete: boolean; excludedTables: string[]; recoveryHeld: boolean; unresolvedIntentIds: string[]; limitations: string[];
}
export interface ImportedRecovery { readonly journal: Journal; readonly report: RecoveryReport; readonly opened: OpenedRecoveryArchive }
const importedRecoveries = new WeakSet<ImportedRecovery>();
export function assertImportedRecovery(imported: ImportedRecovery): void {
  if (!importedRecoveries.has(imported)) throw new Error('Independent offline decryption and fresh import required');
}
/** Restore only validated fixed tables into an exclusively created journal; no archive paths, SQL, scripts or secrets. */
export function importRecoveryArchive(input: { opened: OpenedRecoveryArchive; destination: string }): ImportedRecovery {
  assertOpenedArchive(input.opened);
  if (!isAbsolute(input.destination)) throw new Error('Explicit absolute clean destination required');
  mkdirSync(dirname(input.destination), { recursive: true, mode: 0o700 });
  const fd = openSync(input.destination, 'wx', 0o600); closeSync(fd);
  let journal: Journal | undefined;
  try {
    journal = new Journal(input.destination, { installationId: randomUUID(), bootId: randomUUID() });
    journal.setRecoveryHold();
    const current = journal;
    initializeScheduleSchema(current);
    current.transaction(db => db.exec('CREATE TABLE guided_draft (procedure_id TEXT PRIMARY KEY, recipe_hash TEXT NOT NULL, account_id TEXT NOT NULL, destination_id TEXT NOT NULL, step_index INTEGER NOT NULL, completed INTEGER NOT NULL DEFAULT 0)'));
    const registry = openedArchiveRegistry(input.opened);
    registry?.initialize(current);
    current.transaction(db => {
      db.exec('DELETE FROM audit');
      db.exec("CREATE TABLE oauth_schema (singleton INTEGER PRIMARY KEY CHECK(singleton=1), version INTEGER NOT NULL); INSERT INTO oauth_schema VALUES(1,2); CREATE TABLE oauth_family (grant_id TEXT PRIMARY KEY, family_id TEXT NOT NULL UNIQUE, owner_id TEXT NOT NULL, version INTEGER NOT NULL, state TEXT NOT NULL CHECK(state IN ('active','refreshing','reconcile-required','revoking','revoked','consenting','reconciling')), boot_id TEXT NOT NULL, access_expires_at INTEGER NOT NULL, pending_intent_id TEXT, pending_operation_id TEXT);");
      db.exec('CREATE TABLE engine_schema (singleton INTEGER PRIMARY KEY CHECK(singleton=1), version INTEGER NOT NULL); INSERT INTO engine_schema VALUES(1,1); CREATE TABLE engine_operation (operation_id TEXT PRIMARY KEY REFERENCES operation(operation_id), holds TEXT NOT NULL, deadline TEXT NOT NULL); CREATE TABLE engine_receipt (receipt_id TEXT PRIMARY KEY, operation_id TEXT NOT NULL REFERENCES operation(operation_id), intent_id TEXT REFERENCES intent(intent_id), metadata TEXT NOT NULL);');
      for (const table of Object.keys(recoveryTables) as RecoveryTable[]) {
        if (table === 'schedule_schema') continue; // Owning initializer establishes the validated version, never archive SQL.
        const columns = recoveryTables[table];
        const insert = db.prepare(`INSERT INTO ${table}(${columns.join(',')}) VALUES(${columns.map(() => '?').join(',')})`);
        for (const row of input.opened.metadata.tables[table]) insert.run(...columns.map(column => row[column]!));
      }
      for (const [table, columns] of Object.entries(registry?.schema ?? {})) {
        const actual = db.prepare('SELECT name FROM pragma_table_info(?) ORDER BY cid').all(table).map(row => String(row.name));
        if (actual.join('|') !== columns.join('|')) throw new Error('Additional metadata initializer schema mismatch');
        const insert = db.prepare(`INSERT INTO ${table}(${columns.join(',')}) VALUES(${columns.map(() => '?').join(',')})`);
        for (const row of input.opened.metadata.additionalTables[table]!) { registry!.validateRow(table, row); insert.run(...columns.map(column => row[column]!)); }
      }
      // Restored archive signatures prove history only. No historical signer/grant/session becomes live authority.
      db.exec("UPDATE approver SET revoked=1; UPDATE approval_grant SET cancelled=1; UPDATE session_revocation SET revoked=1; UPDATE operation SET state='reconcile-required' WHERE state!='completed'; UPDATE intent SET state='unknown' WHERE state='pending'; UPDATE oauth_family SET state='reconcile-required' WHERE state!='revoked';");
      current.audit(db, 'offline-metadata-imported-held', null, input.opened.statement.metadataHash);
    });
    registry?.afterImport?.(current);
    chmodSync(input.destination, 0o600);
    for (const suffix of ['-wal', '-shm']) {
      try { chmodSync(input.destination + suffix, 0o600); } catch { /* SQLite may not have produced the sidecar. */ }
    }
    const unresolvedIntentIds = current.read(db => db.prepare("SELECT intent_id FROM intent WHERE state!='observed' ORDER BY intent_id").all().map(row => String(row.intent_id)));
    const imported = Object.freeze({ journal: current, opened: input.opened, report: deepFreeze( { installationId: current.installationId, bootId: current.bootId, sourceInstallationId: input.opened.statement.installationId, metadataHash: input.opened.statement.metadataHash, coverageComplete: uncoveredRecoveryTables(input.opened).length === 0, excludedTables: uncoveredRecoveryTables(input.opened), recoveryHeld: true, unresolvedIntentIds, limitations: ['archive-coverage-U3-U4-U7-U8-U9-and-registered-metadata', 'metadata-only-not-store-value-recovery', 'encrypted-existing-store-backup-required', 'issuer-native-clean-device-access-required', 'all-imported-authority-invalidated', 'dashboard-and-read-sessions-invalidated', 'physical-four-machine-recovery-unverified'] } as RecoveryReport) });
    importedRecoveries.add(imported);
    return imported;
  } catch {
    journal?.close();
    for (const suffix of ['', '-wal', '-shm']) rmSync(input.destination + suffix, { force: true });
    throw new Error('Recovery import rejected; no active restored controller');
  }
}

export interface RecoveryImportProvenance {
  domain: 'keyroot.recovery-imported.v1'; version: 1; installationId: string; sourceInstallationId: string;
  metadataHash: string; coverageComplete: boolean; excludedTables: string[]; importedAt: number;
}
/** Reauthenticate existing held metadata. Plaintext markers and database flags never mint this capability by themselves. */
export async function reauthenticateImportedRecovery(input: {
  opened: OpenedRecoveryArchive; journal: Journal; provenance: RecoveryImportProvenance;
  epochStore?: import('../installation-epoch.js').InstallationEpochStore;
}): Promise<ImportedRecovery> {
  assertOpenedArchive(input.opened);
  const { opened, journal, provenance } = input;
  exactKeys(provenance, ['domain', 'version', 'installationId', 'sourceInstallationId', 'metadataHash', 'coverageComplete', 'excludedTables', 'importedAt']);
  if (provenance.domain !== 'keyroot.recovery-imported.v1' || provenance.version !== 1 || provenance.installationId !== journal.installationId || provenance.installationId === opened.statement.installationId || provenance.sourceInstallationId !== opened.statement.installationId || provenance.metadataHash !== opened.statement.metadataHash || !Number.isSafeInteger(provenance.importedAt) || provenance.importedAt < opened.statement.createdAt || provenance.coverageComplete !== (uncoveredRecoveryTables(opened).length === 0) || canonicalJSON(provenance.excludedTables) !== canonicalJSON(uncoveredRecoveryTables(opened))) throw new Error('Recovery import provenance does not match independently authenticated archive');
  recoveryId(provenance.installationId);
  const held = journal.read(db => db.prepare('SELECT installation_id,boot_id,recovery_hold FROM controller WHERE singleton=1').get());
  if (!held || held.installation_id !== journal.installationId || held.boot_id !== journal.bootId || held.recovery_hold !== 1) throw new Error('Existing target must be the exact held recovered installation');
  const registry = openedArchiveRegistry(opened);
  const current = snapshotRecoveryMetadata(journal, registry);
  const ephemeralSchemas: Record<string, readonly string[]> = {
    recovery_observation: ['id', 'metadata'],
    recovery_ceremony: ['challenge_id', 'challenge', 'binding', 'expires_at', 'used', 'verified'],
    recovery_emergency_counter: ['fingerprint', 'counter'],
  };
  const invalidated = ['controller', 'emergency_reservation', 'emergency_credential', 'emergency_challenge', 'emergency_proof', 'engine_schema', 'oauth_schema', 'sqlite_sequence'];
  for (const table of current.tableInventory) {
    if (Object.hasOwn(recoveryTables, table.name) || Object.hasOwn(registry?.schema ?? {}, table.name) || invalidated.includes(table.name)) continue;
    if (!ephemeralSchemas[table.name] || table.schemaHash !== contentDigest({ name: table.name, columns: ephemeralSchemas[table.name] })) throw new Error('Existing target contains excluded or mismatched security metadata');
  }
  const transform = (table: RecoveryTable, row: import('./export.js').MetadataRow) => {
    const result = { ...row };
    if (table === 'approver') result.revoked = 1;
    if (table === 'approval_grant') result.cancelled = 1;
    if (table === 'session_revocation') result.revoked = 1;
    if (table === 'operation' && result.state !== 'completed') result.state = 'reconcile-required';
    if (table === 'intent' && result.state === 'pending') result.state = 'unknown';
    if (table === 'oauth_family' && result.state !== 'revoked') result.state = 'reconcile-required';
    return result;
  };
  const equal = (a: unknown, b: unknown) => canonicalJSON(a) === canonicalJSON(b);
  const key = (table: RecoveryTable, row: import('./export.js').MetadataRow) => {
    if (table === 'approval_instance') return canonicalJSON([row.grant_id, row.operation_id]);
    if (table === 'schedule_quarantine') return canonicalJSON([row.consumer_id, row.destination_id]);
    return canonicalJSON(row[recoveryTables[table][0]]);
  };
  let postImportEvidence = false;
  for (const table of Object.keys(recoveryTables) as RecoveryTable[]) {
    const expected = opened.metadata.tables[table].map(row => transform(table, row));
    const rows = current.tables[table];
    if (table === 'schedule_schema' && !expected.length && equal(rows, [{ singleton: 1, version: 1 }])) continue;
    if (table === 'audit') {
      for (const original of expected) if (!rows.some(row => equal(row, original))) throw new Error('Historical recovery audit was altered');
      if (!rows.some(row => row.kind === 'offline-metadata-imported-held' && row.reference_id === opened.statement.metadataHash && row.operation_id === null)) throw new Error('Authenticated import journal binding missing');
      continue;
    }
    for (const original of expected) {
      const found = rows.find(row => key(table, row) === key(table, original));
      if (!found) throw new Error('Authenticated restored metadata was removed');
      // Read-only reconciler may append evidence and resolve an old intent; it still confers no fresh issuer proof.
      if (table === 'intent' && original.state === 'unknown' && found.state === 'observed') {
        if (!equal({ ...found, state: 'unknown' }, original)) throw new Error('Restored intent scope was altered');
        const appendedReconciliation = current.tables.receipt.some(receipt => receipt.intent_id === found.intent_id && !opened.metadata.tables.receipt.some(originalReceipt => originalReceipt.receipt_id === receipt.receipt_id) && JSON.parse(String(receipt.metadata)).kind === 'reconciliation' && JSON.parse(String(receipt.metadata)).outcome === 'confirmed');
        const appendedEngineObservation = current.tables.engine_receipt.some(receipt => receipt.intent_id === found.intent_id && !opened.metadata.tables.engine_receipt.some(originalReceipt => originalReceipt.receipt_id === receipt.receipt_id) && !['unknown', 'orphan-unresolved', 'unverified'].includes(String(JSON.parse(String(receipt.metadata)).outcome)));
        if (!appendedReconciliation && !appendedEngineObservation) throw new Error('Observed restored intent lacks appended reconciliation history');
        postImportEvidence = true;
      } else if (!equal(found, original)) throw new Error('Authenticated restored metadata was altered');
    }
    const extra = rows.filter(row => !expected.some(original => key(table, row) === key(table, original)));
    if (extra.length && !['receipt', 'engine_receipt'].includes(table)) throw new Error('Unbound restored authority or security metadata');
    for (const row of extra) {
      if (!current.tables.intent.some(intent => intent.intent_id === row.intent_id)) throw new Error('Post-import receipt has no archived intent');
      postImportEvidence = true;
    }
  }
  for (const [table, rows] of Object.entries(opened.metadata.additionalTables)) {
    if (table === 'controller_runtime') {
      if (!equal(current.additionalTables[table], [{ id: 'runtime', metadata: canonicalJSON({ mode: 'real' }) }])) throw new Error('Recovered controller cannot resume demo authority');
    } else if (!equal(current.additionalTables[table], rows)) throw new Error('Registered restored metadata scope changed');
  }
  // Historical emergency enrollment is not an independently held recovery pin, and cannot be made live locally.
  journal.read(db => {
    for (const table of ['emergency_credential', 'emergency_challenge', 'emergency_proof', 'emergency_reservation']) if (db.prepare(`SELECT 1 FROM ${table} LIMIT 1`).get()) throw new Error('Restored controller contains unbound emergency authority');
  });
  let observedEpoch: import('../installation-epoch.js').EpochRecord | undefined;
  if (input.epochStore) {
    observedEpoch = await input.epochStore.read();
    if (!observedEpoch || !Number.isSafeInteger(observedEpoch.version) || observedEpoch.version < 1 || ![opened.statement.installationId, journal.installationId].includes(observedEpoch.installationId)) throw new Error('Actual shared recovery epoch no longer matches archive or held installation');
    recoveryId(observedEpoch.ownerId);
  }
  if (journal.read(db => db.prepare('SELECT recovery_hold FROM controller').get()?.recovery_hold) !== 1) throw new Error('Recovery hold changed during independent reauthentication');
  // New process, new ceremony: persisted proof flags cannot authorize a replacement phone.
  journal.transaction(db => {
    if (current.tableInventory.some(table => table.name === 'recovery_ceremony')) db.exec('UPDATE recovery_ceremony SET used=1,verified=0');
    journal.audit(db, 'offline-recovery-reauthenticated', null, opened.statement.metadataHash);
  });
  const imported = Object.freeze({ journal, opened, report: deepFreeze({ installationId: journal.installationId, bootId: journal.bootId, sourceInstallationId: opened.statement.installationId, metadataHash: opened.statement.metadataHash, coverageComplete: provenance.coverageComplete, excludedTables: [...provenance.excludedTables], recoveryHeld: true, unresolvedIntentIds: current.tables.intent.filter(row => row.state !== 'observed').map(row => String(row.intent_id)), limitations: ['offline-material-reauthenticated-existing-held-installation', 'prior-process-ceremony-authority-invalidated', 'fresh-store-issuer-and-predecessor-observations-required', ...(observedEpoch ? ['shared-epoch-read-does-not-quiesce-predecessor'] : ['actual-shared-store-epoch-unverified']), ...(postImportEvidence ? ['post-import-receipts-remain-historical-until-fresh-independent-observation'] : []), 'physical-four-machine-recovery-unverified'] } as RecoveryReport) });
  importedRecoveries.add(imported);
  return imported;
}
