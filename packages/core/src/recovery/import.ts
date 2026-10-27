import { randomUUID } from 'node:crypto';
import { chmodSync, closeSync, mkdirSync, openSync, rmSync } from 'node:fs';
import { dirname, isAbsolute } from 'node:path';
import { deepFreeze } from '../manifest.js';
import { Journal } from '../journal.js';
import { assertOpenedArchive, recoveryTables, uncoveredRecoveryTables, type OpenedRecoveryArchive, type RecoveryTable } from './export.js';

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
    current.transaction(db => {
      db.exec('DELETE FROM audit');
      db.exec("CREATE TABLE oauth_schema (singleton INTEGER PRIMARY KEY CHECK(singleton=1), version INTEGER NOT NULL); INSERT INTO oauth_schema VALUES(1,2); CREATE TABLE oauth_family (grant_id TEXT PRIMARY KEY, family_id TEXT NOT NULL UNIQUE, owner_id TEXT NOT NULL, version INTEGER NOT NULL, state TEXT NOT NULL CHECK(state IN ('active','refreshing','reconcile-required','revoking','revoked','consenting','reconciling')), boot_id TEXT NOT NULL, access_expires_at INTEGER NOT NULL, pending_intent_id TEXT, pending_operation_id TEXT);");
      db.exec('CREATE TABLE engine_schema (singleton INTEGER PRIMARY KEY CHECK(singleton=1), version INTEGER NOT NULL); INSERT INTO engine_schema VALUES(1,1); CREATE TABLE engine_operation (operation_id TEXT PRIMARY KEY REFERENCES operation(operation_id), holds TEXT NOT NULL, deadline TEXT NOT NULL); CREATE TABLE engine_receipt (receipt_id TEXT PRIMARY KEY, operation_id TEXT NOT NULL REFERENCES operation(operation_id), intent_id TEXT REFERENCES intent(intent_id), metadata TEXT NOT NULL);');
      for (const table of Object.keys(recoveryTables) as RecoveryTable[]) {
        const columns = recoveryTables[table];
        const insert = db.prepare(`INSERT INTO ${table}(${columns.join(',')}) VALUES(${columns.map(() => '?').join(',')})`);
        for (const row of input.opened.metadata.tables[table]) insert.run(...columns.map(column => row[column]!));
      }
      // Restored archive signatures prove history only. No historical signer/grant/session becomes live authority.
      db.exec("UPDATE approver SET revoked=1; UPDATE approval_grant SET cancelled=1; UPDATE session_revocation SET revoked=1; UPDATE operation SET state='reconcile-required' WHERE state!='completed'; UPDATE intent SET state='unknown' WHERE state='pending'; UPDATE oauth_family SET state='reconcile-required' WHERE state!='revoked';");
      current.audit(db, 'offline-metadata-imported-held', null, input.opened.statement.metadataHash);
    });
    chmodSync(input.destination, 0o600);
    for (const suffix of ['-wal', '-shm']) {
      try { chmodSync(input.destination + suffix, 0o600); } catch { /* SQLite may not have produced the sidecar. */ }
    }
    const unresolvedIntentIds = current.read(db => db.prepare("SELECT intent_id FROM intent WHERE state!='observed' ORDER BY intent_id").all().map(row => String(row.intent_id)));
    const imported = Object.freeze({ journal: current, opened: input.opened, report: deepFreeze( { installationId: current.installationId, bootId: current.bootId, sourceInstallationId: input.opened.statement.installationId, metadataHash: input.opened.statement.metadataHash, coverageComplete: uncoveredRecoveryTables(input.opened).length === 0, excludedTables: uncoveredRecoveryTables(input.opened), recoveryHeld: true, unresolvedIntentIds, limitations: ['archive-coverage-U3-U4-U7-only', 'scheduler-state-not-included', 'metadata-only-not-store-value-recovery', 'encrypted-existing-store-backup-required', 'issuer-native-clean-device-access-required', 'all-imported-authority-invalidated', 'dashboard-and-read-sessions-invalidated', 'physical-four-machine-recovery-unverified'] } as RecoveryReport) });
    importedRecoveries.add(imported);
    return imported;
  } catch {
    journal?.close();
    for (const suffix of ['', '-wal', '-shm']) rmSync(input.destination + suffix, { force: true });
    throw new Error('Recovery import rejected; no active restored controller');
  }
}
