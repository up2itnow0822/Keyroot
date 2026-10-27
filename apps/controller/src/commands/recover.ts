import { constants, closeSync, fstatSync, openSync, readSync, lstatSync, mkdtempSync, writeFileSync, renameSync, rmSync, fsyncSync, realpathSync } from 'node:fs';
import { dirname, isAbsolute, resolve, join, relative, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createPrivateKey, createPublicKey, sign } from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';
import { publicKeyFingerprint } from '../../../../packages/core/src/approval.js';
import type { InstallationEpochStore } from '../../../../packages/core/src/installation-epoch.js';
import { canonicalJSON } from '../../../../packages/core/src/manifest.js';
import { Journal } from '../../../../packages/core/src/journal.js';
import { BootFence } from '../../../../packages/core/src/boot-fence.js';
import { exportRecoveryArchive, openRecoveryArchive, type AdditionalRecoverySchemaRegistry, type VerificationPin, type MetadataRow } from '../../../../packages/core/src/recovery/export.js';
import { importRecoveryArchive, reauthenticateImportedRecovery, type ImportedRecovery, type RecoveryReport } from '../../../../packages/core/src/recovery/import.js';
import { controllerSchema, initializeControllerSchema, validateControllerRow, type ControllerTable } from '../metadata.js';

/** Code-registered schema and semantic validators. An archive cannot register a table or construct SQL. */
export const controllerRecoverySchemaRegistry: AdditionalRecoverySchemaRegistry = Object.freeze({
  id: 'keyroot.controller-metadata.v1', schema: controllerSchema,
  validateRow: (table: string, row: MetadataRow) => validateControllerRow(table as ControllerTable, row),
  initialize: initializeControllerSchema,
  afterImport: (journal: Journal) => journal.transaction(db => {
    db.prepare("INSERT INTO controller_runtime VALUES('runtime',?) ON CONFLICT(id) DO UPDATE SET metadata=excluded.metadata").run(canonicalJSON({ mode: 'real' }));
  }),
});
export interface RecoverFileOptions {
  archivePath: string;
  identityPath: string;
  verificationPinPath: string;
  /** Explicit new staging directory. Never the live controller database. */
  destinationDirectory: string;
  /** Same configured singleton socket used by the controller runtime. */
  controllerSocketPath: string;
  /** Trusted executor clock, not a CLI/HTTP assertion. */
  clock?: () => number;
}
export class RecoveryCommandError extends Error {
  readonly code = 'RECOVERY_IMPORT_DENIED';
  constructor() { super('Recovery import denied; verify private offline files, stopped controller, and a new staging directory.'); }
}
export const RECOVERY_IMPORTED_MARKER = 'recovery-imported.json';
export interface RecoveryImportedMarker {
  domain: 'keyroot.recovery-imported.v1'; version: 1; installationId: string; sourceInstallationId: string;
  metadataHash: string; coverageComplete: boolean; excludedTables: string[]; importedAt: number;
}
function assertAbsent(path: string): void {
  try { lstatSync(path); throw new RecoveryCommandError(); }
  catch (error) { if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error; }
}
function syncFile(path: string): void { const fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW); try { fsyncSync(fd); } finally { closeSync(fd); } }
const MAX_ARCHIVE = 8 * 1024 * 1024 + 65536;
function readPrivateFile(path: string, max: number): Buffer {
  if (!isAbsolute(path)) throw new RecoveryCommandError();
  const fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const stat = fstatSync(fd);
    if (!stat.isFile() || (stat.mode & 0o077) !== 0 || stat.nlink !== 1 || stat.size < 1 || stat.size > max || process.getuid && stat.uid !== process.getuid()) throw new RecoveryCommandError();
    const buffer = Buffer.alloc(stat.size);
    let offset = 0;
    while (offset < buffer.length) { const read = readSync(fd, buffer, offset, buffer.length - offset, offset); if (!read) throw new RecoveryCommandError(); offset += read; }
    const after = fstatSync(fd);
    if (after.size !== stat.size || after.mtimeMs !== stat.mtimeMs || after.ino !== stat.ino) throw new RecoveryCommandError();
    return buffer;
  } finally { closeSync(fd); }
}
function assertPrivateDirectory(path: string): void {
  const stat = lstatSync(path);
  if (!stat.isDirectory() || stat.isSymbolicLink() || (stat.mode & 0o077) !== 0 || process.getuid && stat.uid !== process.getuid()) throw new RecoveryCommandError();
}
/** Operator-only local workflow. This never activates restored credentials or synthesizes recovery observations. */
export async function recoverFromFiles(options: RecoverFileOptions): Promise<RecoveryReport> {
  let fence: BootFence | undefined;
  let identityBytes: Buffer | undefined;
  let pinBytes: Buffer | undefined;
  let stagingDirectory: string | undefined;
  try {
    for (const value of [options.archivePath, options.identityPath, options.verificationPinPath, options.destinationDirectory, options.controllerSocketPath]) if (!isAbsolute(value)) throw new RecoveryCommandError();
    // Exclusion happens before writing a target; acquiring a different/staged journal does not prove upstream quiescence.
    fence = await BootFence.acquire(options.controllerSocketPath);
    const archive = readPrivateFile(options.archivePath, MAX_ARCHIVE);
    identityBytes = readPrivateFile(options.identityPath, 4096);
    pinBytes = readPrivateFile(options.verificationPinPath, 16384);
    const identity = identityBytes.toString('utf8').trim();
    if (!/^AGE-SECRET-KEY-1[0-9A-Z]+$/.test(identity)) throw new RecoveryCommandError();
    const verification: VerificationPin = JSON.parse(pinBytes.toString('utf8')) as VerificationPin;
    const opened = await openRecoveryArchive({ archive, identity, verification, now: options.clock?.() ?? Date.now(), additionalSchemaRegistry: controllerRecoverySchemaRegistry });
    // Build a complete private installation beside the destination, then publish its directory atomically.
    const parent = dirname(options.destinationDirectory);
    assertPrivateDirectory(parent);
    assertAbsent(options.destinationDirectory);
    stagingDirectory = mkdtempSync(join(parent, '.keyroot-recovery-'));
    const imported = importRecoveryArchive({ opened, destination: join(stagingDirectory, 'journal.sqlite') });
    try {
      writeFileSync(join(stagingDirectory, 'installation-id'), imported.journal.installationId + '\n', { flag: 'wx', mode: 0o600 });
      const marker: RecoveryImportedMarker = { domain: 'keyroot.recovery-imported.v1', version: 1, installationId: imported.journal.installationId, sourceInstallationId: imported.report.sourceInstallationId, metadataHash: imported.report.metadataHash, coverageComplete: imported.report.coverageComplete, excludedTables: [...imported.report.excludedTables], importedAt: options.clock?.() ?? Date.now() };
      writeFileSync(join(stagingDirectory, 'runtime-mode'), 'real\n', { flag: 'wx', mode: 0o600 });
      writeFileSync(join(stagingDirectory, RECOVERY_IMPORTED_MARKER), JSON.stringify(marker) + '\n', { flag: 'wx', mode: 0o600 });
    } finally { imported.journal.close(); }
    for (const name of ['journal.sqlite', 'installation-id', 'runtime-mode', RECOVERY_IMPORTED_MARKER]) syncFile(join(stagingDirectory, name));
    syncFile(stagingDirectory);
    assertAbsent(options.destinationDirectory);
    renameSync(stagingDirectory, options.destinationDirectory);
    stagingDirectory = undefined; // Published installation is never removed by failure cleanup.
    syncFile(parent);
    return { ...imported.report, limitations: [...imported.report.limitations, 'controller-stopped-local-singleton-only', 'issuer-inflight-and-predecessor-management-authority-unverified', 'offline-import-process-capability-not-serialized', 'activation-requires-configured-recovery-coordinator', 'permanent-recovery-imported-marker-requires-authenticated-metadata-mode'] };
  } catch { throw new RecoveryCommandError(); }
  finally {
    identityBytes?.fill(0); pinBytes?.fill(0);
    if (stagingDirectory) rmSync(stagingDirectory, { recursive: true, force: true });
    if (fence) await fence.release().catch(() => undefined);
  }
}
export interface RecoverCLIIO { write(text: string): void; error(text: string): void }
/** main.ts forwards only this subcommand's argv here. Values are file paths; raw private keys are never CLI inputs. */
export async function runRecoverCLI(args: readonly string[], io: RecoverCLIIO = { write: text => process.stdout.write(text), error: text => process.stderr.write(text) }): Promise<number> {
  try {
    const flags = new Map<string, string>();
    const names = ['--archive', '--identity-file', '--verification-pin-file', '--destination-directory', '--controller-socket'];
    for (let index = 0; index < args.length; index += 2) {
      const name = args[index], value = args[index + 1];
      if (!name || !names.includes(name) || !value || value.startsWith('--') || flags.has(name)) throw new RecoveryCommandError();
      flags.set(name, value);
    }
    if (names.some(name => !flags.has(name))) throw new RecoveryCommandError();
    const report = await recoverFromFiles({ archivePath: flags.get('--archive')!, identityPath: flags.get('--identity-file')!, verificationPinPath: flags.get('--verification-pin-file')!, destinationDirectory: flags.get('--destination-directory')!, controllerSocketPath: flags.get('--controller-socket')! });
    io.write(JSON.stringify({ status: 'imported-held', report }) + '\n');
    return 0;
  } catch { io.error(JSON.stringify({ status: 'denied', code: 'RECOVERY_IMPORT_DENIED' }) + '\n'); return 1; }
}
export interface BackupFileOptions { sourceDirectory: string; recipientPath: string; signingKeyPath: string; archiveOutputPath: string; clock?: () => number }
export class BackupCommandError extends Error { readonly code = 'RECOVERY_BACKUP_DENIED'; constructor() { super('Recovery backup denied; verify stopped controller, independent private signing material and an exclusive output file.'); } }
/** Owner-controlled offline signing material never comes from the controller, an HTTP body or a command argument value. */
export async function exportFromFiles(options: BackupFileOptions): Promise<{ sourceInstallationId: string; sourceBootId: string; signerFingerprint: string; bytes: number; limitations: string[] }> {
  let fence: BootFence | undefined; let journal: Journal | undefined; let signingBytes: Buffer | undefined; let outputOwned = false;
  try {
    for (const path of [options.sourceDirectory, options.recipientPath, options.signingKeyPath, options.archiveOutputPath]) if (!isAbsolute(path)) throw new Error('Absolute operator paths required');
    assertPrivateDirectory(options.sourceDirectory);
    fence = await BootFence.acquire(join(options.sourceDirectory, 'boot.sock'));
    const sourceReal = realpathSync(options.sourceDirectory), keyReal = realpathSync(options.signingKeyPath);
    const keyRelative = relative(sourceReal, keyReal);
    if (keyRelative === '' || keyRelative !== '..' && !keyRelative.startsWith('..' + sep)) throw new Error('Signing key must be outside controller installation');
    const recipient = readPrivateFile(options.recipientPath, 4096).toString('utf8').trim();
    signingBytes = readPrivateFile(options.signingKeyPath, 16384);
    const privateKey = createPrivateKey(signingBytes);
    if (privateKey.asymmetricKeyType !== 'ec' || privateKey.asymmetricKeyDetails?.namedCurve !== 'prime256v1') throw new Error('Independent P256 export signer required');
    const signerFingerprint = publicKeyFingerprint(createPublicKey(privateKey).export({ format: 'jwk' }));
    const existing = readExistingJournalIdentity(options.sourceDirectory);
    journal = new Journal(join(options.sourceDirectory, 'journal.sqlite'), { installationId: existing.installationId, bootId: existing.bootId });
    const archive = await exportRecoveryArchive({ journal, recipient, now: options.clock?.() ?? Date.now(), signerFingerprint, additionalSchemaRegistry: controllerRecoverySchemaRegistry, sign: async statement => sign('sha256', statement, { key: privateKey, dsaEncoding: 'ieee-p1363' }).toString('base64url') });
    assertPrivateDirectory(dirname(options.archiveOutputPath));
    const fd = openSync(options.archiveOutputPath, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600); outputOwned = true;
    try { writeFileSync(fd, archive); fsyncSync(fd); } finally { closeSync(fd); }
    syncFile(dirname(options.archiveOutputPath)); outputOwned = false;
    return { sourceInstallationId: journal.installationId, sourceBootId: journal.bootId, signerFingerprint, bytes: archive.byteLength, limitations: ['metadata-only-existing-store-value-backup-separate', 'offline-signing-key-physical-independence-unverified', 'physical-four-machine-recovery-unverified'] };
  } catch { if (outputOwned) rmSync(options.archiveOutputPath, { force: true }); throw new BackupCommandError(); }
  finally { signingBytes?.fill(0); journal?.close(); if (fence) await fence.release().catch(() => undefined); }
}
function readExistingJournalIdentity(directory: string): { installationId: string; bootId: string; recoveryHeld: boolean } {
  const path = join(directory, 'journal.sqlite');
  const fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  try { const stat = fstatSync(fd); if (!stat.isFile() || (stat.mode & 0o077) !== 0 || stat.nlink !== 1 || process.getuid && stat.uid !== process.getuid()) throw new Error('Private existing journal required'); } finally { closeSync(fd); }
  const db = new DatabaseSync(path, { readOnly: true });
  try {
    const row = db.prepare('SELECT installation_id,boot_id,recovery_hold FROM controller WHERE singleton=1').get();
    const installationId = readPrivateFile(join(directory, 'installation-id'), 1024).toString('utf8').trim();
    if (!row || row.installation_id !== installationId || typeof row.boot_id !== 'string') throw new Error('Existing installation identity mismatch');
    return { installationId, bootId: row.boot_id, recoveryHeld: row.recovery_hold === 1 };
  } finally { db.close(); }
}
export interface ResumeFileOptions { archivePath: string; identityPath: string; verificationPinPath: string; directory: string; clock?: () => number; epochStore?: InstallationEpochStore }
export interface HeldRecoverySession { readonly imported: ImportedRecovery; close(): Promise<void> }
/** Every resumed process must decrypt again. The returned capability is never serialized in a report or reconstructed from flags. */
export async function openExistingHeldRecovery(options: ResumeFileOptions): Promise<HeldRecoverySession> {
  let fence: BootFence | undefined; let journal: Journal | undefined; let identityBytes: Buffer | undefined; let pinBytes: Buffer | undefined;
  try {
    for (const path of [options.archivePath, options.identityPath, options.verificationPinPath, options.directory]) if (!isAbsolute(path)) throw new Error('Absolute operator paths required');
    assertPrivateDirectory(options.directory);
    fence = await BootFence.acquire(join(options.directory, 'boot.sock'));
    const archive = readPrivateFile(options.archivePath, MAX_ARCHIVE);
    identityBytes = readPrivateFile(options.identityPath, 4096); pinBytes = readPrivateFile(options.verificationPinPath, 16384);
    const identity = identityBytes.toString('utf8').trim(); const verification = JSON.parse(pinBytes.toString('utf8')) as VerificationPin;
    const opened = await openRecoveryArchive({ archive, identity, verification, now: options.clock?.() ?? Date.now(), additionalSchemaRegistry: controllerRecoverySchemaRegistry });
    if (readPrivateFile(join(options.directory, 'runtime-mode'), 64).toString('utf8') !== 'real\n') throw new Error('Recovered runtime must remain real');
    const provenance = JSON.parse(readPrivateFile(join(options.directory, RECOVERY_IMPORTED_MARKER), 16384).toString('utf8')) as RecoveryImportedMarker;
    const existing = readExistingJournalIdentity(options.directory);
    if (!existing.recoveryHeld || existing.installationId === opened.statement.installationId || provenance.installationId !== existing.installationId || provenance.metadataHash !== opened.statement.metadataHash || provenance.sourceInstallationId !== opened.statement.installationId) throw new Error('Held installation/archive provenance mismatch');
    journal = new Journal(join(options.directory, 'journal.sqlite'), { installationId: existing.installationId, bootId: existing.bootId });
    const imported = await reauthenticateImportedRecovery({ opened, journal, provenance, ...(options.epochStore ? { epochStore: options.epochStore } : {}) });
    const ownedJournal = journal, ownedFence = fence; journal = undefined; fence = undefined;
    let closed = false;
    return Object.freeze({ imported, close: async () => { if (closed) return; closed = true; ownedJournal.close(); await ownedFence.release(); } });
  } catch { throw new RecoveryCommandError(); }
  finally { identityBytes?.fill(0); pinBytes?.fill(0); journal?.close(); if (fence) await fence.release().catch(() => undefined); }
}
function parseOperatorFlags(args: readonly string[], names: readonly string[]): Map<string, string> {
  const flags = new Map<string, string>();
  for (let i = 0; i < args.length; i += 2) { const name = args[i], value = args[i + 1]; if (!name || !names.includes(name) || !value || value.startsWith('--') || flags.has(name)) throw new RecoveryCommandError(); flags.set(name, value); }
  if (names.some(name => !flags.has(name))) throw new RecoveryCommandError(); return flags;
}
export async function runBackupCLI(args: readonly string[], io: RecoverCLIIO = { write: text => process.stdout.write(text), error: text => process.stderr.write(text) }): Promise<number> {
  try {
    const flags = parseOperatorFlags(args, ['--source-directory', '--recipient-file', '--signing-key-file', '--output']);
    const report = await exportFromFiles({ sourceDirectory: flags.get('--source-directory')!, recipientPath: flags.get('--recipient-file')!, signingKeyPath: flags.get('--signing-key-file')!, archiveOutputPath: flags.get('--output')! });
    io.write(JSON.stringify({ status: 'backup-exported', report }) + '\n'); return 0;
  } catch { io.error(JSON.stringify({ status: 'denied', code: 'RECOVERY_BACKUP_DENIED' }) + '\n'); return 1; }
}
export async function runResumeCLI(args: readonly string[], io: RecoverCLIIO = { write: text => process.stdout.write(text), error: text => process.stderr.write(text) }): Promise<number> {
  let session: HeldRecoverySession | undefined;
  try {
    const flags = parseOperatorFlags(args, ['--archive', '--identity-file', '--verification-pin-file', '--directory']);
    session = await openExistingHeldRecovery({ archivePath: flags.get('--archive')!, identityPath: flags.get('--identity-file')!, verificationPinPath: flags.get('--verification-pin-file')!, directory: flags.get('--directory')! });
    io.write(JSON.stringify({ status: 'reauthenticated-held', report: session.imported.report }) + '\n'); return 0;
  } catch { io.error(JSON.stringify({ status: 'denied', code: 'RECOVERY_IMPORT_DENIED' }) + '\n'); return 1; }
  finally { if (session) await session.close().catch(() => undefined); }
}
// Supports direct execution after the plain Node build, as well as forwarding from the owning CLI.
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) process.exitCode = process.argv[2] === 'backup' ? await runBackupCLI(process.argv.slice(3)) : process.argv[2] === 'resume' ? await runResumeCLI(process.argv.slice(3)) : await runRecoverCLI(process.argv.slice(2));
