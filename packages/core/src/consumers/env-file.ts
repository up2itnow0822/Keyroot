import { createHash, randomUUID } from 'node:crypto';
import { constants } from 'node:fs';
import { lstat, open, realpath, rename, unlink } from 'node:fs/promises';
import { parseEnv } from 'node:util';
import { dirname, isAbsolute, join, resolve, sep } from 'node:path';
import type { ConsumerStorePort, StoreWriteResult } from '../adapters/store.js';
import type { AuthorizedIntent } from '../journal.js';
import type { EffectContext } from '../engine.js';
import { assertConsumerIntent, beforeConsumerEffect, ConsumerRefusal, deliveryReceipt, pinDescriptor, type ConsumerDescriptor, type ConsumerDriver, type ConsumerTrust } from './consumer.js';

export interface EnvFileDescriptor extends ConsumerDescriptor {
  driver: 'env-file';
  mode: 'deliver' | 'rollback';
  envFormat: 'node-env';
  rootId: string;
  relativePath: string;
  variable: string;
  expectedFileHash: string;
  backupHandle: string;
  backupExpectedVersion: number;
  backupVersion: number;
  /** Required on rollback: exact hash of restored bytes, independent of current revision. */
  backupFileHash?: string;
}
/** Narrow trusted existing-vault capability; encryption and storage belong to the existing vault. */
export interface EnvBackupPort extends ConsumerStorePort {
  write(handle: string, expectedVersion: number, value: string): Promise<StoreWriteResult>;
}
export function fileDigest(bytes: Uint8Array): string { return `sha256:${createHash('sha256').update(bytes).digest('hex')}`; }
const maxFileBytes = 1024 * 1024;
const digest = (s: string) => /^sha256:[a-f0-9]{64}$/.test(s);

export function createEnvFileConsumer(config: { descriptor: EnvFileDescriptor; roots: Readonly<Record<string, string>>; store: ConsumerStorePort; backup: EnvBackupPort; trust: ConsumerTrust }): ConsumerDriver {
  const d = pinDescriptor(config.descriptor, ['mode', 'envFormat', 'rootId', 'relativePath', 'variable', 'expectedFileHash', 'backupHandle', 'backupExpectedVersion', 'backupVersion', 'backupFileHash']);
  const configuredRoot = config.roots[d.rootId];
  if (!configuredRoot || !isAbsolute(configuredRoot) || resolve(configuredRoot) !== configuredRoot || d.driver !== 'env-file' || d.envFormat !== 'node-env' || !['deliver', 'rollback'].includes(d.mode) || !/^[A-Z_][A-Z0-9_]{0,127}$/.test(d.variable) || !digest(d.expectedFileHash) || !Number.isSafeInteger(d.backupExpectedVersion) || d.backupExpectedVersion < 0 || d.backupVersion !== d.backupExpectedVersion + 1 || !/^[-a-zA-Z0-9_./]{1,256}$/.test(d.backupHandle) || isAbsolute(d.relativePath) || d.relativePath.split(/[\\/]/).some(p => !p || p === '.' || p === '..') || (d.mode === 'rollback' && (!d.backupFileHash || !digest(d.backupFileHash)))) throw new ConsumerRefusal();
  const root = configuredRoot; const destination = resolve(root, d.relativePath);
  if (!destination.startsWith(root + sep)) throw new ConsumerRefusal();
  const parent = dirname(destination);
  async function safePath(): Promise<void> {
    if (await realpath(root) !== root) throw new ConsumerRefusal();
    const parts = d.relativePath.split('/'); parts.pop();
    let path = root;
    for (const part of ['', ...parts]) {
      if (part) path = join(path, part);
      const info = await lstat(path);
      if (!info.isDirectory() || info.isSymbolicLink() || (info.mode & 0o022) !== 0 || process.getuid && info.uid !== process.getuid()) throw new ConsumerRefusal();
    }
  }
  async function readCurrent(): Promise<Buffer> {
    await safePath();
    const handle = await open(destination, constants.O_RDONLY | constants.O_NOFOLLOW);
    try { const info = await handle.stat(); if (!info.isFile() || info.nlink !== 1 || info.size > maxFileBytes) throw new ConsumerRefusal(); const bytes = await handle.readFile(); if (bytes.length > maxFileBytes || fileDigest(bytes) !== d.expectedFileHash) throw new ConsumerRefusal(); return bytes; } finally { await handle.close(); }
  }
  function replacement(original: Buffer, value: string): Buffer {
    if (value.includes('\0')) throw new ConsumerRefusal();
    const text = original.toString('utf8');
    if (!Buffer.from(text).equals(original)) throw new ConsumerRefusal();
    // The signed format is Node's env-file grammar. Prove literal roundtrip before touching disk.
    const candidates = ['"' + value + '"', "'" + value + "'", '`' + value + '`', value];
    const encoded = candidates.find(candidate => {
      try { return parseEnv(`${d.variable}=${candidate}\n`)[d.variable] === value; } catch { return false; }
    });
    if (encoded === undefined) throw new ConsumerRefusal();
    const eol = text.includes('\r\n') ? '\r\n' : '\n';
    const entry = `${d.variable}=${encoded}`;
    let replaced = false; let offset = 0; let next = '';
    const lineEnd = (start: number) => { const at = text.slice(start).search(/[\r\n]/); return at < 0 ? text.length : start + at; };
    while (offset < text.length) {
      let end = lineEnd(offset);
      const line = text.slice(offset, end);
      const assignment = /^\s*(?:export\s+)?([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*/.exec(line);
      if (assignment) {
        const valueAt = offset + assignment[0].length; const quote = text[valueAt];
        if (quote === '"' || quote === "'" || quote === '`') {
          const closing = text.indexOf(quote, valueAt + 1); if (closing < 0) throw new ConsumerRefusal();
          end = lineEnd(closing + 1);
        }
      }
      const ending = text.startsWith('\r\n', end) ? '\r\n' : end < text.length ? text[end] ?? '' : '';
      const after = end + ending.length;
      if (assignment?.[1] === d.variable) { if (!replaced) next += entry + ending; replaced = true; }
      else next += text.slice(offset, after);
      offset = after;
    }
    if (!replaced) next = text + (text.length && !/[\r\n]$/.test(text) ? eol : '') + entry + eol;
    const before = parseEnv(text); const after = parseEnv(next);
    if (after[d.variable] !== value || Object.keys(before).some(key => key !== d.variable && before[key] !== after[key]) || Object.keys(after).some(key => key !== d.variable && !(key in before))) throw new ConsumerRefusal();
    const result = Buffer.from(next); if (result.length > maxFileBytes) throw new ConsumerRefusal(); return result;
  }

  return {
    async deliver(intent: AuthorizedIntent, context: EffectContext) {
      let temp: string | undefined; let renamed = false; let backupStarted = false;
      try {
        assertConsumerIntent(intent, d, context);
        const current = await readCurrent();
        let next: Buffer | undefined;
        if (d.mode === 'deliver') {
          const result = await config.store.withValue(d.handleId, d.version, async value => { next = replacement(current, value); });
          if (result.status !== 'resolved' || !next) throw new ConsumerRefusal();
          await beforeConsumerEffect(intent, d, context, config.trust, 'env-backup');
          // Recheck the approved bytes immediately before backing them up.
          await readCurrent();
          backupStarted = true;
          const saved = await config.backup.write(d.backupHandle, d.backupExpectedVersion, current.toString('base64'));
          if (saved.status !== 'written' || saved.version !== d.backupVersion) return deliveryReceipt(context, config.trust, d, 'unknown', ['backup-reconciliation-required']);
        } else {
          const result = await config.backup.withValue(d.backupHandle, d.backupVersion, async value => {
            if (value.length > Math.ceil(maxFileBytes / 3) * 4 || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)) throw new ConsumerRefusal();
            next = Buffer.from(value, 'base64'); if (fileDigest(next) !== d.backupFileHash || next.length > maxFileBytes) throw new ConsumerRefusal();
          });
          if (result.status !== 'resolved' || !next) throw new ConsumerRefusal();
        }
        await beforeConsumerEffect(intent, d, context, config.trust, 'env-temp-write');
        await safePath();
        temp = join(parent, `.keyroot-${randomUUID()}.tmp`);
        const handle = await open(temp, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
        try { await handle.chmod(0o600); await handle.writeFile(next); await handle.sync(); } finally { await handle.close(); }
        await readCurrent();
        await beforeConsumerEffect(intent, d, context, config.trust, 'env-rename');
        await readCurrent();
        await rename(temp, destination); renamed = true; temp = undefined;
        const directory = await open(parent, constants.O_RDONLY | constants.O_NOFOLLOW);
        try { await directory.sync(); } finally { await directory.close(); }
        if (d.mode === 'rollback') return deliveryReceipt(context, config.trust, d, 'unknown', ['authorized-rollback-applied', 'restored-backup-handle', d.backupHandle, `restored-backup-version:${d.backupVersion}`, 'successor-delivery-unverified', 'local-file-only']);
        return deliveryReceipt(context, config.trust, d, 'delivery-accepted', ['local-file-only', 'node-env-grammar', 'unmanaged-copies-uncontrolled']);
      } catch (error) {
        return deliveryReceipt(context, config.trust, d, renamed ? 'unknown' : error instanceof ConsumerRefusal ? 'rejected' : backupStarted ? 'unknown' : 'rejected', renamed ? ['partial-delivery', 'fresh-rollback-authority-required'] : backupStarted ? ['backup-may-exist', 'original-file-preserved'] : ['original-file-preserved']);
      } finally { if (temp) { try { await unlink(temp); } catch { /* A failed cleanup never reveals local bytes or paths. */ } } }
    }
  };
}
