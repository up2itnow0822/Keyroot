import { constants } from 'node:fs';
import { lstat, open, realpath } from 'node:fs/promises';
import { dirname, isAbsolute, resolve, sep } from 'node:path';
import { createEnvFileConsumer, fileDigest, type EnvFileDescriptor, type EnvBackupPort } from '../../../../packages/core/src/consumers/env-file.js';
import type { ConsumerStorePort } from '../../../../packages/core/src/adapters/store.js';
import { HttpFailure } from '../auth.js';
export interface EnvMaintenanceTarget { id: string; descriptor: EnvFileDescriptor; roots: Readonly<Record<string, string>>; store: ConsumerStorePort; backup: EnvBackupPort }
/** Installs U6's actual file/vault executor with its own symlink, CAS, grammar and rollback verification. */
export { createEnvFileConsumer };
export async function inspectEnvTarget(target: EnvMaintenanceTarget): Promise<{ outcome: 'matched' | 'changed'; targetId: string; limitationCodes: string[] }> {
  const d = target.descriptor; const root = target.roots[d.rootId];
  if (!root || !isAbsolute(root) || resolve(root) !== root || isAbsolute(d.relativePath) || d.relativePath.split(/[\\/]/).some(p => !p || p === '.' || p === '..')) throw new HttpFailure(503, 'env_target_unavailable');
  const path = resolve(root, d.relativePath); if (!path.startsWith(root + sep) || await realpath(root) !== root || await realpath(dirname(path)) !== dirname(path)) throw new HttpFailure(503, 'env_target_unavailable');
  const info = await lstat(path); if (!info.isFile() || info.isSymbolicLink() || info.nlink !== 1 || info.size > 1024 * 1024) throw new HttpFailure(503, 'env_target_unavailable');
  const handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  try { const pinned = await handle.stat(); if (!pinned.isFile() || pinned.dev !== info.dev || pinned.ino !== info.ino || pinned.size > 1024 * 1024) throw new HttpFailure(503, 'env_target_unavailable'); const bytes = await handle.readFile(); if (bytes.length > 1024 * 1024) throw new HttpFailure(503, 'env_target_unavailable'); return { outcome: fileDigest(bytes) === d.expectedFileHash ? 'matched' : 'changed', targetId: target.id, limitationCodes: ['file-metadata-only', 'no-successor-adoption-claim'] }; } finally { await handle.close(); }
}
