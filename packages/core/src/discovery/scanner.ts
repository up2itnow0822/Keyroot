import { open, realpath } from 'node:fs/promises';
import { constants } from 'node:fs';
import { isAbsolute, relative, resolve, sep } from 'node:path';

export type Provenance = 'declared' | 'inferred' | 'observed';
export interface Binding { sourceId: string; name: string; consumerId?: string; provenance: Provenance }
export interface Gap { sourceId: string; status: 'unreadable' | 'unscanned' | 'unplaced'; reason: string }
export interface DiscoveryResult { bindings: Binding[]; gaps: Gap[] }
export interface LocalSource { path: string; kind: 'env' | 'agent-config'; consumerId?: string }
const safeName = /^[A-Za-z_][A-Za-z0-9_]{0,127}$/;
const within = (root: string, file: string) => { const r = relative(root, file); return r !== '' && !isAbsolute(r) && r !== '..' && !r.startsWith('..' + sep); };

/** Metadata-only read. Source paths and roots are trusted local configuration, never file content. */
export async function scanLocalSources(input: { roots: string[]; sources: LocalSource[]; maxBytes?: number }): Promise<DiscoveryResult> {
  const result: DiscoveryResult = { bindings: [], gaps: [] };
  const limit = input.maxBytes ?? 1024 * 1024;
  if (!Number.isSafeInteger(limit) || limit < 1 || limit > 1024 * 1024) throw new Error('Invalid discovery size limit');
  const roots: string[] = [];
  for (const configured of input.roots) {
    const sourceId = resolve(configured);
    try { roots.push(await realpath(sourceId)); }
    catch { result.gaps.push({ sourceId, status: 'unscanned', reason: 'configured root unavailable' }); }
  }
  for (const source of input.sources) {
    const sourceId = resolve(source.path);
    if (!roots.some(root => within(root, sourceId))) { result.gaps.push({ sourceId, status: 'unscanned', reason: 'outside allowlist' }); continue; }
    try {
      // Resolve every component, disallowing symlinks even when their target stays inside the root.
      if (await realpath(sourceId) !== sourceId) { result.gaps.push({ sourceId, status: 'unscanned', reason: 'symlink path' }); continue; }
      const file = await open(sourceId, constants.O_RDONLY | constants.O_NOFOLLOW);
      try {
        const stat = await file.stat();
        if (!stat.isFile() || stat.size > limit) { result.gaps.push({ sourceId, status: 'unscanned', reason: 'not a bounded regular file' }); continue; }
        const bytes = Buffer.alloc(limit + 1);
        const { bytesRead } = await file.read(bytes, 0, bytes.length, 0);
        if (bytesRead > limit) { result.gaps.push({ sourceId, status: 'unscanned', reason: 'file exceeds size limit' }); continue; }
        const text = bytes.subarray(0, bytesRead).toString('utf8');
        const names: string[] = [];
        if (source.kind === 'env') {
          for (const line of text.split(/\r?\n/)) { const match = /^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=/.exec(line); if (match && safeName.test(match[1]!)) names.push(match[1]!); }
        } else {
          const json: unknown = JSON.parse(text);
          if (typeof json !== 'object' || json === null || Array.isArray(json)) throw new Error('Invalid configuration');
          const env = (json as Record<string, unknown>).env;
          if (typeof env === 'object' && env !== null && !Array.isArray(env)) names.push(...Object.keys(env).filter(name => safeName.test(name)));
        }
        for (const name of new Set(names)) result.bindings.push({ sourceId, name, ...(source.consumerId ? { consumerId: source.consumerId } : {}), provenance: 'inferred' });
        if (!source.consumerId) result.gaps.push({ sourceId, status: 'unplaced', reason: 'consumer association unknown' });
      } finally { await file.close(); }
    } catch { result.gaps.push({ sourceId, status: 'unreadable', reason: 'source unavailable or invalid' }); }
  }
  return result;
}
