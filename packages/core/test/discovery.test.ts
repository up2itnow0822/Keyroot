import { test } from 'node:test';
import { strict as assert } from 'node:assert';
import { mkdtemp, writeFile, rm, realpath } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { scanLocalSources } from '../src/discovery/scanner.js';
import { scanPlatforms } from '../src/discovery/platform.js';

test('local discovery returns names and provenance without values or writes', async () => {
  const dir = await realpath(await mkdtemp(join(tmpdir(), 'keyroot-discovery-')));
  try {
    const path = join(dir, '.env');
    await writeFile(path, 'API_KEY=sentinel-secret\n');
    const result = await scanLocalSources({ roots: [dir], sources: [{ path, kind: 'env', consumerId: 'app' }] });
    assert.equal(result.bindings[0]?.name, 'API_KEY');
    assert.equal(result.bindings[0]?.provenance, 'inferred');
    assert.ok(!JSON.stringify(result).includes('sentinel-secret'));
  } finally { await rm(dir, { recursive: true, force: true }); }
});

test('platform failures remain unscanned and redact errors', async () => {
  const result = await scanPlatforms([{ id: 'ci', scan: async () => { throw new Error('sentinel-secret'); } }]);
  assert.equal(result.gaps[0]?.status, 'unscanned');
  assert.ok(!JSON.stringify(result).includes('sentinel-secret'));
});

test('symlink, oversized, unplaced, and unreadable sources are explicit gaps', async () => {
  const { symlink, readFile } = await import('node:fs/promises');
  const dir = await realpath(await mkdtemp(join(tmpdir(), 'keyroot-discovery-')));
  try {
    const env = join(dir, '.env'); const alias = join(dir, 'alias');
    await writeFile(env, 'TOKEN=sentinel-secret\n');
    await symlink(env, alias);
    const before = await readFile(env, 'utf8');
    const result = await scanLocalSources({ roots: [dir], maxBytes: 32, sources: [
      { path: env, kind: 'env' }, { path: alias, kind: 'env' }, { path: join(dir, 'missing'), kind: 'env' },
    ] });
    assert.deepEqual(result.gaps.map(g => g.status), ['unplaced', 'unscanned', 'unreadable']);
    assert.equal(await readFile(env, 'utf8'), before);
    const oversized = await scanLocalSources({ roots: [dir], maxBytes: 4, sources: [{ path: env, kind: 'env' }] });
    assert.equal(oversized.gaps[0]?.status, 'unscanned');
    assert.ok(!JSON.stringify(result).includes('sentinel-secret'));
  } finally { await rm(dir, { recursive: true, force: true }); }
});

test('encrypted CI metadata stays unreadable and provider output is sanitized', async () => {
  const result = await scanPlatforms([{ id: 'ci', scan: async () => ({ bindings: [], gaps: [{ sourceId: 'ci/secret', status: 'unreadable', reason: 'sentinel-secret' }] }) }]);
  assert.equal(result.gaps[0]?.status, 'unreadable');
  assert.ok(!JSON.stringify(result).includes('sentinel-secret'));
});


test('unavailable root remains a gap without suppressing other roots', async () => {
  const dir = await realpath(await mkdtemp(join(tmpdir(), 'keyroot-discovery-')));
  try {
    const env = join(dir, '.env'); const missing = join(dir, 'missing-root');
    await writeFile(env, 'TOKEN=sentinel-secret\n');
    const result = await scanLocalSources({ roots: [missing, dir], sources: [{ path: env, kind: 'env', consumerId: 'app' }] });
    assert.equal(result.bindings[0]?.name, 'TOKEN');
    assert.ok(result.gaps.some(g => g.sourceId === missing && g.status === 'unscanned'));
  } finally { await rm(dir, { recursive: true, force: true }); }
});
