import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';

test('owning CLI forwards recovery and propagates a denied recovery exit status', () => {
  const result = spawnSync(process.execPath, ['--import', 'tsx', 'apps/controller/src/cli.ts', 'recover'], { encoding: 'utf8' });
  assert.equal(result.status, 1);
  assert.match(result.stderr, /RECOVERY_IMPORT_DENIED/);
  assert.equal(result.stdout, '');
});

test('owning CLI forwards offline backup and resume and retains refusal exit status', () => {
  for (const command of ['backup', 'recovery-resume']) {
    const result = spawnSync(process.execPath, ['--import', 'tsx', 'apps/controller/src/cli.ts', command], { encoding: 'utf8' });
    assert.equal(result.status, 1);
    assert.match(result.stderr, /DENIED/);
    assert.equal(result.stdout, '');
  }
});
