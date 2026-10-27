import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createThemeController, THEME_STORAGE_KEY, type ThemeChoice } from '../../apps/review/src/theme.js';

test('first visit follows system and future system changes until explicitly chosen', () => {
  const applied: string[] = [];
  const appearance = createThemeController({ storedChoice: null, systemDark: true, apply: value => applied.push(value) });
  assert.equal(appearance.choice, 'system');
  assert.equal(appearance.theme, 'dark');
  appearance.systemChanged(false);
  assert.equal(appearance.theme, 'light');
  appearance.choose('dark');
  appearance.systemChanged(false);
  assert.equal(appearance.theme, 'dark');
  appearance.choose('system');
  assert.equal(appearance.theme, 'light');
  assert.deepEqual(applied, ['dark', 'light', 'dark', 'light']);
});

test('explicit choice persists and reloads; unavailable storage still changes appearance', () => {
  let saved: string | null = null;
  const appearance = createThemeController({ storedChoice: null, systemDark: true, persist: value => { saved = value; } });
  appearance.choose('light');
  assert.equal(saved, 'light');
  assert.equal(createThemeController({ storedChoice: saved, systemDark: true }).theme, 'light');
  const blocked = createThemeController({ storedChoice: 'unexpected', systemDark: false, persist: () => { throw new Error('storage denied'); } });
  assert.doesNotThrow(() => blocked.choose('dark'));
  assert.equal(blocked.theme, 'dark');
  assert.equal(THEME_STORAGE_KEY, 'keyroot.theme');
});

test('appearance has no workflow state and cannot alter the selected draft or manifest', () => {
  const workflow = Object.freeze({ batch: 'weekly-2026-10-26', selected: 'openai-api', draft: 'reviewing', operation: 'waiting-for-approval', manifestBytes: 'sample-immutable-manifest' });
  const before = JSON.stringify(workflow);
  const appearance = createThemeController({ storedChoice: null, systemDark: false });
  for (const choice of ['dark', 'light', 'system'] satisfies ThemeChoice[]) appearance.choose(choice);
  assert.equal(JSON.stringify(workflow), before);
});

test('pre-paint initializer follows the same choice policy and tolerates blocked storage', async () => {
  const { readFile } = await import('node:fs/promises');
  const { runInNewContext } = await import('node:vm');
  const html = await readFile(new URL('../../apps/review/index.html', import.meta.url), 'utf8');
  const initializer = /<script>([\s\S]*?)<\/script>/.exec(html)?.[1];
  assert.ok(initializer, 'inline appearance initializer must run before module scripts');
  assert.ok(html.indexOf(initializer) < html.indexOf('type="module"'));
  for (const scenario of [
    { stored: null, dark: true, denied: false, expected: 'dark' },
    { stored: 'light', dark: true, denied: false, expected: 'light' },
    { stored: 'dark', dark: false, denied: false, expected: 'dark' },
    { stored: 'invalid', dark: false, denied: false, expected: 'light' },
    { stored: 'light', dark: true, denied: true, expected: 'dark' },
  ]) {
    const root = { dataset: {} as Record<string, string>, style: {} as Record<string, string> };
    runInNewContext(initializer, {
      localStorage: { getItem: (key: string) => { assert.equal(key, THEME_STORAGE_KEY); if (scenario.denied) throw new Error('denied'); return scenario.stored; } },
      matchMedia: (query: string) => { assert.equal(query, '(prefers-color-scheme: dark)'); return { matches: scenario.dark }; },
      document: { documentElement: root },
    });
    assert.equal(root.dataset.theme, scenario.expected);
    assert.equal(root.style.colorScheme, scenario.expected);
  }
});
