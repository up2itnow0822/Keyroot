import { readdirSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
const kind = process.argv[2];
const roots = { unit: ['packages/core/test'], integration: ['tests/integration'], browser: ['tests/browser'] };
function walk(dir) {
  try { return readdirSync(dir, { withFileTypes: true }).flatMap(e => e.isDirectory() ? walk(`${dir}/${e.name}`) : /\.test\.(ts|mjs)$/.test(e.name) ? [`${dir}/${e.name}`] : []); }
  catch (e) { if (e.code === 'ENOENT') return []; throw e; }
}
if (!roots[kind]) throw new Error('Unknown test suite');
const files = roots[kind].flatMap(walk);
if (files.length === 0) throw new Error(`No ${kind} tests implemented; this gate has not passed.`);
const result = spawnSync(process.execPath, ['--import', 'tsx', '--test', ...files], { stdio: 'inherit' });
process.exitCode = result.status ?? 1;
