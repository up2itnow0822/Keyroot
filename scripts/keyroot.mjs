import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { join } from 'node:path';
import { homedir } from 'node:os';

const args = process.argv.slice(2);
if (!args.includes('--directory') && !['recover', 'backup', 'recovery-resume'].includes(args[0] ?? '')) {
  const directory = process.env.KEYROOT_DIRECTORY ?? ((process.env.KEYROOT_MODE ?? 'demo') === 'demo'
    ? fileURLToPath(new URL('../runtime/demo-dev', import.meta.url))
    : join(homedir(), '.keyroot'));
  args.push('--directory', directory);
}
const child = spawn(process.execPath, ['--import', 'tsx', fileURLToPath(new URL('../apps/controller/src/cli.ts', import.meta.url)), ...args], { stdio: 'inherit' });
child.on('error', () => { process.stderr.write('Local CLI could not start\n'); process.exitCode = 1; });
child.on('exit', code => { process.exitCode = code ?? 1; });
