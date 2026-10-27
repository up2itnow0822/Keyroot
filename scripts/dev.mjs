import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
const mode = process.env.KEYROOT_MODE ?? 'demo';
const controllerEnv = { ...process.env, KEYROOT_MODE: mode };
if (mode === 'demo') {
  controllerEnv.KEYROOT_DIRECTORY ??= fileURLToPath(new URL('../runtime/demo-dev', import.meta.url));
  controllerEnv.KEYROOT_OWNER_ORIGIN ??= 'http://127.0.0.1:4173';
  controllerEnv.KEYROOT_PHONE_ORIGIN ??= 'http://127.0.0.1:4173';
}
const grouped = process.platform !== 'win32';
const children = [
  spawn('npm', ['run', 'dev', '--workspace', '@keyroot/controller'], { stdio: 'inherit', env: controllerEnv, detached: grouped }),
  spawn('npm', ['run', 'dev', '--workspace', '@keyroot/review', '--', '--host', '127.0.0.1', '--port', '4173', '--strictPort'], { stdio: 'inherit', detached: grouped }),
];
let stopping = false;
function stop(code = 0) {
  if (stopping) return;
  stopping = true;
  for (const child of children) {
    try { if (grouped && child.pid) process.kill(-child.pid, 'SIGTERM'); else child.kill('SIGTERM'); }
    catch (error) { if (error.code !== 'ESRCH') throw error; }
  }
  process.exitCode = code;
}
for (const signal of ['SIGINT', 'SIGTERM']) process.on(signal, () => stop());
for (const child of children) {
  child.on('error', () => stop(1));
  child.on('exit', code => stop(code ?? 1));
}
