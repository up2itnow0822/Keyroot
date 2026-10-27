import { spawn } from 'node:child_process';
const children = [
  spawn('npm', ['run', 'dev', '--workspace', '@keyroot/controller'], { stdio: 'inherit' }),
  spawn('npm', ['run', 'dev', '--workspace', '@keyroot/review', '--', '--host', '127.0.0.1', '--port', '4173', '--strictPort'], { stdio: 'inherit' }),
];
let stopping = false;
function stop(code = 0) {
  if (stopping) return;
  stopping = true;
  for (const child of children) child.kill('SIGTERM');
  process.exitCode = code;
}
for (const signal of ['SIGINT', 'SIGTERM']) process.on(signal, () => stop());
for (const child of children) {
  child.on('error', () => stop(1));
  child.on('exit', code => stop(code ?? 1));
}
