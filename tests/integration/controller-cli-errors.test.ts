import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawn } from 'node:child_process';
import { startController } from '../../apps/controller/src/server.js';

async function cli(...args: string[]) {
  const child = spawn(process.execPath, ['--import', 'tsx', 'apps/controller/src/cli.ts', ...args]); let stdout = ''; let stderr = '';
  child.stdout.on('data', x => { stdout += String(x); }); child.stderr.on('data', x => { stderr += String(x); });
  const status = await new Promise<number | null>(resolve => child.on('close', resolve)); return { status, stdout, stderr };
}
test('CLI reports bounded argument, unavailable and controller rejection codes', async t => {
  const directory = await mkdtemp(join(tmpdir(), 'kr-cli-errors-')); t.after(() => rm(directory, { recursive: true, force: true }));
  const invalid = await cli('prepare'); assert.equal(invalid.status, 1); assert.deepEqual(JSON.parse(invalid.stderr), { error: 'invalid_arguments' });
  const unavailable = await cli('status', '--directory', directory); assert.equal(unavailable.status, 1); assert.deepEqual(JSON.parse(unavailable.stderr), { error: 'controller_unavailable' });
  const app = await startController({ directory, port: 0, mode: 'demo' }); t.after(() => app.close());
  const denied = await cli('prepare', 'unpaired', 'demo-lineage', '--directory', directory); assert.equal(denied.status, 1); assert.deepEqual(JSON.parse(denied.stderr), { error: 'paired_role_required' });
});

test('CLI never echoes an unrecognized secret-shaped error code or response body', async t => {
  const { createServer } = await import('node:http'); const { createServer: localServer } = await import('node:net');
  const directory = await mkdtemp(join(tmpdir(), 'kr-cli-untrusted-')); t.after(() => rm(directory, { recursive: true, force: true }));
  const server = createServer((req, res) => { if (req.url === '/api/session/exchange') { res.setHeader('Set-Cookie', 'fixture=cookie'); res.end(JSON.stringify({ csrfToken: 'fixture' })); } else { res.statusCode = 409; res.end(JSON.stringify({ error: 'secret_shaped_arbitrary_body', message: 'synthetic_sensitive_provider_text' })); } });
  await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve)); const address = server.address(); assert.ok(address && typeof address !== 'string'); const origin = `http://127.0.0.1:${address.port}`;
  const local = localServer(socket => socket.on('data', () => socket.end(JSON.stringify({ code: 'fixture', origin, ownerOrigin: origin }) + '\n'))); await new Promise<void>(resolve => local.listen(join(directory, 'admin.sock'), resolve));
  t.after(async () => { await new Promise<void>(resolve => local.close(() => resolve())); await new Promise<void>(resolve => server.close(() => resolve())); });
  const result = await cli('status', '--directory', directory); assert.equal(result.status, 1); assert.deepEqual(JSON.parse(result.stderr), { error: 'request_rejected' }); assert.doesNotMatch(result.stderr, /secret|sensitive/);
});
