import { createServer, type Server } from 'node:http';
import { createServer as createLocalServer } from 'node:net';
import { chmod, mkdir, readFile, writeFile, stat } from 'node:fs/promises';
import { generateKeyPairSync, createPrivateKey, createPublicKey, randomUUID, type KeyObject } from 'node:crypto';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { BootFence } from '../../../packages/core/src/boot-fence.js';
import { Journal } from '../../../packages/core/src/journal.js';
import { publicKeyFingerprint } from '../../../packages/core/src/approval.js';
import { ControllerAuth, exactObject, identifier } from './auth.js';
import { assertControllerModePorts, ControllerService, type ControllerMode, type TrustedControllerPorts } from './service.js';
import { createHandler } from './routes.js';
export interface StartControllerOptions { directory: string; port?: number; mode?: ControllerMode; phoneOrigin?: string; ownerOrigin?: string; ports?: TrustedControllerPorts; clock?: () => number }
export async function startController(options: StartControllerOptions) {
  assertControllerModePorts(options.mode ?? 'demo', options.ports);
  await mkdir(options.directory, { recursive: true, mode: 0o700 }); await chmod(options.directory, 0o700);
  // This kernel singleton MUST precede Journal boot invalidation.
  const fence = await BootFence.acquire(join(options.directory, 'boot.sock'));
  let journal: Journal | undefined; let server: Server | undefined; let admin: ReturnType<typeof createLocalServer> | undefined;
  try {
    const selectedMode = options.mode ?? 'demo';
    try { const marker = (await readFile(join(options.directory, 'runtime-mode'), 'utf8')).trim(); if (!['demo', 'real'].includes(marker) || marker !== selectedMode) throw new Error('Runtime mode excludes ' + selectedMode); }
    catch (error) { if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error; }
    // Check persisted metadata before Journal's boot fencing mutates the database.
    let databaseExists = true; try { await stat(join(options.directory, 'journal.sqlite')); } catch (error) { if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error; databaseExists = false; }
    if (databaseExists) {
      const db = new DatabaseSync(join(options.directory, 'journal.sqlite'), { readOnly: true });
      try {
        const exists = db.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name='controller_runtime'").get();
        const row = exists ? db.prepare("SELECT metadata FROM controller_runtime WHERE id='runtime'").get() : undefined;
        if (row && (JSON.parse(String(row.metadata)) as { mode: string }).mode !== selectedMode) throw new Error(selectedMode === 'demo' ? 'Real metadata cannot enter demo runtime' : 'Demo metadata cannot enter real runtime');
      } finally { db.close(); }
    }
    await writeFile(join(options.directory, 'runtime-mode'), selectedMode + '\n', { mode: 0o600 });
    let installationId: string;
    try { installationId = identifier((await readFile(join(options.directory, 'installation-id'), 'utf8')).trim()); }
    catch (error) { if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error; installationId = randomUUID(); await writeFile(join(options.directory, 'installation-id'), installationId, { mode: 0o600, flag: 'wx' }); }
    let identityKey: KeyObject;
    try { identityKey = createPrivateKey(await readFile(join(options.directory, 'identity.pem'))); }
    catch (error) { if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error; identityKey = generateKeyPairSync('ec', { namedCurve: 'prime256v1' }).privateKey; await writeFile(join(options.directory, 'identity.pem'), identityKey.export({ type: 'pkcs8', format: 'pem' }), { mode: 0o600, flag: 'wx' }); }
    journal = new Journal(join(options.directory, 'journal.sqlite'), { installationId, bootId: fence.bootId });
    const mode = options.mode ?? 'demo'; const service = new ControllerService(journal, mode, options.ports, options.clock);
    let origin = ''; let expectedHost = '';
    const publicKey = createPublicKey(identityKey).export({ format: 'jwk' }); const fingerprint = publicKeyFingerprint(publicKey);
    const identity = () => ({ installationId, bootId: fence.bootId, publicKey, fingerprint, mode });
    server = createServer((req, res) => { void createHandler({ service, auth, origin: () => options.ownerOrigin ?? origin, host: () => expectedHost, identity, identityKey })(req, res); });
    await new Promise<void>((resolve, reject) => { server!.once('error', reject); server!.listen(options.port ?? 9047, '127.0.0.1', resolve); });
    const address = server.address(); if (!address || typeof address === 'string') throw new Error('Listener unavailable'); expectedHost = `127.0.0.1:${address.port}`; origin = `http://${expectedHost}`;
    const phoneOrigin = options.phoneOrigin ?? origin;
    if (mode === 'real' && (new URL(phoneOrigin).protocol !== 'https:' || phoneOrigin === origin || phoneOrigin === options.ownerOrigin)) throw new Error('Separate HTTPS phone origin required');
    if (new URL(phoneOrigin).origin !== phoneOrigin) throw new Error('Exact phone origin required');
    const auth = new ControllerAuth(journal, phoneOrigin, options.clock); service.configurePhoneOrigin(phoneOrigin);
    admin = createLocalServer(socket => {
      socket.setTimeout(5000, () => socket.destroy()); let raw = '';
      socket.on('data', chunk => {
        raw += chunk.toString('utf8'); if (raw.length > 8192) { socket.destroy(); return; } if (!raw.includes('\n')) return;
        socket.pause();
        try {
          const body = exactObject(JSON.parse(raw.slice(0, raw.indexOf('\n'))) as unknown, ['command'], ['requestId', 'fingerprint']);
          if (body.command === 'session') socket.end(JSON.stringify({ code: auth.issueExchangeCode(), origin, ownerOrigin: options.ownerOrigin ?? origin }) + '\n');
          else if (body.command === 'pair-confirm') { service.confirmLocalPairing(identifier(body.requestId), identifier(body.fingerprint)); socket.end('{"outcome":"paired"}\n'); }
          else if (body.command === 'identity') socket.end(JSON.stringify(identity()) + '\n');
          else socket.end('{"error":"unknown_local_command"}\n');
        } catch { socket.end('{"error":"local_command_rejected"}\n'); }
      });
    });
    await new Promise<void>((resolve, reject) => { admin!.once('error', reject); admin!.listen(join(options.directory, 'admin.sock'), resolve); }); await chmod(join(options.directory, 'admin.sock'), 0o600);
    let closed = false;
    return { server, service, auth, origin, phoneOrigin, identity: identity(), async close() { if (closed) return; closed = true; await new Promise<void>((resolve, reject) => server!.close(error => error ? reject(error) : resolve())); await new Promise<void>((resolve, reject) => admin!.close(error => error ? reject(error) : resolve())); journal!.close(); await fence.release(); } };
  } catch (error) {
    if (server?.listening) await new Promise<void>(resolve => server!.close(() => resolve())); if (admin?.listening) await new Promise<void>(resolve => admin!.close(() => resolve())); journal?.close(); await fence.release(); throw error;
  }
}
