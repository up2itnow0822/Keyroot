import { spawn, type ChildProcess } from 'node:child_process';
import { isAbsolute } from 'node:path';
import type { Readable, Writable } from 'node:stream';
import type { ConsumerStorePort } from './adapters/store.js';
import type { AuthorizedIntent } from './journal.js';
import type { EffectContext } from './engine.js';
import type { LifecycleReceipt } from './receipts.js';
import { beforeConsumerEffect, ConsumerRefusal, deliveryReceipt, pinDescriptor, type ConsumerDescriptor, type ConsumerTrust } from './consumers/consumer.js';

/** No test-only short-grace escape hatch. Issuer expiry may always shorten the real grace. */
export class GraceLease {
  private deadline: number;
  private readonly issuerDeadline: number;
  private readonly graceMs: number;
  private lastNow: number;
  private readonly monotonic: () => number;
  constructor(config: { graceSeconds: number; issuerRemainingMs: number; monotonic?: () => number }) {
    if (!Number.isSafeInteger(config.graceSeconds) || config.graceSeconds < 900 || config.graceSeconds > 1800 || !Number.isFinite(config.issuerRemainingMs) || config.issuerRemainingMs <= 0) throw new ConsumerRefusal();
    this.monotonic = config.monotonic ?? (() => performance.now()); this.lastNow = this.monotonic(); if (!Number.isFinite(this.lastNow)) throw new ConsumerRefusal();
    this.graceMs = config.graceSeconds * 1000; this.issuerDeadline = this.lastNow + config.issuerRemainingMs; this.deadline = Math.min(this.lastNow + this.graceMs, this.issuerDeadline);
  }
  private now() { const current = this.monotonic(); if (!Number.isFinite(current) || current < this.lastNow) throw new ConsumerRefusal(); this.lastNow = current; return current; }
  remainingMs(): number { return Math.max(0, this.deadline - this.now()); }
  /** Caller must obtain a fresh trusted heartbeat first. Expired leases cannot be resurrected. */
  renew(): void { const now = this.now(); if (now >= this.deadline) throw new ConsumerRefusal(); this.deadline = Math.min(now + this.graceMs, this.issuerDeadline); }
}
export interface WrapperDescriptor extends ConsumerDescriptor {
  driver: 'wrapper'; workloadId: string; variable: string; command: string; args: string[];
  environmentKeys: string[]; graceSeconds: number; issuerExpiresAt: number;
}
export type ManagedExit = 'issuer-expired' | 'grace-expired' | 'launcher-lost' | 'stopped' | 'child-exited' | 'supervisor-lost';
export interface ManagedWorkload {
  readonly supervisorPid: number; readonly childPid: number; readonly receipt: LifecycleReceipt;
  readonly exited: Promise<ManagedExit>;
  renew(): Promise<boolean>;
  stop(): Promise<ManagedExit>;
  /** Release of the launcher channel is fail-closed; the independent supervisor cleans its group. */
  releaseLauncher(): void;
}
// Separate POSIX session: this supervisor survives launcher death and owns a different child process group.
// Values enter only via anonymous fd 3, never command arguments, inherited env, stdout or stderr.
const supervisorSource = String.raw`
const {spawn}=require('node:child_process'); const {Socket}=require('node:net');
const input=new Socket({fd:3,readable:true,writable:false}); const output=new Socket({fd:4,readable:false,writable:true});
let child, deadline=0, issuerDeadline=0, graceMs=0, stopping=false, initialized=false, buffer='';
const send=(o)=>{try{output.write(JSON.stringify(o)+'\n');}catch{stop('launcher-lost');}};
function killGroup(signal){if(child&&child.pid){try{process.kill(-child.pid,signal);}catch{}}}
function stop(reason){if(stopping)return;stopping=true;killGroup('SIGTERM');setTimeout(()=>{killGroup('SIGKILL');setTimeout(()=>{send({type:'stopped',reason});process.exit(0);},100);},150);}
for(const signal of ['SIGHUP','SIGQUIT','SIGTERM','SIGINT'])process.on(signal,()=>stop('stopped'));
input.on('end',()=>stop('launcher-lost'));input.on('close',()=>stop('launcher-lost'));input.on('error',()=>stop('launcher-lost'));output.on('error',()=>stop('launcher-lost'));
input.on('data',chunk=>{buffer+=chunk.toString();if(Buffer.byteLength(buffer)>131072){stop('stopped');return;}let index;while((index=buffer.indexOf('\n'))>=0){const line=buffer.slice(0,index);buffer=buffer.slice(index+1);let m;try{m=JSON.parse(line);}catch{stop('stopped');return;}
if(!initialized){initialized=true;if(m.type!=='start'||!Number.isFinite(m.issuerDeadlineMs)||m.issuerDeadlineMs<=Number(process.hrtime.bigint()/1000000n)||!Number.isInteger(m.graceMs)||m.graceMs<900000||m.graceMs>1800000){stop('stopped');return;}
graceMs=m.graceMs;issuerDeadline=m.issuerDeadlineMs;deadline=Math.min(Number(process.hrtime.bigint()/1000000n)+graceMs,issuerDeadline);
try{child=spawn(m.command,m.args,{detached:true,env:m.environment,stdio:'ignore'});m.environment=undefined;child.once('error',()=>stop('child-exited'));child.once('exit',()=>stop('child-exited'));child.once('spawn',()=>send({type:'ready',pid:child.pid}));}catch{stop('child-exited');}}
else if(m.type==='renew'&&!stopping){const now=Number(process.hrtime.bigint()/1000000n);if(now>=deadline){stop(now>=issuerDeadline?'issuer-expired':'grace-expired');return;}deadline=Math.min(now+graceMs,issuerDeadline);}
else if(m.type==='stop')stop('stopped');}});
setInterval(()=>{if(initialized&&!stopping){const now=Number(process.hrtime.bigint()/1000000n);if(now>=deadline)stop(now>=issuerDeadline?'issuer-expired':'grace-expired');}},20);
setTimeout(()=>{if(!initialized)stop('launcher-lost');},5000);
`;
const safeEnvironment = new Set(['PATH', 'LANG', 'LC_ALL', 'LC_CTYPE', 'TZ', 'TERM', 'COLORTERM']);
const reservedSecretVariable = /(?:KEYROOT|CONTROLLER|STORE|VAULT|BAO|ADMIN)/i;
const executableEnvironment = /^(?:NODE_|LD_|DYLD_|PYTHON|PERL|RUBY|GCONV_PATH$|BASH_ENV$|ENV$|IFS$|SHELLOPTS$)/;
function cleanEnvironment(keys: readonly string[], source: Readonly<Record<string, string | undefined>>): Record<string, string> {
  const env: Record<string, string> = {};
  for (const key of keys) if (safeEnvironment.has(key)) { const value = source[key]; if (value !== undefined && value.length <= 4096 && !value.includes('\0')) env[key] = value; }
  return env;
}
function launchSupervisor(d: Readonly<WrapperDescriptor>, value: string, environment: Readonly<Record<string, string | undefined>>, issuerRemainingMs: number): Promise<{ process: ChildProcess; input: Writable; output: Readable; pid: number; exited: Promise<ManagedExit>; close: () => void }> {
  return new Promise((resolve, reject) => {
    const issuerDeadlineMs = Number(process.hrtime.bigint() / 1000000n) + issuerRemainingMs;
    const supervisor = spawn(process.execPath, ['-e', supervisorSource], { detached: true, env: {}, stdio: ['ignore', 'ignore', 'ignore', 'pipe', 'pipe'] });
    const input = supervisor.stdio[3] as Writable; const output = supervisor.stdio[4] as Readable;
    let ready = false; let settled = false; let buffer = ''; let exitResolve!: (reason: ManagedExit) => void; const exited = new Promise<ManagedExit>(r => { exitResolve = r; });
    const close = () => { if (!input.destroyed) input.destroy(); };
    const shutdown = (reason: ManagedExit) => { if (settled) return; settled = true; clearTimeout(timer); exitResolve(reason); close(); output.destroy(); if (!ready) reject(new Error('Managed workload refused')); };
    const timer = setTimeout(() => { close(); try { supervisor.kill('SIGTERM'); } catch { /* No raw process errors. */ } shutdown('supervisor-lost'); }, 5000);
    input.on('error', close);
    supervisor.once('error', () => shutdown('supervisor-lost'));
    supervisor.once('exit', () => shutdown('supervisor-lost'));
    output.on('error', close);
    output.on('data', (chunk: Buffer) => {
      buffer += chunk.toString(); if (buffer.length > 4096) { close(); return; }
      let at: number;
      while ((at = buffer.indexOf('\n')) >= 0) {
        const line = buffer.slice(0, at); buffer = buffer.slice(at + 1);
        let m: { type?: string; pid?: number; reason?: ManagedExit }; try { m = JSON.parse(line) as typeof m; } catch { close(); return; }
        if (m.type === 'ready' && Number.isSafeInteger(m.pid) && Number(m.pid) > 0 && !ready) { ready = true; clearTimeout(timer); resolve({ process: supervisor, input, output, pid: Number(m.pid), exited, close }); }
        else if (m.type === 'stopped' && ['issuer-expired', 'grace-expired', 'launcher-lost', 'stopped', 'child-exited'].includes(String(m.reason))) shutdown(m.reason as ManagedExit);
      }
    });
    // The only environment material sent to the supervisor is the explicit allowlist plus one mapped value.
    input.write(JSON.stringify({ type: 'start', command: d.command, args: d.args, environment: { ...cleanEnvironment(d.environmentKeys, environment), [d.variable]: value }, graceMs: d.graceSeconds * 1000, issuerDeadlineMs }) + '\n');
  });
}
export async function launchManagedWorkload(config: { descriptor: WrapperDescriptor; intent: AuthorizedIntent; context: EffectContext; store: ConsumerStorePort; trust: ConsumerTrust; heartbeat: { assertHealthy(workloadId: string): Promise<void> }; environment?: Readonly<Record<string, string | undefined>> }): Promise<ManagedWorkload> {
  let launched: Awaited<ReturnType<typeof launchSupervisor>> | undefined;
  try {
    const d = pinDescriptor(config.descriptor, ['workloadId', 'variable', 'command', 'args', 'environmentKeys', 'graceSeconds', 'issuerExpiresAt']);
    if (process.platform === 'win32' || d.driver !== 'wrapper' || !/^[-a-zA-Z0-9_.]{1,128}$/.test(d.workloadId) || !/^[A-Z_][A-Z0-9_]{0,127}$/.test(d.variable) || reservedSecretVariable.test(d.variable) || executableEnvironment.test(d.variable) || safeEnvironment.has(d.variable) || !isAbsolute(d.command) || !Array.isArray(d.args) || d.args.length > 128 || d.args.some(a => typeof a !== 'string' || a.length > 4096 || a.includes('\0')) || !Array.isArray(d.environmentKeys) || d.environmentKeys.length > 64 || d.environmentKeys.some(k => typeof k !== 'string') || !Number.isSafeInteger(d.issuerExpiresAt)) throw new ConsumerRefusal();
    const remaining = d.issuerExpiresAt - (config.trust.clock?.() ?? Date.now());
    const startedAt = performance.now(); const lease = new GraceLease({ graceSeconds: d.graceSeconds, issuerRemainingMs: remaining });
    await config.heartbeat.assertHealthy(d.workloadId);
    await beforeConsumerEffect(config.intent, d, config.context, config.trust, 'wrapper-resolve');
    const result = await config.store.withValue(d.handleId, d.version, async value => {
      if (value.includes('\0') || value.length > 32768) throw new ConsumerRefusal();
      await beforeConsumerEffect(config.intent, d, config.context, config.trust, 'wrapper-launch');
      const duration = remaining - (performance.now() - startedAt); if (duration <= 0 || lease.remainingMs() <= 0) throw new ConsumerRefusal();
      launched = await launchSupervisor(d, value, config.environment ?? {}, duration);
    });
    const runtime = launched;
    if (result.status !== 'resolved' || !runtime || !runtime.process.pid) throw new ConsumerRefusal();
    const signalListeners = (['SIGHUP', 'SIGQUIT', 'SIGTERM', 'SIGINT'] as const).map(signal => { const listener = () => runtime.close(); process.on(signal, listener); return { signal, listener }; });
    const aborted = () => runtime.close(); config.context.signal.addEventListener('abort', aborted, { once: true });
    void runtime.exited.then(() => { for (const { signal, listener } of signalListeners) process.removeListener(signal, listener); config.context.signal.removeEventListener('abort', aborted); });
    return Object.freeze({ supervisorPid: runtime.process.pid, childPid: runtime.pid, receipt: deliveryReceipt(config.context, config.trust, d, 'delivery-accepted', ['managed-process-group-only', 'managed-output-suppressed', 'unmanaged-copies-uncontrolled']), exited: runtime.exited,
      async renew() { try { await config.heartbeat.assertHealthy(d.workloadId); await beforeConsumerEffect(config.intent, d, config.context, config.trust, 'wrapper-renew'); lease.renew(); if (runtime.input.destroyed) return false; runtime.input.write('{"type":"renew"}\n'); return true; } catch { return false; } },
      async stop() { if (!runtime.input.destroyed) runtime.input.write('{"type":"stop"}\n'); return runtime.exited; },
      releaseLauncher: runtime.close });
  } catch { if (launched) launched.close(); throw new Error('Managed workload refused'); }
}
