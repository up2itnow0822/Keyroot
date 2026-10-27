import { execFile } from 'node:child_process';
import { isAbsolute } from 'node:path';
import type { NativeSignOutExecutor } from '../../../../packages/core/src/native-sessions.js';
/** Trusted executable paths only. No shell, arbitrary arguments, credential inspection, or output forwarding. */
export function createFixedNativeExecutor(config: { codex?: string; claude?: string; timeoutMs?: number }): NativeSignOutExecutor {
  if (Object.values(config).some(v => typeof v === 'string' && !isAbsolute(v))) throw new Error('Pinned absolute executable required');
  const timeout = config.timeoutMs ?? 15000; if (!Number.isSafeInteger(timeout) || timeout < 1 || timeout > 30000) throw new Error('Invalid native timeout');
  return { execute: action => new Promise<void>((resolve, reject) => {
    const binary = action === 'codex-local-sign-out' ? config.codex : config.claude;
    if (!binary) { reject(new Error('Native command unavailable')); return; }
    execFile(binary, action === 'codex-local-sign-out' ? ['logout'] : ['auth', 'logout'], { shell: false, timeout, maxBuffer: 8192, windowsHide: true }, error => error ? reject(new Error('Native local outcome unverified')) : resolve());
  }) };
}
