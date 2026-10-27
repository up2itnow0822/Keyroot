import { randomBytes, createPublicKey, verify, sign, type KeyObject } from 'node:crypto';
import type { IncomingMessage } from 'node:http';
import type { Journal } from '../../../packages/core/src/journal.js';
import { canonicalJSON } from '../../../packages/core/src/manifest.js';
export class HttpFailure extends Error { constructor(readonly status: number, readonly code: string) { super(code); } }
export interface ReadChallenge { nonce: string; installationId: string; signerId: string; method: 'GET'; path: string; expiresAt: number }
interface Session { csrfToken: string; expiresAt: number }
const random = () => randomBytes(32).toString('base64url');
export class ControllerAuth {
  private readonly codes = new Map<string, number>();
  private readonly sessions = new Map<string, Session>();
  private readonly challenges = new Map<string, ReadChallenge>();
  constructor(readonly journal: Journal, readonly phoneOrigin: string, private readonly clock: () => number = Date.now) {}
  issueExchangeCode(): string { const code = random(); this.codes.set(code, this.clock() + 60000); return code; }
  exchange(code: string): Session & { cookie: string } {
    const expires = this.codes.get(code); this.codes.delete(code);
    if (!expires || expires <= this.clock()) throw new HttpFailure(401, 'invalid_exchange');
    const token = random(); const session = { csrfToken: random(), expiresAt: this.clock() + 600000 }; this.sessions.set(token, session);
    return { ...session, cookie: `keyroot_session=${token}; HttpOnly; SameSite=Strict; Path=/api; Max-Age=600` };
  }
  requireOwner(req: IncomingMessage, origin: string, csrf = false): void {
    if (req.headers.origin && req.headers.origin !== origin) throw new HttpFailure(403, 'origin_denied');
    if (csrf && req.headers.origin !== origin) throw new HttpFailure(403, 'origin_denied');
    const token = req.headers.cookie?.split(';').map(v => v.trim()).find(v => v.startsWith('keyroot_session='))?.slice(16);
    const session = token ? this.sessions.get(token) : undefined;
    if (!session || session.expiresAt <= this.clock()) throw new HttpFailure(401, 'session_required');
    if (csrf && req.headers['x-keyroot-csrf'] !== session.csrfToken) throw new HttpFailure(403, 'csrf_required');
  }
  requirePhone(req: IncomingMessage): void { if (req.headers.origin !== this.phoneOrigin) throw new HttpFailure(403, 'phone_origin_denied'); }
  challenge(signerId: string, path: string): ReadChallenge {
    if (!/^\/api\/(inventory|overview|batches(?:\/[-a-zA-Z0-9]+)?|configurations\/sha256:[a-f0-9]{64})$/.test(path)) throw new HttpFailure(400, 'invalid_read_target');
    if (!this.journal.read(db => db.prepare("SELECT 1 FROM approver WHERE signer_id=? AND role='routine' AND revoked=0").get(signerId))) throw new HttpFailure(401, 'unpaired_signer');
    // Bound memory even if a paired client abandons challenges.
    for (const [key, value] of this.challenges) if (value.expiresAt <= this.clock()) this.challenges.delete(key);
    if (this.challenges.size >= 128) throw new HttpFailure(429, 'challenge_limit');
    const challenge: ReadChallenge = { nonce: random(), installationId: this.journal.installationId, signerId, method: 'GET', path, expiresAt: this.clock() + 30000 };
    this.challenges.set(challenge.nonce, challenge); return challenge;
  }
  consumeRead(req: IncomingMessage, path: string): ReadChallenge {
    this.requirePhone(req);
    const nonce = String(req.headers['x-keyroot-nonce'] ?? ''); const challenge = this.challenges.get(nonce); this.challenges.delete(nonce);
    if (!challenge || challenge.expiresAt <= this.clock() || challenge.path !== path || req.method !== challenge.method) throw new HttpFailure(401, 'read_nonce_denied');
    const row = this.journal.read(db => db.prepare("SELECT public_key FROM approver WHERE signer_id=? AND role='routine' AND revoked=0").get(challenge.signerId));
    const bytes = Buffer.from(String(req.headers['x-keyroot-signature'] ?? ''), 'base64url');
    if (!row || bytes.length !== 64 || !verify('sha256', Buffer.from('keyroot.phone-read.v1\0' + canonicalJSON(challenge)), { key: createPublicKey({ key: JSON.parse(String(row.public_key)), format: 'jwk' }), dsaEncoding: 'ieee-p1363' }, bytes)) throw new HttpFailure(401, 'read_signature_denied');
    return challenge;
  }
  response(challenge: ReadChallenge, data: unknown, identityKey: KeyObject) {
    const payload = { requestNonce: challenge.nonce, method: challenge.method, path: challenge.path, installationId: challenge.installationId, expiresAt: challenge.expiresAt, data };
    const signature = sign('sha256', Buffer.from('keyroot.controller-response.v1\0' + canonicalJSON(payload)), { key: identityKey, dsaEncoding: 'ieee-p1363' }).toString('base64url');
    return { payload, signature };
  }
}
export function exactObject(value: unknown, required: string[], optional: string[] = []): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value) || required.some(k => !Object.hasOwn(value, k)) || Object.keys(value).some(k => !required.includes(k) && !optional.includes(k))) throw new HttpFailure(400, 'invalid_body');
  return value as Record<string, unknown>;
}
export function identifier(value: unknown): string { if (typeof value !== 'string' || !/^[-a-zA-Z0-9_.:@/]{1,256}$/.test(value)) throw new HttpFailure(400, 'invalid_identifier'); return value; }
