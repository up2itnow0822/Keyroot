import type { IncomingMessage, ServerResponse } from 'node:http';
import type { KeyObject } from 'node:crypto';
import type { AuthenticationResponseJSON } from '@simplewebauthn/server';
import { ControllerAuth, exactObject, HttpFailure, identifier } from './auth.js';
import { ControllerService, type AdministrativeAction } from './service.js';
export const actionNames: AdministrativeAction[] = ['cancel', 'retire', 'key-policy', 'approver-removal', 'oauth-consent', 'oauth-reconcile', 'native-sign-out', 'env-dry-run', 'env-rollback', 'platform-discovery', 'guided-completion', 'quarantine', 'emergency-enrollment', 'inventory-update', 'approver-enrollment'];
async function readBody(req: IncomingMessage): Promise<unknown> {
  if (req.headers['content-type']?.split(';')[0] !== 'application/json') throw new HttpFailure(415, 'json_required');
  const chunks: Buffer[] = []; let bytes = 0;
  for await (const chunk of req) { const buffer = Buffer.from(chunk as Uint8Array); bytes += buffer.length; if (bytes > 1024 * 1024) throw new HttpFailure(413, 'body_too_large'); chunks.push(buffer); }
  try { return JSON.parse(Buffer.concat(chunks).toString('utf8')) as unknown; } catch { throw new HttpFailure(400, 'invalid_json'); }
}
export function createHandler(options: { service: ControllerService; auth: ControllerAuth; origin: () => string; host: () => string; identity: () => unknown; identityKey: KeyObject }) {
  return async (req: IncomingMessage, res: ServerResponse): Promise<void> => {
    res.setHeader('Content-Type', 'application/json'); res.setHeader('Cache-Control', 'no-store'); res.setHeader('X-Content-Type-Options', 'nosniff'); res.setHeader('Content-Security-Policy', "default-src 'none'; frame-ancestors 'none'");
    const reply = (data: unknown, status = 200) => { res.statusCode = status; res.end(JSON.stringify(data)); };
    try {
      if (req.headers.host !== options.host()) throw new HttpFailure(403, 'host_denied');
      const path = new URL(req.url ?? '/', options.origin()).pathname;
      if (req.url !== path) throw new HttpFailure(400, 'query_not_allowed');
      if (req.headers.origin === options.auth.phoneOrigin) { res.setHeader('Access-Control-Allow-Origin', options.auth.phoneOrigin); res.setHeader('Vary', 'Origin'); }
      if (req.method === 'OPTIONS') {
        options.auth.requirePhone(req); res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS'); res.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-Keyroot-Nonce, X-Keyroot-Signature'); reply({}); return;
      }
      if (req.method === 'GET' && path === '/api/health') { reply({ service: 'keyroot', mode: options.service.mode }); return; }
      if (req.method === 'GET' && path === '/api/identity') { reply(options.identity()); return; }
      if (req.method === 'POST' && path === '/api/session/demo' && options.service.mode === 'demo') {
        if (req.headers.origin !== options.origin()) throw new HttpFailure(403, 'origin_denied');
        const session = options.auth.exchange(options.auth.issueExchangeCode()); res.setHeader('Set-Cookie', session.cookie + (options.origin().startsWith('https:') ? '; Secure' : '')); reply({ csrfToken: session.csrfToken, expiresAt: session.expiresAt, mode: 'demo' }); return;
      }
      if (req.method === 'POST' && path === '/api/session/exchange') {
        if (req.headers.origin !== options.origin()) throw new HttpFailure(403, 'origin_denied');
        const body = exactObject(await readBody(req), ['code']); const session = options.auth.exchange(String(body.code)); res.setHeader('Set-Cookie', session.cookie + (options.origin().startsWith('https:') ? '; Secure' : '')); reply({ csrfToken: session.csrfToken, expiresAt: session.expiresAt }); return;
      }
      if (req.method === 'POST' && path === '/api/phone/challenge') {
        options.auth.requirePhone(req); const body = exactObject(await readBody(req), ['signerId', 'method', 'path']); if (body.method !== 'GET' || typeof body.path !== 'string') throw new HttpFailure(400, 'invalid_read_target'); reply(options.auth.challenge(identifier(body.signerId), body.path)); return;
      }
      if (req.method === 'POST' && path === '/api/pairing/requests') { options.auth.requirePhone(req); reply(options.service.pairing(await readBody(req)), 201); return; }
      const pairingMeta = /^\/api\/owner\/pairing\/requests\/([-a-zA-Z0-9]+)$/.exec(path);
      if (req.method === 'GET' && pairingMeta) { options.auth.requireOwner(req, options.origin()); reply(options.service.pairingMetadata(pairingMeta[1]!)); return; }
      const registrationMeta = /^\/api\/owner\/emergency\/registrations\/([-a-zA-Z0-9]+)$/.exec(path);
      if (req.method === 'GET' && registrationMeta) { options.auth.requireOwner(req, options.origin()); if (!options.service.enrollment) throw new HttpFailure(503, 'enrollment_unavailable'); reply(options.service.enrollment.metadata(registrationMeta[1]!)); return; }
      const ownerPairing = /^\/api\/pairing\/owner\/([-a-zA-Z0-9]+)$/.exec(path);
      if (req.method === 'GET' && ownerPairing) { options.auth.requireOwner(req, options.origin()); reply(options.service.pairingMetadata(ownerPairing[1]!)); return; }
      const ownerEnrollment = /^\/api\/emergency\/enrollment\/([-a-zA-Z0-9]+)$/.exec(path);
      if (req.method === 'GET' && ownerEnrollment) { options.auth.requireOwner(req, options.origin()); if (!options.service.enrollment) throw new HttpFailure(503, 'enrollment_unavailable'); reply(options.service.enrollment.descriptor(ownerEnrollment[1]!)); return; }
      const pairingProof = /^\/api\/pairing\/requests\/([-a-zA-Z0-9]+)\/proof$/.exec(path);
      if (req.method === 'POST' && pairingProof) { options.auth.requirePhone(req); reply(options.service.pairingProof(pairingProof[1]!, await readBody(req))); return; }
      const pairing = /^\/api\/pairing\/requests\/([-a-zA-Z0-9]+)$/.exec(path);
      if (req.method === 'GET' && pairing) { options.auth.requirePhone(req); reply(options.service.pairingStatus(pairing[1]!)); return; }
      if (req.method === 'POST' && path === '/api/approvals') { options.auth.requirePhone(req); reply(options.service.approve(await readBody(req)), 201); return; }
      if (req.method === 'POST' && path === '/api/emergency/enrollment/challenge') { options.auth.requirePhone(req); if (!options.service.enrollment) throw new HttpFailure(503, 'enrollment_unavailable'); reply(await options.service.enrollment.challenge(await readBody(req))); return; }
      if (req.method === 'POST' && path === '/api/emergency/enrollment/verify') { options.auth.requirePhone(req); if (!options.service.enrollment) throw new HttpFailure(503, 'enrollment_unavailable'); reply(await options.service.enrollment.verify(await readBody(req))); return; }
      if (req.method === 'POST' && path === '/api/emergency/execute') { options.auth.requirePhone(req); reply(await options.service.executeIncident(await readBody(req))); return; }
      if (req.method === 'POST' && path === '/api/emergency/challenge') { options.auth.requirePhone(req); const body = exactObject(await readBody(req), ['grantId', 'operationId', 'actionId']); reply(options.service.emergency.createChallenge({ grantId: identifier(body.grantId), operationId: identifier(body.operationId), actionId: identifier(body.actionId) })); return; }
      if (req.method === 'POST' && path === '/api/emergency/assertion') { options.auth.requirePhone(req); const body = exactObject(await readBody(req), ['challengeId', 'operationId', 'actionId', 'response']); const proofId = await options.service.emergency.verifyAssertion({ challengeId: identifier(body.challengeId), operationId: identifier(body.operationId), actionId: identifier(body.actionId), response: body.response as AuthenticationResponseJSON }); reply({ proofId }); return; }
      const batch = /^\/api\/batches\/([-a-zA-Z0-9]+)$/.exec(path); const descriptor = /^\/api\/configurations\/(sha256:[a-f0-9]{64})$/.exec(path);
      const read = () => path === '/api/inventory' ? options.service.inventory() : path === '/api/overview' ? options.service.overview() : path === '/api/batches' ? { batches: options.service.batches() } : batch ? options.service.batch(batch[1]!) : descriptor ? options.service.configurationDescriptor(descriptor[1]!) : undefined;
      if (req.method === 'GET' && ['/api/inventory', '/api/overview', '/api/batches'].includes(path) || req.method === 'GET' && (batch || descriptor)) {
        if (req.headers['x-keyroot-nonce']) { const challenge = options.auth.consumeRead(req, path); reply(options.auth.response(challenge, read(), options.identityKey)); }
        else { options.auth.requireOwner(req, options.origin()); reply(read()); } return;
      }
      const operation = /^\/api\/operations\/([-a-zA-Z0-9]+)$/.exec(path);
      if (req.method === 'GET' && operation) { options.auth.requireOwner(req, options.origin()); reply(options.service.inspect(operation[1]!)); return; }
      if (req.method === 'GET' && path === '/api/schedules') { options.auth.requireOwner(req, options.origin()); reply({ forecasts: options.service.journal.read(db => db.prepare('SELECT metadata FROM schedule_forecast').all().map(r => JSON.parse(String(r.metadata)) as unknown)), outbox: options.service.interlock.list(), alarms: options.service.interlock.alarms() }); return; }
      const action = /^\/api\/actions\/([-a-z]+)$/.exec(path);
      if (req.method === 'POST' && action && actionNames.includes(action[1] as AdministrativeAction)) { options.auth.requireOwner(req, options.origin(), true); reply(await options.service.administrative(action[1] as AdministrativeAction, await readBody(req))); return; }
      if (req.method === 'POST' && path === '/api/batches/prepare') { options.auth.requireOwner(req, options.origin(), true); reply(options.service.prepare(await readBody(req)), 201); return; }
      if (req.method === 'POST' && path === '/api/operations/run') { options.auth.requireOwner(req, options.origin(), true); reply(await options.service.run(await readBody(req))); return; }
      if (req.method === 'POST' && path === '/api/operations/reconcile') { options.auth.requireOwner(req, options.origin(), true); const body = exactObject(await readBody(req), ['operationId']); reply(await options.service.reconcile(identifier(body.operationId))); return; }
      if (req.method === 'POST' && path === '/api/schedules/forecast') { options.auth.requireOwner(req, options.origin(), true); const body = exactObject(await readBody(req), ['lineageId', 'policyAt', 'intervalDays', 'mfaRequired', 'restartBudget', 'executionBudget'], ['issuerExpiryAt', 'reauthorizationAt']); reply(options.service.forecast.save(body as unknown as import('../../../packages/core/src/schedule.js').ForecastInput)); return; }
      if (req.method === 'POST' && path === '/api/schedules/validity') { options.auth.requireOwner(req, options.origin(), true); const body = exactObject(await readBody(req), ['lineageId']); reply({ outcome: await options.service.validity(identifier(body.lineageId)) }); return; }
      if (req.method === 'POST' && path === '/api/metrics/begin') { options.auth.requireOwner(req, options.origin(), true); const body = exactObject(await readBody(req), ['caseId', 'kind']); const id = crypto.randomUUID(); options.service.metrics.begin(id, identifier(body.caseId), body.kind as import('../../../packages/core/src/metrics.js').OwnerAction); reply({ intervalId: id }); return; }
      if (req.method === 'POST' && path === '/api/metrics/end') { options.auth.requireOwner(req, options.origin(), true); const body = exactObject(await readBody(req), ['intervalId']); options.service.metrics.end(identifier(body.intervalId)); reply({ outcome: 'recorded' }); return; }
      if (req.method === 'POST' && path === '/api/schedules/tick') { options.auth.requireOwner(req, options.origin(), true); const body = exactObject(await readBody(req), ['grantId']); reply(await options.service.tick(identifier(body.grantId))); return; }
      if (req.method === 'POST' && path === '/api/incidents/prepare') { options.auth.requireOwner(req, options.origin(), true); const body = exactObject(await readBody(req), ['grantId', 'proofId']); reply(options.service.prepareIncident(identifier(body.grantId), identifier(body.proofId))); return; }
      if (req.method === 'POST' && path === '/api/incidents/execute') { options.auth.requireOwner(req, options.origin(), true); reply(await options.service.executeIncident(await readBody(req))); return; }
      if (req.method === 'POST' && path === '/api/notifications/acknowledge') { options.auth.requireOwner(req, options.origin(), true); const body = exactObject(await readBody(req), ['notificationId']); options.service.interlock.acknowledge(identifier(body.notificationId)); reply({ outcome: 'acknowledged' }); return; }
      const guided = /^\/api\/guided\/([-a-zA-Z0-9_.]+)(?:\/(step))?$/.exec(path);
      if (guided && req.method === 'GET') { options.auth.requireOwner(req, options.origin()); reply(options.service.guided(guided[1]!)); return; }
      if (guided && req.method === 'POST' && guided[2]) { options.auth.requireOwner(req, options.origin(), true); const body = exactObject(await readBody(req), ['targetId', 'checkpointAcknowledged']); if (typeof body.checkpointAcknowledged !== 'boolean') throw new HttpFailure(400, 'invalid_checkpoint'); reply(options.service.guided(guided[1]!, identifier(body.targetId), body.checkpointAcknowledged)); return; }
      if (req.method === 'GET' && path.startsWith('/api/metrics/')) { options.auth.requireOwner(req, options.origin()); reply(options.service.metrics.report(identifier(path.slice(13)))); return; }
      throw new HttpFailure(404, 'not_found');
    } catch (error) {
      if (typeof error === 'object' && error !== null && 'code' in error && String(error.code).includes('SQLITE') && !('errcode' in error && (Number(error.errcode) & 255) === 19)) {
        try { options.service.interlock.journalFailed('controller-route'); } catch { /* Latch remains closed even when durable alarm persistence fails. */ }
        if (!res.headersSent) reply({ error: 'controller_storage_unavailable' }, 503); else res.destroy(); return;
      }
      if (!res.headersSent) reply({ error: error instanceof HttpFailure ? error.code : 'request_rejected' }, error instanceof HttpFailure ? error.status : 409);
      else res.destroy();
    }
  };
}
