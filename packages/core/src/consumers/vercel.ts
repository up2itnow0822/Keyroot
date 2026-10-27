import type { ConsumerStorePort } from '../adapters/store.js';
import { assertConsumerIntent, beforeConsumerEffect, credentialFingerprint, ConsumerRefusal, deliveryReceipt, pinDescriptor, platformId, platformRequest, platformTimeout, type ConsumerDescriptor, type ConsumerDriver, type ConsumerTrust, type PlatformAdmission } from './consumer.js';
export interface VercelDescriptor extends ConsumerDescriptor {
  driver: 'vercel';
  accountId: string;
  projectId: string;
  teamId?: string;
  environment: 'production' | 'preview' | 'development';
  variable: string;
  pushTokenFingerprint: string;
}
export function createVercelConsumer(config: { descriptor: VercelDescriptor; store: ConsumerStorePort; trust: ConsumerTrust; transport: typeof fetch; pushToken: string; admission: PlatformAdmission; timeoutMs?: number }): ConsumerDriver {
  const d = pinDescriptor(config.descriptor, ['accountId', 'projectId', 'teamId', 'environment', 'variable', 'pushTokenFingerprint']); const timeout = platformTimeout(config.timeoutMs);
  if (d.driver !== 'vercel' || ![d.accountId, d.projectId].every(platformId) || d.teamId !== undefined && !platformId(d.teamId) || !['production', 'preview', 'development'].includes(d.environment) || !/^[A-Z_][A-Z0-9_]{0,127}$/.test(d.variable) || !config.pushToken || d.pushTokenFingerprint !== credentialFingerprint(config.pushToken)) throw new ConsumerRefusal();
  const teamQuery = d.teamId === undefined ? '' : `teamId=${encodeURIComponent(d.teamId)}&`;
  const root = `https://api.vercel.com/v10/projects/${encodeURIComponent(d.projectId)}/env?${teamQuery}upsert=true`;
  return { async deliver(intent, context) {
    let pushed = false;
    try {
      assertConsumerIntent(intent, d, context); await config.admission.assertAdmitted(d);
      const metadata = await platformRequest(config.transport, `https://api.vercel.com/v9/projects/${encodeURIComponent(d.projectId)}${d.teamId === undefined ? '' : `?teamId=${encodeURIComponent(d.teamId)}`}`, config.pushToken, { method: 'GET' }, timeout, context.signal);
      const project = metadata?.body as Record<string, unknown> | undefined;
      if (metadata?.status !== 200 || project?.id !== d.projectId || project?.accountId !== (d.teamId ?? d.accountId)) throw new ConsumerRefusal();
      let accepted = false;
      const resolved = await config.store.withValue(d.handleId, d.version, async value => {
        await config.admission.assertAdmitted(d);
        await beforeConsumerEffect(intent, d, context, config.trust, 'vercel-env-push');
        pushed = true;
        const response = await platformRequest(config.transport, root, config.pushToken, { method: 'POST', body: JSON.stringify({ key: d.variable, value, type: 'encrypted', target: [d.environment] }) }, timeout, context.signal, true);
        const result = response?.body as Record<string, unknown> | undefined;
        const entry = (value: unknown) => { if (!value || typeof value !== 'object' || Array.isArray(value)) return false; const item = value as Record<string, unknown>; return platformId(String(item.id)) && item.key === d.variable && item.type === 'encrypted' && Array.isArray(item.target) && item.target.length === 1 && item.target[0] === d.environment; };
        const created = result?.created;
        accepted = (response?.status === 200 || response?.status === 201) && !!result && (entry(result) || Array.isArray(created) && created.length === 1 && created.every(entry) && Array.isArray(result.failed) && result.failed.length === 0 && (!Array.isArray(result.skipped) || result.skipped.length === 0));
      });
      if (resolved.status !== 'resolved') return deliveryReceipt(context, config.trust, d, pushed ? 'unknown' : 'rejected');
      return deliveryReceipt(context, config.trust, d, accepted ? 'delivery-accepted' : 'unknown', ['new-deployment-required', 'existing-secret-not-read-back']);
    } catch { return deliveryReceipt(context, config.trust, d, pushed ? 'unknown' : 'rejected', pushed ? ['reconciliation-required'] : []); }
  } };
}
