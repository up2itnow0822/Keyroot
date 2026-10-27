import sodium from 'libsodium-wrappers';
import type { ConsumerStorePort } from '../adapters/store.js';
import { assertConsumerIntent, beforeConsumerEffect, credentialFingerprint, ConsumerRefusal, deliveryReceipt, pinDescriptor, platformId, platformRequest, platformTimeout, type ConsumerDescriptor, type ConsumerDriver, type ConsumerTrust, type PlatformAdmission } from './consumer.js';

export interface GitHubActionsDescriptor extends ConsumerDescriptor {
  driver: 'github-actions';
  accountId: string;
  owner: string;
  repository: string;
  secretName: string;
  pushTokenFingerprint: string;
}
/** Optional injectable binding for isolated crypto runtimes; must implement libsodium sealed boxes. */
export interface SealedBoxPort { seal(value: Uint8Array, publicKey: Uint8Array): Promise<Uint8Array> }
export const sodiumSealedBox: SealedBoxPort = { async seal(value, publicKey) { await sodium.ready; if (publicKey.length !== sodium.crypto_box_PUBLICKEYBYTES) throw new ConsumerRefusal(); return sodium.crypto_box_seal(value, publicKey); } };
export function createGitHubActionsConsumer(config: { descriptor: GitHubActionsDescriptor; store: ConsumerStorePort; trust: ConsumerTrust; transport: typeof fetch; pushToken: string; admission: PlatformAdmission; sealedBox?: SealedBoxPort; timeoutMs?: number }): ConsumerDriver {
  const d = pinDescriptor(config.descriptor, ['accountId', 'owner', 'repository', 'secretName', 'pushTokenFingerprint']); const timeout = platformTimeout(config.timeoutMs);
  if (d.driver !== 'github-actions' || ![d.accountId, d.owner, d.repository].every(platformId) || !/^[A-Z_][A-Z0-9_]{0,127}$/.test(d.secretName) || d.secretName.startsWith('GITHUB_') || !config.pushToken || d.pushTokenFingerprint !== credentialFingerprint(config.pushToken)) throw new ConsumerRefusal();
  const root = `https://api.github.com/repos/${encodeURIComponent(d.owner)}/${encodeURIComponent(d.repository)}/actions/secrets`;
  return { async deliver(intent, context) {
    let pushed = false;
    try {
      assertConsumerIntent(intent, d, context); await config.admission.assertAdmitted(d);
      const keyResponse = await platformRequest(config.transport, `${root}/public-key`, config.pushToken, { method: 'GET', headers: { Accept: 'application/vnd.github+json', 'X-GitHub-Api-Version': '2022-11-28' } }, timeout, context.signal);
      const body = keyResponse?.body as Record<string, unknown> | undefined;
      if (keyResponse?.status !== 200 || !body || !platformId(String(body.key_id)) || typeof body.key !== 'string' || !/^[A-Za-z0-9+/]{43}=$/.test(body.key)) throw new ConsumerRefusal();
      const publicKey = Buffer.from(body.key, 'base64'); if (publicKey.length !== 32 || publicKey.toString('base64') !== body.key) throw new ConsumerRefusal();
      let accepted = false;
      const resolved = await config.store.withValue(d.handleId, d.version, async value => {
        const bytes = Buffer.from(value); let sealed: Uint8Array;
        try { sealed = await (config.sealedBox ?? sodiumSealedBox).seal(bytes, publicKey); } finally { bytes.fill(0); }
        if (sealed.length < 48) throw new ConsumerRefusal();
        await config.admission.assertAdmitted(d);
        await beforeConsumerEffect(intent, d, context, config.trust, 'github-secret-push');
        pushed = true;
        const response = await platformRequest(config.transport, `${root}/${encodeURIComponent(d.secretName)}`, config.pushToken, { method: 'PUT', headers: { Accept: 'application/vnd.github+json', 'X-GitHub-Api-Version': '2022-11-28' }, body: JSON.stringify({ encrypted_value: Buffer.from(sealed).toString('base64'), key_id: body.key_id }) }, timeout, context.signal);
        accepted = response?.status === 201 || response?.status === 204;
      });
      if (resolved.status !== 'resolved') return deliveryReceipt(context, config.trust, d, pushed ? 'unknown' : 'rejected');
      return deliveryReceipt(context, config.trust, d, accepted ? 'delivery-accepted' : 'unknown', ['new-job-run-required', 'existing-secret-not-readable']);
    } catch { return deliveryReceipt(context, config.trust, d, pushed ? 'unknown' : 'rejected', pushed ? ['reconciliation-required'] : []); }
  } };
}
