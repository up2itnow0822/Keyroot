import { createHash, randomUUID } from 'node:crypto';
import { createOpenBaoStore } from '../../../packages/core/src/adapters/openbao-kv2.js';
import { createAccountAssessmentWorkflow } from '../../../packages/core/src/adapters/account-assessment.js';
import { createIssuerLifecycleDrivers, issuerConfigurationDescriptor, issuerConfigurationHash, type IssuerConfigurationMetadata } from '../../../packages/core/src/adapters/issuer-drivers.js';
import type { StoreBinding } from '../../../packages/core/src/adapters/store.js';
import type { LifecycleDrivers } from '../../../packages/core/src/engine.js';
import type { AuthorizedIntent } from '../../../packages/core/src/journal.js';
/** Isolated protocol fixture: all requests terminate in this closure, never on the network. */
export function createDemoPorts(clock: () => number = Date.now) {
  const keys = new Map<string, { name: string; value: string }>([['old-key', { name: 'previous', value: 'synthetic-old-value' }]]);
  const stored = new Map<string, { value: string; binding: StoreBinding; version: number }>();
  const request: typeof fetch = async (input, init) => {
    const url = new URL(String(input));
    if (url.hostname === 'vault.fixture.invalid') {
      const handle = url.pathname.split('/data/')[1] ?? '';
      if (init?.method === 'POST') {
        const body = JSON.parse(String(init.body)) as { options: { cas: number }; data: { value: string; binding: StoreBinding } };
        if (body.options.cas !== (stored.get(handle)?.version ?? 0)) return Response.json({}, { status: 400 });
        stored.set(handle, { ...body.data, version: body.options.cas + 1 }); return Response.json({ data: { version: body.options.cas + 1 } });
      }
      const record = stored.get(handle); return record ? Response.json({ data: { data: { value: record.value, binding: record.binding }, metadata: { version: record.version } } }) : new Response(null, { status: 404 });
    }
    if (url.hostname !== 'api.openai.com') throw new Error('Synthetic destination refused');
    if (init?.method === 'POST') {
      const body = JSON.parse(String(init.body)) as { name: string }; const id = 'key-' + randomUUID(); const value = 'synthetic-' + randomUUID(); keys.set(id, { name: body.name, value });
      return Response.json({ object: 'organization.project.service_account.api_key', id, name: body.name, value });
    }
    const keyId = url.pathname.split('/').at(-1)!;
    if (init?.method === 'DELETE') { keys.delete(keyId); return Response.json({ object: 'organization.project.api_key.deleted', id: keyId, deleted: true }); }
    const item = (id: string, name: string) => ({ object: 'organization.project.api_key', id, name, owner: { type: 'service_account', service_account: { id: 'demo-service' } } });
    if (keyId === 'api_keys') return Response.json({ object: 'list', data: [...keys].map(([id, key]) => item(id, key.name)), has_more: false });
    const key = keys.get(keyId); return key ? Response.json(item(keyId, key.name)) : new Response(null, { status: 404 });
  };
  const store = createOpenBaoStore({ baseUrl: 'https://vault.fixture.invalid', mount: 'secret', token: 'synthetic-store-authority', fetch: request });
  function configuration(operationId: string): IssuerConfigurationMetadata { return { accountId: 'demo-account', projectId: 'demo-project', serviceAccountId: 'demo-service', adapterVersion: '1', scopeIds: ['api.read'], expiresInSeconds: 3600, probeMethod: 'synthetic-cheap-v1', probeEndpointId: 'synthetic-cheap', destinationId: 'demo-vault', handleId: `operations/${operationId}`, expectedVersion: 0, issuerAuthorityFingerprint: 'demo-issuer', storeAuthorityFingerprint: 'demo-store' }; }
  async function drivers(config: IssuerConfigurationMetadata, authority: (intent: AuthorizedIntent) => Promise<AuthorizedIntent>, consumers: Pick<LifecycleDrivers, 'deliver' | 'observeConsumer' | 'observeOldUse'>): Promise<LifecycleDrivers> {
    const assessment = createAccountAssessmentWorkflow({ trustDomain: 'synthetic', observerId: 'demo-account-fixture', methodId: config.probeMethod, lifetimeMs: 600000, timeoutMs: 1000, clock, verifier: async request => ({ challenge: request.challenge, scope: request.scope, outcome: 'verified', evidence: { permission: request.scope.action, methodCapability: 'synthetic' }, limitations: ['synthetic-only'], invalidationTriggers: ['configuration-changed'] }) });
    await assessment.assess({ accountId: config.accountId, resourceId: `${config.projectId}:${config.serviceAccountId}`, action: 'validate', adapter: 'openai-service-account', adapterVersion: config.adapterVersion, authorityFingerprint: config.issuerAuthorityFingerprint, configurationHash: issuerConfigurationHash(issuerConfigurationDescriptor(config)) });
    return createIssuerLifecycleDrivers({ configuration: config, currentConfiguration: () => config, transport: { kind: 'synthetic', accountId: config.accountId, projectId: config.projectId, serviceAccountId: config.serviceAccountId, adminToken: 'synthetic-issuer-authority', fetch: request, store }, observerId: 'synthetic-issuer', clock, assertAuthority: authority, consumers,
      probe: { methodId: config.probeMethod, endpointId: config.probeEndpointId, cost: 'no-paid-work', assessment, execute: async value => ({ outcome: [...keys.values()].some(key => key.value === value) ? 'accepted' : 'rejected', confounders: [] }) },
    });
  }
  const seeded = new Set<string>();
  function target(lineageId: string) { const oldResourceId = 'old-' + createHash('sha256').update(lineageId).digest('hex').slice(0, 24); if (!seeded.has(lineageId)) { seeded.add(lineageId); keys.set(oldResourceId, { name: 'previous-' + lineageId, value: 'synthetic-old-' + randomUUID() }); } return { fromGeneration: 1, oldResourceId, oldHandleId: 'old-handle-' + lineageId }; }
  return { configuration, drivers, store, target };
}
