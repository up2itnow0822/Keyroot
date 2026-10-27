import { randomUUID } from 'node:crypto';
import type { LifecycleDrivers, EffectContext } from '../engine.js';
import type { AuthorizedIntent } from '../journal.js';
import { canonicalJSON, contentDigest, deepFreeze, type ActionParameters } from '../manifest.js';
import { safeReceipt, type LifecycleReceipt, type LifecycleReceiptKind, type LifecycleOutcome, type ReceiptSubject } from '../receipts.js';
import { isAccountAssessmentEvaluator, type AccountAssessmentEvaluator } from './account-assessment.js';
import { createOpenAIServiceAccountAdapter, type OpenAIServiceAccountConfig } from './openai-service-account.js';

export interface IssuerConfigurationMetadata {
  accountId: string;
  projectId: string;
  serviceAccountId: string;
  adapterVersion: string;
  scopeIds: readonly string[];
  expiresInSeconds: number;
  probeMethod: string;
  probeEndpointId: string;
  destinationId: string;
  handleId: string;
  expectedVersion: number;
  issuerAuthorityFingerprint: string;
  storeAuthorityFingerprint: string;
}
export interface IssuerConfigurationDescriptor extends IssuerConfigurationMetadata {
  version: 1;
  provider: 'openai-service-account';
}
export interface IssuerActionConfigurationDescriptor extends IssuerConfigurationDescriptor {
  action: { operationId: string; actionId: string; kind: string; parameters: Readonly<Record<string, string | number>> };
}
const id = (value: unknown): value is string => typeof value === 'string' && /^[-a-zA-Z0-9_.:@/]{1,256}$/.test(value);
/** Content-addressed display material for the approval phone. It contains no values or admin material. */
export function issuerConfigurationDescriptor(metadata: IssuerConfigurationMetadata): Readonly<IssuerConfigurationDescriptor> {
  const keys = ['accountId', 'projectId', 'serviceAccountId', 'adapterVersion', 'scopeIds', 'expiresInSeconds', 'probeMethod', 'probeEndpointId', 'destinationId', 'handleId', 'expectedVersion', 'issuerAuthorityFingerprint', 'storeAuthorityFingerprint'];
  if (Object.keys(metadata).length !== keys.length || Object.keys(metadata).some(k => !keys.includes(k)) || Object.entries(metadata).some(([k, v]) => !['scopeIds', 'expiresInSeconds', 'expectedVersion'].includes(k) && !id(v)) || !Array.isArray(metadata.scopeIds) || !metadata.scopeIds.every(id) || new Set(metadata.scopeIds).size !== metadata.scopeIds.length || !Number.isSafeInteger(metadata.expiresInSeconds) || metadata.expiresInSeconds < 1 || metadata.expectedVersion !== 0) throw new Error('Invalid issuer configuration metadata');
  return deepFreeze({ ...metadata, scopeIds: [...metadata.scopeIds], version: 1, provider: 'openai-service-account' });
}
export function issuerActionConfigurationDescriptor(metadata: IssuerConfigurationMetadata, action: Pick<AuthorizedIntent, 'operationId' | 'actionId' | 'kind'> & { parameters: Readonly<ActionParameters> | Readonly<Record<string, string | number>> }): Readonly<IssuerActionConfigurationDescriptor> {
  const parameters: Record<string, string | number> = Object.fromEntries(Object.entries(action.parameters).filter(([key]) => key !== 'configurationHash'));
  if (![action.operationId, action.actionId, action.kind].every(id) || !['create', 'validate', 'revoke', 'cleanup'].includes(action.kind) || Object.entries(parameters).some(([key, value]) => !['resourceId', 'consumerId', 'destinationId', 'handleId', 'generation', 'expectedRevision', 'recipeId', 'adapterId', 'authorityFingerprint', 'reasonCode'].includes(key) || !(id(value) || typeof value === 'number' && Number.isSafeInteger(value) && value >= 0))) throw new Error('Invalid action configuration binding');
  return deepFreeze({ ...issuerConfigurationDescriptor(metadata), action: { operationId: action.operationId, actionId: action.actionId, kind: action.kind, parameters } });
}
/** Validate fetched content before the phone displays it. Unknown fields cannot smuggle provider bodies. */
export function assertIssuerConfigurationDescriptor(value: unknown): asserts value is IssuerConfigurationDescriptor | IssuerActionConfigurationDescriptor {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('Invalid issuer configuration descriptor');
  const { version, provider, action, ...metadata } = value as Record<string, unknown>;
  if (version !== 1 || provider !== 'openai-service-account') throw new Error('Invalid issuer configuration version');
  issuerConfigurationDescriptor(metadata as unknown as IssuerConfigurationMetadata);
  if (Object.hasOwn(value, 'action')) {
    if (!action || typeof action !== 'object' || Array.isArray(action) || Object.keys(action).length !== 4 || !['operationId', 'actionId', 'kind', 'parameters'].every(key => Object.hasOwn(action, key))) throw new Error('Invalid issuer action descriptor');
    const target = action as Record<string, unknown>;
    if (!target.parameters || typeof target.parameters !== 'object' || Array.isArray(target.parameters) || Object.hasOwn(target.parameters, 'configurationHash')) throw new Error('Invalid issuer action descriptor parameters');
    issuerActionConfigurationDescriptor(metadata as unknown as IssuerConfigurationMetadata, target as unknown as Pick<AuthorizedIntent, 'operationId' | 'actionId' | 'kind' | 'parameters'>);
  }
}
export function issuerConfigurationHash(descriptor: IssuerConfigurationDescriptor): string { assertIssuerConfigurationDescriptor(descriptor); return contentDigest(descriptor); }
export function assertIssuerConfigurationHash(hash: unknown, descriptor: IssuerConfigurationDescriptor): void {
  if (typeof hash !== 'string' || !/^sha256:[a-f0-9]{64}$/.test(hash) || hash !== issuerConfigurationHash(descriptor)) throw new Error('Signed issuer configuration mismatch');
}
export type ProbeConfounder = 'network' | 'rate-limit' | 'permissions' | 'endpoint-unavailable' | 'provider-health';
export interface IssuerProbePort {
  methodId: string;
  endpointId: string;
  cost: 'no-paid-work';
  assessment: AccountAssessmentEvaluator;
  execute(value: string, context: Readonly<{ subject: Readonly<ReceiptSubject>; signal?: AbortSignal }>): Promise<{ outcome: 'accepted' | 'rejected' | 'confounded' | 'unknown'; confounders: readonly ProbeConfounder[] }>;
}
export interface IssuerDriversOptions {
  transport: OpenAIServiceAccountConfig;
  configuration: IssuerConfigurationMetadata;
  /** Re-read from trusted owning configuration after asynchronous authority checks. */
  currentConfiguration?: () => IssuerConfigurationMetadata;
  assertAuthority(intent: AuthorizedIntent): Promise<AuthorizedIntent>;
  probe: IssuerProbePort;
  consumers: Pick<LifecycleDrivers, 'deliver' | 'observeConsumer' | 'observeOldUse'> & { reconcile?: LifecycleDrivers['reconcile'] };
  /** Trusted inventory supplies old-generation pinned versions; absent pins remain unknown. */
  resolvePinnedStore?: (subject: Readonly<ReceiptSubject>) => { version: number; operationId: string } | undefined;
  observerId: string;
  clock?: () => number;
  revocationObservation?: {
    methodId: string;
    assessment: AccountAssessmentEvaluator;
    execute(subject: Readonly<ReceiptSubject>, signal?: AbortSignal): Promise<{ outcome: 'confirmed-revoked' | 'confirmed-active' | 'unverified'; methodId: string }>;
  };
}
/** Trusted composition root. No owner JSON can select transports, callbacks, probes or assessment evaluators. */
export function createIssuerLifecycleDrivers(options: IssuerDriversOptions): LifecycleDrivers {
  options = Object.freeze({ ...options, transport: Object.freeze({ ...options.transport }), configuration: deepFreeze({ ...options.configuration, scopeIds: [...options.configuration.scopeIds] }), probe: Object.freeze({ ...options.probe }), consumers: Object.freeze({ ...options.consumers }), ...(options.revocationObservation ? { revocationObservation: Object.freeze({ ...options.revocationObservation }) } : {}) });
  const config = issuerConfigurationDescriptor(options.configuration);
  if (!id(options.observerId) || options.transport.accountId !== config.accountId || options.transport.projectId !== config.projectId || options.transport.serviceAccountId !== config.serviceAccountId || options.probe.methodId !== config.probeMethod || options.probe.endpointId !== config.probeEndpointId || options.probe.cost !== 'no-paid-work' || !isAccountAssessmentEvaluator(options.probe.assessment)) throw new Error('Issuer executor configuration mismatch');
  if (options.transport.kind === 'live' && !options.currentConfiguration) throw new Error('Live executor requires current trusted configuration');
  if (options.transport.kind === 'live' && (options.transport.adapterVersion !== config.adapterVersion || options.transport.authorityFingerprint !== config.issuerAuthorityFingerprint || options.transport.configurationHash !== issuerConfigurationHash(config))) throw new Error('Issuer authority configuration mismatch');
  const adapter = createOpenAIServiceAccountAdapter(options.transport);
  const now = () => options.clock?.() ?? Date.now();
  function checkConfig() {
    if (options.currentConfiguration && canonicalJSON(issuerConfigurationDescriptor(options.currentConfiguration())) !== canonicalJSON(config)) throw new Error('Current issuer configuration drift');
  }
  function exactAuthority(intent: AuthorizedIntent, authorized: AuthorizedIntent): void {
    if (!authorized || authorized.intentId !== intent.intentId || authorized.operationId !== intent.operationId || authorized.actionId !== intent.actionId || authorized.grantId !== intent.grantId || authorized.kind !== intent.kind || canonicalJSON(authorized.parameters) !== canonicalJSON(intent.parameters)) throw new Error('Exact authorized issuer intent mismatch');
  }
  function bound(intent: AuthorizedIntent, context: EffectContext) {
    checkConfig();
    assertIssuerConfigurationHash(intent.parameters.configurationHash, issuerActionConfigurationDescriptor(options.configuration, intent));
    const s = context.subject;
    if (s.operationId !== intent.operationId || s.accountId !== config.accountId || s.generation !== intent.parameters.generation || s.handleId !== intent.parameters.handleId || (s.resourceId !== intent.parameters.resourceId && !(intent.parameters.resourceId === `created:${intent.operationId}` && intent.kind === 'validate')) || (s.handleId !== config.handleId && intent.kind === 'create') || context.signal.aborted) throw new Error('Issuer intent subject mismatch');
    if (intent.parameters.authorityFingerprint !== undefined && intent.parameters.authorityFingerprint !== config.issuerAuthorityFingerprint || intent.parameters.adapterId !== undefined && intent.parameters.adapterId !== 'openai-service-account') throw new Error('Issuer authority scope mismatch');
    if (intent.kind === 'create' && (intent.parameters.resourceId !== `${config.projectId}:${config.serviceAccountId}` || config.handleId !== `operations/${intent.operationId}` || config.destinationId !== intent.parameters.destinationId || String(config.expectedVersion) !== (intent.parameters.expectedRevision ?? '0') || intent.parameters.adapterId !== 'openai-service-account')) throw new Error('Exact signed create/store binding required');
  }
  function receipt(subject: Readonly<ReceiptSubject>, kind: LifecycleReceiptKind, outcome: LifecycleOutcome, limitationCodes: string[] = [], storeBinding?: LifecycleReceipt['storeBinding']): LifecycleReceipt {
    const metadata = { subject: { ...subject }, kind, outcome, observedAt: now(), observerId: options.observerId, limitationCodes: [...(options.transport.kind === 'synthetic' ? ['synthetic-only'] : []), ...limitationCodes], ...(storeBinding ? { storeBinding } : {}) };
    return safeReceipt({ ...metadata, receiptId: randomUUID(), evidenceHash: contentDigest(metadata) });
  }
  function admitProbe() {
    checkConfig();
    const assessment = options.probe.assessment.evaluate({ accountId: config.accountId, resourceId: `${config.projectId}:${config.serviceAccountId}`, action: 'validate', adapter: 'openai-service-account', adapterVersion: config.adapterVersion, authorityFingerprint: config.issuerAuthorityFingerprint, configurationHash: issuerConfigurationHash(config) }, options.transport.kind === 'live' ? 'live' : 'synthetic');
    if (!assessment.admitted) throw new Error('Admitted issuer-specific probe required');
  }
  async function probe(subject: Readonly<ReceiptSubject>, signal?: AbortSignal) {
    admitProbe();
    let confounders: readonly ProbeConfounder[] = [];
    const pin = subject.handleId === config.handleId ? { version: config.expectedVersion + 1, operationId: subject.operationId } : options.resolvePinnedStore?.(subject);
    if (!pin || !Number.isSafeInteger(pin.version) || pin.version < 1 || !id(pin.operationId)) return { status: 'unknown' as const, confounders };
    const version = pin.version;
    const current = await options.transport.store.metadata(subject.handleId);
    const stored = await options.transport.store.metadata(subject.handleId, version);
    if (current.status !== 'found' || current.version !== version || stored.status !== 'found' || stored.version !== version || !stored.binding || stored.binding.operationId !== pin.operationId || stored.binding.issuerId !== subject.resourceId || stored.binding.accountId !== config.accountId || stored.binding.projectId !== config.projectId || stored.binding.serviceAccountId !== config.serviceAccountId) return { status: 'unknown' as const, confounders };
    const consumer = options.transport.store.consumer([subject.handleId]);
    const outcome = await adapter.probe({ withValue: execute => consumer.withValue(subject.handleId, version, execute) }, async value => {
      if (signal?.aborted) return 'unknown';
      admitProbe();
      const result = await options.probe.execute(value, { subject, ...(signal ? { signal } : {}) });
      confounders = result.confounders;
      if (!Array.isArray(confounders) || confounders.some(c => !['network', 'rate-limit', 'permissions', 'endpoint-unavailable', 'provider-health'].includes(c))) return 'unknown';
      return confounders.length ? 'confounded' : result.outcome;
    });
    return { ...outcome, confounders };
  }
  async function observeIssuer(subject: Readonly<ReceiptSubject>, signal?: AbortSignal): Promise<LifecycleReceipt> {
    checkConfig();
    if (subject.accountId !== config.accountId || signal?.aborted) throw new Error('Issuer observation scope mismatch');
    const observer = options.revocationObservation;
    if (observer) {
      if (!isAccountAssessmentEvaluator(observer.assessment) || !observer.assessment.evaluate({ accountId: config.accountId, resourceId: `${config.projectId}:${config.serviceAccountId}`, action: 'observe', adapter: 'openai-service-account', adapterVersion: config.adapterVersion, authorityFingerprint: config.issuerAuthorityFingerprint, configurationHash: issuerConfigurationHash(config) }, options.transport.kind === 'live' ? 'live' : 'synthetic').admitted) throw new Error('Admitted revocation method required');
      try { const result = await observer.execute(subject, signal); return receipt(subject, 'issuer', result.methodId === observer.methodId && ['confirmed-revoked', 'confirmed-active', 'unverified'].includes(result.outcome) ? result.outcome : 'unverified', [observer.methodId]); } catch { return receipt(subject, 'issuer', 'unverified', [observer.methodId]); }
    }
    const result = await adapter.observe(subject.resourceId);
    return receipt(subject, 'issuer', result.status, ['metadata-get-cannot-prove-revoked']);
  }
  async function revoke(intent: AuthorizedIntent, context: EffectContext): Promise<LifecycleReceipt> {
    bound(intent, context);
    const result = await adapter.revoke(context.subject.resourceId, async () => { exactAuthority(intent, await options.assertAuthority(intent)); bound(intent, context); });
    return receipt(context.subject, intent.kind === 'cleanup' ? 'cleanup' : 'revoke', result.status === 'acknowledged' ? 'issuer-acknowledged' : 'unverified', ['delete-ack-is-not-revocation-proof']);
  }
  return {
    deliver: options.consumers.deliver,
    observeConsumer: options.consumers.observeConsumer,
    observeOldUse: options.consumers.observeOldUse,
    async create(intent, context) {
      if (intent.kind !== 'create') throw new Error('Wrong issuer action');
      bound(intent, context);
      if (context.storeTarget.destinationId !== config.destinationId || context.storeTarget.handleId !== config.handleId || context.storeTarget.expectedVersion !== config.expectedVersion) throw new Error('Compound store target mismatch');
      exactAuthority(intent, await options.assertAuthority(intent)); bound(intent, context);
      const result = await adapter.create({ operationId: intent.operationId, scopes: [...config.scopeIds], expiresInSeconds: config.expiresInSeconds, storeTarget: context.storeTarget, signal: context.signal, beforeStore: async () => { exactAuthority(intent, await context.beforeStore()); bound(intent, context); } });
      const subject = { ...context.subject, ...('issuerId' in result ? { resourceId: result.issuerId } : {}) };
      if (result.status === 'created') return receipt(subject, 'create', 'stored', [], { operationId: subject.operationId, lineageId: subject.lineageId, accountId: subject.accountId, generation: subject.generation, issuerId: result.issuerId, handleId: result.handle, destinationId: config.destinationId, version: result.version });
      return receipt(subject, 'create', result.status === 'created-unrecoverable' ? 'created-unrecoverable' : 'unknown', [result.status]);
    },
    async validate(intent, context) {
      if (intent.kind !== 'validate') throw new Error('Wrong issuer action');
      bound(intent, context); exactAuthority(intent, await options.assertAuthority(intent)); bound(intent, context);
      const result = await probe(context.subject, context.signal);
      return receipt(context.subject, 'validate', result.status === 'accepted' ? 'validated' : result.status === 'rejected' ? 'rejected' : 'unknown', [...result.confounders]);
    },
    revoke,
    cleanup: revoke,
    async reconcile(intent, context) {
      if (intent.kind === 'deliver') { if (!options.consumers.reconcile) throw new Error('Consumer reconciliation port missing'); return options.consumers.reconcile(intent, context); }
      bound(intent, context);
      if (intent.kind === 'create') {
        const result = await adapter.reconcile(intent.operationId, { expectedVersion: config.expectedVersion });
        const subject = { ...context.subject, ...('issuerId' in result ? { resourceId: result.issuerId } : {}) };
        if (result.status === 'stored-candidate') return receipt(subject, 'create', 'stored', ['reconciled-issuer-and-pinned-store'], { operationId: subject.operationId, lineageId: subject.lineageId, accountId: subject.accountId, generation: subject.generation, issuerId: result.issuerId, handleId: config.handleId, destinationId: config.destinationId, version: result.version });
        return receipt(subject, 'create', result.status === 'created-unrecoverable' ? 'created-unrecoverable' : 'orphan-unresolved', [result.status]);
      }
      if (intent.kind === 'validate') { const result = await probe(context.subject, context.signal); return receipt(context.subject, 'validate', result.status === 'accepted' ? 'validated' : result.status === 'rejected' ? 'rejected' : 'unknown', [...result.confounders]); }
      if (intent.kind === 'revoke' || intent.kind === 'cleanup') { const observed = await observeIssuer(context.subject, context.signal); return receipt(context.subject, intent.kind, observed.outcome, observed.limitationCodes); }
      throw new Error('Unsupported issuer reconciliation');
    },
    observeIssuer,
    async probeOld(subject, signal) { const result = await probe(subject, signal); return receipt(subject, 'probe', result.status, [...result.confounders]); }
  };
}
