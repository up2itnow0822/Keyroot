import { randomUUID, randomBytes, createPublicKey, verify } from 'node:crypto';
import { Journal, type AuthorizedIntent } from '../../../packages/core/src/journal.js';
import { createLocalBootstrapContext, publicKeyFingerprint, type RealAdmissionContext, type AuthorizeEffectRequest } from '../../../packages/core/src/approval.js';
import { canonicalJSON, canonicalizeManifest, contentDigest, manifestDigest, parseCanonicalManifest, snapshotDigest, type ApprovalManifest, type ManifestAction } from '../../../packages/core/src/manifest.js';
import { type LifecycleDrivers, type LifecycleRequest } from '../../../packages/core/src/engine.js';
import { createScheduledEngine, Scheduler, ForecastStore } from '../../../packages/core/src/schedule.js';
import { QuarantineStore, IncidentCoordinator } from '../../../packages/core/src/incident.js';
import { MutationInterlock } from '../../../packages/core/src/notifier.js';
import { OwnerMetrics } from '../../../packages/core/src/metrics.js';
import { EmergencyWebAuthn } from '../../../packages/core/src/emergency-webauthn.js';
import { OAuthCoordinator, type OAuthExecutor } from '../../../packages/core/src/oauth.js';
import { signOutNative, type NativeSignOutExecutor } from '../../../packages/core/src/native-sessions.js';
import { scanPlatforms, type PlatformProvider } from '../../../packages/core/src/discovery/platform.js';
import { GuidedProcedure, authorizeRecipeAction, recordRecipeAction, recipeHash, recipeDescriptor, type Recipe } from '../../../packages/core/src/recipes/recipe.js';
import { issuerActionConfigurationDescriptor, type IssuerConfigurationMetadata } from '../../../packages/core/src/adapters/issuer-drivers.js';
import type { CredentialLineage, Consumer, ConsumerMap } from '../../../packages/core/src/inventory.js';
import { inspectEnvTarget, createEnvFileConsumer, type EnvMaintenanceTarget } from './http/env.js';
import { EmergencyEnrollmentController } from './http/enrollment.js';
import { createDemoPorts } from './demo.js';
import { initializeControllerSchema, controllerMetadataAdapter, validateInventory } from './metadata.js';
import { exactObject, HttpFailure, identifier } from './auth.js';
export type ControllerMode = 'demo' | 'real';
export type AdministrativeAction = 'cancel' | 'retire' | 'key-policy' | 'approver-removal' | 'oauth-consent' | 'oauth-reconcile' | 'native-sign-out' | 'env-dry-run' | 'env-rollback' | 'platform-discovery' | 'guided-completion' | 'quarantine' | 'emergency-enrollment' | 'inventory-update' | 'approver-enrollment';
export interface Inventory { lineages: CredentialLineage[]; consumers: Consumer[]; consumerMap: ConsumerMap; native: Array<{ client: 'codex' | 'claude-code'; storage: 'unknown'; remoteSignOut: 'unknown'; sessionTelemetry: 'unknown' }> }
export interface TrustedControllerPorts {
  /** Actual owning workflows assert scoped, fresh observations. No request JSON constructs these ports. */
  assertLiveAdmission?: (context: Readonly<RealAdmissionContext>) => Promise<void>;
  liveGates?: { account: () => Promise<void>; store: () => Promise<void>; phoneCustody: () => Promise<void>; origin: () => Promise<void>; isolation: () => Promise<void>; recovery: () => Promise<void> };
  lineageTargets?: (lineageId: string) => { fromGeneration: number; oldResourceId: string; oldHandleId: string };
  deliveryActions?: (operationId: string, lineageId: string, generation: number) => Array<{ action: ManifestAction; descriptor: unknown }>;
  validity?: (lineageId: string, signal: AbortSignal) => Promise<'confirmed-active' | 'confirmed-revoked' | 'unverified'>;
  issuerConfiguration?: (operationId: string, lineageId: string) => IssuerConfigurationMetadata;
  lifecycleDrivers?: (configuration: IssuerConfigurationMetadata, authority: (intent: AuthorizedIntent) => Promise<AuthorizedIntent>) => Promise<LifecycleDrivers>;
  consumers?: Pick<LifecycleDrivers, 'deliver' | 'observeConsumer' | 'observeOldUse'>;
  native?: NativeSignOutExecutor;
  oauth?: OAuthExecutor;
  platforms?: readonly PlatformProvider[];
  envTargets?: readonly EnvMaintenanceTarget[];
  env?: { dryRun(targetId: string, request: AuthorizeEffectRequest): Promise<{ outcome: 'matched' | 'changed' | 'unavailable'; targetId: string; limitationCodes: string[] }>; rollback(targetId: string, request: AuthorizeEffectRequest): Promise<{ outcome: 'applied' | 'unknown' | 'rejected'; targetId: string; limitationCodes: string[] }> };
  recipes?: readonly Recipe[];
}
/** Demo composition is closed: neither direct construction nor embedding may inject external ports. */
export function assertControllerModePorts(mode: ControllerMode, ports?: TrustedControllerPorts): void {
  if (mode === 'demo' && ports !== undefined && (ports === null || typeof ports !== 'object' || Reflect.ownKeys(ports).length !== 0 || ![Object.prototype, null].includes(Object.getPrototypeOf(ports)))) throw new Error('Demo runtime rejects external ports');
}
export interface IncidentPlan { type: 'incident-plan'; version: 1; policy: 'continuity-first' | 'revoke-first'; affectedLineages: string[]; quarantineDestinations: Array<{ consumerId: string; destinationId: string }>; outage: { permitted: boolean; consequence: 'none' | 'declared-interruption' } }
export interface OperationProgress { operationId: string; state: string; actions: Array<{ actionId: string; kind: string; state: 'not-started' | 'pending' | 'observed' | 'unknown' }>; nextActionId: string | null; dispatchComplete: boolean; outcome: { issuer: string; probe: string; replacement: string; deadline: string; holds: string[] } | null }
export interface PreparedBatch { batchId: string; rawManifest: string; digest: string; configurationHashes: string[]; progress: OperationProgress[]; emergencyRegistration: { grantId: string; digest: string } | null; summary: { accountIds: string[]; lineages: string[]; effects: number; mode: ControllerMode; expiresAt: number } }
export interface PairingChallenge { requestId: string; nonce: string; installationId: string; signerId: string; fingerprint: string; expiresAt: number }
interface PairRequest { requestId: string; signerId: string; publicKey: JsonWebKey; fingerprint: string; expiresAt: number; status: 'pending' | 'proved' | 'paired'; challenge: PairingChallenge; proofUsed: boolean }
export class ControllerService {
  readonly interlock: MutationInterlock; readonly quarantine: QuarantineStore; readonly metrics: OwnerMetrics; readonly forecast: ForecastStore;
  readonly approvals; readonly engine; readonly scheduler: Scheduler; readonly incidents: IncidentCoordinator; readonly emergency: EmergencyWebAuthn; readonly oauth: OAuthCoordinator | undefined;
  readonly metadata;
  private readonly pairs = new Map<string, PairRequest>();
  private readonly executors = new Map<string, LifecycleDrivers>();
  private active: ApprovalManifest | undefined; private busy = false;
  private readonly demo;
  enrollment: EmergencyEnrollmentController | undefined; private configuredPhoneOrigin: string | undefined;
  configurePhoneOrigin(origin: string): void { if (this.enrollment) throw new Error('Phone origin already configured'); this.enrollment = new EmergencyEnrollmentController(origin, this.clock); this.configuredPhoneOrigin = origin; }
  constructor(readonly journal: Journal, readonly mode: ControllerMode, private readonly ports: TrustedControllerPorts = {}, private readonly clock: () => number = Date.now) {
    assertControllerModePorts(mode, ports); if (mode === 'demo') this.ports = Object.freeze({});
    initializeControllerSchema(journal); this.metadata = controllerMetadataAdapter(journal);
    journal.transaction(db => { const existing = db.prepare("SELECT metadata FROM controller_runtime WHERE id='runtime'").get(); if (existing && (JSON.parse(String(existing.metadata)) as { mode: string }).mode !== mode) throw new Error(mode === 'demo' ? 'Real metadata cannot enter demo runtime' : 'Demo metadata cannot enter real runtime'); db.prepare("INSERT INTO controller_runtime VALUES('runtime',?) ON CONFLICT(id) DO UPDATE SET metadata=excluded.metadata").run(canonicalJSON({ mode })); });
    this.interlock = new MutationInterlock(journal); this.quarantine = new QuarantineStore(journal); this.metrics = new OwnerMetrics(journal, clock); this.forecast = new ForecastStore(journal);
    this.demo = mode === 'demo' ? createDemoPorts(clock) : undefined;
    const unavailable = async (): Promise<never> => { throw new HttpFailure(503, 'coverage_unavailable'); };
    const dispatch = <K extends keyof LifecycleDrivers>(kind: K): LifecycleDrivers[K] => ((...args: unknown[]) => {
      const first = args[0] as { operationId?: string }; const operationId = first?.operationId;
      const driver = operationId ? this.executors.get(operationId) : undefined;
      const fn = driver?.[kind]; return fn ? Reflect.apply(fn, driver, args) : unavailable();
    }) as LifecycleDrivers[K];
    const drivers: LifecycleDrivers = { create: dispatch('create'), validate: dispatch('validate'), deliver: dispatch('deliver'), revoke: dispatch('revoke'), cleanup: dispatch('cleanup')!, reconcile: dispatch('reconcile'), observeConsumer: dispatch('observeConsumer'), observeOldUse: dispatch('observeOldUse'), observeIssuer: dispatch('observeIssuer'), probeOld: dispatch('probeOld') };
    const composed = createScheduledEngine(journal, this.interlock, drivers, { mode: mode === 'demo' ? 'synthetic' : 'real', clock, assertRealAdmission: async context => {
      if (!ports.liveGates || !ports.assertLiveAdmission || !ports.lifecycleDrivers) throw new HttpFailure(503, 'live_admission_unavailable');
      for (const evaluate of Object.values(ports.liveGates)) await evaluate(); await ports.assertLiveAdmission(context);
    } }, { currentSnapshot: () => { if (!this.active) throw new Error('No current prepared scope'); this.assertCurrent(this.active); return this.active; }, clock });
    this.approvals = composed.approvals; this.engine = composed.engine; this.scheduler = new Scheduler(this.engine, this.interlock, { clock }); this.incidents = new IncidentCoordinator(this.engine, this.interlock, clock); this.emergency = new EmergencyWebAuthn(journal, { clock });
    this.oauth = ports.oauth ? new OAuthCoordinator(journal, this.approvals, ports.oauth) : undefined;
    if (!journal.read(db => db.prepare("SELECT 1 FROM controller_inventory WHERE id='inventory'").get())) this.put('controller_inventory', 'inventory', this.initialInventory());
  }
  private initialInventory(): Inventory {
    return { lineages: this.mode === 'demo' ? [{ id: 'demo-lineage', issuerId: 'openai-service-account', accountId: 'demo-account', credentialType: 'service-account-key', grantType: 'static-key' }] : [], consumers: [1, 2, 3, 4].map(n => ({ id: `machine-${n}`, name: `Declared machine ${n}`, kind: 'dev-machine' as const })), consumerMap: { revision: 1, bindings: [], gaps: [1, 2, 3, 4].map(n => ({ kind: 'unscanned', source: `machine-${n}` })) }, native: ['codex', 'claude-code'].map(client => ({ client: client as 'codex' | 'claude-code', storage: 'unknown', remoteSignOut: 'unknown', sessionTelemetry: 'unknown' })) };
  }
  private put(table: 'controller_inventory' | 'controller_policy' | 'controller_guided', id: string, value: unknown): void {
    const row = { id, metadata: canonicalJSON(value) }; this.metadata.validateRow(table, row);
    this.journal.transaction(db => { this.journal.assertCurrent(db); db.prepare(`INSERT INTO ${table} VALUES(?,?) ON CONFLICT(id) DO UPDATE SET metadata=excluded.metadata`).run(id, row.metadata); });
  }
  inventory(): Inventory { return this.journal.read(db => JSON.parse(String(db.prepare("SELECT metadata FROM controller_inventory WHERE id='inventory'").get()!.metadata)) as Inventory); }
  overview() { return { mode: this.mode, phoneOrigin: this.configuredPhoneOrigin, approvers: this.journal.read(db => db.prepare('SELECT signer_id AS signerId,role,fingerprint FROM approver WHERE revoked=0 ORDER BY signer_id').all()), installationId: this.journal.installationId, bootId: this.journal.bootId, inventory: this.inventory(), batches: this.batches(), operations: this.journal.read(db => db.prepare('SELECT operation_id,state,lineage_id FROM operation').all()), outbox: this.interlock.list(), alarms: this.interlock.alarms(), liveAdmission: this.mode === 'demo' ? 'synthetic-only' : this.ports.liveGates ? 'configured-pending-fresh-evaluation' : 'unavailable', policies: this.journal.read(db => db.prepare('SELECT id,metadata FROM controller_policy').all().map(row => ({ id: row.id, policy: JSON.parse(String(row.metadata)) as unknown }))), coverage: { consumers: this.ports.consumers ? 'configured' : 'unavailable', oauth: this.oauth ? 'configured' : 'unavailable', native: this.ports.native ? 'configured' : 'unavailable', env: this.ports.envTargets?.length || this.ports.env ? 'configured' : 'unavailable', platforms: this.ports.platforms?.length ? 'configured' : 'unavailable' } }; }
  pairing(input: unknown) {
    const body = exactObject(input, ['signerId', 'publicKey', 'role']); if (body.role !== 'routine') throw new HttpFailure(400, 'routine_pairing_only');
    const publicKey = exactObject(body.publicKey, ['kty', 'crv', 'x', 'y'], ['ext', 'key_ops']) as JsonWebKey;
    let fingerprint: string; try { fingerprint = publicKeyFingerprint(publicKey); } catch { throw new HttpFailure(400, 'public_key_required'); }
    for (const [key, value] of this.pairs) if (value.expiresAt <= this.clock()) this.pairs.delete(key);
    if (this.pairs.size >= 16) throw new HttpFailure(429, 'pairing_limit');
    const requestId = randomUUID(); const expiresAt = this.clock() + 300000; const signerId = identifier(body.signerId);
    const challenge: PairingChallenge = { requestId, nonce: randomBytes(32).toString('base64url'), installationId: this.journal.installationId, signerId, fingerprint, expiresAt };
    const pair: PairRequest = { requestId, signerId, publicKey, fingerprint, expiresAt, status: 'pending', challenge, proofUsed: false }; this.pairs.set(requestId, pair);
    return { requestId, fingerprint, expiresAt, challenge };
  }
  pairingProof(id: string, input: unknown) {
    const body = exactObject(input, ['signature']); const pair = this.pairs.get(id);
    if (!pair || pair.proofUsed || pair.expiresAt <= this.clock()) throw new HttpFailure(409, 'pairing_proof_expired');
    pair.proofUsed = true; const bytes = Buffer.from(String(body.signature), 'base64url');
    if (bytes.length !== 64 || !verify('sha256', Buffer.from('keyroot.pairing-possession.v1\0' + canonicalJSON(pair.challenge)), { key: createPublicKey({ key: pair.publicKey as import('node:crypto').JsonWebKey, format: 'jwk' }), dsaEncoding: 'ieee-p1363' }, bytes)) throw new HttpFailure(403, 'pairing_proof_denied');
    pair.status = 'proved'; return { status: pair.status };
  }
  pairingStatus(id: string) { const pair = this.pairs.get(id); if (!pair || pair.expiresAt <= this.clock()) throw new HttpFailure(404, 'pairing_not_found'); return { status: pair.status }; }
  pairingMetadata(id: string) { const pair = this.pairs.get(id); if (!pair || pair.expiresAt <= this.clock()) throw new HttpFailure(404, 'pairing_not_found'); return { requestId: pair.requestId, status: pair.status, role: 'routine', proved: pair.status === 'proved' || pair.status === 'paired', signerId: pair.signerId, fingerprint: pair.fingerprint, expiresAt: pair.expiresAt }; }
  /** Called exclusively by protected local Unix channel, never by an HTTP route. */
  confirmLocalPairing(id: string, independentlyComparedFingerprint: string): void {
    const pair = this.pairs.get(id); if (!pair || pair.status !== 'proved' || pair.expiresAt <= this.clock()) throw new HttpFailure(409, 'pairing_expired');
    this.approvals.bootstrapApprover({ signerId: pair.signerId, role: 'routine', publicKey: pair.publicKey, confirmedFingerprint: independentlyComparedFingerprint, localBootstrap: createLocalBootstrapContext() }); pair.status = 'paired';
  }
  private configuration(operationId: string, lineageId: string): IssuerConfigurationMetadata {
    const config = this.demo?.configuration(operationId) ?? this.ports.issuerConfiguration?.(operationId, lineageId); if (!config) throw new HttpFailure(503, 'issuer_configuration_unavailable'); return config;
  }
  private descriptor(value: unknown): string { const hash = contentDigest(value); this.metadata.validateRow('controller_descriptor', { hash, metadata: canonicalJSON(value) }); this.journal.transaction(db => db.prepare('INSERT OR IGNORE INTO controller_descriptor VALUES(?,?)').run(hash, canonicalJSON(value))); return hash; }
  configurationDescriptor(hash: string) { const row = this.journal.read(db => db.prepare('SELECT metadata FROM controller_descriptor WHERE hash=?').get(hash)); if (!row) throw new HttpFailure(404, 'descriptor_not_found'); return { hash, descriptor: JSON.parse(String(row.metadata)) as unknown }; }
  batches(): PreparedBatch[] { return this.journal.read(db => db.prepare('SELECT id FROM controller_batch ORDER BY rowid DESC').all()).map(row => this.batch(String(row.id))); }
  batch(id: string): PreparedBatch {
    const row = this.journal.read(db => db.prepare('SELECT raw_manifest FROM controller_batch WHERE id=?').get(id)); if (!row) throw new HttpFailure(404, 'batch_not_found');
    const rawManifest = String(row.raw_manifest); const manifest = parseCanonicalManifest(rawManifest);
    const digest = manifestDigest(rawManifest); let emergencyRegistration: PreparedBatch['emergencyRegistration'] = null;
    if (manifest.role === 'emergency' && manifest.nonce === id && manifest.installationId === this.journal.installationId && manifest.bootId === this.journal.bootId && this.clock() >= manifest.notBefore && this.clock() < manifest.expiresAt) {
      const grant = this.journal.read(db => db.prepare("SELECT g.raw_manifest,g.digest FROM approval_grant g JOIN approver a ON a.signer_id=? AND a.role='emergency' AND a.revoked=0 WHERE g.grant_id=? AND g.role='emergency' AND g.cancelled=0 AND g.boot_id=?").get(manifest.signerId, id, this.journal.bootId));
      if (grant?.raw_manifest === rawManifest && grant.digest === digest) { try { this.assertCurrent(manifest); emergencyRegistration = { grantId: id, digest }; } catch { /* stale registrations cannot be resumed */ } }
    }
    return { batchId: id, rawManifest, digest, emergencyRegistration, progress: manifest.operations.map(operation => this.progress(operation)), configurationHashes: [...new Set(manifest.operations.flatMap(op => op.actions.flatMap(a => [a.parameters.configurationHash, (a.parameters as typeof a.parameters & { incidentPlanHash?: string }).incidentPlanHash].filter((hash): hash is string => !!hash))))], summary: { accountIds: [...new Set(manifest.operations.map(op => op.accountId))], lineages: manifest.operations.map(op => op.lineageId), effects: manifest.budgets.effects, mode: this.mode, expiresAt: manifest.expiresAt } };
  }
  private progress(operation: ApprovalManifest['operations'][number]): OperationProgress {
    const intents = this.journal.listIntents(operation.operationId); const existing = this.journal.inspectOperation(operation.operationId); const snapshot = existing ? this.engine.inspect(operation.operationId) : undefined;
    const actions = operation.actions.map(action => ({ actionId: action.id, kind: action.kind, state: intents.find(intent => intent.actionId === action.id)?.state ?? 'not-started' as const }));
    const next = actions.find((action, index) => action.state === 'not-started' && actions.slice(0, index).every(prior => prior.state === 'observed'));
    return { operationId: operation.operationId, state: snapshot?.state ?? 'not-started', actions, nextActionId: next?.actionId ?? null, dispatchComplete: actions.every(a => a.state === 'observed'), outcome: snapshot ? { issuer: snapshot.issuer, probe: snapshot.probe, replacement: snapshot.replacement, deadline: snapshot.deadline, holds: snapshot.holds } : null };
  }
  prepare(input: unknown): PreparedBatch {
    const body = exactObject(input, ['signerId', 'lineageIds'], ['role', 'purpose', 'targetId', 'policy', 'inventory', 'incident']);
    const signerId = identifier(body.signerId); const role = body.role === 'emergency' ? 'emergency' : 'routine'; if (body.role !== undefined && !['routine', 'emergency'].includes(String(body.role))) throw new HttpFailure(400, 'invalid_role');
    const signer = this.journal.read(db => db.prepare('SELECT role FROM approver WHERE signer_id=? AND revoked=0').get(signerId)); if (signer?.role !== role) throw new HttpFailure(403, 'paired_role_required');
    if (!Array.isArray(body.lineageIds) || !body.lineageIds.length || body.lineageIds.length > 20 || new Set(body.lineageIds).size !== body.lineageIds.length) throw new HttpFailure(400, 'finite_lineages_required');
    const inventory = this.inventory(); const now = this.clock();
    let updatedInventory: Inventory | undefined;
    if (body.purpose === 'inventory-update') { identifier(body.targetId); validateInventory(body.inventory); updatedInventory = body.inventory as Inventory; if (updatedInventory.consumerMap.revision !== inventory.consumerMap.revision + 1) throw new HttpFailure(409, 'map_revision_required'); }
    const selectedLineages = body.lineageIds.map((value: unknown) => {
      const lineageId = identifier(value); const lineage = inventory.lineages.find(item => item.id === lineageId) ?? updatedInventory?.lineages.find(item => item.id === lineageId);
      if (!lineage) throw new HttpFailure(404, 'lineage_not_found'); return lineage;
    });
    let incidentPlan: IncidentPlan | undefined; let incidentPlanHash: string | undefined;
    if (role === 'emergency') {
      if (body.purpose && body.purpose !== 'rotation') throw new HttpFailure(400, 'incident_role_scope_required');
      const proposal = exactObject(body.incident, ['policy', 'quarantineDestinations', 'outage']);
      if (!['continuity-first', 'revoke-first'].includes(String(proposal.policy)) || !Array.isArray(proposal.quarantineDestinations) || proposal.quarantineDestinations.length > 100) throw new HttpFailure(400, 'invalid_incident_plan');
      const outage = exactObject(proposal.outage, ['permitted', 'consequence']);
      if (typeof outage.permitted !== 'boolean' || !['none', 'declared-interruption'].includes(String(outage.consequence)) || outage.permitted !== (outage.consequence === 'declared-interruption') || proposal.policy === 'revoke-first' && !outage.permitted) throw new HttpFailure(400, 'explicit_incident_outage_required');
      const quarantineDestinations = proposal.quarantineDestinations.map(value => { const d = exactObject(value, ['consumerId', 'destinationId']); const destination = { consumerId: identifier(d.consumerId), destinationId: identifier(d.destinationId) }; if (!inventory.consumerMap.bindings.some(b => body.lineageIds instanceof Array && body.lineageIds.includes(b.lineageId) && b.consumerId === destination.consumerId && b.destinationId === destination.destinationId)) throw new HttpFailure(400, 'quarantine_outside_affected_inventory'); return destination; }).sort((a,b) => (a.consumerId + ':' + a.destinationId).localeCompare(b.consumerId + ':' + b.destinationId));
      if (new Set(quarantineDestinations.map(d => d.consumerId + ':' + d.destinationId)).size !== quarantineDestinations.length) throw new HttpFailure(400, 'duplicate_quarantine_destination');
      incidentPlan = { type: 'incident-plan', version: 1, policy: proposal.policy as IncidentPlan['policy'], affectedLineages: (body.lineageIds as string[]).map(identifier).sort(), quarantineDestinations, outage: { permitted: outage.permitted, consequence: outage.consequence as IncidentPlan['outage']['consequence'] } }; incidentPlanHash = this.descriptor(incidentPlan);
    } else if (body.incident !== undefined) throw new HttpFailure(400, 'incident_role_required');
    const operations = selectedLineages.map(lineage => {
      const lineageId = lineage.id;
      const retired = this.journal.read(db => db.prepare('SELECT metadata FROM controller_policy WHERE id=?').get(lineageId)); if ((!body.purpose || body.purpose === 'rotation') && retired && (JSON.parse(String(retired.metadata)) as { retired?: boolean }).retired) throw new HttpFailure(409, 'lineage_retired');
      const operationId = randomUUID(); const cost = { effects: 1, newCredentials: 0, restarts: 0 }; let actions: ManifestAction[];
      if (body.purpose && body.purpose !== 'rotation') {
        const purpose = identifier(body.purpose); const allowed = ['cancel', 'retire', 'key-policy', 'approver-removal', 'oauth-consent', 'oauth-reconcile', 'native-sign-out', 'env-dry-run', 'env-rollback', 'platform-discovery', 'guided-completion', 'quarantine', 'emergency-enrollment', 'inventory-update', 'approver-enrollment']; if (!allowed.includes(purpose)) throw new HttpFailure(400, 'unknown_action');
        const targetId = identifier(body.targetId); let policy: unknown;
        if (['retire', 'key-policy'].includes(purpose) && !inventory.lineages.some(l => l.id === targetId)) throw new HttpFailure(404, 'lineage_not_found');
        if (purpose === 'native-sign-out' && !['codex', 'claude-code'].includes(targetId)) throw new HttpFailure(400, 'native_client_unknown');
        if (purpose === 'approver-removal' && !this.journal.read(db => db.prepare('SELECT 1 FROM approver WHERE signer_id=? AND revoked=0').get(targetId))) throw new HttpFailure(404, 'approver_not_found');
        const cancelTarget = purpose === 'cancel' ? this.cancellationTarget(targetId) : undefined;
        if (purpose === 'key-policy') { const p = exactObject(body.policy, ['rotationDays']); if (!Number.isSafeInteger(p.rotationDays) || Number(p.rotationDays) < 1 || Number(p.rotationDays) > 365) throw new HttpFailure(400, 'invalid_policy'); policy = p; }
        const quarantineBinding = purpose === 'quarantine' ? inventory.consumerMap.bindings.find(b => b.consumerId === targetId && b.lineageId === lineageId) as (Inventory['consumerMap']['bindings'][number] & { destinationId?: string; consumerRevision?: string }) | undefined : undefined;
        if (purpose === 'quarantine' && (!quarantineBinding?.destinationId || !quarantineBinding.consumerRevision)) throw new HttpFailure(503, 'consumer_mapping_unavailable');
        const routinePair = purpose === 'approver-enrollment' ? this.pairs.get(targetId) : undefined;
        if (purpose === 'approver-enrollment' && (!routinePair || routinePair.status !== 'proved' || routinePair.expiresAt <= this.clock())) throw new HttpFailure(409, 'proved_pairing_required');
        const routineEnrollment = routinePair ? { purpose: 'approver-enrollment', requestId: routinePair.requestId, signerId: routinePair.signerId, publicKey: routinePair.publicKey, fingerprint: routinePair.fingerprint } : undefined;
        const enrollment = purpose === 'emergency-enrollment' ? this.enrollment?.descriptor(targetId) : undefined;
        if (purpose === 'emergency-enrollment' && !enrollment) throw new HttpFailure(503, 'enrollment_unavailable');
        const envTarget = ['env-dry-run', 'env-rollback'].includes(purpose) ? this.ports.envTargets?.find(t => t.id === targetId) : undefined;
        if (purpose === 'env-rollback' && (!envTarget || envTarget.descriptor.mode !== 'rollback' || envTarget.descriptor.consumerMapRevision !== 'map-' + inventory.consumerMap.revision)) throw new HttpFailure(503, 'env_rollback_coverage_unavailable');
        const descriptor = purpose === 'env-rollback' ? envTarget!.descriptor : enrollment ?? routineEnrollment ?? { purpose, targetId, lineageId, ...(cancelTarget ? { targetDigest: cancelTarget.digest } : {}), ...(policy ? { policy } : {}), ...(updatedInventory ? { inventory: updatedInventory } : {}), ...(quarantineBinding ? { destinationId: quarantineBinding.destinationId } : {}), ...(envTarget ? { envDescriptor: envTarget.descriptor } : {}) }; const configurationHash = this.descriptor(descriptor);
        const family = ['oauth-consent', 'oauth-reconcile'].includes(purpose) ? this.oauth?.inspect(targetId) : undefined;
        if (['oauth-consent', 'oauth-reconcile'].includes(purpose) && !family) throw new HttpFailure(503, 'oauth_family_unavailable');
        const recipe = purpose === 'guided-completion' ? this.ports.recipes?.find(r => r.id === targetId) : undefined;
        actions = [{ id: purpose, kind: purpose === 'env-rollback' ? 'deliver' : purpose === 'native-sign-out' ? 'sign-out' : purpose === 'quarantine' ? 'quarantine' : 'admin', parameters: { resourceId: purpose === 'native-sign-out' ? `native:${targetId}:local` : targetId, generation: 2, authorityFingerprint: 'controller-owner', reasonCode: purpose, configurationHash, ...(purpose === 'quarantine' ? { consumerId: targetId, destinationId: quarantineBinding!.destinationId!, expectedRevision: quarantineBinding!.consumerRevision! } : {}), ...(envTarget && purpose === 'env-rollback' ? { resourceId: targetId, consumerId: envTarget.descriptor.consumerId, destinationId: envTarget.descriptor.destinationId, handleId: envTarget.descriptor.handleId, generation: envTarget.descriptor.generation, expectedRevision: envTarget.descriptor.revision } : {}), ...(family ? { resourceId: family.grantId, handleId: family.familyId, destinationId: family.ownerId, expectedRevision: String(family.version) } : {}), ...(routineEnrollment ? { resourceId: 'routine-approver', destinationId: routineEnrollment.signerId, authorityFingerprint: routineEnrollment.fingerprint } : {}), ...(enrollment ? { resourceId: 'emergency-approver', destinationId: enrollment.signerId, authorityFingerprint: enrollment.enrollmentFingerprint } : {}), ...(recipe ? { resourceId: recipe.id, recipeId: recipe.id, expectedRevision: recipe.version, destinationId: recipe.destinationId, configurationHash: recipeDescriptor(recipe, 'guided-completion', 'controller-owner') } : {}) }, budgetCost: cost }];
        if (recipe) this.journal.transaction(db => db.prepare('INSERT OR IGNORE INTO controller_descriptor VALUES(?,?)').run(actions[0]!.parameters.configurationHash!, canonicalJSON({ purpose: 'guided-completion', recipeHash: contentDigest(recipe), accountId: recipe.accountId, destinationId: recipe.destinationId, authorityFingerprint: 'controller-owner' })));
      } else {
        const config = this.configuration(operationId, lineageId);
        const target = this.demo ? this.demo.target(lineageId) : this.ports.lineageTargets?.(lineageId);
        if (!target || !Number.isSafeInteger(target.fromGeneration) || target.fromGeneration < 0) throw new HttpFailure(503, 'lineage_target_unavailable');
        actions = [
          { id: 'create', kind: 'create', parameters: { resourceId: `${config.projectId}:${config.serviceAccountId}`, adapterId: 'openai-service-account', handleId: config.handleId, destinationId: config.destinationId, generation: 2, expectedRevision: '0' }, budgetCost: { effects: 2, newCredentials: 1, restarts: 0 } },
          { id: 'validate', kind: 'validate', parameters: { resourceId: `created:${operationId}`, handleId: config.handleId, generation: 2 }, budgetCost: cost },
          { id: 'revoke', kind: 'revoke', parameters: { resourceId: target.oldResourceId, handleId: target.oldHandleId, generation: target.fromGeneration }, budgetCost: cost },
        ];
        if (incidentPlan?.policy === 'revoke-first') { actions = actions.filter(action => action.kind === 'revoke'); actions[0]!.parameters.reasonCode = 'incident-revoke-first'; }
        if (incidentPlanHash) for (const action of actions) (action.parameters as typeof action.parameters & { incidentPlanHash?: string }).incidentPlanHash = incidentPlanHash;
        for (const action of actions) { if (action.kind !== 'revoke') action.parameters.generation = target.fromGeneration + 1; action.parameters.configurationHash = this.descriptor(issuerActionConfigurationDescriptor(config, { operationId, actionId: action.id, kind: action.kind, parameters: action.parameters })); }
        if (role === 'routine' || incidentPlan?.policy === 'continuity-first') { const configured = this.ports.deliveryActions?.(operationId, lineageId, target.fromGeneration + 1) ?? []; for (const item of configured) { if (incidentPlanHash) (item.action.parameters as typeof item.action.parameters & { incidentPlanHash?: string }).incidentPlanHash = incidentPlanHash; if (item.action.kind !== 'deliver') throw new Error('Configured consumer action must deliver'); item.action.parameters.configurationHash = this.descriptor(item.descriptor); } actions.splice(2, 0, ...configured.map(item => item.action)); }
      }
      const administrative = !!body.purpose && body.purpose !== 'rotation';
      const operationLineage = administrative ? 'admin:' + identifier(body.targetId) : lineageId;
      const prior = administrative ? this.journal.read(db => db.prepare("SELECT MAX(to_generation) AS generation FROM operation WHERE lineage_id=? AND state='completed'").get(operationLineage)) : undefined;
      const envGeneration = body.purpose === 'env-rollback' ? actions[0]!.parameters.generation : undefined;
      const fromGeneration = envGeneration !== undefined ? Number(envGeneration) - 1 : administrative ? Number(prior?.generation ?? 0) : this.demo ? 1 : this.ports.lineageTargets?.(lineageId)?.fromGeneration ?? 1;
      if (administrative) for (const action of actions) if (action.parameters.generation !== undefined) action.parameters.generation = fromGeneration + 1;
      return { operationId, lineageId: operationLineage, accountId: lineage.accountId, fromGeneration, toGeneration: fromGeneration + 1, actions };
    });
    const totals = operations.flatMap(op => op.actions).reduce((sum, a) => ({ effects: sum.effects + a.budgetCost.effects, newCredentials: sum.newCredentials + a.budgetCost.newCredentials, restarts: sum.restarts + a.budgetCost.restarts }), { effects: 0, newCredentials: 0, restarts: 0 });
    const consumerMap = this.signedConsumerMap(inventory, body.purpose && body.purpose !== 'rotation' ? [] : body.lineageIds as string[]);
    // A maintenance deliver retains its separate administrative lineage while binding its exact U6 target.
    for (const operation of operations) for (const action of operation.actions) if (action.kind === 'deliver' && action.parameters.reasonCode === 'env-rollback' || action.kind === 'quarantine') consumerMap.entries.push({ lineageId: operation.lineageId, consumerId: action.parameters.consumerId!, resourceId: action.parameters.destinationId!, revision: action.parameters.expectedRevision! });
    consumerMap.hash = contentDigest(consumerMap.entries);
    const manifest: ApprovalManifest = { version: 1, domain: 'keyroot.approval.v1', algorithm: 'ECDSA-P256-SHA256', audience: 'keyroot-controller', installationId: this.journal.installationId, bootId: this.journal.bootId, signerId, role, nonce: randomUUID(), notBefore: now, expiresAt: now + 300000, budgets: { ...totals, executions: operations.length }, operations, consumerMap: { revision: 'map-' + inventory.consumerMap.revision, ...consumerMap }, recipes: [], adoptionThreshold: 'direct-use-every-consumer', overlapPolicy: incidentPlan?.policy === 'revoke-first' ? 'unavailable' : 'required', deadline: { at: now + 240000, outcome: 'hold' }, outage: incidentPlan?.outage ?? { permitted: false, consequence: 'none' }, graceSeconds: 900 };
    const raw = canonicalizeManifest(manifest); this.journal.transaction(db => { db.prepare('INSERT INTO controller_batch VALUES(?,?)').run(manifest.nonce, raw); db.prepare('INSERT INTO controller_batch_context VALUES(?,?)').run(manifest.nonce, canonicalJSON({ policyHash: this.policyHash(body.lineageIds as string[]), policyScope: body.lineageIds, mode: this.mode })); }); return this.batch(manifest.nonce);
  }
  private signedConsumerMap(inventory: Inventory, selectedLineages: readonly string[]) {
    const bindings = inventory.consumerMap.bindings.filter(b => selectedLineages.includes(b.lineageId));
    const entries = bindings.map(binding => {
      const b = binding as typeof binding & { destinationId?: string; consumerRevision?: string };
      if (!b.destinationId || !b.consumerRevision) throw new HttpFailure(503, 'consumer_mapping_unavailable');
      return { consumerId: b.consumerId, lineageId: b.lineageId, resourceId: b.destinationId, revision: b.consumerRevision };
    });
    if (new Set(entries.map(e => e.consumerId + ':' + e.lineageId)).size !== entries.length) throw new HttpFailure(409, 'consumer_mapping_conflict');
    return { hash: contentDigest(entries), entries };
  }
  async validity(lineageId: string) { if (!this.ports.validity) throw new HttpFailure(503, 'validity_coverage_unavailable'); if (!this.inventory().lineages.some(l => l.id === lineageId)) throw new HttpFailure(404, 'lineage_not_found'); return this.scheduler.validity(lineageId, 3600000, signal => this.ports.validity!(lineageId, signal)); }
  private incidentPlan(manifest: ApprovalManifest): IncidentPlan {
    if (manifest.role !== 'emergency') throw new HttpFailure(403, 'emergency_role_required');
    const hashes = [...new Set(manifest.operations.flatMap(op => op.actions.map(a => (a.parameters as typeof a.parameters & { incidentPlanHash?: string }).incidentPlanHash)))];
    if (hashes.length !== 1 || !hashes[0]) throw new HttpFailure(409, 'signed_incident_plan_required');
    const hash = hashes[0]; const plan = this.configurationDescriptor(hash).descriptor as IncidentPlan;
    if (plan.type !== 'incident-plan' || contentDigest(plan) !== hash || canonicalJSON(plan.affectedLineages) !== canonicalJSON(manifest.operations.map(op => op.lineageId).sort()) || canonicalJSON(plan.outage) !== canonicalJSON(manifest.outage)) throw new HttpFailure(409, 'incident_plan_mismatch');
    for (const destination of plan.quarantineDestinations) if (!manifest.consumerMap.entries.some(e => e.consumerId === destination.consumerId && e.resourceId === destination.destinationId)) throw new HttpFailure(409, 'signed_quarantine_scope_changed');
    for (const operation of manifest.operations) { const first = operation.actions[0]; if (plan.policy === 'revoke-first' && (first?.kind !== 'revoke' || first.parameters.reasonCode !== 'incident-revoke-first' || !plan.outage.permitted) || plan.policy === 'continuity-first' && first?.kind !== 'create') throw new HttpFailure(409, 'incident_policy_mismatch'); }
    return plan;
  }
  private policyHash(scope: readonly string[]): string { return contentDigest(this.journal.read(db => db.prepare('SELECT id,metadata FROM controller_policy ORDER BY id').all()).filter(row => scope.includes(String(row.id))).map(row => ({ id: row.id, policy: JSON.parse(String(row.metadata)) as unknown }))); }
  private assertCurrent(manifest: ApprovalManifest): void {
    if (manifest.role === 'emergency') this.incidentPlan(manifest);
    const contextRow = this.journal.read(db => db.prepare('SELECT metadata FROM controller_batch_context WHERE id=?').get(manifest.nonce)); if (!contextRow) throw new HttpFailure(409, 'batch_context_unavailable'); const context = JSON.parse(String(contextRow.metadata)) as { policyHash: string; policyScope: string[]; mode: ControllerMode }; if (context.mode !== this.mode || this.policyHash(context.policyScope) !== context.policyHash) throw new HttpFailure(409, 'policy_changed');
    if (manifest.bootId !== this.journal.bootId || manifest.consumerMap.revision !== 'map-' + this.inventory().consumerMap.revision) throw new HttpFailure(409, 'scope_changed');
    for (const op of manifest.operations) for (const action of op.actions) if (['create', 'validate', 'revoke', 'cleanup'].includes(action.kind)) {
      const descriptor = issuerActionConfigurationDescriptor(this.configuration(op.operationId, op.lineageId), { operationId: op.operationId, actionId: action.id, kind: action.kind, parameters: action.parameters });
      if (contentDigest(descriptor) !== action.parameters.configurationHash) throw new HttpFailure(409, 'configuration_changed');
    }
  }
  approve(input: unknown) {
    const body = exactObject(input, ['batchId', 'rawManifest'], ['signature']); const batch = this.batch(identifier(body.batchId));
    if (body.rawManifest !== batch.rawManifest) throw new HttpFailure(409, 'manifest_changed'); const manifest = parseCanonicalManifest(batch.rawManifest); this.assertCurrent(manifest);
    const grantId = manifest.role === 'emergency' ? this.approvals.registerEmergencyGrant(batch.rawManifest, this.clock()) : this.approvals.registerGrant(batch.rawManifest, String(body.signature ?? ''), this.clock()); return { grantId, digest: batch.digest };
  }
  private cancellationTarget(id: string): { digest: string } {
    const row = this.journal.read(db => db.prepare('SELECT raw_manifest,digest FROM approval_grant WHERE grant_id=? AND cancelled=0').get(id));
    if (!row) throw new HttpFailure(404, 'grant_not_found');
    const raw = String(row.raw_manifest); const manifest = parseCanonicalManifest(raw); const digest = manifestDigest(raw);
    if (manifest.nonce !== id || row.digest !== digest || manifest.installationId !== this.journal.installationId) throw new HttpFailure(409, 'scope_changed');
    return { digest };
  }
  private grant(id: string): { manifest: ApprovalManifest; signature: string } {
    const row = this.journal.read(db => db.prepare('SELECT raw_manifest,signature FROM approval_grant WHERE grant_id=? AND cancelled=0').get(id)); if (!row) throw new HttpFailure(404, 'grant_not_found'); const manifest = parseCanonicalManifest(String(row.raw_manifest)); this.assertCurrent(manifest); return { manifest, signature: String(row.signature) };
  }
  private request(body: Record<string, unknown>): AuthorizeEffectRequest {
    const grantId = identifier(body.grantId); const { manifest, signature } = this.grant(grantId); return { grantId, signature, operationId: identifier(body.operationId), actionId: identifier(body.actionId), currentSnapshotDigest: snapshotDigest(manifest), ...(body.emergencyProofId ? { emergencyProofId: identifier(body.emergencyProofId) } : {}) };
  }
  private assertRequestCurrent(request: AuthorizeEffectRequest): void {
    const { manifest } = this.grant(request.grantId); const now = this.clock();
    if (now < manifest.notBefore || now >= manifest.expiresAt) throw new HttpFailure(409, 'approval_expired');
    if (snapshotDigest(manifest) !== request.currentSnapshotDigest) throw new HttpFailure(409, 'scope_changed');
  }
  async run(input: unknown) {
    const body = exactObject(input, ['grantId', 'operationId'], ['emergencyProofs']); if (this.busy) throw new HttpFailure(409, 'controller_busy');
    const { manifest, signature } = this.grant(identifier(body.grantId)); const operationId = identifier(body.operationId); if (!manifest.operations.some(op => op.operationId === operationId)) throw new HttpFailure(403, 'operation_outside_grant');
    this.busy = true; this.active = manifest;
    try {
      await this.prepareExecutors(manifest);
      const request: LifecycleRequest = { operationId, grantId: manifest.nonce, signature, ...(body.emergencyProofs ? { emergencyProofs: this.proofs(body.emergencyProofs) } : {}) }; return await this.engine.run(request);
    } finally { this.active = undefined; this.busy = false; }
  }
  private async prepareExecutors(manifest: ApprovalManifest): Promise<void> {
    for (const op of manifest.operations) {
        const config = this.configuration(op.operationId, op.lineageId); const authority = async (intent: AuthorizedIntent) => {
          const proof = manifest.role === 'emergency' ? this.journal.read(db => db.prepare('SELECT proof_id FROM emergency_proof WHERE grant_id=? AND operation_id=? AND action_id=? AND used=1 AND expires_at>? ORDER BY rowid DESC LIMIT 1').get(intent.grantId, intent.operationId, intent.actionId, this.clock())) : undefined;
          const request = this.request({ grantId: intent.grantId, operationId: intent.operationId, actionId: intent.actionId }); const authorized = await this.approvals.assertReservedIntentAuthority({ ...request, intentId: intent.intentId, ...(proof ? { emergencyProofId: String(proof.proof_id) } : {}) }); this.assertRequestCurrent(request); return authorized;
        };
        const unavailable = async (): Promise<never> => { throw new HttpFailure(503, 'consumer_coverage_unavailable'); };
        const consumers = this.ports.consumers ?? { deliver: unavailable, observeConsumer: unavailable, observeOldUse: unavailable };
        const drivers = this.demo ? await this.demo.drivers(config, authority, consumers) : await this.ports.lifecycleDrivers?.(config, authority);
        if (!drivers) throw new HttpFailure(503, 'lifecycle_coverage_unavailable'); this.executors.set(op.operationId, drivers);
      }
  }
  async tick(grantId: string) {
    if (this.busy) throw new HttpFailure(409, 'controller_busy'); const row = this.journal.read(db => db.prepare('SELECT raw_manifest FROM approval_grant WHERE grant_id=?').get(grantId)); if (!row) throw new HttpFailure(404, 'grant_not_found'); const manifest = parseCanonicalManifest(String(row.raw_manifest)); this.busy = true; this.active = manifest;
    try { await this.prepareExecutors(manifest); return await this.scheduler.tick(grantId); } finally { this.active = undefined; this.busy = false; }
  }
  prepareIncident(grantId: string, proofId: string) { const { manifest } = this.grant(grantId); const plan = this.incidentPlan(manifest); return this.incidents.prepare(grantId, proofId, plan.quarantineDestinations); }
  async executeIncident(input: unknown) {
    const body = exactObject(input, ['grantId', 'proofs']); const grantId = identifier(body.grantId);
    if (this.busy) throw new HttpFailure(409, 'controller_busy'); const { manifest } = this.grant(grantId);
    if (manifest.role !== 'emergency') throw new HttpFailure(403, 'emergency_role_required');
    const raw = exactObject(body.proofs, [], manifest.operations.map(op => op.operationId)); const proofs = Object.fromEntries(Object.entries(raw).map(([id, p]) => [id, this.proofs(p)]));
    const firstProof = Object.values(proofs).flatMap(p => Object.values(p)).find(id => this.journal.read(db => db.prepare('SELECT 1 FROM emergency_proof WHERE proof_id=? AND grant_id=? AND used=0 AND expires_at>?').get(id, grantId, this.clock()))); if (!firstProof) throw new HttpFailure(403, 'verified_assertion_required');
    this.prepareIncident(grantId, firstProof);
    this.busy = true; this.active = manifest;
    try { await this.prepareExecutors(manifest); return await this.incidents.execute(grantId, proofs); } finally { this.active = undefined; this.busy = false; }
  }
  private proofs(input: unknown): Record<string, string> { const object = exactObject(input, [], Object.keys(input as object)); return Object.fromEntries(Object.entries(object).map(([k, v]) => [identifier(k), identifier(v)])); }
  inspect(id: string) { const operation = this.journal.inspectOperation(id); return { operation, snapshot: operation ? this.engine.inspect(id) : null, intents: this.journal.listIntents(id), receipts: this.journal.listReceipts(id) }; }
  async reconcile(id: string) {
    identifier(id); if (this.busy) throw new HttpFailure(409, 'controller_busy'); const row = this.journal.read(db => db.prepare('SELECT g.raw_manifest FROM approval_grant g JOIN intent i ON i.grant_id=g.grant_id WHERE i.operation_id=? ORDER BY i.rowid DESC LIMIT 1').get(id));
    if (!row) throw new HttpFailure(404, 'operation_not_found'); const manifest = parseCanonicalManifest(String(row.raw_manifest)); this.busy = true;
    try { await this.prepareExecutors(manifest); return await this.engine.reconcile(id); } finally { this.busy = false; }
  }
  async administrative(kind: AdministrativeAction, input: unknown): Promise<unknown> {
    const body = exactObject(input, ['grantId', 'operationId', 'actionId'], ['emergencyProofId']); const request = this.request(body); const { manifest } = this.grant(request.grantId);
    const action = manifest.operations.find(op => op.operationId === request.operationId)?.actions.find(a => a.id === request.actionId);
    if (!action || action.parameters.reasonCode !== kind) throw new HttpFailure(403, 'signed_action_mismatch');
    if (kind === 'approver-enrollment') {
      const descriptor = this.configurationDescriptor(action.parameters.configurationHash!).descriptor as { requestId: string; signerId: string; fingerprint: string; publicKey: JsonWebKey };
      const pair = this.pairs.get(descriptor.requestId);
      if (!pair || pair.status !== 'proved' || pair.expiresAt <= this.clock() || pair.signerId !== descriptor.signerId || pair.fingerprint !== descriptor.fingerprint || canonicalJSON(pair.publicKey) !== canonicalJSON(descriptor.publicKey) || manifest.role !== 'routine') throw new HttpFailure(409, 'proved_pairing_required');
      if (action.parameters.destinationId !== pair.signerId || action.parameters.authorityFingerprint !== pair.fingerprint) throw new HttpFailure(403, 'signed_approver_mismatch');
      return this.authorizedObservation(request, async () => { this.journal.transaction(db => { this.journal.assertCurrent(db); db.prepare("INSERT INTO approver(signer_id,role,public_key,fingerprint) VALUES(?,'routine',?,?)").run(pair.signerId, canonicalJSON(pair.publicKey), pair.fingerprint); }); pair.status = 'paired'; return { outcome: 'enrolled', signerId: pair.signerId }; });
    }
    if (kind === 'emergency-enrollment') {
      const descriptor = this.configurationDescriptor(action.parameters.configurationHash!).descriptor as { requestId: string };
      if (!this.enrollment || contentDigest(this.enrollment.descriptor(descriptor.requestId)) !== action.parameters.configurationHash) throw new HttpFailure(409, 'enrollment_scope_changed');
      const intent = await this.approvals.authorizeEffect(request); this.assertRequestCurrent(request); const enrollment = this.enrollment.consume(descriptor.requestId);
      this.emergency.enrollCredential({ ...enrollment, authorizationIntentId: intent.intentId, now: this.clock() }); this.journal.completeOperation(request.operationId); return { outcome: 'enrolled', signerId: enrollment.signerId, physicalCustody: 'unverified' };
    }
    if (kind === 'native-sign-out') {
      if (!this.ports.native || !['native:codex:local', 'native:claude-code:local'].includes(String(action.parameters.resourceId))) throw new HttpFailure(503, 'native_coverage_unavailable');
      try { await signOutNative({ client: action.parameters.resourceId === 'native:codex:local' ? 'codex' : 'claude-code', approval: this.approvals, request, executor: { execute: async action => { this.assertRequestCurrent(request); await this.ports.native!.execute(action); } } }); }
      catch (error) { if (!this.journal.listReceipts(request.operationId).some(r => r.kind === 'sign-out' && r.outcome === 'unknown')) throw error; this.journal.transaction(db => { db.prepare("UPDATE intent SET state='unknown' WHERE operation_id=? AND kind='sign-out'").run(request.operationId); db.prepare("UPDATE operation SET state='reconcile-required' WHERE operation_id=?").run(request.operationId); }); }
      this.completeIfObserved(request.operationId); const receipt = this.journal.listReceipts(request.operationId).filter(r => r.kind === 'sign-out').at(-1); return { outcome: receipt?.outcome === 'confirmed' ? 'local-command-confirmed' : 'unverified', remoteSession: 'unverified' };
    }
    if (kind === 'guided-completion') {
      const recipe = this.ports.recipes?.find(r => r.id === action.parameters.recipeId); if (!recipe) throw new HttpFailure(503, 'recipe_coverage_unavailable'); const procedure = new GuidedProcedure(recipe, { journal: this.journal, procedureId: recipe.id }); if (procedure.current()) throw new HttpFailure(409, 'guided_steps_incomplete');
      const intentId = await authorizeRecipeAction(this.approvals, request, procedure.recipe, 'guided-completion', 'controller-owner'); this.assertRequestCurrent(request);
      if (!request.signature) throw new HttpFailure(409, 'completion_authority_unavailable');
      const receiptId = recordRecipeAction(this.approvals, request, procedure.recipe, intentId, ['owner-attestation', 'provider-unverified', 'store-unverified']);
      this.journal.transaction(db => { const changed = db.prepare('UPDATE guided_draft SET completed=1 WHERE procedure_id=? AND recipe_hash=? AND step_index=? AND completed=0').run(procedure.recipe.id, recipeHash(procedure.recipe), procedure.recipe.steps.length); if (changed.changes !== 1) throw new Error('Draft changed concurrently'); });
      this.completeIfObserved(request.operationId); return { receiptId, intentId, grantId: request.grantId, signature: request.signature, recipeHash: recipeHash(procedure.recipe), limitation: 'Owner attestation only; provider outcome and secret storage are not independently verified.' };
    }
    if (kind === 'env-rollback') {
      const target = this.ports.envTargets?.find(t => t.id === action.parameters.resourceId && contentDigest(t.descriptor) === action.parameters.configurationHash); if (!target) throw new HttpFailure(503, 'env_rollback_coverage_unavailable');
      const d = target.descriptor; const intent = await this.approvals.authorizeEffect(request); this.assertRequestCurrent(request); const operation = manifest.operations.find(op => op.operationId === request.operationId)!;
      const driver = createEnvFileConsumer({ ...target, trust: { clock: this.clock, quarantine: (consumerId, destinationId) => this.quarantine.check(consumerId, destinationId), beforeEffect: async reserved => { await this.approvals.assertReservedIntentAuthority({ ...request, intentId: reserved.intentId }); this.assertRequestCurrent(request); } } });
      const receipt = await driver.deliver(intent, { subject: { operationId: request.operationId, lineageId: operation.lineageId, accountId: operation.accountId, generation: d.generation, resourceId: target.id, handleId: d.handleId, consumerMapRevision: d.consumerMapRevision, consumerId: d.consumerId, revision: d.revision }, signal: new AbortController().signal });
      this.journal.appendReceipt({ receiptId: receipt.receiptId, intentId: intent.intentId, kind: 'delivery-accepted', outcome: receipt.outcome === 'delivery-accepted' ? 'confirmed' : receipt.outcome === 'rejected' ? 'rejected' : 'unknown', generation: d.generation, observedAt: receipt.observedAt, observerId: receipt.observerId, evidenceHash: receipt.evidenceHash, resourceId: target.id, accountId: operation.accountId, consumerId: d.consumerId, destinationId: d.destinationId, handleId: d.handleId, revision: d.revision, limitationCodes: receipt.limitationCodes });
      if (receipt.outcome !== 'delivery-accepted') this.journal.transaction(db => { db.prepare("UPDATE intent SET state='unknown' WHERE intent_id=?").run(intent.intentId); db.prepare("UPDATE operation SET state='reconcile-required' WHERE operation_id=?").run(request.operationId); });
      if (receipt.outcome === 'delivery-accepted') { this.journal.resolveIntent({ intentId: intent.intentId, receiptIds: [receipt.receiptId] }); this.journal.completeOperation(request.operationId); }
      return { outcome: receipt.outcome, targetId: target.id, limitationCodes: receipt.limitationCodes };
    }
    const descriptor = this.configurationDescriptor(action.parameters.configurationHash!).descriptor as { purpose: string; targetId: string; policy?: { rotationDays: number }; inventory?: Inventory; destinationId?: string; targetDigest?: string };
    if (descriptor.purpose !== kind || contentDigest(descriptor) !== action.parameters.configurationHash) throw new HttpFailure(403, 'action_descriptor_mismatch');
    if (kind === 'oauth-consent' || kind === 'oauth-reconcile') {
      if (!this.oauth) throw new HttpFailure(503, 'oauth_coverage_unavailable'); const family = this.oauth.inspect(descriptor.targetId); if (!family) throw new HttpFailure(404, 'oauth_family_not_found');
      if (kind === 'oauth-reconcile') return this.authorizedObservation(request, () => this.oauth!.reconcile(family)); const port = this.ports.oauth!;
      const scoped = new OAuthCoordinator(this.journal, this.approvals, { refresh: input => port.refresh(input), revoke: input => port.revoke(input), reconcile: input => port.reconcile(input), consent: async input => { this.assertRequestCurrent(request); return port.consent({ ...input, beforeStore: async () => { await input.beforeStore(); this.assertRequestCurrent(request); } }); } });
      const result = await scoped.consent({ ...family, request }); this.completeIfObserved(request.operationId); return { outcome: result };
    }
    if (kind === 'env-dry-run') { const target = this.ports.envTargets?.find(t => t.id === descriptor.targetId); if (target) return this.authorizedObservation(request, () => inspectEnvTarget(target)); if (!this.ports.env) throw new HttpFailure(503, 'env_coverage_unavailable'); return this.authorizedObservation(request, () => this.ports.env!.dryRun(descriptor.targetId, request)); }
    if (kind === 'platform-discovery') { if (!this.ports.platforms?.length || !this.ports.platforms.some(p => p.id === descriptor.targetId)) throw new HttpFailure(503, 'platform_coverage_unavailable'); return this.authorizedObservation(request, () => scanPlatforms(this.ports.platforms!.filter(p => p.id === descriptor.targetId))); }
    return this.authorizedObservation(request, async () => {
      if (kind === 'inventory-update') { if (!descriptor.inventory || descriptor.inventory.consumerMap.revision !== this.inventory().consumerMap.revision + 1) throw new HttpFailure(409, 'inventory_changed'); this.put('controller_inventory', 'inventory', descriptor.inventory); }
      else if (kind === 'cancel') { if (this.cancellationTarget(descriptor.targetId).digest !== descriptor.targetDigest) throw new HttpFailure(409, 'scope_changed'); this.approvals.cancelGrant(descriptor.targetId); }
      else if (kind === 'approver-removal') this.approvals.revokeApprover(descriptor.targetId);
      else if (kind === 'key-policy') this.put('controller_policy', descriptor.targetId, descriptor.policy);
      else if (kind === 'retire') this.put('controller_policy', descriptor.targetId, { retired: true });
      else if (kind === 'quarantine') this.journal.transaction(db => db.prepare('INSERT OR IGNORE INTO schedule_quarantine VALUES(?,?,?)').run(descriptor.targetId, descriptor.destinationId!, request.grantId));
      return { outcome: 'recorded', kind, targetId: descriptor.targetId };
    });
  }
  private completeIfObserved(operationId: string): void { const intents = this.journal.listIntents(operationId); if (intents.length && intents.every(i => i.state === 'observed')) this.journal.completeOperation(operationId); }
  private async authorizedObservation(request: AuthorizeEffectRequest, execute: () => Promise<unknown>): Promise<unknown> {
    const intent = await this.approvals.authorizeEffect(request); this.assertRequestCurrent(request); const result = await execute(); const operation = this.journal.inspectOperation(request.operationId)!; const receiptId = randomUUID();
    this.journal.appendReceipt({ receiptId, intentId: intent.intentId, kind: intent.kind === 'quarantine' ? 'quarantine' : 'administration', outcome: 'confirmed', generation: Number(intent.parameters.generation ?? operation.toGeneration), accountId: operation.accountId, resourceId: String(intent.parameters.resourceId), ...(intent.parameters.consumerId ? { consumerId: String(intent.parameters.consumerId) } : {}), ...(intent.parameters.destinationId ? { destinationId: String(intent.parameters.destinationId) } : {}), ...(intent.parameters.expectedRevision ? { revision: String(intent.parameters.expectedRevision) } : {}), observedAt: this.clock(), observerId: 'keyroot-local-controller', evidenceHash: contentDigest({ intentId: intent.intentId, result }), limitationCodes: ['local-controller-action-only'] });
    this.journal.resolveIntent({ intentId: intent.intentId, receiptIds: [receiptId] }); this.journal.completeOperation(request.operationId); return result;
  }
  guided(id: string, targetId?: string, checkpointAcknowledged = false) { const recipe = this.ports.recipes?.find(r => r.id === id); if (!recipe) throw new HttpFailure(503, 'recipe_coverage_unavailable'); const procedure = new GuidedProcedure(recipe, { journal: this.journal, procedureId: id }); if (targetId) procedure.confirmStep(targetId, checkpointAcknowledged); return { recipe, current: procedure.current() ?? null }; }
}
