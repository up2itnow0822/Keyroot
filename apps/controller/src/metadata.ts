import type { Journal } from '../../../packages/core/src/journal.js';
import { publicKeyFingerprint } from '../../../packages/core/src/approval.js';
import { pinDescriptor, type ConsumerDescriptor } from '../../../packages/core/src/consumers/consumer.js';
import { assertIssuerConfigurationDescriptor } from '../../../packages/core/src/adapters/issuer-drivers.js';
import { contentDigest, parseCanonicalManifest } from '../../../packages/core/src/manifest.js';
export const controllerSchema = {
  controller_runtime: ['id', 'metadata'],
  controller_inventory: ['id', 'metadata'],
  controller_batch: ['id', 'raw_manifest'],
  controller_batch_context: ['id', 'metadata'],
  controller_descriptor: ['hash', 'metadata'],
  controller_policy: ['id', 'metadata'],
  controller_guided: ['id', 'metadata'],
} as const;
export type ControllerTable = keyof typeof controllerSchema;
function shape(value: unknown, required: readonly string[], optional: readonly string[] = []): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value) || required.some(k => !Object.hasOwn(value, k)) || Object.keys(value).some(k => !required.includes(k) && !optional.includes(k))) throw new Error('Invalid controller metadata shape');
  return value as Record<string, unknown>;
}
function id(value: unknown): asserts value is string { if (typeof value !== 'string' || !/^[-a-zA-Z0-9_.:@/]{1,256}$/.test(value)) throw new Error('Invalid metadata identifier'); }
function integer(value: unknown, min = 0): void { if (!Number.isSafeInteger(value) || Number(value) < min) throw new Error('Invalid metadata integer'); }
function choice(value: unknown, choices: readonly unknown[]): void { if (!choices.includes(value)) throw new Error('Invalid metadata choice'); }
function list(value: unknown): unknown[] { if (!Array.isArray(value) || value.length > 1000) throw new Error('Invalid metadata list'); return value; }
function ids(values: unknown[]): void { const identifiers = values.map(v => { id(v); return v; }); if (new Set(identifiers).size !== identifiers.length) throw new Error('Duplicate metadata identifier'); }
export function validateInventory(value: unknown): void {
  const inventory = shape(value, ['lineages', 'consumers', 'consumerMap', 'native']);
  const lineages = list(inventory.lineages); const consumers = list(inventory.consumers);
  for (const item of lineages) { const l = shape(item, ['id', 'issuerId', 'accountId', 'credentialType', 'grantType'], ['grantId']); for (const field of ['id', 'issuerId', 'accountId', 'credentialType']) id(l[field]); if (l.grantId !== undefined) id(l.grantId); choice(l.grantType, ['static-key', 'oauth', 'workload-identity', 'native-session', 'other', 'unknown']); }
  ids(lineages.map(l => (l as Record<string, unknown>).id));
  for (const item of consumers) { const c = shape(item, ['id', 'name', 'kind']); id(c.id); if (typeof c.name !== 'string' || c.name.length > 128 || [...c.name].some(char => char.charCodeAt(0) < 32)) throw new Error('Invalid consumer name'); choice(c.kind, ['external', 'dev-machine', 'production', 'ci', 'other']); }
  ids(consumers.map(c => (c as Record<string, unknown>).id));
  const map = shape(inventory.consumerMap, ['revision', 'bindings', 'gaps']); integer(map.revision, 1);
  for (const item of list(map.bindings)) { const b = shape(item, ['id', 'lineageId', 'consumerId', 'association'], ['generationId', 'destinationId', 'consumerRevision']); for (const field of ['id', 'lineageId', 'consumerId']) id(b[field]); if (b.generationId !== undefined) id(b.generationId); if (b.destinationId !== undefined) id(b.destinationId); if (b.consumerRevision !== undefined) id(b.consumerRevision); if (!lineages.some(l => (l as Record<string, unknown>).id === b.lineageId) || !consumers.some(c => (c as Record<string, unknown>).id === b.consumerId)) throw new Error('Unknown inventory binding'); const a = shape(b.association, ['kind', 'source', 'observedAt']); choice(a.kind, ['declared', 'observed', 'inferred']); id(a.source); if (typeof a.observedAt !== 'string' || !Number.isFinite(Date.parse(a.observedAt))) throw new Error('Invalid association time'); }
  ids(list(map.bindings).map(b => (b as Record<string, unknown>).id));
  for (const item of list(map.gaps)) { const gap = shape(item, ['kind', 'source'], ['detail']); choice(gap.kind, ['unplaced', 'inaccessible', 'unscanned']); id(gap.source); if (gap.detail !== undefined && (typeof gap.detail !== 'string' || gap.detail.length > 256)) throw new Error('Invalid gap detail'); }
  for (const item of list(inventory.native)) { const n = shape(item, ['client', 'storage', 'remoteSignOut', 'sessionTelemetry']); choice(n.client, ['codex', 'claude-code']); choice(n.storage, ['unknown']); choice(n.remoteSignOut, ['unknown']); choice(n.sessionTelemetry, ['unknown']); }
}
export function validateControllerRow(table: ControllerTable, value: Record<string, unknown>): void {
  const columns: readonly string[] = controllerSchema[table];
  if (!columns || Object.keys(value).length !== columns.length || columns.some(k => typeof value[k] !== 'string')) throw new Error('Invalid controller metadata row');
  if (table === 'controller_batch') { const m = parseCanonicalManifest(String(value.raw_manifest)); if (m.nonce !== value.id) throw new Error('Batch identity mismatch'); return; }
  const metadata: unknown = JSON.parse(String(value.metadata));
  if (!metadata || typeof metadata !== 'object' || Array.isArray(metadata)) throw new Error('Invalid controller metadata');
  if (table === 'controller_runtime') { if (value.id !== 'runtime') throw new Error('Unknown runtime record'); const r = shape(metadata, ['mode']); choice(r.mode, ['demo', 'real']); }
  if (table === 'controller_inventory') { if (value.id !== 'inventory') throw new Error('Unknown inventory record'); validateInventory(metadata); }
  if (table === 'controller_batch_context') { const context = shape(metadata, ['policyHash', 'policyScope', 'mode']); if (typeof context.policyHash !== 'string' || !/^sha256:[a-f0-9]{64}$/.test(context.policyHash)) throw new Error('Invalid policy snapshot'); ids(list(context.policyScope)); choice(context.mode, ['demo', 'real']); }
  if (table === 'controller_policy') { const p = metadata as Record<string, unknown>; if (Object.hasOwn(p, 'retired')) { shape(p, ['retired']); choice(p.retired, [true]); } else { shape(p, ['rotationDays']); integer(p.rotationDays, 1); if (Number(p.rotationDays) > 365) throw new Error('Policy outside range'); } }
  if (table === 'controller_guided') { const g = shape(metadata, ['recipeId', 'recipeHash', 'accountId', 'destinationId', 'stepIndex', 'completed']); [g.recipeId, g.accountId, g.destinationId].forEach(id); if (typeof g.recipeHash !== 'string' || !/^sha256:[a-f0-9]{64}$/.test(g.recipeHash)) throw new Error('Invalid recipe hash'); integer(g.stepIndex); if (Number(g.stepIndex) > 32) throw new Error('Invalid recipe step'); choice(g.completed, [true, false]); }
  if (table === 'controller_descriptor') {
    if (contentDigest(metadata) !== value.hash) throw new Error('Descriptor hash mismatch');
    const d = metadata as Record<string, unknown>;
    if (d.type === 'incident-plan') { shape(d, ['type', 'version', 'policy', 'affectedLineages', 'quarantineDestinations', 'outage']); choice(d.version, [1]); choice(d.policy, ['continuity-first', 'revoke-first']); const lineages = list(d.affectedLineages); ids(lineages); if (!lineages.length || lineages.length > 20) throw new Error('Invalid incident affected set'); const destinations = list(d.quarantineDestinations).map(value => { const target = shape(value, ['consumerId', 'destinationId']); id(target.consumerId); id(target.destinationId); return String(target.consumerId) + ':' + String(target.destinationId); }); if (new Set(destinations).size !== destinations.length) throw new Error('Duplicate quarantine destination'); const outage = shape(d.outage, ['permitted', 'consequence']); choice(outage.permitted, [true,false]); choice(outage.consequence, ['none', 'declared-interruption']); if (outage.permitted !== (outage.consequence === 'declared-interruption') || d.policy === 'revoke-first' && !outage.permitted) throw new Error('Invalid incident outage'); }
    else if (d.provider !== undefined) assertIssuerConfigurationDescriptor(metadata);
    else if (d.driver !== undefined) {
      choice(d.driver, ['env-file', 'github-actions', 'vercel', 'wrapper']);
      const extras: Record<string, string[]> = { 'env-file': ['mode', 'envFormat', 'rootId', 'relativePath', 'variable', 'expectedFileHash', 'backupHandle', 'backupExpectedVersion', 'backupVersion', 'backupFileHash'], 'github-actions': ['accountId', 'owner', 'repository', 'secretName', 'pushTokenFingerprint'], vercel: ['accountId', 'projectId', 'teamId', 'environment', 'variable', 'pushTokenFingerprint'], wrapper: [] };
      pinDescriptor(d as unknown as ConsumerDescriptor, extras[String(d.driver)]!);
      for (const key of extras[String(d.driver)]!) if (d[key] !== undefined) { if (key === 'relativePath') { if (typeof d[key] !== 'string' || String(d[key]).startsWith('/') || String(d[key]).split('/').some(p => !p || p === '.' || p === '..')) throw new Error('Invalid relative path'); } else if (typeof d[key] === 'number') integer(d[key]); else id(d[key]); }
    }
    else if (d.purpose === 'approver-enrollment') { shape(d, ['purpose', 'requestId', 'signerId', 'publicKey', 'fingerprint']); [d.requestId, d.signerId, d.fingerprint].forEach(id); if (publicKeyFingerprint(d.publicKey as JsonWebKey) !== d.fingerprint) throw new Error('Invalid approver descriptor'); }
    else if (d.purpose === 'emergency-enrollment') { shape(d, ['purpose', 'requestId', 'signerId', 'credentialId', 'rpId', 'origin', 'enrollmentFingerprint', 'publicFingerprint', 'registrationEvidenceHash']); [d.requestId, d.signerId, d.credentialId, d.rpId, d.enrollmentFingerprint, d.publicFingerprint, d.registrationEvidenceHash].forEach(id); if (typeof d.origin !== 'string' || new URL(d.origin).origin !== d.origin || new URL(d.origin).protocol !== 'https:' || new URL(d.origin).hostname !== d.rpId) throw new Error('Invalid registration origin'); }
    else if (d.recipeHash !== undefined) { shape(d, ['purpose', 'recipeHash', 'accountId', 'destinationId', 'authorityFingerprint']); choice(d.purpose, ['guided-completion']); [d.recipeHash, d.accountId, d.destinationId, d.authorityFingerprint].forEach(id); }
    else { shape(d, ['purpose', 'targetId', 'lineageId'], ['policy', 'inventory', 'destinationId', 'envDescriptor', 'targetDigest']); choice(d.purpose, ['cancel', 'retire', 'key-policy', 'approver-removal', 'oauth-consent', 'oauth-reconcile', 'native-sign-out', 'env-dry-run', 'env-rollback', 'platform-discovery', 'guided-completion', 'quarantine', 'inventory-update']); id(d.targetId); id(d.lineageId); if (d.targetDigest !== undefined && (d.purpose !== 'cancel' || typeof d.targetDigest !== 'string' || !/^sha256:[a-f0-9]{64}$/.test(d.targetDigest))) throw new Error('Invalid cancellation target digest'); if (d.envDescriptor !== undefined) { const descriptor = d.envDescriptor as Record<string, unknown>; validateControllerRow('controller_descriptor', { hash: contentDigest(descriptor), metadata: JSON.stringify(descriptor) }); if (d.purpose !== 'env-dry-run') throw new Error('Unexpected env descriptor'); } if (d.purpose === 'quarantine') id(d.destinationId); else if (d.destinationId !== undefined) throw new Error('Unexpected destination'); if (d.purpose === 'inventory-update') validateInventory(d.inventory); else if (d.inventory !== undefined) throw new Error('Unexpected inventory'); if (d.purpose === 'key-policy') { const p = shape(d.policy, ['rotationDays']); integer(p.rotationDays, 1); if (Number(p.rotationDays) > 365) throw new Error('Policy outside range'); } else if (d.policy !== undefined) throw new Error('Unexpected policy'); }
  }
  if (table !== 'controller_descriptor' && !/^[-a-zA-Z0-9_.:@/]{1,256}$/.test(String(value.id))) throw new Error('Invalid controller metadata id');
  if (/"(?:privateKey|secret|token|password|d)"\s*:/.test(String(value.metadata))) throw new Error('Secret-bearing metadata rejected');
}
export const controllerRowValidators = Object.fromEntries(Object.keys(controllerSchema).map(table => [table, (row: Record<string, unknown>) => validateControllerRow(table as ControllerTable, row)]));
export function initializeControllerSchema(journal: Journal): void {
  journal.transaction(db => {
    for (const [table, columns] of Object.entries(controllerSchema)) db.exec(`CREATE TABLE IF NOT EXISTS ${table} (${columns.map((column, index) => `${column} TEXT ${index === 0 ? 'PRIMARY KEY' : 'NOT NULL'}`).join(',')})`);
  });
}
export function controllerMetadataAdapter(journal: Journal) {
  initializeControllerSchema(journal);
  return { schema: controllerSchema, validateRow: validateControllerRow,
    exportRows: () => Object.fromEntries(Object.keys(controllerSchema).map(table => [table, journal.read(db => db.prepare(`SELECT * FROM ${table}`).all())])),
    importRows: (tables: Partial<Record<ControllerTable, Record<string, unknown>[]>>) => journal.transaction(db => {
      for (const [table, rows] of Object.entries(tables)) {
        if (!Object.hasOwn(controllerSchema, table)) throw new Error('Unknown controller table');
        for (const row of rows) { validateControllerRow(table as ControllerTable, row); const columns = controllerSchema[table as ControllerTable]; db.prepare(`INSERT INTO ${table} (${columns.join(',')}) VALUES (${columns.map(() => '?').join(',')})`).run(...columns.map(column => String(row[column]))); }
      }
    }),
  };
}
