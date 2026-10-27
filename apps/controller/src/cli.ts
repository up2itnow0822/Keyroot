import { connect } from 'node:net';
import { join } from 'node:path';
import { homedir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { resolve } from 'node:path';
export const defaultDirectory = (mode: 'demo' | 'real' = 'demo') => join(homedir(), mode === 'demo' ? '.keyroot-demo' : '.keyroot');
const controllerCodes = new Set(['action_descriptor_mismatch', 'approval_expired', 'approver_not_found', 'batch_context_unavailable', 'batch_not_found', 'body_too_large', 'challenge_limit', 'completion_authority_unavailable', 'configuration_changed', 'consumer_coverage_unavailable', 'consumer_mapping_conflict', 'consumer_mapping_unavailable', 'controller_busy', 'controller_storage_unavailable', 'coverage_unavailable', 'cross_origin_ceremony_denied', 'csrf_required', 'descriptor_not_found', 'duplicate_quarantine_destination', 'emergency_role_required', 'enrollment_challenge_expired', 'enrollment_limit', 'enrollment_scope_changed', 'enrollment_unavailable', 'env_coverage_unavailable', 'env_rollback_coverage_unavailable', 'env_target_unavailable', 'explicit_incident_outage_required', 'finite_lineages_required', 'grant_not_found', 'guided_steps_incomplete', 'host_denied', 'incident_plan_mismatch', 'incident_policy_mismatch', 'incident_role_required', 'incident_role_scope_required', 'invalid_body', 'invalid_checkpoint', 'invalid_emergency_key', 'invalid_exchange', 'invalid_identifier', 'invalid_incident_plan', 'invalid_json', 'invalid_policy', 'invalid_read_target', 'invalid_role', 'inventory_changed', 'issuer_configuration_unavailable', 'json_required', 'lifecycle_coverage_unavailable', 'lineage_not_found', 'lineage_retired', 'lineage_target_unavailable', 'live_admission_unavailable', 'manifest_changed', 'map_revision_required', 'native_client_unknown', 'native_coverage_unavailable', 'not_found', 'oauth_coverage_unavailable', 'oauth_family_not_found', 'oauth_family_unavailable', 'operation_not_found', 'operation_outside_grant', 'origin_denied', 'paired_role_required', 'pairing_expired', 'pairing_limit', 'pairing_not_found', 'pairing_proof_denied', 'pairing_proof_expired', 'phone_origin_denied', 'platform_coverage_unavailable', 'policy_changed', 'proved_pairing_required', 'public_key_required', 'quarantine_outside_affected_inventory', 'query_not_allowed', 'read_nonce_denied', 'read_signature_denied', 'recipe_coverage_unavailable', 'registration_not_found', 'request_rejected', 'routine_pairing_only', 'scope_changed', 'secure_emergency_origin_required', 'session_required', 'signed_action_mismatch', 'signed_approver_mismatch', 'signed_incident_plan_required', 'signed_quarantine_scope_changed', 'single_device_emergency_key_required', 'unknown_action', 'unpaired_signer', 'validity_coverage_unavailable', 'verified_assertion_required', 'verified_registration_required']);
class CLIError extends Error { constructor(readonly code: string) { super(code); } }
const cliMode = () => process.env.KEYROOT_MODE === 'real' ? 'real' : 'demo';
/** Private local channel to the existing controller; no Journal constructor or boot mutation. */
export async function localCommand(directory: string, command: Record<string, string>): Promise<Record<string, unknown>> {
  return new Promise((resolve, reject) => {
    const socket = connect(join(directory, 'admin.sock')); let raw = '';
    socket.setTimeout(5000, () => { socket.destroy(); reject(new CLIError('controller_unavailable')); });
    socket.on('error', () => reject(new CLIError('controller_unavailable')));
    socket.on('connect', () => socket.write(JSON.stringify(command) + '\n'));
    socket.on('data', chunk => { raw += chunk.toString('utf8'); if (raw.length > 8192) { socket.destroy(); reject(new CLIError('local_response_invalid')); } });
    socket.on('end', () => { try { const result = JSON.parse(raw) as Record<string, unknown>; if (result.error) reject(new CLIError('local_command_rejected')); else resolve(result); } catch { reject(new CLIError('local_response_invalid')); } });
  });
}
export async function ownerRequest(directory: string, path: string, method = 'GET', body?: unknown): Promise<unknown> {
  const session = await localCommand(directory, { command: 'session' }); const origin = String(session.origin); const ownerOrigin = String(session.ownerOrigin);
  const safeFetch: typeof fetch = async (...args) => { try { return await fetch(...args); } catch { throw new CLIError('controller_unavailable'); } };
  const exchange = await safeFetch(origin + '/api/session/exchange', { method: 'POST', headers: { Origin: ownerOrigin, 'Content-Type': 'application/json' }, body: JSON.stringify({ code: session.code }) });
  if (!exchange.ok) throw new CLIError('owner_authentication_failed'); const cookie = exchange.headers.get('set-cookie')?.split(';')[0]; const data = await exchange.json() as { csrfToken: string };
  if (!cookie) throw new CLIError('owner_authentication_failed');
  const response = await safeFetch(origin + path, { method, headers: { Origin: ownerOrigin, Cookie: cookie, 'Content-Type': 'application/json', 'X-Keyroot-CSRF': data.csrfToken }, ...(body === undefined ? {} : { body: JSON.stringify(body) }) });
  if (!response.ok) { let code = 'request_rejected'; try { const data = await response.json() as { error?: unknown }; if (typeof data.error === 'string' && /^[a-z][a-z0-9_]{0,63}$/.test(data.error) && controllerCodes.has(data.error)) code = data.error; } catch { /* untrusted response */ } throw new CLIError(code); } return response.json() as Promise<unknown>;
}
export async function runCLI(args: string[], output: (text: string) => void = text => process.stdout.write(text + '\n')): Promise<void> {
  const directoryFlag = args.indexOf('--directory'); if (directoryFlag >= 0 && !args[directoryFlag + 1]) throw new CLIError('invalid_arguments'); const directory = directoryFlag >= 0 ? resolve(args[directoryFlag + 1]!) : process.env.KEYROOT_DIRECTORY ?? defaultDirectory(cliMode());
  const command = args[0] ?? 'status';
  if (command === 'recover' || command === 'backup' || command === 'recovery-resume') {
    const recovery = await import('./commands/recover.js');
    const run = command === 'backup' ? recovery.runBackupCLI : command === 'recovery-resume' ? recovery.runResumeCLI : recovery.runRecoverCLI;
    const status = await run(args.slice(1));
    if (status !== 0) throw new Error('Offline command refused');
    return;
  }
  if (command === 'session') { const response = await localCommand(directory, { command: 'session' }); output(JSON.stringify({ code: response.code, ownerOrigin: response.ownerOrigin, expiresInSeconds: 60 })); return; }
  if (command === 'pair-confirm') { if (!args[1] || !args[2]) throw new CLIError('invalid_arguments'); output(JSON.stringify(await localCommand(directory, { command, requestId: args[1], fingerprint: args[2] }))); return; }
  if (command === 'identity') { output(JSON.stringify(await localCommand(directory, { command: 'identity' }))); return; }
  if (command === 'status' || command === 'inventory') { output(JSON.stringify(await ownerRequest(directory, command === 'status' ? '/api/overview' : '/api/inventory'))); return; }
  if (command === 'prepare') { if (!args[1] || !args[2]) throw new CLIError('invalid_arguments'); output(JSON.stringify(await ownerRequest(directory, '/api/batches/prepare', 'POST', { signerId: args[1], lineageIds: [args[2]] }))); return; }
  if (command === 'prepare-action' || command === 'enrollment-prepare') {
    const purpose = command === 'enrollment-prepare' ? 'emergency-enrollment' : args[3]; const targetId = command === 'enrollment-prepare' ? args[3] : args[4];
    if (!args[1] || !args[2] || !purpose || !targetId) throw new CLIError('invalid_arguments');
    output(JSON.stringify(await ownerRequest(directory, '/api/batches/prepare', 'POST', { signerId: args[1], lineageIds: [args[2]], purpose, targetId, ...(purpose === 'key-policy' ? { policy: { rotationDays: Number(args[5]) } } : {}) }))); return;
  }
  if (command === 'enrollment-enact') { output(JSON.stringify(await ownerRequest(directory, '/api/actions/emergency-enrollment', 'POST', { grantId: args[1], operationId: args[2], actionId: 'emergency-enrollment' }))); return; }
  if (command === 'incident-prepare') {
    const policy = args[3]; const permit = args.includes('--allow-interruption'); if (!args[1] || !args[2] || !['continuity-first', 'revoke-first'].includes(String(policy))) throw new CLIError('invalid_arguments');
    if (policy === 'revoke-first' && !permit) throw new CLIError('invalid_arguments');
    const destinations = args[4] && !args[4].startsWith('--') ? args[4].split(',').map(pair => { const [consumerId, destinationId] = pair.split('='); if (!consumerId || !destinationId) throw new CLIError('invalid_arguments'); return { consumerId, destinationId }; }) : [];
    output(JSON.stringify(await ownerRequest(directory, '/api/batches/prepare', 'POST', { signerId: args[1], lineageIds: args[2].split(','), role: 'emergency', incident: { policy, quarantineDestinations: destinations, outage: { permitted: permit, consequence: permit ? 'declared-interruption' : 'none' } } }))); return;
  }
  if (command === 'run') { output(JSON.stringify(await ownerRequest(directory, '/api/operations/run', 'POST', { grantId: args[1], operationId: args[2] }))); return; }
  if (command === 'action') { output(JSON.stringify(await ownerRequest(directory, `/api/actions/${args[1]}`, 'POST', { grantId: args[2], operationId: args[3], actionId: args[4] }))); return; }
  throw new CLIError('invalid_arguments');
}
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) runCLI(process.argv.slice(2)).catch(error => { const code = error instanceof CLIError ? error.code : 'unexpected_error'; process.stderr.write(JSON.stringify({ error: code }) + '\n'); process.exitCode = 1; });
