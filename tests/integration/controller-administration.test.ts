import { test, type TestContext } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, sign } from 'node:crypto';
import { mkdtemp, rm, realpath, writeFile, readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { startController } from '../../apps/controller/src/server.js';
import { localCommand } from '../../apps/controller/src/cli.js';
import type { Inventory, PreparedBatch, TrustedControllerPorts } from '../../apps/controller/src/service.js';
import { canonicalJSON, parseCanonicalManifest } from '../../packages/core/src/manifest.js';
import { fileDigest } from '../../packages/core/src/consumers/env-file.js';

function deferred() { let resolve!: () => void; const promise = new Promise<void>(done => { resolve = done; }); return { promise, resolve }; }
function proposedInventory(initial: Inventory): Inventory {
  return { ...structuredClone(initial), lineages:[{ id:'first-lineage',issuerId:'fixture-issuer',accountId:'first-account',credentialType:'static-key',grantType:'static-key' }], consumerMap:{ revision:initial.consumerMap.revision+1,bindings:[{ id:'first-binding',lineageId:'first-lineage',consumerId:'machine-1',destinationId:'registered-destination',consumerRevision:'consumer-v1',association:{kind:'declared',source:'hermetic-owner-declaration',observedAt:new Date().toISOString()} }],gaps:initial.consumerMap.gaps } };
}
async function fixture(t: TestContext, options: { admission?: TrustedControllerPorts['assertLiveAdmission']; envTargets?: TrustedControllerPorts['envTargets'] } = {}) {
  const directory = await mkdtemp(join(tmpdir(),'kr-admin-boundary-'));
  // Explicit REAL authority over hermetic local metadata/temporary resources. These callbacks
  // exercise admission plumbing and confer no actual owner account/store/phone readiness.
  const testGate = async () => {};
  const ports: TrustedControllerPorts = { assertLiveAdmission: options.admission ?? testGate, liveGates:{account:testGate,store:testGate,phoneCustody:testGate,origin:testGate,isolation:testGate,recovery:testGate}, lifecycleDrivers:async () => { throw new Error('No credential lifecycle driver in metadata-only fixture'); }, ...(options.envTargets ? {envTargets:options.envTargets} : {}) };
  const app = await startController({directory,port:0,mode:'real',phoneOrigin:'https://phone.fixture.invalid',ports});
  t.after(async () => { await app.close(); await rm(directory,{recursive:true,force:true}); });
  const keys = generateKeyPairSync('ec',{namedCurve:'prime256v1'}); const signature = (bytes:string) => sign('sha256',Buffer.from(bytes),{key:keys.privateKey,dsaEncoding:'ieee-p1363'}).toString('base64url');
  const phone = (path:string,body:unknown) => fetch(app.origin+path,{method:'POST',headers:{Origin:app.phoneOrigin,'Content-Type':'application/json'},body:JSON.stringify(body)});
  const request = await phone('/api/pairing/requests',{signerId:'owner-phone',role:'routine',publicKey:keys.publicKey.export({format:'jwk'})}); assert.equal(request.status,201);
  const pair = await request.json() as {requestId:string;fingerprint:string;challenge:unknown};
  assert.equal((await phone('/api/pairing/requests/'+pair.requestId+'/proof',{signature:signature('keyroot.pairing-possession.v1\0'+canonicalJSON(pair.challenge))})).status,200);
  await localCommand(directory,{command:'pair-confirm',requestId:pair.requestId,fingerprint:pair.fingerprint});
  const local = await localCommand(directory,{command:'session'}); const exchange = await fetch(app.origin+'/api/session/exchange',{method:'POST',headers:{Origin:app.origin,'Content-Type':'application/json'},body:JSON.stringify({code:local.code})}); assert.equal(exchange.status,200);
  const session = await exchange.json() as {csrfToken:string}; const cookie=exchange.headers.get('set-cookie')!.split(';')[0]!;
  const owner = (path:string,body?:unknown) => fetch(app.origin+path,{method:body===undefined?'GET':'POST',headers:{Origin:app.origin,Cookie:cookie,'X-Keyroot-CSRF':session.csrfToken,'Content-Type':'application/json'},...(body===undefined?{}:{body:JSON.stringify(body)})});
  const prepare = async (purpose:string,targetId:string,extra:Record<string,unknown>={}) => owner('/api/batches/prepare',{signerId:'owner-phone',lineageIds:['first-lineage'],purpose,targetId,...extra});
  const approve = async (batch:PreparedBatch) => { const response=await phone('/api/approvals',{batchId:batch.batchId,rawManifest:batch.rawManifest,signature:signature(batch.rawManifest)}); assert.equal(response.status,201); return await response.json() as {grantId:string}; };
  const action = (kind:string,batch:PreparedBatch,grantId:string) => owner('/api/actions/'+kind,{grantId,operationId:parseCanonicalManifest(batch.rawManifest).operations[0]!.operationId,actionId:kind});
  const seedExistingFixture = (inventory:Inventory) => { const row={id:'inventory',metadata:canonicalJSON(inventory)};app.service.metadata.validateRow('controller_inventory',row);app.service.journal.transaction(db=>db.prepare("UPDATE controller_inventory SET metadata=? WHERE id='inventory'").run(row.metadata)); };
  return {app,owner,phone,prepare,approve,action,signature,seedExistingFixture};
}

test('fresh REAL inventory is introduced only by the exact approved proposed snapshot and bound account',async t=>{
  const f=await fixture(t); const initial=f.app.service.inventory(); assert.equal(initial.lineages.length,0); const proposal=proposedInventory(initial);
  assert.equal((await f.prepare('key-policy','first-lineage',{inventory:proposal,policy:{rotationDays:7}})).status,404);
  assert.equal((await f.prepare('inventory-update','inventory',{inventory:proposal,lineageIds:[]})).status,400);
  assert.equal((await f.prepare('inventory-update','',{inventory:proposal})).status,400);
  assert.equal((await f.prepare('inventory-update','inventory',{inventory:proposal,lineageIds:['outside-proposal']})).status,404);
  const prepared=await f.prepare('inventory-update','inventory',{inventory:proposal}); assert.equal(prepared.status,201); const batch=await prepared.json() as PreparedBatch; const manifest=parseCanonicalManifest(batch.rawManifest); assert.equal(manifest.operations[0]!.accountId,'first-account');
  assert.equal((await f.action('inventory-update',batch,batch.batchId)).status,404); assert.deepEqual(f.app.service.inventory(),initial);
  const substituted=batch.rawManifest.replaceAll('first-account','substituted-account'); assert.equal((await f.phone('/api/approvals',{batchId:batch.batchId,rawManifest:substituted,signature:f.signature(substituted)})).status,409);
  assert.equal((await f.phone('/api/approvals',{batchId:batch.batchId,rawManifest:batch.rawManifest,signature:Buffer.alloc(64).toString('base64url')})).status,409); assert.deepEqual(f.app.service.inventory(),initial);
  const grant=await f.approve(batch);
  assert.equal((await f.owner('/api/actions/inventory-update',{grantId:grant.grantId,operationId:manifest.operations[0]!.operationId,actionId:'inventory-update',inventory:{...proposal,lineages:[]}})).status,400); assert.deepEqual(f.app.service.inventory(),initial);
  assert.equal((await f.action('inventory-update',batch,grant.grantId)).status,200); assert.deepEqual(f.app.service.inventory(),proposal);
  assert.equal((await f.action('inventory-update',batch,grant.grantId)).status,409); assert.deepEqual(f.app.service.inventory(),proposal);
});

test('routine REAL quarantine signs its administrative lineage and exact recorded destination/revision without replay',async t=>{
  const f=await fixture(t); const inventory=proposedInventory(f.app.service.inventory()); f.seedExistingFixture(inventory);
  assert.equal((await f.prepare('quarantine','machine-2')).status,503); assert.equal((await f.prepare('quarantine','machine-1',{lineageIds:['unrecorded-lineage']})).status,404);
  const response=await f.prepare('quarantine','machine-1'); assert.equal(response.status,201); const batch=await response.json() as PreparedBatch; const manifest=parseCanonicalManifest(batch.rawManifest); const operation=manifest.operations[0]!;
  assert.deepEqual(manifest.consumerMap.entries,[{lineageId:operation.lineageId,consumerId:'machine-1',resourceId:'registered-destination',revision:'consumer-v1'}]); assert.equal(operation.lineageId,'admin:machine-1');
  const sidecar=f.app.service.configurationDescriptor(operation.actions[0]!.parameters.configurationHash!).descriptor as {lineageId:string}; assert.equal(sidecar.lineageId,'first-lineage'); assert.equal(operation.actions[0]!.parameters.expectedRevision,'consumer-v1');
  assert.equal((await f.action('quarantine',batch,batch.batchId)).status,404); assert.equal(await f.app.service.quarantine.check('machine-1','registered-destination'),'clear');
  const grant=await f.approve(batch); assert.equal((await f.action('key-policy',batch,grant.grantId)).status,403);
  assert.equal((await f.action('quarantine',batch,grant.grantId)).status,200); assert.equal(await f.app.service.quarantine.check('machine-1','registered-destination'),'quarantined'); assert.equal(await f.app.service.quarantine.check('machine-1','other-destination'),'clear');
  assert.equal((await f.action('quarantine',batch,grant.grantId)).status,409); assert.equal(f.app.service.journal.listIntents(operation.operationId).length,1); assert.equal(f.app.service.journal.listIntents(operation.operationId)[0]!.state,'observed');
});

test('scope changes while administrative admission awaits prevent the stale local policy mutation',async t=>{
  const entered=deferred(); const release=deferred(); const f=await fixture(t,{admission:async context=>{if(context.action.parameters.reasonCode==='key-policy'){entered.resolve();await release.promise;}}}); const inventory=proposedInventory(f.app.service.inventory()); f.seedExistingFixture(inventory);
  const policyResponse=await f.prepare('key-policy','first-lineage',{policy:{rotationDays:7}}); assert.equal(policyResponse.status,201); const policy=await policyResponse.json() as PreparedBatch; const policyGrant=await f.approve(policy);
  const removal={...structuredClone(inventory),lineages:[],consumerMap:{...inventory.consumerMap,revision:inventory.consumerMap.revision+1,bindings:[]}}; const removalResponse=await f.prepare('inventory-update','inventory',{inventory:removal}); assert.equal(removalResponse.status,201); const update=await removalResponse.json() as PreparedBatch; const updateGrant=await f.approve(update);
  const stale=f.action('key-policy',policy,policyGrant.grantId); await entered.promise;
  try { assert.equal((await f.action('inventory-update',update,updateGrant.grantId)).status,200); } finally { release.resolve(); }
  const denied=await stale; assert.equal(denied.status,409); assert.deepEqual(await denied.json(),{error:'scope_changed'}); assert.equal(f.app.service.inventory().lineages.length,0);
  assert.equal(f.app.service.journal.read(db=>db.prepare("SELECT 1 FROM controller_policy WHERE id='first-lineage'").get()),undefined); assert.equal(f.app.service.journal.listReceipts(parseCanonicalManifest(policy.rawManifest).operations[0]!.operationId).length,0);
});

test('env rollback rechecks current scope after awaited vault reads and before file mutation',async t=>{
  const root=await realpath(await mkdtemp(join(tmpdir(),'kr-admin-env-race-'))); t.after(()=>rm(root,{recursive:true,force:true})); const current=Buffer.from('API_KEY=synthetic-current\n'); const backup=Buffer.from('API_KEY=synthetic-prior\n'); const path=join(root,'.env'); await writeFile(path,current,{mode:0o600});
  const entered=deferred(); const release=deferred();
  const f=await fixture(t,{envTargets:[{id:'registered-env',descriptor:{driver:'env-file',mode:'rollback',envFormat:'node-env',consumerId:'machine-1',destinationId:'registered-env-destination',revision:'env-v1',consumerMapRevision:'map-2',generation:1,handleId:'mapped-handle',version:1,mappingTokenFingerprint:'sha256:'+'a'.repeat(64),rootId:'fixture',relativePath:'.env',variable:'API_KEY',expectedFileHash:fileDigest(current),backupHandle:'backup',backupExpectedVersion:0,backupVersion:1,backupFileHash:fileDigest(backup)},roots:{fixture:root},store:{withValue:async()=>({status:'denied'})},backup:{write:async()=>({status:'denied'}),withValue:async(_handle,_version,execute)=>{entered.resolve();await release.promise;await execute(backup.toString('base64'));return{status:'resolved'};}}}]}); const inventory=proposedInventory(f.app.service.inventory());f.seedExistingFixture(inventory);
  const rollbackResponse=await f.prepare('env-rollback','registered-env');assert.equal(rollbackResponse.status,201);const rollback=await rollbackResponse.json() as PreparedBatch;const rollbackGrant=await f.approve(rollback);
  const removal={...structuredClone(inventory),lineages:[],consumerMap:{...inventory.consumerMap,revision:inventory.consumerMap.revision+1,bindings:[]}};const removalResponse=await f.prepare('inventory-update','inventory',{inventory:removal});assert.equal(removalResponse.status,201);const update=await removalResponse.json() as PreparedBatch;const updateGrant=await f.approve(update);
  const pending=f.action('env-rollback',rollback,rollbackGrant.grantId);await entered.promise;try{assert.equal((await f.action('inventory-update',update,updateGrant.grantId)).status,200);}finally{release.resolve();}
  const response=await pending;assert.equal(response.status,200);const result=await response.json() as {outcome:string;limitationCodes:string[]};assert.equal(result.outcome,'rejected');assert.ok(!result.limitationCodes.includes('authorized-rollback-applied'));assert.deepEqual(await readFile(path),current);
});
