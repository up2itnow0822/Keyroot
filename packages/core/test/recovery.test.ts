import { test } from 'node:test';
import { strict as assert } from 'node:assert';
import { generateKeyPairSync, sign } from 'node:crypto';
import { mkdtempSync, rmSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { generateX25519Identity, identityToRecipient, Encrypter, Decrypter } from 'age-encryption';
import { Journal } from '../src/journal.js';
import { publicKeyFingerprint } from '../src/approval.js';
import { canonicalJSON, contentDigest } from '../src/manifest.js';
import { exportRecoveryArchive, openRecoveryArchive } from '../src/recovery/export.js';
import { importRecoveryArchive } from '../src/recovery/import.js';

export async function archiveFixture() {
  const dir = mkdtempSync(join(tmpdir(), 'kr-recovery-'));
  const journal = new Journal(join(dir, 'source.sqlite'), { installationId: 'old-install', bootId: 'old-boot' });
  const owner = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const publicKey = owner.publicKey.export({ format: 'jwk' });
  const identity = await generateX25519Identity();
  const recipient = await identityToRecipient(identity);
  const pin = { publicKey, fingerprint: publicKeyFingerprint(publicKey) };
  const archive = await exportRecoveryArchive({ journal, recipient, now: 1000, signerFingerprint: pin.fingerprint, sign: async bytes => sign('sha256', bytes, { key: owner.privateKey, dsaEncoding: 'ieee-p1363' }).toString('base64url') });
  return { dir, journal, owner, identity, recipient, pin, archive, cleanup: () => { journal.close(); rmSync(dir, { recursive: true, force: true }); } };
}

test('U12 actual age and independently pinned owner signature restore only into a fresh held journal', async () => {
  const f = await archiveFixture();
  try {
    const opened = await openRecoveryArchive({ archive: f.archive, identity: f.identity, verification: f.pin, now: 2000 });
    const restored = importRecoveryArchive({ opened, destination: join(f.dir, 'clean', 'restored.sqlite') });
    assert.notEqual(restored.journal.installationId, f.journal.installationId);
    assert.notEqual(restored.journal.bootId, f.journal.bootId);
    assert.equal(restored.report.recoveryHeld, true);
    assert.equal(statSync(join(f.dir, 'clean', 'restored.sqlite')).mode & 0o777, 0o600);
    assert.throws(() => restored.journal.createOperation({ operationId: 'new', lineageId: 'new', accountId: 'account', fromGeneration: 0, toGeneration: 1 }), /hold/);
    restored.journal.close();
  } finally { f.cleanup(); }
});

test('U12 wrong recipient, corruption, downgrade, arbitrary paths and fake sender sharing recipient fail', async () => {
  const f = await archiveFixture();
  try {
    const wrong = await generateX25519Identity();
    await assert.rejects(openRecoveryArchive({ archive: f.archive, identity: wrong, verification: f.pin, now: 2000 }));
    const corrupt = new Uint8Array(f.archive); corrupt[corrupt.length - 1]! ^= 1;
    await assert.rejects(openRecoveryArchive({ archive: corrupt, identity: f.identity, verification: f.pin, now: 2000 }));
    const decrypter = new Decrypter(); decrypter.addIdentity(f.identity);
    const envelope = JSON.parse(await decrypter.decrypt(f.archive, 'text')) as { statement: { version: number }; signature: string; metadata: unknown; path?: string };
    for (const altered of [{ ...envelope, statement: { ...envelope.statement, version: 0 } }, { ...envelope, signature: 'A'.repeat(86) }, { ...envelope, path: '../../outside' }]) {
      const e = new Encrypter(); e.addRecipient(f.recipient);
      const forged = await e.encrypt(canonicalJSON(altered));
      await assert.rejects(openRecoveryArchive({ archive: forged, identity: f.identity, verification: f.pin, now: 2000 }));
    }
    const attacker = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    const fake = { ...envelope, signature: sign('sha256', Buffer.from(canonicalJSON(envelope.statement)), { key: attacker.privateKey, dsaEncoding: 'ieee-p1363' }).toString('base64url') };
    const e = new Encrypter(); e.addRecipient(f.recipient);
    await assert.rejects(openRecoveryArchive({ archive: await e.encrypt(canonicalJSON(fake)), identity: f.identity, verification: f.pin, now: 2000 }), /signature/);
  } finally { f.cleanup(); }
});


test('U12 even authentic signed archives reject SQL/table injection, value-bearing fields and duplicate canonical keys', async () => {
  const f = await archiveFixture();
  try {
    const d = new Decrypter(); d.addIdentity(f.identity);
    const raw = await d.decrypt(f.archive, 'text');
    for (const fault of ['arbitrary-table', 'secret-field', 'duplicate-key', 'metadata-tamper'] as const) {
      const envelope = JSON.parse(raw) as { statement: Record<string, unknown>; metadata: { tables: Record<string, unknown[]> }; signature: string };
      if (fault === 'arbitrary-table') envelope.metadata.tables['arbitrary;DROP TABLE controller'] = [];
      if (fault === 'secret-field') envelope.metadata.tables.source_evidence = [{ evidence_id: 'id', source_id: 'source', evidence_hash: 'sha256:metadata', observed_at: 1, secretValue: 'synthetic-value-must-never-import' }];
      if (fault === 'metadata-tamper') envelope.metadata.tables.source_evidence = [{ evidence_id: 'id', source_id: 'source', evidence_hash: 'sha256:metadata', observed_at: 1 }];
      else envelope.statement.metadataHash = contentDigest(envelope.metadata);
      envelope.signature = sign('sha256', Buffer.from(canonicalJSON(envelope.statement)), { key: f.owner.privateKey, dsaEncoding: 'ieee-p1363' }).toString('base64url');
      let payload = canonicalJSON(envelope);
      if (fault === 'duplicate-key') payload = payload.replace('"version":1', '"version":1,"version":1');
      const e = new Encrypter(); e.addRecipient(f.recipient);
      await assert.rejects(openRecoveryArchive({ archive: await e.encrypt(payload), identity: f.identity, verification: f.pin, now: 2000 }));
    }
    await assert.rejects(openRecoveryArchive({ archive: f.archive, identity: f.identity, verification: f.pin, now: 2000, minimumCreatedAt: 1001 }));
  } finally { f.cleanup(); }
});
