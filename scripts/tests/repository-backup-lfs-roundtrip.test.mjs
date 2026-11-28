// Operator composition with real HTTPS, Ed25519, file loss and private copies.
// The child is an explicit native-protocol peer over opaque bytes. This proves
// operator interoperability, NOT Rust archive decoding or a native restore drill.
import test from 'node:test';
import assert from 'node:assert/strict';
import { get } from 'node:https';
import { readFile, writeFile, unlink, lstat } from 'node:fs/promises';
import { join } from 'node:path';
import { uploadRepositoryBackup } from '../lib/repository-backup-upload.mjs';
import { downloadRepositoryBackup } from '../lib/repository-backup-download.mjs';
import { runApprovedRepositoryBackup } from '../lib/repository-backup-native.mjs';
import { tlsFixture, DATA, digest } from './backup-download-fixture.mjs';

const approvalModule = new URL('../lib/repository-backup-approval.mjs', import.meta.url).href;
const bindingModule = new URL('../lib/repository-backup-native-approval.mjs', import.meta.url).href;
const LFS = Buffer.alloc(70003, 0x67), LFS_SHA = digest(LFS);
async function nativePeer(root) {
  const path = join(root, 'native-pair-peer'), calls = join(root, 'native-pair-calls');
  await writeFile(path, `#!${process.execPath}
import assert from 'node:assert/strict';
import { readFile, appendFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { authenticateRepositoryBackupFile } from ${JSON.stringify(approvalModule)};
import { nativeBackupApprovalBinding } from ${JSON.stringify(bindingModule)};
const args = process.argv.slice(2), flags = {}, hash = bytes => createHash('sha256').update(bytes).digest('hex');
assert.equal(args[0], 'backup'); assert.equal(args[1], 'verify');
for (let i = 4; i < args.length; i++) {
  const flag = args[i]; assert.equal(Object.hasOwn(flags, flag), false);
  flags[flag] = flag === '--trusted-local' ? true : args[++i];
}
assert.equal(flags['--trusted-local'], true);
const policy = Object.fromEntries(['tenant_id','repository_id','incarnation_id','object_format','minimum_head_generation']
  .map(key => [key, flags['--' + key.replaceAll('_', '-')]]));
const encoded = await readFile(flags['--approval']), key = await readFile(flags['--trust-key']);
const { authentication } = await authenticateRepositoryBackupFile(args[2], encoded, key, policy);
const statement = authentication.statement, lfs = await readFile(flags['--lfs-archive']);
assert.equal(hash(lfs), '${LFS_SHA}'); assert.equal(flags['--expected-lfs-sha256'], '${LFS_SHA}');
assert.equal(flags['--expected-sha256'], statement.artifact.sha256);
assert.equal(lfs.length, ${LFS.length});
await appendFile(${JSON.stringify(calls)}, JSON.stringify({ source: args[2], lfs: flags['--lfs-archive'],
  source_sha256: statement.artifact.sha256, lfs_sha256: hash(lfs) }) + '\\n');
const result = { type: 'repository_source_backup_verify', schema_version: 1,
  ...Object.fromEntries(['tenant_id','repository_id','incarnation_id','object_format'].map(k => [k, statement[k]])),
  sha256: statement.artifact.sha256, head_generation: statement.head_generation,
  objects: 2, references: 1, payload_bytes: 9, complete: true, scope: 'authority_and_selected_git_objects',
  object_graph_verified: true, original_payload_commitments_verified: true, node_closed: true, signature_verified: true,
  routing_published: false, archive_bytes: Number(statement.artifact.bytes), transport_version: 1,
  retained_outcome_checkpoint_verified: false, retained_outcome_checkpoint_root: null,
  retained_outcome_objects: 0, retained_outcome_payload_bytes: 0,
  local_edges: 1, external_gitlinks: 0, verification_instance: Number(flags['--verification-instance']),
  authority_import_verified: true, git_payloads_written: false, destination_authority_published: false,
  scratch_removed: true, destination_readback_verified: false, newest_checkpoint_verified: false, external_artifacts_verified: false,
  approval: { type: 'repository_backup_approval_authentication', signature_verified: true,
    ...nativeBackupApprovalBinding(encoded, key, policy), minimum_head_generation: policy.minimum_head_generation,
    statement, newest_checkpoint_verified: false, complete_capsule_verified: false },
  lfs_companion: { sha256: hash(lfs), bytes: lfs.length, objects: 2, payload_bytes: lfs.length - 100, exact_snapshot: true },
  lfs_payloads_verified: true };
// Top-level native counters are numbers; nested signed declarations stay strings.
process.stdout.write(JSON.stringify(result).replace(/("head_generation":)"([0-9]+)"/, '$1$2') + '\\n');
`, { mode: 0o700 });
  return { path, calls };
}

for (const format of ['sha1', 'sha256']) test(`offsite source/LFS roundtrip survives original-input loss (${format})`, async t => {
  const f = await tlsFixture(t);
  await f.sign(DATA, { object_format: format, expires_at: null });
  const originalApproval = await readFile(f.approval), objects = new Map(), actions = [];
  f.server.on('checkContinue', (req, res) => { res.writeContinue(); f.server.emit('request', req, res); });
  f.setHandler(async (req, res) => {
    try {
      const path = new URL(req.url, f.url).pathname; actions.push(`${req.method} ${path}`);
      assert.equal(req.headers['user-agent'], 'frankengit-agent (+https://github.com/Dicklesworthstone/frankengit)');
      if (req.method === 'GET') {
        const body = objects.get(path); res.writeHead(body ? 200 : 404, { 'content-length': body?.length ?? 0 }); res.end(body); return;
      }
      assert.equal(req.method, 'PUT'); assert.equal(req.headers['if-none-match'], '*');
      if (objects.has(path)) { res.writeHead(412, { 'content-length': 0 }); res.end(); return; }
      const chunks = []; for await (const chunk of req) chunks.push(chunk);
      if (path === '/approval') {
        assert.deepEqual(objects.get('/source'), DATA); assert.deepEqual(objects.get('/lfs'), LFS);
      }
      objects.set(path, Buffer.concat(chunks)); res.writeHead(201, { 'content-length': 0 }); res.end();
    } catch (error) { res.destroy(error); }
  });
  const origin = new URL(f.url).origin, target = Object.fromEntries(['archive', 'lfs', 'approval'].map(kind => [kind,
    { get: `${origin}/${kind === 'archive' ? 'source' : kind}?cap=GET`, put: `${origin}/${kind === 'archive' ? 'source' : kind}?cap=PUT` }]));
  const companion = join(f.root, 'original.fglf'); await writeFile(companion, LFS, { mode: 0o600 });
  const peer = await nativePeer(f.root), policy = { ...f.options.policy, object_format: format };
  const shared = { trustKey: f.trustKey, caFile: f.caFile, policy, maximumBytes: DATA.length,
    timeoutMs: 20000, fg: peer.path, trustedLocal: true, verificationInstance: '9001' };
  const published = await uploadRepositoryBackup({ ...shared, input: f.local, approval: f.approval,
    target, lfsArchive: companion, expectedLfsSha256: LFS_SHA, maximumTotalBytes: 3 * (DATA.length + LFS.length) });
  assert.equal(published.state, 'complete'); assert.equal(published.native_content_verified, true);
  assert.equal(published.lfs_companion_signed, false); assert.equal(published.lfs_companion.sha256, LFS_SHA);
  assert.deepEqual(objects.get('/approval'), originalApproval);
  assert.ok(actions.indexOf('GET /lfs') < actions.indexOf('PUT /approval'));
  // Simulate loss of every original archive and adjacent approval. Only the
  // independently retained public key, policy and companion pins remain local.
  await unlink(f.local); await unlink(f.approval); await unlink(companion);
  const downloadedApproval = join(f.root, 'offsite.approval');
  const ca = await readFile(f.caFile);
  const response = await new Promise((resolve, reject) => {
    get(target.approval.get, { agent: false, ca, rejectUnauthorized: true,
      headers: { 'user-agent': 'frankengit-agent (+https://github.com/Dicklesworthstone/frankengit)' } }, resolve).once('error', reject);
  });
  assert.equal(response.statusCode, 200);
  const parts = []; let bytes = 0;
  for await (const part of response) { bytes += part.length; assert.ok(bytes <= 16384); parts.push(part); }
  await writeFile(downloadedApproval, Buffer.concat(parts), { mode: 0o600 });
  const recovered = await downloadRepositoryBackup({ ...shared, approval: downloadedApproval, destination: f.destination,
    sources: [target.archive.get], lfsSources: [target.lfs.get], expectedLfsSha256: LFS_SHA,
    expectedLfsBytes: String(LFS.length), maximumTotalBytes: 4 * DATA.length + 3 * LFS.length });
  assert.equal(recovered.state, 'complete'); assert.equal(recovered.native_content_verified, true);
  assert.deepEqual(await readFile(recovered.candidate.input), DATA);
  assert.deepEqual(await readFile(recovered.candidate.approval), originalApproval);
  assert.deepEqual(await readFile(recovered.lfs_archive), LFS);
  assert.equal(recovered.lfs_companion.sha256, LFS_SHA);
  assert.equal(recovered.streaming.total_payload_bytes_read, String(4 * DATA.length + 3 * LFS.length));
  for (const file of [recovered.candidate.input, recovered.candidate.approval, recovered.lfs_archive]) {
    const st = await lstat(file); assert.equal(st.mode & 0o777, 0o600); assert.equal(st.nlink, 1);
  }
  const final = await runApprovedRepositoryBackup({ operation: 'verify', fg: peer.path, trustedLocal: true,
    input: recovered.candidate.input, approval: recovered.candidate.approval, trustKey: f.trustKey, policy,
    lfsArchive: recovered.lfs_archive, expectedLfsSha256: recovered.lfs_companion.sha256,
    verificationInstance: '9002', maximumBytes: DATA.length, timeoutMs: 10000 });
  assert.equal(final.state, 'complete'); assert.equal(final.native.lfs_payloads_verified, true);
  const calls = (await readFile(peer.calls, 'utf8')).trim().split('\n').map(JSON.parse);
  assert.equal(calls.length, 3); assert.ok(calls.every(call => call.lfs_sha256 === LFS_SHA && call.source_sha256 === digest(DATA)));
  assert.ok(calls.every(call => !call.source.includes('cap=') && !call.lfs.includes('cap=')));
});
