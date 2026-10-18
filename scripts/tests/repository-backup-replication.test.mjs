// Real filesystem + Ed25519 operator publication tests. No fake native receipt
// or claim of fg, authority, capsule, cross-platform or physical-crash evidence.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync } from 'node:crypto';
import { mkdtemp, mkdir, writeFile, readFile, readdir, lstat, unlink, rm, symlink, chmod, rename, link } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { replicateRepositoryBackup, repositoryBackupReplicationOptions } from '../lib/repository-backup-replication.mjs';
import { selectRepositoryBackup } from '../lib/repository-backup-selection.mjs';
import { signRepositoryBackupFile } from '../lib/repository-backup-approval.mjs';

const NOW = Date.parse('2026-10-11T12:00:00Z');
const ID = { tenant_id: '1'.repeat(32), repository_id: '2'.repeat(32), incarnation_id: '3'.repeat(32), object_format: 'sha256' };
const POLICY = { ...ID, minimum_head_generation: '1' };
const DATA = Buffer.alloc(131089, 0x61);
const sha = value => createHash('sha256').update(value).digest('hex');
const hasCode = code => error => { assert.equal(error.code, code); return true; };
async function fixture(t) {
  const root = await mkdtemp(join(tmpdir(), 'fg-replica-publish-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const destination = join(root, 'replicas'); await mkdir(destination, { mode: 0o700 });
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const privatePem = privateKey.export({ format: 'pem', type: 'pkcs8' });
  const trustKey = join(root, 'trusted.pem');
  await writeFile(trustKey, publicKey.export({ format: 'pem', type: 'spki' }), { mode: 0o600 });
  async function signed(name, generation = '9007199254740993', bytes = DATA, declarations = {}) {
    const input = join(root, `${name}.fgbackup`), approval = join(root, `${name}.approval`);
    await writeFile(input, bytes, { mode: 0o600 });
    const result = await signRepositoryBackupFile(input, Buffer.from(privatePem), { ...ID, head_generation: generation,
      issued_at: '2026-10-11T11:00:00Z', expires_at: '2026-10-12T12:00:00Z', ...declarations }, { now: NOW });
    await writeFile(approval, result.envelope, { mode: 0o600 });
    return { input, approval };
  }
  const row = await signed('source');
  const envelope = await readFile(row.approval);
  const paths = { input: join(destination, `archive-sha256-${sha(DATA)}.fgbackup`),
    approval: join(destination, `checkpoint-sha256-${sha(envelope)}.approval.json`) };
  const options = { candidates: [row], trustKey, policy: POLICY, destination, maximumBytes: DATA.length, now: NOW };
  return { root, destination, row, signed, envelope, paths, options,
    replicate: extra => replicateRepositoryBackup({ ...options, ...extra }) };
}
async function absent(file) { await assert.rejects(lstat(file), { code: 'ENOENT' }); }
async function noTemporary(directory) { assert.equal((await readdir(directory)).filter(n => n.startsWith('.fg-')).length, 0); }

test('streamed publication preserves exact bytes and is selectable without source files', async t => {
  const f = await fixture(t), phases = [];
  const result = await f.replicate({ onProgress(event) { phases.push(event.phase); } });
  assert.equal(result.state, 'complete'); assert.deepEqual(result.candidate, f.paths);
  assert.deepEqual(result.disposition, { archive: 'created', approval: 'created' });
  assert.deepEqual(await readFile(result.candidate.input), DATA);
  assert.deepEqual(await readFile(result.candidate.approval), f.envelope);
  assert.equal(result.authentication.statement.head_generation, '9007199254740993');
  assert.equal(result.streaming.total_payload_bytes_read, String(DATA.length * 3));
  assert.equal(result.streaming.maximum_read_bytes, 65536);
  assert.equal(result.files_and_directory_synced, true);
  assert.equal(result.native_content_verified, false); assert.equal(result.complete_capsule_verified, false);
  assert.equal(result.newest_checkpoint_verified, false);
  assert(phases.indexOf('copy_archive') < phases.indexOf('verify_published_archive'));
  assert(phases.indexOf('verify_published_archive') < phases.indexOf('archive_durable'));
  await unlink(f.row.input); await unlink(f.row.approval);
  const selected = await selectRepositoryBackup([result.candidate], f.options.trustKey, POLICY, { now: NOW });
  assert.equal(selected.report.checkpoint.approval_sha256, sha(f.envelope));
  for (const file of Object.values(result.candidate)) {
    const stat = await lstat(file); assert.equal(stat.mode & 0o777, 0o600); assert.equal(stat.nlink, 1);
  }
  await noTemporary(f.destination);
});

test('identical retry reuses both immutable files without replacing either inode', async t => {
  const f = await fixture(t), a = await f.replicate();
  const before = await Promise.all(Object.values(f.paths).map(p => lstat(p, { bigint: true })));
  const b = await f.replicate();
  assert.deepEqual(b.candidate, a.candidate); assert.deepEqual(b.disposition, { archive: 'reused', approval: 'reused' });
  assert.equal(b.streaming.total_payload_bytes_read, String(DATA.length * 2));
  const after = await Promise.all(Object.values(f.paths).map(p => lstat(p, { bigint: true })));
  assert.deepEqual(after.map(s => s.ino), before.map(s => s.ino)); await noTemporary(f.destination);
});

test('approval remains absent through body copy, readback, and durability boundary', async t => {
  const f = await fixture(t); let observed = 0;
  await f.replicate({ async onProgress(event) {
    if (['copy_archive', 'archive_staged', 'verify_published_archive', 'archive_durable'].includes(event.phase)) {
      await absent(f.paths.approval); observed++;
    }
    if (event.phase === 'archive_durable') assert.deepEqual(await readFile(f.paths.input), DATA);
  } });
  assert(observed >= 8); assert.deepEqual(await readFile(f.paths.approval), f.envelope);
});

test('interruption after durable body is resumed without rewriting the body', async t => {
  const f = await fixture(t), controller = new AbortController();
  await assert.rejects(f.replicate({ signal: controller.signal, onProgress(event) {
    if (event.phase === 'archive_durable') controller.abort();
  } }), error => { assert.equal(error.code, 'backup_cancelled'); assert.equal(error.publication_state, 'archive_durable'); return true; });
  await absent(f.paths.approval); const original = await lstat(f.paths.input, { bigint: true });
  const resumed = await f.replicate();
  assert.deepEqual(resumed.disposition, { archive: 'reused', approval: 'created' });
  assert.equal((await lstat(f.paths.input, { bigint: true })).ino, original.ino);
  await noTemporary(f.destination);
});

test('cancelled partial copy retires only its temporary file and publishes nothing', async t => {
  const f = await fixture(t), controller = new AbortController();
  await writeFile(join(f.destination, 'unrelated'), 'retain me');
  await assert.rejects(f.replicate({ signal: controller.signal, onProgress(e) { if (e.phase === 'copy_archive') controller.abort(); } }), hasCode('backup_cancelled'));
  await absent(f.paths.input); await absent(f.paths.approval); await noTemporary(f.destination);
  assert.equal(await readFile(join(f.destination, 'unrelated'), 'utf8'), 'retain me');
});

test('source replaced after selection is reauthenticated during streaming', async t => {
  const f = await fixture(t);
  await assert.rejects(f.replicate({ async onProgress(e) {
    if (e.phase === 'selection_complete') await writeFile(f.row.input, Buffer.alloc(DATA.length, 0x62));
  } }), hasCode('backup_replica_digest_mismatch'));
  await absent(f.paths.approval); await absent(f.paths.input); await noTemporary(f.destination);
});

test('source modified during streaming refuses and cleans the owned staging file', async t => {
  const f = await fixture(t); let changed = false;
  await assert.rejects(f.replicate({ async onProgress(e) {
    if (e.phase === 'copy_archive' && !changed) { changed = true; await writeFile(f.row.input, Buffer.alloc(DATA.length, 0x62)); }
  } }), hasCode('backup_replica_file_changed'));
  await absent(f.paths.approval); await absent(f.paths.input); await noTemporary(f.destination);
});

test('different valid approval bytes cannot replace the pinned selected envelope', async t => {
  const f = await fixture(t);
  await assert.rejects(f.replicate({ async onProgress(e) {
    if (e.phase === 'selection_complete') await writeFile(f.row.approval, JSON.stringify(JSON.parse(f.envelope), null, 2));
  } }), hasCode('backup_replica_approval_changed'));
  assert.deepEqual(await readdir(f.destination), []);
});

test('staged-file substitution before publication is refused', async t => {
  const f = await fixture(t);
  await assert.rejects(f.replicate({ async onProgress(e) {
    if (e.phase === 'archive_staged') {
      const name = (await readdir(f.destination)).find(n => n.startsWith('.fg-backup-replica-'));
      await writeFile(join(f.destination, name), Buffer.alloc(DATA.length, 0x62));
    }
  } }), hasCode('backup_replica_file_changed'));
  await absent(f.paths.input); await absent(f.paths.approval); await noTemporary(f.destination);
});

test('destination changed after readback cannot gain an approval', async t => {
  const f = await fixture(t);
  await assert.rejects(f.replicate({ async onProgress(e) {
    if (e.phase === 'archive_durable') await writeFile(f.paths.input, Buffer.alloc(DATA.length, 0x62));
  } }), hasCode('backup_replica_file_changed'));
  await absent(f.paths.approval); await noTemporary(f.destination);
});

test('corrupt existing archive is never overwritten, even with a valid source', async t => {
  const f = await fixture(t); await writeFile(f.paths.input, Buffer.alloc(DATA.length, 0x62));
  const before = await lstat(f.paths.input, { bigint: true });
  await assert.rejects(f.replicate(), hasCode('backup_replica_digest_mismatch'));
  assert.equal((await lstat(f.paths.input, { bigint: true })).ino, before.ino);
  assert.deepEqual(await readFile(f.paths.input), Buffer.alloc(DATA.length, 0x62)); await absent(f.paths.approval);
});

test('existing mismatched approval refuses before staging an archive', async t => {
  const f = await fixture(t); await writeFile(f.paths.approval, 'not the signed intent');
  await assert.rejects(f.replicate(), hasCode('backup_replica_approval_conflict'));
  assert.equal(await readFile(f.paths.approval, 'utf8'), 'not the signed intent'); await absent(f.paths.input);
});

test('dangling destination archive symlink is not followed or replaced', async t => {
  const f = await fixture(t), outside = join(f.root, 'absent'); await symlink(outside, f.paths.input);
  await assert.rejects(f.replicate(), hasCode('ELOOP'));
  assert((await lstat(f.paths.input)).isSymbolicLink()); await absent(outside); await absent(f.paths.approval);
});

test('destination directory must be private and must not be a symlink', async t => {
  const f = await fixture(t); await chmod(f.destination, 0o755);
  await assert.rejects(f.replicate(), hasCode('backup_replica_private_directory_required'));
  await chmod(f.destination, 0o700); const alias = join(f.root, 'alias'); await symlink(f.destination, alias);
  await assert.rejects(f.replicate({ destination: alias }), hasCode('backup_replica_private_directory_required'));
  assert.deepEqual(await readdir(f.destination), []);
});

test('destination directory replacement after selection is detected', async t => {
  const f = await fixture(t), moved = join(f.root, 'moved');
  await assert.rejects(f.replicate({ async onProgress(e) {
    if (e.phase === 'destination_checked') { await rename(f.destination, moved); await mkdir(f.destination, { mode: 0o700 }); }
  } }), hasCode('backup_replica_directory_changed'));
  assert.deepEqual(await readdir(f.destination), []); assert.deepEqual(await readdir(moved), []);
});

test('expired highest checkpoint cannot publish an older signed backup', async t => {
  const f = await fixture(t), older = await f.signed('older', '7', DATA, { expires_at: '2026-10-20T12:00:00Z' });
  await assert.rejects(f.replicate({ candidates: [older, f.row], now: Date.parse('2026-10-13T12:00:00Z') }), hasCode('backup_approval_expired'));
  assert.deepEqual(await readdir(f.destination), []);
});

test('conflicting highest checkpoints cause no destination effects', async t => {
  const f = await fixture(t), rival = await f.signed('rival', '9007199254740993', Buffer.from('different'));
  await assert.rejects(f.replicate({ candidates: [f.row, rival] }), hasCode('backup_checkpoint_ambiguous'));
  assert.deepEqual(await readdir(f.destination), []);
});

test('incorrect external namespace refuses without touching destination', async t => {
  const f = await fixture(t);
  await assert.rejects(f.replicate({ policy: { ...POLICY, incarnation_id: '4'.repeat(32) } }), hasCode('backup_approval_identity_mismatch'));
  assert.deepEqual(await readdir(f.destination), []);
});

test('copy and readback share one total budget including selection', async t => {
  const f = await fixture(t);
  await assert.rejects(f.replicate({ maximumTotalBytes: DATA.length * 3 - 1 }), hasCode('backup_replication_read_budget'));
  assert.deepEqual(await readdir(f.destination), []);
  const result = await f.replicate({ maximumTotalBytes: DATA.length * 3 });
  assert.equal(result.streaming.total_payload_bytes_read, String(DATA.length * 3));
});

test('whole-operation deadline survives progress callbacks', async t => {
  const f = await fixture(t);
  await assert.rejects(f.replicate({ timeoutMs: 1000, async onProgress(e) {
    if (e.phase === 'archive_staged') await delay(1100);
  } }), hasCode('backup_deadline'));
  await absent(f.paths.approval); await absent(f.paths.input); await noTemporary(f.destination);
});

test('observer failure after durable body preserves actionable publication state', async t => {
  const f = await fixture(t), stop = new Error('operator disconnected');
  await assert.rejects(f.replicate({ onProgress(e) { if (e.phase === 'archive_durable') throw stop; } }), error => {
    assert.equal(error, stop); assert.equal(error.publication_state, 'archive_durable'); assert.deepEqual(error.replica, f.paths); return true;
  });
  await absent(f.paths.approval); assert.deepEqual(await readFile(f.paths.input), DATA);
  assert.equal((await f.replicate()).state, 'complete');
});

test('missing body under an identical existing approval is recreated from signed bytes', async t => {
  const f = await fixture(t), first = await f.replicate();
  const root = await lstat(f.paths.approval, { bigint: true }); await unlink(f.paths.input);
  const second = await f.replicate();
  assert.deepEqual(second.disposition, { archive: 'created', approval: 'reused' });
  assert.equal((await lstat(f.paths.approval, { bigint: true })).ino, root.ino);
  assert.deepEqual(second.candidate, first.candidate); assert.deepEqual(await readFile(f.paths.input), DATA);
});

test('invalid options refuse synchronously before any I/O', () => {
  const args = { candidates: [{ input: '/absent/in', approval: '/absent/sig' }], trustKey: '/absent/key',
    policy: POLICY, destination: '/absent/dir' };
  for (const maximumTotalBytes of [0, -1, Infinity, 1.5, 2 ** 53]) {
    assert.throws(() => repositoryBackupReplicationOptions({ ...args, maximumTotalBytes }), hasCode('backup_replication_read_limit'));
  }
  assert.throws(() => repositoryBackupReplicationOptions({ ...args, unsigned: true }), hasCode('backup_invalid_replication_options'));
});

test('an identical concurrent publisher wins without being overwritten', async t => {
  const f = await fixture(t); let winner;
  const loser = await f.replicate({ async onProgress(e) {
    if (e.phase === 'archive_staged') winner = await f.replicate();
  } });
  assert.deepEqual(winner.disposition, { archive: 'created', approval: 'created' });
  assert.deepEqual(loser.disposition, { archive: 'reused', approval: 'reused' });
  assert.deepEqual(winner.candidate, loser.candidate); await noTemporary(f.destination);
});

test('a conflicting concurrent body cannot be overwritten or approved', async t => {
  const f = await fixture(t);
  await assert.rejects(f.replicate({ async onProgress(e) {
    if (e.phase === 'archive_staged') await writeFile(f.paths.input, Buffer.alloc(DATA.length, 0x62), { flag: 'wx' });
  } }), hasCode('backup_replica_digest_mismatch'));
  assert.deepEqual(await readFile(f.paths.input), Buffer.alloc(DATA.length, 0x62));
  await absent(f.paths.approval); await noTemporary(f.destination);
});

test('a reused approval substituted during body verification does not return success', async t => {
  const f = await fixture(t); await f.replicate();
  await assert.rejects(f.replicate({ async onProgress(e) {
    if (e.phase === 'archive_durable') await writeFile(f.paths.approval, Buffer.alloc(f.envelope.length, 0x62));
  } }), error => {
    assert.equal(error.code, 'backup_replica_approval_conflict'); assert.equal(error.publication_state, 'approval_visible'); return true;
  });
  assert.deepEqual(await readFile(f.paths.approval), Buffer.alloc(f.envelope.length, 0x62));
});

test('an existing root removed during retry is not silently reported complete', async t => {
  const f = await fixture(t); await f.replicate();
  await assert.rejects(f.replicate({ async onProgress(e) {
    if (e.phase === 'archive_durable') await unlink(f.paths.approval);
  } }), hasCode('backup_replica_approval_disappeared'));
});

test('a symlink at the approval publication slot refuses without affecting its target', async t => {
  const f = await fixture(t), outside = join(f.root, 'other-control'); await writeFile(outside, 'untouched');
  await symlink(outside, f.paths.approval);
  await assert.rejects(f.replicate(), hasCode('ELOOP'));
  assert.equal(await readFile(outside, 'utf8'), 'untouched'); await absent(f.paths.input);
});

test('a pre-cancelled operation has no filesystem side effects', async t => {
  const f = await fixture(t), controller = new AbortController(); controller.abort();
  await assert.rejects(f.replicate({ signal: controller.signal }), hasCode('backup_cancelled'));
  assert.deepEqual(await readdir(f.destination), []);
});

test('caller mutations after the first await cannot widen the pinned policy', async t => {
  const f = await fixture(t), policy = { ...POLICY }, rows = [{ ...f.row }];
  const pending = f.replicate({ candidates: rows, policy });
  rows[0].input = '/does-not-exist'; policy.incarnation_id = '4'.repeat(32); policy.minimum_head_generation = '18446744073709551615';
  const result = await pending;
  assert.equal(result.authentication.policy.incarnation_id, ID.incarnation_id);
  assert.equal(result.authentication.policy.minimum_head_generation, '1');
});


test('a matching but externally writable destination file is not approved', async t => {
  const f = await fixture(t); await writeFile(f.paths.input, DATA, { mode: 0o644 });
  await assert.rejects(f.replicate(), hasCode('backup_replica_private_file_required'));
  await absent(f.paths.approval); assert.deepEqual(await readFile(f.paths.input), DATA);
});

test('an existing archive with another hard link is not treated as private immutable output', async t => {
  const f = await fixture(t); await link(f.row.input, f.paths.input);
  await assert.rejects(f.replicate(), hasCode('backup_replica_private_file_required'));
  await absent(f.paths.approval); assert.equal((await lstat(f.paths.input)).nlink, 2);
});
