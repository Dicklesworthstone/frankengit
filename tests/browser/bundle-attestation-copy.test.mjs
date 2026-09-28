// Real Ed25519 + filesystem publication tests. The bytes are opaque artifacts,
// not a claim of native Git/FrankenGit restore or hostile same-user containment.
import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, createHash } from 'node:crypto';
import { open, mkdtemp, writeFile, readFile, rename, symlink, chmod, mkdir, rm, readdir, lstat } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { tmpdir } from 'node:os';
import { spawnSync, fork } from 'node:child_process';
import { once } from 'node:events';
import { signSourceBackup, signSourceBackupFile, authenticateSourceBackupFile, copyAuthenticatedSourceBackup }
  from '../../scripts/lib/source-attestation.mjs';
const pair = generateKeyPairSync('ed25519');
const privatePem = Buffer.from(pair.privateKey.export({ type: 'pkcs8', format: 'pem' }));
const publicPem = Buffer.from(pair.publicKey.export({ type: 'spki', format: 'pem' }));
const now = Date.parse('2026-09-28T12:00:00Z');
const meta = { repository: 'team/repo', sequence: '42', issued_at: '2026-09-28T11:59:59Z' };
const policy = { repository: meta.repository, minimum_sequence: '42' }, options = { now };
const body = Buffer.from(Array.from({ length: 200003 }, (_, i) => i % 251));
const hash = bytes => createHash('sha256').update(bytes).digest('hex');
const rejected = code => error => error.code === code;
async function fixture(work) {
  const directory = await mkdtemp(join(tmpdir(), 'fg-authenticated-copy-'));
  const input = join(directory, 'input.bundle'), destination = join(directory, 'ready.bundle');
  const envelope = join(directory, 'input.dsse.json'), pub = join(directory, 'public.pem');
  const signed = await signSourceBackup(body, privatePem, meta, options);
  await writeFile(input, body); await writeFile(envelope, signed.envelope); await writeFile(pub, publicPem);
  try { return await work({ directory, input, destination, envelope, pub, signed }); }
  finally { await rm(directory, { recursive: true, force: true }); }
}
const copy = (f, extra = {}) => copyAuthenticatedSourceBackup(f.input, f.destination, f.signed.envelope, publicPem, policy, { ...options, ...extra });
async function absent(path) { await assert.rejects(lstat(path), error => error.code === 'ENOENT'); }
async function clean(f) { assert(!(await readdir(f.directory)).some(name => name.startsWith('.fgit-authenticated-'))); }
const cli = args => spawnSync(process.execPath, [resolve('scripts/attest_git_bundle.mjs'), ...args],
  { encoding: 'utf8', timeout: 30000, env: { ...process.env, PATH: '/nonexistent' } });

test('publish a private byte-identical authenticated copy only after readback and synchronization', () => fixture(async f => {
  const events = [], result = await copy(f, { onProgress: event => events.push(event) });
  assert.deepEqual(await readFile(f.destination), body); assert.deepEqual(await readFile(f.input), body);
  assert.equal((await lstat(f.destination)).mode & 0o777, 0o600);
  assert.equal(result.copy.state, 'complete'); assert.equal(result.copy.path, f.destination);
  assert.equal(result.copy.sha256, hash(body)); assert.equal(result.copy.bytes, body.length);
  for (const name of ['readback_checked', 'file_synced', 'directory_synced', 'approval_checked_before_publication']) assert.equal(result.copy[name], true);
  assert.equal(result.authentication.signature_verified, true); assert.equal(result.authentication.object_closure_verified, false);
  assert.equal(result.streaming.maximum_read_bytes, 65536); assert.equal(result.copy.write_calls, 4);
  assert(events.every(Object.isFrozen)); assert.equal(events[0].phase, 'staging'); assert.equal(events.at(-1).phase, 'published');
  await clean(f);
}));

test('the input is not reopened between authentication and copying', () => fixture(async f => {
  const result = await copy(f, { async onProgress(event) { if (event.phase === 'before_readback') await rm(f.input); } });
  assert.equal(result.copy.state, 'complete'); assert.deepEqual(await readFile(f.destination), body); await absent(f.input); await clean(f);
}));

for (const kind of ['wrong-key', 'wrong-repository', 'rollback', 'expired', 'oversized']) test(`${kind} refuses before source or output-directory access`, () => fixture(async f => {
  let key = publicPem, expected = policy, envelope = f.signed.envelope, limits = options, code;
  if (kind === 'wrong-key') { key = Buffer.from(generateKeyPairSync('ed25519').publicKey.export({ format: 'pem', type: 'spki' })); code = 'attestation_key_hint_mismatch'; }
  if (kind === 'wrong-repository') { expected = { ...policy, repository: 'wrong/repo' }; code = 'attestation_repository_mismatch'; }
  if (kind === 'rollback') { expected = { ...policy, minimum_sequence: '43' }; code = 'attestation_below_sequence_floor'; }
  if (kind === 'expired') { envelope = (await signSourceBackup(body, privatePem, { ...meta, expires_at: '2026-09-28T12:00:01Z' }, options)).envelope; limits = { now: now + 1000 }; code = 'attestation_expired'; }
  if (kind === 'oversized') { limits = { ...options, maximumBytes: body.length - 1 }; code = 'invalid_attestation_artifact'; }
  await assert.rejects(copyAuthenticatedSourceBackup('/missing-input', join(f.directory, 'absent-parent', 'output'), envelope, key, expected, limits), rejected(code));
  await absent(f.destination); await clean(f);
}));

for (const kind of ['file', 'directory', 'symlink', 'dangling']) test(`existing ${kind} destinations are never replaced`, () => fixture(async f => {
  if (kind === 'file') await writeFile(f.destination, 'keep');
  if (kind === 'directory') await mkdir(f.destination);
  if (kind === 'symlink' || kind === 'dangling') await symlink(kind === 'symlink' ? f.input : 'missing', f.destination);
  const before = await lstat(f.destination); let progress = 0;
  await assert.rejects(copy(f, { onProgress() { progress++; } }), error => error.code === 'EEXIST' && error.attestation_state === 'not_created');
  const after = await lstat(f.destination); assert.equal(after.ino, before.ino); assert.equal(after.mode, before.mode); assert.equal(progress, 0);
  if (kind === 'file') assert.equal(await readFile(f.destination, 'utf8'), 'keep'); await clean(f);
}));

test('competing real copy operations cannot overwrite the winner', () => fixture(async f => {
  const other = f.input + '.other', otherBody = Buffer.from(body); otherBody[0] ^= 255;
  await writeFile(other, otherBody); const signed = await signSourceBackup(otherBody, privatePem, meta, options);
  let arrivals = 0, release; const gate = new Promise(resolve => { release = resolve; });
  const onProgress = async event => { if (event.phase === 'before_readback') { if (++arrivals === 2) release(); await gate; } };
  const results = await Promise.allSettled([copy(f, { onProgress }),
    copyAuthenticatedSourceBackup(other, f.destination, signed.envelope, publicPem, policy, { ...options, onProgress })]);
  assert.equal(results.filter(r => r.status === 'fulfilled').length, 1);
  assert.equal(results.find(r => r.status === 'rejected').reason.code, 'EEXIST');
  const bytes = await readFile(f.destination); assert(bytes.equals(body) || bytes.equals(otherBody)); await clean(f);
}));

test('same-size input substitution never publishes an unauthenticated copy', () => fixture(async f => {
  const wrong = Buffer.from(body); wrong[1111] ^= 1; await writeFile(f.input, wrong);
  await assert.rejects(copy(f), error => error.code === 'attestation_artifact_mismatch' && error.attestation_state === 'staging');
  await absent(f.destination); assert.deepEqual(await readFile(f.input), wrong); await clean(f);
}));

test('changes after an earlier input chunk was copied do not create mixed authenticated output', () => fixture(async f => {
  let changed = false;
  await assert.rejects(copy(f, { async onProgress(event) {
    if (event.phase !== 'copying' || !event.bytes_hashed || changed) return; changed = true;
    const file = await open(f.input, 'r+'); try { await file.write(Buffer.of(255), 0, 1, 0); } finally { await file.close(); }
  } }), rejected('attestation_file_changed'));
  await absent(f.destination); await clean(f);
}));

test('readback catches corrupted staging bytes before the final destination exists', () => fixture(async f => {
  await assert.rejects(copy(f, { async onProgress(event) {
    if (event.phase === 'before_readback') { const file = await open(event.temporary, 'r+'); try { await file.write(Buffer.of(255), 0, 1, 77); } finally { await file.close(); } }
  } }), rejected('attestation_artifact_mismatch'));
  await absent(f.destination); await clean(f);
}));

test('same-byte replacement of the temporary inode is not published or deleted as owned', () => fixture(async f => {
  let temporary;
  await assert.rejects(copy(f, { async onProgress(event) {
    if (event.phase === 'before_readback') { temporary = event.temporary; await rename(temporary, temporary + '.original'); await writeFile(temporary, body, { mode: 0o600 }); }
  } }), error => error.code === 'attestation_temporary_changed' && error.attestation_cleanup_error === 'attestation_temporary_cleanup_failed' && error.attestation_temporary === temporary);
  await absent(f.destination); assert.deepEqual(await readFile(temporary), body); assert.deepEqual(await readFile(temporary + '.original'), body);
}));

test('output-parent substitution/permission loss fails closed instead of publishing elsewhere', () => fixture(async f => {
  await assert.rejects(copy(f, { async onProgress(event) { if (event.phase === 'before_readback') await chmod(f.directory, 0o777); } }),
    error => error.code === 'attestation_output_parent_changed' && error.attestation_cleanup_error === 'attestation_temporary_cleanup_failed');
  await absent(f.destination); await chmod(f.directory, 0o700);
}));

for (const phase of ['staging', 'copying', 'readback']) test(`cancellation during ${phase} removes only this attempt's temporary file`, () => fixture(async f => {
  const signal = new AbortController();
  await assert.rejects(copy(f, { signal: signal.signal, onProgress(event) { if (event.phase === phase) signal.abort(); } }), rejected('attestation_cancelled'));
  await absent(f.destination); await clean(f); assert.deepEqual(await readFile(f.input), body);
}));

test('pre-cancelled requests and invalid limits have no filesystem effects', () => fixture(async f => {
  const stopped = new AbortController(); stopped.abort();
  await assert.rejects(copy(f, { signal: stopped.signal }), rejected('attestation_cancelled'));
  await assert.rejects(copy(f, { timeoutMs: 0 }), rejected('invalid_attestation_file_limits'));
  await absent(f.destination); await clean(f);
}));

test('a shared deadline covers copying and readback', () => fixture(async f => {
  await assert.rejects(copy(f, { timeoutMs: 5, async onProgress(event) { if (event.phase === 'staging') await new Promise(resolve => setTimeout(resolve, 20)); } }), rejected('attestation_deadline'));
  await absent(f.destination); await clean(f);
}));

test('approval expiration before publication refuses and removes the owned temporary', () => fixture(async f => {
  f.signed = await signSourceBackup(body, privatePem, { ...meta, expires_at: '2026-09-28T12:00:01Z' }, options);
  const original = Date.now; let current = now;
  try {
    Date.now = () => current;
    await assert.rejects(copyAuthenticatedSourceBackup(f.input, f.destination, f.signed.envelope, publicPem, policy, {
      onProgress(event) { if (event.phase === 'before_readback') current += 1000; }
    }), rejected('attestation_expired'));
  } finally { Date.now = original; }
  await absent(f.destination); await clean(f);
}));

test('cancellation and expiration after publication do not skip finalization or roll back output', () => fixture(async f => {
  const signed = await signSourceBackup(body, privatePem, { ...meta, expires_at: '2026-09-28T12:00:01Z' }, options);
  const original = Date.now, controller = new AbortController(); let current = now;
  try {
    Date.now = () => current;
    const result = await copyAuthenticatedSourceBackup(f.input, f.destination, signed.envelope, publicPem, policy, {
      signal: controller.signal, onProgress(event) { if (event.phase === 'published') { current += 1000; controller.abort(); } }
    });
    assert.equal(result.copy.state, 'complete'); assert.equal(result.copy.cancellation_requested, true);
    assert.equal(result.copy.directory_synced, true);
  } finally { Date.now = original; }
  assert.deepEqual(await readFile(f.destination), body); await clean(f);
}));

for (const phase of ['copying', 'published']) for (const value of ['observer failed', null, false]) test(`an observer throwing ${JSON.stringify(value)} at ${phase} still finalizes owned resources`, () => fixture(async f => {
  await assert.rejects(copy(f, { onProgress(event) { if (event.phase === phase) throw value; } }),
    error => error.code === 'attestation_observer_failed' && error.attestation_state === (phase === 'published' ? 'published' : 'staging'));
  if (phase === 'published') assert.deepEqual(await readFile(f.destination), body); else await absent(f.destination);
  await clean(f);
}));

test('the real CLI keeps check read-only unless --copy-to is supplied explicitly', () => fixture(async f => {
  // Use a fresh archival approval because the real CLI uses the real wall clock.
  const signed = await signSourceBackup(body, privatePem, { repository: 'team/repo', sequence: '42' }); await writeFile(f.envelope, signed.envelope);
  const args = ['check', f.input, f.envelope, '--trust-key', f.pub, '--repository', 'team/repo', '--minimum-sequence', '42'];
  const read = cli(args); assert.equal(read.status, 0, read.stderr); await absent(f.destination); assert(!JSON.parse(read.stdout).copy);
  const copied = cli([...args, '--copy-to', f.destination]); assert.equal(copied.status, 0, copied.stderr);
  assert.equal(JSON.parse(copied.stdout).copy.state, 'complete'); assert.deepEqual(await readFile(f.destination), body);
  const again = cli([...args, '--copy-to', f.destination]); assert.equal(again.status, 1); assert.equal(again.stdout, ''); assert.equal(JSON.parse(again.stderr).code, 'EEXIST');
  for (const path of [f.input, f.envelope, f.pub]) {
    const result = cli([...args, '--copy-to', path]); assert.equal(result.status, 1); assert.equal(JSON.parse(result.stderr).code, 'attestation_output_conflicts_with_input');
  }
  await clean(f);
}));

test('copying a file beyond 16 MiB requires an explicit allowance and remains chunked', () => fixture(async f => {
  const size = 32 * 1024 * 1024 + 1, file = await open(f.input, 'w'); await file.truncate(size); await file.close();
  const signed = await signSourceBackupFile(f.input, privatePem, meta, { ...options, maximumBytes: size });
  await assert.rejects(copyAuthenticatedSourceBackup(f.input, f.destination, signed.envelope, publicPem, policy, options), rejected('invalid_attestation_artifact'));
  await absent(f.destination);
  const result = await copyAuthenticatedSourceBackup(f.input, f.destination, signed.envelope, publicPem, policy, { ...options, maximumBytes: size });
  assert.equal(result.copy.bytes, size); assert.equal(result.streaming.maximum_read_bytes, 65536);
  assert.equal(result.copy.write_calls, Math.ceil(size / 65536));
  const checked = await authenticateSourceBackupFile(f.destination, signed.envelope, publicPem, policy, { ...options, maximumBytes: size });
  assert.equal(checked.authentication.signature_verified, true); await clean(f);
}));

for (const phase of ['copying', 'published']) test(`SIGKILL at ${phase} does not expose partial output or permit overwriting a published copy`, { timeout: 15000 }, () => fixture(async f => {
  const child = fork(resolve('tests/browser/bundle-attestation-copy-child.mjs'), [f.input, f.destination, f.envelope, f.pub, phase],
    { stdio: ['ignore', 'ignore', 'pipe', 'ipc'], env: { ...process.env, PATH: '/nonexistent' } });
  let stderr = ''; child.stderr.on('data', chunk => { stderr += chunk; });
  const cleanupTimer = setTimeout(() => child.kill('SIGKILL'), 10000); cleanupTimer.unref();
  try {
    const event = await new Promise((resolve, reject) => {
      child.once('message', resolve); child.once('error', reject); child.once('exit', code => reject(new Error(`child exited ${code}: ${stderr}`)));
    });
    assert.equal(event.phase, phase); const exited = once(child, 'exit'); child.kill('SIGKILL'); const [, signal] = await exited; assert.equal(signal, 'SIGKILL');
    if (phase === 'copying') {
      await absent(f.destination); assert.equal((await lstat(event.temporary)).size, 65536);
      const orphan = await readFile(event.temporary); await copy(f); assert.deepEqual(await readFile(event.temporary), orphan);
    } else {
      const before = await lstat(f.destination); await assert.rejects(copy(f), rejected('EEXIST'));
      assert.equal((await lstat(f.destination)).ino, before.ino);
    }
    assert.deepEqual(await readFile(f.destination), body);
    assert.equal((await authenticateSourceBackupFile(f.destination, f.signed.envelope, publicPem, policy, options)).authentication.signature_verified, true);
  } finally { clearTimeout(cleanupTimer); if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL'); }
}));


test('foreign hard links to staging bytes block publication and are not removed by cleanup', () => fixture(async f => {
  const foreign = join(f.directory, 'foreign.bundle');
  await assert.rejects(copy(f, { async onProgress(event) {
    if (event.phase === 'before_readback') {
      const { link } = await import('node:fs/promises'); await link(event.temporary, foreign);
    }
  } }), rejected('attestation_temporary_changed'));
  await absent(f.destination); assert.deepEqual(await readFile(foreign), body); await clean(f);
}));
