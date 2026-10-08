// These are operator orchestration tests with a clearly fake native adapter.
// Real native admission is tested separately when FG_NATIVE_BIN is available.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync } from 'node:crypto';
import { mkdtemp, mkdir, writeFile, readFile, chmod, rm, readdir, rename, symlink, link, stat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync, spawn } from 'node:child_process';
import { deflateSync } from 'node:zlib';
import { importNativeSource, readNativeImportOutcome, retryNativeSourceImport } from '../../scripts/lib/native-source-import.mjs';
import { signSourceBackup } from '../../scripts/lib/source-attestation.mjs';
const HERE = dirname(fileURLToPath(import.meta.url));
const CLI = resolve(HERE, '../../scripts/import_git_bundle_native.mjs');
const sha = bytes => createHash('sha256').update(bytes).digest('hex');
const TENANT = '1'.repeat(32), REPO = '2'.repeat(32), PRINCIPAL = '3'.repeat(32);
async function fixture(t, mode = {}) {
  const root = await mkdtemp(join(tmpdir(), 'fgit-import-test-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const fg = join(root, 'fake-fg.mjs'), storage = join(root, 'node'), source = join(root, 'backup.bundle');
  const fake = await readFile(join(HERE, 'fixtures/native-import-fake.mjs'), 'utf8');
  await writeFile(fg, `#!${process.execPath}\n${fake}`, { mode: 0o700 });
  await mkdir(storage, { mode: 0o700 });
  const bytes = Buffer.from('THIS IS NOT GIT: fake native content fixture only\n');
  await writeFile(source, bytes);
  const state = { ...mode };
  const setMode = async changes => { Object.assign(state, changes); await writeFile(join(root, 'mode.json'), JSON.stringify(state)); };
  await setMode({});
  const calls = async () => (await readFile(join(root, 'calls.jsonl'), 'utf8')).trim().split('\n').filter(Boolean).map(JSON.parse);
  return { root, fg, storage, source, bytes, calls, setMode,
    config: { fg, storage, tenant: TENANT, repository: REPO, principal: PRINCIPAL,
      format: mode.format ?? 'sha1', recovery: join(root, 'recovery'), trustedLocal: true, timeoutMs: 10000 },
    recovery: { fg, trustedLocal: true, timeoutMs: 10000 } };
}
async function manifest(f) { return JSON.parse(await readFile(join(f.config.recovery, 'intent.json'))); }
async function failedImport(f, mode = 'fail-before') {
  await f.setMode({ import: mode });
  await assert.rejects(importNativeSource(f.source, f.config), error => error.details?.submission_attempted === true);
}
for (const format of ['sha1', 'sha256']) test(`import and read-only status preserve native identity (${format})`, async t => {
  const f = await fixture(t, { format });
  const result = await importNativeSource(f.source, { ...f.config, expected: { sha256: sha(f.bytes), refs: [
    { ref_hex: Buffer.from('refs/heads/main').toString('hex'), object_id: 'a'.repeat(format === 'sha1' ? 40 : 64) }], exact_refs: true } });
  assert.equal(result.outcome, 'committed'); assert.equal(result.submission_attempted, true);
  assert.equal(result.forge_state_restored, false); assert.equal(result.capsule_restored, false);
  const before = await readFile(join(f.config.recovery, 'intent.json'));
  assert.equal(sha(before), result.intent_sha256);
  assert.deepEqual(await readFile(join(f.config.recovery, 'source.bundle')), f.bytes);
  assert.equal((await stat(f.config.recovery)).mode & 0o777, 0o700);
  for (const name of ['intent.json', 'source.bundle']) assert.equal((await stat(join(f.config.recovery, name))).mode & 0o777, 0o600);
  await rm(f.source); // Original source is neither needed nor reopened.
  const status = await readNativeImportOutcome(f.config.recovery, { ...f.recovery, intentSha256: result.intent_sha256 });
  assert.equal(status.outcome, 'committed'); assert.equal(status.submission_attempted, false);
  assert.equal(status.transaction_id, result.transaction_id); assert.deepEqual(status.terminal, result.terminal);
  assert.deepEqual(await readFile(join(f.config.recovery, 'intent.json')), before);
  assert.equal((await f.calls()).filter(args => args[1] === 'import').length, 1);
});
test('lost committed response resolves without reexecution, even with snapshot missing', async t => {
  const f = await fixture(t); await failedImport(f, 'lose-commit');
  await rm(join(f.config.recovery, 'source.bundle')); await rm(f.source);
  const status = await readNativeImportOutcome(f.config.recovery, f.recovery);
  assert.equal(status.outcome, 'committed');
  const retried = await retryNativeSourceImport(f.config.recovery, f.recovery);
  assert.equal(retried.outcome, 'committed'); assert.equal(retried.submission_attempted, false);
  assert.equal((await f.calls()).filter(args => args[1] === 'import').length, 1);
});
test('explicit pending retry uses the original key and original snapshot', async t => {
  const f = await fixture(t); await failedImport(f);
  const intent = await manifest(f), before = await readFile(join(f.config.recovery, 'intent.json'));
  await writeFile(f.source, 'replacement original source');
  await f.setMode({ import: 'commit' });
  const result = await retryNativeSourceImport(f.config.recovery, f.recovery);
  assert.equal(result.outcome, 'committed'); assert.equal(result.submission_attempted, true);
  const submissions = (await f.calls()).filter(args => args[1] === 'import');
  assert.equal(submissions.length, 2);
  const attempts = (await readFile(join(f.root, 'attempts.jsonl'), 'utf8')).trim().split('\n').map(JSON.parse);
  assert.equal(attempts[0].key, intent.idempotency_key); assert.equal(attempts[1].key, intent.idempotency_key);
  assert.equal(submissions[1][5], join(f.config.recovery, 'source.bundle'));
  assert.equal(submissions.flat().includes(intent.idempotency_key), false);
  assert.deepEqual(await readFile(join(f.config.recovery, 'intent.json')), before);
  const accepted = JSON.parse((await readFile(join(f.root, 'submissions.jsonl'), 'utf8')).trim());
  assert.equal(accepted.digest, sha(f.bytes));
});
test('a nonterminal native recovery observation is never reported committed or automatically retried', async t => {
  const f = await fixture(t, { import: 'pending' });
  await assert.rejects(importNativeSource(f.source, f.config), e => e.details?.outcome === 'unknown_pending');
  assert.equal((await readNativeImportOutcome(f.config.recovery, f.recovery)).outcome, 'unknown_pending');
  assert.equal((await f.calls()).filter(args => args[1] === 'import').length, 1);
});
test('a canonical refusal remains terminal without another submission', async t => {
  const f = await fixture(t, { import: 'refuse' });
  const result = await importNativeSource(f.source, f.config);
  assert.equal(result.outcome, 'refused'); assert.equal(result.terminal.code, 'TargetRefMoved');
  await rm(join(f.config.recovery, 'source.bundle'));
  const retry = await retryNativeSourceImport(f.config.recovery, f.recovery);
  assert.deepEqual(retry.terminal, result.terminal); assert.equal(retry.submission_attempted, false);
});
test('native content refusal precedes recovery creation and target commands', async t => {
  const f = await fixture(t, { verify: 'refuse' });
  await assert.rejects(importNativeSource(f.source, f.config));
  assert.equal((await readdir(f.root)).includes('recovery'), false);
  assert.equal((await f.calls()).every(args => args[1] === 'verify'), true);
});
test('changed source after the owned read cannot change imported bytes', async t => {
  const f = await fixture(t); await f.setMode({ mutateSource: f.source });
  await importNativeSource(f.source, f.config);
  assert.notDeepEqual(await readFile(f.source), f.bytes);
  assert.deepEqual(await readFile(join(f.config.recovery, 'source.bundle')), f.bytes);
});
test('occupied recovery directory is retained and never permits a second import', async t => {
  const f = await fixture(t); await mkdir(f.config.recovery, { mode: 0o700 });
  await writeFile(join(f.config.recovery, 'owned-by-someone-else'), 'keep');
  await assert.rejects(importNativeSource(f.source, f.config), { code: 'EEXIST' });
  assert.deepEqual(await readdir(f.config.recovery), ['owned-by-someone-else']);
  assert.equal((await f.calls()).some(args => args[1] === 'import'), false);
});
test('bad options refuse before reading source or launching a process', async t => {
  const f = await fixture(t);
  for (const patch of [{ trustedLocal: false }, { fg: 'fg' }, { format: 'sha512' }, { tenant: 'x' },
    { timeoutMs: 0 }, { unexpected: true }, { expected: { sha256: 'bad' } }, { expected: { object_format: 'sha256' } }]) {
    await assert.rejects(importNativeSource('/does-not-exist', { ...f.config, ...patch }));
  }
  assert.equal((await readdir(f.root)).includes('calls.jsonl'), false);
});
test('independent identity mismatch cannot reach native import', async t => {
  const f = await fixture(t);
  await assert.rejects(importNativeSource(f.source, { ...f.config, expected: { sha256: 'f'.repeat(64) } }));
  assert.equal((await readdir(f.root)).includes('recovery'), false);
});
test('unsafe source and recovery filesystem entries refuse', async t => {
  const f = await fixture(t);
  const alias = join(f.root, 'alias'); await symlink(f.source, alias);
  await assert.rejects(importNativeSource(alias, f.config));
  await importNativeSource(f.source, f.config);
  await chmod(f.config.recovery, 0o755);
  await assert.rejects(readNativeImportOutcome(f.config.recovery, f.recovery));
  await chmod(f.config.recovery, 0o700);
  await chmod(join(f.config.recovery, 'intent.json'), 0o644);
  await assert.rejects(readNativeImportOutcome(f.config.recovery, f.recovery));
  await chmod(join(f.config.recovery, 'intent.json'), 0o600);
  await link(join(f.config.recovery, 'intent.json'), join(f.root, 'intent-hardlink'));
  await assert.rejects(readNativeImportOutcome(f.config.recovery, f.recovery));
});
test('replacement target directory refuses even with the same tenant/repository strings', async t => {
  const f = await fixture(t); await failedImport(f);
  await rename(f.storage, f.storage + '-old'); await mkdir(f.storage, { mode: 0o700 });
  await assert.rejects(readNativeImportOutcome(f.config.recovery, f.recovery), { code: 'native_import_directory_changed' });
  await assert.rejects(retryNativeSourceImport(f.config.recovery, f.recovery), { code: 'native_import_directory_changed' });
});
test('snapshot corruption never gets resubmitted but does not block read-only lookup', async t => {
  const f = await fixture(t); await failedImport(f);
  await writeFile(join(f.config.recovery, 'source.bundle'), 'corrupt');
  assert.equal((await readNativeImportOutcome(f.config.recovery, f.recovery)).outcome, 'unknown_pending');
  await assert.rejects(retryNativeSourceImport(f.config.recovery, f.recovery), { code: 'native_import_snapshot_mismatch' });
  assert.equal((await f.calls()).filter(args => args[1] === 'import').length, 1);
});
test('intent pin and canonical grammar refuse altered recovery identities', async t => {
  const f = await fixture(t); const done = await importNativeSource(f.source, f.config);
  await assert.rejects(readNativeImportOutcome(f.config.recovery, { ...f.recovery, intentSha256: '0'.repeat(64) }), { code: 'native_import_intent_pin_mismatch' });
  const path = join(f.config.recovery, 'intent.json'), bytes = await readFile(path, 'utf8');
  for (const changed of [bytes + ' ', bytes.replace('{', '{"type":"invalid",'), '{}\n', bytes.replace('fg-source-import-', 'different-')]) {
    await writeFile(path, changed);
    await assert.rejects(readNativeImportOutcome(f.config.recovery, f.recovery));
  }
  await writeFile(path, bytes);
  assert.equal((await readNativeImportOutcome(f.config.recovery, { ...f.recovery, intentSha256: done.intent_sha256 })).outcome, 'committed');
});
for (const field of ['badReceipt', 'wrongNamespace', 'wrongFormat', 'wrongCount', 'unknownField', 'duplicate', 'wrongExit', 'overflow']) {
  test(`untrusted native ${field} receipt leaves a recoverable unknown, not rollback`, async t => {
    const f = await fixture(t, { [field]: 'import' });
    await assert.rejects(importNativeSource(f.source, f.config), error => error.details?.submission_attempted === true
      && error.details?.outcome === 'unknown_pending' && error.details?.absence_proves_non_commit === false);
    await f.setMode({ [field]: null });
    assert.equal((await readNativeImportOutcome(f.config.recovery, f.recovery)).outcome, 'committed');
  });
}
for (const target of ['mutateSnapshot', 'mutateIntent']) test(`retry detects ${target} during native verification`, async t => {
  const f = await fixture(t); await failedImport(f);
  await f.setMode({ import: 'commit', [target]: join(f.config.recovery, target === 'mutateSnapshot' ? 'source.bundle' : 'intent.json') });
  await assert.rejects(retryNativeSourceImport(f.config.recovery, f.recovery));
  assert.equal((await f.calls()).filter(args => args[1] === 'import').length, 1);
});
test('cancellation drains a child that ignores TERM, preserving a committed unknown for status', async t => {
  const f = await fixture(t, { import: 'hang-after' });
  const controller = new AbortController();
  const operation = importNativeSource(f.source, { ...f.config, signal: controller.signal });
  let count = 0;
  while (!(await readdir(f.root)).includes('submissions.jsonl')) {
    assert.ok(++count < 500, 'fake import started'); await new Promise(resolve => setTimeout(resolve, 10));
  }
  controller.abort();
  await assert.rejects(operation, error => error.code === 'native_import_cancelled' && error.details?.submission_attempted);
  await f.setMode({ import: 'commit' });
  assert.equal((await readNativeImportOutcome(f.config.recovery, f.recovery)).outcome, 'committed');
});
test('expired budget never acquires a fresh verification/admission allowance', async t => {
  const f = await fixture(t, { verify: 'hang' });
  await assert.rejects(importNativeSource(f.source, { ...f.config, timeoutMs: 100 }));
  assert.equal((await readdir(f.root)).includes('recovery'), false);
});
test('two explicit retries share the original request identity', async t => {
  const f = await fixture(t); await failedImport(f); await f.setMode({ import: 'commit' });
  const results = await Promise.all([retryNativeSourceImport(f.config.recovery, f.recovery), retryNativeSourceImport(f.config.recovery, f.recovery)]);
  assert.equal(results[0].transaction_id, results[1].transaction_id);
  assert.equal(results.every(result => result.outcome === 'committed'), true);
  const keys = new Set((await readFile(join(f.root, 'attempts.jsonl'), 'utf8')).trim().split('\n').map(JSON.parse).map(v => v.key));
  assert.equal(keys.size, 1); // This checks identity, NOT real authority CAS.
});
test('CLI commits, reads and preserves canonical refusal/nonterminal exit semantics', async t => {
  for (const [mode, expected] of [['commit', 0], ['refuse', 3], ['pending', 4]]) {
    const f = await fixture(t, { import: mode });
    const common = ['--trusted-local', '--fg', f.fg];
    const result = spawnSync(process.execPath, [CLI, 'import', f.source, ...common, '--storage', f.storage,
      '--tenant', TENANT, '--repository-id', REPO, '--principal', PRINCIPAL, '--object-format', 'sha1',
      '--recovery-directory', f.config.recovery], { encoding: 'utf8', timeout: 20000 });
    assert.equal(result.status, mode === 'pending' ? 2 : expected, result.stderr);
    const status = spawnSync(process.execPath, [CLI, 'status', f.config.recovery, ...common], { encoding: 'utf8', timeout: 20000 });
    assert.equal(status.status, expected, status.stderr); assert.equal(JSON.parse(status.stdout).submission_attempted, false);
    const unknown = spawnSync(process.execPath, [CLI, 'status', f.config.recovery, ...common, '--storage', f.storage], { encoding: 'utf8' });
    assert.equal(unknown.status, 2);
  }
});
test('CLI receipt loss cannot erase the durable recovery directory', async t => {
  const f = await fixture(t);
  const child = spawn(process.execPath, [CLI, 'import', f.source, '--trusted-local', '--fg', f.fg,
    '--storage', f.storage, '--tenant', TENANT, '--repository-id', REPO, '--principal', PRINCIPAL,
    '--object-format', 'sha1', '--recovery-directory', f.config.recovery], { stdio: ['ignore', 'pipe', 'pipe'] });
  child.stdout.destroy(); child.stderr.resume();
  await new Promise(resolve => child.on('close', resolve));
  const status = await readNativeImportOutcome(f.config.recovery, f.recovery);
  assert.equal(status.outcome, 'committed'); assert.equal(status.submission_attempted, false);
});

function realBundle(format) {
  const oid = (type, body) => createHash(format).update(`${type} ${body.length}\0`).update(body).digest();
  const blob = Buffer.from('native source restoration\n');
  const tree = Buffer.concat([Buffer.from('100644 restored.txt\0'), oid('blob', blob)]);
  const commit = Buffer.from(`tree ${oid('tree', tree).toString('hex')}\nauthor Test <test@example.invalid> 1 +0000\ncommitter Test <test@example.invalid> 1 +0000\n\nnative restore fixture\n`);
  const entry = (type, body) => {
    let remaining = body.length >>> 4, first = (type << 4) | (body.length & 15); const header = [];
    if (remaining) first |= 128; header.push(first);
    while (remaining) { let byte = remaining & 127; remaining >>>= 7; if (remaining) byte |= 128; header.push(byte); }
    return Buffer.concat([Buffer.from(header), deflateSync(body)]);
  };
  const pack = Buffer.concat([Buffer.from('5041434b0000000200000003', 'hex'), entry(3, blob), entry(2, tree), entry(1, commit)]);
  const head = `# v3 git bundle\n@object-format=${format}\n${oid('commit', commit).toString('hex')} refs/heads/main\n\n`;
  return Buffer.concat([Buffer.from(head), pack, createHash(format).update(pack).digest()]);
}
test('actual native fg verification, import and canonical recovery in both hash domains', {
  skip: !process.env.FG_NATIVE_BIN && 'FG_NATIVE_BIN not supplied: no native admission execution claimed', timeout: 120000,
}, async t => {
  const fg = resolve(process.env.FG_NATIVE_BIN);
  for (const format of ['sha1', 'sha256']) {
    const f = await fixture(t, { format });
    // The node itself creates the storage root through its explicit init command.
    await rm(f.storage, { recursive: true });
    const initialized = spawnSync(fg, ['init', f.storage, TENANT, REPO, '--object-format', format], { encoding: 'utf8', timeout: 30000 });
    assert.equal(initialized.status, 0, initialized.stderr);
    await chmod(f.storage, 0o700); await writeFile(f.source, realBundle(format));
    const result = await importNativeSource(f.source, { ...f.config, fg, timeoutMs: 60000 });
    assert.equal(result.outcome, 'committed');
    const status = await readNativeImportOutcome(f.config.recovery, { ...f.recovery, fg, timeoutMs: 30000 });
    assert.equal(status.transaction_id, result.transaction_id); assert.deepEqual(status.terminal, result.terminal);
  }
});

async function signedFixture(t, mode = {}, metadata = {}) {
  const f = await fixture(t, mode);
  const pair = generateKeyPairSync('ed25519');
  const privatePem = Buffer.from(pair.privateKey.export({ type: 'pkcs8', format: 'pem' }));
  const publicPem = Buffer.from(pair.publicKey.export({ type: 'spki', format: 'pem' }));
  const policy = { repository: 'Dicklesworthstone/frankengit', minimum_sequence: '9007199254740993' };
  const signed = await signSourceBackup(f.bytes, privatePem, { repository: policy.repository,
    sequence: policy.minimum_sequence, ...metadata });
  const envelope = join(f.root, 'original.dsse.json'), key = join(f.root, 'public.pem');
  await writeFile(envelope, signed.envelope); await writeFile(key, publicPem);
  return { ...f, signed, publicPem, policy, envelope, key,
    config: { ...f.config, approval: { envelope, key, policy } } };
}
for (const format of ['sha1', 'sha256']) test(`signed restoration persists exact approval and external u64 floor (${format})`, async t => {
  const f = await signedFixture(t, { format });
  const result = await importNativeSource(f.source, f.config);
  assert.equal(result.outcome, 'committed'); assert.equal(result.source_approval.required, true);
  assert.equal(result.source_approval.checked_before_this_submission, true);
  assert.equal(result.source_approval.current_validity_claimed, false);
  const intent = await manifest(f);
  assert.equal(intent.schema_version, 2);
  assert.equal(intent.approval.policy.minimum_sequence, '9007199254740993');
  assert.equal(intent.approval.envelope_sha256, sha(f.signed.envelope));
  assert.equal(intent.approval.public_key_sha256, sha(f.publicPem));
  assert.deepEqual(await readFile(join(f.config.recovery, 'approval.dsse.json')), f.signed.envelope);
  assert.deepEqual(await readFile(join(f.config.recovery, 'trusted-public-key.pem')), f.publicPem);
  for (const file of ['approval.dsse.json', 'trusted-public-key.pem']) assert.equal((await stat(join(f.config.recovery, file))).mode & 0o777, 0o600);
  const args = await f.calls();
  assert.equal(args.flat().some(arg => arg === f.envelope || arg === f.key || arg.includes('PRIVATE KEY')), false);
});
test('wrong signing key refuses before opening source or launching fg', async t => {
  const f = await signedFixture(t);
  const foreign = generateKeyPairSync('ed25519').publicKey.export({ type: 'spki', format: 'pem' });
  await writeFile(f.key, foreign);
  await assert.rejects(importNativeSource('/missing-source', f.config), { code: 'attestation_key_hint_mismatch' });
  assert.equal((await readdir(f.root)).includes('calls.jsonl'), false);
});
for (const change of ['repository', 'minimum_sequence']) test(`signed import rejects wrong ${change} without native execution`, async t => {
  const f = await signedFixture(t);
  const policy = { ...f.policy, [change]: change === 'repository' ? 'elsewhere/repo' : '9007199254740994' };
  await assert.rejects(importNativeSource(f.source, { ...f.config, approval: { ...f.config.approval, policy } }));
  assert.equal((await readdir(f.root)).includes('calls.jsonl'), false);
});
test('valid approval cannot bypass changed bytes or explicit independent identity pins', async t => {
  const f = await signedFixture(t);
  await writeFile(f.source, 'a different artifact');
  await assert.rejects(importNativeSource(f.source, f.config), { code: 'attestation_artifact_mismatch' });
  await writeFile(f.source, f.bytes);
  await assert.rejects(importNativeSource(f.source, { ...f.config, expected: { sha256: 'f'.repeat(64) } }));
  assert.equal((await readdir(f.root)).includes('calls.jsonl'), false);
});
test('signed unresolved retry uses retained original approval, not mutable original paths', async t => {
  const f = await signedFixture(t, { import: 'fail-before' });
  await assert.rejects(importNativeSource(f.source, f.config), e => e.details?.submission_attempted === true);
  await rm(f.source); await rm(f.envelope); await rm(f.key);
  await f.setMode({ import: 'commit' });
  const result = await retryNativeSourceImport(f.config.recovery, f.recovery);
  assert.equal(result.outcome, 'committed'); assert.equal(result.source_approval.checked_before_this_submission, true);
  const imports = (await f.calls()).filter(args => args[1] === 'import');
  assert.equal(imports.length, 2);
  const attempts = (await readFile(join(f.root, 'attempts.jsonl'), 'utf8')).trim().split('\n').map(JSON.parse);
  assert.equal(attempts[0].key, attempts[1].key);
});
test('expired signed retry remains unresolved and never downgrades to unsigned', async t => {
  const now = Date.now(), expires = Math.floor(now / 1000) * 1000 + 60000;
  const f = await signedFixture(t, { import: 'fail-before' }, { expires_at: new Date(expires).toISOString().replace('.000Z', 'Z') });
  await assert.rejects(importNativeSource(f.source, f.config));
  t.mock.method(Date, 'now', () => expires + 1000);
  const before = (await f.calls()).filter(args => args[1] === 'verify').length;
  await assert.rejects(retryNativeSourceImport(f.config.recovery, f.recovery), { code: 'attestation_expired' });
  const status = await readNativeImportOutcome(f.config.recovery, f.recovery);
  assert.equal(status.outcome, 'unknown_pending'); assert.equal(status.source_approval.checked_before_this_submission, false);
  assert.equal((await f.calls()).filter(args => args[1] === 'verify').length, before);
  assert.equal((await f.calls()).filter(args => args[1] === 'import').length, 1);
  await assert.rejects(retryNativeSourceImport(f.config.recovery, { ...f.recovery, approval: undefined }));
});
test('expired or missing approval cannot hide a historical committed decision', async t => {
  const now = Date.now(), expires = Math.floor(now / 1000) * 1000 + 60000;
  const f = await signedFixture(t, { import: 'lose-commit' }, { expires_at: new Date(expires).toISOString().replace('.000Z', 'Z') });
  await assert.rejects(importNativeSource(f.source, f.config), e => e.details?.outcome === 'unknown_pending');
  t.mock.method(Date, 'now', () => expires + 1000);
  for (const file of ['approval.dsse.json', 'trusted-public-key.pem', 'source.bundle']) await rm(join(f.config.recovery, file));
  const status = await readNativeImportOutcome(f.config.recovery, f.recovery);
  const retry = await retryNativeSourceImport(f.config.recovery, f.recovery);
  assert.equal(status.outcome, 'committed'); assert.equal(retry.outcome, 'committed');
  assert.equal(retry.submission_attempted, false); assert.equal(retry.source_approval.checked_before_this_submission, false);
  assert.equal((await f.calls()).filter(args => args[1] === 'import').length, 1);
});
for (const file of ['approval.dsse.json', 'trusted-public-key.pem']) test(`changed retained ${file} blocks resubmission, not status`, async t => {
  const f = await signedFixture(t, { import: 'fail-before' });
  await assert.rejects(importNativeSource(f.source, f.config));
  await writeFile(join(f.config.recovery, file), 'changed');
  await assert.rejects(retryNativeSourceImport(f.config.recovery, f.recovery), { code: 'native_import_approval_changed' });
  assert.equal((await readNativeImportOutcome(f.config.recovery, f.recovery)).outcome, 'unknown_pending');
  assert.equal((await f.calls()).filter(args => args[1] === 'import').length, 1);
});
test('approval expiring during native verification refuses before target submission', async t => {
  const now = Date.now(), expires = Math.floor(now / 1000) * 1000 + 60000;
  const f = await signedFixture(t, {}, { expires_at: new Date(expires).toISOString().replace('.000Z', 'Z') });
  const gate = join(f.root, 'verify-release'); await f.setMode({ verifyGate: gate });
  const operation = importNativeSource(f.source, f.config);
  let tries = 0;
  while (!(await readdir(f.root)).includes('calls.jsonl')) {
    assert.ok(++tries < 500); await new Promise(resolve => setTimeout(resolve, 5));
  }
  t.mock.method(Date, 'now', () => expires + 1000); await writeFile(gate, 'release');
  await assert.rejects(operation, { code: 'attestation_expired' });
  assert.equal((await f.calls()).some(args => args[1] === 'import'), false);
  assert.equal((await readdir(f.root)).includes('recovery'), false);
});
test('signed CLI requires the complete trust group, then performs native import', async t => {
  const f = await signedFixture(t);
  const args = [CLI, 'import', f.source, '--trusted-local', '--fg', f.fg, '--storage', f.storage,
    '--tenant', TENANT, '--repository-id', REPO, '--principal', PRINCIPAL, '--object-format', 'sha1',
    '--recovery-directory', f.config.recovery, '--attestation', f.envelope, '--trust-key', f.key,
    '--source-repository', f.policy.repository, '--minimum-sequence', f.policy.minimum_sequence];
  const partial = spawnSync(process.execPath, args.slice(0, -2), { encoding: 'utf8' });
  assert.equal(partial.status, 2); assert.equal(JSON.parse(partial.stderr).error, 'complete_import_approval_required');
  assert.equal((await readdir(f.root)).includes('calls.jsonl'), false);
  const complete = spawnSync(process.execPath, args, { encoding: 'utf8', timeout: 20000 });
  assert.equal(complete.status, 0, complete.stderr);
  assert.equal(JSON.parse(complete.stdout).source_approval.checked_before_this_submission, true);
});

test('full-width native u64 decision sequences are preserved as decimal strings', async t => {
  const f = await fixture(t, { sequence: '18446744073709551615' });
  const result = await importNativeSource(f.source, f.config);
  assert.equal(result.terminal.decision_sequence, '18446744073709551615');
  assert.equal((await readNativeImportOutcome(f.config.recovery, f.recovery)).terminal.decision_sequence, '18446744073709551615');
});
test('native cleanup failure cannot turn an explicit terminal receipt into noncommit', async t => {
  const f = await fixture(t, { cleanup: 'import' });
  const result = await importNativeSource(f.source, f.config);
  assert.equal(result.outcome, 'committed'); assert.equal(result.node_closed, false);
  assert.equal(result.cleanup_error, 'fake native shutdown failed');
  assert.equal((await readNativeImportOutcome(f.config.recovery, f.recovery)).outcome, 'committed');
});

test('real SHA-1/SHA-256 native-test fixtures pass the pinned Git 2.47.3 oracle', {
  skip: spawnSync('git', ['--version'], { encoding: 'utf8' }).stdout?.trim() !== 'git version 2.47.3'
    && 'pinned Git 2.47.3 unavailable; this is fixture evidence only',
}, async t => {
  for (const format of ['sha1', 'sha256']) {
    const f = await fixture(t), bare = join(f.root, 'oracle.git');
    await writeFile(f.source, realBundle(format));
    const env = { ...process.env, GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: '/dev/null',
      GIT_CONFIG_SYSTEM: '/dev/null', GIT_ALLOW_PROTOCOL: 'file', HOME: f.root };
    const git = args => {
      const result = spawnSync('git', args, { encoding: 'utf8', timeout: 10000, env });
      assert.equal(result.status, 0, result.stderr); return result.stdout;
    };
    git(['init', '--bare', '--object-format=' + format, bare]);
    git(['-C', bare, 'bundle', 'verify', f.source]);
    git(['-C', bare, 'fetch', f.source, 'refs/heads/main:refs/heads/main']);
    git(['-C', bare, 'fsck', '--strict']);
    assert.equal(git(['-C', bare, 'show', 'refs/heads/main:restored.txt']), 'native source restoration\n');
  }
});
for (const phase of ['hang-before', 'hang-after']) test(`SIGKILL of the operator retains recovery across ${phase}`, { timeout: 15000 }, async t => {
  const f = await fixture(t, { import: phase });
  const child = spawn(process.execPath, [CLI, 'import', f.source, '--trusted-local', '--fg', f.fg,
    '--storage', f.storage, '--tenant', TENANT, '--repository-id', REPO, '--principal', PRINCIPAL,
    '--object-format', 'sha1', '--recovery-directory', f.config.recovery], { stdio: ['ignore', 'pipe', 'pipe'] });
  child.stdout.resume(); child.stderr.resume();
  const closed = new Promise(resolve => child.on('close', resolve));
  let tries = 0;
  const ready = phase === 'hang-after' ? 'submissions.jsonl' : 'attempts.jsonl';
  while (!(await readdir(f.root)).includes(ready)) {
    assert.ok(++tries < 500); await new Promise(resolve => setTimeout(resolve, 5));
  }
  const pid = Number(await readFile(join(f.root, 'import-child.pid'), 'utf8'));
  // Explicitly kill BOTH owned test processes: no orphan fake worker is left.
  child.kill('SIGKILL'); process.kill(pid, 'SIGKILL'); await closed;
  const status = await readNativeImportOutcome(f.config.recovery, f.recovery);
  assert.equal(status.outcome, phase === 'hang-after' ? 'committed' : 'unknown_pending');
  await f.setMode({ import: 'commit' });
  const resumed = await retryNativeSourceImport(f.config.recovery, f.recovery);
  assert.equal(resumed.outcome, 'committed');
  assert.equal(resumed.submission_attempted, phase === 'hang-before');
});
