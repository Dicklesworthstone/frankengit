import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, writeFileSync, readdirSync, mkdirSync, existsSync, lstatSync, truncateSync, unlinkSync, symlinkSync, chmodSync, renameSync, linkSync } from 'node:fs';
import { fork, spawnSync } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { hostname } from 'node:os';
import { once } from 'node:events';
import { join, resolve } from 'node:path';
import { recoverGitBundle } from '../../scripts/lib/source-recovery.mjs';
import { prepareGitBundleRecovery } from '../../crates/fgit-node/src/smart_http/server/browser/bundle-verify.mjs';
import { fixture, withTemp, git, bytes, objectId, bundle, webcrypto } from './bundle-recovery-fixtures.mjs';
const LOCK = '.frankengit-source-recovery.lock', MARKER = '.frankengit-source-recovery.json', STAGE = '.frankengit-source-recovery-head';
const OWNERS = '.frankengit-source-recovery-owners', script = resolve('scripts/recover_git_bundle.mjs');
const noGit = root => ({ ...process.env, PATH: join(root, 'home') });
const cli = (root, input, target, extras = []) => spawnSync(process.execPath, [script, input, target, '--head', 'refs/heads/main', '--resume', ...extras],
  { encoding: 'utf8', timeout: 10000, env: noGit(root) });
async function interrupted(f, target, phase = 'before_publication') {
  const controller = new AbortController();
  await assert.rejects(recoverGitBundle(f.input, target, f.request, { signal: controller.signal, onProgress(event) {
    if (event.phase === phase) controller.abort();
  } }), error => error.code === 'recovery_cancelled');
}
async function paused(root, f, target, phase, resume = false) {
  const input = join(root, 'input.bundle'); writeFileSync(input, f.input);
  const child = fork(new URL('./bundle-recovery-child.mjs', import.meta.url), [input, target, phase, String(resume)],
    { env: noGit(root), silent: true });
  let diagnostics = ''; child.stderr.on('data', data => { diagnostics += data; });
  const event = await new Promise((accept, reject) => {
    const timer = setTimeout(() => { child.kill('SIGKILL'); reject(new Error(`child phase timeout: ${diagnostics}`)); }, 10000);
    child.once('error', error => { clearTimeout(timer); reject(error); });
    child.once('exit', (code, signal) => { clearTimeout(timer); reject(new Error(`early child exit ${code}/${signal}: ${diagnostics}`)); });
    child.once('message', event => { clearTimeout(timer); if (event.failure || event.unexpected_completion) { child.kill('SIGKILL'); reject(new Error(JSON.stringify(event))); } else accept(event); });
  });
  return { child, event, input, async kill() { const finished = once(child, 'exit'); child.kill('SIGKILL'); const [code, signal] = await finished; assert.equal(code, null); assert.equal(signal, 'SIGKILL'); } };
}
for (const format of ['sha1', 'sha256']) for (const phase of ['reserved', 'staged:packed-refs', 'writing:config', 'before_publication', 'published']) {
  test(`${format}: SIGKILL at ${phase} resumes through the actual CLI and clones exact source`, () => withTemp(async root => {
    const f = fixture(format, format === 'sha1' ? 6 : 7), target = join(root, 'restore.git');
    const process = await paused(root, f, target, phase); await process.kill();
    assert.equal(existsSync(join(target, LOCK)), true, 'SIGKILL must leave the actual owner lock');
    assert.equal(existsSync(join(target, 'HEAD')), phase === 'published');
    const resumed = cli(root, process.input, target, ['--expect-format', format, '--expect-ref', `refs/heads/main=${f.tip}`]);
    assert.equal(resumed.status, 0, resumed.stderr); const result = JSON.parse(resumed.stdout);
    assert.equal(result.resumed, true); assert.equal(result.state, 'complete'); assert.equal(result.already_published, phase === 'published');
    assert.equal(result.owner_sequence, 1); assert(!existsSync(join(target, LOCK))); assert(!existsSync(join(target, STAGE)));
    git(root, ['--git-dir', target, 'fsck', '--strict', '--full']);
    const clone = join(root, 'clone.git'); git(root, ['clone', '--bare', '--quiet', target, clone]);
    assert.equal(git(root, ['--git-dir', clone, 'rev-parse', 'HEAD']).toString().trim(), f.tip);
    assert.deepEqual(git(root, ['--git-dir', clone, 'show', 'HEAD:executable']), f.content);
    assert.equal(git(root, ['--git-dir', clone, 'rev-parse', 'refs/tags/release']).toString().trim(), f.tag);
  }));
}
test('SIGKILL during a real partial pack write resumes the verified suffix without replacing the file', () => withTemp(async root => {
  const content = Buffer.alloc(300000); let state = 0x193174;
  for (let i = 0; i < content.length; i++) { state ^= state << 13; state ^= state >>> 17; state ^= state << 5; content[i] = state & 255; }
  const id = (kind, body) => objectId(kind, body);
  const tree = Buffer.concat([bytes('100644 file\0'), Buffer.from(id('blob', content), 'hex')]);
  const commit = bytes(`tree ${id('tree', tree)}\nauthor A <a@invalid> 1 +0000\ncommitter A <a@invalid> 1 +0000\n\nx\n`);
  const f = { input: bundle([{ kind: 'blob', body: content, compression: { level: 0 } }, { kind: 'tree', body: tree }, { kind: 'commit', body: commit }], 'sha1',
    { refs: [{ name: 'refs/heads/main', id: id('commit', commit) }] }), request: { head_ref_hex: bytes('refs/heads/main').toString('hex') } };
  const target = join(root, 'large.git'), process = await paused(root, f, target, 'partial-pack'); await process.kill();
  const path = join(target, process.event.phase.slice('writing:'.length)), before = lstatSync(path), prefix = readFileSync(path);
  assert(before.size > 0 && before.size < process.event.total);
  const result = cli(root, process.input, target); assert.equal(result.status, 0, result.stderr);
  assert.equal(lstatSync(path).ino, before.ino); assert.deepEqual(readFileSync(path).subarray(0, prefix.length), prefix);
  assert(JSON.parse(result.stdout).appended_bytes > 0);
  assert.deepEqual(git(root, ['--git-dir', target, 'show', 'HEAD:file']), content);
}));
test('a resumed writer can itself die; the next run supersedes only the dead sequence', () => withTemp(async root => {
  const f = fixture(), target = join(root, 'again.git');
  const first = await paused(root, f, target, 'reserved'); await first.kill();
  for (let sequence = 1; sequence <= 2; sequence++) {
    const retry = await paused(root, f, target, 'resuming', true); await retry.kill();
    assert(existsSync(join(target, OWNERS, `${String(sequence).padStart(6, '0')}.lease`)));
    assert(!existsSync(join(target, OWNERS, `${String(sequence).padStart(6, '0')}.done`)));
  }
  const result = cli(root, first.input, target); assert.equal(result.status, 0, result.stderr); assert.equal(JSON.parse(result.stdout).owner_sequence, 3);
  assert.equal(git(root, ['--git-dir', target, 'rev-parse', 'HEAD']).toString().trim(), f.tip);
}));
test('an active original writer is never stolen; its death permits the same resume', () => withTemp(async root => {
  const f = fixture(), target = join(root, 'active.git'), original = await paused(root, f, target, 'reserved');
  try {
    const before = readFileSync(join(target, LOCK));
    const refused = cli(root, original.input, target); assert.equal(refused.status, 1); assert.equal(refused.stdout, '');
    assert.equal(JSON.parse(refused.stderr).code, 'recovery_owner_active');
    assert.deepEqual(readFileSync(join(target, LOCK)), before); assert(!existsSync(join(target, OWNERS)));
  } finally { await original.kill(); }
  const allowed = cli(root, original.input, target); assert.equal(allowed.status, 0, allowed.stderr);
}));
test('concurrent resumptions cannot steal an active numbered lease', () => withTemp(async root => {
  const f = fixture(), target = join(root, 'concurrent.git'); await interrupted(f, target, 'reserved');
  let enter, finish; const entered = new Promise(resolve => { enter = resolve; }), gate = new Promise(resolve => { finish = resolve; });
  const first = recoverGitBundle(f.input, target, f.request, { resume: true, onProgress: async ({ phase }) => { if (phase === 'resuming') { enter(); await gate; } } });
  await entered;
  try { await assert.rejects(recoverGitBundle(f.input, target, f.request, { resume: true }), error => error.code === 'recovery_owner_active'); }
  finally { finish(); }
  assert.equal((await first).state, 'complete');
  const next = await recoverGitBundle(f.input, target, f.request, { resume: true }); assert.equal(next.owner_sequence, 2); assert.equal(next.appended_bytes, 0);
}));
for (const relative of ['config', 'packed-refs', STAGE, 'pack', 'index']) test(`verified partial ${relative} keeps its original inode and complete siblings`, () => withTemp(async root => {
  const f = fixture(), target = join(root, 'partial.git'); await interrupted(f, target);
  const name = relative === 'pack' || relative === 'index' ? 'objects/pack/' + readdirSync(join(target, 'objects/pack')).find(p => p.endsWith(relative === 'pack' ? '.pack' : '.idx')) : relative;
  const path = join(target, name), original = readFileSync(path); truncateSync(path, Math.floor(original.length / 2));
  const before = lstatSync(path), prefix = readFileSync(path), receiptBefore = lstatSync(join(target, MARKER));
  const report = await recoverGitBundle(f.input, target, f.request, { resume: true });
  assert.equal(report.state, 'complete'); assert(report.appended_bytes > 0);
  const resulting = relative === STAGE ? join(target, 'HEAD') : path;
  assert.equal(lstatSync(resulting).ino, before.ino); assert.deepEqual(readFileSync(resulting), original);
  assert.deepEqual(readFileSync(resulting).subarray(0, prefix.length), prefix);
  assert.equal(lstatSync(join(target, MARKER)).mtimeMs, receiptBefore.mtimeMs, 'complete matching file bytes are not rewritten');
}));
for (const relative of ['config', 'packed-refs', STAGE]) test(`mismatching ${relative} is preserved and never repaired by truncation`, () => withTemp(async root => {
  const f = fixture(), target = join(root, 'bad.git'); await interrupted(f, target);
  const path = join(target, relative), data = readFileSync(path); data[0] ^= 1; writeFileSync(path, data.subarray(0, Math.max(1, data.length - 1)));
  const before = readFileSync(path);
  await assert.rejects(recoverGitBundle(f.input, target, f.request, { resume: true }), error => error.code === 'recovery_file_mismatch');
  assert.deepEqual(readFileSync(path), before); assert(!existsSync(join(target, OWNERS))); assert(!existsSync(join(target, 'HEAD')));
}));
for (const path of ['hooks', 'objects/info', 'refs/heads', 'unexpected']) test(`unknown ${path} blocks resume before any claim or data writes`, () => withTemp(async root => {
  const f = fixture(), target = join(root, 'foreign.git'); await interrupted(f, target);
  mkdirSync(join(target, path), { mode: 0o700 }); writeFileSync(join(target, path, 'private'), 'keep', { mode: 0o600 });
  await assert.rejects(recoverGitBundle(f.input, target, f.request, { resume: true }), error => error.code === 'unexpected_recovery_entry');
  assert.equal(readFileSync(join(target, path, 'private'), 'utf8'), 'keep'); assert(!existsSync(join(target, OWNERS)));
}));
test('symlinks and public permissions are refused without following or rewriting them', () => withTemp(async root => {
  const f = fixture(), target = join(root, 'symlink.git'), sentinel = join(root, 'sentinel'); await interrupted(f, target);
  writeFileSync(sentinel, 'keep', { mode: 0o600 }); unlinkSync(join(target, 'config')); symlinkSync(sentinel, join(target, 'config'));
  await assert.rejects(recoverGitBundle(f.input, target, f.request, { resume: true })); assert.equal(readFileSync(sentinel, 'utf8'), 'keep');
  unlinkSync(join(target, 'config')); chmodSync(target, 0o755);
  await assert.rejects(recoverGitBundle(f.input, target, f.request, { resume: true }), e => e.code === 'recovery_permissions_or_owner');
}));
test('wrong bundle or changed HEAD cannot reuse the prior recovery marker', () => withTemp(async root => {
  const f = fixture(), target = join(root, 'wrong.git'); await interrupted(f, target);
  const changed = bundle(f.records, f.format, { refs: [...f.refs, { name: 'refs/heads/other', id: f.tip }] });
  const before = readFileSync(join(target, MARKER));
  await assert.rejects(recoverGitBundle(changed, target, { head_ref_hex: bytes('refs/heads/other').toString('hex') }, { resume: true }));
  assert.deepEqual(readFileSync(join(target, MARKER)), before); assert(!existsSync(join(target, OWNERS)));
}));
test('completed recovery can be rechecked and finalized without rewriting source files', () => withTemp(async root => {
  const f = fixture('sha256'), target = join(root, 'complete.git'); await recoverGitBundle(f.input, target, f.request);
  const before = lstatSync(join(target, 'HEAD')), config = readFileSync(join(target, 'config'));
  const result = await recoverGitBundle(f.input, target, f.request, { resume: true });
  assert.equal(result.already_published, true); assert.equal(result.appended_bytes, 0); assert.equal(lstatSync(join(target, 'HEAD')).ino, before.ino);
  assert.equal(lstatSync(join(target, 'HEAD')).mtimeMs, before.mtimeMs); assert.deepEqual(readFileSync(join(target, 'config')), config);
}));
test('a published but incomplete repository is not silently repaired or re-published', () => withTemp(async root => {
  const f = fixture(), target = join(root, 'published.git'); await recoverGitBundle(f.input, target, f.request);
  truncateSync(join(target, 'config'), 3); const before = readFileSync(join(target, 'HEAD'));
  await assert.rejects(recoverGitBundle(f.input, target, f.request, { resume: true }), e => e.code === 'published_recovery_incomplete');
  assert.equal(readFileSync(join(target, 'config')).length, 3); assert.deepEqual(readFileSync(join(target, 'HEAD')), before); assert(!existsSync(join(target, OWNERS)));
}));
test('same-byte fake release file cannot impersonate the same-inode ownership release', () => withTemp(async root => {
  const f = fixture(), target = join(root, 'release.git'); await interrupted(f, target);
  await recoverGitBundle(f.input, target, f.request, { resume: true });
  const done = join(target, OWNERS, '000001.done'), data = readFileSync(done); unlinkSync(done); writeFileSync(done, data, { mode: 0o600 });
  await assert.rejects(recoverGitBundle(f.input, target, f.request, { resume: true }), e => e.code === 'recovery_owner_release_mismatch');
  assert(!existsSync(join(target, OWNERS, '000002.lease')));
}));
test('owner-sequence gaps and foreign-host owner records fail closed', () => withTemp(async root => {
  const f = fixture(), target = join(root, 'owners.git'); await interrupted(f, target);
  const marker = JSON.parse(readFileSync(join(target, MARKER)));
  writeFileSync(join(target, LOCK), JSON.stringify({ schema: 'frankengit-source-recovery-lock-v1', hostname: hostname() + '-other', pid: 1,
    nonce: randomUUID(), plan_sha256: marker.plan_sha256 }), { mode: 0o600 });
  await assert.rejects(recoverGitBundle(f.input, target, f.request, { resume: true }), e => e.code === 'recovery_owner_host_mismatch');
  unlinkSync(join(target, LOCK)); await recoverGitBundle(f.input, target, f.request, { resume: true });
  renameSync(join(target, OWNERS, '000001.lease'), join(target, OWNERS, '000002.lease'));
  await assert.rejects(recoverGitBundle(f.input, target, f.request, { resume: true }), e => e.code === 'recovery_owner_sequence_gap');
}));
test('interrupted unpublished lease candidates do not gain ownership or prevent a bounded retry', () => withTemp(async root => {
  const f = fixture(), target = join(root, 'candidate.git'); await interrupted(f, target, 'reserved');
  mkdirSync(join(target, OWNERS), { mode: 0o700 });
  const name = `candidate-${process.pid}-${randomUUID()}`; writeFileSync(join(target, OWNERS, name), '{partial', { mode: 0o600 });
  const result = await recoverGitBundle(f.input, target, f.request, { resume: true }); assert.equal(result.owner_sequence, 1);
  assert.equal(readFileSync(join(target, OWNERS, name), 'utf8'), '{partial');
}));
test('no receipt and no exact original owner means no claim on an existing directory', () => withTemp(async root => {
  const f = fixture(), target = join(root, 'empty'); mkdirSync(target, { mode: 0o700 });
  await assert.rejects(recoverGitBundle(f.input, target, f.request, { resume: true }), e => e.code === 'recovery_receipt_missing_or_partial');
  assert.deepEqual(readdirSync(target), []);
}));
test('graceful interruption of a resume releases only its own lease and the next attempt finishes', () => withTemp(async root => {
  const f = fixture(), target = join(root, 'cancel.git'); await interrupted(f, target, 'reserved');
  const controller = new AbortController();
  await assert.rejects(recoverGitBundle(f.input, target, f.request, { resume: true, signal: controller.signal, onProgress({ phase }) {
    if (phase === 'staged:packed-refs') controller.abort();
  } }), e => e.code === 'recovery_cancelled');
  assert(existsSync(join(target, OWNERS, '000001.done'))); assert(!existsSync(join(target, 'HEAD')));
  const result = await recoverGitBundle(f.input, target, f.request, { resume: true }); assert.equal(result.state, 'complete'); assert.equal(result.owner_sequence, 2);
}));
test('resume finalizes publication even when cancellation is requested immediately after HEAD visibility', () => withTemp(async root => {
  const f = fixture(), target = join(root, 'finish.git'); await interrupted(f, target);
  const controller = new AbortController();
  const result = await recoverGitBundle(f.input, target, f.request, { resume: true, signal: controller.signal, onProgress({ phase }) {
    if (phase === 'published') controller.abort();
  } });
  assert.equal(result.state, 'complete'); assert.equal(result.cancellation_requested, true); assert(existsSync(join(target, OWNERS, '000001.done')));
}));

test('foreign hard links cannot make a partial-file append modify another pathname', () => withTemp(async root => {
  const f = fixture(), target = join(root, 'linked.git'); await interrupted(f, target);
  const path = join(target, 'config'), outside = join(root, 'outside'); truncateSync(path, 4); linkSync(path, outside);
  const before = readFileSync(outside);
  await assert.rejects(recoverGitBundle(f.input, target, f.request, { resume: true }), e => e.code === 'recovery_file_changed');
  assert.deepEqual(readFileSync(outside), before); assert(!existsSync(join(target, OWNERS)));
}));
test('lease sequence 128 is permitted but a 129th attempt refuses without adding records', () => withTemp(async root => {
  const f = fixture(), target = join(root, 'bounded.git'); await interrupted(f, target);
  const marker = JSON.parse(readFileSync(join(target, MARKER))), owners = join(target, OWNERS); mkdirSync(owners, { mode: 0o700 });
  // Synthetic released ownership history exercises the format/limit boundary;
  // the real-process death and contention tests above cover acquisition itself.
  for (let sequence = 1; sequence < 128; sequence++) {
    const slot = String(sequence).padStart(6, '0'), lease = join(owners, slot + '.lease');
    writeFileSync(lease, JSON.stringify({ schema: 'frankengit-source-recovery-owner-v1', hostname: hostname(), pid: process.pid,
      nonce: randomUUID(), plan_sha256: marker.plan_sha256, sequence }), { mode: 0o600 }); linkSync(lease, join(owners, slot + '.done'));
  }
  const result = await recoverGitBundle(f.input, target, f.request, { resume: true }); assert.equal(result.owner_sequence, 128);
  const count = readdirSync(owners).length;
  await assert.rejects(recoverGitBundle(f.input, target, f.request, { resume: true }), e => e.code === 'recovery_owner_limit');
  assert.equal(readdirSync(owners).length, count);
}));
test('resume has one aggregate deadline across verification and staged-file work', () => withTemp(async root => {
  const f = fixture(), target = join(root, 'deadline.git'); await interrupted(f, target, 'reserved');
  await assert.rejects(recoverGitBundle(f.input, target, f.request, { resume: true, timeoutMs: 100,
    onProgress: async ({ phase }) => { if (phase === 'resuming') await new Promise(resolve => setTimeout(resolve, 120)); },
  }), e => e.code === 'recovery_deadline');
  assert(!existsSync(join(target, 'HEAD')));
  assert.equal((await recoverGitBundle(f.input, target, f.request, { resume: true })).state, 'complete');
}));

test('loss of current ownership before publication refuses without creating HEAD', () => withTemp(async root => {
  const f = fixture(), target = join(root, 'lost-lease.git'); await interrupted(f, target);
  await assert.rejects(recoverGitBundle(f.input, target, f.request, { resume: true, onProgress({ phase }) {
    if (phase === 'before_publication') linkSync(join(target, OWNERS, '000001.lease'), join(target, OWNERS, '000001.done'));
  } }), e => e.code === 'recovery_owner_released_early');
  assert(!existsSync(join(target, 'HEAD')));
  assert.equal((await recoverGitBundle(f.input, target, f.request, { resume: true })).state, 'complete');
}));
