import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, writeFileSync, readdirSync, existsSync, mkdirSync, symlinkSync, lstatSync, unlinkSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { join, resolve } from 'node:path';
import { recoverGitBundle, SourceRecoveryError } from '../../scripts/lib/source-recovery.mjs';
import { fixture, main, withTemp, git } from './bundle-recovery-fixtures.mjs';
const script = resolve('scripts/recover_git_bundle.mjs');
const lockName = '.frankengit-source-recovery.lock';
for (const format of ['sha1', 'sha256']) for (const delta of [6, 7]) {
  test(`${format} delta ${delta}: actual offline command creates a cloneable bare repository with no Git on PATH`, () => withTemp(async root => {
    const f = fixture(format, delta), file = join(root, 'input.bundle'), repo = join(root, 'recovered.git'); writeFileSync(file, f.input);
    const child = spawnSync(process.execPath, [script, file, repo, '--head', 'refs/heads/main', '--expect-format', format,
      '--expect-ref', `refs/heads/main=${f.tip}`], { encoding: 'utf8', timeout: 10000, env: { ...process.env, PATH: join(root, 'home') } });
    assert.equal(child.status, 0, child.stderr); assert.equal(child.stderr, '');
    const result = JSON.parse(child.stdout); assert.equal(result.state, 'complete'); assert.equal(result.files_synced, true);
    assert.equal(result.native_authority_restored, false); assert.equal(result.verification.caller_expectations_matched, true);
    assert.equal(existsSync(join(repo, lockName)), false); assert.equal(existsSync(join(repo, '.frankengit-source-recovery-head')), false);
    assert.equal(lstatSync(repo).mode & 0o777, 0o700); assert.equal(lstatSync(join(repo, 'config')).mode & 0o777, 0o600);
    assert.deepEqual(readFileSync(file), f.input, 'input must not be modified');
    git(root, ['--git-dir', repo, 'fsck', '--strict', '--full']);
    const clone = join(root, 'clone.git'); git(root, ['clone', '--bare', '--quiet', repo, clone]);
    assert.equal(git(root, ['--git-dir', clone, 'rev-parse', 'HEAD']).toString().trim(), f.tip);
    assert.deepEqual(git(root, ['--git-dir', clone, 'show', 'HEAD:executable']), f.content);
    assert.deepEqual(git(root, ['--git-dir', clone, 'show', 'HEAD:link']), f.link);
    assert.equal(existsSync(join(repo, 'link')), false, 'do not create worktree symlinks');
  }));
}
for (const kind of ['directory', 'file', 'symlink', 'dangling-symlink']) test(`existing ${kind} destination is untouched`, () => withTemp(async root => {
  const f = fixture(), repo = join(root, 'existing'), sentinel = join(root, 'sentinel'); writeFileSync(sentinel, 'unchanged');
  if (kind === 'directory') { mkdirSync(repo); writeFileSync(join(repo, 'valuable'), 'data'); }
  else if (kind === 'file') writeFileSync(repo, 'valuable');
  else symlinkSync(kind === 'symlink' ? sentinel : join(root, 'missing'), repo);
  await assert.rejects(recoverGitBundle(f.input, repo, f.request), error => error instanceof SourceRecoveryError && error.state === 'not_created' && error.code === 'EEXIST');
  assert.equal(readFileSync(sentinel, 'utf8'), 'unchanged');
  if (kind === 'directory') assert.deepEqual(readdirSync(repo), ['valuable']);
  if (kind === 'file') assert.equal(readFileSync(repo, 'utf8'), 'valuable');
  if (kind.includes('symlink')) assert.equal(lstatSync(repo).isSymbolicLink(), true);
}));
test('bad bundle, trust pin or recovery request creates no destination', () => withTemp(async root => {
  const f = fixture(), input = Buffer.from(f.input); input[input.length - 1] ^= 1;
  for (const [bytes, request] of [[input, f.request], [f.input, { head_ref_hex: main, expectations: { sha256: 'a'.repeat(64) } }],
    [f.input, { head_ref_hex: 'ff' }]]) {
    const repo = join(root, 'new'); await assert.rejects(recoverGitBundle(bytes, repo, request), error => error.state === 'not_created');
    assert.equal(existsSync(repo), false);
  }
}));
for (const phase of ['verified', 'reserved', 'before:packed-refs', 'staged:packed-refs', 'staged:HEAD', 'before_publication']) {
  test(`cancellation at ${phase} drains handles and never publishes HEAD`, () => withTemp(async root => {
    const f = fixture(), repo = join(root, 'new'), controller = new AbortController();
    await assert.rejects(recoverGitBundle(f.input, repo, f.request, { signal: controller.signal, onProgress(event) {
      if (event.phase === phase) controller.abort();
    } }), error => error.code === 'recovery_cancelled' && ['staging', 'not_created'].includes(error.state));
    assert.equal(existsSync(join(repo, 'HEAD')), false); assert.equal(existsSync(join(repo, lockName)), false);
    const completed = await recoverGitBundle(f.input, join(root, 'twin'), f.request); assert.equal(completed.state, 'complete');
  }));
}
test('HEAD is absent throughout staging and installed only after every object/ref/config file', () => withTemp(async root => {
  const f = fixture(), repo = join(root, 'new'), phases = [];
  await recoverGitBundle(f.input, repo, f.request, { onProgress({ phase }) {
    phases.push(phase);
    if (phase !== 'published') assert.equal(existsSync(join(repo, 'HEAD')), false, phase);
    else {
      assert.equal(readFileSync(join(repo, 'HEAD'), 'utf8'), 'ref: refs/heads/main\n');
      assert.equal(readdirSync(join(repo, 'objects', 'pack')).length, 2); assert(existsSync(join(repo, 'packed-refs')));
    }
  } });
  assert.equal(phases.at(-1), 'published');
}));
test('cancellation after publication completes finalization instead of claiming rollback', () => withTemp(async root => {
  const f = fixture(), repo = join(root, 'new'), controller = new AbortController();
  const result = await recoverGitBundle(f.input, repo, f.request, { signal: controller.signal, onProgress({ phase }) {
    if (phase === 'published') controller.abort();
  } });
  assert.equal(result.state, 'complete'); assert.equal(result.cancellation_requested, true); assert(existsSync(join(repo, 'HEAD')));
  git(root, ['--git-dir', repo, 'fsck', '--full']);
}));
for (const format of ['sha1', 'sha256']) test(`${format}: failure after publication drains finalization and reports published`, () => withTemp(async root => {
  const f = fixture(format), repo = join(root, 'new'), stagedHead = join(repo, '.frankengit-source-recovery-head');
  const observerError = new Error('simulated post-link failure');
  await assert.rejects(recoverGitBundle(f.input, repo, f.request, { onProgress({ phase }) {
    if (phase === 'published') {
      assert.equal(readFileSync(join(repo, 'HEAD'), 'utf8'), 'ref: refs/heads/main\n');
      assert(existsSync(stagedHead)); assert(existsSync(join(repo, lockName)));
      throw observerError;
    }
  } }), error => {
    assert(error instanceof SourceRecoveryError); assert.equal(error.state, 'published');
    assert.equal(error.cause, observerError); assert.equal(error.lock_cleanup_error, undefined);
    return true;
  });
  assert(existsSync(join(repo, 'HEAD'))); assert(!existsSync(stagedHead)); assert(!existsSync(join(repo, lockName)));
  assert.equal(git(root, ['--git-dir', repo, 'rev-parse', 'HEAD']).toString().trim(), f.tip);
  assert.deepEqual(git(root, ['--git-dir', repo, 'show', 'HEAD:executable']), f.content);
  assert.deepEqual(git(root, ['--git-dir', repo, 'show', 'HEAD:link']), f.link);
  git(root, ['--git-dir', repo, 'fsck', '--strict', '--full']);
}));
test('post-write corruption is caught by readback before HEAD publication', () => withTemp(async root => {
  const f = fixture(), repo = join(root, 'new');
  await assert.rejects(recoverGitBundle(f.input, repo, f.request, { onProgress({ phase }) {
    if (phase === 'before_publication') writeFileSync(join(repo, 'config'), 'corrupted');
  } }), error => ['recovery_file_changed', 'recovery_file_mismatch'].includes(error.code) && error.state === 'staging');
  assert(!existsSync(join(repo, 'HEAD'))); assert.equal(readFileSync(join(repo, 'config'), 'utf8'), 'corrupted');
}));
test('planted symlinks are refused, never followed for writing or cleanup', () => withTemp(async root => {
  const f = fixture(), repo = join(root, 'new'), sentinel = join(root, 'sentinel'); writeFileSync(sentinel, 'unchanged');
  await assert.rejects(recoverGitBundle(f.input, repo, f.request, { onProgress({ phase }) {
    if (phase === 'before:config') symlinkSync(sentinel, join(repo, 'config'));
  } }), error => error.code === 'EEXIST' && error.state === 'staging');
  assert.equal(readFileSync(sentinel, 'utf8'), 'unchanged'); assert(lstatSync(join(repo, 'config')).isSymbolicLink());
  assert(!existsSync(join(repo, 'HEAD')));
}));
test('another HEAD is never overwritten, even when inserted immediately before publication', () => withTemp(async root => {
  const f = fixture(), repo = join(root, 'new');
  await assert.rejects(recoverGitBundle(f.input, repo, f.request, { onProgress({ phase }) {
    if (phase === 'before_publication') writeFileSync(join(repo, 'HEAD'), 'other writer');
  } }), error => error.state === 'publication_unknown' && error.code === 'EEXIST');
  assert.equal(readFileSync(join(repo, 'HEAD'), 'utf8'), 'other writer');
}));
test('concurrent default recoveries have one exclusive destination winner', () => withTemp(async root => {
  const f = fixture(), repo = join(root, 'new');
  const results = await Promise.allSettled([recoverGitBundle(f.input, repo, f.request), recoverGitBundle(f.input, repo, f.request)]);
  assert.equal(results.filter(result => result.status === 'fulfilled').length, 1);
  assert.equal(results.find(result => result.status === 'rejected').reason.code, 'EEXIST');
  assert.equal(git(root, ['--git-dir', repo, 'rev-parse', 'HEAD']).toString().trim(), f.tip);
}));
test('bad CLI expectations and omitted default branch refuse before opening input', () => withTemp(async root => {
  for (const extra of [[], ['--head', 'refs/tags/release'], ['--head', 'refs/heads/main', '--expect-sha256', 'bad'],
    ['--head', 'refs/heads/main', '--expect-format', 'sha1'], ['--head', 'refs/heads/main', '--unknown']]) {
    const child = spawnSync(process.execPath, [script, join(root, 'missing.bundle'), join(root, 'new'), ...extra], { encoding: 'utf8', timeout: 10000 });
    assert.equal(child.status, 1); assert.equal(child.stdout, ''); assert.notEqual(JSON.parse(child.stderr).code, 'ENOENT');
    assert(!existsSync(join(root, 'new')));
  }
  const help = spawnSync(process.execPath, [script, '--help'], { encoding: 'utf8', timeout: 10000 });
  assert.equal(help.status, 0); assert.match(help.stdout, /NEW_DIRECTORY/);
}));
