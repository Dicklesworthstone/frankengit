// Executable CLI, private-file and HTTP/TLS composition. The network peers use
// native schemas and actual Git-built candidates, not the Rust fg authority.
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm, readFile, writeFile, lstat, chmod, symlink, unlink } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { spawn, execFileSync } from 'node:child_process';
import { Writable } from 'node:stream';
import { main } from '../fg_source_replay.mjs';
import { buildSourceChanges, canonical, sha256 } from '../operator/source_changes.mjs';
import { loadSourceReplay } from '../operator/source_replay_capture.mjs';
import { inspectSourceApply } from '../operator/source_edit_publish.mjs';
import { changeFixture, hexPath, intent } from './source_changes_fixture.mjs';
import { replayPair, selectSource } from './source_replay_fixture.mjs';
import { nativePeer, TOKEN, ROTATED_TOKEN, PRINCIPAL } from './source_changes_native_fixture.mjs';
const CLI = new URL('../fg_source_replay.mjs', import.meta.url).pathname;
const AUTHOR = new URL('../fg_source_changes.mjs', import.meta.url).pathname;
const PUBLISH = new URL('../fg_source_edit.mjs', import.meta.url).pathname;
const missing = path => assert.rejects(lstat(path), { code: 'ENOENT' });
function processRun(args, ready) {
  return new Promise((resolve, reject) => {
    const p = spawn(process.execPath, args, { stdio: ['ignore', 'pipe', 'pipe'] }), stdout = [], stderr = []; let size = 0, failed = false;
    const timer = setTimeout(() => { failed = true; p.kill('SIGKILL'); reject(new Error('CLI test timeout')); }, 20000);
    for (const [stream, out] of [[p.stdout, stdout], [p.stderr, stderr]]) stream.on('data', b => {
      size += b.length;
      if (size > 131072) { failed = true; p.kill('SIGKILL'); reject(new Error('CLI test output overflow')); } else out.push(b);
      if (stream === p.stdout) ready?.(p, Buffer.concat(stdout).toString());
    });
    p.once('error', e => { clearTimeout(timer); reject(e); });
    p.once('close', (code, signal) => { clearTimeout(timer); if (!failed) resolve({ code, signal, out: Buffer.concat(stdout).toString(), err: Buffer.concat(stderr).toString() }); });
  });
}
const cli = (script, args) => processRun([script, ...args]);
async function setup(t, format = 'sha1', network = false) {
  const pair = replayPair(format), peer = network ? await nativePeer(format, { files: pair.after, tls: format === 'sha256' }) : null;
  if (peer) { pair.next = selectSource(peer.fixture, pair.selected); t.after(() => peer.close()); }
  const changes = intent([{ operation: 'replace-once', path_hex: hexPath('src/file'), before_utf8: 'beta', after_utf8: 'reviewed' },
    { operation: 'copy', from_path_hex: hexPath('run.sh'), path_hex: hexPath('bin/run.sh') }]);
  const draft = await buildSourceChanges(pair.old.bytes, pair.old.expected, changes), pin = sha256(canonical(draft.manifest));
  const root = await mkdtemp(join(tmpdir(), 'fg-source-replay-cli-')), output = join(root, 'capture');
  t.after(() => rm(root, { recursive: true, force: true }));
  const bodies = { old: pair.old.bytes, oldExpect: canonical(pair.old.expected), next: pair.next.bytes, nextExpect: canonical(pair.next.expected), changes: canonical(changes) };
  const paths = {};
  for (const [name, bytes] of Object.entries(bodies)) { paths[name] = join(root, `${name}.json`); await writeFile(paths[name], bytes, { mode: 0o600 }); }
  const args = ['capture', '--package', paths.old, '--expect', paths.oldExpect, '--changes', paths.changes,
    '--confirm-draft-sha256', pin, '--next-package', paths.next, '--next-expect', paths.nextExpect, '--output', output];
  return { ...pair, peer, changes, pin, root, output, paths, args };
}
for (const format of ['sha1', 'sha256']) {
  test(`${format}: CLI capture and fresh-process inspect survive loss of all original input files`, async t => {
    const s = await setup(t, format), captured = await cli(CLI, s.args); assert.equal(captured.code, 0, captured.err);
    const r = JSON.parse(captured.out); assert.notEqual(r.draft_sha256, s.pin); assert.equal(r.new_review_required, true);
    for (const path of Object.values(s.paths)) await unlink(path);
    const reopened = await cli(CLI, ['inspect', '--capture', s.output, '--sha256', r.capture_sha256]); assert.equal(reopened.code, 0, reopened.err);
    assert.equal(JSON.parse(reopened.out).capture_sha256, r.capture_sha256);
    const draft = await cli(AUTHOR, ['draft', '--package', join(s.output, 'source.json'), '--expect', join(s.output, 'expected.json'),
      '--changes', join(s.output, 'changes.json'), '--output', join(s.root, 'standard-draft')]);
    assert.equal(draft.code, 0, draft.err); assert.equal(JSON.parse(draft.out).manifest_sha256, r.draft_sha256);
    assert.deepEqual(await readFile(join(s.output, 'patch.diff')), await readFile(join(s.root, 'standard-draft', 'patch.diff')));
  });
  test(`${format}: new-base replay requires new consent through actual prepare/stage and original-key recovery`, async t => {
    const s = await setup(t, format, true), captured = await cli(CLI, s.args); assert.equal(captured.code, 0, captured.err);
    const r = JSON.parse(captured.out), draft = JSON.parse(await readFile(join(s.output, 'draft.json')));
    const selection = join(s.root, 'selection.json'), token = join(s.root, 'token'), ca = join(s.root, 'ca');
    await writeFile(selection, canonical(s.peer.selection(draft.effects.map(e => e.path_hex))), { mode: 0o600 });
    await writeFile(token, TOKEN, { mode: 0o600 }); if (s.peer.ca) await writeFile(ca, s.peer.ca, { mode: 0o600 });
    const tls = s.peer.ca ? ['--ca-file', ca] : [], common = ['--package', join(s.output, 'source.json'), '--expect', join(s.output, 'expected.json'), '--changes', join(s.output, 'changes.json')];
    const candidate = join(s.root, 'candidate');
    const prepare = pin => ['prepare', ...common, '--selection', selection, '--token-file', token, '--confirm-draft-sha256', pin, '--output', candidate, ...tls];
    const refused = await cli(AUTHOR, prepare(s.pin)); assert.equal(refused.code, 2, refused.err); assert.equal(s.peer.requests.length, 0); await missing(candidate);
    const prepared = await cli(AUTHOR, prepare(r.draft_sha256)); assert.equal(prepared.code, 0, prepared.err); const p = JSON.parse(prepared.out);
    assert.equal(p.binding.expected_tree, r.expected_tree);
    const after = s.after.map(row => row.path === 'src/file' ? { ...row, bytes: 'alpha\nreviewed\n' } : row);
    after.push({ path: 'bin/run.sh', bytes: '#!/bin/sh\necho old\n', mode: 0o100755 });
    assert.equal(r.expected_tree, changeFixture(format, after).tree);
    const journal = join(s.root, 'journal');
    const stage = pin => ['stage', ...common, '--selection', selection, '--candidate', candidate, '--sha256', p.manifest_sha256,
      '--confirm-draft-sha256', pin, '--principal', PRINCIPAL, '--confirm-candidate', p.candidate_commit, '--journal', journal];
    assert.equal((await cli(AUTHOR, stage(s.pin))).code, 2); await missing(journal);
    const staged = await cli(AUTHOR, stage(r.draft_sha256)); assert.equal(staged.code, 0, staged.err); const j = JSON.parse(staged.out);
    assert.equal((await inspectSourceApply(journal, j.request_sha256)).state, 'not_dispatched'); assert.equal(s.peer.applies, 0);
    for (const path of Object.values(s.paths)) await unlink(path);
    await rm(s.output, { recursive: true }); await rm(candidate, { recursive: true });
    s.peer.lostApply = true;
    const apply = await cli(PUBLISH, ['apply', '--journal', journal, '--request-sha256', j.request_sha256, '--token-file', token, ...tls]);
    assert.notEqual(apply.code, 0); assert.equal(s.peer.applies, 1, apply.err);
    await writeFile(token, ROTATED_TOKEN);
    const recovered = await cli(PUBLISH, ['recover', '--journal', journal, '--request-sha256', j.request_sha256, '--token-file', token, ...tls]);
    assert.equal(recovered.code, 0, recovered.err); const terminal = JSON.parse(recovered.out);
    assert.equal(terminal.key, j.key); assert.equal(terminal.decision.decision_sequence, '18446744073709551615');
    assert.equal(terminal.decision.outcome, 'committed'); assert.equal(terminal.submission_retried, false); assert.equal(s.peer.applies, 1);
    assert.deepEqual(s.peer.failures, []);
  });
  test(`${format}: hidden candidate changes remain refused after an otherwise valid replay`, async t => {
    const s = await setup(t, format, true), captured = await cli(CLI, s.args); assert.equal(captured.code, 0, captured.err);
    const r = JSON.parse(captured.out), draft = JSON.parse(await readFile(join(s.output, 'draft.json')));
    const selection = join(s.root, 'selection'), token = join(s.root, 'token'), ca = join(s.root, 'ca');
    await writeFile(selection, canonical(s.peer.selection(draft.effects.map(e => e.path_hex))), { mode: 0o600 });
    await writeFile(token, TOKEN, { mode: 0o600 }); if (s.peer.ca) await writeFile(ca, s.peer.ca, { mode: 0o600 });
    const candidate = join(s.root, 'candidate'), args = ['prepare', '--package', join(s.output, 'source.json'), '--expect', join(s.output, 'expected.json'),
      '--changes', join(s.output, 'changes.json'), '--selection', selection, '--token-file', token, '--confirm-draft-sha256', r.draft_sha256, '--output', candidate,
      ...(s.peer.ca ? ['--ca-file', ca] : [])];
    s.peer.fault = 'unreported-addition'; const rejected = await cli(AUTHOR, args); assert.equal(rejected.code, 2, rejected.err); await missing(candidate);
    assert.match(rejected.err, /source_changes_candidate_tree/); assert.equal(s.peer.applies, 0);
    s.peer.fault = null; assert.equal((await cli(AUTHOR, args)).code, 0); assert.deepEqual(s.peer.failures, []);
  });
}
test('CLI has no token, target, journal, overwrite or retry options', async () => {
  assert.equal((await cli(CLI, ['--help'])).code, 0);
  for (const args of [[], ['apply'], ['capture', '--token-file', '/secret'], ['inspect', '--journal', '/existing'],
    ['inspect', '--capture', '/x', '--sha256', 'f'.repeat(64), '--force', 'true'],
    ['inspect', '--capture', '/x', '--sha256', 'f'.repeat(64), '--timeout-ms', '300001']]) assert.equal((await cli(CLI, args)).code, 2);
});
test('CLI inputs reject public files, symlinks and FIFOs without blocking', async t => {
  const s = await setup(t); await chmod(s.paths.nextExpect, 0o644);
  assert.equal((await cli(CLI, s.args)).code, 2); await missing(s.output); await chmod(s.paths.nextExpect, 0o600);
  const original = await readFile(s.paths.next); await unlink(s.paths.next); await symlink(s.paths.old, s.paths.next);
  assert.equal((await cli(CLI, s.args)).code, 2); await unlink(s.paths.next);
  execFileSync('mkfifo', [s.paths.next]); assert.equal((await cli(CLI, s.args)).code, 2); await unlink(s.paths.next);
  await writeFile(s.paths.next, original, { mode: 0o600 }); assert.equal((await cli(CLI, s.args)).code, 0);
});
test('original pin and explicit second-base conflicts fail without output or disclosed file contents', async t => {
  const s = await setup(t), wrong = s.args.map(v => v === s.pin ? 'f'.repeat(64) : v);
  const rejected = await cli(CLI, wrong); assert.equal(rejected.code, 2); await missing(s.output);
  assert.match(rejected.err, /source_replay_confirmation/); assert.ok(!rejected.err.includes('beta'));
  const changed = selectSource(changeFixture('sha1', s.after.map(row => row.path === 'run.sh' ? { ...row, mode: 0o100644 } : row)), s.selected);
  await writeFile(s.paths.next, changed.bytes); await writeFile(s.paths.nextExpect, canonical(changed.expected));
  const conflict = await cli(CLI, s.args); assert.equal(conflict.code, 2); await missing(s.output);
  assert.match(conflict.err, /source_replay_read_set_changed/);
});
test('lost stdout retains a complete replay identity that can be independently reopened', async t => {
  const s = await setup(t), diagnostics = [];
  const stdout = new Writable({ write(_b, _e, cb) { cb(new Error('broken pipe')); } });
  const stderr = new Writable({ write(b, _e, cb) { diagnostics.push(b); cb(); } });
  assert.equal(await main(s.args, { stdout, stderr }), 4);
  const r = JSON.parse(Buffer.concat(diagnostics)); assert.ok(r.retained_result.capture_sha256);
  await loadSourceReplay(s.output, r.retained_result.capture_sha256);
});
test('SIGTERM cancels blocked receipt output without discarding its already complete capture', async t => {
  const s = await setup(t), diagnostics = [];
  const stdout = new Writable({ write() { process.emit('SIGTERM'); } });
  const stderr = new Writable({ write(b, _e, cb) { diagnostics.push(b); cb(); } });
  assert.equal(await main(s.args, { stdout, stderr }), 4);
  const r = JSON.parse(Buffer.concat(diagnostics)); await loadSourceReplay(s.output, r.retained_result.capture_sha256);
});
test('a real SIGTERM at an in-flight digest exits before claiming an output slot', async t => {
  const s = await setup(t), script = `
    import { webcrypto } from 'node:crypto';
    import { main } from ${JSON.stringify(new URL('../fg_source_replay.mjs', import.meta.url).href)};
    const digest = webcrypto.subtle.digest.bind(webcrypto.subtle); let first = true;
    webcrypto.subtle.digest = async (...args) => {
      if (first) { first = false; await new Promise(resolve => {
        const timer = setTimeout(resolve, 5000);
        process.once('SIGTERM', () => { clearTimeout(timer); resolve(); }); process.stdout.write('digest-ready\\n');
      }); }
      return digest(...args);
    };
    process.exitCode = await main(${JSON.stringify(s.args)});`;
  let sent = false;
  const result = await processRun(['--input-type=module', '-e', script], (child, output) => {
    if (!sent && output.includes('digest-ready')) { sent = true; child.kill('SIGTERM'); }
  });
  assert.equal(sent, true); assert.equal(result.code, 3, result.err); assert.equal(result.signal, null); await missing(s.output);
});
test('competing CLI creators cannot overwrite or replace the confirmed capture', async t => {
  const s = await setup(t), results = await Promise.all([cli(CLI, s.args), cli(CLI, s.args)]);
  assert.equal(results.filter(r => r.code === 0).length, 1); assert.equal(results.filter(r => r.code === 2).length, 1);
  const r = JSON.parse(results.find(r => r.code === 0).out); await loadSourceReplay(s.output, r.capture_sha256);
});
