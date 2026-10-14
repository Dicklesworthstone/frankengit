// Real private-file/CLI/client composition with explicit native-schema peers.
// Peer Git use is test-only; no native authorization or CAS claim is made here.
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, writeFile, readFile, rm, lstat, chmod } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawn } from 'node:child_process';
import { Writable } from 'node:stream';
import { buildSourceChanges, canonical, sha256 } from '../operator/source_changes.mjs';
import { prepareSourceChanges, stageVerifiedSourceChanges } from '../operator/source_changes_prepare.mjs';
import { captureSourceEdit } from '../operator/source_edit_candidate.mjs';
import { saveSourceEdit, inspectSourceApply, dispatchSourceApply, recoverSourceApply } from '../operator/source_edit_publish.mjs';
import { nativePeer, TOKEN, ROTATED_TOKEN, PRINCIPAL } from './source_changes_native_fixture.mjs';
import { hexPath, intent } from './source_changes_fixture.mjs';
import { main } from '../fg_source_changes.mjs';
const CLI = new URL('../fg_source_changes.mjs', import.meta.url).pathname;
const absent = async path => assert.rejects(lstat(path), { code: 'ENOENT' });
async function setup(t, format = 'sha1') {
  const peer = await nativePeer(format), root = await mkdtemp(join(tmpdir(), 'fg-verified-stage-'));
  t.after(async () => { await peer.close(); await rm(root, { recursive: true, force: true }); });
  const changes = intent([{ operation: 'rename', from_path_hex: hexPath('src/main.rs'), path_hex: hexPath('lib/main.rs') },
    { operation: 'copy', from_path_hex: hexPath('run.sh'), path_hex: hexPath('bin/run.sh') }]);
  const f = peer.fixture, draft = await buildSourceChanges(f.bytes, f.expected, changes);
  const pin = sha256(canonical(draft.manifest)), selection = peer.selection(draft.manifest.effects.map(e => e.path_hex));
  const candidate = await prepareSourceChanges(f.bytes, f.expected, changes, selection, TOKEN, { confirmDraftSha256: pin });
  const path = join(root, 'candidate'), saved = await saveSourceEdit(path, candidate.capture, candidate.bundle);
  const consent = { confirmDraftSha256: pin, confirmCandidate: candidate.candidate_commit, principal: PRINCIPAL };
  const stage = (journal = join(root, 'journal'), opts = {}, select = selection) => stageVerifiedSourceChanges(journal,
    path, saved.manifest_sha256, f.bytes, f.expected, changes, select, { ...consent, ...opts });
  const paths = { package: join(root, 'package.json'), expect: join(root, 'expect.json'), changes: join(root, 'changes.json'), selection: join(root, 'selection.json') };
  for (const [key, bytes] of Object.entries({ package: f.bytes, expect: canonical(f.expected), changes: canonical(changes), selection: canonical(selection) })) {
    await writeFile(paths[key], bytes, { mode: 0o600 });
  }
  const args = (journal = join(root, 'journal')) => ['stage', '--package', paths.package, '--expect', paths.expect,
    '--changes', paths.changes, '--selection', paths.selection, '--candidate', path, '--sha256', saved.manifest_sha256,
    '--confirm-draft-sha256', pin, '--principal', PRINCIPAL, '--confirm-candidate', candidate.candidate_commit, '--journal', journal];
  return { peer, root, f, changes, draft, pin, selection, candidate, path, saved, consent, stage, args, paths };
}
function cli(args) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [CLI, ...args], { stdio: ['ignore', 'pipe', 'pipe'] });
    const stdout = [], stderr = []; let size = 0;
    const timer = setTimeout(() => { child.kill('SIGKILL'); reject(new Error('CLI did not settle')); }, 15000);
    for (const [stream, out] of [[child.stdout, stdout], [child.stderr, stderr]]) stream.on('data', data => {
      size += data.length; if (size > 131072) { child.kill('SIGKILL'); reject(new Error('CLI output overflow')); } else out.push(data);
    });
    child.once('error', error => { clearTimeout(timer); reject(error); });
    child.once('close', (code, signal) => { clearTimeout(timer); resolve({ code, signal,
      stdout: Buffer.concat(stdout).toString(), stderr: Buffer.concat(stderr).toString() }); });
  });
}
for (const format of ['sha1', 'sha256']) {
  test(`${format}: verified staging owns the exact selected candidate without network work`, async t => {
    const s = await setup(t, format), result = await s.stage();
    assert.equal(result.transmission_attempted, false); assert.equal(result.remote_mutation_attempted, false);
    assert.equal(result.principal_id, PRINCIPAL); assert.equal(result.candidate_commit, s.candidate.candidate_commit);
    assert.equal(result.binding.target_selection_matched, true);
    assert.equal(result.binding.independent_selection_sha256, sha256(canonical(s.selection)));
    assert.equal(result.binding.draft_sha256, s.pin); assert.equal(result.binding.expected_tree, s.draft.tree.afterTree);
    assert.equal(result.binding.candidate_manifest_sha256, s.saved.manifest_sha256);
    const state = await inspectSourceApply(result.journal, result.request_sha256);
    assert.equal(state.state, 'not_dispatched'); assert.equal(state.key, result.key);
    const request = JSON.parse(await readFile(join(result.journal, 'request.json')));
    assert.equal(request.candidate_manifest_sha256, s.saved.manifest_sha256);
    assert.equal(sha256(await readFile(join(result.journal, 'request.json'))), result.request_sha256);
    assert.equal(s.peer.requests.length, 2); assert.equal(s.peer.applies, 0);
    assert.deepEqual(s.peer.failures, []);
  });
  test(`${format}: relocated source publication recovers original key after lost reply and loss of external inputs`, async t => {
    const s = await setup(t, format), staged = await s.stage();
    await rm(s.path, { recursive: true }); await rm(s.paths.package);
    s.peer.lostApply = true;
    await assert.rejects(dispatchSourceApply(staged.journal, staged.request_sha256, TOKEN), error => {
      assert.equal(error.retained_request.key, staged.key); return true;
    });
    const recovered = await recoverSourceApply(staged.journal, staged.request_sha256, ROTATED_TOKEN);
    assert.equal(recovered.key, staged.key); assert.equal(recovered.decision.outcome, 'committed');
    assert.equal(recovered.decision.decision_sequence, '18446744073709551615');
    assert.equal(recovered.submission_retried, false); assert.equal(s.peer.applies, 1);
    const count = s.peer.requests.length;
    assert.deepEqual(await recoverSourceApply(staged.journal, staged.request_sha256, ROTATED_TOKEN), recovered);
    assert.deepEqual(await dispatchSourceApply(staged.journal, staged.request_sha256, TOKEN), recovered);
    assert.equal(s.peer.requests.length, count); assert.equal(s.peer.applies, 1); assert.deepEqual(s.peer.failures, []);
  });
  test(`${format}: endpoint, namespace, branch and metadata require an independent exact target match`, async t => {
    const s = await setup(t, format), mutations = [v => { v.endpoint = 'https://elsewhere.invalid/repo'; },
      ...['tenant_id', 'repository_id', 'repository_incarnation'].map(key => v => { v.scope[key] = '5'.repeat(32); }),
      v => { v.ref = 'refs/heads/other'; }, v => { v.metadata.author = 'Other <other@example.invalid>'; },
      v => { v.metadata.committer = 'Other <other@example.invalid>'; }, v => { v.metadata.timestamp++; },
      v => { v.metadata.message = 'another message'; }];
    for (let i = 0; i < mutations.length; i++) {
      const selection = structuredClone(s.selection); mutations[i](selection); const journal = join(s.root, `wrong-${i}`);
      await assert.rejects(s.stage(journal, {}, selection), /source_changes_target_selection/); await absent(journal);
    }
    assert.equal(s.peer.requests.length, 2);
    assert.ok((await s.stage()).key);
  });
  test(`${format}: draft, candidate and principal consent fail before a journal exists`, async t => {
    const s = await setup(t, format);
    for (const opts of [{ confirmDraftSha256: 'f'.repeat(64) }, { confirmCandidate: 'e'.repeat(format === 'sha1' ? 40 : 64) },
      { confirmCandidate: '0'.repeat(format === 'sha1' ? 40 : 64) }, { principal: 'not-a-principal' },
      { confirmDraftSha256: undefined }, { confirmCandidate: undefined }, { principal: undefined }]) {
      await assert.rejects(s.stage(undefined, opts)); await absent(join(s.root, 'journal'));
    }
    assert.ok((await s.stage(undefined, { confirmCandidate: `${format}:${s.candidate.candidate_commit}` })).request_sha256);
    assert.equal(s.peer.requests.length, 2);
  });
  test(`${format}: a self-consistent hidden-change candidate cannot be staged even with its exact hash and ID`, async t => {
    const s = await setup(t, format); s.peer.fault = 'unreported-addition';
    const bad = await captureSourceEdit(s.selection, s.draft.bytes, TOKEN), path = join(s.root, 'malicious');
    const saved = await saveSourceEdit(path, bad.capture, bad.bundle), journal = join(s.root, 'journal');
    await assert.rejects(stageVerifiedSourceChanges(journal, path, saved.manifest_sha256, s.f.bytes, s.f.expected,
      s.changes,
      s.selection, { ...s.consent, confirmCandidate: bad.candidate_commit }), /source_changes_candidate_tree/);
    await absent(journal); assert.equal(s.peer.applies, 0);
    assert.ok((await s.stage()).key); assert.deepEqual(s.peer.failures, []);
  });
  test(`${format}: command-line staging produces a usable private journal with no token input`, async t => {
    const s = await setup(t, format), reply = await cli([...s.args(), '--timeout-ms', '30000']);
    assert.equal(reply.code, 0, reply.stderr); assert.equal(reply.signal, null);
    const result = JSON.parse(reply.stdout); assert.equal(result.binding.target_selection_matched, true);
    assert.equal(result.candidate_commit, s.candidate.candidate_commit); assert.equal(result.stop_requested, false);
    assert.equal((await lstat(result.journal)).mode & 0o777, 0o700);
    assert.equal((await lstat(join(result.journal, 'request.json'))).mode & 0o777, 0o600);
    assert.equal((await inspectSourceApply(result.journal, result.request_sha256)).state, 'not_dispatched');
    assert.equal(s.peer.requests.length, 2); assert.equal(s.peer.applies, 0);
  });
}
test('staging snapshots mutable source, choices and target selection before asynchronous work', async t => {
  const s = await setup(t), bytes = Buffer.from(s.f.bytes), expected = structuredClone(s.f.expected), selection = structuredClone(s.selection);
  const changes = intent([{ operation: 'rename', from_path_hex: hexPath('src/main.rs'), path_hex: hexPath('lib/main.rs') },
    { operation: 'copy', from_path_hex: hexPath('run.sh'), path_hex: hexPath('bin/run.sh') }]);
  const consent = { ...s.consent }, pending = stageVerifiedSourceChanges(join(s.root, 'journal'), s.path,
    s.saved.manifest_sha256, bytes, expected, changes, selection, consent);
  bytes.fill(0); expected.files.length = 0; changes.changes.length = 0; selection.endpoint = 'https://elsewhere.invalid/repo';
  selection.metadata.message = 'substitution'; consent.principal = '5'.repeat(32); consent.confirmCandidate = 'e'.repeat(40);
  const result = await pending;
  assert.equal(result.principal_id, PRINCIPAL); assert.equal(result.binding.independent_selection_sha256, sha256(canonical(s.selection)));
});
test('cancelled or malformed staging cannot claim a journal or start a request', async t => {
  const s = await setup(t), controller = new AbortController(); controller.abort();
  await assert.rejects(s.stage(undefined, { signal: controller.signal })); await absent(join(s.root, 'journal'));
  const mid = new AbortController(), pending = s.stage(undefined, { signal: mid.signal }); queueMicrotask(() => mid.abort());
  await assert.rejects(pending); await absent(join(s.root, 'journal'));
  for (const opts of [{ timeoutMs: 0 }, { timeoutMs: 300001 }, { ca: Buffer.from('unused') }, { token: TOKEN }]) {
    await assert.rejects(s.stage(undefined, opts)); await absent(join(s.root, 'journal'));
  }
  assert.equal(s.peer.requests.length, 2); assert.ok((await s.stage()).key);
});
test('competing staging processes cannot replace the first publication owner', async t => {
  const s = await setup(t), results = await Promise.all([cli(s.args()), cli(s.args())]);
  assert.deepEqual(results.map(r => r.code).sort(), [0, 2]);
  const winner = JSON.parse(results.find(r => r.code === 0).stdout);
  const state = await inspectSourceApply(winner.journal, winner.request_sha256);
  assert.equal(state.key, winner.key); assert.equal(state.state, 'not_dispatched');
  const before = await readFile(join(winner.journal, 'request.json'));
  assert.equal((await cli(s.args())).code, 2); assert.deepEqual(await readFile(join(winner.journal, 'request.json')), before);
  assert.equal(s.peer.requests.length, 2); assert.equal(s.peer.applies, 0);
});
test('lost stage stdout retains the exact request hash rather than claiming no journal', async t => {
  const s = await setup(t), errors = [];
  const stdout = new Writable({ write(_chunk, _encoding, cb) { cb(new Error('output unavailable')); } });
  const stderr = new Writable({ write(chunk, _encoding, cb) { errors.push(Buffer.from(chunk)); cb(); } });
  const code = await main(s.args(), { stdout, stderr });
  assert.equal(code, 4);
  const reported = JSON.parse(Buffer.concat(errors)), retained = reported.retained_result;
  assert.equal(retained.transmission_attempted, false); assert.equal(retained.binding.target_selection_matched, true);
  assert.equal((await inspectSourceApply(retained.journal, retained.request_sha256)).key, retained.key);
  assert.equal(s.peer.requests.length, 2);
});
test('stage CLI rejects credential/network flags and missing confirmations before writes', async t => {
  const s = await setup(t);
  for (const extra of [['--token-file', s.paths.package], ['--ca-file', s.paths.package], ['--timeout-ms', '0']]) {
    const result = await cli([...s.args(), ...extra]); assert.equal(result.code, 2); await absent(join(s.root, 'journal'));
  }
  for (const flag of ['--principal', '--confirm-candidate', '--selection', '--confirm-draft-sha256']) {
    const args = s.args(), at = args.indexOf(flag); args.splice(at, 2);
    assert.equal((await cli(args)).code, 2); await absent(join(s.root, 'journal'));
  }
  assert.equal(s.peer.requests.length, 2);
});
test('public inputs and modified candidate bytes refuse instead of staging a successful prefix', async t => {
  const s = await setup(t); await chmod(s.paths.selection, 0o644);
  assert.equal((await cli(s.args())).code, 2); await absent(join(s.root, 'journal')); await chmod(s.paths.selection, 0o600);
  const bodyPath = join(s.path, 'candidate.bundle'), original = await readFile(bodyPath);
  await writeFile(bodyPath, Buffer.concat([original, Buffer.from('corrupt')]));
  await assert.rejects(s.stage()); await absent(join(s.root, 'journal'));
  await writeFile(bodyPath, original); assert.ok((await s.stage()).key);
  assert.equal(s.peer.requests.length, 2);
});
