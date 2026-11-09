// Real private-file/operator/HTTP composition with native-schema Git-oracle
// peers. Canonical grant enforcement is tested separately by the Rust server.
import test from 'node:test';
import assert from 'node:assert/strict';
import { Writable } from 'node:stream';
import { mkdtemp, readFile, writeFile, rm, lstat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { main as editMain } from '../fg_source_edit.mjs';
import { main as changesMain } from '../fg_source_changes.mjs';
import { buildSourceChanges, canonical, sha256 } from '../operator/source_changes.mjs';
import { prepareSourceChanges } from '../operator/source_changes_prepare.mjs';
import { saveSourceEdit, stageSourceApply, dispatchSourceApply, inspectSourceApply } from '../operator/source_edit_publish.mjs';
import { exchange, clock } from '../operator/source_edit_wire.mjs';
import { nativePeer, TOKEN, PRINCIPAL } from './source_changes_native_fixture.mjs';
import { intent, replace } from './source_changes_fixture.mjs';

const AGENT = `fgagent_${'c'.repeat(64)}`;
const denied = error => error.code === 'source_edit_credential';
function collector() {
  const chunks = [];
  return { stream: new Writable({ write(chunk, _encoding, done) { chunks.push(Buffer.from(chunk)); done(); } }),
    text: () => Buffer.concat(chunks).toString() };
}
async function invoke(main, args) {
  const stdout = collector(), stderr = collector();
  const code = await main(args, { stdout: stdout.stream, stderr: stderr.stream });
  assert.equal(stdout.text().includes(AGENT), false);
  assert.equal(stderr.text().includes(AGENT), false);
  return { code, stdout: stdout.text(), stderr: stderr.text() };
}
async function setup(t, format = 'sha256') {
  const peer = await nativePeer(format, { candidateToken: AGENT, nativePatchBundle: true });
  const root = await mkdtemp(join(tmpdir(), 'fg-sponsored-source-candidate-'));
  t.after(async () => { await peer.close(); await rm(root, { recursive: true, force: true }); });
  const changes = intent([replace('src/main.rs', 'fn main() { sponsored_candidate(); }\n')]);
  const f = peer.fixture, draft = await buildSourceChanges(f.bytes, f.expected, changes);
  const pin = sha256(canonical(draft.manifest)), selection = peer.selection(draft.manifest.effects.map(e => e.path_hex));
  const files = {};
  for (const [name, bytes] of Object.entries({ package: f.bytes, expect: canonical(f.expected), changes: canonical(changes),
    selection: canonical(selection), patch: draft.bytes, token: Buffer.from(AGENT) })) {
    files[name] = join(root, name); await writeFile(files[name], bytes, { mode: 0o600 });
  }
  const prepare = () => prepareSourceChanges(f.bytes, f.expected, changes, selection, AGENT, { confirmDraftSha256: pin });
  const edits = op => [op, '--selection', files.selection, '--patch-file', files.patch, '--token-file', files.token,
    '--output', join(root, op), ...(op === 'prepare-verified' ? ['--package', files.package, '--expect', files.expect] : [])];
  const authored = op => [op, '--package', files.package, '--expect', files.expect, '--changes', files.changes,
    '--selection', files.selection, '--token-file', files.token, '--confirm-draft-sha256', pin, '--output', join(root, `authored-${op}`)];
  return { peer, root, files, prepare, edits, authored };
}

for (const format of ['sha1', 'sha256']) {
  test(`${format}: sponsored preparation preserves exact tokens and hands off a grant-free candidate`, async t => {
    const s = await setup(t, format), candidate = await s.prepare();
    assert.equal(candidate.binding.publication_authorized, false);
    assert.equal(candidate.publication_authorized, false);
    assert.deepEqual(s.peer.requests.map(r => r.route), ['source/prepare', 'source/inspect']);
    for (const request of s.peer.requests) {
      assert.equal(request.headers.authorization, `Bearer ${AGENT}`);
      assert.equal(request.headers['idempotency-key'], undefined);
    }
    const path = join(s.root, 'candidate'), journal = join(s.root, 'journal');
    const saved = await saveSourceEdit(path, candidate.capture, candidate.bundle);
    for (const name of ['manifest.json', 'capture.json', 'candidate.bundle']) {
      assert.equal((await readFile(join(path, name))).includes(Buffer.from(AGENT)), false);
    }
    const staged = await stageSourceApply(journal, path, saved.manifest_sha256, PRINCIPAL);
    await assert.rejects(dispatchSourceApply(journal, staged.request_sha256, AGENT), denied);
    await assert.rejects(lstat(join(journal, 'dispatch')), { code: 'ENOENT' });
    assert.equal((await inspectSourceApply(journal, staged.request_sha256)).state, 'not_dispatched');
    assert.equal(s.peer.requests.length, 2);
    // The saved artifact remains publishable by a separately authorized
    // ordinary credential; it does not persist or promote the agent bearer.
    const applied = await dispatchSourceApply(journal, staged.request_sha256, TOKEN);
    assert.equal(applied.decision.outcome, 'committed');
    assert.equal(s.peer.applies, 1);
    assert.equal(s.peer.requests.at(-1).headers.authorization, `Bearer ${TOKEN}`);
    assert.deepEqual(s.peer.failures, []);
  });
}

test('source transport rejects sponsored publication, recovery and route substitutions before networking', async t => {
  const s = await setup(t);
  for (const operation of ['apply', 'outcomes', 'initial/prepare', 'rebase/prepare', 'rebase/inspect', 'bundle/import', 'prepare/extra', 'inspect?force=true']) {
    await assert.rejects(exchange(s.peer.endpoint, AGENT, operation,
      operation === 'outcomes' ? null : { bytes: Buffer.from('unsubmitted'), contentType: 'application/octet-stream' },
      clock(), 65536, ['apply', 'outcomes'].includes(operation) ? 'original-key' : null), denied);
  }
  for (const token of [`${AGENT}x`, AGENT.toUpperCase(), `fgagent_${'c'.repeat(63)}`, `${AGENT}\n`, `${AGENT}\0`]) {
    await assert.rejects(exchange(s.peer.endpoint, token, 'prepare', { bytes: Buffer.from('unsubmitted') }, clock(), 65536), denied);
  }
  assert.equal(s.peer.requests.length, 0);
});

test('both shipped authoring CLIs read complete private sponsored tokens and only prepare/inspect', async t => {
  const s = await setup(t);
  // Verified preparation needs actual before/after review bytes. Read them
  // from the fixture's Git objects instead of relaxing its preimage check.
  s.peer.onRequest = route => {
    if (route !== 'source/inspect') return;
    for (const row of s.peer.candidate.inspection.comparison.entries) {
      const before = s.peer.objectBody(row.before.oid), after = s.peer.objectBody(row.after.oid);
      const span = bytes => ({ byte_start: 0, byte_end: bytes.length, line_start: 0,
        line_count: [...bytes].filter(byte => byte === 10).length });
      row.content = { type: 'text', algorithm: 'test-git-whole-file', additions: 1, deletions: 1,
        before_bytes: before.length, after_bytes: after.length, hunks: [
          { old: span(before), new: span(after), before_hex: before.toString('hex'), after_hex: after.toString('hex') },
        ] };
    }
  };
  for (const [main, args, ending] of [
    [editMain, s.edits('prepare'), '\r\n'],
    [editMain, s.edits('prepare-verified'), ''],
    [changesMain, s.authored('prepare'), '\n'],
    [changesMain, s.authored('prepare-packed'), '\r\n'],
  ]) {
    await writeFile(s.files.token, `${AGENT}${ending}`);
    const before = s.peer.requests.length, result = await invoke(main, args);
    assert.equal(result.code, 0, result.stderr);
    const receipt = JSON.parse(result.stdout);
    assert.ok(receipt.candidate_commit);
    assert.deepEqual(s.peer.requests.slice(before).map(r => r.route), ['source/prepare', 'source/inspect']);
    for (const request of s.peer.requests.slice(before)) assert.equal(request.headers.authorization, `Bearer ${AGENT}`);
    assert.equal((await readFile(join(receipt.directory, 'capture.json'))).includes(Buffer.from(AGENT)), false);
  }
  assert.equal(s.peer.applies, 0);
  assert.deepEqual(s.peer.failures, []);
});

test('source publication CLI rejects sponsored apply and recovery before touching a journal', async t => {
  const s = await setup(t);
  for (const op of ['apply', 'recover']) {
    const journal = join(s.root, `absent-${op}`);
    const result = await invoke(editMain, [op, '--journal', journal, '--request-sha256', 'd'.repeat(64), '--token-file', s.files.token]);
    assert.equal(result.code, 2);
    assert.equal(JSON.parse(result.stderr).code, 'source_edit_credential');
    await assert.rejects(lstat(journal), { code: 'ENOENT' });
  }
  assert.equal(s.peer.requests.length, 0);
});

test('private sponsored token readers reject malformed endings without persisting or sending secrets', async t => {
  const s = await setup(t);
  for (const bad of [`${AGENT}\n\n`, `${AGENT} `, `${AGENT}\0`, AGENT.toUpperCase(), `fgagent_${'c'.repeat(63)}`]) {
    await writeFile(s.files.token, bad);
    for (const [main, args] of [[editMain, s.edits('prepare')], [changesMain, s.authored('prepare')]]) {
      const result = await invoke(main, args);
      assert.equal(result.code, 2);
      assert.equal(result.stdout, '');
      assert.equal(result.stderr.includes(bad), false);
    }
  }
  assert.equal(s.peer.requests.length, 0);
  await assert.rejects(lstat(join(s.root, 'prepare')), { code: 'ENOENT' });
  await assert.rejects(lstat(join(s.root, 'authored-prepare')), { code: 'ENOENT' });
});
