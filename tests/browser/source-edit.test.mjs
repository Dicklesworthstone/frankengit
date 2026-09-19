import test from 'node:test';
import assert from 'node:assert/strict';
import { SourceEditClient } from '../../crates/fgit-node/src/smart_http/server/browser/source-edit.mjs';
import { Transport, hex, utf8 } from '../../crates/fgit-node/src/smart_http/server/browser/pulls-core.mjs';
import { fullFilePatch, normalizeEdits, sourcePath, PATCH_LIMIT, FILE_LIMIT } from '../../crates/fgit-node/src/smart_http/server/browser/source-edit-patch.mjs';
import { sourceEnvelope, prepared, inspected, digest, sourceUpload, coordinates, commitMetadata } from '../../crates/fgit-node/src/smart_http/server/browser/source-edit-protocol.mjs';
import { fixture, token, crypto, href, edit, metadata, multipart, decodeUpload } from './source-edit-fixtures.mjs';
async function connected(f) { const c = new SourceEditClient({ href, fetchImpl: f.fetchImpl, cryptoImpl: crypto }); await c.connect(token); return c; }
async function candidate(f) { const c = await connected(f); await c.select('refs/heads/main', f.algorithm); await c.prepareEdits(f.edits, metadata); return c; }
for (const algorithm of ['sha1', 'sha256']) {
  test(`${algorithm}: complete branch/file/edit/inspect/apply workflow`, async () => {
    const f = await fixture(algorithm), c = await connected(f);
    const selected = await c.select('refs/heads/main', algorithm); assert.equal(selected.fields.expected_commit, f.base);
    const file = await c.loadFile(f.edits[0].path_hex); assert.deepEqual(file.before.bytes, f.edits[0].before.bytes);
    const ready = await c.prepareEdits(f.edits, metadata); assert.equal(ready.fields.candidate_commit, f.candidate);
    assert.deepEqual(f.calls.map(c => c.endpoint), ['source/tree', 'source/blob', 'source/prepare', 'source/inspect']);
    const body = decodeUpload(f.calls[2].options); assert.deepEqual(body.payload, f.patch.bytes);
    assert.deepEqual([...body.command.keys()].sort(), ['author','committer','expected_commit','message','object_format','ref','timestamp'].sort());
    const p = await c.stageApply(); assert.equal(p.sent, false); assert.equal(f.calls.length, 4);
    const terminal = await c.send(); assert.equal(terminal.outcome, 'committed'); assert.equal(c.pending, null); assert.equal(c.selection, null);
    assert.equal(f.calls.at(-1).headers['idempotency-key'], p.key);
  });
  test(`${algorithm}: lost response and receipt restoration resend exact original bytes`, async () => {
    const f = await fixture(algorithm), c = await candidate(f); await c.stageApply(); f.config.loseApply = true;
    await assert.rejects(c.send(), e => e.outcomeUnknown === true); const original = f.calls.at(-1);
    const receipt = c.exportReceipt(); assert(!receipt.includes(token)); c.disconnect(); assert(c.pending);
    const next = await connected(f); await next.restoreReceipt(receipt); f.config.loseApply = false;
    await next.send(); const retried = f.calls.at(-1);
    assert.deepEqual(retried.body, original.body); assert.equal(retried.headers['idempotency-key'], original.headers['idempotency-key']);
    assert.equal(retried.headers['content-type'], original.headers['content-type']);
  });
  test(`${algorithm}: unchanged retry after canonical refusal is terminal, not an HTTP error`, async () => {
    const f = await fixture(algorithm), c = await candidate(f); await c.stageApply(); f.config.refuseApply = true;
    const result = await c.send(); assert.equal(result.outcome, 'refused'); assert.equal(result.refusal, 'TargetRefMoved'); assert.equal(c.pending, null);
  });
  test(`${algorithm}: raw Git patch preparation still requires native inspection`, async () => {
    const f = await fixture(algorithm), c = await connected(f); await c.select('refs/heads/main', algorithm);
    await c.preparePatch(f.patch.bytes, metadata); assert.equal(c.candidate.fields.candidate_commit, f.candidate);
    assert.deepEqual(f.calls.slice(-2).map(c => c.endpoint), ['source/prepare', 'source/inspect']);
  });
}
for (const [name, change] of [
  ['parent', r => r.parents.push(r.parents[0])], ['candidate hash', r => r.candidate_commit_body_hex += '00'],
  ['tree', r => r.comparison.after_tree = 'd'.repeat(r.object_format === 'sha1' ? 40 : 64)],
  ['scope', r => r.repository_incarnation = '6'.repeat(32)], ['ref', r => r.ref = 'refs/heads/other'],
  ['bundle', r => r.bundle_sha256 = '6'.repeat(64)], ['effect', r => r.comparison.entries[0].after.mode = 0o100644],
  ['extra path', r => r.comparison.entries.push(r.comparison.entries[0])], ['authority', r => r.publication_authorized = true],
  ['incomplete diff', r => r.all_changed_paths = false], ['unknown content', r => r.comparison.entries[0].content.type = 'not-a-diff'],
]) test(`inspection refuses changed ${name} before any publication can be staged`, async () => {
  const f = await fixture(), c = await connected(f); await c.select('refs/heads/main', 'sha1'); f.config.inspect = change;
  await assert.rejects(c.prepareEdits(f.edits, metadata)); assert.equal(c.candidate, null); await assert.rejects(c.stageApply());
  assert(!f.calls.some(c => c.endpoint === 'source/apply'));
});
for (const [name, change] of [
  ['wrong patch', r => r.patch_sha256 = '0'.repeat(64)], ['missing effect', r => r.paths = []],
  ['duplicate path', r => r.paths.push(r.paths[0])], ['changed blob', r => r.paths[0].new_blob = 'e'.repeat(40)],
  ['changed mode', r => r.paths[0].new_mode = 0o100644], ['published', r => r.published = true],
]) test(`preparation rejects ${name} and never proceeds to inspection`, async () => {
  const f = await fixture(), c = await connected(f); await c.select('refs/heads/main', 'sha1'); f.config.prepare = change;
  await assert.rejects(c.prepareEdits(f.edits, metadata)); assert.equal(c.candidate, null);
  assert(!f.calls.some(c => c.endpoint === 'source/inspect'));
});
for (const [name, change] of [
  ['partial file', r => r.next_offset = 1], ['oversized file', r => r.total_bytes = FILE_LIMIT + 1],
  ['symlink', r => r.kind = 'symlink'], ['wrong bytes', r => r.content_hex = '61'],
  ['wrong snapshot', r => r.snapshot_token = `alg:1:${'5'.repeat(64)}`],
  ['wrong commit', r => r.source_commit = 'd'.repeat(40)], ['wrong path', r => r.path_hex = '61'],
]) test(`file loading refuses ${name}; no prefix or foreign bytes enter the editor`, async () => {
  const f = await fixture(), c = await connected(f); await c.select('refs/heads/main', 'sha1'); f.config.read = change;
  await assert.rejects(c.loadFile(f.edits[0].path_hex)); assert.equal(c.candidate, null);
});
test('read-only recovery preserves unknown states and never resubmits a mutation', async () => {
  const f = await fixture(), c = await candidate(f); await c.stageApply();
  for (const state of ['key_not_observed', 'seal_not_observed', 'undecided']) {
    f.config.outcome = state; const result = await c.recover(); assert.equal(result.terminal, false); assert(c.pending);
    assert.equal(f.calls.at(-1).endpoint, 'outcomes'); assert.equal(f.calls.at(-1).body, undefined);
  }
  f.config.outcome = 'committed'; const result = await c.recover(); assert.equal(result.outcome, 'committed'); assert.equal(c.pending, null);
  assert(!f.calls.some(c => c.endpoint === 'source/apply'));
});
test('unsent requests are locally discardable but exported or sent requests are not', async () => {
  const f = await fixture(), c = await candidate(f); await c.stageApply(); c.discardUnsent(); assert.equal(c.pending, null);
  await c.stageApply(); c.exportReceipt(); assert.throws(() => c.discardUnsent()); await assert.rejects(c.select('refs/heads/other', 'sha1'));
});
test('all public candidate and pending views are detached from the frozen publication', async () => {
  const f = await fixture(), c = await candidate(f); c.candidate.fields.candidate_commit = 'd'.repeat(40);
  await c.stageApply(); const p = c.pending; p.fields.ref = 'refs/heads/other'; p.key = 'changed';
  await c.send(); const command = decodeUpload(f.calls.at(-1).options).command;
  assert.equal(command.get('ref'), 'refs/heads/main'); assert.equal(command.get('candidate_commit'), f.candidate);
});
test('invalid preparation clears a previously inspected candidate', async () => {
  const f = await fixture(), c = await candidate(f); await assert.rejects(c.prepareEdits([], metadata)); assert.equal(c.candidate, null);
});
test('editor invalidation during inspection cannot restore an obsolete candidate', async () => {
  const f = await fixture(), c = await connected(f); await c.select('refs/heads/main', 'sha1');
  let release; f.config.inspect = () => new Promise(resolve => { release = resolve; });
  const promise = c.prepareEdits(f.edits, metadata); while (!release) await new Promise(resolve => setImmediate(resolve));
  c.invalidateCandidate(); release(); await assert.rejects(promise); assert.equal(c.candidate, null);
});
test('disconnect clears source data but retains a possibly published request', async () => {
  const f = await fixture(), c = await candidate(f); await c.stageApply(); f.config.loseApply = true; await assert.rejects(c.send());
  c.disconnect(); assert.equal(c.connected, false); assert.equal(c.selection, null); assert.equal(c.candidate, null); assert(c.pending);
  await assert.rejects(c.connect('8'.repeat(64))); await c.connect(token); assert(c.pending);
});
for (const [name, change] of [
  ['branch', r => r.fields.ref = 'refs/heads/other'], ['parent', r => r.fields.expected_commit = 'd'.repeat(40)],
  ['candidate', r => r.fields.candidate_commit = 'e'.repeat(40)], ['bundle', r => r.bundle_base64 = Buffer.from('altered').toString('base64')],
  ['route', r => r.route = '/other.git'], ['origin', r => r.origin = 'https://example.invalid'],
  ['scope', r => r.scope.repository = '9'.repeat(32)], ['nonce', r => r.nonce = '0'.repeat(32)],
  ['injected authority', r => r.force = true],
]) test(`restored receipts cannot change ${name} under the original key`, async () => {
  const f = await fixture(), c = await candidate(f); await c.stageApply(); const saved = JSON.parse(c.exportReceipt()); change(saved);
  const restored = await connected(f); await assert.rejects(restored.restoreReceipt(JSON.stringify(saved))); assert.equal(restored.pending, null);
});
test('source transport cannot call PR endpoints and PR transport cannot call source endpoints', async () => {
  const f = await fixture();
  for (const [suffix, path] of [['/ui/source/', 'pulls/1/merge'], ['/ui/pulls/', 'source/apply']]) {
    const transport = new Transport({ href: href.replace('/ui/source/', suffix), pageSuffix: suffix, fetchImpl: f.fetchImpl, cryptoImpl: crypto });
    await transport.connect(token); await assert.rejects(transport.request(path, { method: 'POST' }));
  }
  assert.equal(f.calls.length, 0);
});
test('native source commands have no implicit principal, refresh, force, or timestamps', () => {
  const fields = { ref: 'refs/heads/main', object_format: 'sha1', expected_commit: 'a'.repeat(40) };
  assert.throws(() => coordinates({ ...fields, force: true })); assert.throws(() => coordinates({ ...fields, ref: 'refs/tags/v1' }));
  assert.throws(() => commitMetadata({ ...metadata, timestamp: undefined })); assert.throws(() => commitMetadata({ ...metadata, principal: 'admin' }));
});
test('patch builder preserves CRLF, missing newline, executable mode, raw paths, and sorted multi-file changes', () => {
  const a = edit(); a.path_hex = '61200aff'; const b = { path_hex: '7a', before: null, after: { mode: 0o100644, bytes: utf8.encode('new\n') } };
  const first = fullFilePatch([b, a]), second = fullFilePatch([a, b]); assert.deepEqual(first.bytes, second.bytes);
  const text = Buffer.from(first.bytes).toString(); assert(text.includes('"a/a \\012\\377"'));
  assert(text.includes('-before\r\n+after\n\\ No newline at end of file\n')); assert(text.includes('new mode 100755'));
});
for (const path of ['', '2f61', '612f', '2e', '2e2e', '612f2e2e2f62', '2e6769742f61', '2e476954', '610062'])
  test(`unsafe byte path ${path || '(empty)'} refuses before patch generation`, () => assert.throws(() => sourcePath(path)));
test('duplicate and nonadjacent ancestor overlaps fail closed', () => {
  const row = path_hex => ({ path_hex, before: null, after: { bytes: utf8.encode('new'), mode: 0o100644 } });
  assert.throws(() => normalizeEdits([row('61'), row('61')])); assert.throws(() => normalizeEdits([row('61'), row('612d'), row('612f62')]));
});
test('patch/file/count/line/mode budgets refuse without allocating an oversized patch', () => {
  const a = edit(); a.after.bytes = new Uint8Array(FILE_LIMIT + 1).fill(65); assert.throws(() => fullFilePatch([a]));
  a.after.bytes = new Uint8Array(65537).fill(10); assert.throws(() => fullFilePatch([a]));
  a.after.bytes = new Uint8Array([0]); assert.throws(() => fullFilePatch([a]));
  a.after.bytes = utf8.encode('new'); a.after.mode = 0o120000; assert.throws(() => fullFilePatch([a]));
  assert.throws(() => fullFilePatch(Array.from({ length: 65 }, (_, n) => ({ ...edit(), path_hex: Buffer.from(String(n)).toString('hex') }))));
});
test('multipart preparation refuses truncation, suffixes, and wrong framing', async () => {
  const f = await fixture(), value = multipart(f.prepared, f.bundle, f.sha256);
  for (const altered of [{ ...value, value: value.value.subarray(0, value.value.length - 1) },
    { ...value, value: new Uint8Array([...value.value, 1]) }, { ...value, type: 'multipart/mixed; boundary=x' }]) assert.throws(() => sourceEnvelope(altered));
  assert.throws(() => sourceUpload(f.fields, utf8.encode('--collision'), 'patch', 'collision'));
});
