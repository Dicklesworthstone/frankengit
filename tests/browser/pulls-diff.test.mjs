// Production browser client and controller against the native source_diff schema.
// Injected HTTP/minimal DOM contracts, not a live node or a real-browser campaign.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { setImmediate as tick } from 'node:timers/promises';
import { PullClient, PR_DIFF_LIMITS } from '../../crates/fgit-node/src/smart_http/server/browser/pulls.mjs';
import { Transport } from '../../crates/fgit-node/src/smart_http/server/browser/pulls-core.mjs';
import { mountPulls, renderInspection, renderPullDiff, DISPLAY_BYTES } from '../../crates/fgit-node/src/smart_http/server/browser/pulls-view.mjs';
import { token, ids, head, show, data, row, metadata, hex, json, options, deferred, webcrypto } from './pulls-fixtures.mjs';
const native = (letter, algorithm = 'sha1') => `${algorithm}:${letter.repeat(algorithm === 'sha1' ? 40 : 64)}`;
function observed(algorithm = 'sha1') {
  return show({ object_format: algorithm, pull_request: row(1, { data: data({ object_format: algorithm,
    source_tip: native('a', algorithm), target_tip: native('b', algorithm) }) }) });
}
function entry(algorithm = 'sha1', extra = {}) {
  return { path_hex: hex('src/a.txt'), kind: 'modified', before: { mode: '100644', object_id: native('c', algorithm) },
    after: { mode: '100644', object_id: native('d', algorithm) }, content: { kind: 'text', algorithm: 'Myers', additions: 1, deletions: 1,
      before_bytes: 5, after_bytes: 5, hunks: [{ old: { byte_start: 0, byte_end: 5, line_start: 0, line_count: 2 },
        new: { byte_start: 0, byte_end: 5, line_start: 0, line_count: 2 }, before_hex: '610d0aff62', after_hex: '610d0afe63' }] }, ...extra };
}
function diff(algorithm = 'sha1', mode = 'merge-base', extra = {}) {
  const original = observed(algorithm), data = original.pull_request.data;
  return { ...ids, object_format: algorithm, type: 'source_diff', profile: 'native-tree-review-v1', source_head: original.source_head,
    snapshot_token: head, mode, pull_request: { number: 1, version: 1 }, read_only: true, transaction_created: false, published: false,
    approval_created: false, complete: true, line_origin: 0, context_lines: 3, before_ref_hex: data.target_ref_hex, after_ref_hex: data.source_ref_hex,
    requested_before: data.target_tip, requested_after: data.source_tip, compared_before: native(mode === 'direct' ? 'b' : 'e', algorithm),
    before_tree: native('f', algorithm), after_tree: native('1', algorithm), entry_count: 1, path_prefixes_hex: [], entries: [entry(algorithm)], ...extra };
}
async function setup(respond = () => json(diff()), algorithm = 'sha1', initial = observed(algorithm)) {
  const calls = [], client = new PullClient(options((url, init) => {
    calls.push({ url: String(url), ...init }); return calls.length === 1 ? json(initial) : respond(calls.at(-1));
  }));
  await client.connect(token); const selected = await client.show(1);
  return { client, selected, calls };
}
for (const algorithm of ['sha1', 'sha256']) for (const mode of ['merge-base', 'direct']) {
  test(`${algorithm} ${mode} compares the exact recorded PR snapshot without a candidate`, async () => {
    const raw = diff(algorithm, mode), { client, selected, calls } = await setup(() => json(raw), algorithm);
    const result = await client.diff(1, selected, mode), request = calls[1], fields = new URLSearchParams(request.body);
    assert.equal(request.url, 'https://forge.example/team/repo.git/api/v1/pulls/1/diff'); assert.equal(request.method, 'POST');
    assert.equal(request.headers['Idempotency-Key'], undefined); assert.equal(request.headers.Authorization, `Bearer ${token}`);
    assert.equal(fields.get('expected_head'), head); assert.equal(fields.get('expected_version'), '1');
    assert.equal(fields.get('expected_before'), native('b', algorithm).split(':')[1]);
    assert.equal(fields.get('expected_after'), native('a', algorithm).split(':')[1]);
    assert.equal(fields.get('mode'), mode); assert.equal(fields.get('context_lines'), '3');
    for (const [name, value] of Object.entries(PR_DIFF_LIMITS)) assert.equal(fields.get(name), String(value));
    for (const name of ['author', 'committer', 'timestamp', 'policy_epoch', 'candidate_commit', 'principal']) assert.equal(fields.has(name), false);
    assert.deepEqual(result.reply, raw); assert.equal(result.comparison.entries[0].before.mode, 0o100644);
    assert.equal(result.comparison.entries[0].content.hunks[0].before_hex, '610d0aff62');
    assert.equal(client.candidate, null); assert.equal(client.pending, null); assert.equal(calls.length, 2);
  });
}
const edits = [
  ['different tenant', r => r.tenant_id = 'other'], ['repository', r => r.repository_id = 'other'],
  ['incarnation', r => r.repository_incarnation = 'other'], ['hash domain', r => r.object_format = 'sha256'],
  ['snapshot', r => r.snapshot_token = `alg:1:${'c'.repeat(64)}`], ['authority head', r => r.source_head = 'other'],
  ['profile', r => r.profile = 'other'], ['type', r => r.type = 'merge_candidate_inspection'],
  ['mode', r => r.mode = 'direct'], ['partial result', r => r.complete = false], ['read-only flag', r => r.read_only = false],
  ['transaction', r => r.transaction_created = true], ['publication', r => r.published = true], ['approval', r => r.approval_created = true],
  ['line origin', r => r.line_origin = 1], ['context', r => r.context_lines = 20],
  ['PR number', r => r.pull_request.number = 2], ['PR version', r => r.pull_request.version = 2],
  ['before reference', r => r.before_ref_hex = hex('refs/heads/other')], ['after reference', r => r.after_ref_hex = hex('refs/heads/other')],
  ['before tip', r => r.requested_before = native('c')], ['after tip', r => r.requested_after = native('c')],
  ['zero base', r => r.compared_before = native('0')], ['bad tree', r => r.before_tree = 'x'],
  ['hidden path filter', r => r.path_prefixes_hex = ['737263']], ['missing paths', r => r.entry_count = 2],
  ['duplicate paths', r => { r.entries.push(structuredClone(r.entries[0])); r.entry_count++; }],
  ['dot path', r => r.entries[0].path_hex = hex('src/../a')], ['NUL path', r => r.entries[0].path_hex = '00'],
  ['bad mode', r => r.entries[0].before.mode = '100600'], ['wrong change kind', r => r.entries[0].kind = 'added'],
  ['unchanged identity', r => r.entries[0].after = r.entries[0].before],
  ['unknown content', r => r.entries[0].content.kind = 'omitted'], ['binary smuggles body', r => r.entries[0].content.kind = 'binary'],
  ['blob too large', r => r.entries[0].content.before_bytes = 1048577],
  ['impossible addition count', r => r.entries[0].content.additions = 6],
  ['bad hunk bytes', r => r.entries[0].content.hunks[0].before_hex = 'zz'],
  ['wrong hunk size', r => r.entries[0].content.hunks[0].old.byte_end = 4],
  ['wrong line count', r => r.entries[0].content.hunks[0].old.line_count = 1],
  ['wrong first line', r => r.entries[0].content.hunks[0].old.line_start = 1],
  ['mid-line end', r => r.entries[0].content.before_bytes = 6],
  ['overlapping hunks', r => r.entries[0].content.hunks.push(structuredClone(r.entries[0].content.hunks[0]))],
];
for (const [name, mutate] of edits) test(`diff refuses ${name}, never an empty or refreshed view`, async () => {
  const raw = diff(); mutate(raw); const { client, selected, calls } = await setup(() => json(raw));
  await assert.rejects(client.diff(1, selected)); assert.equal(calls.length, 2); assert.equal(client.candidate, null); assert.equal(client.pending, null);
});
test('direct mode cannot substitute a merge base for the selected target', async () => {
  const { client, selected } = await setup(() => json(diff('sha1', 'direct', { compared_before: native('e') })));
  await assert.rejects(client.diff(1, selected, 'direct'));
});
test('byte-only refs are compared without a lossy text form or authority-field injection', async () => {
  const initial = observed(); initial.pull_request.data.source_ref = null; initial.pull_request.data.source_ref_hex += 'ff';
  const raw = diff('sha1', 'merge-base', { after_ref_hex: initial.pull_request.data.source_ref_hex });
  const { client, selected, calls } = await setup(() => json(raw), 'sha1', initial);
  await client.diff(1, selected); assert.equal(new URLSearchParams(calls[1].body).has('source_ref'), false);
});
test('binary, mode-only, directory and deleted paths retain explicit non-text semantics', async () => {
  const a = entry(), binary = { kind: 'binary', before_bytes: 5, after_bytes: 5 };
  const rows = [entry('sha1', { path_hex: hex('a'), content: binary }),
    entry('sha1', { path_hex: hex('b'), kind: 'mode_changed', after: { ...a.before, mode: '100755' }, content: { kind: 'identical' } }),
    entry('sha1', { path_hex: hex('c'), before: { ...a.before, mode: '040000' }, after: { ...a.after, mode: '040000' }, content: { kind: 'object_only' } }),
    entry('sha1', { path_hex: hex('d'), kind: 'deleted', after: null, content: { ...binary, after_bytes: 0 } })];
  const { client, selected } = await setup(() => json(diff('sha1', 'merge-base', { entries: rows, entry_count: rows.length })));
  const result = await client.diff(1, selected);
  assert.deepEqual(result.comparison.entries.map(e => e.content.type), ['binary', 'identical', 'object_only', 'binary']);
  assert.equal(result.comparison.entries[0].content.body_included, false);
});
test('missing, malformed and moved PR observations refuse before disclosure', async () => {
  const { client, selected, calls } = await setup(() => assert.fail('invalid observation dispatched'));
  for (const mutate of [r => { r.head = null; }, r => { r.reply.pull_request.data = null; },
    r => { r.reply.pull_request.version = 0; }, r => { r.reply.repository_incarnation = 'other'; }, r => { r.reply.pull_request.number = 2; }]) {
    const bad = structuredClone(selected); mutate(bad); await assert.rejects(client.diff(1, bad));
  }
  await assert.rejects(client.diff(1, selected, 'automatic')); assert.equal(calls.length, 1);
});
test('a diff read snapshots caller inputs before asynchronous transport', async () => {
  const wait = deferred(), { client, selected } = await setup(() => wait.promise);
  const read = client.diff(1, selected); selected.reply.pull_request.data.source_tip = native('f'); selected.head = 'wrong';
  wait.resolve(json(diff())); assert.equal((await read).reply.requested_after, native('a'));
});
for (const status of [403, 404, 409, 413, 429]) test(`HTTP ${status} does not synthesize an empty comparison or retry`, async () => {
  const { client, selected, calls } = await setup(() => json({ error: 'unavailable' }, status));
  await assert.rejects(client.diff(1, selected), error => error.status === status);
  assert.equal(client.connected, true); assert.equal(calls.length, 2);
});
test('diff reads leave an exported pending mutation unchanged', async () => {
  const { client, selected, calls } = await setup(); await client.stageMetadata(1, 'update', metadata()); client.exportReceipt();
  const original = client.pending; await client.diff(1, selected); assert.deepEqual(client.pending, original);
  assert.equal(calls[1].headers['Idempotency-Key'], undefined);
});
test('disconnect and read cancellation reject late diffs without reviving identities', async () => {
  for (const cancel of [client => client.disconnect(), client => client.cancelReads()]) {
    const wait = deferred(), { client, selected } = await setup(() => wait.promise);
    const read = client.diff(1, selected); cancel(client); wait.resolve(json(diff())); await assert.rejects(read);
    assert.equal(client.candidate, null);
  }
});
test('diff transport rejects mutation semantics, query drift and every non-PR browser profile', async () => {
  const transport = new Transport(options(() => assert.fail('invalid diff dispatched'))); await transport.connect(token);
  for (const extra of [{ method: 'GET' }, { key: 'write-key' }, { read: false }, { binary: true }, { statuses: [200, 409] },
    { contentType: 'application/json' }, { body: new Blob(['x']) }]) {
    await assert.rejects(transport.request('pulls/1/diff', { method: 'POST', body: 'x=1', ...extra }));
  }
  await assert.rejects(transport.request('pulls/1/diff?mode=direct', { method: 'POST', body: 'x=1' }));
  for (const pageSuffix of ['/ui/source/', '/ui/initial/', '/ui/branches/', '/ui/search/', '/ui/transfers/', '/ui/tags/', '/ui/replay/', '/ui/rebase/']) {
    const transport = new Transport({ ...options(() => assert.fail('cross-profile diff dispatched')), href: `https://forge.example/r.git${pageSuffix}`, pageSuffix });
    await transport.connect(token); await assert.rejects(transport.request('pulls/1/diff', { method: 'POST', body: 'x=1' }));
  }
});
test('diff text-file and aggregate payload budgets reject before presentation', async () => {
  const rows = Array.from({ length: 65 }, (_, i) => entry('sha1', { path_hex: hex(String(i).padStart(3, '0')) }));
  const { client, selected } = await setup(() => json(diff('sha1', 'merge-base', { entries: rows, entry_count: rows.length })));
  await assert.rejects(client.diff(1, selected), /text files/);
  const raw = diff(), content = raw.entries[0].content, size = 1024 * 1024;
  content.before_bytes = content.after_bytes = size; content.hunks[0] = { old: { byte_start: 0, byte_end: size, line_start: 0, line_count: 1 },
    new: { byte_start: 0, byte_end: size, line_start: 0, line_count: 1 }, before_hex: '61'.repeat(size), after_hex: '62'.repeat(size) };
  const large = await setup(() => json(raw)); await assert.rejects(large.client.diff(1, large.selected), /payload/);
});

// Minimal event/DOM surface; no HTML parser or real-browser claim.
class Element {
  constructor(tag = 'div') { this.tagName = tag.toUpperCase(); this.children = []; this.listeners = new Map(); this.value = ''; this.disabled = false; this.text = ''; }
  set textContent(value) { this.text = String(value); this.children = []; }
  get textContent() { return this.text + this.children.map(n => n.textContent).join(''); }
  set innerHTML(_) { assert.fail('HTML parsing is forbidden'); }
  append(...nodes) { this.children.push(...nodes); }
  replaceChildren(...nodes) { this.text = ''; this.children = [...nodes]; }
  addEventListener(name, fn) { const list = this.listeners.get(name) ?? []; list.push(fn); this.listeners.set(name, list); }
  fire(name) { for (const fn of this.listeners.get(name) ?? []) fn({ preventDefault() {} }); }
  setAttribute(name, value) { this[name] = value; }
}
async function documentFixture() {
  const html = await readFile(new URL('../../crates/fgit-node/src/smart_http/server/browser/pulls.html', import.meta.url), 'utf8');
  const nodes = new Map(Array.from(html.matchAll(/id="([^"]+)"/g), match => [match[1], new Element()]));
  return { nodes, createElement: tag => new Element(tag), createDocumentFragment: () => new Element(), createTextNode: text => {
    const node = new Element(); node.textContent = text; return node;
  }, getElementById: id => nodes.get(id), defaultView: { location: { href: options().href }, addEventListener() {} } };
}
const descendants = node => [node, ...node.children.flatMap(descendants)];
const button = (doc, name) => descendants(doc.nodes.get('selected')).find(node => node.tagName === 'BUTTON' && node.textContent === name);
async function settled(doc) {
  for (let i = 0; i < 1000; i++) { await tick(); if (!doc.nodes.get('refresh').disabled) return; }
  assert.fail('controller did not settle');
}
async function mounted(respond = () => json(diff())) {
  const doc = await documentFixture(), calls = [], downloads = [];
  const ui = mountPulls(doc, { ...options((url, init) => { calls.push({ url: String(url), ...init });
    return calls.length === 1 ? json(observed()) : respond(calls.at(-1)); }), downloadImpl: (name, text) => downloads.push({ name, text }) });
  await ui.client.connect(token); await ui.loadPr(1); return { doc, ui, calls, downloads };
}
test('served PR controller exposes both read modes and exports the complete raw native diff only on demand', async () => {
  const { doc, ui, calls, downloads } = await mounted(call => json(diff('sha1', new URLSearchParams(call.body).get('mode'))));
  assert.equal(calls.length, 1); assert.equal(button(doc, 'Download full diff JSON').disabled, true);
  doc.nodes.get('source-tip').value = native('f'); doc.nodes.get('author').value = '';
  button(doc, 'Compare merge-base — read only').fire('click'); await settled(doc);
  assert.match(doc.nodes.get('selected').textContent, /not the result of merging/); assert.match(doc.nodes.get('selected').textContent, /\\xffb/);
  assert.equal(ui.client.candidate, null); assert.equal(ui.client.pending, null); assert.equal(doc.nodes.get('merge-stage').disabled, true);
  assert.equal(new URLSearchParams(calls[1].body).get('expected_after'), 'a'.repeat(40)); assert.equal(downloads.length, 0);
  button(doc, 'Download full diff JSON').fire('click'); await settled(doc);
  assert.deepEqual(JSON.parse(downloads[0].text), diff()); assert.equal(downloads[0].text.includes(token), false);
  button(doc, 'Compare direct — read only').fire('click'); await settled(doc);
  assert.match(doc.nodes.get('selected').textContent, /target-only divergence/); assert.equal(calls.length, 3);
});
test('a failed comparison clears the previous report and disables stale exports without refreshing or preparing', async () => {
  let read = 0; const { doc, calls, downloads } = await mounted(() => ++read === 1 ? json(diff()) : json({}, 409));
  button(doc, 'Compare merge-base — read only').fire('click'); await settled(doc);
  button(doc, 'Compare direct — read only').fire('click'); await settled(doc);
  assert.equal(button(doc, 'Download full diff JSON').disabled, true); assert.doesNotMatch(doc.nodes.get('selected').textContent, /PR #1 changes/);
  assert.match(doc.nodes.get('status').textContent, /refresh explicitly/); assert.equal(calls.length, 3); assert.equal(downloads.length, 0);
});
test('disconnect removes comparison controls and late completion cannot resurrect private diff bytes', async () => {
  const wait = deferred(), { doc, ui } = await mounted(() => wait.promise);
  button(doc, 'Compare merge-base — read only').fire('click'); ui.disconnect(); wait.resolve(json(diff()));
  for (let i = 0; i < 10; i++) await tick();
  assert.equal(doc.nodes.get('selected').textContent, ''); assert.equal(ui.client.connected, false);
});
test('diff renderer escapes hostile source, clips display bytes but preserves every path label and full report', async () => {
  const raw = diff(); raw.entries[0].path_hex = hex('<script>\u202e');
  const content = raw.entries[0].content, size = DISPLAY_BYTES + 100;
  content.before_bytes = content.after_bytes = size;
  content.hunks = [{ old: { byte_start: 0, byte_end: size, line_start: 0, line_count: 1 }, new: { byte_start: 0, byte_end: size, line_start: 0, line_count: 1 },
    before_hex: '61'.repeat(size), after_hex: '62'.repeat(size) }];
  raw.entries.push(entry('sha1', { path_hex: hex('z-last-path'), content: { kind: 'binary', before_bytes: 5, after_bytes: 5 } })); raw.entry_count++;
  const { client, selected } = await setup(() => json(raw)); const result = await client.diff(1, selected);
  const doc = await documentFixture(), parent = new Element();
  assert.equal(renderPullDiff(doc, parent, result).clipped, true);
  assert.match(parent.textContent, /DISPLAY CLIPPED/); assert.match(parent.textContent, /z-last-path/); assert.match(parent.textContent, /<script>\\u202e/);
  assert.equal(descendants(parent).some(node => ['SCRIPT', 'IFRAME', 'IMG'].includes(node.tagName)), false);
  assert.equal(result.reply.entries[0].content.hunks[0].after_hex.length, size * 2);
});
test('candidate inspection keeps its distinct identity and empty-comparison wording after renderer reuse', async () => {
  const doc = await documentFixture(), parent = new Element();
  renderInspection(doc, parent, { candidate_commit: native('a'), subject: { pull_request: 1, pull_request_version: 1, policy_epoch: 1 },
    merge_base: native('b'), parents: [native('c'), native('d')], bundle: { bytes: 1, sha256: 'e'.repeat(64) }, snapshot_token: head,
    comparison: { entries: [] } });
  assert.match(parent.textContent, /Inspected candidate/); assert.match(parent.textContent, /commit identity is still significant/);
  assert.doesNotMatch(parent.textContent, /PR #1 changes/);
});
