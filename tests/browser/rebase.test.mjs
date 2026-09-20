import test from 'node:test';
import assert from 'node:assert/strict';
import { RebaseClient } from '../../crates/fgit-node/src/smart_http/server/browser/rebase.mjs';
import { Transport, hex, utf8 } from '../../crates/fgit-node/src/smart_http/server/browser/pulls-core.mjs';
import { objectHash, prepareCommand, addResolutions, resolutionUpload, FILE_BYTES } from '../../crates/fgit-node/src/smart_http/server/browser/rebase-data.mjs';
import { fixture, token, crypto, href, decodeUpload, response } from './rebase-fixtures.mjs';
async function setup(algorithm = 'sha1', count = 2) {
  const f = await fixture(algorithm, count), c = new RebaseClient({ href, cryptoImpl: crypto, fetchImpl: f.fetchImpl });
  await c.connect(token); await c.select('refs/heads/topic', 'refs/heads/main', algorithm); return { f, c };
}
for (const algorithm of ['sha1', 'sha256']) {
  test(`${algorithm}: complete series inspects actual bundle then freezes original-tip publication`, async () => {
    const { f, c } = await setup(algorithm);
    assert.equal(new URLSearchParams(f.calls[1].body).get('expected_head'), f.selection.head);
    const result = await c.prepare(f.parameters); assert.equal(result.candidate.inspection.commit_count, 2);
    const upload = decodeUpload(f.calls.at(-1)); assert.deepEqual(upload.payload, f.bundle);
    assert.equal(upload.command.get('expected_source'), f.source); assert.equal(upload.command.get('expected_onto'), f.onto);
    assert.equal(upload.command.get('upstream'), null);
    const before = f.calls.length, pending = await c.stage(); assert.equal(f.calls.length, before);
    assert.notEqual(pending.fields.expected_source, pending.fields.onto); pending.fields.expected_source = 'bad';
    const done = await c.send(); assert.equal(done.outcome, 'committed'); assert.equal(c.pending, null);
    const sent = f.calls.at(-1); assert.equal(sent.endpoint, 'source/rebase/apply');
    assert.equal(decodeUpload(sent).command.get('expected_source'), f.source); assert.equal(c.selection, null);
  });
  test(`${algorithm}: zero-rewritten-commit series still inspects and uses expected-old lease`, async () => {
    const { f, c } = await setup(algorithm, 0); await c.prepare(f.parameters);
    assert.equal(c.candidate.fields.candidate_commit, f.onto); assert.equal(c.candidate.inspection.commit_count, 0);
    await c.stage(); await c.send(); assert.equal(decodeUpload(f.calls.at(-1)).command.get('onto'), f.onto);
  });
  test(`${algorithm}: all-dropped suffix preserves onto tree and has no invented commits`, async () => {
    const { f, c } = await setup(algorithm);
    f.config.prepare = r => Object.assign(r, { empty: 'drop', candidate_commit: f.onto, root_tree: f.ontoTree, generated_objects: 0, pack_objects: 0,
      steps: f.steps.map(s => ({ ...s, rewritten: f.onto, tree: f.ontoTree, kind: 'dropped_empty' })) });
    f.config.inspect = r => { r.candidate_commit = f.onto; r.commit_count = 0; r.commits = []; r.bundle.pack_objects = 0;
      r.net_change = f.diff(f.source, f.onto, f.sourceTree, f.ontoTree); };
    await c.prepare({ ...f.parameters, empty: 'drop' }); assert.equal(c.candidate.fields.candidate_commit, f.onto);
  });
  test(`${algorithm}: two successive conflict recipes retain original commits, choices and snapshot`, async () => {
    const { f, c } = await setup(algorithm); f.config.prepare = r => { for (const k of Object.keys(r)) delete r[k]; Object.assign(r, f.stopped(0)); };
    await c.prepare(f.parameters); await assert.rejects(c.stage()); assert.equal(f.calls.filter(x => x.endpoint.endsWith('/inspect')).length, 0);
    const bytes = new Uint8Array([0, 255, 13, 10]), fileResult = { mode: 0o100755, oid: await objectHash('blob', bytes, algorithm, crypto) };
    const first = { original: f.steps[0].original, paths: [{ conflict: structuredClone(f.conflict), choice: 'file', result: fileResult }] };
    f.config.resolve = (r, options) => {
      const { command } = decodeUpload(options); assert.equal(command.get('expected_head'), f.selection.head);
      assert(command.get('resolution').startsWith(`${first.original}:`));
      for (const k of Object.keys(r)) delete r[k]; Object.assign(r, f.stopped(1), { resolution_profile: 'original-commit-path-v1',
        resolution_input_commits: 1, resolution_consumed_commits: 1, resolutions: [first] });
    };
    await c.resolve([{ path_hex: f.conflict.path_hex, choice: 'file', mode: 0o100755, bytes }]);
    assert.equal(c.report.stopped_commit, f.source); assert.equal(c.candidate, null);
    f.config.resolve = (r, options) => {
      const { command } = decodeUpload(options); assert.equal(command.getAll('resolution').length, 2);
      Object.assign(r, { resolution_profile: 'original-commit-path-v1', resolution_input_commits: 2, resolution_consumed_commits: 2,
        resolutions: [first, { original: f.source, paths: [{ conflict: structuredClone(f.conflict), choice: 'theirs', result: f.conflict.theirs }] }] });
    };
    await c.resolve([{ path_hex: f.conflict.path_hex, choice: 'theirs' }]);
    assert.equal(c.candidate.inspection.commit_count, 2); await c.stage(); assert(!f.calls.some(x => x.endpoint.endsWith('/apply')));
  });
}
const badPreparation = [
  ['source tip', r => { r.expected_source = r.onto; }], ['onto branch', r => { r.onto_ref = r.source_ref; }],
  ['policy', r => { r.empty = 'drop'; }], ['committer', r => { r.committer = 'Other <other@example.invalid>'; }],
  ['snapshot', r => { r.snapshot_token = `alg:2:${'8'.repeat(64)}`; }], ['authority label', r => { r.source_head = 'another-head'; }],
  ['tenant', r => { r.tenant_id = '4'.repeat(32); }], ['count', r => { r.step_count++; }],
  ['duplicate originals', r => { r.steps[0].original = r.steps[1].original; }],
  ['frontier', r => { r.steps[0].rewritten = r.onto; }], ['missing source step', r => { r.steps.pop(); r.step_count--; }],
  ['provisional final', r => { r.provisional_steps = true; }], ['incomplete series', r => { r.series_complete = false; }],
  ['bundle digest', r => { r.bundle.sha256 = '0'.repeat(64); }], ['invented approval', r => { r.publication_authorized = true; }],
  ['signature claim', r => { r.original_signatures_copied = true; }], ['wrong empty tree', r => { r.steps[0].kind = 'preserved_empty'; }],
];
for (const [name, mutate] of badPreparation) test(`preparation rejects ${name} before inspection/publication`, async () => {
  const { f, c } = await setup(); f.config.prepare = mutate;
  await assert.rejects(c.prepare(f.parameters)); assert.equal(c.candidate, null); assert(!f.calls.some(x => x.endpoint.endsWith('/inspect')));
});
const badInspection = [
  ['missing commit', r => { r.commits.pop(); r.commit_count--; }], ['commit count', r => { r.commit_count++; }],
  ['parent chain', r => { r.commits[1].parent = r.onto; }], ['hash body', r => { r.commits[0].body_hex += '00'; }],
  ['tree', r => { r.commits[0].tree = r.commits[1].tree; }], ['bundle', r => { r.bundle.sha256 = 'f'.repeat(64); }],
  ['whole-series coverage', r => { r.all_rewritten_commits = false; }], ['equivalence claim', r => { r.replay_equivalence_verified = true; }],
  ['net source', r => { r.net_change.requested_before = r.onto; }], ['step basis', r => { r.commits[1].diff.before_tree = r.net_change.before_tree; }],
  ['filtered paths', r => { r.net_change.path_prefixes_hex = ['61']; }], ['snapshot', r => { r.commits[0].diff.snapshot_token = `alg:2:${'8'.repeat(64)}`; }],
];
for (const [name, mutate] of badInspection) test(`inspection rejects ${name} and never retains a candidate`, async () => {
  const { f, c } = await setup(); f.config.inspect = mutate; await assert.rejects(c.prepare(f.parameters));
  assert.equal(c.candidate, null); await assert.rejects(c.stage()); assert(!f.calls.some(x => x.endpoint.endsWith('/apply')));
});
test('became-empty stop exposes no candidate; changing policy is an explicit new preparation', async () => {
  const { f, c } = await setup(); f.config.prepare = r => { for (const k of Object.keys(r)) delete r[k]; Object.assign(r, f.stopped(1, 'became_empty')); };
  await c.prepare(f.parameters); assert.equal(c.report.state, 'became_empty'); await assert.rejects(c.stage());
  await assert.rejects(c.resolve([])); assert.equal(c.candidate, null);
});
test('lost write restores exact bytes/key after reload, without re-reading moved branches', async () => {
  const { f, c } = await setup(); await c.prepare(f.parameters); await c.stage(); f.config.lose = true;
  await assert.rejects(c.send(), e => e.outcomeUnknown === true); const sent = f.calls.at(-1), receipt = c.exportReceipt();
  assert(!receipt.includes(token)); c.disconnect(); assert(c.pending); await assert.rejects(c.connect('8'.repeat(64)));
  const next = new RebaseClient({ href, cryptoImpl: crypto, fetchImpl: f.fetchImpl }); await next.connect(token);
  const count = f.calls.length; await next.restoreReceipt(receipt); assert.equal(f.calls.length, count); f.config.lose = false;
  await next.send(); const retried = f.calls.at(-1);
  assert.deepEqual(retried.body, sent.body); assert.equal(retried.headers['idempotency-key'], sent.headers['idempotency-key']);
  assert.equal(next.pending, null);
});
for (const state of ['key_not_observed', 'seal_not_observed', 'undecided', 'committed', 'refused']) test(`bodyless original outcome lookup: ${state}`, async () => {
  const { f, c } = await setup(); await c.prepare(f.parameters); await c.stage(); f.config.outcome = state;
  const result = await c.recover(); assert.equal(f.calls.at(-1).body, undefined);
  assert.equal(result.terminal, ['committed', 'refused'].includes(state)); assert.equal(c.pending === null, result.terminal);
});
test('canonical HTTP 409 refusal settles the original request, not a generic conflict', async () => {
  const { f, c } = await setup(); await c.prepare(f.parameters); await c.stage();
  f.config.apply = r => { r.outcome = 'refused'; r.refusal_code = 'TargetMoved'; };
  assert.equal((await c.send()).outcome, 'refused'); assert.equal(c.pending, null);
});
test('mismatched terminal keeps pending responsibility and prohibits replacement operations', async () => {
  const { f, c } = await setup(); await c.prepare(f.parameters); await c.stage(); f.config.apply = r => { r.expected_source = r.onto; };
  await assert.rejects(c.send()); assert(c.pending.sent); await assert.rejects(c.prepare(f.parameters));
  await assert.rejects(c.select('refs/heads/topic', 'refs/heads/main', 'sha1')); assert.throws(() => c.discardUnsent());
});
test('tampered recovery fields, bundle, namespace, or profile cannot reuse the key', async () => {
  const { f, c } = await setup(); await c.prepare(f.parameters); await c.stage(); const original = JSON.parse(c.exportReceipt());
  for (const mutate of [r => { r.fields.onto = f.source; }, r => { r.fields.expected_source = f.onto; },
    r => { r.scope.incarnation = 'f'.repeat(32); }, r => { r.bundle_base64 = btoa('changed'); }, r => { r.schema = 'source-retry'; },
    r => { r.fields.force = true; }]) {
    const other = new RebaseClient({ href, cryptoImpl: crypto, fetchImpl: f.fetchImpl }); await other.connect(token);
    const value = structuredClone(original); mutate(value); await assert.rejects(other.restoreReceipt(JSON.stringify(value))); assert.equal(other.pending, null);
  }
});
test('invalid inputs and incomplete/conflicting resolution choices do no network work', async () => {
  const { f, c } = await setup(); const count = f.calls.length;
  for (const value of [{ ...f.parameters, empty: 'automatic' }, { ...f.parameters, timestamp: -1 },
    { ...f.parameters, committer: 'Bad\n <b@example.invalid>' }, { ...f.parameters, upstream: 'HEAD~3' }, { ...f.parameters, force: true }]) await assert.rejects(c.prepare(value));
  assert.equal(f.calls.length, count);
  const stop = f.stopped();
  for (const choice of [[], [{ path_hex: '62', choice: 'ours' }], [{ path_hex: f.conflict.path_hex, choice: 'file', mode: 0o120000, bytes: new Uint8Array() }],
    [{ path_hex: f.conflict.path_hex, choice: 'file', mode: 0o100644, bytes: new Uint8Array(FILE_BYTES + 1) }]]) await assert.rejects(addResolutions(stop, choice, [], crypto, () => {}));
  stop.conflicts[0].ours = null;
  await assert.rejects(addResolutions(stop, [{ path_hex: f.conflict.path_hex, choice: 'ours' }], [], crypto, () => {}));
});
test('custom empty binary resolution uses exactly one named empty part; sides use forms', async () => {
  const f = await fixture();
  for (const choice of [{ choice: 'delete' }, { choice: 'file', mode: 0o100644, bytes: new Uint8Array() }]) {
    const recipes = await addResolutions(f.stopped(), [{ ...choice, path_hex: f.conflict.path_hex }], [], crypto, () => {});
    const value = resolutionUpload(prepareCommand(f.selection, f.parameters), recipes, '0'.repeat(32));
    if (choice.choice === 'file') assert(Buffer.from(value.body).includes(Buffer.from('name="file_0"\r\nContent-Type: application/octet-stream\r\n\r\n\r\n')));
    else assert.equal(new URLSearchParams(value.body).get('resolution'), `${f.steps[0].original}:${f.conflict.path_hex}:delete`);
  }
});
test('cancellation and disconnect cannot resurrect a late candidate', async () => {
  const { f, c } = await setup(); let release;
  f.config.hold = async endpoint => { if (endpoint === 'source/rebase/inspect') await new Promise(resolve => { release = resolve; }); };
  const run = c.prepare(f.parameters); while (!release) await new Promise(resolve => setImmediate(resolve));
  c.disconnect(); release(); await assert.rejects(run); assert.equal(c.candidate, null); assert.equal(c.report, null);
});
test('selection rejects mixed source/onto snapshots and preserves no partial selection', async () => {
  const { f, c } = await setup(); f.config.tree = (r, n) => { if (r.ref.endsWith('/main')) r.snapshot_token = `alg:2:${'5'.repeat(64)}`; };
  await assert.rejects(c.select('refs/heads/topic', 'refs/heads/main', 'sha1')); assert.equal(c.selection, null);
});
test('rebase transport cannot escape its closed endpoint or method profile', async () => {
  let calls = 0; const t = new Transport({ href, pageSuffix: '/ui/rebase/', cryptoImpl: crypto, fetchImpl: async () => { calls++; return response({}); } });
  await t.connect(token);
  for (const path of ['source/apply', 'pulls/1/merge', '../secret', 'source/rebase/apply?force=1']) await assert.rejects(t.request(path, { method: 'POST', body: 'x=1' }));
  await assert.rejects(t.request('source/rebase/apply', { method: 'POST', body: 'x=1' }));
  await assert.rejects(t.request('source/rebase/prepare', { method: 'GET', body: 'x=1' }));
  await assert.rejects(t.request('outcomes', { method: 'POST', body: 'x=1', key: 'key', read: false }));
  assert.equal(calls, 0);
});
test('other profiles do not gain rebase write access', async () => {
  for (const profile of ['pulls', 'source', 'search', 'replay', 'initial']) {
    const t = new Transport({ href: href.replace('/rebase/', `/${profile}/`), pageSuffix: `/ui/${profile}/`, cryptoImpl: crypto, fetchImpl: () => { throw new Error('must not dispatch'); } });
    await t.connect(token); await assert.rejects(t.request('source/rebase/apply', { method: 'POST', body: 'x=1', key: 'key', read: false }));
  }
});
test('whole-operation deadline covers preparation plus inspection and leaves no candidate', async () => {
  const f = await fixture(), c = new RebaseClient({ href, cryptoImpl: crypto, fetchImpl: f.fetchImpl, operationTimeoutMs: 10 });
  await c.connect(token); await c.select('refs/heads/topic', 'refs/heads/main', 'sha1');
  f.config.hold = async endpoint => { if (endpoint.endsWith('/inspect')) await new Promise(resolve => setTimeout(resolve, 30)); };
  await assert.rejects(c.prepare(f.parameters)); assert.equal(c.candidate, null); assert.equal(c.pending, null);
});
test('native diff mode, exact hunk spans, binary and directory entries are accepted without executing bytes', async () => {
  const { f, c } = await setup();
  const entry = { path_hex: hex(utf8.encode('file\xff')), kind: 'modified', before: { mode: '100644', object_id: f.id('5') }, after: { mode: '100644', object_id: f.id('6') },
    content: { kind: 'text', algorithm: 'Myers', additions: 1, deletions: 1, before_bytes: 3, after_bytes: 3,
      hunks: [{ old: { byte_start: 0, byte_end: 3, line_start: 0, line_count: 1 }, new: { byte_start: 0, byte_end: 3, line_start: 0, line_count: 1 }, before_hex: '61ff0a', after_hex: '62ff0a' }] } };
  f.config.inspect = r => { r.net_change.entries = [entry]; r.net_change.entry_count = 1; };
  await c.prepare(f.parameters); assert(c.candidate);
  for (const change of [e => { e.content.hunks[0].old.byte_end++; }, e => { e.kind = 'added'; }, e => { e.before.mode = '100600'; },
    e => { e.content.hunks[0].new.line_count = 0; }, e => { e.content.before_bytes = 2; }]) {
    const bad = structuredClone(entry); change(bad);
    f.config.inspect = r => { r.net_change.entries = [bad]; r.net_change.entry_count = 1; };
    await assert.rejects(c.prepare(f.parameters)); assert.equal(c.candidate, null);
  }
});
test('inspection budgets are shared across net change and every commit comparison', async () => {
  const { f, c } = await setup();
  const entry = i => ({ path_hex: hex(utf8.encode(`dir${String(i).padStart(3, '0')}`)), kind: 'added', before: null,
    after: { mode: '040000', object_id: f.id('5') }, content: { kind: 'object_only' } });
  f.config.inspect = r => { r.net_change.entries = Array.from({ length: 128 }, (_, i) => entry(i)); r.net_change.entry_count = 128;
    r.commits[0].diff.entries = [entry(0)]; r.commits[0].diff.entry_count = 1; };
  await assert.rejects(c.prepare(f.parameters), /aggregate/); assert.equal(c.candidate, null);
});
test('a correct commit hash alone cannot authorize a substituted committer', async () => {
  const { verifyCommit } = await import('../../crates/fgit-node/src/smart_http/server/browser/rebase-inspection.mjs');
  const f = await fixture(), row = structuredClone(f.inspection.commits[0]);
  const bytes = utf8.encode(Buffer.from(row.body_hex, 'hex').toString().replace(inputCommitter(f), 'Other <other@example.invalid>'));
  row.body_hex = hex(bytes); row.commit = await objectHash('commit', bytes, 'sha1', crypto);
  await assert.rejects(verifyCommit(row, f.onto, row.tree, prepareCommand(f.selection, f.parameters), crypto, () => {}));
});
function inputCommitter(f) { return f.parameters.committer; }
test('a resolved receipt must retain the reported conflict, exact choice and output identity', async () => {
  for (const mutation of [r => { r.paths[0].choice = 'base'; }, r => { r.paths[0].result.oid = 'f'.repeat(40); }, r => { r.paths[0].conflict.theirs.mode = 0o100644; }]) {
    const { f, c } = await setup(); f.config.prepare = r => { for (const k of Object.keys(r)) delete r[k]; Object.assign(r, f.stopped(0)); };
    await c.prepare(f.parameters);
    f.config.resolve = r => {
      const receipt = { original: f.steps[0].original, paths: [{ conflict: structuredClone(f.conflict), choice: 'theirs', result: structuredClone(f.conflict.theirs) }] };
      mutation(receipt); Object.assign(r, { resolution_profile: 'original-commit-path-v1', resolution_input_commits: 1, resolution_consumed_commits: 1, resolutions: [receipt] });
    };
    await assert.rejects(c.resolve([{ path_hex: f.conflict.path_hex, choice: 'theirs' }])); assert.equal(c.candidate, null);
  }
});
