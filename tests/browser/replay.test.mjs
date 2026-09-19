import test from 'node:test';
import assert from 'node:assert/strict';
import { ReplayClient } from '../../crates/fgit-node/src/smart_http/server/browser/replay.mjs';
import { SourceEditClient } from '../../crates/fgit-node/src/smart_http/server/browser/source-edit.mjs';
import { Transport } from '../../crates/fgit-node/src/smart_http/server/browser/pulls-core.mjs';
import { replayCommand, resolutionChoices, resolutionUpload, FILE_LIMIT, RESOLUTION_LIMIT } from '../../crates/fgit-node/src/smart_http/server/browser/replay-protocol.mjs';
import { fixture, crypto, token, href, deferred, upload, hex } from './replay-fixtures.mjs';
const connected = async f => { const c = new ReplayClient({ href, cryptoImpl: crypto, fetchImpl: f.fetchImpl }); await c.connect(token); return c; };
const selected = async f => { const c = await connected(f); await c.select('refs/heads/main', 'refs/heads/topic', f.algorithm); return c; };
const ready = async (f, direction = 'cherry-pick') => { const c = await selected(f); await c.prepare(direction, f.input()); return c; };
const staged = async f => { const c = await ready(f); await c.stageApply(); return c; };
for (const algorithm of ['sha1', 'sha256']) for (const direction of ['cherry-pick', 'revert']) {
  test(`${algorithm} ${direction}: select, prepare, inspect and explicitly publish one exact candidate`, async () => {
    const f = await fixture(algorithm), c = await ready(f, direction), p = await c.stageApply();
    assert.equal(f.calls.length, 4); assert(!p.sent);
    assert.deepEqual(f.calls.map(x => x.path), ['source/tree', 'source/tree', `source/${direction}/prepare`, 'source/inspect']);
    assert.equal(new URLSearchParams(f.calls[1].body).get('expected_head'), f.selection.snapshot_token);
    const command = new URLSearchParams(f.calls[2].body);
    assert.equal(command.get('expected_source'), f.topic); assert.equal(command.get('expected_target'), f.base); assert(!command.has('mainline'));
    assert.equal(f.calls[2].headers['idempotency-key'], undefined);
    const result = await c.send(); assert.equal(result.outcome, 'committed'); assert.equal(c.pending, null); assert.equal(c.selection, null);
    const call = f.calls.at(-1); assert.equal(call.path, 'source/apply'); assert.equal(call.headers['idempotency-key'], p.key);
    assert.deepEqual(upload(call).files.get('bundle'), f.bundle); assert.equal(upload(call).fields.get('expected_commit'), f.base);
    assert.equal(upload(call).fields.has('force'), false); assert.equal(upload(call).fields.has('direction'), false);
  });
  test(`${algorithm} ${direction}: no-change is a read result, not a candidate or transaction`, async () => {
    const f = await fixture(algorithm); f.config.state = 'no_change'; const c = await ready(f, direction);
    assert.equal(c.report.state, 'no_change'); assert.equal(c.candidate, null); await assert.rejects(c.stageApply());
    assert(!f.calls.some(x => x.path === 'source/inspect' || x.path === 'source/apply'));
  });
  test(`${algorithm} ${direction}: conflicts require explicit binary or empty-file resolution and reinspection`, async () => {
    for (const bytes of [Uint8Array.of(0, 255, 13, 10), new Uint8Array()]) {
      const f = await fixture(algorithm); f.config.state = 'conflicted'; const c = await ready(f, direction);
      assert.equal(c.candidate, null); await assert.rejects(c.stageApply());
      await c.resolve([{ path_hex: f.path, choice: 'file', mode: 0o100755, bytes }]);
      assert.equal(c.report.state, 'resolved'); assert(c.candidate);
      const call = f.calls.find(x => x.path.endsWith('/resolve')), form = upload(call);
      assert.deepEqual(form.files.get('file_0'), bytes); assert.equal(form.fields.get('expected_head'), f.selection.snapshot_token);
      assert.deepEqual(f.calls.slice(-2).map(x => x.path), [`source/${direction}/resolve`, 'source/inspect']);
      assert.equal(call.headers['idempotency-key'], undefined); await c.stageApply(); await c.send();
    }
  });
}
test('reverting within the target branch selects its snapshot once', async () => {
  const f = await fixture(), c = await connected(f); await c.select('refs/heads/main', 'refs/heads/main', 'sha1');
  assert.equal(f.calls.length, 1); await c.prepare('revert', { ...f.input(), commit: f.base }); assert(c.candidate);
});
for (const mainline of [1, 2, 65535]) test(`an explicit mainline ${mainline} is retained, never guessed`, async () => {
  const f = await fixture(), c = await selected(f); await c.prepare('cherry-pick', { ...f.input(), mainline });
  assert.equal(c.report.selected_mainline, mainline); assert.equal(new URLSearchParams(f.calls[2].body).get('mainline'), String(mainline));
});
test('a root commit uses no synthetic selected parent or mainline', async () => {
  const f = await fixture(); f.config.root = true; const c = await ready(f); assert.equal(c.report.selected_parent, null); assert(c.candidate);
  await assert.rejects(c.prepare('cherry-pick', { ...f.input(), mainline: 1 })); assert.equal(c.candidate, null);
});
for (const [label, mutate] of [
  ['direction', r => r.direction = 'revert'], ['source', r => r.expected_source = 'c'.repeat(40)],
  ['target', r => r.expected_target = 'c'.repeat(40)], ['commit', r => r.selected_commit = 'c'.repeat(40)],
  ['snapshot', r => r.snapshot_token = `alg:1:${'5'.repeat(64)}`], ['incarnation', r => r.repository_incarnation = '5'.repeat(32)],
  ['parent', r => r.parents.push(r.parents[0])], ['implicit mainline', r => r.selected_mainline = 2],
  ['authority', r => r.publication_authorized = true], ['identity trust', r => r.author_identity_verified = true],
  ['bundle', r => r.bundle.sha256 = '0'.repeat(64)], ['object budget', r => r.pack_objects = 10001],
  ['invented resolution', r => r.state = 'resolved'], ['unknown state', r => r.state = 'success'],
]) test(`preparation rejects changed ${label} without enabling publication`, async () => {
  const f = await fixture(), c = await selected(f); f.config.prepare = mutate;
  await assert.rejects(c.prepare('cherry-pick', f.input())); assert.equal(c.candidate, null); await assert.rejects(c.stageApply());
  assert(!f.calls.some(x => x.path === 'source/apply' || x.path === 'source/inspect'));
});
for (const [label, mutate] of [
  ['commit bytes', r => r.candidate_commit_body_hex += '0a'], ['tree', r => r.comparison.after_tree = 'c'.repeat(40)],
  ['old tree', r => r.comparison.before_tree = 'd'.repeat(40)], ['metadata', r => r.candidate_commit_body_hex = r.candidate_commit_body_hex.replace(hex('Alice'), hex('Other'))],
  ['all paths', r => r.all_changed_paths = false], ['bundle', r => r.bundle_bytes++], ['scope', r => r.tenant_id = '6'.repeat(32)],
  ['parent', r => r.parents = []], ['snapshot', r => r.snapshot_token = `alg:1:${'6'.repeat(64)}`],
  ['duplicate path', r => { r.comparison.entries.push(r.comparison.entries[0]); r.comparison.entry_count++; }],
]) test(`native inspection rejects changed ${label}`, async () => {
  const f = await fixture(), c = await selected(f); f.config.inspect = mutate;
  await assert.rejects(c.prepare('cherry-pick', f.input())); assert.equal(c.candidate, null); await assert.rejects(c.stageApply());
});
for (const [label, mutate] of [
  ['path', r => r.resolutions[0].conflict.path_hex = hex('another')], ['side', r => r.resolutions[0].choice = 'ours'],
  ['result', r => r.resolutions[0].result.oid = 'c'.repeat(40)], ['mode', r => r.resolutions[0].result.mode = 0o100644],
  ['missing receipt', r => r.resolutions = []], ['original base', r => r.resolutions[0].conflict.base = null],
  ['selected parent', r => r.selected_parent = 'c'.repeat(40)], ['profile', r => r.resolution_profile = 'guessed'],
]) test(`resolution rejects changed ${label} before inspection`, async () => {
  const f = await fixture(); f.config.state = 'conflicted'; const c = await ready(f); f.config.resolve = mutate;
  await assert.rejects(c.resolve([{ path_hex: f.path, choice: 'file', mode: 0o100755, bytes: Uint8Array.of(1, 2) }]));
  assert.equal(c.candidate, null); assert.equal(c.report.state, 'conflicted');
  assert(!f.calls.some(x => x.path === 'source/inspect'));
});
test('unchanged resolution reports no change; choosing an absent side never means deletion', async () => {
  const f = await fixture(); f.config.state = 'conflicted'; f.config.resolvedState = 'no_change';
  const c = await ready(f); await c.resolve([{ path_hex: f.path, choice: 'ours' }]); assert.equal(c.report.state, 'no_change'); await assert.rejects(c.stageApply());
  const meta = { conflicts: [{ ...f.conflict, base: null }] };
  await assert.rejects(resolutionChoices(meta, [{ path_hex: f.path, choice: 'base' }], 'sha1', crypto));
  const choices = await resolutionChoices(meta, [{ path_hex: f.path, choice: 'delete' }], 'sha1', crypto);
  assert.equal(choices[0].result, null);
});
test('side and delete resolutions use exact form requests without unused file bodies', async () => {
  for (const choice of ['theirs', 'delete']) {
    const f = await fixture(); f.config.state = 'conflicted'; const c = await ready(f);
    await c.resolve([{ path_hex: f.path, choice }]); assert(c.candidate);
    const call = f.calls.find(x => x.path.endsWith('/resolve')); assert.equal(typeof call.body, 'string');
    assert.equal(new URLSearchParams(call.body).get('resolution'), `${f.path}:${choice}`);
  }
});
test('missing, repeated, extra, unsupported, oversized and overlapping conflict choices refuse locally', async () => {
  const f = await fixture(); f.config.state = 'conflicted'; const c = await ready(f), count = f.calls.length;
  const valid = { path_hex: f.path, choice: 'file', bytes: Uint8Array.of(1), mode: 0o100644 };
  for (const rows of [[], [valid, valid], [{ ...valid, path_hex: hex('clean') }], [{ ...valid, mode: 0o120000 }],
    [{ ...valid, bytes: new Uint8Array(FILE_LIMIT + 1) }], [{ ...valid, choice: 'auto' }], [{ path_hex: f.path, choice: 'ours', mode: 0o100644 }]]) await assert.rejects(c.resolve(rows));
  assert.equal(f.calls.length, count);
  const rows = Array.from({ length: 5 }, (_, i) => ({ ...valid, path_hex: hex(`file${i}`), bytes: new Uint8Array(FILE_LIMIT) }));
  await assert.rejects(resolutionChoices({ conflicts: rows.map(r => ({ ...f.conflict, path_hex: r.path_hex })) }, rows, 'sha1', crypto));
  assert.equal(RESOLUTION_LIMIT, 1024 * 1024);
});
test('resolution boundary collisions are rejected and all inputs are owned before digest awaits', async () => {
  const f = await fixture(), bytes = Uint8Array.of(0, 255), original = bytes.slice();
  const pending = resolutionChoices({ conflicts: [f.conflict] }, [{ path_hex: f.path, choice: 'file', mode: 0o100755, bytes }], 'sha1', crypto);
  bytes.fill(99); const choices = await pending; assert.deepEqual(choices[0].bytes, original);
  const nonce = 'a'.repeat(32); choices[0].bytes = new TextEncoder().encode(`--fg-replay-${nonce}`);
  assert.throws(() => resolutionUpload({}, choices, nonce));
});
test('invalid inputs cannot relax direction, mainline, metadata, exact tips or hidden-history access', async () => {
  const f = await fixture(), c = await selected(f), selection = c.selection.fields;
  for (const change of [{ mainline: 0 }, { mainline: 1.5 }, { mainline: 65536 }, { commit: '0'.repeat(40) },
    { commit: 'a'.repeat(64) }, { timestamp: -1 }, { message: '\0' }, { force: true }, { expected_target: f.topic }]) {
    assert.throws(() => replayCommand('cherry-pick', selection, { ...f.input(), ...change }));
  }
  assert.throws(() => replayCommand('auto', selection, f.input()));
  const original = f.fetchImpl;
  const other = new ReplayClient({ href, cryptoImpl: crypto, fetchImpl: (url, options) => String(url).endsWith('/prepare')
    ? new Response(JSON.stringify({ type: 'source_error', code: 'not_found' }), { status: 404, headers: { 'Content-Type': 'application/json' } }) : original(url, options) });
  await other.connect(token); await other.select('refs/heads/main', 'refs/heads/topic', 'sha1');
  await assert.rejects(other.prepare('cherry-pick', f.input())); assert.equal(other.report, null);
});
test('source branch selection cannot silently switch the target snapshot', async () => {
  const f = await fixture(), c = await connected(f); f.config.select = r => { if (r.ref.endsWith('topic')) r.snapshot_token = `alg:1:${'6'.repeat(64)}`; };
  await assert.rejects(c.select('refs/heads/main', 'refs/heads/topic', 'sha1')); assert.equal(c.selection, null);
});
test('changing caller metadata during transport cannot change the expected commit', async () => {
  const f = await fixture(), c = await selected(f), d = deferred(), input = f.input(); f.config.prepare = () => d.promise;
  const preparing = c.prepare('cherry-pick', input); input.message = 'replaced'; input.commit = f.base;
  d.resolve(); await preparing; assert(c.candidate); assert.equal(new URLSearchParams(f.calls[2].body).get('message'), f.input().message);
});
for (const phase of ['select', 'prepare', 'inspect', 'resolve']) test(`disconnect during ${phase} cannot resurrect a candidate`, async () => {
  const f = await fixture(), d = deferred(); if (phase === 'resolve') f.config.state = 'conflicted';
  const c = phase === 'select' ? await connected(f) : phase === 'resolve' ? await ready(f) : await selected(f);
  f.config[phase] = () => d.promise;
  const work = phase === 'select' ? c.select('refs/heads/main', 'refs/heads/topic', 'sha1') : phase === 'resolve'
    ? c.resolve([{ path_hex: f.path, choice: 'theirs' }]) : c.prepare('cherry-pick', f.input());
  await new Promise(setImmediate); c.disconnect(); d.resolve(); await assert.rejects(work); assert.equal(c.candidate, null); assert.equal(c.selection, null);
});
test('lost publication replies preserve original bytes and key without rerunning replay or reading refs', async () => {
  const f = await fixture(), c = await staged(f); f.config.loseApply = true;
  await assert.rejects(c.send(), e => e.outcomeUnknown); const original = f.calls.at(-1), receipt = c.exportReceipt();
  assert(!receipt.includes(token)); c.disconnect(); assert(c.pending);
  const n = await connected(f), count = f.calls.length; await n.restoreReceipt(receipt); assert.equal(f.calls.length, count);
  f.config.loseApply = false; await n.send(); assert.equal(f.calls.length, count + 1); assert.deepEqual(f.calls.at(-1).body, original.body);
  assert.equal(f.calls.at(-1).headers['idempotency-key'], original.headers['idempotency-key']);
});
test('replay retry files interoperate with ordinary source publication without a new key', async () => {
  const f = await fixture(), c = await staged(f), receipt = c.exportReceipt(), key = c.pending.key;
  const n = new SourceEditClient({ href: href.replace('/ui/replay/', '/ui/source/'), cryptoImpl: crypto, fetchImpl: f.fetchImpl });
  await n.connect(token); const before = f.calls.length; await n.restoreReceipt(receipt); assert.equal(f.calls.length, before);
  await n.send(); assert.equal(f.calls.at(-1).headers['idempotency-key'], key);
});
for (const state of ['committed', 'refused']) test(`canonical ${state} publication settles exactly once`, async () => {
  const f = await fixture(), c = await staged(f); f.config.refuseApply = state === 'refused';
  assert.equal((await c.send()).outcome, state); assert.equal(c.pending, null); await assert.rejects(c.send());
});
for (const [label, mutate] of [
  ['target', r => r.fields.expected_commit = 'd'.repeat(40)], ['candidate', r => r.fields.candidate_commit = 'd'.repeat(40)],
  ['branch', r => r.fields.ref = 'refs/heads/other'], ['scope', r => r.scope.incarnation = '8'.repeat(32)],
  ['nonce', r => r.nonce = '8'.repeat(32)], ['body', r => r.bundle_base64 = Buffer.from('changed').toString('base64')],
]) test(`retry receipt rejects changed ${label}`, async () => {
  const f = await fixture(), c = await staged(f), r = JSON.parse(c.exportReceipt()); mutate(r);
  const n = await connected(f); await assert.rejects(n.restoreReceipt(JSON.stringify(r))); assert.equal(n.pending, null);
});
test('pending or exported requests cannot be replaced; changing forms never changes the frozen effect', async () => {
  const f = await fixture(), c = await staged(f), p = c.pending; p.fields.ref = 'refs/heads/other';
  assert.notEqual(c.pending.fields.ref, p.fields.ref); await assert.rejects(c.prepare('revert', f.input()));
  c.exportReceipt(); assert.throws(() => c.discardUnsent()); await assert.rejects(c.connect('8'.repeat(64))); assert(c.pending);
});
test('bodyless outcome lookup preserves unknown states, original transaction and principal', async () => {
  const f = await fixture(), c = await staged(f);
  for (const state of ['key_not_observed', 'seal_not_observed', 'undecided']) {
    f.config.outcome = state; assert.equal((await c.recover()).terminal, false); assert.equal(f.calls.at(-1).body, undefined);
  }
  f.config.outcome = 'key_not_observed'; await assert.rejects(c.recover());
  f.config.outcome = 'committed'; f.config.recover = r => r.principal_id = '8'.repeat(32); await assert.rejects(c.recover());
  f.config.recover = null; assert.equal((await c.recover()).outcome, 'committed'); assert.equal(c.pending, null);
  assert(!f.calls.some(x => x.path === 'source/apply'));
});
test('generic conflicts and mismatched terminal receipts do not imply rollback or success', async () => {
  const f = await fixture(), c = await staged(f); f.config.apply = r => r.candidate_commit = 'd'.repeat(40);
  await assert.rejects(c.send(), e => e.outcomeUnknown); assert(c.pending); assert.throws(() => c.discardUnsent());
});
test('read cancellation never aborts an in-flight publication', async () => {
  const f = await fixture(), c = await staged(f), d = deferred(); f.config.apply = () => d.promise;
  const sending = c.send(); await new Promise(setImmediate); const call = f.calls.at(-1); c.cancel();
  assert.equal(call.signal.aborted, false); d.resolve(); assert.equal((await sending).outcome, 'committed');
});
test('the replay transport cannot widen existing profiles or reach unrelated mutation routes', async () => {
  const t = new Transport({ href, pageSuffix: '/ui/replay/', cryptoImpl: crypto, fetchImpl: () => { throw new Error('must not send'); } }); await t.connect(token);
  for (const path of ['source/prepare', 'source/branches/delete', 'source/tags/delete', 'source/bundle/import', 'pulls/1/merge', 'source/cherry-pick/prepare?force=true']) {
    await assert.rejects(t.request(path, { method: 'POST', body: 'x=1' }), /route/);
  }
  for (const [path, options] of [['source/apply', { method: 'POST', body: 'x' }], ['source/revert/prepare', { method: 'POST', body: 'x', key: 'write' }], ['outcomes', { method: 'POST', key: 'key', read: false, body: 'mutation' }]]) await assert.rejects(t.request(path, options), /profile/);
  for (const suffix of ['/ui/source/', '/ui/pulls/', '/ui/initial/', '/ui/branches/', '/ui/tags/', '/ui/search/', '/ui/transfers/']) {
    const other = new Transport({ href: href.replace('/ui/replay/', suffix), pageSuffix: suffix, cryptoImpl: crypto }); await other.connect(token);
    await assert.rejects(other.request('source/revert/prepare', { method: 'POST', body: 'x=1' }));
  }
});
