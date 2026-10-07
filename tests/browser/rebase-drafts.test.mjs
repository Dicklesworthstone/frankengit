// Draft persistence exercises the real browser client/codec with the existing
// explicitly synthetic HTTP fixture. It does not execute the native Rust engine.
import test from 'node:test';
import assert from 'node:assert/strict';
import { RebaseClient, DRAFT_BYTES } from '../../crates/fgit-node/src/smart_http/server/browser/rebase.mjs';
import { FILE_BYTES, RESOLUTION_BYTES } from '../../crates/fgit-node/src/smart_http/server/browser/rebase-data.mjs';
import { utf8 } from '../../crates/fgit-node/src/smart_http/server/browser/pulls-core.mjs';
import { digest } from '../../crates/fgit-node/src/smart_http/server/browser/pulls-candidate.mjs';
import { fixture, token, href, crypto } from './rebase-session-fixtures.mjs';

async function client(f, options = {}) {
  const c = new RebaseClient({ href, cryptoImpl: crypto, fetchImpl: f.fetchImpl, ...options });
  await c.connect(token); return c;
}
async function setup(algorithm = 'sha1') {
  const f = await fixture(algorithm), c = await client(f);
  await c.select(f.command.source_ref, f.command.onto_ref, algorithm);
  return { f, c };
}
async function saved(algorithm = 'sha1', binary = false) {
  const { f, c } = await setup(algorithm);
  if (binary) {
    f.config.sequence = [f.stopped(0), f.stopped(1)];
    await c.prepare(f.input);
    await c.resolve([{ path_hex: f.conflict(0).path_hex, choice: 'file', mode: 0o100755, bytes: new Uint8Array([0, 255, 13, 10]) }]);
  } else await c.prepare(f.input);
  return { f, c, draft: await c.exportDraft() };
}
// Deliberately recompute the UNSIGNED checksum: semantic validation must still
// reject invalid input, rather than treating a checksum as authorization.
async function rewrite(draft, edit, envelope = () => {}) {
  const outer = JSON.parse(draft), data = JSON.parse(outer.payload);
  edit(data); outer.payload = JSON.stringify(data); envelope(outer);
  outer.sha256 = await digest(utf8.encode(JSON.stringify([outer.schema, outer.origin, outer.route, outer.payload])), crypto);
  return JSON.stringify(outer);
}
const noWrites = f => assert(!f.calls.some(c => c.endpoint.endsWith('/apply') || c.endpoint === 'outcomes'));
const readCalls = f => f.calls.map(c => c.endpoint);

for (const algorithm of ['sha1', 'sha256']) {
  test(`${algorithm}: restore is local, resume reauthenticates both exact roots before native inspection`, async () => {
    const { f, c, draft } = await saved(algorithm), selection = c.selection, command = c.state.command;
    assert(!draft.includes(token));
    const data = JSON.parse(JSON.parse(draft).payload);
    assert.deepEqual(Object.keys(data), ['selection', 'input', 'recipes']);
    for (const k of ['candidate', 'bundle', 'key', 'fingerprint', 'report', 'inspection']) assert(!(k in data));
    const fresh = await client(f); f.calls.length = 0;
    await fresh.restoreDraft(draft);
    assert.deepEqual(readCalls(f), []); assert.deepEqual(fresh.selection, selection);
    assert.deepEqual(fresh.state.command, command); assert.equal(fresh.state.resumeRequired, true);
    assert.equal(fresh.report, null); assert.equal(fresh.candidate, null); assert.equal(fresh.pending, null);
    await assert.rejects(fresh.stage(), /inspection/);
    await assert.rejects(fresh.prepare(f.input), /Resume/);
    await fresh.resumeDraft();
    assert.deepEqual(readCalls(f), ['source/tree', 'source/tree', 'source/rebase/prepare', 'source/rebase/inspect']);
    for (const call of f.calls.slice(0, 2)) assert.equal(call.command.get('expected_head'), selection.head);
    assert.deepEqual(fresh.state.command, command); assert.equal(fresh.state.resumeRequired, false);
    assert.equal(fresh.candidate.sha256, c.candidate.sha256);
    await fresh.stage(); assert(fresh.pending); assert.equal(fresh.pending.sent, false); noWrites(f);
    c.disconnect(); fresh.disconnect();
  });
  test(`${algorithm}: successive binary/empty resolutions keep original commit and byte path bindings`, async () => {
    const { f, c } = await setup(algorithm);
    f.config.sequence = [f.stopped(0), f.stopped(1)]; await c.prepare(f.input);
    const bytes = Uint8Array.from({ length: 256 }, (_, i) => i);
    await c.resolve([{ path_hex: f.conflict(0).path_hex, choice: 'file', mode: 0o100755, bytes }]);
    const draft = await c.exportDraft([{ path_hex: f.conflict(1).path_hex, choice: 'file', mode: 0o100644, bytes: new Uint8Array() }]);
    // Saving current choices does not submit or alter the live stopped session.
    assert.equal(c.state.resolutionPaths, 1); assert.equal(c.report.state, 'conflicted');
    const fresh = await client(f); f.calls.length = 0; await fresh.restoreDraft(draft);
    assert.equal(fresh.state.resolutionPaths, 2); assert.deepEqual(fresh.state.resolutionCommits, f.original);
    await fresh.resumeDraft(); const call = f.calls.find(c => c.endpoint === 'source/rebase/resolve');
    assert.deepEqual(call.files.get('file_0'), bytes); assert.equal(call.files.get('file_1').length, 0);
    assert.deepEqual(call.command.getAll('resolution'), [
      `${f.original[0]}:${f.conflict(0).path_hex}:file:100755:file_0`,
      `${f.original[1]}:${f.conflict(1).path_hex}:file:100644:file_1`]);
    assert.equal(fresh.candidate.metadata.resolution_consumed_commits, 2); noWrites(f);
    c.disconnect(); fresh.disconnect();
  });
  for (const choice of ['base', 'ours', 'theirs', 'delete']) {
    test(`${algorithm}: saved ${choice} choice retains its exact native result`, async () => {
      const { f, c } = await setup(algorithm); f.config.sequence = [f.stopped(0)]; await c.prepare(f.input);
      const draft = await c.exportDraft([{ path_hex: f.conflict(0).path_hex, choice }]);
      const fresh = await client(f); await fresh.restoreDraft(draft); await fresh.resumeDraft();
      const receipt = fresh.candidate.metadata.resolutions[0].paths[0];
      assert.equal(receipt.choice, choice); assert.deepEqual(receipt.result, choice === 'delete' ? null : f.conflict(0)[choice]);
      noWrites(f); c.disconnect(); fresh.disconnect();
    });
  }
  test(`${algorithm}: a different scoped credential can resume reads, but does not inherit publication`, async () => {
    const { f, c, draft } = await saved(algorithm);
    const fresh = await client(f); await fresh.connect('8'.repeat(64)); f.calls.length = 0;
    await fresh.restoreDraft(draft); await fresh.resumeDraft();
    assert(f.calls.every(call => new Headers(call.options.headers).get('Authorization') === `Bearer ${'8'.repeat(64)}`));
    assert(f.calls.every(call => !new Headers(call.options.headers).has('Idempotency-Key')));
    assert.equal(fresh.pending, null); noWrites(f); c.disconnect(); fresh.disconnect();
  });
  test(`${algorithm}: resumed publication still retains its original key on a lost reply`, async () => {
    const { f, c, draft } = await saved(algorithm), fresh = await client(f);
    await fresh.restoreDraft(draft); await fresh.resumeDraft(); await fresh.stage();
    const key = fresh.pending.key; f.config.lose = true; await assert.rejects(fresh.send(), /lost/);
    const pending = fresh.pending, count = f.calls.length;
    await assert.rejects(fresh.exportDraft(), /saved rebase publication/);
    await assert.rejects(fresh.restoreDraft(draft), /saved rebase publication/);
    await assert.rejects(fresh.resumeDraft(), /saved rebase publication/);
    assert.equal(f.calls.length, count); assert.deepEqual(fresh.pending, pending);
    const receipt = fresh.exportReceipt(); const recoverer = await client(f); await recoverer.restoreReceipt(receipt);
    f.config.outcome = 'committed'; await recoverer.recover();
    const last = f.calls.at(-1); assert.equal(last.endpoint, 'outcomes'); assert.equal(last.options.body, undefined);
    assert.equal(new Headers(last.options.headers).get('Idempotency-Key'), key);
    assert.equal(recoverer.pending, null); c.disconnect(); fresh.disconnect(); recoverer.disconnect();
  });
}

const corruptions = {
  'unknown input / force': d => { d.input.force = true; },
  'unknown payload / candidate': d => { d.candidate = {}; },
  'missing input limit': d => { delete d.input.max_commits; },
  'widened input limit': d => { d.input.max_commits = 33; },
  'unsafe timestamp': d => { d.input.timestamp = Number.MAX_SAFE_INTEGER + 1; },
  'header injection': d => { d.input.committer = 'A <a>\nparent stolen'; },
  'unknown empty policy': d => { d.input.empty = 'automatic'; },
  'invalid snapshot': d => { d.selection.head = 'latest'; },
  'same branch': d => { d.selection.onto.ref = d.selection.source.ref; },
  'wrong hash width': d => { d.selection.source.commit = 'a'.repeat(64); },
  'zero root': d => { d.selection.source.tree = '0'.repeat(40); },
  'scope capability injection': d => { d.selection.scope.principal = 'administrator'; },
  'duplicate original': d => { d.recipes.push(structuredClone(d.recipes[0])); },
  'upstream as original': d => { d.recipes[0].original = d.input.upstream; },
  'missing conflict list': d => { d.recipes[0].paths = []; },
  'duplicate path': d => { d.recipes[0].paths.push(structuredClone(d.recipes[0].paths[0])); },
  'unsafe path': d => { d.recipes[0].paths[0].conflict.path_hex = '2e6769742f636f6e666967'; },
  'invalid choice': d => { d.recipes[0].paths[0].choice = 'auto'; },
  'invalid file mode': d => { d.recipes[0].paths[0].mode = 0o120000; },
  'odd hex bytes': d => { d.recipes[0].paths[0].bytes_hex = '0'; },
  'oversize file': d => { d.recipes[0].paths[0].bytes_hex = '00'.repeat(FILE_BYTES + 1); },
  'untrusted result': d => { d.recipes[0].paths[0].result = { oid: 'a'.repeat(40), mode: 0o100644 }; },
  'unknown conflict': d => { d.recipes[0].paths[0].conflict.kind = 'clean'; },
  'invalid side identity': d => { d.recipes[0].paths[0].conflict.base.oid = '0'.repeat(40); },
  'file bytes attached to side': d => { d.recipes[0].paths[0].choice = 'ours'; },
  'absent side': d => { const p = d.recipes[0].paths[0]; delete p.bytes_hex; delete p.mode; p.choice = 'ours'; p.conflict.ours = null; },
  'nonadjacent ancestor path': d => {
    const p = d.recipes[0].paths[0]; d.recipes[0].paths = ['a', 'a-else', 'a/b'].map(name => ({ ...p,
      conflict: { ...p.conflict, path_hex: Buffer.from(name).toString('hex') } }));
  },
  'aggregate bytes': d => { const p = d.recipes[0].paths[0]; d.recipes[0].paths = [1, 2, 3, 4].map(n => ({ ...p,
    bytes_hex: '00'.repeat(FILE_BYTES), conflict: { ...p.conflict, path_hex: Buffer.from(`file${n}`).toString('hex') } })); },
  'aggregate choices': d => { const p = d.recipes[0].paths[0]; d.recipes[0].paths = Array.from({ length: 65 }, (_, n) => ({ ...p,
    conflict: { ...p.conflict, path_hex: Buffer.from(`f${n.toString().padStart(3, '0')}`).toString('hex') } })); },
};
for (const [name, edit] of Object.entries(corruptions)) test(`refuse ${name} even with a recomputed checksum, without replacing existing work`, async () => {
  const { f, c, draft } = await saved('sha1', true); const before = c.state, count = f.calls.length;
  await assert.rejects(c.restoreDraft(await rewrite(draft, edit)));
  assert.equal(f.calls.length, count); assert.deepEqual(c.state, before); c.disconnect();
});
for (const [name, edit] of Object.entries({
  origin: r => { r.origin = 'https://attacker.invalid'; }, route: r => { r.route = '/other.git'; },
  schema: r => { r.schema = 'frankengit-rebase-retry-v1'; }, extra: r => { r.token = token; },
})) test(`draft ${name} cannot select another network scope or operation`, async () => {
  const { f, c, draft } = await saved(); const count = f.calls.length;
  await assert.rejects(c.restoreDraft(await rewrite(draft, () => {}, edit)));
  assert.equal(f.calls.length, count); c.disconnect();
});
test('checksum changes, truncation, duplicate keys and oversized drafts refuse locally', async () => {
  const { f, c, draft } = await saved(); const count = f.calls.length;
  for (const bad of [draft.slice(0, -1), draft.replace('refs/heads/topic', 'refs/heads/other'), ' '.repeat(DRAFT_BYTES + 1),
    draft.replace('{"schema":', '{"schema":"duplicate","schema":'), draft + '\n']) await assert.rejects(c.restoreDraft(bad));
  assert.equal(f.calls.length, count); c.disconnect();
});
for (const side of ['source', 'onto']) for (const field of ['commit', 'tree', 'snapshot', 'scope']) {
  test(`${side} ${field} changed: resume refuses before uploading saved file contents`, async () => {
    const { f, c, draft } = await saved('sha1', true), fresh = await client(f);
    await fresh.restoreDraft(draft); f.calls.length = 0;
    f.config.root = r => {
      if ((r.ref === f.command.source_ref) !== (side === 'source')) return;
      if (field === 'commit') r.source_commit = f.id(99);
      if (field === 'tree') r.root_tree = r.object_id = f.id(99);
      if (field === 'snapshot') r.snapshot_token = `alg:2:${'5'.repeat(64)}`;
      if (field === 'scope') r.repository_incarnation = '6'.repeat(32);
    };
    await assert.rejects(fresh.resumeDraft()); assert(f.calls.every(call => call.endpoint === 'source/tree'));
    assert.equal(fresh.state.resumeRequired, true); assert.equal(fresh.candidate, null);
    f.config.root = null; await fresh.resumeDraft(); assert(fresh.candidate); noWrites(f);
    c.disconnect(); fresh.disconnect();
  });
}
test('native conflict revalidation rejects a forged saved basis even with valid file checksum', async () => {
  const { f, c, draft } = await saved('sha1', true), fresh = await client(f);
  await fresh.restoreDraft(await rewrite(draft, d => { d.recipes[0].paths[0].conflict.base.oid = f.id(99); }));
  await assert.rejects(fresh.resumeDraft(), /requested side/);
  assert.equal(fresh.candidate, null); assert.equal(fresh.state.resumeRequired, true); noWrites(f);
  c.disconnect(); fresh.disconnect();
});
test('failed candidate inspection retains the draft but cannot authorize publication', async () => {
  const { f, c, draft } = await saved(), fresh = await client(f);
  await fresh.restoreDraft(draft); f.config.inspect = r => { r.commits[0].body_hex += 'ff'; };
  await assert.rejects(fresh.resumeDraft(), /hash mismatch/); await assert.rejects(fresh.stage(), /inspection/);
  assert.equal(fresh.state.resumeRequired, true); assert.equal(await fresh.exportDraft(), draft);
  f.config.inspect = null; await fresh.resumeDraft(); assert(fresh.candidate); c.disconnect(); fresh.disconnect();
});
for (const action of ['cancel', 'disconnect']) test(`${action} during resume cannot resurrect a candidate`, async () => {
  const { f, c, draft } = await saved(), fresh = await client(f); await fresh.restoreDraft(draft);
  let release, entered; const wait = new Promise(r => { release = r; }); const begun = new Promise(r => { entered = r; });
  f.config.wait = async () => { entered(); await wait; };
  const operation = fresh.resumeDraft(); await begun; fresh[action](); release(); await assert.rejects(operation);
  assert.equal(fresh.candidate, null); assert.equal(fresh.pending, null);
  if (action === 'cancel') assert.equal(fresh.state.resumeRequired, true);
  else { assert.equal(fresh.selection, null); assert.equal(fresh.state.resolutionPaths, 0); }
  noWrites(f); c.disconnect(); fresh.disconnect();
});
test('the whole resume shares one deadline, including both root checks', async () => {
  const { f, c, draft } = await saved(), fresh = await client(f, { operationTimeoutMs: 100 });
  await fresh.restoreDraft(draft);
  f.config.wait = () => new Promise(r => setTimeout(r, 150));
  await assert.rejects(fresh.resumeDraft()); assert.equal(fresh.state.resumeRequired, true); assert.equal(fresh.candidate, null);
  noWrites(f); c.disconnect(); fresh.disconnect();
});
test('saved choices are detached from later editor mutation and never submit during export', async () => {
  const { f, c } = await setup(); f.config.sequence = [f.stopped(0)]; await c.prepare(f.input);
  const bytes = new Uint8Array([0, 255]), choices = [{ path_hex: f.conflict(0).path_hex, choice: 'file', mode: 0o100755, bytes }];
  const count = f.calls.length, exporting = c.exportDraft(choices); bytes.fill(42); choices[0].mode = 0o100644;
  const draft = await exporting, p = JSON.parse(JSON.parse(draft).payload).recipes[0].paths[0];
  assert.equal(p.bytes_hex, '00ff'); assert.equal(p.mode, 0o100755); assert.equal(f.calls.length, count);
  assert.equal(c.state.resolutionPaths, 0); c.disconnect();
});
test('a fresh client cannot save absent work or resume an unimported session', async () => {
  const f = await fixture(), c = await client(f);
  await assert.rejects(c.exportDraft(), /Prepare/); await assert.rejects(c.resumeDraft(), /Load/); noWrites(f); c.disconnect();
});
test('maximum-size binary file preserves its bytes and resource accounting', async () => {
  const { f, c } = await setup(); f.config.sequence = [f.stopped(0)]; await c.prepare(f.input);
  const bytes = new Uint8Array(FILE_BYTES); const draft = await c.exportDraft([{path_hex:f.conflict(0).path_hex,choice:'file',mode:0o100755,bytes}]);
  const fresh = await client(f); await fresh.restoreDraft(draft);
  assert.equal(fresh.state.resolutionBytes, FILE_BYTES + f.conflict(0).path_hex.length / 2);
  assert(fresh.state.resolutionBytes <= RESOLUTION_BYTES); await fresh.resumeDraft(); assert(fresh.candidate);
  c.disconnect(); fresh.disconnect();
});
