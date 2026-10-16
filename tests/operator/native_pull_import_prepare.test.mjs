import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile, writeFile, rm, readdir, mkdir, stat } from 'node:fs/promises';
import { join } from 'node:path';
import { preparePullImport, inspectPullImport, loadPullImport, importSlot } from '../../scripts/lib/native-pull-import.mjs';
import { readPullImportSource } from '../../scripts/lib/native-pull-import-source.mjs';
import { compilePullImport } from '../../scripts/lib/native-pull-import-plan.mjs';
import { lifetime, digest, encode } from '../../scripts/lib/forge-pull-archive-store.mjs';
import { submitPull } from '../../scripts/operator/remote_pull.mjs';
import { importFixture, row, TOKEN, SRC } from './native-pull-import-fixture.mjs';

for (const format of ['sha1', 'sha256']) test(`archive to native publication with full production modules: ${format}`, async t => {
  const f = await importFixture(t, { format }), before = f.requests.length;
  const prepared = await preparePullImport(f.prepare); assert.equal(f.requests.length, before); assert.equal(prepared.steps, 11);
  assert.deepEqual(prepared.mapping.map(r => [r.source, r.destination]), [[1, '100'], [9, '101']]);
  await rm(f.archiveDir, { recursive: true });
  const life = lifetime({}); t.after(() => life.close());
  const loaded = await loadPullImport(f.workdir, prepared.plan_sha256, life, true);
  for (const intent of loaded.intents) {
    const result = await submitPull(intent, TOKEN, { confirmKey: intent.key }); assert.equal(result.outcome.state, 'committed');
    assert.equal(intent.scope.principal_id, f.scope.principal_id);
  }
  assert.equal(f.pulls.get('100').fields.title, f.rows[0].data.title); assert.equal(f.pulls.get('100').fields.body, f.rows[0].data.body);
  assert.equal(f.pulls.get('101').state, 'closed'); assert.equal(f.pulls.get('100').comments.length, 4);
  assert(f.pulls.get('100').comments[3].includes('"decision":"approve"'));
  assert(!f.requests.some(r => /\/reviews|\/merge|fast-forward/.test(r.path) && r.method === 'POST'));
  const inspected = await inspectPullImport({ workdir: f.workdir, confirm: prepared.plan_sha256 }); assert.equal(inspected.steps, 11);
});
test('closed import of merged PRs requires explicit consent and never creates a merge request', async t => {
  const f = await importFixture(t, { rows: [row(2, 'sha1', 'merged')] });
  await assert.rejects(preparePullImport(f.prepare), /merged_requires_closed_consent/);
  assert(!(await readdir(f.root)).includes('migration'));
  const p = await preparePullImport({ ...f.prepare, selection: { ...f.selection, merged: 'as-closed' } });
  assert.equal(p.mapping[0].destination_state, 'closed');
  const life = lifetime({}); t.after(() => life.close()); const loaded = await loadPullImport(f.workdir, p.plan_sha256, life);
  assert.deepEqual(loaded.intents.map(i => i.action), ['open', 'comment', 'comment', 'comment', 'comment', 'close']);
  assert(loaded.intents[1].fields.body.includes('merge_commit'));
});
test('full width destination u64 identity does not round', async t => {
  const f = await importFixture(t), selection = { ...f.selection, number_start: '18446744073709551614' };
  const p = await preparePullImport({ ...f.prepare, selection });
  assert.deepEqual(p.mapping.map(r => r.destination), ['18446744073709551614', '18446744073709551615']);
  const life = lifetime({}); t.after(() => life.close());
  const l = await loadPullImport(f.workdir, p.plan_sha256, life);
  assert.equal((await submitPull(l.intents[0], TOKEN, { confirmKey: l.intents[0].key })).outcome.state, 'committed');
});
test('byte-only source branches require a lossless explicit destination mapping', async t => {
  const r = row(1); r.data.source_ref = null; r.data.source_ref_hex = Buffer.from('refs/heads/').toString('hex') + 'ff';
  const f = await importFixture(t, { rows: [r] });
  await assert.rejects(preparePullImport(f.prepare), /byte_only_ref_needs_mapping/);
  const p = await preparePullImport({ ...f.prepare, selection: { ...f.selection, ref_map: [{ source_hex: r.data.source_ref_hex, destination: 'refs/heads/imported' }] } });
  const intent = JSON.parse(await readFile(join(f.workdir, 'requests', importSlot(0), 'intent.json')));
  assert.equal(intent.fields.source_ref, 'refs/heads/imported'); assert.equal(p.steps, 5);
});
for (const [name, alter, pattern] of [
  ['cross hash domains', s => { s.scope.object_format = 'sha256'; }, /hash_domain_change/],
  ['same repository', s => { Object.assign(s.scope, SRC); }, /same_repository/],
  ['number overflow', s => { s.number_start = '18446744073709551615'; }, /u64/],
  ['unused ref map', s => { s.ref_map = [{ source_hex: Buffer.from('refs/heads/unused').toString('hex'), destination: 'refs/heads/new' }]; }, /unused_ref_mapping/],
  ['ref alias', s => { s.ref_map = [{ source_hex: Buffer.from('refs/heads/topic-1').toString('hex'), destination: 'refs/heads/main' }]; }, /ref_mapping_alias/],
  ['step cap', s => { s.max_steps = 4; }, /step_limit/],
  ['request byte cap', s => { s.max_request_bytes = 10; }, /request_limit/],
  ['source byte cap', s => { s.max_source_bytes = 10; }, /source_limit/],
  ['unknown grants', s => { s.approvals = true; }, /invalid_pull_fields/],
]) test(`whole-source preflight refuses ${name} before creating a key slot`, async t => {
  const f = await importFixture(t), selection = structuredClone(f.selection); alter(selection); const before = f.requests.length;
  await assert.rejects(preparePullImport({ ...f.prepare, selection }), pattern);
  assert.equal(f.requests.length, before); assert(!(await readdir(f.root)).includes('migration'));
});
test('metadata-less legacy merge refuses rather than inventing a title or successful prefix', async t => {
  const r = row(9, 'sha1', 'merged'); r.data = null; r.merge_only = true;
  const f = await importFixture(t, { rows: [row(1), r] });
  await assert.rejects(preparePullImport({ ...f.prepare, selection: { ...f.selection, merged: 'as-closed' } }), /merge_only_metadata/);
  assert(!(await readdir(f.root)).includes('migration'));
});
test('long multilingual review and comment bodies split at exact byte boundaries', async t => {
  const body = '\ufeff' + '😀\r\n'.repeat(9000) + 'END';
  const f = await importFixture(t, { rows: [row(1)], comments: 1, reviews: 1, modify: (reply, kind) => {
    if (kind === 'comments') reply.comments[0].body = body;
    if (kind === 'reviews') reply.reviews[0].reason = body;
  } });
  const source = await readPullImportSource({ workdir: f.archiveDir, confirm: f.archiveConfirm });
  const plan = compilePullImport(source, f.selection);
  const comments = plan.steps.filter(s => s.action === 'comment').slice(1);
  for (const kind of ['comment', 'review']) {
    const parts = comments.filter(s => s.fields.body.startsWith(`Imported ${kind} observation`));
    assert.equal(parts.length, 2); assert.equal(parts.map(s => s.fields.body.slice(s.fields.body.indexOf('\n\n') + 2)).join(''), body);
    assert(parts.every(s => Buffer.byteLength(s.fields.body) <= 65536));
  }
});
test('retained source bytes and every native intent are authenticated offline', async t => {
  const f = await importFixture(t), p = await preparePullImport(f.prepare);
  const file = join(f.workdir, 'requests', importSlot(1), 'intent.json'), original = await readFile(file);
  const intent = JSON.parse(original); intent.fields.body = 'changed'; await writeFile(file, JSON.stringify(intent));
  await assert.rejects(inspectPullImport({ workdir: f.workdir, confirm: p.plan_sha256 }));
  await writeFile(file, original);
  const page = join(f.workdir, 'archive', 'page-000001.json'); const v = JSON.parse(await readFile(page)); v.pull_requests[0].data.body += 'changed'; await writeFile(page, encode(v));
  await assert.rejects(inspectPullImport({ workdir: f.workdir, confirm: p.plan_sha256 }), /page_commitment/);
});
test('recalculated request hash cannot change the compiler-selected action', async t => {
  const f = await importFixture(t), p = await preparePullImport(f.prepare);
  const file = join(f.workdir, 'manifest.json'), m = JSON.parse(await readFile(file)); m.steps_sha256 = '0'.repeat(64);
  await writeFile(file, encode(m)); await assert.rejects(inspectPullImport({ workdir: f.workdir, confirm: digest(encode(m)) }), /plan_changed/);
});
test('pre-cancelled preparation and bad source pins publish nothing', async t => {
  const f = await importFixture(t), c = new AbortController(); c.abort();
  await assert.rejects(preparePullImport({ ...f.prepare, signal: c.signal }));
  await assert.rejects(preparePullImport({ ...f.prepare, archiveConfirm: '0'.repeat(64) }), /pin_mismatch/);
  assert(!(await readdir(f.root)).includes('migration'));
});
test('competing preparers cannot overwrite an established migration', async t => {
  const f = await importFixture(t); const results = await Promise.allSettled([preparePullImport(f.prepare), preparePullImport(f.prepare)]);
  assert.equal(results.filter(r => r.status === 'fulfilled').length, 1);
  const p = results.find(r => r.status === 'fulfilled').value;
  assert.equal((await inspectPullImport({ workdir: f.workdir, confirm: p.plan_sha256 })).steps, p.steps);
  for (const name of ['manifest.json', 'requests/step-000001/intent.json']) assert.equal((await stat(join(f.workdir, name))).mode & 0o777, 0o600);
});
test('empty archive prepares a complete zero-operation plan', async t => {
  const f = await importFixture(t, { rows: [] }); const p = await preparePullImport(f.prepare); assert.equal(p.steps, 0); assert.deepEqual(p.mapping, []);
});

test('historical PRs with different bases need explicit per-PR destination branches', async t => {
  const later = row(9, 'sha1', 'closed'); later.data.target_tip = 'sha1:' + 'c'.repeat(40);
  const f = await importFixture(t, { rows: [row(1), later] }); const before = f.requests.length;
  await assert.rejects(preparePullImport(f.prepare), /destination_ref_tip_conflict/);
  assert.equal(f.requests.length, before); assert(!(await readdir(f.root)).includes('migration'));
  const target_ref = 'refs/heads/import/pr-9/base';
  const p = await preparePullImport({ ...f.prepare, selection: { ...f.selection,
    pull_ref_map: [{ source_number: '9', source_ref: later.data.source_ref, target_ref }] } });
  // Provision the separately selected immutable base in the response peer. The
  // importer itself must not move or create refs, even to make a PR open pass.
  f.refs.set(target_ref, 'c'.repeat(40)); const beforeRefs = Array.from(f.refs);
  const life = lifetime({}); t.after(() => life.close()); const loaded = await loadPullImport(f.workdir, p.plan_sha256, life);
  for (const intent of loaded.intents) assert.equal((await submitPull(intent, TOKEN, { confirmKey: intent.key })).outcome.state, 'committed');
  assert.equal(f.pulls.get('101').fields.target_ref, target_ref); assert.equal(f.pulls.get('101').fields.target_tip, 'c'.repeat(40));
  assert.equal(f.pulls.get('101').state, 'closed'); assert.deepEqual(Array.from(f.refs), beforeRefs);
});
for (const mapping of [
  [{ source_number: '99', source_ref: 'refs/heads/topic', target_ref: 'refs/heads/main' }],
  [{ source_number: '1', source_ref: 'refs/heads/topic', target_ref: 'refs/heads/main' }, { source_number: '1', source_ref: 'refs/heads/other', target_ref: 'refs/heads/main' }],
  [{ source_number: '1', source_ref: 'refs/heads/topic', target_ref: 'refs/heads/main', target_tip: 'd'.repeat(40) }],
]) test('per-PR mappings refuse unused, duplicate or tip-changing selections', async t => {
  const f = await importFixture(t); await assert.rejects(preparePullImport({ ...f.prepare, selection: { ...f.selection, pull_ref_map: mapping } }));
  assert(!(await readdir(f.root)).includes('migration'));
});

test('new basis preflight does not reinterpret retained v1 command compilation', async t => {
  const later = row(9, 'sha1', 'closed'); later.data.target_tip = 'sha1:' + 'c'.repeat(40);
  const f = await importFixture(t, { rows: [row(1), later] });
  const source = await readPullImportSource({ workdir: f.archiveDir, confirm: f.archiveConfirm });
  const retained = compilePullImport(source, f.selection);
  assert(!Object.hasOwn(retained.selection, 'pull_ref_map'));
  const laterOpen = retained.steps.find(s => s.source_number === 9 && s.action === 'open');
  assert.equal(laterOpen.fields.target_ref, 'refs/heads/main'); assert.equal(laterOpen.fields.target_tip, 'c'.repeat(40));
  assert.throws(() => compilePullImport(source, retained.selection, { validateDestinationBasis: true }), /destination_ref_tip_conflict/);
  assert.deepEqual(compilePullImport(source, retained.selection).steps, retained.steps);
});
