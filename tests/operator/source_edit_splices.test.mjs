// Complete production splice/compiler/client modules, installed Git only as a
// nonproduction oracle. HTTP schemas below are NOT a native Rust patch server.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spliceSourceFiles, compileSourceSplices, captureSourceSplices, SPLICE_PROFILE } from '../../scripts/operator/source_edit_splices.mjs';
import { peer, TOKEN, digest } from './source_edit_fixture.mjs';
const bytes = value => Buffer.from(value), hex = value => bytes(value).toString('hex');
const native = (value, format = 'sha1') => createHash(format).update(`blob ${value.length}\0`).update(value).digest('hex');
const edit = (at, before, after) => ({ byte_start: at, before: bytes(before), after: bytes(after) });
const file = (original, edits, format = 'sha1', name = 'file', mode = 0o100644, afterMode = mode) => ({
  path_hex: hex(name), before: { bytes: bytes(original), mode, blob: native(bytes(original), format) }, after_mode: afterMode, edits });
function oracle(format, files, desired, options = {}) {
  const dir = mkdtempSync(join(tmpdir(), 'fg-splice-git-'));
  try {
    const git = (args, input) => execFileSync('git', ['-C', dir, ...args], { input,
      env: { ...process.env, GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: '/dev/null' } });
    git(['init', '--quiet', `--object-format=${format}`]);
    const index = rows => {
      git(['read-tree', '--empty']);
      const entries = [...rows, { path_hex: hex('untouched'), bytes: bytes('untouched\n'), mode: 0o100644 }];
      git(['update-index', '-z', '--index-info'], Buffer.concat(entries.map(row => {
        const oid = git(['hash-object', '-w', '--stdin'], row.bytes).toString().trim();
        return Buffer.concat([bytes(`${row.mode.toString(8)} ${oid}\t`), Buffer.from(row.path_hex, 'hex'), Buffer.from([0])]);
      })));
      return git(['write-tree']).toString().trim();
    };
    const initial = index(files.map(f => ({ path_hex: f.path_hex, ...f.before })));
    const compiled = compileSourceSplices(format, files, options);
    git(['apply', '--cached', '--unidiff-zero', '--check', '-'], compiled.patch);
    git(['apply', '--cached', '--unidiff-zero', '-'], compiled.patch);
    const result = git(['write-tree']).toString().trim();
    git(['apply', '--cached', '--unidiff-zero', '-R', '-'], compiled.patch);
    assert.equal(git(['write-tree']).toString().trim(), initial);
    const wanted = index(files.map((f, i) => ({ path_hex: f.path_hex, bytes: bytes(desired[i]), mode: f.after_mode })));
    assert.equal(result, wanted);
    assert.equal(compiled.splice_profile, SPLICE_PROFILE);
    assert.equal(compiled.source_membership_verified, false);
    assert.equal(compiled.publication_authorized, false);
    return compiled;
  } finally { rmSync(dir, { recursive: true, force: true }); }
}

for (const format of ['sha1', 'sha256']) {
  for (const [label, original, edits, wanted] of [
    ['length-changing edits use original coordinates', 'abcdefghij', [edit(1, 'bc', 'LONG'), edit(7, 'hi', 'Q')], 'aLONGdefgQj'],
    ['insert at beginning and EOF', 'abc', [edit(0, '', '<'), edit(3, '', '>')], '<abc>'],
    ['delete every byte leaves empty file', 'abc', [edit(0, 'abc', '')], ''],
    ['empty existing file accepts insertion', '', [edit(0, '', 'new\n')], 'new\n'],
    ['adjacent ranges are simultaneous', 'abcd', [edit(0, 'ab', 'X'), edit(2, 'cd', 'Y')], 'XY'],
    ['CRLF and missing final LF', 'a\r\nb\r\nlast', [edit(3, 'b', 'BB'), edit(6, 'last', 'tail')], 'a\r\nBB\r\ntail'],
    ['byte coordinates do not assume Unicode', Buffer.from([255, 195, 169, 10]), [edit(1, [195, 169], [254, 253])], Buffer.from([255, 254, 253, 10])],
    ['insertion on preceding range end', 'abc', [edit(0, 'ab', 'X'), edit(2, '', 'Y')], 'XYc'],
  ]) test(`${format}: ${label}`, () => oracle(format, [file(original, edits, format)], [wanted]));
  test(`${format}: raw paths, mode changes and repeated tokens retain exact identities`, () => {
    oracle(format, [file('same same same', [edit(5, 'same', 'middle')], format, Buffer.from([255, 34, 92, 10]), 0o100644, 0o100755),
      file('', [], format, 'empty', 0o100644, 0o100755)], ['same middle same', '']);
  });
  test(`${format}: explicit binary mode preserves forward and reverse byte edits`, () => {
    const rows = [file([0, 1, 2, 3, 255], [edit(1, [1, 2], [0, 254, 253])], format)];
    assert.throws(() => compileSourceSplices(format, rows), /binary/);
    const result = oracle(format, rows, [[0, 0, 254, 253, 3, 255]], { binary: 'literal' });
    assert.equal(result.binary_files, 1);
  });
}

test('caller order cannot create sequential overwrite semantics', () => {
  const a = file('abcdefghij', [edit(7, 'hi', 'Q'), edit(1, 'bc', 'LONG')], 'sha1', 'z');
  const b = file('hello', [edit(5, '', '!')], 'sha1', 'a');
  const first = compileSourceSplices('sha1', [a, b]);
  a.edits.reverse();
  assert.deepEqual(compileSourceSplices('sha1', [b, a]), first);
  const result = spliceSourceFiles('sha1', [a, b]); a.before.bytes.fill(0); a.edits[0].after.fill(0);
  assert.equal(result.changes[1].after.bytes.toString(), 'aLONGdefgQj');
  result.changes[1].before.bytes.fill(0);
  assert.equal(result.changes[1].after.bytes.toString(), 'aLONGdefgQj');
});
for (const [label, edits] of [
  ['overlap', [edit(1, 'bc', 'x'), edit(2, 'cd', 'y')]],
  ['contained range', [edit(0, 'abcd', 'x'), edit(1, 'b', 'y')]],
  ['duplicate insertion', [edit(1, '', 'x'), edit(1, '', 'y')]],
  ['insert and replacement at same start', [edit(1, '', 'x'), edit(1, 'b', 'y')]],
]) test(`${label} refuses rather than choosing an ordering`, () => {
  assert.throws(() => spliceSourceFiles('sha1', [file('abcd', edits)]), /overlap/);
});
for (const [label, mutate] of [
  ['changed complete original', f => { f.before.bytes[0] ^= 1; }],
  ['wrong hash domain', f => { f.before.blob = 'f'.repeat(64); }],
  ['stale excerpt', f => { f.edits[0].before = bytes('zz'); }],
  ['search elsewhere prohibited', f => { f.edits[0].byte_start = 0; }],
  ['out of range', f => { f.edits[0].byte_start = 100; }],
  ['fractional position', f => { f.edits[0].byte_start = 1.5; }],
  ['negative position', f => { f.edits[0].byte_start = -1; }],
  ['NaN position', f => { f.edits[0].byte_start = NaN; }],
  ['unsafe integer position', f => { f.edits[0].byte_start = Number.MAX_SAFE_INTEGER + 1; }],
  ['unknown edit field', f => { f.edits[0].search = true; }],
  ['symlink mode', f => { f.before.mode = 0o120000; }],
  ['gitlink result', f => { f.after_mode = 0o160000; }],
  ['null source is not creation', f => { f.before = null; }],
]) test(`refuse ${label}`, () => {
  const f = file('abcdef', [edit(1, 'bc', 'Q')]); mutate(f);
  assert.throws(() => compileSourceSplices('sha1', [f]));
});
test('empty/no-op instructions and collectively unchanged effects refuse', () => {
  for (const f of [file('abc', []), file('abc', [edit(0, '', '')]), file('abc', [edit(0, 'a', 'a')]),
    file('aa', [edit(0, 'a', ''), edit(2, '', 'a')])]) assert.throws(() => spliceSourceFiles('sha1', [f]), /no_effect/);
});
test('unsafe paths, duplicate files and file/descendant collisions refuse as one operation', () => {
  for (const p of ['', '.git/config', '../x', '/x', 'x//y', 'x\0y']) assert.throws(() => spliceSourceFiles('sha1', [file('a', [edit(0, 'a', 'b')], 'sha1', p)]));
  for (const names of [['a', 'a'], ['a', 'a/b']]) assert.throws(() => spliceSourceFiles('sha1', names.map(p => file('a', [edit(0, 'a', 'b')], 'sha1', p))), /paths/);
});
test('shared source/result/expected/inserted/count budgets have exact permitted twins', () => {
  const rows = [file('abcdef', [edit(1, 'bc', 'XYZ')]), file('abcdef', [edit(1, 'bc', 'XYZ')], 'sha1', 'other')];
  const result = spliceSourceFiles('sha1', rows, { maxSourceBytes: 12, maxResultBytes: 14, maxExpectedBytes: 4, maxInsertedBytes: 6, maxSplices: 2 });
  assert.equal(result.splice_count, 2); assert.equal(result.expected_bytes, 4); assert.equal(result.inserted_bytes, 6);
  for (const limit of [{ maxSourceBytes: 11 }, { maxResultBytes: 13 }, { maxExpectedBytes: 3 }, { maxInsertedBytes: 5 }, { maxSplices: 1 }, { maxSplices: 4097 }, { maxSplices: null }, { maxInsertedBytes: undefined }, { force: true }]) {
    assert.throws(() => spliceSourceFiles('sha1', rows, limit));
  }
  const full = compileSourceSplices('sha1', rows);
  assert.deepEqual(compileSourceSplices('sha1', rows, { maxPatchBytes: full.patch.length }).patch, full.patch);
  assert.throws(() => compileSourceSplices('sha1', rows, { maxPatchBytes: full.patch.length - 1 }));
});
test('4096 edits and 32 files are real whole-inventory ceilings', () => {
  const f = file('a'.repeat(8192), Array.from({ length: 4096 }, (_, i) => edit(i * 2, 'a', 'b')));
  assert.equal(spliceSourceFiles('sha1', [f]).splice_count, 4096);
  f.edits.push(edit(8192, '', 'b')); assert.throws(() => spliceSourceFiles('sha1', [f]), /count/);
  const files = Array.from({ length: 32 }, (_, i) => file('a', [edit(0, 'a', 'b')], 'sha1', `f${i}`));
  assert.equal(spliceSourceFiles('sha1', files).changes.length, 32);
  files.push(file('a', [edit(0, 'a', 'b')], 'sha1', 'extra')); assert.throws(() => spliceSourceFiles('sha1', files), /files/);
});
test('result size is bounded before allocation and calculated from the final simultaneous edits', () => {
  const original = Buffer.alloc(1048576, 65);
  const f = file(original, [edit(0, '', 'x'), edit(1048575, [65], '')]);
  assert.equal(spliceSourceFiles('sha1', [f]).changes[0].after.bytes.length, 1048576);
  f.edits.pop(); assert.throws(() => spliceSourceFiles('sha1', [f]), /result_limit/);
});
test('cancellation and a late-file mismatch never return a successful prefix', () => {
  const rows = [file('abc', [edit(1, 'b', 'Q')]), file('abc', [edit(1, 'X', 'Q')], 'sha1', 'other')];
  assert.throws(() => compileSourceSplices('sha1', rows), /context_mismatch/);
  let calls = 0;
  assert.throws(() => compileSourceSplices('sha1', rows.slice(0, 1), {}, () => { if (++calls === 4) throw new Error('cancel'); }), /cancel/);
});
test('2000 deterministic splice inventories agree with independent right-to-left application', () => {
  let seed = 391;
  const rand = n => { seed = (Math.imul(seed, 1664525) + 1013904223) >>> 0; return seed % n; };
  for (let sample = 0; sample < 2000; sample++) {
    const original = Buffer.from(Array.from({ length: 16 + rand(64) }, () => rand(256)));
    const edits = [];
    for (let at = rand(4); at < original.length; at += 4 + rand(4)) {
      edits.push({ byte_start: at, before: original.subarray(at, at + rand(3)), after: Buffer.from([rand(256), rand(256), rand(256), 9]) });
    }
    let desired = Buffer.from(original);
    for (const e of [...edits].reverse()) desired = Buffer.concat([desired.subarray(0, e.byte_start), e.after, desired.subarray(e.byte_start + e.before.length)]);
    const result = spliceSourceFiles('sha1', [file(original, [...edits].reverse())]);
    assert.deepEqual(result.changes[0].after.bytes, desired);
  }
});

// Real original/candidate objects and bundle; the socket peer reports their
// native schemas but does not claim to run native parsing or repository CAS.
async function acquisition(t, format) {
  const f = await peer(t, format), dir = mkdtempSync(join(tmpdir(), 'fg-splice-peer-'));
  try {
    const git = (args, input) => execFileSync('git', ['-C', dir, ...args], { input,
      env: { ...process.env, GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: '/dev/null' } });
    git(['init', '--quiet', `--object-format=${format}`]);
    const write = (kind, data) => git(['hash-object', '-w', '-t', kind, '--stdin'], data).toString().trim();
    const original = bytes('old\r\n'), desired = bytes('new\r\n'), oldBlob = write('blob', original), newBlob = write('blob', desired);
    const tree = id => write('tree', Buffer.concat([bytes('100644 file\0'), Buffer.from(id, 'hex')]));
    const beforeTree = tree(oldBlob), afterTree = tree(newBlob), m = f.request.metadata;
    const base = write('commit', bytes(`tree ${beforeTree}\nauthor Example <e@example.invalid> 1 +0000\ncommitter Example <e@example.invalid> 1 +0000\n\nbase\n`));
    const body = bytes(`tree ${afterTree}\nparent ${base}\nauthor ${m.author} ${m.timestamp} +0000\ncommitter ${m.committer} ${m.timestamp} +0000\n\n${m.message}`);
    const candidate = write('commit', body); git(['update-ref', 'refs/heads/main', candidate]);
    git(['bundle', 'create', join(dir, 'candidate.bundle'), 'refs/heads/main', `^${base}`]);
    const bundle = readFileSync(join(dir, 'candidate.bundle')), files = [file(original, [edit(0, 'old', 'new')], format)];
    const compiled = compileSourceSplices(format, files), p = f.preparation, i = f.inspection;
    Object.assign(p, { source_commit: base, candidate_commit: candidate, root_tree: afterTree, patch_sha256: digest(compiled.patch), bundle: { bytes: bundle.length, sha256: digest(bundle) } });
    p.paths[0].old_blob = oldBlob; p.paths[0].new_blob = newBlob;
    Object.assign(i, { expected_commit: base, candidate_commit: candidate, parents: [base], bundle_bytes: bundle.length,
      bundle_sha256: digest(bundle), candidate_commit_body_hex: body.toString('hex') });
    Object.assign(i.comparison, { before_tree: beforeTree, after_tree: afterTree });
    const row = i.comparison.entries[0];
    Object.assign(row, { kind: 'modified', before: { mode: 0o100644, oid: oldBlob }, after: { mode: 0o100644, oid: newBlob } });
    row.content = { type: 'text', algorithm: 'Myers', additions: 1, deletions: 1, before_bytes: original.length, after_bytes: desired.length,
      hunks: [{ old: { byte_start: 0, byte_end: original.length, line_start: 0, line_count: 1 }, new: { byte_start: 0, byte_end: desired.length, line_start: 0, line_count: 1 },
        before_hex: original.toString('hex'), after_hex: desired.toString('hex') }] };
    const selection = { ...f.request, expected_commit: base, expected_result_tree: afterTree };
    f.control.handler = async (_req, res, call) => {
      const reply = structuredClone(call.operation === 'prepare' ? p : i); await f.control.mutate?.(reply, call);
      const response = call.operation === 'prepare' ? f.frame(reply, bundle) : { type: 'application/json', bytes: bytes(JSON.stringify(reply)) };
      res.writeHead(200, { 'Content-Type': response.type }); res.end(response.bytes);
    };
    return { ...f, selection, files, compiled, candidate, bundle };
  } finally { rmSync(dir, { recursive: true, force: true }); }
}
for (const format of ['sha1', 'sha256']) test(`${format}: real sockets acquire exact spliced candidate through unchanged preparation/inspection`, async t => {
  const f = await acquisition(t, format), result = await captureSourceSplices(f.selection, f.files, TOKEN);
  assert.equal(result.candidate_commit, f.candidate); assert.equal(result.splice_count, 1);
  assert.equal(result.preimages_verified, true); assert.equal(result.publication_authorized, false);
  assert.deepEqual(result.bundle, f.bundle); assert.equal(result.capture.patch_sha256, digest(f.compiled.patch));
  assert.deepEqual(f.calls.map(c => c.operation), ['prepare', 'inspect']);
  assert.ok(f.calls.every(c => c.headers['idempotency-key'] === undefined));
});
test('every original/span/root/scope check precedes any connection', async t => {
  const f = await acquisition(t, 'sha1');
  const invalid = structuredClone(f.files); invalid[0].edits[0].before[0] ^= 1;
  await assert.rejects(captureSourceSplices(f.selection, invalid, TOKEN), /context_mismatch/);
  const noRoot = { ...f.selection }; delete noRoot.expected_result_tree;
  await assert.rejects(captureSourceSplices(noRoot, f.files, TOKEN), /result_required/);
  await assert.rejects(captureSourceSplices({ ...f.selection, paths_hex: [hex('other')] }, f.files, TOKEN), /paths/);
  const stop = new AbortController(); stop.abort();
  await assert.rejects(captureSourceSplices(f.selection, f.files, TOKEN, { signal: stop.signal }), /cancelled/);
  assert.equal(f.calls.length, 0);
});
test('caller mutation after invocation cannot substitute offsets, source or inserted bytes', async t => {
  const f = await acquisition(t, 'sha256'), selection = structuredClone(f.selection), files = structuredClone(f.files);
  const pending = captureSourceSplices(selection, files, TOKEN);
  files[0].before.bytes.fill(0); files[0].edits[0].after.fill(0); files[0].edits[0].byte_start = 999;
  selection.expected_result_tree = 'f'.repeat(64);
  assert.equal((await pending).candidate_commit, f.candidate);
  assert.ok(f.calls[0].body.includes(f.compiled.patch));
});
test('shared response allowance has an exact permitted twin and no retry', async t => {
  const f = await acquisition(t, 'sha1'), full = await captureSourceSplices(f.selection, f.files, TOKEN);
  const maxWireBytes = full.metrics.response_bytes;
  await captureSourceSplices(f.selection, f.files, TOKEN, { maxWireBytes });
  await assert.rejects(captureSourceSplices(f.selection, f.files, TOKEN, { maxWireBytes: maxWireBytes - 1 }));
  assert.equal(f.calls.length, 6);
});
test('returned wrong result is refused at preparation, never replaced or inspected', async t => {
  const f = await acquisition(t, 'sha1'); f.control.mutate = r => { r.root_tree = 'f'.repeat(40); };
  await assert.rejects(captureSourceSplices(f.selection, f.files, TOKEN), /result_tree_mismatch/);
  assert.deepEqual(f.calls.map(c => c.operation), ['prepare']);
});

for (const format of ['sha1', 'sha256']) test(`${format}: large binary splices retain explicit delta support and bounded reversible output`, () => {
  const original = Buffer.alloc(800000, 97); original[0] = 0;
  const desired = Buffer.from(original); desired[400000] = 255;
  const files = [file(original, [edit(400000, [97], [255])], format)];
  // Whole forward/reverse literals cannot fit; do not enlarge that allowance.
  assert.throws(() => compileSourceSplices(format, files, { binary: 'literal' }), /patch_limit/);
  const result = oracle(format, files, [desired], { binary: 'delta' });
  assert.equal(result.profile, 'frankengit-source-replacements-delta-v1');
  assert.equal(result.binary_files, 1); assert.equal(result.delta_members, 2);
  assert.equal(result.literal_members, 0); assert.ok(result.patch.length < 1024);
  assert.deepEqual(compileSourceSplices(format, files,
    { binary: 'delta', maxPatchBytes: result.patch.length }).patch, result.patch);
  assert.throws(() => compileSourceSplices(format, files,
    { binary: 'delta', maxPatchBytes: result.patch.length - 1 }), /patch_limit/);
});
