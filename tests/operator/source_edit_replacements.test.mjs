// Full production compiler/acquisition and installed Git as nonproduction oracle.
// HTTP peers expose response schemas; they do not execute native Rust patches.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { compileSourceReplacements, captureSourceReplacements, REPLACEMENT_PROFILE } from '../../scripts/operator/source_edit_replacements.mjs';
import { peer, TOKEN, digest } from './source_edit_fixture.mjs';
const hex = value => Buffer.from(value).toString('hex');
const hash = (bytes, format) => createHash(format).update(`blob ${bytes.length}\0`).update(bytes).digest('hex');
function change(format, name, old, next, oldMode = 0o100644, newMode = 0o100644) {
  const before = old === null ? null : { mode: oldMode, bytes: Buffer.from(old), blob: hash(Buffer.from(old), format) };
  const after = next === null ? null : { mode: newMode, bytes: Buffer.from(next) };
  return { path_hex: hex(name), before, after };
}
function oracle(format, changes) {
  const root = mkdtempSync(join(tmpdir(), 'fg-replacement-git-'));
  try {
    const git = (args, input) => execFileSync('git', ['-C', root, ...args], { input,
      env: { ...process.env, GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: '/dev/null' } });
    git(['init', '--quiet', `--object-format=${format}`]);
    const write = bytes => git(['hash-object', '-w', '--stdin'], bytes).toString().trim();
    const index = rows => {
      git(['read-tree', '--empty']);
      const entries = [{ path_hex: hex('untouched'), mode: 0o100644, bytes: Buffer.from('preserved\n') }, ...rows];
      const body = Buffer.concat(entries.map(row => Buffer.concat([
        Buffer.from(`${row.mode.toString(8)} ${write(row.bytes)}\t`), Buffer.from(row.path_hex, 'hex'), Buffer.from([0]),
      ])));
      git(['update-index', '-z', '--index-info'], body);
      return git(['write-tree']).toString().trim();
    };
    index(changes.filter(row => row.before).map(row => ({ path_hex: row.path_hex, ...row.before })));
    const compiled = compileSourceReplacements(format, changes);
    git(['apply', '--cached', '--unidiff-zero', '--check', '-'], compiled.patch);
    git(['apply', '--cached', '--unidiff-zero', '-'], compiled.patch);
    const actual = git(['write-tree']).toString().trim();
    const expected = index(changes.filter(row => row.after).map(row => ({ path_hex: row.path_hex, ...row.after })));
    assert.equal(actual, expected);
    assert.equal(compiled.profile, REPLACEMENT_PROFILE);
    assert.equal(compiled.source_membership_verified, false);
    assert.equal(compiled.publication_authorized, false);
    return compiled;
  } finally { rmSync(root, { recursive: true, force: true }); }
}
for (const format of ['sha1', 'sha256']) {
  const cases = [
    ['addition', null, 'created\n'], ['deletion', 'removed\n', null],
    ['empty addition', null, ''], ['empty deletion', '', null],
    ['empty to text', '', 'hello\n'], ['text to empty', 'hello\n', ''],
    ['CRLF', 'before\r\nlast', 'after\r\nlast'], ['missing final LF', 'before', 'after'],
    ['new final LF', 'before', 'after\n'], ['removed final LF', 'before\n', 'after'],
    ['mixed bytes', Buffer.from([255, 13, 10, 254]), Buffer.from([253, 10, 252])],
  ];
  for (const [name, before, after] of cases) test(`${format}: Git applies exact ${name} bytes`, () => {
    oracle(format, [change(format, 'src/file', before, after)]);
  });
  test(`${format}: raw quoted names, multiple changes and sibling preservation`, () => {
    oracle(format, [change(format, Buffer.from([255, 32, 34, 92, 9, 10]), 'old\n', 'new\n'),
      change(format, 'src/added', null, 'created\n'), change(format, 'src/deleted', 'gone', null)]);
  });
  test(`${format}: executable mode-only change and empty mode change`, () => {
    oracle(format, [change(format, 'mode', 'same\r\n', 'same\r\n', 0o100644, 0o100755),
      change(format, 'empty', '', '', 0o100755, 0o100644)]);
  });
  test(`${format}: generated patches flow through normal root-pinned preparation and inspection`, async t => {
    const f = await peer(t, format), rows = [change(format, 'file', null, f.data)];
    const compiled = compileSourceReplacements(format, rows);
    f.control.mutate = (reply, call) => { if (call.operation === 'prepare') reply.patch_sha256 = digest(compiled.patch); };
    const captured = await captureSourceReplacements({ ...f.request, expected_result_tree: f.tree }, rows, TOKEN);
    assert.equal(captured.candidate_commit, f.candidate);
    assert.equal(captured.capture.patch_sha256, digest(compiled.patch));
    assert.equal(captured.replacement_profile, REPLACEMENT_PROFILE);
    assert.deepEqual(f.calls.map(c => c.operation), ['prepare', 'inspect']);
    assert.ok(f.calls[0].body.includes(compiled.patch));
    assert.ok(f.calls.every(c => c.headers['idempotency-key'] === undefined));
  });
}
test('compilation is deterministic by raw path and input buffers are detached', () => {
  const rows = [change('sha1', 'z', 'old\n', 'new\n'), change('sha1', 'a', null, 'added')];
  const a = compileSourceReplacements('sha1', rows), b = compileSourceReplacements('sha1', [...rows].reverse());
  assert.deepEqual(a, b); rows[0].before.bytes.fill(0); rows[1].after.bytes.fill(0);
  assert.deepEqual(a, b);
});
test('full patch limit and record limit have exact allowed boundaries', () => {
  const rows = [change('sha1', 'file', 'old\nlast', 'new\nlast')], result = compileSourceReplacements('sha1', rows);
  assert.deepEqual(compileSourceReplacements('sha1', rows, { maxPatchBytes: result.patch.length }).patch, result.patch);
  assert.throws(() => compileSourceReplacements('sha1', rows, { maxPatchBytes: result.patch.length - 1 }), /patch_limit/);
  assert.deepEqual(compileSourceReplacements('sha1', rows, { maxRecords: result.records }).patch, result.patch);
  assert.throws(() => compileSourceReplacements('sha1', rows, { maxRecords: result.records - 1 }), /patch_limit/);
  const many = [change('sha1', 'file', '\n'.repeat(500000), 'new\n')];
  assert.throws(() => compileSourceReplacements('sha1', many, { maxRecords: 8 }), /patch_limit/);
});
test('source/result totals enforce logical bytes and cannot be widened', () => {
  const rows = [change('sha1', 'a', 'abc', 'defg'), change('sha1', 'b', 'abc', 'defg')];
  assert.ok(compileSourceReplacements('sha1', rows, { maxSourceBytes: 6, maxResultBytes: 8 }));
  for (const limits of [{ maxSourceBytes: 5 }, { maxResultBytes: 7 }, { maxPatchBytes: 1048577 }, { maxRecords: 0 }, { force: true }]) {
    assert.throws(() => compileSourceReplacements('sha1', rows, limits));
  }
});
for (const name of ['', '../escape', '.git/config', 'a/.GiT/config', '/root', 'a//b', 'a/./b', 'x\0y']) {
  test(`invalid repository path ${JSON.stringify(name)} refuses`, () => {
    assert.throws(() => compileSourceReplacements('sha1', [change('sha1', name, null, 'data\n')]), /path/);
  });
}
test('duplicate targets, ancestors and no-op effects refuse', () => {
  for (const rows of [[], [change('sha1', 'a', null, 'x'), change('sha1', 'a', null, 'x')],
    [change('sha1', 'a', null, 'x'), change('sha1', 'a/b', null, 'x')],
    [change('sha1', 'a', 'same', 'same')], [change('sha1', 'a', null, null)]]) {
    assert.throws(() => compileSourceReplacements('sha1', rows));
  }
});
test('binary bodies and unverified original hashes cannot be relabeled as exact text', () => {
  const bad = change('sha1', 'file', 'old', 'new'); bad.before.blob = 'f'.repeat(40);
  for (const row of [bad, change('sha1', 'file', 'a\0b', 'new'), change('sha1', 'file', 'old', 'a\0b'),
    change('sha1', 'file', 'old', 'new', 0o120000), change('sha1', 'file', 'old', 'new', 0o100644, 0o160000)]) {
    assert.throws(() => compileSourceReplacements('sha1', [row]));
  }
});
test('scope/root/cancellation checks happen before any source request', async t => {
  const f = await peer(t), rows = [change('sha1', 'file', null, f.data)];
  await assert.rejects(captureSourceReplacements(f.request, rows, TOKEN), /result_required/);
  await assert.rejects(captureSourceReplacements({ ...f.request, expected_result_tree: f.tree, paths_hex: [hex('other')] }, rows, TOKEN), /paths/);
  const stop = new AbortController(); stop.abort();
  await assert.rejects(captureSourceReplacements({ ...f.request, expected_result_tree: f.tree }, rows, TOKEN, { signal: stop.signal }), /cancelled/);
  assert.equal(f.calls.length, 0);
  let checks = 0;
  assert.throws(() => compileSourceReplacements('sha1', rows, {}, () => { if (++checks === 5) throw new Error('stop'); }), /stop/);
});
test('acquisition owns replacements before awaiting transport and refuses wrong roots', async t => {
  const f = await peer(t), rows = [change('sha1', 'file', null, f.data)], compiled = compileSourceReplacements('sha1', rows);
  f.control.mutate = (reply, call) => { if (call.operation === 'prepare') reply.patch_sha256 = digest(compiled.patch); };
  const selection = { ...f.request, expected_result_tree: f.tree };
  const pending = captureSourceReplacements(selection, rows, TOKEN);
  rows[0].after.bytes.fill(0); selection.expected_result_tree = 'f'.repeat(40);
  assert.equal((await pending).candidate_commit, f.candidate);
  await assert.rejects(captureSourceReplacements(selection, [change('sha1', 'file', null, f.data)], TOKEN), /result_tree_mismatch/);
  assert.equal(f.calls.at(-1).operation, 'prepare');
});
for (const format of ['sha1', 'sha256']) test(`${format}: exhaustive small line-sequence replacements preserve the exact resulting tree`, () => {
  const values = ['', 'a', 'a\n', '\n', 'b\r\n', 'a\nb'];
  const rows = [];
  for (const before of values) for (const after of values) if (before !== after) {
    rows.push(change(format, `cases/f${String(rows.length).padStart(2, '0')}`, before, after));
  }
  assert.equal(rows.length, 30); oracle(format, rows);
});
