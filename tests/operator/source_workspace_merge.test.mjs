// Full production imports; no source, diff, merge or codec replacements.
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { spawnSync } from 'node:child_process';
import { createWorkspaceTextMerger, TEXT_MERGE_LIMITS } from '../../scripts/operator/source_workspace_merge.mjs';
const bytes = s => Buffer.isBuffer(s) ? s : Buffer.from(s);
const merge = (a, b, c, options) => createWorkspaceTextMerger(options).merge(...[a, b, c].map(bytes));
const clean = (a, b, c, expected) => {
  const result = merge(a, b, c);
  assert.equal(result.status, 'merged', result.reason); assert.deepEqual(result.bytes, bytes(expected));
  assert.deepEqual(merge(a, b, c), result); assert.deepEqual(merge(a, c, b).bytes, result.bytes);
  assert(Number.isSafeInteger(result.work_used)); return result;
};
for (const [name, base, local, selected, expected] of [
  ['separate replacements', 'a\nb\nc\nd\ne\n', 'A\nb\nc\nd\ne\n', 'a\nb\nc\nd\nE\n', 'A\nb\nc\nd\nE\n'],
  ['adjacent replacements', 'a\nb\nc\n', 'A\nb\nc\n', 'a\nB\nc\n', 'A\nB\nc\n'],
  ['insertion and distant deletion', 'a\nb\nc\nd\ne\n', 'a\nextra\nb\nc\nd\ne\n', 'a\nb\nc\ne\n', 'a\nextra\nb\nc\ne\n'],
  ['unequal replacement lengths', 'a\nb\nc\nd\ne\n', 'A1\nA2\nb\nc\nd\ne\n', 'a\nb\nc\nE\n', 'A1\nA2\nb\nc\nE\n'],
  ['common insertion once', 'a\nb\nc\nd\n', 'a\nx\nb\nc\nD\n', 'a\nx\nb\nc\nd\n', 'a\nx\nb\nc\nD\n'],
  ['CRLF preserved', 'a\r\nb\nc\r\n', 'A\r\nb\nc\r\n', 'a\r\nb\nC\r\n', 'A\r\nb\nC\r\n'],
  ['unterminated final line', 'a\nb\nc', 'A\nb\nc', 'a\nb\nC', 'A\nb\nC'],
  ['EOF newline is real content', 'a\nb\nc', 'A\nb\nc', 'a\nb\nc\n', 'A\nb\nc\n'],
  ['Unicode and BOM exact', '\ufeffα\n中\n😀\n', '\ufeffβ\n中\n😀\n', '\ufeffα\n中\n😁\n', '\ufeffβ\n中\n😁\n'],
  ['leading blank deletion beside source edit', '\na\nb\n', 'a\nb\n', '\nA\nb\n', 'A\nb\n'],
  ['blank lines', 'a\n\nb\n\nc\n', 'A\n\nb\n\nc\n', 'a\n\nb\n\nC\n', 'A\n\nb\n\nC\n'],
  ['empty base agreed', '', 'x\n', 'x\n', 'x\n'],
  ['same deletion once', 'a\nb\nc\nd\ne\n', 'a\nc\nd\nE\n', 'a\nc\nd\ne\n', 'a\nc\nd\nE\n'],
]) test(name, () => clean(base, local, selected, expected));
for (const [name, base, local, selected] of [
  ['different same-line replacements', 'a\nb\n', 'A\nb\n', 'X\nb\n'],
  ['deletion versus replacement', 'a\nb\nc\n', 'a\nc\n', 'a\nB\nc\n'],
  ['different insertion at same boundary', 'a\nb\n', 'a\nx\nb\n', 'a\ny\nb\n'],
  ['insertion at replacement start', 'a\nb\nc\n', 'a\nx\nb\nc\n', 'a\nB\nc\n'],
  ['insertion at replacement end', 'a\nb\nc\n', 'a\nb\nx\nc\n', 'a\nB\nc\n'],
  ['nested replacement', 'a\nb\nc\nd\n', 'a\nBC\nd\n', 'a\nb\nC\nd\n'],
]) test(name, () => {
  const a = merge(base, local, selected), b = merge(base, selected, local);
  for (const result of [a, b]) { assert.equal(result.reason, 'overlapping_changes'); assert(!Object.hasOwn(result, 'bytes')); }
});
test('all 961 short repeated-line single-sided changes round-trip exactly', () => {
  const sequences = [''];
  for (let n = 1; n <= 4; n++) for (let k = 0; k < 2 ** n; k++) sequences.push(Array.from({ length: n }, (_, i) => k & (1 << i) ? 'a\n' : 'b\n').join(''));
  for (const base of sequences) for (const after of sequences) {
    clean(base, after, base, after);
    clean(base, after, after, after);
  }
});
test('3000 generated disjoint insert/delete/replace cases retain both exact effects', () => {
  let seed = 87123; const random = n => { seed = (Math.imul(seed, 1664525) + 1013904223) >>> 0; return seed % n; };
  const apply = (a, effects) => { const out = a.slice(); for (const e of [...effects].reverse()) out.splice(e.at, e.remove, ...e.add); return out.join(''); };
  for (let sample = 0; sample < 3000; sample++) {
    const a = Array.from({ length: 24 }, (_, i) => `base-${i}\n`);
    if (sample % 3 === 0) a[23] = 'last';
    const left = { at: random(8), remove: random(3), add: Array.from({ length: random(3) }, (_, i) => `L-${sample}-${i}\n`) };
    const right = { at: 13 + random(7), remove: random(3), add: Array.from({ length: random(3) }, (_, i) => `R-${sample}-${i}\n`) };
    clean(a.join(''), apply(a, [left]), apply(a, [right]), apply(a, [left, right]));
  }
});
test('installed Git agrees on separated text edits (test oracle, not pinned conformance)', t => {
  const dir = mkdtempSync(join(tmpdir(), 'fg-text-merge-')); t.after(() => rmSync(dir, { recursive: true, force: true }));
  const version = spawnSync('git', ['--version'], { encoding: 'utf8', timeout: 3000 });
  assert.equal(version.status, 0, version.stderr); t.diagnostic(version.stdout.trim());
  for (const eol of ['\n', '\r\n']) for (const finalNewline of [false, true]) {
    const base = Array.from({ length: 30 }, (_, i) => `line${i}${i < 29 || finalNewline ? eol : ''}`);
    const local = base.slice(), next = base.slice(); local[3] = `local${eol}`; next[25] = `source${eol}`;
    const files = ['local', 'base', 'selected'].map(name => join(dir, name));
    [local, base, next].forEach((value, i) => writeFileSync(files[i], value.join('')));
    const oracle = spawnSync('git', ['merge-file', '-p', ...files], { timeout: 3000, maxBuffer: 1048576, env: { PATH: process.env.PATH, HOME: dir, GIT_CONFIG_NOSYSTEM: '1' } });
    assert.equal(oracle.status, 0, oracle.stderr.toString());
    clean(base.join(''), local.join(''), next.join(''), oracle.stdout);
  }
});
for (const body of [Buffer.from([0]), Buffer.from([255]), Buffer.from([0xc0, 0xaf])]) test(`binary/malformed UTF-8 ${body.toString('hex')} remains an explicit conflict`, () => {
  const result = merge(body, Buffer.concat([body, bytes('ours')]), Buffer.concat([body, bytes('theirs')]));
  assert.equal(result.reason, 'not_text'); assert(!Object.hasOwn(result, 'bytes'));
});
test('work and line budgets are shared and never reset per file', () => {
  for (const limits of [{ work: 1 }, { lines: 3 }]) {
    const m = createWorkspaceTextMerger({ limits });
    const first = m.merge(bytes('a\nb\n'), bytes('A\nb\n'), bytes('a\nB\n'));
    assert.equal(first.status, 'conflict'); assert.match(first.reason, /^(work|line)_limit$/);
    const observed = m.witness(); assert.equal(m.merge(bytes(''), bytes(''), bytes('')).status, 'conflict');
    assert.equal(m.witness().work_used, observed.work_used);
    assert(observed.work_used <= observed.limits.work); assert(observed.lines_used <= observed.limits.lines);
  }
  const m = createWorkspaceTextMerger({ limits: { lines: 6 } });
  assert.equal(m.merge(bytes('a\n'), bytes('b\n'), bytes('a\n')).status, 'merged');
  assert.equal(m.merge(bytes('a\n'), bytes('b\n'), bytes('a\n')).status, 'merged');
  assert.equal(m.merge(bytes('a\n'), bytes('b\n'), bytes('a\n')).reason, 'line_limit');
});
test('edit-distance bound has a permitted neighbor and returns no partial merge', () => {
  const args = ['a\nb\nc\n', 'A\nb\nc\n', 'a\nb\nC\n'];
  assert.equal(merge(...args, { limits: { distance: 1 } }).reason, 'distance_limit');
  assert.equal(merge(...args, { limits: { distance: 2 } }).status, 'merged');
  const x = Array.from({ length: 130 }, (_, i) => `${i}\n`).join('');
  assert.equal(merge(x, x.replaceAll('\n', 'x\n'), x).reason, 'distance_limit');
});
test('combined output ceiling holds even when every input fits', () => {
  const result = merge('a\nb\nc\n', '12345678\nb\nc\n', 'a\nb\n87654321\n', { limits: { fileBytes: 14 } });
  assert.equal(result.reason, 'output_limit'); assert(!Object.hasOwn(result, 'bytes'));
  assert.equal(merge('a\nb\nc\n', '12345678\nb\nc\n', 'a\nb\n87654321\n', { limits: { fileBytes: 20 } }).status, 'merged');
});
test('cancellation/consumer exceptions propagate, never become a conflict', () => {
  const stopped = new Error('stop'); let calls = 0;
  const m = createWorkspaceTextMerger({ check() { if (++calls === 5) throw stopped; } });
  assert.throws(() => m.merge(bytes('a\nb\nc\n'), bytes('A\nb\nc\n'), bytes('a\nb\nC\n')), error => error === stopped);
});
test('own input images and detached witnesses survive caller mutation', () => {
  const args = ['a\nb\nc\n', 'A\nb\nc\n', 'a\nb\nC\n'].map(bytes); let changed = false;
  const m = createWorkspaceTextMerger({ check() { if (!changed) { changed = true; args.forEach(b => b.fill(0)); } } });
  assert.equal(m.merge(...args).bytes.toString(), 'A\nb\nC\n');
  const observed = m.witness(); observed.limits.lines = 999; observed.work_used = -1;
  assert.equal(m.witness().limits.lines, TEXT_MERGE_LIMITS.lines); assert(m.witness().work_used > 0);
});
for (const limits of [{ work: 0 }, { work: Infinity }, { lines: -1 }, { distance: 257 }, { fileBytes: 1048577 }, { unknown: 1 }]) test(`invalid limits ${JSON.stringify(limits)}`, () => assert.throws(() => createWorkspaceTextMerger({ limits })));
test('input kinds and allocation limits refuse before work', () => {
  const m = createWorkspaceTextMerger();
  for (const wrong of [null, 'text', [], new Uint8Array(new SharedArrayBuffer(1)), Buffer.alloc(TEXT_MERGE_LIMITS.fileBytes + 1)]) {
    assert.throws(() => m.merge(wrong, bytes(''), bytes('')));
  }
  assert.equal(m.witness().attempts, 0);
});

test('explicit null/undefined option values cannot disable a checkpoint or budget', () => {
  for (const options of [{ check: null }, { check: undefined }, { limits: null }, { limits: undefined }, { silent: true }])
    assert.throws(() => createWorkspaceTextMerger(options));
});
