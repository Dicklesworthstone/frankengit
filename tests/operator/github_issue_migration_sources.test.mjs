import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, writeFile, chmod, symlink, link, rm, mkdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHash } from 'node:crypto';
import { parseGithubIssueMigrationSources as parse, loadGithubIssueMigrationSources as load } from '../../scripts/lib/github-issue-migration-sources.mjs';

const hash = bytes => createHash('sha256').update(bytes).digest('hex');
const encode = (value, indent) => Buffer.from(JSON.stringify(value, null, indent) + '\n');
function selected(count = 2) {
  return { schema: 'frankengit-github-issue-migration-sources-v1',
    inventory: { path: '/private/inventory.json', sha256: '1'.repeat(64) },
    captures: Array.from({ length: count }, (_, index) => ({ batch: index + 1, path: `/private/capture-${index + 1}.json`, sha256: hash(String(index)) })),
    offset: 500, maxSteps: 10000, maxCaptureBytes: 64 * 1024 * 1024, maxRequestBytes: 128 * 1024 * 1024 };
}
async function fixture(t, bytes = encode(selected(), 2)) {
  const root = await mkdtemp(join(tmpdir(), 'fg-migration-sources-'));
  await chmod(root, 0o700); t.after(() => rm(root, { recursive: true, force: true }));
  const path = join(root, 'sources.json'); await writeFile(path, bytes, { mode: 0o600 });
  return { root, path, bytes, sha256: hash(bytes) };
}

test('compact and two-space source selections preserve exact pins and native options', () => {
  const value = selected(); value.captures.reverse();
  for (const indent of [undefined, 2]) {
    const result = parse(encode(value, indent));
    assert.deepEqual(result, { inventoryFile: value.inventory.path, inventorySha256: value.inventory.sha256,
      captures: [...value.captures].reverse(), offset: 500, maxSteps: 10000,
      maxCaptureBytes: 64 * 1024 * 1024, maxRequestBytes: 128 * 1024 * 1024 });
    assert.ok(Object.isFrozen(result)); assert.ok(Object.isFrozen(result.captures)); assert.ok(Object.isFrozen(result.captures[0]));
  }
});

test('one and 128 captures are supported without changing native batch or input identities', () => {
  for (const count of [1, 128]) {
    const value = selected(count); value.offset = Number.MAX_SAFE_INTEGER;
    const result = parse(encode(value));
    assert.equal(result.captures.length, count); assert.equal(result.offset, Number.MAX_SAFE_INTEGER);
    assert.deepEqual(result.captures, value.captures);
  }
});

test('omitted optional bounds retain the existing preparer defaults rather than inventing overrides', () => {
  const value = selected(); for (const key of ['offset', 'maxSteps', 'maxCaptureBytes', 'maxRequestBytes']) delete value[key];
  const result = parse(encode(value));
  assert.deepEqual(Object.keys(result), ['inventoryFile', 'inventorySha256', 'captures']);
});

for (const [label, mutate] of [
  ['unknown schema', v => { v.schema = 'other'; }], ['unknown authority fields', v => { v.href = 'https://evil.example/'; }],
  ['credential override', v => { v.tokenFile = '/other/token'; }], ['execution override', v => { v.operation = 'run'; }],
  ['missing inventory', v => { delete v.inventory; }], ['missing captures', v => { delete v.captures; }],
  ['empty captures', v => { v.captures = []; }], ['over 128 captures', v => { v.captures = selected(129).captures; }],
  ['non-array captures', v => { v.captures = {}; }], ['skipped batch', v => { v.captures[0].batch = 3; }],
  ['repeated batch', v => { v.captures[1].batch = 1; }], ['fractional batch', v => { v.captures[0].batch = 1.5; }],
  ['zero batch', v => { v.captures[0].batch = 0; }], ['relative path', v => { v.inventory.path = 'inventory.json'; }],
  ['path traversal', v => { v.captures[0].path = '/private/../capture'; }],
  ['embedded NUL', v => { v.captures[0].path += '\0'; }], ['unpaired surrogate', v => { v.captures[0].path += '\ud800'; }],
  ['oversize path', v => { v.captures[0].path = '/' + 'a'.repeat(4096); }],
  ['duplicate capture path', v => { v.captures[1].path = v.captures[0].path; }],
  ['inventory as capture', v => { v.captures[0].path = v.inventory.path; }],
  ['extra capture field', v => { v.captures[0].retry = true; }], ['missing capture pin', v => { delete v.captures[0].sha256; }],
  ['uppercase pin', v => { v.captures[0].sha256 = 'A'.repeat(64); }], ['short pin', v => { v.inventory.sha256 = '1'.repeat(63); }],
  ['negative offset', v => { v.offset = -1; }], ['inexact offset', v => { v.offset = Number.MAX_SAFE_INTEGER + 1; }],
  ['over-limit steps', v => { v.maxSteps = 10001; }], ['zero steps', v => { v.maxSteps = 0; }],
  ['over-limit capture bytes', v => { v.maxCaptureBytes++; }], ['over-limit request bytes', v => { v.maxRequestBytes++; }]
]) test(`source selection refuses ${label}`, () => {
  const value = selected(); mutate(value); assert.throws(() => parse(encode(value)));
});

test('duplicate keys, exponent spellings, truncation, invalid UTF-8 and unbounded input are refused', () => {
  const bytes = encode(selected()), text = bytes.toString();
  for (const bad of [Buffer.from(text.replace('"offset":500', '"offset":400,"offset":500')),
    Buffer.from(text.replace('"offset":500', '"offset":5e2')), bytes.subarray(0, -2),
    Buffer.concat([Buffer.from([0xff]), bytes]), Buffer.alloc(1024 * 1024 + 1), Buffer.from(text.trimEnd()),
    Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), bytes])]) assert.throws(() => parse(bad));
});

test('private file load verifies the independent descriptor pin before returning a frozen selection', async t => {
  const f = await fixture(t);
  const result = await load({ path: f.path, sha256: f.sha256 });
  assert.equal(result.captures.length, 2); assert.equal(result.inventorySha256, '1'.repeat(64));
  assert.throws(() => { result.captures[0].sha256 = '2'.repeat(64); });
  await assert.rejects(load({ path: f.path, sha256: '0'.repeat(64) }), /pin_mismatch/);
});

test('public, linked, aliased, directory and oversized descriptors fail closed', async t => {
  for (const kind of ['public', 'hardlink', 'symlink', 'parent_alias', 'directory', 'large']) {
    const f = await fixture(t); let path = f.path;
    if (kind === 'public') await chmod(path, 0o644);
    if (kind === 'hardlink') await link(path, join(f.root, 'hardlink'));
    if (kind === 'symlink') { path = join(f.root, 'symlink'); await symlink(f.path, path); }
    if (kind === 'parent_alias') { await symlink(f.root, join(f.root, 'alias')); path = join(f.root, 'alias', 'sources.json'); }
    if (kind === 'directory') { path = join(f.root, 'directory'); await mkdir(path, { mode: 0o700 }); }
    if (kind === 'large') await writeFile(path, Buffer.alloc(1024 * 1024 + 1));
    await assert.rejects(load({ path, sha256: f.sha256 }));
  }
});

test('cancellation precedes file access and loader options cannot widen scope', async t => {
  const f = await fixture(t), stop = new AbortController(); stop.abort(new Error('stopped'));
  await assert.rejects(load({ path: '/missing/sources.json', sha256: f.sha256, signal: stop.signal }), /stopped/);
  await assert.rejects(load({ path: f.path, sha256: f.sha256, force: true }), /fields/);
  await assert.rejects(load({ path: f.path, sha256: f.sha256, signal: {} }), /signal/);
});
