// Actual private files and complete shared source verifiers, not native TreeFS.
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm, writeFile, readFile, unlink, chmod, mkdir, lstat, symlink, link } from 'node:fs/promises';
import { existsSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { mergeSelectedSourcePackages } from '../operator/source_package_union.mjs';
import { createSourceWorkspace, expandSourceWorkspace, loadSourceWorkspace, inspectSourceWorkspace, localPath } from '../operator/source_workspace.mjs';
import { readSourcePackage } from '../../crates/fgit-node/src/smart_http/server/browser/search-context-package.mjs';
import { canonical, sha256 } from '../operator/source_changes.mjs';
import { changeFixture, hexPath } from './source_changes_fixture.mjs';
import { selectSource, withParent } from './source_replay_fixture.mjs';

const rows = [{ path: 'src/a', bytes: 'original a\n' }, { path: 'run.sh', bytes: 'echo old\n', mode: 0o100755 },
  { path: 'deleted', bytes: 'remove this\n' }, { path: 'lib/b', bytes: 'more source\n' },
  { path: 'lib/c', bytes: '', mode: 0o100755 }, { path: 'opaque/secret', bytes: 'unselected\n' }];
const originalPaths = ['deleted', 'run.sh', 'src/a'], morePaths = ['lib/b', 'lib/c', 'src/a'];
function split(format = 'sha1', input = rows, left = originalPaths, right = morePaths) {
  const full = changeFixture(format, input);
  return { full, left: selectSource(full, left), right: selectSource(full, right) };
}
const merge = (s, options) => mergeSelectedSourcePackages(s.left.bytes, s.left.expected, s.right.bytes, s.right.expected, options);
const absent = path => assert.rejects(lstat(path), { code: 'ENOENT' });
async function setup(t, format = 'sha1', input, left, right) {
  const s = split(format, input, left, right), root = await mkdtemp(join(tmpdir(), 'fg-expand-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const original = join(root, 'original'), output = join(root, 'expanded');
  const first = await createSourceWorkspace(original, s.left.bytes, s.left.expected);
  return { ...s, root, original, output, first,
    expand: options => expandSourceWorkspace(original, first.workspace_sha256, s.right.bytes, s.right.expected, output, options) };
}
for (const format of ['sha1', 'sha256']) {
  test(`${format}: deterministic exact union adds source without expanding opaque siblings`, async () => {
    const s = split(format), result = await merge(s);
    const checked = await readSourcePackage(result.packageBytes, result.expected);
    assert.equal(checked.verified.files.length, 5); assert.equal(checked.verified.rootTree, s.full.tree);
    assert.deepEqual(result.expected.files.map(f => f.pathHex), ['deleted','lib/b','lib/c','run.sh','src/a'].map(hexPath));
    assert.deepEqual(checked.package.membership.trees.map(t => t.pathHex), [null, hexPath('lib'), hexPath('src')]);
    const reversed = await mergeSelectedSourcePackages(s.right.bytes, s.right.expected, s.left.bytes, s.left.expected);
    assert.deepEqual(reversed.packageBytes, result.packageBytes);
    const scrambled = structuredClone(s.right.value);
    scrambled.membership.commit = { bodyHex: scrambled.membership.commit.bodyHex, oid: scrambled.membership.commit.oid };
    scrambled.membership.trees.reverse();
    scrambled.membership.trees = scrambled.membership.trees.map(t => ({ bodyHex: t.bodyHex, oid: t.oid, pathHex: t.pathHex }));
    scrambled.blobs = scrambled.blobs.map(b => ({ bytesHex: b.bytesHex, oid: b.oid }));
    const reordered = await mergeSelectedSourcePackages(s.left.bytes, s.left.expected, canonical(scrambled), s.right.expected);
    assert.deepEqual(reordered.packageBytes, result.packageBytes);
  });
  test(`${format}: carry selected edits, modes and deletions; materialize newly admitted source`, async t => {
    const s = await setup(t, format);
    await writeFile(localPath(s.original, hexPath('src/a')), Buffer.from([0,255,13,10,42]));
    await chmod(localPath(s.original, hexPath('run.sh')), 0o600);
    await unlink(localPath(s.original, hexPath('deleted')));
    const result = await s.expand();
    assert.equal(result.type, 'source_workspace_expanded'); assert.equal(result.files, 5);
    assert.equal(result.expansion.original_workspace_sha256, s.first.workspace_sha256);
    assert.equal(result.expansion.preserved_deletions, 1); assert.equal(result.original_workspace_changed, false);
    assert.deepEqual(await readFile(localPath(s.output, hexPath('src/a'))), Buffer.from([0,255,13,10,42]));
    await absent(localPath(s.output, hexPath('deleted')));
    assert.equal((await lstat(localPath(s.output, hexPath('run.sh')))).mode & 0o777, 0o600);
    assert.equal((await lstat(localPath(s.output, hexPath('lib/c')))).mode & 0o777, 0o700);
    assert.equal((await readFile(localPath(s.output, hexPath('lib/b')))).toString(), 'more source\n');
    await absent(localPath(s.output, hexPath('opaque')));
    const states = await inspectSourceWorkspace(s.output, result.workspace_sha256);
    assert.deepEqual(states.entries.map(f => f.state), ['deleted','unchanged','unchanged','modified','modified']);
    assert.deepEqual((await loadSourceWorkspace(s.original, s.first.workspace_sha256)).packageBytes, s.left.bytes);
    assert.notEqual(result.workspace_sha256, s.first.workspace_sha256);
    await assert.rejects(loadSourceWorkspace(s.output, s.first.workspace_sha256), /manifest_changed/);
    await rm(s.original, { recursive: true });
    assert.equal((await loadSourceWorkspace(s.output, result.workspace_sha256)).expected.files.length, 5);
  });
  test(`${format}: preserve raw POSIX names and binary bodies while deduplicating identical subtrees`, async t => {
    const raw = Buffer.from([0xff,47,0xfe]), s = await setup(t, format,
      [{ path: raw, bytes: Buffer.from([0,1,255]), mode: 0o100755 }, { path: 'a/x', bytes: 'same' }, { path: 'b/x', bytes: 'same' }],
      [raw, 'a/x'], ['b/x']);
    const result = await s.expand(), loaded = await loadSourceWorkspace(s.output, result.workspace_sha256);
    assert.equal(loaded.verified.uniqueSourceBytes, 7); assert.equal(loaded.verified.logicalSourceBytes, 11);
    assert.deepEqual(await readFile(localPath(s.output, raw.toString('hex'))), Buffer.from([0,1,255]));
    const pkg = JSON.parse(loaded.packageBytes); const a = pkg.membership.trees.find(t => t.pathHex === hexPath('a'));
    assert.equal(a.oid, pkg.membership.trees.find(t => t.pathHex === hexPath('b')).oid);
    assert.equal(pkg.membership.trees.length, 4);
  });
  test(`${format}: altered commit or hash domain cannot refresh the workspace base`, async t => {
    const s = await setup(t, format), next = selectSource(withParent(s.full, s.full.commit), morePaths);
    await assert.rejects(expandSourceWorkspace(s.original, s.first.workspace_sha256, next.bytes, next.expected, s.output), /source_union_basis/);
    await absent(s.output);
    const other = split(format === 'sha1' ? 'sha256' : 'sha1').right;
    await assert.rejects(expandSourceWorkspace(s.original, s.first.workspace_sha256, other.bytes, other.expected, s.output), /source_union_basis/);
    await absent(s.output);
  });
}
test('individually incomplete supplemental proof is not repaired by the original package', async t => {
  const s = await setup(t), value = structuredClone(s.right.value);
  value.membership.trees = value.membership.trees.filter(t => t.pathHex !== null);
  await assert.rejects(expandSourceWorkspace(s.original, s.first.workspace_sha256, canonical(value), s.right.expected, s.output));
  await absent(s.output);
});
test('tampered body and independently unselected extra files fail before materialization', async t => {
  const s = await setup(t), broken = structuredClone(s.right.value); broken.blobs[0].bytesHex += '00';
  await assert.rejects(expandSourceWorkspace(s.original, s.first.workspace_sha256, canonical(broken), s.right.expected, s.output));
  const narrowed = { ...s.right.expected, files: s.right.expected.files.slice(0,1) };
  await assert.rejects(expandSourceWorkspace(s.original, s.first.workspace_sha256, s.right.bytes, narrowed, s.output));
  await absent(s.output);
});
test('no additional selected file refuses without an output slot', async t => {
  const s = await setup(t);
  await assert.rejects(expandSourceWorkspace(s.original, s.first.workspace_sha256, s.left.bytes, s.left.expected, s.output), /no_expansion/);
  await absent(s.output);
});
test('combined 32-file boundary succeeds; independently valid 33-file union refuses', async () => {
  const input = Array.from({ length: 33 }, (_, i) => ({ path: `f${String(i).padStart(2,'0')}`, bytes: '' }));
  const s = split('sha1', input, input.slice(0,16).map(f=>f.path), input.slice(16,32).map(f=>f.path));
  assert.equal((await merge(s)).expected.files.length, 32);
  const tooMany = selectSource(s.full, input.slice(16).map(f=>f.path));
  await assert.rejects(mergeSelectedSourcePackages(s.left.bytes, s.left.expected, tooMany.bytes, tooMany.expected), /selection_limit/);
});
test('combined logical byte limit includes repeated blobs even when bodies deduplicate', async () => {
  const input = Array.from({ length: 9 }, (_, i) => ({ path: `f${i}`, bytes: Buffer.alloc(1048576,65) }));
  const s = split('sha1', input, ['f0','f1','f2','f3'], ['f4','f5','f6','f7']);
  assert.equal((await merge(s)).verified.logicalSourceBytes, 8388608);
  const extra = selectSource(s.full, ['f4','f5','f6','f7','f8']);
  await assert.rejects(mergeSelectedSourcePackages(s.left.bytes, s.left.expected, extra.bytes, extra.expected), /byte limit/);
});
test('overlapping local output paths refuse before touching original workspace', async t => {
  const s = await setup(t);
  for (const path of [s.original, join(s.original,'new'), s.root]) {
    await assert.rejects(expandSourceWorkspace(s.original,s.first.workspace_sha256,s.right.bytes,s.right.expected,path), /overlapping_output/);
  }
  await loadSourceWorkspace(s.original,s.first.workspace_sha256);
});
for (const kind of ['file','symlink','directory','hardlink']) test(`occupied newly selected ${kind} cannot be silently discarded`, async t => {
  const s = await setup(t), parent = localPath(s.original,hexPath('lib')); await mkdir(parent,{mode:0o700});
  const path = localPath(s.original,hexPath('lib/b'));
  if (kind === 'file') await writeFile(path, 'untracked work', {mode:0o600});
  if (kind === 'symlink') await symlink('/etc/passwd',path);
  if (kind === 'directory') await mkdir(path,{mode:0o700});
  if (kind === 'hardlink') await link(localPath(s.original,hexPath('src/a')),path);
  await assert.rejects(s.expand()); await absent(s.output);
});
test('unselected local work stays untouched and is not walked into the new workspace', async t => {
  const s = await setup(t); await symlink('/etc/passwd',localPath(s.original,hexPath('not-selected')));
  const result = await s.expand(); assert.equal(result.expansion.unselected_local_files_copied,false);
  await absent(localPath(s.output,hexPath('not-selected'))); assert.ok((await lstat(localPath(s.original,hexPath('not-selected')))).isSymbolicLink());
});
test('owns supplemental buffers and independent expectation before asynchronous workspace I/O', async t => {
  const s = await setup(t), bytes = Buffer.from(s.right.bytes), expected = structuredClone(s.right.expected);
  const pending = expandSourceWorkspace(s.original,s.first.workspace_sha256,bytes,expected,s.output);
  bytes.fill(0); expected.files.length = 0; expected.commit = '0'.repeat(40);
  const result = await pending; assert.equal(result.files,5);
});
test('cancellation before ownership creates nothing; late interruption keeps incomplete slot', async t => {
  const s = await setup(t), stop = new AbortController(); stop.abort();
  await assert.rejects(s.expand({signal:stop.signal})); await absent(s.output);
  let error;
  try { await s.expand({check:()=>{ if(existsSync(join(s.output,'source.json'))) throw Error('injected stop'); }}); }
  catch(e){error=e;}
  assert.equal(error.publication_unconfirmed.type,'source_workspace_expanded');
  await absent(join(s.output,'manifest.json')); await assert.rejects(s.expand(),/output_exists/);
  await loadSourceWorkspace(s.original,s.first.workspace_sha256);
});
test('changed predecessor while new files are written is detected before publishing the root', async t => {
  const s = await setup(t); let changed = false;
  await assert.rejects(s.expand({check:()=>{
    if(!changed && existsSync(join(s.output,'expected.json'))){ changed=true; writeFileSync(localPath(s.original,hexPath('src/a')),'concurrent editor'); }
  }}),/source_workspace_changed/);
  assert.equal(changed,true); await absent(join(s.output,'manifest.json'));
});
test('competing expanders leave exactly one complete create-only output', async t => {
  const s = await setup(t), results = await Promise.allSettled([s.expand(),s.expand()]);
  assert.equal(results.filter(r=>r.status==='fulfilled').length,1);
  await loadSourceWorkspace(s.output,results.find(r=>r.status==='fulfilled').value.workspace_sha256);
});
test('corrupted original pin or baseline cannot be replaced with a valid additional package', async t => {
  const s = await setup(t);
  await assert.rejects(expandSourceWorkspace(s.original,'0'.repeat(64),s.right.bytes,s.right.expected,s.output),/manifest_changed/);
  await writeFile(join(s.original,'source.json'),'{}'); await assert.rejects(s.expand(),/baseline_changed/);
  await absent(s.output);
});
test('invalid option and malformed independent selections are refused', async () => {
  const s = split();
  for (const expected of [{...s.right.expected,files:[]},{...s.right.expected,files:s.right.expected.files.slice().reverse()},
    {...s.right.expected,files:[{pathHex:hexPath('../x'),blob:s.right.expected.files[0].blob}]}, {...s.right.expected,network:true}]) {
    await assert.rejects(mergeSelectedSourcePackages(s.left.bytes,s.left.expected,s.right.bytes,expected));
  }
  await assert.rejects(merge(s,{check:42})); await assert.rejects(merge(s,{token:'not-an-option'}));
});
test('combined proof-directory limit is checked after union, not raised per input', async () => {
  const names = Array.from({ length: 3 }, (_, i) => `${String.fromCharCode(97+i)}/${'d/'.repeat(47)}file`);
  const s = split('sha1', names.map(path=>({path,bytes:'x'})),[names[0],names[1]],[names[2]]);
  await assert.rejects(merge(s), /invalid package inventory/);
});
test('preserved edited bytes plus newly selected bytes must fit before output ownership', async t => {
  const input = Array.from({length:9},(_,i)=>({path:`f${i}`,bytes:i===8?Buffer.alloc(1048576,65):''}));
  const s = await setup(t,'sha1',input,input.slice(0,8).map(f=>f.path),['f8']);
  for(const f of input.slice(0,8)) await writeFile(localPath(s.original,hexPath(f.path)),Buffer.alloc(1048576,66));
  await assert.rejects(s.expand(),/materialization_budget/); await absent(s.output);
});
