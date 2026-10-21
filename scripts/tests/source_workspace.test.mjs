// Complete production modules and actual POSIX files, not native Rust TreeFS.
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, realpath, rm, readFile, writeFile, lstat, chmod, symlink, link, mkdir, unlink, rename } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawn } from 'node:child_process';
import { Writable } from 'node:stream';
import { createSourceWorkspace, loadSourceWorkspace, inspectSourceWorkspace, readWorkspaceFiles, localPath, selectedPaths } from '../operator/source_workspace.mjs';
import { canonical, sha256 } from '../operator/source_changes.mjs';
import { changeFixture, hexPath } from './source_changes_fixture.mjs';
import { main } from '../fg_source_workspace.mjs';
const CLI = new URL('../fg_source_workspace.mjs', import.meta.url).pathname;
const missing = p => assert.rejects(lstat(p), { code: 'ENOENT' });
async function setup(t, format = 'sha1', input) {
  const root = await realpath(await mkdtemp(join(tmpdir(), 'fg-local-workspace-'))), path = join(root, 'workspace');
  t.after(() => rm(root, { recursive: true, force: true }));
  const f = changeFixture(format, input);
  return { root, path, f, create: options => createSourceWorkspace(path, f.bytes, f.expected, options) };
}
function cli(args) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [CLI, ...args], { stdio: ['ignore', 'pipe', 'pipe'] }), out = [], err = [];
    const timer = setTimeout(() => { child.kill('SIGKILL'); reject(Error('CLI deadline')); }, 15000);
    child.stdout.on('data', b => out.push(b)); child.stderr.on('data', b => err.push(b));
    child.once('error', e => { clearTimeout(timer); reject(e); });
    child.once('close', code => { clearTimeout(timer); resolve({ code, out: Buffer.concat(out).toString(), err: Buffer.concat(err).toString() }); });
  });
}
for (const format of ['sha1', 'sha256']) {
  test(`${format}: create/reopen exact private files and deterministic root`, async t => {
    const s = await setup(t, format), first = await s.create();
    assert.equal(first.repository_changed, false); assert.equal(first.files, 3);
    assert.equal((await lstat(s.path)).mode & 0o777, 0o700);
    for (const f of s.f.files) {
      const path = localPath(s.path, f.path.toString('hex'));
      assert.deepEqual(await readFile(path), f.bytes);
      assert.equal((await lstat(path)).mode & 0o777, f.mode === 0o100755 ? 0o700 : 0o600);
    }
    const loaded = await loadSourceWorkspace(s.path, first.workspace_sha256);
    assert.deepEqual(loaded.expected, s.f.expected); assert.deepEqual(loaded.packageBytes, s.f.bytes);
    const status = await inspectSourceWorkspace(s.path, first.workspace_sha256);
    assert.ok(status.entries.every(e => e.state === 'unchanged')); assert.equal(status.unselected_paths_examined, false);
    const second = await createSourceWorkspace(join(s.root, 'other'), s.f.bytes, s.f.expected);
    assert.equal(second.workspace_sha256, first.workspace_sha256);
  });
  test(`${format}: sparse selected set never materializes an unrelated subtree`, async t => {
    const s = await setup(t, format), p = s.f.value;
    p.membership.files = p.membership.files.filter(f => f.pathHex === hexPath('run.sh'));
    p.membership.trees = p.membership.trees.filter(f => f.pathHex === null);
    p.blobs = p.blobs.filter(b => b.oid === p.membership.files[0].blob);
    const expected = { ...s.f.expected, files: s.f.expected.files.filter(f => f.pathHex === hexPath('run.sh')) };
    const saved = await createSourceWorkspace(s.path, canonical(p), expected);
    assert.equal(saved.files, 1); await missing(localPath(s.path, hexPath('src')));
  });
  for (const [names, path] of [['UTF-8', Buffer.from('🌱/file\n')], ['raw-byte', Buffer.from([0xff,47,0xfe,10])]]) {
    const unsupported = names === 'raw-byte' && process.platform === 'darwin';
    test(`${format}: ${names} materialization ${unsupported ? 'refuses before destination acquisition on macOS' : 'preserves binary bytes, CRLF and missing newline'}`, async t => {
      const s = await setup(t, format, [
        { path, bytes: Buffer.from([0,255,10,13]) },
        { path: 'notes.txt', bytes: 'a\r\nb', mode: 0o100755 }, { path: 'empty', bytes: '' },
      ]);
      if (unsupported) {
        await assert.rejects(s.create(), { code: 'source_workspace_host_path_unrepresentable' });
        await missing(s.path);
        t.diagnostic('typed macOS host refusal; raw-name materialization must execute on Linux');
        return;
      }
      const result = await s.create();
      for (const f of s.f.files) assert.deepEqual(await readFile(localPath(s.path, f.path.toString('hex'))), f.bytes);
      assert.ok((await inspectSourceWorkspace(s.path, result.workspace_sha256)).entries.every(f => f.state === 'unchanged'));
    });
  }
  test(`${format}: edits/deletion/mode are observed without touching original evidence`, async t => {
    const s = await setup(t, format), r = await s.create();
    await writeFile(localPath(s.path, hexPath('src/main.rs')), 'replacement\n');
    await unlink(localPath(s.path, hexPath('empty.txt'))); await chmod(localPath(s.path, hexPath('run.sh')), 0o600);
    const status = await inspectSourceWorkspace(s.path, r.workspace_sha256);
    assert.deepEqual(status.entries.map(e => e.state), ['deleted', 'modified', 'modified']);
    const loaded = await loadSourceWorkspace(s.path, r.workspace_sha256); assert.deepEqual(loaded.packageBytes, s.f.bytes);
  });
}
for (const kind of ['wrong-pin', 'package', 'expectation', 'manifest']) test(`tampered ${kind} refuses while original twin reopens`, async t => {
  const s = await setup(t), r = await s.create(); await loadSourceWorkspace(s.path, r.workspace_sha256);
  if (kind === 'wrong-pin') return assert.rejects(loadSourceWorkspace(s.path, '0'.repeat(64)), /manifest_changed/);
  const name = { package: 'source.json', expectation: 'expected.json', manifest: 'manifest.json' }[kind];
  await writeFile(join(s.path, name), '{}\n');
  await assert.rejects(loadSourceWorkspace(s.path, r.workspace_sha256), /changed/);
});
for (const kind of ['symlink-file','hardlink-file','public-file','symlink-parent','public-parent','file-parent','directory-file']) {
  test(`unsafe ${kind} refuses without reading its contents`, async t => {
    const s = await setup(t), r = await s.create(), p = localPath(s.path, hexPath('src/main.rs')), d = localPath(s.path, hexPath('src'));
    assert.equal((await inspectSourceWorkspace(s.path, r.workspace_sha256)).entries.length, 3);
    if (kind === 'symlink-file') { await unlink(p); await symlink('/etc/passwd', p); }
    if (kind === 'hardlink-file') await link(p, join(s.root, 'alias'));
    if (kind === 'public-file') await chmod(p, 0o644);
    if (kind === 'symlink-parent') { await rename(d, join(s.root, 'moved')); await symlink(join(s.root, 'moved'), d); }
    if (kind === 'public-parent') await chmod(d, 0o755);
    if (kind === 'file-parent') { await rm(d, { recursive: true }); await writeFile(d, '', { mode: 0o600 }); }
    if (kind === 'directory-file') { await unlink(p); await mkdir(p, { mode: 0o700 }); }
    await assert.rejects(inspectSourceWorkspace(s.path, r.workspace_sha256));
  });
}
test('unselected local files are not scanned or disclosed', async t => {
  const s = await setup(t), r = await s.create();
  await symlink('/etc/passwd', localPath(s.path, hexPath('not-selected')));
  const status = await inspectSourceWorkspace(s.path, r.workspace_sha256);
  assert.equal(status.entries.length, 3); assert.equal(status.unselected_paths_examined, false);
});
test('competing creators leave exactly one completed workspace', async t => {
  const s = await setup(t), results = await Promise.allSettled([s.create(),s.create()]);
  assert.equal(results.filter(r => r.status === 'fulfilled').length, 1);
  const r = results.find(r => r.status === 'fulfilled').value;
  await loadSourceWorkspace(s.path, r.workspace_sha256);
  await assert.rejects(s.create(), { code: 'EEXIST' });
});
test('cancellation before ownership creates nothing; interruption retains an incomplete slot', async t => {
  const s = await setup(t), controller = new AbortController(); controller.abort();
  await assert.rejects(s.create({ signal: controller.signal })); await missing(s.path);
  let failure;
  try { await s.create({ check: () => { if (existsSync(join(s.path, 'source.json'))) throw Error('interrupt'); } }); }
  catch (error) { failure = error; }
  assert.ok(failure?.publication_unconfirmed?.workspace_sha256); assert.ok(existsSync(s.path));
  await missing(join(s.path, 'manifest.json')); await assert.rejects(s.create(), { code: 'EEXIST' });
});
test('caller mutation after invocation cannot replace the owned source or expected commit', async t => {
  const s = await setup(t), bytes = Buffer.from(s.f.bytes), expected = structuredClone(s.f.expected);
  const pending = createSourceWorkspace(s.path, bytes, expected); bytes.fill(0); expected.commit = '0'.repeat(40); expected.files.length = 0;
  const r = await pending; assert.equal(r.source_commit, s.f.commit);
});
test('invalid independent membership refuses before output creation', async t => {
  const s = await setup(t); await assert.rejects(createSourceWorkspace(s.path, s.f.bytes, { ...s.f.expected, commit: '1'.repeat(40) }));
  await missing(s.path);
});
test('local path profile rejects dot-git, aliases, depth and component overflow', () => {
  for (const v of ['../x','a/./x','.git/config','a/.GiT/config','a//b','/' ,'x'.repeat(256)]) assert.throws(() => selectedPaths([hexPath(v)]));
  assert.throws(() => selectedPaths([hexPath('a'), hexPath('a/b')]));
  assert.throws(() => selectedPaths([hexPath('a'), hexPath('a')]));
  assert.deepEqual(selectedPaths([hexPath('a/b'),hexPath('a.c')]), [hexPath('a.c'),hexPath('a/b')]);
});
test('file one-over bound refuses before creating output; exact bound succeeds', async t => {
  const s = await setup(t, 'sha1', [{ path:'a', bytes: Buffer.alloc(1048577,65) }]);
  await assert.rejects(s.create(), /source_budget/); await missing(s.path);
  const f = changeFixture('sha1', [{path:'a', bytes: Buffer.alloc(1048576,65)}]);
  assert.equal((await createSourceWorkspace(s.path, f.bytes, f.expected)).source_bytes, 1048576);
});
test('snapshot recheck detects edits and changes to previously missing paths', async t => {
  const s = await setup(t); await s.create(); const a = hexPath('src/main.rs'), b = hexPath('new/file');
  const first = await readWorkspaceFiles(s.path, [a]); await writeFile(localPath(s.path,a),'raced'); await assert.rejects(first.recheck(), /changed/);
  const second = await readWorkspaceFiles(s.path, [b]); assert.equal(second.files.get(b),null);
  await mkdir(localPath(s.path,hexPath('new')), {mode:0o700}); await assert.rejects(second.recheck(), /changed/);
});
test('real CLI creates and reopens in another process, rejecting a wrong pin', async t => {
  const s = await setup(t); const packagePath = join(s.root,'package.json'), expectPath=join(s.root,'expected.json');
  await writeFile(packagePath,s.f.bytes,{mode:0o600}); await writeFile(expectPath,canonical(s.f.expected),{mode:0o600});
  const created = await cli(['create','--package',packagePath,'--expect',expectPath,'--output',s.path]);
  assert.equal(created.code,0,created.err); const r = JSON.parse(created.out);
  const checked = await cli(['status','--workspace',s.path,'--sha256',r.workspace_sha256]); assert.equal(checked.code,0,checked.err);
  const bad = await cli(['status','--workspace',s.path,'--sha256','0'.repeat(64)]); assert.equal(bad.code,2);
  assert.equal(bad.out,''); assert.equal(JSON.parse(bad.err).network_attempted,false);
});
test('CLI refuses public inputs, network/execute options, duplicate flags and missing values', async t => {
  const s = await setup(t), p=join(s.root,'package.json'), e=join(s.root,'expected.json');
  await writeFile(p,s.f.bytes,{mode:0o644}); await writeFile(e,canonical(s.f.expected),{mode:0o600});
  const args=['create','--package',p,'--expect',e,'--output',s.path];
  for (const a of [args,[...args,'--token-file',p],[...args,'--execute','sh'],[...args,'--package',p],args.slice(0,-1)]) {
    assert.equal((await cli(a)).code,2); await missing(s.path);
  }
});
test('failed stdout retains the completed workspace and pin, without leaking source', async t => {
  const s=await setup(t), p=join(s.root,'package.json'), e=join(s.root,'expected.json');
  await writeFile(p,s.f.bytes,{mode:0o600}); await writeFile(e,canonical(s.f.expected),{mode:0o600});
  const diagnostics=[];
  const stdout=new Writable({write(_chunk,_encoding,cb){cb(Error('lost stdout'));}}), stderr=new Writable({write(chunk,_encoding,cb){diagnostics.push(chunk);cb();}});
  const code=await main(['create','--package',p,'--expect',e,'--output',s.path],{stdout,stderr}); assert.equal(code,4);
  const report=JSON.parse(Buffer.concat(diagnostics)); assert.ok(report.retained_result.workspace_sha256);
  await loadSourceWorkspace(s.path,report.retained_result.workspace_sha256);
  assert.ok(!Buffer.concat(diagnostics).toString().includes('old();'));
});
