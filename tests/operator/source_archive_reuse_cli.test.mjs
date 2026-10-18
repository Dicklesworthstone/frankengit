// Real files, CLI processes and HTTP sockets. The server is a native-schema
// fixture, not Rust fg; the complete archive and acquisition modules are used.
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, writeFile, readFile, rm, readdir, chmod, symlink, link } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawn } from 'node:child_process';
import { Writable } from 'node:stream';
import { captureSource, validateCapture, sha256 } from '../../scripts/operator/source_archive.mjs';
import { buildSourceArchive, inspectSourceArchive, restoreSourceCapture } from '../../scripts/operator/source_archive_tar.mjs';
import { main } from '../../scripts/fg_source_archive.mjs';
import { fixture, repository, token, hex } from './fixtures/source_archive_native.mjs';
const cli = new URL('../../scripts/fg_source_archive.mjs', import.meta.url).pathname;
const save = (path, bytes) => writeFile(path, Buffer.isBuffer(bytes) || typeof bytes === 'string' ? bytes : JSON.stringify(bytes), { mode: 0o600 });
function child(t, args) {
  const proc = spawn(process.execPath, [cli, ...args], { stdio: ['ignore', 'pipe', 'pipe'] });
  t.after(() => { if (proc.exitCode === null && proc.signalCode === null) proc.kill('SIGKILL'); });
  let stdout = '', stderr = '';
  proc.stdout.on('data', b => { stdout += b; }); proc.stderr.on('data', b => { stderr += b; });
  return { proc, done: new Promise((resolve, reject) => {
    proc.once('error', reject); proc.once('close', (code, signal) => resolve({ code, signal, stdout, stderr }));
  }) };
}
async function setup(t, format = 'sha1', layout = 'portable', definitions) {
  const f = await fixture(t, { format, definitions }), { capture } = await captureSource(f.selection, token);
  const archive = buildSourceArchive(capture, layout), root = await mkdtemp(join(tmpdir(), 'fg-archive-reuse-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const base = join(root, 'prior.tar'), output = join(root, 'new.tar'), selected = join(root, 'selected.json'), credential = join(root, 'token');
  await save(base, archive.bytes); await save(selected, f.selection); await save(credential, token);
  f.calls.length = 0;
  const args = ['capture', '--selection', selected, '--token-file', credential, '--layout', layout, '--output', output,
    '--reuse-archive', base, '--reuse-sha256', archive.receipt.archive_sha256];
  return { ...f, capture, archive, root, base, output, selected, credential, args };
}
async function absent(path) { await assert.rejects(readFile(path), e => e.code === 'ENOENT'); }
for (const format of ['sha1', 'sha256']) for (const layout of ['portable', 'objects']) {
  test(`${format}/${layout}: restore verifies the full archive and detaches every file`, async t => {
    const f = await setup(t, format, layout), input = Buffer.from(f.archive.bytes);
    const restored = restoreSourceCapture(input, f.archive.receipt.archive_sha256);
    assert.deepEqual(validateCapture(restored), validateCapture(f.capture));
    assert.deepEqual(buildSourceArchive(restored, layout).bytes, f.archive.bytes);
    input.fill(0); assert.deepEqual(buildSourceArchive(restored, layout).bytes, f.archive.bytes);
    assert.equal(f.calls.length, 0);
  });
  test(`${format}/${layout}: CLI reused export equals cold bytes and stays readable without the base`, async t => {
    const f = await setup(t, format, layout), run = await child(t, f.args).done;
    assert.equal(run.code, 0, run.stderr); const receipt = JSON.parse(run.stdout);
    assert.equal(receipt.reuse_archive_sha256, f.archive.receipt.archive_sha256);
    assert.equal(receipt.read_metrics.blob_requests, 0); assert.equal(receipt.read_metrics.reused_files, 3);
    assert.equal(receipt.read_metrics.downloaded_blob_bytes, 0);
    assert.deepEqual(f.calls.map(c => c.operation), ['log', 'tree', 'tree']);
    assert.deepEqual(await readFile(f.output), f.archive.bytes);
    assert.deepEqual(await readFile(f.base), f.archive.bytes);
    await rm(f.base); await rm(f.credential); await rm(f.selected); const count = f.calls.length;
    const read = await child(t, ['inspect', '--archive', f.output, '--sha256', receipt.archive_sha256]).done;
    assert.equal(read.code, 0, read.stderr); assert.equal(f.calls.length, count);
    assert.equal(JSON.parse(read.stdout).source_commit, f.repo.commit);
    assert.equal(JSON.parse(read.stdout).authority_signatures_verified, false);
    assert.ok(!run.stdout.includes(token)); assert.ok(!run.stdout.includes(f.base));
  });
}
for (const format of ['sha1', 'sha256']) test(`${format}: changed snapshot uses fresh membership and one changed blob through the CLI`, async t => {
  const f = await setup(t, format), readme = f.repo.files.get(hex('README.md')).data;
  const next = repository(format, [{ path: 'renamed', kind: 'executable', data: readme }, { path: 'new', data: Buffer.from('new contents') }]);
  next.common.source_head = 'fresh-head'; Object.assign(f.repo, next); f.selection.expected_commit = next.commit;
  await save(f.selected, f.selection);
  const run = await child(t, f.args).done; assert.equal(run.code, 0, run.stderr);
  const receipt = JSON.parse(run.stdout), output = await readFile(f.output);
  assert.equal(receipt.source_commit, next.commit); assert.equal(receipt.read_metrics.reused_files, 1);
  assert.equal(receipt.read_metrics.blob_requests, 1); assert.equal(receipt.read_metrics.downloaded_blob_bytes, 12);
  assert.deepEqual(f.calls.filter(c => c.operation === 'blob').map(c => c.form.get('path_hex')), [hex('new')]);
  const current = restoreSourceCapture(output, receipt.archive_sha256);
  assert.equal(current.source_head, 'fresh-head'); assert.equal(current.files.length, 2);
  assert.equal(current.files.find(row => row.path_hex === hex('renamed')).kind, 'executable');
  const cold = await captureSource(f.selection, token);
  assert.deepEqual(output, buildSourceArchive(cold.capture, 'portable').bytes);
});
for (const layout of ['portable', 'objects']) test(`reuse can explicitly change ${layout} output layout without a delta format`, async t => {
  const f = await setup(t, 'sha1', layout), nextLayout = layout === 'portable' ? 'objects' : 'portable';
  const args = [...f.args]; args[args.indexOf('--layout') + 1] = nextLayout;
  const run = await child(t, args).done; assert.equal(run.code, 0, run.stderr);
  const receipt = JSON.parse(run.stdout); assert.equal(receipt.layout, nextLayout);
  assert.deepEqual(await readFile(f.output), buildSourceArchive(f.capture, nextLayout).bytes);
  assert.equal(receipt.read_metrics.blob_requests, 0);
});
test('restored duplicate payloads do not alias sibling buffers', async t => {
  const f = await setup(t, 'sha1', 'objects', [{ path: 'a', data: Buffer.from('same') }, { path: 'b', data: Buffer.from('same') }]);
  const current = restoreSourceCapture(f.archive.bytes, f.archive.receipt.archive_sha256);
  current.files[0].bytes[0] ^= 1; assert.equal(current.files[1].bytes.toString(), 'same');
  assert.equal(inspectSourceArchive(f.archive.bytes, f.archive.receipt.archive_sha256).files, 2);
});
for (const bad of ['changed-hash', 'changed-payload-rehashed', 'extra-trailer-rehashed', 'missing-hash', 'hash-without-base', 'bad-hash']) {
  test(`invalid reuse ${bad} is not silently ignored and sends no request`, async t => {
    const f = await setup(t), args = [...f.args];
    if (bad === 'changed-hash') args[args.indexOf('--reuse-sha256') + 1] = 'f'.repeat(64);
    if (bad === 'changed-payload-rehashed') {
      const bytes = Buffer.from(f.archive.bytes); const marker = bytes.indexOf(Buffer.from('hello\r\nworld\n'));
      assert.ok(marker > 0); bytes[marker] ^= 1; await save(f.base, bytes);
      args[args.indexOf('--reuse-sha256') + 1] = sha256(bytes);
    }
    if (bad === 'extra-trailer-rehashed') {
      const bytes = Buffer.concat([f.archive.bytes, Buffer.alloc(512)]); await save(f.base, bytes);
      args[args.indexOf('--reuse-sha256') + 1] = sha256(bytes);
    }
    if (bad === 'missing-hash') args.splice(args.indexOf('--reuse-sha256'), 2);
    if (bad === 'hash-without-base') args.splice(args.indexOf('--reuse-archive'), 2);
    if (bad === 'bad-hash') args[args.indexOf('--reuse-sha256') + 1] = 'untrusted';
    const run = await child(t, args).done; assert.equal(run.code, 2, run.stderr);
    assert.equal(f.calls.length, 0); await absent(f.output);
  });
}
for (const mode of ['permissions', 'symlink', 'hardlink', 'missing']) test(`unsafe ${mode} reuse file cannot open the network`, async t => {
  const f = await setup(t);
  if (mode === 'permissions') await chmod(f.base, 0o644);
  if (mode === 'symlink') { await rm(f.base); await symlink(f.selected, f.base); }
  if (mode === 'hardlink') await link(f.base, join(f.root, 'alias.tar'));
  if (mode === 'missing') await rm(f.base);
  const run = await child(t, f.args).done; assert.equal(run.code, 2, run.stderr); assert.equal(f.calls.length, 0); await absent(f.output);
});
test('an existing prior archive cannot become the new destination', async t => {
  const f = await setup(t), args = [...f.args]; args[args.indexOf('--output') + 1] = f.base;
  const run = await child(t, args).done; assert.equal(run.code, 2); assert.equal(f.calls.length, 0);
  assert.deepEqual(await readFile(f.base), f.archive.bytes);
});
test('base replacement after connection cannot mutate previously verified bytes', async t => {
  const f = await setup(t); let replaced = false;
  f.control.mutate = async () => { if (!replaced) { replaced = true; await save(f.base, 'external replacement'); } };
  const run = await child(t, f.args).done; assert.equal(run.code, 0, run.stderr);
  assert.deepEqual(await readFile(f.output), f.archive.bytes); assert.equal(await readFile(f.base, 'utf8'), 'external replacement');
});
test('scope mismatch is rejected before network despite a valid base archive', async t => {
  const f = await setup(t); await save(f.selected, { ...f.selection, repository_incarnation: 'f'.repeat(32) });
  const run = await child(t, f.args).done; assert.equal(run.code, 2); assert.equal(f.calls.length, 0); await absent(f.output);
});
test('reuse does not convert revoked credentials into offline capture', async t => {
  const f = await setup(t);
  f.control.respond = (_req, res) => { res.writeHead(401); res.end('{}'); };
  const run = await child(t, f.args).done; assert.equal(run.code, 2); assert.equal(f.calls.length, 1); await absent(f.output);
});
test('base verification spends the configured deadline before any network request', async t => {
  const f = await setup(t, 'sha256', 'objects', [{ path: 'large', data: Buffer.alloc(16 * 1024 * 1024, 11) }]);
  const limits = join(f.root, 'limits.json'); await save(limits, { timeoutMs: 1 });
  const run = await child(t, [...f.args, '--limits', limits]).done;
  assert.equal(run.code, 2, run.stderr); assert.match(run.stderr, /deadline/); assert.equal(f.calls.length, 0); await absent(f.output);
});
for (const signal of ['SIGTERM', 'SIGKILL']) test(`${signal} during warm acquisition preserves the base and creates no output`, async t => {
  const f = await setup(t); let started;
  const ready = new Promise(resolve => { started = resolve; });
  f.control.respond = (_req, _res) => { started(); };
  const run = child(t, f.args); await ready; run.proc.kill(signal); const result = await run.done;
  if (signal === 'SIGTERM') assert.equal(result.code, 3, result.stderr); else assert.equal(result.signal, signal);
  await absent(f.output); assert.deepEqual(await readFile(f.base), f.archive.bytes);
});
test('broken stdout preserves a complete reused archive and its verification receipt', async t => {
  const f = await setup(t); let diagnostic = '';
  const stdout = new Writable({ write(_b, _e, done) { done(new Error('closed output')); } });
  const stderr = new Writable({ write(b, _e, done) { diagnostic += b; done(); } });
  assert.equal(await main(f.args, { stdout, stderr }), 4);
  const receipt = JSON.parse(diagnostic).retained_receipt;
  assert.equal(receipt.reuse_archive_sha256, f.archive.receipt.archive_sha256);
  assert.equal(inspectSourceArchive(await readFile(f.output), receipt.archive_sha256).files, 3);
  assert.deepEqual(await readFile(f.base), f.archive.bytes);
});
test('inspect remains a closed offline command and refuses reuse flags', async t => {
  const f = await setup(t);
  const run = await child(t, ['inspect', '--archive', f.base, '--sha256', f.archive.receipt.archive_sha256,
    '--reuse-archive', f.base, '--reuse-sha256', f.archive.receipt.archive_sha256]).done;
  assert.equal(run.code, 2); assert.equal(f.calls.length, 0);
});
