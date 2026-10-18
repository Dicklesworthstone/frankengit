import test from 'node:test';
import assert from 'node:assert/strict';
import { Writable } from 'node:stream';
import { spawn, execFileSync } from 'node:child_process';
import { mkdtemp, writeFile, readFile, chmod, mkdir, readdir, lstat, stat, symlink, link, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { main } from '../fg_source_changes.mjs';
import { buildSourceChanges, canonical, sha256, CHANGES_INPUT_BYTES } from '../operator/source_changes.mjs';
import { loadSourceEdit } from '../operator/source_edit_publish.mjs';
import { nativePeer, TOKEN } from './source_changes_native_fixture.mjs';
import { changeFixture, intent, replace, hexPath } from './source_changes_fixture.mjs';
const script = resolve('scripts/fg_source_changes.mjs');
const edit = () => intent([replace('src/main.rs', 'fn main() { new(); }\n')]);
function launch(args) {
  const child = spawn(process.execPath, [script, ...args], { stdio: ['ignore', 'pipe', 'pipe'], env: { ...process.env, NODE_OPTIONS: '' } });
  const out = [], err = []; let size = 0;
  const result = new Promise((resolveResult, reject) => {
    const timeout = setTimeout(() => { child.kill('SIGKILL'); reject(new Error('CLI test deadline')); }, 15000);
    child.on('error', reject);
    for (const [stream, chunks] of [[child.stdout, out], [child.stderr, err]]) stream.on('data', b => {
      size += b.length; if (size > 128 * 1024) { child.kill('SIGKILL'); reject(new Error('CLI test output bound')); } else chunks.push(b);
    });
    child.once('close', (code, signal) => { clearTimeout(timeout); resolveResult({ code, signal,
      stdout: Buffer.concat(out).toString(), stderr: Buffer.concat(err).toString() }); });
  });
  return { child, result };
}
const run = args => launch(args).result;
async function inputs(f = changeFixture(), changes = edit()) {
  const root = await mkdtemp(join(tmpdir(), 'fg-authored-cli-'));
  const files = { package: join(root, 'package.json'), expect: join(root, 'expect.json'), changes: join(root, 'changes.json'), token: join(root, 'token') };
  for (const [key, bytes] of [['package', f.bytes], ['expect', canonical(f.expected)], ['changes', canonical(changes)], ['token', Buffer.from(TOKEN)]]) {
    await writeFile(files[key], bytes, { mode: 0o600 });
  }
  const common = ['--package', files.package, '--expect', files.expect, '--changes', files.changes];
  const draft = await buildSourceChanges(f.bytes, f.expected, changes), hash = sha256(canonical(draft.manifest));
  return { root, files, common, draft, hash, cleanup: () => rm(root, { recursive: true, force: true }) };
}
async function nativeArgs(peer, i, output = join(i.root, 'candidate'), extra = []) {
  const path = join(i.root, 'selection.json');
  await writeFile(path, canonical(peer.selection(i.draft.manifest.effects.map(e => e.path_hex))), { mode: 0o600 });
  return ['prepare', ...i.common, '--selection', path, '--token-file', i.files.token,
    '--confirm-draft-sha256', i.hash, '--output', output, ...extra];
}
function collector() {
  const chunks = [], stream = new Writable({ write(chunk, _encoding, done) { chunks.push(Buffer.from(chunk)); done(); } });
  return { stream, text: () => Buffer.concat(chunks).toString() };
}
for (const format of ['sha1', 'sha256']) {
  test(`${format}: CLI creates the exact private draft and passes the unchanged candidate loader after native preparation`, async () => {
    const peer = await nativePeer(format), i = await inputs(peer.fixture);
    try {
      const out = join(i.root, 'draft'), drafted = await run(['draft', ...i.common, '--output', out]);
      assert.equal(drafted.code, 0, drafted.stderr); const receipt = JSON.parse(drafted.stdout);
      assert.equal(receipt.manifest_sha256, i.hash); assert.equal(receipt.remote_mutation_attempted, false);
      assert.deepEqual(await readdir(out), ['manifest.json', 'patch.diff']); assert.equal((await stat(out)).mode & 0o777, 0o700);
      assert.ok((await readFile(join(out, 'patch.diff'))).equals(i.draft.bytes));
      const manifest = await readFile(join(out, 'manifest.json'));
      assert.equal(sha256(manifest), i.hash); assert.equal((await stat(join(out, 'manifest.json'))).mode & 0o777, 0o600);
      assert.equal((await stat(join(out, 'patch.diff'))).mode & 0o777, 0o600);
      assert.equal(peer.requests.length, 0);
      const candidate = join(i.root, 'candidate'), response = await run(await nativeArgs(peer, i, candidate));
      assert.equal(response.code, 0, response.stderr); const prepared = JSON.parse(response.stdout);
      assert.equal(prepared.binding.draft_sha256, i.hash); assert.equal(prepared.binding.intended_effect_reports_matched, true);
      const loaded = await loadSourceEdit(candidate, prepared.manifest_sha256);
      assert.equal(loaded.candidate_commit, prepared.candidate_commit);
      assert.deepEqual((await readdir(candidate)).sort(), ['candidate.bundle', 'capture.json', 'manifest.json']);
      assert.deepEqual(peer.requests.map(r => r.route), ['source/prepare', 'source/inspect']); assert.deepEqual(peer.failures, []);
      const serialized = Buffer.concat(await Promise.all((await readdir(candidate)).map(name => readFile(join(candidate, name)))));
      assert.equal(serialized.includes(Buffer.from(TOKEN)), false);
      await peer.close();
      const checked = await run(['inspect-candidate', ...i.common, '--candidate', candidate, '--sha256', prepared.manifest_sha256, '--confirm-draft-sha256', i.hash]);
      assert.equal(checked.code, 0, checked.stderr); assert.deepEqual(JSON.parse(checked.stdout).binding, prepared.binding);
      const bad = await run(['inspect-candidate', ...i.common, '--candidate', candidate, '--sha256', 'f'.repeat(64), '--confirm-draft-sha256', i.hash]);
      assert.equal(bad.code, 2); assert.equal(bad.stdout, '');
    } finally { await peer.close(); await i.cleanup(); }
  });
}
test('private CLI drafting preserves explicit no-op accounting without a network credential', async () => {
  const i = await inputs(changeFixture(), intent([replace('empty.txt', ''), replace('run.sh', 'changed\n')]));
  try {
    const response = await run(['draft', ...i.common, '--output', join(i.root, 'draft')]);
    assert.equal(response.code, 0, response.stderr); const receipt = JSON.parse(response.stdout);
    assert.equal(receipt.effect_count, 1); assert.equal(receipt.no_op_count, 1);
    const manifest = JSON.parse(await readFile(join(i.root, 'draft/manifest.json')));
    assert.deepEqual(manifest.no_op_paths_hex, [hexPath('empty.txt')]);
  } finally { await i.cleanup(); }
});
test('wrong draft consent or changed native selection refuses before any HTTP work', async () => {
  const peer = await nativePeer(), i = await inputs(peer.fixture);
  try {
    let args = await nativeArgs(peer, i); args[args.indexOf('--confirm-draft-sha256') + 1] = 'f'.repeat(64);
    assert.equal((await run(args)).code, 2); assert.equal(peer.requests.length, 0);
    args = await nativeArgs(peer, i);
    const path = args[args.indexOf('--selection') + 1], selected = JSON.parse(await readFile(path)); selected.paths_hex = [hexPath('run.sh')];
    await writeFile(path, canonical(selected));
    const result = await run(args); assert.equal(result.code, 2); assert.equal(JSON.parse(result.stderr).code, 'source_changes_selection_mismatch');
    assert.equal(peer.requests.length, 0); await assert.rejects(lstat(join(i.root, 'candidate')), { code: 'ENOENT' });
  } finally { await peer.close(); await i.cleanup(); }
});
for (const fault of ['wrong-after', 'wrong-before-tree', 'wrong-old-mode']) {
  test(`CLI refuses ${fault} without publishing a usable candidate directory`, async () => {
    const peer = await nativePeer(), i = await inputs(peer.fixture);
    try {
      peer.fault = fault; const result = await run(await nativeArgs(peer, i));
      assert.equal(result.code, 2, result.stderr); assert.equal(result.stdout, '');
      await assert.rejects(lstat(join(i.root, 'candidate')), { code: 'ENOENT' }); assert.deepEqual(peer.failures, []);
    } finally { await peer.close(); await i.cleanup(); }
  });
}
for (const type of ['public', 'symlink', 'hardlink', 'fifo']) {
  test(`CLI input custody refuses ${type} files without hanging or overwriting`, async () => {
    const i = await inputs();
    try {
      if (type === 'public') await chmod(i.files.changes, 0o644);
      else {
        const path = join(i.root, 'unsafe');
        if (type === 'symlink') await symlink(i.files.changes, path);
        else if (type === 'hardlink') await link(i.files.changes, path);
        else execFileSync('mkfifo', ['-m', '600', path], { timeout: 5000 });
        i.common[i.common.indexOf('--changes') + 1] = path;
      }
      const result = await run(['draft', ...i.common, '--output', join(i.root, 'draft')]);
      assert.equal(result.code, 2, result.stderr); assert.equal(result.stdout, '');
      await assert.rejects(lstat(join(i.root, 'draft')), { code: 'ENOENT' });
    } finally { await i.cleanup(); }
  });
}
test('unsafe parent directories and alias destinations refuse before credentials or HTTP', async () => {
  const peer = await nativePeer(), i = await inputs(peer.fixture);
  try {
    const publicParent = join(i.root, 'public'); await mkdir(publicParent, { mode: 0o755 });
    const alias = join(i.root, 'alias'); await symlink(i.root, alias);
    for (const path of [join(publicParent, 'candidate'), join(alias, 'candidate')]) {
      const result = await run(await nativeArgs(peer, i, path)); assert.equal(result.code, 2);
    }
    assert.equal(peer.requests.length, 0);
  } finally { await peer.close(); await i.cleanup(); }
});
test('existing and interrupted output slots remain untouched and cannot be reused', async () => {
  const peer = await nativePeer(), i = await inputs(peer.fixture);
  try {
    const out = join(i.root, 'incomplete'); await mkdir(out, { mode: 0o700 }); await writeFile(join(out, 'patch.diff'), 'retained incomplete bytes', { mode: 0o600 });
    for (const args of [['draft', ...i.common, '--output', out], await nativeArgs(peer, i, out)]) {
      const result = await run(args); assert.equal(result.code, 2);
    }
    assert.equal(peer.requests.length, 0); assert.equal(await readFile(join(out, 'patch.diff'), 'utf8'), 'retained incomplete bytes');
    assert.deepEqual(await readdir(out), ['patch.diff']);
  } finally { await peer.close(); await i.cleanup(); }
});
test('competing draft creators produce one complete immutable output, not an overwrite', async () => {
  const i = await inputs();
  try {
    const out = join(i.root, 'draft'), args = ['draft', ...i.common, '--output', out];
    const results = await Promise.all([run(args), run(args)]);
    assert.deepEqual(results.map(r => r.code).sort(), [0, 2]);
    assert.equal(sha256(await readFile(join(out, 'manifest.json'))), i.hash);
    assert.ok((await readFile(join(out, 'patch.diff'))).equals(i.draft.bytes));
    assert.deepEqual((await readdir(out)).sort(), ['manifest.json', 'patch.diff']);
  } finally { await i.cleanup(); }
});
test('closed CLI profiles reject ambient credential, publication, retry and path overrides', async () => {
  const i = await inputs();
  try {
    const args = ['draft', ...i.common, '--output', join(i.root, 'draft')];
    for (const extra of [['--token-file', i.files.token], ['--apply', 'true'], ['--retry', '1'], ['--endpoint', 'https://bad.invalid/repo'],
      ['--changes', i.files.changes], ['--timeout-ms', '0'], ['--timeout-ms', '300001'], ['--unknown', 'x']]) {
      const response = await run([...args, ...extra]); assert.equal(response.code, 2); assert.equal(response.stdout, '');
    }
    assert.equal((await run(['draft'])).code, 2); assert.equal((await run(['--help'])).code, 0);
  } finally { await i.cleanup(); }
});
test('duplicate-key, malformed and oversized changes never leak input prose into diagnostics', async () => {
  const i = await inputs();
  try {
    const secret = 'PRIVATE_SOURCE_NOT_FOR_STDERR';
    for (const bytes of [Buffer.from(`{"schema":"frankengit-source-changes-v1","changes":[],"changes":"${secret}"}`),
      Buffer.from(`not json: ${secret}`), Buffer.from([0xff, 0xfe]), Buffer.alloc(CHANGES_INPUT_BYTES + 1, 65)]) {
      await writeFile(i.files.changes, bytes);
      const response = await run(['draft', ...i.common, '--output', join(i.root, 'draft')]);
      assert.equal(response.code, 2); assert.equal(response.stdout, ''); assert.equal(response.stderr.includes(secret), false);
      assert.ok(response.stderr.length < 1024);
    }
  } finally { await i.cleanup(); }
});
test('SIGTERM during native preparation closes the read without saving or retrying a candidate', async () => {
  const peer = await nativePeer(), i = await inputs(peer.fixture);
  try {
    peer.held = true;
    const args = await nativeArgs(peer, i), launched = launch(args);
    peer.onRequest = () => launched.child.kill('SIGTERM');
    const result = await launched.result;
    assert.equal(result.code, 3, result.stderr); assert.equal(result.signal, null);
    assert.deepEqual(peer.requests.map(r => r.route), ['source/prepare']);
    await assert.rejects(lstat(join(i.root, 'candidate')), { code: 'ENOENT' });
  } finally { await peer.close(); await i.cleanup(); }
});
test('CLI total deadline bounds a silent native preparation response', async () => {
  const peer = await nativePeer(), i = await inputs(peer.fixture);
  try {
    peer.held = true; const start = performance.now();
    const result = await run(await nativeArgs(peer, i, join(i.root, 'candidate'), ['--timeout-ms', '150']));
    assert.equal(result.code, 2); assert.ok(performance.now() - start < 3000);
    assert.equal(peer.requests.length, 1); assert.equal(result.stdout, '');
  } finally { await peer.close(); await i.cleanup(); }
});
for (const operation of ['draft', 'prepare']) {
  test(`${operation}: lost stdout preserves the actual published output and returns its original hashes`, async () => {
    const peer = await nativePeer(), i = await inputs(peer.fixture), errors = collector();
    try {
      const out = join(i.root, 'result'), args = operation === 'draft' ? ['draft', ...i.common, '--output', out] : await nativeArgs(peer, i, out);
      const stdout = new Writable({ write(_chunk, _encoding, done) { done(new Error('output closed')); } });
      assert.equal(await main(args, { stdout, stderr: errors.stream }), 4);
      const error = JSON.parse(errors.text()), receipt = error.retained_result;
      assert.equal(receipt.directory, out); assert.equal(error.remote_mutation_attempted, false);
      assert.equal(sha256(await readFile(join(out, 'manifest.json'))), receipt.manifest_sha256);
      if (operation === 'draft') assert.ok((await readFile(join(out, 'patch.diff'))).equals(i.draft.bytes));
      else assert.equal((await loadSourceEdit(out, receipt.manifest_sha256)).candidate_commit, receipt.candidate_commit);
    } finally { await peer.close(); await i.cleanup(); }
  });
}
test('explicit trusted TLS roots are required by the actual CLI transport', async () => {
  const peer = await nativePeer('sha256', { tls: true }), i = await inputs(peer.fixture);
  try {
    const ca = join(i.root, 'ca.pem'); await writeFile(ca, peer.ca, { mode: 0o600 });
    assert.equal((await run(await nativeArgs(peer, i))).code, 2); assert.equal(peer.requests.length, 0);
    const result = await run(await nativeArgs(peer, i, join(i.root, 'candidate'), ['--ca-file', ca]));
    assert.equal(result.code, 0, result.stderr); assert.equal(peer.requests.length, 2); assert.deepEqual(peer.failures, []);
  } finally { await peer.close(); await i.cleanup(); }
});
