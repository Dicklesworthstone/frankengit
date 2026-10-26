// Real fg is opt-in. The schema peer is used only for preflight/provider controls;
// generated saved context selects actual native objects, not a search oracle.
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, writeFile, readFile, chmod, lstat, readdir, realpath } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, dirname, resolve } from 'node:path';
import { createHash } from 'node:crypto';
import { deflateSync } from 'node:zlib';
import { spawn } from 'node:child_process';
import { createServer, request } from 'node:http';
import { once } from 'node:events';
import { fileURLToPath } from 'node:url';
import { captureSourcePackage, inspectSourcePackage } from '../operator/source_package.mjs';
import { runNativeProcess } from '../lib/native-process-owner.mjs';
import { fixture, peer, TOKEN, sha256 } from './source_package_fixture.mjs';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
const FG = process.env.FG_NATIVE_BIN;
const pin = `alg:1:${'a'.repeat(64)}`;
function pinnedFixture(format) {
  const f = fixture(format); f.envelope.snapshot_token = pin; f.context.retrieval.snapshot_token = pin; return f;
}
test('native capture requires an independent head before any source request', async t => {
  const p = await peer(t, pinnedFixture());
  const selected = { ...p.selected, expected_head: null };
  await assert.rejects(captureSourcePackage(p.context, p.contextHash, selected, p.expected, TOKEN,
    { nativeFg: process.execPath }), /independent.*head/i);
  assert.equal(p.requests.length, 0);
});
test('native capture refuses unsupported URL and proof-call budget before network', async t => {
  const p = await peer(t, pinnedFixture());
  const context = Buffer.from(JSON.stringify(p.f.context));
  await assert.rejects(captureSourcePackage(context, sha256(context),
    { ...p.selected, endpoint: 'https://example.invalid/repo' }, p.expected, TOKEN,
    { nativeFg: process.execPath }), /numeric.loopback/i);
  await assert.rejects(captureSourcePackage(p.context, p.contextHash, p.selected, p.expected, TOKEN,
    { nativeFg: process.execPath, limits: { package: { maxBlobRequests: 9 } } }), /proof.*budget/i);
  assert.equal(p.requests.length, 0);
});
test('successful wrong provider cannot substitute an empty-file native receipt', async t => {
  const p = await peer(t, pinnedFixture());
  await assert.rejects(captureSourcePackage(p.context, p.contextHash, p.selected, p.expected, TOKEN,
    { nativeFg: await realpath('/usr/bin/true') }), error => error.code === 'native_source_proof_invalid_report');
  assert.ok(p.requests.length > 0, 'existing content verification still runs');
});
test('unknown scratch from an explicit stand-in is retained and reported', async t => {
  const p = await peer(t, pinnedFixture());
  const directory = await mkdtemp(join(tmpdir(), 'fg-package-provider-')), provider = join(directory, 'provider.mjs');
  await writeFile(provider, `#!${process.execPath}\nimport {writeFileSync} from 'node:fs';\nimport {dirname,join} from 'node:path';\nconst output=process.argv[process.argv.indexOf('--output')+1];\nwriteFileSync(join(dirname(output),'unknown'),'retain this evidence',{mode:0o600});\n`, { mode: 0o700 });
  let retained;
  await assert.rejects(captureSourcePackage(p.context, p.contextHash, p.selected, p.expected, TOKEN,
    { nativeFg: provider }), asyncError => {
      assert.equal(asyncError.code, 'native_source_proof_invalid_report');
      assert.ok(asyncError.nativeScratch); retained = asyncError.nativeScratch; t.diagnostic(`retained unknown scratch: ${asyncError.nativeScratch}`);
      return true;
    });
  assert.equal(await readFile(join(retained, 'unknown'), 'utf8'), 'retain this evidence');
  assert.equal((await lstat(join(retained, 'token'))).mode & 0o777, 0o600);
});

async function run(dir, label, executable, args, expected = 0) {
  const r = await runNativeProcess(executable, args, { timeoutMs: 60000, stdoutLimit: 16 * 1024 * 1024,
    stderrLimit: 1024 * 1024 });
  await writeFile(join(dir, `${label}.stdout`), r.stdout, { flag: 'wx', mode: 0o600 });
  await writeFile(join(dir, `${label}.stderr`), r.stderr, { flag: 'wx', mode: 0o600 });
  assert.equal(r.signal, null); assert.equal(r.code, expected, r.stderr.toString()); return r;
}
async function native(t, format) {
  const dir = await mkdtemp(join(tmpdir(), 'fg-native-package-test-')); await chmod(dir, 0o700);
  t.diagnostic(`retained native artifacts: ${dir}`);
  const f = fixture(format), source = join(dir, 'source'), storage = join(dir, 'node');
  await mkdir(join(source, 'refs/heads'), { recursive: true, mode: 0o700 });
  await writeFile(join(source, 'HEAD'), 'ref: refs/heads/main\n');
  await writeFile(join(source, 'config'), `[core]\nbare = true\nrepositoryformatversion = ${format === 'sha1' ? '0\n' : '1\n[extensions]\nobjectformat = sha256\n'}`);
  async function loose(kind, body) {
    const framed = Buffer.concat([Buffer.from(`${kind} ${body.length}\0`), body]);
    const id = createHash(format).update(framed).digest('hex'), parent = join(source, 'objects', id.slice(0, 2));
    await mkdir(parent, { recursive: true, mode: 0o700 });
    await writeFile(join(parent, id.slice(2)), deflateSync(framed)); return id;
  }
  for (const row of f.rows) assert.equal(await loose('blob', row.bytes), row.id);
  await loose('blob', Buffer.from('/private')); await loose('tree', Buffer.alloc(0));
  for (const tree of f.trees.values()) assert.equal(await loose('tree', tree.bytes), tree.id);
  assert.equal(await loose('commit', f.commit), f.commitId);
  await writeFile(join(source, 'refs/heads/main'), `${f.commitId}\n`);
  const ids = [f.envelope.tenant_id, f.envelope.repository_id], principal = '4'.repeat(32);
  await run(dir, 'init', FG, ['init', storage, ...ids, format, '--root-layout', 'ref-merkle-v1']);
  await run(dir, 'import', FG, ['import', storage, ...ids, principal, 'source-package-fixture', source]);
  const show = JSON.parse((await run(dir, 'pin', FG, ['show', storage, ...ids, '--trusted-local',
    '--ref', 'refs/heads/main', '--object-format', format, '--path', 'empty', '--max-bytes', '1'])).stdout);
  for (const name of Object.keys(f.envelope)) if (Object.hasOwn(show, name)) f.envelope[name] = show[name];
  f.context.retrieval = { ...f.context.retrieval, ...f.envelope, type: 'source_search_initial', profile: 'source-initial-retrieval-v1' };
  const tokenFile = join(dir, 'read-token'), credentials = join(dir, 'credentials'), stop = join(dir, 'stop');
  await writeFile(tokenFile, `${TOKEN}\n`, { mode: 0o600 });
  const header = (await run(dir, 'credentials-header', FG,
    ['serve-http', storage, ...ids, '127.0.0.1:0', '--trusted-local', '--print-credentials-header'])).stdout;
  await writeFile(credentials, Buffer.concat([header, Buffer.from(`${sha256(TOKEN)} ${principal} read\n`)]), { mode: 0o600 });
  const child = spawn(FG, ['serve-http', storage, ...ids, '127.0.0.1:0', '--trusted-local',
    '--credentials-file', credentials, '--allow-source', '--continuous', '--stop-file', stop,
    '--max-in-flight', '2', '--session-timeout-secs', '60'], { stdio: ['ignore', 'pipe', 'pipe'] });
  const out = [], err = []; let ready, text = '', size = 0;
  child.stdout.on('data', b => { out.push(b); text += b; size += b.length;
    for (const line of text.split('\n').slice(0, -1)) { try { const x = JSON.parse(line); if (x.type === 'smart_http_listening') ready = x; } catch {} }
    if (size > 1024 * 1024) child.kill('SIGTERM'); });
  child.stderr.on('data', b => { err.push(b); size += b.length; if (size > 1024 * 1024) child.kill('SIGTERM'); });
  const closed = once(child, 'close');
  t.after(async () => {
    if (child.exitCode === null && child.signalCode === null) await writeFile(stop, '', { flag: 'wx' });
    const watchdog = setTimeout(() => child.kill('SIGKILL'), 10000);
    try { const [code, signal] = await closed; assert.equal(code, 0); assert.equal(signal, null); }
    finally { clearTimeout(watchdog); await writeFile(join(dir, 'server.stdout'), Buffer.concat(out)); await writeFile(join(dir, 'server.stderr'), Buffer.concat(err)); }
    const drained = Buffer.concat(out).toString().trim().split('\n').map(JSON.parse).filter(x => x.type === 'smart_http_drained');
    assert.equal(drained.length, 1); assert.equal(drained[0].accepted, drained[0].completed_transports + drained[0].refused_transports);
  });
  const until = performance.now() + 30000;
  while (!ready && performance.now() < until) {
    assert.equal(child.exitCode, null, Buffer.concat(err).toString());
    await new Promise(r => setTimeout(r, 10));
  }
  assert.ok(ready?.source_enabled, Buffer.concat(err).toString());
  // Local fg show supplies the independent head; the owned native listener's
  // readiness record supplies its actual incarnation (show omits that field).
  f.envelope.repository_incarnation = ready.repository_incarnation;
  f.context.retrieval.repository_incarnation = ready.repository_incarnation;
  const selected = { endpoint: ready.url, tenant_id: f.envelope.tenant_id, repository_id: f.envelope.repository_id,
    repository_incarnation: f.envelope.repository_incarnation, object_format: format, ref: f.envelope.ref,
    expected_commit: f.commitId, expected_head: show.snapshot_token };
  const context = Buffer.from(JSON.stringify(f.context));
  return { dir, f, context, selected, contextHash: sha256(context), tokenFile, storage, ids };
}
async function proxy(t, endpoint, mode) {
  const sockets = new Set(), seen = []; let resolveHeld;
  const held = new Promise(r => { resolveHeld = r; });
  const server = createServer((req, res) => {
    const proof = req.url.includes('/source/verified-blob'); seen.push({ proof, url: req.url });
    if (proof && mode === 'hold') { resolveHeld(); req.socket.once('close', () => res.destroy()); return; }
    const target = new URL(endpoint); target.pathname = req.url.split('?')[0]; target.search = req.url.includes('?') ? req.url.slice(req.url.indexOf('?')) : '';
    const upstream = request(target, { method: req.method, headers: { ...req.headers, host: target.host,
      'user-agent': 'frankengit-agent (+https://github.com/Dicklesworthstone/frankengit)' } }, incoming => {
      const chunks = []; let length = 0;
      incoming.on('data', b => { length += b.length; if (length > 34 * 1024 * 1024) upstream.destroy(); else chunks.push(b); });
      incoming.on('end', () => { const body = Buffer.concat(chunks); if (proof && mode === 'tamper' && incoming.statusCode === 200 &&
          target.searchParams.get('path_hex') === Buffer.from('src/a.txt').toString('hex')) body[body.length - 1] ^= 1;
        res.writeHead(incoming.statusCode, incoming.headers); res.end(body); });
      incoming.on('error', () => res.destroy());
    });
    upstream.on('error', () => res.destroy()); res.on('close', () => upstream.destroy()); req.pipe(upstream);
  });
  server.on('connection', s => { sockets.add(s); s.once('close', () => sockets.delete(s)); });
  await new Promise(r => server.listen(0, '127.0.0.1', r));
  t.after(async () => { for (const socket of sockets) socket.destroy(); await new Promise(r => server.close(r)); });
  return { endpoint: `http://127.0.0.1:${server.address().port}${new URL(endpoint).pathname}`, seen, held };
}
for (const format of ['sha1', 'sha256']) test(`${format}: real native proofs gate package publication and offline interchange`,
  { skip: !FG, timeout: 180000 }, async t => {
    const p = await native(t, format), files = {};
    const acquired = await captureSourcePackage(p.context, p.contextHash, p.selected, p.f.expected, TOKEN,
      { nativeFg: FG, limits: { timeoutMs: 60000 } });
    assert.equal(acquired.receipt.native_read.verified_at_capture, true);
    for (const [name, bytes] of Object.entries({ selection: JSON.stringify(p.selected), context: p.context,
      expect: JSON.stringify(p.f.expected), token: `${TOKEN}\n`, limits: JSON.stringify({ timeoutMs: 60000 }) })) {
      files[name] = join(p.dir, `${name}.json`); await writeFile(files[name], bytes, { mode: 0o600 });
    }
    const output = join(p.dir, 'package.json'), common = ['--selection', files.selection, '--context', files.context,
      '--context-sha256', p.contextHash, '--expect', files.expect, '--limits', files.limits];
    const r = await run(p.dir, 'capture', process.execPath, [join(ROOT, 'scripts/fg_source_package.mjs'),
      'capture', ...common, '--token-file', files.token, '--output', output, '--native-fg', FG]);
    const receipt = JSON.parse(r.stdout), bytes = await readFile(output);
    assert.equal(receipt.native_read.verified_at_capture, true); assert.equal(receipt.native_read.head, p.selected.expected_head);
    assert.equal(receipt.native_read.files, 4); assert.equal(receipt.native_read.binary_sha256, sha256(await readFile(FG)));
    assert.equal(receipt.verified.authorityVerified, false, 'portable format must not claim retained authority proofs');
    assert.equal(receipt.read_metrics.blobRequests, 6); assert.equal(receipt.read_metrics.nativeProofRequests, 4);
    assert.equal(receipt.package_sha256, sha256(bytes)); assert.equal((await lstat(output)).mode & 0o777, 0o600);
    assert.deepEqual(bytes, acquired.bytes, 'module and command retain the same portable format');
    assert.equal(r.stdout.includes(TOKEN), false);
    const replay = await run(p.dir, 'inspect', process.execPath, [join(ROOT, 'scripts/fg_source_package.mjs'),
      'inspect', ...common, '--package', output, '--package-sha256', receipt.package_sha256]);
    assert.equal(JSON.parse(replay.stdout).native_read, undefined, 'offline replay does not re-attest a capture event');
    await run(p.dir, 'old-verifier', process.execPath, [join(ROOT, 'scripts/fg_verify_source_package.mjs'),
      '--package', output, '--expect', files.expect]);
    const again = await run(p.dir, 'existing-output', process.execPath, [join(ROOT, 'scripts/fg_source_package.mjs'),
      'capture', ...common, '--token-file', files.token, '--output', output, '--native-fg', FG], 2);
    assert.equal(JSON.parse(again.stderr).phase, 'private_inputs'); assert.deepEqual(await readFile(output), bytes);
    const bad = await proxy(t, p.selected.endpoint, 'tamper');
    const tamperedSelection = join(p.dir, 'tampered-selection.json'), refusedOutput = join(p.dir, 'tampered-package.json');
    await writeFile(tamperedSelection, JSON.stringify({ ...p.selected, endpoint: bad.endpoint }), { mode: 0o600 });
    const negative = await run(p.dir, 'tampered-proof', process.execPath, [join(ROOT, 'scripts/fg_source_package.mjs'),
      'capture', ...common.map(value => value === files.selection ? tamperedSelection : value),
      '--token-file', files.token, '--output', refusedOutput, '--native-fg', FG], 2);
    assert.equal(negative.stdout.length, 0); assert.equal(JSON.parse(negative.stderr).native_code, 'verification_refused');
    await assert.rejects(lstat(refusedOutput), error => error.code === 'ENOENT');
    assert.ok(bad.seen.some(x => x.proof));
    const held = await proxy(t, p.selected.endpoint, 'hold'), stop = new AbortController();
    const pending = captureSourcePackage(p.context, p.contextHash, { ...p.selected, endpoint: held.endpoint },
      p.f.expected, TOKEN, { nativeFg: FG, signal: stop.signal, limits: { timeoutMs: 60000 } });
    await held.held; stop.abort();
    await assert.rejects(pending, error => error.code === 'native_process_cancelled' || error.name === 'AbortError');
    const stale = Buffer.from(JSON.stringify({ ...p.f.context, retrieval: { ...p.f.context.retrieval, snapshot_token: pin } }));
    await assert.rejects(captureSourcePackage(stale, sha256(stale), { ...p.selected, expected_head: pin },
      p.f.expected, TOKEN, { nativeFg: FG, limits: { timeoutMs: 60000 } }));
    await assert.rejects(captureSourcePackage(p.context, p.contextHash, p.selected, p.f.expected, '0'.repeat(64),
      { nativeFg: FG, limits: { timeoutMs: 60000 } }));
    const final = JSON.parse((await run(p.dir, 'final-pin', FG, ['show', p.storage, ...p.ids, '--trusted-local',
      '--ref', 'refs/heads/main', '--object-format', format, '--path', 'empty', '--max-bytes', '1'])).stdout);
    assert.equal(final.snapshot_token, p.selected.expected_head, 'read-only package acquisition leaves authority unchanged');
    assert.equal((await readdir(p.dir)).some(n => n.includes('.writing-')), false);
  });
