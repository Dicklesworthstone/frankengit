import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, chmod, writeFile, readFile, lstat, readdir, unlink, symlink, link, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawn } from 'node:child_process';
import { Writable } from 'node:stream';
import { main } from '../fg_source_package.mjs';
import { fixture, peer, TOKEN, sha256 } from './source_package_fixture.mjs';
const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
const CLI = join(ROOT, 'scripts/fg_source_package.mjs');
// Capture before MockTimers replaces globals: the safety watchdog stays real.
const realSetTimeout = globalThis.setTimeout, realClearTimeout = globalThis.clearTimeout;
async function inputs(t, p) {
  const dir = await mkdtemp(join(tmpdir(), 'fg-source-package-')); await chmod(dir, 0o700);
  t.after(() => rm(dir, { recursive: true, force: true }));
  const files = Object.fromEntries(['selection', 'expect', 'context', 'token', 'package', 'limits'].map(name => [name, join(dir, `${name}.json`)]));
  const expectedBytes = Buffer.from(`${JSON.stringify(p.expected, null, 2)}\n`);
  for (const [name, bytes] of [['selection', JSON.stringify(p.selected)], ['expect', expectedBytes], ['context', p.context], ['token', `${TOKEN}\r\n`]]) {
    await writeFile(files[name], bytes, { mode: 0o600 });
  }
  const common = ['--selection', files.selection, '--context', files.context, '--context-sha256', p.contextHash, '--expect', files.expect];
  return { dir, files, expectedBytes,
    capture: ['capture', ...common, '--token-file', files.token, '--output', files.package],
    inspect: hash => ['inspect', ...common, '--package', files.package, '--package-sha256', hash] };
}
function launch(t, args, script = CLI) {
  const child = spawn(process.execPath, [script, ...args], { cwd: ROOT, stdio: ['ignore', 'pipe', 'pipe'] });
  t.after(() => { if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL'); });
  const result = new Promise((resolveResult, reject) => {
    const out = [], err = []; let size = 0;
    const timer = setTimeout(() => { child.kill('SIGKILL'); reject(new Error('CLI child deadline exceeded')); }, 10000);
    for (const [stream, chunks] of [[child.stdout, out], [child.stderr, err]]) stream.on('data', bytes => {
      size += bytes.length;
      if (size > 1024 * 1024) { child.kill('SIGKILL'); reject(new Error('CLI output bound exceeded')); }
      else chunks.push(bytes);
    });
    child.once('error', error => { clearTimeout(timer); reject(error); });
    child.once('close', (code, signal) => { clearTimeout(timer); resolveResult({ code, signal, stdout: Buffer.concat(out).toString(), stderr: Buffer.concat(err).toString() }); });
  });
  return { child, result };
}
const run = (t, args, script) => launch(t, args, script).result;
const absent = async path => assert.rejects(lstat(path), error => error.code === 'ENOENT');
function sink(onWrite = () => {}) {
  const chunks = [];
  const stream = new Writable({ write(bytes, _encoding, done) { chunks.push(bytes); onWrite(); done(); } });
  return { stream, text: () => Buffer.concat(chunks).toString() };
}

for (const format of ['sha1', 'sha256']) test(`${format}: real CLI capture, offline inspect and preexisting verifier interoperate`, async t => {
  const p = await peer(t, fixture(format, { paged: true })), i = await inputs(t, p);
  const result = await run(t, i.capture); assert.equal(result.code, 0, result.stderr); assert.equal(result.stderr, '');
  const receipt = JSON.parse(result.stdout), bytes = await readFile(i.files.package), stat = await lstat(i.files.package);
  assert.equal(stat.mode & 0o777, 0o600); assert.equal(stat.nlink, 1); assert.equal(stat.uid, process.getuid());
  assert.equal(receipt.package_sha256, sha256(bytes)); assert.equal(receipt.context_sha256, p.contextHash);
  assert.equal(receipt.expected_input_sha256, sha256(i.expectedBytes));
  assert.equal(receipt.expected_selection_sha256, sha256(Buffer.from(JSON.stringify(p.expected))));
  assert.equal(receipt.verified.selected_file_count, 4); assert.equal(receipt.verified.files, undefined);
  assert.equal(receipt.read_metrics.metadataRequests, 4); assert.equal(receipt.read_metrics.blobRequests, 6);
  assert.equal(receipt.context_excerpt_bytes_verified, true); assert.equal(receipt.stop_requested, false);
  assert.ok(result.stdout.length < 4096);
  for (const secret of [TOKEN, 'Untrusted source', p.selected.endpoint, p.f.rows[1].pathHex]) assert.equal(result.stdout.includes(secret), false);
  const before = p.requests.length; await unlink(i.files.token);
  const replay = await run(t, i.inspect(receipt.package_sha256)); assert.equal(replay.code, 0, replay.stderr);
  assert.equal(JSON.parse(replay.stdout).expected_input_sha256, receipt.expected_input_sha256);
  const old = await run(t, ['--package', i.files.package, '--expect', i.files.expect], join(ROOT, 'scripts/fg_verify_source_package.mjs'));
  assert.equal(old.code, 0, old.stderr); assert.equal(JSON.parse(old.stdout).files.length, 4);
  assert.equal(p.requests.length, before); assert.ok((await readFile(i.files.context)).equals(p.context));
  assert.ok((await readFile(i.files.expect)).equals(i.expectedBytes));
  assert.equal((await readdir(i.dir)).some(name => name.includes('.writing-')), false);
});

for (const kind of ['existing output', 'symlink input', 'hardlink input', 'public input', 'public directory', 'invalid token', 'empty token', 'oversized expectation']) {
  test(`${kind} refuses without source I/O or output replacement`, async t => {
    const p = await peer(t), i = await inputs(t, p);
    if (kind === 'existing output') await writeFile(i.files.package, 'keep original', { mode: 0o600 });
    if (kind === 'symlink input') { await unlink(i.files.context); await symlink(i.files.expect, i.files.context); }
    if (kind === 'hardlink input') await link(i.files.context, join(i.dir, 'alias'));
    if (kind === 'public input') await chmod(i.files.context, 0o644);
    if (kind === 'public directory') await chmod(i.dir, 0o755);
    if (kind === 'invalid token') await writeFile(i.files.token, 'NEVER-EMIT-THIS-SECRET');
    if (kind === 'empty token') await writeFile(i.files.token, '');
    if (kind === 'oversized expectation') await writeFile(i.files.expect, Buffer.alloc(128 * 1024 + 1, 32));
    const result = await run(t, i.capture); assert.equal(result.code, 2, result.stderr); assert.equal(result.stdout, '');
    assert.equal(result.stderr.includes('NEVER-EMIT'), false); assert.equal(p.requests.length, 0);
    if (kind === 'existing output') assert.equal(await readFile(i.files.package, 'utf8'), 'keep original');
    else await absent(i.files.package);
  });
}

test('CLI grammar is closed and offline inspect cannot accept acquisition credentials', async t => {
  const p = await peer(t), i = await inputs(t, p);
  const cases = [[], ['capture'], ['--help', '--force'], [...i.capture, '--force', 'true'],
    [...i.capture, '--token-file', i.files.token], i.capture.slice(0, -1),
    [...i.inspect('0'.repeat(64)), '--token-file', i.files.token],
    i.capture.map(value => value === p.contextHash ? 'not-a-retained-hash' : value),
    i.capture.map(value => value === i.files.context ? 'relative.json' : value)];
  for (const args of cases) { const result = await run(t, args); assert.equal(result.code, 2, JSON.stringify(args)); assert.equal(result.stdout, ''); }
  assert.equal(p.requests.length, 0); await absent(i.files.package);
  const help = await run(t, ['--help']); assert.equal(help.code, 0); assert.match(help.stdout, /prepare|independently/);
});

test('malformed private JSON and budget preflight do not expose source or spend reads', async t => {
  const p = await peer(t), i = await inputs(t, p);
  await writeFile(i.files.selection, '{"secret":"DO-NOT-EMIT-PRIVATE-BYTES" BAD');
  const bad = await run(t, i.capture); assert.equal(bad.code, 2); assert.equal(bad.stderr.includes('PRIVATE-BYTES'), false);
  await writeFile(i.files.selection, JSON.stringify(p.selected));
  await writeFile(i.files.limits, JSON.stringify({ package: { maxBlobRequests: 5 } }), { mode: 0o600 });
  const limited = await run(t, [...i.capture, '--limits', i.files.limits]); assert.equal(limited.code, 2);
  assert.equal(p.requests.length, 0); await absent(i.files.package);
});

for (const failure of ['revocation', 'tampered blob', 'changed context hash', 'dishonest excerpt']) test(`${failure} never publishes a package`, async t => {
  const p = await peer(t, fixture(), (value, call) => {
    if (failure === 'revocation') { call.res.writeHead(401); call.res.end('PRIVATE SERVER DIAGNOSTIC'); return false; }
    if (failure === 'tampered blob' && value.type === 'source_blob' && value.content_hex) value.content_hex = 'ff' + value.content_hex.slice(2);
  });
  if (failure === 'dishonest excerpt') {
    const context = JSON.parse(p.context); context.native_response.files[1].excerpts[0].untrusted_bytes_hex = 'ff'.repeat(8);
    p.context = Buffer.from(JSON.stringify(context)); p.contextHash = sha256(p.context);
  }
  const i = await inputs(t, p);
  if (failure === 'changed context hash') await writeFile(i.files.context, Buffer.concat([p.context, Buffer.from(' ')]));
  const result = await run(t, i.capture); assert.equal(result.code, 2); assert.equal(result.stdout, '');
  assert.equal(result.stderr.includes('PRIVATE SERVER'), false); await absent(i.files.package);
  assert.equal((await readdir(i.dir)).some(name => name.includes('.writing-')), false);
});

test('competing captures never overwrite: one complete package, no temporary debris', async t => {
  let release, arrivals = 0;
  const gate = new Promise(resolveGate => { release = resolveGate; });
  const p = await peer(t, fixture(), async value => {
    if (value.type === 'source_log') { if (++arrivals === 2) release(); await gate; }
  });
  const i = await inputs(t, p);
  const results = await Promise.all([run(t, i.capture), run(t, i.capture)]);
  assert.deepEqual(results.map(result => result.code).sort(), [0, 4]);
  const accepted = JSON.parse(results.find(result => result.code === 0).stdout);
  const refused = JSON.parse(results.find(result => result.code === 4).stderr);
  assert.equal(refused.phase, 'publication'); assert.equal(refused.publication_unconfirmed.package_sha256, accepted.package_sha256);
  assert.equal(sha256(await readFile(i.files.package)), accepted.package_sha256);
  assert.equal((await readdir(i.dir)).some(name => name.includes('.writing-')), false);
  const checked = await run(t, i.inspect(accepted.package_sha256)); assert.equal(checked.code, 0, checked.stderr);
});

test('SIGTERM during a real HTTP read exits cancelled before local publication', async t => {
  let entered;
  const reading = new Promise(resolveRead => { entered = resolveRead; });
  const p = await peer(t, fixture(), (_value, call) => { call.res.writeHead(200, { 'Content-Type': 'application/json' }); call.res.write('{'); entered(); return false; });
  const i = await inputs(t, p), running = launch(t, i.capture);
  await reading; running.child.kill('SIGTERM');
  const result = await running.result; assert.equal(result.code, 3, result.stderr); assert.equal(result.signal, null);
  const error = JSON.parse(result.stderr); assert.equal(error.stop_requested, true); assert.equal(error.publication_unconfirmed, undefined);
  assert.equal(p.requests.length, 1); await absent(i.files.package);
});

test('deterministic 200ms deadline aborts an entered HTTP response without partial output', { timeout: 10000 }, async t => {
  let entered, now = 0;
  const reading = new Promise(resolveRead => { entered = resolveRead; });
  const p = await peer(t, fixture(), (_value, call) => {
    call.res.writeHead(200, { 'Content-Type': 'application/json' }); call.res.write('{'); entered(); return false;
  });
  const i = await inputs(t, p); await writeFile(i.files.limits, '{"timeoutMs":200}', { mode: 0o600 });
  // Host scheduling can expire the whole budget during private-input reads.
  // Control only the clock; keep the real files, HTTP body, deadline and abort.
  t.mock.method(performance, 'now', () => now);
  t.mock.timers.enable({ apis: ['setTimeout'] });
  let watchdog;
  const expired = new Promise((_resolve, reject) => {
    watchdog = realSetTimeout(() => { process.emit('SIGTERM'); reject(new Error('Held-response test exceeded its real 10s guard.')); }, 10000);
  });
  t.after(() => realClearTimeout(watchdog));
  const guarded = promise => Promise.race([promise, expired]);
  const stdout = sink(), stderr = sink(); let completed = false;
  const pending = main([...i.capture, '--limits', i.files.limits], { stdout: stdout.stream, stderr: stderr.stream });
  pending.then(() => { completed = true; });
  await guarded(reading); assert.equal(p.requests.length, 1);
  now = 199; t.mock.timers.tick(199); await new Promise(setImmediate);
  assert.equal(completed, false, 'held body remains pending before the unchanged deadline');
  now = 200; t.mock.timers.tick(1);
  assert.equal(await guarded(pending), 2); assert.equal(JSON.parse(stderr.text()).phase, 'capture');
  assert.equal(stdout.text(), ''); await absent(i.files.package); assert.equal(p.requests.length, 1);
});

test('the same 200ms budget includes preflight before any HTTP request', { timeout: 10000 }, async t => {
  const p = await peer(t), i = await inputs(t, p), stdout = sink(), stderr = sink(); let now = 0;
  await writeFile(i.files.limits, '{"timeoutMs":200}', { mode: 0o600 });
  t.mock.method(performance, 'now', () => now);
  const pending = main([...i.capture, '--limits', i.files.limits], { stdout: stdout.stream, stderr: stderr.stream });
  now = 201;
  assert.equal(await pending, 2); assert.equal(JSON.parse(stderr.text()).phase, 'private_inputs');
  assert.equal(stdout.text(), ''); assert.equal(p.requests.length, 0); await absent(i.files.package);
});

test('stdout failure retains the published file and original inspection hashes', async t => {
  const p = await peer(t), i = await inputs(t, p), stderr = sink();
  const stdout = new Writable({ write(_bytes, _encoding, done) { done(new Error('sink failed')); } });
  const before = process.listenerCount('SIGTERM');
  const code = await main(i.capture, { stdout, stderr: stderr.stream }); assert.equal(code, 4);
  const error = JSON.parse(stderr.text()); assert.equal(error.phase, 'stdout');
  assert.equal(error.retained_receipt.package_sha256, sha256(await readFile(i.files.package)));
  assert.equal(process.listenerCount('SIGTERM'), before);
  const replay = await run(t, i.inspect(error.retained_receipt.package_sha256)); assert.equal(replay.code, 0, replay.stderr);
});

test('publication race with a selected late stop preserves uncertainty rather than reporting absence', async t => {
  // Occupy the destination after network preflight but before create-only link.
  // A stop requested while reporting that local effect must not erase its receipt.
  let i;
  const p = await peer(t, fixture(), async value => {
    if (value.type === 'source_blob' && i && !i.occupied) {
      i.occupied = true; await writeFile(i.files.package, 'original writer', { mode: 0o600 });
    }
  });
  i = await inputs(t, p); const err = sink(() => process.emit('SIGTERM')), out = sink();
  const code = await main(i.capture, { stdout: out.stream, stderr: err.stream });
  assert.equal(code, 4); const error = JSON.parse(err.text());
  assert.equal(error.phase, 'publication'); assert.ok(error.publication_unconfirmed.package_sha256);
  assert.equal(await readFile(i.files.package, 'utf8'), 'original writer');
  assert.equal((await readdir(i.dir)).some(name => name.includes('.writing-')), false);
});

test('offline inspection rejects changed hashes, package bytes and original context', async t => {
  const p = await peer(t), i = await inputs(t, p), result = await run(t, i.capture);
  assert.equal(result.code, 0, result.stderr); const receipt = JSON.parse(result.stdout), count = p.requests.length;
  assert.equal((await run(t, i.inspect('0'.repeat(64)))).code, 2);
  const original = await readFile(i.files.package), tampered = JSON.parse(original); tampered.blobs.find(row => row.bytesHex).bytesHex += '00';
  const changed = Buffer.from(JSON.stringify(tampered)); await writeFile(i.files.package, changed);
  assert.equal((await run(t, i.inspect(sha256(changed)))).code, 2);
  await writeFile(i.files.package, original); await writeFile(i.files.context, Buffer.concat([p.context, Buffer.from(' ')]));
  assert.equal((await run(t, i.inspect(receipt.package_sha256))).code, 2);
  assert.equal(p.requests.length, count);
});
