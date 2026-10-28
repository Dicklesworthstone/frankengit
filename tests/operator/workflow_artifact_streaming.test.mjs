// Real files and loopback peers; these are operator contracts, not native fg acceptance.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { createServer } from 'node:http';
import { once, getEventListeners } from 'node:events';
import { createReadStream } from 'node:fs';
import { mkdtemp, open, writeFile, readFile, readdir, stat, rm, symlink, chmod } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { downloadArtifact, artifactDownloadCommand, publishArtifactStream, ArtifactDownloadError }
  from '../../scripts/operator/workflow_artifact_download.mjs';

const hash = bytes => createHash('sha256').update(bytes).digest('hex');
const expected = bytes => ({ payload_bytes: bytes.length, payload_sha256: hash(bytes) });
const token = 'ab'.repeat(32), id = 'cd'.repeat(32);
const scope = { tenant_id: '11'.repeat(16), repository_id: '22'.repeat(16),
  repository_incarnation_id: '33'.repeat(16), trust_domain: 'trusted-workflow-local-owner' };
async function directory(t) {
  const dir = await mkdtemp(join(tmpdir(), 'fg-artifact-stream-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  return dir;
}
async function absent(path) { await assert.rejects(stat(path), { code: 'ENOENT' }); }
async function eventually(check) {
  const deadline = Date.now() + 3000;
  while (!await check()) {
    assert(Date.now() < deadline, 'observable streaming progress did not occur');
    await delay(5);
  }
}
async function fileHash(path) {
  const digest = createHash('sha256');
  for await (const chunk of createReadStream(path)) digest.update(chunk);
  return digest.digest('hex');
}
async function handlePrototype(t, dir) {
  const probe = await open(join(dir, 'probe'), 'wx', 0o600);
  const proto = Object.getPrototypeOf(probe);
  await probe.close();
  return proto;
}
async function fixture(t, { bytes = Buffer.from('verified\0binary\xff'), log = false, handle } = {}) {
  const dir = await directory(t), output = join(dir, 'output');
  const file = { path_hex: '6f7574', artifact_id_sha256: id, ...expected(bytes), executable: true };
  const manifest = { type: 'trusted_workflow_artifact_provenance', schema_version: 1,
    producer: { tenant_id: scope.tenant_id, repository_id: scope.repository_id,
      repository_incarnation: scope.repository_incarnation_id }, job_id_hex: '6275696c64',
    outputs: [file], job_success_asserted: false, cache_reuse_authorized: false };
  const receipt = { type: 'trusted_workflow_artifact_receipt', manifest_id_sha256: 'ef'.repeat(32), manifest };
  if (log) {
    delete manifest.outputs;
    receipt.type = 'trusted_workflow_log_receipt';
    manifest.type = 'trusted_workflow_log_provenance'; manifest.observed_job_outcome = 'failed';
    manifest.logs = ['stdout', 'stderr'].map(stream => ({ step_index: 0, step_name_hex: null,
      script_sha256: '12'.repeat(32), stream, observed_step_outcome: 'failed', exit_code: 2,
      output_complete: false, artifact_id_sha256: id, ...expected(bytes) }));
  }
  const metadata = { type: 'artifact_metadata', schema_version: 1, ...scope, scope_sha256: '34'.repeat(32),
    artifact_id: id, ...expected(bytes), media_type: 'application/octet-stream', kind: log ? 'build_log' : 'ci_artifact',
    build_capsule_sha256: null, check_receipt_sha256: null, source_rcr_sha256: null, retention_canonical_hex: '00',
    payload_verified: true, provenance_authenticated: false, canonical_repository_published: false,
    retention_enforced: false, read_only: true };
  const calls = [], sockets = new Set(), errors = [];
  const server = createServer((request, response) => {
    request.resume();
    request.once('end', () => {
      calls.push(request.url);
      void (async () => {
        const content = request.url.endsWith('/content');
        assert.equal(request.headers.authorization, `Bearer ${token}`);
        assert.equal(request.headers['idempotency-key'], undefined);
        if (await handle?.({ content, request, response, metadata, bytes, dir, output })) return;
        const body = content ? bytes : Buffer.from(JSON.stringify(metadata));
        response.writeHead(200, { 'Content-Type': content ? 'application/octet-stream' : 'application/json',
          'Content-Length': body.length,
          ...(content ? { 'Content-Disposition': `attachment; filename="artifact-${id}"` } : {}) });
        response.end(body);
      })().catch(error => { errors.push(error); response.destroy(); });
    });
  });
  server.on('connection', socket => { sockets.add(socket); socket.once('close', () => sockets.delete(socket)); });
  server.listen(0, '127.0.0.1'); await once(server, 'listening');
  t.after(async () => {
    for (const socket of sockets) socket.destroy();
    await new Promise(resolve => server.close(resolve));
    assert.deepEqual(errors, []);
  });
  const input = { endpoint: `http://127.0.0.1:${server.address().port}/repo.git`, scope,
    job_id_hex: manifest.job_id_hex, ...(log ? { step_index: 0, stream: 'stderr' } : { path_hex: file.path_hex }) };
  return { dir, output, input, receipt, metadata, calls, sockets, bytes,
    send: options => downloadArtifact(input, receipt, token, output, options) };
}
function contentHeaders(size) {
  return { 'Content-Type': 'application/octet-stream', 'Content-Length': size,
    'Content-Disposition': `attachment; filename="artifact-${id}"` };
}

test('stream stages each chunk privately before requesting the next and publishes only verified bytes', async t => {
  const dir = await directory(t), output = join(dir, 'output');
  const bytes = Buffer.alloc(192 * 1024 + 17, 0xa5);
  let consumed = 0, finalized = false;
  async function* source() {
    try {
      for (let offset = 0; offset < bytes.length; offset += 32768) {
        if (offset) {
          const names = await readdir(dir);
          assert.equal(names.length, 1); assert(names[0].startsWith('output.writing-'));
          const staged = await stat(join(dir, names[0]));
          assert.equal(staged.size, offset); assert.equal(staged.mode & 0o777, 0o600);
          await absent(output);
        }
        consumed++; yield bytes.subarray(offset, offset + 32768);
      }
    } finally { finalized = true; }
  }
  assert.equal(await publishArtifactStream(output, expected(bytes), source()), bytes.length);
  assert(consumed > 1 && finalized); assert.equal(await fileHash(output), hash(bytes));
  assert.equal((await stat(output)).mode & 0o777, 0o600);
  assert.deepEqual(await readdir(dir), ['output']);
});

test('disk writes remain at most 64KiB even when a source yields a multi-megabyte chunk', async t => {
  const dir = await directory(t), output = join(dir, 'output'), proto = await handlePrototype(t, dir);
  const original = proto.writeFile, sizes = [];
  t.mock.method(proto, 'writeFile', async function (bytes, ...args) {
    sizes.push(bytes.length); assert(bytes.length <= 64 * 1024);
    return original.call(this, bytes, ...args);
  });
  const bytes = Buffer.alloc(4 * 1024 * 1024 + 3, 0x79);
  await publishArtifactStream(output, expected(bytes), [bytes]);
  assert.equal(sizes.length, 65); assert.equal(await fileHash(output), hash(bytes));
});

test('empty binary streams verify and publish a private empty file', async t => {
  const dir = await directory(t), output = join(dir, 'output');
  assert.equal(await publishArtifactStream(output, expected(Buffer.alloc(0)), []), 0);
  assert.equal((await stat(output)).size, 0); assert.deepEqual(await readdir(dir), ['output']);
});

for (const kind of ['digest', 'short', 'long', 'not-bytes']) {
  test(`stream refuses ${kind} without retaining a staging name or destination`, async t => {
    const dir = await directory(t), output = join(dir, 'output'), bytes = Buffer.from('selected');
    const values = kind === 'digest' ? [Buffer.from('tampered')] : kind === 'short' ? [bytes.subarray(0, 1)]
      : kind === 'long' ? [bytes, Buffer.from('!')] : ['selected'];
    await assert.rejects(publishArtifactStream(output, expected(bytes), values), { code: 'artifact_payload_mismatch' });
    assert.deepEqual(await readdir(dir), []);
  });
}

test('overflow closes the source iterator without requesting another chunk', async t => {
  const dir = await directory(t); let finalized = false, advanced = false;
  async function* source() {
    try { yield Buffer.from('too many'); advanced = true; yield Buffer.from('later'); }
    finally { finalized = true; }
  }
  await assert.rejects(publishArtifactStream(join(dir, 'output'), expected(Buffer.from('x')), source()));
  assert(finalized); assert.equal(advanced, false); assert.deepEqual(await readdir(dir), []);
});

test('source failure after partial disk progress is preserved and staging is removed', async t => {
  const dir = await directory(t), error = new Error('source failed');
  async function* source() { yield Buffer.from('first'); throw error; }
  await assert.rejects(publishArtifactStream(join(dir, 'output'), expected(Buffer.from('firstlast')), source()), e => e === error);
  assert.deepEqual(await readdir(dir), []);
});

test('a falsy thrown source failure cannot become a successful publication', async t => {
  const dir = await directory(t);
  async function* source() { yield Buffer.from('x'); throw null; }
  let rejected = false;
  try { await publishArtifactStream(join(dir, 'output'), expected(Buffer.from('x')), source()); }
  catch (error) { rejected = true; assert.equal(error, null); }
  assert(rejected); assert.deepEqual(await readdir(dir), []);
});

test('cancellation before fsync and between fsync and publication removes staging', async t => {
  for (const boundary of [5, 6]) {
    const dir = await directory(t), error = new ArtifactDownloadError('artifact_download_cancelled'); let checks = 0;
    await assert.rejects(publishArtifactStream(join(dir, 'output'), expected(Buffer.from('x')), [Buffer.from('x')], () => {
      if (++checks === boundary) throw error;
    }), e => e === error);
    assert.equal(checks, boundary); assert.deepEqual(await readdir(dir), []);
  }
});

test('a cancellation racing the publication boundary cannot erase the verified result', async t => {
  const dir = await directory(t), output = join(dir, 'output'), controller = new AbortController(); let checks = 0;
  await publishArtifactStream(output, expected(Buffer.from('x')), [Buffer.from('x')], () => {
    controller.signal.throwIfAborted();
    if (++checks === 6) queueMicrotask(() => controller.abort());
  });
  assert(controller.signal.aborted); assert.equal(await readFile(output, 'utf8'), 'x');
  assert.deepEqual(await readdir(dir), ['output']);
});

for (const target of ['regular', 'symlink']) {
  test(`create-only publication never overwrites a competing ${target}`, async t => {
    const dir = await directory(t), output = join(dir, 'output');
    await writeFile(join(dir, 'other'), 'keep', { mode: 0o600 });
    async function* source() {
      yield Buffer.from('x');
      if (target === 'regular') await writeFile(output, 'keep', { mode: 0o600 });
      else await symlink(join(dir, 'other'), output);
    }
    await assert.rejects(publishArtifactStream(output, expected(Buffer.from('x')), source()), { code: 'EEXIST' });
    assert.equal(await readFile(output, 'utf8'), 'keep'); assert.equal(await readFile(join(dir, 'other'), 'utf8'), 'keep');
    assert.deepEqual((await readdir(dir)).sort(), ['other', 'output']);
  });
}

test('unsafe parent directories and oversized receipts refuse before consuming bytes', async t => {
  const dir = await directory(t); let pulled = false;
  async function* source() { pulled = true; yield Buffer.from('x'); }
  await chmod(dir, 0o755);
  await assert.rejects(publishArtifactStream(join(dir, 'output'), expected(Buffer.from('x')), source()));
  await chmod(dir, 0o700);
  await assert.rejects(publishArtifactStream(join(dir, 'output'),
    { payload_bytes: 64 * 1024 * 1024 + 1, payload_sha256: '00'.repeat(32) }, source()), { code: 'artifact_output_invalid' });
  assert.equal(pulled, false); assert.deepEqual(await readdir(dir), []);
});

test('write failure is preserved and closes the generator before removing partial staging', async t => {
  const dir = await directory(t), proto = await handlePrototype(t, dir), error = Object.assign(new Error('disk full'), { code: 'ENOSPC' });
  const original = proto.writeFile; let calls = 0, finalized = false;
  t.mock.method(proto, 'writeFile', async function (bytes, ...args) {
    if (++calls === 2) throw error;
    return original.call(this, bytes, ...args);
  });
  async function* source() { try { yield Buffer.alloc(100000); } finally { finalized = true; } }
  await assert.rejects(publishArtifactStream(join(dir, 'output'), expected(Buffer.alloc(100000)), source()), e => e === error);
  assert(finalized); assert.deepEqual(await readdir(dir), ['probe']);
});

test('file fsync failure cannot publish and cleanup still runs', async t => {
  const dir = await directory(t), proto = await handlePrototype(t, dir), original = proto.sync;
  const error = Object.assign(new Error('sync failed'), { code: 'EIO' }); let calls = 0;
  t.mock.method(proto, 'sync', async function () { if (++calls === 1) throw error; return original.call(this); });
  await assert.rejects(publishArtifactStream(join(dir, 'output'), expected(Buffer.from('x')), [Buffer.from('x')]), e => e === error);
  assert.equal(calls, 2); assert.deepEqual(await readdir(dir), ['probe']);
});

test('HTTP payload reaches private staging before the peer sends its tail', async t => {
  const bytes = Buffer.alloc(256 * 1024, 0x41); let sawStaging = false;
  const f = await fixture(t, { bytes, handle: async ({ content, response, dir, output }) => {
    if (!content) return false;
    response.writeHead(200, contentHeaders(bytes.length)); response.write(bytes.subarray(0, 65536));
    await eventually(async () => {
      const name = (await readdir(dir)).find(n => n.startsWith('output.writing-'));
      return name && (await stat(join(dir, name))).size > 0;
    });
    await absent(output); sawStaging = true; response.end(bytes.subarray(65536)); return true;
  } });
  const result = await f.send();
  assert(sawStaging); assert.equal(result.payload_bytes, bytes.length); assert.equal(await fileHash(f.output), hash(bytes));
  assert.deepEqual(await readdir(f.dir), ['output']);
});

test('large artifact transfer never concatenates the complete payload', async t => {
  const bytes = Buffer.alloc(8 * 1024 * 1024, 0x72), concat = Buffer.concat;
  const f = await fixture(t, { bytes, handle: async ({ content, response }) => {
    if (!content) return false;
    response.writeHead(200, contentHeaders(bytes.length));
    for (let offset = 0; offset < bytes.length; offset += 32768) {
      if (!response.write(bytes.subarray(offset, offset + 32768))) await once(response, 'drain');
    }
    response.end(); return true;
  } });
  t.mock.method(Buffer, 'concat', function (list, length) {
    const size = length ?? list.reduce((n, b) => n + b.length, 0);
    assert(size <= 128 * 1024, `unexpected whole-payload concatenation: ${size}`);
    return concat(list, length);
  });
  await f.send(); assert.equal(await fileHash(f.output), hash(bytes));
  assert.equal((await stat(f.output)).size, bytes.length);
});

test('streaming logs preserve failed and incomplete observations without applying executable mode', async t => {
  const f = await fixture(t, { log: true, bytes: Buffer.alloc(1024 * 1024, 0x91) });
  const result = await f.send();
  assert.equal(result.log_observation.stream, 'stderr'); assert.equal(result.log_observation.output_complete, false);
  assert.equal(result.log_observation.observed_job_outcome, 'failed'); assert.equal(result.job_success_asserted, false);
  assert.equal(result.provenance_authenticated, false); assert.equal(result.executable_mode_applied, false);
  assert.equal((await stat(f.output)).mode & 0o777, 0o600); assert.equal(await fileHash(f.output), hash(f.bytes));
});

for (const mode of ['cancel', 'timeout', 'disconnect']) {
  test(`HTTP ${mode} drains partial streaming and removes private staging`, async t => {
    const controller = new AbortController();
    const f = await fixture(t, { bytes: Buffer.alloc(256 * 1024), handle: async ({ content, response, dir }) => {
      if (!content) return false;
      response.writeHead(200, contentHeaders(256 * 1024)); response.write(Buffer.alloc(65536));
      await eventually(async () => {
        const name = (await readdir(dir)).find(n => n.startsWith('output.writing-'));
        return name && (await stat(join(dir, name))).size > 0;
      });
      if (mode === 'cancel') controller.abort();
      if (mode === 'disconnect') response.destroy();
      return true;
    } });
    await assert.rejects(f.send({ signal: controller.signal, timeoutMs: mode === 'timeout' ? 250 : 5000 }), error => {
      assert(error instanceof ArtifactDownloadError);
      if (mode !== 'disconnect') assert.equal(error.code, `artifact_download_${mode === 'cancel' ? 'cancelled' : 'timeout'}`);
      return true;
    });
    assert.deepEqual(await readdir(f.dir), []); assert.equal(getEventListeners(controller.signal, 'abort').length, 0);
    await eventually(() => f.sockets.size === 0);
  });
}

test('bad metadata still refuses before opening a content request or a staging file', async t => {
  const f = await fixture(t); f.metadata.repository_id = '99'.repeat(16);
  await assert.rejects(f.send(), { code: 'artifact_metadata_mismatch' });
  assert.equal(f.calls.length, 1); assert.deepEqual(await readdir(f.dir), []);
});

test('cancellation while a disk write is pending drains it before cleanup and rejection', async t => {
  const controller = new AbortController(), f = await fixture(t, { bytes: Buffer.alloc(200000) });
  const proto = await handlePrototype(t, f.dir), original = proto.writeFile;
  let release, began;
  const blocked = new Promise(resolve => { began = resolve; });
  const gate = new Promise(resolve => { release = resolve; });
  let writes = 0, finished = false;
  t.mock.method(proto, 'writeFile', async function (bytes, ...args) {
    if (++writes === 1) { began(); await gate; }
    return original.call(this, bytes, ...args);
  });
  const downloading = f.send({ signal: controller.signal }).finally(() => { finished = true; });
  const rejected = assert.rejects(downloading, { code: 'artifact_download_cancelled' });
  await blocked; controller.abort(); await delay(20); assert.equal(finished, false);
  release(); await rejected;
  assert.deepEqual(await readdir(f.dir), ['probe']); assert.equal(getEventListeners(controller.signal, 'abort').length, 0);
});

test('command entry point retains receipt, token-file, deadline, and binary output behavior', async t => {
  const f = await fixture(t, { bytes: Buffer.alloc(1024 * 1024, 0xe3) });
  for (const [name, value] of [['input', JSON.stringify(f.input)], ['receipt', JSON.stringify(f.receipt)], ['token', token + '\n']]) {
    await writeFile(join(f.dir, name), value, { mode: 0o600 });
  }
  const result = await artifactDownloadCommand(['--input', join(f.dir, 'input'), '--receipt', join(f.dir, 'receipt'),
    '--token-file', join(f.dir, 'token'), '--output', f.output, '--timeout-ms', '5000']);
  assert.equal(result.payload_bytes, f.bytes.length); assert.equal(await fileHash(f.output), hash(f.bytes));
  assert.equal(result.execution_performed, false); assert(!JSON.stringify(result).includes(token));
  assert.deepEqual((await readdir(f.dir)).sort(), ['input', 'output', 'receipt', 'token']);
});
