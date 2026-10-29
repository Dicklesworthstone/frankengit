// Real operator/files/sockets with explicit native-schema peers, NOT native fg.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { mkdtemp, realpath, writeFile, readFile, rm, stat, readdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHash } from 'node:crypto';
import { spawn } from 'node:child_process';
import { createServer as tlsServer } from 'node:https';
import { execFileSync } from 'node:child_process';
import { downloadArtifact, selectArtifact } from '../../scripts/operator/workflow_artifact_download.mjs';
const hash = b => createHash('sha256').update(b).digest('hex');
const token = 'ab'.repeat(32), id = '45'.repeat(32), job = Buffer.from('build').toString('hex'), path = '646973742fff';
const scope = { tenant_id: '11'.repeat(16), repository_id: '22'.repeat(16),
  repository_incarnation_id: '33'.repeat(16), trust_domain: 'trusted-workflow-local-owner' };
const cli = new URL('../../scripts/fg_workflow_watch.mjs', import.meta.url);
async function fixture(t, options = {}) {
  const dir = await mkdtemp(join(await realpath(tmpdir()), 'fg-artifact-download-')); t.after(() => rm(dir, { recursive: true, force: true }));
  const bytes = options.bytes ?? Buffer.from([0, 255, 13, 10, 38, 0x1b, 0xc3, 0xa9]), output = join(dir, 'output');
  const file = { path_hex: path, artifact_id_sha256: id, payload_sha256: hash(bytes), payload_bytes: bytes.length, executable: true };
  let receipt = { type: 'trusted_workflow_artifact_receipt', manifest_id_sha256: '56'.repeat(32),
    manifest: { type: 'trusted_workflow_artifact_provenance', schema_version: 1, producer: {
      tenant_id: scope.tenant_id, repository_id: scope.repository_id, repository_incarnation: scope.repository_incarnation_id },
    job_id_hex: job, outputs: [file], job_success_asserted: false, cache_reuse_authorized: false } };
  const log = options.log ? { step_index: 2, step_name_hex: null, script_sha256: '78'.repeat(32),
    stream: 'stdout', observed_step_outcome: 'failed', exit_code: 7, output_complete: true,
    artifact_id_sha256: id, payload_sha256: hash(bytes), payload_bytes: bytes.length, ...options.log } : null;
  if (log) {
    const { outputs, ...manifest } = receipt.manifest;
    receipt = { ...receipt, type: 'trusted_workflow_log_receipt', manifest: { ...manifest,
      type: 'trusted_workflow_log_provenance', observed_job_outcome: options.jobOutcome ?? 'failed',
      logs: [log, { ...log, stream: log.stream === 'stdout' ? 'stderr' : 'stdout',
        artifact_id_sha256: '89'.repeat(32), payload_sha256: hash(Buffer.alloc(0)), payload_bytes: 0 }] } };
  }
  const metadata = { type: 'artifact_metadata', schema_version: 1, ...scope, scope_sha256: '67'.repeat(32),
    artifact_id: id, payload_sha256: file.payload_sha256, payload_bytes: bytes.length, media_type: 'text/html', kind: log ? 'build_log' : 'ci_artifact',
    build_capsule_sha256: null, check_receipt_sha256: null, source_rcr_sha256: null, retention_canonical_hex: '00',
    payload_verified: true, provenance_authenticated: false, canonical_repository_published: false,
    retention_enforced: false, read_only: true };
  const calls = [], sockets = new Set();
  const handler = (request, response) => {
    request.resume(); request.once('end', () => {
      calls.push({ path: request.url, method: request.method, headers: request.headers });
      const content = request.url.endsWith('/content');
      if (options.handle?.({ request, response, content, metadata, calls })) return;
      const data = content ? options.content ?? bytes : Buffer.from(options.encode?.(metadata) ?? JSON.stringify(metadata));
      response.writeHead(200, { 'Content-Type': content ? 'application/octet-stream' : 'application/json',
        'Content-Length': data.length, ...(content ? { 'Content-Disposition': `attachment; filename="artifact-${id}"` } : {}),
        ...(options.headers?.(content) ?? {}) }); response.end(data);
    });
  };
  const server = options.tls ? tlsServer(options.tls, handler) : createServer(handler);
  server.on('connection', socket => { sockets.add(socket); socket.on('close', () => sockets.delete(socket)); });
  await new Promise(r => server.listen(0, '127.0.0.1', r));
  t.after(async () => { for (const socket of sockets) socket.destroy(); await new Promise(r => server.close(r)); });
  const input = { endpoint: `${options.tls ? 'https' : 'http'}://127.0.0.1:${server.address().port}/repo.git`, scope, job_id_hex: job,
    ...(log ? { step_index: log.step_index, stream: log.stream } : { path_hex: path }) };
  const send = opts => downloadArtifact(input, receipt, token, output, opts);
  async function invoke(extra = [], control = {}) {
    for (const [name, value] of [['input', input], ['receipt', receipt]]) await writeFile(join(dir, name), JSON.stringify(value), { mode: 0o600 });
    await writeFile(join(dir, 'token'), token + '\n', { mode: 0o600 });
    const child = spawn(process.execPath, [cli.pathname, 'artifact-download', '--input', join(dir, 'input'),
      '--receipt', join(dir, 'receipt'), '--token-file', join(dir, 'token'), '--output', output, ...extra]);
    control.spawned?.(child);
    const out = [], err = []; child.stdout.on('data', b => out.push(b)); child.stderr.on('data', b => err.push(b));
    const timer = setTimeout(() => child.kill('SIGKILL'), 10000);
    const code = await new Promise((r, j) => { child.once('error', j); child.once('close', r); }); clearTimeout(timer);
    return { code, stdout: Buffer.concat(out).toString(), stderr: Buffer.concat(err).toString() };
  }
  return { dir, bytes, output, file, log, receipt, metadata, input, calls, send, invoke };
}
for (const bytes of [Buffer.alloc(0), Buffer.from([0, 255, 13, 10, 38, 0xc3, 0xa9])]) {
  test(`API downloads selected complete binary payload (${bytes.length} bytes), never applies executable mode`, async t => {
    const f = await fixture(t, { bytes }); const result = await f.send();
    assert((await readFile(f.output)).equals(bytes)); assert.equal((await stat(f.output)).mode & 0o777, 0o600);
    assert.equal(result.payload_sha256, hash(bytes)); assert.equal(result.payload_sha256_verified, true);
    assert.equal(result.provenance_authenticated, false); assert.equal(result.canonical_repository_published, false);
    assert.equal(result.job_success_asserted, false); assert.equal(result.execution_performed, false);
    assert.deepEqual(f.calls.map(x => [x.method, x.path]), [['GET', `/repo.git/api/v1/artifacts/${id}`],
      ['GET', `/repo.git/api/v1/artifacts/${id}/content`]]);
    for (const call of f.calls) {
      assert.equal(call.headers.authorization, `Bearer ${token}`);
      assert.equal(call.headers['user-agent'], 'frankengit-agent (+https://github.com/Dicklesworthstone/frankengit)');
      assert.equal(call.headers['idempotency-key'], undefined); assert.equal(call.headers.cookie, undefined);
    }
    assert.deepEqual(await readdir(f.dir), ['output']);
  });
}
test('CLI selects a retained job/path and publishes the same bytes without a local native/root configuration', async t => {
  const f = await fixture(t), r = await f.invoke(); assert.equal(r.code, 0, r.stderr);
  assert((await readFile(f.output)).equals(f.bytes)); assert.equal(JSON.parse(r.stdout).artifact_id, id);
  assert(!r.stdout.includes(token) && !r.stderr.includes(token));
});
for (const [key, value] of [['tenant_id', '99'.repeat(16)], ['repository_id', '99'.repeat(16)],
  ['repository_incarnation_id', '99'.repeat(16)], ['trust_domain', 'different'], ['artifact_id', '99'.repeat(32)],
  ['payload_sha256', '99'.repeat(32)], ['payload_bytes', 999], ['kind', 'provenance'],
  ['provenance_authenticated', true], ['canonical_repository_published', true], ['payload_verified', false]]) {
  test(`metadata mismatch ${key} refuses before requesting payload or creating output`, async t => {
    const f = await fixture(t); f.metadata[key] = value;
    await assert.rejects(f.send()); assert.equal(f.calls.length, 1); await assert.rejects(stat(f.output), { code: 'ENOENT' });
  });
}
for (const bytes of [Buffer.from('tampered'), Buffer.from([0, 255, 13, 10, 38, 0x1b, 0xc3, 0xa8])]) {
  test('changed payload length or same-length digest refuses without a destination', async t => {
    const f = await fixture(t, { content: bytes }); await assert.rejects(f.send());
    assert.equal(f.calls.length, 2); await assert.rejects(stat(f.output), { code: 'ENOENT' });
  });
}
for (const status of [301, 401, 403, 404, 413, 429, 503]) test(`HTTP ${status} never redirects, retries or falls back`, async t => {
  const f = await fixture(t, { handle: ({ response }) => {
    response.writeHead(status, { Location: 'https://elsewhere.example/' }); response.end(token); return true;
  } });
  await assert.rejects(f.send(), e => !e.message.includes(token));
  assert.equal(f.calls.length, 1); await assert.rejects(stat(f.output), { code: 'ENOENT' });
});
test('ambiguous duplicate receipt outputs and changed producer scope refuse before I/O', async t => {
  const f = await fixture(t);
  f.receipt.manifest.outputs.push({ ...f.file }); assert.throws(() => selectArtifact(f.input, f.receipt));
  f.receipt.manifest.outputs.pop(); f.receipt.manifest.producer.repository_incarnation = '99'.repeat(16);
  await assert.rejects(f.send()); assert.equal(f.calls.length, 0);
});
test('wrong job, absent path and metadata ID substituted for payload digest refuse', async t => {
  const f = await fixture(t);
  assert.throws(() => selectArtifact({ ...f.input, job_id_hex: '00' }, f.receipt));
  assert.throws(() => selectArtifact({ ...f.input, path_hex: '00' }, f.receipt));
  assert.notEqual(f.file.artifact_id_sha256, f.file.payload_sha256);
});
test('existing destination refuses before I/O and remains unchanged', async t => {
  const f = await fixture(t); await writeFile(f.output, 'keep', { mode: 0o600 });
  await assert.rejects(f.send()); assert.equal(f.calls.length, 0); assert.equal(await readFile(f.output, 'utf8'), 'keep');
});
test('publication race preserves the competing file and reports failure', async t => {
  // The race is installed when the payload is requested, after destination preflight.
  const race = await fixture(t, { handle: ({ content, response, metadata }) => {
    if (!content) return false;
    writeFile(race.output, 'racer', { mode: 0o600 }).then(() => {
      response.writeHead(200, { 'Content-Type': 'application/octet-stream', 'Content-Length': race.bytes.length,
        'Content-Disposition': `attachment; filename="artifact-${id}"` }); response.end(race.bytes);
    }); return true;
  } });
  await assert.rejects(race.send()); assert.equal(await readFile(race.output, 'utf8'), 'racer');
});
test('cancelled and expired operations never publish partial files', async t => {
  const controller = new AbortController();
  const f = await fixture(t, { handle: ({ content, response }) => {
    if (!content) return false; response.writeHead(200, { 'Content-Type': 'application/octet-stream',
      'Content-Length': f.bytes.length, 'Content-Disposition': `attachment; filename="artifact-${id}"` });
    response.write(f.bytes.subarray(0, 1)); controller.abort(); return true;
  } });
  await assert.rejects(f.send({ signal: controller.signal })); await assert.rejects(stat(f.output), { code: 'ENOENT' });
  const held = await fixture(t, { handle: () => true });
  await assert.rejects(held.send({ timeoutMs: 50 })); await assert.rejects(stat(held.output), { code: 'ENOENT' });
});
for (const [name, options] of [
  ['duplicate metadata key', { encode: value => JSON.stringify(value).replace('"artifact_id":', '"artifact_id":"wrong","artifact_id":') }],
  ['empty success stand-in', { encode: () => '{}' }],
  ['invalid metadata UTF8', { handle: ({ content, response }) => {
    if (content) return false; response.writeHead(200, { 'Content-Type': 'application/json', 'Content-Length': 1 });
    response.end(Buffer.from([255])); return true;
  } }],
  ['encoding', { headers: () => ({ 'Content-Encoding': 'gzip' }) }],
  ['active content media', { headers: content => content ? { 'Content-Type': 'text/html' } : {} }],
  ['wrong attachment ID', { headers: content => content ? { 'Content-Disposition': 'attachment; filename="other"' } : {} }],
  ['declared oversize', { headers: content => content ? { 'Content-Length': String(64 * 1024 * 1024 + 1) } : {} }],
  ['duplicate framing', { headers: () => ({ 'Content-Type': ['application/json', 'application/json'] }) }],
  ['truncated content', { handle: ({ content, response }) => {
    if (!content) return false; response.writeHead(200, { 'Content-Type': 'application/octet-stream',
      'Content-Length': 8, 'Content-Disposition': `attachment; filename="artifact-${id}"` });
    response.end(Buffer.from([0])); return true;
  } }],
]) test(`refuse ${name} without a visible payload`, async t => {
  const f = await fixture(t, options); await assert.rejects(f.send({ timeoutMs: 1000 }));
  await assert.rejects(stat(f.output), { code: 'ENOENT' }); assert(f.calls.length <= 2);
});
test('noncanonical endpoint, unsupported scope and pre-cancellation refuse before any request', async t => {
  const f = await fixture(t), controller = new AbortController(); controller.abort();
  await assert.rejects(f.send({ signal: controller.signal })); assert.equal(f.calls.length, 0);
  for (const endpoint of ['http://localhost/repo.git', 'http://remote.example/repo.git', 'https://x/repo.git?token=x',
    'https://user:pass@x/repo.git', 'https://x/repo.git/']) {
    assert.throws(() => selectArtifact({ ...f.input, endpoint }, f.receipt));
  }
  await assert.rejects(f.send({ rejectUnauthorized: false })); assert.equal(f.calls.length, 0);
});
test('HTTPS verifies explicit private CA and hostname; untrusted or wrong-name peers cannot disclose', async t => {
  const dir = await mkdtemp(join(await realpath(tmpdir()), 'fg-artifact-tls-')); t.after(() => rm(dir, { recursive: true, force: true }));
  async function tls(name, alt) {
    const key = join(dir, name + '.key'), cert = join(dir, name + '.cert');
    // OpenSSL creates test credentials only; it is not an artifact verifier.
    const output = execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
      '-subj', '/CN=artifact-test', '-addext', 'subjectAltName=' + alt, '-keyout', key, '-out', cert],
      { timeout: 10000, stdio: ['ignore', 'pipe', 'pipe'] });
    assert.equal(output.length, 0);
    return { key: await readFile(key), cert: await readFile(cert) };
  }
  const matching = await tls('matching', 'IP:127.0.0.1'), f = await fixture(t, { tls: matching });
  await assert.rejects(f.send()); assert.equal(f.calls.length, 0);
  await f.send({ ca: matching.cert }); assert((await readFile(f.output)).equals(f.bytes));
  const wrong = await tls('wrong', 'DNS:wrong.example'), p = await fixture(t, { tls: wrong });
  await assert.rejects(p.send({ ca: wrong.cert })); assert.equal(p.calls.length, 0);
  await assert.rejects(stat(p.output), { code: 'ENOENT' });
});
test('CLI refuses wrong scope without a destination or token-bearing diagnostics', async t => {
  const f = await fixture(t); f.metadata.repository_incarnation_id = '99'.repeat(16);
  const r = await f.invoke(); assert.equal(r.code, 2); assert(!r.stdout.includes(token) && !r.stderr.includes(token));
  assert.equal(JSON.parse(r.stderr).code, 'artifact_metadata_mismatch'); assert.equal(f.calls.length, 1);
  await assert.rejects(stat(f.output), { code: 'ENOENT' });
});
test('CLI SIGTERM during an incomplete payload drains its read without publishing', async t => {
  let child;
  const f = await fixture(t, { handle: ({ content, response }) => {
    if (!content) return false;
    response.writeHead(200, { 'Content-Type': 'application/octet-stream', 'Content-Length': f.bytes.length,
      'Content-Disposition': `attachment; filename="artifact-${id}"` }); response.write(f.bytes.subarray(0, 1));
    child.kill('SIGTERM'); return true;
  } });
  const r = await f.invoke([], { spawned: value => { child = value; } });
  assert.equal(r.code, 3); assert.equal(JSON.parse(r.stderr).code, 'artifact_download_cancelled');
  await assert.rejects(stat(f.output), { code: 'ENOENT' }); assert.equal(f.calls.length, 2);
});
test('CLI duplicate/widened options refuse before I/O', async t => {
  for (const args of [['--output', '/tmp/another'], ['--trusted-local'], ['--timeout-ms', '0'], ['--timeout-ms', '300001']]) {
    const f = await fixture(t), r = await f.invoke(args); assert.equal(r.code, 2);
    assert.equal(f.calls.length, 0); await assert.rejects(stat(f.output), { code: 'ENOENT' });
  }
});

for (const stream of ['stdout', 'stderr']) for (const complete of [true, false]) {
  test(`log ${stream} preserves binary bytes and receipt completeness ${complete} without asserting job success`, async t => {
    const f = await fixture(t, { log: { stream, output_complete: complete } });
    const r = await f.send(); assert((await readFile(f.output)).equals(f.bytes));
    assert.equal(r.payload_sha256_verified, true); assert.equal(r.job_success_asserted, false);
    assert.equal(r.log_observation.stream, stream); assert.equal(r.log_observation.step_index, 2);
    assert.equal(r.log_observation.output_complete, complete); assert.equal(r.log_observation.exit_code, 7);
    assert.equal(r.log_observation.observed_step_outcome, 'failed'); assert.equal(r.log_observation.observed_job_outcome, 'failed');
    assert.equal(r.provenance_authenticated, false); assert.equal(r.execution_performed, false);
    assert.equal((await stat(f.output)).mode & 0o777, 0o600); assert.equal(f.calls.length, 2);
  });
}
test('CLI retrieves an empty cancelled log as empty, preserving its non-success observation', async t => {
  const f = await fixture(t, { bytes: Buffer.alloc(0), jobOutcome: 'cancelled',
    log: { stream: 'stderr', observed_step_outcome: 'cancelled', exit_code: null, output_complete: false } });
  const r = await f.invoke(); assert.equal(r.code, 0, r.stderr);
  const v = JSON.parse(r.stdout); assert.equal(v.log_observation.observed_job_outcome, 'cancelled');
  assert.equal(v.log_observation.output_complete, false); assert.equal(v.job_success_asserted, false);
  assert.equal((await stat(f.output)).size, 0); assert.equal(f.calls.length, 2);
});
test('two empty streams may share one artifact ID; coordinates still select the exact stream', async t => {
  const f = await fixture(t, { bytes: Buffer.alloc(0), log: { stream: 'stderr' } });
  f.receipt.manifest.logs[1].artifact_id_sha256 = id;
  const r = await f.send(); assert.equal(r.artifact_id, id); assert.equal(r.log_observation.stream, 'stderr');
  assert.equal((await stat(f.output)).size, 0); assert.equal(f.calls.length, 2);
});
for (const patch of [{ step_index: '2' }, { step_index: -1 }, { step_index: 1.5 }, { stream: 'combined' },
  { path_hex: path }, { job_id_hex: '00' }]) test(`refuse invalid or ambiguous log selector ${JSON.stringify(patch)}`, async t => {
  const f = await fixture(t, { log: {} }); assert.throws(() => selectArtifact({ ...f.input, ...patch }, f.receipt));
  assert.equal(f.calls.length, 0);
});
for (const change of [
  m => { m.logs.push({ ...m.logs[0] }); },
  m => { m.logs.pop(); },
  m => { m.logs[1].script_sha256 = '90'.repeat(32); },
  m => { m.logs[1].output_complete = false; },
  m => { m.logs[1].exit_code = 0; },
  m => { m.logs[0].payload_bytes = 64 * 1024 * 1024 + 1; },
  m => { m.observed_job_outcome = 'green'; },
]) test('refuse ambiguous, incomplete or inconsistent log receipt before I/O', async t => {
  const f = await fixture(t, { log: {} }); change(f.receipt.manifest);
  await assert.rejects(f.send()); assert.equal(f.calls.length, 0); await assert.rejects(stat(f.output), { code: 'ENOENT' });
});
test('file and log receipt/kind cannot be substituted even with identical bytes', async t => {
  const log = await fixture(t, { log: {} }); log.metadata.kind = 'ci_artifact';
  await assert.rejects(log.send()); assert.equal(log.calls.length, 1);
  const file = await fixture(t); file.metadata.kind = 'build_log';
  await assert.rejects(file.send()); assert.equal(file.calls.length, 1);
  assert.throws(() => selectArtifact(file.input, log.receipt));
  assert.throws(() => selectArtifact(log.input, file.receipt));
});
test('log hash mismatch and cancellation retain no output or local fallback', async t => {
  const f = await fixture(t, { log: {}, content: Buffer.from('bad') }); await assert.rejects(f.send());
  await assert.rejects(stat(f.output), { code: 'ENOENT' }); assert.equal(f.calls.length, 2);
  const controller = new AbortController();
  const p = await fixture(t, { log: {}, handle: ({ content, response }) => {
    if (!content) return false; response.writeHead(200, { 'Content-Type': 'application/octet-stream',
      'Content-Length': p.bytes.length, 'Content-Disposition': `attachment; filename="artifact-${id}"` });
    response.write(p.bytes.subarray(0, 1)); controller.abort(); return true;
  } });
  await assert.rejects(p.send({ signal: controller.signal })); await assert.rejects(stat(p.output), { code: 'ENOENT' });
});
function nearManifestLimit(receipt) {
  // Synthetic native-schema boundary, not evidence that the runner accepted
  // this step name or produced this receipt. Native wraps its <=1MiB manifest.
  const maximum = 1024 * 1024, before = Buffer.byteLength(JSON.stringify(receipt.manifest));
  const name = '61'.repeat(Math.floor((maximum - before + 4) / 4));
  for (const log of receipt.manifest.logs) log.step_name_hex = name;
  const size = Buffer.byteLength(JSON.stringify(receipt.manifest));
  assert(size <= maximum && size >= maximum - 3);
  assert(Buffer.byteLength(JSON.stringify(receipt)) > maximum);
}
test('CLI accepts a bounded near1MiB log manifest plus its fixed receipt envelope', async t => {
  const f = await fixture(t, { log: {} }); nearManifestLimit(f.receipt);
  const r = await f.invoke(); assert.equal(r.code, 0, r.stderr); assert((await readFile(f.output)).equals(f.bytes));
  assert.equal(f.calls.length, 2);
});
test('a manifest over1MiB refuses even if it fits the finite receipt envelope allowance', async t => {
  const f = await fixture(t, { log: {} }); nearManifestLimit(f.receipt);
  for (const log of f.receipt.manifest.logs) log.step_name_hex += '61';
  assert(Buffer.byteLength(JSON.stringify(f.receipt.manifest)) > 1024 * 1024);
  assert.throws(() => selectArtifact(f.input, f.receipt), /artifact_manifest_limit/); assert.equal(f.calls.length, 0);
});
