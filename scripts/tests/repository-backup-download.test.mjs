import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile, readdir, lstat, writeFile, unlink, symlink, rename, chmod } from 'node:fs/promises';
import { join } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { downloadRepositoryBackup, repositoryBackupDownloadOptions } from '../lib/repository-backup-download.mjs';
import { selectRepositoryBackup } from '../lib/repository-backup-selection.mjs';
import { tlsFixture, DATA, NOW, ID, digest } from './backup-download-fixture.mjs';

const code = expected => error => { assert.equal(error.code, expected); return true; };
async function empty(f) { assert.deepEqual(await readdir(f.destination), []); }
async function noSockets(f) { for (let i = 0; i < 50 && f.sockets.size; i++) await delay(5); assert.equal(f.sockets.size, 0); }
function privateReport(value) { const s = JSON.stringify(value); assert(!s.includes('capability-do-not-log')); assert(!s.includes('127.0.0.1')); }

for (const format of ['sha1', 'sha256']) test(`real HTTPS -> signed durable replica -> selection (${format})`, async t => {
  const f = await tlsFixture(t); await f.sign(DATA, { object_format: format });
  const result = await downloadRepositoryBackup({ ...f.options, policy: { ...f.options.policy, object_format: format } });
  assert.equal(result.state, 'complete'); assert.equal(result.authentication.statement.head_generation, '9007199254740993');
  assert.deepEqual(await readFile(result.candidate.input), DATA);
  assert.deepEqual(await readFile(result.candidate.approval), await readFile(f.approval));
  assert.equal(result.streaming.total_payload_bytes_read, String(DATA.length * 4));
  assert.equal(result.streaming.network_payload_bytes_read, String(DATA.length));
  assert.equal(result.native_content_verified, false); assert.equal(result.complete_capsule_verified, false);
  assert.equal(result.publication.files_and_directory_synced, true);
  await unlink(f.local); await unlink(f.approval);
  const chosen = await selectRepositoryBackup([result.candidate], f.trustKey, { ...f.options.policy, object_format: format }, { now: NOW });
  assert.deepEqual(chosen.report.checkpoint, result.checkpoint);
  assert.equal((await readdir(f.destination)).length, 2); privateReport(result); await noSockets(f);
});

test('chunked response without Content-Length is streamed and authenticated', async t => {
  const f = await tlsFixture(t); f.setHandler((_, res) => { res.write(DATA.subarray(0, 71)); res.end(DATA.subarray(71)); });
  const result = await downloadRepositoryBackup(f.options); assert.deepEqual(await readFile(result.candidate.input), DATA); await noSockets(f);
});

test('exact retry reuses immutable output inodes', async t => {
  const f = await tlsFixture(t), first = await downloadRepositoryBackup(f.options), before = await lstat(first.candidate.input);
  const next = await downloadRepositoryBackup({ ...f.options, checkpoint: first.checkpoint });
  assert.equal((await lstat(next.candidate.input)).ino, before.ino);
  assert.equal(next.publication.disposition.archive, 'reused'); assert.equal(next.streaming.total_payload_bytes_read, String(DATA.length * 3));
});

test('a missing or corrupt remote copy uses only the next explicit URL of the same approval', async t => {
  const f = await tlsFixture(t);
  f.setHandler((req, res) => {
    if (req.url.startsWith('/missing')) { res.writeHead(404); res.end('absent'); }
    else if (req.url.startsWith('/bad')) res.end(Buffer.alloc(DATA.length, 0x42));
    else res.end(DATA);
  });
  const result = await downloadRepositoryBackup({ ...f.options,
    sources: [f.url.replace('/backup', '/missing'), f.url.replace('/backup', '/bad'), f.url] });
  assert.deepEqual(result.source_attempts.map(a => a.outcome), ['unavailable', 'unavailable', 'authenticated']);
  assert.equal(result.streaming.total_payload_bytes_read, String(DATA.length * 5));
  privateReport(result); assert.equal(f.requests.length, 3); await noSockets(f);
});

test('all damaged copies refuse without publication', async t => {
  const f = await tlsFixture(t); f.setHandler((_, res) => res.end(Buffer.alloc(DATA.length, 0x42)));
  await assert.rejects(downloadRepositoryBackup({ ...f.options, sources: [f.url, f.url.replace('/backup', '/b')] }), error => {
    assert.equal(error.code, 'backup_download_no_source'); assert.equal(error.source_attempts.length, 2); privateReport(error); return true;
  }); await empty(f); await noSockets(f);
});

test('4N exact total payload budget succeeds; 4N-1 refuses before network or scratch', async t => {
  const f = await tlsFixture(t);
  await assert.rejects(downloadRepositoryBackup({ ...f.options, maximumTotalBytes: DATA.length * 4 - 1 }), code('backup_download_read_budget'));
  assert.equal(f.requests.length, 0); await empty(f);
  await downloadRepositoryBackup({ ...f.options, maximumTotalBytes: DATA.length * 4 });
});

test('failed mirror consumes shared work and cannot spend the publication reservation', async t => {
  const f = await tlsFixture(t); f.setHandler((_, res) => res.end(Buffer.alloc(DATA.length, 0x42)));
  await assert.rejects(downloadRepositoryBackup({ ...f.options, sources: [f.url, f.url.replace('/backup', '/b')], maximumTotalBytes: DATA.length * 5 - 1 }), code('backup_download_read_budget'));
  assert.equal(f.requests.length, 1); await empty(f);
});

for (const status of [301, 302, 307, 308]) test(`HTTP ${status} never follows a credential-bearing redirect`, async t => {
  const f = await tlsFixture(t); f.setHandler((_, res) => { res.writeHead(status, { location: f.url.replace('/backup', '/redirect-target') }); res.end(); });
  await assert.rejects(downloadRepositoryBackup(f.options), error => { code('backup_download_redirect_refused')(error); privateReport(error); return true; });
  assert.equal(f.requests.length, 1); await empty(f); await noSockets(f);
});

for (const [name, configure, errorCode] of [
  ['gzip', res => res.setHeader('content-encoding', 'gzip'), 'backup_download_encoding'],
  ['partial range', res => res.setHeader('content-range', `bytes 0-${DATA.length - 1}/${DATA.length}`), 'backup_download_partial_response'],
  ['oversized length', res => res.setHeader('content-length', DATA.length + 1), 'backup_download_no_source'],
  ['short length', res => res.setHeader('content-length', DATA.length - 1), 'backup_download_no_source'],
  ['206 response', res => { res.statusCode = 206; }, 'backup_download_http_status'],
  ['401 response', res => { res.statusCode = 401; }, 'backup_download_http_status'],
  ['403 response', res => { res.statusCode = 403; }, 'backup_download_http_status'],
]) test(`refuse ${name}`, async t => {
  const f = await tlsFixture(t); f.setHandler((_, res) => { configure(res); res.end(DATA); });
  await assert.rejects(downloadRepositoryBackup(f.options), code(errorCode)); await empty(f); await noSockets(f);
});

test('chunked body longer than signed length never publishes', async t => {
  const f = await tlsFixture(t); f.setHandler((_, res) => { res.write(DATA); res.end('x'); });
  await assert.rejects(downloadRepositoryBackup(f.options), code('backup_download_no_source')); await empty(f);
});

test('short chunked body never publishes', async t => {
  const f = await tlsFixture(t); f.setHandler((_, res) => { res.write(DATA.subarray(0, 17)); res.end(); });
  await assert.rejects(downloadRepositoryBackup(f.options), code('backup_download_no_source')); await empty(f);
});

test('response trailers are not accepted as extra verification material', async t => {
  const f = await tlsFixture(t); f.setHandler((_, res) => { res.write(DATA); res.addTrailers({ 'x-digest': digest(DATA) }); res.end(); });
  await assert.rejects(downloadRepositoryBackup(f.options), code('backup_download_trailers')); await empty(f);
});

test('untrusted TLS is fatal and does not fall through to another URL', async t => {
  const f = await tlsFixture(t), { caFile, ...options } = f.options;
  await assert.rejects(downloadRepositoryBackup({ ...options, sources: [f.url, f.url.replace('/backup', '/second')] }), code('backup_download_tls'));
  assert.equal(f.requests.length, 0); await empty(f); await noSockets(f);
});

test('invalid signature and a stronger independent floor refuse before connecting', async t => {
  const f = await tlsFixture(t);
  await assert.rejects(downloadRepositoryBackup({ ...f.options, policy: { ...f.options.policy, minimum_head_generation: '9007199254740994' } }), code('backup_approval_below_floor'));
  const envelope = JSON.parse(await readFile(f.approval)); const sig = Buffer.from(envelope.signatures[0].sig, 'base64'); sig[0] ^= 1;
  envelope.signatures[0].sig = sig.toString('base64'); await writeFile(f.approval, JSON.stringify(envelope));
  await assert.rejects(downloadRepositoryBackup(f.options), code('backup_invalid_signature')); assert.equal(f.requests.length, 0); await empty(f);
});

test('wrong explicit original checkpoint refuses before connecting', async t => {
  const f = await tlsFixture(t);
  await assert.rejects(downloadRepositoryBackup({ ...f.options, checkpoint: { approval_sha256: '0'.repeat(64), trusted_key_id: f.signed.trusted_key_id } }), code('backup_download_checkpoint_mismatch'));
  assert.equal(f.requests.length, 0); await empty(f);
});

test('approval replacement after download cannot retarget the local publisher', async t => {
  const f = await tlsFixture(t);
  await assert.rejects(downloadRepositoryBackup({ ...f.options, async onProgress(event) {
    if (event.phase === 'download_verified') await f.sign(DATA, { head_generation: '9007199254740994' });
  } }), code('backup_replication_checkpoint_mismatch')); await empty(f);
});

test('trusted observer errors resembling remote absence do not trigger failover', async t => {
  const f = await tlsFixture(t); const problem = Object.assign(new Error('observer'), { code: 'ECONNRESET' });
  await assert.rejects(downloadRepositoryBackup({ ...f.options, sources: [f.url, f.url.replace('/backup', '/b')],
    onProgress(event) { if (event.phase === 'download') throw problem; } }), error => error === problem);
  assert.equal(f.requests.length, 1); await empty(f); await noSockets(f);
});

test('pre-cancelled invocation has no filesystem or network effects', async t => {
  const f = await tlsFixture(t), controller = new AbortController(); controller.abort();
  await assert.rejects(downloadRepositoryBackup({ ...f.options, signal: controller.signal }), code('backup_cancelled'));
  assert.equal(f.requests.length, 0); await empty(f);
});

for (const boundary of ['headers', 'payload', 'after-length']) test(`absolute deadline drains a silent peer at ${boundary}`, async t => {
  const f = await tlsFixture(t); f.setHandler((_, res) => {
    if (boundary === 'headers') return;
    res.writeHead(200); res.flushHeaders();
    if (boundary === 'after-length') res.write(DATA); else res.write(DATA.subarray(0, 1));
  });
  await assert.rejects(downloadRepositoryBackup({ ...f.options, timeoutMs: 200 }), code('backup_deadline'));
  await noSockets(f); await empty(f);
});

test('midstream cancellation closes the request and removes only owned scratch', async t => {
  const f = await tlsFixture(t), controller = new AbortController();
  const unrelated = join(f.destination, '.fg-backup-download-other.tmp'); await writeFile(unrelated, 'unrelated');
  await assert.rejects(downloadRepositoryBackup({ ...f.options, signal: controller.signal,
    onProgress(event) { if (event.phase === 'download') controller.abort(); } }), code('backup_cancelled'));
  assert.deepEqual(await readdir(f.destination), ['.fg-backup-download-other.tmp']); await noSockets(f);
});

test('symlinked and public destination directories refuse before connecting', async t => {
  const f = await tlsFixture(t), alias = join(f.root, 'alias'); await symlink(f.destination, alias);
  await assert.rejects(downloadRepositoryBackup({ ...f.options, destination: alias }), code('backup_download_private_directory'));
  await chmod(f.destination, 0o755); await assert.rejects(downloadRepositoryBackup(f.options), code('backup_download_private_directory'));
  assert.equal(f.requests.length, 0);
});

test('destination substitution refuses without cleaning a replacement directory', async t => {
  const f = await tlsFixture(t), old = f.destination + '-old';
  await assert.rejects(downloadRepositoryBackup({ ...f.options, async onProgress(event) {
    if (event.phase === 'download_verified') { await rename(f.destination, old); await symlink(old, f.destination); }
  } }), error => { assert.equal(error.code, 'backup_download_private_directory'); assert(error.retained_download); return true; });
  assert.equal((await readdir(old)).filter(p => p.endsWith('.tmp')).length, 1);
});

test('strict source and option grammar snapshots intent before any I/O', async t => {
  const f = await tlsFixture(t);
  for (const source of ['http://example.com/a', 'https://u:p@example.com/a', 'https://example.com/a#x', 'https://example.com/a\n', '', {}, 'not a URL']) {
    assert.throws(() => repositoryBackupDownloadOptions({ ...f.options, sources: [source] }), code('backup_download_invalid_url'));
  }
  assert.throws(() => repositoryBackupDownloadOptions({ ...f.options, sources: [f.url, f.url] }), code('backup_download_source_limit'));
  assert.throws(() => repositoryBackupDownloadOptions({ ...f.options, rejectUnauthorized: false }), code('backup_invalid_download_options'));
  const sources = [f.url], options = { ...f.options, sources };
  const result = downloadRepositoryBackup(options); sources[0] = 'http://untrusted.example/'; options.policy = { ...ID, minimum_head_generation: '18446744073709551615' };
  assert.equal((await result).state, 'complete');
});

test('reset during an awaited observer is owned and can use the next mirror', async t => {
  const f = await tlsFixture(t); let response;
  f.setHandler((req, res) => { if (req.url.startsWith('/bad')) { response = res; res.write(DATA.subarray(0, 100)); } else res.end(DATA); });
  let reset = false;
  const result = await downloadRepositoryBackup({ ...f.options, sources: [f.url.replace('/backup', '/bad'), f.url],
    async onProgress(event) { if (event.phase === 'download' && !reset) { reset = true; response.destroy(); await delay(10); } } });
  assert.equal(result.source_attempts.length, 2); assert.equal(result.source_attempts[1].outcome, 'authenticated'); await noSockets(f);
});

test('multiple TLS certificates cannot expand the explicit single-anchor policy', async t => {
  const f = await tlsFixture(t), ca = await readFile(f.caFile); await writeFile(f.caFile, Buffer.concat([ca, ca]));
  await assert.rejects(downloadRepositoryBackup(f.options), code('backup_download_invalid_ca')); assert.equal(f.requests.length, 0); await empty(f);
});

test('oversized headers are fatal and redacted, without trying an alias', async t => {
  const f = await tlsFixture(t); f.setHandler((_, res) => { res.setHeader('x-too-large', 'secret'.repeat(4000)); res.end(DATA); });
  await assert.rejects(downloadRepositoryBackup({ ...f.options, sources: [f.url, f.url.replace('/backup', '/b')] }), error => {
    code('backup_download_transport')(error); privateReport(error); return true;
  }); assert.equal(f.requests.length, 1); await empty(f); await noSockets(f);
});

test('expiry during network work refuses publication', async t => {
  const f = await tlsFixture(t);
  const issued = new Date(Math.floor(Date.now() / 1000) * 1000 - 1000).toISOString().replace('.000Z', 'Z');
  const expires = new Date(Math.floor(Date.now() / 1000) * 1000 + 1000).toISOString().replace('.000Z', 'Z');
  await f.sign(DATA, { issued_at: issued, expires_at: expires }, Date.now());
  const { now, ...options } = f.options;
  await assert.rejects(downloadRepositoryBackup({ ...options, async onProgress(event) {
    if (event.phase === 'source_started') await delay(Math.max(1, Date.parse(expires) - Date.now() + 5));
  } }), code('backup_approval_expired')); await empty(f);
});

test('informational-response floods are bounded and do not reach publication', async t => {
  const f = await tlsFixture(t); f.setHandler((_, res) => {
    for (let i = 0; i < 9; i++) res.writeEarlyHints({ link: '</asset>; rel=preload; as=script' });
    res.end(DATA);
  });
  await assert.rejects(downloadRepositoryBackup(f.options), code('backup_download_headers')); await empty(f); await noSockets(f);
});

test('protocol upgrades do not escape socket ownership', async t => {
  const f = await tlsFixture(t); f.setHandler((_, res) => { res.writeHead(101, { connection: 'Upgrade', upgrade: 'websocket' }); res.flushHeaders(); });
  await assert.rejects(downloadRepositoryBackup(f.options), code('backup_download_upgrade')); await empty(f); await noSockets(f);
});

test('transfer codings other than chunked cannot masquerade as an identity body', async t => {
  const f = await tlsFixture(t); f.setHandler((_, res) => { res.setHeader('transfer-encoding', 'gzip, chunked'); res.end(DATA); });
  await assert.rejects(downloadRepositoryBackup(f.options), code('backup_download_encoding')); await empty(f); await noSockets(f);
});
