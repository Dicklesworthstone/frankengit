// Real loopback TLS and conditional objects, NOT a native fg/server-store oracle.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile, writeFile, unlink, symlink } from 'node:fs/promises';
import { once } from 'node:events';
import { uploadRepositoryBackup, repositoryBackupUploadOptions } from '../lib/repository-backup-upload.mjs';
import { tlsFixture, DATA, ID, NOW } from './backup-download-fixture.mjs';

async function fixture(t) {
  const f = await tlsFixture(t), objects = new Map(), events = [];
  let intercept; const races = new Map();
  f.server.on('checkContinue', (req, res) => {
    const path = new URL(req.url, f.url).pathname;
    if (races.has(path)) {
      objects.set(path, races.get(path)); races.delete(path);
      events.push({ method: req.method, path, headers: req.headers });
      assert.equal(req.headers['if-none-match'], '*');
      res.writeHead(412, { 'content-length': 0 }); res.end();
    } else { res.writeContinue(); f.server.emit('request', req, res); }
  });
  f.setHandler(async (req, res) => {
    const path = new URL(req.url, f.url).pathname;
    events.push({ method: req.method, path, headers: req.headers });
    if (intercept && await intercept(req, res, path)) return;
    if (req.method === 'GET') {
      const bytes = objects.get(path);
      res.writeHead(bytes ? 200 : 404, { 'content-length': bytes?.length ?? 0 }); res.end(bytes); return;
    }
    assert.equal(req.method, 'PUT'); assert.equal(req.headers['if-none-match'], '*');
    if (objects.has(path)) { res.writeHead(412, { 'content-length': 0 }); res.end(); return; }
    const chunks = [];
    try {
      for await (const chunk of req) chunks.push(chunk);
      objects.set(path, Buffer.concat(chunks)); res.writeHead(201, { 'content-length': 0 }); res.end();
    } catch { res.destroy(); }
  });
  const base = new URL(f.url).origin;
  const target = Object.fromEntries(['archive', 'approval'].map(kind => [kind, {
    get: `${base}/${kind}?secret=GET-CAPABILITY`, put: `${base}/${kind}?secret=PUT-CAPABILITY` }]));
  const options = { input: f.local, approval: f.approval, trustKey: f.trustKey, caFile: f.caFile,
    policy: f.options.policy, target, maximumBytes: DATA.length, maximumTotalBytes: 3 * DATA.length, now: NOW, timeoutMs: 3000 };
  return { ...f, objects, events, options, intercept(fn) { intercept = fn; }, race(kind, bytes) { races.set('/' + kind, bytes); } };
}
async function code(promise, expected) {
  let error; try { await promise; } catch (caught) { error = caught; }
  assert.ok(error, `expected ${expected}`); assert.equal(error.code, expected);
  assert.ok(!JSON.stringify(error).includes('CAPABILITY'), 'capabilities never enter diagnostic metadata'); return error;
}
function puts(f) { return f.events.filter(e => e.method === 'PUT'); }

for (const object_format of ['sha1', 'sha256']) test(`publish and re-read original signed archive (${object_format})`, async t => {
  const f = await fixture(t); await f.sign(DATA, { object_format });
  f.options.policy = { ...f.options.policy, object_format };
  const result = await uploadRepositoryBackup(f.options);
  assert.equal(result.state, 'complete'); assert.equal(result.remote_readback_verified, true);
  assert.deepEqual(f.objects.get('/archive'), DATA); assert.deepEqual(f.objects.get('/approval'), await readFile(f.approval));
  assert.deepEqual(f.events.map(e => `${e.method} ${e.path}`), ['GET /approval', 'GET /archive', 'PUT /archive', 'GET /archive', 'PUT /approval', 'GET /approval']);
  assert.equal(result.streaming.total_payload_bytes, String(3 * DATA.length));
  assert.equal(result.streaming.requests, 6); assert.equal(result.remote_physical_durability_verified, false);
  assert.equal(result.authentication.statement.head_generation, '9007199254740993');
  assert.ok(!JSON.stringify(result).includes('CAPABILITY'));
});
test('exact restart verifies both objects without another PUT', async t => {
  const f = await fixture(t), first = await uploadRepositoryBackup(f.options);
  f.events.length = 0; const again = await uploadRepositoryBackup({ ...f.options, checkpoint: first.checkpoint });
  assert.deepEqual(again.disposition, { archive: 'reused', approval: 'reused' });
  assert.equal(puts(f).length, 0); assert.equal(again.streaming.total_payload_bytes, String(2 * DATA.length));
});
test('body-only interrupted publication resumes with only approval PUT', async t => {
  const f = await fixture(t); f.objects.set('/archive', DATA);
  const result = await uploadRepositoryBackup(f.options);
  assert.deepEqual(puts(f).map(e => e.path), ['/approval']); assert.equal(result.disposition.archive, 'reused');
});
for (const kind of ['archive', 'approval']) test(`exact concurrent ${kind} publisher wins without overwrite`, async t => {
  const f = await fixture(t), envelope = await readFile(f.approval);
  f.race(kind, kind === 'archive' ? DATA : envelope);
  const result = await uploadRepositoryBackup(f.options);
  assert.equal(result.disposition[kind], 'concurrent_exact'); assert.equal(puts(f).filter(e => e.path === '/' + kind).length, 1);
});
test('conflicting concurrent body refuses approval', async t => {
  const f = await fixture(t);
  f.race('archive', Buffer.alloc(DATA.length, 1));
  await code(uploadRepositoryBackup(f.options), 'backup_upload_digest'); assert.equal(f.objects.has('/approval'), false);
});
for (const kind of ['archive', 'approval']) test(`conflicting existing ${kind} causes no writes`, async t => {
  const f = await fixture(t), original = kind === 'archive' ? DATA : await readFile(f.approval);
  f.objects.set('/' + kind, Buffer.alloc(original.length, 9));
  await code(uploadRepositoryBackup(f.options), 'backup_upload_digest'); assert.equal(puts(f).length, 0);
});
test('approval with missing dependency is not silently repaired', async t => {
  const f = await fixture(t); f.objects.set('/approval', await readFile(f.approval));
  await code(uploadRepositoryBackup(f.options), 'backup_upload_missing_dependency'); assert.equal(puts(f).length, 0);
});
test('false successful PUT without stored bytes never publishes approval', async t => {
  const f = await fixture(t); f.intercept(async (req, res, path) => {
    if (req.method === 'PUT' && path === '/archive') { for await (const _ of req) {} res.writeHead(201); res.end(); return true; }
  });
  await code(uploadRepositoryBackup(f.options), 'backup_upload_missing_readback'); assert.equal(f.objects.has('/approval'), false);
});
for (const kind of ['archive', 'approval']) test(`lost ${kind} PUT response is ambiguous, explicit restart only`, async t => {
  const f = await fixture(t); let onceOnly = true;
  f.intercept(async (req, res, path) => {
    if (onceOnly && req.method === 'PUT' && path === '/' + kind) {
      onceOnly = false; const parts = []; for await (const part of req) parts.push(part);
      f.objects.set(path, Buffer.concat(parts)); req.socket.destroy(); return true;
    }
  });
  const error = await code(uploadRepositoryBackup(f.options), 'backup_upload_transport');
  assert.equal(error.publication_state, kind + '_put_unknown'); assert.equal(puts(f).filter(e => e.path === '/' + kind).length, 1);
  const before = puts(f).length;
  const result = await uploadRepositoryBackup({ ...f.options, checkpoint: error.checkpoint });
  assert.equal(result.state, 'complete'); assert.equal(puts(f).length - before, kind === 'archive' ? 1 : 0);
});
test('invalid local digest fails before sockets', async t => {
  const f = await fixture(t); await writeFile(f.local, Buffer.alloc(DATA.length, 7));
  await code(uploadRepositoryBackup(f.options), 'backup_upload_source_digest'); assert.equal(f.events.length, 0);
});
test('changed source after verification fails before sockets', async t => {
  const f = await fixture(t);
  await code(uploadRepositoryBackup({ ...f.options, async onProgress(e) {
    if (e.phase === 'source_verified') await writeFile(f.local, Buffer.alloc(DATA.length, 8));
  } }), 'backup_upload_source_changed'); assert.equal(f.events.length, 0);
});
test('invalid signature cannot start a remote request', async t => {
  const f = await fixture(t), envelope = JSON.parse(await readFile(f.approval, 'utf8'));
  envelope.signatures[0].sig = Buffer.alloc(64).toString('base64'); await writeFile(f.approval, JSON.stringify(envelope));
  await code(uploadRepositoryBackup(f.options), 'backup_invalid_signature'); assert.equal(f.events.length, 0);
});
test('independent checkpoint pin mismatch fails before sockets', async t => {
  const f = await fixture(t);
  await code(uploadRepositoryBackup({ ...f.options, checkpoint: { approval_sha256: '0'.repeat(64), trusted_key_id: f.signed.authentication?.trusted_key_id ?? 'sha256:' + '1'.repeat(64) } }), 'backup_upload_checkpoint_mismatch');
  assert.equal(f.events.length, 0);
});
test('expired approval and external floor refuse before sockets', async t => {
  const f = await fixture(t);
  await assert.rejects(uploadRepositoryBackup({ ...f.options, now: NOW + 3 * 86400000 }));
  await assert.rejects(uploadRepositoryBackup({ ...f.options, policy: { ...f.options.policy, minimum_head_generation: '18446744073709551615' } }));
  assert.equal(f.events.length, 0);
});
test('3N-1 aggregate limit refuses before network; 3N succeeds', async t => {
  const f = await fixture(t);
  await code(uploadRepositoryBackup({ ...f.options, maximumTotalBytes: 3 * DATA.length - 1 }), 'backup_upload_budget');
  assert.equal(f.events.length, 0); assert.equal((await uploadRepositoryBackup(f.options)).state, 'complete');
});
test('larger total budget does not enlarge archive ceiling', async t => {
  const f = await fixture(t); await assert.rejects(uploadRepositoryBackup({ ...f.options, maximumBytes: DATA.length - 1 })); assert.equal(f.events.length, 0);
});
for (const status of [301, 401, 403, 409, 500]) test(`HTTP ${status} refuses without retry or redirect`, async t => {
  const f = await fixture(t); f.intercept((req, res) => { res.writeHead(status, { location: f.url }); res.end('SECRET'); return true; });
  const error = await code(uploadRepositoryBackup(f.options), 'backup_upload_http_status');
  assert.equal(error.http_status, status); assert.equal(f.events.length, 1); assert.equal(puts(f).length, 0);
});
test('fragmented chunked remote readback works', async t => {
  const f = await fixture(t); f.objects.set('/archive', DATA);
  f.intercept(async (req, res, path) => {
    if (req.method === 'GET' && path === '/archive') {
      res.writeHead(200); for (let at = 0; at < DATA.length; at += 3001) { res.write(DATA.subarray(at, at + 3001)); await new Promise(r => setImmediate(r)); }
      res.end(); return true;
    }
  });
  assert.equal((await uploadRepositoryBackup(f.options)).state, 'complete');
});
test('wrong content length refuses without PUT', async t => {
  const f = await fixture(t); f.intercept((req, res, path) => { if (path === '/archive') { res.writeHead(200, { 'content-length': DATA.length + 1 }); res.end(DATA); return true; } });
  await code(uploadRepositoryBackup(f.options), 'backup_upload_length'); assert.equal(puts(f).length, 0);
});
test('trailers are rejected even when bytes hash correctly', async t => {
  const f = await fixture(t); f.intercept((req, res, path) => { if (path === '/archive') {
    res.writeHead(200, { trailer: 'X-Foo' }); res.write(DATA); res.addTrailers({ 'X-Foo': 'bar' }); res.end(); return true;
  } });
  await code(uploadRepositoryBackup(f.options), 'backup_upload_incomplete_response'); assert.equal(puts(f).length, 0);
});
test('encoding transforms are refused', async t => {
  const f = await fixture(t); f.intercept((req, res) => { res.writeHead(200, { 'content-encoding': 'gzip' }); res.end(); return true; });
  await code(uploadRepositoryBackup(f.options), 'backup_upload_encoding');
});
test('stalled headers hit one deadline and release connection', async t => {
  const f = await fixture(t); f.intercept(() => true);
  await code(uploadRepositoryBackup({ ...f.options, timeoutMs: 200 }), 'backup_deadline');
  await new Promise(r => setTimeout(r, 30)); assert.equal(f.sockets.size, 0);
});
test('abort drains an in-flight GET and sends no PUT', async t => {
  const f = await fixture(t), controller = new AbortController();
  f.intercept(() => { controller.abort(); return true; });
  await code(uploadRepositoryBackup({ ...f.options, signal: controller.signal }), 'backup_cancelled');
  await new Promise(r => setTimeout(r, 30)); assert.equal(f.sockets.size, 0); assert.equal(puts(f).length, 0);
});
test('cancel after verified archive preserves unadvertised body', async t => {
  const f = await fixture(t), controller = new AbortController();
  await code(uploadRepositoryBackup({ ...f.options, signal: controller.signal,
    onProgress: e => { if (e.phase === 'archive_verified') controller.abort(); } }), 'backup_cancelled');
  assert.deepEqual(f.objects.get('/archive'), DATA); assert.equal(f.objects.has('/approval'), false);
  assert.equal((await uploadRepositoryBackup(f.options)).state, 'complete');
});
test('observer error code does not permit a retry or root publication', async t => {
  const f = await fixture(t), error = new Error('local observer'); error.code = 'ECONNRESET';
  await code(uploadRepositoryBackup({ ...f.options, onProgress(e) { if (e.phase === 'archive_verified') throw error; } }), 'ECONNRESET');
  assert.equal(f.objects.has('/approval'), false);
});
test('TLS verification cannot be disabled by the environment', async t => {
  const f = await fixture(t), old = process.env.NODE_TLS_REJECT_UNAUTHORIZED;
  process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
  try { const { caFile, ...raw } = f.options; await code(uploadRepositoryBackup(raw), 'backup_upload_transport'); }
  finally { if (old === undefined) delete process.env.NODE_TLS_REJECT_UNAUTHORIZED; else process.env.NODE_TLS_REJECT_UNAUTHORIZED = old; }
  assert.equal(f.events.length, 0);
});
test('invalid targets are rejected synchronously and copied before await', async t => {
  const f = await fixture(t);
  for (const target of [null, {}, { archive: { get: 'http://example.com/a', put: 'http://example.com/a' }, approval: f.options.target.approval },
    { archive: { get: f.url, put: f.url.replace('/backup', '/wrong') }, approval: f.options.target.approval },
    { archive: f.options.target.archive, approval: f.options.target.archive }]) {
    assert.throws(() => repositoryBackupUploadOptions({ ...f.options, target }));
  }
  const task = uploadRepositoryBackup(f.options); f.options.target.archive.put = 'https://example.invalid/wrong';
  assert.equal((await task).state, 'complete');
});
test('final-component source symlink is refused', async t => {
  const f = await fixture(t); const alias = f.local + '-alias'; await symlink(f.local, alias);
  await assert.rejects(uploadRepositoryBackup({ ...f.options, input: alias })); assert.equal(f.events.length, 0);
});
test('existing approval is rechecked after dependency verification', async t => {
  const f = await fixture(t); f.objects.set('/archive', DATA); f.objects.set('/approval', await readFile(f.approval));
  await code(uploadRepositoryBackup({ ...f.options, onProgress(e) {
    if (e.phase === 'archive_verified') f.objects.set('/approval', Buffer.alloc(f.objects.get('/approval').length, 7));
  } }), 'backup_upload_digest'); assert.equal(puts(f).length, 0);
});
test('an early successful PUT reply cannot advertise missing content', async t => {
  const f = await fixture(t); f.intercept((req, res) => { if (req.method === 'PUT') { res.writeHead(201); res.end(); return true; } });
  await assert.rejects(uploadRepositoryBackup(f.options)); assert.equal(f.objects.has('/approval'), false);
});
test('a body without HTTP EOF remains bounded and is not advertised', async t => {
  const f = await fixture(t); f.intercept((req, res, path) => { if (req.method === 'GET' && path === '/archive') { res.writeHead(200); res.write(DATA); return true; } });
  await code(uploadRepositoryBackup({ ...f.options, timeoutMs: 200 }), 'backup_deadline'); assert.equal(puts(f).length, 0);
});
test('mutating source while PUT streams cannot publish its approval', async t => {
  const f = await fixture(t), data = Buffer.alloc(4 * 1024 ** 2, 0x43);
  await f.sign(data); f.options.maximumBytes = data.length; f.options.maximumTotalBytes = data.length * 3;
  f.intercept(async (req, res, path) => {
    if (req.method !== 'PUT' || path !== '/archive') return;
    try {
      await once(req, 'data'); await writeFile(f.local, Buffer.alloc(data.length, 0x62));
      for await (const _ of req) {} res.writeHead(201); res.end();
    } catch { res.destroy(); }
    return true;
  });
  await code(uploadRepositoryBackup(f.options), 'backup_upload_source_changed'); assert.equal(f.objects.has('/approval'), false);
});
