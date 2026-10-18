// Adversarial real-TLS stream ownership; not remote storage durability evidence.
import test from 'node:test';
import assert from 'node:assert/strict';
import { uploadRepositoryBackup } from '../lib/repository-backup-upload.mjs';
import { tlsFixture, DATA, NOW } from './backup-download-fixture.mjs';
function options(f, size = DATA.length) {
  const origin = new URL(f.url).origin;
  return { input: f.local, approval: f.approval, trustKey: f.trustKey, caFile: f.caFile,
    policy: f.options.policy, now: NOW, maximumBytes: size, maximumTotalBytes: 3 * size, timeoutMs: 1500,
    target: Object.fromEntries(['archive', 'approval'].map(k => [k, { get: `${origin}/${k}`, put: `${origin}/${k}` }])) };
}
const absent = res => { res.writeHead(404, { 'content-length': 0 }); res.end(); };
test('deadline drains a backpressured PUT without waiting for an unread peer', async t => {
  const f = await tlsFixture(t), data = Buffer.alloc(32 * 1024 ** 2, 0x43); await f.sign(data);
  let held, writes = 0;
  f.setHandler((req, res) => {
    if (req.method === 'GET') { absent(res); return; }
    held = req; writes++;
    // Deliberately do not consume data or reply. This exceeds socket buffers.
  });
  let error;
  try { await uploadRepositoryBackup(options(f, data.length)); } catch (caught) { error = caught; }
  assert.equal(error?.code, 'backup_deadline'); assert.equal(error.publication_state, 'archive_put_unknown');
  assert.equal(writes, 1); assert.ok(held); assert.ok(Number(error.streaming.upload_source_bytes_read) < data.length);
  // Local ownership already settled. The hostile peer needs to resume reading
  // before its HTTP parser can observe closure; that is not client quiescence.
  const closed = new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('peer close not observed')), 2000);
    held.socket.once('close', () => { clearTimeout(timer); resolve(); });
  });
  held.resume(); await closed;
});
test('oversized successful PUT response refuses before approval publication', async t => {
  const f = await tlsFixture(t), writes = [];
  f.setHandler(async (req, res) => {
    if (req.method === 'GET') { absent(res); return; }
    writes.push(req.url);
    try { for await (const _ of req) {} res.writeHead(201, { 'content-length': 16385 }); res.end(Buffer.alloc(16385)); }
    catch { res.destroy(); }
  });
  await assert.rejects(uploadRepositoryBackup(options(f)), { code: 'backup_upload_response_limit' });
  assert.deepEqual(writes, ['/archive']);
});
test('protocol upgrade is refused without any PUT', async t => {
  const f = await tlsFixture(t);
  f.setHandler((req, res) => { res.writeHead(101, { connection: 'upgrade', upgrade: 'other' }); res.end(); });
  await assert.rejects(uploadRepositoryBackup(options(f)), { code: 'backup_upload_upgrade' }); assert.equal(f.requests.length, 1);
});
test('final header-pair ceiling is checked independently of header bytes', async t => {
  const f = await tlsFixture(t);
  f.setHandler((req, res) => { res.writeHead(200, { ...Object.fromEntries(Array.from({ length: 65 }, (_, i) => ['x-' + i, 'v'])), 'content-length': 0 }); res.end(); });
  await assert.rejects(uploadRepositoryBackup(options(f)), { code: 'backup_upload_headers' }); assert.equal(f.requests.length, 1);
});
