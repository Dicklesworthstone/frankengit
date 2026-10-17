import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile, writeFile, unlink, readdir, stat } from 'node:fs/promises';
import { join } from 'node:path';
import { sourceFixture, HEAD } from './remote-bundle-export-fixture.mjs';
import { fixture as destinationFixture } from './remote-bundle-fixture.mjs';
import { exportRemoteBundle, inspectRemoteDownload } from '../../scripts/operator/remote_bundle_export.mjs';
import { prepareRemoteBundle, runRemoteBundle } from '../../scripts/operator/remote_bundle.mjs';
import { hash, encode, BUNDLE_REMOTE_LIMITS as L } from '../../scripts/operator/remote_bundle_protocol.mjs';

for (const format of ['sha1', 'sha256']) test(`source-to-destination payload transfer with separate permissions: ${format}`, async t => {
  const source = await sourceFixture(t, { format }), destination = await destinationFixture(t, { format });
  const r = await exportRemoteBundle(source.options); assert.equal(r.complete, true); assert.equal(r.source.snapshot_token, HEAD);
  assert.equal(r.native_bundle_validated, false); assert.equal(r.artifact_sha256, hash(source.bytes));
  assert((await readFile(r.bundle_file)).equals(source.bytes)); assert.equal(source.requests.length, 1);
  assert.equal((await stat(r.bundle_file)).mode & 0o777, 0o600);
  await source.close(); await unlink(source.token);
  const inspected = await inspectRemoteDownload({ workdir: r.workdir, confirm: r.download_sha256 });
  const job = await prepareRemoteBundle({ ...destination.options, bundleFile: inspected.bundle_file, bundleConfirm: inspected.artifact_sha256 });
  await unlink(r.bundle_file);
  const result = await runRemoteBundle({ workdir: job.workdir, confirm: job.intent_sha256, tokenFile: destination.token });
  assert.equal(result.complete, true); assert(destination.requests.find(r => r.payload).payload.equals(source.bytes));
});
for (const [label, alter] of [
  ['scope', h => { h['x-fgit-repository'] = '99'.repeat(16); }],
  ['incarnation', h => { h['x-fgit-repository-incarnation'] = '99'.repeat(16); }],
  ['format', h => { h['x-fgit-object-format'] = 'sha256'; }],
  ['snapshot', h => { h['x-fgit-snapshot'] = 'alg:2:' + '77'.repeat(32); }],
  ['profile', h => { h['x-fgit-bundle-profile'] = 'incremental'; }],
  ['read-only', h => { h['x-fgit-read-only'] = 'false'; }],
  ['digest', h => { h['x-fgit-artifact-sha256'] = '0'.repeat(64); }],
  ['declared length', h => { h['content-length'] = String(L.bundle + 1); }],
  ['no length', h => { delete h['content-length']; }],
  ['content type', h => { h['content-type'] = 'application/json'; }],
  ['content coding', h => { h['content-encoding'] = 'gzip'; }],
  ['duplicate binding header', h => { h['x-fgit-tenant'] = [h['x-fgit-tenant'], h['x-fgit-tenant']]; }],
]) test(`download refuses ${label} without a successful local prefix`, async t => {
  const f = await sourceFixture(t, { intercept: ({ headers }) => alter(headers) });
  await assert.rejects(exportRemoteBundle(f.options)); assert.equal(f.requests.length, 1);
  assert(!(await readdir(f.root)).includes('download'));
});
test('exact selected byte limit succeeds and one byte less refuses', async t => {
  const f = await sourceFixture(t); const r = await exportRemoteBundle({ ...f.options, selection: { ...f.selection, max_bytes: f.bytes.length } });
  assert.equal(r.bytes, f.bytes.length);
  await assert.rejects(exportRemoteBundle({ ...f.options, workdir: join(f.root, 'small'), selection: { ...f.selection, max_bytes: f.bytes.length - 1 } }));
});
test('first-snapshot selection stays optional and is retained exactly', async t => {
  const f = await sourceFixture(t); delete f.selection.expected_head;
  const r = await exportRemoteBundle(f.options); assert.equal(r.source.snapshot_token, HEAD);
  assert.equal(new URLSearchParams(f.requests[0].body).has('expected_head'), false);
  assert.equal((await inspectRemoteDownload({ workdir: r.workdir, confirm: r.download_sha256 })).source.snapshot_token, HEAD);
});
test('redirect or expired pin never causes a second export request', async t => {
  const f = await sourceFixture(t, { intercept: ({ res }) => { res.writeHead(302, { location: '/steal' }); res.end(); return false; } });
  await assert.rejects(exportRemoteBundle(f.options)); assert.equal(f.requests.length, 1);
});
test('aborted response cannot publish a partial download manifest', async t => {
  const stop = new AbortController();
  const f = await sourceFixture(t, { intercept: ({ res, headers, bytes }) => {
    res.writeHead(200, headers); res.write(bytes.subarray(0, 1)); setTimeout(() => stop.abort(), 20); return false;
  } });
  await assert.rejects(exportRemoteBundle({ ...f.options, signal: stop.signal, timeoutMs: 1000 }));
  assert(!(await readdir(f.root)).includes('download'));
});
test('download deadline bounds stalled bodies', async t => {
  const f = await sourceFixture(t, { intercept: ({ res, headers }) => { res.writeHead(200, headers); res.write('x'); return false; } });
  await assert.rejects(exportRemoteBundle({ ...f.options, timeoutMs: 50 })); assert.equal(f.requests.length, 1);
});
test('offline download inspection rejects changed bytes, pins and unknown files', async t => {
  const f = await sourceFixture(t), r = await exportRemoteBundle(f.options); await f.close(); await unlink(f.token);
  await assert.rejects(inspectRemoteDownload({ workdir: r.workdir, confirm: '0'.repeat(64) }), /download_pin/);
  await writeFile(join(r.workdir, 'extra'), 'x', { mode: 0o600 });
  await assert.rejects(inspectRemoteDownload({ workdir: r.workdir, confirm: r.download_sha256 }), /unexpected_file/);
  await unlink(join(r.workdir, 'extra')); await writeFile(r.bundle_file, Buffer.alloc(r.bytes));
  await assert.rejects(inspectRemoteDownload({ workdir: r.workdir, confirm: r.download_sha256 }), /export_digest/);
});
test('changed manifest source cannot pass even with recalculated root hash', async t => {
  const f = await sourceFixture(t), r = await exportRemoteBundle(f.options), file = join(r.workdir, 'download.json');
  const m = JSON.parse(await readFile(file)); m.source.scope.repository_id = '99'.repeat(16); const bytes = encode(m); await writeFile(file, bytes);
  await assert.rejects(inspectRemoteDownload({ workdir: r.workdir, confirm: hash(bytes) }), /export_scope/);
});
test('occupied output refuses before credential/network use', async t => {
  const f = await sourceFixture(t), r = await exportRemoteBundle(f.options); const n = f.requests.length;
  await assert.rejects(exportRemoteBundle(f.options), /exists/); assert.equal(f.requests.length, n);
  assert.equal((await inspectRemoteDownload({ workdir: r.workdir, confirm: r.download_sha256 })).complete, true);
});
test('actual 64 MiB payload downloads and verifies at the operator ceiling', async t => {
  const f = await sourceFixture(t, { bytes: Buffer.alloc(L.bundle, 0xa5) }), r = await exportRemoteBundle(f.options);
  assert.equal(r.bytes, L.bundle); assert.equal((await inspectRemoteDownload({ workdir: r.workdir, confirm: r.download_sha256 })).bytes, L.bundle);
});
