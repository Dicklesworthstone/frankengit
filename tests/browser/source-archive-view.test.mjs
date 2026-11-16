// Production source-view controls with injected DOM and HTTP streams. These are
// module contract tests, not evidence of a live browser or native fg service.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { mount } from '../../crates/fgit-node/src/smart_http/server/browser/browser.mjs';
import { fixture, dom, location, response, waitFor, webcrypto } from './source-browser-fixtures.mjs';

const deferred = () => { let resolve; const promise = new Promise(r => { resolve = r; }); return { promise, resolve }; };
function archive(f, { body = new Uint8Array(2048).fill(97), length = 2048, selectedTree = f.common.root_tree, archiveFormat = 'tar', changes = {}, status = 200 } = {}) {
  return new Response(body, { status, headers: {
    'Content-Type': archiveFormat === 'zip' ? 'application/zip' : 'application/x-tar',
    'Content-Disposition': `attachment; filename="source.${archiveFormat}"`,
    'Content-Length': String(length), 'Cache-Control': 'no-store',
    'X-FrankenGit-Archive-Profile': archiveFormat === 'zip' ? 'zip-store-source-v1' : 'ustar-source-v1',
    'X-FrankenGit-Archive-Entries': '2',
    'X-FrankenGit-Archive-Gitlinks': '0', 'X-FrankenGit-Snapshot-Token': f.common.snapshot_token,
    'X-FrankenGit-Source-Commit': f.format + ':' + f.common.source_commit,
    'X-FrankenGit-Root-Tree': f.format + ':' + f.common.root_tree,
    'X-FrankenGit-Selected-Tree': f.format + ':' + selectedTree, ...changes,
  } });
}
function setup(f, respond, options = {}) {
  const d = dom(), calls = []; d.get('format').value = f.format;
  const client = mount(d.document, location, async (url, init) => {
    const call = { url: String(url), init, fields: new URLSearchParams(init.body) }; calls.push(call);
    return respond(call, calls.length);
  }, { cryptoImpl: webcrypto, urlApi: d.urlApi, ...options });
  const button = (id, label) => { const value = d.buttons(id).find(b => b.textContent === label); assert.ok(value, label); return value; };
  const open = async () => {
    d.get('token').value = 'a'.repeat(64); d.get('connection').emit('submit');
    await waitFor(() => d.buttons('breadcrumbs').some(b => b.textContent === 'Download directory'));
  };
  const download = (archiveFormat = 'tar') => button('breadcrumbs', archiveFormat === 'zip' ? 'Download directory as ZIP' : 'Download directory').click();
  return { ...d, client, calls, button, open, download };
}
for (const format of ['sha1', 'sha256']) {
  for (const archiveFormat of ['tar', 'zip']) {
  test(format + '/' + archiveFormat + ': Download directory carries the selected pins and exposes only the complete inert archive', async () => {
    const f = fixture(format), bytes = Uint8Array.from({ length: archiveFormat === 'zip' ? 1733 : 2560 }, (_, i) => i % 251);
    const d = setup(f, (_, n) => n === 1 ? response(f.tree()) : archive(f, { body: bytes, length: bytes.length, archiveFormat }));
    d.get('expected-commit').value = f.common.source_commit;
    await d.open(); const stale = d.button('breadcrumbs', archiveFormat === 'zip' ? 'Download directory as ZIP' : 'Download directory');
    assert.equal(d.urls.size, 0); d.download(archiveFormat);
    await waitFor(() => d.get('status').textContent.startsWith('Source archive ready.'));
    assert.equal(d.calls.length, 2);
    const call = d.calls[1];
    assert.equal(call.url, location.origin + '/repo.git/api/v1/source/archive');
    assert.equal(call.init.method, 'POST'); assert.equal(call.init.credentials, 'omit'); assert.equal(call.init.redirect, 'error');
    assert.equal(call.init.mode, 'same-origin'); assert.equal(call.init.cache, 'no-store'); assert.equal(call.init.referrerPolicy, 'no-referrer');
    assert.equal(call.init.headers.Accept, archiveFormat === 'zip' ? 'application/zip' : 'application/x-tar');
    assert.equal(call.fields.get('archive_format'), archiveFormat === 'zip' ? 'zip' : null);
    assert.equal(call.init.headers.Authorization, 'Bearer ' + 'a'.repeat(64));
    assert.equal(call.fields.get('expected_head'), f.common.snapshot_token); assert.equal(call.fields.get('expected_commit'), f.common.source_commit);
    assert.equal(call.fields.get('ref'), f.selected.reference); assert.equal(call.fields.get('object_format'), format);
    assert.equal(call.fields.has('path_hex'), false); assert.equal(call.init.headers['Idempotency-Key'], undefined);
    assert.deepEqual(d.document.downloads.map(item => item.filename), [`source.${archiveFormat}`]);
    const blob = d.urls.values().next().value;
    assert.equal(blob.type, call.init.headers.Accept); assert.deepEqual(new Uint8Array(await blob.arrayBuffer()), bytes);
    assert.match(d.get('content').textContent, /did not cryptographically verify/);
    stale.click(); assert.equal(d.calls.length, 2, 'detached directory controls cannot start a new read');
    const repeat = d.button('content', `Download source.${archiveFormat} again`); repeat.click();
    assert.equal(d.document.downloads.length, 2); assert.equal(d.calls.length, 2);
    d.client.disconnect(); assert.equal(d.urls.size, 0); assert.equal(d.revoked.length, 1);
    repeat.click(); assert.equal(d.document.downloads.length, 2);
  });
  }
}

test('a ZIP selection never accepts an otherwise valid tar response and tar never accepts ZIP', async () => {
  for (const requested of ['tar', 'zip']) {
    const f = fixture(), sent = requested === 'zip' ? 'tar' : 'zip';
    const d = setup(f, (_, n) => n === 1 ? response(f.tree()) : archive(f, { archiveFormat: sent }));
    await d.open(); d.download(requested);
    await waitFor(() => d.calls.length === 2 && d.get('cancel-read').disabled);
    assert.equal(d.urls.size, 0); assert.equal(d.document.downloads.length, 0);
    assert.match(d.get('status').textContent, /headers or profile/); d.client.disconnect();
  }
});

test('a byte-named subdirectory downloads that exact path and selected tree', async () => {
  const f = fixture('sha256'), path = '73ff', tree = 'd'.repeat(64);
  const root = { ...f.tree(), entries: [{ name_hex: path, object_id: tree, kind: 'directory' }] };
  const child = { ...f.tree(), path_hex: path, object_id: tree, entries: [] };
  const d = setup(f, (_, n) => n === 1 ? response(root) : n === 2 ? response(child) : archive(f, { selectedTree: tree }));
  await d.open(); d.button('content', 's\\xff').click();
  await waitFor(() => d.get('content').textContent.includes('This directory is empty.'));
  d.download(); await waitFor(() => d.document.downloads.length === 1);
  assert.equal(d.calls[2].fields.get('path_hex'), path);
  assert.match(d.get('content').textContent, new RegExp(tree)); d.client.disconnect();
});

test('a partial response never creates a Blob URL before its final chunk arrives', async () => {
  const f = fixture(), started = deferred(); let writer;
  const bytes = new Uint8Array(2048).fill(31);
  const body = new ReadableStream({ start(controller) { writer = controller; },
    pull(controller) { if (!this.sent) { this.sent = true; controller.enqueue(bytes.slice(0, 512)); started.resolve(); } } },
    { highWaterMark: 0 });
  const d = setup(f, (_, n) => n === 1 ? response(f.tree()) : archive(f, { body }));
  await d.open(); d.download(); await started.promise; await new Promise(setImmediate);
  assert.equal(d.urls.size, 0); assert.equal(d.document.downloads.length, 0);
  writer.enqueue(bytes.slice(512)); writer.close();
  await waitFor(() => d.document.downloads.length === 1);
  assert.deepEqual(new Uint8Array(await d.urls.values().next().value.arrayBuffer()), bytes); d.client.disconnect();
});

test('wrong snapshot, commit, root, selected tree or length clears the view without a download', async () => {
  for (const changes of [
    { 'X-FrankenGit-Snapshot-Token': 'alg:2:' + 'e'.repeat(64) },
    { 'X-FrankenGit-Source-Commit': 'sha1:' + 'e'.repeat(40) },
    { 'X-FrankenGit-Root-Tree': 'sha1:' + 'e'.repeat(40) },
    { 'X-FrankenGit-Selected-Tree': 'sha1:' + 'e'.repeat(40) },
    { 'Content-Length': '2560' }, { 'Content-Length': '1536' },
    { 'Content-Length': String(128 * 1024 * 1024 + 512) }, { 'Content-Encoding': 'gzip' },
  ]) {
    const f = fixture(), d = setup(f, (_, n) => n === 1 ? response(f.tree()) : archive(f, { changes }));
    await d.open(); d.download();
    await waitFor(() => d.calls.length === 2 && d.get('cancel-read').disabled);
    assert.equal(d.urls.size, 0); assert.equal(d.document.downloads.length, 0);
    assert.equal(d.get('content').textContent, ''); assert.doesNotMatch(d.get('status').textContent, /archive ready/i);
    d.client.disconnect();
  }
});

for (const event of ['cancel', 'disconnect', 'pagehide', 'settings']) {
  for (const archiveFormat of ['tar', 'zip']) {
  test(event + '/' + archiveFormat + ' during archive streaming discards the prefix and cancels the owned reader', async () => {
    const f = fixture(), entered = deferred(); let cancellations = 0;
    const body = new ReadableStream({ pull(controller) {
      if (!this.sent) { this.sent = true; controller.enqueue(new Uint8Array(512)); }
      else entered.resolve();
    }, cancel() { cancellations++; } }, { highWaterMark: 0 });
    const d = setup(f, (_, n) => n === 1 ? response(f.tree()) : archive(f, { body, archiveFormat }));
    await d.open(); d.download(archiveFormat); await entered.promise;
    if (event === 'pagehide') d.document.defaultView.emit('pagehide');
    else if (event === 'settings') { d.get('reference').value = 'refs/heads/other'; d.get('reference').emit('input'); }
    else d.client[event]();
    await waitFor(() => cancellations === 1); await new Promise(setImmediate);
    assert.equal(d.calls[1].init.signal.aborted, true); assert.equal(body.locked, false);
    assert.equal(d.urls.size, 0); assert.equal(d.document.downloads.length, 0);
    assert.equal(d.get('content').textContent, ''); assert.equal(d.get('snapshot').textContent, '');
    d.client.disconnect();
  });
  }
}

test('the original request deadline cancels a stalled archive without offering partial bytes', async () => {
  const f = fixture(); let cancellations = 0;
  const body = new ReadableStream({ pull() {}, cancel() { cancellations++; } }, { highWaterMark: 0 });
  const d = setup(f, (_, n) => n === 1 ? response(f.tree()) : archive(f, { body }), { timeoutMs: 100 });
  await d.open(); d.download();
  await waitFor(() => /timed out/.test(d.get('status').textContent));
  assert.equal(cancellations, 1); assert.equal(d.calls[1].init.signal.aborted, true);
  assert.equal(d.urls.size, 0); assert.equal(d.document.downloads.length, 0); d.client.disconnect();
});

test('cancellation during Blob URL creation is checked again before any download click', async () => {
  const f = fixture(), d = setup(f, (_, n) => n === 1 ? response(f.tree()) : archive(f));
  const create = d.urlApi.createObjectURL;
  d.urlApi.createObjectURL = blob => { const url = create(blob); d.client.cancel(); return url; };
  await d.open(); d.download();
  await waitFor(() => d.revoked.length === 1);
  assert.equal(d.document.downloads.length, 0); assert.equal(d.urls.size, 0);
  assert.match(d.get('status').textContent, /Read canceled/); d.client.disconnect();
});

test('the completed archive URL is revoked automatically and recreated only for an explicit repeat download', async () => {
  const f = fixture(), d = setup(f, (_, n) => n === 1 ? response(f.tree()) : archive(f));
  await d.open(); d.download(); await waitFor(() => d.document.downloads.length === 1);
  await waitFor(() => d.urls.size === 0);
  assert.equal(d.revoked.length, 1); d.button('content', 'Download source.tar again').click();
  assert.equal(d.document.downloads.length, 2); assert.equal(d.calls.length, 2);
  assert.equal(d.urls.size, 1); d.client.disconnect(); assert.equal(d.revoked.length, 2);
});

test('401 requires new credentials and 409 never silently follows a moved reference', async () => {
  for (const status of [401, 409]) {
    const f = fixture(), d = setup(f, (_, n) => n === 1 ? response(f.tree()) : new Response('', { status }));
    await d.open(); d.download(); await waitFor(() => d.calls.length === 2 && d.get('cancel-read').disabled);
    assert.equal(d.document.downloads.length, 0); assert.equal(d.urls.size, 0); assert.equal(d.get('snapshot').textContent, '');
    assert.match(d.get('status').textContent, status === 401 ? /Token rejected or revoked/ : /snapshot moved/);
    d.client.disconnect();
  }
});

test('the served page states the archive size and server-validation boundary', () => {
  const html = readFileSync(new URL('../../crates/fgit-node/src/smart_http/server/browser/index.html', import.meta.url), 'utf8');
  assert.match(html, /Download directory/); assert.match(html, /source\.tar/); assert.match(html, /128 MiB/);
  assert.match(html, /Download directory as ZIP/); assert.match(html, /source\.zip/);
  assert.match(html, /does not cryptographically verify or extract/);
});
