// Header and stream contract tests against injected responses. The synthetic
// payloads are not archive oracles; native source_archive_http tests own bytes.
import test from 'node:test';
import assert from 'node:assert/strict';
import { collectSourceArchive, sourceArchiveMetadata, MAX_SOURCE_ARCHIVE_BYTES }
  from '../../crates/fgit-node/src/smart_http/server/browser/source-archive.mjs';

function fixture(format = 'sha1', length = 2048, archiveFormat = 'tar') {
  const width = format === 'sha1' ? 40 : 64;
  const expected = { format, archiveFormat, head: 'alg:2:' + 'a'.repeat(64), commit: 'b'.repeat(width),
    rootTree: 'c'.repeat(width), selectedTree: 'd'.repeat(width) };
  const headers = new Headers({
    'Content-Type': archiveFormat === 'zip' ? 'application/zip' : 'application/x-tar',
    'Content-Disposition': `attachment; filename="source.${archiveFormat}"`,
    'Content-Length': String(length), 'Cache-Control': 'no-store',
    'X-FrankenGit-Archive-Profile': archiveFormat === 'zip' ? 'zip-store-source-v1' : 'ustar-source-v1',
    'X-FrankenGit-Archive-Entries': '3',
    'X-FrankenGit-Archive-Gitlinks': '1', 'X-FrankenGit-Snapshot-Token': expected.head,
    'X-FrankenGit-Source-Commit': format + ':' + expected.commit,
    'X-FrankenGit-Root-Tree': format + ':' + expected.rootTree,
    'X-FrankenGit-Selected-Tree': format + ':' + expected.selectedTree,
  });
  return { expected, headers, bytes: Uint8Array.from({ length }, (_, i) => i % 251) };
}
const deferred = () => { let resolve; const promise = new Promise(r => { resolve = r; }); return { promise, resolve }; };
for (const format of ['sha1', 'sha256']) {
  for (const archiveFormat of ['tar', 'zip']) {
  test(format + '/' + archiveFormat + ': irregular chunks produce exactly one complete archive at the selected directory', async () => {
    const length = archiveFormat === 'zip' ? 1763 : 3584;
    const f = fixture(format, length, archiveFormat), pieces = [f.bytes.slice(0, 19), f.bytes.slice(19, 513), f.bytes.slice(513)];
    const stream = new ReadableStream({ pull(controller) {
      if (pieces.length) controller.enqueue(pieces.shift()); else controller.close();
    } }, { highWaterMark: 0 });
    const result = await collectSourceArchive(new Response(stream, { headers: f.headers }), f.expected);
    assert.deepEqual(result.bytes, f.bytes);
    assert.equal(result.length, length); assert.equal(result.entries, 3); assert.equal(result.gitlinks, 1);
    for (const key of ['format', 'archiveFormat', 'head', 'commit', 'rootTree', 'selectedTree']) assert.equal(result[key], f.expected[key]);
    assert.equal(result.filename, `source.${archiveFormat}`);
    assert.equal(result.mediaType, f.headers.get('Content-Type'));
    assert.equal(stream.locked, false);
  });
  test(format + '/' + archiveFormat + ': the minimum root-only profile is admitted at its exact byte bound', async () => {
    const minimum = archiveFormat === 'zip' ? 112 : 1536;
    const f = fixture(format, minimum, archiveFormat);
    f.headers.set('X-FrankenGit-Archive-Entries', '1'); f.headers.set('X-FrankenGit-Archive-Gitlinks', '0');
    f.headers.set('X-FrankenGit-Selected-Tree', f.expected.rootTree);
    f.expected.selectedTree = f.expected.rootTree;
    const result = await collectSourceArchive(new Response(f.bytes, { headers: f.headers }), f.expected, { maxBytes: minimum });
    assert.deepEqual(result.bytes, f.bytes); assert.equal(result.entries, 1); assert.equal(result.gitlinks, 0);
    await assert.rejects(collectSourceArchive(new Response(f.bytes, { headers: f.headers }), f.expected, { maxBytes: minimum - 1 }), /length/);
  });
  test(format + '/' + archiveFormat + ': independently changed head, commit, root or selected tree never return bytes', async () => {
    const f = fixture(format, 2048, archiveFormat);
    const fields = ['X-FrankenGit-Snapshot-Token', 'X-FrankenGit-Source-Commit', 'X-FrankenGit-Root-Tree', 'X-FrankenGit-Selected-Tree'];
    for (const field of fields) {
      const headers = new Headers(f.headers);
      headers.set(field, field === 'X-FrankenGit-Snapshot-Token' ? 'alg:2:' + 'e'.repeat(64) : format + ':' + 'e'.repeat(f.expected.commit.length));
      await assert.rejects(collectSourceArchive(new Response(f.bytes, { headers }), f.expected), /snapshot or selected directory changed/);
    }
  });
  }
}

test('the requested encoding pins all ZIP headers and cannot silently fall back to tar', async () => {
  const f = fixture('sha256', 112, 'zip');
  f.headers.set('X-FrankenGit-Archive-Entries', '1');
  f.headers.set('X-FrankenGit-Archive-Gitlinks', '0');
  for (const [field, value] of [
    ['Content-Type', 'application/x-tar'],
    ['Content-Disposition', 'attachment; filename="source.tar"'],
    ['Content-Disposition', 'attachment; filename="../source.zip"'],
    ['X-FrankenGit-Archive-Profile', 'ustar-source-v1'],
    ['X-FrankenGit-Archive-Profile', 'zip64-source-v1'],
    ['Content-Length', '111'],
    ['X-FrankenGit-Archive-Entries', '65536'],
    ['Content-Encoding', 'gzip'],
  ]) {
    const headers = new Headers(f.headers); headers.set(field, value);
    let reads = 0, cancellations = 0;
    const body = new ReadableStream({ pull() { reads++; }, cancel() { cancellations++; } }, { highWaterMark: 0 });
    await assert.rejects(collectSourceArchive(new Response(body, { headers }), f.expected), Error, field);
    assert.equal(reads, 0); assert.equal(cancellations, 1); assert.equal(body.locked, false);
  }
  for (const requested of ['tar', 'zip']) {
    const sent = fixture('sha1', 2048, requested === 'zip' ? 'tar' : 'zip');
    await assert.rejects(collectSourceArchive(new Response(sent.bytes, { headers: sent.headers }),
      { ...sent.expected, archiveFormat: requested }), /headers or profile/);
  }
  const tar = fixture(); delete tar.expected.archiveFormat;
  assert.equal(sourceArchiveMetadata(tar.headers, tar.expected).archiveFormat, 'tar', 'omitted format preserves tar');
  await assert.rejects(collectSourceArchive(new Response(f.bytes, { headers: f.headers }),
    { ...f.expected, archiveFormat: undefined }), /headers or profile/);
});

test('malformed headers and excess lengths refuse before reading any body chunk', async () => {
  const f = fixture(), cases = [
    ['Content-Length', null], ['Content-Length', '02048'], ['Content-Length', '-1'], ['Content-Length', '2e3'],
    ['Content-Length', '0'], ['Content-Length', '1024'], ['Content-Length', '2049'],
    ['Content-Length', String(MAX_SOURCE_ARCHIVE_BYTES + 512)], ['Content-Length', '99999999999999999999'],
    ['Content-Type', 'text/html'], ['Content-Disposition', 'inline'], ['Content-Disposition', 'attachment; filename="../../escape.tar"'],
    ['Content-Encoding', 'gzip'], ['Cache-Control', 'public'], ['X-FrankenGit-Archive-Profile', 'future-v2'],
    ['X-FrankenGit-Archive-Entries', '0'], ['X-FrankenGit-Archive-Entries', '100001'], ['X-FrankenGit-Archive-Entries', '03'],
    ['X-FrankenGit-Archive-Gitlinks', '3'], ['X-FrankenGit-Archive-Gitlinks', '-1'], ['X-FrankenGit-Archive-Gitlinks', null],
    ['X-FrankenGit-Source-Commit', 'sha256:' + 'b'.repeat(64)], ['X-FrankenGit-Root-Tree', '0'.repeat(40)],
    ['X-FrankenGit-Selected-Tree', null],
  ];
  for (const [field, value] of cases) {
    const headers = new Headers(f.headers);
    if (value === null) headers.delete(field); else headers.set(field, value);
    let reads = 0, cancellations = 0;
    const body = new ReadableStream({ pull() { reads++; }, cancel() { cancellations++; } }, { highWaterMark: 0 });
    await assert.rejects(collectSourceArchive(new Response(body, { headers }), f.expected), Error, field + '=' + value);
    assert.equal(reads, 0, field); assert.equal(cancellations, 1, field); assert.equal(body.locked, false);
  }
});

test('truncated and overlong bodies never release an apparently complete prefix', async () => {
  const f = fixture();
  await assert.rejects(collectSourceArchive(new Response(f.bytes.slice(0, -1), { headers: f.headers }), f.expected), /Truncated/);
  const larger = new Uint8Array(f.bytes.length + 1); larger.set(f.bytes);
  await assert.rejects(collectSourceArchive(new Response(larger, { headers: f.headers }), f.expected), /exceeded its declared/);
});

test('a failing last read releases the reader and does not return partial archive bytes', async () => {
  const f = fixture(), failure = new Error('connection lost');
  let reads = 0;
  const body = new ReadableStream({ pull(controller) {
    if (++reads === 1) controller.enqueue(f.bytes.slice(0, 512)); else controller.error(failure);
  } }, { highWaterMark: 0 });
  await assert.rejects(collectSourceArchive(new Response(body, { headers: f.headers }), f.expected), error => error === failure);
  assert.equal(body.locked, false);
});

test('canceling a stalled stream drains its pending read and releases its lock', async () => {
  const f = fixture(), started = deferred(), hold = deferred(), controller = new AbortController();
  let reads = 0, cancellations = 0;
  const body = new ReadableStream({ pull(stream) {
    if (++reads === 1) { stream.enqueue(f.bytes.slice(0, 512)); return; }
    started.resolve(); return hold.promise;
  }, cancel() { cancellations++; hold.resolve(); } }, { highWaterMark: 0 });
  const pending = collectSourceArchive(new Response(body, { headers: f.headers }), f.expected, { signal: controller.signal });
  await started.promise;
  const reason = new DOMException('Canceled by the reader', 'AbortError'); controller.abort(reason);
  await assert.rejects(pending, error => error === reason);
  assert.equal(cancellations, 1); assert.equal(body.locked, false);
});

test('the original operation checkpoint can expire after a chunk without releasing the prefix', async () => {
  const f = fixture(), deadline = new DOMException('Original deadline expired', 'TimeoutError');
  let checks = 0, cancellations = 0;
  const body = new ReadableStream({ pull(controller) { controller.enqueue(f.bytes.slice(0, 512)); },
    cancel() { cancellations++; } }, { highWaterMark: 0 });
  await assert.rejects(collectSourceArchive(new Response(body, { headers: f.headers }), f.expected,
    { checkpoint() { if (++checks >= 3) throw deadline; } }), error => error === deadline);
  assert.equal(cancellations, 1); assert.equal(body.locked, false);
});

test('invalid caller budgets and source identities cannot relax the closed archive profile', () => {
  const f = fixture();
  for (const maxBytes of [0, -1, Infinity, NaN, 1.5, MAX_SOURCE_ARCHIVE_BYTES + 1]) {
    assert.throws(() => sourceArchiveMetadata(f.headers, f.expected, maxBytes));
  }
  for (const head of ['', 'alg:0:' + 'a'.repeat(64), 'alg:65536:' + 'a'.repeat(64), 'alg:2:' + '0'.repeat(64)]) {
    assert.throws(() => sourceArchiveMetadata(f.headers, { ...f.expected, head }));
  }
  assert.throws(() => sourceArchiveMetadata(f.headers, { ...f.expected, format: 'sha512' }));
  for (const archiveFormat of ['', 'ZIP', 'tar.gz', 'zip64', {}, true]) {
    assert.throws(() => sourceArchiveMetadata(f.headers, { ...f.expected, archiveFormat }));
  }
});
