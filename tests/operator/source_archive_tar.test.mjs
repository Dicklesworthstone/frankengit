import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { archiveSelection, sha256 } from '../../scripts/operator/source_archive.mjs';
import { buildSourceArchive, inspectSourceArchive, portablePath, TAR_LIMIT } from '../../scripts/operator/source_archive_tar.mjs';
import { repository, hex } from './fixtures/source_archive_native.mjs';
function capture(format, definitions) {
  const repo = repository(format, definitions);
  return { schema: 'frankengit-source-capture-v1', selection: archiveSelection({ endpoint: 'https://forge.example/repo.git', ...repo.scope,
    ref: repo.common.ref, expected_commit: repo.commit }), snapshot_token: repo.snapshot, source_head: repo.common.source_head,
    source_rcr: 'fixture-rcr', commit: { object_id: repo.commit, body_hex: hex(repo.body) },
    trees: [...repo.dirs].map(([path_hex, dir]) => ({ path_hex, object_id: dir.id, body_hex: hex(dir.body) })),
    files: [...repo.files].map(([path_hex, row]) => ({ path_hex, kind: row.kind, object_id: row.id, bytes: row.data })) };
}
function segments(bytes) {
  const rows = []; let at = 0;
  while (at < bytes.length - 1024) {
    const size = parseInt(bytes.subarray(at + 124, at + 136).toString(), 8), length = 512 + Math.ceil(size / 512) * 512;
    rows.push({ name: bytes.subarray(at, at + 100).toString().replace(/\0.*$/s, ''), size, start: at, length, bytes: Buffer.from(bytes.subarray(at, at + length)) }); at += length;
  }
  return rows;
}
function checksum(header) {
  header.fill(32, 148, 156);
  header.write(header.reduce((sum, b) => sum + b, 0).toString(8).padStart(6, '0') + '\0 ', 148, 'ascii');
}
function alterManifest(bytes, work) {
  const [first, ...rest] = segments(bytes), value = JSON.parse(first.bytes.subarray(512, 512 + first.size));
  work(value); const data = Buffer.from(JSON.stringify(value) + '\n'), header = Buffer.from(first.bytes.subarray(0, 512));
  header.write(data.length.toString(8).padStart(11, '0') + '\0', 124, 'ascii'); checksum(header);
  return Buffer.concat([header, data, Buffer.alloc((512 - data.length % 512) % 512), ...rest.map(row => row.bytes), Buffer.alloc(1024)]);
}
for (const format of ['sha1', 'sha256']) for (const layout of ['portable', 'objects']) {
  test(`${format}/${layout}: archive reopens offline with complete commit/tree/file proof`, () => {
    const c = capture(format), output = buildSourceArchive(c, layout), read = inspectSourceArchive(output.bytes, output.receipt.archive_sha256);
    assert.deepEqual(read, output.receipt); assert.equal(read.files, 3); assert.equal(read.gitlinks, 1);
    assert.equal(read.native_content_and_paths_verified, true); assert.equal(read.authority_signatures_verified, false);
    assert.equal(read.executable_files_created, false); assert.equal(read.symlinks_created, false);
  });
}
test('Python tarfile independently reads normal paths, inert symlinks, modes, directory and gitlink records', () => {
  const output = buildSourceArchive(capture(), 'portable');
  const python = `import tarfile,io,sys,json\nt=tarfile.open(fileobj=io.BytesIO(sys.stdin.buffer.read()),mode='r:')\nprint(json.dumps([{'name':x.name,'mode':x.mode,'dir':x.isdir(),'file':x.isfile(),'link':x.issym(),'data':t.extractfile(x).read().hex() if x.isfile() else None} for x in t]))`;
  const rows = JSON.parse(execFileSync('python3', ['-c', python], { input: output.bytes }));
  const link = rows.find(row => row.name === 'source/link'); assert.equal(link.file, true); assert.equal(link.link, false); assert.equal(link.data, hex('../outside'));
  assert.equal(rows.find(row => row.name === 'source/vendor').dir, true);
  assert.equal(rows.find(row => row.name === 'source/src/main.rs').mode, 0o644);
  assert.equal(rows.find(row => row.name === 'source').mode, 0o755);
  assert.ok(rows.every(row => row.dir || row.file));
});
test('archive is deterministic across capture traversal and input property order', () => {
  const c = capture(), first = buildSourceArchive(c, 'portable'); c.trees.reverse(); c.files.reverse();
  c.selection = Object.fromEntries(Object.entries(c.selection).reverse()); c.commit = Object.fromEntries(Object.entries(c.commit).reverse());
  assert.deepEqual(buildSourceArchive(c, 'portable').bytes, first.bytes);
});
test('identical blobs deduplicate only in object layout while both exact paths remain in the manifest', () => {
  const c = capture('sha256', [{ path: 'a', data: Buffer.from('same') }, { path: 'b', data: Buffer.from('same') }]);
  const objects = buildSourceArchive(c, 'objects'), portable = buildSourceArchive(c, 'portable');
  assert.equal(segments(objects.bytes).length, 3); assert.equal(segments(portable.bytes).length, 4);
  assert.equal(inspectSourceArchive(objects.bytes, objects.receipt.archive_sha256).files, 2);
  assert.equal(JSON.parse(segments(objects.bytes)[0].bytes.subarray(512, 512 + segments(objects.bytes)[0].size)).files.length, 2);
});
for (const definitions of [[], [{ path: 'empty', data: Buffer.alloc(0) }], [{ path: 'empty-dir', kind: 'directory' }]]) {
  test(`empty source material remains a verified complete archive: ${definitions.length}`, () => {
    const output = buildSourceArchive(capture('sha1', definitions), 'portable');
    assert.equal(inspectSourceArchive(output.bytes, output.receipt.archive_sha256).source_bytes, 0);
  });
}
for (const path of [Buffer.from([255]), '.git/config', 'DIR/.GiT/HEAD', '.hg/hgrc', 'con.txt', 'aux', 'CLOCK$', 'CONIN$', 'CONOUT$', 'a:b', 'a\\b', 'trailing.', 'trailing ', 'line\nbreak', 'git~1/config', 'long'.repeat(50)]) {
  test(`objects layout losslessly retains a path refused by portable layout: ${hex(path)}`, () => {
    const c = capture('sha1', [{ path, data: Buffer.from('bytes') }]);
    assert.throws(() => buildSourceArchive(c, 'portable'));
    const output = buildSourceArchive(c, 'objects'); assert.equal(inspectSourceArchive(output.bytes, output.receipt.archive_sha256).files, 1);
    const first = segments(output.bytes)[0], manifest = JSON.parse(first.bytes.subarray(512, 512 + first.size));
    assert.equal(manifest.files[0].path_hex, hex(path)); assert.match(manifest.files[0].member, /^payloads\/sha1-[0-9a-f]{40}\.blob$/);
  });
}
test('case collisions refuse the portable profile instead of silently replacing a file', () => {
  const c = capture('sha1', [{ path: 'a', data: Buffer.from('a') }, { path: 'A', data: Buffer.from('A') }]);
  assert.throws(() => buildSourceArchive(c, 'portable'), /colliding/);
  const archive = buildSourceArchive(c, 'objects'); assert.equal(inspectSourceArchive(archive.bytes, archive.receipt.archive_sha256).files, 2);
});
test('ustar prefix supports bounded long paths without PAX or GNU name overrides', () => {
  const path = `${'dir'.repeat(30)}/${'file'.repeat(20)}`, c = capture('sha1', [{ path, data: Buffer.from('content') }]);
  const output = buildSourceArchive(c, 'portable'); assert.equal(inspectSourceArchive(output.bytes, output.receipt.archive_sha256).files, 1);
  const names = execFileSync('python3', ['-c', 'import tarfile,io,sys; print("\\n".join(tarfile.open(fileobj=io.BytesIO(sys.stdin.buffer.read())).getnames()))'], { input: output.bytes }).toString();
  assert.ok(names.includes(`source/${path}`));
});
test('independent archive hash is mandatory and checked before accepting the embedded proof', () => {
  const output = buildSourceArchive(capture(), 'portable');
  for (const hash of [null, '', 'f'.repeat(64), output.receipt.archive_sha256.toUpperCase()]) assert.throws(() => inspectSourceArchive(output.bytes, hash));
});
test('file corruption is detected even when the transport/archive hash is recomputed', () => {
  const output = buildSourceArchive(capture(), 'portable'), bytes = Buffer.from(output.bytes), member = segments(bytes).find(row => row.name === 'source/README.md');
  bytes[member.start + 512] ^= 1;
  assert.throws(() => inspectSourceArchive(bytes, sha256(bytes)), /payload/);
});
for (const [label, work] of [
  ['authority claim', m => m.claims.authority_signatures_verified = true], ['file omission', m => m.files.pop()],
  ['unreachable body', m => m.trees.push(m.trees[0])], ['tree proof', m => m.trees[0].body_hex += '00'],
  ['different filename', m => m.files[0].member = 'source/elsewhere'], ['unknown field', m => m.extra = true],
  ['submodule hydration', m => m.claims.submodules_hydrated = true], ['missing gitlink', m => m.gitlinks = []],
]) test(`a self-rehashed manifest cannot introduce ${label}`, () => {
  const output = buildSourceArchive(capture(), 'portable'), changed = alterManifest(output.bytes, work);
  assert.throws(() => inspectSourceArchive(changed, sha256(changed)));
});
for (const [label, work] of [
  ['symlink', h => h[156] = 50], ['hardlink', h => h[156] = 49], ['executable', h => h.write('0000755\0', 100)],
  ['traversal', h => { h.fill(0, 0, 100); h.write('../outside', 0); }], ['owner', h => h.write('0000001\0', 108)],
  ['extended header', h => h[156] = 120], ['unchecked trailing name bytes', h => h[99] = 65],
]) test(`foreign tar ${label} semantics are rejected without extraction`, () => {
  const output = buildSourceArchive(capture(), 'portable'), bytes = Buffer.from(output.bytes), row = segments(bytes).find(r => r.name === 'source/README.md');
  const h = bytes.subarray(row.start, row.start + 512); work(h); checksum(h);
  assert.throws(() => inspectSourceArchive(bytes, sha256(bytes)));
});
test('duplicates, reordered members, nonzero padding, truncated and extended trailers refuse', () => {
  const output = buildSourceArchive(capture(), 'portable'), rows = segments(output.bytes), trailer = Buffer.alloc(1024);
  const duplicate = Buffer.concat([...rows.map(r => r.bytes), rows[1].bytes, trailer]);
  const reordered = Buffer.concat([rows[0].bytes, ...rows.slice(1).reverse().map(r => r.bytes), trailer]);
  const padding = Buffer.from(output.bytes); padding[rows[0].start + 512 + rows[0].size] = 1;
  for (const bytes of [duplicate, reordered, padding, output.bytes.subarray(0, output.bytes.length - 512), Buffer.concat([output.bytes, Buffer.alloc(512)])]) {
    assert.throws(() => inspectSourceArchive(bytes, sha256(bytes)));
  }
});
test('one full native maximum-sized blob exports and verifies without range-size widening', () => {
  const c = capture('sha256', [{ path: 'maximum.bin', data: Buffer.alloc(16 * 1024 * 1024, 255) }]);
  const output = buildSourceArchive(c, 'portable');
  assert.equal(inspectSourceArchive(output.bytes, output.receipt.archive_sha256).source_bytes, 16 * 1024 * 1024);
});
test('invalid layout, traversal and oversized input refuse before output', () => {
  assert.throws(() => buildSourceArchive(capture(), 'links'));
  for (const path of ['', '../a', '/a', 'a//b']) assert.throws(() => portablePath(hex(path)));
  assert.throws(() => inspectSourceArchive(Buffer.alloc(TAR_LIMIT + 1), 'a'.repeat(64)), /mismatch/);
});
