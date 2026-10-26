// A larger native PACK/idx pair built from the independent recovery goldens.
// The added blob is intentionally unreferenced; original history/refs stay intact.
// The harness still uses a FAKE fg: these fixtures test materialization and
// bounded I/O, not execution of Rust object verification or index construction.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdir, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { deflateSync } from 'node:zlib';
import { harness, readFixture } from './native-recovery-harness.mjs';

const checksum = (format, bytes) => createHash(format).update(bytes).digest();
const crcTable = Uint32Array.from({ length: 256 }, (_, value) => {
  for (let bit = 0; bit < 8; bit++) value = value & 1 ? 0xedb88320 ^ (value >>> 1) : value >>> 1;
  return value >>> 0;
});
function crc32(bytes) {
  let value = 0xffffffff;
  for (const byte of bytes) value = crcTable[(value ^ byte) & 255] ^ (value >>> 8);
  return (value ^ 0xffffffff) >>> 0;
}
function blobHeader(length) {
  const bytes = [];
  let byte = 0x30 | (length % 16);
  length = Math.floor(length / 16);
  while (length) { bytes.push(byte | 0x80); byte = length % 128; length = Math.floor(length / 128); }
  bytes.push(byte); return Buffer.from(bytes);
}

export async function makeLargeRecoveryHarness(t, { bytes = 192 * 1024 + 17, format = 'sha1' } = {}) {
  assert.ok(Number.isSafeInteger(bytes) && bytes > 0 && bytes <= 32 * 1024 * 1024);
  const h = await harness(t, format), width = format === 'sha1' ? 20 : 32;
  const packOffset = h.bytes.indexOf(Buffer.from('\n\n')) + 2;
  assert.ok(packOffset > 1);
  const originalPack = h.bytes.subarray(packOffset), originalIndex = await readFixture(format, 'idx');
  assert.equal(originalPack.subarray(0, 4).toString(), 'PACK');
  assert.equal(originalIndex.readUInt32BE(0), 0xff744f63);
  assert.equal(originalIndex.readUInt32BE(4), 2);
  const count = originalPack.readUInt32BE(8), namesAt = 8 + 256 * 4;
  assert.equal(originalIndex.readUInt32BE(8 + 255 * 4), count);
  const crcsAt = namesAt + count * width, offsetsAt = crcsAt + count * 4;
  // These small independent goldens have no 64-bit offset table.
  assert.equal(originalIndex.length, offsetsAt + count * 4 + 2 * width);
  const entries = Array.from({ length: count }, (_, at) => ({
    id: originalIndex.subarray(namesAt + at * width, namesAt + (at + 1) * width),
    crc: originalIndex.readUInt32BE(crcsAt + at * 4),
    offset: originalIndex.readUInt32BE(offsetsAt + at * 4),
  }));
  assert.ok(entries.every(entry => entry.offset < 0x80000000));
  const body = Buffer.alloc(bytes, 0x78);
  // Stored DEFLATE keeps the bundle itself above the selected size threshold.
  const encoded = Buffer.concat([blobHeader(body.length), deflateSync(body, { level: 0 })]);
  const id = createHash(format).update(`blob ${body.length}\0`).update(body).digest();
  assert.ok(entries.every(entry => !entry.id.equals(id)));
  entries.push({ id, crc: crc32(encoded), offset: originalPack.length - width });
  entries.sort((left, right) => Buffer.compare(left.id, right.id));
  const packBody = Buffer.concat([originalPack.subarray(0, -width), encoded]);
  packBody.writeUInt32BE(count + 1, 8);
  const packChecksum = checksum(format, packBody), pack = Buffer.concat([packBody, packChecksum]);
  const indexBody = Buffer.alloc(namesAt + entries.length * (width + 8));
  indexBody.writeUInt32BE(0xff744f63, 0); indexBody.writeUInt32BE(2, 4);
  const fanout = new Uint32Array(256);
  for (const entry of entries) fanout[entry.id[0]]++;
  for (let at = 0, total = 0; at < 256; at++) { total += fanout[at]; indexBody.writeUInt32BE(total, 8 + at * 4); }
  const newCrcsAt = namesAt + entries.length * width, newOffsetsAt = newCrcsAt + entries.length * 4;
  for (const [at, entry] of entries.entries()) {
    entry.id.copy(indexBody, namesAt + at * width);
    indexBody.writeUInt32BE(entry.crc, newCrcsAt + at * 4);
    indexBody.writeUInt32BE(entry.offset, newOffsetsAt + at * 4);
  }
  const indexWithPack = Buffer.concat([indexBody, packChecksum]);
  const index = Buffer.concat([indexWithPack, checksum(format, indexWithPack)]);
  const bundle = Buffer.concat([h.bytes.subarray(0, packOffset), pack]);
  const fixtures = join(h.root, 'large-fixtures'); await mkdir(fixtures, { mode: 0o700 });
  await writeFile(join(fixtures, `${format}.bundle.hex`), bundle.toString('hex') + '\n');
  await writeFile(join(fixtures, `${format}.idx${format === 'sha256' ? '.zlib' : ''}.hex`),
    (format === 'sha256' ? deflateSync(index) : index).toString('hex') + '\n');
  await h.configure({ fixtures, report: { object_count: count + 1, payload_bytes: bytes + 512 } });
  const input = join(h.root, 'input.bundle'); await writeFile(input, bundle);
  return { ...h, input, bytes: bundle, expected_pack: pack, expected_index: index, pack_offset: packOffset };
}
