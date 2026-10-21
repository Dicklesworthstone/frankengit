// Deterministic Git literal members. Stored DEFLATE blocks need no compression
// engine, subprocess or native library. Not a decoder, delta selector or packer.
import { fail, integer } from './source_edit_wire.mjs';
const MAX_FILE_BYTES = 1048576, BLOCK_BYTES = 65535, ROW_BYTES = 52;
const BASE85 = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!#$%&()*+-;<=>?@^_`{|}~';

// Exact wire/record cost before allocating a framed body. Include the empty
// stored block, zlib header, Adler-32, length prefixes, padding and blank line.
export function binaryLiteralCost(length) {
  integer(length, 0, MAX_FILE_BYTES);
  const framed = length + 6 + 5 * Math.max(1, Math.ceil(length / BLOCK_BYTES));
  const full = Math.floor(framed / ROW_BYTES), tail = framed % ROW_BYTES;
  return { framed_bytes: framed,
    bytes: 9 + String(length).length + full * 67 + (tail ? 2 + Math.ceil(tail / 4) * 5 : 0) + 1,
    records: 2 + Math.ceil(framed / ROW_BYTES) };
}
function frame(bytes, check) {
  const output = Buffer.alloc(binaryLiteralCost(bytes.length).framed_bytes);
  output[0] = 0x78; output[1] = 0x01; // DEFLATE, 32 KiB window, no dictionary.
  let at = 2, source = 0, a = 1, b = 0;
  do {
    check(); const size = Math.min(BLOCK_BYTES, bytes.length - source);
    output[at++] = Number(source + size === bytes.length); // BFINAL, BTYPE=stored.
    output.writeUInt16LE(size, at); output.writeUInt16LE(size ^ 0xffff, at + 2); at += 4;
    bytes.copy(output, at, source, source + size); at += size;
    for (let end = source + size; source < end;) {
      check(); const until = Math.min(end, source + 4096);
      for (; source < until; source++) { a += bytes[source]; b += a; }
      a %= 65521; b %= 65521;
    }
  } while (source < bytes.length);
  output.writeUInt32BE(b * 65536 + a, at); check();
  return output;
}
// Caller reserves BOTH complete members against the shared patch budget first.
// Each emitted value is exactly one ASCII line, including its terminating LF.
export function emitBinaryLiteral(bytes, put, check) {
  if (!Buffer.isBuffer(bytes) || bytes.length > MAX_FILE_BYTES ||
      typeof put !== 'function' || typeof check !== 'function') fail('source_replacement_binary_input');
  check(); const encoded = frame(bytes, check);
  put(`literal ${bytes.length}\n`);
  for (let start = 0; start < encoded.length; start += ROW_BYTES) {
    check(); const length = Math.min(ROW_BYTES, encoded.length - start), end = start + length;
    let line = String.fromCharCode(length <= 26 ? 64 + length : 70 + length);
    for (let offset = start; offset < end; offset += 4) {
      let value = 0;
      for (let i = 0; i < 4; i++) value = value * 256 + (offset + i < end ? encoded[offset + i] : 0);
      let digits = '';
      for (let i = 0; i < 5; i++) { digits = BASE85[value % 85] + digits; value = Math.floor(value / 85); }
      line += digits;
    }
    put(line + '\n');
  }
  put('\n'); check();
}
