// Independent test encoders. Native zlib and Git are test oracles only; neither
// is imported or invoked by the production verifier or its offline command.
import { createHash, webcrypto } from 'node:crypto';
import { deflateSync, constants } from 'node:zlib';
export { webcrypto, constants };
export const bytes = value => Buffer.isBuffer(value) ? value : Buffer.from(value);
export const hash = (value, format = 'sha1') => createHash(format).update(value).digest();
export const objectId = (kind, body, format = 'sha1') => hash(Buffer.concat([Buffer.from(`${kind} ${body.length}\0`), bytes(body)]), format).toString('hex');
export function size(value, type = null) {
  const out = []; let first = type === null ? value % 128 : (type << 4) | (value % 16);
  value = Math.floor(value / (type === null ? 128 : 16));
  while (value) { out.push(first | 128); first = value % 128; value = Math.floor(value / 128); }
  out.push(first); return Buffer.from(out);
}
export function offset(value) {
  const out = [value & 127];
  while ((value = Math.floor(value / 128))) out.unshift((--value & 127) | 128);
  return Buffer.from(out);
}
export function literalDelta(base, result) {
  const chunks = [size(base.length), size(result.length)];
  for (let at = 0; at < result.length; at += 127) { const part = result.subarray(at, at + 127); chunks.push(Buffer.from([part.length]), part); }
  return Buffer.concat(chunks);
}
export function pack(records, format = 'sha1', { count = records.length, tail = Buffer.alloc(0) } = {}) {
  const chunks = [Buffer.from('PACK'), Buffer.from([0, 0, 0, 2]), Buffer.alloc(4)], offsets = [];
  chunks[2].writeUInt32BE(count); let at = 12;
  for (const row of records) {
    offsets.push(at);
    const body = bytes(row.body), type = row.type ?? { commit: 1, tree: 2, blob: 3, tag: 4 }[row.kind ?? 'blob'];
    const reference = type === 6 ? offset(at - offsets[row.base]) : type === 7 ? Buffer.from(row.baseId, 'hex') : Buffer.alloc(0);
    const encoded = Buffer.concat([size(row.declared ?? body.length, type), row.reference ?? reference, row.zlib ?? deflateSync(body, row.compression)]);
    chunks.push(encoded); at += encoded.length;
  }
  chunks.push(tail); const body = Buffer.concat(chunks); return Buffer.concat([body, hash(body, format)]);
}
export function bundle(records, format = 'sha1', options = {}) {
  const refs = options.refs ?? [{ name: Buffer.from('refs/tags/test'), id: objectId('blob', records[0].body, format) }];
  const header = options.header ?? Buffer.concat([
    Buffer.from(format === 'sha1' ? '# v2 git bundle\n' : '# v3 git bundle\n@object-format=sha256\n'),
    ...refs.map(row => Buffer.concat([Buffer.from(`${row.id} `), bytes(row.name), Buffer.from('\n')])), Buffer.from('\n'),
  ]);
  return Buffer.concat([header, options.pack ?? pack(records, format, options)]);
}
export const rewriteTrailer = (input, format = 'sha1') => Buffer.concat([input.subarray(0, -(format === 'sha1' ? 20 : 32)), hash(input.subarray(0, -(format === 'sha1' ? 20 : 32)), format)]);
