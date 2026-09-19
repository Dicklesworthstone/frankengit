import { webcrypto, createHash } from 'node:crypto';
import { deflateSync } from 'node:zlib';
export const crypto = webcrypto;
export const base = '../../crates/fgit-node/src/smart_http/server/browser/';
export const token = 'ab'.repeat(32);
export const hash = (format, bytes) => createHash(format).update(bytes).digest('hex');
export const hex = bytes => Buffer.from(bytes).toString('hex');
export const encode = value => Buffer.from(value, 'utf8');
export const head = `alg:1:${'a'.repeat(64)}`;
export const oid = algorithm => 'b'.repeat(algorithm === 'sha1' ? 40 : 64);
export const row = (name, algorithm = 'sha1') => ({ ref: name, ref_hex: hex(encode(name)), object_id: oid(algorithm) });
export function page(algorithm = 'sha1', rows = [row('refs/heads/main', algorithm)], extra = {}) {
  return { type: 'source_refs', schema_version: 1, tenant_id: 'tenant', repository_id: 'repository', repository_incarnation: 'incarnation',
    object_format: algorithm, namespace: 'all', source_head: 'head-object', snapshot_token: head, after: null, limit: 100, next_after: null,
    read_only: true, transaction_created: false, published: false, direct_refs_only: true, refs: rows, ...extra };
}
// Valid framing/checksums with a single compressed blob. The advertised target
// deliberately is not in this pack: unit fixtures do NOT prove object closure.
export function bundle(algorithm = 'sha1', rows = [row('refs/heads/main', algorithm)], options = {}) {
  const width = algorithm === 'sha1' ? 20 : 32;
  const signature = algorithm === 'sha1' ? '# v2 git bundle\n' : '# v3 git bundle\n@object-format=sha256\n';
  const lines = rows.map(row => Buffer.concat([encode(`${row.object_id} `), Buffer.from(row.ref_hex, 'hex'), encode('\n')]));
  if (options.head) lines.unshift(encode(`${options.head} HEAD\n`));
  const header = Buffer.concat([encode(signature), ...(options.lines ?? lines), encode('\n')]);
  const ph = Buffer.alloc(12); ph.write('PACK'); ph.writeUInt32BE(options.version ?? 2, 4); ph.writeUInt32BE(options.objects ?? 1, 8);
  const body = Buffer.concat([ph, Buffer.from([0x33]), deflateSync(Buffer.from('abc'))]);
  const checksum = Buffer.from(hash(algorithm, body), 'hex');
  if (checksum.length !== width) throw new Error('fixture format');
  return new Uint8Array(Buffer.concat([header, body, checksum]));
}
export function headers(bytes, algorithm = 'sha1', extra = {}) {
  return { 'content-type': 'application/x-git-bundle', 'content-length': String(bytes.length),
    'x-fgit-bundle-profile': 'full-v1', 'x-fgit-object-format': algorithm, 'x-fgit-tenant': 'tenant',
    'x-fgit-repository': 'repository', 'x-fgit-repository-incarnation': 'incarnation', 'x-fgit-source-head': 'head-object',
    'x-fgit-snapshot': head, 'x-fgit-artifact-sha256': hash('sha256', bytes), 'x-fgit-read-only': 'true', ...extra };
}
export const json = value => new Response(JSON.stringify(value), { headers: { 'Content-Type': 'application/json' } });
export const binary = (bytes, algorithm = 'sha1', extra = {}) => new Response(bytes, { headers: headers(bytes, algorithm, extra) });
export const options = fetchImpl => ({ href: 'https://forge.invalid/r.git/ui/export/', fetchImpl, cryptoImpl: crypto });
export function deferred() { let resolve, reject; const promise = new Promise((a, b) => { resolve = a; reject = b; }); return { promise, resolve, reject }; }
