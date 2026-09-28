// Independent native Git encoders for signed-workflow tests. Node's zlib is a
// fixture producer only; all verification/recovery uses the production modules.
import { createHash, generateKeyPairSync } from 'node:crypto';
import { deflateSync } from 'node:zlib';
import { mkdtemp, writeFile, rm, lstat, readdir, readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { signSourceBackup } from '../../scripts/lib/source-attestation.mjs';
export const root = resolve(fileURLToPath(new URL('../../', import.meta.url)));
export const repository = 'signed-test/source', sequence = '42';
export const headHex = Buffer.from('refs/heads/main').toString('hex');
const identity = 'Backup Test <backup@example.invalid> 1700000000 +0000';
export const hash = (body, format = 'sha256') => createHash(format).update(body).digest();
function packSize(value, type) {
  const bytes = []; let byte = (type << 4) | (value % 16); value = Math.floor(value / 16);
  while (value) { bytes.push(byte | 128); byte = value % 128; value = Math.floor(value / 128); }
  bytes.push(byte); return Buffer.from(bytes);
}
export function nativeBundle(format = 'sha1', { large = false, missing = null, branch = Buffer.from('refs/heads/main') } = {}) {
  const objects = [], byName = {}, ids = {};
  const add = (name, kind, body) => {
    body = Buffer.from(body); const id = hash(Buffer.concat([Buffer.from(`${kind} ${body.length}\0`), body]), format).toString('hex');
    const row = { name, kind, body, id }; objects.push(row); byName[name] = row; ids[name] = id; return id;
  };
  const binary = Buffer.alloc(large ? 192 * 1024 : 19); let state = 0x2468ace1;
  for (let at = 0; at < binary.length; at++) { state ^= state << 13; state ^= state >>> 17; state ^= state << 5; binary[at] = state & 255; }
  binary[0] = 0; binary[1] = 255;
  add('binary', 'blob', binary); add('text', 'blob', '# Source backup\r\nUnicode: 🦀\n'); add('link', 'blob', 'binary.dat');
  const tree = Buffer.concat([['100644', 'binary.dat', ids.binary], ['120000', 'link', ids.link], ['100644', 'text.txt', ids.text]].map(([mode, name, id]) =>
    Buffer.concat([Buffer.from(`${mode} ${name}\0`), Buffer.from(id, 'hex')])));
  add('tree', 'tree', tree);
  const commit = (parents, message) => `tree ${ids.tree}\n${parents.map(id => `parent ${id}\n`).join('')}author ${identity}\ncommitter ${identity}\n\n${message}\n`;
  add('parent', 'commit', commit([], 'Original')); add('tip', 'commit', commit([ids.parent], 'Backed up'));
  add('tag', 'tag', `object ${ids.tip}\ntype commit\ntag release\ntagger ${identity}\n\nSigned-source fixture\n`);
  const selected = objects.filter(row => row.name !== missing), header = Buffer.alloc(12);
  header.write('PACK'); header.writeUInt32BE(2, 4); header.writeUInt32BE(selected.length, 8);
  const packed = Buffer.concat([header, ...selected.map(row => Buffer.concat([packSize(row.body.length, { commit: 1, tree: 2, blob: 3, tag: 4 }[row.kind]), deflateSync(row.body, { level: 0 })]))]);
  const bundle = Buffer.concat([Buffer.from(format === 'sha1' ? '# v2 git bundle\n' : '# v3 git bundle\n@object-format=sha256\n'),
    Buffer.from(`${ids.tip} `), branch, Buffer.from(`\n${ids.tag} refs/tags/release\n\n`), packed, hash(packed, format)]);
  return { bundle, ids, byName, objects, format, branch, sha256: hash(bundle).toString('hex') };
}
export async function withSignedFixture(work, format = 'sha1', bundleOptions = {}) {
  const directory = await mkdtemp(join(tmpdir(), 'fg-signed-flow-')), keys = generateKeyPairSync('ed25519');
  const native = nativeBundle(format, bundleOptions), input = join(directory, 'source.bundle'), envelope = join(directory, 'source.dsse.json'),
    privateKey = join(directory, 'private.pem'), publicKey = join(directory, 'public.pem'), destination = join(directory, 'recovered.git');
  const privatePem = Buffer.from(keys.privateKey.export({ format: 'pem', type: 'pkcs8' }));
  const publicPem = Buffer.from(keys.publicKey.export({ format: 'pem', type: 'spki' }));
  await writeFile(input, native.bundle, { mode: 0o600 }); await writeFile(privateKey, privatePem, { mode: 0o600 }); await writeFile(publicKey, publicPem);
  const f = { ...native, directory, input, envelope, privateKey, publicKey, privatePem, publicPem, destination,
    authArgs: ['--attestation', envelope, '--trust-key', publicKey, '--repository', repository, '--minimum-sequence', sequence],
    async resign(metadata = {}, options = {}) {
      const signed = await signSourceBackup(await readFile(input), privatePem, { repository, sequence, ...metadata }, options);
      await writeFile(envelope, signed.envelope); return signed;
    },
  };
  await f.resign();
  try { return await work(f); }
  finally { privatePem.fill(0); await rm(directory, { recursive: true, force: true }); }
}
export function cli(script, args, options = {}) {
  return spawnSync(process.execPath, [join(root, 'scripts', script), ...args], {
    encoding: 'utf8', timeout: 15000, env: { ...process.env, PATH: '/nonexistent' }, ...options,
  });
}
export function git(f, args) {
  const env = Object.fromEntries(Object.entries(process.env).filter(([key]) => !key.startsWith('GIT_')));
  Object.assign(env, { HOME: f.directory, XDG_CONFIG_HOME: f.directory, GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: '/dev/null', GIT_TERMINAL_PROMPT: '0' });
  return spawnSync('git', args, { timeout: 15000, env });
}
export async function absent(path) { try { await lstat(path); return false; } catch (error) { if (error.code === 'ENOENT') return true; throw error; } }
// Read-only comparisons ignore atime: reads may update it. Content, inode,
// permissions, links and all write-change timestamps must remain unchanged.
export async function treeSnapshot(path) {
  const result = {};
  async function visit(relative) {
    const file = relative ? join(path, relative) : path, stat = await lstat(file, { bigint: true });
    result[relative] = Object.fromEntries(['dev', 'ino', 'mode', 'nlink', 'size', 'mtimeNs', 'ctimeNs'].map(key => [key, String(stat[key])]));
    if (stat.isDirectory()) for (const name of (await readdir(file)).sort()) await visit(relative ? `${relative}/${name}` : name);
    else if (stat.isFile()) result[relative].sha256 = hash(await readFile(file)).toString('hex');
  }
  await visit(''); return result;
}
