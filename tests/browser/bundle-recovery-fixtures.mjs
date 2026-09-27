// Native object encoders and installed-Git observations, not native fg E2E.
import { mkdtempSync, rmSync, mkdirSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { bytes, objectId, bundle, literalDelta, webcrypto } from './bundle-verify-fixtures.mjs';
export { bytes, objectId, bundle, webcrypto };
export const main = Buffer.from('refs/heads/main').toString('hex');
export function fixture(format = 'sha1', delta = null) {
  const old = bytes('before\n'), content = bytes([0, 255, 13, 10, 128, 10]), link = bytes('../not-followed');
  const id = (kind, body) => objectId(kind, body, format);
  const tree = Buffer.concat([bytes('100755 executable\0'), Buffer.from(id('blob', content), 'hex'),
    bytes('120000 link\0'), Buffer.from(id('blob', link), 'hex')]);
  const author = 'A <a@example.invalid> 1700000000 +0000';
  const parent = bytes(`tree ${id('tree', tree)}\nauthor ${author}\ncommitter ${author}\n\nparent\n`);
  const commit = bytes(`tree ${id('tree', tree)}\nparent ${id('commit', parent)}\nauthor ${author}\ncommitter ${author}\n\nmessage\n`);
  const tag = bytes(`object ${id('commit', commit)}\ntype commit\ntag release\n\nannotation\n`);
  const records = delta === null ? [{ kind: 'blob', body: content }] :
    [{ kind: 'blob', body: old }, { type: delta, base: 0, baseId: id('blob', old), body: literalDelta(old, content) }];
  records.push({ kind: 'blob', body: link }, { kind: 'tree', body: tree }, { kind: 'commit', body: parent },
    { kind: 'commit', body: commit }, { kind: 'tag', body: tag });
  const refs = [{ name: 'refs/heads/main', id: id('commit', commit) }, { name: 'refs/tags/release', id: id('tag', tag) }];
  return { format, records, refs, content, link, tip: refs[0].id, tag: refs[1].id, input: bundle(records, format, { refs }),
    request: { head_ref_hex: main, expectations: { object_format: format, refs: [{ ref_hex: main, object_id: refs[0].id }] } } };
}
export async function withTemp(work) {
  const root = mkdtempSync(join(tmpdir(), 'fg-source-recovery-')); mkdirSync(join(root, 'home'));
  try { return await work(root); } finally { rmSync(root, { recursive: true, force: true }); }
}
export function git(root, args, options = {}) {
  const env = { ...process.env, HOME: join(root, 'home'), XDG_CONFIG_HOME: join(root, 'home'), GIT_CONFIG_NOSYSTEM: '1',
    GIT_CONFIG_GLOBAL: '/dev/null', GIT_NO_REPLACE_OBJECTS: '1', LC_ALL: 'C' };
  for (const key of Object.keys(env)) if (key.startsWith('GIT_') && !['GIT_CONFIG_NOSYSTEM', 'GIT_CONFIG_GLOBAL', 'GIT_NO_REPLACE_OBJECTS'].includes(key)) delete env[key];
  return execFileSync('git', args, { env, timeout: 10000, maxBuffer: 16 * 1024 * 1024, ...options });
}
