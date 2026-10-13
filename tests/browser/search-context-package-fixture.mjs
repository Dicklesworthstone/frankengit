// Independent Git-byte fixtures; no native Rust server or search index is run.
import { fixture, repository, hex, token } from '../operator/fixtures/source_archive_native.mjs';
import { Transport } from '../../crates/fgit-node/src/smart_http/server/browser/pulls-core.mjs';
import { webcrypto } from 'node:crypto';
export { repository, hex, token, webcrypto };
export const definitions = [
  { path: 'alpha', data: Buffer.from('recover\n\0\xff') },
  { path: 'src/main.rs', kind: 'executable', data: Buffer.from('pub fn recover() {}\r\n') },
  { path: 'unused/secret', data: Buffer.from('not selected') },
];
export function basis(repo, paths = ['alpha', 'src/main.rs'].map(hex)) {
  const files = paths.slice().sort().map(pathHex => ({ pathHex, blob: repo.files.get(pathHex).id,
    sourceBytes: repo.files.get(pathHex).data.length }));
  return { query: { mode: 'initial', maxFileBytes: 8388608 },
    scope: { tenant: repo.scope.tenant_id, repository: repo.scope.repository_id, incarnation: repo.scope.repository_incarnation, format: repo.format },
    pin: { head: repo.snapshot, sourceHead: repo.common.source_head, rcr: 'fixture-rcr', commit: repo.commit, tree: repo.root.id },
    vector: { lexical: { token: `alg:2:${'e'.repeat(64)}`, number: 1 }, symbols: null }, context: { files } };
}
export function expectedFor(repo, paths) {
  return { format: repo.format, commit: repo.commit,
    files: basis(repo, paths).context.files.map(({ pathHex, blob }) => ({ pathHex, blob })) };
}
export function packageFor(repo, paths) {
  const expected = expectedFor(repo, paths), dirs = new Set([null]), blobs = new Map();
  for (const file of expected.files) {
    const path = Buffer.from(file.pathHex, 'hex');
    for (let i = 0; i < path.length; i++) if (path[i] === 47) dirs.add(hex(path.subarray(0, i)));
    blobs.set(file.blob, hex(repo.files.get(file.pathHex).data));
  }
  return { schema: 'frankengit-selected-source-package-v1', membership: {
    schema: 'frankengit-context-membership-proof-v1', objectFormat: repo.format,
    commit: { oid: repo.commit, bodyHex: hex(repo.body) },
    trees: [...dirs].map(pathHex => ({ pathHex, oid: repo.dirs.get(pathHex).id, bodyHex: hex(repo.dirs.get(pathHex).body) })),
    files: expected.files.map(file => ({ ...file, kind: repo.files.get(file.pathHex).kind })) },
    blobs: [...blobs].sort(([a], [b]) => a < b ? -1 : 1).map(([oid, bytesHex]) => ({ oid, bytesHex })) };
}
export async function online(t, options = {}) {
  const f = await fixture(t, { definitions, ...options });
  const transport = new Transport({ href: `${f.selection.endpoint}/ui/search/`, pageSuffix: '/ui/search/', cryptoImpl: webcrypto, timeoutMs: options.timeoutMs ?? 30000 });
  await transport.connect(token); t.after(() => transport.disconnect());
  return { ...f, transport, result: basis(f.repo, options.paths),
    request: (path, options) => transport.request(path, options), expected: expectedFor(f.repo, options.paths) };
}
