// Independently framed commit/tree/blob test data, not a native server or an
// authority receipt. The Git oracle tests separately check the entire tree.
import { createHash } from 'node:crypto';
export const hexPath = value => Buffer.from(value).toString('hex');
export const objectId = (kind, bytes, format) => createHash(format).update(`${kind} ${bytes.length}\0`).update(bytes).digest('hex');
export function changeFixture(format = 'sha1', input = [
  { path: 'src/main.rs', bytes: 'fn main() { old(); }\n', mode: 0o100644 },
  { path: 'run.sh', bytes: '#!/bin/sh\necho old\n', mode: 0o100755 },
  { path: 'empty.txt', bytes: '', mode: 0o100644 },
]) {
  const files = input.map(row => ({ path: Buffer.from(row.path), bytes: Buffer.from(row.bytes), mode: row.mode ?? 0o100644 }))
    .sort((a, b) => Buffer.compare(a.path, b.path));
  const root = new Map(), blobs = new Map();
  for (const file of files) {
    file.id = objectId('blob', file.bytes, format); blobs.set(file.id, file.bytes);
    const parts = []; let start = 0;
    for (let end = 0; end <= file.path.length; end++) if (end === file.path.length || file.path[end] === 47) {
      parts.push(file.path.subarray(start, end).toString('hex')); start = end + 1;
    }
    let tree = root;
    for (const part of parts.slice(0, -1)) { if (!tree.has(part)) tree.set(part, new Map()); tree = tree.get(part); }
    tree.set(parts.at(-1), file);
  }
  const trees = [];
  function frame(node, pathHex) {
    const rows = [...node].map(([name, value]) => {
      const directory = value instanceof Map;
      const id = directory ? frame(value, pathHex === null ? name : `${pathHex}2f${name}`) : value.id;
      const bytes = Buffer.from(name, 'hex');
      return { bytes, id, mode: directory ? '40000' : value.mode.toString(8),
        key: Buffer.concat([bytes, Buffer.from(directory ? '/' : '\0')]) };
    }).sort((a, b) => Buffer.compare(a.key, b.key));
    const body = Buffer.concat(rows.map(row => Buffer.concat([Buffer.from(`${row.mode} `), row.bytes, Buffer.from([0]), Buffer.from(row.id, 'hex')])));
    const id = objectId('tree', body, format); trees.push({ pathHex, oid: id, bodyHex: body.toString('hex') }); return id;
  }
  const tree = frame(root, null), body = Buffer.from(`tree ${tree}\nauthor Test <test@example.invalid> 1 +0000\ncommitter Test <test@example.invalid> 1 +0000\n\nsource fixture\n`);
  const commit = objectId('commit', body, format);
  const selected = files.map(file => ({ pathHex: file.path.toString('hex'), blob: file.id }));
  const expected = { format, commit, files: selected };
  const value = { schema: 'frankengit-selected-source-package-v1', membership: {
    schema: 'frankengit-context-membership-proof-v1', objectFormat: format, commit: { oid: commit, bodyHex: body.toString('hex') },
    trees, files: selected.map((file, i) => ({ ...file, kind: files[i].mode === 0o100755 ? 'executable' : 'file' })) },
    blobs: [...blobs].sort(([a], [b]) => a < b ? -1 : 1).map(([oid, bytes]) => ({ oid, bytesHex: bytes.toString('hex') })) };
  return { bytes: Buffer.from(JSON.stringify(value)), value, expected, files, tree, commit, format };
}
export const intent = changes => ({ schema: 'frankengit-source-changes-v1', changes });
export const replace = (path, text, extra = {}) => ({ path_hex: hexPath(path), operation: 'replace', content_utf8: text, ...extra });
