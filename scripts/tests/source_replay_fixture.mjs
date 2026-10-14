// Independent native object framing; no source-replay implementation is used to
// construct either base. The existing Git peer tests the resulting patch later.
import { changeFixture, hexPath, objectId } from './source_changes_fixture.mjs';
export function selectSource(f, paths) {
  const wanted = new Set(paths.map(hexPath)), directories = new Set([null]);
  for (const path of wanted) {
    const bytes = Buffer.from(path, 'hex');
    for (let i = 0; i < bytes.length; i++) if (bytes[i] === 47) directories.add(bytes.subarray(0, i).toString('hex'));
  }
  const value = structuredClone(f.value), expected = structuredClone(f.expected);
  expected.files = expected.files.filter(row => wanted.has(row.pathHex));
  value.membership.files = value.membership.files.filter(row => wanted.has(row.pathHex));
  value.membership.trees = value.membership.trees.filter(row => directories.has(row.pathHex));
  const blobs = new Set(expected.files.map(row => row.blob)); value.blobs = value.blobs.filter(row => blobs.has(row.oid));
  return { ...f, value, expected, bytes: Buffer.from(JSON.stringify(value)) };
}
export function withParent(f, parent, message = 'new independent base') {
  const value = structuredClone(f.value), expected = structuredClone(f.expected);
  const body = Buffer.from(`tree ${f.tree}\n${parent ? `parent ${parent}\n` : ''}author Test <test@example.invalid> 2 +0000\ncommitter Test <test@example.invalid> 2 +0000\n\n${message}\n`);
  const commit = objectId('commit', body, f.format); value.membership.commit = { oid: commit, bodyHex: body.toString('hex') }; expected.commit = commit;
  return { ...f, commit, value, expected, bytes: Buffer.from(JSON.stringify(value)) };
}
export function replayPair(format = 'sha1', selected = ['src/file', 'run.sh', 'empty']) {
  const shared = [{ path: 'src/file', bytes: 'alpha\nbeta\n' }, { path: 'run.sh', bytes: '#!/bin/sh\necho old\n', mode: 0o100755 },
    { path: 'empty', bytes: '' }];
  const before = [...shared, { path: 'README', bytes: 'before\n' }, { path: 'src/sibling', bytes: 'old sibling\n' }];
  const after = [...shared, { path: 'README', bytes: 'concurrent README\n' }, { path: 'src/sibling', bytes: 'new sibling\n' },
    { path: 'opaque/new', bytes: 'other agent\n' }];
  const old = selectSource(changeFixture(format, before), selected);
  const next = selectSource(withParent(changeFixture(format, after), old.commit), selected);
  return { old, next, before, after, selected };
}
