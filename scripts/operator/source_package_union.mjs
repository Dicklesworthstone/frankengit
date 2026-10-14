// Combine explicitly selected immutable source, never infer scope from a package.
// The existing verifier owns native parsing, membership, hashes and union limits.
import { webcrypto } from 'node:crypto';
import { readSourcePackage, encodeSourcePackage, SOURCE_PACKAGE_BYTES } from '../../crates/fgit-node/src/smart_http/server/browser/search-context-package.mjs';
import { pathBytes } from '../../crates/fgit-node/src/smart_http/server/browser/source-patch.mjs';
import { oid } from '../../crates/fgit-node/src/smart_http/server/browser/pulls-core.mjs';
import { fields, clock } from './source_edit_wire.mjs';
import { canonical, sha256, fail } from './source_changes.mjs';

// Own bounded inputs before any asynchronous file read or verification. Paths
// remain repository byte paths, not local filesystem names or inferred grants.
export function ownSelectedSourceInput(input, selection) {
  if (!(input instanceof Uint8Array) || !(input.buffer instanceof ArrayBuffer) ||
      !input.length || input.length > SOURCE_PACKAGE_BYTES) fail('source_union_package');
  fields(selection, ['format', 'commit', 'files']);
  const commit = oid(selection.commit, selection.format);
  if (!Array.isArray(selection.files) || !selection.files.length || selection.files.length > 32) fail('source_union_selection');
  let total = 0, previous = '';
  const files = selection.files.map(row => {
    fields(row, ['pathHex', 'blob']);
    const path = pathBytes(row.pathHex);
    if ((total += path.length) > 32768 || row.pathHex <= previous) fail('source_union_selection');
    previous = row.pathHex;
    return { pathHex: row.pathHex, blob: oid(row.blob, selection.format) };
  });
  return { bytes: Buffer.from(input), expected: { format: selection.format, commit, files } };
}
export async function mergeSelectedSourcePackages(leftBytes, leftSelection, rightBytes, rightSelection, options = {}) {
  fields(options, ['signal', 'timeoutMs', 'check'], []);
  const time = clock({ signal: options.signal, timeoutMs: options.timeoutMs });
  const checkpoint = options.check;
  if (checkpoint !== undefined && typeof checkpoint !== 'function') fail('source_union_options');
  const check = () => { time.check(); checkpoint?.(); };
  check();
  const left = ownSelectedSourceInput(leftBytes, leftSelection), right = ownSelectedSourceInput(rightBytes, rightSelection);
  if (left.expected.format !== right.expected.format || left.expected.commit !== right.expected.commit) fail('source_union_basis');
  const chosen = new Map();
  for (const row of [...left.expected.files, ...right.expected.files]) {
    const old = chosen.get(row.pathHex);
    if (old && old.blob !== row.blob) fail('source_union_selection_conflict');
    chosen.set(row.pathHex, row);
  }
  if (chosen.size > 32) fail('source_union_selection_limit');
  const expected = { format: left.expected.format, commit: left.expected.commit,
    files: [...chosen.values()].sort((a, b) => a.pathHex < b.pathHex ? -1 : 1) };
  // Each independently selected input must stand alone; the other package must
  // never fill a missing body or proof that would make an invalid input pass.
  const a = await readSourcePackage(left.bytes, left.expected, webcrypto, check);
  const b = await readSourcePackage(right.bytes, right.expected, webcrypto, check);
  check();
  if (a.package.membership.commit.oid !== b.package.membership.commit.oid ||
      a.package.membership.commit.bodyHex !== b.package.membership.commit.bodyHex) fail('source_union_commit_conflict');
  const trees = new Map(), treeBodies = new Map(), files = new Map(), blobs = new Map();
  const add = (map, key, value) => {
    const old = map.get(key);
    if (old !== undefined && !canonical(old).equals(canonical(value))) fail('source_union_content_conflict');
    if (old === undefined) map.set(key, value);
  };
  for (const item of [a.package, b.package]) {
    for (const tree of item.membership.trees) {
      check(); add(trees, tree.pathHex, { pathHex: tree.pathHex, oid: tree.oid, bodyHex: tree.bodyHex });
      add(treeBodies, tree.oid, tree.bodyHex);
    }
    for (const file of item.membership.files) { check(); add(files, file.pathHex, { pathHex: file.pathHex, blob: file.blob, kind: file.kind }); }
    for (const blob of item.blobs) { check(); add(blobs, blob.oid, { oid: blob.oid, bytesHex: blob.bytesHex }); }
  }
  // Identical subtrees at different paths retain distinct membership entries.
  // Content bodies deduplicate only by identity, with exact byte equality above.
  const packageValue = { schema: a.package.schema, membership: {
    schema: a.package.membership.schema, objectFormat: expected.format,
    commit: { oid: a.package.membership.commit.oid, bodyHex: a.package.membership.commit.bodyHex },
    trees: [...trees.values()].sort((x, y) => x.pathHex === y.pathHex ? 0 : x.pathHex === null ? -1 : y.pathHex === null ? 1 : x.pathHex < y.pathHex ? -1 : 1),
    files: expected.files.map(row => files.get(row.pathHex)),
  }, blobs: [...blobs.values()].sort((x, y) => x.oid < y.oid ? -1 : 1) };
  // Re-verify the combined limits and complete topology, not just the inputs.
  const encoded = await encodeSourcePackage(packageValue, expected, webcrypto, check);
  check();
  return { packageBytes: Buffer.from(encoded.serialized), expected, verified: encoded.verified,
    provenance: { original_package_sha256: sha256(left.bytes), additional_package_sha256: sha256(right.bytes),
      original_expected_sha256: sha256(canonical(left.expected)), additional_expected_sha256: sha256(canonical(right.expected)),
      source_commit: expected.commit, selected_files: expected.files.length,
      selected_sources_verified: true, authority_verified: false, freshness_verified: false } };
}
