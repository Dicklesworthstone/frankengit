// Bind an explicit source edit to independently verified selected-source bytes.
// The package is evidence only: native source preparation/admission still owns
// repository scope, patch semantics, policy and publication authority.
import { webcrypto } from 'node:crypto';
import { readSourcePackage, SOURCE_PACKAGE_BYTES } from '../../crates/fgit-node/src/smart_http/server/browser/search-context-package.mjs';
import { editInput } from './source_edit_candidate.mjs';
import { fail, hash } from './source_edit_wire.mjs';

export { SOURCE_PACKAGE_BYTES };

export async function bindVerifiedEditSource(packageBytes, expected, selection, check = () => {}) {
  if (!(packageBytes instanceof Uint8Array) || !packageBytes.length || packageBytes.length > SOURCE_PACKAGE_BYTES ||
      typeof check !== 'function') fail('source_edit_package_input');
  check();
  // editInput owns the closed mutation-selection grammar before any async hash.
  const request = editInput(structuredClone(selection));
  const expectedOwned = structuredClone(expected);
  const bytes = Buffer.from(packageBytes);
  const loaded = await readSourcePackage(bytes, expectedOwned, webcrypto, check);
  check();
  if (request.scope.object_format !== loaded.package.membership.objectFormat ||
      request.expected_commit !== loaded.verified.commit) {
    fail('source_edit_package_commit');
  }
  const selected = new Map(loaded.verified.files.map(file => [file.pathHex, file]));
  for (const path of request.paths_hex) {
    if (!selected.has(path)) fail('source_edit_package_path');
  }
  return Object.freeze({
    request,
    package_sha256: hash(bytes),
    verified_commit: loaded.verified.commit,
    verified_paths: request.paths_hex.map(path => Object.freeze({
      path_hex: path,
      blob: selected.get(path).blob,
      kind: selected.get(path).kind,
      source_bytes: selected.get(path).sourceBytes,
    })),
    source_package_verified: true,
    authority_verified: false,
    freshness_verified: false,
    publication_authorized: false,
  });
}
