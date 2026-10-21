// Offline desired-result commitments. Caller-selected local files are data,
// never commands; native preparation/admission remains a separate operation.
import { lstat } from 'node:fs/promises';
import { dirname } from 'node:path';
import { absolute, directory, readPrivate, writeNew } from './workflow_watch_io.mjs';
import { sourceEditResultSelection, SOURCE_EXPECTED_BYTES } from './source_edit_from_package.mjs';
import { canonical } from './source_edit_candidate.mjs';
import { clock, fields, fail, parse, hash } from './source_edit_wire.mjs';

export async function saveSourceEditResultPlan(destination, sourceBytes, fileSpecBytes, options = {}) {
  const time = clock(options); time.check(); absolute(destination);
  // Parse bounded owned bytes synchronously. A caller cannot change which local
  // files are read, the independent source, or their modes during an await.
  const source = parse(sourceBytes, SOURCE_EXPECTED_BYTES);
  const spec = fields(parse(fileSpecBytes, SOURCE_EXPECTED_BYTES), ['files']);
  if (!Array.isArray(spec.files) || !spec.files.length || spec.files.length > 32) fail('source_edit_result_files');
  const files = spec.files.map(row => {
    fields(row, ['path_hex', 'kind', 'body_file']);
    if (typeof row.path_hex !== 'string' || !/^(?:[0-9a-f]{2}){1,4096}$/.test(row.path_hex)) fail('source_edit_result_path');
    if (row.body_file === null) {
      if (row.kind !== null) fail('source_edit_result_files');
    } else if (!['file', 'executable'].includes(row.kind)) fail('source_edit_result_files');
    else absolute(row.body_file);
    return { pathHex: row.path_hex, kind: row.kind, file: row.body_file };
  });
  await directory(dirname(destination)); time.check();
  try { await lstat(destination); fail('source_edit_destination_exists'); } catch (e) { if (e.code !== 'ENOENT') throw e; }
  const changes = []; let total = 0;
  for (const row of files) {
    time.check(); let bytes = null;
    if (row.file !== null) {
      await directory(dirname(row.file)); time.check();
      bytes = await readPrivate(row.file, Math.min(1024 * 1024, 8 * 1024 * 1024 - total));
      total += bytes.length; time.check();
    }
    changes.push({ pathHex: row.pathHex, bytes, kind: row.kind });
  }
  const expected = sourceEditResultSelection(source, changes, time.check), bytes = canonical(expected);
  if (bytes.length > SOURCE_EXPECTED_BYTES) fail('source_edit_evidence_limit');
  const receipt = { type: 'source_edit_result_plan', file: destination, expected_sha256: hash(bytes), expected_bytes: bytes.length,
    source_commit: expected.source.commit, paths_hex: expected.after.map(row => row.pathHex),
    local_body_bytes_read: total, network_requests: 0, source_membership_verified: false, publication_authorized: false };
  time.check();
  try {
    // Atomic create-only publication drains through synchronization/readback.
    // Cancellation or lost stdout cannot undo a file already linked into place.
    await writeNew(destination, bytes);
    if (!bytes.equals(await readPrivate(destination, SOURCE_EXPECTED_BYTES))) fail('source_edit_result_readback');
    return receipt;
  } catch (error) { error.publication_unconfirmed = receipt; throw error; }
}
