// Private-file adapter for original-coordinate splices. No source discovery,
// network access, source execution or repository publication.
import { createHash } from 'node:crypto';
import { dirname } from 'node:path';
import { absolute, directory, readPrivate } from './workflow_watch_io.mjs';
import { fields, parse, fail, integer, hash } from './source_edit_wire.mjs';
import { SPLICE_LIMITS } from './source_edit_splices.mjs';
import { REPLACEMENT_LIMITS } from './source_edit_replacements.mjs';
export const SPLICE_FILE_PROFILE = 'frankengit-source-splice-files-v1';
const PLAN_BYTES = 512 * 1024, FILE_BYTES = 1048576, MODES = [0o100644, 0o100755];
async function read(path, maximum, check) {
  check(); await directory(dirname(absolute(path))); check();
  const bytes = await readPrivate(path, maximum); check(); return bytes;
}
function operand(value) {
  fields(value, ['hex', 'file'], []);
  if (Object.keys(value).length !== 1) fail('source_patch_splice_operand');
  if (Object.hasOwn(value, 'file')) return { file: absolute(value.file) };
  if (typeof value.hex !== 'string' || value.hex.length > 2 * FILE_BYTES ||
      value.hex.length % 2 || /[^0-9a-f]/.test(value.hex)) fail('source_patch_splice_hex');
  return { hex: value.hex };
}
function inventory(plan, check) {
  fields(plan, ['schema', 'object_format', 'files']);
  if (plan.schema !== SPLICE_FILE_PROFILE || !['sha1', 'sha256'].includes(plan.object_format) ||
      !Array.isArray(plan.files) || !plan.files.length || plan.files.length > 32) fail('source_patch_splice_plan');
  const width = plan.object_format === 'sha1' ? 40 : 64, names = [];
  let count = 0, pathBytes = 0;
  // Validate and copy the entire inventory before the first payload await.
  return plan.files.map(row => {
    check(); fields(row, ['path_hex', 'before', 'after_mode', 'edits']);
    if (typeof row.path_hex !== 'string' || !/^(?:[0-9a-f]{2}){1,4096}$/.test(row.path_hex)) fail('source_splice_path');
    const path = Buffer.from(row.path_hex, 'hex'), parts = path.toString('latin1').split('/');
    if (path.includes(0) || parts.length > 64 || parts.some(p => !p || p === '.' || p === '..' || p.toLowerCase() === '.git')) fail('source_splice_path');
    if ((pathBytes += path.length) > 32768 || names.some(name => name === row.path_hex ||
        name.startsWith(`${row.path_hex}2f`) || row.path_hex.startsWith(`${name}2f`))) fail('source_splice_paths');
    names.push(row.path_hex);
    const before = fields(row.before, ['file', 'blob', 'mode']);
    if (!MODES.includes(before.mode) || !MODES.includes(row.after_mode)) fail('source_patch_mode');
    if (typeof before.blob !== 'string' || !new RegExp(`^[0-9a-f]{${width}}$`).test(before.blob)) fail('source_splice_preimage');
    if (!Array.isArray(row.edits) || row.edits.length > SPLICE_LIMITS.maxSplices - count) fail('source_splice_count');
    count += row.edits.length;
    return { path_hex: row.path_hex, before: { file: absolute(before.file), blob: before.blob, mode: before.mode },
      after_mode: row.after_mode, edits: row.edits.map(edit => {
        check(); fields(edit, ['byte_start', 'before', 'after']);
        return { byte_start: integer(edit.byte_start, 0, FILE_BYTES), before: operand(edit.before), after: operand(edit.after) };
      }) };
  });
}
export async function readSourceSplicePlan(path, check = () => {}) {
  if (typeof check !== 'function') fail('source_splice_input');
  const raw = await read(path, PLAN_BYTES, check), plan = parse(raw, PLAN_BYTES);
  return { ...await loadSourceSpliceFiles(plan, check), plan_sha256: hash(raw) };
}
// The CLI already owns its plan bytes; do not reopen a mutable plan file.
export async function loadSourceSpliceFiles(plan, check = () => {}) {
  if (typeof check !== 'function') fail('source_splice_input');
  const rows = inventory(plan, check), format = plan.object_format;
  const remaining = { source: REPLACEMENT_LIMITS.maxSourceBytes,
    before: SPLICE_LIMITS.maxExpectedBytes, after: SPLICE_LIMITS.maxInsertedBytes };
  const payload = async (value, category) => {
    check(); const maximum = Math.min(FILE_BYTES, remaining[category]);
    // Pass the remaining allowance into the bounded read BEFORE allocation.
    // Empty operands remain legal when the byte allowance is exhausted.
    let bytes;
    if (Object.hasOwn(value, 'hex')) {
      if (value.hex.length / 2 > maximum) fail('source_splice_bytes');
      bytes = Buffer.from(value.hex, 'hex');
    } else bytes = await read(value.file, maximum, check);
    remaining[category] -= bytes.length; check(); return bytes;
  };
  const files = [];
  for (const row of rows) {
    const bytes = await payload(row.before, 'source');
    const blob = createHash(format).update(`blob ${bytes.length}\0`).update(bytes).digest('hex');
    if (blob !== row.before.blob) fail('source_splice_preimage');
    const edits = [];
    for (const edit of row.edits) {
      check(); const before = await payload(edit.before, 'before');
      if (edit.byte_start > bytes.length || before.length > bytes.length - edit.byte_start) fail('source_splice_range');
      if (!bytes.subarray(edit.byte_start, edit.byte_start + before.length).equals(before)) fail('source_splice_context_mismatch');
      edits.push({ byte_start: edit.byte_start, before, after: await payload(edit.after, 'after') });
    }
    files.push({ path_hex: row.path_hex, before: { bytes, blob, mode: row.before.mode }, after_mode: row.after_mode, edits });
  }
  check(); return { format, files };
}
