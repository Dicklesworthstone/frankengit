// Explicit private operands for the offline exact-tree-v1 author. No repository
// lookup, destination existence claim, executable text, or implicit body search.
import { dirname } from 'node:path';
import { absolute, directory, readPrivate } from './workflow_watch_io.mjs';
import { fields, parse, fail, hash } from './source_edit_wire.mjs';
import { REFACTOR_PROFILE, REPLACEMENT_LIMITS } from './source_edit_replacements.mjs';
const PLAN_BYTES = 512 * 1024, FILE_BYTES = 1048576, MODES = [0o100644, 0o100755];
async function read(path, maximum, check) {
  check(); await directory(dirname(absolute(path)));
  const bytes = await readPrivate(path, maximum); check(); return bytes;
}
export async function loadSourceRefactorFiles(filename, check = () => {}) {
  if (typeof check !== 'function') fail('source_refactor_input');
  const raw = await read(filename, PLAN_BYTES, check), plan = parse(raw, PLAN_BYTES);
  fields(plan, ['schema', 'object_format', 'changes']);
  if (plan.schema !== REFACTOR_PROFILE || !['sha1', 'sha256'].includes(plan.object_format) ||
      !Array.isArray(plan.changes) || !plan.changes.length || plan.changes.length > 32) fail('source_refactor_plan');
  // Copy the descriptor inventory before any operand read can yield. An absent
  // after.file means preserve the original bytes, only for an explicit move.
  const rows = plan.changes.map(row => {
    check(); fields(row, ['path_hex', 'destination_hex', 'before', 'after'], ['path_hex', 'before', 'after']);
    const moved = Object.hasOwn(row, 'destination_hex');
    if (moved && (row.before === null || row.after === null)) fail('source_refactor_move');
    const original = row.before === null ? null : fields(row.before, ['file', 'blob', 'mode']);
    const result = row.after === null ? null : fields(row.after, ['file', 'mode'], moved ? ['mode'] : ['file', 'mode']);
    if ([original, result].some(side => side && !MODES.includes(side.mode))) fail('source_refactor_mode');
    return { path_hex: row.path_hex, ...(moved ? { destination_hex: row.destination_hex } : {}),
      before: original === null ? null : { file: absolute(original.file), mode: original.mode, blob: original.blob },
      after: result === null ? null : { mode: result.mode, ...(Object.hasOwn(result, 'file') ? { file: absolute(result.file) } : {}) } };
  });
  const changes = []; let sourceBytes = 0, resultBytes = 0;
  for (const row of rows) {
    check(); let before = null, after = null;
    if (row.before) {
      const bytes = await read(row.before.file, Math.min(FILE_BYTES, REPLACEMENT_LIMITS.maxSourceBytes - sourceBytes), check);
      sourceBytes += bytes.length; before = { mode: row.before.mode, blob: row.before.blob, bytes };
    }
    if (row.after) {
      const remaining = REPLACEMENT_LIMITS.maxResultBytes - resultBytes;
      const bytes = Object.hasOwn(row.after, 'file') ? await read(row.after.file, Math.min(FILE_BYTES, remaining), check) : before.bytes;
      if (bytes.length > remaining) fail('source_replacement_bytes');
      resultBytes += bytes.length; after = { mode: row.after.mode, bytes };
    }
    changes.push({ path_hex: row.path_hex, ...(Object.hasOwn(row, 'destination_hex') ? { destination_hex: row.destination_hex } : {}), before, after });
  }
  check(); return { format: plan.object_format, changes, plan_sha256: hash(raw) };
}
