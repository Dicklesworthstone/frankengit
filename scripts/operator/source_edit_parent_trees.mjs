// Commit-anchored tree metadata for explicit local source capture v4.
// Reuse the existing codecs; unchanged blob bodies are never fetched or copied.
import { createHash } from 'node:crypto';
import { MEMBERSHIP_LIMITS, TREE_TRANSITION_LIMITS, decodeTreeRows, decodeCommitTree,
  encodeVerifiedTreeRows } from '../../crates/fgit-node/src/smart_http/server/browser/search-context-membership.mjs';
import { oid } from '../../crates/fgit-node/src/smart_http/server/browser/pulls-core.mjs';
import { fields, fail } from './source_edit_wire.mjs';

export const PARENT_TREE_PROFILE = 'verified-parent-trees-v1';
const hash = (kind, body, format) => createHash(format).update(`${kind} ${body.length}\0`).update(body).digest('hex');
const modes = { file: 0o100644, executable: 0o100755, directory: 0o40000, symlink: 0o120000, gitlink: 0o160000 };
function path(value) {
  if (typeof value !== 'string' || !/^(?:[0-9a-f]{2}){1,4096}$/.test(value)) fail('source_edit_parent_path');
  const bytes = Buffer.from(value, 'hex'), parts = bytes.toString('latin1').split('/');
  if (bytes.includes(0) || parts.length > 64 || parts.some(p => !p || p === '.' || p === '..')) fail('source_edit_parent_path');
  return value;
}
const parent = value => {
  // A byte slash must start at an even hex offset; a nibble pair is not a path separator.
  for (let i = value.length - 2; i >= 0; i -= 2) if (value.slice(i, i + 2) === '2f') return value.slice(0, i);
  return ''; };
const name = value => { const p = parent(value); return value.slice(p ? p.length + 2 : 0); };
const needed = (directory, paths) => directory === '' || paths.some(p => p.startsWith(directory + '2f'));
function bytes(value, maximum) {
  if (typeof value !== 'string' || value.length > maximum * 2 || !/^(?:[0-9a-f]{2})*$/.test(value)) fail('source_edit_parent_bytes');
  return Buffer.from(value, 'hex');
}

function verifiedBasis(value, format, commit, paths) {
  if (!Array.isArray(paths) || !paths.length || paths.length > 64) fail('source_edit_parent_path_limit');
  paths.forEach(path);
  fields(value, ['commit', 'trees']); fields(value.commit, ['oid', 'bodyHex']);
  const expected = oid(commit, format), body = bytes(value.commit.bodyHex, 65536);
  if (oid(value.commit.oid, format) !== expected || hash('commit', body, format) !== expected) fail('source_edit_parent_commit');
  const root = decodeCommitTree(body, format).root;
  if (!Array.isArray(value.trees) || !value.trees.length || value.trees.length > MEMBERSHIP_LIMITS.maxTrees) fail('source_edit_parent_tree_limit');
  let total = 0, entries = 0;
  const trees = new Map(), encoded = [];
  for (const raw of value.trees) {
    fields(raw, ['pathHex', 'oid', 'bodyHex']);
    const at = raw.pathHex === null ? '' : path(raw.pathHex);
    if (!needed(at, paths) || trees.has(at)) fail('source_edit_parent_inventory');
    const data = bytes(raw.bodyHex, MEMBERSHIP_LIMITS.maxTreeBytes);
    if ((total += data.length) > MEMBERSHIP_LIMITS.maxTreeBytes) fail('source_edit_parent_byte_limit');
    const rows = decodeTreeRows(data, format, () => {
      if (++entries > MEMBERSHIP_LIMITS.maxEntries) fail('source_edit_parent_entry_limit');
    }, () => {});
    const id = oid(raw.oid, format);
    if (hash('tree', data, format) !== id) fail('source_edit_parent_tree_identity');
    trees.set(at, { id, rows }); encoded.push({ pathHex: at === '' ? null : at, oid: id, bodyHex: data.toString('hex') });
  }
  if (trees.get('')?.id !== root) fail('source_edit_parent_root');
  for (const [at, tree] of trees) {
    if (at === '') continue;
    const original = trees.get(parent(at))?.rows.find(row => row.name_hex === name(at));
    if (!original || original.kind !== 'directory' || original.object_id !== tree.id) fail('source_edit_parent_membership');
  }
  encoded.sort((a, b) => (a.pathHex ?? '') < (b.pathHex ?? '') ? -1 : (a.pathHex ?? '') > (b.pathHex ?? '') ? 1 : 0);
  return { root, trees, value: { commit: { oid: expected, bodyHex: body.toString('hex') }, trees: encoded } };
}
export function ownParentTreeBasis(value, format, commit, paths) {
  return verifiedBasis(value, format, commit, paths).value;
}
// A package is owned by the authoring caller before this function runs. The
// extracted metadata still passes the same commit/root/membership checks.
export function parentTreeBasisFromPackage(packageBytes, format, commit, paths) {
  let pkg;
  try { pkg = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(packageBytes)); }
  catch { fail('source_edit_parent_package'); }
  if (!Array.isArray(pkg?.membership?.trees)) fail('source_edit_parent_package');
  const selected = pkg.membership.trees.filter(row => row?.pathHex === null ||
    typeof row?.pathHex === 'string' && needed(row.pathHex, paths));
  return ownParentTreeBasis({ commit: pkg.membership.commit, trees: selected }, format, commit, paths);
}

// Every row is kept in the capture. The returned leaves are only a matching
// view after all parent identities and the complete resulting root are checked.
export function parentTreeFileRows(rows, format, commit, paths, basis, beforeRoot, afterRoot) {
  if (!Array.isArray(rows) || rows.length > 512) fail('source_edit_comparison');
  const original = verifiedBasis(basis, format, commit, paths);
  if (oid(beforeRoot, format) !== original.root) fail('source_edit_parent_before_root');
  const directories = new Map(), files = []; let previous = '', workEntries = 0, workBytes = 0;
  const descriptor = (at, before, after) => {
    const known = original.trees.get(at);
    if (before !== null && (!known || known.id !== before)) fail('source_edit_parent_missing');
    if (before === null && known) fail('source_edit_parent_creation');
    const initial = before === null ? [] : known.rows;
    const map = new Map(initial.map(row => [row.name_hex, row]));
    directories.set(at, { before, after, original: map, result: after === null ? null : new Map(map) });
  };
  descriptor('', original.root, oid(afterRoot, format));
  for (const row of rows) {
    fields(row, ['path_hex', 'kind', 'before', 'after', 'content']); const at = path(row.path_hex);
    if (at <= previous) fail('source_edit_comparison'); previous = at;
    if (row.before?.mode !== 0o40000 && row.after?.mode !== 0o40000) { files.push(row); continue; }
    const b = row.before, a = row.after;
    const kind = b === null && a?.mode === 0o40000 ? 'added' : a === null && b?.mode === 0o40000 ? 'deleted'
      : b?.mode === 0o40000 && a?.mode === 0o40000 ? 'modified' : null;
    if (kind === null || row.kind !== kind || !needed(at, paths)) fail('source_edit_parent_directory_kind');
    for (const side of [b, a]) if (side !== null) fields(side, ['mode', 'oid']);
    fields(row.content, ['type', 'content_read']);
    if (row.content.type !== 'object_only' || row.content.content_read !== false) fail('source_edit_parent_content');
    const old = b === null ? null : oid(b.oid, format), next = a === null ? null : oid(a.oid, format);
    if (old === next) fail('source_edit_parent_directory_kind');
    descriptor(at, old, next);
  }
  const change = (at, before, after) => {
    const owner = directories.get(parent(at)), key = name(at);
    if (!owner) fail('source_edit_parent_missing');
    const existing = owner.original.get(key);
    if (before === null ? existing !== undefined : !existing || existing.object_id !== oid(before.oid, format) || modes[existing.kind] !== before.mode) {
      fail('source_edit_parent_preimage');
    }
    if (owner.result === null) { if (after !== null) fail('source_edit_parent_deleted'); return; }
    if (after === null) owner.result.delete(key);
    else {
      const kind = Object.keys(modes).find(kind => modes[kind] === after.mode);
      if (!kind) fail('source_edit_parent_mode');
      const raw = Buffer.from(key, 'hex'), order = Buffer.concat([raw, Buffer.from(kind === 'directory' ? '/' : '\0')]);
      owner.result.set(key, { name_hex: key, bytes: raw, order, kind, object_id: oid(after.oid, format) });
    }
  };
  for (const row of files) {
    if (!paths.includes(row.path_hex)) fail('source_edit_parent_unselected');
    // Leaf shape/mode/content validation also runs in the existing validator.
    for (const value of [row.before, row.after]) if (value !== null) {
      fields(value, ['mode', 'oid']);
      if (![0o100644, 0o100755].includes(value.mode)) fail('source_edit_parent_mode');
    }
    change(row.path_hex, row.before, row.after);
  }
  for (const [at, directory] of [...directories].sort((a, b) => b[0].length - a[0].length)) {
    if (directory.after !== null) {
      const children = [...directory.result.values()];
      if (at !== '' && !children.length) fail('source_edit_parent_empty');
      for (const row of children) {
        if (++workEntries > TREE_TRANSITION_LIMITS.maxEntries ||
            (workBytes += String(modes[row.kind].toString(8)).length + 2 + row.bytes.length + row.object_id.length / 2) > TREE_TRANSITION_LIMITS.maxTreeBytes) {
          fail('source_edit_parent_work_limit');
        }
      }
      const data = encodeVerifiedTreeRows(children, () => {});
      if (hash('tree', data, format) !== directory.after) fail('source_edit_parent_after_identity');
    } else if (directory.original.size !== files.filter(row => parent(row.path_hex) === at).length +
        [...directories.keys()].filter(child => child !== '' && parent(child) === at).length) {
      fail('source_edit_parent_unreported_deletion');
    }
    if (at !== '') change(at, directory.before === null ? null : { mode: 0o40000, oid: directory.before },
      directory.after === null ? null : { mode: 0o40000, oid: directory.after });
  }
  return files;
}
