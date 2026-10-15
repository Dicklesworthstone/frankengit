// Opt-in local discovery over an independently pinned sparse workspace.
// This verifies retained custody, NOT native membership or mutation authority.
import { constants as F } from 'node:fs';
import { lstat, realpath, open, opendir } from 'node:fs/promises';
import { resolve } from 'node:path';
import { createHash } from 'node:crypto';

export const SCAN_SCHEMA = 'frankengit-workspace-scan-v1';
export const SCAN_LIMITS = Object.freeze({ entries: 4096, directories: 256, files: 256,
  fileBytes: 1048576, totalBytes: 16777216, pathsBytes: 262144, reportBytes: 262144 });
const ROOT_SCHEMA = 'frankengit-selected-source-workspace-v1';
const encode = value => Buffer.from(`${JSON.stringify(value)}\n`);
const hash = bytes => createHash('sha256').update(bytes).digest('hex');
const error = code => { const e = new Error(code); e.code = code; throw e; };
const fields = (v, names, required = names) => {
  if (!v || typeof v !== 'object' || Array.isArray(v) || Object.keys(v).some(k => !names.includes(k)) ||
      required.some(k => !Object.hasOwn(v, k))) error('source_workspace_scan_fields');
};
const digest = value => {
  if (typeof value !== 'string' || !/^[0-9a-f]{64}$/.test(value)) error('source_workspace_scan_pin');
  return value;
};
const integer = (v, min, max) => {
  if (!Number.isSafeInteger(v) || v < min || v > max) error('source_workspace_scan_limit');
  return v;
};
const same = (a, b) => ['dev', 'ino', 'mode', 'uid', 'gid', 'nlink', 'size', 'mtimeNs', 'ctimeNs'].every(k => a[k] === b[k]);
function pathBytes(value, root = false) {
  if (root && value === '') return Buffer.alloc(0);
  if (typeof value !== 'string' || !value.length || value.length > 8192 || value.length % 2 || /[^0-9a-f]/.test(value)) error('source_workspace_scan_path');
  const bytes = Buffer.from(value, 'hex'), parts = bytes.toString('latin1').split('/');
  if (bytes.includes(0) || parts.length > 64 || parts.some(p => !p || p.length > 255 || ['.', '..', '.git'].includes(p.toLowerCase()))) error('source_workspace_scan_path');
  return bytes;
}
const within = (parent, child) => parent === '' || parent === child || child.startsWith(`${parent}2f`);
function pathSet(value, allowEmptyList = false) {
  if (!Array.isArray(value) || (!value.length && !allowEmptyList) || value.length > 32) error('source_workspace_scan_scope');
  const paths = value.map(p => { pathBytes(p, true); return p; }).sort();
  if (paths.some((p, i) => paths.some((q, j) => i !== j && within(p, q)))) error('source_workspace_scan_scope');
  return paths;
}
export function workspaceScanScope(value) {
  fields(value, ['roots_hex', 'exclude_hex', 'include_unselected'], ['roots_hex']);
  const roots = pathSet(value.roots_hex), excludes = pathSet(value.exclude_hex ?? [], true);
  const include = value.include_unselected ?? false;
  if (typeof include !== 'boolean' || excludes.some(p => p === '' || !roots.some(r => within(r, p)) || roots.includes(p))) error('source_workspace_scan_scope');
  return { roots_hex: roots, exclude_hex: excludes, include_unselected: include };
}
function life(options) {
  fields(options, ['signal', 'timeoutMs', 'check', 'limits'], []);
  if (typeof process.getuid !== 'function' || process.platform === 'win32') error('source_workspace_scan_posix_required');
  const end = performance.now() + integer(options.timeoutMs ?? 30000, 1, 300000), signal = options.signal;
  if (signal !== undefined && !(signal instanceof AbortSignal) || options.check !== undefined && typeof options.check !== 'function') error('source_workspace_scan_options');
  fields(options.limits ?? {}, Object.keys(SCAN_LIMITS), []);
  const limits = Object.fromEntries(Object.entries(SCAN_LIMITS).map(([k, max]) => [k, integer(options.limits?.[k] ?? max, 1, max)]));
  const check = () => { signal?.throwIfAborted(); if (performance.now() >= end) error('source_workspace_scan_deadline'); options.check?.(); };
  check(); return { check, limits };
}
function normalized(root) {
  if (typeof root !== 'string' || !root.startsWith('/') || root === '/' || root.includes('\0') || Buffer.byteLength(root) > 4096 || resolve(root) !== root) error('source_workspace_scan_root');
  return root;
}
const child = (root, hex = '') => Buffer.concat([Buffer.from(`${root}/files`), ...(hex ? [Buffer.from('/'), pathBytes(hex)] : [])]);
const safeDir = s => s.isDirectory() && s.uid === BigInt(process.getuid()) && (s.mode & 0o7777n) === 0o700n;
const safeFile = (s, limit) => s.isFile() && s.uid === BigInt(process.getuid()) && s.nlink === 1n &&
  [0o600n, 0o700n].includes(s.mode & 0o7777n) && s.size >= 0n && s.size <= BigInt(limit);
async function named(path) {
  try { return await lstat(path, { bigint: true }); }
  catch (e) { if (e.code === 'ENOENT') return null; throw e; }
}
// Reads are bounded before allocation. Nonblocking/no-follow protects opening
// a file that was replaced by a FIFO or symlink between lstat and open.
async function readFile(path, limit, check, observations, totals = null) {
  check(); const before = await named(path); check();
  if (!before) { observations.push({ path, stat: null }); return null; }
  if (!safeFile(before, limit)) error('source_workspace_scan_unsafe_file');
  if (totals && (totals.bytes += Number(before.size)) > totals.limit) error('source_workspace_scan_byte_budget');
  const handle = await open(path, F.O_RDONLY | F.O_NOFOLLOW | F.O_NONBLOCK);
  try {
    check(); const opened = await handle.stat({ bigint: true });
    if (!safeFile(opened, limit) || !same(before, opened)) error('source_workspace_scan_changed');
    const bytes = Buffer.alloc(Number(opened.size)); let offset = 0;
    while (offset < bytes.length) {
      check(); const part = await handle.read(bytes, offset, Math.min(65536, bytes.length - offset), offset); check();
      if (!part.bytesRead) error('source_workspace_scan_changed'); offset += part.bytesRead;
    }
    const extra = await handle.read(Buffer.alloc(1), 0, 1, offset), after = await handle.stat({ bigint: true });
    const current = await named(path); check();
    if (extra.bytesRead || !current || !same(opened, after) || !same(opened, current) ||
        !(await realpath(path, { encoding: 'buffer' })).equals(Buffer.from(path))) error('source_workspace_scan_changed');
    observations.push({ path, stat: opened });
    return { bytes, executable: (opened.mode & 0o100n) !== 0n };
  } finally { await handle.close(); }
}
async function directory(path, check, observations, optional = false) {
  check(); const stat = await named(path); check();
  if (!stat && optional) { observations.push({ path, stat: null }); return false; }
  if (!stat || !safeDir(stat) || !(await realpath(path, { encoding: 'buffer' })).equals(Buffer.from(path))) error('source_workspace_scan_unsafe_directory');
  observations.push({ path, stat }); return true;
}
async function recheck(observations, check) {
  for (const { path, stat } of observations) {
    check(); const current = await named(path); check();
    if (stat === null ? current !== null : current === null || !same(stat, current)) error('source_workspace_scan_changed');
  }
}
function parse(bytes) {
  try { return JSON.parse(new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes)); }
  catch { error('source_workspace_scan_json'); }
}
// The retained workspace root already commits to these bytes. No second Git
// decoder is implemented here; capture reuses the existing membership verifier.
async function baseline(root, rootHash, check, observations) {
  await directory(Buffer.from(root), check, observations);
  const rootFile = await readFile(Buffer.from(`${root}/manifest.json`), 131072, check, observations);
  if (!rootFile || hash(rootFile.bytes) !== rootHash) error('source_workspace_manifest_changed');
  const m = parse(rootFile.bytes);
  fields(m, ['schema', 'package_sha256', 'package_bytes', 'expected_sha256', 'expected_bytes', 'object_format', 'source_commit', 'root_tree', 'files']);
  if (m.schema !== ROOT_SCHEMA || !['sha1', 'sha256'].includes(m.object_format) ||
      !Array.isArray(m.files) || !m.files.length || m.files.length > 32 || !encode(m).equals(rootFile.bytes)) error('source_workspace_scan_baseline');
  const oid = value => { if (typeof value !== 'string' || !new RegExp(`^[0-9a-f]{${m.object_format === 'sha1' ? 40 : 64}}$`).test(value) || /^0+$/.test(value)) error('source_workspace_scan_baseline'); return value; };
  oid(m.source_commit); oid(m.root_tree); digest(m.package_sha256); digest(m.expected_sha256);
  integer(m.package_bytes, 1, 33554432); integer(m.expected_bytes, 1, 131072);
  const source = await readFile(Buffer.from(`${root}/source.json`), m.package_bytes, check, observations);
  const expected = await readFile(Buffer.from(`${root}/expected.json`), m.expected_bytes, check, observations);
  if (!source || !expected || source.bytes.length !== m.package_bytes || hash(source.bytes) !== m.package_sha256 ||
      expected.bytes.length !== m.expected_bytes || hash(expected.bytes) !== m.expected_sha256) error('source_workspace_baseline_changed');
  const pkg = parse(source.bytes), exp = parse(expected.bytes);
  fields(exp, ['format', 'commit', 'files']);
  if (exp.format !== m.object_format || exp.commit !== m.source_commit || !Array.isArray(exp.files) || exp.files.length !== m.files.length ||
      !pkg || pkg.schema !== 'frankengit-selected-source-package-v1' || !Array.isArray(pkg.blobs) || pkg.blobs.length > 32) error('source_workspace_scan_baseline');
  const blobs = new Map();
  for (const b of pkg.blobs) {
    check(); fields(b, ['oid', 'bytesHex']); oid(b.oid);
    if (blobs.has(b.oid) || typeof b.bytesHex !== 'string' || b.bytesHex.length > 2097152 || b.bytesHex.length % 2 || /[^0-9a-f]/.test(b.bytesHex)) error('source_workspace_scan_baseline');
    blobs.set(b.oid, b.bytesHex);
  }
  const files = new Map(); let previous = '', total = 0, pathTotal = 0;
  for (const [i, f] of m.files.entries()) {
    check(); fields(f, ['path_hex', 'blob', 'executable', 'bytes']); const path = pathBytes(f.path_hex); oid(f.blob);
    fields(exp.files[i], ['pathHex', 'blob']);
    if (f.path_hex <= previous || files.has(f.path_hex) || typeof f.executable !== 'boolean' ||
        exp.files[i].pathHex !== f.path_hex || exp.files[i].blob !== f.blob || !blobs.has(f.blob)) error('source_workspace_scan_baseline');
    previous = f.path_hex; integer(f.bytes, 0, 1048576); total += f.bytes; pathTotal += path.length;
    if (total > 8388608 || pathTotal > 32768 || blobs.get(f.blob).length !== f.bytes * 2) error('source_workspace_scan_baseline');
    files.set(f.path_hex, { sha256: hash(Buffer.from(blobs.get(f.blob), 'hex')), bytes: f.bytes, executable: f.executable });
  }
  const keys = [...files.keys()];
  if (keys.some(p => keys.some(q => p !== q && within(p, q)))) error('source_workspace_scan_baseline');
  return { manifest: m, files };
}
export async function scanSourceWorkspace(root, workspaceHash, inputScope, options = {}) {
  normalized(root); digest(workspaceHash); const scope = workspaceScanScope(inputScope), { check, limits } = life(options);
  const observations = [], base = await baseline(root, workspaceHash, check, observations);
  await directory(child(root), check, observations);
  const excluded = p => scope.exclude_hex.some(e => within(e, p));
  const selected = p => scope.roots_hex.some(r => within(r, p)) && !excluded(p);
  const originals = new Map([...base.files].filter(([p]) => selected(p))), discovered = new Map();
  const directories = new Set(), counts = { entries: 0, paths: 0 }, totals = { bytes: 0, limit: limits.totalBytes };
  const inspect = async hex => {
    if (directories.has(hex)) return true;
    if (directories.size >= limits.directories) error('source_workspace_scan_directory_budget');
    if (!await directory(child(root, hex), check, observations, true)) return false;
    directories.add(hex); return true;
  };
  const walk = async hex => {
    check(); if (!await inspect(hex)) return;
    const dir = await opendir(child(root, hex), { encoding: 'buffer', bufferSize: 1 });
    try {
      while (true) {
        check(); const entry = await dir.read(); check(); if (!entry) break;
        if (++counts.entries > limits.entries) error('source_workspace_scan_entry_budget');
        const name = Buffer.isBuffer(entry.name) ? entry.name : Buffer.from(entry.name);
        if (name.includes(47) || name.includes(0)) error('source_workspace_scan_path');
        const path = hex ? `${hex}2f${name.toString('hex')}` : name.toString('hex');
        if (excluded(path)) continue;
        counts.paths += pathBytes(path).length;
        if (counts.paths > limits.pathsBytes) error('source_workspace_scan_path_budget');
        const stat = await named(child(root, path)); check();
        if (!stat) error('source_workspace_scan_changed');
        if (stat.isDirectory()) await walk(path);
        else {
          if (discovered.size >= limits.files) error('source_workspace_scan_file_budget');
          const file = await readFile(child(root, path), limits.fileBytes, check, observations, totals);
          if (!file) error('source_workspace_scan_changed');
          discovered.set(path, { sha256: hash(file.bytes), bytes: file.bytes.length, executable: file.executable });
        }
      }
    } finally { await dir.close(); }
  };
  for (const hex of scope.roots_hex) {
    check(); const bytes = pathBytes(hex, true); let present = true;
    for (let i = 0; i < bytes.length; i++) if (bytes[i] === 47 && !await inspect(bytes.subarray(0, i).toString('hex'))) { present = false; break; }
    if (present) await walk(hex);
  }
  const paths = [...new Set([...originals.keys(), ...discovered.keys()])].sort();
  const entries = paths.map(path_hex => {
    const before = originals.get(path_hex) ?? null, after = discovered.get(path_hex) ?? null;
    return { path_hex, state: before === null ? 'unselected' : after === null ? 'deleted'
      : before.sha256 === after.sha256 && before.executable === after.executable ? 'unchanged' : 'modified', before, after };
  });
  const scan = { schema: SCAN_SCHEMA, directory: root, workspace_sha256: workspaceHash,
    object_format: base.manifest.object_format, source_commit: base.manifest.source_commit,
    scope, entries, source_material_untrusted: true, complete_repository: false,
    native_membership_reverified: false, absence_verified: false, atomic_filesystem_snapshot: false,
    repository_changed: false, source_executed: false, network_attempted: false };
  const bytes = encode(scan); if (bytes.length > limits.reportBytes) error('source_workspace_scan_report_budget');
  await recheck(observations, check); check();
  return { type: 'source_workspace_scan', scan_sha256: hash(bytes), scan };
}
// These exact post-edit observations also bind the existing capture read. They
// are not a substitute for the immutable baseline or proved source-path absence.
export function workspaceObservations(value, paths) {
  if (!Array.isArray(value) || value.length !== paths.length || value.length > 32) error('source_workspace_scan_observations');
  return value.map((r, i) => {
    fields(r, ['path_hex', 'sha256', 'bytes', 'executable']); pathBytes(r.path_hex);
    if (r.path_hex !== paths[i]) error('source_workspace_scan_observations');
    if (r.sha256 === null) { if (r.bytes !== 0 || r.executable !== null) error('source_workspace_scan_observations'); }
    else { digest(r.sha256); integer(r.bytes, 0, 1048576); if (typeof r.executable !== 'boolean') error('source_workspace_scan_observations'); }
    return { path_hex: r.path_hex, sha256: r.sha256, bytes: r.bytes, executable: r.executable };
  });
}
export function checkWorkspaceObservations(observations, files) {
  for (const row of observations) {
    if (!files.has(row.path_hex)) error('source_workspace_scan_changed');
    const actual = files.get(row.path_hex);
    if (row.sha256 === null ? actual !== null : !actual || actual.bytes.length !== row.bytes ||
        actual.executable !== row.executable || hash(actual.bytes) !== row.sha256) error('source_workspace_scan_changed');
  }
}
function reviewedReport(report, approvedHash) {
  digest(approvedHash); fields(report, ['type', 'scan_sha256', 'scan']);
  const v = report.scan;
  fields(v, ['schema', 'directory', 'workspace_sha256', 'object_format', 'source_commit', 'scope', 'entries',
    'source_material_untrusted', 'complete_repository', 'native_membership_reverified', 'absence_verified',
    'atomic_filesystem_snapshot', 'repository_changed', 'source_executed', 'network_attempted']);
  normalized(v.directory); digest(v.workspace_sha256);
  if (report.type !== 'source_workspace_scan' || report.scan_sha256 !== approvedHash || v.schema !== SCAN_SCHEMA ||
      !['sha1', 'sha256'].includes(v.object_format) || typeof v.source_commit !== 'string' ||
      !new RegExp(`^[0-9a-f]{${v.object_format === 'sha1' ? 40 : 64}}$`).test(v.source_commit) || /^0+$/.test(v.source_commit) ||
      v.source_material_untrusted !== true || ['complete_repository', 'native_membership_reverified', 'absence_verified',
        'atomic_filesystem_snapshot', 'repository_changed', 'source_executed', 'network_attempted'].some(k => v[k] !== false)) error('source_workspace_scan_approval');
  const scope = workspaceScanScope(v.scope);
  if (!encode(scope).equals(encode(v.scope)) || !Array.isArray(v.entries) || v.entries.length > SCAN_LIMITS.files + 32) error('source_workspace_scan_entries');
  let previous = '', originals = 0, present = 0, pathTotal = 0;
  for (const row of v.entries) {
    fields(row, ['path_hex', 'state', 'before', 'after']); pathTotal += pathBytes(row.path_hex).length;
    if (pathTotal > SCAN_LIMITS.pathsBytes + 32768 || row.path_hex <= previous ||
        !scope.roots_hex.some(r => within(r, row.path_hex)) || scope.exclude_hex.some(e => within(e, row.path_hex))) error('source_workspace_scan_entries');
    previous = row.path_hex;
    for (const side of [row.before, row.after]) if (side !== null) {
      fields(side, ['sha256', 'bytes', 'executable']); digest(side.sha256); integer(side.bytes, 0, 1048576);
      if (typeof side.executable !== 'boolean') error('source_workspace_scan_entries');
    }
    if (row.before !== null && ++originals > 32 || row.after !== null && ++present > SCAN_LIMITS.files ||
        row.before === null && row.after === null) error('source_workspace_scan_entries');
    const state = row.before === null ? 'unselected' : row.after === null ? 'deleted'
      : row.before.sha256 === row.after.sha256 && row.before.bytes === row.after.bytes && row.before.executable === row.after.executable ? 'unchanged' : 'modified';
    if (row.state !== state) error('source_workspace_scan_entries');
  }
  // Shape and lengths are bounded before encoding or taking an owned copy.
  const bytes = encode(v);
  if (bytes.length > SCAN_LIMITS.reportBytes || hash(bytes) !== approvedHash) error('source_workspace_scan_approval');
  return parse(bytes);
}
export function selectionFromWorkspaceScan(report, approvedHash, profiles = {}) {
  const reviewed = reviewedReport(report, approvedHash);
  fields(profiles, ['byte_profile', 'patch_profile'], []);
  if (Object.hasOwn(profiles, 'byte_profile') && profiles.byte_profile !== 'binary-safe-v1' ||
      Object.hasOwn(profiles, 'patch_profile') && !['trim-common-lines-v1', 'bounded-line-hunks-v1'].includes(profiles.patch_profile)) error('source_workspace_scan_profile');
  const selected = reviewed.entries.filter(r => r.state === 'modified' || r.state === 'deleted' || (r.state === 'unselected' && reviewed.scope.include_unselected));
  if (!selected.length || selected.length > 32) error('source_workspace_scan_capture_count');
  const paths = selected.map(r => r.path_hex);
  if (paths.some(p => paths.some(q => p !== q && within(p, q)))) error('source_workspace_scan_entries');
  return { paths_hex: paths, ...profiles, observations: workspaceObservations(selected.map(r => ({ path_hex: r.path_hex,
    sha256: r.after?.sha256 ?? null, bytes: r.after?.bytes ?? 0, executable: r.after?.executable ?? null })), paths) };
}
// Re-scan the same explicit scope without silently changing the reviewed intent.
// After this, capture checks the selected bytes again; files created later are
// not automatically added to the approved path set.
export async function prepareWorkspaceScanCapture(root, workspaceHash, report, approvedHash, profiles = {}, options = {}) {
  const { check, limits } = life(options), end = performance.now() + (options.timeoutMs ?? 30000);
  const reviewed = reviewedReport(report, approvedHash), selection = selectionFromWorkspaceScan(report, approvedHash, profiles);
  if (reviewed.directory !== root || reviewed.workspace_sha256 !== workspaceHash) error('source_workspace_scan_subject');
  const current = await scanSourceWorkspace(root, workspaceHash, reviewed.scope,
    { check, signal: options.signal, limits, timeoutMs: Math.max(1, Math.ceil(end - performance.now())) });
  check();
  if (current.scan_sha256 !== approvedHash) error('source_workspace_scan_stale');
  return selection;
}
// The injected boundary makes composition testable without replacing the native
// authoring kernel in production. The CLI always uses the default implementation.
export function workspaceScanCapturer(capture) {
  if (typeof capture !== 'function') error('source_workspace_scan_capture_boundary');
  return async (root, workspaceHash, report, approvedHash, output, profiles = {}, options = {}) => {
    normalized(root); normalized(output);
    if (root === output || output.startsWith(`${root}/`) || root.startsWith(`${output}/`)) error('source_workspace_overlapping_output');
    const { check } = life(options), end = performance.now() + (options.timeoutMs ?? 30000);
    const reviewed = reviewedReport(report, approvedHash), owned = { type: 'source_workspace_scan', scan_sha256: approvedHash, scan: reviewed };
    const remaining = () => { check(); return Math.max(1, Math.ceil(end - performance.now())); };
    const selection = await prepareWorkspaceScanCapture(root, workspaceHash, owned, approvedHash, profiles,
      { ...options, check, timeoutMs: remaining() });
    check();
    const result = await capture(root, workspaceHash, selection, output,
      { check, signal: options.signal, timeoutMs: remaining() });
    // Once the capture root exists, late cancellation is not proof of absence.
    if (!result || result.type !== 'source_workspace_change_capture' || result.directory !== output ||
        result.workspace_sha256 !== workspaceHash || result.source_commit !== reviewed.source_commit ||
        result.selected_path_count !== selection.paths_hex.length || result.changed_path_count !== selection.paths_hex.length ||
        result.unchanged_path_count !== 0 || result.repository_changed !== false || result.selected_files_only !== true ||
        result.source_material_untrusted !== true || typeof result.capture_sha256 !== 'string' ||
        !/^[0-9a-f]{64}$/.test(result.capture_sha256) || typeof result.draft_sha256 !== 'string' ||
        !/^[0-9a-f]{64}$/.test(result.draft_sha256)) {
      const e = new Error('source_workspace_scan_capture_reply'); e.code = e.message;
      e.publication_unconfirmed = { directory: output, workspace_sha256: workspaceHash, reviewed_scan_sha256: approvedHash };
      throw e;
    }
    return { type: 'source_workspace_scan_capture', directory: output, workspace_sha256: workspaceHash,
      reviewed_scan_sha256: approvedHash, discovery_scope: reviewed.scope, capture: result,
      repository_changed: false, source_executed: false, network_attempted: false };
  };
}
export const captureWorkspaceScan = workspaceScanCapturer(async (...args) =>
  (await import('./source_workspace_changes.mjs')).captureWorkspaceChanges(...args));
export { encode as encodeWorkspaceScan, hash as workspaceScanHash };
// Small owner-private control files; never use this as an unbounded JSON loader.
export async function readWorkspaceScanInput(path, options = {}) {
  normalized(path); const { check } = life(options), observations = [];
  const slash = path.lastIndexOf('/');
  await directory(Buffer.from(path.slice(0, slash) || '/'), check, observations);
  const file = await readFile(Buffer.from(path), SCAN_LIMITS.reportBytes + 4096, check, observations);
  if (!file) error('source_workspace_scan_input_missing');
  const result = parse(file.bytes); await recheck(observations, check); return result;
}
