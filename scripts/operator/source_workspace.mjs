// A trusted-local editing materialization, not a Git checkout or an authority.
// The independently retained root pins the immutable inputs; files/ is mutable.
import { constants as F } from 'node:fs';
import { lstat, realpath, open, mkdir } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { webcrypto } from 'node:crypto';
import { readSourcePackage, SOURCE_PACKAGE_BYTES } from '../../crates/fgit-node/src/smart_http/server/browser/search-context-package.mjs';
import { pathBytes } from '../../crates/fgit-node/src/smart_http/server/browser/source-patch.mjs';
import { oid } from '../../crates/fgit-node/src/smart_http/server/browser/pulls-core.mjs';
import { absolute, contains, directory, readPrivate, writeNew, syncDirectory } from './workflow_watch_io.mjs';
import { canonical, sha256 } from './source_changes.mjs';
import { parse } from './source_edit_wire.mjs';
import { ownSelectedSourceInput, mergeSelectedSourcePackages } from './source_package_union.mjs';

export const WORKSPACE_SCHEMA = 'frankengit-selected-source-workspace-v1';
export const WORKSPACE_LIMITS = Object.freeze({ files: 32, fileBytes: 1048576,
  totalBytes: 8388608, pathBytes: 32768, expectedBytes: 131072, manifestBytes: 131072 });
export { SOURCE_PACKAGE_BYTES };
export class SourceWorkspaceError extends Error {
  constructor(code) { super(code); this.name = 'SourceWorkspaceError'; this.code = code; }
}
export const fail = code => { throw new SourceWorkspaceError(code); };
export function fields(value, names, required = names) {
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
      Object.keys(value).some(k => !names.includes(k)) || required.some(k => !Object.hasOwn(value, k))) fail('source_workspace_fields');
}
export function pin(value) {
  if (typeof value !== 'string' || !/^[0-9a-f]{64}$/.test(value)) fail('source_workspace_pin');
  return value;
}
export function lifetime(options = {}) {
  fields(options, ['signal', 'timeoutMs', 'check'], []);
  if (typeof process.getuid !== 'function' || process.platform === 'win32') fail('source_workspace_posix_required');
  const timeout = options.timeoutMs ?? 30000, signal = options.signal, checkpoint = options.check;
  if (!Number.isSafeInteger(timeout) || timeout < 1 || timeout > 300000 ||
      signal !== undefined && !(signal instanceof AbortSignal) || checkpoint !== undefined && typeof checkpoint !== 'function') fail('source_workspace_options');
  const end = performance.now() + timeout;
  const check = () => { signal?.throwIfAborted(); if (performance.now() >= end) fail('source_workspace_deadline'); checkpoint?.(); };
  check(); return { check, signal, remaining: () => { check(); return Math.max(1, Math.ceil(end - performance.now())); } };
}
export function selectedPaths(values) {
  if (!Array.isArray(values) || !values.length || values.length > WORKSPACE_LIMITS.files) fail('source_workspace_paths');
  let total = 0;
  const paths = values.map(value => {
    const bytes = pathBytes(value);
    if ((total += bytes.length) > WORKSPACE_LIMITS.pathBytes || Buffer.from(bytes).toString('latin1').split('/').some(p => p.length > 255)) fail('source_workspace_path_budget');
    return value;
  }).sort();
  if (new Set(paths).size !== paths.length || paths.some(p => paths.some(q => p !== q && p.startsWith(`${q}2f`)))) fail('source_workspace_paths');
  return paths;
}
function expectation(value) {
  fields(value, ['format', 'commit', 'files']);
  const commit = oid(value.commit, value.format);
  if (!Array.isArray(value.files) || value.files.length > WORKSPACE_LIMITS.files) fail('source_workspace_expectation');
  const paths = selectedPaths(value.files.map(f => { fields(f, ['pathHex', 'blob']); return f.pathHex; }));
  // Preserve the shared verifier's strict sorted selection contract.
  if (paths.some((p, i) => p !== value.files[i].pathHex)) fail('source_workspace_expectation');
  return { format: value.format, commit, files: value.files.map(f => ({ pathHex: f.pathHex, blob: oid(f.blob, value.format) })) };
}
function manifest(bytes, expected, verified) {
  const expectedBytes = canonical(expected);
  if (expectedBytes.length > WORKSPACE_LIMITS.expectedBytes || verified.logicalSourceBytes > WORKSPACE_LIMITS.totalBytes ||
      verified.files.some(f => f.sourceBytes > WORKSPACE_LIMITS.fileBytes)) fail('source_workspace_source_budget');
  return { schema: WORKSPACE_SCHEMA, package_sha256: sha256(bytes), package_bytes: bytes.length,
    expected_sha256: sha256(expectedBytes), expected_bytes: expectedBytes.length,
    object_format: expected.format, source_commit: verified.commit, root_tree: verified.rootTree,
    files: verified.files.map(f => ({ path_hex: f.pathHex, blob: f.blob, executable: f.kind === 'executable', bytes: f.sourceBytes })) };
}
export const localPath = (root, hex = null) => Buffer.concat([Buffer.from(`${root}/files`),
  ...(hex === null ? [] : [Buffer.from('/'), Buffer.from(hex, 'hex')])]);
const same = (a, b) => ['dev', 'ino', 'mode', 'uid', 'gid', 'nlink', 'size', 'mtimeNs', 'ctimeNs'].every(k => a[k] === b[k]);
async function privateDirectory(path) {
  const stat = await lstat(path, { bigint: true });
  if (!stat.isDirectory() || stat.uid !== BigInt(process.getuid()) || (stat.mode & 0o7777n) !== 0o700n ||
      !(await realpath(path, { encoding: 'buffer' })).equals(Buffer.from(path))) fail('source_workspace_unsafe_directory');
  return stat;
}
async function writeFileNew(path, bytes, executable) {
  const handle = await open(path, F.O_CREAT | F.O_EXCL | F.O_WRONLY | F.O_NOFOLLOW, executable ? 0o700 : 0o600);
  try { await handle.writeFile(bytes); await handle.sync(); } finally { await handle.close(); }
}
async function syncRaw(path) {
  const handle = await open(path, F.O_RDONLY | F.O_DIRECTORY | F.O_NOFOLLOW);
  try { await handle.sync(); } finally { await handle.close(); }
}
function receipt(root, hash, value) {
  return { type: 'source_workspace_created', directory: root, workspace_sha256: hash,
    source_commit: value.source_commit, object_format: value.object_format, files: value.files.length,
    source_bytes: value.files.reduce((n, f) => n + f.bytes, 0),
    source_material_untrusted: true, complete_repository: false, source_executed: false,
    repository_changed: false, authority_verified: false };
}
export async function createSourceWorkspace(root, inputBytes, independentExpected, options = {}) {
  const time = lifetime(options); absolute(root);
  if (!(inputBytes instanceof Uint8Array) || !inputBytes.length || inputBytes.length > SOURCE_PACKAGE_BYTES ||
      !(inputBytes.buffer instanceof ArrayBuffer)) fail('source_workspace_package');
  // No caller-owned mutable bytes or expectation remain across the first await.
  const bytes = Buffer.from(inputBytes), expected = expectation(independentExpected);
  const loaded = await readSourcePackage(bytes, expected, webcrypto, time.check); time.check();
  return publishWorkspace(root, bytes, expected, loaded, time);
}
// One root-last owner for both initial materialization and expansion. Overrides
// are private owned snapshots from the predecessor, never caller-minted source.
async function publishWorkspace(root, bytes, expected, loaded, time, carried = new Map(), beforeRoot = null, expansion = null) {
  const value = manifest(bytes, expected, loaded.verified), encoded = canonical(value);
  if (encoded.length > WORKSPACE_LIMITS.manifestBytes) fail('source_workspace_manifest_budget');
  const hash = sha256(encoded), answer = { ...receipt(root, hash, value), ...(expansion ? {
    type: 'source_workspace_expanded', expansion, original_workspace_changed: false,
  } : {}) };
  const bodies = new Map(loaded.package.blobs.map(b => [b.oid, b.bytesHex])), outputs = new Map();
  let total = 0;
  for (const f of value.files) {
    const file = carried.has(f.path_hex) ? carried.get(f.path_hex)
      : { bytes: Buffer.from(bodies.get(f.blob), 'hex'), executable: f.executable };
    total += file?.bytes.length ?? 0;
    if (total > WORKSPACE_LIMITS.totalBytes) fail('source_workspace_materialization_budget');
    outputs.set(f.path_hex, file);
  }
  await directory(dirname(root)); time.check();
  await beforeRoot?.(); time.check();
  // mkdir is the exclusive ownership boundary. A competing creator cannot
  // replace an existing slot, and no interrupted slot is deleted or recycled.
  await mkdir(root, { mode: 0o700 });
  try {
    await directory(root); await syncDirectory(dirname(root)); time.check();
    await writeNew(join(root, 'source.json'), bytes);
    await writeNew(join(root, 'expected.json'), canonical(expected)); time.check();
    const dirs = new Set([null]);
    for (const file of value.files) {
      const raw = Buffer.from(file.path_hex, 'hex');
      for (let at = 0; at < raw.length; at++) if (raw[at] === 47) dirs.add(raw.subarray(0, at).toString('hex'));
    }
    const ordered = [...dirs].sort((a, b) => a === b ? 0 : a === null ? -1 : b === null ? 1 : a < b ? -1 : 1);
    for (const hex of ordered) { time.check(); await mkdir(localPath(root, hex), { mode: 0o700 }); await privateDirectory(localPath(root, hex)); }
    for (const [path, f] of outputs) { time.check(); if (f) await writeFileNew(localPath(root, path), f.bytes, f.executable); }
    // Read every owned output before the last-written root marks completion.
    const snapshot = await readWorkspaceFiles(root, value.files.map(f => f.path_hex), { check: time.check, timeoutMs: time.remaining() });
    for (const [path, wanted] of outputs) {
      const actual = snapshot.files.get(path);
      if (wanted === null ? actual !== null : !actual || actual.executable !== wanted.executable ||
          !actual.bytes.equals(wanted.bytes)) fail('source_workspace_readback');
    }
    if (!bytes.equals(await readPrivate(join(root, 'source.json'), SOURCE_PACKAGE_BYTES)) ||
        !canonical(expected).equals(await readPrivate(join(root, 'expected.json'), WORKSPACE_LIMITS.expectedBytes))) fail('source_workspace_readback');
    for (const hex of ordered.reverse()) { time.check(); await syncRaw(localPath(root, hex)); }
    await snapshot.recheck(); await beforeRoot?.(); time.check();
    // Once root publication begins, drain sync/readback; a late stop does not
    // imply absence. The returned pin always names these exact completed bytes.
    await writeNew(join(root, 'manifest.json'), encoded);
    if (!encoded.equals(await readPrivate(join(root, 'manifest.json'), WORKSPACE_LIMITS.manifestBytes))) fail('source_workspace_readback');
    await syncDirectory(root); await syncDirectory(dirname(root));
    return { ...answer, stop_requested: time.signal?.aborted ?? false };
  } catch (error) { error.publication_unconfirmed = answer; throw error; }
}
// Admit additional independently selected source WITHOUT resetting local edits,
// changing the immutable commit, scanning unselected paths or modifying the old
// workspace. The create-only result is an ordinary v1 workspace, not a rebase.
export async function expandSourceWorkspace(root, workspaceHash, additionalBytes, additionalExpected, output, options = {}) {
  const time = lifetime(options); absolute(root); absolute(output); pin(workspaceHash);
  if (contains(root, output) || contains(output, root)) fail('source_workspace_overlapping_output');
  const additional = ownSelectedSourceInput(additionalBytes, additionalExpected);
  // Check host path limits too before any input I/O; the source package itself
  // supports byte components larger than a POSIX materialization can create.
  selectedPaths(additional.expected.files.map(f => f.pathHex));
  await directory(dirname(output));
  try { await lstat(output); fail('source_workspace_output_exists'); } catch (e) { if (e.code !== 'ENOENT') throw e; }
  const baseline = await loadSourceWorkspace(root, workspaceHash, { check: time.check, timeoutMs: time.remaining() });
  const merged = await mergeSelectedSourcePackages(baseline.packageBytes, baseline.expected,
    additional.bytes, additional.expected, { check: time.check, signal: time.signal, timeoutMs: time.remaining() });
  const oldPaths = new Set(baseline.expected.files.map(f => f.pathHex));
  const added = merged.expected.files.filter(f => !oldPaths.has(f.pathHex)).map(f => f.pathHex);
  if (!added.length) fail('source_workspace_no_expansion');
  selectedPaths(merged.expected.files.map(f => f.pathHex));
  // A newly selected path already present locally may be untracked user work.
  // Refuse instead of silently replacing it with the fetched baseline version.
  const snapshot = await readWorkspaceFiles(root, merged.expected.files.map(f => f.pathHex),
    { check: time.check, timeoutMs: time.remaining() });
  if (added.some(p => snapshot.files.get(p) !== null)) fail('source_workspace_expansion_occupied');
  const carried = new Map([...snapshot.files].filter(([p]) => oldPaths.has(p)));
  const loaded = await readSourcePackage(merged.packageBytes, merged.expected, webcrypto, time.check);
  await snapshot.recheck(); time.check();
  const expansion = { ...merged.provenance, original_workspace_sha256: workspaceHash,
    added_paths_hex: added, preserved_selected_paths: carried.size,
    preserved_deletions: [...carried.values()].filter(f => f === null).length,
    unselected_local_files_copied: false, atomic_filesystem_snapshot: false };
  return publishWorkspace(output, merged.packageBytes, merged.expected, loaded, time, carried, snapshot.recheck, expansion);
}
export async function loadSourceWorkspace(root, expectedHash, options = {}) {
  const time = lifetime(options); absolute(root); pin(expectedHash);
  await directory(root); time.check();
  const rootBytes = await readPrivate(join(root, 'manifest.json'), WORKSPACE_LIMITS.manifestBytes);
  if (sha256(rootBytes) !== expectedHash) fail('source_workspace_manifest_changed');
  const raw = parse(rootBytes, WORKSPACE_LIMITS.manifestBytes);
  fields(raw, ['schema', 'package_sha256', 'package_bytes', 'expected_sha256', 'expected_bytes', 'object_format', 'source_commit', 'root_tree', 'files']);
  if (raw.schema !== WORKSPACE_SCHEMA) fail('source_workspace_schema');
  const bytes = await readPrivate(join(root, 'source.json'), SOURCE_PACKAGE_BYTES); time.check();
  const expectedBytes = await readPrivate(join(root, 'expected.json'), WORKSPACE_LIMITS.expectedBytes); time.check();
  if (sha256(bytes) !== raw.package_sha256 || bytes.length !== raw.package_bytes ||
      sha256(expectedBytes) !== raw.expected_sha256 || expectedBytes.length !== raw.expected_bytes) fail('source_workspace_baseline_changed');
  const expected = expectation(parse(expectedBytes, WORKSPACE_LIMITS.expectedBytes));
  const loaded = await readSourcePackage(bytes, expected, webcrypto, time.check); time.check();
  const value = manifest(bytes, expected, loaded.verified);
  if (!canonical(value).equals(rootBytes) || !canonical(expected).equals(expectedBytes)) fail('source_workspace_manifest_changed');
  await privateDirectory(localPath(root)); time.check();
  return { packageBytes: bytes, expected, manifest: value, workspace_sha256: expectedHash, verified: loaded.verified };
}
// Only explicit paths are opened. No recursive scan, ignore rule, executable or
// repository content can widen the selection. Every name stays a byte path.
export async function readWorkspaceFiles(root, inputPaths, options = {}) {
  const time = lifetime(options), paths = selectedPaths(inputPaths); absolute(root);
  await directory(root); time.check();
  const observations = new Map(), files = new Map(); let total = 0;
  const remember = (path, stat) => {
    const key = path.toString('hex'), old = observations.get(key);
    if (old && (old.stat === null ? stat !== null : stat === null || !same(old.stat, stat))) fail('source_workspace_changed');
    if (!old) observations.set(key, { path, stat });
  };
  const inspectDirectory = async path => {
    time.check();
    try { const stat = await privateDirectory(path); remember(path, stat); return true; }
    catch (e) { if (e.code !== 'ENOENT') throw e; remember(path, null); return false; }
  };
  if (!await inspectDirectory(localPath(root))) fail('source_workspace_missing_files');
  for (const hex of paths) {
    time.check(); const raw = Buffer.from(hex, 'hex'); let absent = false;
    for (let at = 0; at < raw.length; at++) if (raw[at] === 47 && !await inspectDirectory(localPath(root, raw.subarray(0, at).toString('hex')))) { absent = true; break; }
    if (absent) { files.set(hex, null); continue; }
    const path = localPath(root, hex); let named;
    try { named = await lstat(path, { bigint: true }); }
    catch (e) { if (e.code !== 'ENOENT') throw e; remember(path, null); files.set(hex, null); continue; }
    const valid = s => s.isFile() && s.uid === BigInt(process.getuid()) && s.nlink === 1n &&
      [0o600n, 0o700n].includes(s.mode & 0o7777n) && s.size <= BigInt(WORKSPACE_LIMITS.fileBytes);
    if (!valid(named) || (total += Number(named.size)) > WORKSPACE_LIMITS.totalBytes) fail('source_workspace_unsafe_file_or_budget');
    const handle = await open(path, F.O_RDONLY | F.O_NOFOLLOW | F.O_NONBLOCK);
    try {
      const before = await handle.stat({ bigint: true }); time.check();
      if (!valid(before) || !same(before, named)) fail('source_workspace_changed');
      const bytes = Buffer.alloc(Number(before.size)); let at = 0;
      while (at < bytes.length) {
        time.check(); const part = await handle.read(bytes, at, Math.min(65536, bytes.length - at), at); time.check();
        if (!part.bytesRead) fail('source_workspace_changed'); at += part.bytesRead;
      }
      const extra = await handle.read(Buffer.alloc(1), 0, 1, at);
      const after = await handle.stat({ bigint: true }), current = await lstat(path, { bigint: true }); time.check();
      if (extra.bytesRead || !same(before, after) || !same(before, current) ||
          !(await realpath(path, { encoding: 'buffer' })).equals(path)) fail('source_workspace_changed');
      remember(path, before); files.set(hex, { bytes, executable: (before.mode & 0o100n) !== 0n });
    } finally { await handle.close(); }
  }
  const recheck = async () => {
    for (const { path, stat } of observations.values()) {
      time.check(); let current;
      try { current = await lstat(path, { bigint: true }); }
      catch (e) { if (e.code !== 'ENOENT' || stat !== null) throw e; current = null; }
      if (stat === null ? current !== null : current === null || !same(stat, current)) fail('source_workspace_changed');
    }
    time.check();
  };
  await recheck(); return { files, recheck, bytesRead: total };
}
export async function inspectSourceWorkspace(root, expectedHash, options = {}) {
  const time = lifetime(options);
  const baseline = await loadSourceWorkspace(root, expectedHash, { check: time.check, timeoutMs: time.remaining() });
  const snapshot = await readWorkspaceFiles(root, baseline.manifest.files.map(f => f.path_hex), { check: time.check, timeoutMs: time.remaining() });
  const original = new Map(JSON.parse(baseline.packageBytes.toString('utf8')).blobs.map(b => [b.oid, b.bytesHex]));
  const entries = baseline.manifest.files.map(f => {
    const file = snapshot.files.get(f.path_hex), state = !file ? 'deleted' : file.bytes.toString('hex') === original.get(f.blob) &&
      file.executable === f.executable ? 'unchanged' : 'modified';
    return { path_hex: f.path_hex, state, bytes: file?.bytes.length ?? 0, executable: file?.executable ?? null };
  });
  await snapshot.recheck(); time.check();
  return { type: 'source_workspace_status', workspace_sha256: expectedHash, source_commit: baseline.manifest.source_commit,
    entries, bytes_read: snapshot.bytesRead, selected_files_only: true, unselected_paths_examined: false,
    atomic_filesystem_snapshot: false, repository_changed: false, source_material_untrusted: true };
}
// Deterministic baseline data construction; callers must supply a freshly
// verified package result. The returned manifest alone is never an authority.
export { manifest as workspaceManifest };
