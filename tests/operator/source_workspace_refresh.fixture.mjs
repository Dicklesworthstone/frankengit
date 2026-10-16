// Explicit source-service fixtures, NOT the native membership/tree verifier.
// The tests execute the complete production workspace module and unchanged
// POSIX custody helper. Only its existing source/codec service imports change.
import { createHash } from 'node:crypto';
import { readFile, mkdtemp, rm, writeFile, chmod, unlink } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import assert from 'node:assert/strict';

export const canonical = value => Buffer.from(`${JSON.stringify(value)}\n`);
export const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');
export const SOURCE_PACKAGE_BYTES = 32 * 1024 * 1024;
export const hooks = { verify: null };
export function pathBytes(hex) {
  assert.equal(typeof hex, 'string'); assert.match(hex, /^(?:[0-9a-f]{2})+$/);
  const bytes = Buffer.from(hex, 'hex'); assert(bytes.length <= 4096 && !bytes.includes(0));
  const parts = bytes.toString('latin1').split('/');
  assert(parts.length <= 64 && parts.every(p => p && !['.', '..', '.git'].includes(p.toLowerCase())));
  return bytes;
}
export function oid(value, format) {
  assert(['sha1', 'sha256'].includes(format));
  assert.match(value, new RegExp(`^[0-9a-f]{${format === 'sha1' ? 40 : 64}}$`)); return value;
}
export function parse(bytes, maximum) { assert(bytes.length <= maximum); return JSON.parse(bytes.toString()); }
export function ownSelectedSourceInput(bytes, expected) {
  assert(bytes instanceof Uint8Array && bytes.buffer instanceof ArrayBuffer && bytes.length && bytes.length <= SOURCE_PACKAGE_BYTES);
  const selected = structuredClone(expected); oid(selected.commit, selected.format);
  assert(selected.files.length && selected.files.length <= 32);
  for (const f of selected.files) { pathBytes(f.pathHex); oid(f.blob, selected.format); }
  return { bytes: Buffer.from(bytes), expected: selected };
}
export async function mergeSelectedSourcePackages() { throw new Error('Unexpected union service call'); }
export async function readSourcePackage(bytes, expected, crypto, check) {
  check(); await hooks.verify?.(bytes, expected); check();
  const pkg = parse(bytes, SOURCE_PACKAGE_BYTES);
  assert.equal(pkg.schema, 'workspace-refresh-test-source-service-v1');
  assert.equal(pkg.membership.commit.oid, expected.commit);
  assert.equal(pkg.membership.objectFormat, expected.format);
  assert.deepEqual(pkg.membership.files.map(f => ({ pathHex: f.pathHex, blob: f.blob })), expected.files);
  const bodies = new Map(pkg.blobs.map(b => [b.oid, Buffer.from(b.bytesHex, 'hex')]));
  for (const [id, bytes] of bodies) assert.equal(id, nativeHash('blob', bytes, expected.format));
  const files = pkg.membership.files.map(f => ({ ...f, sourceBytes: bodies.get(f.blob).length }));
  return { package: pkg, verified: { commit: expected.commit, rootTree: pkg.rootTree,
    files, logicalSourceBytes: files.reduce((sum, f) => sum + f.sourceBytes, 0) } };
}
export function nativeHash(type, bytes, format) {
  return createHash(format).update(`${type} ${bytes.length}\0`).update(bytes).digest('hex');
}
export function source(rows, format = 'sha1', marker = 'base') {
  const blobs = new Map(), files = rows.map(row => {
    const bytes = Buffer.from(row.bytes), blob = nativeHash('blob', bytes, format);
    blobs.set(blob, { oid: blob, bytesHex: bytes.toString('hex') });
    return { pathHex: row.path ?? '61', blob, kind: row.executable ? 'executable' : 'file' };
  }).sort((a, b) => a.pathHex < b.pathHex ? -1 : 1);
  const rootTree = nativeHash('tree', canonical(files), format);
  const commit = nativeHash('commit', Buffer.from(`${rootTree}:${marker}`), format);
  const expected = { format, commit, files: files.map(f => ({ pathHex: f.pathHex, blob: f.blob })) };
  const bytes = canonical({ schema: 'workspace-refresh-test-source-service-v1', rootTree,
    membership: { objectFormat: format, commit: { oid: commit }, files },
    blobs: [...blobs.values()].sort((a, b) => a.oid < b.oid ? -1 : 1) });
  return { bytes, expected };
}
export async function loadWorkspaceModule() {
  const url = new URL('../../scripts/operator/source_workspace.mjs', import.meta.url);
  let code = await readFile(url, 'utf8');
  // Rewrite specifiers only; do not extract functions or modify any function body.
  code = code.replace(/from '([^']+)'/g, (match, specifier) => {
    if (specifier.startsWith('node:')) return match;
    return `from '${specifier === './workflow_watch_io.mjs'
      ? new URL('../../scripts/operator/workflow_watch_io.mjs', import.meta.url).href : import.meta.url}'`;
  });
  return import(`data:text/javascript;base64,${Buffer.from(code).toString('base64')}`);
}
export let workspace, WORKSPACE_LIMITS;
export async function initWorkspace() { workspace = await loadWorkspaceModule(); WORKSPACE_LIMITS = workspace.WORKSPACE_LIMITS; return workspace; }
export async function setup(t, rows = [{ bytes: 'base' }], format = 'sha1') {
  const parent = await mkdtemp(join(tmpdir(), 'fg-refresh-')); await chmod(parent, 0o700);
  t.after(() => rm(parent, { recursive: true, force: true }));
  const root = join(parent, 'original'), output = join(parent, 'refreshed'), original = source(rows, format);
  const created = await workspace.createSourceWorkspace(root, original.bytes, original.expected);
  const preview = (next, options) => workspace.previewSourceWorkspaceRefresh(root, created.workspace_sha256, next.bytes, next.expected, options);
  const apply = (next, hash, options) => workspace.refreshSourceWorkspace(root, created.workspace_sha256, next.bytes, next.expected, output, hash, options);
  return { parent, root, output, original, created, preview, apply, format };
}
export async function local(f, path, bytes, executable = false) {
  const name = workspace.localPath(f.root, path);
  if (bytes === null) await unlink(name);
  else { await writeFile(name, bytes); await chmod(name, executable ? 0o700 : 0o600); }
}

// Facades connect the unchanged CLI body to the full workspace module above.
export const createSourceWorkspace = (...a) => workspace.createSourceWorkspace(...a);
export const expandSourceWorkspace = (...a) => workspace.expandSourceWorkspace(...a);
export const inspectSourceWorkspace = (...a) => workspace.inspectSourceWorkspace(...a);
export const previewSourceWorkspaceRefresh = (...a) => workspace.previewSourceWorkspaceRefresh(...a);
export const refreshSourceWorkspace = (...a) => workspace.refreshSourceWorkspace(...a);
export const lifetime = (...a) => workspace.lifetime(...a);
export const pin = (...a) => workspace.pin(...a);
export const fail = (...a) => workspace.fail(...a);
export async function captureWorkspaceChanges() { throw new Error('Unexpected capture call'); }
export async function inspectWorkspaceChangeCapture() { throw new Error('Unexpected capture inspection'); }
export async function loadCli() {
  const url = new URL('../../scripts/fg_source_workspace.mjs', import.meta.url);
  const code = (await readFile(url, 'utf8')).replace(/from '([^']+)'/g, (match, specifier) => {
    if (specifier.startsWith('node:')) return match;
    return `from '${specifier === './operator/workflow_watch_io.mjs'
      ? new URL('../../scripts/operator/workflow_watch_io.mjs', import.meta.url).href : import.meta.url}'`;
  });
  return import(`data:text/javascript;base64,${Buffer.from(code).toString('base64')}`);
}
