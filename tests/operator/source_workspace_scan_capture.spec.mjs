// Run with --experimental-vm-modules. Execute the actual capture source, with
// explicit fixtures ONLY for its pre-existing workspace/authoring services.
// These tests do not establish native membership, tree derivation or Rust fg.
import test from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs/promises';
import { constants as F } from 'node:fs';
import * as path from 'node:path';
import { webcrypto } from 'node:crypto';
import { SourceTextModule, SyntheticModule, createContext } from 'node:vm';
import { performance } from 'node:perf_hooks';
import * as scanner from '../../scripts/operator/source_workspace_scan.mjs';
import { fixture } from './source_workspace_scan.fixture.mjs';
const { encodeWorkspaceScan: encode, workspaceScanHash: hash } = scanner;
const hex = s => Buffer.from(s).toString('hex');
const fail = code => { const e = new Error(code); e.code = code; throw e; };
function fields(v, names, required = names) {
  if (!v || typeof v !== 'object' || Array.isArray(v) || Object.keys(v).some(k => !names.includes(k)) || required.some(k => !Object.hasOwn(v, k))) fail('fixture_fields');
}
function manifest(bytes, exp, verified) {
  return { schema: 'frankengit-selected-source-workspace-v1', package_sha256: hash(bytes), package_bytes: bytes.length,
    expected_sha256: hash(encode(exp)), expected_bytes: encode(exp).length, object_format: exp.format,
    source_commit: verified.commit, root_tree: verified.rootTree,
    files: verified.files.map(f => ({ path_hex: f.pathHex, blob: f.blob, executable: f.kind === 'executable', bytes: f.sourceBytes })) };
}
async function captureModule(f, hooks = {}) {
  const counters = { absence: 0, reads: 0, builds: 0, membership: 0 };
  const limits = { expectedBytes: 131072, manifestBytes: 131072 }, sourceLimit = 33554432;
  const lifetime = options => {
    const end = performance.now() + (options.timeoutMs ?? 30000);
    const check = () => { options.signal?.throwIfAborted(); options.check?.(); if (performance.now() >= end) fail('fixture_deadline'); };
    check(); return { check, signal: options.signal, remaining: () => { check(); return Math.max(1, Math.ceil(end - performance.now())); } };
  };
  const readSourcePackage = async bytes => {
    counters.membership++; const pkg = JSON.parse(Buffer.from(bytes).toString('utf8'));
    const blobs = new Map(pkg.blobs.map(b => [b.oid, b.bytesHex]));
    return { package: pkg, verified: { commit: pkg.membership.commit.oid,
      rootTree: pkg.membership.trees.find(t => t.pathHex === null).oid,
      files: pkg.membership.files.map(r => ({ ...r, sourceBytes: blobs.get(r.blob).length / 2 })) } };
  };
  const readWorkspaceFiles = async (root, paths) => {
    counters.reads++; const files = new Map();
    for (const p of paths) {
      try { const name = Buffer.concat([Buffer.from(`${root}/files/`), Buffer.from(p, 'hex')]);
        const stat = await fs.lstat(name); files.set(p, { bytes: await fs.readFile(name), executable: Boolean(stat.mode & 0o100) }); }
      catch (e) { if (e.code !== 'ENOENT') throw e; files.set(p, null); }
    }
    await hooks.afterRead?.(files);
    return { files, recheck: async () => { await hooks.recheck?.(); }, bytesRead: [...files.values()].reduce((n, f) => n + (f?.bytes.length ?? 0), 0) };
  };
  const readPrivate = async (name, max) => { const b = await fs.readFile(name); if (b.length > max) fail('fixture_budget'); return b; };
  const writeNew = async (name, b) => { const h = await fs.open(name, F.O_WRONLY | F.O_CREAT | F.O_EXCL | F.O_NOFOLLOW, 0o600); try { await h.writeFile(b); await h.sync(); } finally { await h.close(); } };
  const directory = async name => { const s = await fs.lstat(name); if (!s.isDirectory() || (s.mode & 0o777) !== 0o700) fail('fixture_directory'); };
  const services = {
    'node:fs/promises': fs, 'node:path': path, 'node:crypto': { webcrypto },
    './source_workspace.mjs': {
      loadSourceWorkspace: async (root, pin) => { assert.equal(root, f.root); assert.equal(pin, f.pin);
        return { manifest: f.manifest, packageBytes: await fs.readFile(path.join(root, 'source.json')), expected: f.expected }; },
      readWorkspaceFiles, selectedPaths: paths => { assert(paths.length > 0 && paths.length <= 32); return [...paths].sort(); },
      workspaceManifest: manifest, lifetime, fields, pin: value => { assert.match(value, /^[0-9a-f]{64}$/); return value; }, fail,
      WORKSPACE_LIMITS: limits, SOURCE_PACKAGE_BYTES: sourceLimit,
    },
    './source_changes.mjs': {
      buildSourceChanges: async (bytes, exp, changes) => { counters.builds++; await hooks.build?.();
        // An explicitly non-native authoring oracle. This suite tests capture
        // ownership/guards, not the Git algorithm behind this service boundary.
        return { bytes: encode(changes), manifest: { source_commit: exp.commit, changes_sha256: hash(encode(changes)),
          no_op_paths_hex: [] }, tree: { afterTree: f.manifest.root_tree } }; },
      canonical: encode, sha256: hash, CHANGES_SCHEMA: 'frankengit-source-changes-v1', CHANGES_INPUT_BYTES: 10485760,
      sourceByteProfile: value => { if (value !== 'binary-safe-v1') fail('fixture_profile'); return value; },
      sourcePatchProfile: value => { if (!['trim-common-lines-v1', 'bounded-line-hunks-v1'].includes(value)) fail('fixture_profile'); return value; },
    },
    '../../crates/fgit-node/src/smart_http/server/browser/search-context-package.mjs': { readSourcePackage },
    '../../crates/fgit-node/src/smart_http/server/browser/search-context-membership.mjs': {
      verifyPathAbsence: async (...args) => { counters.absence++; await hooks.absence?.(...args); },
    },
    './workflow_watch_io.mjs': { absolute: value => assert.equal(path.resolve(value), value),
      contains: (a, b) => a === b || b.startsWith(`${a}/`), directory, readPrivate, writeNew,
      syncDirectory: async name => { const h = await fs.open(name, F.O_RDONLY | F.O_DIRECTORY); try { await h.sync(); } finally { await h.close(); } },
    },
    './source_edit_wire.mjs': { parse: b => JSON.parse(Buffer.from(b).toString('utf8')) },
    './source_workspace_scan.mjs': scanner,
  };
  const source = await fs.readFile(new URL('../../scripts/operator/source_workspace_changes.mjs', import.meta.url), 'utf8');
  const context = createContext({ Buffer, Uint8Array, TextDecoder, performance, process, AbortSignal });
  const module = new SourceTextModule(source, { context, identifier: 'actual-source-workspace-changes' });
  await module.link(name => {
    const exports = services[name]; assert(exports, `unexpected dependency ${name}`);
    return new SyntheticModule(Object.keys(exports), function () { for (const [k, v] of Object.entries(exports)) this.setExport(k, v); }, { context });
  });
  await module.evaluate(); return { api: module.namespace, counters };
}
for (const format of ['sha1', 'sha256']) test(`${format}: actual capture/inspect code retains reviewed observations and independent baseline`, async t => {
  const f = await fixture(t, undefined, format); await f.put('src/a', Buffer.from([0, 255])); await fs.rm(f.local('README')); await f.put('new', 'new');
  const report = await f.scan({ roots_hex: [''], include_unselected: true });
  const { api, counters } = await captureModule(f), capture = scanner.workspaceScanCapturer(api.captureWorkspaceChanges), out = path.join(f.parent, 'capture');
  const result = await capture(f.root, f.pin, report, report.scan_sha256, out, { byte_profile: 'binary-safe-v1', patch_profile: 'bounded-line-hunks-v1' });
  const selection = JSON.parse(await fs.readFile(path.join(out, 'paths.json'))), changes = JSON.parse(await fs.readFile(path.join(out, 'changes.json')));
  assert.equal(selection.observations.length, 3); assert.equal(changes.changes.length, 3); assert.equal(counters.absence, 1);
  assert.equal(changes.changes.find(r => r.path_hex === hex('src/a')).content_hex, '00ff');
  await fs.rm(f.root, { recursive: true });
  const inspected = await api.inspectWorkspaceChangeCapture(out, result.capture.capture_sha256);
  assert.equal(inspected.offline_recomputed, true); assert.equal(inspected.capture_sha256, result.capture.capture_sha256);
  assert.equal(counters.membership, 1); assert.equal(counters.builds, 2);
});
for (const [name, mutate] of [
  ['contents', async f => f.put('src/a', 'later')], ['mode', async f => fs.chmod(f.local('src/a'), 0o700)],
  ['missing file', async f => fs.rm(f.local('src/a'))],
]) test(`actual collector rejects ${name} changed after scan preflight before building or publishing`, async t => {
  const f = await fixture(t); await f.put('src/a', 'reviewed'); const r = await f.scan();
  const selection = await scanner.prepareWorkspaceScanCapture(f.root, f.pin, r, r.scan_sha256); await mutate(f);
  const { api, counters } = await captureModule(f), out = path.join(f.parent, 'capture');
  await assert.rejects(api.captureWorkspaceChanges(f.root, f.pin, selection, out), /scan_changed/);
  assert.equal(counters.builds, 0); await assert.rejects(fs.lstat(out), { code: 'ENOENT' });
});
test('a reviewed deletion cannot become an empty replacement during capture', async t => {
  const f = await fixture(t); await fs.rm(f.local('README')); const r = await f.scan(), selection = scanner.selectionFromWorkspaceScan(r, r.scan_sha256);
  await f.put('README', ''); const { api } = await captureModule(f);
  await assert.rejects(api.collectWorkspaceChanges(f.root, f.pin, selection), /scan_changed/);
});
test('unselected local files still require the original native absence service before reading', async t => {
  const f = await fixture(t); await f.put('new', 'new'); const r = await f.scan({ roots_hex: [''], include_unselected: true });
  const { api, counters } = await captureModule(f, { absence: async () => { throw new Error('native absence fixture refusal'); } });
  await assert.rejects(api.collectWorkspaceChanges(f.root, f.pin, scanner.selectionFromWorkspaceScan(r, r.scan_sha256)), /absence/);
  assert.equal(counters.absence, 1); assert.equal(counters.reads, 0); assert.equal(counters.builds, 0);
});
test('legacy explicit selections keep their original bytes and no observations field', async t => {
  const f = await fixture(t); await f.put('src/a', 'edit'); const { api } = await captureModule(f);
  const input = { paths_hex: [hex('src/a')] }, collected = await api.collectWorkspaceChanges(f.root, f.pin, input);
  assert.equal(collected.payloads['paths.json'].toString(), encode(input).toString());
  assert.equal(Object.hasOwn(collected.selection, 'observations'), false);
});
test('offline inspection rejects substituted reviewed hashes even after all local root checksums are rebuilt', async t => {
  const f = await fixture(t); await f.put('src/a', 'reviewed'); const r = await f.scan(), { api } = await captureModule(f), out = path.join(f.parent, 'capture');
  await api.captureWorkspaceChanges(f.root, f.pin, scanner.selectionFromWorkspaceScan(r, r.scan_sha256), out);
  const selected = JSON.parse(await fs.readFile(path.join(out, 'paths.json'))); selected.observations[0].sha256 = '0'.repeat(64);
  const bytes = encode(selected); await fs.writeFile(path.join(out, 'paths.json'), bytes);
  const m = JSON.parse(await fs.readFile(path.join(out, 'manifest.json'))), row = m.payloads.find(p => p.name === 'paths.json');
  row.sha256 = hash(bytes); row.bytes = bytes.length; await fs.writeFile(path.join(out, 'manifest.json'), encode(m));
  await assert.rejects(api.inspectWorkspaceChangeCapture(out, hash(encode(m))), /scan_changed/);
});
test('the real collector owns observation rows before asynchronous baseline reads', async t => {
  const f = await fixture(t); await f.put('src/a', 'reviewed'); const r = await f.scan(), { api } = await captureModule(f);
  const selection = scanner.selectionFromWorkspaceScan(r, r.scan_sha256), pending = api.collectWorkspaceChanges(f.root, f.pin, selection);
  selection.observations[0].sha256 = '0'.repeat(64);
  const collected = await pending; assert.notEqual(collected.selection.observations[0].sha256, selection.observations[0].sha256);
});
test('offline inspection also checks observations for selected but unchanged files', async t => {
  const f = await fixture(t); await f.put('src/a', 'reviewed'); const r = await f.scan(), { api } = await captureModule(f), out = path.join(f.parent, 'capture');
  const selection = { paths_hex: r.scan.entries.map(e => e.path_hex), observations: r.scan.entries.map(e => ({ path_hex: e.path_hex, ...e.after })) };
  const result = await api.captureWorkspaceChanges(f.root, f.pin, selection, out);
  assert.equal(result.unchanged_path_count, 1);
  const checked = await api.inspectWorkspaceChangeCapture(out, result.capture_sha256); assert.equal(checked.unchanged_path_count, 1);
  const saved = JSON.parse(await fs.readFile(path.join(out, 'paths.json'))); saved.observations[0].executable = true;
  const bytes = encode(saved); await fs.writeFile(path.join(out, 'paths.json'), bytes);
  const m = JSON.parse(await fs.readFile(path.join(out, 'manifest.json'))), row = m.payloads.find(p => p.name === 'paths.json');
  row.sha256 = hash(bytes); row.bytes = bytes.length; await fs.writeFile(path.join(out, 'manifest.json'), encode(m));
  await assert.rejects(api.inspectWorkspaceChangeCapture(out, hash(encode(m))), /scan_changed/);
});
