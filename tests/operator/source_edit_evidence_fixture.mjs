// Git constructs the independent basis and candidate. The HTTP peer only emits
// explicit native response schemas: it is not Rust patch/admission execution.
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { peer, TOKEN, digest } from './source_edit_fixture.mjs';
export { TOKEN, PRINCIPAL } from './source_edit_fixture.mjs';
const cache = new Map();
const hex = bytes => Buffer.from(bytes).toString('hex');
export function evidenceFixture(format = 'sha1', scenario = 'text') {
  const key = `${format}:${scenario}`;
  if (cache.has(key)) return structuredClone(cache.get(key));
  const dir = mkdtempSync(join(tmpdir(), 'fg-evidence-git-'));
  try {
    const git = (args, input) => execFileSync('git', ['-C', dir, ...args], { input,
      env: { ...process.env, GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: '/dev/null' } });
    const id = (args, input) => git(args, input).toString().trim();
    git(['init', '--quiet', `--object-format=${format}`]);
    const write = (kind, bytes) => id(['hash-object', '-w', '-t', kind, '--stdin'], bytes);
    const tree = rows => id(['mktree', '-z'], Buffer.concat(rows.map(([name, mode, oid]) =>
      Buffer.concat([Buffer.from(`${mode} ${mode === '040000' ? 'tree' : 'blob'} ${oid}\t`), Buffer.from(name), Buffer.from([0])]))));
    const path = scenario === 'raw' ? Buffer.from([255, 46, 114, 115]) : Buffer.from(scenario === 'nested-delete' ? 'src/file' : 'file');
    const old = scenario === 'binary' ? Buffer.from('old\0data') : scenario === 'empty' ? Buffer.alloc(0) : Buffer.from('keep\r\nold\r\nlast');
    const next = ['delete', 'nested-delete'].includes(scenario) ? null : scenario === 'mode' ? old :
      scenario === 'binary' ? Buffer.from('new\0data') : scenario === 'empty' ? Buffer.from('new\n') : Buffer.from('keep\r\nnew\r\nlast');
    const beforeMode = '100644', afterMode = scenario === 'mode' ? '100755' : '100644';
    const oldId = write('blob', old), newId = next === null ? null : write('blob', next);
    const sibling = write('blob', Buffer.from('unchanged\n')), hidden = write('blob', Buffer.from('hidden\n'));
    const nested = scenario === 'nested-delete', inner = nested ? tree([['file', beforeMode, oldId]]) : null;
    const beforeTree = tree([['untouched', '100644', sibling], nested ? ['src', '040000', inner] : [path, beforeMode, oldId]]);
    const newRows = [['untouched', '100644', scenario === 'hidden' ? hidden : sibling]];
    if (next !== null) newRows.push([path, afterMode, newId]);
    const afterTree = tree(newRows);
    const baseBody = Buffer.from(`tree ${beforeTree}\nauthor Fixture <f@example.invalid> 1 +0000\ncommitter Fixture <f@example.invalid> 1 +0000\n\nbase\n`);
    const base = write('commit', baseBody), metadata = { author: 'Fixture <f@example.invalid>', committer: 'Fixture <f@example.invalid>', timestamp: 2, message: 'edit\n' };
    const body = Buffer.from(`tree ${afterTree}\nparent ${base}\nauthor ${metadata.author} 2 +0000\ncommitter ${metadata.committer} 2 +0000\n\n${metadata.message}`);
    const candidate = write('commit', body); git(['update-ref', 'refs/heads/main', candidate]);
    git(['bundle', 'create', join(dir, 'candidate.bundle'), 'refs/heads/main', `^${base}`]);
    const bundle = readFileSync(join(dir, 'candidate.bundle'));
    const patch = git(['diff', '--binary', base, candidate]);
    const pathHex = hex(path), expected = { format, commit: base, files: [{ pathHex, blob: oldId }] };
    const pkg = { schema: 'frankengit-selected-source-package-v1', membership: {
      schema: 'frankengit-context-membership-proof-v1', objectFormat: format, commit: { oid: base, bodyHex: hex(baseBody) },
      trees: [{ pathHex: null, oid: beforeTree, bodyHex: hex(git(['cat-file', 'tree', beforeTree])) },
        ...(nested ? [{ pathHex: hex('src'), oid: inner, bodyHex: hex(git(['cat-file', 'tree', inner])) }] : [])],
      files: [{ pathHex, blob: oldId, kind: 'file' }] }, blobs: [{ oid: oldId, bytesHex: hex(old) }] };
    const scope = { tenant_id: '1'.repeat(32), repository_id: '2'.repeat(32), repository_incarnation: '3'.repeat(32), object_format: format };
    const request = { endpoint: 'http://127.0.0.1:1/repo.git', scope, ref: 'refs/heads/main', expected_commit: base, metadata, paths_hex: [pathHex] };
    const common = { schema_version: 1, ...scope, ref: request.ref, ref_hex: hex(request.ref), read_only: true,
      objects_staged: false, transaction_created: false, published: false, publication_authorized: false };
    const prep = { type: 'source_preparation', ...common, source_commit: base, source_rcr: 'fixture-rcr', candidate_commit: candidate,
      root_tree: afterTree, patch_sha256: digest(patch), object_count: 3, bundle: { bytes: bundle.length, sha256: digest(bundle) },
      paths: [{ path_hex: pathHex, old_blob: oldId, new_blob: newId, new_mode: next === null ? null : parseInt(afterMode, 8), hunks: 1 }] };
    const full = ['empty', 'delete', 'nested-delete'].includes(scenario);
    const oldStart = full ? 0 : 6, oldEnd = full ? old.length : 11, after = next ?? Buffer.alloc(0);
    const newStart = full ? 0 : 6, newEnd = full ? after.length : 11;
    const span = (bytes, a, b) => ({ byte_start: a, byte_end: b,
      line_start: bytes.subarray(0, a).reduce((n, b) => n + Number(b === 10), 0),
      line_count: bytes.subarray(a, b).reduce((n, b) => n + Number(b === 10), 0) + Number(b > a && bytes[b - 1] !== 10) });
    const content = scenario === 'mode' ? { type: 'identical', content_read: false } : scenario === 'binary' ?
      { type: 'binary', before_bytes: old.length, after_bytes: after.length, body_included: false } :
      { type: 'text', algorithm: 'Myers', additions: 1, deletions: 1, before_bytes: old.length, after_bytes: after.length,
        hunks: [{ old: span(old, oldStart, oldEnd), new: span(after, newStart, newEnd),
          before_hex: hex(old.subarray(oldStart, oldEnd)), after_hex: hex(after.subarray(newStart, newEnd)) }] };
    const inspection = { type: 'source_inspection', ...common, source_head: 'fixture-head', snapshot_token: `alg:2:${'5'.repeat(64)}`,
      expected_commit: base, candidate_commit: candidate, parents: [base], bundle_bytes: bundle.length, bundle_sha256: digest(bundle),
      all_changed_paths: true, binary_bodies_included: false, candidate_commit_body_hex: hex(body), comparison: {
        mode: 'direct', before_tree: beforeTree, after_tree: afterTree, entry_count: 1, entries: [{ path_hex: pathHex,
          kind: next === null ? 'deleted' : scenario === 'mode' ? 'mode_changed' : 'modified',
          before: { mode: parseInt(beforeMode, 8), oid: oldId }, after: next === null ? null : { mode: parseInt(afterMode, 8), oid: newId }, content }] } };
    const capture = { schema: 'frankengit-source-edit-capture-v1', request, patch_sha256: digest(patch), patch_bytes: patch.length,
      preparation: prep, inspection };
    const result = { base, beforeTree, afterTree, candidate, oldId, newId, pathHex, old: hex(old), next: next === null ? null : hex(next),
      bundle: hex(bundle), patch: hex(patch), capture, package: pkg, expected };
    cache.set(key, result); return structuredClone(result);
  } finally { rmSync(dir, { recursive: true, force: true }); }
}
export const material = f => ({ package_bytes: Buffer.from(JSON.stringify(f.package)), expected: structuredClone(f.expected) });
export async function evidencePeer(t, format = 'sha1', scenario = 'text') {
  const native = await peer(t, format), f = evidenceFixture(format, scenario), control = {};
  f.capture.request.endpoint = native.request.endpoint;
  native.control.handler = async (req, res, call) => {
    if (control.handler) return control.handler(req, res, call);
    if (req.headers.authorization !== `Bearer ${TOKEN}` || req.headers['idempotency-key']) { res.writeHead(403); res.end('{}'); return; }
    const reply = structuredClone(call.operation === 'prepare' ? f.capture.preparation : f.capture.inspection);
    await control.mutate?.(reply, call);
    const body = call.operation === 'prepare' ? native.frame(reply, Buffer.from(f.bundle, 'hex')) :
      { type: 'application/json', bytes: Buffer.from(JSON.stringify(reply)) };
    res.writeHead(200, { 'Content-Type': body.type }); res.end(body.bytes);
  };
  return { ...f, control, calls: native.calls, request: f.capture.request, bundleBytes: Buffer.from(f.bundle, 'hex'),
    patchBytes: Buffer.from(f.patch, 'hex'), evidence: material(f) };
}
