// Git is an independent nonproduction object/index oracle. HTTP peers below
// model response schemas, not native Rust preparation, admission or policy.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, rmSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { compileSourceReplacements } from '../../scripts/operator/source_edit_replacements.mjs';
import { peer, TOKEN, digest } from './source_edit_fixture.mjs';
export { TOKEN };
export const hex = value => Buffer.from(value).toString('hex');
export const blob = (bytes, format) => createHash(format).update(`blob ${bytes.length}\0`).update(bytes).digest('hex');
export function change(format, name, old, next, oldMode = 0o100644, newMode = 0o100644) {
  return { path_hex: hex(name), before: old === null ? null : { mode: oldMode, bytes: Buffer.from(old), blob: blob(Buffer.from(old), format) },
    after: next === null ? null : { mode: newMode, bytes: Buffer.from(next) } };
}
export function withOracle(format, changes, action) {
  const dir = mkdtempSync(join(tmpdir(), 'fg-binary-literal-'));
  try {
    const git = (args, input) => execFileSync('git', ['-C', dir, ...args], { input, stdio: ['pipe', 'pipe', 'pipe'],
      env: { ...process.env, GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: '/dev/null', GIT_ATTR_NOSYSTEM: '1' } });
    const id = (args, bytes) => git(args, bytes).toString().trim();
    git(['init', '--quiet', `--object-format=${format}`]);
    const index = side => {
      git(['read-tree', '--empty']);
      const rows = [{ path_hex: hex('untouched'), mode: 0o100644, bytes: Buffer.from('sibling\n') },
        ...changes.filter(r => r[side]).map(r => ({ path_hex: r.path_hex, ...r[side] }))];
      git(['update-index', '-z', '--index-info'], Buffer.concat(rows.map(row => Buffer.concat([
        Buffer.from(`${row.mode.toString(8)} ${id(['hash-object', '-w', '--stdin'], row.bytes)}\t`),
        Buffer.from(row.path_hex, 'hex'), Buffer.from([0]),
      ]))));
      return id(['write-tree']);
    };
    const before = index('before'), after = index('after'); git(['read-tree', before]);
    return action({ git, id, before, after, dir });
  } finally { rmSync(dir, { recursive: true, force: true }); }
}
export function oracle(format, changes, options = { binary: 'literal' }) {
  const compiled = compileSourceReplacements(format, changes, options);
  withOracle(format, changes, ({ git, id, before, after }) => {
    git(['apply', '--cached', '--unidiff-zero', '--check', '-'], compiled.patch);
    git(['apply', '--cached', '--unidiff-zero', '-'], compiled.patch);
    assert.equal(id(['write-tree']), after, 'forward tree includes every exact desired body/mode');
    git(['apply', '--cached', '--unidiff-zero', '--reverse', '-'], compiled.patch);
    assert.equal(id(['write-tree']), before, 'reverse restores every original and untouched sibling');
  });
  return compiled;
}
export async function binaryPeer(t, format = 'sha1') {
  const transport = await peer(t, format);
  const rows = [change(format, 'file', Buffer.from([0, 255, 1, 10]), Buffer.from([0, 254, 2, 13, 10]))];
  const objects = withOracle(format, rows, ({ git, id, before, after, dir }) => {
    const meta = transport.request.metadata;
    const baseBody = Buffer.from(`tree ${before}\nauthor ${meta.author} 1 +0000\ncommitter ${meta.committer} 1 +0000\n\nbase\n`);
    const base = id(['hash-object', '-w', '-t', 'commit', '--stdin'], baseBody);
    const body = Buffer.from(`tree ${after}\nparent ${base}\nauthor ${meta.author} ${meta.timestamp} +0000\ncommitter ${meta.committer} ${meta.timestamp} +0000\n\n${meta.message}`);
    const candidate = id(['hash-object', '-w', '-t', 'commit', '--stdin'], body);
    git(['update-ref', 'refs/heads/main', candidate]);
    git(['bundle', 'create', join(dir, 'candidate.bundle'), 'refs/heads/main', `^${base}`]);
    return { base, body, candidate, beforeTree: before, tree: after, bundle: readFileSync(join(dir, 'candidate.bundle')) };
  });
  const compiled = compileSourceReplacements(format, rows, { binary: 'literal' });
  const request = { ...transport.request, expected_commit: objects.base, expected_result_tree: objects.tree };
  const p = structuredClone(transport.preparation), i = structuredClone(transport.inspection);
  Object.assign(p, { source_commit: objects.base, candidate_commit: objects.candidate, root_tree: objects.tree,
    patch_sha256: digest(compiled.patch), bundle: { bytes: objects.bundle.length, sha256: digest(objects.bundle) },
    paths: [{ path_hex: rows[0].path_hex, old_blob: rows[0].before.blob, new_blob: compiled.changes[0].after_blob, new_mode: 0o100644, hunks: 2 }] });
  Object.assign(i, { expected_commit: objects.base, candidate_commit: objects.candidate, parents: [objects.base],
    bundle_bytes: objects.bundle.length, bundle_sha256: digest(objects.bundle), candidate_commit_body_hex: hex(objects.body),
    comparison: { mode: 'direct', before_tree: objects.beforeTree, after_tree: objects.tree, entry_count: 1, entries: [{
      path_hex: rows[0].path_hex, kind: 'modified', before: { mode: 0o100644, oid: rows[0].before.blob },
      after: { mode: 0o100644, oid: compiled.changes[0].after_blob },
      content: { type: 'binary', before_bytes: rows[0].before.bytes.length, after_bytes: rows[0].after.bytes.length, body_included: false },
    }] } });
  const control = {};
  transport.control.handler = async (req, res, call) => {
    if (control.handler) return control.handler(req, res, call);
    if (req.headers.authorization !== `Bearer ${TOKEN}` || req.headers['idempotency-key']) { res.writeHead(403); res.end('{}'); return; }
    const reply = structuredClone(call.operation === 'prepare' ? p : i); await control.mutate?.(reply, call);
    const framed = call.operation === 'prepare' ? transport.frame(reply, objects.bundle)
      : { type: 'application/json', bytes: Buffer.from(JSON.stringify(reply)) };
    res.writeHead(200, { 'Content-Type': framed.type }); res.end(framed.bytes);
  };
  return { ...transport, ...objects, request, rows, compiled, control };
}
