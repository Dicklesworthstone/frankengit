// Real Git objects, HTTP sockets and exact native schemas. Not a Rust server.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { compileCompactSourceSplices } from '../../scripts/operator/source_edit_compact_splices.mjs';
import { SPLICE_PROFILE } from '../../scripts/operator/source_edit_splices.mjs';
import { MULTI_HUNK_PATCH_PROFILE } from '../../crates/fgit-node/src/smart_http/server/browser/source-patch.mjs';
import { peer, TOKEN, digest } from './source_edit_fixture.mjs';
const bytes = value => Buffer.from(value), hex = value => bytes(value).toString('hex');
const native = (value, format = 'sha1') => createHash(format).update(`blob ${value.length}\0`).update(value).digest('hex');
const edit = (at, before, after) => ({ byte_start: at, before: bytes(before), after: bytes(after) });
const file = (original, edits, format = 'sha1', name = 'file', mode = 0o100644, afterMode = mode) => ({
  path_hex: hex(name), before: { bytes: bytes(original), mode, blob: native(bytes(original), format) }, after_mode: afterMode, edits });
async function oracle(format, files, desired, options = { patchProfile: MULTI_HUNK_PATCH_PROFILE }) {
  const dir = mkdtempSync(join(tmpdir(), 'fg-splice-git-'));
  try {
    const git = (args, input) => execFileSync('git', ['-C', dir, ...args], { input,
      env: { ...process.env, GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: '/dev/null' } });
    git(['init', '--quiet', `--object-format=${format}`]);
    const index = rows => {
      git(['read-tree', '--empty']);
      const entries = [...rows, { path_hex: hex('untouched'), bytes: bytes('untouched\n'), mode: 0o100644 }];
      git(['update-index', '-z', '--index-info'], Buffer.concat(entries.map(row => {
        const oid = git(['hash-object', '-w', '--stdin'], row.bytes).toString().trim();
        return Buffer.concat([bytes(`${row.mode.toString(8)} ${oid}\t`), Buffer.from(row.path_hex, 'hex'), Buffer.from([0])]);
      })));
      return git(['write-tree']).toString().trim();
    };
    const initial = index(files.map(f => ({ path_hex: f.path_hex, ...f.before })));
    const compiled = await compileCompactSourceSplices(format, files, options);
    git(['apply', '--cached', '--unidiff-zero', '--check', '-'], compiled.patch);
    git(['apply', '--cached', '--unidiff-zero', '-'], compiled.patch);
    const result = git(['write-tree']).toString().trim();
    git(['apply', '--cached', '--unidiff-zero', '-R', '-'], compiled.patch);
    assert.equal(git(['write-tree']).toString().trim(), initial);
    const wanted = index(files.map((f, i) => ({ path_hex: f.path_hex, bytes: bytes(desired[i]), mode: f.after_mode })));
    assert.equal(result, wanted);
    assert.equal(compiled.splice_profile, SPLICE_PROFILE);
    assert.equal(compiled.source_membership_verified, false);
    assert.equal(compiled.publication_authorized, false);
    return compiled;
  } finally { rmSync(dir, { recursive: true, force: true }); }
}

async function acquisition(t, format) {
  const f = await peer(t, format), dir = mkdtempSync(join(tmpdir(), 'fg-splice-peer-'));
  try {
    const git = (args, input) => execFileSync('git', ['-C', dir, ...args], { input,
      env: { ...process.env, GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: '/dev/null' } });
    git(['init', '--quiet', `--object-format=${format}`]);
    const write = (kind, data) => git(['hash-object', '-w', '-t', kind, '--stdin'], data).toString().trim();
    const original = bytes('old\r\n'), desired = bytes('new\r\n'), oldBlob = write('blob', original), newBlob = write('blob', desired);
    const tree = id => write('tree', Buffer.concat([bytes('100644 file\0'), Buffer.from(id, 'hex')]));
    const beforeTree = tree(oldBlob), afterTree = tree(newBlob), m = f.request.metadata;
    const base = write('commit', bytes(`tree ${beforeTree}\nauthor Example <e@example.invalid> 1 +0000\ncommitter Example <e@example.invalid> 1 +0000\n\nbase\n`));
    const body = bytes(`tree ${afterTree}\nparent ${base}\nauthor ${m.author} ${m.timestamp} +0000\ncommitter ${m.committer} ${m.timestamp} +0000\n\n${m.message}`);
    const candidate = write('commit', body); git(['update-ref', 'refs/heads/main', candidate]);
    git(['bundle', 'create', join(dir, 'candidate.bundle'), 'refs/heads/main', `^${base}`]);
    const bundle = readFileSync(join(dir, 'candidate.bundle')), files = [file(original, [edit(0, 'old', 'new')], format)];
    const compiled = await compileCompactSourceSplices(format, files, { patchProfile: MULTI_HUNK_PATCH_PROFILE }), p = f.preparation, i = f.inspection;
    Object.assign(p, { source_commit: base, candidate_commit: candidate, root_tree: afterTree, patch_sha256: digest(compiled.patch), bundle: { bytes: bundle.length, sha256: digest(bundle) } });
    p.paths[0].old_blob = oldBlob; p.paths[0].new_blob = newBlob;
    Object.assign(i, { expected_commit: base, candidate_commit: candidate, parents: [base], bundle_bytes: bundle.length,
      bundle_sha256: digest(bundle), candidate_commit_body_hex: body.toString('hex') });
    Object.assign(i.comparison, { before_tree: beforeTree, after_tree: afterTree });
    const row = i.comparison.entries[0];
    Object.assign(row, { kind: 'modified', before: { mode: 0o100644, oid: oldBlob }, after: { mode: 0o100644, oid: newBlob } });
    row.content = { type: 'text', algorithm: 'Myers', additions: 1, deletions: 1, before_bytes: original.length, after_bytes: desired.length,
      hunks: [{ old: { byte_start: 0, byte_end: original.length, line_start: 0, line_count: 1 }, new: { byte_start: 0, byte_end: desired.length, line_start: 0, line_count: 1 },
        before_hex: original.toString('hex'), after_hex: desired.toString('hex') }] };
    const selection = { ...f.request, expected_commit: base, expected_result_tree: afterTree };
    f.control.handler = async (_req, res, call) => {
      const reply = structuredClone(call.operation === 'prepare' ? p : i); await f.control.mutate?.(reply, call);
      const response = call.operation === 'prepare' ? f.frame(reply, bundle) : { type: 'application/json', bytes: bytes(JSON.stringify(reply)) };
      res.writeHead(200, { 'Content-Type': response.type }); res.end(response.bytes);
    };
    return { ...f, selection, files, compiled, candidate, bundle };
  } finally { rmSync(dir, { recursive: true, force: true }); }
}
export { file, edit, oracle, acquisition, bytes, hex, native, TOKEN, digest };
