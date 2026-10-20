// Independent Git-built trees, original objects and real bundles. HTTP replies
// are explicit native-schema peers, not Rust preparation or authorization.
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { peer, TOKEN, digest } from './source_edit_fixture.mjs';
export { TOKEN, PRINCIPAL } from './source_edit_fixture.mjs';
export const hex = value => Buffer.from(value).toString('hex');
const cache = new Map();
export function creationFixture(format = 'sha1', scenario = 'root') {
  const key = `${format}:${scenario}`;
  if (cache.has(key)) return structuredClone(cache.get(key));
  const dir = mkdtempSync(join(tmpdir(), 'fg-create-git-'));
  try {
    const git = (args, input) => execFileSync('git', ['-C', dir, ...args], { input,
      env: { ...process.env, GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: '/dev/null' } });
    const id = (args, input) => git(args, input).toString().trim();
    git(['init', '--quiet', `--object-format=${format}`]);
    const write = (kind, bytes) => id(['hash-object', '-w', '-t', kind, '--stdin'], bytes);
    const row = (path, body, mode = '100644') => ({ pathHex: hex(path), body: hex(body), mode,
      oid: write('blob', Buffer.from(body)) });
    const baseFiles = [row('src/base.rs', 'keep\r\nold\r\n'), row('hidden/secret', 'unselected\n'),
      row('sibling', 'unchanged\n'), row('link', 'src', '120000')];
    baseFiles.push({ pathHex: hex('submodule'), oid: 'b'.repeat(format === 'sha1' ? 40 : 64), mode: '160000' });
    const build = files => {
      const root = new Map(), trees = new Map();
      for (const file of files) {
        const parts = Buffer.from(file.pathHex, 'hex').toString('latin1').split('/'); let at = root;
        for (const name of parts.slice(0, -1)) {
          if (!at.has(name)) at.set(name, new Map());
          at = at.get(name);
        }
        at.set(parts.at(-1), file);
      }
      function visit(children, path) {
        const data = [];
        for (const [name, value] of children) {
          const rawName = Buffer.from(name, 'latin1'), pathHex = path === null ? hex(rawName) : `${path}2f${hex(rawName)}`;
          const directory = value instanceof Map;
          const object = directory ? visit(value, pathHex) : value.oid;
          const mode = directory ? '040000' : value.mode;
          data.push(Buffer.concat([Buffer.from(`${mode} ${directory ? 'tree' : mode === '160000' ? 'commit' : 'blob'} ${object}\t`), rawName, Buffer.from([0])]));
        }
        const oid = id(['mktree', '--missing', '-z'], Buffer.concat(data));
        trees.set(path, { pathHex: path, oid, bodyHex: hex(git(['cat-file', 'tree', oid])) });
        return oid;
      }
      return { root: visit(root, null), trees };
    };
    const original = build(baseFiles), baseBody = Buffer.from(`tree ${original.root}\nauthor Fixture <f@example.invalid> 1 +0000\ncommitter Fixture <f@example.invalid> 1 +0000\n\ncreation basis\n`);
    const base = write('commit', baseBody);
    const target = scenario === 'nested' ? 'new/deep/file.rs' : scenario === 'parent' ? 'src/new.rs' :
      scenario === 'raw' ? Buffer.from([255, 47, 254, 46, 114, 115]) : 'new.rs';
    const data = scenario === 'empty' ? Buffer.alloc(0) : scenario === 'binary' ? Buffer.from([0, 255, 10]) : Buffer.from('new\r\nlast');
    const added = row(target, data, scenario === 'executable' ? '100755' : '100644');
    const changes = [{ before: null, after: added }];
    let nextFiles = [...baseFiles, added];
    if (scenario === 'mixed') {
      const before = baseFiles[0], after = row('src/base.rs', 'changed\n');
      changes.push({ before, after }); nextFiles = nextFiles.map(v => v === before ? after : v);
    }
    if (scenario === 'hidden') nextFiles.push(row('surprise', 'hidden change\n'));
    const result = build(nextFiles), metadata = { author: 'Fixture <f@example.invalid>', committer: 'Fixture <f@example.invalid>', timestamp: 2, message: 'create\n' };
    const body = Buffer.from(`tree ${result.root}\nparent ${base}\nauthor ${metadata.author} 2 +0000\ncommitter ${metadata.committer} 2 +0000\n\n${metadata.message}`);
    const candidate = write('commit', body); git(['update-ref', 'refs/heads/main', candidate]);
    git(['bundle', 'create', join(dir, 'candidate.bundle'), 'refs/heads/main', `^${base}`]);
    const bundle = readFileSync(join(dir, 'candidate.bundle')), patch = git(['diff', '--binary', base, candidate]);
    const selected = baseFiles[0];
    const source = { format, commit: base, files: [{ pathHex: selected.pathHex, blob: selected.oid }] };
    const pkg = { schema: 'frankengit-selected-source-package-v1', membership: {
      schema: 'frankengit-context-membership-proof-v1', objectFormat: format, commit: { oid: base, bodyHex: hex(baseBody) },
      trees: [original.trees.get(null), original.trees.get(hex('src'))],
      files: [{ pathHex: selected.pathHex, blob: selected.oid, kind: 'file' }] }, blobs: [{ oid: selected.oid, bytesHex: selected.body }] };
    const expected = { schema: 'frankengit-source-edit-create-selection-v1', source, create_paths_hex: [added.pathHex] };
    changes.sort((a, b) => (a.after ?? a.before).pathHex < (b.after ?? b.before).pathHex ? -1 : 1);
    const scope = { tenant_id: '1'.repeat(32), repository_id: '2'.repeat(32), repository_incarnation: '3'.repeat(32), object_format: format };
    const request = { endpoint: 'http://127.0.0.1:1/repo.git', scope, ref: 'refs/heads/main', expected_commit: base, metadata,
      paths_hex: changes.map(v => (v.after ?? v.before).pathHex) };
    const common = { schema_version: 1, ...scope, ref: request.ref, ref_hex: hex(request.ref), read_only: true,
      objects_staged: false, transaction_created: false, published: false, publication_authorized: false };
    const span = bytes => ({ byte_start: 0, byte_end: bytes.length, line_start: 0,
      line_count: bytes.reduce((n, b) => n + Number(b === 10), 0) + Number(bytes.length > 0 && bytes.at(-1) !== 10) });
    const entries = changes.map(({ before, after }) => {
      const old = Buffer.from(before?.body ?? '', 'hex'), next = Buffer.from(after?.body ?? '', 'hex');
      const side = v => v === null ? null : ({ mode: parseInt(v.mode, 8), oid: v.oid });
      return { path_hex: (after ?? before).pathHex, kind: before === null ? 'added' : after === null ? 'deleted' : 'modified',
        before: side(before), after: side(after), content: scenario === 'binary' ?
          { type: 'binary', before_bytes: old.length, after_bytes: next.length, body_included: false } :
          { type: 'text', algorithm: 'Myers', additions: span(next).line_count, deletions: span(old).line_count,
            before_bytes: old.length, after_bytes: next.length, hunks: next.length || old.length ?
              [{ old: span(old), new: span(next), before_hex: hex(old), after_hex: hex(next) }] : [] } };
    });
    const preparation = { type: 'source_preparation', ...common, source_commit: base, source_rcr: 'fixture-rcr', candidate_commit: candidate,
      root_tree: result.root, patch_sha256: digest(patch), object_count: 3, bundle: { bytes: bundle.length, sha256: digest(bundle) },
      paths: entries.map(e => ({ path_hex: e.path_hex, old_blob: e.before?.oid ?? null, new_blob: e.after?.oid ?? null,
        new_mode: e.after?.mode ?? null, hunks: e.content.hunks?.length ?? 0 })) };
    const inspection = { type: 'source_inspection', ...common, source_head: 'fixture-head', snapshot_token: `alg:2:${'5'.repeat(64)}`,
      expected_commit: base, candidate_commit: candidate, parents: [base], bundle_bytes: bundle.length, bundle_sha256: digest(bundle),
      all_changed_paths: true, binary_bodies_included: false, candidate_commit_body_hex: hex(body), comparison: {
        mode: 'direct', before_tree: original.root, after_tree: result.root, entry_count: entries.length, entries } };
    const capture = { schema: 'frankengit-source-edit-capture-v1', request, patch_sha256: digest(patch), patch_bytes: patch.length, preparation, inspection };
    const answer = { capture, package: pkg, expected, bundle: hex(bundle), patch: hex(patch), target: added.pathHex,
      candidate, beforeTree: original.root, afterTree: result.root, base };
    cache.set(key, answer); return structuredClone(answer);
  } finally { rmSync(dir, { recursive: true, force: true }); }
}
export const material = f => ({ package_bytes: Buffer.from(JSON.stringify(f.package)), expected: structuredClone(f.expected) });
export async function creationPeer(t, format = 'sha1', scenario = 'root') {
  const native = await peer(t, format), f = creationFixture(format, scenario), control = {};
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
