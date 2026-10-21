// Actual Git objects/bundles, built independently of the production tree kernel.
// The HTTP peer models native response schemas, NOT native patch admission.
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHash } from 'node:crypto';
import { createServer } from 'node:http';
export const TOKEN = 'a'.repeat(64), PRINCIPAL = '4'.repeat(32);
export const hex = value => Buffer.from(value).toString('hex');
const digest = value => createHash('sha256').update(value).digest('hex');
const lineCount = bytes => bytes.reduce((n, b) => n + Number(b === 10), 0) + Number(bytes.length > 0 && bytes.at(-1) !== 10);
export function resultFixture(format = 'sha1', edits = [{ path: 'src/new.rs', data: Buffer.from('pub fn new_file() {}\r\n') }], options = {}) {
  const dir = mkdtempSync(join(tmpdir(), 'fg-create-verified-'));
  try {
    const git = (args, input) => execFileSync('git', ['-C', dir, ...args], { input, timeout: 10000, maxBuffer: 20 * 1024 * 1024,
      env: { ...process.env, GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: '/dev/null' } });
    git(['init', '--quiet', `--object-format=${format}`]);
    const write = (kind, bytes) => git(['hash-object', '-w', '-t', kind, '--stdin'], bytes).toString().trim();
    const initial = options.before ?? [
      { path: 'src/anchor.rs', data: Buffer.from('pub fn anchor() {}\n') },
      { path: 'root-anchor', data: Buffer.from('root\n') },
      { path: 'unproved/secret', data: Buffer.from('private\n') },
      { path: 'top-link', mode: 0o120000, data: Buffer.from('src') },
      { path: 'submodule', mode: 0o160000, oid: 'f'.repeat(format === 'sha1' ? 40 : 64) },
    ];
    const fileMap = definitions => new Map(definitions.map(d => [hex(d.path), {
      path: Buffer.from(d.path), mode: d.mode ?? 0o100644,
      ...(d.data === undefined ? { oid: d.oid } : { data: Buffer.from(d.data), oid: write('blob', d.data) }),
    }]));
    function tree(files) {
      const root = { children: new Map() }, trees = new Map();
      for (const f of files.values()) {
        const parts = f.path.toString('latin1').split('/').map(p => Buffer.from(p, 'latin1'));
        let at = root;
        for (const part of parts.slice(0, -1)) {
          if (!at.children.has(hex(part))) at.children.set(hex(part), { name: part, children: new Map() });
          at = at.children.get(hex(part));
        }
        at.children.set(hex(parts.at(-1)), { ...f, name: parts.at(-1) });
      }
      function visit(node, pathHex = null) {
        const rows = [];
        for (const entry of node.children.values()) {
          const path = pathHex === null ? hex(entry.name) : `${pathHex}2f${hex(entry.name)}`;
          const id = entry.children ? visit(entry, path) : entry.oid;
          const mode = entry.children ? '40000' : entry.mode.toString(8);
          rows.push(Buffer.concat([Buffer.from(`${mode} ${entry.children ? 'tree' : entry.mode === 0o160000 ? 'commit' : 'blob'} ${id}\t`), entry.name, Buffer.from([0])]));
        }
        const oid = git(['mktree', '-z', '--missing'], Buffer.concat(rows)).toString().trim();
        trees.set(pathHex, { pathHex, oid, bodyHex: hex(git(['cat-file', 'tree', oid])) }); return oid;
      }
      return { oid: visit(root), trees };
    }
    const before = fileMap(initial), oldTree = tree(before);
    const baseBody = Buffer.from(`tree ${oldTree.oid}\nauthor Example <e@example.invalid> 1 +0000\ncommitter Example <e@example.invalid> 1 +0000\n\nbase\n`);
    const base = write('commit', baseBody), after = new Map(before);
    for (const e of [...edits, ...(options.hidden ?? [])]) {
      if (e.data === null) after.delete(hex(e.path));
      else { const f = fileMap([e]); after.set(hex(e.path), f.get(hex(e.path))); }
    }
    const nextTree = tree(after), metadata = { author: 'Example <e@example.invalid>', committer: 'Example <e@example.invalid>', timestamp: 2, message: 'verified creation\n' };
    const body = Buffer.from(`tree ${nextTree.oid}\nparent ${base}\nauthor ${metadata.author} 2 +0000\ncommitter ${metadata.committer} 2 +0000\n\n${metadata.message}`);
    const candidate = write('commit', body); git(['update-ref', 'refs/heads/main', candidate]);
    git(['bundle', 'create', join(dir, 'candidate.bundle'), 'refs/heads/main', `^${base}`]);
    const bundle = readFileSync(join(dir, 'candidate.bundle')), patch = git(['diff', '--binary', base, candidate]);
    const paths = edits.map(e => hex(e.path)).sort(), selected = (options.selected ?? ['src/anchor.rs']).map(hex).sort();
    const dirs = new Set([null]), blobs = new Map();
    for (const path of selected) {
      const raw = Buffer.from(path, 'hex');
      for (let at = 0; at < raw.length; at++) if (raw[at] === 47) dirs.add(hex(raw.subarray(0, at)));
      const f = before.get(path); blobs.set(f.oid, hex(f.data));
    }
    const source = { format, commit: base, files: selected.map(pathHex => ({ pathHex, blob: before.get(pathHex).oid })) };
    const absent = paths.filter(path => !before.has(path));
    const expected = absent.length ? { schema: 'frankengit-source-edit-create-selection-v1', source, create_paths_hex: absent } : source;
    const sourcePackage = { schema: 'frankengit-selected-source-package-v1', membership: {
      schema: 'frankengit-context-membership-proof-v1', objectFormat: format,
      commit: { oid: base, bodyHex: hex(baseBody) }, trees: [...dirs].map(p => oldTree.trees.get(p)),
      files: selected.map(pathHex => ({ pathHex, blob: before.get(pathHex).oid, kind: before.get(pathHex).mode === 0o100755 ? 'executable' : 'file' })) },
      blobs: [...blobs].sort(([a], [b]) => a < b ? -1 : 1).map(([oid, bytesHex]) => ({ oid, bytesHex })) };
    const scope = { tenant_id: '1'.repeat(32), repository_id: '2'.repeat(32), repository_incarnation: '3'.repeat(32), object_format: format }, ref = 'refs/heads/main';
    const request = { endpoint: 'http://127.0.0.1:1/repo.git', scope, ref, expected_commit: base, metadata, paths_hex: paths };
    const common = { schema_version: 1, ...scope, ref, ref_hex: hex(ref), read_only: true, objects_staged: false,
      transaction_created: false, published: false, publication_authorized: false };
    const oid = id => `${format}:${id}`, side = f => f ? { mode: f.mode, oid: oid(f.oid) } : null;
    const entries = paths.map(path_hex => {
      const old = before.get(path_hex), next = after.get(path_hex), a = old?.data ?? Buffer.alloc(0), b = next?.data ?? Buffer.alloc(0);
      const content = a.includes(0) || b.includes(0)
        ? { type: 'binary', before_bytes: a.length, after_bytes: b.length, body_included: false }
        : old && next && old.oid === next.oid ? { type: 'identical', content_read: false }
        : { type: 'text', algorithm: 'Myers', additions: lineCount(b), deletions: lineCount(a), before_bytes: a.length, after_bytes: b.length,
          hunks: a.length || b.length ? [{ old: { byte_start: 0, byte_end: a.length, line_start: 0, line_count: lineCount(a) },
            new: { byte_start: 0, byte_end: b.length, line_start: 0, line_count: lineCount(b) }, before_hex: hex(a), after_hex: hex(b) }] : [] };
      return { path_hex, kind: !old ? 'added' : !next ? 'deleted' : old.mode !== next.mode ? 'mode_changed' : 'modified', before: side(old), after: side(next), content };
    });
    const preparation = { type: 'source_preparation', ...common, source_commit: oid(base), source_rcr: 'fixture-rcr', candidate_commit: oid(candidate),
      root_tree: oid(nextTree.oid), patch_sha256: digest(patch), object_count: git(['rev-list', '--objects', candidate, `^${base}`]).toString().trim().split('\n').length,
      bundle: { bytes: bundle.length, sha256: digest(bundle) }, paths: entries.map(row => ({ path_hex: row.path_hex, old_blob: row.before?.oid ?? null,
        new_blob: row.after?.oid ?? null, new_mode: row.after?.mode ?? null, hunks: row.content.hunks?.length ?? 0 })) };
    const inspection = { type: 'source_inspection', ...common, source_head: 'fixture-head', snapshot_token: `alg:2:${'5'.repeat(64)}`,
      expected_commit: oid(base), candidate_commit: oid(candidate), parents: [oid(base)], bundle_bytes: bundle.length, bundle_sha256: digest(bundle),
      all_changed_paths: true, binary_bodies_included: false, candidate_commit_body_hex: hex(body),
      comparison: { mode: 'direct', before_tree: oid(oldTree.oid), after_tree: oid(nextTree.oid), entry_count: entries.length, entries } };
    const capture = { schema: 'frankengit-source-edit-capture-v1', request, patch_sha256: digest(patch), patch_bytes: patch.length, preparation, inspection };
    return { format, base, candidate, before, after, oldTree, nextTree, patch, bundle, capture,
      evidence: { package_bytes: Buffer.from(JSON.stringify(sourcePackage)), expected } };
  } finally { rmSync(dir, { recursive: true, force: true }); }
}
export async function resultPeer(t, f) {
  const calls = [], control = {};
  const server = createServer(async (req, res) => {
    try {
      const chunks = []; for await (const chunk of req) chunks.push(chunk);
      const body = Buffer.concat(chunks), operation = req.url.split('/').at(-1), call = { operation, headers: req.headers, body }; calls.push(call);
      if (control.handler) { await control.handler(req, res, call); return; }
      if (req.headers.authorization !== `Bearer ${TOKEN}` || req.headers['idempotency-key'] || !['prepare', 'inspect'].includes(operation)) { res.writeHead(403); res.end(); return; }
      const reply = structuredClone(operation === 'prepare' ? f.capture.preparation : f.capture.inspection); await control.mutate?.(reply, call);
      if (operation === 'inspect') { res.writeHead(200, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(reply)); return; }
      const b = `fg-source-${digest(f.bundle).slice(0, 48)}-0`;
      res.writeHead(200, { 'Content-Type': `multipart/mixed; boundary=${b}` });
      res.end(Buffer.concat([Buffer.from(`--${b}\r\nContent-Type: application/json; charset=utf-8\r\nContent-Disposition: inline; name="metadata"\r\n\r\n${JSON.stringify(reply)}\r\n--${b}\r\nContent-Type: application/x-git-bundle\r\nContent-Disposition: attachment; name="bundle"; filename="candidate.bundle"\r\n\r\n`), f.bundle, Buffer.from(`\r\n--${b}--\r\n`)]));
    } catch { res.destroy(); }
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(async () => { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); });
  f.capture.request.endpoint = `http://127.0.0.1:${server.address().port}/repo.git`;
  return { ...f, calls, control };
}
