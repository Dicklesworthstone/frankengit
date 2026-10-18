// Contract HTTP peer, not Rust fg. Test-only Git constructs a genuinely
// conflicted graph and the selected result; production invokes no Git process.
import { execFileSync, spawnSync } from 'node:child_process';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHash } from 'node:crypto';
import { createServer } from 'node:http';
import { createServer as createTlsServer } from 'node:https';
import { once } from 'node:events';
import assert from 'node:assert/strict';
import { reports, mixed, sendJson, TOKEN, SCOPE, META, HEAD } from './pull_candidate_fixture.mjs';
export { TOKEN, SCOPE, META, HEAD };
const cache = new Map();
export async function conflictFixture(algorithm = 'sha1', method = 'merge-commit', choice = 'theirs', bytes = Buffer.from('resolved\n'), mode = '100644') {
  const key = `${algorithm}:${method}:${choice}:${mode}:${createHash('sha256').update(bytes).digest('hex')}`;
  if (!cache.has(key)) cache.set(key, build());
  return structuredClone(await cache.get(key));
  async function build() {
    const root = await mkdtemp(join(tmpdir(), 'fg-resolved-git-'));
    const env = { PATH: process.env.PATH, HOME: root, GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: '/dev/null',
      GIT_TERMINAL_PROMPT: '0', LC_ALL: 'C', TZ: 'UTC', GIT_AUTHOR_NAME: 'Alice', GIT_AUTHOR_EMAIL: 'alice@example.invalid',
      GIT_COMMITTER_NAME: 'Bob', GIT_COMMITTER_EMAIL: 'bob@example.invalid', GIT_AUTHOR_DATE: '@1700000000 +0000', GIT_COMMITTER_DATE: '@1700000000 +0000' };
    const git = (args, input) => execFileSync('git', ['-C', root, ...args], { env, input, timeout: 10000, maxBuffer: 4 * 1024 * 1024 });
    const id = (args, input) => git(args, input).toString('utf8').trim();
    try {
      git(['init', '--bare', '--quiet', `--object-format=${algorithm}`]);
      const path = Buffer.from([102, 105, 108, 101, 255]), before = Buffer.from('ours\n');
      const bodies = { base: Buffer.from('base\n'), ours: before, theirs: Buffer.from('theirs\n'), file: Buffer.from(bytes) };
      const blobs = Object.fromEntries(Object.entries(bodies).map(([k, b]) => [k, id(['hash-object', '-w', '--stdin'], b)]));
      const tree = (blob, m = '100644') => id(['mktree', '-z'], blob === null ? Buffer.alloc(0)
        : Buffer.concat([Buffer.from(`${m} blob ${blob}\t`), path, Buffer.from([0])]));
      const baseTree = tree(blobs.base), oldTree = tree(blobs.ours), sourceTree = tree(blobs.theirs);
      const base = id(['commit-tree', baseTree], 'base\n');
      const target = id(['commit-tree', oldTree, '-p', base], 'target\n'), source = id(['commit-tree', sourceTree, '-p', base], 'source\n');
      const conflict = spawnSync('git', ['-C', root, 'merge-tree', '--write-tree', target, source], { env, timeout: 10000, maxBuffer: 1024 * 1024 });
      assert.equal(conflict.status, 1, 'Git independently reports a content conflict');
      const removed = choice === 'delete', after = removed ? Buffer.alloc(0) : bodies[choice];
      const newBlob = removed ? null : blobs[choice], newTree = tree(newBlob, choice === 'file' ? mode : '100644');
      const parents = method === 'squash' ? [target] : [target, source];
      const candidate = id(['commit-tree', newTree, ...parents.flatMap(p => ['-p', p])], META.message);
      for (const [name, value] of Object.entries({ target, source, candidate })) git(['update-ref', `refs/heads/${name}`, value]);
      const bundlePath = join(root, 'candidate.bundle');
      git(['bundle', 'create', bundlePath, 'refs/heads/candidate', '^refs/heads/target', '^refs/heads/source']);
      git(['bundle', 'verify', bundlePath]);
      const bundle = await readFile(bundlePath), commitBody = git(['cat-file', 'commit', candidate]);
      assert.equal(id(['hash-object', '-t', 'commit', '--stdin'], commitBody), candidate);
      const pack = bundle.indexOf(Buffer.from('\n\n')) + 2;
      return { algorithm, method, bundle, commitBody, parents, prerequisites: bundle.subarray(0, pack - 2).toString('ascii').split('\n')
        .filter(s => s.startsWith('-')).map(s => s.slice(1).split(' ')[0]), oldTree, newTree, oldBlob: blobs.ours,
        newBlob, baseBlob: blobs.base, sourceBlob: blobs.theirs, base, source, target, candidate, path, before, after,
        mode: Number.parseInt(choice === 'file' ? mode : '100644', 8), pack_bytes: bundle.length - pack,
        pack_objects: bundle.readUInt32BE(pack + 8), closure_objects: id(['rev-list', '--objects', candidate]).split('\n').length };
    } finally { await rm(root, { recursive: true, force: true }); }
  }
}
export async function resolutionPeer(t, options = {}) {
  const { algorithm = 'sha1', method = 'merge-commit', choice = 'theirs', bytes = Buffer.from('resolved\n'), mode = '100644', handle, tls } = options;
  const f = await conflictFixture(algorithm, method, choice, bytes, mode);
  // structuredClone detaches Buffers as Uint8Arrays. Restore Buffer methods only
  // for the existing fixture renderer, not for the implementation under test.
  for (const k of ['path', 'before', 'after', 'bundle', 'commitBody']) f[k] = Buffer.from(f[k]);
  const original = reports({ ...f, newBlob: f.sourceBlob }, 'conflicted');
  original.preparation.conflicts[0].base.oid = `${algorithm}:${f.baseBlob}`;
  const clean = reports({ ...f, newBlob: f.newBlob ?? f.oldBlob });
  const result = choice === 'delete' ? null : { mode: f.mode, oid: `${algorithm}:${f.newBlob}` };
  const resolved = { ...clean.preparation, state: 'resolved', resolution_profile: 'exact-path-resolutions-v1',
    resolutions: [{ ...structuredClone(original.preparation.conflicts[0]), choice, result }] };
  if (choice === 'ours') { clean.inspection.comparison.entries = []; clean.inspection.comparison.entry_count = 0; }
  else {
    const entry = clean.inspection.comparison.entries[0]; entry.after = result;
    if (choice === 'delete') { entry.kind = 'deleted'; entry.content = { type: 'object_only', content_read: false }; }
    else if (f.after.includes(0) || f.after.length > 65536) entry.content = { type: 'binary', before_bytes: f.before.length, after_bytes: f.after.length, body_included: false };
    if (entry.content.type === 'text') {
      const count = b => b.filter(x => x === 10).length + Number(b.length && b.at(-1) !== 10);
      entry.content.hunks[0].new.line_count = count(f.after);
    }
  }
  const p = { f, original, resolved, inspection: clean.inspection, requests: [], errors: [] };
  p.choices = [{ path_hex: f.path.toString('hex'), choice, ...(choice === 'file' ? { mode, content_hex: Buffer.from(bytes).toString('hex') } : {}) }];
  const sockets = new Set();
  const listener = async (req, res) => {
    try {
      const parts = []; let size = 0;
      for await (const part of req) { size += part.length; assert.ok(size < 20 * 1024 * 1024); parts.push(part); }
      const r = { url: req.url, method: req.method, headers: req.headers, body: Buffer.concat(parts) }; p.requests.push(r);
      // Optional native-schema publication peer for complete operator integration.
      if (options.commandHandle && await options.commandHandle(r, res, p)) return;
      assert.equal(r.headers.authorization, `Bearer ${TOKEN}`); assert.equal(r.headers['idempotency-key'], undefined);
      if (handle && await handle(r, res, p)) return;
      const path = new URL(r.url, 'http://peer.invalid').pathname;
      if (path.endsWith('/pulls/7')) sendJson(res, p.original.pull);
      else if (path.endsWith('/reviews')) sendJson(res, { type: 'review_page', schema_version: 1, ...SCOPE, object_format: algorithm,
        source_head: p.original.pull.source_head, snapshot_token: HEAD, number: 7, found: true, pull_request_version: 9, policy_epoch: 3,
        after: null, limit: 50, next_after: null, merge_authorized: false, reviews: p.original.reviews });
      else if (path.endsWith('/prepare')) sendJson(res, p.original.preparation, 409);
      else if (path.endsWith('/resolve')) {
        const reply = mixed(p.resolved, f.bundle); res.writeHead(200, { 'Content-Type': reply.type }); res.end(reply.bytes);
      } else if (path.endsWith('/inspect')) {
        assert.ok(r.body.includes(f.bundle)); sendJson(res, p.inspection);
      } else throw new Error(`Unexpected request ${r.url}`);
    } catch (e) { p.errors.push(e); res.destroy(); }
  };
  const server = tls ? createTlsServer(tls, listener) : createServer(listener);
  server.on('connection', socket => { sockets.add(socket); socket.on('close', () => sockets.delete(socket)); });
  server.listen(0, '127.0.0.1'); await once(server, 'listening');
  t.after(async () => { for (const s of sockets) s.destroy(); await new Promise(resolve => server.close(resolve)); assert.deepEqual(p.errors, []); });
  p.input = { endpoint: `${tls ? 'https' : 'http'}://127.0.0.1:${server.address().port}/repo.git`, scope: { ...SCOPE, object_format: algorithm },
    number: '7', method, metadata: { ...META }, expected_head: null };
  return p;
}
