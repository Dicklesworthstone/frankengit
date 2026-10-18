// Native-schema HTTP peers, NOT a Rust fg server. Git runs only here as a
// bounded independent fixture oracle, producing real native commits/bundles.
import { execFileSync } from 'node:child_process';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHash } from 'node:crypto';
import { createServer as httpServer } from 'node:http';
import { createServer as httpsServer } from 'node:https';
import { once } from 'node:events';
import assert from 'node:assert/strict';

export const TOKEN = 'a'.repeat(64), REVIEWER = '00000000000000000000000000000001';
export const SCOPE = Object.freeze({ tenant_id: '1'.repeat(32), repository_id: '2'.repeat(32), repository_incarnation: '3'.repeat(32) });
export const HEAD = `alg:1:${'b'.repeat(64)}`, SOURCE_HEAD = 'native-head-at-selected-snapshot';
export const META = Object.freeze({ author: 'Alice <alice@example.invalid>', committer: 'Bob <bob@example.invalid>',
  timestamp: '1700000000', message: 'Merge the reviewed topic\n' });
const cache = new Map();
export async function gitFixture(algorithm = 'sha1', method = 'merge-commit') {
  const key = `${algorithm}-${method}`;
  if (!cache.has(key)) cache.set(key, build(algorithm, method));
  const fixture = await cache.get(key);
  return { ...fixture, bundle: Buffer.from(fixture.bundle), commitBody: Buffer.from(fixture.commitBody) };
}
async function build(algorithm, method) {
  const root = await mkdtemp(join(tmpdir(), 'fg-candidate-git-oracle-'));
  const env = { PATH: process.env.PATH, HOME: root, GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: '/dev/null',
    GIT_TERMINAL_PROMPT: '0', LC_ALL: 'C', TZ: 'UTC', GIT_AUTHOR_NAME: 'Alice', GIT_AUTHOR_EMAIL: 'alice@example.invalid',
    GIT_COMMITTER_NAME: 'Bob', GIT_COMMITTER_EMAIL: 'bob@example.invalid', GIT_AUTHOR_DATE: '@1700000000 +0000', GIT_COMMITTER_DATE: '@1700000000 +0000' };
  const git = (args, input) => execFileSync(process.env.FG_GIT_ORACLE ?? 'git', ['-C', root, ...args],
    { input, env, timeout: 10000, maxBuffer: 1024 * 1024, stdio: ['pipe', 'pipe', 'pipe'] });
  const id = (args, input) => git(args, input).toString('utf8').trim();
  try {
    const version = id(['--version']);
    git(['init', '--bare', '--quiet', `--object-format=${algorithm}`]);
    const path = Buffer.from([102, 105, 108, 101, 255]), before = Buffer.from('before\n'), after = Buffer.from('after\n');
    const oldBlob = id(['hash-object', '-w', '--stdin'], before), newBlob = id(['hash-object', '-w', '--stdin'], after);
    const tree = blob => id(['mktree', '-z'], Buffer.concat([Buffer.from(`100644 blob ${blob}\t`), path, Buffer.from([0])]));
    const oldTree = tree(oldBlob), newTree = tree(newBlob);
    const base = id(['commit-tree', oldTree], 'base\n');
    const target = id(['commit-tree', oldTree, '-p', base], 'target\n'), source = id(['commit-tree', newTree, '-p', base], 'source\n');
    const parents = method === 'squash' ? [target] : [target, source];
    const candidate = id(['commit-tree', newTree, ...parents.flatMap(p => ['-p', p])], META.message);
    for (const [name, value] of Object.entries({ target, source, candidate })) git(['update-ref', `refs/heads/${name}`, value]);
    const file = join(root, 'candidate.bundle');
    git(['bundle', 'create', file, 'refs/heads/candidate', '^refs/heads/target', '^refs/heads/source']);
    git(['bundle', 'verify', file]);
    const bundle = await readFile(file), commitBody = git(['cat-file', 'commit', candidate]);
    assert.equal(id(['hash-object', '-t', 'commit', '--stdin'], commitBody), candidate);
    const headEnd = bundle.indexOf(Buffer.from('\n\n')), pack = headEnd + 2;
    assert.equal(bundle.subarray(pack, pack + 4).toString(), 'PACK');
    const prerequisites = bundle.subarray(0, headEnd).toString('ascii').split('\n')
      .filter(line => line.startsWith('-')).map(line => line.slice(1).split(' ')[0]);
    const closure = id(['rev-list', '--objects', 'refs/heads/candidate']).split('\n').length;
    return { algorithm, method, version, bundle, commitBody, parents, prerequisites, oldTree, newTree, oldBlob, newBlob,
      base, source, target, candidate, path, before, after, pack_bytes: bundle.length - pack,
      pack_objects: bundle.readUInt32BE(pack + 8), closure_objects: closure };
  } finally { await rm(root, { recursive: true, force: true }); }
}
const q = (f, id) => `${f.algorithm}:${id}`;
function header(f) { return { schema_version: 1, ...SCOPE, object_format: f.algorithm, source_head: SOURCE_HEAD, snapshot_token: HEAD }; }
function subject(f, numberField = 'pull_request') {
  return { [numberField]: 7, pull_request_version: 9, policy_epoch: 3, source_ref: 'refs/heads/source',
    source_ref_hex: Buffer.from('refs/heads/source').toString('hex'), target_ref: 'refs/heads/target',
    target_ref_hex: Buffer.from('refs/heads/target').toString('hex'), source_tip: q(f, f.source), target_tip: q(f, f.target) };
}
export function reports(f, state = 'clean', reviewCount = 1) {
  const noEffects = { read_only: true, objects_staged: false, transaction_created: false, published: false, merge_authorized: false };
  const s = subject(f), { pull_request, pull_request_version, policy_epoch, ...data } = s;
  const pull = { type: 'pull_request', ...header(f), number: 7, found: true, pull_request: {
    number: 7, version: 9, state: 'open', data: { ...data, object_format: f.algorithm, title: 'Review topic', body: 'Repository text is data.' },
    opened_by: 'f'.repeat(32), last_metadata_actor: 'f'.repeat(32), merge_only: false, merge: null } };
  const reviews = Array.from({ length: reviewCount }, (_, i) => ({ reviewer: (i + 1).toString(16).padStart(32, '0'), version: 2,
    subject: subject(f, 'number'), candidate: { merge_base: q(f, f.base), candidate_commit: q(f, f.candidate) },
    decision: 'request-changes', reason: 'Inspect the exact candidate.', freshness: 'current', reviewer_is_opener: false }));
  const conflict = { path_hex: f.path.toString('hex'), kind: 'content', base: { mode: 0o100644, oid: q(f, f.oldBlob) },
    ours: { mode: 0o100644, oid: q(f, f.oldBlob) }, theirs: { mode: 0o100644, oid: q(f, f.newBlob) } };
  const preparation = { type: 'merge_preparation', ...header(f), profile: 'path-merge-v1', method: f.method, ...noEffects,
    subject: s, state, ...(state === 'conflicted' ? { merge_base: q(f, f.base) } : {}),
    candidate: state === 'clean' ? { merge_base: q(f, f.base), commit: q(f, f.candidate), tree: q(f, f.newTree), new_object_count: f.pack_objects } : null,
    bundle: state === 'clean' ? { bytes: f.bundle.length, sha256: createHash('sha256').update(f.bundle).digest('hex') } : null,
    conflicts: state === 'conflicted' ? [conflict] : [] };
  const inspection = { type: 'candidate_inspection', ...header(f), ...noEffects, all_changed_paths: true,
    binary_bodies_included: false, comparison_profile: 'full-tree-direct-path-myers-v1', context_lines: 3, subject: structuredClone(s),
    merge_base: q(f, f.base), candidate_commit: q(f, f.candidate), parents: f.parents.map(id => q(f, id)),
    prerequisites: f.prerequisites.map(id => q(f, id)), candidate_commit_body_hex: f.commitBody.toString('hex'),
    bundle: { bytes: f.bundle.length, pack_bytes: f.pack_bytes, pack_objects: f.pack_objects, expanded_bytes: f.commitBody.length,
      closure_objects: f.closure_objects, transport_only_objects: 0, sha256: createHash('sha256').update(f.bundle).digest('hex') },
    comparison: { mode: 'direct', before: q(f, f.target), after: q(f, f.candidate), before_tree: q(f, f.oldTree), after_tree: q(f, f.newTree),
      entry_count: 1, entries: [{ path_hex: f.path.toString('hex'), kind: 'modified', before: { mode: 0o100644, oid: q(f, f.oldBlob) },
        after: { mode: 0o100644, oid: q(f, f.newBlob) }, content: { type: 'text', algorithm: 'Myers', additions: 1, deletions: 1,
          before_bytes: f.before.length, after_bytes: f.after.length, hunks: [{ old: { byte_start: 0, byte_end: f.before.length, line_start: 0, line_count: 1 },
            new: { byte_start: 0, byte_end: f.after.length, line_start: 0, line_count: 1 }, before_hex: f.before.toString('hex'), after_hex: f.after.toString('hex') }] } }] } };
  return { pull, reviews, preparation, inspection };
}
export function mixed(metadata, bundle) {
  const boundary = `fg-prepare-${createHash('sha256').update(bundle).digest('hex').slice(0, 48)}-0`;
  return { type: `multipart/mixed; boundary=${boundary}`, bytes: Buffer.concat([
    Buffer.from(`--${boundary}\r\nContent-Type: application/json; charset=utf-8\r\nContent-Disposition: inline; name="metadata"\r\n\r\n${JSON.stringify(metadata)}\r\n--${boundary}\r\nContent-Type: application/x-git-bundle\r\nContent-Disposition: attachment; name="bundle"; filename="candidate.bundle"\r\n\r\n`),
    bundle, Buffer.from(`\r\n--${boundary}--\r\n`),
  ]) };
}
export function sendJson(response, value, status = 200) {
  const bytes = Buffer.from(JSON.stringify(value));
  response.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Content-Length': bytes.length }); response.end(bytes);
}
export async function candidatePeer(t, { algorithm = 'sha1', method = 'merge-commit', state = 'clean', reviewCount = 1, handle, tls } = {}) {
  const f = await gitFixture(algorithm, method), p = { fixture: f, ...reports(f, state, reviewCount), requests: [], errors: [] }, sockets = new Set();
  const listener = async (request, response) => {
    try {
      const chunks = []; let size = 0;
      for await (const chunk of request) { size += chunk.length; assert.ok(size <= 19 * 1024 * 1024); chunks.push(chunk); }
      const r = { method: request.method, url: request.url, headers: request.headers, body: Buffer.concat(chunks, size) };
      p.requests.push(r);
      assert.equal(r.headers.authorization, `Bearer ${TOKEN}`); assert.equal(r.headers['idempotency-key'], undefined);
      assert.equal(r.headers.cookie, undefined);
      if (handle && await handle(r, response, p)) return;
      const url = new URL(r.url, 'http://fixture.invalid');
      if (url.pathname === '/repo.git/api/v1/pulls/7') {
        assert.equal(r.method, 'GET'); assert.equal(size, 0); sendJson(response, p.pull);
      } else if (url.pathname === '/repo.git/api/v1/pulls/7/reviews') {
        assert.equal(r.method, 'GET'); assert.equal(size, 0); assert.equal(url.searchParams.get('expected_head'), HEAD);
        const after = url.searchParams.get('after'), limit = Number(url.searchParams.get('limit'));
        const remaining = p.reviews.filter(row => after === null || row.reviewer > after), rows = remaining.slice(0, limit);
        sendJson(response, { type: 'review_page', ...header(f), number: 7, found: true, pull_request_version: 9, policy_epoch: 3,
          after, limit, next_after: remaining.length > limit ? rows.at(-1).reviewer : null, merge_authorized: false, reviews: rows });
      } else if (url.pathname === '/repo.git/api/v1/pulls/7/prepare') {
        assert.equal(r.method, 'POST');
        const command = new URLSearchParams(r.body.toString('utf8'));
        assert.equal([...command].length, 13); assert.equal(command.get('profile'), 'path-merge-v1');
        assert.equal(command.get('source_tip'), f.source); assert.equal(command.get('target_tip'), f.target);
        assert.equal(command.get('method'), method); assert.equal(command.get('timestamp'), META.timestamp);
        assert.equal(command.get('author'), META.author); assert.equal(command.get('message'), META.message);
        if (p.preparation.state === 'clean') { const body = mixed(p.preparation, f.bundle);
          response.writeHead(200, { 'Content-Type': body.type, 'Content-Length': body.bytes.length }); response.end(body.bytes);
        } else sendJson(response, p.preparation, p.preparation.state === 'conflicted' ? 409 : 200);
      } else if (url.pathname === '/repo.git/api/v1/pulls/7/inspect') {
        assert.equal(r.method, 'POST');
        const boundary = r.headers['content-type'].split('boundary=')[1];
        const marker = Buffer.from('Content-Type: application/x-git-bundle\r\n\r\n'), start = r.body.indexOf(marker) + marker.length;
        const end = r.body.length - Buffer.byteLength(`\r\n--${boundary}--\r\n`);
        assert.deepEqual(r.body.subarray(start, end), f.bundle);
        const commandStart = r.body.indexOf(Buffer.from('\r\n\r\n')) + 4;
        const commandEnd = r.body.indexOf(Buffer.from(`\r\n--${boundary}\r\n`), commandStart);
        const command = new URLSearchParams(r.body.subarray(commandStart, commandEnd).toString('utf8'));
        assert.equal([...command].length, 9); assert.equal(command.get('candidate_commit'), f.candidate);
        assert.equal(command.get('policy_epoch'), '3'); assert.equal(command.get('pull_request_version'), '9');
        sendJson(response, p.inspection);
      } else throw new Error('Unexpected route: ' + r.url);
    } catch (error) { p.errors.push(error); response.destroy(); }
  };
  const server = tls ? httpsServer(tls, listener) : httpServer(listener);
  server.on('connection', socket => { sockets.add(socket); socket.on('close', () => sockets.delete(socket)); });
  server.listen(0, '127.0.0.1'); await once(server, 'listening');
  t.after(async () => { for (const socket of sockets) socket.destroy(); await new Promise(resolve => server.close(resolve)); assert.deepEqual(p.errors, []); });
  p.endpoint = `${tls ? 'https' : 'http'}://127.0.0.1:${server.address().port}/repo.git`;
  p.input = { endpoint: p.endpoint, scope: { ...SCOPE, object_format: algorithm }, number: '7', metadata: { ...META }, method, expected_head: null };
  return p;
}
