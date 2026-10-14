// Explicit native-schema HTTP/TLS peer. Git runs ONLY here as a test oracle to
// apply actual patches and construct real candidate trees/commits/bundles. These
// replies are not Rust fg, native policy, admission or authority-CAS execution.
import assert from 'node:assert/strict';
import { createServer as httpServer } from 'node:http';
import { createServer as httpsServer } from 'node:https';
import { mkdtemp, mkdir, writeFile, readFile, chmod, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { execFileSync } from 'node:child_process';
import { changeFixture, hexPath } from './source_changes_fixture.mjs';
import { sha256 } from '../operator/source_changes.mjs';

export const TOKEN = 'a'.repeat(64), ROTATED_TOKEN = 'b'.repeat(64), PRINCIPAL = '4'.repeat(32);
export const SCOPE = { tenant_id: '1'.repeat(32), repository_id: '2'.repeat(32), repository_incarnation: '3'.repeat(32) };
const encoded = value => Buffer.from(JSON.stringify(value).replace('"18446744073709551615"', '18446744073709551615'));
function multipart(body, type) {
  const boundary = /boundary=([a-z0-9-]+)$/.exec(type)?.[1]; assert.ok(boundary);
  const header = Buffer.from(`--${boundary}\r\nContent-Disposition: form-data; name="command"\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\n`);
  const split = body.indexOf(Buffer.from(`\r\n--${boundary}\r\n`), header.length); assert.ok(split >= header.length);
  const start = body.indexOf(Buffer.from('\r\n\r\n'), split + 4) + 4;
  const end = body.length - Buffer.byteLength(`\r\n--${boundary}--\r\n`);
  assert.ok(body.subarray(0, header.length).equals(header));
  return { command: new URLSearchParams(body.subarray(header.length, split).toString()), payload: body.subarray(start, end) };
}
export async function nativePeer(format = 'sha1', options = {}) {
  const fixture = changeFixture(format, options.files), root = await mkdtemp(join(tmpdir(), 'fg-authored-native-peer-'));
  const env = { PATH: process.env.PATH, HOME: root, GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: '/dev/null',
    GIT_CONFIG_COUNT: '0', LC_ALL: 'C', GIT_OPTIONAL_LOCKS: '0' };
  const git = (args, input) => execFileSync('git', ['-C', root, ...args], { env, input, timeout: 15000, maxBuffer: 20 * 1024 * 1024 });
  const peer = { fixture, requests: [], failures: [], fault: null, held: false, lostApply: false, candidate: null, applies: 0 };
  git(['init', '--quiet', `--object-format=${format}`]);
  for (const file of fixture.files) {
    const path = Buffer.concat([Buffer.from(root + '/'), file.path]), slash = path.lastIndexOf(47);
    await mkdir(path.subarray(0, slash), { recursive: true }); await writeFile(path, file.bytes); await chmod(path, file.mode & 0o777);
  }
  git(['add', '--all']); assert.equal(git(['write-tree']).toString().trim(), fixture.tree);
  assert.equal(git(['hash-object', '-w', '-t', 'commit', '--stdin'], Buffer.from(fixture.value.membership.commit.bodyHex, 'hex')).toString().trim(), fixture.commit);
  git(['update-ref', 'refs/heads/main', fixture.commit]);
  const scope = { ...SCOPE, object_format: format }, ref = 'refs/heads/main', ref_hex = hexPath(ref);
  const effects = { read_only: true, objects_staged: false, transaction_created: false, published: false, publication_authorized: false };
  const metadata = { author: 'Test <test@example.invalid>', committer: 'Test <test@example.invalid>', timestamp: 1700000001, message: 'authored change\n' };
  function treeEntries(tree) {
    const raw = git(['ls-tree', '-r', '-z', tree]), entries = new Map(); let at = 0;
    while (at < raw.length) {
      const nul = raw.indexOf(0, at), tab = raw.indexOf(9, at), [mode, , oid] = raw.subarray(at, tab).toString('ascii').split(' ');
      entries.set(raw.subarray(tab + 1, nul).toString('hex'), { mode: parseInt(mode, 8), oid }); at = nul + 1;
    }
    return entries;
  }
  async function prepared(patch, command) {
    assert.equal(command.get('expected_commit'), fixture.commit); assert.equal(command.get('ref'), ref);
    git(['read-tree', fixture.commit]); git(['apply', '--cached', '--whitespace=nowarn', '-'], patch);
    if (peer.fault === 'wrong-after' || peer.fault === 'wrong-new-mode') {
      const id = peer.fault === 'wrong-after' ? git(['hash-object', '-w', '--stdin'], Buffer.from('wrong but self-consistent\n')).toString().trim()
        : treeEntries(git(['write-tree']).toString().trim()).get(hexPath('src/main.rs')).oid;
      git(['update-index', '--add', '--cacheinfo', `${peer.fault === 'wrong-new-mode' ? '100755' : '100644'},${id},src/main.rs`]);
    }
    // Planted malicious peer: the real candidate contains this additional file,
    // but both advertised effect lists omit it. The commit/body/bundle remain
    // mutually consistent, exercising a whole-root check rather than a typo.
    const hidden = hexPath('unreported/payload');
    if (peer.fault === 'unreported-addition') {
      const id = git(['hash-object', '-w', '--stdin'], Buffer.from('unreported change\n')).toString().trim();
      git(['update-index', '--add', '--cacheinfo', `100644,${id},unreported/payload`]);
    }
    const tree = git(['write-tree']).toString().trim(), m = Object.fromEntries(['author', 'committer', 'timestamp', 'message'].map(k => [k, command.get(k)]));
    const body = Buffer.from(`tree ${tree}\nparent ${fixture.commit}\nauthor ${m.author} ${m.timestamp} +0000\ncommitter ${m.committer} ${m.timestamp} +0000\n\n${m.message}`);
    const commit = git(['hash-object', '-w', '-t', 'commit', '--stdin'], body).toString().trim();
    git(['update-ref', 'refs/heads/candidate', commit]);
    let bundle = git(['bundle', 'create', '-', '--all']);
    const before = treeEntries(fixture.tree), after = treeEntries(tree), entries = [];
    for (const path_hex of [...new Set([...before.keys(), ...after.keys()])].sort()) {
      if (peer.fault === 'unreported-addition' && path_hex === hidden) continue;
      const old = before.get(path_hex) ?? null, next = after.get(path_hex) ?? null;
      if (old?.oid === next?.oid && old?.mode === next?.mode) continue;
      entries.push({ path_hex, kind: old === null ? 'added' : next === null ? 'deleted' : old.mode !== next.mode ? 'mode_changed' : 'modified',
        before: old, after: next, content: { type: 'object_only', content_read: false } });
    }
    if (peer.fault === 'wrong-old-mode') {
      entries[0].before.mode = entries[0].before.mode === 0o100644 ? 0o100755 : 0o100644;
      entries[0].kind = entries[0].after === null ? 'deleted' : entries[0].before.mode === entries[0].after.mode ? 'modified' : 'mode_changed';
    }
    if (peer.fault === 'wrong-old-blob') entries[0].before.oid = 'e'.repeat(format === 'sha1' ? 40 : 64);
    // Optional fixture matching patch.rs::pack, rather than the older full
    // history fixture. Derive the inventory from Git's actual changed entries
    // and tree walk, never from the production JS expected-inventory function.
    let packedCount = git(['rev-list', '--objects', '--all']).toString().trim().split('\n').length;
    if (options.nativePatchBundle) {
      const dirty = new Set(['']), ids = new Set([commit]);
      for (const entry of entries) {
        if (entry.after) ids.add(entry.after.oid);
        const path = Buffer.from(entry.path_hex, 'hex');
        for (let at = 0; at < path.length; at++) if (path[at] === 47) dirty.add(path.subarray(0, at).toString('hex'));
      }
      ids.add(tree);
      const raw = git(['ls-tree', '-r', '-t', '-z', tree]); let at = 0;
      while (at < raw.length) {
        const nul = raw.indexOf(0, at), tab = raw.indexOf(9, at);
        const [, kind, id] = raw.subarray(at, tab).toString('ascii').split(' ');
        if (kind === 'tree' && dirty.has(raw.subarray(tab + 1, nul).toString('hex'))) ids.add(id);
        at = nul + 1;
      }
      peer.packedIds = [...ids].sort(); packedCount = ids.size;
      peer.packHeader = Buffer.from(`${format === 'sha1' ? '# v2 git bundle\n' : '# v3 git bundle\n@object-format=sha256\n'}-${fixture.commit} patch base\n${commit} ${ref}\n\n`);
      peer.packObjects = selected => git(['pack-objects', '--stdout', '--window=0', '--no-reuse-delta', '--no-reuse-object'], selected.join('\n') + '\n');
      peer.objectBody = id => git(['cat-file', '-p', id]);
      peer.objectKind = id => git(['cat-file', '-t', id]).toString().trim();
      bundle = Buffer.concat([peer.packHeader, peer.packObjects(peer.packedIds)]);
      if (peer.transformPack) bundle = peer.transformPack(bundle);
    }
    const paths = entries.map(e => ({ path_hex: e.path_hex, old_blob: e.before?.oid ?? null,
      new_blob: e.after?.oid ?? null, new_mode: e.after?.mode ?? null, hunks: e.before?.oid === e.after?.oid ? 0 : 1 }));
    const preparation = { type: 'source_preparation', schema_version: 1, ...scope, ref, ref_hex,
      source_commit: fixture.commit, source_rcr: 'rcr-before', candidate_commit: commit, root_tree: tree,
      patch_sha256: sha256(patch), object_count: packedCount,
      ...effects, bundle: { bytes: bundle.length, sha256: sha256(bundle) }, paths };
    const inspection = { type: 'source_inspection', schema_version: 1, ...scope, ref, ref_hex, source_head: 'head-before', snapshot_token: 'alg:1:1234',
      expected_commit: fixture.commit, candidate_commit: commit, parents: [fixture.commit], bundle_bytes: bundle.length,
      bundle_sha256: sha256(bundle), ...effects, all_changed_paths: true, binary_bodies_included: false,
      candidate_commit_body_hex: body.toString('hex'), comparison: { mode: 'direct',
        before_tree: peer.fault === 'wrong-before-tree' ? 'f'.repeat(format === 'sha1' ? 40 : 64) : fixture.tree,
        after_tree: tree, entry_count: entries.length, entries } };
    const boundary = `fg-source-${'a'.repeat(48)}-0`;
    const response = Buffer.concat([Buffer.from(`--${boundary}\r\nContent-Type: application/json; charset=utf-8\r\nContent-Disposition: inline; name="metadata"\r\n\r\n`), encoded(preparation),
      Buffer.from(`\r\n--${boundary}\r\nContent-Type: application/x-git-bundle\r\nContent-Disposition: attachment; name="bundle"; filename="candidate.bundle"\r\n\r\n`), bundle, Buffer.from(`\r\n--${boundary}--\r\n`)]);
    peer.candidate = { commit, tree, bundle, preparation, inspection, patch: Buffer.from(patch) };
    return { response, type: `multipart/mixed; boundary=${boundary}` };
  }
  let server, ca;
  if (options.tls) {
    const key = join(root, 'tls.key'), cert = join(root, 'tls.crt');
    execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', key, '-out', cert,
      '-days', '1', '-subj', '/CN=127.0.0.1', '-addext', 'subjectAltName=IP:127.0.0.1'], { timeout: 15000, stdio: ['ignore', 'pipe', 'pipe'] });
    ca = await readFile(cert); server = httpsServer({ key: await readFile(key), cert: ca });
  } else server = httpServer();
  const sockets = new Set(); server.on('connection', s => { sockets.add(s); s.on('close', () => sockets.delete(s)); });
  server.on('request', (req, res) => { void (async () => {
    const chunks = []; let size = 0;
    for await (const chunk of req) { size += chunk.length; assert.ok(size <= 12 * 1024 * 1024); chunks.push(chunk); }
    const bytes = Buffer.concat(chunks), route = req.url.replace('/repo/api/v1/', '');
    peer.requests.push({ route, bytes, headers: { ...req.headers } }); peer.onRequest?.(route);
    assert.equal(req.method, 'POST');
    assert.ok([`Bearer ${TOKEN}`, `Bearer ${ROTATED_TOKEN}`].includes(req.headers.authorization));
    if (peer.held) return;
    if (peer.httpStatus) { res.writeHead(peer.httpStatus, { 'Content-Type': 'application/json' }); res.end('{"error":"private server diagnostic"}'); return; }
    let response, type = 'application/json';
    if (route === 'source/prepare') {
      assert.equal(req.headers['idempotency-key'], undefined);
      const { command, payload } = multipart(bytes, req.headers['content-type']);
      ({ response, type } = await prepared(payload, command));
    } else if (route === 'source/inspect') {
      assert.equal(req.headers['idempotency-key'], undefined);
      const { command, payload } = multipart(bytes, req.headers['content-type']);
      assert.ok(payload.equals(peer.candidate.bundle)); assert.equal(command.get('candidate_commit'), peer.candidate.commit);
      response = encoded(peer.candidate.inspection);
    } else if (route === 'source/apply') {
      const { command, payload } = multipart(bytes, req.headers['content-type']);
      assert.ok(payload.equals(peer.candidate.bundle)); assert.equal(command.get('candidate_commit'), peer.candidate.commit);
      assert.ok(req.headers['idempotency-key']); peer.originalKey = req.headers['idempotency-key']; peer.applies++;
      if (peer.lostApply) { res.destroy(); return; }
      response = encoded({ type: 'source_publication', schema_version: 1, ...scope, principal_id: PRINCIPAL, ref, ref_hex,
        expected_commit: fixture.commit, candidate_commit: peer.candidate.commit, tx_id: 'tx-authored', outcome: 'committed',
        decision_sequence: '18446744073709551615', decision_record: 'rcr-authored', refusal_code: null, delivery_acknowledged: null });
    } else if (route === 'outcomes') {
      assert.equal(bytes.length, 0); assert.equal(req.headers['idempotency-key'], peer.originalKey);
      response = encoded({ type: 'transaction_outcome', schema_version: 1, ...SCOPE, principal_id: PRINCIPAL,
        selector: 'transaction', command_index: null, state: 'committed', terminal: true,
        transaction: { tx_id: 'tx-authored', seal_id: 'seal-authored', request_schema: 'source-apply-v1', canonical_request_digest: { algorithm: 1, hex: '44'.repeat(32) } },
        decision: { kind: 'committed', decision_sequence: '18446744073709551615', repository_commit_id: 'rcr-authored' },
        read_only: true, request_reexecuted: false, absence_proves_non_commit: false, session_completeness_established: false });
    } else throw new Error(`Unexpected test peer route: ${route}`);
    res.writeHead(200, { 'Content-Type': type, 'Content-Length': String(response.length) }); res.end(response);
  })().catch(error => { peer.failures.push(error); if (!res.headersSent) res.writeHead(500, { 'Content-Type': 'application/json' }); res.end('{}'); }); });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  peer.endpoint = `${options.tls ? 'https' : 'http'}://127.0.0.1:${server.address().port}/repo`; peer.ca = ca;
  peer.selection = paths => ({ endpoint: peer.endpoint, scope: { ...scope }, ref, expected_commit: fixture.commit, metadata: { ...metadata }, paths_hex: [...paths] });
  peer.close = async () => { for (const socket of sockets) socket.destroy(); await new Promise(resolve => server.close(resolve)); await rm(root, { recursive: true, force: true }); };
  return peer;
}
