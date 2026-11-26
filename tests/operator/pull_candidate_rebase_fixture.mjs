// Controlled native-schema peers, not Rust fg or native admission evidence.
// Reuse real computed commit-body hashes; opaque bundle bytes test custody only.
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { once } from 'node:events';
import { createHash } from 'node:crypto';
import { sample, metadata } from '../browser/pulls-rebase-fixtures.mjs';
import { show, reviews, reviewRow, data, row, actor, reviewer, token, head } from '../browser/pulls-fixtures.mjs';
export { actor, reviewer, token, head };
export const sha = bytes => createHash('sha256').update(bytes).digest('hex');
export function localRebase(algorithm = 'sha1', state = 'clean') {
  const f = sample(algorithm), width = algorithm === 'sha1' ? 40 : 64;
  const preparation = { ...f.metadata, original_authors_preserved: true, original_messages_preserved: true,
    original_signatures_copied: false, author_identity_verified: false,
    generated_objects: 4, pack_objects: 4, borrowed_objects: 0 };
  const scope = { tenant_id: preparation.tenant_id, repository_id: preparation.repository_id,
    repository_incarnation: preparation.repository_incarnation, object_format: algorithm };
  const subject = { ...preparation.subject, number: 1 }; delete subject.pull_request;
  const review = reviewRow({ subject, candidate: { merge_base: f.fields.merge_base, candidate_commit: f.fields.candidate_commit },
    version: 5, decision: 'request-changes' });
  const capture = { schema: 'frankengit-pull-candidate-capture-v1', request: { endpoint: 'https://forge.invalid/repo.git',
    scope, number: '1', metadata: { upstream: f.fields.merge_base, committer: metadata.committer,
      timestamp: String(metadata.timestamp), empty: metadata.empty }, method: 'rebase', expected_head: null },
    pull: show({ object_format: algorithm, pull_request: row(1, { data: data({ object_format: algorithm,
      source_tip: f.fields.source_tip, target_tip: f.fields.target_tip }) }) }),
    review_pages: [reviews({ object_format: algorithm, limit: 50, reviews: [review] })],
    preparation_status: state === 'clean' ? 200 : 409, preparation, inspection: f.inspection };
  if (state !== 'clean') {
    Object.assign(preparation, { state, series_complete: false, provisional_steps: true, candidate_commit: null,
      root_tree: null, bundle: null, stopped_commit: f.fields.source_tip, steps: preparation.steps.slice(0, 1), step_count: 1,
      conflicts: state === 'conflicted' ? [{ path_hex: '66696c65ff', kind: 'content',
        base: { mode: 0o100644, oid: 'c'.repeat(width) }, ours: { mode: 0o100644, oid: 'd'.repeat(width) },
        theirs: { mode: 0o100644, oid: 'e'.repeat(width) } }] : [] });
    for (const key of ['generated_objects', 'pack_objects', 'borrowed_objects']) delete preparation[key];
    capture.inspection = null;
  }
  return { capture, bundle: state === 'clean' ? Buffer.from(f.bundle) : null };
}
export function rawReferences(capture, source = Buffer.from('refs/heads/raw-\u0085'), target = Buffer.from('refs/heads/main')) {
  const fields = Object.fromEntries([['source', source], ['target', target]].flatMap(([side, bytes]) => [
    [side + '_ref', null], [side + '_ref_hex', bytes.toString('hex')],
  ]));
  Object.assign(capture.pull.pull_request.data, fields);
  Object.assign(capture.preparation.subject, fields);
  if (capture.inspection) Object.assign(capture.inspection.subject, fields);
  for (const page of capture.review_pages) for (const review of page.reviews) Object.assign(review.subject, fields);
}
export function mixed(metadata, bundle) {
  const boundary = `fg-prepare-${sha(bundle).slice(0, 48)}-0`;
  return { type: `multipart/mixed; boundary=${boundary}`, body: Buffer.concat([
    Buffer.from(`--${boundary}\r\nContent-Type: application/json; charset=utf-8\r\nContent-Disposition: inline; name="metadata"\r\n\r\n${JSON.stringify(metadata)}\r\n--${boundary}\r\nContent-Type: application/x-git-bundle\r\nContent-Disposition: attachment; name="bundle"; filename="candidate.bundle"\r\n\r\n`),
    bundle, Buffer.from(`\r\n--${boundary}--\r\n`),
  ]) };
}
export function reply(response, value, status = 200) {
  const body = Buffer.from(JSON.stringify(value));
  response.writeHead(status, { 'Content-Type': 'application/json', 'Content-Length': body.length }); response.end(body);
}
function checkRefs(command, capture) {
  const data = capture.pull.pull_request.data;
  for (const side of ['source', 'target']) {
    const name = side + '_ref', encoded = name + '_hex';
    assert.equal(command.get(name), data[name]);
    assert.equal(command.get(encoded), data[name] === null ? data[encoded] : null);
  }
}
export async function rebasePeer(t, { algorithm = 'sha1', state = 'clean', mutate, handle, reviewCount = 1 } = {}) {
  const p = { ...localRebase(algorithm, state), requests: [], errors: [] };
  if (mutate) mutate(p);
  p.reviews = Array.from({ length: reviewCount }, (_, i) => ({ ...structuredClone(p.capture.review_pages[0].reviews[0]),
    reviewer: reviewCount === 1 ? reviewer : (i + 1).toString(16).padStart(32, '0') }));
  const sockets = new Set();
  const server = createServer(async (request, response) => {
    try {
      const chunks = []; let size = 0;
      for await (const chunk of request) { size += chunk.length; assert.ok(size <= 19 * 1024 * 1024); chunks.push(chunk); }
      const r = { method: request.method, url: request.url, headers: request.headers, body: Buffer.concat(chunks) };
      p.requests.push(r);
      assert.equal(r.headers.authorization, `Bearer ${token}`); assert.equal(r.headers['idempotency-key'], undefined);
      assert.equal(r.headers.cookie, undefined);
      if (handle && await handle(r, response, p)) return;
      const url = new URL(r.url, 'http://fixture.invalid'), capture = p.capture;
      if (url.pathname === '/repo.git/api/v1/pulls/1') {
        assert.equal(r.method, 'GET'); assert.equal(size, 0); reply(response, capture.pull);
      } else if (url.pathname === '/repo.git/api/v1/pulls/1/reviews') {
        assert.equal(r.method, 'GET'); assert.equal(url.searchParams.get('expected_head'), head);
        const after = url.searchParams.get('after'), limit = Number(url.searchParams.get('limit'));
        const remaining = p.reviews.filter(row => after === null || row.reviewer > after), rows = remaining.slice(0, limit);
        reply(response, { ...capture.review_pages[0], after, limit, reviews: rows, next_after: remaining.length > limit ? rows.at(-1).reviewer : null });
      } else if (url.pathname === '/repo.git/api/v1/pulls/1/prepare-rebase') {
        assert.equal(r.method, 'POST');
        const command = new URLSearchParams(r.body.toString()); checkRefs(command, capture);
        assert.equal([...command].length, 12); assert.equal(command.get('profile'), 'path-v1');
        for (const key of ['upstream', 'committer', 'timestamp', 'empty']) assert.equal(command.get(key), capture.request.metadata[key]);
        assert.equal(command.has('method'), false); assert.equal(command.has('author'), false); assert.equal(command.has('message'), false);
        if (capture.preparation.state === 'clean') {
          const body = mixed(capture.preparation, p.bundle);
          response.writeHead(200, { 'Content-Type': body.type, 'Content-Length': body.body.length }); response.end(body.body);
        } else reply(response, capture.preparation, 409);
      } else if (url.pathname === '/repo.git/api/v1/pulls/1/inspect-rebase') {
        assert.equal(r.method, 'POST');
        const boundary = r.headers['content-type'].split('boundary=')[1];
        const marker = Buffer.from('Content-Type: application/x-git-bundle\r\n\r\n'), start = r.body.indexOf(marker) + marker.length;
        const end = r.body.length - Buffer.byteLength(`\r\n--${boundary}--\r\n`);
        assert.deepEqual(r.body.subarray(start, end), p.bundle);
        const commandStart = r.body.indexOf(Buffer.from('\r\n\r\n')) + 4;
        const commandEnd = r.body.indexOf(Buffer.from(`\r\n--${boundary}\r\n`), commandStart);
        const command = new URLSearchParams(r.body.subarray(commandStart, commandEnd).toString()); checkRefs(command, capture);
        assert.equal([...command].length, 9); assert.equal(command.get('candidate_commit'), capture.preparation.candidate_commit);
        reply(response, capture.inspection);
      } else throw new Error('Unexpected candidate route: ' + r.url);
    } catch (error) { p.errors.push(error); response.destroy(); }
  });
  server.on('connection', socket => { sockets.add(socket); socket.on('close', () => sockets.delete(socket)); });
  server.listen(0, '127.0.0.1'); await once(server, 'listening');
  t.after(async () => { for (const socket of sockets) socket.destroy(); await new Promise(resolve => server.close(resolve)); assert.deepEqual(p.errors, []); });
  p.capture.request.endpoint = `http://127.0.0.1:${server.address().port}/repo.git`;
  p.input = p.capture.request;
  return p;
}
