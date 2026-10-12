// Native HTTP schema contract, real sockets/files and shipped clients; not an fg run.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { IssueClient } from '../../crates/fgit-node/src/smart_http/server/browser/issues.mjs';
import { runIssueOperation } from '../../scripts/lib/forge-issue-operator.mjs';

const tenant = 'a'.repeat(32), repository = 'b'.repeat(32), token = 'c'.repeat(64);
const actor = 'd'.repeat(32), snapshot = `alg:2:${'e'.repeat(64)}`;
const binding = { schema_version: 1, tenant_id: tenant, repository_id: repository };
const missing = (limit = 1) => ({ ...binding, type: 'issue_history', snapshot_token: snapshot,
  found: false, issue: null, after_version: 0, limit, next_after_version: null, events: [] });
const existing = (limit = 1) => ({ ...missing(limit), found: true,
  issue: { number: 7, version: 1, title: 'Existing', body: '', labels: [], state: 'open',
    opened_by: actor, last_actor: actor, comments: 0, assignees: [] },
  events: [{ version: 1, actor, action: { name: 'open', title: 'Existing', body: '', labels: [] } }] });
const response = (value, status) => new Response(JSON.stringify(value), {
  status, headers: { 'Content-Type': 'application/json' } });
async function client(value, status) {
  const c = new IssueClient({ href: 'https://forge.example/repo.git/ui/issues/',
    fetchImpl: async () => response(value, status) });
  await c.connect(token); return c;
}
async function fixture(t, history = missing()) {
  const dir = await mkdtemp(join(tmpdir(), 'fg-issue-native-absence-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const tokenFile = join(dir, 'token'), record = join(dir, 'request.json');
  await writeFile(tokenFile, token, { mode: 0o600 });
  const calls = [], server = createServer(async (request, reply) => {
    let body = ''; for await (const bytes of request) body += bytes;
    calls.push({ method: request.method, path: request.url, body, key: request.headers['idempotency-key'] });
    reply.setHeader('Content-Type', 'application/json');
    if (request.method === 'GET') { reply.writeHead(history.found ? 200 : 404); reply.end(JSON.stringify(history)); return; }
    // A durable, exact original request must already exist before publication.
    const saved = JSON.parse(await readFile(record, 'utf8'));
    assert.equal(saved.receipt.request.key, request.headers['idempotency-key']);
    assert.equal(saved.receipt.request.body, body);
    reply.end(JSON.stringify({ ...binding, type: 'issue_publication', number: 7, expected_version: 0,
      action: 'open', principal_id: actor, tx_id: 'tx-1', outcome: 'committed', decision_sequence: 1,
      repository_commit_id: 'rcr-1', refusal_code: null, refusal_record_id: null, delivery_acknowledged: null }));
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => { server.closeAllConnections(); return new Promise(resolve => server.close(resolve)); });
  return { dir, calls, options: { href: `http://127.0.0.1:${server.address().port}/repo.git/ui/issues/`,
    tenant, repository, tokenFile, record, operation: 'open', number: 7, expectedVersion: 0,
    fields: { title: 'Imported issue', body: 'Original text', labels: [] } } };
}

test('native 404 history allows the operator to persist and publish a new issue', async t => {
  const f = await fixture(t);
  const result = await runIssueOperation(f.options);
  assert.equal(result.state, 'terminal_observed'); assert.equal(result.result.outcome, 'committed');
  assert.equal(result.mutation_submitted, true);
  assert.deepEqual(f.calls.map(c => c.method), ['GET', 'POST']);
  assert.equal(f.calls[0].key, undefined); assert.equal(f.calls[1].path, '/repo.git/api/v1/issues/7/open');
  assert.match(f.calls[1].body, /expected_version=0/);
});

test('occupied issue number never becomes a new-stream mutation', async t => {
  const f = await fixture(t, existing());
  await assert.rejects(runIssueOperation(f.options), /version_moved/);
  assert.deepEqual(f.calls.map(c => c.method), ['GET']);
  await assert.rejects(readFile(f.options.record), { code: 'ENOENT' });
});

test('native absent and present history twins remain readable', async () => {
  for (const [reply, status, found] of [[missing(), 404, false], [existing(), 200, true]]) {
    const c = await client(reply, status);
    assert.equal((await c.read(7, { limit: 1 })).reply.found, found);
    assert.deepEqual(c.binding, { tenant, repository }); assert.equal(c.pending, null); c.disconnect();
  }
});

test('404 cannot carry a present history or fabricate an empty repository list', async () => {
  const c = await client(existing(), 404);
  await assert.rejects(c.read(7, { limit: 1 }), /status|presence/i);
  assert.equal(c.binding, null); c.disconnect();
  const listing = await client({ ...binding, type: 'issue_page', snapshot_token: snapshot,
    after: 0, limit: 20, next_after: null, issues: [] }, 404);
  await assert.rejects(listing.read(), error => error.status === 404);
  listing.disconnect();
});

for (const [name, change] of [
  ['generic route error', () => ({ error: 'not_found' })],
  ['wrong type', v => ({ ...v, type: 'outcome_error' })],
  ['missing snapshot', v => ({ ...v, snapshot_token: null })],
  ['event disclosure', v => ({ ...v, events: existing().events })],
  ['stray continuation', v => ({ ...v, next_after_version: 1 })],
  ['wrong page', v => ({ ...v, limit: 2 })],
]) test(`404 refuses ${name} without installing a repository observation`, async () => {
  const c = await client(change(missing()), 404);
  await assert.rejects(c.read(7, { limit: 1 })); assert.equal(c.binding, null); c.disconnect();
});

test('absence is still bound to the selected repository and snapshot', async () => {
  let reply = existing();
  const c = new IssueClient({ href: 'https://forge.example/repo.git/ui/issues/',
    fetchImpl: async () => response(reply, reply.found ? 200 : 404) });
  await c.connect(token); await c.read(7, { limit: 1 });
  reply = { ...missing(), repository_id: 'f'.repeat(32) };
  await assert.rejects(c.read(8, { limit: 1 }), /identity/);
  reply = missing();
  await assert.rejects(c.read(8, { limit: 1, head: `alg:2:${'0'.repeat(64)}` }), /snapshot/i);
  assert.deepEqual(c.binding, { tenant, repository }); c.disconnect();
});

test('legacy 200 absent histories remain compatible, without interpreting generic errors as absence', async () => {
  const c = await client(missing(), 200);
  assert.equal((await c.read(7, { limit: 1 })).reply.found, false); c.disconnect();
});
