// Explicit HTTP schema peer: these tests exercise the production Node client,
// traversal and private custody, not a native Rust authority or deployment.
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { mkdtemp, writeFile, readFile, rm, chmod } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { recordDigest } from '../../scripts/lib/forge-operator-io.mjs';
import { listenForFetch } from '../fetch-peer.mjs';

export const tenant = '1'.repeat(32), repository = '2'.repeat(32), token = 'a'.repeat(64);
export const actor = '3'.repeat(32), other = '4'.repeat(32);
export const head = 'alg:2:' + '6'.repeat(64), sourceHead = 'head-immutable-discussions-1';
export const encode = value => Buffer.from(JSON.stringify(value) + '\n');
export const event = (version, who, name, fields = {}) => ({ version, actor: who, action: { name, ...fields } });
export const data = () => [
  { discussion: { number: 1, version: 12, title: 'Edited while locked', body: 'New body <script>data</script>\r\n尾',
    state: 'closed', opened_by: actor, last_actor: other, comments: 3, locked: true },
    events: [event(1, actor, 'open', { title: 'Original title', body: 'Original body' }),
      event(2, other, 'comment', { body: 'Original comment\n\u202e preserved' }), event(3, actor, 'lock'),
      event(4, other, 'edit', { body: 'New body <script>data</script>\r\n尾' }), event(5, actor, 'close'),
      event(6, other, 'reopen'), event(7, actor, 'unlock'),
      event(8, other, 'comment', { body: 'After unlock' }), event(9, actor, 'close'),
      event(10, other, 'comment', { body: 'Allowed while closed and unlocked' }), event(11, actor, 'lock'),
      event(12, other, 'edit', { title: 'Edited while locked' })] },
  { discussion: { number: Number.MAX_SAFE_INTEGER, version: 1, title: 'Largest exact discussion number', body: '',
    state: 'open', opened_by: other, last_actor: other, comments: 0, locked: false },
    events: [event(1, other, 'open', { title: 'Largest exact discussion number', body: '' })] },
];

export async function fixture(t, { items = data(), change = null, handle = null } = {}) {
  const parent = await mkdtemp(join(tmpdir(), 'fg-discussion-archive-')); await chmod(parent, 0o700);
  const tokenFile = join(parent, 'token'); await writeFile(tokenFile, token + '\n', { mode: 0o600 });
  const calls = [];
  const server = createServer(async (req, res) => {
    try {
      const url = new URL(req.url, 'http://127.0.0.1');
      const after = Number(url.searchParams.get('after') ?? url.searchParams.get('after_version') ?? 0);
      const limit = Number(url.searchParams.get('limit'));
      const id = url.pathname.match(/\/discussions\/(\d+)$/)?.[1] ?? null;
      calls.push({ method: req.method, url, authorization: req.headers.authorization, key: req.headers['idempotency-key'] });
      if (handle && await handle(req, res, calls)) return;
      assert.equal(req.method, 'GET'); assert.equal(req.headers.authorization, 'Bearer ' + token);
      assert.equal(req.headers['idempotency-key'], undefined);
      assert.equal(url.searchParams.has('render'), false);
      assert.match(url.pathname, /^\/repo\/api\/v1\/discussions(?:\/\d+)?$/);
      if (calls.length > 1) assert.equal(url.searchParams.get('expected_head'), head);
      const header = { schema_version: 1, tenant_id: tenant, repository_id: repository,
        snapshot_token: head, source_head: sourceHead, scope: 'repository_discussions' };
      let body;
      if (id === null) {
        const remaining = items.filter(row => row.discussion.number > after), selected = remaining.slice(0, limit);
        body = { type: 'discussion_page', ...header, after, limit, next_after: remaining.length > limit
          ? selected.at(-1).discussion.number : null, discussions: selected.map(row => structuredClone(row.discussion)) };
      } else {
        const item = items.find(row => row.discussion.number === Number(id));
        const remaining = item.events.filter(row => row.version > after);
        body = { type: 'discussion_history', ...header, found: true, discussion: structuredClone(item.discussion),
          after_version: after, limit, next_after_version: remaining.length > limit ? after + limit : null,
          events: structuredClone(remaining.slice(0, limit)) };
      }
      const status = await change?.(body, calls.length, { parent, req, res });
      res.writeHead(status ?? 200, { 'Content-Type': 'application/json' }); res.end(encode(body));
    } catch (error) { res.writeHead(500); res.end(String(error)); }
  });
  t.after(async () => {
    server.closeAllConnections();
    if (server.listening) await new Promise((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
    await rm(parent, { recursive: true, force: true });
  });
  await listenForFetch(server);
  const options = { workdir: join(parent, 'archive'), href: `http://127.0.0.1:${server.address().port}/repo/ui/discussions/`,
    tenant, repository, tokenFile, pageSize: 1 };
  return { parent, options, calls, server, items };
}
export async function noRoot(options) { await assert.rejects(readFile(join(options.workdir, 'archive.json')), { code: 'ENOENT' }); }
export async function mutateRoot(options, edit) {
  const path = join(options.workdir, 'archive.json'), value = JSON.parse(await readFile(path)); edit(value);
  const bytes = encode(value); await writeFile(path, bytes); return recordDigest(bytes);
}
