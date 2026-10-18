// Explicit --import fixture for command tests, never a production transport.
import assert from 'node:assert/strict';
import { appendFile, writeFile } from 'node:fs/promises';
import { makePeer } from './github-inventory-fixture.mjs';
const config = JSON.parse(process.env.FG_INVENTORY_TEST_CASE);
const peer = makePeer({ count: config.count ?? 5, pullEvery: config.pullEvery ?? 3,
  repositoryId: config.repositoryId ?? '42', commentCount: config.commentCount ?? 2,
  async onRequest(request) {
    if (config.token) assert.equal(request.init.headers.Authorization, `Bearer ${config.token}`);
    if (config.log) await appendFile(config.log, JSON.stringify({ path: request.url.pathname,
      query: request.url.search, method: request.init.method }) + '\n', { mode: 0o600 });
  },
  modify(reply) {
    if (config.replacedIssue && reply.kind === 'issue') reply.value.id = '987654321';
    if (config.fail) { reply.status = 403; reply.value = { message: 'SECRET SOURCE DIAGNOSTIC' }; }
  },
});
globalThis.fetch = async (...args) => {
  if (config.offline) throw Error('Network forbidden in offline command');
  if (config.stall) {
    await writeFile(config.ready, 'ready', { mode: 0o600 });
    return new Response(new ReadableStream({ start(c) { c.enqueue(Buffer.from('{')); },
      async cancel() { await writeFile(config.cancelled, 'cancelled', { mode: 0o600 }); },
    }), { headers: { 'Content-Type': 'application/json' } });
  }
  return peer.fetchImpl(...args);
};
