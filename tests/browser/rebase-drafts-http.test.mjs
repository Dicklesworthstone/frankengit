// Real loopback HTTP and Node's default Fetch. Responses deliberately come from
// a protocol double, not a native server. No production endpoint is contacted.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { RebaseClient } from '../../crates/fgit-node/src/smart_http/server/browser/rebase.mjs';
import { fixture, token, crypto } from './rebase-session-fixtures.mjs';
for (const algorithm of ['sha1', 'sha256']) test(`${algorithm}: real HTTP draft resume and lost-reply recovery preserve exact bodies`, async t => {
  const f = await fixture(algorithm), server = createServer(async (req, res) => {
    try {
      assert.equal(req.headers.authorization, `Bearer ${token}`);
      assert.equal(req.method, 'POST');
      let size = 0; const chunks = [];
      for await (const chunk of req) { size += chunk.length; assert(size <= 2 * 1024 * 1024); chunks.push(chunk); }
      const bytes = Buffer.concat(chunks), type = req.headers['content-type'] ?? '';
      const body = !size ? undefined : type.startsWith('application/x-www-form-urlencoded') ? bytes.toString('utf8') : new Uint8Array(bytes);
      const response = await f.fetchImpl(new URL(req.url, 'http://127.0.0.1'), { method: req.method, body, headers: req.headers });
      res.writeHead(response.status, Object.fromEntries(response.headers)); res.end(new Uint8Array(await response.arrayBuffer()));
    } catch (error) {
      if (f.config.lose && req.url.endsWith('/apply')) req.socket.destroy();
      else { res.writeHead(500); res.end(error.message); }
    }
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const href = `http://127.0.0.1:${server.address().port}/repo.git/ui/rebase/`, clients = [];
  t.after(async () => { clients.forEach(c => c.disconnect()); server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); });
  async function client() {
    const c = new RebaseClient({ href, cryptoImpl: crypto }); clients.push(c); await c.connect(token); return c;
  }
  const c = await client(); await c.select(f.command.source_ref, f.command.onto_ref, algorithm);
  f.config.sequence = [f.stopped(0), f.stopped(1)]; await c.prepare(f.input);
  const bytes = new Uint8Array([0, 255, 13, 10, 27]);
  await c.resolve([{ path_hex: f.conflict(0).path_hex, choice: 'file', mode: 0o100755, bytes }]);
  const draft = await c.exportDraft([{ path_hex: f.conflict(1).path_hex, choice: 'file', mode: 0o100644, bytes: new Uint8Array() }]);
  const fresh = await client(), before = f.calls.length; await fresh.restoreDraft(draft);
  assert.equal(f.calls.length, before); assert.equal(fresh.candidate, null); await fresh.resumeDraft();
  assert.deepEqual(f.calls.slice(before).map(c => c.endpoint), ['source/tree', 'source/tree', 'source/rebase/resolve', 'source/rebase/inspect']);
  const resolution = f.calls.findLast(c => c.endpoint === 'source/rebase/resolve');
  assert.deepEqual(resolution.files.get('file_0'), bytes); assert.equal(resolution.files.get('file_1').length, 0);
  await fresh.stage(); const pending = fresh.pending; f.config.lose = true;
  await assert.rejects(fresh.send()); assert.equal(fresh.pending.key, pending.key);
  const sent = f.calls.at(-1), receipt = fresh.exportReceipt(), restored = await client();
  await restored.restoreReceipt(receipt); f.config.lose = false; await restored.send();
  assert.deepEqual(f.calls.at(-1).options.body, sent.options.body);
  assert.equal(new Headers(f.calls.at(-1).options.headers).get('Idempotency-Key'), pending.key);
  assert.equal(restored.pending, null);
  const recoverer = await client(); await recoverer.restoreReceipt(receipt); f.config.outcome = 'committed'; await recoverer.recover();
  assert.equal(f.calls.at(-1).endpoint, 'outcomes'); assert.equal(f.calls.at(-1).options.body, undefined);
  assert.equal(new Headers(f.calls.at(-1).options.headers).get('Idempotency-Key'), pending.key);
  assert.equal(f.calls.filter(c => c.endpoint.endsWith('/apply')).length, 2);
});
