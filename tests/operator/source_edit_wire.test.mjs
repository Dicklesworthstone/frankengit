// Real socket/header contracts only; no Git or native authority is simulated.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { once } from 'node:events';
import { exchange, clock, upload } from '../../scripts/operator/source_edit_wire.mjs';

for (const operation of ['prepare', 'inspect', 'apply', 'outcomes']) {
  test(`${operation}: source transport sends honest project identity without credential leakage`, async t => {
    let seen;
    const server = createServer((request, response) => {
      seen = request.headers;
      request.resume();
      request.on('end', () => {
        response.writeHead(200, { 'Content-Type': operation === 'prepare'
          ? 'multipart/mixed; boundary=wire-contract' : 'application/json', 'Content-Length': '2' });
        response.end('{}');
      });
    });
    server.listen(0, '127.0.0.1'); await once(server, 'listening');
    t.after(() => new Promise(resolve => server.close(resolve)));
    const credential = 'a'.repeat(64);
    const key = ['apply', 'outcomes'].includes(operation) ? 'retained-original-key' : null;
    const reply = await exchange(`http://127.0.0.1:${server.address().port}/repository.git`, credential,
      operation, operation === 'outcomes' ? null : upload({}, Buffer.from('wire bytes'), 'bundle'), clock(), 1024, key);
    assert.equal(reply.status, 200);
    assert.equal(seen['user-agent'], 'frankengit-agent (+https://github.com/Dicklesworthstone/frankengit)');
    assert.equal(seen.authorization, `Bearer ${credential}`);
    assert.equal(seen['idempotency-key'], key ?? undefined);
    assert.equal(seen.cookie, undefined);
    assert.equal(seen['user-agent'].includes(credential), false);
  });
}
