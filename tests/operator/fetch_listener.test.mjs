// Actual loopback sockets and Fetch, with only port allocation fault-injected.
// The issue/milestone peers remain schema fixtures, not native fg authority.
import test from 'node:test';
import assert from 'node:assert/strict';
import { Server, createServer } from 'node:http';
import { createServer as createPortProbe } from 'node:net';
import { once } from 'node:events';
import { listenForFetch } from './fetch_listener_helper.mjs';
import { peer as issuePeer } from './native_issue_transfer_helper.mjs';
import { milestonePeer } from './native_milestone_transfer_helper.mjs';

async function availableBlockedPort() {
  for (const port of [6667, 6666, 10080, 6000]) {
    const probe = createPortProbe();
    try {
      probe.listen(port, '127.0.0.1'); await once(probe, 'listening');
      await new Promise(resolve => probe.close(resolve)); return port;
    } catch (error) { if (error.code !== 'EADDRINUSE') throw error; }
  }
  throw new Error('No unoccupied Fetch-forbidden port for the transport regression.');
}
function injectPort(t, choose) {
  const descriptor = Object.getOwnPropertyDescriptor(Server.prototype, 'listen');
  const original = Server.prototype.listen;
  Server.prototype.listen = function (port, ...args) {
    return original.call(this, port === 0 ? choose() : port, ...args);
  };
  t.after(() => {
    if (descriptor) Object.defineProperty(Server.prototype, 'listen', descriptor);
    else delete Server.prototype.listen;
  });
}
for (const [kind, factory] of [['issue', issuePeer], ['milestone', milestonePeer]]) {
  test(`${kind} peer drains a forbidden initial listener before serving real Fetch`, async t => {
    const blocked = await availableBlockedPort(); let attempts = 0;
    injectPort(t, () => ++attempts === 1 ? blocked : 0);
    const peer = await factory();
    try {
      assert.ok(Number(new URL(peer.href).port) > 10080); assert.ok(attempts >= 2);
      const response = await fetch(peer.href.replace('/ui/issues/', '/api/v1/issues?after=0&limit=20'), {
        signal: AbortSignal.timeout(5000), headers: { Authorization: 'Bearer ' + peer.token,
          'User-Agent': 'frankengit-agent (+https://github.com/Dicklesworthstone/frankengit)' },
      });
      assert.equal(response.status, 200); assert.equal((await response.json()).type, 'issue_page');
      assert.equal(peer.calls.length, 1, 'listener selection must not send speculative API requests');
    } finally { await peer.close(); }
  });
}
test('repeated forbidden allocations refuse after bounded, fully drained listeners', async t => {
  const blocked = await availableBlockedPort(); let attempts = 0, closes = 0;
  injectPort(t, () => { attempts += 1; return blocked; });
  const server = createServer(); server.on('close', () => { closes += 1; });
  await assert.rejects(listenForFetch(server), { code: 'fetch_listener_unavailable' });
  assert.equal(attempts, 16); assert.equal(closes, 16); assert.equal(server.listening, false);
});
test('a real bind error is reported without retries or a leaked listener', async t => {
  const held = createPortProbe(); held.listen(0, '127.0.0.1'); await once(held, 'listening');
  const server = createServer(); let attempts = 0;
  injectPort(t, () => { attempts += 1; return held.address().port; });
  try {
    await assert.rejects(listenForFetch(server), { code: 'EADDRINUSE' });
    assert.equal(attempts, 1); assert.equal(server.listening, false);
  } finally { await new Promise(resolve => held.close(resolve)); }
});
