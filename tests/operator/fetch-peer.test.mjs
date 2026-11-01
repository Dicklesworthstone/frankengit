// Real Node sockets and Fetch, not native forge or external-service evidence.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { listenForFetch } from '../fetch-peer.mjs';

const headers = { 'User-Agent': 'frankengit-agent (+https://github.com/Dicklesworthstone/frankengit)' };
const close = server => new Promise((resolve, reject) => {
  server.closeAllConnections(); server.close(error => error ? reject(error) : resolve());
});
const bind = (server, port) => new Promise((resolve, reject) => {
  const failed = error => { server.removeListener('listening', ready); reject(error); };
  const ready = () => { server.removeListener('error', failed); resolve(); };
  server.once('error', failed); server.once('listening', ready); server.listen(port, '127.0.0.1');
});
async function peer(t, restricted = false) {
  let contacts = 0;
  const server = createServer((request, response) => { contacts++; response.end('actual peer'); });
  t.after(async () => { if (server.listening) await close(server); });
  if (restricted) {
    let bound = false;
    for (const port of [6000, 6666, 10080]) {
      try { await bind(server, port); bound = true; break; }
      catch (error) { if (error.code !== 'EADDRINUSE') throw error; }
    }
    assert(bound, 'none of the three real restricted-port controls was available');
  }
  return { server, contacts: () => contacts };
}

test('a real Fetch-blocked listener is retired before exposing a usable peer URL', async t => {
  const f = await peer(t, true), oldPort = f.server.address().port;
  await assert.rejects(fetch(`http://127.0.0.1:${oldPort}/`, { headers }), error => {
    assert.equal(error.cause?.message, 'bad port'); return true;
  });
  assert.equal(f.contacts(), 0, 'Fetch refuses before any TCP request');
  const address = await listenForFetch(f.server);
  assert.notEqual(address.port, oldPort);
  assert.equal(await (await fetch(`http://127.0.0.1:${address.port}/`, { headers })).text(), 'actual peer');
  assert.equal(f.contacts(), 1);
});

test('an already usable peer retains its bound port and normal Fetch behavior', async t => {
  const f = await peer(t), first = await listenForFetch(f.server);
  const second = await listenForFetch(f.server);
  assert.equal(first.port, second.port);
  assert.equal(await (await fetch(`http://127.0.0.1:${second.port}/`, { headers })).text(), 'actual peer');
  assert.equal(f.contacts(), 1);
});

test('persistent restricted-port allocation fails within the finite bind budget and leaves no listener', async t => {
  const f = await peer(t, true), restrictedPort = f.server.address().port;
  const originalListen = f.server.listen.bind(f.server);
  let binds = 0;
  // Explicit allocator fault injection. Every attempt still binds the real
  // Node HTTP server; no network result or forge receipt is fabricated.
  f.server.listen = (port, ...rest) => { binds++; return originalListen(restrictedPort, ...rest); };
  await assert.rejects(listenForFetch(f.server), { code: 'fetch_peer_port_exhausted' });
  assert(binds > 0 && binds <= 16, `unbounded bind attempts: ${binds}`);
  assert.equal(f.server.listening, false);
});
