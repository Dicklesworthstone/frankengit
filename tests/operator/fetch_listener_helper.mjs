// Test-only HTTP peers must publish ports accepted by the pinned Node Fetch.
// Match the native HTTP campaign's policy: every forbidden port is <= 10080.
import { once } from 'node:events';

export async function listenForFetch(server) {
  for (let attempt = 0; attempt < 16; attempt += 1) {
    server.listen(0, '127.0.0.1'); await once(server, 'listening');
    const { port } = server.address();
    if (port > 10080) return port;
    // The URL has not escaped yet. Drain this listener before asking the OS
    // for another; never retry a client request or change its original key.
    server.closeAllConnections();
    await new Promise((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
  }
  throw Object.assign(new Error('No Fetch-permitted port after 16 drained listeners.'), {
    code: 'fetch_listener_unavailable',
  });
}
