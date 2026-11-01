// Test-only peer allocation. Some hosts allocate ephemeral ports from 1024,
// including Fetch's forbidden ports. Never publish an unusable fixture URL.
// Port data matches the WHATWG/pinned Node Undici bad-port table; no production
// request, refusal, retry policy or server address contract changes here.
const blocked = new Set([
  1, 7, 9, 11, 13, 15, 17, 19, 20, 21, 22, 23, 25, 37, 42, 43, 53, 69, 77, 79,
  87, 95, 101, 102, 103, 104, 109, 110, 111, 113, 115, 117, 119, 123, 135, 137,
  139, 143, 161, 179, 389, 427, 465, 512, 513, 514, 515, 526, 530, 531, 532,
  540, 548, 554, 556, 563, 587, 601, 636, 989, 990, 993, 995, 1719, 1720, 1723,
  2049, 3659, 4045, 4190, 5060, 5061, 6000, 6566, 6665, 6666, 6667, 6668,
  6669, 6679, 6697, 10080,
]);
const close = server => new Promise((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
const bind = server => new Promise((resolve, reject) => {
  const clear = () => { server.removeListener('error', failed); server.removeListener('listening', ready); };
  const failed = error => { clear(); reject(error); };
  const ready = () => { clear(); resolve(); };
  server.once('error', failed); server.once('listening', ready);
  try { server.listen(0, '127.0.0.1'); } catch (error) { failed(error); }
});

// Call before exposing the URL or accepting requests. An already bound usable
// peer keeps its listener; a forbidden selection is closed before reallocating.
// All sixteen forbidden selections are retired before exhaustion is reported.
export async function listenForFetch(server) {
  for (let attempt = 0; attempt < 16; attempt++) {
    if (!server.listening) await bind(server);
    const address = server.address();
    if (address && typeof address !== 'string' && Number.isInteger(address.port)
        && address.port > 0 && !blocked.has(address.port)) return address;
    await close(server);
  }
  throw Object.assign(new Error('no Fetch-compatible test peer port within the bind budget'), {
    code: 'fetch_peer_port_exhausted',
  });
}
