// Native-schema HTTP peers, not an fg server or a native codec oracle.
import { createServer } from 'node:http';
import { createServer as createTlsServer } from 'node:https';
import { once } from 'node:events';
export const TOKEN = '42'.repeat(32);
export function config(endpoint = 'http://127.0.0.1:9419/repo.git', format = 'sha1') {
  return { type: 'frankengit_event_subscription', schema_version: 1, endpoint,
    scope: { tenant_id: 'a1'.repeat(16), repository_id: 'a2'.repeat(16), repository_incarnation: 'a3'.repeat(16),
      object_format: format, issues_read: true, pulls_read: false }, after: '0', page_size: 20 };
}
export function row(sequence = '1', index = '0') {
  return { cursor: `${sequence}:${index}`, repository_sequence: sequence, event_index: index,
    tx_id: 'opaque-tx', policy_epoch: '0', aggregate: 'issue-1', aggregate_version: '1', kind: 25, event_frame_hex: '00ff80' };
}
export function page(configuration, { rows = [row()], resume = undefined, more = false, head = '01' } = {}) {
  const watermark = resume === undefined ? rows.at(-1)?.cursor ?? null : resume;
  return { type: 'forge_event_page', schema_version: 1, ...configuration.scope, source_head: `opaque-head-${head}`,
    snapshot_token: `alg:1:${head.repeat(32)}`, read_only: true, disclosure_profile: 'issues-pulls-v1',
    omits_other_event_families: true, cursor_discloses_repository_activity: true, events: rows,
    next_after: more ? watermark : null, resume_after: watermark, has_more: more, complete: !more };
}
export function json(response, value, status = 200, headers = {}) {
  const bytes = Buffer.from(JSON.stringify(value));
  response.writeHead(status, { 'Content-Type': 'application/json', 'Content-Length': bytes.length, ...headers }); response.end(bytes);
}
export async function peer(handler, tls = null) {
  const requests = [], sockets = new Set();
  const listener = (request, response) => { requests.push({ url: request.url, method: request.method, headers: request.headers }); handler(request, response, requests.length); };
  const server = tls ? createTlsServer(tls, listener) : createServer(listener);
  server.on('connection', socket => { sockets.add(socket); socket.once('close', () => sockets.delete(socket)); });
  server.listen(0, '127.0.0.1'); await once(server, 'listening');
  return { endpoint: `${tls ? 'https' : 'http'}://127.0.0.1:${server.address().port}/repo.git`, requests, sockets,
    async close() { for (const socket of sockets) socket.destroy(); server.close(); await once(server, 'close'); } };
}
