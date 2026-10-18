// Independent native-v1 JSON peers, not a Rust node or authorization oracle.
import { createServer } from 'node:http';
import { createServer as createTlsServer } from 'node:https';
import { once } from 'node:events';
export const TOKEN = '0123456789abcdef'.repeat(4);
export const NUMBER = '9007199254740993', VERSION = '9007199254740995', EPOCH = '18446744073709551615';
export const HEAD = 'alg:1:' + 'd'.repeat(64), SOURCE = 'native-head-identity';
export const person = n => n.toString(16).padStart(32, '0');
export function selection(endpoint, format = 'sha1') {
  return { endpoint, scope: { tenant_id: person(1), repository_id: person(2), repository_incarnation: person(3), object_format: format },
    number: NUMBER, expected_head: null };
}
export function data(format = 'sha1', byteOnly = false) {
  const source = Buffer.concat([Buffer.from('refs/heads/topic'), ...(byteOnly ? [Buffer.from([255])] : [])]);
  return { source_ref: byteOnly ? null : source.toString(), source_ref_hex: source.toString('hex'), target_ref: 'refs/heads/main',
    target_ref_hex: Buffer.from('refs/heads/main').toString('hex'), object_format: format,
    source_tip: `${format}:${'a'.repeat(format === 'sha1' ? 40 : 64)}`, target_tip: `${format}:${'b'.repeat(format === 'sha1' ? 40 : 64)}`,
    title: 'Review 🦀', body: '<script>data only</script>\n\u202e' };
}
export function fixture(selected, { count = 3, byteOnly = false, found = true, state = 'open', legacyMerge = false } = {}) {
  const header = { schema_version: 1, ...selected.scope, source_head: SOURCE, snapshot_token: HEAD };
  const metadata = data(selected.scope.object_format, byteOnly);
  const pull = { type: 'pull_request', ...header, number: selected.number, found,
    pull_request: !found ? null : { number: selected.number, version: VERSION, state, data: legacyMerge ? null : metadata,
      opened_by: legacyMerge ? null : person(99), last_metadata_actor: legacyMerge ? null : person(99), merge_only: legacyMerge,
      merge: state !== 'merged' ? null : { object_format: selected.scope.object_format,
        ...Object.fromEntries(['source_ref', 'source_ref_hex', 'target_ref', 'target_ref_hex', 'source_tip'].map(k => [k, metadata[k]])),
        target_tip_before: metadata.target_tip, base_tip: metadata.target_tip, merge_commit: metadata.source_tip } } };
  const subject = { number: selected.number, pull_request_version: VERSION, policy_epoch: EPOCH,
    ...Object.fromEntries(['source_ref', 'source_ref_hex', 'target_ref', 'target_ref_hex', 'source_tip', 'target_tip'].map(k => [k, metadata[k]])) };
  const reviews = Array.from({ length: count }, (_, i) => ({ reviewer: person(i + 10), version: String(BigInt(VERSION) + BigInt(i)),
    subject: structuredClone(subject), candidate: { merge_base: metadata.target_tip, candidate_commit: `${selected.scope.object_format}:${'c'.repeat(selected.scope.object_format === 'sha1' ? 40 : 64)}` },
    decision: i === 1 ? 'request-changes' : 'approve', reason: `Vote ${i}: %2f \" \\ 🦀`,
    freshness: state === 'open' ? 'current' : 'pull_request_closed', reviewer_is_opener: legacyMerge ? null : false }));
  return { pull, reviews, page(after = null, limit = 2) {
    const left = reviews.filter(row => after === null || row.reviewer > after), rows = left.slice(0, limit);
    return { type: 'review_page', ...header, number: selected.number, found: true, pull_request_version: VERSION, policy_epoch: EPOCH,
      after, limit, next_after: left.length > limit ? rows.at(-1).reviewer : null, merge_authorized: false, reviews: rows };
  } };
}
export function wire(value) {
  const counters = new Set(['number', 'version', 'pull_request_version', 'policy_epoch']);
  return JSON.stringify(value, (key, value) => counters.has(key) && typeof value === 'string' ? JSON.rawJSON(value) : value);
}
export function respond(res, value, status = 200) { res.writeHead(status, { 'Content-Type': 'application/json' }); res.end(wire(value)); }
export async function peer(t, options = {}) {
  const state = { requests: [], sockets: new Set() };
  const handler = async (req, res) => {
    const chunks = []; for await (const chunk of req) chunks.push(chunk);
    const url = new URL(req.url, state.selected.endpoint), record = { url, headers: req.headers, method: req.method, body: Buffer.concat(chunks) };
    state.requests.push(record);
    if (options.handle && await options.handle(record, res, state)) return;
    if (url.pathname.endsWith('/reviews')) respond(res, state.native.page(url.searchParams.get('after'), Number(url.searchParams.get('limit'))));
    else respond(res, state.native.pull, state.native.pull.found ? 200 : 404);
  };
  const server = options.tls ? createTlsServer(options.tls, handler) : createServer(handler);
  server.on('connection', socket => { state.sockets.add(socket); socket.on('close', () => state.sockets.delete(socket)); });
  server.listen(0, '127.0.0.1'); await once(server, 'listening');
  state.selected = selection(`${options.tls ? 'https' : 'http'}://127.0.0.1:${server.address().port}/repo.git`, options.format);
  state.native = fixture(state.selected, options);
  t.after(async () => { for (const socket of state.sockets) socket.destroy(); await new Promise(resolve => server.close(resolve)); });
  return state;
}
