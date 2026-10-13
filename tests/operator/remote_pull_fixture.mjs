// Explicit native-schema HTTP peers, not Rust admission or a repository engine.
import { createServer as httpServer } from 'node:http';
import { createServer as httpsServer } from 'node:https';
import { once } from 'node:events';
import { preparePull } from '../../scripts/operator/remote_pull.mjs';

export const TOKEN = 'a'.repeat(64), ROTATED = 'b'.repeat(64);
export const BASE_SCOPE = Object.freeze({ tenant_id: '1'.repeat(32), repository_id: '2'.repeat(32),
  repository_incarnation: '3'.repeat(32), principal_id: '4'.repeat(32) });
export function input(endpoint, action = 'open', algorithm = 'sha1') {
  const fields = action === 'comment' ? { expected_version: '0', body: 'Discussion, not approval.\n🦀' }
    : { [action === 'fast-forward' ? 'pull_request_version' : 'expected_version']: action === 'open' ? '0' : '9007199254740993',
      source_ref: 'refs/heads/topic', target_ref: 'refs/heads/main',
      source_tip: 'a'.repeat(algorithm === 'sha1' ? 40 : 64), target_tip: 'b'.repeat(algorithm === 'sha1' ? 40 : 64),
      ...(action === 'fast-forward' ? {} : { title: 'Review 🦀', body: '<script>not executed</script>\n%2f\u202e' }) };
  return { endpoint, scope: { ...BASE_SCOPE, object_format: algorithm }, number: '18446744073709551615', action, fields };
}
export function publication(intent, state = 'committed') {
  const ff = intent.action === 'fast-forward', comment = intent.action === 'comment', committed = state === 'committed';
  return { type: ff ? 'fast_forward_merge_publication' : comment ? 'pull_request_comment_publication' : 'pull_request_publication',
    schema_version: 1, ...intent.scope, number: intent.number, action: intent.action,
    ...(ff ? { pull_request_version: intent.fields.pull_request_version,
      ...Object.fromEntries(['source', 'target'].flatMap(side => [[`${side}_ref`, intent.fields[`${side}_ref`]],
        [`${side}_ref_hex`, Buffer.from(intent.fields[`${side}_ref`]).toString('hex')],
        [`${side}_tip`, `${intent.scope.object_format}:${intent.fields[`${side}_tip`]}`]])) }
      : { expected_version: intent.fields.expected_version, ...(comment ? { refs_changed: false,
        comment_version: committed ? String(BigInt(intent.fields.expected_version) + 1n) : null } : {}) }),
    tx_id: 'native-transaction', outcome: state, decision_sequence: '18446744073709551615',
    repository_commit_id: committed ? 'native-rcr' : null, refusal_record_id: committed ? null : 'native-refusal',
    refusal_code: committed ? null : 'PolicyDenied', refusal_code_point: committed ? null : 17, delivery_acknowledged: null };
}
export function outcome(intent, state = 'key_not_observed') {
  const p = publication(intent, state), { object_format: _, ...scope } = intent.scope;
  const terminal = ['committed', 'refused'].includes(state), present = !['key_not_observed', 'seal_not_observed'].includes(state);
  return { type: 'transaction_outcome', schema_version: 1, ...scope, selector: 'transaction', command_index: null, state, terminal,
    transaction: !present ? null : { tx_id: p.tx_id, seal_id: 'native-seal', request_schema: 'native-pr-schema-v1',
      canonical_request_digest: { algorithm: 1, hex: 'c'.repeat(64) } },
    decision: !terminal ? null : { kind: state, decision_sequence: p.decision_sequence,
      ...(state === 'committed' ? { repository_commit_id: p.repository_commit_id } :
        { code: p.refusal_code, code_point: p.refusal_code_point, refusal_record_id: p.refusal_record_id }) },
    read_only: true, request_reexecuted: false, absence_proves_non_commit: false, session_completeness_established: false };
}
export function wire(value) {
  const counters = ['number', 'expected_version', 'pull_request_version', 'comment_version', 'decision_sequence'];
  return JSON.stringify(value, (key, data) => counters.includes(key) && typeof data === 'string' ? JSON.rawJSON(data) : data);
}
export function respond(response, value, status = 200, headers = {}) {
  response.writeHead(status, { 'Content-Type': 'application/json', ...headers }); response.end(wire(value));
}
export async function peer(t, options = {}) {
  const state = { requests: [], intent: null, published: false, reads: 0, state: options.state ?? 'committed' };
  const sockets = new Set();
  const listener = async (request, response) => {
    const parts = []; for await (const chunk of request) parts.push(chunk);
    const record = { url: request.url, method: request.method, headers: request.headers, body: Buffer.concat(parts).toString('utf8') };
    state.requests.push(record);
    if (options.handle && await options.handle(record, response, state, request)) return;
    if (record.url === '/repo.git/api/v1/outcomes') {
      state.reads++;
      respond(response, outcome(state.intent, state.published ? state.state : 'key_not_observed'));
    } else {
      state.published = true;
      respond(response, publication(state.intent, state.state), state.state === 'committed' ? 200 : 409);
    }
  };
  const server = options.tls ? httpsServer(options.tls, listener) : httpServer(listener);
  server.on('connection', socket => { sockets.add(socket); socket.on('close', () => sockets.delete(socket)); });
  server.listen(0, '127.0.0.1'); await once(server, 'listening');
  t.after(async () => { for (const socket of sockets) socket.destroy(); await new Promise(resolve => server.close(resolve)); });
  state.endpoint = `${options.tls ? 'https' : 'http'}://127.0.0.1:${server.address().port}/repo.git`;
  state.intent = preparePull(input(state.endpoint, options.action, options.algorithm), TOKEN);
  return state;
}
export function consent(intent, options = {}) {
  return { confirmKey: intent.key, ...(intent.action === 'fast-forward' ? { confirmFastForward: true } : {}), ...options };
}
