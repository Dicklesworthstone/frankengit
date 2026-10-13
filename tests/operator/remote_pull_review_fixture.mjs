// Native-schema transport peers, not native Git validation or a policy engine.
// The binary payload deliberately exercises all byte values as opaque transport.
import { createServer } from 'node:http';
import { createServer as createTlsServer } from 'node:https';
import { once } from 'node:events';
import { preparePull } from '../../scripts/operator/remote_pull.mjs';
import { BASE_SCOPE, TOKEN, outcome } from './remote_pull_fixture.mjs';
export { TOKEN, ROTATED } from './remote_pull_fixture.mjs';
export const BUNDLE = Buffer.from(Array.from({ length: 4096 }, (_, i) => i % 256));
export function reviewInput(endpoint, action = 'approve', format = 'sha1', method = 'merge-commit') {
  const width = format === 'sha1' ? 40 : 64;
  return { endpoint, scope: { ...BASE_SCOPE, object_format: format }, number: '9007199254740993', action,
    fields: { pull_request_version: '9007199254740994', policy_epoch: '18446744073709551615',
      source_ref: 'refs/heads/topic-🦀', target_ref: 'refs/heads/main', source_tip: 'a'.repeat(width),
      target_tip: 'b'.repeat(width), merge_base: 'c'.repeat(width), candidate_commit: 'd'.repeat(width),
      ...(action === 'merge' ? { required_reviewers: ['6'.repeat(32), '5'.repeat(32)], method }
        : { expected_version: action === 'withdraw' ? '9007199254740995' : '0', reason: 'Exact candidate reviewed.\n<script>inert</script> 🦀' }) } };
}
export function reviewPublication(intent, state = 'committed') {
  const f = intent.fields, format = intent.scope.object_format, committed = state === 'committed', merge = intent.action === 'merge';
  return { type: merge ? 'reviewed_merge_publication' : 'candidate_review_publication', schema_version: 1,
    ...intent.scope, action: intent.action, ...(merge ? { method: f.method } : {}),
    review_expected_version: merge ? null : f.expected_version,
    subject: { number: intent.number, pull_request_version: f.pull_request_version, policy_epoch: f.policy_epoch,
      source_ref: f.source_ref, source_ref_hex: Buffer.from(f.source_ref).toString('hex'),
      target_ref: f.target_ref, target_ref_hex: Buffer.from(f.target_ref).toString('hex'),
      source_tip: `${format}:${f.source_tip}`, target_tip: `${format}:${f.target_tip}` },
    merge_base: `${format}:${f.merge_base}`, candidate_commit: `${format}:${f.candidate_commit}`,
    required_reviewers: merge ? [...f.required_reviewers] : null,
    tx_id: 'native-transaction', outcome: state, decision_sequence: '18446744073709551615',
    repository_commit_id: committed ? 'native-rcr' : null, refusal_record_id: committed ? null : 'native-refusal',
    refusal_code: committed ? null : 'PolicyDenied', refusal_code_point: committed ? null : 17, delivery_acknowledged: null };
}
export function reviewWire(value) {
  const counters = ['number', 'pull_request_version', 'policy_epoch', 'review_expected_version', 'decision_sequence'];
  return JSON.stringify(value, (key, data) => counters.includes(key) && typeof data === 'string' ? JSON.rawJSON(data) : data);
}
export function reviewReply(res, value, status = 200) {
  res.writeHead(status, { 'Content-Type': 'application/json' }); res.end(reviewWire(value));
}
export function reviewConsent(intent, bundle = BUNDLE) {
  return { confirmKey: intent.key, confirmCandidate: intent.fields.candidate_commit,
    ...(intent.action === 'merge' ? { confirmMergeMethod: intent.fields.method } : {}),
    ...(intent.action === 'withdraw' ? {} : { bundle }) };
}
export async function reviewPeer(t, options = {}) {
  const state = { requests: [], published: false, intent: null, state: options.state ?? 'committed' }, sockets = new Set();
  const listener = async (req, res) => {
    const parts = []; for await (const bytes of req) parts.push(bytes);
    const record = { url: req.url, method: req.method, headers: req.headers, bytes: Buffer.concat(parts) };
    state.requests.push(record);
    if (options.handle && await options.handle(record, res, state, req)) return;
    if (record.url === '/repo.git/api/v1/outcomes') {
      reviewReply(res, outcome(state.intent, state.published ? state.state : 'key_not_observed')); return;
    }
    const action = state.intent.action;
    const path = `/repo.git/api/v1/pulls/${state.intent.number}/${action === 'merge' ? 'merge' : `reviews/${action}`}`;
    if (req.url !== path || req.method !== 'POST') { res.writeHead(404); res.end(); return; }
    state.published = true;
    reviewReply(res, reviewPublication(state.intent, state.state), state.state === 'committed' ? 200 : 409);
  };
  const server = options.tls ? createTlsServer(options.tls, listener) : createServer(listener);
  server.on('connection', socket => { sockets.add(socket); socket.on('close', () => sockets.delete(socket)); });
  server.listen(0, '127.0.0.1'); await once(server, 'listening');
  t.after(async () => { for (const socket of sockets) socket.destroy(); await new Promise(resolve => server.close(resolve)); });
  state.endpoint = `${options.tls ? 'https' : 'http'}://127.0.0.1:${server.address().port}/repo.git`;
  state.intent = preparePull(reviewInput(state.endpoint, options.action, options.format, options.method), TOKEN,
    options.action === 'withdraw' ? null : BUNDLE);
  return state;
}
