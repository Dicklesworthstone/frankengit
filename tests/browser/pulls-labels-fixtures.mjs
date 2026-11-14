// Controlled HTTP fixtures, not evidence of native publication or live DOM.
import { actor, ids, head, data, row, show, page, json, token, options } from './pulls-fixtures.mjs';
import { PullClient } from '../../crates/fgit-node/src/smart_http/server/browser/pulls.mjs';
export { actor, json, token };

export function observed(format = 'sha1', extra = {}) {
  const width = format === 'sha1' ? 40 : 64;
  return show({ object_format: format, pull_request: row(1, { version: 9, labels: ['bug'], labels_version: 2,
    labels_actor: actor, data: data({ object_format: format, source_tip: 'a'.repeat(width), target_tip: 'b'.repeat(width) }), ...extra }) });
}
export function labelsReply(observation = observed(), extra = {}) {
  const pr = observation.pull_request;
  return { ...ids, object_format: observation.object_format, type: 'pull_request_labels', number: observation.number,
    source_head: observation.source_head, snapshot_token: observation.snapshot_token, found: true,
    pull_request_version: pr.version, labels_version: pr.labels_version ?? 2, labels_actor: Object.hasOwn(pr, 'labels_actor') ? pr.labels_actor : actor,
    labels: structuredClone(pr.labels ?? ['bug']), read_only: true, transaction_created: false, ...extra };
}
export function labelsTerminal(pending, outcome = 'committed', extra = {}) {
  return { ...ids, object_format: pending.scope.format, type: 'pull_request_labels_publication',
    number: pending.number, action: 'set-labels', expected_version: pending.fields.expected_version,
    labels: structuredClone(pending.fields.labels), labels_version: outcome === 'committed' ? pending.fields.expected_version + 1 : null,
    principal_id: actor, tx_id: 'labels-transaction', decision_sequence: 8, outcome,
    repository_commit_id: outcome === 'committed' ? 'labels-rcr' : null,
    refusal_record_id: outcome === 'refused' ? 'labels-refusal' : null,
    refusal_code: outcome === 'refused' ? 'AggregateVersionMismatch' : null,
    refusal_code_point: outcome === 'refused' ? 1 : null, delivery_acknowledged: null,
    refs_changed: false, pull_request_version_changed: false, ...extra };
}
export function labelsOutcome(state = 'key_not_observed', extra = {}) {
  const terminal = ['committed', 'refused'].includes(state);
  return { ...ids, type: 'transaction_outcome', selector: 'transaction', command_index: null,
    principal_id: actor, read_only: true, request_reexecuted: false, absence_proves_non_commit: false,
    session_completeness_established: false, state, terminal,
    transaction: terminal || state === 'undecided' ? { tx_id: 'labels-transaction', seal_id: 'labels-seal',
      request_schema: 'receive-admission/v1.0', canonical_request_digest: { algorithm: 2, hex: 'ab'.repeat(32) } } : null,
    decision: !terminal ? null : state === 'committed'
      ? { kind: state, decision_sequence: 8, repository_commit_id: 'labels-rcr' }
      : { kind: state, decision_sequence: 8, refusal_record_id: 'labels-refusal', code: 'AggregateVersionMismatch', code_point: 1 }, ...extra };
}
export async function clientFixture({ observation = observed(), read = null, dispatch = null, recover = null, request = null, transport = {} } = {}) {
  const calls = []; let client;
  client = new PullClient({ ...options(async (url, init) => {
    const call = { url: new URL(url), ...init, bytes: init.body === undefined ? null
      : typeof init.body === 'string' ? init.body : await init.body.text() };
    calls.push(call);
    if (request) { const response = await request(call, client); if (response) return response; }
    if (url.pathname.endsWith('/outcomes')) return recover ? recover(call, client.pending) : json(labelsOutcome());
    if (url.pathname.endsWith('/labels')) return init.method === 'GET'
      ? read ? read(call) : json(labelsReply(observation))
      : dispatch ? dispatch(call, client.pending) : json(labelsTerminal(client.pending));
    if (url.pathname.endsWith('/pulls')) return json(page({ object_format: observation.object_format,
      source_head: observation.source_head, snapshot_token: observation.snapshot_token, labels: [], pull_requests: [observation.pull_request] }));
    if (/\/pulls\/[1-9][0-9]*$/.test(url.pathname)) return json(observation);
    throw new Error(`Unexpected fixture request ${url}`);
  }), ...transport });
  await client.connect(token);
  const selected = await client.show(observation.number);
  return { client, calls, selected, observation, load: () => client.labels(observation.number, selected) };
}
