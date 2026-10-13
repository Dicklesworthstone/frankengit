// Exact saved metadata publication and separate original-key recovery. No replan.
import { join } from 'node:path';
import { lstat } from 'node:fs/promises';
import { setTimeout as sleep } from 'node:timers/promises';
import { loadPlan } from './pull_sync_custody.mjs';
import { encode, hash, LIMITS, operationContext } from './pull_sync_plan.mjs';
import { exactKeys, fail, syncRequest, parseSyncJson, tokenValue } from './pull_sync_transport.mjs';
import { outcomeEndpoint, lookupOutcome, validateOutcomeReply } from './transaction_outcome.mjs';
import { directory, names, readPrivate, writeNew, lock } from './workflow_watch_io.mjs';
import { integer, opaque } from '../../crates/fgit-node/src/smart_http/server/browser/pulls-core.mjs';

const RECORD_BYTES = 16 * 1024;
// writeNew publishes a synced file with link(), then removes its temporary
// name. An independent recovery process may read between those two operations.
// Never accept nlink=2, changing metadata or orphaned temporary files as valid:
// retry only the local immutable observation, with finite time AND work bounds.
// Persistent damage still refuses, and no alias is removed by a reader. This
// does not retry an HTTP request or relax any canonical/schema validation.
async function settledRecords(read) {
  const deadline = performance.now() + 250;
  for (let attempt = 0; ; attempt++) {
    try { return await read(); }
    catch (error) {
      const transient = error.message === 'Expected a bounded private regular custody file.' ||
        error.message === 'Custody file changed while reading.' ||
        error.code === 'orphaned_sync_custody_requires_inspection';
      const remaining = deadline - performance.now();
      if (!transient || attempt === 31 || remaining <= 0) throw error;
      await sleep(Math.min(8, remaining));
    }
  }
}

const scope = plan => {
  const d = plan.discovery.destination;
  return { tenant_id: d.tenant_id, repository_id: d.repository_id, repository_incarnation: d.repository_incarnation, principal_id: d.principal_id };
};
const recordPath = (state, kind, index) => join(state, `${kind}-${String(index).padStart(3, '0')}.json`);
function sequence(value) {
  if (typeof value !== 'string' || !/^[1-9][0-9]{0,19}$/.test(value) || BigInt(value) > 18446744073709551615n) fail('invalid_sync_terminal_sequence');
  return value;
}
function terminal(value) {
  exactKeys(value, ['outcome', 'tx_id', 'decision_sequence', 'repository_commit_id', 'refusal_record_id', 'refusal_code', 'refusal_code_point']);
  opaque(value.tx_id); sequence(value.decision_sequence);
  if (value.outcome === 'committed') {
    opaque(value.repository_commit_id);
    if (value.refusal_record_id !== null || value.refusal_code !== null || value.refusal_code_point !== null) fail('inconsistent_sync_terminal');
  } else if (value.outcome === 'refused') {
    opaque(value.refusal_record_id); opaque(value.refusal_code); integer(value.refusal_code_point, 'refusal code', 0, 65535);
    if (value.repository_commit_id !== null) fail('inconsistent_sync_terminal');
  } else fail('invalid_sync_terminal');
  return structuredClone(value);
}
function fromOutcome(reply) {
  return reply.terminal ? terminal({ outcome: reply.state, tx_id: reply.transaction.tx_id, decision_sequence: reply.decision.decision_sequence,
    repository_commit_id: reply.decision.repository_commit_id ?? null, refusal_record_id: reply.decision.refusal_record_id ?? null,
    refusal_code: reply.decision.code ?? null, refusal_code_point: reply.decision.code_point ?? null }) : null;
}
export function publicationReply(reply, status, plan, request) {
  const dest = plan.discovery.destination;
  exactKeys(reply, ['type', 'schema_version', 'tenant_id', 'repository_id', 'repository_incarnation', 'object_format', 'principal_id',
    'number', 'expected_version', 'action', 'tx_id', 'outcome', 'decision_sequence', 'repository_commit_id', 'refusal_record_id',
    'refusal_code', 'refusal_code_point', 'delivery_acknowledged']);
  if (Object.keys(scope(plan)).some(key => reply[key] !== dest[key]) || reply.object_format !== dest.object_format ||
      reply.type !== 'pull_request_publication' || reply.schema_version !== 1 || reply.action !== 'update' ||
      reply.number !== request.number || reply.expected_version !== request.fields.expected_version || reply.delivery_acknowledged !== null ||
      status !== (reply.outcome === 'committed' ? 200 : 409)) fail('sync_publication_identity_changed');
  return terminal(Object.fromEntries(['outcome', 'tx_id', 'decision_sequence', 'repository_commit_id', 'refusal_record_id', 'refusal_code', 'refusal_code_point'].map(key => [key, reply[key]])));
}
function terminalRecord(plan, request, origin, status, reply) {
  const result = origin === 'publication' ? publicationReply(reply, status, plan, request)
    : origin === 'outcome' && status === 200 ? fromOutcome(validateOutcomeReply(reply, scope(plan))) : fail('invalid_sync_observation_origin');
  if (!result) fail('nonterminal_sync_observation');
  return { schema: 'frankengit-pr-sync-terminal-v1', plan_sha256: plan.plan_sha256, request_sha256: hash(encode(request)), origin, status, reply, result };
}
function checkedTerminal(value, plan, request) {
  exactKeys(value, ['schema', 'plan_sha256', 'request_sha256', 'origin', 'status', 'reply', 'result']);
  const normalized = terminalRecord(plan, request, value.origin, value.status, value.reply);
  if (!encode(normalized).equals(encode(value))) fail('sync_terminal_record_changed');
  return normalized;
}
const inventory = state => settledRecords(() => readInventory(state));
async function readInventory(state) {
  const plan = await loadPlan(state), files = await names(state, 3 * LIMITS.changes + 3);
  const allowed = new Set(['plan.json', 'owner.lock', 'recovery.lock']), rows = [];
  let bytes = 0;
  const read = async path => {
    const raw = await readPrivate(path, RECORD_BYTES, true); if (raw === null) return null;
    bytes += raw.length;
    if (bytes > 3 * LIMITS.changes * RECORD_BYTES) fail('sync_receipt_capacity');
    return parseSyncJson(raw, RECORD_BYTES);
  };
  for (let index = 0; index < plan.requests.length; index++) {
    const request = plan.requests[index], requestHash = hash(encode(request));
    const row = { index, request, started: false, observed: null, terminal: null };
    for (const kind of ['started', 'observed', 'terminal']) {
      const name = `${kind}-${String(index).padStart(3, '0')}.json`; allowed.add(name);
      const value = await read(join(state, name)); if (value === null) continue;
      if (value.plan_sha256 !== plan.plan_sha256 || value.request_sha256 !== requestHash) fail('sync_record_request_changed');
      if (kind === 'started') {
        exactKeys(value, ['schema', 'plan_sha256', 'request_sha256']);
        if (value.schema !== 'frankengit-pr-sync-start-v1') fail('invalid_sync_start'); row.started = true;
      } else if (kind === 'observed') {
        exactKeys(value, ['schema', 'plan_sha256', 'request_sha256', 'reply']);
        if (value.schema !== 'frankengit-pr-sync-observed-v1') fail('invalid_sync_observation');
        row.observed = validateOutcomeReply(value.reply, scope(plan));
        if (!row.observed.transaction) fail('sync_observation_requires_transaction');
      } else row.terminal = checkedTerminal(value, plan, request);
    }
    if ((row.observed || row.terminal) && !row.started) fail('sync_receipt_lost_start_responsibility');
    if (row.observed && row.terminal) {
      if (row.observed.transaction.tx_id !== row.terminal.result.tx_id ||
          (row.observed.terminal && !encode(fromOutcome(row.observed)).equals(encode(row.terminal.result)))) fail('sync_terminal_conflicts_with_observation');
    }
    // A complete outcome already synced as the first transaction observation
    // remains known even if a later terminal-file write failed. This is a read
    // projection of retained evidence, not automatic repair or a new decision.
    if (!row.terminal && row.observed?.terminal) row.terminal = terminalRecord(plan, request, 'outcome', 200, row.observed);
    rows.push(row);
  }
  if (files.some(file => !allowed.has(file))) fail('orphaned_sync_custody_requires_inspection');
  return { plan, rows };
}
function summary(data) {
  return { type: 'pull_sync_status', schema_version: 1, plan_sha256: data.plan.plan_sha256,
    historical_observations: true, refs_changed: false, approvals_carried_forward: false,
    jobs: data.rows.map(row => ({ number: row.request.number, state: row.terminal?.result.outcome ?? (row.started ? 'unknown' : 'prepared'),
      ...(row.terminal ? { terminal: row.terminal.result } : {}) })) };
}
const ownerPresent = path => lstat(path).then(() => true, error => { if (error.code === 'ENOENT') return false; throw error; });
export async function status(state) {
  const data = await inventory(state);
  return { ...summary(data), read_only: true, owner_present: await ownerPresent(join(state, 'owner.lock')),
    recovery_owner_present: await ownerPresent(join(state, 'recovery.lock')) };
}
async function persistObserved(state, data, row, reply) {
  if (!reply.transaction) return;
  const value = { schema: 'frankengit-pr-sync-observed-v1', plan_sha256: data.plan.plan_sha256, request_sha256: hash(encode(row.request)), reply };
  if (encode(value).length > RECORD_BYTES) fail('sync_observation_byte_limit');
  try { await writeNew(recordPath(state, 'observed', row.index), encode(value)); row.observed = reply; }
  catch (error) {
    if (error.code !== 'EEXIST') throw error;
    const actual = await inventory(state), previous = actual.rows[row.index].observed;
    if (!previous) fail('sync_observation_disappeared');
    validateOutcomeReply(reply, scope(data.plan), previous); row.observed = previous;
  }
}
async function persistTerminal(state, data, row, value) {
  if (encode(value).length > RECORD_BYTES) fail('sync_terminal_byte_limit');
  if (row.observed && (row.observed.transaction.tx_id !== value.result.tx_id ||
      (row.observed.terminal && !encode(fromOutcome(row.observed)).equals(encode(value.result))))) fail('sync_terminal_conflicts_with_observation');
  try { await writeNew(recordPath(state, 'terminal', row.index), encode(value)); row.terminal = value; }
  catch (error) {
    if (error.code !== 'EEXIST') { error.retained_terminal = value.result; throw error; }
    try {
      const actual = await inventory(state), previous = actual.rows[row.index].terminal;
      if (!previous || !encode(previous.result).equals(encode(value.result))) fail('sync_terminal_conflicted');
      row.terminal = previous;
    } catch (failure) {
      if (failure.code !== 'sync_terminal_conflicted') failure.retained_terminal = value.result;
      throw failure;
    }
  }
}
const refreshKnowledge = (state, data, row) => settledRecords(() => readKnowledge(state, data, row));
async function readKnowledge(state, data, row) {
  const observed = await readPrivate(recordPath(state, 'observed', row.index), RECORD_BYTES, true);
  if (observed) {
    const value = parseSyncJson(observed, RECORD_BYTES);
    exactKeys(value, ['schema', 'plan_sha256', 'request_sha256', 'reply']);
    if (value.schema !== 'frankengit-pr-sync-observed-v1' || value.plan_sha256 !== data.plan.plan_sha256 ||
        value.request_sha256 !== hash(encode(row.request))) fail('sync_record_request_changed');
    row.observed = validateOutcomeReply(value.reply, scope(data.plan), row.observed);
    if (!row.observed.transaction) fail('sync_observation_requires_transaction');
  }
  const raw = await readPrivate(recordPath(state, 'terminal', row.index), RECORD_BYTES, true);
  if (raw) row.terminal = checkedTerminal(parseSyncJson(raw, RECORD_BYTES), data.plan, row.request);
  else if (row.observed?.terminal) row.terminal = terminalRecord(data.plan, row.request, 'outcome', 200, row.observed);
}
async function lookup(state, data, row, token, cx) {
  await refreshKnowledge(state, data, row);
  if (row.terminal) return null;
  const reply = await lookupOutcome(data.plan.discovery.destination.endpoint, token, { ...scope(data.plan), key: row.request.key },
    { signal: cx.signal, timeoutMs: cx.remaining(), ca: cx.ca, known: row.observed });
  // A concurrent recovery may have learned more while this socket was open.
  // Compare that durable knowledge before any retry or record publication.
  await refreshKnowledge(state, data, row);
  validateOutcomeReply(reply, scope(data.plan), row.observed);
  if (row.terminal && (!reply.terminal || !encode(fromOutcome(reply)).equals(encode(row.terminal.result)))) fail('sync_outcome_regressed_or_conflicted');
  try {
    await persistObserved(state, data, row, reply);
    if (reply.terminal) await persistTerminal(state, data, row, terminalRecord(data.plan, row.request, 'outcome', 200, reply));
  } catch (error) { if (reply.terminal) error.retained_terminal = fromOutcome(reply); throw error; }
  return reply;
}
async function owned(state, name, work) {
  await directory(state); const release = await lock(join(state, name)); let result, failure;
  try { result = await work(); return result; }
  catch (error) { failure = error; throw error; }
  finally {
    try { await release(); }
    catch (error) { if (failure) failure.cleanup_error = error.message; else { error.retained_result = result; error.local_cleanup_failed = true; throw error; } }
  }
}
function controls(options, writing) {
  if (!options || typeof options !== 'object' || Array.isArray(options) ||
      Object.keys(options).some(key => !['endpoint', 'confirmation', 'retry', 'maxRequests', 'timeoutMs', 'signal', 'ca', 'onObservation'].includes(key))) fail('invalid_sync_operation_controls');
  options = { ...options };
  outcomeEndpoint(options.endpoint);
  if (writing) {
    if (typeof options.confirmation !== 'string' || !/^[0-9a-f]{64}$/.test(options.confirmation) ||
        (options.retry !== undefined && typeof options.retry !== 'boolean')) fail('explicit_sync_confirmation_required');
  } else if (options.confirmation !== undefined || options.retry !== undefined) fail('recovery_cannot_publish_or_retry');
  const observer = options.onObservation ?? (() => {}); if (typeof observer !== 'function') fail('invalid_sync_observer');
  return { ...options, observer, maxRequests: integer(options.maxRequests ?? 128, 'sync work bound', 1, 128),
    cx: operationContext({ signal: options.signal, timeoutMs: options.timeoutMs, ca: options.ca }) };
}
async function operate(state, token, supplied, writing) {
  tokenValue(token); const options = controls(supplied, writing), cx = options.cx;
  return owned(state, writing ? 'owner.lock' : 'recovery.lock', async () => {
    const data = await inventory(state), plan = data.plan;
    if (options.endpoint !== plan.discovery.destination.endpoint) fail('sync_independent_endpoint_mismatch');
    if (writing && (options.confirmation !== plan.plan_sha256 || hash(token) !== plan.credential_sha256)) fail('sync_original_credential_and_plan_confirmation_required');
    if (writing && !options.retry && data.rows.some(row => row.started && !row.terminal)) fail('sync_unresolved_requires_explicit_retry_or_recovery');
    let requests = 0, updates = 0, lookups = 0;
    for (const row of data.rows) {
      if (row.terminal || (!writing && !row.started)) continue;
      if (requests === options.maxRequests || cx.signal?.aborted) break;
      requests++;
      try {
        if (row.started) { await lookup(state, data, row, token, cx); lookups++; }
        if (writing && !row.terminal && !cx.signal?.aborted) {
          cx.remaining();
          if (!row.started) {
            await writeNew(recordPath(state, 'started', row.index), encode({ schema: 'frankengit-pr-sync-start-v1',
              plan_sha256: plan.plan_sha256, request_sha256: hash(encode(row.request)) }));
            row.started = true;
          }
          const raw = await syncRequest(options.endpoint, token, { kind: 'update', ...row.request },
            { signal: cx.signal, ca: cx.ca, timeoutMs: cx.remaining() }); updates++;
          const value = terminalRecord(plan, row.request, 'publication', raw.status, raw.value);
          await persistTerminal(state, data, row, value);
        }
        if (row.terminal) {
          try { await options.observer({ type: 'pull_sync_observed', number: row.request.number, ...structuredClone(row.terminal.result),
            refs_changed: false, approvals_carried_forward: false }); }
          catch (error) { error.retained_terminal = row.terminal.result; throw error; }
        }
      } catch (error) {
        error.publication_unknown = row.started && !row.terminal && !error.retained_terminal;
        error.retained_result = summary(data); throw error;
      }
    }
    return { ...summary(data), updates, lookups, stopped: cx.signal?.aborted === true,
      limit_reached: requests === options.maxRequests && data.rows.some(row => !row.terminal && (writing || row.started)) };
  });
}
export const send = (state, token, options) => operate(state, token, options, true);
export const recover = (state, token, options) => operate(state, token, options, false);
