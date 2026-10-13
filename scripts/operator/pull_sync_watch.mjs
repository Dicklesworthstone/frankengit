// Opt-in unattended PR-tip synchronization. Native APIs remain the only authority.
import { join } from 'node:path';
import { mkdir, lstat } from 'node:fs/promises';
import { setTimeout as sleep } from 'node:timers/promises';
import { absolute, directory, names, readPrivate, writeNew, syncDirectory, lock } from './workflow_watch_io.mjs';
import { destination, selection, discover, freezePlan, encode, hash } from './pull_sync_plan.mjs';
import { savePlan, loadPlan } from './pull_sync_custody.mjs';
import { send, status as planStatus } from './pull_sync_publish.mjs';
import { exactKeys, fail, tokenValue } from './pull_sync_transport.mjs';
import { integer } from '../../crates/fgit-node/src/smart_http/server/browser/pulls-core.mjs';

const BINDING_BYTES = 32768, RECEIPTS_PER_REQUEST = 3 * 16384;
export function configuration(value) {
  exactKeys(value, ['schema', 'destination', 'selected', 'state_directory', 'max_batches', 'state_bytes', 'policy']);
  if (value.schema !== 'frankengit-pr-sync-watch-v1' || value.policy !== 'recorded-tips-only') fail('explicit_sync_watch_policy_required');
  const selected = selection(value.selected);
  const result = { schema: value.schema, destination: destination(value.destination),
    selected: Array.isArray(selected) ? Object.freeze(selected) : selected, state_directory: absolute(value.state_directory),
    max_batches: integer(value.max_batches, 'watch batch capacity', 1, 128),
    state_bytes: integer(value.state_bytes, 'watch custody byte capacity', 65536, 64 * 1024 * 1024), policy: value.policy };
  if (encode(result).length > BINDING_BYTES) fail('sync_watch_configuration_limit');
  return Object.freeze(result);
}
const requestIdentity = request => hash(encode([request.number, request.fields]));
const batchPath = (config, index) => join(config.state_directory, `batch-${String(index).padStart(6, '0')}`);
const isPending = job => job.state === 'prepared' || job.state === 'unknown';
const view = rows => rows.map(row => ({ batch: row.index, directory: row.path, plan_sha256: row.sha,
  jobs: row.status.jobs.length, committed: row.status.jobs.filter(job => job.state === 'committed').length,
  refused: row.status.jobs.filter(job => job.state === 'refused').length,
  prepared: row.status.jobs.filter(job => job.state === 'prepared').length,
  unknown: row.status.jobs.filter(job => job.state === 'unknown').length,
  owner_present: row.status.owner_present, recovery_owner_present: row.status.recovery_owner_present }));
async function inventory(config, initialize = false, check = () => {}) {
  await directory(config.state_directory);
  const files = await names(config.state_directory, config.max_batches + 2);
  const raw = await readPrivate(join(config.state_directory, 'binding.json'), BINDING_BYTES, true);
  if (raw && !raw.equals(encode(config))) fail('sync_watch_configuration_changed');
  if (!raw) {
    if (files.some(name => name !== 'owner.lock')) fail('unbound_sync_watch_directory_not_empty');
    if (initialize) await writeNew(join(config.state_directory, 'binding.json'), encode(config));
  }
  const rows = [], decided = new Map(); let reserved = encode(config).length;
  for (const name of files) {
    check();
    if (name === 'binding.json' || name === 'owner.lock') continue;
    const match = /^batch-([0-9]{6})$/.exec(name), index = rows.length + 1;
    if (!match || Number(match[1]) !== index || index > config.max_batches) fail('sync_watch_custody_gap_or_unknown_file');
    if (rows.some(row => row.status.jobs.some(isPending))) fail('sync_watch_later_batch_before_settlement');
    const path = batchPath(config, index), plan = await loadPlan(path);
    if (!encode(plan.discovery.destination).equals(encode(config.destination)) || !Array.isArray(plan.discovery.selected) ||
        plan.discovery.unchanged.length || !plan.requests.length || plan.requests.length !== plan.discovery.selected.length ||
        (config.selected !== 'all-open' && plan.discovery.selected.some(number => !config.selected.includes(number)))) fail('sync_watch_batch_scope_changed');
    reserved += encode(plan).length + plan.requests.length * RECEIPTS_PER_REQUEST;
    if (reserved > config.state_bytes) fail('sync_watch_receipt_capacity');
    const status = await planStatus(path);
    if (status.plan_sha256 !== plan.plan_sha256) fail('sync_watch_plan_changed_during_read');
    for (let i = 0; i < plan.requests.length; i++) {
      const identity = requestIdentity(plan.requests[i]), job = status.jobs[i];
      if (job.number !== plan.requests[i].number || decided.has(identity)) fail('sync_watch_duplicate_or_substituted_request');
      if (!isPending(job)) decided.set(identity, job.state);
    }
    rows.push({ index, path, sha: plan.plan_sha256, status });
  }
  return { rows, decided, reserved };
}
export async function status(config) {
  config = configuration(config);
  const { rows, reserved } = await inventory(config);
  const owner = await lstat(join(config.state_directory, 'owner.lock')).then(() => true, error => { if (error.code === 'ENOENT') return false; throw error; });
  return { type: 'pull_sync_watch_status', schema_version: 1, configuration_sha256: hash(encode(config)),
    read_only: true, historical_observations: true, owner_present: owner, reserved_bytes: reserved,
    batches: view(rows), refs_changed: false, approvals_carried_forward: false };
}
function options(value, continuous) {
  if (!value || typeof value !== 'object' || Array.isArray(value) || Object.keys(value).some(key =>
    !['signal', 'ca', 'timeoutMs', 'maxUpdates', 'onObservation', ...(continuous ? ['pollMs', 'maxPolls'] : [])].includes(key))) fail('invalid_sync_watch_options');
  if (value.signal !== undefined && !(value.signal instanceof AbortSignal)) fail('invalid_sync_watch_signal');
  const observer = value.onObservation ?? (() => {}); if (typeof observer !== 'function') fail('invalid_sync_watch_observer');
  const ca = value.ca === undefined ? undefined : Buffer.isBuffer(value.ca) && value.ca.length > 0 && value.ca.length <= 128 * 1024
    ? Buffer.from(value.ca) : fail('invalid_sync_watch_ca');
  return { signal: value.signal, ca, observer,
    timeoutMs: integer(value.timeoutMs ?? 120000, 'watch sweep timeout', 1, 300000),
    maxUpdates: integer(value.maxUpdates ?? 128, 'watch updates per sweep', 1, 128),
    ...(continuous ? { pollMs: integer(value.pollMs ?? 1000, 'watch poll interval', 100, 60000),
      maxPolls: integer(value.maxPolls ?? 1000000, 'watch poll count', 1, 1000000) } : {}) };
}
async function owned(config, work) {
  await directory(config.state_directory); const release = await lock(join(config.state_directory, 'owner.lock'));
  let result, failure;
  try { result = await work(); return result; }
  catch (error) { failure = error; throw error; }
  finally {
    try { await release(); }
    catch (error) { if (failure) failure.cleanup_error = error.message; else { error.retained_result = result; error.local_cleanup_failed = true; throw error; } }
  }
}
async function emit(options, event) {
  try { await options.observer(structuredClone(event)); }
  catch (error) { error.retained_result = event; error.local_output_failed = true; throw error; }
}
async function sweep(config, token, options) {
  const deadline = performance.now() + options.timeoutMs;
  const remaining = () => {
    const left = Math.floor(deadline - performance.now());
    if (left < 1) fail('sync_watch_sweep_deadline');
    return left;
  };
  const check = () => {
    if (options.signal?.aborted) { const error = new Error('sync_watch_stop_requested'); error.watch_phase = 'checkpoint'; throw error; }
    remaining();
  };
  const data = await inventory(config, true, check);
  let active = data.rows.find(row => row.status.jobs.some(isPending)), discovery = null, suppressed = [];
  // Remote terminal knowledge is not evidence that a crash-held local owner has
  // drained. A retained sender lock blocks NEW batches too; recovery stays separate.
  if (data.rows.some(row => row.status.owner_present)) fail('sync_watch_sender_owner_requires_inspection');
  if (active?.status.jobs.some(job => job.state === 'unknown')) fail('sync_watch_unresolved_publication_use_original_recovery');
  if (!active) {
    check();
    try { discovery = await discover(config.destination, token, config.selected, { signal: options.signal, ca: options.ca, timeoutMs: remaining() }); }
    catch (error) { error.watch_phase = 'discovery'; throw error; }
    const changes = discovery.changes.filter(row => {
      const prior = data.decided.get(requestIdentity({ number: row.number, fields: row.fields }));
      if (prior) { suppressed.push({ number: row.number, outcome: prior }); return false; }
      return true;
    });
    if (changes.length) {
      if (data.rows.length === config.max_batches) fail('sync_watch_batch_capacity');
      // This is a subset of one validated observation, not a fresh read or
      // synthesized metadata. Do not label suppressed/refused PRs "unchanged".
      const subset = { ...discovery, selected: changes.map(row => row.number), scanned: changes.length, unchanged: [], changes };
      const plan = freezePlan(subset, token);
      const reserved = data.reserved + encode(plan).length + plan.requests.length * RECEIPTS_PER_REQUEST;
      if (reserved > config.state_bytes) fail('sync_watch_receipt_capacity');
      check();
      const index = data.rows.length + 1, path = batchPath(config, index);
      await mkdir(path, { mode: 0o700 }); await syncDirectory(config.state_directory);
      // An interrupted empty/partial batch is left visible and refuses restart.
      // No new namespace replaces it, and no command is sent before its plan sync.
      await savePlan(path, plan);
      active = { index, path, sha: plan.plan_sha256, status: await planStatus(path) }; data.rows.push(active);
      data.reserved = reserved;
    }
  }
  let updates = 0, committed = 0, refused = 0;
  if (active) {
    while (active.status.jobs.some(isPending) && updates < options.maxUpdates && !options.signal?.aborted) {
      check();
      // Drain one bounded publication on SIGTERM rather than destroying its
      // socket. Stop is checked between jobs; there is no automatic resend.
      const result = await send(active.path, token, { endpoint: config.destination.endpoint, confirmation: active.sha,
        maxRequests: 1, timeoutMs: Math.min(remaining(), 30000), ca: options.ca,
        onObservation: async event => {
          if (event.outcome === 'committed') committed++; else refused++;
          await emit(options, { ...event, batch: active.index, state_directory: active.path });
        } });
      updates += result.updates;
      active.status = await planStatus(active.path);
      if (active.status.jobs.some(job => job.state === 'unknown')) fail('sync_watch_unresolved_publication_use_original_recovery');
      if (result.updates === 0 && active.status.jobs.some(isPending)) fail('sync_watch_no_publication_progress');
    }
  }
  return { type: 'pull_sync_watch_sweep', schema_version: 1, updates, committed, refused,
    scanned: discovery?.scanned ?? null, unchanged: discovery?.unchanged ?? null,
    suppressed_historical_requests: suppressed, batches: view(data.rows), reserved_bytes: data.reserved,
    stopped: options.signal?.aborted === true, limit_reached: !!active?.status.jobs.some(isPending),
    refs_changed: false, approvals_carried_forward: false };
}
export async function once(config, token, supplied = {}) {
  config = configuration(config); tokenValue(token); const selected = options(supplied, false);
  return owned(config, () => sweep(config, token, selected));
}
function retryableRead(error) {
  return error.watch_phase === 'discovery' && (['sync_transport_unavailable', 'sync_request_timeout'].includes(error.code) ||
    (error.code === 'sync_http_refused' && [408, 409, 429, 502, 503, 504].includes(error.status)));
}
export async function serve(config, token, supplied = {}) {
  config = configuration(config); tokenValue(token); const selected = options(supplied, true);
  return owned(config, async () => {
    let polls = 0, updates = 0, refused = 0, failures = 0, consecutive = 0, last = null;
    while (polls < selected.maxPolls && !selected.signal?.aborted) {
      polls++;
      try {
        last = await sweep(config, token, selected); consecutive = 0; updates += last.updates; refused += last.refused;
        await emit(selected, last);
      } catch (error) {
        if (selected.signal?.aborted && ['discovery', 'checkpoint'].includes(error.watch_phase) && !error.local_output_failed) break;
        if (error.local_output_failed || !retryableRead(error) || ++consecutive >= 3) throw error;
        failures++;
        await emit(selected, { type: 'pull_sync_watch_read_unavailable', code: error.code, status: error.status,
          consecutive_failures: consecutive, mutations_sent: 0 });
      }
      if (polls === selected.maxPolls || selected.signal?.aborted) break;
      try { await sleep(Math.min(60000, selected.pollMs * 2 ** consecutive), undefined, { signal: selected.signal }); }
      catch (error) { if (!selected.signal?.aborted) throw error; }
    }
    // A stop before the first completed sweep must not conceal retained pending work.
    if (last === null) last = { type: 'pull_sync_watch_idle', schema_version: 1, batches: view((await inventory(config)).rows) };
    return { type: 'pull_sync_watch_service', schema_version: 1, polls, updates, refused, read_failures: failures,
      stopped: selected.signal?.aborted === true, poll_limit_reached: polls === selected.maxPolls, last,
      refs_changed: false, approvals_carried_forward: false };
  });
}
