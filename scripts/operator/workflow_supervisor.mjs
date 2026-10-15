// Compose the existing trusted-local operators; Rust remains the only executor
// and publication authority. This journal binds custody, never a second truth.
import { join } from 'node:path';
import { lstat } from 'node:fs/promises';
import { absolute, contains, directory, fail, lock, names, parseJson, readPrivate, writeNew } from './workflow_watch_io.mjs';

const MAX_BYTES = 1024 * 1024;
const encode = value => Buffer.from(`${JSON.stringify(value)}\n`);
const overlap = (a, b) => contains(a, b) || contains(b, a);
function keys(value, expected) {
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
      Object.keys(value).length !== expected.length || expected.some(key => !Object.hasOwn(value, key))) fail('Missing or unsupported supervisor fields.');
}
function integer(value, low, high) {
  if (!Number.isSafeInteger(value) || value < low || value > high) fail('Invalid supervisor budget.');
  return value;
}
function optionsFor(options) {
  if (!options || typeof options !== 'object' || Array.isArray(options) ||
      Object.keys(options).some(key => !['signal', 'readTimeoutMs', 'dispatchTimeoutMs', 'timeoutMs', 'maxPublications'].includes(key))) fail('Unsupported supervisor options.');
  if (options.signal !== undefined && !(options.signal instanceof AbortSignal)) fail('Invalid supervisor cancellation signal.');
  return { signal: options.signal, readTimeoutMs: integer(options.readTimeoutMs ?? 30_000, 1, 30_000),
    dispatchTimeoutMs: integer(options.dispatchTimeoutMs ?? 660_000, 1, 660_000),
    timeoutMs: integer(options.timeoutMs ?? 660_000, 1, 660_000), maxPublications: integer(options.maxPublications ?? 128, 1, 128) };
}
function publication(value) {
  if (value?.type !== 'workflow_check_status' || value.schema_version !== 1 || value.authoritative_check !== false ||
      value.execution_retried !== false || !Array.isArray(value.runs) || value.runs.length > 128) fail('Invalid native publisher observation.');
  const counts = { runs: value.runs.length, jobs: 0, committed: 0, refused: 0, pending: 0, unknown: 0 };
  for (const row of value.runs) {
    for (const field of ['jobs', 'committed', 'refused', 'pending', 'unknown']) counts[field] += integer(row[field], 0, 128);
    if (row.committed + row.refused + row.pending !== row.jobs || row.unknown > row.pending) fail('Inconsistent publisher observation counters.');
  }
  return { ...counts, limit_reached: value.limit_reached === true, stopped: value.stopped === true };
}
function execution(value) {
  if (!['workflow_watch_result', 'workflow_watch_idle'].includes(value?.type) ||
      value.schema_version !== 1 || value.authoritative_check !== false ||
      (value.outcome !== undefined && !['observed_succeeded', 'observed_failed', 'observed_stopped', 'no_matching_workflows'].includes(value.outcome))) fail('Invalid native watcher observation.');
  if (value.type === 'workflow_watch_result' && value.outcome === undefined) fail('Missing native watcher outcome.');
  return { type: value.type, ...(value.reason === undefined ? {} : { reason: value.reason }),
    ...(value.commit === undefined ? {} : { commit: value.commit }), ...(value.outcome === undefined ? {} : { outcome: value.outcome }) };
}
function watcherStatus(value) {
  if (value?.type !== 'workflow_watch_status' || value.schema_version !== 1 || !Array.isArray(value.records) ||
      value.records.length > 4096 || value.read_only !== true) fail('Invalid watcher status observation.');
  const counts = { records: value.records.length, queued: 0, execution_unknown: 0, observed_succeeded: 0,
    observed_failed: 0, observed_stopped: 0, no_matching_workflows: 0, owner_present: value.owner_present === true };
  for (const row of value.records) {
    if (!['queued', 'execution_unknown', 'observed_succeeded', 'observed_failed', 'observed_stopped', 'no_matching_workflows'].includes(row.state)) fail('Invalid watcher custody state.');
    counts[row.state]++;
  }
  return counts;
}
function errorObservation(error, stage) {
  return { stage, message: String(error?.message ?? error).slice(0, 2048),
    containment_unknown: error?.containment_unknown === true, phase: typeof error?.phase === 'string' ? error.phase.slice(0, 128) : null };
}
function aggregate(lanes, signal) {
  return { type: 'workflow_supervisor_cycle', schema_version: 1, lanes,
    failed: lanes.some(row => row.error || row.execution?.outcome === 'observed_failed' || row.execution?.outcome === 'observed_stopped' ||
      row.before?.refused > 0 || row.after?.refused > 0),
    pending: lanes.some(row => row.blocked || row.skipped || row.before?.pending > 0 || row.after?.pending > 0),
    stopped: signal?.aborted === true, containment_unknown: lanes.some(row => row.error?.containment_unknown),
    authoritative_check: false, execution_retried: false };
}

// The injected boundary is used by deterministic orchestration tests. Production
// always composes the real watcher and check publisher via nativeController().
export function createController(backend) {
  for (const field of ['configuration', 'execute', 'publish', 'watchStatus', 'publicationStatus']) {
    if (typeof backend?.[field] !== 'function') fail('Incomplete supervisor backend.');
  }
  function configuration(value) {
    keys(value, ['schema', 'state_directory', 'lanes']);
    if (value.schema !== 'frankengit-workflow-supervisor-v1') fail('Unsupported supervisor schema.');
    absolute(value.state_directory);
    if (!Array.isArray(value.lanes) || value.lanes.length < 1 || value.lanes.length > 64) fail('Select between one and 64 explicit trusted lanes.');
    const lanes = value.lanes.map(lane => {
      keys(lane, ['name', 'publisher']);
      if (typeof lane.name !== 'string' || !/^[a-z0-9][a-z0-9_-]{0,63}$/.test(lane.name)) fail('Invalid supervisor lane name.');
      return Object.freeze({ name: lane.name, publisher: backend.configuration(lane.publisher) });
    }).sort((a, b) => a.name < b.name ? -1 : a.name > b.name ? 1 : 0);
    if (new Set(lanes.map(lane => lane.name)).size !== lanes.length) fail('Duplicate supervisor lane name.');
    const custody = [value.state_directory], stores = [], binaries = [], selections = new Set();
    for (const { publisher } of lanes) {
      const watch = publisher.watch;
      custody.push(watch.state_directory, watch.run_parent, publisher.state_directory);
      stores.push(watch.storage_root); binaries.push(watch.fg);
      const selection = JSON.stringify([watch.storage_root, watch.tenant_id, watch.repository_id, watch.ref_hex]);
      if (selections.has(selection)) fail('A selected branch must have exactly one execution lane.');
      selections.add(selection);
    }
    for (let i = 0; i < custody.length; i++) {
      absolute(custody[i]);
      if (custody.slice(i + 1).some(path => overlap(custody[i], path)) ||
          [...stores, ...binaries].some(path => overlap(custody[i], path))) fail('All supervisor, watcher, run and publisher custody must be disjoint from each other, stores and executables.');
    }
    for (let i = 0; i < stores.length; i++) {
      if (stores.slice(i + 1).some(path => path !== stores[i] && overlap(path, stores[i]))) fail('Overlapping native stores are not independent.');
    }
    const config = { schema: value.schema, state_directory: value.state_directory, lanes: Object.freeze(lanes) };
    if (encode(config).length > MAX_BYTES) fail('Supervisor configuration exceeds its byte budget.');
    return Object.freeze(config);
  }
  async function binding(config, initialize = false) {
    await directory(config.state_directory);
    const entries = await names(config.state_directory, 3);
    if (entries.some(name => !['binding.json', 'owner.lock'].includes(name))) fail('Unrecognized supervisor custody; nothing is erased automatically.');
    const saved = await readPrivate(join(config.state_directory, 'binding.json'), MAX_BYTES, true);
    if (saved && !saved.equals(encode(config))) fail('Supervisor configuration changed; retain the original branch, principal and custody bindings.');
    if (!saved && initialize) await writeNew(join(config.state_directory, 'binding.json'), encode(config));
    return saved !== null;
  }
  async function owned(config, work) {
    await directory(config.state_directory);
    const release = await lock(join(config.state_directory, 'owner.lock'));
    let retain = false;
    try {
      await binding(config, true);
      const result = await work(); retain = result.containment_unknown === true;
      return result;
    } catch (error) { retain = error.containment_unknown === true; throw error; }
    finally { if (!retain) await release(); }
  }
  async function laneOnce(lane, options) {
    const row = { name: lane.name }; let stage = 'publication_before_execution';
    const publicationOptions = { signal: options.signal, timeoutMs: options.timeoutMs, maxPublications: options.maxPublications };
    try {
      // Backpressure is deliberate: do not create fresh executions while an old
      // publication is uncertain or cannot fit in this bounded publication pass.
      row.before = publication(await backend.publish(lane.publisher, publicationOptions));
      if (row.before.pending || row.before.unknown || row.before.limit_reached || row.before.stopped || options.signal?.aborted) {
        row.blocked = true; return row;
      }
      stage = 'execution';
      row.execution = execution(await backend.execute(lane.publisher.watch, {
        signal: options.signal, readTimeoutMs: options.readTimeoutMs, dispatchTimeoutMs: options.dispatchTimeoutMs }));
      if (options.signal?.aborted) { row.blocked = true; return row; }
      stage = 'publication_after_execution';
      row.after = publication(await backend.publish(lane.publisher, publicationOptions));
      row.blocked = row.after.pending > 0 || row.after.unknown > 0 || row.after.limit_reached || row.after.stopped;
    } catch (error) { row.error = errorObservation(error, stage); row.blocked = true; }
    return row;
  }
  async function sweep(config, options) {
    const lanes = []; let containmentUnknown = false;
    for (const lane of config.lanes) {
      if (options.signal?.aborted || containmentUnknown) {
        lanes.push({ name: lane.name, skipped: containmentUnknown ? 'containment_unknown' : 'stopped' }); continue;
      }
      const row = await laneOnce(lane, options); lanes.push(row);
      containmentUnknown ||= row.error?.containment_unknown === true;
    }
    return aggregate(lanes, options.signal);
  }
  async function once(value, options = {}) {
    const config = configuration(value), selected = optionsFor(options);
    return owned(config, () => sweep(config, selected));
  }
  async function status(value) {
    const config = configuration(value), bound = await binding(config), lanes = [];
    const owner = await lstat(join(config.state_directory, 'owner.lock')).then(() => true, error => {
      if (error.code === 'ENOENT') return false; throw error;
    });
    for (const lane of config.lanes) {
      const row = { name: lane.name };
      try {
        row.watcher = watcherStatus(await backend.watchStatus(lane.publisher.watch));
        const observed = await backend.publicationStatus(lane.publisher);
        row.publication = publication(observed);
        row.publication_owner_present = observed.owner_present === true;
        row.recovery_owner_present = observed.recovery_owner_present === true;
      } catch (error) { row.error = errorObservation(error, 'status'); }
      lanes.push(row);
    }
    return { type: 'workflow_supervisor_status', schema_version: 1, read_only: true, bound, owner_present: owner,
      lanes, authoritative_check: false, execution_retried: false };
  }
  return Object.freeze({ configuration, once, status,
    async loadConfiguration(path) { return configuration(parseJson(await readPrivate(path, MAX_BYTES), MAX_BYTES)); } });
}

export async function nativeController() {
  const [watch, publisher] = await Promise.all([import('./workflow_watch.mjs'), import('./workflow_check_publish.mjs')]);
  return createController({ configuration: publisher.configuration, execute: watch.once, publish: publisher.once,
    watchStatus: watch.status, publicationStatus: publisher.status });
}
