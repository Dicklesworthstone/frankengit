// Publish saved watcher jobs through fg's existing admission path. Never execute a job.
import { join } from 'node:path';
import { lstat } from 'node:fs/promises';
import { setTimeout as sleep } from 'node:timers/promises';
import { configuration as watchConfiguration, status as watchStatus, dispatchReport } from './workflow_watch.mjs';
import { absolute, contains, directory, executable, fail, lock, names, parseJson, readPrivate, runNative, writeNew } from './workflow_watch_io.mjs';
import { encode, sha256, hex, record, keys, integer, text, digest, principal, oid, pin,
  conclusion, historyPage, jobKey, validateJob, publication, validateTerminal } from './workflow_check_protocol.mjs';
import { lookupOutcome, outcomeEndpoint } from './transaction_outcome.mjs';
import { recoveryScope, recoveryRecord, validateRecoveryRecord, recoveredTerminal, matchPublication } from './workflow_check_outcome.mjs';

const MAX_RUNS = 128, MAX_JOBS = 128, MANIFEST_BYTES = 1024 * 1024, STATE_BYTES = 64 * 1024 * 1024;
const PLAN_RECEIPT_BYTES = 32 * 1024 * 1024;
export function configuration(value) {
  keys(value, ['schema', 'watch', 'state_directory', 'principal_id']);
  if (value.schema !== 'frankengit-workflow-check-publisher-v1') fail('Unsupported workflow publisher configuration.');
  const watch = watchConfiguration(value.watch), state = absolute(value.state_directory);
  principal(value.principal_id);
  for (const path of [watch.storage_root, watch.state_directory, watch.run_parent, watch.fg]) {
    if (contains(state, path) || contains(path, state)) fail('Check publication custody must be disjoint from watcher, native storage, runs and executable.');
  }
  const result = { schema: value.schema, watch, state_directory: state, principal_id: value.principal_id };
  if (encode(result).length > 128 * 1024) fail('Workflow publisher configuration exceeds its byte budget.');
  return Object.freeze(result);
}
const binding = config => sha256(encode(config));
const planPath = (config, id) => join(config.state_directory, `plan-${id}.json`);
const jobPath = (config, id, index, kind) => join(config.state_directory, `${kind}-${id}-${String(index).padStart(3, '0')}.json`);
function manifest(value, config) {
  keys(value, ['schema', 'binding_sha256', 'watch_id', 'intent_sha256', 'report_sha256', 'jobs']);
  for (const field of ['watch_id', 'intent_sha256', 'report_sha256']) digest(value[field]);
  if (value.schema !== 'frankengit-workflow-check-plan-v1' || value.binding_sha256 !== binding(config) ||
      !Array.isArray(value.jobs) || value.jobs.length > MAX_JOBS) fail('Invalid saved workflow publication plan.');
  const seen = new Set();
  const batch = join(config.watch.run_parent, `dispatch-${value.watch_id.slice(0, 32)}`);
  for (const job of value.jobs) {
    validateJob(job, config, value.watch_id); absolute(job.directory);
    if (!job.directory.startsWith(`${batch}/workflow-`) || !/^[0-9a-f]{32}$/.test(job.directory.slice(`${batch}/workflow-`.length)) ||
        seen.has(job.key)) fail('Saved publication changed a native directory or repeats a job.');
    seen.add(job.key);
  }
  return value;
}
// Reserve room for every start and terminal BEFORE admitting a new plan. The
// reader's aggregate ceiling must not make an already-started job unrecoverable.
function capacity(config, plans) {
  // Keep the original plan/start/native-terminal admission ceiling unchanged.
  // Extra outcome records have a separate allowance; recovery must not narrow
  // which already-admitted plans remain readable or enlarge new-work capacity.
  let original = encode(config).length, recovery = 8192;
  for (const plan of plans) {
    original += encode(plan).length + plan.jobs.length * 2 * 8192;
    recovery += plan.jobs.length * 2 * 8192;
    if (original > PLAN_RECEIPT_BYTES || original + recovery > STATE_BYTES) fail('Workflow publication receipt capacity reached; retain existing custody.');
  }
}
async function inventory(config, initialize = false) {
  await directory(config.state_directory);
  const files = await names(config.state_directory, MAX_RUNS * (1 + 4 * MAX_JOBS) + 4);
  const fileSet = new Set(files);
  const saved = await readPrivate(join(config.state_directory, 'binding.json'), 128 * 1024, true);
  if (saved && !saved.equals(encode(config))) fail('Workflow publisher configuration changed; original principal and keys must be retained.');
  if (!saved) {
    if (files.some(file => file !== 'owner.lock')) fail('Unbound publication directory is not empty.');
    if (!initialize) return [];
    await writeNew(join(config.state_directory, 'binding.json'), encode(config));
  }
  const remote = await readPrivate(join(config.state_directory, 'recovery-binding.json'), 8192, true);
  if (remote) {
    const value = parseJson(remote, 8192);
    keys(value, ['schema', 'publisher_binding_sha256', 'endpoint']);
    if (value.schema !== 'frankengit-workflow-check-recovery-binding-v1' || value.publisher_binding_sha256 !== binding(config)) fail('Recovery endpoint lost its publisher binding.');
    outcomeEndpoint(value.endpoint);
  }
  const groups = new Map(), selected = new Set(['binding.json', 'owner.lock', 'recovery.lock', 'recovery-binding.json']); let total = remote?.length ?? 0;
  const read = async (path, maximum) => {
    const raw = await readPrivate(path, maximum); total += raw.length;
    if (total > STATE_BYTES) fail('Publication custody exceeds aggregate read budget.');
    return parseJson(raw, maximum);
  };
  for (const file of files) {
    const match = /^plan-([0-9a-f]{64})\.json$/.exec(file);
    if (!match) continue;
    if (groups.size === MAX_RUNS) fail('Publication run capacity reached.');
    const plan = manifest(await read(join(config.state_directory, file), MANIFEST_BYTES), config);
    if (plan.watch_id !== match[1]) fail('Publication plan filename changed.');
    const rows = [];
    for (let index = 0; index < plan.jobs.length; index++) {
      const job = plan.jobs[index], row = { job, index, started: false, terminal: null, observed: null, recovered: null };
      for (const kind of ['started', 'terminal', 'observed', 'recovered']) {
        const name = `${kind}-${plan.watch_id}-${String(index).padStart(3, '0')}.json`;
        selected.add(name);
        if (!fileSet.has(name)) continue;
        const value = await read(join(config.state_directory, name), 8192);
        if (kind === 'started') {
          keys(value, ['schema', 'request_sha256']);
          if (value.schema !== 'frankengit-workflow-check-start-v1' || value.request_sha256 !== sha256(encode(job))) fail('Original publication-start identity changed.');
          row.started = true;
        } else if (kind === 'terminal') row.terminal = validateTerminal(value, job);
        else {
          if (!remote) fail('Saved outcome lost its independent endpoint binding.');
          row[kind] = validateRecoveryRecord(value, config, job, kind === 'recovered' ? row.observed : null);
          if (row[kind].reply.transaction === null || (kind === 'recovered' && (!row.observed || !row[kind].reply.terminal))) fail('Saved outcome lost its original transaction observation.');
        }
      }
      matchPublication(row.terminal, row.observed); matchPublication(row.terminal, row.recovered);
      row.terminal ??= row.recovered ? recoveredTerminal(row.recovered) : row.observed ? recoveredTerminal(row.observed) : null;
      if ((row.terminal || row.observed || row.recovered) && !row.started) fail('Terminal publication lost its original start responsibility.');
      rows.push(row);
    }
    selected.add(file); groups.set(plan.watch_id, { plan, rows });
  }
  if (files.some(file => !selected.has(file))) fail('Orphaned or interrupted publication custody; no state is erased automatically.');
  const result = [...groups.values()];
  capacity(config, result.map(group => group.plan));
  return result;
}
function context(options = {}) {
  const deadline = performance.now() + integer(options.timeoutMs ?? 660_000, 1, 660_000), signal = options.signal;
  return { signal, maxPublications: integer(options.maxPublications ?? 128, 1, 128),
    check() { signal?.throwIfAborted(); if (performance.now() >= deadline) fail('Workflow publication operation deadline exceeded.'); },
    remaining() { this.check(); return Math.max(1, Math.floor(deadline - performance.now())); } };
}
async function native(config, args, cx, reading) {
  cx.check();
  const value = await runNative(config.watch.fg, args, { signal: cx.signal, drain: !reading,
    timeoutMs: Math.min(cx.remaining(), reading ? 30_000 : 660_000), maximum: reading ? 8 * 1024 * 1024 : 128 * 1024 });
  if (value.forced || value.signal || value.spawn_error || (reading && value.code !== 0)) {
    const error = new Error(`Native workflow ${reading ? 'recovery' : 'publication'} unresolved; retain original custody and keys. Exit=${value.code}, signal=${value.signal}, reason=${value.reason ?? value.spawn_error ?? 'unavailable'}.`);
    error.containment_unknown = value.forced; error.native_stderr_hex = hex(value.stderr); throw error;
  }
  return value;
}
function markerMatches(marker, run) {
  if (marker.type !== 'trusted_workflow_attempt' || marker.state !== 'started') fail('Original workflow marker is unavailable.');
  for (const [name, value] of Object.entries(run)) {
    if (['type', 'succeeded', 'workspaces_closed', 'request_interrupted', 'execution'].includes(name)) continue;
    if (JSON.stringify(marker[name]) !== JSON.stringify(value)) fail('Original workflow marker changed the selected executed input.');
  }
  record(marker.execution_plan);
  for (const [name, value] of Object.entries(run.execution)) {
    const expected = name === 'jobs' ? [] : name === 'succeeded' ? false : value;
    if (JSON.stringify(marker.execution_plan[name]) !== JSON.stringify(expected)) fail('Original workflow marker changed its compiled plan.');
  }
}
async function completedJobs(config, intent, report, cx) {
  const watch = config.watch, jobs = [], budget = { bytes: 0, pages: 0, batches: 0 };
  for (const run of report.runs) {
    cx.check();
    const directoryPath = join(watch.run_parent, `dispatch-${intent.run_id}`, `workflow-${run.run_id}`);
    await directory(directoryPath);
    const marker = await readPrivate(join(directoryPath, 'attempt.json'), 512 * 1024);
    markerMatches(parseJson(marker, 512 * 1024), run);
    const journal = sha256(marker), scope = { tenant: watch.tenant_id, repository: watch.repository_id, journal_id: journal };
    const wanted = new Map(run.execution.jobs.map(job => [job.id, job])), found = new Map(), batches = new Set();
    let snapshot = null, previous = null, after = null, ordinal = -1, runHash = null, attemptHash = null;
    const definition = report.plan.workflows.find(definition => definition.run_id === run.run_id);
    do {
      if (++budget.pages > 128) fail('Workflow recovery page budget exceeded.');
      const args = ['workflow', 'recover', directoryPath, watch.tenant_id, watch.repository_id, '--journal-id', journal,
        '--limit', '128', '--page-bytes', '1048576', '--timeout-ms', String(Math.min(cx.remaining(), 30000))];
      if (snapshot) args.push('--minimum-pin', snapshot, '--at-pin', snapshot, '--after-batch', after);
      const result = await native(config, args, cx, true); budget.bytes += result.stdout.length;
      if (budget.bytes > 16 * 1024 * 1024) fail('Workflow recovery aggregate byte budget exceeded.');
      const page = historyPage(parseJson(result.stdout, 8 * 1024 * 1024), scope, previous);
      snapshot = page.snapshot; previous = page;
      for (const entry of page.entries) {
        record(entry); digest(entry.batch_sha256); integer(entry.ordinal, ordinal + 1, Number.MAX_SAFE_INTEGER); ordinal = entry.ordinal;
        integer(entry.body_bytes, 1, 8 * 1024 * 1024);
        if (++budget.batches > 1024 || batches.has(entry.batch_sha256)) fail('Workflow history batch bound or identity repeated.');
        batches.add(entry.batch_sha256);
        for (const field of ['run_sha256', 'attempt_sha256', 'authority_basis_sha256', 'workflow_graph_sha256']) digest(entry[field]);
        runHash ??= entry.run_sha256; attemptHash ??= entry.attempt_sha256;
        if (entry.run_sha256 !== runHash || entry.attempt_sha256 !== attemptHash || entry.authority_basis_sha256 !== intent.snapshot_token.slice(6) ||
            entry.object_format !== watch.object_format || oid(entry.source_commit, watch.object_format) !== intent.commit ||
            entry.workflow_graph_sha256 !== definition.graph_sha256 || entry.trust_domain !== 'trusted-local-owner' ||
            !['pending', 'acknowledged'].includes(entry.delivery)) fail('Saved workflow batch changed source, graph or attempt.');
        if (entry.delivery === 'acknowledged') digest(entry.delivery_receipt_sha256);
        else if (entry.delivery_receipt_sha256 !== null) fail('Conflicting journal delivery observation.');
        const profile = record(entry.profile), execution = run.execution;
        digest(profile.source_sha256);
        if (profile.name !== 'trusted-local-foreground-v1' || profile.step_timeout_nanos !== execution.step_timeout_millis * 1_000_000 ||
            profile.run_timeout_nanos !== execution.run_timeout_millis * 1_000_000 || profile.stream_bytes !== execution.stream_bytes ||
            profile.total_output_bytes !== execution.total_output_bytes || !Array.isArray(entry.facts) || entry.facts.length > 128) fail('Saved workflow execution profile changed.');
        for (let index = 0; index < entry.facts.length; index++) {
          const fact = record(entry.facts[index]); text(fact.job); integer(fact.logical_millis, 0, Number.MAX_SAFE_INTEGER);
          if (!['queued', 'in_progress', 'completed'].includes(fact.status)) fail('Unknown native workflow fact.');
          if (fact.status !== 'completed') continue;
          digest(fact.evidence_sha256);
          if (!wanted.has(fact.job) || found.has(fact.job) || !['failure', 'cancelled', 'timed_out', 'action_required'].includes(fact.conclusion)) fail('Completed native workflow fact is duplicated or not in the executed plan.');
          found.set(fact.job, { directory: directoryPath, journal_id: journal, minimum_pin: snapshot,
            batch_sha256: entry.batch_sha256, fact_index: index, job: fact.job, source_commit: intent.commit,
            run_id: entry.run_sha256, attempt_id: entry.attempt_sha256, graph_root: entry.workflow_graph_sha256,
            evidence_sha256: fact.evidence_sha256, conclusion: conclusion(wanted.get(fact.job).outcome) });
        }
      }
      after = page.next_after;
      if (after !== null && batches.size >= page.retained_batches) fail('Native workflow continuation exceeds retained batch count.');
    } while (after !== null);
    if (batches.size !== previous.retained_batches || found.size !== wanted.size) fail('Saved history omitted completed workflow jobs; nothing from this run was prepared.');
    for (const job of run.execution.jobs) {
      const selected = found.get(job.id); selected.key = jobKey(binding(config), intent.id, selected);
      jobs.push(selected);
      if (jobs.length > MAX_JOBS) fail('Workflow publication exceeds the 128-job batch bound.');
    }
  }
  return jobs;
}
async function prepare(config, row, cx, groups) {
  cx.check();
  const watch = config.watch;
  await directory(watch.run_parent); await directory(row.native_directory);
  const intent = parseJson(await readPrivate(join(watch.state_directory, `intent-${row.id}.json`), 128 * 1024));
  const expected = parseJson(await readPrivate(join(watch.state_directory, `result-${row.id}.json`), 128 * 1024));
  const report = parseJson(await readPrivate(join(row.native_directory, 'report.json'), 40 * 1024 * 1024), 40 * 1024 * 1024);
  const selected = dispatchReport(watch, intent, report);
  if (!encode(expected).equals(encode(selected))) fail('Native workflow report changed after the watcher retained completion.');
  const plan = manifest({ schema: 'frankengit-workflow-check-plan-v1', binding_sha256: binding(config), watch_id: row.id,
    intent_sha256: selected.intent_sha256, report_sha256: selected.report_sha256, jobs: await completedJobs(config, intent, report, cx) }, config);
  const bytes = encode(plan);
  if (bytes.length > MANIFEST_BYTES) fail('Workflow publication plan exceeds its byte budget.');
  capacity(config, [...groups.map(group => group.plan), plan]);
  cx.check(); await writeNew(planPath(config, row.id), bytes);
  return { plan, rows: plan.jobs.map((job, index) => ({ job, index, started: false, terminal: null })) };
}
async function submit(config, group, row, cx) {
  cx.check();
  const { job, index } = row, watch = config.watch;
  if (!row.started) {
    await writeNew(jobPath(config, group.plan.watch_id, index, 'started'), encode({ schema: 'frankengit-workflow-check-start-v1', request_sha256: sha256(encode(job)) }));
    row.started = true;
  }
  // After this durable point an error never proves absence of earlier publication.
  const args = ['workflow', 'publish', watch.storage_root, watch.tenant_id, watch.repository_id, watch.ref_hex,
    '--trusted-local', '--ref-hex', '--run-directory', job.directory, '--journal-id', job.journal_id,
    '--minimum-pin', job.minimum_pin, '--batch', job.batch_sha256, '--fact-index', String(job.fact_index),
    '--principal-id', config.principal_id, '--idempotency-key', job.key, '--expected-incarnation', watch.repository_incarnation,
    '--object-format', watch.object_format, '--timeout-ms', String(Math.min(cx.remaining(), 30000))];
  const nativeResult = await native(config, args, cx, false);
  const reply = parseJson(nativeResult.stdout, 128 * 1024);
  const terminal = publication(reply, config, job, nativeResult.code);
  matchPublication(terminal, row.observed); matchPublication(terminal, row.recovered);
  try {
    await writeNew(jobPath(config, group.plan.watch_id, index, 'terminal'), encode(terminal));
    row.terminal = terminal;
    if (!reply.node_closed) fail('Canonical workflow terminal observed, but native node cleanup failed.');
  } catch (error) { error.retained_terminal = terminal; throw error; }
  return terminal;
}
function summary(groups) {
  return { type: 'workflow_check_status', schema_version: 1, historical_observations: true, authoritative_check: false,
    execution_retried: false, runs: groups.map(group => ({ id: group.plan.watch_id, jobs: group.rows.length,
      committed: group.rows.filter(row => row.terminal?.outcome === 'committed').length,
      refused: group.rows.filter(row => row.terminal?.outcome === 'refused').length,
      pending: group.rows.filter(row => !row.terminal).length,
      unknown: group.rows.filter(row => row.started && !row.terminal).length })) };
}
export async function status(config) {
  config = configuration(config);
  const groups = await inventory(config);
  const owner = await lstat(join(config.state_directory, 'owner.lock')).then(() => true, error => { if (error.code === 'ENOENT') return false; throw error; });
  const recovering = await lstat(join(config.state_directory, 'recovery.lock')).then(() => true, error => { if (error.code === 'ENOENT') return false; throw error; });
  return { ...summary(groups), read_only: true, owner_present: owner, recovery_owner_present: recovering };
}
async function owned(config, work) {
  await directory(config.state_directory); await executable(config.watch.fg);
  await directory(config.watch.storage_root, false);
  const release = await lock(join(config.state_directory, 'owner.lock'));
  let failure;
  try { return await work(); } catch (error) { failure = error; throw error; }
  finally {
    if (!failure?.containment_unknown) {
      try { await release(); }
      catch (error) { if (failure) { failure.cleanup_error = error.message; } else throw error; }
    }
  }
}
async function sweep(config, options) {
  const cx = context(options), groups = await inventory(config, true);
  if (!options.resume && groups.some(group => group.rows.some(row => row.started && !row.terminal))) fail('Original check publication unresolved; use explicit resume with the same principal and keys.');
  const observer = options.onObservation ?? (() => {});
  if (typeof observer !== 'function') fail('Invalid publication observer.');
  let calls = 0;
  const processGroup = async group => {
    for (const row of group.rows) {
      if (row.terminal) continue;
      if (cx.signal?.aborted || calls === cx.maxPublications) return false;
      let terminal;
      try { terminal = await submit(config, group, row, cx); }
      catch (error) {
        if (row.started && !row.terminal && !error.retained_terminal) error.publication_unknown = true;
        throw error;
      }
      calls++;
      const event = { type: 'workflow_check_observed', schema_version: 1, watch_id: group.plan.watch_id, job: row.job.job,
        conclusion: row.job.conclusion, ...terminal, authoritative_check: false, execution_retried: false };
      try { await observer(event); } catch (error) { error.retained_terminal = terminal; throw error; }
    }
    return true;
  };
  const stopped = () => ({ ...summary(groups), publications: calls, limit_reached: calls === cx.maxPublications, stopped: cx.signal?.aborted === true });
  for (const group of groups) if (!await processGroup(group)) return stopped();
  if (!options.resume) {
    const watched = await watchStatus(config.watch);
    for (const row of watched.records) {
      if (['execution_unknown', 'queued'].includes(row.state) || groups.some(group => group.plan.watch_id === row.id)) continue;
      if (groups.length === MAX_RUNS) fail('Workflow publication run capacity reached; no history is evicted.');
      if (cx.signal?.aborted || calls === cx.maxPublications) return stopped();
      const group = await prepare(config, row, cx, groups); groups.push(group);
      if (!await processGroup(group)) return stopped();
    }
  }
  return { ...summary(groups), publications: calls, limit_reached: false, stopped: cx.signal?.aborted === true };
}
export async function once(config, options = {}) {
  options = { ...options };
  config = configuration(config);
  if (options.resume !== undefined && typeof options.resume !== 'boolean') fail('Invalid publication resume choice.');
  return owned(config, () => sweep(config, options));
}
export async function serve(config, options = {}) {
  options = { ...options };
  config = configuration(config);
  if (options.resume !== undefined) fail('Continuous publishing never retries an uncertain submission. Use explicit resume.');
  const pollMs = integer(options.pollMs ?? 1000, 100, 60_000), maxPolls = integer(options.maxPolls ?? 1_000_000, 1, 1_000_000);
  return owned(config, async () => {
    let polls = 0, publications = 0, last = null;
    while (polls < maxPolls && !options.signal?.aborted) {
      last = await sweep(config, options); polls++; publications += last.publications;
      if (polls === maxPolls || options.signal?.aborted) break;
      try { await sleep(pollMs, undefined, { signal: options.signal }); }
      catch (error) { if (!options.signal?.aborted) throw error; }
    }
    return { type: 'workflow_check_service', schema_version: 1, polls, publications, stopped: options.signal?.aborted === true,
      poll_limit_reached: polls === maxPolls, last, authoritative_check: false, execution_retried: false };
  });
}


// This lock protects only local recovery observations. A retained publisher
// owner.lock is deliberately neither acquired nor removed: an outcome receipt
// cannot prove that a crashed native process was reaped or its node closed.
export async function recover(config, address, token, options = {}) {
  config = configuration(config); address = outcomeEndpoint(address);
  if (typeof token !== 'string' || !/^[0-9a-f]{64}$/.test(token)) fail('A current same-principal outcome credential is required.');
  if (!options || typeof options !== 'object' || Array.isArray(options) ||
      Object.keys(options).some(key => !['maxLookups', 'timeoutMs', 'requestTimeoutMs', 'signal', 'ca', 'onObservation'].includes(key))) fail('Unsupported workflow recovery options.');
  const maxLookups = integer(options.maxLookups ?? 128, 1, 128), requestTimeout = integer(options.requestTimeoutMs ?? 30000, 1, 300000);
  const timeout = integer(options.timeoutMs ?? 660000, 1, 660000), signal = options.signal;
  if (signal !== undefined && !(signal instanceof AbortSignal)) fail('Invalid recovery cancellation signal.');
  const observer = options.onObservation ?? (() => {});
  if (typeof observer !== 'function') fail('Invalid recovery observer.');
  const ca = options.ca === undefined ? undefined : Buffer.isBuffer(options.ca) && options.ca.length && options.ca.length <= 128 * 1024
    ? Buffer.from(options.ca) : fail('Invalid recovery TLS CA.');
  const deadline = performance.now() + timeout;
  const check = () => { signal?.throwIfAborted(); if (performance.now() >= deadline) fail('Workflow recovery deadline exceeded.'); };
  check(); await directory(config.state_directory);
  // Refuse accidental initialization: only existing, verified publisher plans
  // can select original keys. No original run files or executable are read.
  await inventory(config);
  if (!await readPrivate(join(config.state_directory, 'binding.json'), 128 * 1024, true)) fail('Retain the original publisher binding and plans before recovery.');
  const release = await lock(join(config.state_directory, 'recovery.lock'));
  let result, failure, groups, lookups = 0, terminalCount = 0;
  const snapshot = () => ({ ...summary(groups), type: 'workflow_check_recovery', remote_read_only: true,
    request_reexecuted: false, absence_proves_non_commit: false, process_containment_asserted: false,
    local_observations_persisted: true, lookups, recovered_terminals: terminalCount,
    limit_reached: groups.some(group => group.rows.some(row => row.started && !row.terminal)) && lookups === maxLookups,
    stopped: signal?.aborted === true });
  try {
    groups = await inventory(config);
    const endpointPath = join(config.state_directory, 'recovery-binding.json');
    const expected = encode({ schema: 'frankengit-workflow-check-recovery-binding-v1', publisher_binding_sha256: binding(config), endpoint: address });
    const saved = await readPrivate(endpointPath, 8192, true);
    if (saved && !saved.equals(expected)) fail('Recovery endpoint changed; retain the independently selected original endpoint.');
    check(); if (!saved) await writeNew(endpointPath, expected);
    for (const group of groups) for (const row of group.rows) {
      if (!row.started || row.terminal) continue;
      if (signal?.aborted || lookups === maxLookups) { result = snapshot(); return result; }
      check();
      const reply = await lookupOutcome(address, token, { ...recoveryScope(config), key: row.job.key }, {
        signal, ca, timeoutMs: Math.max(1, Math.min(requestTimeout, Math.floor(deadline - performance.now()))), known: row.observed?.reply ?? null });
      lookups++;
      const observed = recoveryRecord(reply, config, row.job, row.observed), terminal = recoveredTerminal(observed);
      try {
        // An active native sender may have finalized while this read was in flight.
        const nativeBytes = await readPrivate(jobPath(config, group.plan.watch_id, row.index, 'terminal'), 8192, true);
        if (nativeBytes) {
          const local = validateTerminal(parseJson(nativeBytes, 8192), row.job);
          matchPublication(local, observed);
          if (!reply.terminal) fail('A newer local terminal was retained during recovery; repeat the read instead of losing knowledge.');
          row.terminal = local;
        }
        if (reply.transaction !== null) {
          const kind = row.observed ? 'recovered' : 'observed';
          if (!row.observed || terminal) {
            const bytes = encode(observed);
            if (bytes.length > 8192) fail('Recovery observation exceeds its reserved receipt capacity.');
            await writeNew(jobPath(config, group.plan.watch_id, row.index, kind), bytes);
            row[kind] = observed;
          }
        }
        if (terminal) { row.terminal ??= terminal; terminalCount++; }
        // No post-response cancellation check: retain a validated terminal even
        // when stopping. Cancellation prevents only the next original-key read.
        await observer({ type: 'workflow_check_outcome_observed', schema_version: 1, watch_id: group.plan.watch_id,
          job: row.job.job, state: reply.state, terminal: reply.terminal, tx_id: reply.transaction?.tx_id ?? null,
          decision: reply.decision, check_id: null, authoritative_check: false, execution_retried: false, request_reexecuted: false });
      } catch (error) {
        if (terminal) error.retained_terminal = terminal;
        throw error;
      }
    }
    // Reconcile concurrent native receipts before reporting complete custody.
    groups = await inventory(config); result = snapshot(); return result;
  } catch (error) {
    failure = error;
    if (groups) error.retained_recovery = snapshot();
    throw error;
  } finally {
    try { await release(); }
    catch (error) {
      if (failure) failure.cleanup_error = error.message;
      else { error.retained_recovery = result; throw error; }
    }
  }
}
