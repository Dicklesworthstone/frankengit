// External trusted-local automation. Rust owns Git, workflow execution and authority.
import { createHash } from 'node:crypto';
import { join } from 'node:path';
import { lstat } from 'node:fs/promises';
import { setTimeout as sleep } from 'node:timers/promises';
import { absolute, contains, directory, executable, fail, lock, names, parseJson,
  readPrivate, runNative, writeNew } from './workflow_watch_io.mjs';

const hex = bytes => Buffer.from(bytes).toString('hex');
const encode = value => Buffer.from(`${JSON.stringify(value)}\n`);
const digest = bytes => createHash('sha256').update(bytes).digest('hex');
const object = value => { if (!value || typeof value !== 'object' || Array.isArray(value)) fail('Expected a JSON record.'); return value; };
function keys(value, allowed) {
  object(value);
  if (Object.keys(value).some(key => !allowed.includes(key)) || allowed.some(key => !Object.hasOwn(value, key))) fail('Missing or unsupported watcher fields.');
}
function bounded(value, max, label) {
  if (typeof value !== 'string' || !value || Buffer.byteLength(value) > max || /[\0-\x1f\x7f]/u.test(value)) fail(`Invalid ${label}.`);
  return value;
}
function number(value, min, max) {
  if (!Number.isSafeInteger(value) || value < min || value > max) fail('Invalid bounded watcher counter.');
  return value;
}
const id = value => { if (typeof value !== 'string' || !/^[0-9a-f]{32}$/.test(value)) fail('Invalid repository identity.'); return value; };
function bytes(value, maximum = 4096) {
  if (typeof value !== 'string' || !value || value.length > maximum * 2 || !/^(?:[0-9a-f]{2})+$/.test(value)) fail('Expected bounded lowercase path bytes.');
  return Buffer.from(value, 'hex');
}
function pathBytes(value, branch = false) {
  const raw = bytes(value, branch ? 1024 : 4096);
  // Split bytes, not hex digits: a byte pair may straddle a textual "2f".
  const components = []; let start = 0;
  for (let end = 0; end <= raw.length; end++) if (end === raw.length || raw[end] === 47) { components.push(raw.subarray(start, end)); start = end + 1; }
  if (raw.includes(0) || components.some(part => !part.length || part.equals(Buffer.from('.')) || part.equals(Buffer.from('..')) ||
      (part.length === 4 && part[0] === 46 && (part[1] | 32) === 103 && (part[2] | 32) === 105 && (part[3] | 32) === 116))) fail('Unsafe native path.');
  if (branch && (!raw.subarray(0, 11).equals(Buffer.from('refs/heads/')) ||
      raw.some(b => b <= 32 || b === 127 || Buffer.from('~^:?*[\\').includes(b)) ||
      raw.includes(Buffer.from('..')) || raw.includes(Buffer.from('@{')) || raw.at(-1) === 46 ||
      components.some(part => part[0] === 46 || part.subarray(-5).equals(Buffer.from('.lock'))))) fail('A complete native branch reference is required.');
  return value;
}
function oid(value, format) {
  const raw = typeof value === 'string' && value.startsWith(`${format}:`) ? value.slice(format.length + 1) : value;
  if (typeof raw !== 'string' || !new RegExp(`^[0-9a-f]{${format === 'sha1' ? 40 : 64}}$`).test(raw) || /^0+$/.test(raw)) fail('Native object format or identity mismatch.');
  return raw;
}
const head = value => { if (typeof value !== 'string' || !/^alg:2:[0-9a-f]{64}$/.test(value)) fail('Unsupported native snapshot token.'); return value; };
const SETTLED_STOPS = ['request_stopped', 'output_budget_exhausted', 'workflow_refused', 'workflow_timed_out', 'workflow_output_limit'];
const CONFIG = ['schema', 'fg', 'storage_root', 'tenant_id', 'repository_id', 'repository_incarnation',
  'object_format', 'ref_hex', 'workflow_directory_hex', 'input_prefixes_hex', 'event', 'state_directory', 'run_parent', 'max_runs', 'trust'];
export function configuration(value) {
  keys(value, CONFIG);
  if (process.platform !== 'linux' || value.schema !== 'frankengit-workflow-watch-v1' ||
      value.trust !== 'selected-branch-host-execution' || !['push', 'workflow_dispatch'].includes(value.event) ||
      !['sha1', 'sha256'].includes(value.object_format)) fail('Select the explicit trusted-local Linux workflow profile.');
  const result = Object.fromEntries(CONFIG.map(key => [key, value[key]]));
  for (const key of ['fg', 'storage_root', 'state_directory', 'run_parent']) absolute(result[key]);
  for (const key of ['tenant_id', 'repository_id', 'repository_incarnation']) id(result[key]);
  pathBytes(result.ref_hex, true); pathBytes(result.workflow_directory_hex);
  const prefixes = result.input_prefixes_hex;
  if (!Array.isArray(prefixes) || !prefixes.length || prefixes.length > 1024) fail('Choose explicit bounded workflow inputs.');
  result.input_prefixes_hex = prefixes.map(value => {
    pathBytes(value); if (bytes(value).includes(47)) fail('Workflow inputs must be top-level native paths.'); return value;
  }).sort();
  if (new Set(prefixes).size !== prefixes.length || !prefixes.some(prefix =>
      result.workflow_directory_hex === prefix || result.workflow_directory_hex.startsWith(`${prefix}2f`))) fail('Workflow directory must be included exactly once in selected inputs.');
  number(result.max_runs, 1, 4096);
  const dirs = [result.storage_root, result.state_directory, result.run_parent];
  for (let a = 0; a < dirs.length; a++) for (let b = a + 1; b < dirs.length; b++) {
    if (contains(dirs[a], dirs[b]) || contains(dirs[b], dirs[a])) fail('Native storage, run parent and watcher custody must be disjoint.');
  }
  if (encode(result).length > 128 * 1024) fail('Watcher configuration exceeds its byte limit.');
  Object.freeze(result.input_prefixes_hex);
  return Object.freeze(result);
}
export async function loadConfiguration(path) { return configuration(parseJson(await readPrivate(path, 128 * 1024))); }
async function preflight(config, mode = 'execute') {
  await directory(config.state_directory);
  if (mode !== 'status') await directory(config.run_parent);
  if (mode === 'execute') { await directory(config.storage_root, false); await executable(config.fg); }
}
function intentFor(config, selected) {
  const configHash = digest(encode(config));
  const key = digest(Buffer.from(`frankengit/workflow-watch-observed-commit/v1\0${configHash}\0${selected.commit}`));
  return { schema: 'frankengit-workflow-watch-intent-v1', id: key, configuration_sha256: configHash,
    run_id: key.slice(0, 32), snapshot_token: selected.snapshot_token, source_head: selected.source_head,
    commit: selected.commit, trigger_provenance: 'observed_branch_tip_not_push_event' };
}
function validateIntent(config, value) {
  keys(value, ['schema', 'id', 'configuration_sha256', 'run_id', 'snapshot_token', 'source_head', 'commit', 'trigger_provenance']);
  head(value.snapshot_token); bounded(value.source_head, 256, 'source head'); oid(value.commit, config.object_format);
  const expected = intentFor(config, { ...value, commit: oid(value.commit, config.object_format) });
  if (!encode(expected).equals(encode(value))) fail('Retained watcher intent changed scope or identity.');
  return value;
}
function paths(config, intent) {
  return { intent: join(config.state_directory, `intent-${intent.id}.json`),
    started: join(config.state_directory, `started-${intent.id}.json`),
    result: join(config.state_directory, `result-${intent.id}.json`),
    batch: join(config.run_parent, `dispatch-${intent.run_id}`) };
}
async function identicalOrNew(path, data) {
  const wanted = encode(data);
  try { await writeNew(path, wanted); }
  catch (error) {
    if (error.code !== 'EEXIST') throw error;
    if (!(await readPrivate(path, 128 * 1024)).equals(wanted)) fail('Conflicting immutable watcher observation.');
  }
}
async function inventory(config, bind = false) {
  const bindingPath = join(config.state_directory, 'binding.json');
  const saved = await readPrivate(bindingPath, 128 * 1024, true);
  if (saved && !saved.equals(encode(config))) fail('Watcher configuration changed; never reset an existing run namespace.');
  const entries = await names(config.state_directory, 3 * config.max_runs + 2);
  if (!saved) {
    if (entries.some(name => name !== 'owner.lock')) fail('Unbound watcher directory is not empty.');
    if (!bind) return [];
    await writeNew(bindingPath, encode(config));
  }
  const records = new Map();
  for (const name of entries) {
    if (['binding.json', 'owner.lock'].includes(name)) continue;
    const match = /^(intent|started|result)-([0-9a-f]{64})\.json$/.exec(name);
    if (!match) fail('Unrecognized custody entry; interrupted writes must be inspected, never erased automatically.');
    const row = records.get(match[2]) ?? {};
    row[match[1]] = parseJson(await readPrivate(join(config.state_directory, name), 128 * 1024));
    records.set(match[2], row);
  }
  if (records.size > config.max_runs) fail('Watcher run capacity reached.');
  for (const [key, record] of records) {
    if (!record.intent || validateIntent(config, record.intent).id !== key) fail('Orphaned watcher observation.');
    const intentHash = digest(encode(record.intent));
    if (record.started) keys(record.started, ['schema', 'intent_sha256']);
    if (record.result) {
      const stopped = record.result.outcome === 'observed_stopped';
      keys(record.result, ['schema', 'intent_sha256', 'report_sha256', 'outcome', 'matched_count', 'executed_count', 'authoritative_check', ...(stopped ? ['stop_reason'] : [])]);
      number(record.result.matched_count, 0, 32); number(record.result.executed_count, 0, record.result.matched_count);
      if ((!stopped && record.result.executed_count !== record.result.matched_count) || record.result.authoritative_check !== false ||
          (stopped ? !SETTLED_STOPS.includes(record.result.stop_reason)
            : (record.result.outcome === 'no_matching_workflows') !== (record.result.matched_count === 0))) fail('Invalid completion custody counts or authority claim.');
    }
    if (record.started && (record.started.schema !== 'frankengit-workflow-watch-start-v1' || record.started.intent_sha256 !== intentHash)) fail('Execution-start custody changed.');
    if (record.result && (!record.started || record.result.intent_sha256 !== intentHash ||
        record.result.schema !== 'frankengit-workflow-watch-result-v1' ||
        !['observed_succeeded', 'observed_failed', 'observed_stopped', 'no_matching_workflows'].includes(record.result.outcome) ||
        !/^[0-9a-f]{64}$/.test(record.result.report_sha256))) fail('Completion custody changed.');
  }
  return [...records.values()];
}
function nativeFailure(result, label) {
  const error = new Error(`${label}; native exit=${result.code}, signal=${result.signal}, reason=${result.reason ?? result.spawn_error ?? 'invalid_response'}. No execution retry was made.`);
  error.native_stderr_hex = hex(result.stderr); error.containment_unknown = result.forced;
  return error;
}
export async function observe(config, { signal, readTimeoutMs = 30_000 } = {}) {
  let cursor = null, snapshot = null, sourceHead = null, total = 0;
  const deadline = performance.now() + number(readTimeoutMs, 1, 30_000);
  for (let page = 0; page < 256; page++) {
    signal?.throwIfAborted();
    const args = ['refs', config.storage_root, config.tenant_id, config.repository_id, '--trusted-local',
      '--object-format', config.object_format, '--limit', '100'];
    if (cursor !== null) args.push('--after-hex', cursor, '--expected-head', snapshot);
    const remaining = Math.floor(deadline - performance.now());
    if (remaining < 1) fail('Whole reference-observation deadline exceeded.');
    const native = await runNative(config.fg, args, { signal, timeoutMs: remaining, maximum: 1024 * 1024 });
    if (native.forced || native.code !== 0 || native.signal || native.spawn_error) throw nativeFailure(native, 'Native reference observation unavailable');
    total += native.stdout.length;
    if (total > 16 * 1024 * 1024) fail('Reference scan exceeds its aggregate byte limit.');
    const value = parseJson(native.stdout, 1024 * 1024);
    if (value.type !== 'reference_page' || value.schema_version !== 1 || value.node_closed !== true ||
        value.tenant_id !== config.tenant_id || value.repository_id !== config.repository_id || value.object_format !== config.object_format ||
        !Array.isArray(value.references) || value.references.length > 100 || typeof value.has_more !== 'boolean' ||
        value.has_more !== (value.next_after_hex !== null)) fail('Invalid native reference page.');
    head(value.snapshot_token); bounded(value.source_head, 256, 'source head');
    if (snapshot !== null && (snapshot !== value.snapshot_token || sourceHead !== value.source_head)) fail('Native reference snapshot moved between pages.');
    snapshot = value.snapshot_token; sourceHead = value.source_head;
    let previous = cursor ?? '', found = null, passed = false;
    for (const row of value.references) {
      keys(row, ['reference_hex', 'tip']); bytes(row.reference_hex, 1024);
      if (row.reference_hex <= previous) fail('Native reference ordering or cursor regressed.');
      previous = row.reference_hex;
      const commit = oid(row.tip, config.object_format);
      if (row.reference_hex === config.ref_hex) found = commit;
      if (row.reference_hex > config.ref_hex) passed = true;
    }
    if (value.has_more && (value.references.length !== 100 || value.next_after_hex !== previous)) fail('Invalid native reference continuation.');
    if (found) return { commit: found, source_head: sourceHead, snapshot_token: snapshot };
    if (passed || !value.has_more) return null;
    cursor = value.next_after_hex;
  }
  fail('Reference scan page limit reached; branch absence is not established.');
}
function childId(batch, event, path) {
  const frame = part => { const length = Buffer.alloc(8); length.writeBigUInt64BE(BigInt(part.length)); return Buffer.concat([length, part]); };
  return digest(Buffer.concat([Buffer.from('frankengit/workflow-dispatch-child/v1\0'), Buffer.from(batch, 'hex'),
    frame(Buffer.from(event)), frame(Buffer.from(path, 'hex'))])).slice(0, 32);
}
function executionReport(run, plan, totals, graph) {
  const report = object(run.execution);
  if (report.schema_version !== 1 || report.profile !== 'trusted-local-foreground-v1' || report.authoritative_check !== false ||
      report.shell !== '/bin/sh' || JSON.stringify(report.shell_flags) !== JSON.stringify(['-eu', '-c']) ||
      report.environment?.PATH !== '/usr/bin:/bin' || report.environment?.LANG !== 'C' ||
      Object.keys(report.environment).length !== 2 || !Array.isArray(report.jobs) || !report.jobs.length || report.jobs.length > 128) fail('Unsupported native execution report.');
  bounded(report.workflow_source, 256, 'workflow commitment');
  if (report.workflow_graph !== `alg:2:${graph}`) fail('Native execution changed the selected workflow graph.');
  number(report.run_timeout_millis, 1, plan.run_timeout_ms); number(report.step_timeout_millis, 1, report.run_timeout_millis);
  number(report.stream_bytes, 1, 2 * 1024 * 1024); number(report.total_output_bytes, 2, plan.total_output_bytes);
  const ids = new Set(); let output = 0;
  for (const job of report.jobs) {
    object(job); bounded(job.id, 1024, 'workflow job');
    if (ids.has(job.id) || !['succeeded', 'failed', 'skipped', 'cancelled', 'timed_out', 'output_limit', 'refused'].includes(job.outcome) ||
        !Array.isArray(job.steps) || job.steps.length > 512 || ++totals.jobs > 128) fail('Invalid native job report or aggregate job bound.');
    ids.add(job.id);
    // A skipped job did not execute, and neither successful nor skipped jobs
    // may conceal a failed close. These are also native completion conditions.
    if ((job.outcome === 'skipped' && (job.steps.length !== 0 || job.failure !== null)) ||
        (job.outcome === 'succeeded' && job.failure !== null)) fail('Contradictory native job completion.');
    if (job.failure !== null) {
      object(job.failure);
      if (job.failure.workspace_retained !== false || typeof job.failure.detail !== 'string' || Buffer.byteLength(job.failure.detail) > 4096) fail('Native job containment remains unproved.');
    }
    let previous = -1;
    for (const step of job.steps) {
      object(step); number(step.index, previous + 1, 511); previous = step.index;
      if (++totals.steps > 512 || !['succeeded', 'failed', 'cancelled', 'timed_out', 'output_limit', 'containment_failure'].includes(step.outcome) ||
          step.workspace_retained !== false || step.outcome === 'containment_failure') fail('Native step containment remains unproved.');
      if (step.name !== null && (typeof step.name !== 'string' || Buffer.byteLength(step.name) > 4096)) fail('Invalid native step name.');
      bounded(step.script, 256, 'script commitment'); number(step.elapsed_millis, 0, Number.MAX_SAFE_INTEGER);
      if (step.exit_code !== null) number(step.exit_code, -2147483648, 2147483647);
      if (typeof step.output_complete !== 'boolean' || (step.outcome === 'succeeded' && (step.exit_code !== 0 || !step.output_complete)) ||
          (job.outcome === 'succeeded' && step.outcome !== 'succeeded')) fail('Contradictory native step success.');
      for (const field of ['stdout_hex', 'stderr_hex']) {
        const value = step[field];
        if (typeof value !== 'string' || value.length > report.stream_bytes * 2 || !/^(?:[0-9a-f]{2})*$/.test(value)) fail('Invalid bounded native output bytes.');
        output += value.length / 2; totals.output += value.length / 2;
        if (output > report.total_output_bytes || totals.output > plan.total_output_bytes) fail('Native aggregate output bound exceeded.');
      }
    }
  }
  // WorkflowReport's legacy evidence bit still means EVERY job succeeded.
  // Since 41102c6, the node's whole-run bit also permits genuinely unexecuted
  // conditional skips. Neither encoding carries a new version: accept exactly
  // those two meanings, never normalize saved reports or recalculate old keys.
  // The checks above already require successful steps, no failed closes and
  // closed workspaces for both forms; interruption cannot be a successful run.
  const succeeded = report.jobs.every(job => job.outcome === 'succeeded');
  const legacy = !run.request_interrupted && succeeded;
  const completed = !run.request_interrupted && report.jobs.some(job => job.outcome === 'succeeded') &&
    report.jobs.every(job => job.outcome === 'succeeded' || job.outcome === 'skipped');
  if (report.succeeded !== succeeded || (run.succeeded !== legacy && run.succeeded !== completed)) {
    fail('Native execution success disagrees with completed jobs.');
  }
}
// Validate exact native scope and completion, not scripts, signatures or CI authority.
export function dispatchReport(config, intent, report) {
  object(report); const plan = object(report.plan), locations = paths(config, intent);
  if (report.type !== 'trusted_workflow_dispatch' || plan.type !== 'trusted_workflow_dispatch_plan' || plan.schema_version !== 1 ||
      plan.tenant_id !== config.tenant_id || plan.repository_id !== config.repository_id || plan.repository_incarnation !== config.repository_incarnation ||
      plan.object_format !== config.object_format || plan.source_head !== intent.source_head || oid(plan.source_commit, config.object_format) !== intent.commit ||
      plan.source_ref_hex !== config.ref_hex || plan.workflow_directory_hex !== config.workflow_directory_hex ||
      JSON.stringify(plan.read_prefixes_hex) !== JSON.stringify(config.input_prefixes_hex) || plan.event !== config.event ||
      plan.run_id !== intent.run_id || plan.run_directory_hex !== hex(locations.batch) || plan.trigger_provenance !== 'explicit_local_operator' ||
      ['authoritative_check', 'hostile_code_isolated', 'published', 'execution_retried'].some(key => plan[key] !== false)) fail('Native dispatch changed the retained source, scope or execution profile.');
  oid(plan.source_tree, config.object_format); bounded(plan.source_rcr, 256, 'source record');
  number(plan.run_timeout_ms, 1, 600_000); number(plan.total_output_bytes, 2, 16 * 1024 * 1024);
  if (!Array.isArray(plan.workflows) || plan.workflows.length > 32 || !Array.isArray(report.runs) || report.runs.length > 32 ||
      typeof report.succeeded !== 'boolean') fail('Invalid native dispatch manifest.');
  let previous = ''; const selected = [];
  for (const definition of plan.workflows) {
    pathBytes(definition.path_hex); oid(definition.blob, config.object_format);
    const prefix = `${config.workflow_directory_hex}2f`, suffix = definition.path_hex.slice(prefix.length);
    if (!definition.path_hex.startsWith(prefix) || bytes(suffix).includes(47) ||
        !(suffix.endsWith('2e796d6c') || suffix.endsWith('2e79616d6c')) || definition.path_hex <= previous ||
        typeof definition.selected !== 'boolean' || !/^[0-9a-f]{64}$/.test(definition.graph_sha256) ||
        definition.run_id !== childId(intent.run_id, config.event, definition.path_hex)) fail('Native workflow selection identity changed.');
    previous = definition.path_hex;
    if (definition.selected) selected.push(definition);
  }
  if (report.matched_count !== selected.length || report.executed_count !== report.runs.length || report.runs.length > selected.length) fail('Native dispatch counts disagree.');
  // Native stopped reports distinguish intentionally unstarted children from
  // ambiguous execution. Only known stop reasons plus closed workspaces settle
  // this batch. Containment-unproved or missing reports still block all work.
  const stopped = SETTLED_STOPS.includes(report.stop_reason);
  if ((report.stop_reason !== null && !stopped) || (!stopped && report.runs.length !== selected.length)) fail('Native dispatch stopped or is incomplete; inspect original child journals, do not replay.');
  const totals = { jobs: 0, steps: 0, output: 0 };
  for (let i = 0; i < report.runs.length; i++) {
    const run = object(report.runs[i]), definition = selected[i];
    if (run.type !== 'trusted_workflow_run' || run.schema_version !== 1 ||
        ['tenant_id', 'repository_id', 'repository_incarnation', 'source_head', 'source_rcr', 'object_format', 'source_ref_hex', 'source_tree'].some(key => run[key] !== plan[key]) ||
        oid(run.source_commit, config.object_format) !== intent.commit || oid(run.executed_commit, config.object_format) !== intent.commit ||
        run.executed_tree !== plan.source_tree || run.workflow_blob !== definition.blob || run.workflow_path_hex !== definition.path_hex ||
        run.run_id !== definition.run_id || run.run_directory_hex !== hex(join(locations.batch, `workflow-${definition.run_id}`)) ||
        JSON.stringify(run.read_prefixes_hex) !== JSON.stringify(plan.read_prefixes_hex) || run.candidate !== null || run.merge !== null ||
        run.input_kind !== 'canonical' || run.workspaces_closed !== true || typeof run.request_interrupted !== 'boolean' || (!stopped && run.request_interrupted) ||
        ['authoritative_check', 'hostile_code_isolated', 'published'].some(key => run[key] !== false) || typeof run.succeeded !== 'boolean') fail('Native child report changed identity or did not finish cleanup.');
    executionReport(run, plan, totals, definition.graph_sha256);
  }
  if (report.succeeded !== (!stopped && report.runs.every(run => run.succeeded))) fail('Native aggregate success disagrees with child observations.');
  return { schema: 'frankengit-workflow-watch-result-v1', intent_sha256: digest(encode(intent)),
    report_sha256: digest(encode(report)), outcome: stopped ? 'observed_stopped' : !selected.length ? 'no_matching_workflows' : report.succeeded ? 'observed_succeeded' : 'observed_failed',
    matched_count: selected.length, executed_count: report.runs.length, authoritative_check: false, ...(stopped ? { stop_reason: report.stop_reason } : {}) };
}
async function reconcileOne(config, record) {
  const location = paths(config, record.intent);
  if (!record.started) return false;
  await directory(location.batch);
  const raw = await readPrivate(join(location.batch, 'report.json'), 40 * 1024 * 1024, true);
  if (!raw) return false;
  const result = dispatchReport(config, record.intent, parseJson(raw, 40 * 1024 * 1024));
  await identicalOrNew(location.result, result); record.result = result;
  return true;
}
export async function status(config) {
  config = configuration(config);
  await preflight(config, 'status');
  const records = await inventory(config);
  const owner = await lstat(join(config.state_directory, 'owner.lock')).then(() => true, error => { if (error.code === 'ENOENT') return false; throw error; });
  return { type: 'workflow_watch_status', schema_version: 1, owner_present: owner, read_only: true,
    records: records.map(record => ({ id: record.intent.id, commit: record.intent.commit, run_id: record.intent.run_id,
      state: record.result?.outcome ?? (record.started ? 'execution_unknown' : 'queued'),
      ...(record.result?.stop_reason ? { stop_reason: record.result.stop_reason, unstarted_workflows: record.result.matched_count - record.result.executed_count } : {}), native_directory: paths(config, record.intent).batch })) };
}
export async function reconcile(config) {
  config = configuration(config);
  await preflight(config, 'reconcile');
  const records = await inventory(config);
  if (records.filter(record => !record.result).length > 1) fail('Multiple unresolved execution records require inspection.');
  for (const record of records) if (!record.result && record.started) {
    // Missing native evidence is never permission to run a second time.
    try { await reconcileOne(config, record); } catch (error) { if (error.code === 'ENOENT') continue; throw error; }
  }
  return status(config);
}
function checkpoint(signal) {
  try { signal?.throwIfAborted(); } catch (error) { error.phase = 'before_execution'; throw error; }
}
async function execute(config, intent, options) {
  const location = paths(config, intent);
  checkpoint(options.signal);
  await identicalOrNew(location.started, { schema: 'frankengit-workflow-watch-start-v1', intent_sha256: digest(encode(intent)) });
  const args = ['workflow', 'dispatch', config.storage_root, config.tenant_id, config.repository_id, config.ref_hex,
    '--trusted-local', '--ref-hex', '--event', config.event, '--workflow-hex', config.workflow_directory_hex,
    '--run-parent', config.run_parent, '--run-id', intent.run_id, '--expected-head', intent.snapshot_token,
    '--expected-commit', intent.commit, '--expected-incarnation', config.repository_incarnation, '--object-format', config.object_format];
  for (const prefix of config.input_prefixes_hex) args.push('--input-hex', prefix);
  // Abort after the synced start marker must leave an uncertain record, not an
  // invented rollback. No caller-provided command or shell is accepted here.
  const native = await runNative(config.fg, args, { signal: options.signal, drain: true, timeoutMs: options.dispatchTimeoutMs ?? 660_000 });
  if (native.forced) throw nativeFailure(native, 'Native containment was not established');
  const record = { intent, started: true };
  if (!native.signal && !native.spawn_error && [0, 1].includes(native.code)) {
    const envelope = parseJson(native.stdout, 40 * 1024 * 1024);
    if (envelope.type !== 'workflow_dispatch_result' || envelope.schema_version !== 1 || envelope.node_closed !== true || envelope.node_cleanup_error !== null) fail('Native node finalization was not established.');
    const reported = dispatchReport(config, intent, envelope.dispatch);
    if (native.code !== (envelope.dispatch.succeeded ? 0 : 1)) fail('Native exit and dispatch observation disagree.');
    if (!await reconcileOne(config, record) || reported.report_sha256 !== record.result.report_sha256) fail('Saved native report differs from the returned dispatch.');
    return { type: 'workflow_watch_result', schema_version: 1, id: intent.id, commit: intent.commit, ...record.result, native_directory: location.batch };
  }
  // A missing stdout reply can be recovered without a second executable run.
  // Reconciliation is explicit so a cleanup failure is never silently ignored.
  throw nativeFailure(native, `Dispatch unresolved; inspect ${location.batch} and use reconcile`);
}
function executionOptions(options) {
  return { signal: options.signal, readTimeoutMs: number(options.readTimeoutMs ?? 30_000, 1, 30_000),
    dispatchTimeoutMs: number(options.dispatchTimeoutMs ?? 660_000, 1, 660_000) };
}
async function owned(config, work) {
  await preflight(config);
  const release = await lock(join(config.state_directory, 'owner.lock'));
  let containmentUnknown = false;
  try { return await work(); }
  catch (error) { containmentUnknown = error.containment_unknown === true; throw error; }
  finally { if (!containmentUnknown) await release(); }
}
async function sweep(config, options) {
  const records = await inventory(config, true), pending = records.filter(record => !record.result);
  for (const record of pending) {
    if (record.started) fail('An original execution is unresolved. Use status/reconcile; automatic replay is forbidden.');
  }
  if (pending.length > 1) fail('Multiple queued intents require inspection.');
  if (pending.length) return execute(config, pending[0].intent, options);
  checkpoint(options.signal);
  let selected;
  try { selected = await observe(config, options); }
  catch (error) { error.phase = 'observation'; throw error; }
  if (!selected) return { type: 'workflow_watch_idle', schema_version: 1, reason: 'branch_unavailable', authoritative_check: false };
  const intent = intentFor(config, selected), prior = records.find(record => record.intent.id === intent.id);
  if (prior) return { type: 'workflow_watch_idle', schema_version: 1, reason: 'commit_already_observed', commit: intent.commit, outcome: prior.result.outcome, authoritative_check: false };
  if (records.length >= config.max_runs) fail('Watcher run capacity reached; no history is evicted or replayed.');
  checkpoint(options.signal);
  await writeNew(paths(config, intent).intent, encode(intent));
  return execute(config, intent, options);
}
export async function once(config, options = {}) {
  config = configuration(config); options = executionOptions(options);
  return owned(config, () => sweep(config, options));
}

// One owner spans polling, execution and output. Only read-only observation
// failures are retried; a started execution is never resubmitted automatically.
export async function serve(config, options = {}) {
  config = configuration(config);
  const execution = executionOptions(options), signal = execution.signal;
  const pollMs = number(options.pollMs ?? 1000, 100, 60_000);
  const maxPolls = number(options.maxPolls ?? 1_000_000, 1, 1_000_000);
  const observer = options.onObservation ?? (() => {});
  if (typeof observer !== 'function') fail('Invalid watcher observation consumer.');
  const summary = { type: 'workflow_watch_service', schema_version: 1, polls: 0, runs: 0, failed_runs: 0,
    no_match_runs: 0, stopped_runs: 0, idle_polls: 0, read_failures: 0, stopped: false, poll_limit_reached: false,
    authoritative_check: false, execution_retried: false };
  return owned(config, async () => {
    let consecutiveReadFailures = 0;
    while (summary.polls < maxPolls && !signal?.aborted) {
      summary.polls++;
      let event;
      try {
        event = await sweep(config, execution); consecutiveReadFailures = 0;
        if (event.type === 'workflow_watch_idle') summary.idle_polls++;
        else {
          summary.runs++;
          if (event.outcome === 'observed_failed') summary.failed_runs++;
          if (event.outcome === 'no_matching_workflows') summary.no_match_runs++;
          if (event.outcome === 'observed_stopped') summary.stopped_runs++;
        }
      } catch (error) {
        if (signal?.aborted && ['observation', 'before_execution'].includes(error.phase) && !error.containment_unknown) break;
        if (error.phase !== 'observation' || error.containment_unknown) throw error;
        summary.read_failures++; consecutiveReadFailures++;
        if (consecutiveReadFailures >= 3) throw error;
        event = { type: 'workflow_watch_observation_unavailable', schema_version: 1,
          message: error.message, read_attempt: consecutiveReadFailures, execution_started: false,
          ...(error.native_stderr_hex ? { native_stderr_hex: error.native_stderr_hex } : {}) };
      }
      // An output failure is fatal, never a reason to retry the completed run.
      // Consumers must settle promptly; CLI output owns its own bounded deadline.
      try { await observer(structuredClone(event)); }
      catch (error) { error.retained_observation = event; throw error; }
      if (summary.polls >= maxPolls || signal?.aborted) break;
      try { await sleep(Math.min(60_000, pollMs * 2 ** consecutiveReadFailures), undefined, { signal }); }
      catch (error) { if (!signal?.aborted) throw error; }
    }
    summary.stopped = signal?.aborted === true;
    summary.poll_limit_reached = summary.polls === maxPolls;
    return summary;
  });
}
