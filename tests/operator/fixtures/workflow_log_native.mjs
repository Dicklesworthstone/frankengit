// Explicit native-schema peer for operator tests. No Git, workflow script,
// artifact store or canonical publication runs in this fixture.
import { createHash } from 'node:crypto';
import { readFile, writeFile, appendFile, mkdir } from 'node:fs/promises';
import { dirname, join } from 'node:path';

export const hex = value => Buffer.from(value).toString('hex');
export const sha256 = value => createHash('sha256').update(value).digest('hex');
export const encode = value => Buffer.from(`${JSON.stringify(value)}\n`);
export function watchConfig(root, format = 'sha1', event = 'push') {
  return { schema: 'frankengit-workflow-watch-v1', fg: join(root, 'fg'), storage_root: join(root, 'store'),
    tenant_id: '1'.repeat(32), repository_id: '2'.repeat(32), repository_incarnation: '3'.repeat(32), object_format: format,
    ref_hex: hex('refs/heads/main'), workflow_directory_hex: hex('ci'), input_prefixes_hex: [hex('ci'), hex('src')],
    event, state_directory: join(root, 'state'), run_parent: join(root, 'runs'), max_runs: 16,
    trust: 'selected-branch-host-execution', artifacts: { root: join(root, 'artifacts'), selections: [], capture_logs: true } };
}
export function intentFor(config) {
  const configuration_sha256 = sha256(encode(config)), commit = 'a'.repeat(config.object_format === 'sha1' ? 40 : 64);
  const id = sha256(Buffer.from(`frankengit/workflow-watch-observed-commit/v1\0${configuration_sha256}\0${commit}`));
  return { schema: 'frankengit-workflow-watch-intent-v1', id, configuration_sha256, run_id: id.slice(0, 32),
    snapshot_token: `alg:2:${'4'.repeat(64)}`, source_head: 'fixture-head', commit,
    trigger_provenance: 'observed_branch_tip_not_push_event' };
}
export function nativeReport(config, intent, options = {}) {
  const outcome = options.outcome ?? 'succeeded', stopped = options.stopped ?? false, width = config.object_format === 'sha1' ? 40 : 64;
  const oid = byte => `${config.object_format}:${byte.repeat(width)}`, workflow = hex('ci/build.yml');
  const frame = part => { const prefix = Buffer.alloc(8); prefix.writeBigUInt64BE(BigInt(part.length)); return Buffer.concat([prefix, part]); };
  const child = sha256(Buffer.concat([Buffer.from('frankengit/workflow-dispatch-child/v1\0'), Buffer.from(intent.run_id, 'hex'),
    frame(Buffer.from(config.event)), frame(Buffer.from(workflow, 'hex'))])).slice(0, 32);
  const batch = join(config.run_parent, `dispatch-${intent.run_id}`), childDirectory = join(batch, `workflow-${child}`);
  const a = config.artifacts;
  const contract = { schema_version: 1, root_hex: hex(a.root), trust_domain: 'trusted-workflow-local-owner',
    maximum_file_bytes: a.maximum_file_mib * 1048576, total_payload_bytes: a.total_payload_mib * 1048576, retention_ttl_seconds: 86400,
    selections: a.selections.map(s => ({ workflow_path_hex: s.workflow_path_hex, job_id_hex: hex(s.job_id), output_path_hex: s.output_path_hex })),
    ...(a.capture_logs ? { log_capture: { schema_version: 1, streams: ['stdout', 'stderr'] } } : {}) };
  const source = { tenant_id: config.tenant_id, repository_id: config.repository_id, repository_incarnation: config.repository_incarnation,
    object_format: config.object_format, source_head: intent.source_head, source_rcr: `alg:2:${'5'.repeat(64)}`,
    source_commit: oid('a'), source_tree: oid('b'), source_ref_hex: config.ref_hex, read_prefixes_hex: config.input_prefixes_hex };
  const plan = { type: 'trusted_workflow_dispatch_plan', schema_version: 1, ...source, workflow_directory_hex: config.workflow_directory_hex,
    event: config.event, run_id: intent.run_id, run_directory_hex: hex(batch), trigger_provenance: 'explicit_local_operator',
    authoritative_check: false, hostile_code_isolated: false, published: false, execution_retried: false,
    artifact_contract: structuredClone(contract), run_timeout_ms: 600000, total_output_bytes: 16 * 1048576,
    workflows: [{ path_hex: workflow, blob: oid('c'), graph_sha256: '6'.repeat(64), selected: true, run_id: child }] };
  const step = { index: 2, name: 'binary: λ', script: `alg:2:${'7'.repeat(64)}`, outcome,
    exit_code: outcome === 'succeeded' ? 0 : outcome === 'failed' ? 7 : null, elapsed_millis: 1,
    output_complete: ['succeeded', 'failed'].includes(outcome), workspace_retained: false, stdout_hex: '00ff800a', stderr_hex: '' };
  const job = { id: 'build', outcome, failure: null, steps: [step] };
  const execution = { schema_version: 1, profile: 'trusted-local-foreground-v1', authoritative_check: false,
    shell: '/bin/sh', shell_flags: ['-eu', '-c'], environment: { PATH: '/usr/bin:/bin', LANG: 'C' },
    workflow_source: `alg:2:${'8'.repeat(64)}`, workflow_graph: `alg:2:${'6'.repeat(64)}`,
    step_timeout_millis: 30000, run_timeout_millis: 600000, stream_bytes: 262144, total_output_bytes: 16 * 1048576,
    succeeded: outcome === 'succeeded', jobs: [job] };
  const artifacts = a.selections.length ? [{ job_id_hex: hex('build'), manifest_id_sha256: sha256('file-manifest'),
    outputs: a.selections.map(s => ({ path_hex: s.output_path_hex, artifact_id_sha256: sha256('file-id'),
      payload_sha256: sha256('file'), payload_bytes: 4, executable: false })) }] : [];
  const logs = [{ job_id_hex: hex(job.id), manifest_id_sha256: sha256('log-manifest'), observed_job_outcome: outcome,
    logs: ['stdout', 'stderr'].map(stream => ({ step_index: step.index, step_name_hex: hex(step.name), script_sha256: '7'.repeat(64),
      stream, observed_step_outcome: step.outcome, exit_code: step.exit_code, output_complete: step.output_complete,
      artifact_id_sha256: sha256(`log:${stream}`), payload_sha256: sha256(Buffer.from(step[`${stream}_hex`], 'hex')),
      payload_bytes: step[`${stream}_hex`].length / 2 })) }];
  const run = { type: 'trusted_workflow_run', schema_version: 1, ...source, executed_commit: oid('a'), executed_tree: oid('b'),
    workflow_blob: oid('c'), workflow_path_hex: workflow, run_id: child, run_directory_hex: hex(childDirectory), input_kind: 'canonical',
    candidate: null, merge: null, workspaces_closed: true, request_interrupted: stopped,
    authoritative_check: false, hostile_code_isolated: false, published: false, succeeded: !stopped && outcome === 'succeeded',
    artifact_contract: structuredClone(contract), execution, artifacts, ...(a.capture_logs ? { artifact_logs: logs } : {}) };
  const report = { type: 'trusted_workflow_dispatch', plan, runs: [run], matched_count: 1, executed_count: 1,
    succeeded: !stopped && run.succeeded, stop_reason: stopped ? 'request_stopped' : null };
  return { report, batch, childDirectory };
}
export function attemptMarker(run) {
  const marker = { type: 'trusted_workflow_attempt', state: 'started' };
  for (const [key, value] of Object.entries(run)) {
    if (!['type', 'succeeded', 'workspaces_closed', 'request_interrupted', 'execution', 'artifacts', 'artifact_inputs', 'artifact_logs'].includes(key)) {
      marker[key] = structuredClone(value);
    }
  }
  marker.execution_plan = { ...structuredClone(run.execution), jobs: [], succeeded: false };
  return marker;
}

export async function runPeer(args) {
  const root = dirname(process.argv[1]), control = JSON.parse(await readFile(join(root, 'control.json'))), config = control.config;
  await appendFile(join(root, 'calls.ndjson'), encode(args));
  const intent = intentFor(config);
  if (args[0] === 'refs') {
    process.stdout.write(encode({ type: 'reference_page', schema_version: 1, node_closed: true,
      tenant_id: config.tenant_id, repository_id: config.repository_id, object_format: config.object_format,
      snapshot_token: intent.snapshot_token, source_head: intent.source_head, has_more: false, next_after_hex: null,
      references: [{ reference_hex: config.ref_hex, tip: `${config.object_format}:${intent.commit}` }] }));
    return;
  }
  if (args[0] !== 'workflow' || args[1] !== 'dispatch') throw new Error('Unexpected fixture command.');
  const get = key => args[args.indexOf(key) + 1];
  if (get('--run-id') !== intent.run_id || get('--expected-head') !== intent.snapshot_token || get('--expected-commit') !== intent.commit ||
      get('--artifact-root') !== config.artifacts.root || args.includes('--artifact-logs') !== (config.artifacts.capture_logs === true)) {
    throw new Error('Fixture dispatch changed pinned arguments or log opt-in.');
  }
  const { report, batch, childDirectory } = nativeReport(config, intent, control);
  await mkdir(batch, { mode: 0o700 }); await mkdir(childDirectory, { mode: 0o700 });
  await writeFile(join(childDirectory, 'attempt.json'), encode(attemptMarker(report.runs[0])), { mode: 0o600, flag: 'wx' });
  if (control.corrupt_log) report.runs[0].artifact_logs[0].logs[0].payload_sha256 = sha256('substituted');
  await appendFile(join(root, 'dispatches.ndjson'), encode({ id: intent.id }));
  await writeFile(join(batch, 'report.json'), encode(report), { mode: 0o600, flag: 'wx' });
  if (control.drop_reply) { process.exitCode = 2; return; }
  process.stdout.write(encode({ type: 'workflow_dispatch_result', schema_version: 1, node_closed: true, node_cleanup_error: null, dispatch: report }));
  process.exitCode = report.succeeded ? 0 : 1;
}
