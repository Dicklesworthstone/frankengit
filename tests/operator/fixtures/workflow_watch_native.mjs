// Native-schema process peer. It is NOT fg, Rust execution or authority evidence.
import { readFile, writeFile, appendFile, mkdir } from 'node:fs/promises';
import { join } from 'node:path';
import { createHash } from 'node:crypto';
const args = process.argv.slice(2), dispatch = args[0] === 'workflow' && args[1] === 'dispatch';
const storage = args[dispatch ? 2 : 1];
const control = JSON.parse(await readFile(join(storage, 'control.json'), 'utf8'));
await appendFile(join(storage, 'calls.ndjson'), `${JSON.stringify(args)}\n`, { mode: 0o600 });
const get = key => args[args.indexOf(key) + 1];
const hash = value => createHash('sha256').update(value).digest('hex');
const hex = value => Buffer.from(value).toString('hex');
const json = (path, value) => writeFile(path, `${JSON.stringify(value)}\n`, { mode: 0o600 });
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
if (!dispatch) {
  if (args[0] !== 'refs') throw new Error('unexpected fixture command');
  if (control.read_delay) await sleep(control.read_delay);
  if (control.read_fail) { console.error('fixture read refusal'); process.exit(2); }
  const all = control.references ?? [{ reference_hex: control.ref_hex, tip: `${control.format}:${control.commit}` }];
  const cursor = args.includes('--after-hex') ? get('--after-hex') : '';
  const remaining = all.filter(row => row.reference_hex > cursor), rows = remaining.slice(0, 100);
  const value = { type: 'reference_page', schema_version: 1, tenant_id: control.tenant, repository_id: control.repository,
    object_format: control.format, source_head: control.source_head, snapshot_token: control.snapshot,
    references: rows, next_after_hex: remaining.length > 100 ? rows.at(-1).reference_hex : null,
    has_more: remaining.length > 100, node_closed: true, ...(cursor ? control.later_page_patch : control.page_patch) };
  if (control.change_after_read) await json(join(storage, 'control.json'), { ...control, ...control.change_after_read, change_after_read: null });
  console.log(JSON.stringify(value));
} else {
  if (get('--expected-head') !== control.snapshot || get('--expected-commit') !== control.commit ||
      get('--expected-incarnation') !== control.incarnation || get('--object-format') !== control.format || args[5] !== control.ref_hex) {
    console.error('fixture native source pin refusal before batch creation'); process.exit(2);
  }
  const batchId = get('--run-id'), batch = join(get('--run-parent'), `dispatch-${batchId}`);
  try { await mkdir(batch, { mode: 0o700 }); }
  catch { console.error('fixture occupied batch refuses execution'); process.exit(2); }
  const path = `${get('--workflow-hex')}2f63692e796d6c`, event = get('--event');
  const frame = value => { const length = Buffer.alloc(8); length.writeBigUInt64BE(BigInt(value.length)); return Buffer.concat([length, value]); };
  const runId = hash(Buffer.concat([Buffer.from('frankengit/workflow-dispatch-child/v1\0'), Buffer.from(batchId, 'hex'), frame(Buffer.from(event)), frame(Buffer.from(path, 'hex'))])).slice(0, 32);
  const oid = char => `${control.format}:${char.repeat(control.format === 'sha1' ? 40 : 64)}`;
  const prefixes = args.flatMap((value, index) => value === '--input-hex' ? [args[index + 1]] : []);
  // Fixture-only reconstruction of the native JSON contract from actual argv.
  // No artifact is stored, copied or executed by this schema peer.
  let artifactContract;
  if (args.includes('--artifact-root')) {
    const values = flag => args.flatMap((value, index) => value === flag ? [args[index + 1]] : []);
    artifactContract = { schema_version: 1, root_hex: hex(get('--artifact-root')), trust_domain: 'trusted-workflow-local-owner',
      maximum_file_bytes: Number(get('--max-artifact-mib')) * 1048576,
      total_payload_bytes: Number(get('--max-artifact-total-mib')) * 1048576, retention_ttl_seconds: 86400,
      selections: values('--artifact-hex').map(value => {
        const [workflow_path_hex, job, output_path_hex] = value.split(':');
        return { workflow_path_hex, job_id_hex: hex(job), output_path_hex };
      }) };
    const inputs = values('--artifact-input-hex');
    if (inputs.length) artifactContract.input_delivery = { schema_version: 1, namespace_hex: hex('.fgit-artifacts'),
      total_delivery_bytes: Number(get('--max-artifact-input-total-mib')) * 1048576,
      selections: inputs.map(value => {
        const [workflow_path_hex, consumer, producer, output_path_hex, destination_hex] = value.split(':');
        return { workflow_path_hex, consumer_job_id_hex: hex(consumer), producer_job_id_hex: hex(producer), output_path_hex, destination_hex };
      }) };
  }
  const selected = !control.no_match;
  const definition = { path_hex: path, blob: oid('b'), graph_sha256: 'c'.repeat(64), run_id: runId, selected };
  const plan = { type: 'trusted_workflow_dispatch_plan', schema_version: 1, tenant_id: control.tenant, repository_id: control.repository,
    repository_incarnation: control.incarnation, source_head: control.source_head, source_rcr: 'fixture-rcr',
    source_commit: `${control.format}:${control.commit}`, source_tree: oid('d'), object_format: control.format,
    source_ref_hex: control.ref_hex, workflow_directory_hex: get('--workflow-hex'), read_prefixes_hex: prefixes, event,
    trigger_provenance: 'explicit_local_operator', run_id: batchId, run_directory_hex: hex(batch), authoritative_check: false,
    hostile_code_isolated: false, published: false, execution_retried: false, run_timeout_ms: 600000, total_output_bytes: 16777216,
    ...(artifactContract ? { artifact_contract: artifactContract } : {}), workflows: [definition] };
  await json(join(batch, 'dispatch.json'), plan);
  await appendFile(join(storage, 'effects.ndjson'), `${JSON.stringify({ run: batchId, commit: control.commit })}\n`, { mode: 0o600 });
  if (control.dispatch_delay) await sleep(control.dispatch_delay);
  if (control.no_report) { console.error('fixture interrupted after execution marker'); process.exit(2); }
  // Deliberately synthetic observations with the actual native receipt shape.
  // Contract-only echoes cannot stand in for producer/consumer completion.
  const artifactJobs = [], artifactReceipts = [], inputReceipts = [];
  if (artifactContract) {
    const captures = artifactContract.selections.filter(row => row.workflow_path_hex === path);
    const inputs = (artifactContract.input_delivery?.selections ?? []).filter(row => row.workflow_path_hex === path);
    const ids = [...new Set([...captures.map(row => row.job_id_hex), ...inputs.map(row => row.consumer_job_id_hex)])].sort();
    const finished = new Map();
    while (finished.size < ids.length) {
      const ready = ids.find(id => !finished.has(id) && inputs.filter(row => row.consumer_job_id_hex === id)
        .every(row => finished.has(row.producer_job_id_hex)));
      if (!ready) throw new Error('cyclic or absent fixture artifact producer');
      const incoming = inputs.filter(row => row.consumer_job_id_hex === ready);
      const skipped = incoming.some(row => finished.get(row.producer_job_id_hex) !== 'succeeded');
      const outcome = skipped ? 'skipped' : control.job_failure ? 'failed' : 'succeeded';
      artifactJobs.push({ id: Buffer.from(ready, 'hex').toString(), outcome, failure: null,
        steps: skipped ? [] : [{ index: 0, name: null, script: 'alg:2:' + 'f'.repeat(64), outcome,
          exit_code: control.job_failure ? 1 : 0, stdout_hex: '', stderr_hex: '', elapsed_millis: 1,
          output_complete: true, workspace_retained: false, ...control.step_patch }] });
      if (!skipped) {
        if (incoming.length) inputReceipts.push({ job_id_hex: ready, workspace_plan_sha256: hash(`fixture-workspace:${runId}:${ready}`),
          inputs: incoming.map(row => {
            const producer = artifactReceipts.find(receipt => receipt.job_id_hex === row.producer_job_id_hex);
            return { producer_job_id_hex: row.producer_job_id_hex, producer_manifest_id_sha256: producer.manifest_id_sha256,
              output: { ...producer.outputs.find(output => output.path_hex === row.output_path_hex) },
              destination_path_hex: hex('.fgit-artifacts/') + row.destination_hex };
          }) });
        const selectedOutputs = captures.filter(row => row.job_id_hex === ready);
        if (selectedOutputs.length) artifactReceipts.push({ job_id_hex: ready, manifest_id_sha256: hash(`fixture-manifest:${runId}:${ready}`),
          outputs: selectedOutputs.map(row => ({ path_hex: row.output_path_hex, artifact_id_sha256: hash(`fixture-artifact:${runId}:${ready}:${row.output_path_hex}`),
            payload_sha256: hash('x'), payload_bytes: 1, executable: false })) });
      }
      finished.set(ready, outcome);
    }
  }
  const run = { type: 'trusted_workflow_run', schema_version: 1, tenant_id: control.tenant, repository_id: control.repository,
    repository_incarnation: control.incarnation, source_head: control.source_head, source_rcr: 'fixture-rcr', source_commit: plan.source_commit,
    source_tree: plan.source_tree, object_format: control.format, source_ref_hex: control.ref_hex, workflow_blob: definition.blob,
    workflow_path_hex: path, read_prefixes_hex: prefixes, run_id: runId, run_directory_hex: hex(join(batch, `workflow-${runId}`)),
    authoritative_check: false, hostile_code_isolated: false, published: false, input_kind: 'canonical', executed_commit: plan.source_commit,
    executed_tree: plan.source_tree, candidate: null, merge: null, succeeded: !control.job_failure, workspaces_closed: true,
    request_interrupted: false, ...(artifactContract ? { artifact_contract: artifactContract, artifacts: artifactReceipts,
      ...(artifactContract.input_delivery ? { artifact_inputs: inputReceipts } : {}) } : {}),
    execution: { schema_version: 1, profile: 'trusted-local-foreground-v1', authoritative_check: false,
      workflow_source: 'alg:2:' + 'b'.repeat(64), workflow_graph: 'alg:2:' + 'c'.repeat(64),
      shell: '/bin/sh', shell_flags: ['-eu', '-c'], environment: { PATH: '/usr/bin:/bin', LANG: 'C' },
      step_timeout_millis: 60000, run_timeout_millis: 600000, stream_bytes: 262144, total_output_bytes: 16777216,
      succeeded: !control.job_failure, jobs: artifactContract ? artifactJobs : [{ id: 'fixture-job', outcome: control.job_failure ? 'failed' : 'succeeded', failure: null,
        steps: [{ index: 0, name: null, script: 'alg:2:' + 'f'.repeat(64), outcome: control.job_failure ? 'failed' : 'succeeded',
          exit_code: control.job_failure ? 1 : 0, stdout_hex: '', stderr_hex: '', elapsed_millis: 1, output_complete: true, workspace_retained: false, ...control.step_patch }] }],
      ...control.execution_patch }, ...control.run_patch };
  if (selected) await mkdir(join(batch, `workflow-${runId}`), { mode: 0o700 });
  const report = { type: 'trusted_workflow_dispatch', plan: { ...plan, ...control.plan_patch }, matched_count: Number(selected), executed_count: Number(selected),
    succeeded: !selected || !control.job_failure, stop_reason: null, runs: selected ? [run] : [], ...control.report_patch };
  await json(join(batch, 'report.json'), report);
  if (control.drop_stdout) { console.error('fixture output lost after saved report'); process.exit(2); }
  console.log(JSON.stringify({ type: 'workflow_dispatch_result', schema_version: 1, node_closed: true, node_cleanup_error: null,
    dispatch: control.stdout_patch ? { ...report, ...control.stdout_patch } : report }));
  process.exitCode = control.exit_code ?? (report.succeeded ? 0 : 1);
}
