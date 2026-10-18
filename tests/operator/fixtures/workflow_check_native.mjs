// Native-schema process peer, not fg or proof of native authorization/CAS.
import { readFile, writeFile, appendFile } from 'node:fs/promises';
import { join } from 'node:path';
import { createHash } from 'node:crypto';
const hash = bytes => createHash('sha256').update(bytes).digest('hex');
const read = async path => JSON.parse(await readFile(path, 'utf8'));
const save = (path, value) => writeFile(path, JSON.stringify(value), { mode: 0o600 });
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
export async function handle(args) {
  const mode = args[1];
  if (args[0] !== 'workflow' || !['recover', 'publish'].includes(mode)) return false;
  const get = key => args[args.indexOf(key) + 1];
  const directory = mode === 'recover' ? args[2] : get('--run-directory');
  const data = await read(join(directory, 'custody.json')), control = await read(join(data.store, 'control.json'));
  await appendFile(join(data.store, 'calls.ndjson'), `${JSON.stringify(args)}\n`, { mode: 0o600 });
  const actual = hash(await readFile(join(directory, 'attempt.json')));
  if (get('--journal-id') !== actual || actual !== data.history.scope.journal_id) {
    console.error('fixture original marker commitment changed'); process.exitCode = 2; return true;
  }
  if (mode === 'recover') {
    if (control.recovery_delay) await sleep(control.recovery_delay);
    if (control.recovery_fail) { console.error('fixture recovery read failed'); process.exitCode = 2; return true; }
    const all = data.history.entries, after = args.includes('--after-batch') ? get('--after-batch') : null;
    const start = after === null ? 0 : all.findIndex(entry => entry.batch_sha256 === after) + 1;
    const count = control.recovery_page_size ?? 128, entries = all.slice(start, start + count);
    const reply = { ...data.history, entries, next_after: start + count < all.length ? entries.at(-1).batch_sha256 : null,
      ...(after !== null ? control.second_history_patch : control.history_patch) };
    if (control.change_after_recovery) await save(join(data.store, 'control.json'), { ...control, ...control.change_after_recovery, change_after_recovery: null });
    console.log(JSON.stringify(reply)); return true;
  }
  if (args[2] !== data.store || args[3] !== data.history.scope.tenant || args[4] !== data.history.scope.repository ||
      args[5] !== data.ref_hex || get('--expected-incarnation') !== data.incarnation || get('--minimum-pin') !== data.history.snapshot ||
      !args.includes('--trusted-local') || !args.includes('--ref-hex')) throw new Error('fixture publication changed native selection');
  const entry = data.history.entries.find(entry => entry.batch_sha256 === get('--batch'));
  const fact = entry?.facts[Number(get('--fact-index'))];
  if (!fact || fact.status !== 'completed') throw new Error('fixture missing native fact');
  const key = get('--idempotency-key'), decisionPath = join(data.store, `decision-${hash(key)}.json`);
  let reply;
  try { reply = await read(decisionPath); }
  catch (error) {
    if (error.code !== 'ENOENT') throw error;
    const refused = control.refuse === true;
    reply = { type: 'workflow_check_publication', schema_version: 1, trusted_local: true,
      tenant_id: data.history.scope.tenant, repository_id: data.history.scope.repository, repository_incarnation: data.incarnation,
      principal_id: get('--principal-id'), object_format: entry.object_format, check_id: `check/${hash(key).slice(0, 51)}0`,
      job: fact.job, source_ref_hex: data.ref_hex, source_commit: entry.source_commit,
      run_id: entry.run_sha256, attempt_id: entry.attempt_sha256, graph_root: entry.workflow_graph_sha256,
      conclusion: data.conclusions[fact.job], journal_id: actual, batch_sha256: entry.batch_sha256, fact_index: Number(get('--fact-index')),
      evidence_sha256: fact.evidence_sha256, evidence_bytes: 64, evidence_payload_included: false,
      tx_id: `fixture-tx-${hash(key)}`, outcome: refused ? 'refused' : 'committed', decision_sequence: '18446744073709551615',
      command_committed: !refused, repository_commit_id: refused ? null : `fixture-rcr-${hash(key)}`,
      refusal_record_id: refused ? `fixture-refusal-${hash(key)}` : null, refusal_code: refused ? 'EvidenceStale' : null,
      scope: 'trusted_workflow_observations', merge_permission: null, authoritative_check: false, execution_retried: false,
      journal_acknowledged: false, refs_changed: false, historical_outcome: true, current_refs_asserted: false,
      delivery_acknowledged: null, node_closed: true, cleanup_error: null };
    await save(decisionPath, reply);
    await appendFile(join(data.store, 'published.ndjson'), `${JSON.stringify({ key, job: fact.job, outcome: reply.outcome })}\n`, { mode: 0o600 });
  }
  if (control.publish_delay) await sleep(control.publish_delay);
  if (control.drop_publication || control.drop_job === fact.job) { console.error('fixture reply lost after decision'); process.exitCode = 2; return true; }
  if (control.cleanup_failure) reply = { ...reply, node_closed: false, cleanup_error: 'fixture close failed after decision' };
  console.log(JSON.stringify({ ...reply, ...control.publication_patch }));
  process.exitCode = control.publish_exit ?? (reply.node_closed ? reply.outcome === 'committed' ? 0 : 3 : 2);
  return true;
}
