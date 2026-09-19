// Synthetic HTTP replies only; native Rust admission is NOT exercised here.
import { webcrypto } from 'node:crypto';
import { utf8, hex } from '../../crates/fgit-node/src/smart_http/server/browser/pulls-core.mjs';
import { digest, joinBytes } from '../../crates/fgit-node/src/smart_http/server/browser/pulls-candidate.mjs';
import { initialPlan } from '../../crates/fgit-node/src/smart_http/server/browser/initial-plan.mjs';
export const crypto = webcrypto, token = '7'.repeat(64), actor = '9'.repeat(32);
export const href = 'http://127.0.0.1:9418/repo.git/ui/initial/';
export const metadata = { author: 'Alice <a@example.invalid>', committer: 'Builder <b@example.invalid>', timestamp: 1, message: 'First commit\r\n' };
export const file = (name = 'README.md', content = 'First file\r\n', mode = 0o100644) => ({ path_hex: hex(utf8.encode(name)), bytes: utf8.encode(content), mode });
export const fields = algorithm => ({ ref: 'refs/heads/main', object_format: algorithm, expected_absent: true });
export function json(value, status = 200) { return new Response(JSON.stringify(value), { status, headers: { 'Content-Type': 'application/json' } }); }
export function envelope(value, bundle, sha) {
  const b = `fg-initial-${sha.slice(0, 48)}-0`;
  return { status: 200, type: `multipart/mixed; boundary=${b}`, value: joinBytes(utf8.encode(
    `--${b}\r\nContent-Type: application/json; charset=utf-8\r\nContent-Disposition: inline; name="metadata"\r\n\r\n${JSON.stringify(value)}\r\n--${b}\r\nContent-Type: application/x-git-bundle\r\nContent-Disposition: attachment; name="bundle"; filename="initial.bundle"\r\n\r\n`), bundle, utf8.encode(`\r\n--${b}--\r\n`)) };
}
export async function fixture(algorithm = 'sha1', files = [file()]) {
  const plan = await initialPlan(files, metadata, algorithm, crypto), scope = { tenant: '1'.repeat(32), repository: '2'.repeat(32), incarnation: '3'.repeat(32), format: algorithm };
  const common = { schema_version: 1, tenant_id: scope.tenant, repository_id: scope.repository, repository_incarnation: scope.incarnation, object_format: algorithm };
  const bundle = utf8.encode('# synthetic initial bundle fixture\nPACK\n'), sha = await digest(bundle, crypto);
  const prepared = { ...common, type: 'initial_source_preparation', ref: fields(algorithm).ref, ref_hex: hex(utf8.encode(fields(algorithm).ref)),
    source_head: 'head-1', snapshot_token: `alg:1:${'4'.repeat(64)}`, expected_absent: true, parents: [], prerequisites: [],
    candidate_commit: plan.commit, root_tree: plan.tree, patch_sha256: plan.patchSha256, object_count: plan.objectCount,
    read_only: true, objects_staged: false, transaction_created: false, published: false, publication_authorized: false, default_branch_changed: false,
    bundle: { bytes: bundle.length, sha256: sha }, candidate_commit_body_hex: hex(plan.commitBody), files: plan.files };
  const terminal = { ...common, type: 'initial_source_publication', principal_id: actor, ref: prepared.ref, ref_hex: prepared.ref_hex,
    expected_absent: true, candidate_commit: plan.commit, tx_id: 'tx-original', decision_sequence: 1, outcome: 'committed',
    decision: { repository_commit_id: 'rcr-first' }, atomic: true, terminal: true, receipt_confirms_transport_revalidation: false, default_branch_changed: false };
  const config = { prepare: null, publish: null, lose: false, refused: false, status: null, outcome: 'key_not_observed', recover: null }, calls = [];
  const fetchImpl = async (url, options) => {
    const endpoint = new URL(url).pathname.split('/api/v1/')[1];
    calls.push({ endpoint, body: options.body?.slice?.() ?? options.body, headers: Object.fromEntries(new Headers(options.headers)), options });
    if (endpoint === 'source/initial/prepare') {
      const value = structuredClone(prepared); await config.prepare?.(value);
      const r = envelope(value, bundle, sha); return new Response(r.value, { status: r.status, headers: { 'Content-Type': r.type } });
    }
    if (endpoint === 'source/initial/apply') {
      if (config.lose) throw new TypeError('Lost initial publication reply');
      const value = structuredClone(terminal);
      if (config.refused) { value.outcome = 'refused'; value.decision = { code: 'TargetRefMoved', code_point: 1, refusal_record_id: 'refusal-original' }; }
      await config.publish?.(value); return json(value, config.status ?? (config.refused ? 409 : 200));
    }
    if (endpoint === 'outcomes') {
      const state = config.outcome, terminal = ['committed', 'refused'].includes(state);
      const value = { ...common, type: 'transaction_outcome', principal_id: actor, selector: 'transaction', command_index: null, state, terminal,
        transaction: ['undecided', 'committed', 'refused'].includes(state) ? { tx_id: 'tx-original', seal_id: 'seal-original', request_schema: 'initial-v1', canonical_request_digest: { algorithm: 1, hex: '5'.repeat(64) } } : null,
        decision: state === 'committed' ? { kind: state, decision_sequence: 1, repository_commit_id: 'rcr-first' } : state === 'refused' ? { kind: state, decision_sequence: 1, code: 'TargetRefMoved', code_point: 1, refusal_record_id: 'refusal-original' } : null,
        read_only: true, request_reexecuted: false, absence_proves_non_commit: false, session_completeness_established: false };
      config.recover?.(value); return json(value);
    }
    throw new Error(`Unexpected initial fixture request ${endpoint}`);
  };
  return { plan, scope, prepared, terminal, bundle, sha, config, calls, fetchImpl, files, fields: fields(algorithm) };
}
