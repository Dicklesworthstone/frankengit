// Native-wire protocol doubles, not a Rust replay engine or proof of admission.
import { webcrypto } from 'node:crypto';
import { utf8, hex } from '../../crates/fgit-node/src/smart_http/server/browser/pulls-core.mjs';
import { digest } from '../../crates/fgit-node/src/smart_http/server/browser/pulls-candidate.mjs';
import { objectHash } from '../../crates/fgit-node/src/smart_http/server/browser/rebase-data.mjs';
import { multipart, response, decodeUpload } from './source-edit-fixtures.mjs';
export const crypto = webcrypto, token = '7'.repeat(64), actor = '9'.repeat(32);
export const href = 'http://127.0.0.1:9418/repo.git/ui/rebase/';
export const input = { upstream: '', empty: 'stop', committer: 'Reviewer <review@example.invalid>', timestamp: 20 };
export async function fixture(algorithm = 'sha1', count = 2) {
  const id = n => n.repeat(algorithm === 'sha1' ? 40 : 64), source = id('a'), upstream = id('b'), onto = id('c');
  const sourceTree = id('d'), ontoTree = id('e'), rootTree = count ? id(String(count)) : ontoTree;
  const common = { schema_version: 1, tenant_id: '1'.repeat(32), repository_id: '2'.repeat(32), repository_incarnation: '3'.repeat(32), object_format: algorithm };
  const scope = { tenant: common.tenant_id, repository: common.repository_id, incarnation: common.repository_incarnation, format: algorithm };
  const head = `alg:2:${'4'.repeat(64)}`, sourceHead = 'head-original';
  const selection = { scope, head, sourceHead, source: { ref: 'refs/heads/topic', commit: source, tree: sourceTree }, onto: { ref: 'refs/heads/main', commit: onto, tree: ontoTree } };
  const parameters = { ...input, upstream: count ? upstream : source };
  const flags = { read_only: true, objects_staged: false, transaction_created: false, published: false, publication_authorized: false };
  function diff(before, after, beforeTree, afterTree, entries = []) {
    return { ...common, type: 'source_diff', profile: 'native-tree-review-v1', source_head: sourceHead, snapshot_token: head,
      mode: 'direct', pull_request: null, read_only: true, transaction_created: false, published: false, approval_created: false,
      complete: true, line_origin: 0, context_lines: 3, before_ref_hex: hex(utf8.encode(selection.source.ref)),
      after_ref_hex: hex(utf8.encode(selection.source.ref)), requested_before: before, compared_before: before, requested_after: after,
      before_tree: beforeTree, after_tree: afterTree, entry_count: entries.length, path_prefixes_hex: [], entries };
  }
  const rows = [], steps = []; let parent = onto, tree = ontoTree;
  for (let i = 0; i < count; i++) {
    const newTree = id(String(i + 1));
    const bytes = utf8.encode(`tree ${newTree}\nparent ${parent}\nauthor Original <old@example.invalid> 1 +0000\ncommitter ${input.committer} ${input.timestamp} +0000\n\nOriginal message ${i}\n`);
    const commit = await objectHash('commit', bytes, algorithm, crypto);
    rows.push({ index: i, commit, parent, tree: newTree, body_hex: hex(bytes), diff: diff(parent, commit, tree, newTree) });
    steps.push({ original: i === count - 1 ? source : id('4'), rewritten: commit, tree: newTree, kind: 'replayed' });
    parent = commit; tree = newTree;
  }
  const bundle = utf8.encode('# explicit synthetic bundle for wire-contract tests, NOT native pack validation\n'), sha256 = await digest(bundle, crypto);
  const prepared = { ...common, ...flags, type: 'rebase_preparation', profile: 'linear-v1', source_head: sourceHead, snapshot_token: head,
    source_ref: selection.source.ref, source_ref_hex: hex(utf8.encode(selection.source.ref)), onto_ref: selection.onto.ref, onto_ref_hex: hex(utf8.encode(selection.onto.ref)),
    expected_source: source, upstream: parameters.upstream, onto, empty: input.empty, committer: input.committer, timestamp: input.timestamp,
    original_authors_preserved: true, original_messages_preserved: true, original_signatures_copied: false, author_identity_verified: false,
    state: 'clean', series_complete: true, provisional_steps: false, candidate_commit: parent, root_tree: rootTree,
    generated_objects: count * 2, pack_objects: count * 2, borrowed_objects: 0, bundle: { bytes: bundle.length, sha256 },
    stopped_commit: null, conflicts: [], step_count: steps.length, steps };
  const inspection = { ...common, ...flags, type: 'rebase_inspection', profile: 'linear-v1', source_head: sourceHead, snapshot_token: head,
    expected_source: source, onto, candidate_commit: parent, source_ref_hex: prepared.source_ref_hex, onto_ref_hex: prepared.onto_ref_hex,
    approval_created: false, replay_equivalence_verified: false, complete: true, all_changed_paths: true, all_rewritten_commits: true,
    binary_bodies_included: false, bundle: { bytes: bundle.length, pack_bytes: 12, pack_objects: count * 2, expanded_bytes: 100,
      closure_objects: count * 2, transport_only_objects: 0, sha256 }, commit_count: count,
    net_change: diff(source, parent, sourceTree, rootTree), commits: rows };
  const terminal = { ...common, type: 'rebase_publication', principal_id: actor, ref: selection.source.ref, ref_hex: prepared.source_ref_hex,
    expected_source: source, onto, candidate_commit: parent, tx_id: 'transaction-original', outcome: 'committed', decision_sequence: 1,
    decision_record: 'canonical-rcr', refusal_code: null, delivery_acknowledged: null };
  const conflict = { path_hex: hex(utf8.encode('file.bin')), kind: 'binary', base: { mode: 0o100644, oid: id('5') },
    ours: { mode: 0o100644, oid: id('6') }, theirs: { mode: 0o100755, oid: id('7') } };
  function stopped(index = 0, kind = 'conflicted') {
    const r = structuredClone(prepared);
    Object.assign(r, { state: kind, series_complete: false, provisional_steps: true, candidate_commit: null, root_tree: null, bundle: null,
      stopped_commit: steps[index].original, conflicts: kind === 'conflicted' ? [structuredClone(conflict)] : [], steps: steps.slice(0, index), step_count: index });
    for (const k of ['generated_objects', 'pack_objects', 'borrowed_objects']) delete r[k]; return r;
  }
  const calls = [], config = { prepare: null, inspect: null, tree: null, resolve: null, apply: null, lose: false, outcome: 'key_not_observed', hold: null };
  const fetchImpl = async (url, options) => {
    const endpoint = new URL(url).pathname.split('/api/v1/')[1];
    calls.push({ endpoint, method: options.method, body: typeof options.body === 'string' ? options.body : options.body?.slice(),
      headers: Object.fromEntries(new Headers(options.headers)), options });
    await config.hold?.(endpoint, options);
    if (endpoint === 'source/tree') {
      const fields = new URLSearchParams(options.body), ref = fields.get('ref'), value = ref === selection.source.ref ? selection.source : selection.onto;
      const reply = { ...common, type: 'source_tree', source_head: sourceHead, snapshot_token: head, source_rcr: 'rcr-original',
        ref, ref_hex: hex(utf8.encode(ref)), source_commit: value.commit, root_tree: value.tree, object_id: value.tree,
        read_only: true, transaction_created: false, published: false, path_hex: null, after_hex: null, limit: 1, entries: [], next_after_hex: null };
      config.tree?.(reply, calls.length); return response(reply);
    }
    if (endpoint === 'source/rebase/prepare' || endpoint === 'source/rebase/resolve') {
      const r = structuredClone(prepared); await (endpoint.endsWith('resolve') ? config.resolve : config.prepare)?.(r, options);
      if (r.state !== 'clean') return response(r, 409);
      const m = multipart(r, bundle, sha256); return new Response(m.value, { status: 200, headers: { 'Content-Type': m.type } });
    }
    if (endpoint === 'source/rebase/inspect') {
      const r = structuredClone(inspection); await config.inspect?.(r, options); return response(r);
    }
    if (endpoint === 'source/rebase/apply') {
      if (config.lose) throw new TypeError('lost response after simulated admission');
      const r = structuredClone(terminal); config.apply?.(r); return response(r, r.outcome === 'committed' ? 200 : 409);
    }
    if (endpoint === 'outcomes') {
      const state = config.outcome, decided = ['committed', 'refused'].includes(state), observed = ['undecided', 'committed', 'refused'].includes(state);
      return response({ ...common, type: 'transaction_outcome', principal_id: actor, selector: 'transaction', command_index: null,
        state, terminal: decided, read_only: true, request_reexecuted: false, absence_proves_non_commit: false, session_completeness_established: false,
        transaction: observed ? { tx_id: terminal.tx_id, seal_id: 'seal-original', request_schema: 'receive', canonical_request_digest: { algorithm: 2, hex: '8'.repeat(64) } } : null,
        decision: state === 'committed' ? { kind: state, decision_sequence: 1, repository_commit_id: terminal.decision_record }
          : state === 'refused' ? { kind: state, decision_sequence: 1, code: 'TargetMoved', code_point: 1, refusal_record_id: 'refused-rcr' } : null });
    }
    throw new Error(`Unexpected test endpoint ${endpoint}`);
  };
  return { algorithm, id, source, upstream, onto, sourceTree, ontoTree, rootTree, scope, selection, parameters, bundle, sha256,
    prepared, inspection, terminal, steps, conflict, stopped, diff, calls, config, fetchImpl };
}
export { response, multipart, decodeUpload };
