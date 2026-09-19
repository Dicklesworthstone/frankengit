// Deliberately synthetic native service responses; these fixtures test browser
// contracts, not Rust admission. Object hashes use actual WebCrypto algorithms.
import { webcrypto } from 'node:crypto';
import { utf8, hex } from '../../crates/fgit-node/src/smart_http/server/browser/pulls-core.mjs';
import { digest, objectHash, editManifest } from '../../crates/fgit-node/src/smart_http/server/browser/source-edit-protocol.mjs';
import { fullFilePatch } from '../../crates/fgit-node/src/smart_http/server/browser/source-edit-patch.mjs';
export const crypto = webcrypto, token = '7'.repeat(64), actor = '9'.repeat(32);
export const href = 'http://127.0.0.1:9418/repo.git/ui/source/';
export const metadata = { author: 'Alice <a@example.invalid>', committer: 'Alice <a@example.invalid>', timestamp: 1, message: 'Exact source edit\n' };
export const edit = () => ({ path_hex: hex(utf8.encode('file.txt')), before: { mode: 0o100644, bytes: utf8.encode('before\r\n') }, after: { mode: 0o100755, bytes: utf8.encode('after') } });
export function response(value, status = 200) { return new Response(JSON.stringify(value), { status, headers: { 'Content-Type': 'application/json; charset=utf-8' } }); }
export function multipart(metadata, bundle, sha256) {
  const boundary = `fg-source-${sha256.slice(0, 48)}-0`;
  const opening = utf8.encode(`--${boundary}\r\nContent-Type: application/json; charset=utf-8\r\nContent-Disposition: inline; name="metadata"\r\n\r\n${JSON.stringify(metadata)}\r\n--${boundary}\r\nContent-Type: application/x-git-bundle\r\nContent-Disposition: attachment; name="bundle"; filename="candidate.bundle"\r\n\r\n`);
  const closing = utf8.encode(`\r\n--${boundary}--\r\n`);
  const body = new Uint8Array(opening.length + bundle.length + closing.length);
  body.set(opening); body.set(bundle, opening.length); body.set(closing, opening.length + bundle.length);
  return { type: `multipart/mixed; boundary=${boundary}`, status: 200, value: body };
}
export function decodeUpload(options) {
  const type = new Headers(options.headers).get('Content-Type'), boundary = type.split('boundary=')[1];
  const bytes = Buffer.from(options.body), separator = bytes.indexOf('\r\n\r\n') + 4;
  const middle = bytes.indexOf(`\r\n--${boundary}\r\n`, separator), payloadStart = bytes.indexOf('\r\n\r\n', middle + 4) + 4;
  const payloadEnd = bytes.lastIndexOf(`\r\n--${boundary}--\r\n`);
  return { command: new URLSearchParams(bytes.subarray(separator, middle).toString()), payload: new Uint8Array(bytes.subarray(payloadStart, payloadEnd)) };
}
export async function fixture(algorithm = 'sha1', edits = [edit()], patchOptions = {}) {
  const width = algorithm === 'sha1' ? 40 : 64;
  const base = 'a'.repeat(width), tree = 'b'.repeat(width), oldTree = 'c'.repeat(width);
  const commit = utf8.encode(`tree ${tree}\nparent ${base}\nauthor Alice <a@example.invalid> 1 +0000\ncommitter Alice <a@example.invalid> 1 +0000\n\nExact source edit\n`);
  const candidate = await objectHash('commit', commit, algorithm, crypto);
  const patch = fullFilePatch(edits, patchOptions), manifest = await editManifest(patch.edits, algorithm, crypto);
  const bundle = utf8.encode('# synthetic bounded native-bundle fixture\nPACK\n'), sha256 = await digest(bundle, crypto);
  const common = { schema_version: 1, tenant_id: '1'.repeat(32), repository_id: '2'.repeat(32), repository_incarnation: '3'.repeat(32), object_format: algorithm };
  const selection = { ...common, source_head: 'head-1', snapshot_token: `alg:1:${'4'.repeat(64)}`, source_rcr: 'rcr-base',
    ref: 'refs/heads/main', ref_hex: hex(utf8.encode('refs/heads/main')), source_commit: base, root_tree: oldTree,
    read_only: true, transaction_created: false, published: false };
  const scope = { tenant: common.tenant_id, repository: common.repository_id, incarnation: common.repository_incarnation, format: algorithm };
  const fields = { ref: selection.ref, object_format: algorithm, expected_commit: base };
  const flags = { read_only: true, objects_staged: false, transaction_created: false, published: false, publication_authorized: false };
  const prepared = { ...common, ...flags, type: 'source_preparation', ref: selection.ref, ref_hex: selection.ref_hex,
    source_commit: base, source_rcr: selection.source_rcr, candidate_commit: candidate, root_tree: tree,
    patch_sha256: await digest(patch.bytes, crypto), object_count: 3, bundle: { bytes: bundle.length, sha256 },
    paths: manifest.map(p => ({ path_hex: p.path_hex, old_blob: p.old_blob, new_blob: p.new_blob, new_mode: p.new_mode, hunks: 1 })) };
  const inspection = { ...common, ...flags, type: 'source_inspection', ref: selection.ref, ref_hex: selection.ref_hex,
    source_head: selection.source_head, snapshot_token: selection.snapshot_token, expected_commit: base,
    candidate_commit: candidate, parents: [base], bundle_bytes: bundle.length, bundle_sha256: sha256,
    all_changed_paths: true, binary_bodies_included: false, candidate_commit_body_hex: hex(commit),
    comparison: { mode: 'direct', before_tree: oldTree, after_tree: tree, entry_count: manifest.length,
      entries: manifest.map(p => ({ path_hex: p.path_hex, kind: p.old_blob === null ? 'added' : p.new_blob === null ? 'deleted' : 'modified',
        before: p.old_blob === null ? null : { mode: p.old_mode, oid: p.old_blob },
        after: p.new_blob === null ? null : { mode: p.new_mode, oid: p.new_blob }, content: { type: 'object_only', content_read: false } })) } };
  const terminal = { ...common, type: 'source_publication', principal_id: actor, ref: selection.ref, ref_hex: selection.ref_hex,
    expected_commit: base, candidate_commit: candidate, tx_id: 'tx-original', outcome: 'committed', decision_sequence: 1,
    decision_record: 'rcr-new', refusal_code: null, delivery_acknowledged: null };
  const calls = [], config = { loseApply: false, refuseApply: false, inspect: null, prepare: null, read: null, outcome: 'key_not_observed' };
  const fetchImpl = async (url, options) => {
    const endpoint = new URL(url).pathname.split('/api/v1/')[1];
    calls.push({ endpoint, method: options.method, headers: Object.fromEntries(new Headers(options.headers)),
      body: options.body instanceof Uint8Array ? options.body.slice() : options.body, options });
    if (endpoint === 'source/tree') return response({ ...selection, type: 'source_tree', object_id: oldTree, path_hex: null,
      after_hex: null, limit: 1, entries: [], next_after_hex: null });
    if (endpoint === 'source/blob') {
      const params = new URLSearchParams(options.body), selected = edits.find(p => p.path_hex === params.get('path_hex'));
      if (!selected?.before) return response({ type: 'source_error', code: 'not_found' }, 404);
      const value = { ...selection, type: 'source_blob', object_id: await objectHash('blob', selected.before.bytes, algorithm, crypto),
        path_hex: selected.path_hex, kind: selected.before.mode === 0o100755 ? 'executable' : 'file', total_bytes: selected.before.bytes.length,
        offset: 0, returned_bytes: selected.before.bytes.length, next_offset: null, content_hex: hex(selected.before.bytes), symlink_followed: false };
      config.read?.(value); return response(value);
    }
    if (endpoint === 'source/prepare') {
      const { payload } = decodeUpload(options), value = structuredClone(prepared); value.patch_sha256 = await digest(payload, crypto);
      config.prepare?.(value); const envelope = multipart(value, bundle, sha256);
      return new Response(envelope.value, { status: 200, headers: { 'Content-Type': envelope.type } });
    }
    if (endpoint === 'source/inspect') {
      const value = structuredClone(inspection); await config.inspect?.(value); return response(value);
    }
    if (endpoint === 'source/apply') {
      if (config.loseApply) throw new TypeError('Simulated lost reply');
      const value = structuredClone(terminal);
      if (config.refuseApply) { value.outcome = 'refused'; value.decision_record = 'refusal-record'; value.refusal_code = 'TargetRefMoved'; }
      return response(value, config.refuseApply ? 409 : 200);
    }
    if (endpoint === 'outcomes') {
      const state = config.outcome, terminalState = ['committed', 'refused'].includes(state);
      const transaction = ['undecided', 'committed', 'refused'].includes(state) ? { tx_id: 'tx-original', seal_id: 'seal-original', request_schema: 'source-v1', canonical_request_digest: { algorithm: 1, hex: '5'.repeat(64) } } : null;
      const decision = state === 'committed' ? { kind: 'committed', decision_sequence: 1, repository_commit_id: 'rcr-new' }
        : state === 'refused' ? { kind: 'refused', decision_sequence: 1, code: 'TargetRefMoved', code_point: 1, refusal_record_id: 'refusal-record' } : null;
      return response({ ...common, type: 'transaction_outcome', principal_id: actor, selector: 'transaction', command_index: null,
        state, terminal: terminalState, transaction, decision, read_only: true, request_reexecuted: false,
        absence_proves_non_commit: false, session_completeness_established: false });
    }
    throw new Error(`Unexpected fixture endpoint ${endpoint}`);
  };
  return { algorithm, edits, patch, scope, selection, fields, base, candidate, tree, bundle, sha256,
    prepared, inspection, terminal, manifest, calls, config, fetchImpl };
}
