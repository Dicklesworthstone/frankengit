// HTTP/authority doubles. Native tag object IDs use an independent Node hash.
import { webcrypto, createHash } from 'node:crypto';
export const crypto = webcrypto, token = '7'.repeat(64), actor = '9'.repeat(32);
export const href = 'https://forge.example/repo.git/ui/tags/';
export const hex = value => Buffer.from(value).toString('hex');
export const head = `alg:1:${'4'.repeat(64)}`;
export const json = (value, status = 200) => new Response(JSON.stringify(value), { status, headers: { 'Content-Type': 'application/json' } });
export const deferred = () => { let resolve; const promise = new Promise(r => { resolve = r; }); return { promise, resolve }; };
export function objectId(body, algorithm) { return createHash(algorithm).update(`tag ${body.length}\0`).update(body).digest('hex'); }
export function objectBody(fields) {
  return Buffer.concat([Buffer.from(`object ${fields.target}\ntype ${fields.target_kind}\ntag `), Buffer.from(fields.ref_hex, 'hex').subarray(10),
    Buffer.from(`\ntagger ${fields.tagger} ${fields.timestamp} +0000\n\n`), Buffer.from(fields.message_hex, 'hex')]);
}
export const destination = hex('refs/tags/new'), source = hex('refs/heads/main'), existing = hex('refs/tags/v1');
export function annotationInput() { return { ref_hex: destination, source_ref_hex: source, target_kind: 'commit', tagger: 'Author <a@b>', timestamp: 0, message_hex: hex('hello\r\nworld') }; }
export function fixture(algorithm = 'sha1') {
  const common = { schema_version: 1, tenant_id: '1'.repeat(32), repository_id: '2'.repeat(32), repository_incarnation: '3'.repeat(32), object_format: algorithm };
  const commit = 'a'.repeat(algorithm === 'sha1' ? 40 : 64);
  const bytes = objectBody({ ref_hex: existing, target: commit, target_kind: 'commit', tagger: 'Legacy <a@b>', timestamp: 1, message_hex: hex('old') });
  const tag = objectId(bytes, algorithm);
  const refs = [{ ref: 'refs/heads/main', ref_hex: source, object_id: commit }, { ref: 'refs/tags/v1', ref_hex: existing, object_id: tag }];
  const inspection = { ...common, type: 'source_tag', source_head: 'authority-head', snapshot_token: head, read_only: true, transaction_created: false, published: false,
    signature_verified: false, tagger_is_authenticated_principal: false, ref_hex: existing, object_id: tag, peeled_object: commit, peeled_kind: 'commit', annotation_count: 1,
    annotations: [{ object_id: tag, target: commit, target_kind: 'commit', signature: 'absent', signature_verified: false, body_bytes: bytes.length, body_hex: hex(bytes) }] };
  const config = { lose: false, refuse: false, list: null, inspect: null, terminal: null, outcome: 'key_not_observed', recover: null };
  const calls = [];
  async function fetchImpl(url, options) {
    const path = new URL(url).pathname.split('/api/v1/')[1];
    const call = { path, ...options, headers: Object.fromEntries(new Headers(options.headers)) }; calls.push(call);
    const fields = Object.fromEntries(new URLSearchParams(options.body));
    if (path === 'source/refs') {
      const after = fields.after ?? null, limit = Number(fields.limit);
      const remaining = refs.filter(r => after === null || r.ref_hex > hex(after));
      const r = { ...common, type: 'source_refs', source_head: 'authority-head', snapshot_token: head, namespace: 'all', after, limit,
        next_after: remaining.length > limit ? remaining[limit - 1].ref : null, refs: structuredClone(remaining.slice(0, limit)),
        read_only: true, transaction_created: false, published: false, direct_refs_only: true };
      await config.list?.(r, call); return json(r);
    }
    if (path === 'source/tags/inspect') { const r = structuredClone(inspection); await config.inspect?.(r, call); return json(r); }
    if (path === 'outcomes') {
      const state = config.outcome, terminal = ['committed', 'refused'].includes(state), exists = terminal || state === 'undecided';
      const r = { ...common, type: 'transaction_outcome', principal_id: actor, selector: 'transaction', command_index: null,
        state, terminal, transaction: exists ? { tx_id: 'tx-original', seal_id: 'seal', request_schema: 'native-receive', canonical_request_digest: { algorithm: 1, hex: '5'.repeat(64) } } : null,
        decision: state === 'committed' ? { kind: state, decision_sequence: 1, repository_commit_id: 'rcr-original' }
          : state === 'refused' ? { kind: state, decision_sequence: 1, code: 'RefMismatch', code_point: 1, refusal_record_id: 'refusal' } : null,
        read_only: true, request_reexecuted: false, absence_proves_non_commit: false, session_completeness_established: false };
      await config.recover?.(r, call); return json(r);
    }
    const operation = path.split('/').at(-1);
    if (!['lightweight', 'annotated', 'delete'].includes(operation)) throw new Error(`Unexpected path ${path}`);
    if (config.lose) throw new Error('Simulated lost response');
    const r = { ...common, type: 'tag_publication', operation, principal_id: actor, ref_hex: fields.ref_hex,
      expected_object: operation === 'delete' ? fields.expected_object : null,
      new_object: operation === 'delete' ? null : operation === 'lightweight' ? fields.target : objectId(objectBody(fields), algorithm),
      tx_id: 'tx-original', decision_sequence: 1, atomic: true, terminal: true, force: false, forge_transition: false,
      signature_verified: false, tagger_is_authenticated_principal: false, outcome: config.refuse ? 'refused' : 'committed',
      ...(config.refuse ? { code: 'RefMismatch', code_point: 1, refusal_record_id: 'refusal' } : { repository_commit_id: 'rcr-original' }) };
    await config.terminal?.(r, call); return json(r, config.refuse ? 409 : 200);
  }
  return { algorithm, common, commit, tag, refs, inspection, config, calls, fetchImpl };
}
