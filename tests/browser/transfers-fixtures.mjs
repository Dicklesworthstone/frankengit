// HTTP/authority doubles. The tiny pack is deliberately empty despite its
// advertised refs: checksum verification MUST NOT be called object admission.
// transfers-git-oracle.mjs separately exercises real pinned-Git bundles.
import { webcrypto, createHash } from 'node:crypto';
export const crypto = webcrypto, token = '7'.repeat(64), actor = '9'.repeat(32);
export const href = 'https://forge.example/repo.git/ui/transfers/';
export const hex = value => Buffer.from(value).toString('hex');
export const sha = bytes => createHash('sha256').update(bytes).digest('hex');
export const head = `alg:1:${'4'.repeat(64)}`;
export const json = (value, status = 200) => new Response(JSON.stringify(value), { status, headers: { 'Content-Type': 'application/json' } });
export const deferred = () => { let resolve; const promise = new Promise(r => { resolve = r; }); return { promise, resolve }; };
export function bundleBytes(algorithm = 'sha1', header = null) {
  const id = 'a'.repeat(algorithm === 'sha1' ? 40 : 64);
  const pack = Buffer.from('5041434b0000000200000000', 'hex'), checksum = createHash(algorithm).update(pack).digest();
  const prefix = header ?? `${algorithm === 'sha1' ? '# v2 git bundle' : '# v3 git bundle\n@object-format=sha256'}\n${id} refs/heads/main\n${id} refs/tags/v1\n${id} HEAD\n\n`;
  return new Uint8Array(Buffer.concat([Buffer.from(prefix), pack, checksum]));
}
export function decodeUpload(call) {
  const boundary = call.headers['content-type'].split('boundary=')[1], bytes = Buffer.from(call.body);
  const start = bytes.indexOf('\r\n\r\n') + 4, middle = bytes.indexOf(`\r\n--${boundary}\r\n`, start);
  const payloadStart = bytes.indexOf('\r\n\r\n', middle + 4) + 4, end = bytes.lastIndexOf(`\r\n--${boundary}--\r\n`);
  return { fields: new URLSearchParams(bytes.subarray(start, middle).toString()), payload: new Uint8Array(bytes.subarray(payloadStart, end)) };
}
export function fixture(algorithm = 'sha1', input = bundleBytes(algorithm)) {
  const common = { schema_version: 1, tenant_id: '1'.repeat(32), repository_id: '2'.repeat(32),
    repository_incarnation: '3'.repeat(32), object_format: algorithm };
  const selection = { ...common, type: 'source_refs', namespace: 'all', after: null, limit: 1, next_after: null, refs: [],
    direct_refs_only: true, source_head: 'authority-head', snapshot_token: head, read_only: true, transaction_created: false, published: false };
  const exportHeaders = { 'Content-Type': 'application/x-git-bundle', 'Content-Length': String(input.length),
    'X-Fgit-Bundle-Profile': 'full-v1', 'X-Fgit-Object-Format': algorithm, 'X-Fgit-Tenant': common.tenant_id,
    'X-Fgit-Repository': common.repository_id, 'X-Fgit-Repository-Incarnation': common.repository_incarnation,
    'X-Fgit-Source-Head': 'authority-head', 'X-Fgit-Snapshot': head, 'X-Fgit-Artifact-Sha256': sha(input), 'X-Fgit-Read-Only': 'true' };
  const config = { lose: false, refuse: false, select: null, export: null, terminal: null, outcome: 'key_not_observed', recover: null, importCount: 2 };
  const calls = [];
  async function fetchImpl(url, options) {
    const path = new URL(url).pathname.split('/api/v1/')[1];
    const call = { path, ...options, body: options.body instanceof Uint8Array ? options.body.slice() : options.body,
      headers: Object.fromEntries(new Headers(options.headers)) }; calls.push(call);
    if (path === 'source/refs') { const r = structuredClone(selection); await config.select?.(r, call); return json(r); }
    if (path === 'source/bundle/export') {
      const response = { bytes: input.slice(), headers: { ...exportHeaders }, status: 200 };
      await config.export?.(response, call);
      return new Response(response.bytes, { status: response.status, headers: response.headers });
    }
    if (path === 'outcomes') {
      const state = config.outcome, terminal = ['committed', 'refused'].includes(state), exists = terminal || state === 'undecided';
      const r = { ...common, type: 'transaction_outcome', principal_id: actor, selector: 'transaction', command_index: null,
        state, terminal, transaction: exists ? { tx_id: 'tx-original', seal_id: 'seal', request_schema: 'native-bundle-command',
          canonical_request_digest: { algorithm: 1, hex: '5'.repeat(64) } } : null,
        decision: state === 'committed' ? { kind: state, decision_sequence: 1, repository_commit_id: 'rcr-original' }
          : state === 'refused' ? { kind: state, decision_sequence: 1, code: 'RefMismatch', code_point: 1, refusal_record_id: 'refusal' } : null,
        read_only: true, request_reexecuted: false, absence_proves_non_commit: false, session_completeness_established: false };
      await config.recover?.(r, call); return json(r);
    }
    if (!['source/bundle/import', 'source/bundle/fetch'].includes(path)) throw new Error(`Unexpected endpoint ${path}`);
    if (config.lose) throw new Error('Simulated lost response');
    const operation = path.split('/').at(-1), { fields } = decodeUpload(call);
    const r = { ...common, type: 'source_bundle_publication', operation, principal_id: actor, tx_id: 'tx-original', decision_sequence: 1,
      command_count: operation === 'import' ? config.importCount : fields.getAll('mapping').length,
      outcome: config.refuse ? 'refused' : 'committed', decision: config.refuse ? { code: 'RefMismatch', code_point: 1, refusal_record_id: 'refusal' }
        : { repository_commit_id: 'rcr-original' }, atomic: true, terminal: true, forge_state_imported: false,
      default_branch_changed: false, receipt_confirms_transport_revalidation: false };
    await config.terminal?.(r, call); return json(r, config.refuse ? 409 : 200);
  }
  return { algorithm, input, common, selection, exportHeaders, config, calls, fetchImpl };
}
