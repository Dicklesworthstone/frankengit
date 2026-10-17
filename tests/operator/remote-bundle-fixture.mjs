// HTTP response-schema peer only. These opaque payloads are NOT validated Git
// bundles, and this fixture does not implement admission, reachability or CAS.
import { createServer } from 'node:http';
import { mkdtemp, writeFile, chmod, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import assert from 'node:assert/strict';
import { hash } from '../../scripts/operator/remote_bundle_protocol.mjs';

export const TOKEN = 'aa'.repeat(32);
export const SCOPE = { tenant_id: '11'.repeat(16), repository_id: '22'.repeat(16), repository_incarnation: '33'.repeat(16),
  principal_id: '44'.repeat(16), object_format: 'sha1' };
export const SEQ = '18446744073709551615';
export const hex = value => Buffer.from(value).toString('hex');
export const payload = Buffer.from('opaque test payload\0\xff\r\nnot a native Git oracle');
export const wire = v => JSON.stringify(v).replace(/"decision_sequence":"([0-9]+)"/g, '"decision_sequence":$1');
export function outcome(scope, state = 'key_not_observed') {
  const { object_format, ...s } = scope;
  const present = ['undecided', 'committed', 'refused'].includes(state), terminal = ['committed', 'refused'].includes(state);
  return { type: 'transaction_outcome', schema_version: 1, ...s, selector: 'transaction', command_index: null,
    state, terminal, transaction: present ? { tx_id: 'tx-native-1', seal_id: 'seal-1', request_schema: 'native-schema-1',
      canonical_request_digest: { algorithm: 2, hex: '12'.repeat(32) } } : null,
    decision: terminal ? { kind: state, decision_sequence: SEQ, ...(state === 'committed' ? { repository_commit_id: 'rcr-native-1' }
      : { code: 'RefMismatch', code_point: 42, refusal_record_id: 'refusal-1' }) } : null,
    read_only: true, request_reexecuted: false, absence_proves_non_commit: false, session_completeness_established: false };
}
export function publication(scope, operation, count = 2, refused = false) {
  return { type: 'source_bundle_publication', schema_version: 1, operation, ...scope, tx_id: 'tx-native-1', decision_sequence: SEQ,
    command_count: count, outcome: refused ? 'refused' : 'committed', decision: refused
      ? { code: 'RefMismatch', code_point: 42, refusal_record_id: 'refusal-1' } : { repository_commit_id: 'rcr-native-1' },
    atomic: true, terminal: true, forge_state_imported: false, default_branch_changed: false, receipt_confirms_transport_revalidation: false };
}
export async function fixture(t, config = {}) {
  const root = await mkdtemp(join(tmpdir(), 'fg-remote-bundle-')); await chmod(root, 0o700);
  const token = join(root, 'token'), bundle = join(root, 'source.bundle');
  await writeFile(token, `${TOKEN}\n`, { mode: 0o600 }); await writeFile(bundle, payload, { mode: 0o600 });
  const scope = { ...SCOPE, object_format: config.format ?? 'sha1' }, requests = [], states = new Map(), sockets = new Set();
  const server = createServer(async (req, res) => {
    try {
      const chunks = []; let size = 0;
      for await (const c of req) { size += c.length; if (size > 65 * 1024 * 1024) throw new Error('fixture body limit'); chunks.push(c); }
      const body = Buffer.concat(chunks), key = req.headers['idempotency-key'];
      const call = { path: req.url, key, body, headers: req.headers }; requests.push(call);
      assert.equal(req.method, 'POST'); assert(key); assert.match(req.headers.authorization, /^Bearer [0-9a-f]{64}$/);
      let reply, status = 200;
      if (req.url === '/repo/api/v1/outcomes') {
        assert.equal(body.length, 0); reply = outcome(config.recoveryScope ?? scope, states.get(key));
      } else {
        assert(['/repo/api/v1/source/bundle/import', '/repo/api/v1/source/bundle/fetch'].includes(req.url));
        const boundary = req.headers['content-type'].split('boundary=')[1];
        const marker = Buffer.from(`\r\n--${boundary}`), first = body.indexOf(Buffer.from('\r\n\r\n')) + 4;
        const formEnd = body.indexOf(marker, first), dataStart = body.indexOf(Buffer.from('\r\n\r\n'), formEnd) + 4;
        const dataEnd = body.lastIndexOf(marker);
        const form = new URLSearchParams(body.subarray(first, formEnd).toString());
        call.form = form; call.payload = body.subarray(dataStart, dataEnd);
        assert.equal(hash(call.payload), form.get('artifact_sha256'));
        assert.equal(form.get('object_format'), scope.object_format);
        if (!config.noCommit) states.set(key, config.refuse ? 'refused' : 'committed');
        const operation = req.url.split('/').at(-1);
        reply = publication(scope, operation, operation === 'fetch' ? form.getAll('mapping').length : 2, config.refuse);
        status = config.refuse ? 409 : 200;
      }
      const decision = await config.intercept?.({ req, res, call, reply, states, requests });
      if (decision === false) return;
      res.writeHead(status, { 'content-type': 'application/json' }); res.end(wire(reply));
    } catch (e) { if (!res.destroyed) { res.writeHead(500, { 'content-type': 'application/json' }); res.end(JSON.stringify({ error: e.message })); } }
  });
  server.on('connection', s => { sockets.add(s); s.on('close', () => sockets.delete(s)); });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  let closed = false;
  const close = async () => { if (closed) return; closed = true; for (const s of sockets) s.destroy(); await new Promise(resolve => server.close(resolve)); };
  t.after(async () => { await close(); await rm(root, { recursive: true, force: true }); });
  const endpoint = `http://127.0.0.1:${server.address().port}/repo`;
  const selection = { endpoint, scope, operation: config.operation ?? 'import', ...(config.operation === 'fetch' ? {
    mappings: [{ source_hex: hex('refs/heads/main'), destination_hex: hex('refs/remotes/import/main'), expected_old: 'absent' },
      { source_hex: hex('refs/heads/main'), destination_hex: hex('refs/heads/copied'), expected_old: 'b'.repeat(scope.object_format === 'sha1' ? 40 : 64) }] } : {}) };
  return { root, token, bundle, endpoint, scope, states, requests, close, selection,
    options: { workdir: join(root, 'job'), selection, bundleFile: bundle, bundleConfirm: hash(payload), tokenFile: token } };
}
