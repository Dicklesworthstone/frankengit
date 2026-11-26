// Schema-speaking TCP peer, not native Git, branch policy or authority-CAS evidence.
import { createServer } from 'node:http';
import { isUtf8 } from 'node:buffer';
import { createHash } from 'node:crypto';

export const TOKEN = 'a'.repeat(64), ROTATED = 'b'.repeat(64), AGENT = 'fgagent_' + 'c'.repeat(64);
export const hex = text => Buffer.from(text).toString('hex');
const digest = text => createHash('sha256').update(text).digest('hex');
export async function fixture(t, format = 'sha1') {
  const oid = c => c.repeat(format === 'sha1' ? 40 : 64), calls = [], decisions = new Map(), sockets = new Set();
  const scope = { tenant_id: '1'.repeat(32), repository_id: '2'.repeat(32), repository_incarnation: '3'.repeat(32),
    principal_id: '4'.repeat(32), object_format: format };
  const refs = new Map([[hex('refs/heads/main'), oid('1')], [hex('refs/heads/topic'), oid('2')], [hex('refs/heads/remove'), oid('3')]]);
  const state = { refs, drop: false, delay: 0, refuse: false, tamper: null, hook: null, suppressOutcome: false };
  const server = createServer(async (req, res) => {
    try {
      const chunks = []; for await (const part of req) chunks.push(part);
      const body = Buffer.concat(chunks).toString(), form = new URLSearchParams(body);
      const call = { path: req.url, body, form, headers: req.headers, method: req.method }; calls.push(call);
      if (state.hook && await state.hook(call, req, res)) return;
      if (![TOKEN, ROTATED, AGENT].some(token => req.headers.authorization === 'Bearer ' + token)) { res.writeHead(401); res.end(); return; }
      const key = req.headers['idempotency-key'];
      let value, status = 200;
      if (req.url === '/team/repo.git/api/v1/source/branches/transaction') {
        if (req.headers.authorization === 'Bearer ' + AGENT) { res.writeHead(403); res.end(); return; }
        const old = decisions.get(key);
        if (old && old.body !== body) { res.writeHead(409, { 'Content-Type': 'application/json' }); res.end('{"type":"source_error","code":"idempotency_key_reuse"}'); return; }
        if (old) value = old.value;
        else {
          const changes = [...form].filter(([name]) => name !== 'object_format').map(([operation, operand]) => {
            const [ref, first, second] = operand.split(':');
            return { operation, ref, expected: operation === 'create' ? null : first, next: operation === 'delete' ? null : operation === 'create' ? first : second };
          });
          const refused = state.refuse || changes.some(row => (state.refs.get(row.ref) ?? null) !== row.expected);
          value = { type: 'branch_publication', schema_version: 1, ...scope, operation: 'transaction',
            atomic: true, terminal: true, tx_id: 'tx-' + digest(key), decision_sequence: '18446744073709551615',
            outcome: refused ? 'refused' : 'committed', forge_transition: false, updates: changes.map(row => {
              const name = Buffer.from(row.ref, 'hex');
              return { ref: isUtf8(name) ? name.toString() : null, ref_hex: row.ref,
                expected_commit: row.expected, new_commit: row.next, force: false };
            }), ...(refused ? { code: 'TargetRefMoved', code_point: 7, refusal_record_id: 'refusal-' + digest(key) }
              : { repository_commit_id: 'rcr-' + digest(key) }) };
          decisions.set(key, { body, value });
          if (!refused) for (const row of changes) { if (row.next === null) state.refs.delete(row.ref); else state.refs.set(row.ref, row.next); }
        }
        status = value.outcome === 'committed' ? 200 : 409;
        if (state.drop) { req.socket.destroy(); return; }
      } else if (req.url === '/team/repo.git/api/v1/outcomes') {
        const known = state.suppressOutcome ? null : decisions.get(key)?.value;
        const { object_format: _, ...binding } = scope;
        value = { type: 'transaction_outcome', schema_version: 1, ...binding, selector: 'transaction', command_index: null,
          state: known?.outcome ?? 'key_not_observed', terminal: !!known,
          transaction: known ? { tx_id: known.tx_id, seal_id: 'seal-' + digest(key), request_schema: 'fixture-atomic-receive',
            canonical_request_digest: { algorithm: 2, hex: digest(decisions.get(key).body) } } : null,
          decision: !known ? null : known.outcome === 'committed' ? { kind: 'committed', decision_sequence: known.decision_sequence,
            repository_commit_id: known.repository_commit_id } : { kind: 'refused', decision_sequence: known.decision_sequence,
              code: known.code, code_point: known.code_point, refusal_record_id: known.refusal_record_id },
          read_only: true, request_reexecuted: false, absence_proves_non_commit: false, session_completeness_established: false };
      } else { res.writeHead(404); res.end(); return; }
      value = structuredClone(value); await state.tamper?.(value, call);
      if (state.delay) await new Promise(resolve => setTimeout(resolve, state.delay));
      res.writeHead(status, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(value).replace(/"decision_sequence":"([0-9]+)"/g, '"decision_sequence":$1'));
    } catch { if (!res.headersSent) res.writeHead(500); res.end(); }
  });
  server.on('connection', socket => { sockets.add(socket); socket.on('close', () => sockets.delete(socket)); });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(async () => { for (const socket of sockets) socket.destroy(); await new Promise(resolve => server.close(resolve)); });
  const endpoint = 'http://127.0.0.1:' + server.address().port + '/team/repo.git';
  const input = { endpoint, scope, changes: [
    { operation: 'update', ref_hex: hex('refs/heads/main'), expected_commit: oid('1'), new_commit: oid('4') },
    { operation: 'delete', ref_hex: hex('refs/heads/remove'), expected_commit: oid('3') },
    { operation: 'create', ref_hex: hex('refs/heads/new'), new_commit: oid('2') },
  ] };
  return { input, scope, oid, endpoint, calls, decisions, state };
}
