// Real HTTP fixture speaking the inspected Rust schema; NOT native authority/CAS.
import { createServer } from 'node:http';
import { createHash } from 'node:crypto';
export const TOKEN = 'a'.repeat(64), ROTATED = 'b'.repeat(64), ACTOR = '3'.repeat(32);
const hex = value => Buffer.from(value).toString('hex');
const hash = value => createHash('sha256').update(value).digest('hex');
export function row(number = 1, format = 'sha1', patch = {}) {
  const size = format === 'sha1' ? 40 : 64;
  return { number, version: 3, state: 'open', data: { object_format: format,
    source_ref: `refs/heads/topic-${number}`, source_ref_hex: hex(`refs/heads/topic-${number}`),
    target_ref: 'refs/heads/main', target_ref_hex: hex('refs/heads/main'),
    source_tip: `${format}:${'1'.repeat(size)}`, target_tip: `${format}:${'2'.repeat(size)}`,
    title: `PR ${number} <script>`, body: 'Résumé\r\n\u202e exact text\n' },
    opened_by: '4'.repeat(32), last_metadata_actor: '4'.repeat(32), merge_only: false, merge: null, ...patch };
}
export async function fixture(t, format = 'sha1', count = 2) {
  const size = format === 'sha1' ? 40 : 64, calls = [], decisions = new Map(), sockets = new Set();
  const state = { rows: Array.from({ length: count }, (_, i) => row(i + 1, format)),
    tips: new Map([['refs/heads/main', 'c'.repeat(size)], ...Array.from({ length: count }, (_, i) => [`refs/heads/topic-${i + 1}`, 'd'.repeat(size)])]),
    head: `alg:2:${'e'.repeat(64)}`, source_head: 'fixture-head', mutate: null, hook: null, delay: 0, drop: false, refuse: false };
  const dest = { endpoint: '', tenant_id: '1'.repeat(32), repository_id: '2'.repeat(32), repository_incarnation: '5'.repeat(32), object_format: format, principal_id: ACTOR };
  const header = () => ({ schema_version: 1, tenant_id: dest.tenant_id, repository_id: dest.repository_id,
    repository_incarnation: dest.repository_incarnation, object_format: format, snapshot_token: state.head, source_head: state.source_head });
  const server = createServer(async (req, res) => {
    try {
      const chunks = []; for await (const part of req) chunks.push(part);
      const body = Buffer.concat(chunks).toString(), url = new URL(req.url, 'http://127.0.0.1'), form = new URLSearchParams(body);
      const call = { method: req.method, path: url.pathname, query: url.searchParams, body, form, headers: req.headers }; calls.push(call);
      if (state.hook && await state.hook(call, req, res)) return;
      if (![TOKEN, ROTATED].some(token => req.headers.authorization === `Bearer ${token}`)) { res.writeHead(401); res.end(); return; }
      const wanted = form.get('expected_head') ?? url.searchParams.get('expected_head');
      if (wanted && wanted !== state.head) { res.writeHead(409); res.end(); return; }
      let result, status = 200;
      if (url.pathname.endsWith('/api/v1/pulls')) {
        const after = Number(url.searchParams.get('after')), limit = Number(url.searchParams.get('limit'));
        const selected = state.rows.filter(r => r.number > after).sort((a, b) => a.number - b.number), rows = selected.slice(0, limit);
        result = { ...header(), type: 'pull_request_page', after, limit, pull_requests: rows,
          next_after: selected.length > limit ? rows.at(-1).number : null };
      } else if (/\/pulls\/[0-9]+$/.test(url.pathname)) {
        const number = Number(url.pathname.split('/').at(-1)), selected = state.rows.find(r => r.number === number);
        result = { ...header(), type: 'pull_request', number, found: !!selected, pull_request: selected ?? null }; status = selected ? 200 : 404;
      } else if (url.pathname.endsWith('/source/refs')) {
        const after = form.get('after'), limit = Number(form.get('limit'));
        const selected = [...state.tips].sort((a, b) => Buffer.compare(Buffer.from(a[0]), Buffer.from(b[0])))
          .filter(([name]) => after === null || Buffer.compare(Buffer.from(name), Buffer.from(after)) > 0);
        const rows = selected.slice(0, limit).map(([name, oid]) => ({ ref: name, ref_hex: hex(name), object_id: `${format}:${oid}` }));
        result = { ...header(), type: 'source_refs', namespace: 'branches', after, limit, next_after: selected.length > limit ? rows.at(-1).ref : null,
          read_only: true, transaction_created: false, published: false, direct_refs_only: true, refs: rows };
      } else if (/\/pulls\/[0-9]+\/update$/.test(url.pathname)) {
        const number = Number(url.pathname.split('/').at(-2)), key = req.headers['idempotency-key'], old = decisions.get(key);
        if (old && old.body !== body) { res.writeHead(422); res.end(); return; }
        if (old) { result = old.reply; status = result.outcome === 'committed' ? 200 : 409; }
        else {
          const selected = state.rows.find(r => r.number === number), version = Number(form.get('expected_version'));
          const refused = state.refuse || !selected || selected.state !== 'open' || selected.version !== version ||
            form.get('source_tip') !== state.tips.get(form.get('source_ref')) || form.get('target_tip') !== state.tips.get(form.get('target_ref'));
          result = { ...header(), type: 'pull_request_publication', principal_id: ACTOR, number, expected_version: version, action: 'update',
            tx_id: `fixture-tx-${hash(key)}`, outcome: refused ? 'refused' : 'committed', decision_sequence: '18446744073709551615',
            repository_commit_id: refused ? null : `fixture-rcr-${hash(key)}`, refusal_record_id: refused ? `fixture-refusal-${hash(key)}` : null,
            refusal_code: refused ? 'TargetRefMoved' : null, refusal_code_point: refused ? 7 : null, delivery_acknowledged: null };
          delete result.source_head; delete result.snapshot_token;
          decisions.set(key, { body, reply: result });
          if (!refused) { selected.version++; for (const field of ['title', 'body', 'source_ref', 'target_ref', 'source_tip', 'target_tip']) selected.data[field] = form.get(field); }
          status = refused ? 409 : 200;
        }
        if (state.drop === true || state.drop === number) { req.socket.destroy(); return; }
      } else if (url.pathname.endsWith('/outcomes')) {
        const key = req.headers['idempotency-key'], known = decisions.get(key)?.reply;
        const transaction = known ? { tx_id: known.tx_id, seal_id: `fixture-seal-${hash(key)}`, request_schema: 'fixture-native-pr-update',
          canonical_request_digest: { algorithm: 2, hex: hash(key) } } : null;
        result = { type: 'transaction_outcome', schema_version: 1, tenant_id: dest.tenant_id, repository_id: dest.repository_id,
          repository_incarnation: dest.repository_incarnation, principal_id: ACTOR, selector: 'transaction', command_index: null,
          state: known?.outcome ?? 'key_not_observed', terminal: !!known, transaction,
          decision: !known ? null : known.outcome === 'committed' ? { kind: 'committed', decision_sequence: known.decision_sequence, repository_commit_id: known.repository_commit_id }
            : { kind: 'refused', decision_sequence: known.decision_sequence, code: known.refusal_code, code_point: known.refusal_code_point, refusal_record_id: known.refusal_record_id },
          read_only: true, request_reexecuted: false, absence_proves_non_commit: false, session_completeness_established: false };
      } else { res.writeHead(404); res.end(); return; }
      result = structuredClone(result); await state.mutate?.(result, call);
      if (state.delay) await new Promise(resolve => setTimeout(resolve, state.delay));
      const json = JSON.stringify(result).replace(/"decision_sequence":"([0-9]+)"/g, '"decision_sequence":$1');
      res.writeHead(status, { 'Content-Type': 'application/json' }); res.end(json);
    } catch (error) { res.writeHead(500); res.end(JSON.stringify({ fixture_error: error.message })); }
  });
  server.on('connection', socket => { sockets.add(socket); socket.on('close', () => sockets.delete(socket)); });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve)); dest.endpoint = `http://127.0.0.1:${server.address().port}/team/repo.git`;
  t.after(async () => { for (const s of sockets) s.destroy(); await new Promise(resolve => server.close(resolve)); });
  return { dest, state, calls, decisions, header, server };
}
