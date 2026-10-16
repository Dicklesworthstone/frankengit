// Explicit native HTTP response-schema peer. It is NOT fg/admission/Git/CAS.
import { createServer } from 'node:http';
import { mkdtemp, chmod, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHash } from 'node:crypto';
import { exportPullArchive } from '../../scripts/lib/forge-pull-archive.mjs';
export const SRC = { tenant_id: '11'.repeat(16), repository_id: '22'.repeat(16), repository_incarnation: '33'.repeat(16) };
export const DST = { tenant_id: 'aa'.repeat(16), repository_id: 'bb'.repeat(16), repository_incarnation: 'cc'.repeat(16), principal_id: 'dd'.repeat(16) };
export const TOKEN = 'ee'.repeat(32), HEAD = 'alg:2:' + '66'.repeat(32), ACTOR = '44'.repeat(16);
const hex = s => Buffer.from(s).toString('hex');
const hash = s => createHash('sha256').update(s).digest('hex');
export function row(number, format = 'sha1', state = 'open') {
  const oid = c => `${format}:${c.repeat(format === 'sha1' ? 40 : 64)}`;
  const data = { object_format: format, source_ref: `refs/heads/topic-${number}`, source_ref_hex: hex(`refs/heads/topic-${number}`),
    target_ref: 'refs/heads/main', target_ref_hex: hex('refs/heads/main'), source_tip: oid('a'), target_tip: oid('b'),
    title: `Pull ${number}`, body: `Original body ${number}\r\n雪\n` };
  return { number, version: 7, state, merge_only: false, data, opened_by: ACTOR, last_metadata_actor: ACTOR,
    merge: state !== 'merged' ? null : { object_format: format, source_ref: data.source_ref, source_ref_hex: data.source_ref_hex,
      target_ref: data.target_ref, target_ref_hex: data.target_ref_hex, source_tip: data.source_tip,
      target_tip_before: data.target_tip, base_tip: oid('c'), merge_commit: oid('d') } };
}
export async function importFixture(t, { format = 'sha1', rows = [row(1, format), row(9, format, 'closed')],
  comments = 2, reviews = 1, modify = null, drop = null, refuse = null, mutate = null } = {}) {
  const root = await mkdtemp(join(tmpdir(), 'fg-native-pull-import-')); await chmod(root, 0o700);
  const tokenFile = join(root, 'token'); await writeFile(tokenFile, TOKEN + '\n', { mode: 0o600 });
  const scope = { ...DST, object_format: format }, requests = [], outcomes = new Map(), pulls = new Map(), sockets = new Set();
  let sequence = 0;
  const common = () => ({ schema_version: 1, ...SRC, object_format: format, source_head: 'source-head-1', snapshot_token: HEAD });
  const send = (res, status, value) => { res.writeHead(status, { 'content-type': 'application/json' });
    // Match Rust's unquoted u64 spellings, including above Number.MAX_SAFE_INTEGER.
    res.end(JSON.stringify(value).replace(/"(number|expected_version|comment_version|decision_sequence)":"([0-9]+)"/g, '"$1":$2')); };
  function outcome(key) {
    const terminal = outcomes.get(key);
    return { type: 'transaction_outcome', schema_version: 1, ...DST, selector: 'transaction', command_index: null,
      state: terminal?.outcome ?? 'key_not_observed', terminal: Boolean(terminal),
      transaction: terminal ? { tx_id: terminal.tx_id, seal_id: `seal-${terminal.decision_sequence}`, request_schema: 'native-pr-v1',
        canonical_request_digest: { algorithm: 2, hex: terminal.body_sha256 } } : null,
      decision: terminal ? { kind: terminal.outcome, decision_sequence: terminal.decision_sequence,
        ...(terminal.outcome === 'committed' ? { repository_commit_id: terminal.repository_commit_id }
          : { code: terminal.refusal_code, code_point: terminal.refusal_code_point, refusal_record_id: terminal.refusal_record_id }) } : null,
      read_only: true, request_reexecuted: false, absence_proves_non_commit: false, session_completeness_established: false };
  }
  const server = createServer(async (req, res) => {
    try {
      const url = new URL(req.url, 'http://127.0.0.1'), parts = url.pathname.split('/'), query = url.searchParams;
      const chunks = []; for await (const chunk of req) chunks.push(chunk); const body = Buffer.concat(chunks).toString();
      const request = { path: url.pathname, method: req.method, key: req.headers['idempotency-key'], body, head: query.get('expected_head') };
      requests.push(request);
      if (req.headers.authorization !== `Bearer ${TOKEN}`) { send(res, 401, {}); return; }
      if (parts[1] === 'source') {
        if (req.method !== 'GET' || request.key || body) throw new Error('source is read only');
        const n = Number(parts[5]), selected = rows.find(r => r.number === n), kind = parts[6] ?? (parts[5] ? 'show' : 'list');
        const limit = Number(query.get('limit') ?? 20), after = kind === 'reviews' ? query.get('after') : Number(query.get('after') ?? 0);
        if (request.head !== null && request.head !== HEAD) { send(res, 409, {}); return; }
        let reply;
        if (kind === 'list') { const rest = rows.filter(r => r.number > after), page = rest.slice(0, limit);
          reply = { ...common(), type: 'pull_request_page', after, limit, pull_requests: page, next_after: rest.length > limit ? page.at(-1).number : null }; }
        else if (kind === 'show') reply = { ...common(), type: 'pull_request', number: n, found: true, pull_request: selected };
        else if (kind === 'reviews') {
          const data = selected.data ?? row(n, format).data;
          const all = Array.from({ length: reviews }, (_, i) => ({ reviewer: (i + 1).toString(16).padStart(32, '0'), version: 3,
            subject: { number: n, pull_request_version: selected.version, policy_epoch: 5, source_ref: data.source_ref,
              source_ref_hex: data.source_ref_hex, target_ref: data.target_ref, target_ref_hex: data.target_ref_hex,
              source_tip: data.source_tip, target_tip: data.target_tip }, candidate: null, decision: 'approve', freshness: 'current',
            reviewer_is_opener: false, reason: `Source review ${i}` }));
          const rest = all.filter(r => after === null || r.reviewer > after), page = rest.slice(0, limit);
          reply = { ...common(), type: 'review_page', number: n, found: true, merge_authorized: false,
            pull_request_version: selected.version, policy_epoch: 5, after, limit, reviews: page,
            next_after: rest.length > limit ? page.at(-1).reviewer : null };
        } else if (kind === 'comments') {
          const page = Array.from({ length: Math.min(Math.max(comments - after, 0), limit) }, (_, i) => ({
            version: after + i + 1, actor: ACTOR, body: `Original comment ${after + i + 1}\r\n`, body_rendered: null }));
          const next = after + page.length < comments ? after + page.length : null;
          reply = { ...common(), type: 'pull_request_comments', number: n, found: true, discussion_version: comments,
            after, limit, next_after: next, complete: next === null, merge_permission: null, transaction_created: false, comments: page };
        } else throw new Error('unknown source endpoint');
        modify?.(reply, kind); send(res, 200, reply); return;
      }
      if (parts[1] !== 'dest' || req.method !== 'POST' || !request.key) throw new Error('unexpected destination request');
      if (parts[4] === 'outcomes') { if (body) throw new Error('outcome body'); const result = outcome(request.key);
        if (await mutate?.(request, res, result) === false) return; send(res, 200, result); return; }
      const number = parts[5], action = parts[6] === 'comments' ? 'comment' : parts[6], f = Object.fromEntries(new URLSearchParams(body));
      if (!['open', 'close', 'comment'].includes(action)) throw new Error('migration escalated authority');
      let receipt = outcomes.get(request.key);
      if (receipt && receipt.body_sha256 !== hash(body)) throw new Error('changed original key body');
      if (!receipt) {
        const previous = pulls.get(number);
        const bad = refuse?.({ number, action, f }) || (action === 'open' ? Boolean(previous) || f.expected_version !== '0'
          : !previous || (action === 'comment' ? f.expected_version !== String(previous.comments.length) : f.expected_version !== String(previous.version)));
        const seq = String(++sequence), committed = !bad;
        receipt = { type: action === 'comment' ? 'pull_request_comment_publication' : 'pull_request_publication',
          schema_version: 1, ...scope, number, action, tx_id: `tx-${seq}`, outcome: committed ? 'committed' : 'refused',
          decision_sequence: seq, repository_commit_id: committed ? `rcr-${seq}` : null,
          refusal_record_id: committed ? null : `refusal-${seq}`, refusal_code: committed ? null : 'ExpectedVersionMismatch',
          refusal_code_point: committed ? null : 42, delivery_acknowledged: null, expected_version: f.expected_version,
          ...(action === 'comment' ? { comment_version: committed ? String(BigInt(f.expected_version) + 1n) : null, refs_changed: false } : {}) };
        if (committed) {
          if (action === 'open') pulls.set(number, { fields: f, version: 1, state: 'open', comments: [] });
          else if (action === 'comment') previous.comments.push(f.body);
          else { previous.state = 'closed'; previous.version++; }
        }
        outcomes.set(request.key, { ...receipt, body_sha256: hash(body) });
      }
      const { body_sha256, ...publicReceipt } = receipt;
      if (drop?.(request, publicReceipt)) { req.socket.destroy(); return; }
      if (await mutate?.(request, res, publicReceipt) === false) return;
      send(res, publicReceipt.outcome === 'committed' ? 200 : 409, publicReceipt);
    } catch (e) { if (!res.headersSent) send(res, 500, { error: e.message }); else res.destroy(); }
  });
  server.on('connection', socket => { sockets.add(socket); socket.on('close', () => sockets.delete(socket)); });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(async () => { for (const socket of sockets) socket.destroy(); await new Promise(resolve => server.close(resolve)); await rm(root, { recursive: true, force: true }); });
  const base = `http://127.0.0.1:${server.address().port}`, archiveDir = join(root, 'archive'), workdir = join(root, 'migration');
  const archived = await exportPullArchive({ workdir: archiveDir, href: base + '/source/ui/pulls/', tenant: SRC.tenant_id,
    repository: SRC.repository_id, tokenFile, pageSize: 1 });
  const selection = { endpoint: base + '/dest', scope, number_start: '100' };
  return { root, tokenFile, scope, requests, outcomes, pulls, rows, archiveDir, archiveConfirm: archived.archive_sha256,
    workdir, selection, prepare: { workdir, archiveDir, archiveConfirm: archived.archive_sha256, selection, tokenFile } };
}
