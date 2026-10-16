// Response-schema peer, NOT Rust fg. Production client/custody runs unchanged.
import { createServer } from 'node:http';
import { once } from 'node:events';
import { randomBytes } from 'node:crypto';
import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { exportIssueArchive } from '../../scripts/lib/forge-issue-archive.mjs';
export const tenant = '1'.repeat(32), repository = '2'.repeat(32), actor = '3'.repeat(32);
export const destinationTenant = '4'.repeat(32), destinationRepository = '5'.repeat(32);
export const head = `alg:2:${'a'.repeat(64)}`;
export const encode = value => Buffer.from(JSON.stringify(value) + '\n');
export function fixtureIssues(count = 3) {
  return Array.from({ length: count }, (_, i) => {
    const actions = [{ name: 'open', title: `Issue ${i + 1}`, body: `Original ${i + 1}`, labels: ['bug'] }];
    if (i % 3 === 0) actions.push({ name: 'comment', body: 'A discussion\r\nwith <script> and Unicode 雪.' },
      { name: 'edit', title: 'Edited title', body: 'Current body', labels: ['done'] },
      { name: 'assign', assignees: ['6'.repeat(32)] }, { name: 'close' });
    return { number: i + 1, events: actions.map((action, index) => ({ version: index + 1,
      actor: index % 2 ? '7'.repeat(32) : actor, action })) };
  });
}
export function snapshot(row) {
  let state;
  for (const event of row.events) {
    const a = event.action;
    if (a.name === 'open') state = { number: row.number, version: 0, title: a.title, body: a.body,
      labels: a.labels ?? [], state: 'open', opened_by: event.actor, last_actor: event.actor, comments: 0, assignees: [] };
    if (a.name === 'edit') for (const field of ['title', 'body', 'labels']) if (field in a) state[field] = a[field];
    if (a.name === 'comment') state.comments++;
    if (a.name === 'close') state.state = 'closed';
    if (a.name === 'reopen') state.state = 'open';
    if (a.name === 'assign') state.assignees = [...new Set([...state.assignees, ...a.assignees])].sort();
    if (a.name === 'unassign') state.assignees = state.assignees.filter(x => !a.assignees.includes(x));
    state.version = event.version; state.last_actor = event.actor;
  }
  return structuredClone(state);
}
export async function peer({ rows = [], tenantId = tenant, repositoryId = repository, fault, afterMutation } = {}) {
  const token = randomBytes(32).toString('hex'), calls = [], decisions = new Map();
  const source = new Map(rows.map(row => [row.number, structuredClone(row)]));
  let sequence = 0;
  const common = { schema_version: 1, tenant_id: tenantId, repository_id: repositoryId };
  const server = createServer(async (req, res) => {
    try {
      const chunks = []; for await (const bytes of req) chunks.push(bytes);
      const body = Buffer.concat(chunks).toString();
      const url = new URL(req.url, 'http://127.0.0.1'), key = req.headers['idempotency-key'];
      const call = { method: req.method, path: url.pathname, query: url.searchParams, body, key };
      calls.push(call);
      const send = (value, status = 200) => { res.writeHead(status, { 'Content-Type': 'application/json' }); res.end(encode(value)); };
      if (req.headers.authorization !== `Bearer ${token}`) return send({}, 401);
      if (fault && await fault({ req, res, call, decisions, send })) return;
      if (url.pathname.endsWith('/outcomes')) {
        const d = decisions.get(key);
        return send({ ...common, type: 'transaction_outcome', selector: 'transaction', command_index: null,
          read_only: true, request_reexecuted: false, absence_proves_non_commit: false, session_completeness_established: false,
          repository_incarnation: '8'.repeat(32), principal_id: actor, state: d?.outcome ?? 'key_not_observed',
          terminal: Boolean(d), transaction: d ? { tx_id: d.tx_id } : null,
          decision: d ? { kind: d.outcome, decision_sequence: d.decision_sequence,
            repository_commit_id: d.repository_commit_id, refusal_record_id: d.refusal_record_id, code: d.refusal_code } : null });
      }
      const match = /\/api\/v1\/issues(?:\/(\d+))?(?:\/(\w+))?$/.exec(url.pathname);
      if (!match) return send({}, 404);
      const number = match[1] ? Number(match[1]) : null, action = match[2];
      if (req.method === 'GET') {
        const limit = Number(url.searchParams.get('limit'));
        if (url.searchParams.has('expected_head') && url.searchParams.get('expected_head') !== head) return send({}, 409);
        const base = { ...common, source_head: 'native-fixture-head', snapshot_token: head, limit };
        if (number === null) {
          const after = Number(url.searchParams.get('after')), all = [...source.values()].filter(r => r.number > after).sort((a, b) => a.number - b.number);
          const chosen = all.slice(0, limit);
          return send({ ...base, type: 'issue_page', after, issues: chosen.map(snapshot),
            next_after: all.length > chosen.length ? chosen.at(-1).number : null });
        }
        const after = Number(url.searchParams.get('after_version')), row = source.get(number);
        const events = row?.events.slice(after, after + limit) ?? [];
        return send({ ...base, type: 'issue_history', requested_number: number, after_version: after,
          found: Boolean(row), issue: row ? snapshot(row) : null, events,
          next_after_version: row && row.events.length > after + events.length ? after + events.length : null }, row ? 200 : 404);
      }
      if (req.method !== 'POST' || !action || !key) return send({}, 400);
      const old = decisions.get(key);
      if (old) return send(old, old.outcome === 'committed' ? 200 : 409);
      const form = new URLSearchParams(body), expected = Number(form.get('expected_version')), row = source.get(number);
      const committed = expected === (row?.events.length ?? 0) && (action === 'open') === !row;
      const d = { ...common, type: 'issue_publication', number, expected_version: expected, action,
        outcome: committed ? 'committed' : 'refused', delivery_acknowledged: null, principal_id: actor,
        tx_id: `fixture-tx-${++sequence}`, decision_sequence: sequence, repository_commit_id: committed ? `fixture-rcr-${sequence}` : null,
        refusal_record_id: committed ? null : `fixture-refusal-${sequence}`, refusal_code: committed ? null : 'expected_version' };
      decisions.set(key, d);
      if (committed) {
        const a = { name: action };
        for (const field of ['title', 'body']) if (form.has(field)) a[field] = form.get(field);
        if (action === 'open' || form.has('label')) a.labels = form.getAll('label');
        const target = row ?? { number, events: [] }; source.set(number, target);
        target.events.push({ version: expected + 1, actor, action: a });
      }
      if (afterMutation && await afterMutation({ req, res, call, decision: d })) return;
      send(d, committed ? 200 : 409);
    } catch (error) { res.destroy(error); }
  });
  server.listen(0, '127.0.0.1'); await once(server, 'listening');
  return { href: `http://127.0.0.1:${server.address().port}/repository/ui/issues/`, token, calls, source, decisions,
    async close() { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); } };
}
export async function setup(t, rows = fixtureIssues(), options = {}) {
  const root = await mkdtemp(join(tmpdir(), 'fg-native-transfer-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const src = await peer({ rows }); t.after(() => src.close());
  const tokenFile = join(root, 'source-token'); await writeFile(tokenFile, src.token, { mode: 0o600 });
  const archiveDir = join(root, 'archive');
  const archive = await exportIssueArchive({ workdir: archiveDir, href: src.href, tenant, repository, tokenFile, ...options });
  return { root, archiveDir, archive, src };
}
