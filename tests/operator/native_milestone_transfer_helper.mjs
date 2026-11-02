// HTTP response-schema peer, NOT a Rust fg authority. Production operators,
// clients, sockets, pinned archive traversal and private custody run unchanged.
import { createServer } from 'node:http';
import { once } from 'node:events';
import { randomBytes } from 'node:crypto';
import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { exportIssueArchive } from '../../scripts/lib/forge-issue-archive.mjs';
import { snapshot as oldSnapshot, tenant, repository, actor, head, encode }
  from './native_issue_transfer_helper.mjs';
export { tenant, repository, actor, head, encode };

export function issueSnapshot(row) {
  const result = oldSnapshot(row); result.milestone = null;
  for (const { action } of row.events) {
    if (action.name === 'set-milestone') result.milestone = action.milestone;
    if (action.name === 'clear-milestone') result.milestone = null;
  }
  return result;
}
export function milestoneSnapshot(row, issues = []) {
  let state;
  for (const event of row.events) {
    const a = event.action;
    if (a.name === 'open') state = { number: row.number, version: 0, title: a.title, body: a.body,
      due_at: a.due_at ?? null, state: 'open', opened_by: event.actor, last_actor: event.actor };
    if (a.name === 'edit') for (const key of ['title', 'body', 'due_at']) if (Object.hasOwn(a, key)) state[key] = a[key];
    if (a.name === 'close' || a.name === 'reopen') state.state = a.name === 'close' ? 'closed' : 'open';
    state.version = event.version; state.last_actor = event.actor;
  }
  state.open_issues = 0; state.closed_issues = 0;
  for (const issue of issues) {
    const current = issueSnapshot(issue);
    if (current.milestone === row.number) state[current.state === 'open' ? 'open_issues' : 'closed_issues']++;
  }
  return structuredClone(state);
}
const events = actions => actions.map((action, i) => ({ version: i + 1,
  actor: i % 2 ? '7'.repeat(32) : actor, action }));
export function fixtureMilestones() {
  return [
    { number: 1, events: events([{ name: 'open', title: 'First release', body: 'Original release 雪.', due_at: 0 },
      { name: 'edit', body: 'Edited release <script> & text.\r\n', due_at: 253402300799 }, { name: 'close' }]) },
    { number: 2, events: events([{ name: 'open', title: 'Next release', body: 'Another release', due_at: null },
      { name: 'edit', due_at: 42 }, { name: 'close' }, { name: 'reopen' }, { name: 'edit', due_at: null }]) },
    { number: 3, events: events([{ name: 'open', title: 'Unreferenced release', body: 'Preserve this too.', due_at: 1 }]) },
  ];
}
export function fixtureMilestoneIssues() {
  const open = number => ({ name: 'open', title: `Issue ${number}`, body: `Original body ${number}`, labels: ['plan'] });
  return [
    { number: 1, events: events([open(1), { name: 'comment', body: 'Literal discussion \r\n & <script> 雪.' },
      { name: 'set-milestone', milestone: 1, expected_milestone_version: 2 }, { name: 'close' }, { name: 'lock' }]) },
    { number: 2, events: events([open(2), { name: 'set-milestone', milestone: 2, expected_milestone_version: 2 },
      { name: 'clear-milestone' }, { name: 'comment', body: 'The historical membership is preserved in the archive.' }]) },
    { number: 3, events: events([open(3), { name: 'set-milestone', milestone: 2, expected_milestone_version: 4 }]) },
    { number: 4, events: events([open(4)]) },
  ];
}
export async function milestonePeer({ rows = [], milestones = [], tenantId = tenant, repositoryId = repository,
  fault, afterMutation } = {}) {
  const token = randomBytes(32).toString('hex'), calls = [], decisions = new Map();
  const source = new Map(rows.map(row => [row.number, structuredClone(row)]));
  const milestoneSource = new Map(milestones.map(row => [row.number, structuredClone(row)]));
  const common = { schema_version: 1, tenant_id: tenantId, repository_id: repositoryId };
  let sequence = 0;
  const server = createServer(async (req, res) => {
    try {
      const chunks = []; for await (const chunk of req) chunks.push(chunk);
      const body = Buffer.concat(chunks).toString(), url = new URL(req.url, 'http://127.0.0.1');
      const key = req.headers['idempotency-key'];
      const call = { method: req.method, path: url.pathname, query: url.searchParams, body, key }; calls.push(call);
      const send = (value, status = 200) => { res.writeHead(status, { 'Content-Type': 'application/json' }); res.end(encode(value)); };
      if (req.headers.authorization !== `Bearer ${token}`) return send({}, 401);
      if (fault && await fault({ req, res, call, decisions, send, source, milestoneSource })) return;
      if (url.pathname.endsWith('/outcomes')) {
        const d = decisions.get(key);
        return send({ ...common, type: 'transaction_outcome', selector: 'transaction', command_index: null,
          read_only: true, request_reexecuted: false, absence_proves_non_commit: false, session_completeness_established: false,
          repository_incarnation: '8'.repeat(32), principal_id: actor, state: d?.outcome ?? 'key_not_observed',
          terminal: Boolean(d), transaction: d ? { tx_id: d.tx_id } : null,
          decision: d ? { kind: d.outcome, decision_sequence: d.decision_sequence,
            repository_commit_id: d.repository_commit_id, refusal_record_id: d.refusal_record_id, code: d.refusal_code } : null });
      }
      const match = /\/api\/v1\/(issues|milestones)(?:\/(\d+))?(?:\/([a-z-]+))?$/.exec(url.pathname);
      if (!match) return send({}, 404);
      const milestone = match[1] === 'milestones', family = milestone ? 'milestone' : 'issue';
      const collection = milestone ? milestoneSource : source;
      const number = match[2] ? Number(match[2]) : null, action = match[3];
      const snapshot = row => milestone ? milestoneSnapshot(row, source.values()) : issueSnapshot(row);
      if (req.method === 'GET') {
        const limit = Number(url.searchParams.get('limit'));
        if (url.searchParams.has('expected_head') && url.searchParams.get('expected_head') !== head) return send({}, 409);
        const base = { ...common, source_head: 'native-fixture-head', snapshot_token: head,
          scope: milestone ? 'repository_milestones' : 'repository_issues', limit };
        if (number === null) {
          const after = Number(url.searchParams.get('after'));
          const all = [...collection.values()].filter(row => row.number > after).sort((a, b) => a.number - b.number);
          const selected = all.slice(0, limit);
          return send({ ...base, type: `${family}_page`, after, [match[1]]: selected.map(snapshot),
            next_after: all.length > selected.length ? selected.at(-1).number : null });
        }
        const after = Number(url.searchParams.get('after_version')), row = collection.get(number);
        const chosen = row?.events.slice(after, after + limit) ?? [];
        return send({ ...base, type: `${family}_history`, after_version: after, found: Boolean(row),
          [family]: row ? snapshot(row) : null, events: chosen,
          next_after_version: row && row.events.length > after + chosen.length ? after + chosen.length : null }, row ? 200 : 404);
      }
      if (req.method !== 'POST' || !action || !key || number === null) return send({}, 400);
      if (decisions.has(key)) { const d = decisions.get(key); return send(d, d.outcome === 'committed' ? 200 : 409); }
      const form = new URLSearchParams(body), expected = Number(form.get('expected_version')), row = collection.get(number);
      const current = row ? snapshot(row) : null;
      let refusal = expected !== (row?.events.length ?? 0) || (action === 'open') !== !row ? 'EvidenceStale' : null;
      if (!refusal && ['close', 'reopen'].includes(action) && current?.state === (action === 'close' ? 'closed' : 'open')) refusal = 'ProtectedRefTransitionDenied';
      if (!milestone && !refusal) {
        if (action === 'comment' && current?.locked || action === 'lock' && current?.locked || action === 'unlock' && !current?.locked) refusal = 'ProtectedRefTransitionDenied';
        if (action === 'set-milestone') {
          const selected = milestoneSource.get(Number(form.get('milestone')));
          const selectedState = selected ? milestoneSnapshot(selected) : null;
          if (!selectedState || selectedState.version !== Number(form.get('expected_milestone_version'))) refusal = 'EvidenceStale';
          else if (selectedState.state !== 'open') refusal = 'ProtectedRefTransitionDenied';
        }
      }
      const committed = refusal === null;
      const decision = { ...common, type: `${family}_publication`, number, expected_version: expected, action,
        outcome: committed ? 'committed' : 'refused', delivery_acknowledged: null, principal_id: actor,
        tx_id: `fixture-tx-${++sequence}`, decision_sequence: sequence, repository_commit_id: committed ? `fixture-rcr-${sequence}` : null,
        refusal_record_id: committed ? null : `fixture-refusal-${sequence}`, refusal_code: refusal };
      decisions.set(key, decision);
      if (committed) {
        const a = { name: action };
        for (const field of ['title', 'body']) if (form.has(field)) a[field] = form.get(field);
        if (milestone) {
          if (action === 'open' || form.has('due_at') || form.has('clear_due_at')) a.due_at = form.has('due_at') ? Number(form.get('due_at')) : null;
        } else {
          if (action === 'open' || form.has('label') || form.has('clear_labels')) a.labels = form.getAll('label');
          if (action === 'set-milestone') for (const field of ['milestone', 'expected_milestone_version']) a[field] = Number(form.get(field));
        }
        const target = row ?? { number, events: [] }; collection.set(number, target);
        target.events.push({ version: expected + 1, actor, action: a });
      }
      if (afterMutation && await afterMutation({ req, res, call, decision })) return;
      send(decision, committed ? 200 : 409);
    } catch (error) { res.destroy(error); }
  });
  server.listen(0, '127.0.0.1'); await once(server, 'listening');
  return { href: `http://127.0.0.1:${server.address().port}/repository/ui/issues/`, token, calls, source, milestoneSource, decisions,
    async close() { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); } };
}
export async function setupMilestones(t, { rows = fixtureMilestoneIssues(), milestones = fixtureMilestones(), ...options } = {}) {
  const root = await mkdtemp(join(tmpdir(), 'fg-native-milestone-transfer-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const src = await milestonePeer({ rows, milestones }); t.after(() => src.close());
  const tokenFile = join(root, 'source-token'); await writeFile(tokenFile, src.token, { mode: 0o600 });
  const archiveDir = join(root, 'archive');
  const archive = await exportIssueArchive({ workdir: archiveDir, href: src.href, tenant, repository, tokenFile,
    includeMilestones: true, ...options });
  return { root, archiveDir, archive, src, tokenFile };
}
