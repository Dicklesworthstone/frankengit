// Deliberately simulated native authority: the shipped DiscussionClient, real
// HTTP sockets, private filesystem and CLI execute, but no Rust node does.
import { createServer } from 'node:http';
import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { spawn } from 'node:child_process';
import { listenForFetch } from '../fetch-peer.mjs';

export const tenant = '11'.repeat(16), repository = '22'.repeat(16), token = 'ab'.repeat(32);
export const actor = '33'.repeat(16);
const cli = resolve('scripts/forge_discussions.mjs');
const snapshot = n => `alg:2:${(n + 1).toString(16).padStart(64, '0')}`;
export const mutations = fixture => fixture.calls.filter(call => call.method === 'POST' && /\/discussions\/\d+\//.test(call.path));

export async function discussionPeer(t) {
  const root = await mkdtemp(join(tmpdir(), 'fg-discussion-operator-'));
  const tokenFile = join(root, 'token'); await writeFile(tokenFile, token + '\n', { mode: 0o600 });
  const f = { root, tokenFile, mode: null, sequence: 0, rows: new Map(), histories: new Map(), snapshots: new Map(),
    calls: [], decisions: new Map(), onMutation: null, allowRead: true, allowWrite: true, allowOutcome: true };
  f.save = () => { f.head = snapshot(f.sequence); f.snapshots.set(f.head, structuredClone({ rows: f.rows, histories: f.histories })); };
  f.apply = (number, action, fields = {}, principal = actor) => {
    let row = f.rows.get(number);
    if (action === 'open') {
      row = { number, version: 0, title: fields.title, body: fields.body, state: 'open', locked: false,
        opened_by: principal, last_actor: principal, comments: 0 };
      f.rows.set(number, row); f.histories.set(number, []);
    }
    row.version++; row.last_actor = principal;
    if (action === 'edit') for (const key of ['title', 'body']) if (Object.hasOwn(fields, key)) row[key] = fields[key];
    if (['comment', 'append-comment'].includes(action)) row.comments++;
    if (['close', 'reopen'].includes(action)) row.state = action === 'close' ? 'closed' : 'open';
    if (['lock', 'unlock'].includes(action)) row.locked = action === 'lock';
    f.histories.get(number).push({ version: row.version, actor: principal,
      action: { name: action === 'append-comment' ? 'comment' : action, ...fields } });
    f.sequence++; f.save();
  };
  f.seed = (number = 1, title = `Discussion ${number}`, body = 'Original discussion') => f.apply(number, 'open', { title, body });
  f.save();
  const common = () => ({ schema_version: 1, tenant_id: f.mode === 'wrong-identity' ? 'ff'.repeat(16) : tenant,
    repository_id: repository });
  const server = createServer(async (req, res) => {
    let body = ''; for await (const chunk of req) body += chunk;
    const url = new URL(req.url, 'http://localhost'), key = req.headers['idempotency-key'];
    f.calls.push({ method: req.method, path: url.pathname, query: url.searchParams, body, key,
      authorization: req.headers.authorization, userAgent: req.headers['user-agent'] });
    const reply = (status, value) => { res.writeHead(status, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(value)); };
    if (req.headers.authorization !== `Bearer ${token}` || f.mode === 'unauthorized') return reply(401, {});
    if (f.mode === 'redirect') { res.writeHead(307, { Location: '/untrusted' }); return res.end(); }
    if (url.pathname === '/repo/api/v1/outcomes' && req.method === 'POST') {
      if (!f.allowOutcome) return reply(403, {});
      const decision = f.decisions.get(key), state = decision?.outcome ?? 'key_not_observed';
      return reply(200, { type: 'transaction_outcome', ...common(), repository_incarnation: '44'.repeat(16), principal_id: actor,
        selector: 'transaction', command_index: null, read_only: true, request_reexecuted: false,
        absence_proves_non_commit: false, session_completeness_established: false, terminal: Boolean(decision), state,
        transaction: decision ? { tx_id: decision.tx_id } : null,
        decision: decision ? { kind: state, decision_sequence: decision.decision_sequence,
          repository_commit_id: decision.repository_commit_id, refusal_record_id: decision.refusal_record_id,
          code: decision.refusal_code } : null });
    }
    const selected = url.searchParams.get('expected_head') ?? f.head, view = f.snapshots.get(selected);
    if (req.method === 'GET' && /^\/repo\/api\/v1\/discussions(?:\/\d+)?$/.test(url.pathname)) {
      if (!f.allowRead) return reply(403, {});
      if (!view) return reply(409, {});
      const head = f.mode === 'wrong-head' ? snapshot(1000) : selected;
      const shared = { ...common(), scope: f.mode === 'wrong-family' ? 'repository_issues' : 'repository_discussions', snapshot_token: head };
      const limit = Number(url.searchParams.get('limit'));
      if (url.pathname === '/repo/api/v1/discussions') {
        const after = Number(url.searchParams.get('after'));
        const all = [...view.rows.values()].filter(row => row.number > after).sort((a, b) => a.number - b.number);
        const rows = structuredClone(all.slice(0, limit));
        if (f.mode === 'extra-fields' && rows.length) rows[0].unvalidated_extension = 'must not be returned';
        return reply(200, { type: 'discussion_page', ...shared, after, limit, discussions: rows,
          next_after: all.length > rows.length ? rows.at(-1).number : null });
      }
      const number = Number(url.pathname.split('/').at(-1)), row = view.rows.get(number) ?? null;
      const after = Number(url.searchParams.get('after_version')), history = view.histories.get(number) ?? [];
      const events = structuredClone(history.slice(after, after + limit));
      if (f.mode === 'corrupt-tail' && after && events.length) events[0].version++;
      return reply(row ? 200 : 404, { type: 'discussion_history', ...shared, after_version: after, limit,
        found: Boolean(row), discussion: row, events,
        next_after_version: history.length > after + events.length ? after + events.length : null });
    }
    const match = /^\/repo\/api\/v1\/discussions\/([1-9][0-9]*)\/(open|edit|comment|append-comment|close|reopen|lock|unlock)$/.exec(url.pathname);
    if (req.method !== 'POST' || !match) return reply(404, {});
    if (!f.allowWrite) return reply(403, {});
    f.onMutation?.({ key, body });
    const number = Number(match[1]), action = match[2], form = new URLSearchParams(body), append = action === 'append-comment';
    if (append === form.has('expected_version')) return reply(400, {});
    const expected = append ? null : Number(form.get('expected_version'));
    let decision = f.decisions.get(key);
    if (decision && (decision.original_body !== body || decision.action !== action || decision.number !== number)) return reply(409, { error: 'key reuse' });
    if (!decision) {
      const row = f.rows.get(number), fields = Object.fromEntries(['title', 'body'].filter(name => form.has(name)).map(name => [name, form.get(name)]));
      const lifecycle = action === 'open' ? !row : !row ? false : ['comment', 'append-comment'].includes(action) ? !row.locked
        : action === 'close' ? row.state === 'open' : action === 'reopen' ? row.state === 'closed'
        : action === 'lock' ? !row.locked : action === 'unlock' ? row.locked : true;
      const committed = (append ? Boolean(row) : expected === (row?.version ?? 0)) && lifecycle && f.mode !== 'refuse';
      if (committed) f.apply(number, action, fields);
      else { f.sequence++; f.save(); }
      decision = { type: 'discussion_publication', ...common(), number, expected_version: expected, action,
        principal_id: actor, tx_id: `tx-${key}`, decision_sequence: f.sequence, outcome: committed ? 'committed' : 'refused',
        repository_commit_id: committed ? `rcr-${f.sequence}` : null, refusal_record_id: committed ? null : `refusal-${f.sequence}`,
        refusal_code: committed ? null : !lifecycle ? 'ProtectedRefTransitionDenied' : 'EvidenceStale', delivery_acknowledged: null };
      f.decisions.set(key, { ...decision, original_body: body });
    }
    const { original_body: _, ...wire } = decision;
    if (f.mode === 'lost-reply') return res.destroy();
    if (f.mode === 'wait') return;
    if (f.mode === 'wrong-publication') wire.type = 'issue_publication';
    reply(wire.outcome === 'committed' ? 200 : 409, wire);
  });
  await listenForFetch(server);
  f.href = `http://127.0.0.1:${server.address().port}/repo/ui/discussions/`;
  f.connection = { href: f.href, tenant, repository, tokenFile };
  f.operation = (operation = 'open', record = join(root, 'request.json')) => ({ ...f.connection, operation, record,
    ...(operation === 'open' ? { number: 1, expectedVersion: 0, fields: { title: 'Plan 雪', body: 'Literal <script> & text' } } : {}) });
  f.flags = (operation, record = null) => [operation, '--url', f.href, '--tenant-id', tenant, '--repository-id', repository,
    '--token-file', tokenFile, ...(record === null ? [] : ['--record', record])];
  t.after(async () => { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); await rm(root, { recursive: true, force: true }); });
  return f;
}

export function discussionCommand(args) {
  const child = spawn(process.execPath, [cli, ...args], { stdio: ['ignore', 'pipe', 'pipe'] });
  const out = [], err = []; child.stdout.on('data', bytes => out.push(bytes)); child.stderr.on('data', bytes => err.push(bytes));
  return { child, done: new Promise((resolve, reject) => { child.once('error', reject);
    child.once('close', (code, signal) => resolve({ code, signal, stdout: Buffer.concat(out).toString(), stderr: Buffer.concat(err).toString() })); }) };
}
