// DELIBERATELY SIMULATED native HTTP authority. Tests run the shipped clients,
// real fetch/sockets/files and CLI processes, not an fgit-node server.
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { spawn } from 'node:child_process';
import { listenForFetch } from '../fetch-peer.mjs';

export const tenant = '11'.repeat(16), repository = '22'.repeat(16), principal = '33'.repeat(16);
export const incarnation = '44'.repeat(16), token = 'ab'.repeat(32);
export const versionField = kind => ({ issue: 'issue_version', discussion: 'discussion_version', pull_request: 'activity_version' })[kind];
const clone = value => structuredClone(value);
const initialRows = kind => [
  { number: 7, [versionField(kind)]: 4, title: 'A thread', state: 'open', preference_version: 2,
    mode: 'automatic', read_through: 1, latest_other_version: 3, unread: true, reasons: ['author', 'participant'] },
  { number: 9, [versionField(kind)]: 2, title: 'Muted thread', state: 'closed', preference_version: 1,
    mode: 'muted', read_through: null, latest_other_version: 2, unread: true, reasons: [] },
  { number: 11, [versionField(kind)]: 1, title: 'Own activity', state: 'open', preference_version: null,
    mode: 'automatic', read_through: null, latest_other_version: null, unread: false, reasons: ['author', 'participant'] },
];
export async function fixture(t) {
  const root = await mkdtemp(join(tmpdir(), 'fg-inbox-operator-'));
  const tokenFile = join(root, 'token'); await writeFile(tokenFile, token + '\n', { mode: 0o600 });
  const f = { root, tokenFile, calls: [], decisions: new Map(), snapshots: new Map(), errors: [],
    rows: { issue: initialRows('issue'), discussion: initialRows('discussion'), pull_request: initialRows('pull_request') }, generation: 0,
    principal, incarnation, mode: null, onMutation: null, onRead: null, afterRead: null };
  f.capture = () => {
    f.generation++;
    f.head = 'alg:2:' + f.generation.toString(16).padStart(64, '0');
    f.snapshots.set(f.head, { rows: clone(f.rows), generation: f.generation });
    return f.head;
  };
  f.capture();
  f.row = (kind = 'issue', number = 7) => f.rows[kind].find(row => row.number === number);
  const common = () => ({ schema_version: 1, tenant_id: f.mode === 'wrong-repository' ? 'ee'.repeat(16) : tenant,
    repository_id: repository, principal_id: f.principal, repository_incarnation: f.incarnation });
  const server = createServer(async (req, res) => {
    const respond = (status, value) => { res.writeHead(status, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(value)); };
    try {
      let body = ''; for await (const part of req) body += part;
      const url = new URL(req.url, 'http://localhost'), key = req.headers['idempotency-key'];
      f.calls.push({ method: req.method, path: url.pathname, query: Object.fromEntries(url.searchParams), body, key,
        authorization: req.headers.authorization, userAgent: req.headers['user-agent'] });
      if (req.headers.authorization !== `Bearer ${token}` || f.mode === 'unauthorized') return respond(401, {});
      if (f.mode === 'redirect') { res.writeHead(307, { Location: '/leak' }); return res.end(); }
      if (url.pathname === '/repo/api/v1/outcomes') {
        const decision = f.decisions.get(key), state = decision?.outcome ?? 'key_not_observed';
        return respond(200, { type: 'transaction_outcome', ...common(), selector: 'transaction', command_index: null,
          read_only: true, request_reexecuted: false, absence_proves_non_commit: false, session_completeness_established: false,
          terminal: Boolean(decision), state, transaction: decision ? { tx_id: decision.tx_id } : null,
          decision: decision ? { kind: state, decision_sequence: decision.decision_sequence,
            repository_commit_id: decision.repository_commit_id, refusal_record_id: decision.refusal_record_id, code: decision.refusal_code } : null });
      }
      const match = /^\/repo\/api\/v1\/notifications(\/(?:discussions|pulls))?(?:\/(\d+)(?:\/(subscribe|mute|automatic|read|unread))?)?$/.exec(url.pathname);
      if (!match) return respond(404, {});
      const kind = match[1] === '/pulls' ? 'pull_request' : match[1] ? 'discussion' : 'issue', number = match[2] === undefined ? null : Number(match[2]), action = match[3];
      const prefix = kind === 'issue' ? 'notification' : kind + '_notification';
      const target = kind === 'issue' ? {} : { target_kind: kind };
      if (req.method === 'GET' && !action) {
        if (f.mode === 'wait-read') return;
        const head = url.searchParams.get('expected_head') ?? f.head, source = f.snapshots.get(head);
        if (!source) return respond(409, { error: 'snapshot_expired' });
        const base = { ...common(), ...target, snapshot_token: head, source_positions: {
          authority_head_generation: source.generation, forge_position_root: 'forge-' + head, outbox_root: 'outbox-' + head, complete: true } };
        let reply;
        if (number !== null) {
          const row = source.rows[kind].find(row => row.number === number);
          reply = { type: `${prefix}_thread`, ...base, found: Boolean(row), thread: clone(row ?? null) };
        } else {
          const after = Number(url.searchParams.get('after')), limit = Number(url.searchParams.get('limit'));
          const unreadOnly = url.searchParams.get('unread_only') === 'true', includeMuted = url.searchParams.get('include_muted') === 'true';
          const selected = source.rows[kind].filter(row => row.number > after && (!unreadOnly || row.unread) &&
            (includeMuted ? row.reasons.length || row.mode === 'muted' : row.reasons.length && row.mode !== 'muted'));
          const rows = selected.slice(0, limit);
          reply = { type: `${prefix}_page`, ...base, after, limit, unread_only: unreadOnly, include_muted: includeMuted,
            next_after: selected.length > rows.length ? rows.at(-1).number : null, threads: clone(rows) };
        }
        if (f.onRead) f.onRead({ reply, kind, number, head });
        respond(reply.found === false ? 404 : 200, reply);
        if (f.afterRead) f.afterRead({ reply, kind, number, head });
        return;
      }
      if (req.method !== 'POST' || !action) return respond(404, {});
      if (f.onMutation) f.onMutation({ kind, number, action, key, body });
      const form = new URLSearchParams(body);
      if (form.get('expected_principal') !== f.principal || form.get('expected_incarnation') !== f.incarnation) {
        return respond(409, { error: 'notification_identity_changed' });
      }
      let decision = f.decisions.get(key);
      if (decision && (decision.original_body !== body || decision.kind !== kind || decision.number !== number || decision.action !== action)) {
        return respond(409, { error: 'key_reuse' });
      }
      if (!decision) {
        const expected = Number(form.get('expected_version')), row = f.row(kind, number);
        const readThrough = Number(form.get('read_through'));
        const committed = row && (row.preference_version ?? 0) === expected && f.mode !== 'refuse' &&
          (action !== 'read' || (readThrough > 0 && readThrough <= row[versionField(kind)]));
        decision = { type: `${prefix}_publication`, ...common(), ...target, number, expected_version: expected, action,
          tx_id: 'tx-' + key, decision_sequence: f.decisions.size + 1, outcome: committed ? 'committed' : 'refused',
          repository_commit_id: committed ? 'rcr-' + (f.decisions.size + 1) : null, refusal_record_id: committed ? null : 'refusal-1',
          refusal_code: committed ? null : 'expected_version', delivery_acknowledged: null };
        f.decisions.set(key, { ...decision, kind, original_body: body });
        if (committed) {
          row.preference_version = expected + 1;
          if (action === 'read') row.read_through = readThrough;
          else if (action === 'unread') row.read_through = null;
          else row.mode = { subscribe: 'subscribed', mute: 'muted', automatic: 'automatic' }[action];
          row.reasons = row.reasons.filter(reason => reason !== 'subscribed');
          if (row.mode === 'subscribed') row.reasons.push('subscribed');
          row.unread = (row.latest_other_version ?? 0) > (row.read_through ?? 0);
          f.capture();
        }
      }
      const { original_body: _, kind: __, ...wire } = decision;
      if (f.mode === 'lost-reply') return res.destroy();
      if (f.mode === 'wait') return;
      if (f.mode === 'bad-reply') wire.number = number + 1;
      if (f.mode === 'bad-refusal') return respond(409, { error: 'unrecognized refusal' });
      respond(wire.outcome === 'committed' ? 200 : 409, wire);
    } catch (error) { f.errors.push(error); if (!res.headersSent) respond(500, {}); else res.destroy(); }
  });
  await listenForFetch(server);
  f.href = kind => `http://127.0.0.1:${server.address().port}/repo/ui/${kind === 'pull_request' ? 'pull-notifications' : kind === 'discussion' ? 'discussion-notifications' : 'notifications'}/`;
  f.options = (operation = 'subscribe', kind = 'issue', record = join(root, 'request.json')) => ({
    operation, kind, href: f.href(kind), tenant, repository, tokenFile,
    ...(['list', 'show'].includes(operation) ? {} : { record }),
    ...(['list', 'status', 'retry'].includes(operation) ? {} : { number: 7 }),
    ...(['list', 'show', 'status', 'retry'].includes(operation) ? {} : {
      expectedVersion: f.row(kind).preference_version ?? 0, expectedPrincipal: principal, expectedIncarnation: incarnation,
      ...(operation === 'read' ? { readThrough: 4 } : {}) }),
  });
  t.after(async () => {
    server.closeAllConnections(); await new Promise(resolve => server.close(resolve));
    await rm(root, { recursive: true, force: true }); assert.deepEqual(f.errors, []);
  });
  return f;
}
export const mutations = f => f.calls.filter(call => /\/(subscribe|mute|automatic|read|unread)$/.test(call.path));
export const reads = f => f.calls.filter(call => call.method === 'GET');
export function command(args) {
  const child = spawn(process.execPath, [resolve('scripts/forge_inbox.mjs'), ...args], { stdio: ['ignore', 'pipe', 'pipe'] });
  const out = [], err = []; child.stdout.on('data', bytes => out.push(bytes)); child.stderr.on('data', bytes => err.push(bytes));
  return { child, done: new Promise((resolve, reject) => {
    child.on('error', reject); child.on('close', (code, signal) => resolve({ code, signal, stdout: Buffer.concat(out).toString(), stderr: Buffer.concat(err).toString() }));
  }) };
}
export function flags(f, operation, kind = 'issue', record = join(f.root, 'request.json')) {
  return [operation, '--kind', kind, '--url', f.href(kind), '--tenant-id', tenant, '--repository-id', repository, '--token-file', f.tokenFile,
    ...(['list', 'show'].includes(operation) ? [] : ['--record', record])];
}
export const guards = version => ['--number', '7', '--expected-version', String(version), '--expected-principal', principal, '--expected-incarnation', incarnation];
