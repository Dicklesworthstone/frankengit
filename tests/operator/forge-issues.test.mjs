import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { mkdtemp, writeFile, readFile, chmod, rm, lstat, symlink, link, readdir } from 'node:fs/promises';
import { readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { spawn } from 'node:child_process';
import { runIssueOperation, issueOperatorOptions } from '../../scripts/lib/forge-issue-operator.mjs';
import { issueArguments } from '../../scripts/forge_issues.mjs';
import { operatorJson } from '../../scripts/lib/forge-operator-io.mjs';

const tenant = '11'.repeat(16), repository = '22'.repeat(16), token = 'ab'.repeat(32);
const actor = '33'.repeat(16), snapshot = 'alg:2:' + '12'.repeat(32);
const cli = resolve('scripts/forge_issues.mjs');
// DELIBERATELY SIMULATED native HTTP authority. The real shipped IssueClient,
// fetch, sockets, filesystem and CLI run. This is not fgit-node execution.
async function fixture(t) {
  const root = await mkdtemp(join(tmpdir(), 'fg-issue-operator-'));
  const tokenFile = join(root, 'token'); await writeFile(tokenFile, token + '\n', { mode: 0o600 });
  const f = { root, tokenFile, mode: null, version: 0, row: null, events: [], calls: [], decisions: new Map(), onMutation: null };
  const common = () => ({ schema_version: 1, tenant_id: f.mode === 'wrong-identity' ? 'ff'.repeat(16) : tenant, repository_id: repository });
  const server = createServer(async (req, res) => {
    let body = ''; for await (const part of req) body += part;
    const url = new URL(req.url, 'http://localhost'), key = req.headers['idempotency-key'];
    f.calls.push({ method: req.method, path: url.pathname, body, key, authorization: req.headers.authorization });
    const respond = (status, value) => { res.writeHead(status, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(value)); };
    if (req.headers.authorization !== `Bearer ${token}` || f.mode === 'unauthorized') return respond(401, {});
    if (f.mode === 'redirect') { res.writeHead(307, { Location: '/leak' }); return res.end(); }
    if (url.pathname === '/repo/api/v1/outcomes') {
      const decision = f.decisions.get(key), state = decision?.outcome ?? 'key_not_observed';
      return respond(200, { type: 'transaction_outcome', ...common(), repository_incarnation: '44'.repeat(16), principal_id: actor,
        selector: 'transaction', command_index: null, read_only: true, request_reexecuted: false,
        absence_proves_non_commit: false, session_completeness_established: false, terminal: Boolean(decision), state,
        transaction: decision ? { tx_id: decision.tx_id } : null,
        decision: decision ? { kind: state, decision_sequence: decision.decision_sequence, repository_commit_id: decision.repository_commit_id,
          refusal_record_id: decision.refusal_record_id, code: decision.refusal_code } : null });
    }
    if (req.method === 'GET' && url.pathname === '/repo/api/v1/issues/1') {
      const limit = Number(url.searchParams.get('limit')), after = Number(url.searchParams.get('after_version'));
      const events = f.events.slice(after, after + limit);
      return respond(200, { type: 'issue_history', ...common(), snapshot_token: snapshot, after_version: after, limit,
        found: Boolean(f.row), issue: f.row, events, next_after_version: f.events.length > after + events.length ? after + events.length : null });
    }
    const match = /^\/repo\/api\/v1\/issues\/1\/(open|edit|comment|close|reopen)$/.exec(url.pathname);
    if (!match || req.method !== 'POST') return respond(404, {});
    if (f.onMutation) f.onMutation({ key, body });
    const form = new URLSearchParams(body), action = match[1], expected = Number(form.get('expected_version'));
    let decision = f.decisions.get(key);
    if (decision && decision.original_body !== body) return respond(409, { error: 'key reuse' });
    if (!decision) {
      const committed = expected === f.version && f.mode !== 'refuse';
      decision = { type: 'issue_publication', ...common(), number: 1, expected_version: expected, action,
        principal_id: actor, tx_id: 'tx-' + key, decision_sequence: f.decisions.size + 1,
        outcome: committed ? 'committed' : 'refused', repository_commit_id: committed ? 'rcr-1' : null,
        refusal_code: committed ? null : 'expected_version', refusal_record_id: committed ? null : 'refusal-1', delivery_acknowledged: null };
      f.decisions.set(key, { ...decision, original_body: body });
      if (committed) {
        f.version++;
        if (action === 'open') f.row = { number: 1, version: 1, title: form.get('title'), body: form.get('body'), labels: form.getAll('label'),
          state: 'open', opened_by: actor, last_actor: actor, comments: 0 };
        f.row.version = f.version;
        if (action === 'close' || action === 'reopen') f.row.state = action === 'close' ? 'closed' : 'open';
        if (action === 'comment') f.row.comments++;
        if (action === 'edit') {
          for (const k of ['title', 'body']) if (form.has(k)) f.row[k] = form.get(k);
          if (form.has('label') || form.has('clear_labels')) f.row.labels = form.getAll('label');
        }
        const eventAction = { name: action };
        for (const k of ['title', 'body']) if (form.has(k)) eventAction[k] = form.get(k);
        if (form.has('label') || action === 'open') eventAction.labels = form.getAll('label');
        f.events.push({ version: f.version, actor, action: eventAction });
      }
    }
    const { original_body: _, ...wire } = decision;
    if (f.mode === 'lost-reply') return res.destroy();
    if (f.mode === 'wait') return;
    if (f.mode === 'bad-reply') wire.number = 2;
    respond(wire.outcome === 'committed' ? 200 : 409, wire);
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  f.href = `http://127.0.0.1:${server.address().port}/repo/ui/issues/`;
  f.options = (operation = 'open', record = join(root, 'request.json')) => ({ operation, href: f.href, tenant, repository, tokenFile,
    record, ...(operation === 'open' ? { number: 1, expectedVersion: 0, fields: { title: 'Real request', body: 'private draft' } } : {}) });
  t.after(async () => { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); await rm(root, { recursive: true, force: true }); });
  return f;
}
const mutations = f => f.calls.filter(c => /issues\/1\/(open|edit|comment|close|reopen)$/.test(c.path));
function command(args) {
  const child = spawn(process.execPath, [cli, ...args], { stdio: ['ignore', 'pipe', 'pipe'] });
  const out = [], err = []; child.stdout.on('data', b => out.push(b)); child.stderr.on('data', b => err.push(b));
  return { child, done: new Promise((resolve, reject) => { child.on('error', reject); child.on('close', code => resolve({ code, stdout: Buffer.concat(out).toString(), stderr: Buffer.concat(err).toString() })); }) };
}
function flags(f, operation, record = join(f.root, 'request.json')) {
  return [operation, '--url', f.href, '--tenant-id', tenant, '--repository-id', repository, '--token-file', f.tokenFile, '--record', record];
}

test('fresh mutation syncs exact token-free receipt before HTTP and recovers without a write', async t => {
  const f = await fixture(t), o = f.options();
  f.onMutation = ({ key, body }) => {
    const bytes = readFileSync(o.record), record = JSON.parse(bytes);
    assert.equal(record.receipt.request.key, key); assert.equal(record.receipt.request.body, body);
    assert.ok(!bytes.includes(token));
  };
  const result = await runIssueOperation(o);
  assert.equal(result.state, 'terminal_observed'); assert.equal(result.result.outcome, 'committed');
  assert.equal(Number((await lstat(o.record)).mode) & 0o777, 0o600);
  const status = await runIssueOperation(f.options('status'));
  assert.equal(status.result.outcome, 'committed'); assert.equal(status.mutation_submitted, false);
  const retry = await runIssueOperation(f.options('retry'));
  assert.equal(retry.result.outcome, 'committed'); assert.equal(mutations(f).length, 1);
});
test('lost mutation reply retains key; status observes real remote terminal fixture', async t => {
  const f = await fixture(t); f.mode = 'lost-reply';
  await assert.rejects(runIssueOperation(f.options()), e => e.operator_state === 'submitted_unknown');
  const original = await readFile(f.options().record); f.mode = null;
  const result = await runIssueOperation(f.options('retry'));
  assert.equal(result.result.outcome, 'committed'); assert.equal(mutations(f).length, 1);
  assert.deepEqual(await readFile(f.options().record), original); assert.equal(f.version, 1);
});
test('pre-send interruption preserves record; status never sends; explicit retry uses original key/body', async t => {
  const f = await fixture(t);
  await assert.rejects(runIssueOperation({ ...f.options(), onProgress: ({ phase }) => { if (phase === 'receipt_saved') throw Error('interrupt'); } }));
  const original = JSON.parse(await readFile(f.options().record));
  const status = await runIssueOperation(f.options('status'));
  assert.equal(status.state, 'unresolved'); assert.equal(status.absence_proves_non_commit, false); assert.equal(mutations(f).length, 0);
  const result = await runIssueOperation(f.options('retry'));
  assert.equal(result.result.outcome, 'committed'); assert.equal(mutations(f)[0].key, original.receipt.request.key);
  assert.equal(mutations(f)[0].body, original.receipt.request.body);
});
test('new operations require a new record, never overwrite an unresolved one', async t => {
  const f = await fixture(t); await runIssueOperation(f.options());
  const calls = f.calls.length, bytes = await readFile(f.options().record);
  await assert.rejects(runIssueOperation(f.options()), e => e.code === 'operator_record_exists');
  assert.equal(f.calls.length, calls); assert.deepEqual(await readFile(f.options().record), bytes);
});
test('wrong repository, stale version and token rejection stop before recording or submission', async t => {
  const f = await fixture(t);
  f.mode = 'wrong-identity'; await assert.rejects(runIssueOperation(f.options()), e => e.code === 'issue_operator_repository_mismatch');
  f.mode = 'unauthorized'; await assert.rejects(runIssueOperation(f.options()));
  f.mode = null; await assert.rejects(runIssueOperation({ ...f.options('close'), number: 1, expectedVersion: 3, fields: {} }), e => e.code === 'issue_operator_version_moved');
  assert.equal(mutations(f).length, 0); assert.deepEqual(await readdir(f.root), ['token']);
  assert.equal((await runIssueOperation(f.options())).result.outcome, 'committed');
});
test('terminal refusal is not success or an HTTP transport error', async t => {
  const f = await fixture(t); f.mode = 'refuse';
  const result = await runIssueOperation(f.options());
  assert.equal(result.result.outcome, 'refused'); assert.equal(result.state, 'terminal_observed');
  assert.equal((await runIssueOperation(f.options('retry'))).result.outcome, 'refused'); assert.equal(mutations(f).length, 1);
});
test('malformed success is unknown; later status can recover original decision', async t => {
  const f = await fixture(t); f.mode = 'bad-reply';
  await assert.rejects(runIssueOperation(f.options()), e => e.operator_state === 'submitted_unknown');
  f.mode = null; assert.equal((await runIssueOperation(f.options('status'))).result.outcome, 'committed');
});
test('credential, identity and original-body tampering refuse before a recovery HTTP request', async t => {
  const f = await fixture(t); await runIssueOperation(f.options()); const original = await readFile(f.options().record);
  const calls = f.calls.length;
  await writeFile(f.tokenFile, 'cd'.repeat(32)); await assert.rejects(runIssueOperation(f.options('status'))); await writeFile(f.tokenFile, token);
  await assert.rejects(runIssueOperation({ ...f.options('retry'), repository: '55'.repeat(16) }));
  const v = JSON.parse(original); v.receipt.request.fields.body = 'substituted'; await writeFile(f.options().record, JSON.stringify(v) + '\n');
  await assert.rejects(runIssueOperation(f.options('retry'))); assert.equal(f.calls.length, calls);
  await writeFile(f.options().record, original); assert.equal((await runIssueOperation(f.options('status'))).result.outcome, 'committed');
});
test('all issue transitions compose through exact expected versions and existing codec', async t => {
  const f = await fixture(t); await runIssueOperation(f.options());
  for (const [i, operation, fields] of [[1, 'comment', { body: 'next' }], [2, 'edit', { title: 'updated', labels: ['a', 'z'] }],
    [3, 'close', {}], [4, 'reopen', {}], [5, 'edit', { labels: [] }]]) {
    const result = await runIssueOperation({ ...f.options(operation, join(f.root, `request-${i}.json`)), number: 1, expectedVersion: i, fields });
    assert.equal(result.result.outcome, 'committed');
  }
  assert.equal(f.version, 6); assert.equal(f.row.state, 'open'); assert.equal(f.row.title, 'updated'); assert.deepEqual(f.row.labels, []);
  assert.ok(mutations(f).at(-1).body.includes('clear_labels=true'));
});
test('caller mutation cannot replace snapshotted fields or target', async t => {
  const f = await fixture(t), options = f.options();
  options.onProgress = ({ phase }) => { if (phase === 'source_checked') { options.fields.body = 'attacker'; options.href = 'http://remote.invalid/ui/issues/'; } };
  await runIssueOperation(options); assert.equal(f.row.body, 'private draft');
});
test('redirect is refused without forwarding credentials or a mutation', async t => {
  const f = await fixture(t); f.mode = 'redirect'; await assert.rejects(runIssueOperation(f.options()));
  assert.equal(f.calls.length, 1); assert.equal(mutations(f).length, 0);
});
test('cancellation after remote publication retains original responsibility', async t => {
  const f = await fixture(t), stop = new AbortController(); f.mode = 'wait'; f.onMutation = () => setTimeout(() => stop.abort(), 5);
  await assert.rejects(runIssueOperation({ ...f.options(), signal: stop.signal }), e => e.operator_state === 'submitted_unknown');
  f.mode = null; assert.equal((await runIssueOperation(f.options('status'))).result.outcome, 'committed'); assert.equal(f.version, 1);
});
test('unsafe token file permissions, symlinks and hard links are rejected', async t => {
  const f = await fixture(t); await chmod(f.tokenFile, 0o644); await assert.rejects(runIssueOperation(f.options())); await chmod(f.tokenFile, 0o600);
  const alias = join(f.root, 'alias'); await symlink(f.tokenFile, alias); await assert.rejects(runIssueOperation({ ...f.options(), tokenFile: alias })); await rm(alias);
  await link(f.tokenFile, alias); await assert.rejects(runIssueOperation(f.options())); await rm(alias);
  assert.equal(f.calls.length, 0); assert.equal((await runIssueOperation(f.options())).result.outcome, 'committed');
});
test('cancellation before intake and invalid grammar cause no network effects', async t => {
  const f = await fixture(t), stop = new AbortController(); stop.abort();
  await assert.rejects(runIssueOperation({ ...f.options(), signal: stop.signal }));
  for (const patch of [{ href: 'http://example.com/repo/ui/issues/' }, { href: 'https://user:pass@example.com/repo/ui/issues/' },
    { href: 'https://example.com/repo/ui/issues/?q=1' }, { principal: actor }, { timeoutMs: 0 }, { expectedVersion: 1 }, { number: Number.MAX_SAFE_INTEGER + 1 }]) {
    assert.throws(() => issueOperatorOptions({ ...f.options(), ...patch }));
  }
  assert.throws(() => issueArguments([...flags(f, 'retry'), '--body', 'replacement']));
  assert.throws(() => issueArguments([...flags(f, 'status'), '--token', token])); assert.equal(f.calls.length, 0);
});
test('CLI loads private body files, sends once and can recover in a separate process', async t => {
  const f = await fixture(t), body = join(f.root, 'draft'); await writeFile(body, 'CLI private body\n', { mode: 0o600 });
  const first = await command([...flags(f, 'open'), '--number', '1', '--expected-version', '0', '--title', 'CLI title', '--body-file', body]).done;
  assert.equal(first.code, 0, first.stderr); assert.equal(JSON.parse(first.stdout).result.outcome, 'committed');
  assert.equal(f.row.body, 'CLI private body\n'); assert.ok(!first.stdout.includes(token));
  const next = await command(flags(f, 'status')).done; assert.equal(next.code, 0, next.stderr); assert.equal(mutations(f).length, 1);
});
test('actual SIGKILL after server sees mutation leaves a usable synchronized receipt', async t => {
  const f = await fixture(t); f.mode = 'wait';
  const running = command([...flags(f, 'open'), '--number', '1', '--expected-version', '0', '--title', 'kill fixture']);
  f.onMutation = () => running.child.kill('SIGKILL');
  await running.done; assert.equal(f.version, 1); f.mode = null;
  const outcome = await command(flags(f, 'retry')).done;
  assert.equal(outcome.code, 0, outcome.stderr); assert.equal(mutations(f).length, 1);
});
test('record corruption after durable preparation refuses without submission', async t => {
  const f = await fixture(t);
  await assert.rejects(runIssueOperation({ ...f.options(), onProgress: ({ phase }) => {
    if (phase === 'receipt_saved') { const fs = process.getBuiltinModule('fs'); fs.writeFileSync(f.options().record, 'damaged'); }
  } }), e => e.code === 'issue_operator_record_changed'); assert.equal(mutations(f).length, 0);
});
test('operator JSON escapes terminal controls without changing parsed data', () => {
  const value = { body: 'x\u001b\u0085\u202e\n' }, text = operatorJson(value);
  assert.deepEqual(JSON.parse(text), value); assert.ok(!text.includes('\u0085')); assert.ok(!text.includes('\u202e'));
});
test('empty private body file can clear an existing issue body', async t => {
  const f = await fixture(t); await runIssueOperation(f.options());
  const body = join(f.root, 'empty'); await writeFile(body, '', { mode: 0o600 });
  const result = await command([...flags(f, 'edit', join(f.root, 'edit.json')), '--number', '1', '--expected-version', '1', '--body-file', body]).done;
  assert.equal(result.code, 0, result.stderr); assert.equal(f.row.body, '');
});
test('unresumable oversized receipt refuses before network mutation', async t => {
  const f = await fixture(t);
  await assert.rejects(runIssueOperation({ ...f.options(), fields: { title: 'large', body: '\x01'.repeat(65536) } }), e => e.code === 'issue_operator_receipt_limit');
  assert.equal(mutations(f).length, 0); assert.deepEqual(await readdir(f.root), ['token']);
});
test('one operation deadline bounds stalled response and retains uncertainty', async t => {
  const f = await fixture(t); f.mode = 'wait';
  await assert.rejects(runIssueOperation({ ...f.options(), timeoutMs: 100 }), e => e.operator_state === 'submitted_unknown');
  f.mode = null; assert.equal((await runIssueOperation(f.options('status'))).result.outcome, 'committed');
});
test('simultaneous fresh preparations cannot both publish under one record path', async t => {
  const f = await fixture(t);
  const attempts = await Promise.allSettled([runIssueOperation(f.options()), runIssueOperation(f.options())]);
  assert.equal(attempts.filter(r => r.status === 'fulfilled').length, 1);
  assert.equal(mutations(f).length, 1); assert.equal(f.version, 1);
});
