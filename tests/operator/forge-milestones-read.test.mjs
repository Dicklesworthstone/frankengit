// Real HTTP, private files and the shipped client/CLI, with an explicitly
// simulated response-schema peer. This is not native Rust authority evidence.
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawn } from 'node:child_process';
import { milestoneReadOptions, runMilestoneRead } from '../../scripts/lib/forge-milestone-reader.mjs';
import { milestoneArguments, runMilestoneCommand } from '../../scripts/forge_milestones.mjs';
import { operatorJson } from '../../scripts/lib/forge-operator-io.mjs';
import { milestonePeer, milestoneSnapshot, fixtureMilestones, fixtureMilestoneIssues,
  tenant, repository, head } from './native_milestone_transfer_helper.mjs';

async function fixture(t, options = {}) {
  const root = await mkdtemp(join(tmpdir(), 'fg-milestone-read-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const peer = await milestonePeer({ rows: fixtureMilestoneIssues(), milestones: fixtureMilestones(), ...options });
  t.after(() => peer.close());
  const tokenFile = join(root, 'token');
  await writeFile(tokenFile, peer.token, { mode: 0o600 });
  const connection = { href: peer.href.replace('/ui/issues/', '/ui/milestones/'), tenant, repository, tokenFile };
  return { ...peer, root, tokenFile, connection,
    flags: operation => [operation, '--url', connection.href, '--tenant-id', tenant,
      '--repository-id', repository, '--token-file', tokenFile] };
}

function readOnly(f) {
  assert.ok(f.calls.every(call => call.method === 'GET' && call.key === undefined));
  assert.equal(f.decisions.size, 0);
}

function common(call) {
  return { schema_version: 1, tenant_id: tenant, repository_id: repository,
    scope: 'repository_milestones', snapshot_token: head, limit: Number(call.query.get('limit')) };
}

// Construct responses through the existing fixture's fold; faults change only
// the particular envelope or field under examination.
function listReply({ call, source, milestoneSource }) {
  const after = Number(call.query.get('after')), limit = Number(call.query.get('limit'));
  const all = [...milestoneSource.values()].filter(row => row.number > after).sort((a, b) => a.number - b.number);
  const selected = all.slice(0, limit);
  return { ...common(call), type: 'milestone_page', after,
    milestones: selected.map(row => milestoneSnapshot(row, source.values())),
    next_after: all.length > selected.length ? selected.at(-1).number : null };
}

function historyReply({ call, source, milestoneSource }, number) {
  const row = milestoneSource.get(number), after = Number(call.query.get('after_version'));
  const limit = Number(call.query.get('limit')), events = structuredClone(row?.events.slice(after, after + limit) ?? []);
  return { ...common(call), type: 'milestone_history', after_version: after, found: Boolean(row),
    milestone: row ? milestoneSnapshot(row, source.values()) : null, events,
    next_after_version: row && row.events.length > after + events.length ? after + events.length : null };
}

function command(args) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [fileURLToPath(new URL('../../scripts/forge_milestones.mjs', import.meta.url)), ...args],
      { stdio: ['ignore', 'pipe', 'pipe'] });
    let stdout = '', stderr = '';
    child.stdout.setEncoding('utf8'); child.stderr.setEncoding('utf8');
    child.stdout.on('data', chunk => { stdout += chunk; });
    child.stderr.on('data', chunk => { stderr += chunk; });
    const timer = setTimeout(() => { child.kill('SIGKILL'); reject(new Error('milestone CLI exceeded test deadline')); }, 10000);
    child.once('error', error => { clearTimeout(timer); reject(error); });
    child.once('close', (code, signal) => { clearTimeout(timer); resolve({ code, signal, stdout, stderr }); });
  });
}

test('milestone list continuations pin every subsequent request and preserve current member counts', async t => {
  const f = await fixture(t);
  const first = await runMilestoneRead({ ...f.connection, operation: 'list', limit: 1 });
  assert.equal(first.complete, false); assert.equal(first.stop_reason, 'page_budget');
  assert.equal(first.read_only, true); assert.equal(first.mutation_submitted, false);
  assert.deepEqual(first.continuation, { operation: 'list', expected_head: head, after: 1, limit: 1 });
  assert.equal(first.pages[0].milestones[0].open_issues, 0);
  assert.equal(first.pages[0].milestones[0].closed_issues, 1);
  assert.equal(first.pages[0].milestones[0].due_at, 253402300799);

  const rest = await runMilestoneRead({ ...f.connection, operation: 'list', after: 1,
    head: first.snapshot_token, limit: 1, maxPages: 2 });
  assert.equal(rest.complete, true); assert.equal(rest.continuation, null); assert.equal(rest.page_count, 2);
  assert.deepEqual(rest.pages.flatMap(page => page.milestones.map(row => row.number)), [2, 3]);
  assert.deepEqual(rest.pages.flatMap(page => page.milestones.map(row => [row.open_issues, row.closed_issues])), [[1, 0], [0, 0]]);
  assert.equal(rest.pages[0].milestones[0].due_at, null);
  assert.deepEqual(f.calls.map(call => call.query.get('after')), ['0', '1', '2']);
  assert.deepEqual(f.calls.map(call => call.query.get('expected_head')), [null, head, head]);
  assert.ok(f.calls.every(call => call.path === '/repository/api/v1/milestones'));
  readOnly(f);
});

test('milestone show traverses contiguous lifecycle history with explicit bounded continuation', async t => {
  const f = await fixture(t);
  const first = await runMilestoneRead({ ...f.connection, operation: 'show', number: 2, limit: 2 });
  assert.equal(first.complete, false); assert.equal(first.page_count, 1);
  assert.deepEqual(first.pages[0].events.map(event => event.version), [1, 2]);
  assert.deepEqual(first.continuation, { operation: 'show', expected_head: head, after: 2, number: 2, limit: 2 });
  const rest = await runMilestoneRead({ ...f.connection, operation: 'show', number: 2,
    after: 2, head, limit: 2, maxPages: 2 });
  assert.equal(rest.complete, true); assert.equal(rest.page_count, 2);
  assert.deepEqual(rest.pages.flatMap(page => page.events.map(event => event.version)), [3, 4, 5]);
  assert.deepEqual(rest.pages.flatMap(page => page.events.map(event => event.action.name)), ['close', 'reopen', 'edit']);
  assert.deepEqual(rest.pages[1].events[0].action, { name: 'edit', due_at: null });
  assert.equal(rest.pages[1].milestone.state, 'open');
  assert.equal(rest.pages[1].milestone.open_issues, 1);
  assert.ok(f.calls.slice(1).every(call => call.query.get('expected_head') === head));
  readOnly(f);
});

test('missing milestone is a checked empty history and not a generic HTTP absence', async t => {
  let generic404 = false;
  const f = await fixture(t, { fault({ send }) { if (generic404) { send({}, 404); return true; } } });
  const result = await runMilestoneRead({ ...f.connection, operation: 'show', number: 99 });
  assert.equal(result.complete, true); assert.equal(result.page_count, 1); assert.equal(result.continuation, null);
  assert.equal(result.pages[0].found, false); assert.equal(result.pages[0].milestone, null);
  assert.deepEqual(result.pages[0].events, []);
  generic404 = true;
  await assert.rejects(runMilestoneRead({ ...f.connection, operation: 'show', number: 99 }),
    error => error.operator_state === 'read_incomplete');
  readOnly(f);
});

test('unvalidated extensions and rendered HTML never enter milestone CLI read data', async t => {
  const f = await fixture(t, { fault(context) {
    const list = context.call.path.endsWith('/milestones');
    const reply = list ? listReply(context) : historyReply(context, 1);
    reply.unvalidated_extension = { private: 'omit this' };
    for (const row of list ? reply.milestones : [reply.milestone]) {
      row.unvalidated_extension = 'omit this'; row.body_rendered = '<script>not canonical</script>';
    }
    for (const event of reply.events ?? []) {
      event.unvalidated_extension = 'omit this';
      if (Object.hasOwn(event.action, 'body')) event.action.body_rendered = '<script>not canonical</script>';
    }
    context.send(reply); return true;
  } });
  for (const operation of ['list', 'show']) {
    const result = await runMilestoneRead({ ...f.connection, operation, ...(operation === 'show' ? { number: 1 } : {}) });
    const text = JSON.stringify(result);
    assert.ok(!text.includes('unvalidated_extension')); assert.ok(!text.includes('body_rendered'));
    assert.ok(!text.includes('not canonical')); assert.ok(!text.includes('omit this'));
    const row = operation === 'list' ? result.pages[0].milestones[0] : result.pages[0].milestone;
    assert.equal(row.body, 'Edited release <script> & text.\r\n');
  }
  readOnly(f);
});

test('foreign repository or scope and invalid member counts refuse the entire observation', async t => {
  let change = reply => { reply.tenant_id = '9'.repeat(32); };
  const f = await fixture(t, { fault(context) {
    if (!change) return;
    const reply = listReply(context); change(reply); context.send(reply); return true;
  } });
  for (const mutate of [
    reply => { reply.tenant_id = '9'.repeat(32); },
    reply => { reply.repository_id = '9'.repeat(32); },
    reply => { reply.scope = 'repository_issues'; },
    reply => { reply.milestones[0].open_issues = -1; },
    reply => { reply.milestones[0].closed_issues = 0.5; },
    reply => { reply.milestones[0].open_issues = Number.MAX_SAFE_INTEGER; reply.milestones[0].closed_issues = 1; },
  ]) {
    change = mutate;
    await assert.rejects(runMilestoneRead({ ...f.connection, operation: 'list' }),
      error => error.operator_state === 'read_incomplete');
  }
  change = null;
  assert.equal((await runMilestoneRead({ ...f.connection, operation: 'list' })).complete, true);
  readOnly(f);
});

test('moved snapshots, changed identity, revoked access and nonprogressing cursors cannot return a successful prefix', async t => {
  let mode = 'head';
  const f = await fixture(t, { fault(context) {
    if (Number(context.call.query.get('after')) === 0 || mode === null) return;
    if (mode === 'revoked') { context.send({}, 401); return true; }
    const reply = listReply(context);
    if (mode === 'head') reply.snapshot_token = `alg:2:${'b'.repeat(64)}`;
    if (mode === 'identity') reply.repository_id = '9'.repeat(32);
    if (mode === 'cursor') reply.next_after = Number(context.call.query.get('after'));
    context.send(reply); return true;
  } });
  for (const selected of ['head', 'identity', 'revoked', 'cursor']) {
    mode = selected; const before = f.calls.length, progress = [];
    await assert.rejects(runMilestoneRead({ ...f.connection, operation: 'list', limit: 1, maxPages: 3,
      onProgress: page => progress.push(page) }), error => error.operator_state === 'read_incomplete');
    assert.equal(f.calls.length - before, 2); assert.equal(progress.length, 1);
    assert.equal(progress[0].pages, 1); assert.equal(progress[0].next_after, 1);
  }
  mode = null;
  assert.equal((await runMilestoneRead({ ...f.connection, operation: 'list', limit: 1, maxPages: 3 })).complete, true);
  readOnly(f);
});

test('a missing or gapped later history page refuses instead of truncating a milestone history', async t => {
  let mode = 'gap';
  const f = await fixture(t, { fault(context) {
    if (Number(context.call.query.get('after_version')) === 0 || mode === null) return;
    const reply = historyReply(context, 2);
    if (mode === 'gap') reply.events[0].version++;
    if (mode === 'missing') reply.events = [];
    context.send(reply); return true;
  } });
  for (const selected of ['gap', 'missing']) {
    mode = selected;
    await assert.rejects(runMilestoneRead({ ...f.connection, operation: 'show', number: 2, limit: 1, maxPages: 5 }),
      error => error.operator_state === 'read_incomplete');
  }
  mode = null;
  const complete = await runMilestoneRead({ ...f.connection, operation: 'show', number: 2, limit: 1, maxPages: 5 });
  assert.equal(complete.complete, true); assert.equal(complete.pages.length, 5);
  readOnly(f);
});

test('output budget covers both retained pages and the complete response envelope', async t => {
  const f = await fixture(t);
  await assert.rejects(runMilestoneRead({ ...f.connection, operation: 'list', maxOutputBytes: 32 }),
    error => error.code === 'milestone_read_output_limit' && error.operator_state === 'read_incomplete');
  const result = await runMilestoneRead({ ...f.connection, operation: 'list' });
  const pageBytes = Buffer.byteLength(operatorJson(result.pages[0]));
  assert.ok(Buffer.byteLength(operatorJson(result)) > pageBytes);
  await assert.rejects(runMilestoneRead({ ...f.connection, operation: 'list', maxOutputBytes: pageBytes }),
    error => error.code === 'milestone_read_output_limit' && error.operator_state === 'read_incomplete');
  readOnly(f);
});

test('explicit cancellation stops before intake or after a checked page without further HTTP', async t => {
  const f = await fixture(t), before = new AbortController(); before.abort();
  await assert.rejects(runMilestoneRead({ ...f.connection, operation: 'list', signal: before.signal }),
    error => error.code === 'milestone_read_cancelled_or_deadline');
  assert.equal(f.calls.length, 0);
  const after = new AbortController();
  await assert.rejects(runMilestoneRead({ ...f.connection, operation: 'list', limit: 1, maxPages: 3,
    signal: after.signal, onProgress: () => after.abort() }),
    error => error.code === 'milestone_read_cancelled_or_deadline' && error.operator_state === 'read_incomplete');
  assert.equal(f.calls.length, 1);
  readOnly(f);
});

test('one operation deadline stops a stalled response and redirect targets never receive credentials', { timeout: 5000 }, async t => {
  let mode = 'stall', stalled = false;
  const f = await fixture(t, { fault({ res }) {
    if (mode === 'stall') { stalled = true; res.writeHead(200, { 'Content-Type': 'application/json' }); res.write('{"type":'); return true; }
    if (mode === 'redirect') { res.writeHead(302, { Location: '/untrusted' }); res.end(); return true; }
  } });
  await assert.rejects(runMilestoneRead({ ...f.connection, operation: 'list', timeoutMs: 100 }),
    error => error.operator_state === 'read_incomplete');
  assert.equal(stalled, true); assert.equal(f.calls.length, 1);
  mode = 'redirect';
  await assert.rejects(runMilestoneRead({ ...f.connection, operation: 'list' }),
    error => error.operator_state === 'read_incomplete');
  assert.equal(f.calls.some(call => call.path === '/untrusted'), false);
  readOnly(f);
});

test('milestone CLI subprocess reads report continuation, safe literal text and no credential leakage', async t => {
  const milestones = fixtureMilestones(), literal = '\u202e\u001b[2J literal & <script> 雪';
  milestones[0].events[0].action.body = literal;
  const f = await fixture(t, { milestones });
  const prefix = await command([...f.flags('list'), '--limit', '1']);
  assert.equal(prefix.code, 4, prefix.stderr); assert.equal(prefix.stderr, '');
  const result = JSON.parse(prefix.stdout);
  assert.equal(result.read_only, true); assert.equal(result.continuation.after, 1);
  const rest = await command([...f.flags('list'), '--after', '1', '--expected-head', result.snapshot_token,
    '--limit', '1', '--max-pages', '2']);
  assert.equal(rest.code, 0, rest.stderr); assert.equal(rest.stderr, '');
  assert.deepEqual(JSON.parse(rest.stdout).pages.flatMap(page => page.milestones.map(row => row.number)), [2, 3]);
  const shown = await command([...f.flags('show'), '--number', '1', '--limit', '1']);
  assert.equal(shown.code, 4, shown.stderr); assert.equal(JSON.parse(shown.stdout).pages[0].events[0].action.body, literal);
  assert.ok(!shown.stdout.includes('\u202e')); assert.ok(!shown.stdout.includes('\u001b'));
  const calls = f.calls.length;
  const bad = await command([...f.flags('list'), '--after', '1']);
  assert.equal(bad.code, 2); assert.equal(bad.stdout, '');
  assert.equal(JSON.parse(bad.stderr).code, 'milestone_read_snapshot_required');
  assert.equal(f.calls.length, calls);
  for (const output of [prefix, rest, shown, bad]) {
    assert.ok(!output.stdout.includes(f.token)); assert.ok(!output.stderr.includes(f.token));
    assert.ok(!output.stdout.includes(f.tokenFile)); assert.ok(!output.stderr.includes(f.tokenFile));
  }
  const missing = await runMilestoneCommand([...f.flags('show'), '--number', '99']);
  assert.equal(missing.exitCode, 0); assert.equal(JSON.parse(missing.text).pages[0].found, false);
  readOnly(f);
});

test('milestone read grammar refuses ambiguous cursors and mutation-only options before any HTTP', async t => {
  const f = await fixture(t), reading = { ...f.connection, operation: 'list' };
  for (const raw of [
    { ...reading, number: 1 }, { ...reading, after: 1 }, { ...reading, operation: 'search' },
    { ...reading, limit: 0 }, { ...reading, limit: 101 }, { ...reading, maxPages: 101 },
    { ...reading, maxOutputBytes: 8388609 }, { ...reading, record: join(f.root, 'record') },
    { ...reading, operation: 'show' }, { ...reading, operation: 'show', number: 0 },
  ]) assert.throws(() => milestoneReadOptions(raw));
  for (const args of [
    [...f.flags('list'), '--record', join(f.root, 'record')],
    [...f.flags('list'), '--expected-version', '1'], [...f.flags('list'), '--body', 'x'],
    [...f.flags('list'), '--due-at', '0'], [...f.flags('list'), '--clear-due-at'],
    [...f.flags('list'), '--number', '1'], [...f.flags('show'), '--number', '01'],
    [...f.flags('show'), '--number', '1', '--number', '2'], [...f.flags('list'), '--limit'],
  ]) assert.throws(() => milestoneArguments(args));
  assert.equal(f.calls.length, 0); readOnly(f);
});
