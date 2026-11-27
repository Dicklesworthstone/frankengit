import test from 'node:test';
import assert from 'node:assert/strict';
import { writeFile, readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { discussionReadOptions, runDiscussionRead } from '../../scripts/lib/forge-discussion-reader.mjs';
import { discussionArguments, runDiscussionCommand } from '../../scripts/forge_discussions.mjs';
import { discussionPeer, mutations, discussionCommand } from './discussion-operator-fixture.mjs';

test('bounded list continuations pin the original snapshot while new discussions arrive', async t => {
  const f = await discussionPeer(t); f.seed(1); f.seed(3); f.seed(7);
  const first = await runDiscussionRead({ ...f.connection, operation: 'list', limit: 1 });
  assert.equal(first.complete, false); assert.equal(first.page_count, 1); assert.equal(first.continuation.after, 1);
  const head = first.snapshot_token; f.seed(5);
  const rest = await runDiscussionRead({ ...f.connection, operation: 'list', after: first.continuation.after, head, limit: 1, maxPages: 3 });
  assert.equal(rest.complete, true); assert.equal(rest.snapshot_token, head);
  assert.deepEqual(rest.pages.flatMap(page => page.discussions.map(row => row.number)), [3, 7]);
  assert.ok(f.calls.slice(1).every(call => call.query.get('expected_head') === head));
  const current = await runDiscussionRead({ ...f.connection, operation: 'list' });
  assert.deepEqual(current.pages[0].discussions.map(row => row.number), [1, 3, 5, 7]);
  assert.equal(mutations(f).length, 0); assert.ok(f.calls.every(call => call.key === undefined));
});

test('show walks exact contiguous history, preserves literal text and returns resumable bounded prefixes', async t => {
  const f = await discussionPeer(t); f.seed(1, 'Plan', '\u202e\u001b[2J literal');
  f.apply(1, 'comment', { body: 'First reply' }); f.apply(1, 'edit', { title: 'Edited' }); f.apply(1, 'close');
  const prefix = await runDiscussionRead({ ...f.connection, operation: 'show', number: 1, limit: 2 });
  assert.equal(prefix.complete, false); assert.equal(prefix.continuation.after, 2); assert.equal(prefix.continuation.number, 1);
  const rest = await runDiscussionRead({ ...f.connection, operation: 'show', number: 1, after: 2,
    head: prefix.snapshot_token, limit: 1, maxPages: 2 });
  assert.equal(rest.complete, true); assert.deepEqual(rest.pages.flatMap(page => page.events.map(event => event.version)), [3, 4]);
  assert.equal(rest.pages.at(-1).discussion.state, 'closed');
  const output = await runDiscussionCommand([...f.flags('show'), '--number', '1', '--limit', '2']);
  assert.equal(output.exitCode, 4); assert.ok(!output.text.includes('\u202e')); assert.ok(!output.text.includes('\u001b'));
  assert.equal(JSON.parse(output.text).pages[0].events[0].action.body, '\u202e\u001b[2J literal');
});

test('missing discussion is a checked empty history, and unknown extensions are omitted', async t => {
  const f = await discussionPeer(t);
  const absent = await runDiscussionRead({ ...f.connection, operation: 'show', number: 7 });
  assert.equal(absent.complete, true); assert.equal(absent.pages[0].found, false);
  f.seed(); f.mode = 'extra-fields';
  const page = await runDiscussionRead({ ...f.connection, operation: 'list' });
  assert.equal(Object.hasOwn(page.pages[0].discussions[0], 'unvalidated_extension'), false);
});

test('foreign scope, wrong repository and a malformed later page cannot return a successful prefix', async t => {
  const f = await discussionPeer(t); f.seed(); f.apply(1, 'comment', { body: 'Tail' });
  for (const mode of ['wrong-family', 'wrong-identity']) {
    f.mode = mode;
    await assert.rejects(runDiscussionRead({ ...f.connection, operation: 'list' }), error => error.operator_state === 'read_incomplete');
  }
  f.mode = 'corrupt-tail';
  await assert.rejects(runDiscussionRead({ ...f.connection, operation: 'show', number: 1, limit: 1, maxPages: 2 }),
    error => error.operator_state === 'read_incomplete');
  f.mode = null;
  assert.equal((await runDiscussionRead({ ...f.connection, operation: 'show', number: 1, limit: 1, maxPages: 2 })).complete, true);
});

test('snapshot changes and post-page revocation fail the whole read', async t => {
  const f = await discussionPeer(t); f.seed(1); f.seed(2);
  for (const mode of ['wrong-head', 'unauthorized']) {
    f.mode = null;
    await assert.rejects(runDiscussionRead({ ...f.connection, operation: 'list', limit: 1, maxPages: 2,
      onProgress: () => { f.mode = mode; } }), error => error.operator_state === 'read_incomplete');
  }
  f.mode = null; assert.equal((await runDiscussionRead({ ...f.connection, operation: 'list', limit: 1, maxPages: 2 })).complete, true);
});

test('output budget, redirects and explicit cancellation refuse without hidden writes', async t => {
  const f = await discussionPeer(t); f.seed();
  await assert.rejects(runDiscussionRead({ ...f.connection, operation: 'list', maxOutputBytes: 32 }), error => error.code === 'discussion_read_output_limit');
  const stop = new AbortController();
  await assert.rejects(runDiscussionRead({ ...f.connection, operation: 'list', signal: stop.signal,
    onProgress: () => stop.abort() }), error => error.code === 'discussion_read_cancelled_or_deadline');
  f.mode = 'redirect'; await assert.rejects(runDiscussionRead({ ...f.connection, operation: 'list' }));
  assert.equal(f.calls.some(call => call.path === '/untrusted'), false); assert.equal(mutations(f).length, 0);
});

test('CLI reads are ordinary subprocesses with explicit continuation and no credentials in output', async t => {
  const f = await discussionPeer(t); f.seed(1); f.seed(2);
  const prefix = await discussionCommand([...f.flags('list'), '--limit', '1']).done;
  assert.equal(prefix.code, 4, prefix.stderr); assert.equal(prefix.stderr, '');
  const p = JSON.parse(prefix.stdout); assert.equal(p.continuation.after, 1); assert.equal(p.read_only, true);
  const rest = await discussionCommand([...f.flags('list'), '--after', '1', '--expected-head', p.snapshot_token, '--limit', '1']).done;
  assert.equal(rest.code, 0, rest.stderr); assert.equal(JSON.parse(rest.stdout).pages[0].discussions[0].number, 2);
  const bad = await discussionCommand([...f.flags('list'), '--after', '1']).done;
  assert.equal(bad.code, 2); assert.equal(bad.stdout, '');
  assert.equal(JSON.parse(bad.stderr).code, 'discussion_read_snapshot_required');
  const token = (await readFile(f.tokenFile, 'utf8')).trim(); assert.ok(!prefix.stdout.includes(token)); assert.ok(!rest.stdout.includes(token));
});

test('CLI body files preserve empty edits, reject invalid UTF-8 and never leak private diagnostics', async t => {
  const f = await discussionPeer(t); f.seed(); const path = join(f.root, 'body');
  await writeFile(path, '', { mode: 0o600 });
  const edit = await discussionCommand([...f.flags('edit', join(f.root, 'edit.json')), '--number', '1', '--expected-version', '1', '--body-file', path]).done;
  assert.equal(edit.code, 0, edit.stderr); assert.equal(f.rows.get(1).body, '');
  const calls = f.calls.length; await writeFile(path, Buffer.from([0xff, 0x70, 0x72, 0x69, 0x76, 0x61, 0x74, 0x65]));
  const bad = await discussionCommand([...f.flags('append-comment', join(f.root, 'bad.json')), '--number', '1', '--body-file', path]).done;
  assert.equal(bad.code, 2); assert.equal(bad.stdout, ''); assert.ok(!bad.stderr.includes('private')); assert.equal(f.calls.length, calls);
});

test('read and mutation grammars reject ambiguous options and preserve strict versus append modes', async t => {
  const f = await discussionPeer(t), reading = { ...f.connection, operation: 'list' };
  for (const raw of [{ ...reading, number: 1 }, { ...reading, after: 1 }, { ...reading, limit: 101 },
      { ...reading, maxPages: 101 }, { ...reading, maxOutputBytes: 8388609 }, { ...reading, operation: 'search' },
      { ...reading, record: join(f.root, 'unexpected') }]) assert.throws(() => discussionReadOptions(raw));
  const base = f.flags('append-comment', join(f.root, 'record'));
  assert.equal(discussionArguments([...base, '--number', '1', '--body', 'hello']).options.expectedVersion, null);
  for (const args of [[...base, '--number', '1', '--expected-version', '1', '--body', 'hello'],
      [...base, '--number', '1', '--body', 'x', '--body-file', '/tmp/file'],
      [...base, '--number', '1', '--label', 'x'], [...base, '--number', '1', '--title', 'x'],
      [...base, '--number', '1', '--number', '2'], [...f.flags('list'), '--record', '/tmp/file'],
      [...f.flags('show'), '--number', '01'], [...f.flags('retry', '/tmp/file'), '--expected-version', '1'],
      [...f.flags('comment', '/tmp/file'), '--number', '1', '--body', 'hello'],
      [...f.flags('edit', '/tmp/file'), '--number', '1', '--expected-version', '1'],
      [...f.flags('list'), '--limit']]) assert.throws(() => discussionArguments(args));
  assert.equal(f.calls.length, 0);
});
