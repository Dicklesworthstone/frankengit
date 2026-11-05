import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile, writeFile, chmod, lstat, readdir, symlink, link, open } from 'node:fs/promises';
import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { runInboxOperation, inboxOperatorOptions } from '../../scripts/lib/forge-inbox-operator.mjs';
import { inboxArguments, runInboxCommand } from '../../scripts/forge_inbox.mjs';
import { operatorJson } from '../../scripts/lib/forge-operator-io.mjs';
import { fixture, mutations, reads, command, flags, guards, principal, incarnation, token, versionField } from './inbox-peer.mjs';

const interrupted = ({ phase }) => { if (phase === 'receipt_saved') throw Error('simulated interruption before dispatch'); };
const originalBytes = f => readFile(f.options().record);

for (const kind of ['issue', 'discussion']) {
  test(`${kind}: complete list, exact show and canonical absence use the correct authenticated namespace`, async t => {
    const f = await fixture(t);
    const list = await runInboxOperation(f.options('list', kind));
    assert.equal(list.complete, true); assert.equal(list.read_only, true); assert.equal(list.mutation_submitted, false);
    assert.deepEqual(list.pages[0].threads.map(row => row.number), [7, 11]);
    assert.equal(list.pages[0].threads[0][versionField(kind)], 4);
    const show = await runInboxOperation(f.options('show', kind));
    assert.equal(show.pages[0].thread.number, 7); assert.equal(show.pages[0].found, true);
    const absent = await runInboxOperation({ ...f.options('show', kind), number: 99 });
    assert.equal(absent.pages[0].found, false); assert.equal(absent.pages[0].thread, null); assert.equal(absent.complete, true);
    const family = kind === 'discussion' ? '/repo/api/v1/notifications/discussions' : '/repo/api/v1/notifications';
    assert.deepEqual(reads(f).map(call => call.path), [family, family + '/7', family + '/99']);
    assert.equal(mutations(f).length, 0); assert.deepEqual(await readdir(f.root), ['token']);
  });

  test(`${kind}: multiple pages retain the original snapshot when current activity advances`, async t => {
    const f = await fixture(t), pinned = f.head;
    f.afterRead = () => { f.afterRead = null; f.row(kind, 11).title = 'Newer title'; f.capture(); };
    const result = await runInboxOperation({ ...f.options('list', kind), limit: 1, maxPages: 5 });
    assert.equal(result.page_count, 2); assert.equal(result.complete, true); assert.equal(result.snapshot_token, pinned);
    assert.deepEqual(result.pages.map(page => page.threads[0].title), ['A thread', 'Own activity']);
    assert.equal(reads(f)[0].query.expected_head, undefined); assert.equal(reads(f)[1].query.expected_head, pinned);
    assert.deepEqual(result.pages.map(page => page.source_positions.authority_head_generation), [1, 1]);
  });

  test(`${kind}: all preference operations preserve the other namespace and use exact predecessor versions`, async t => {
    const f = await fixture(t), otherKind = kind === 'issue' ? 'discussion' : 'issue', other = structuredClone(f.rows[otherKind]);
    const actions = ['subscribe', 'mute', 'automatic', 'read', 'unread'];
    for (const [index, action] of actions.entries()) {
      const options = f.options(action, kind, join(f.root, action + '.json'));
      if (action === 'read') options.readThrough = 3;
      const result = await runInboxOperation(options);
      assert.equal(result.result.outcome, 'committed'); assert.equal(result.mutation_submitted, true);
      assert.equal(f.row(kind).preference_version, 3 + index);
      assert.equal(f.row(kind).mode, index === 0 ? 'subscribed' : index === 1 ? 'muted' : 'automatic');
      assert.equal(f.row(kind).read_through, index < 3 ? 1 : index === 3 ? 3 : null);
      assert.equal(f.row(kind).unread, index !== 3);
      const call = mutations(f)[index], form = new URLSearchParams(call.body);
      assert.equal(form.get('expected_version'), String(2 + index));
      assert.equal(form.get('expected_principal'), principal); assert.equal(form.get('expected_incarnation'), incarnation);
      assert.equal(form.get('read_through'), action === 'read' ? '3' : null);
      assert.match(call.key, kind === 'discussion' ? /^fgdn-[0-9a-f]{32}-[0-9a-f]{64}$/ : /^fgni-[0-9a-f]{32}-[0-9a-f]{64}$/);
    }
    assert.deepEqual(f.rows[otherKind], other); assert.equal(mutations(f).length, actions.length);
  });

  test(`${kind}: read acknowledges precisely the observed prefix across a racing comment`, async t => {
    const f = await fixture(t);
    f.afterRead = () => { f.afterRead = null; f.row(kind)[versionField(kind)] = 5; f.row(kind).latest_other_version = 5; f.capture(); };
    const result = await runInboxOperation(f.options('read', kind));
    assert.equal(result.result.outcome, 'committed'); assert.equal(f.row(kind).read_through, 4);
    assert.equal(f.row(kind).latest_other_version, 5); assert.equal(f.row(kind).unread, true);
    assert.equal(new URLSearchParams(mutations(f)[0].body).get('read_through'), '4');
  });
}

test('bounded CLI read returns a recipient-bound continuation that a fresh process can resume', async t => {
  const f = await fixture(t);
  const first = await command([...flags(f, 'list'), '--limit', '1']).done;
  assert.equal(first.code, 4); assert.equal(first.stderr, '');
  const result = JSON.parse(first.stdout), continuation = result.continuation;
  assert.equal(result.complete, false); assert.equal(result.stop_reason, 'page_budget');
  assert.equal(continuation.expected_principal, principal); assert.equal(continuation.expected_incarnation, incarnation);
  const next = await command([...flags(f, 'list'), '--limit', '1', '--after', String(continuation.after),
    '--expected-head', continuation.expected_head, '--expected-principal', continuation.expected_principal,
    '--expected-incarnation', continuation.expected_incarnation]).done;
  assert.equal(next.code, 0); assert.deepEqual(JSON.parse(next.stdout).pages[0].threads.map(row => row.number), [11]);
  const show = await command([...flags(f, 'show'), '--number', '7']).done;
  assert.equal(show.code, 0); assert.equal(JSON.parse(show.stdout).pages[0].thread.number, 7);
  assert.equal(mutations(f).length, 0);
});

test('unread and muted filters remain explicit and are checked against every returned row', async t => {
  const f = await fixture(t);
  const unread = await runInboxOperation({ ...f.options('list'), unreadOnly: true });
  assert.deepEqual(unread.pages[0].threads.map(row => row.number), [7]);
  const muted = await runInboxOperation({ ...f.options('list'), unreadOnly: true, includeMuted: true });
  assert.deepEqual(muted.pages[0].threads.map(row => row.number), [7, 9]);
  assert.equal(reads(f).at(-1).query.unread_only, 'true'); assert.equal(reads(f).at(-1).query.include_muted, 'true');
  f.onRead = ({ reply }) => { reply.threads = [structuredClone(f.row('issue', 9))]; };
  await assert.rejects(runInboxOperation(f.options('list')));
});

test('snapshot, recipient, incarnation and source-position drift cannot produce an apparently complete read', async t => {
  const f = await fixture(t);
  for (const mutate of [
    reply => { reply.snapshot_token = 'alg:2:' + 'ff'.repeat(32); },
    reply => { reply.principal_id = '55'.repeat(16); },
    reply => { reply.repository_incarnation = '66'.repeat(16); },
    reply => { reply.repository_id = '77'.repeat(16); },
    reply => { reply.source_positions.complete = false; },
    reply => { reply.source_positions.authority_head_generation++; },
    reply => { reply.source_positions.forge_position_root += '-different'; },
    reply => { reply.source_positions.outbox_root += '-different'; },
    reply => { reply.target_kind = 'discussion'; },
    reply => { reply.next_after = reply.after; },
  ]) {
    let page = 0; f.onRead = ({ reply }) => { if (++page === 2) mutate(reply); };
    const output = await command([...flags(f, 'list'), '--limit', '1', '--max-pages', '3']).done;
    assert.equal(output.code, 2); assert.equal(output.stdout, '');
    assert.equal(JSON.parse(output.stderr).state, 'read_incomplete'); assert.equal(page, 2);
  }
});

test('historical continuation refuses a changed recipient even when the first page of a new process is valid', async t => {
  const f = await fixture(t), head = f.head; f.principal = '88'.repeat(16);
  await assert.rejects(runInboxOperation({ ...f.options('list'), after: 7, head,
    expectedPrincipal: principal, expectedIncarnation: incarnation }), error => error.code === 'inbox_operator_identity_changed');
  assert.equal(mutations(f).length, 0);
});

test('read output is bounded, strips unvalidated server extras and escapes terminal controls', async t => {
  const f = await fixture(t); f.row().title = 'Thread\u202ewith direction'; f.capture();
  f.onRead = ({ reply }) => { reply.debug_token = token; for (const row of reply.threads ?? []) row.private_body = 'do not forward'; };
  const result = await runInboxCommand(flags(f, 'list'));
  assert.equal(result.exitCode, 0); assert.ok(result.text.includes('\\u202e')); assert.ok(!result.text.includes('\u202e'));
  assert.ok(!result.text.includes(token)); assert.ok(!result.text.includes('private_body'));
  assert.equal(JSON.parse(result.text).pages[0].threads[0].title, 'Thread\u202ewith direction');
  await assert.rejects(runInboxOperation({ ...f.options('list'), maxOutputBytes: 10 }), error => error.code === 'inbox_read_output_limit');
});

test('fresh write retains an exact private token-free record before the first HTTP mutation', async t => {
  const f = await fixture(t), options = f.options();
  f.onMutation = ({ key, body }) => {
    const bytes = readFileSync(options.record), record = JSON.parse(bytes);
    assert.equal(record.receipt.request.key, key); assert.equal(record.receipt.request.body, body);
    assert.equal(record.receipt.request.binding.principal, principal); assert.equal(record.receipt.request.binding.incarnation, incarnation);
    assert.ok(!bytes.includes(token)); assert.equal(record.receipt.request.exported, true);
  };
  const result = await runInboxOperation(options);
  assert.equal(result.state, 'terminal_observed'); assert.match(result.record_sha256, /^[0-9a-f]{64}$/);
  assert.equal(Number((await lstat(options.record)).mode) & 0o777, 0o600);
  const bytes = await originalBytes(f);
  for (const operation of ['status', 'retry']) {
    const recovered = await runInboxOperation(f.options(operation));
    assert.equal(recovered.result.outcome, 'committed'); assert.equal(recovered.mutation_submitted, false);
  }
  assert.equal(mutations(f).length, 1); assert.deepEqual(await originalBytes(f), bytes);
  for (const call of f.calls) assert.equal(call.userAgent, 'frankengit-agent (+https://github.com/Dicklesworthstone/frankengit)');
});

test('fresh writes refuse missing threads, stale preferences, unobserved read prefixes and changed identity before recording', async t => {
  const f = await fixture(t);
  for (const [change, code] of [
    [{ number: 99 }, 'inbox_operator_thread_missing'],
    [{ expectedVersion: 1 }, 'inbox_operator_preference_moved'],
    [{ operation: 'read', readThrough: 5 }, 'inbox_operator_read_prefix_unobserved'],
    [{ expectedPrincipal: '55'.repeat(16) }, 'inbox_operator_identity_changed'],
    [{ expectedIncarnation: '66'.repeat(16) }, 'inbox_operator_identity_changed'],
  ]) await assert.rejects(runInboxOperation({ ...f.options(), ...change }), error => error.code === code);
  f.mode = 'wrong-repository'; await assert.rejects(runInboxOperation(f.options()), error => error.code === 'inbox_operator_repository_mismatch');
  f.mode = 'unauthorized'; await assert.rejects(runInboxOperation(f.options()));
  assert.equal(mutations(f).length, 0); assert.deepEqual(await readdir(f.root), ['token']);
});

test('implicit preferences accept exactly zero and subscriptions work outside the current inbox', async t => {
  const f = await fixture(t); f.row('issue', 11).reasons = []; f.capture();
  const list = await runInboxOperation(f.options('list'));
  assert.deepEqual(list.pages[0].threads.map(row => row.number), [7]);
  const result = await runInboxOperation({ ...f.options(), number: 11, expectedVersion: 0 });
  assert.equal(result.result.outcome, 'committed'); assert.equal(f.row('issue', 11).preference_version, 1);
  assert.deepEqual(f.row('issue', 11).reasons, ['subscribed']);
});

test('a preference race produces a canonical terminal refusal without silently refreshing the version', async t => {
  const f = await fixture(t);
  f.afterRead = () => { f.afterRead = null; f.row().preference_version++; f.capture(); };
  const output = await command([...flags(f, 'subscribe'), ...guards(2)]).done;
  assert.equal(output.code, 3); assert.equal(output.stderr, ''); assert.equal(JSON.parse(output.stdout).result.outcome, 'refused');
  assert.equal(new URLSearchParams(mutations(f)[0].body).get('expected_version'), '2');
  assert.equal((await runInboxOperation(f.options('retry'))).result.outcome, 'refused'); assert.equal(mutations(f).length, 1);
});

test('pre-send interruption preserves custody; status observes only and retry resends the original exact key/body', async t => {
  const f = await fixture(t);
  await assert.rejects(runInboxOperation({ ...f.options(), onProgress: interrupted }), error => error.operator_state === 'recorded_unknown');
  const bytes = await originalBytes(f), record = JSON.parse(bytes);
  const status = await command(flags(f, 'status')).done;
  assert.equal(status.code, 2); assert.equal(JSON.parse(status.stdout).state, 'unresolved'); assert.equal(mutations(f).length, 0);
  const retried = await command(flags(f, 'retry')).done;
  assert.equal(retried.code, 0); assert.equal(JSON.parse(retried.stdout).mutation_submitted, true);
  assert.equal(mutations(f)[0].key, record.receipt.request.key); assert.equal(mutations(f)[0].body, record.receipt.request.body);
  assert.deepEqual(await originalBytes(f), bytes); assert.equal(f.row().preference_version, 3);
});

test('lost reply recovers after another preference change without overwriting the later intent', async t => {
  const f = await fixture(t); f.mode = 'lost-reply';
  await assert.rejects(runInboxOperation(f.options()), error => error.operator_state === 'submitted_unknown');
  const bytes = await originalBytes(f); f.mode = null;
  await runInboxOperation(f.options('mute', 'issue', join(f.root, 'later-mute.json')));
  const retried = await command(flags(f, 'retry')).done;
  assert.equal(retried.code, 0); assert.equal(JSON.parse(retried.stdout).result.outcome, 'committed');
  assert.equal(JSON.parse(retried.stdout).mutation_submitted, false); assert.equal(mutations(f).length, 2);
  assert.equal(f.row().mode, 'muted'); assert.equal(f.row().preference_version, 4); assert.deepEqual(await originalBytes(f), bytes);
});

test('a killed sending process is recoverable from its original private record in a fresh process', async t => {
  const f = await fixture(t); f.mode = 'wait';
  const running = command([...flags(f, 'subscribe'), ...guards(2)]);
  f.onMutation = () => { running.child.kill('SIGKILL'); };
  const killed = await running.done; assert.equal(killed.signal, 'SIGKILL'); assert.equal(mutations(f).length, 1);
  const bytes = await originalBytes(f); f.onMutation = null; f.mode = null;
  const recovered = await command(flags(f, 'retry')).done;
  assert.equal(recovered.code, 0); assert.equal(JSON.parse(recovered.stdout).mutation_submitted, false);
  assert.equal(mutations(f).length, 1); assert.deepEqual(await originalBytes(f), bytes);
});

test('malformed success and noncanonical conflict remain unknown until original-key outcome recovery', async t => {
  for (const mode of ['bad-reply', 'bad-refusal']) {
    const f = await fixture(t); f.mode = mode;
    await assert.rejects(runInboxOperation(f.options()), error => error.operator_state === 'submitted_unknown');
    f.mode = null;
    assert.equal((await runInboxOperation(f.options('status'))).result.outcome, 'committed'); assert.equal(mutations(f).length, 1);
  }
});

test('changed authenticated recipient or repository incarnation cannot recover or retry an old record', async t => {
  const f = await fixture(t);
  await assert.rejects(runInboxOperation({ ...f.options(), onProgress: interrupted }));
  for (const key of ['principal', 'incarnation']) {
    const before = f[key]; f[key] = '77'.repeat(16);
    await assert.rejects(runInboxOperation(f.options('retry'))); f[key] = before;
  }
  assert.equal(mutations(f).length, 0);
  assert.equal((await runInboxOperation(f.options('retry'))).result.outcome, 'committed');
});

test('record scope, credential and committed request bytes are checked before any recovery HTTP', async t => {
  const f = await fixture(t); await runInboxOperation(f.options());
  const bytes = await originalBytes(f), calls = f.calls.length;
  await writeFile(f.tokenFile, 'cd'.repeat(32)); await assert.rejects(runInboxOperation(f.options('retry'))); await writeFile(f.tokenFile, token);
  await assert.rejects(runInboxOperation(f.options('retry', 'discussion')));
  await assert.rejects(runInboxOperation({ ...f.options('retry'), repository: '55'.repeat(16) }));
  for (const modify of [
    value => { value.receipt.request.action = 'mute'; },
    value => { value.receipt.request.body += '&read_through=4'; },
    value => { value.receipt.request.binding.principal = '99'.repeat(16); },
    value => { value.receipt.request.key = value.receipt.request.key.replace(/^fgni-/, 'fgdn-'); },
  ]) {
    const value = JSON.parse(bytes); modify(value); await writeFile(f.options().record, JSON.stringify(value) + '\n');
    await assert.rejects(runInboxOperation(f.options('retry')));
  }
  await writeFile(f.options().record, bytes.subarray(0, 20)); await assert.rejects(runInboxOperation(f.options('status')));
  assert.equal(f.calls.length, calls); await writeFile(f.options().record, bytes);
  assert.equal((await runInboxOperation(f.options('status'))).result.outcome, 'committed');
});

test('record and token files enforce private regular single-link ownership without overwriting custody', async t => {
  const f = await fixture(t), options = f.options();
  await chmod(f.tokenFile, 0o644); await assert.rejects(runInboxOperation(options)); await chmod(f.tokenFile, 0o600);
  const tokenLink = join(f.root, 'token-link'); await symlink(f.tokenFile, tokenLink);
  await assert.rejects(runInboxOperation({ ...options, tokenFile: tokenLink }));
  await runInboxOperation(options); const bytes = await originalBytes(f), calls = f.calls.length;
  await assert.rejects(runInboxOperation(options), error => error.code === 'operator_record_exists');
  await chmod(options.record, 0o644); await assert.rejects(runInboxOperation(f.options('status'))); await chmod(options.record, 0o600);
  const recordLink = join(f.root, 'record-link'); await symlink(options.record, recordLink);
  await assert.rejects(runInboxOperation(f.options('retry', 'issue', recordLink)));
  const hardLink = join(f.root, 'record-hardlink'); await link(options.record, hardLink);
  await assert.rejects(runInboxOperation(f.options('retry')));
  assert.equal(f.calls.length, calls); assert.deepEqual(await originalBytes(f), bytes);
});

for (const failure of ['file', 'directory']) test(`${failure} sync failure prevents retry dispatch even for a complete readable record`, async t => {
  const f = await fixture(t);
  await assert.rejects(runInboxOperation({ ...f.options(), onProgress: interrupted }));
  const bytes = await originalBytes(f), probe = await open(f.options().record, 'r');
  const proto = Object.getPrototypeOf(probe), sync = proto.sync; await probe.close();
  let barriers = 0;
  proto.sync = async function () {
    const stat = await this.stat();
    if (failure === 'file' ? stat.isFile() : stat.isDirectory()) { barriers++; throw Object.assign(Error('injected sync error'), { code: 'EIO' }); }
    return sync.call(this);
  };
  try {
    await assert.rejects(runInboxOperation(f.options('retry')), error => error.code === 'EIO');
    assert.equal((await runInboxOperation(f.options('status'))).state, 'unresolved'); assert.equal(mutations(f).length, 0);
  } finally { proto.sync = sync; }
  assert.equal(barriers, 1); assert.deepEqual(await originalBytes(f), bytes);
  assert.equal((await runInboxOperation(f.options('retry'))).result.outcome, 'committed');
  assert.equal(mutations(f)[0].body, JSON.parse(bytes).receipt.request.body);
});

test('changed record after durable save prevents dispatch, and concurrent preparation never overwrites a winner', async t => {
  const f = await fixture(t), options = f.options();
  await assert.rejects(runInboxOperation({ ...options, onProgress: ({ phase }) => {
    if (phase === 'receipt_saved') writeFileSync(options.record, '{}\n');
  } }), error => error.code === 'inbox_operator_record_changed');
  assert.equal(mutations(f).length, 0); assert.equal((await originalBytes(f)).toString(), '{}\n');
  const concurrent = f.options('subscribe', 'issue', join(f.root, 'concurrent.json'));
  const results = await Promise.allSettled([runInboxOperation(concurrent), runInboxOperation(concurrent)]);
  assert.equal(results.filter(result => result.status === 'fulfilled').length, 1);
  assert.equal(mutations(f).length, 1); assert.equal(f.row().preference_version, 3);
});

test('cancellation and whole-invocation deadlines stop reads or retain unknown submitted custody', async t => {
  const f = await fixture(t), stop = new AbortController(); stop.abort();
  await assert.rejects(runInboxOperation({ ...f.options(), signal: stop.signal }), error => error.operator_state === 'not_submitted');
  assert.equal(f.calls.length, 0);
  f.mode = 'wait-read';
  await assert.rejects(runInboxOperation({ ...f.options('list'), timeoutMs: 60 }), error => error.operator_state === 'read_incomplete');
  const sending = new AbortController(); f.mode = 'wait'; f.onMutation = () => sending.abort();
  await assert.rejects(runInboxOperation({ ...f.options(), signal: sending.signal }), error => error.operator_state === 'submitted_unknown');
  assert.equal(mutations(f).length, 1); f.mode = null; f.onMutation = null;
  assert.equal((await runInboxOperation(f.options('status'))).result.outcome, 'committed');
});

test('closed CLI grammar requires kind, paired identities, exact recovery and safe integer coordinates', async t => {
  const f = await fixture(t), list = flags(f, 'list'), mutation = [...flags(f, 'subscribe'), ...guards(2)];
  for (const args of [
    list.filter((_, index) => index !== 1 && index !== 2),
    [...list, '--principal', principal], [...list, '--recipient', principal], [...list, '--kind', 'discussion'],
    [...list, '--after', '7'], [...list, '--expected-head', f.head], [...list, '--expected-principal', principal],
    [...flags(f, 'show'), '--number', '7', '--limit', '1'], [...list, '--number', '7'],
    [...mutation, '--read-through', '4'], [...flags(f, 'read'), ...guards(2)],
    [...flags(f, 'retry'), '--expected-version', '2'], [...flags(f, 'status'), '--expected-principal', principal, '--expected-incarnation', incarnation],
    [...list, '--after', '9007199254740992'], [...list, '--limit', '01'], [...list, '--limit', '101'],
  ]) assert.throws(() => inboxArguments(args));
  assert.throws(() => inboxOperatorOptions({ ...f.options(), kind: 'pull_request' }));
  assert.throws(() => inboxOperatorOptions({ ...f.options(), href: 'http://example.com/repo/ui/notifications/' }));
  assert.throws(() => inboxOperatorOptions({ ...f.options(), href: f.href('discussion') }));
  assert.throws(() => inboxOperatorOptions({ ...f.options(), expectedVersion: Number.MAX_SAFE_INTEGER }));
  assert.throws(() => inboxOperatorOptions({ ...f.options(), record: f.tokenFile }));
  assert.equal(inboxArguments(mutation).expectedVersion, 2); assert.equal(f.calls.length, 0);
  assert.deepEqual(JSON.parse(operatorJson({ title: 'a\u202eb' })), { title: 'a\u202eb' });
});
