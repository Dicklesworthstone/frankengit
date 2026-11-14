// Real client, WebCrypto and streaming HTTP bodies, with controlled server
// replies. Native event/CAS and browser rendering are separate evidence lanes.
import test from 'node:test';
import assert from 'node:assert/strict';
import { PullClient } from '../../crates/fgit-node/src/smart_http/server/browser/pulls.mjs';
import { Transport, pullLabels, pullLabelState, pullLabelsReply, prRow, listReply } from '../../crates/fgit-node/src/smart_http/server/browser/pulls-core.mjs';
import { pullLabelsCommand, requestBody, requestPath, publication } from '../../crates/fgit-node/src/smart_http/server/browser/pulls-actions.mjs';
import { options, deferred, scope, page, row, ids, head, metadata } from './pulls-fixtures.mjs';
import { fixture as candidateFixture } from './pulls-candidate-fixtures.mjs';
import { actor, token, json, observed, labelsReply, labelsTerminal, labelsOutcome, clientFixture } from './pulls-labels-fixtures.mjs';

const route = 'pulls/1/labels';
const writing = { method: 'POST', body: 'expected_version=2&label=bug', key: 'original-label-key',
  read: false, statuses: [200, 409], maximum: 32 * 1024 };
const reading = { statuses: [200, 404], maximum: 32 * 1024 };

test('label identity preserves case, spaces and Unicode while matching native UTF-8 ordering', () => {
  const supplied = ['𐀀', '\ue000', 'é', 'e\u0301', ' bug ', 'Bug', 'bug', '<script>inert</script>'];
  const expected = [...supplied].sort((a, b) => Buffer.compare(Buffer.from(a), Buffer.from(b)));
  assert.deepEqual(pullLabels(supplied), expected);
  assert.notDeepEqual([...supplied].sort(), expected, 'UTF-16 sorting would change the canonical set');
  assert.deepEqual(pullLabels(expected, true), expected);
  assert.deepEqual(supplied, ['𐀀', '\ue000', 'é', 'e\u0301', ' bug ', 'Bug', 'bug', '<script>inert</script>']);
  assert.throws(() => pullLabels([...expected].reverse(), true));
  assert.equal(pullLabels(['é'.repeat(32)])[0].length, 32);
  assert.equal(pullLabels(['🦀'.repeat(16)])[0].length, 32);
  assert.equal(pullLabels(Array.from({ length: 32 }, (_, n) => String(n))).length, 32);
  assert.deepEqual(pullLabels(['\ufeff']), ['\ufeff'], 'BOM is literal text, not Rust White_Space');
  for (const blank of [' ', '\u00a0', '\u1680', '\u2000', '\u200a', '\u2028', '\u2029', '\u202f', '\u205f', '\u3000']) {
    assert.throws(() => pullLabels([blank]));
  }
});

for (const [name, values] of [
  ['not an array', 'bug'], ['empty name', ['']], ['blank name', [' \t ']], ['duplicate', ['bug', 'bug']],
  ['count', Array.from({ length: 33 }, (_, n) => String(n))], ['ASCII bytes', ['a'.repeat(65)]],
  ['UTF-8 bytes', ['é'.repeat(33)]], ['astral bytes', ['🦀'.repeat(17)]], ['unpaired surrogate', ['\ud800']],
  ['NUL', ['a\0b']], ['newline', ['a\nb']], ['DEL', ['a\x7fb']], ['C1 control', ['a\x85b']],
]) test(`invalid labels refuse ${name}`, () => assert.throws(() => pullLabels(values)));

test('label state distinguishes untouched, cleared, malformed and older-server rows', () => {
  assert.deepEqual(pullLabelState({ labels: [], labels_version: 0, labels_actor: null }), { labels: [], version: 0, actor: null });
  assert.deepEqual(pullLabelState({ labels: [], labels_version: 3, labels_actor: actor }), { labels: [], version: 3, actor });
  assert.equal(pullLabelState(row(), { optional: true }), null);
  assert.doesNotThrow(() => prRow(row(), 'sha1'));
  for (const patch of [{ labels: ['bug'] }, { labels: [], labels_version: 0 },
    { labels: ['bug'], labels_version: 0, labels_actor: null }, { labels: [], labels_version: 0, labels_actor: actor },
    { labels: [], labels_version: 1, labels_actor: null }, { labels: [], labels_version: Number.MAX_SAFE_INTEGER + 1, labels_actor: actor }]) {
    assert.throws(() => prRow(row(1, patch), 'sha1'));
  }
});

for (const format of ['sha1', 'sha256']) {
  test(`${format}: replacement and explicit clearing encode only independent labels version and complete set`, () => {
    const original = { object_format: format, expected_version: 2, labels: ['triage + &', 'bug'] };
    const body = requestBody('set-labels', original, null, 'a'.repeat(32));
    assert.deepEqual(body.fields, { ...original, labels: ['bug', 'triage + &'] });
    assert.deepEqual([...new URLSearchParams(new TextDecoder().decode(body.bytes))],
      [['expected_version', '2'], ['label', 'bug'], ['label', 'triage + &']]);
    assert.equal(requestPath(1, 'set-labels'), route);
    const clear = requestBody('set-labels', { ...original, expected_version: 0, labels: [] }, null, 'b'.repeat(32));
    assert.equal(new TextDecoder().decode(clear.bytes), 'expected_version=0&clear_labels=true');
    for (const extra of [{ expected_version: -1 }, { expected_version: '2' }, { expected_version: Number.MAX_SAFE_INTEGER },
      { labels: undefined }, { labels: ['bug', 'bug'] }, { principal: actor }, { force: true }, { pull_request_version: 9 },
      { source_tip: 'a'.repeat(40) }, { clear_labels: true }]) assert.throws(() => pullLabelsCommand({ ...original, ...extra }));
    assert.throws(() => requestBody('set-labels', original, new Uint8Array([1]), 'a'.repeat(32)));
    assert.throws(() => requestBody('set-labels', original, null, 'wrong'));
    assert.deepEqual(original.labels, ['triage + &', 'bug']);
    // Labels never become an implicit field in existing full metadata writes.
    assert.equal(new URLSearchParams(new TextDecoder().decode(requestBody('update', metadata(), null, 'a'.repeat(32)).bytes)).has('label'), false);
  });

  test(`${format}: exact GET pins selected PR version and scope before replacement`, async () => {
    const f = await clientFixture({ observation: observed(format) });
    const selected = await f.load();
    assert.equal(f.calls.at(-1).url.searchParams.get('expected_head'), f.selected.head);
    assert.equal(f.calls.at(-1).method, 'GET'); assert.equal(f.calls.at(-1).body, undefined);
    assert.equal(f.calls.at(-1).headers['Idempotency-Key'], undefined);
    assert.equal(selected.reply.pull_request_version, 9); assert.equal(selected.reply.labels_version, 2);
    await f.client.stageLabels(1, selected, ['reviewed']);
    assert.equal(f.client.pending.fields.expected_version, 2);
    assert.equal(f.client.pending.fields.object_format, format);
    assert.equal(f.calls.length, 2, 'staging creates no network effect');
    const terminal = await f.client.send();
    assert.equal(terminal.action, 'set-labels'); assert.equal(terminal.number, 1); assert.equal(terminal.outcome, 'committed');
    assert.equal(f.client.pending, null); f.client.disconnect();
  });
}

test('labels GET rejects changed head, source head, metadata version, label version, set, scope and contradictory absence', async () => {
  const good = observed();
  for (const patch of [{ snapshot_token: `alg:1:${'c'.repeat(64)}` }, { source_head: 'different-head' },
    { repository_incarnation: 'different-incarnation' }, { object_format: 'sha256' }, { number: 2 },
    { pull_request_version: 2 }, { labels_version: 3 }, { labels_actor: '7'.repeat(32) }, { labels: ['other'] },
    { read_only: false }, { transaction_created: true }, { found: false },
    { type: 'pull_request' }, { labels: ['z', 'a'] }]) {
    const f = await clientFixture({ observation: good, read: () => json(labelsReply(good, patch)) });
    await assert.rejects(f.load(), JSON.stringify(patch));
    assert.equal(f.client.pending, null); f.client.disconnect();
  }
  const absent = labelsReply(good, { found: false, pull_request_version: null, labels_version: null, labels_actor: null, labels: null });
  const f = await clientFixture({ read: () => json(absent, 404) });
  const missing = await f.load(); assert.equal(missing.reply.found, false);
  await assert.rejects(f.client.stageLabels(1, missing, ['bug'])); f.client.disconnect();
  const wrongStatus = await clientFixture({ read: () => json(absent, 200) });
  await assert.rejects(wrongStatus.load()); wrongStatus.client.disconnect();
});

test('closed and merged native PR labels remain editable but merge-only records do not', async () => {
  for (const state of ['closed', 'merged']) {
    const value = observed(); value.pull_request.state = state;
    if (state === 'merged') value.pull_request.merge = { ...value.pull_request.data,
      target_tip_before: value.pull_request.data.target_tip, base_tip: 'c'.repeat(40), merge_commit: 'd'.repeat(40) };
    const f = await clientFixture({ observation: value }); await f.client.stageLabels(1, await f.load(), ['triage']);
    assert.equal((await f.client.send()).outcome, 'committed'); f.client.disconnect();
    if (state === 'merged') {
      value.pull_request.data = null; value.pull_request.merge_only = true;
      const old = await clientFixture({ observation: value }); await assert.rejects(old.load());
      assert.equal(old.calls.length, 1); old.client.disconnect();
    }
  }
});

test('legacy PR responses stay readable while unsupported labels never enable staging', async () => {
  const value = observed(); for (const key of ['labels', 'labels_version', 'labels_actor']) delete value.pull_request[key];
  const f = await clientFixture({ observation: value, read: () => json({}, 404) });
  assert.equal(f.selected.reply.found, true); await assert.rejects(f.load());
  await assert.rejects(f.client.stageLabels(1, f.selected, ['bug'])); assert.equal(f.client.pending, null);
  f.client.disconnect();
});

test('filtered listing canonicalizes AND predicates, pins continuation and refuses filter or row substitution', async () => {
  const filters = ['bug', 'needs review'];
  let requests = 0;
  const client = new PullClient(options((url) => {
    requests += 1;
    assert.deepEqual(url.searchParams.getAll('label'), filters);
    const after = Number(url.searchParams.get('after'));
    if (after) assert.equal(url.searchParams.get('expected_head'), head);
    return json(page({ labels: filters, after, limit: 1, next_after: after ? null : 3,
      pull_requests: [row(after ? 7 : 3, { labels: filters, labels_version: 4, labels_actor: actor })] }));
  }));
  await client.connect(token);
  const input = ['needs review', 'bug'], first = await client.list({ limit: 1, labels: input });
  assert.deepEqual(input, ['needs review', 'bug']);
  await client.list({ after: first.reply.next_after, limit: 1, head: first.head, labels: filters });
  assert.equal(requests, 2);
  await assert.rejects(client.list({ after: 3, labels: filters }));
  await assert.rejects(client.list({ labels: ['bug', 'bug'] }));
  assert.equal(requests, 2); client.disconnect();
  const args = { labels: filters }, good = page({ labels: filters,
    pull_requests: [row(1, { labels: filters, labels_version: 4, labels_actor: actor })] });
  assert.doesNotThrow(() => listReply(good, args));
  for (const value of [page(), { ...good, labels: ['bug'] }, { ...good, labels: [...filters].reverse() },
    { ...good, pull_requests: [row()] }, { ...good, pull_requests: [row(1, { labels: ['bug'], labels_version: 4, labels_actor: actor })] }]) {
    assert.throws(() => listReply(value, args));
  }
});

test('closed labels transport checks read/write envelopes before request and other page profiles refuse it', async () => {
  const calls = [], transport = new Transport(options((url, init) => { calls.push({ url, ...init }); return json({}); }));
  await transport.connect(token);
  for (const override of [{ method: 'PUT' }, { method: 'GET' }, { key: undefined }, { key: '' }, { body: undefined },
    { read: true }, { binary: true }, { contentType: 'application/json' }, { statuses: [200] },
    { statuses: [200, 404] }, { maximum: 32769 }, { headerNames: ['x-unknown'] }]) {
    await assert.rejects(transport.request(route, { ...writing, ...override }), JSON.stringify(override));
  }
  await assert.rejects(transport.request(`${route}?label=bug`, writing));
  for (const override of [{ body: 'label=bug' }, { key: 'key' }, { read: false }, { method: 'DELETE' }, { statuses: [200] }]) {
    await assert.rejects(transport.request(route, { ...reading, ...override }));
  }
  assert.equal(calls.length, 0);
  await transport.request(route, reading); await transport.request(route, writing);
  assert.equal(calls.length, 2);
  assert.equal(calls[1].headers['Idempotency-Key'], writing.key);
  for (const pageSuffix of ['/ui/source/', '/ui/initial/', '/ui/branches/', '/ui/default-branch/', '/ui/search/',
    '/ui/transfers/', '/ui/tags/', '/ui/replay/', '/ui/rebase/', '/ui/queues/', '/ui/artifacts/']) {
    const other = new Transport({ ...options(() => { throw new Error('No request permitted'); }),
      href: `https://forge.example/team/repo.git${pageSuffix}`, pageSuffix });
    await other.connect(token); await assert.rejects(other.request(route, writing));
    await assert.rejects(other.request(route, reading)); other.disconnect();
  }
  transport.disconnect();
});

test('staging freezes caller arrays, returned summaries and predecessor before asynchronous key derivation', async () => {
  const f = await clientFixture(), selected = await f.load(), supplied = ['bug', 'reviewed'];
  const preparing = f.client.stageLabels(1, selected, supplied);
  supplied.push('late'); selected.reply.labels_version = 90; selected.reply.labels.push('changed');
  await preparing;
  const pending = f.client.pending; pending.fields.labels.push('mutated summary');
  assert.deepEqual(f.client.pending.fields.labels, ['bug', 'reviewed']);
  assert.equal(f.client.pending.fields.expected_version, 2);
  await assert.rejects(f.client.stageLabels(1, selected, ['replacement']));
  assert.equal(f.calls.length, 2); f.client.disconnect();
});

test('lost label reply and absent recovery retain original body, key and responsibility until explicit retry', async () => {
  let attempts = 0;
  const f = await clientFixture({ dispatch: (_call, pending) => {
    if (++attempts === 1) throw new Error('lost after possible commit');
    return json(labelsTerminal(pending));
  } });
  await f.client.stageLabels(1, await f.load(), ['bug', 'reviewed']); const pending = f.client.pending;
  await assert.rejects(f.client.send(), error => error.outcomeUnknown === true);
  assert.equal(f.client.pending.key, pending.key); assert.throws(() => f.client.discardUnsent());
  const unknown = await f.client.recover(); assert.equal(unknown.terminal, false); assert.equal(unknown.action, 'set-labels');
  assert.equal(attempts, 1); assert.equal(f.calls.at(-1).body, undefined);
  assert.equal(f.calls.at(-1).headers['Idempotency-Key'], pending.key);
  await f.client.send(); assert.equal(f.client.pending, null);
  const writes = f.calls.filter(call => call.url.pathname.endsWith('/labels') && call.method === 'POST');
  assert.equal(writes.length, 2); assert.equal(writes[0].bytes, writes[1].bytes);
  assert.equal(writes[0].headers['Idempotency-Key'], writes[1].headers['Idempotency-Key']); f.client.disconnect();
});

test('token-free receipts restore exact replacement and reject label/version/number/scope/action tampering', async () => {
  const f = await clientFixture(); await f.client.stageLabels(1, await f.load(), ['bug', 'reviewed']);
  const receipt = f.client.exportReceipt(), original = JSON.parse(receipt);
  assert.equal(receipt.includes(token), false); assert.equal(original.request.bundle_base64, null);
  assert.throws(() => f.client.discardUnsent()); f.client.disconnect();
  const restored = await clientFixture(); await restored.client.restoreReceipt(receipt);
  assert.deepEqual(JSON.parse(restored.client.exportReceipt()), original); assert.equal(restored.calls.length, 1);
  await restored.client.send();
  assert.equal(restored.calls.at(-1).bytes, 'expected_version=2&label=bug&label=reviewed');
  restored.client.disconnect();
  for (const alter of [r => { r.request.fields.labels = ['different']; }, r => { r.request.fields.expected_version = 9; },
    r => { r.request.number = 2; }, r => { r.request.scope.incarnation = 'other'; },
    r => { r.request.action = 'update'; }, r => { r.request.fields.force = true; }]) {
    const value = structuredClone(original); alter(value);
    const other = await clientFixture(); await assert.rejects(other.client.restoreReceipt(JSON.stringify(value)));
    assert.equal(other.client.pending, null); assert.equal(other.calls.length, 1); other.client.disconnect();
  }
});

test('terminal labels receipts must echo the exact set and independent version with unchanged refs and PR metadata', async () => {
  const f = await clientFixture(); await f.client.stageLabels(1, await f.load(), ['bug', 'reviewed']);
  const pending = f.client.pending;
  for (const outcome of ['committed', 'refused']) {
    const good = labelsTerminal(pending, outcome), status = outcome === 'committed' ? 200 : 409;
    assert.equal(publication(good, pending, status).outcome, outcome);
    for (const patch of [{ labels: ['bug'] }, { labels: ['reviewed', 'bug'] }, { expected_version: 9 },
      { labels_version: 10 }, { refs_changed: true }, { pull_request_version_changed: true },
      { number: 2 }, { action: 'update' }, { type: 'pull_request_publication' }, { delivery_acknowledged: true }]) {
      assert.throws(() => publication({ ...good, ...patch }, pending, status), JSON.stringify(patch));
    }
    assert.throws(() => publication(good, pending, status === 200 ? 409 : 200));
  }
  f.client.disconnect();
});

test('malformed terminal or missing write grant preserves the original label request', async () => {
  for (const status of [200, 401, 403]) {
    const f = await clientFixture({ dispatch: (_call, pending) => json(status === 200
      ? labelsTerminal(pending, 'committed', { labels: ['substituted'] }) : {}, status) });
    await f.client.stageLabels(1, await f.load(), ['reviewed']); const key = f.client.pending.key;
    await assert.rejects(f.client.send()); assert.equal(f.client.pending.key, key); assert.equal(f.client.pending.sent, true);
    assert.equal(f.client.connected, status !== 401); f.client.disconnect();
  }
});

test('label publication and terminal recovery preserve an inspected merge candidate', async () => {
  for (const recover of [false, true]) {
    const candidate = candidateFixture();
    const f = await clientFixture({ observation: observed('sha1', { version: 1 }),
      request: call => call.url.pathname.endsWith('/inspect') ? json(candidate.inspection) : null,
      recover: () => json(labelsOutcome('committed')) });
    await f.client.inspect(1, candidate.fields, candidate.bundle); const before = f.client.candidate;
    await f.client.stageLabels(1, await f.load(), ['reviewed']);
    const result = recover ? await f.client.recover() : await f.client.send();
    assert.equal(result.action, 'set-labels'); assert.deepEqual(f.client.candidate, before);
    f.client.disconnect();
  }
});

test('read cancellation cannot cancel publication and disconnect suppresses a late terminal while retaining its key', async () => {
  const late = deferred(); let dispatched;
  const f = await clientFixture({ dispatch: call => { dispatched = call; return late.promise; } });
  await f.client.stageLabels(1, await f.load(), ['reviewed']); const pending = f.client.pending;
  const sending = f.client.send(), rejected = assert.rejects(sending);
  while (!dispatched) await new Promise(setImmediate);
  f.client.cancelReads(); assert.equal(dispatched.signal.aborted, false);
  f.client.disconnect(); assert.equal(dispatched.signal.aborted, true);
  late.resolve(json(labelsTerminal(pending))); await rejected;
  assert.equal(f.client.pending.key, pending.key); assert.equal(f.client.pending.sent, true);
});

test('disconnect during labels GET cannot select or stage the detached observation', async () => {
  const late = deferred(); let call;
  const f = await clientFixture({ read: value => { call = value; return late.promise; } });
  const reading = f.load(), rejected = assert.rejects(reading);
  while (!call) await new Promise(setImmediate);
  f.client.disconnect(); late.resolve(json(labelsReply(f.observation))); await rejected;
  assert.equal(call.signal.aborted, true); assert.equal(f.client.pending, null);
});

test('rotated credentials can recover a retained label receipt but never resend or read labels', async () => {
  const f = await clientFixture(); await f.client.stageLabels(1, await f.load(), ['reviewed']);
  const receipt = f.client.exportReceipt(), key = f.client.pending.key; f.client.disconnect();
  const calls = [], client = new PullClient(options((url, init) => {
    calls.push({ url, ...init }); return json(labelsOutcome('committed'));
  }));
  await client.connect('d'.repeat(64), { recoveryOnly: true, originalPrincipal: actor });
  await client.restoreReceipt(receipt);
  await assert.rejects(client.send()); await assert.rejects(client.labels(1, f.selected));
  const result = await client.recover(); assert.equal(result.outcome, 'committed'); assert.equal(result.action, 'set-labels');
  assert.equal(calls.length, 1); assert.equal(calls[0].url.pathname.endsWith('/outcomes'), true);
  assert.equal(calls[0].body, undefined); assert.equal(calls[0].headers['Idempotency-Key'], key);
  assert.equal(client.pending, null); client.disconnect();
});
