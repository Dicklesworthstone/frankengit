// Real client, WebCrypto and request envelopes with controlled HTTP replies.
// Native union/CAS behavior is verified separately by the native labels tests.
import test from 'node:test';
import assert from 'node:assert/strict';
import { PullClient } from '../../crates/fgit-node/src/smart_http/server/browser/pulls.mjs';
import { Transport } from '../../crates/fgit-node/src/smart_http/server/browser/pulls-core.mjs';
import { addPullLabelsCommand, requestBody, requestPath, publication } from '../../crates/fgit-node/src/smart_http/server/browser/pulls-actions.mjs';
import { options, deferred } from './pulls-fixtures.mjs';
import { fixture as candidateFixture } from './pulls-candidate-fixtures.mjs';
import { actor, token, json, observed, labelsTerminal, labelsOutcome, clientFixture } from './pulls-labels-fixtures.mjs';

const route = 'pulls/1/labels/add';
const writing = { method: 'POST', body: 'label=reviewed', key: 'original-add-label-key',
  read: false, statuses: [200, 409], maximum: 32 * 1024 };

for (const format of ['sha1', 'sha256']) {
  test(format + ': additions encode only a nonempty canonical set with no observed version or clear flag', () => {
    const original = { object_format: format, labels: ['𐀀', '\ue000', 'triage + &', 'bug'] };
    const body = requestBody('add-labels', original, null, 'a'.repeat(32));
    assert.deepEqual(body.fields, { object_format: format, labels: ['bug', 'triage + &', '\ue000', '𐀀'] });
    assert.equal(requestPath(1, 'add-labels'), route);
    assert.deepEqual([...new URLSearchParams(new TextDecoder().decode(body.bytes))],
      [['label', 'bug'], ['label', 'triage + &'], ['label', '\ue000'], ['label', '𐀀']]);
    assert.deepEqual(original.labels, ['𐀀', '\ue000', 'triage + &', 'bug']);
    assert.equal(addPullLabelsCommand({ object_format: format, labels: ['🦀'.repeat(16)] }).labels.length, 1);
    assert.equal(addPullLabelsCommand({ object_format: format,
      labels: Array.from({ length: 32 }, (_, n) => String(n)) }).labels.length, 32);
    for (const labels of [[], undefined, 'bug', [''], [' '], ['bug', 'bug'], ['a'.repeat(65)], ['é'.repeat(33)],
      ['🦀'.repeat(17)], ['\ud800'], ['a\0b'], ['a\nb'], ['a\x85b'], Array.from({ length: 33 }, (_, n) => String(n))]) {
      assert.throws(() => addPullLabelsCommand({ object_format: format, labels }));
    }
    for (const extra of [{ expected_version: 2 }, { expected_version: null }, { clear_labels: true },
      { labels_version: 2 }, { pull_request_version: 9 }, { principal: actor }, { force: true }]) {
      assert.throws(() => addPullLabelsCommand({ ...original, ...extra }));
    }
    assert.throws(() => requestBody('add-labels', original, new Uint8Array([1]), 'a'.repeat(32)));
    assert.throws(() => requestBody('add-labels', original, null, 'wrong'));
  });

  test(format + ': additions stage without loading a labels predecessor and retain only the supplied labels', async () => {
    const f = await clientFixture({ observation: observed(format) }), supplied = ['triage', 'reviewed'];
    const preparing = f.client.stageAddLabels(1, supplied);
    supplied.push('late');
    await preparing;
    const pending = f.client.pending;
    assert.equal(pending.action, 'add-labels');
    assert.deepEqual(pending.fields, { object_format: format, labels: ['reviewed', 'triage'] });
    pending.fields.labels.push('edited summary');
    assert.deepEqual(f.client.pending.fields.labels, ['reviewed', 'triage']);
    assert.equal(f.calls.length, 1, 'staging performs no labels read or publication');
    await assert.rejects(f.client.stageAddLabels(1, ['another']));
    const terminal = await f.client.send();
    assert.equal(terminal.action, 'add-labels'); assert.equal(terminal.number, 1);
    assert.equal(terminal.outcome, 'committed'); assert.equal(Object.hasOwn(terminal, 'labels'), false);
    assert.equal(f.calls.at(-1).url.pathname.endsWith('/' + route), true);
    assert.equal(f.calls.at(-1).bytes, 'label=reviewed&label=triage');
    assert.equal(f.calls.at(-1).headers['Idempotency-Key'], pending.key);
    assert.equal(f.client.pending, null); f.client.disconnect();
  });
}

test('additions transport is closed to GET, queries, missing keys, read lifecycles and other browser profiles', async () => {
  const calls = [], transport = new Transport(options((url, init) => { calls.push({ url, ...init }); return json({}); }));
  await transport.connect(token);
  for (const override of [{ method: 'PUT' }, { method: 'GET' }, { key: undefined }, { key: '' }, { body: undefined },
    { read: true }, { binary: true }, { contentType: 'application/json' }, { statuses: [200] },
    { statuses: [200, 404] }, { maximum: 32769 }, { headerNames: ['x-unknown'] }]) {
    await assert.rejects(transport.request(route, { ...writing, ...override }), JSON.stringify(override));
  }
  await assert.rejects(transport.request(route, { statuses: [200, 404], maximum: 32 * 1024 }));
  await assert.rejects(transport.request(route + '?label=reviewed', writing));
  for (const path of ['pulls/0/labels/add', 'pulls/01/labels/add', 'pulls/1/labels/remove', route + '/']) {
    await assert.rejects(transport.request(path, writing));
  }
  assert.equal(calls.length, 0);
  await transport.request(route, writing); assert.equal(calls.length, 1);
  for (const pageSuffix of ['/ui/source/', '/ui/initial/', '/ui/branches/', '/ui/default-branch/', '/ui/search/',
    '/ui/transfers/', '/ui/tags/', '/ui/replay/', '/ui/rebase/', '/ui/queues/', '/ui/artifacts/']) {
    const other = new Transport({ ...options(() => { throw new Error('No request permitted'); }),
      href: 'https://forge.example/team/repo.git' + pageSuffix, pageSuffix });
    await other.connect(token); await assert.rejects(other.request(route, writing)); other.disconnect();
  }
  transport.disconnect();
});

test('additions receipts bind the original additions and command profile without claiming the final set or version', async () => {
  const f = await clientFixture(); await f.client.stageAddLabels(1, ['reviewed', 'triage']);
  const pending = f.client.pending;
  for (const outcome of ['committed', 'refused']) {
    const good = labelsTerminal(pending, outcome), status = outcome === 'committed' ? 200 : 409;
    const terminal = publication(good, pending, status);
    assert.equal(terminal.outcome, outcome); assert.equal(Object.hasOwn(terminal, 'labels'), false);
    for (const patch of [{ command_profile: undefined }, { command_profile: 'pull-request.set-labels.v1' },
      { expected_version: undefined }, { expected_version: 2 }, { labels_version: undefined }, { labels_version: 3 },
      { labels: ['bug', 'reviewed', 'triage'] }, { labels: ['reviewed'] }, { labels: ['triage', 'reviewed'] },
      { labels: [] }, { refs_changed: true }, { pull_request_version_changed: true }, { number: 2 },
      { action: 'set-labels' }, { type: 'pull_request_publication' }, { delivery_acknowledged: true }]) {
      assert.throws(() => publication({ ...good, ...patch }, pending, status), JSON.stringify(patch));
    }
    assert.throws(() => publication(good, pending, status === 200 ? 409 : 200));
  }
  f.client.disconnect();
});

test('a lost additions response retains the original key and bytes across absent recovery, export, restore and retry', async () => {
  let attempts = 0;
  const dispatch = (_call, pending) => {
    if (++attempts === 1) throw new Error('lost after possible commit');
    return json(labelsTerminal(pending));
  };
  const f = await clientFixture({ dispatch }); await f.client.stageAddLabels(1, ['reviewed']);
  const pending = f.client.pending;
  await assert.rejects(f.client.send(), error => error.outcomeUnknown === true);
  assert.equal(f.client.pending.key, pending.key); assert.throws(() => f.client.discardUnsent());
  const unknown = await f.client.recover();
  assert.equal(unknown.terminal, false); assert.equal(unknown.action, 'add-labels'); assert.equal(unknown.number, 1);
  assert.equal(attempts, 1); assert.equal(f.calls.at(-1).body, undefined);
  const receipt = f.client.exportReceipt();
  assert.equal(receipt.includes(token), false); f.client.disconnect();
  const restored = await clientFixture({ dispatch }); await restored.client.restoreReceipt(receipt);
  assert.equal(restored.calls.length, 1, 'restoring performs no send or additional read');
  assert.deepEqual(JSON.parse(restored.client.exportReceipt()), JSON.parse(receipt));
  await restored.client.send(); assert.equal(restored.client.pending, null); assert.equal(attempts, 2);
  const original = f.calls.find(call => call.url.pathname.endsWith('/labels/add'));
  assert.equal(restored.calls.at(-1).bytes, original.bytes);
  assert.equal(restored.calls.at(-1).headers['Idempotency-Key'], original.headers['Idempotency-Key']);
  restored.client.disconnect();
});

test('additions recovery receipts reject changed labels, target, action, profile fields and repository identity', async () => {
  const f = await clientFixture(); await f.client.stageAddLabels(1, ['reviewed']);
  const receipt = JSON.parse(f.client.exportReceipt()); f.client.disconnect();
  for (const alter of [r => { r.request.fields.labels = ['other']; }, r => { r.request.fields.expected_version = 2; },
    r => { r.request.fields.clear_labels = true; }, r => { r.request.fields.labels = []; },
    r => { r.request.number = 2; }, r => { r.request.action = 'set-labels'; },
    r => { r.request.scope.incarnation = 'other'; }, r => { r.request.fields.object_format = 'sha256'; }]) {
    const value = structuredClone(receipt); alter(value);
    const other = await clientFixture(); await assert.rejects(other.client.restoreReceipt(JSON.stringify(value)));
    assert.equal(other.client.pending, null); assert.equal(other.calls.length, 1); other.client.disconnect();
  }
});

test('malformed additive receipts and missing write grants retain the original request as unresolved', async () => {
  for (const status of [200, 401, 403]) {
    const f = await clientFixture({ dispatch: (_call, pending) => json(status === 200
      ? labelsTerminal(pending, 'committed', { labels: ['bug', 'reviewed'] }) : {}, status) });
    await f.client.stageAddLabels(1, ['reviewed']); const key = f.client.pending.key;
    await assert.rejects(f.client.send(), error => error.outcomeUnknown === true);
    assert.equal(f.client.pending.key, key); assert.equal(f.client.pending.sent, true);
    assert.equal(f.client.connected, status !== 401); f.client.disconnect();
  }
});

test('additions publication and terminal recovery preserve the inspected candidate on commit and refusal', async () => {
  for (const recover of [false, true]) for (const outcome of ['committed', 'refused']) {
    const candidate = candidateFixture();
    const f = await clientFixture({ observation: observed('sha1', { version: 1 }),
      request: call => call.url.pathname.endsWith('/inspect') ? json(candidate.inspection) : null,
      dispatch: (_call, pending) => json(labelsTerminal(pending, outcome), outcome === 'committed' ? 200 : 409),
      recover: () => json(labelsOutcome(outcome)) });
    await f.client.inspect(1, candidate.fields, candidate.bundle); const before = f.client.candidate;
    await f.client.stageAddLabels(1, ['reviewed']);
    const result = recover ? await f.client.recover() : await f.client.send();
    assert.equal(result.action, 'add-labels'); assert.equal(result.outcome, outcome); assert.equal(result.number, 1);
    assert.deepEqual(f.client.candidate, before); assert.equal(f.client.pending, null); f.client.disconnect();
  }
});

test('additions dispatch survives read cancellation and retains its key after disconnect suppresses the late reply', async () => {
  const late = deferred(); let dispatched;
  const f = await clientFixture({ dispatch: call => { dispatched = call; return late.promise; } });
  await f.client.stageAddLabels(1, ['reviewed']); const pending = f.client.pending;
  const rejected = assert.rejects(f.client.send());
  while (!dispatched) await new Promise(setImmediate);
  f.client.cancelReads(); assert.equal(dispatched.signal.aborted, false);
  f.client.disconnect(); assert.equal(dispatched.signal.aborted, true);
  late.resolve(json(labelsTerminal(pending))); await rejected;
  assert.equal(f.client.pending.key, pending.key); assert.equal(f.client.pending.sent, true);
});

test('rotated credentials recover the original additions without allowing preparation, reads or resend', async () => {
  const f = await clientFixture(); await f.client.stageAddLabels(1, ['reviewed']);
  const receipt = f.client.exportReceipt(), key = f.client.pending.key; f.client.disconnect();
  const calls = [], client = new PullClient(options((url, init) => {
    calls.push({ url, ...init }); return json(labelsOutcome('committed'));
  }));
  await client.connect('d'.repeat(64), { recoveryOnly: true, originalPrincipal: actor });
  await client.restoreReceipt(receipt);
  await assert.rejects(client.send()); await assert.rejects(client.stageAddLabels(1, ['other']));
  await assert.rejects(client.labels(1, f.selected));
  const result = await client.recover();
  assert.equal(result.action, 'add-labels'); assert.equal(result.outcome, 'committed');
  assert.equal(calls.length, 1); assert.equal(calls[0].url.pathname.endsWith('/outcomes'), true);
  assert.equal(calls[0].body, undefined); assert.equal(calls[0].headers['Idempotency-Key'], key);
  assert.equal(client.pending, null); client.disconnect();
});
