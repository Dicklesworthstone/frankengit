// Production browser client and WebCrypto with controlled HTTP responses.
// These are exact-command and recovery tests, not evidence of native CAS execution.
import test from 'node:test';
import assert from 'node:assert/strict';
import { PullClient } from '../../crates/fgit-node/src/smart_http/server/browser/pulls.mjs';
import { Transport } from '../../crates/fgit-node/src/smart_http/server/browser/pulls-core.mjs';
import { appendCommentCommand, commentCommand, requestBody, requestPath, publication } from '../../crates/fgit-node/src/smart_http/server/browser/pulls-actions.mjs';
import { SOURCE_COMMENT_FIELDS } from '../../crates/fgit-node/src/smart_http/server/browser/pulls-comments.mjs';
import { token, actor, ids, page, row, data, json, options, deferred } from './pulls-fixtures.mjs';
import { anchor } from './pulls-comment-anchor-fixtures.mjs';
import { fixture as candidateFixture } from './pulls-candidate-fixtures.mjs';

const appendPath = 'pulls/1/comments/append';
const writing = { method: 'POST', body: 'body=Original', key: 'original-key', read: false, statuses: [200, 409] };
const params = encoded => new URLSearchParams(new TextDecoder().decode(encoded.bytes));
function terminal(pending, outcome = 'committed', extra = {}) {
  const strict = pending.action === 'comment';
  return { ...ids, object_format: pending.scope.format, type: 'pull_request_comment_publication',
    number: pending.number, action: pending.action, expected_version: strict ? pending.fields.expected_version : null,
    comment_version: strict && outcome === 'committed' ? pending.fields.expected_version + 1 : null,
    principal_id: actor, tx_id: 'comment-tx', decision_sequence: 7, outcome,
    repository_commit_id: outcome === 'committed' ? 'comment-rcr' : null,
    refusal_record_id: outcome === 'refused' ? 'comment-refusal' : null,
    refusal_code: outcome === 'refused' ? 'EvidenceStale' : null,
    refusal_code_point: outcome === 'refused' ? 1 : null, refs_changed: false, delivery_acknowledged: null,
    ...(pending.fields.anchor ? { anchor: structuredClone(pending.fields.anchor) } : {}), ...extra };
}
function outcome(state, format = 'sha1') {
  const terminal = ['committed', 'refused'].includes(state);
  return { ...ids, object_format: format, type: 'transaction_outcome', selector: 'transaction', command_index: null,
    read_only: true, request_reexecuted: false, absence_proves_non_commit: false, session_completeness_established: false,
    principal_id: actor, state, terminal,
    transaction: terminal || state === 'undecided' ? { tx_id: 'comment-tx', seal_id: 'comment-seal', request_schema: 'request/v1',
      canonical_request_digest: { algorithm: 2, hex: 'ab'.repeat(32) } } : null,
    decision: !terminal ? null : state === 'committed'
      ? { kind: state, decision_sequence: 7, repository_commit_id: 'comment-rcr' }
      : { kind: state, decision_sequence: 7, refusal_record_id: 'comment-refusal', code: 'EvidenceStale', code_point: 1 } };
}
async function setup(handler = () => { throw new Error('Unexpected publication'); }, format = 'sha1') {
  const calls = []; let client;
  client = new PullClient(options((url, init) => {
    calls.push({ url: String(url), ...init });
    if (new URL(url).pathname.endsWith('/pulls')) {
      const width = format === 'sha1' ? 40 : 64;
      return json(page({ object_format: format, pull_requests: [row(1, { data: data({ object_format: format,
        source_tip: 'a'.repeat(width), target_tip: 'b'.repeat(width) }) })] }));
    }
    return handler(url, init, client);
  }));
  await client.connect(token); await client.list(); return { client, calls };
}

for (const format of ['sha1', 'sha256']) {
  test(`${format} append form binds exact body and source coordinates without a conversation precondition`, () => {
    const fields = { object_format: format, body: ' é\r\n<script>literal</script> & + ' };
    const plain = requestBody('append-comment', fields, null, 'a'.repeat(32));
    assert.deepEqual(plain.fields, fields);
    assert.deepEqual([...params(plain)], [['body', fields.body]]);
    assert.equal(plain.contentType, 'application/x-www-form-urlencoded');
    assert.equal(requestPath(1, 'append-comment'), appendPath);
    const selected = anchor(format, { path_hex: '7372632fff2e7273', source_ref_hex: '726566732f68656164732fff' });
    const anchored = requestBody('append-comment', { ...fields, anchor: selected }, null, 'a'.repeat(32));
    const form = params(anchored);
    assert.equal(form.get('body'), fields.body);
    assert.deepEqual([...form.keys()], ['body', ...SOURCE_COMMENT_FIELDS.map(name => `anchor_${name}`)]);
    for (const name of SOURCE_COMMENT_FIELDS) assert.equal(form.get(`anchor_${name}`), String(selected[name]), name);
    assert.deepEqual(anchored.fields.anchor, selected);
    for (const extra of [{ expected_version: 0 }, { expected_version: null }, { principal: actor },
      { pull_request_version: 1 }, { source_tip: selected.source_tip }, { line: 2 }, { force: true },
      { anchor: null }, { anchor: { ...selected, blob: 'd'.repeat(format === 'sha1' ? 64 : 40) } },
      { body: ' \n' }, { body: 'a\0b' }, { body: 'é'.repeat(32769) }]) {
      assert.throws(() => appendCommentCommand({ ...fields, ...extra }), JSON.stringify(extra));
    }
    assert.throws(() => requestBody('append-comment', fields, new Uint8Array([1]), 'a'.repeat(32)));
    assert.throws(() => requestBody('append-comment', fields, null, 'invalid-nonce'));
    // Existing callers retain their original explicit version and route.
    const strictFields = { ...fields, expected_version: 2 };
    assert.deepEqual(commentCommand(strictFields), strictFields);
    const strict = requestBody('comment', strictFields, null, 'a'.repeat(32));
    assert.deepEqual([...params(strict)], [['expected_version', '2'], ['body', fields.body]]);
    assert.equal(requestPath(1, 'comment'), 'pulls/1/comments');
  });
}

test('append transport rejects missing grants and invalid lifecycle envelopes before any network request', async () => {
  const calls = [];
  const transport = new Transport(options((url, init) => { calls.push({ url, ...init }); return json({}); }));
  await assert.rejects(transport.request(appendPath, writing));
  assert.equal(calls.length, 0);
  await transport.connect(token);
  await assert.rejects(transport.request(appendPath, { statuses: [200, 404] }));
  for (const override of [{ method: 'PUT' }, { method: 'GET' }, { body: undefined }, { key: undefined },
    { key: '' }, { read: true }, { binary: true }, { statuses: [200] }, { statuses: [200, 404] },
    { contentType: 'application/octet-stream' }]) {
    await assert.rejects(transport.request(appendPath, { ...writing, ...override }), JSON.stringify(override));
  }
  await assert.rejects(transport.request(`${appendPath}?expected_version=2`, writing));
  assert.equal(calls.length, 0);
  await transport.request(appendPath, writing);
  assert.equal(calls.length, 1);
  const call = calls[0];
  assert.equal(call.url.href, 'https://forge.example/team/repo.git/api/v1/pulls/1/comments/append');
  assert.equal(call.headers.Authorization, `Bearer ${token}`);
  assert.equal(call.headers['Idempotency-Key'], writing.key);
  assert.equal(call.body, writing.body); assert.equal(call.credentials, 'omit');
  assert.equal(call.redirect, 'error'); assert.equal(call.mode, 'same-origin'); assert.equal(call.cache, 'no-store');
});

test('other page profiles, workflow-only grants and recovery-only grants cannot publish append comments', async () => {
  for (const pageSuffix of ['/ui/source/', '/ui/initial/', '/ui/branches/', '/ui/search/', '/ui/transfers/',
    '/ui/tags/', '/ui/replay/', '/ui/rebase/']) {
    let calls = 0;
    const transport = new Transport({ ...options(() => { calls += 1; throw new Error('Unexpected request'); }),
      href: `https://forge.example/team/repo.git${pageSuffix}`, pageSuffix });
    await transport.connect(token);
    await assert.rejects(transport.request(appendPath, writing));
    assert.equal(calls, 0, pageSuffix);
  }
  for (const recoveryOnly of [false, true]) {
    let calls = 0;
    const transport = new Transport({ ...options(() => { calls += 1; throw new Error('Unexpected request'); }),
      checkEvidenceOnly: !recoveryOnly });
    await transport.connect(token, null, recoveryOnly ? { key: writing.key, principal: actor } : null);
    await assert.rejects(transport.request(appendPath, writing));
    assert.equal(calls, 0);
  }
});

test('canceling views does not cancel an append publication, but disconnect invalidates its response', async () => {
  const delayed = deferred(); let call;
  const transport = new Transport(options((_url, init) => { call = init; return delayed.promise; }));
  await transport.connect(token);
  const sending = transport.request(appendPath, writing), rejected = assert.rejects(sending);
  transport.cancelReads(); assert.equal(call.signal.aborted, false);
  transport.disconnect(); assert.equal(call.signal.aborted, true);
  delayed.resolve(json({})); await rejected; assert.equal(transport.connected, false);
});

for (const format of ['sha1', 'sha256']) {
  test(`${format} staging copies the anchor before hashing and lost responses retry the identical append intent`, async () => {
    let sends = 0;
    const { client, calls } = await setup((_url, _init, owner) => {
      if (++sends === 1) throw new Error('Response lost after possible publication');
      return json(terminal(owner.pending));
    }, format);
    const selected = anchor(format), original = structuredClone(selected);
    const preparing = client.stageAppendComment(1, 'Literal\r\nbody', selected);
    selected.byte_end = 9; await preparing;
    const saved = client.pending;
    assert.equal(calls.length, 1); assert.equal(saved.action, 'append-comment');
    assert.equal(Object.hasOwn(saved.fields, 'expected_version'), false);
    assert.deepEqual(saved.fields.anchor, original);
    const copy = client.pending; copy.fields.body = 'Changed'; copy.fields.anchor.line_start = 8;
    assert.equal(client.pending.fields.body, 'Literal\r\nbody');
    assert.deepEqual(client.pending.fields.anchor, original);
    await assert.rejects(client.send(), error => error.outcomeUnknown === true);
    assert.equal(client.pending.key, saved.key); assert.equal(client.pending.sent, true);
    assert.throws(() => client.discardUnsent());
    await assert.rejects(client.stageAppendComment(1, 'Replacement text'));
    await assert.rejects(client.stageComment(1, 9, 'Changed profile'));
    const result = await client.send();
    assert.equal(result.outcome, 'committed'); assert.equal(result.action, 'append-comment'); assert.equal(client.pending, null);
    const writes = calls.slice(1);
    assert.equal(writes.length, 2);
    assert.ok(writes.every(call => call.url.endsWith(`/${appendPath}`)));
    assert.equal(writes[0].headers['Idempotency-Key'], saved.key);
    assert.equal(writes[1].headers['Idempotency-Key'], saved.key);
    const body = await writes[0].body.text(); assert.equal(await writes[1].body.text(), body);
    const form = new URLSearchParams(body);
    assert.equal(form.has('expected_version'), false); assert.equal(form.get('body'), 'Literal\r\nbody');
    for (const name of SOURCE_COMMENT_FIELDS) assert.equal(form.get(`anchor_${name}`), String(original[name]), name);
  });
}

test('append receipts restore exact original bytes and reject changed body, anchors, scope and strict-profile substitution', async () => {
  const { client } = await setup(); await client.stageAppendComment(1, 'Private original', anchor());
  const saved = client.exportReceipt(), record = JSON.parse(saved);
  assert.equal(saved.includes(token), false); assert.equal(record.schema, 'frankengit-pr-retry-v1');
  assert.equal(record.request.action, 'append-comment'); assert.equal(record.request.bundle_base64, null);
  assert.equal(Object.hasOwn(record.request.fields, 'expected_version'), false);
  assert.throws(() => client.discardUnsent());
  const { client: restored, calls } = await setup((_url, _init, owner) => json(terminal(owner.pending)));
  await restored.restoreReceipt(saved); assert.equal(calls.length, 1);
  assert.equal(restored.pending.key, record.request.key); assert.equal(restored.pending.sent, true);
  assert.deepEqual(JSON.parse(restored.exportReceipt()), record);
  await restored.send();
  const expected = requestBody('append-comment', record.request.fields, null, record.request.nonce);
  assert.equal(await calls.at(-1).body.text(), new TextDecoder().decode(expected.bytes));
  assert.equal(calls.at(-1).headers['Idempotency-Key'], record.request.key);
  for (const alter of [r => { r.request.fields.body = 'Changed'; }, r => { r.request.number = 2; },
    r => { r.request.scope.incarnation = 'other'; }, r => { r.request.nonce = 'f'.repeat(32); },
    r => { r.request.fields.anchor.byte_end = 6; }, r => { delete r.request.fields.anchor; },
    r => { r.request.fields.expected_version = 0; },
    r => { r.request.action = 'comment'; r.request.fields.expected_version = 0; }]) {
    const changed = structuredClone(record); alter(changed);
    const { client: other, calls: attempts } = await setup();
    await assert.rejects(other.restoreReceipt(JSON.stringify(changed)));
    assert.equal(attempts.length, 1); assert.equal(other.pending, null);
  }
  const other = new PullClient(options(() => { throw new Error('Unexpected request'); }));
  await other.connect('d'.repeat(64)); await assert.rejects(other.restoreReceipt(saved));
});

test('append terminal receipts require explicit null positions and the exact original anchor and action', async () => {
  const { client } = await setup(); await client.stageAppendComment(1, 'Original', anchor()); const pending = client.pending;
  for (const state of ['committed', 'refused']) {
    const status = state === 'committed' ? 200 : 409, valid = terminal(pending, state);
    assert.equal(publication(valid, pending, status).outcome, state);
    for (const extra of [{ expected_version: 0 }, { expected_version: undefined }, { comment_version: 1 },
      { comment_version: undefined }, { number: 2 }, { action: 'comment' }, { refs_changed: true },
      { type: 'pull_request_publication' }, { delivery_acknowledged: true }, { anchor_status: 'current' },
      { anchor: { ...pending.fields.anchor, byte_end: 6 } }]) {
      assert.throws(() => publication({ ...valid, ...extra }, pending, status), JSON.stringify(extra));
    }
    const unanchored = structuredClone(valid); delete unanchored.anchor;
    assert.throws(() => publication(unanchored, pending, status));
    assert.throws(() => publication(valid, pending, status === 200 ? 409 : 200));
  }
  client.discardUnsent(); await client.stageAppendComment(1, 'Plain');
  assert.throws(() => publication(terminal(client.pending, 'committed', { anchor: anchor() }), client.pending, 200));
});

test('a fabricated append position preserves uncertainty until an exact canonical refusal settles it', async () => {
  let wrong = true;
  const { client, calls } = await setup((_url, _init, owner) => wrong
    ? json(terminal(owner.pending, 'committed', { comment_version: 3 }))
    : json(terminal(owner.pending, 'refused'), 409));
  await client.stageAppendComment(1, 'Original'); const key = client.pending.key;
  await assert.rejects(client.send(), error => error.outcomeUnknown === true);
  assert.equal(client.pending.key, key); assert.equal(client.pending.sent, true);
  wrong = false; assert.equal((await client.send()).outcome, 'refused'); assert.equal(client.pending, null);
  assert.equal(calls.at(-1).headers['Idempotency-Key'], key);
});

for (const format of ['sha1', 'sha256']) {
  test(`${format} a rotated credential can recover the original append key but cannot replay or replace its command`, async () => {
    const { client } = await setup(undefined, format); await client.stageAppendComment(1, 'Original private body', anchor(format));
    const saved = client.exportReceipt(), original = JSON.parse(saved), calls = []; let state = 'key_not_observed';
    const rotated = 'd'.repeat(64);
    const recovery = new PullClient(options((url, init) => { calls.push({ url, ...init }); return json(outcome(state, format)); }));
    await recovery.connect(rotated, { recoveryOnly: true, originalPrincipal: actor });
    await recovery.restoreReceipt(saved);
    assert.deepEqual(JSON.parse(recovery.exportReceipt()), original);
    await assert.rejects(recovery.send(), /Recovery-only/);
    await assert.rejects(recovery.stageAppendComment(1, 'Replacement'), /Recovery-only/);
    await assert.rejects(recovery.stageComment(1, 0, 'Replacement'), /Recovery-only/);
    await assert.rejects(recovery.list(), /Recovery-only/); assert.equal(calls.length, 0);
    assert.equal((await recovery.recover()).terminal, false); assert.equal(recovery.pending.key, original.request.key);
    state = 'undecided'; assert.equal((await recovery.recover()).tx, 'comment-tx');
    assert.equal(recovery.pending.observedPrincipal, actor); assert.equal(recovery.pending.observedTx, 'comment-tx');
    const retained = JSON.parse(recovery.exportReceipt());
    assert.equal(retained.request.fingerprint, original.request.fingerprint);
    assert.deepEqual(retained.request.fields, original.request.fields);
    state = 'committed'; const result = await recovery.recover();
    assert.equal(result.outcome, 'committed'); assert.equal(result.action, 'append-comment'); assert.equal(recovery.pending, null);
    assert.equal(calls.length, 3);
    for (const call of calls) {
      assert.equal(call.url.pathname, '/team/repo.git/api/v1/outcomes'); assert.equal(call.method, 'POST');
      assert.equal(call.body, undefined); assert.equal(call.headers['Idempotency-Key'], original.request.key);
      assert.equal(call.headers.Authorization, `Bearer ${rotated}`);
    }
  });
}

for (const action of ['comment', 'append-comment']) for (const recovery of [false, true]) {
  test(`${action} ${recovery ? 'recovery' : 'publication'} preserves an independently inspected candidate`, async () => {
    for (const state of ['committed', 'refused']) {
      const f = candidateFixture();
      const { client, calls } = await setup((url, _init, owner) => {
        if (new URL(url).pathname.endsWith('/inspect')) return json(f.inspection);
        if (new URL(url).pathname.endsWith('/outcomes')) return json(outcome(state));
        return json(terminal(owner.pending, state), state === 'committed' ? 200 : 409);
      });
      await client.inspect(1, f.fields, f.bundle); const candidate = client.candidate;
      if (action === 'comment') await client.stageComment(1, 2, 'Discussion alongside review');
      else await client.stageAppendComment(1, 'Discussion alongside review');
      const key = client.pending.key, result = await (recovery ? client.recover() : client.send());
      assert.equal(result.action, action); assert.equal(result.outcome, state); assert.equal(client.pending, null);
      assert.deepEqual(client.candidate, candidate);
      if (recovery) { assert.equal(calls.at(-1).body, undefined); assert.equal(calls.at(-1).headers['Idempotency-Key'], key); }
    }
  });
}

test('legacy exact-version receipts still restore and publish through the original route and terminal shape', async () => {
  const { client } = await setup(); await client.stageComment(1, 2, 'Legacy exact intent', anchor());
  const saved = client.exportReceipt(), original = JSON.parse(saved);
  assert.equal(original.request.action, 'comment'); assert.equal(original.request.fields.expected_version, 2);
  const { client: restored, calls } = await setup((_url, _init, owner) => json(terminal(owner.pending)));
  await restored.restoreReceipt(saved); assert.deepEqual(JSON.parse(restored.exportReceipt()), original);
  const pending = restored.pending;
  assert.throws(() => publication(terminal(pending, 'committed', {
    action: 'append-comment', expected_version: null, comment_version: null,
  }), pending, 200));
  const result = await restored.send(); assert.equal(result.action, 'comment'); assert.equal(result.outcome, 'committed');
  assert.equal(new URL(calls.at(-1).url).pathname, '/team/repo.git/api/v1/pulls/1/comments');
  const form = new URLSearchParams(await calls.at(-1).body.text());
  assert.equal(form.get('expected_version'), '2'); assert.equal(form.get('body'), 'Legacy exact intent');
  assert.equal(calls.at(-1).headers['Idempotency-Key'], original.request.key);
});
