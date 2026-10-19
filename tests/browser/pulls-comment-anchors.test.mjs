// Production protocol/client/WebCrypto with controlled HTTP responses; these
// checks do not replace native source authentication or admission evidence.
import test from 'node:test';
import assert from 'node:assert/strict';
import { PullClient } from '../../crates/fgit-node/src/smart_http/server/browser/pulls.mjs';
import { commentsReply, sourceCommentAnchor, SOURCE_COMMENT_FIELDS } from '../../crates/fgit-node/src/smart_http/server/browser/pulls-comments.mjs';
import { commentCommand, requestBody, publication } from '../../crates/fgit-node/src/smart_http/server/browser/pulls-actions.mjs';
import { token, actor, ids, head, page, row, data, json, options, hex } from './pulls-fixtures.mjs';
import { anchor } from './pulls-comment-anchor-fixtures.mjs';

function conversation(format = 'sha1', comments = []) {
  return { ...ids, object_format: format, type: 'pull_request_comments', number: 1, found: true,
    source_head: 'head-id', snapshot_token: head, discussion_version: comments.length,
    after: 0, limit: 20, next_after: null, complete: true, merge_permission: null,
    transaction_created: false, comments: comments.map((comment, index) => ({ version: index + 1, actor, body: 'Original discussion', ...comment })) };
}
function terminal(pending, extra = {}) {
  return { ...ids, object_format: pending.scope.format, type: 'pull_request_comment_publication',
    number: pending.number, action: 'comment', expected_version: pending.fields.expected_version,
    comment_version: pending.fields.expected_version + 1, principal_id: actor, tx_id: 'source-comment-transaction',
    decision_sequence: 7, outcome: 'committed', repository_commit_id: 'source-comment-rcr',
    refusal_record_id: null, refusal_code: null, refusal_code_point: null,
    refs_changed: false, delivery_acknowledged: null,
    ...(pending.fields.anchor ? { anchor: structuredClone(pending.fields.anchor) } : {}), ...extra };
}
async function setup(format = 'sha1', handler = (_call, pending) => json(terminal(pending))) {
  const calls = [], width = format === 'sha1' ? 40 : 64; let client;
  client = new PullClient(options(async (url, init) => {
    const call = { url: String(url), ...init, bytes: init.body ? await init.body.text() : null }; calls.push(call);
    if (url.pathname.endsWith('/pulls')) return json(page({ object_format: format,
      pull_requests: [row(1, { data: data({ object_format: format, source_tip: 'a'.repeat(width), target_tip: 'b'.repeat(width) }) })] }));
    return handler(call, client.pending);
  }));
  await client.connect(token); await client.list(); return { client, calls };
}

for (const format of ['sha1', 'sha256']) {
  test(`${format}: mixed ordinary, exact and outdated history retains immutable source anchors`, () => {
    const a = anchor(format), old = anchor(format, { pull_request_version: 3, side: 'before', mode: '120000' });
    const reply = conversation(format, [{}, { anchor: a, anchor_status: 'exact' }, { anchor: old, anchor_status: 'outdated' }]);
    assert.equal(commentsReply(reply, 1).reply, reply);
    assert.equal(Object.hasOwn(reply.comments[0], 'anchor'), false);
    assert.deepEqual(reply.comments[2].anchor, old);
    assert.deepEqual(sourceCommentAnchor(a, format), a);
    for (const status of ['current', 'moved', null, true]) {
      assert.throws(() => commentsReply(conversation(format, [{ anchor: a, anchor_status: status }]), 1));
    }
    for (const partial of [{ anchor: a }, { anchor_status: 'exact' }, { anchor: null, anchor_status: 'outdated' }]) {
      assert.throws(() => commentsReply(conversation(format, [partial]), 1));
    }
  });

  test(`${format}: the whole source selection survives exact retry and recovery`, async () => {
    let sends = 0;
    const h = await setup(format, (_call, pending) => {
      if (++sends === 1) throw new Error('response lost after possible commit');
      return json(terminal(pending));
    });
    const selected = anchor(format, { source_ref_hex: hex(Buffer.from('refs/heads/')).concat('ff'), path_hex: 'ff2e7273' });
    const staged = h.client.stageComment(1, 2, 'Exact\r\nsource observation', selected);
    selected.path_hex = hex('different.rs'); await staged;
    const saved = h.client.pending, originalPath = saved.fields.anchor.path_hex;
    assert.equal(originalPath, 'ff2e7273'); assert.equal(h.calls.length, 1);
    const decoded = new URLSearchParams(new TextDecoder().decode(requestBody('comment', saved.fields, null, '1'.repeat(32)).bytes));
    assert.deepEqual([...decoded.keys()], ['expected_version', 'body', ...SOURCE_COMMENT_FIELDS.map(name => `anchor_${name}`)]);
    assert.equal(decoded.get('anchor_path_hex'), originalPath); assert.equal(decoded.has('anchor_profile'), false);
    assert.equal(decoded.has('object_format'), false); assert.equal(decoded.get('body'), 'Exact\r\nsource observation');
    await assert.rejects(h.client.send(), error => error.outcomeUnknown);
    const receipt = h.client.exportReceipt(); assert.equal(receipt.includes(token), false);
    const resumed = await setup(format); await resumed.client.restoreReceipt(receipt);
    assert.deepEqual(resumed.client.pending.fields, saved.fields);
    assert.equal(resumed.client.pending.key, saved.key); await resumed.client.send();
    assert.equal(h.calls[1].bytes, resumed.calls[1].bytes);
    assert.equal(h.calls[1].headers['Idempotency-Key'], resumed.calls[1].headers['Idempotency-Key']);
    assert.equal(resumed.client.pending, null); assert.equal(resumed.client.candidate, null);
    for (const change of [a => { a.path_hex = hex('another.rs'); }, a => { a.side = 'before'; },
      a => { a.blob = 'c'.repeat(format === 'sha1' ? 40 : 64); }, a => { a.byte_end++; },
      a => { a.pull_request_version++; }, a => { delete a.profile; }]) {
      const altered = JSON.parse(receipt); change(altered.request.fields.anchor);
      const other = await setup(format); await assert.rejects(other.client.restoreReceipt(JSON.stringify(altered)));
      assert.equal(other.client.pending, null); assert.equal(other.calls.length, 1);
    }
  });
}

test('source anchors reject incomplete, ambiguous, oversized and foreign-domain coordinates', () => {
  const good = anchor();
  for (const field of ['profile', ...SOURCE_COMMENT_FIELDS]) {
    const missing = { ...good }; delete missing[field];
    assert.throws(() => sourceCommentAnchor(missing, 'sha1'), field);
  }
  for (const bad of [{ profile: 'lines' }, { extra: true }, { pull_request_version: 0 },
    { pull_request_version: Number.MAX_SAFE_INTEGER + 1 }, { source_ref_hex: '' }, { source_ref_hex: '00' },
    { source_ref_hex: hex('refs/tags/topic') }, { source_ref_hex: hex('refs/heads/../bad') }, { source_ref_hex: hex('refs/heads/topic.lock') },
    { source_ref_hex: good.target_ref_hex }, { path_hex: hex('../escape') }, { path_hex: hex('/absolute') },
    { path_hex: 'ABCDEF' }, { path_hex: hex(Array(65).fill('a').join('/')) }, { blob: `sha256:${'d'.repeat(64)}` }, { side: 'new' }, { mode: 0o100644 },
    { mode: '160000' }, { comparison: 'merge-base' }, { comparison: 'direct' },
    { byte_start: 1 }, { byte_end: 0 }, { byte_end: 64 * 1024 + 1 }, { byte_end: 1024 * 1024 + 1 },
    { byte_start: '0' }, { line_start: 1 }, { line_count: 0 }, { line_count: 129 }, { line_count: 6 }]) {
    assert.throws(() => sourceCommentAnchor({ ...good, ...bad }, 'sha1'), JSON.stringify(bad));
  }
  assert.equal(sourceCommentAnchor({ ...good, comparison: 'direct', compared_base: good.target_tip }, 'sha1').comparison, 'direct');
  assert.equal(sourceCommentAnchor({ ...good, byte_end: 64 * 1024, line_count: 128 }, 'sha1').line_count, 128);
  assert.throws(() => commentCommand({ object_format: 'sha1', expected_version: 0, body: 'text', anchor: null }));
});

test('a terminal reply must echo exactly the retained anchor, including on refusal', async () => {
  const { client } = await setup(); await client.stageComment(1, 2, 'Specific lines', anchor());
  const saved = client.pending;
  assert.equal(publication(terminal(saved), saved, 200).terminal, true);
  const refused = terminal(saved, { outcome: 'refused', comment_version: null, repository_commit_id: null,
    refusal_record_id: 'refusal', refusal_code: 'EvidenceStale', refusal_code_point: 1 });
  assert.equal(publication(refused, saved, 409).outcome, 'refused');
  const absent = terminal(saved); delete absent.anchor;
  for (const changed of [absent, terminal(saved, { anchor: null }), terminal(saved, { anchor_status: 'exact' }),
    terminal(saved, { anchor: anchor('sha1', { side: 'before' }) }), terminal(saved, { anchor: anchor('sha1', { byte_end: 6 }) })]) {
    assert.throws(() => publication(changed, saved, 200));
  }
  client.discardUnsent(); await client.stageComment(1, 2, 'Ordinary comment');
  assert.throws(() => publication(terminal(client.pending, { anchor: anchor() }), client.pending, 200));
  assert.equal(publication(terminal(client.pending), client.pending, 200).terminal, true);
});
