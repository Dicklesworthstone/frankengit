// Real policy clients and Web Crypto. Native tree proofs are tested in Rust.
import test from 'node:test';
import assert from 'node:assert/strict';
import { protectionPolicy, protectionChanges } from '../../crates/fgit-node/src/smart_http/server/browser/pulls-actions.mjs';
import { editorPolicy } from '../../crates/fgit-node/src/smart_http/server/browser/protection-view.mjs';
import { TOKEN, ADMIN, REVIEWER, hex, policy, snapshot, response, harness, webcrypto } from './protection-fixtures.mjs';
import { harness as viewHarness, snapshot as viewSnapshot, actor } from './protection-standalone-fixture.mjs';

const rule = (path_hex = '7372632fff', scope = 'subtree', required_approvals = 1) => ({
  path_hex, scope, required_reviewers: [REVIEWER], required_approvals,
});
const selected = () => ({ administrators: [ADMIN], branches: [{
  reference_hex: hex('refs/heads/main'), required_reviewers: [], path_reviews: [rule()],
}] });

test('empty path rules preserve historical saved request bytes and keys', async () => {
  const old = policy(), explicit = policy(); explicit.branches[0].path_reviews = [];
  assert.deepEqual(protectionPolicy(explicit), protectionPolicy(old));
  const cryptoImpl = { subtle: webcrypto.subtle, getRandomValues: bytes => bytes.fill(7) };
  const a = harness({ cryptoImpl }), b = harness({ cryptoImpl,
    respond: call => call.method === 'GET' ? response(snapshot('sha1', { policy: explicit })) : null });
  await a.ready(); await b.ready();
  assert.deepEqual((await b.client.stage(explicit)).intent, (await a.client.stage(old)).intent);
  assert.equal(a.client.exportReceipt(), b.client.exportReceipt());
  assert.equal(new URLSearchParams(b.client.pending.intent.body).has('required_path_review'), false);
});

test('path selectors preserve raw bytes and normalize canonical order without duplicate precedence', () => {
  const value = selected();
  value.branches[0].path_reviews = [rule(hex('src/a')), rule(hex('src')), rule(hex('src'), 'exact')];
  assert.deepEqual(protectionPolicy(value).branches[0].path_reviews,
    [rule(hex('src'), 'exact'), rule(hex('src')), rule(hex('src/a'))]);
  assert.deepEqual(protectionPolicy(selected()), selected());
  for (const path_reviews of [null, {}, [null], [rule(), rule()], [rule('', 'exact')],
    [rule(hex('/src'))], [rule(hex('src/'))], [rule(hex('src//a'))], [rule(hex('src/../a'))],
    [rule(hex('src/\0'))], [rule('FF')], [rule('ff', 'glob')], [rule('ff', 'exact', 0)],
    [rule('ff', 'exact', 2)], [rule('ff', 'exact', '1')], [{ ...rule(), unchecked: true }],
    [{ ...rule(), required_reviewers: [REVIEWER, REVIEWER] }]]) {
    const invalid = selected(); invalid.branches[0].path_reviews = path_reviews;
    assert.throws(() => protectionPolicy(invalid));
  }
});

test('path rule counts and aggregate native byte budgets are enforced without truncation', () => {
  const value = selected();
  value.branches[0].path_reviews = Array.from({ length: 32 }, (_, i) => rule(hex(`src/${i}`)));
  assert.equal(protectionPolicy(value).branches[0].path_reviews.length, 32);
  value.branches[0].path_reviews.push(rule(hex('overflow')));
  assert.throws(() => protectionPolicy(value));
  value.branches[0].path_reviews = Array.from({ length: 16 }, (_, i) => rule(hex(String(i).padStart(4, '0') + 'x'.repeat(4092))));
  assert.equal(protectionPolicy(value).branches[0].path_reviews.length, 16);
  value.branches[0].path_reviews.push(rule(hex('one-more-byte')));
  assert.throws(() => protectionPolicy(value));
  value.branches[0].path_reviews = [rule('61'.repeat(4097))];
  assert.throws(() => protectionPolicy(value));
});

test('standalone path editing is explicit and complete replacement previews expose removals', () => {
  const current = selected(), reference = current.branches[0].reference_hex;
  assert.deepEqual(editorPolicy(ADMIN, `${reference} -`, current.branches, null, []), current);
  const changed = editorPolicy(ADMIN, `${reference} - 0`, current.branches, null, [],
    `${reference} exact 6162 1 ${REVIEWER}`);
  assert.deepEqual(changed.branches[0].path_reviews, [rule('6162', 'exact')]);
  const delta = protectionChanges(current, changed).branches[0];
  assert.deepEqual(delta.path_reviews_removed, [rule()]);
  assert.deepEqual(delta.path_reviews_added, [rule('6162', 'exact')]);
  assert.throws(() => editorPolicy(ADMIN, `${reference} - 0`, current.branches, null, [], ''));
  assert.throws(() => editorPolicy(ADMIN, '', current.branches, null, [], `${reference} exact 6162 1 ${REVIEWER}`));
  assert.equal(editorPolicy(ADMIN, `${reference} ${REVIEWER} all`, current.branches, null, [], '').branches[0].path_reviews, undefined);
});

test('standalone page reads, retains and edits path-only rules before freezing the original request', async () => {
  const calls = [];
  const h = viewHarness({
    async load() { this.observed = { ...viewSnapshot(), policy: { ...selected(), administrators: [actor] } }; return this.observed; },
    async stage(replacement, clear) { calls.push({ replacement, clear }); },
  });
  await h.connect();
  assert.ok(h.get('policy').textContent.includes('7372632fff'));
  assert.ok(h.get('paths').value.includes('subtree 7372632fff 1'));
  await h.get('edit').fire('submit');
  assert.deepEqual(calls[0].replacement.branches[0].path_reviews, [rule()]);
  h.get('paths').value = h.get('paths').value.replace('subtree', 'exact');
  await h.get('edit').fire('submit');
  assert.equal(calls[1].replacement.branches[0].path_reviews[0].scope, 'exact');
});

for (const format of ['sha1', 'sha256']) test(`${format}: lost path policy replies retain exact retry bytes and reject altered evidence`, async () => {
  const current = selected();
  const h = harness({ format, respond: call => {
    if (call.method === 'POST') throw new Error('connection lost after request');
    return response(snapshot(format, { policy: current }));
  } });
  await h.ready(); const pending = await h.client.stage(current);
  assert.deepEqual(new URLSearchParams(pending.intent.body).getAll('required_path_review'),
    [`${current.branches[0].reference_hex}:subtree:7372632fff:1:${REVIEWER}`]);
  await assert.rejects(h.client.send(), /connection lost/);
  const saved = h.client.exportReceipt();
  const restored = harness({ format }); await restored.client.connect(TOKEN, ADMIN);
  await restored.client.restoreReceipt(saved); await restored.client.send();
  assert.equal(restored.calls.length, 1);
  assert.equal(restored.calls[0].body, pending.intent.body);
  assert.equal(restored.calls[0].headers['Idempotency-Key'], pending.intent.key);
  for (const place of ['source', 'replacement']) {
    const changed = JSON.parse(saved);
    (place === 'source' ? changed.intent.source.policy : changed.intent.replacement).branches[0].path_reviews[0].path_hex = '616263';
    const fresh = harness({ format }); await fresh.client.connect(TOKEN, ADMIN);
    await assert.rejects(fresh.client.restoreReceipt(JSON.stringify(changed)));
    assert.equal(fresh.calls.length, 0);
  }
});
