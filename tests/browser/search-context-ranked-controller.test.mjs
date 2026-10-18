// Actual CodeSearch/context modules with explicit shared Transport/Initial
// adapters. These check the controller boundary, not native HTTP conformance.
import test from 'node:test';
import assert from 'node:assert/strict';
import { setup } from './search-context-harness.mjs';
import { copy, hex } from './search-context-fixtures.mjs';
import { PROFILE, rankedFixture } from './search-context-ranked-fixtures.mjs';
const query = () => ({ mode: 'initial', termsHex: [hex('thing')], symbol: { nameHex: hex('Thing'), policy: 'optional' },
  context: { maxFiles: 1, selection: PROFILE } });
function response() {
  const f = rankedFixture();
  f.retrieval.pin = { head: 'selected-head', commit: 'selected-commit', tree: 'selected-tree' };
  f.retrieval.lexicalCheckpoint = { token: 'lexical-checkpoint', number: 3 };
  f.retrieval.symbols.result.index = { token: 'symbol-checkpoint', number: 7 };
  f.reply.retrieval = { normalized: f.retrieval };
  return f;
}
function deferred() { let resolve; const promise = new Promise(r => { resolve = r; }); return { resolve, promise }; }
test('ranked context is one native request with no client-selected paths or weights', async t => {
  const f = response(), { client, calls } = await setup(t, async () => ({ value: f.reply }));
  const result = await client.search(query());
  assert.equal(calls.length, 1); assert.equal(calls[0].path, 'source/context-initial');
  const form = new URLSearchParams(calls[0].options.body);
  assert.equal(form.get('context_selection'), PROFILE); assert.equal(form.get('context_max_files'), '1');
  for (const key of form.keys()) assert.equal(/path_hex|weight|score|rank_constant/u.test(key), false);
  assert.equal(result.context.ranking.selected[0].score_q16, 4279);
  assert.deepEqual(client.state.indexMinimum, f.retrieval.lexicalCheckpoint);
  assert.deepEqual(client.state.symbolMinimum, f.retrieval.symbols.result.index);
  result.context.ranking.selected.pop(); assert.equal(client.state.result.context.ranking.selected.length, 1);
});
test('altered rank receipts do not advance any pin, checkpoint, result or fallback request', async t => {
  const f = response(); let next = f.reply;
  const { client, calls } = await setup(t, async () => ({ value: next }));
  await client.search(query()); const state = client.state;
  next = copy(f.reply); next.retrieval.normalized.pin.head = 'unaccepted-head';
  next.retrieval.normalized.lexicalCheckpoint.number = 8;
  next.retrieval.normalized.symbols.result.index.number = 9;
  next.ranking.selected[0].contributions[0].score_q16++;
  await assert.rejects(client.search(query()), /ranked/);
  assert.deepEqual(client.state.pin, state.pin); assert.deepEqual(client.state.indexMinimum, state.indexMinimum);
  assert.deepEqual(client.state.symbolMinimum, state.symbolMinimum); assert.equal(client.state.result, null);
  assert.equal(calls.length, 2);
  const body = new URLSearchParams(calls[1].options.body);
  assert.equal(body.get('expected_head'), state.pin.head); assert.equal(body.get('context_selection'), PROFILE);
  assert.equal(body.get('minimum_lexical_number'), '3'); assert.equal(body.get('minimum_symbol_number'), '7');
});
test('request selection is frozen before suspension and cannot be downgraded by caller edits', async t => {
  const f = response(), pending = deferred(), { client, calls } = await setup(t, () => pending.promise);
  const input = query(), task = client.search(input); input.context.selection = 'raw-path-prefix';
  input.context.maxFiles = 32; input.termsHex.push(hex('elsewhere')); pending.resolve({ value: f.reply });
  const result = await task;
  assert.equal(result.context.selection, PROFILE);
  assert.equal(new URLSearchParams(calls[0].options.body).get('context_max_files'), '1');
});
test('disconnect while ranked hydration is pending prevents installation and automatic retries', async t => {
  const f = response(), pending = deferred(), { client, calls } = await setup(t, () => pending.promise);
  const task = client.search(query()); client.disconnect(); pending.resolve({ value: f.reply });
  await assert.rejects(task, /superseded|disconnected/);
  assert.equal(client.state.result, null); assert.equal(client.state.indexMinimum, null);
  assert.equal(client.state.symbolMinimum, null); assert.equal(client.state.pin, null); assert.equal(calls.length, 1);
});
test('an older ranked response cannot replace a newer selected read', async t => {
  const f = response(), pending = deferred(); let count = 0;
  const { client } = await setup(t, () => ++count === 1 ? pending.promise : Promise.resolve({ value: f.reply }));
  const old = client.search(query()); await client.search(query()); const state = client.state;
  pending.resolve({ value: f.reply }); await assert.rejects(old, /superseded/); assert.deepEqual(client.state, state);
});
test('unsupported selection and arbitrary ranking parameters fail before dispatch', async t => {
  const { client, calls } = await setup(t, () => { throw new Error('unexpected request'); });
  for (const options of [{ selection: 'ranked' }, { selection: PROFILE, weights: { symbol: 99 } }, { selection: PROFILE, rankConstant: 1 }]) {
    const input = query(); Object.assign(input.context, options); await assert.rejects(client.search(input));
  }
  assert.equal(calls.length, 0);
});
test('a ranked reply still requires the independent nested Initial validator', async t => {
  const f = response(); f.reply.retrieval.reject = true;
  const { client } = await setup(t, async () => ({ value: f.reply }));
  await assert.rejects(client.search(query()), /Initial adapter/);
  assert.equal(client.state.result, null); assert.equal(client.state.pin, null);
});
