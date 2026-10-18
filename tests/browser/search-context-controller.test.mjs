// Controller isolation: the production CodeSearch and context modules run
// byte-for-byte. Shared transport/Initial-parser adapters below are EXPLICIT
// test doubles, not HTTP, native authorization, or shared-parser conformance.
import test from 'node:test';
import assert from 'node:assert/strict';
import { fixture, hex, copy } from './search-context-fixtures.mjs';
import { setup } from './search-context-harness.mjs';
function response() {
  const f = fixture();
  Object.assign(f.retrieval, { pin: { head: 'selected-head', commit: 'selected-commit', tree: 'selected-tree' },
    lexicalCheckpoint: { token: 'lexical-checkpoint', number: 3 } });
  f.retrieval.symbols.result.index = { token: 'symbol-checkpoint', number: 7 };
  f.reply.retrieval = { normalized: f.retrieval };
  return f;
}
const query = (context = {}) => ({ mode: 'initial', termsHex: [hex('thing')], symbol: { nameHex: hex('Thing'), policy: 'optional' }, context });
function deferred() { let resolve; const promise = new Promise(r => { resolve = r; }); return { promise, resolve }; }

test('one context read publishes the source, checkpoints and hydrated files together', async t => {
  const f = response(), { client, calls } = await setup(t, async () => ({ value: f.reply }));
  const result = await client.search(query());
  assert.equal(calls.length, 1); assert.equal(calls[0].path, 'source/context-initial');
  assert.equal(calls[0].options.method, 'POST'); assert.equal(calls[0].options.headers, undefined);
  const body = new URLSearchParams(calls[0].options.body);
  assert.equal(body.get('context_max_files'), '8'); assert.equal(body.get('ref'), 'refs/heads/main');
  assert.deepEqual(client.state.pin, f.retrieval.pin); assert.equal(result.context.files.length, 1);
  assert.deepEqual(client.state.symbolMinimum, { token: 'symbol-checkpoint', number: 7 });
  result.context.files[0].blob = 'caller-modification'; assert.notEqual(client.state.result.context.files[0].blob, 'caller-modification');
});
test('ordinary Initial is still index-only, with no implicit hydration fields', async t => {
  const f = response(), { client, calls } = await setup(t, async () => ({ value: f.reply.retrieval }));
  const input = query(); delete input.context;
  const result = await client.search(input); assert.equal(calls[0].path, 'source/search-initial');
  assert.equal(calls[0].options.body.includes('context_'), false); assert.equal('context' in result, false);
});
test('invalid hydration does not replace the existing pin or checkpoint floors', async t => {
  const f = response(); let next = f.reply;
  const { client, calls } = await setup(t, async () => ({ value: next }));
  await client.search(query()); const state = client.state;
  next = copy(f.reply); next.retrieval.normalized.pin.head = 'unaccepted-head';
  next.retrieval.normalized.lexicalCheckpoint.number = 99; next.excerpt_bytes++;
  await assert.rejects(client.search(query()), /accounting/);
  assert.deepEqual(client.state.pin, state.pin); assert.deepEqual(client.state.indexMinimum, state.indexMinimum);
  assert.deepEqual(client.state.symbolMinimum, state.symbolMinimum); assert.equal(client.state.result, null);
  assert.equal(calls.length, 2);
  const retry = new URLSearchParams(calls[1].options.body);
  assert.equal(retry.get('expected_head'), 'selected-head'); assert.equal(retry.get('minimum_lexical_number'), '3');
  assert.equal(retry.get('minimum_symbol_number'), '7');
});
test('the nested Initial validator cannot be skipped by a plausible hydration envelope', async t => {
  const f = response(); f.reply.retrieval.reject = true;
  const { client, calls } = await setup(t, async () => ({ value: f.reply }));
  await assert.rejects(client.search(query()), /Initial adapter rejected/);
  assert.equal(client.state.pin, null); assert.equal(client.state.indexMinimum, null); assert.equal(calls.length, 1);
});
test('query/options are copied before a suspended network read', async t => {
  const f = response(), read = deferred(); const { client, calls } = await setup(t, () => read.promise);
  const input = query(); const task = client.search(input);
  input.context.maxFiles = 1; input.termsHex[0] = hex('different');
  read.resolve({ value: f.reply }); const result = await task;
  assert.equal(new URLSearchParams(calls[0].options.body).get('context_max_files'), '8');
  assert.deepEqual(result.query.termsHex, [hex('thing')]); assert.equal(result.context.limits.maxFiles, 8);
});
test('disconnect prevents an in-flight read from installing source bytes or pins', async t => {
  const f = response(), read = deferred(); const { client } = await setup(t, () => read.promise);
  const task = client.search(query()); client.disconnect(); read.resolve({ value: f.reply });
  await assert.rejects(task, /superseded|disconnected/); assert.equal(client.state.result, null);
  assert.equal(client.state.pin, null); assert.equal(client.state.indexMinimum, null);
});
test('a newer query supersedes an older response without overwriting its result', async t => {
  const f = response(), first = deferred(); let calls = 0;
  const { client } = await setup(t, () => ++calls === 1 ? first.promise : Promise.resolve({ value: f.reply }));
  const old = client.search(query()); await client.search(query());
  const chosen = client.state; first.resolve({ value: f.reply });
  await assert.rejects(old, /superseded/); assert.deepEqual(client.state, chosen);
});
test('context failures never trigger an index-only fallback or retry', async t => {
  const { client, calls } = await setup(t, async () => { throw Object.assign(new Error('source moved'), { status: 409 }); });
  await assert.rejects(client.search(query()), /source moved/);
  assert.equal(calls.length, 1); assert.equal(calls[0].path, 'source/context-initial'); assert.equal(client.state.result, null);
});
test('context limits and mode mismatch are refused before any request', async t => {
  const { client, calls } = await setup(t, async () => { throw new Error('unexpected dispatch'); });
  await assert.rejects(client.search(query({ maxFiles: 33 })), /maxFiles/);
  await assert.rejects(client.search({ mode: 'literal', context: {} }), /Initial/);
  assert.equal(calls.length, 0);
});
test('one absolute controller deadline spans request completion and context validation', async t => {
  const f = response(), read = deferred(); const { client, calls } = await setup(t, () => read.promise, 1);
  const task = client.search(query()); await new Promise(resolve => setTimeout(resolve, 15));
  read.resolve({ value: f.reply }); await assert.rejects(task, /total time limit/);
  assert.equal(client.state.result, null); assert.equal(client.state.pin, null); assert.equal(calls.length, 1);
});
