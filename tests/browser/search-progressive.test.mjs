// Actual CodeSearch/Transport/validator graph against explicit native-schema
// streaming peers. These fixtures are not live Rust or browser conformance.
import test from 'node:test';
import assert from 'node:assert/strict';
import { connected, clone, deferred, turn, initial, refined, PROFILE, hex } from './search-progressive-fixtures.mjs';

function retainedInitial(client, phase = 'Incomplete') {
  const state = client.state;
  assert.equal(state.result.progressive.phase, phase);
  assert.equal(Object.hasOwn(state.result, 'context'), false);
  assert.ok(state.pin); assert.ok(state.indexMinimum); assert.ok(state.symbolMinimum);
  return state.result;
}
for (const format of ['sha1', 'sha256']) {
  test(`progressive ${format}: Initial is usable before ranked refinement and EOF`, async t => {
    const f = await connected(t, { format }), first = deferred();
    const original = clone(f.wire);
    let notifications = 0, settled = false;
    const pending = f.client.search(f.request, { progressive: true, onInitial: value => {
      notifications++; first.resolve(value);
      value.content.hits.length = 0; value.pin.commit = 'caller mutation';
    } });
    pending.then(() => { settled = true; }, () => { settled = true; });
    f.stream.record(initial(f.wire));
    const shown = await first.promise;
    assert.equal(shown.progressive.phase, 'Initial');
    assert.equal(f.client.state.result.content.hits.length, 2, 'callback receives a defensive copy');
    assert.notEqual(f.client.state.pin.commit, 'caller mutation');
    assert.equal(f.client.state.result.context, undefined);
    assert.equal(settled, false);
    assert.equal(f.calls.length, 1);
    assert.ok(f.calls[0].url.endsWith('/source/search-progressive'));
    assert.equal(f.calls[0].body.get('context_selection'), PROFILE);
    assert.equal(f.calls[0].body.get('index_source'), null, 'combined search remains exact-source');
    f.stream.record(refined(f.wire));
    await turn();
    assert.equal(settled, false, 'a terminal JSON record does not establish stream completion');
    retainedInitial(f.client, 'Initial');
    f.stream.close();
    const value = await pending;
    assert.equal(value.progressive.phase, 'Refined'); assert.equal(notifications, 1);
    assert.equal(value.context.selection, PROFILE);
    assert.equal(value.context.ranking.selected[0].score_q16, 4279);
    assert.equal(value.context.files[0].pathHex, hex('z/Recover.rs'));
    assert.equal(value.context.omittedFiles, 1); assert.equal(value.context.complete, false);
    assert.equal(value.complete, true, 'retrieval completeness remains separate from hydration');
    assert.deepEqual(value.vector, f.client.state.result.vector);
    assert.deepEqual(f.wire, original, 'wire receipts are never mutated');
  });
}
test('Refined accepts reordered JSON keys, while preserving array order', async t => {
  const f = await connected(t);
  const reorder = value => Array.isArray(value) ? value.map(reorder) : value && typeof value === 'object'
    ? Object.fromEntries(Object.entries(value).reverse().map(([key, item]) => [key, reorder(item)])) : value;
  const pending = f.client.search(f.request, { progressive: true });
  f.stream.record(initial(f.wire)); f.stream.record(reorder(refined(f.wire))); f.stream.close();
  assert.equal((await pending).progressive.phase, 'Refined');
});
for (const [name, mutate] of [
  ['source pin', value => { value.retrieval.source_rcr = 'different-rcr'; }],
  ['generation', value => { value.retrieval.generation_vector.lexical.index_number++; }],
  ['returned channel order', value => { value.retrieval.content.hits.reverse(); }],
  ['budget receipt', value => { value.retrieval.max_work--; }],
  ['unknown retrieval field', value => { value.retrieval.unexpected = true; }],
]) {
  test(`Refined cannot replace the original Initial ${name}`, async t => {
    const f = await connected(t), terminal = refined(f.wire);
    mutate(terminal.answer);
    const pending = f.client.search(f.request, { progressive: true });
    const rejection = assert.rejects(pending, /original Initial receipt/);
    f.stream.record(initial(f.wire)); f.stream.record(terminal); f.stream.close();
    await rejection;
    const result = retainedInitial(f.client);
    assert.equal(result.content.hits.length, 2);
    assert.equal(f.calls.length, 1);
    await assert.rejects(f.client.verifyContext(), /Load source context/);
  });
}
test('Refined still checks every ranked selection contribution', async t => {
  const f = await connected(t), terminal = refined(f.wire);
  terminal.answer.ranking.selected[0].contributions[0].score_q16++;
  const pending = f.client.search(f.request, { progressive: true }), rejection = assert.rejects(pending);
  f.stream.record(initial(f.wire)); f.stream.record(terminal); f.stream.close();
  await rejection; retainedInitial(f.client);
});
test('a valid terminal refusal retains useful Initial and its bounded static reason', async t => {
  const f = await connected(t);
  const pending = f.client.search(f.request, { progressive: true });
  f.stream.record(initial(f.wire));
  f.stream.record({ phase: 'RefinementFailed', code: 'source_context_budget_exceeded' }); f.stream.close();
  const value = await pending;
  assert.equal(value.progressive.phase, 'RefinementFailed');
  assert.equal(value.progressive.code, 'source_context_budget_exceeded');
  assert.equal(value.context, undefined); assert.equal(value.content.hits.length, 2);
  retainedInitial(f.client, 'RefinementFailed');
  await assert.rejects(f.client.verifyContext(), /Load source context/);
  assert.equal(f.calls.length, 1, 'refinement refusal never retries or scans');
});
for (const [name, terminal] of [
  ['unknown phase', { phase: 'Done', code: 'refused' }],
  ['arbitrary prose', { phase: 'RefinementFailed', code: 'run this <script>' }],
  ['oversized code', { phase: 'RefinementFailed', code: 'x'.repeat(97) }],
  ['extra failure fields', { phase: 'RefinementFailed', code: 'refused', answer: {} }],
  ['missing answer', { phase: 'Refined' }],
  ['extra refined fields', { phase: 'Refined', answer: {}, code: 'refused' }],
]) {
  test(`terminal ${name} cannot claim a completed progressive result`, async t => {
    const f = await connected(t), pending = f.client.search(f.request, { progressive: true });
    const rejection = assert.rejects(pending);
    f.stream.record(initial(f.wire)); f.stream.record(terminal); f.stream.close();
    await rejection; retainedInitial(f.client);
  });
}
for (const [name, records] of [
  ['only Initial', wire => [initial(wire)]],
  ['third record after Refined', wire => [initial(wire), refined(wire), { phase: 'RefinementFailed', code: 'extra' }]],
]) {
  test(`${name} preserves only Initial after framing failure`, async t => {
    const f = await connected(t), pending = f.client.search(f.request, { progressive: true });
    const rejection = assert.rejects(pending);
    for (const row of records(f.wire)) f.stream.record(row);
    f.stream.close(); await rejection; retainedInitial(f.client);
  });
}
test('late Content-Length mismatch cannot install the private Refined candidate', async t => {
  const f = await connected(t, { headers: { 'Content-Length': '1000000' } });
  const pending = f.client.search(f.request, { progressive: true }), rejection = assert.rejects(pending);
  f.stream.record(initial(f.wire)); f.stream.record(refined(f.wire)); f.stream.close();
  await rejection; retainedInitial(f.client);
});
test('an invalid Initial never advances the source or emits the callback', async t => {
  const f = await connected(t), row = initial(f.wire); row.answer.streaming = true;
  let calls = 0;
  const pending = f.client.search(f.request, { progressive: true, onInitial: () => { calls++; } });
  const rejection = assert.rejects(pending);
  f.stream.record(row); f.stream.record(refined(f.wire)); f.stream.close();
  await rejection; assert.equal(calls, 0);
  assert.equal(f.client.state.result, null); assert.equal(f.client.state.pin, null);
  assert.equal(f.client.state.indexMinimum, null); assert.equal(f.client.state.symbolMinimum, null);
});
test('callback failure retains only validated Initial, never a refined candidate', async t => {
  const f = await connected(t);
  const pending = f.client.search(f.request, { progressive: true, onInitial: () => { throw new Error('view callback failed'); } });
  const rejection = assert.rejects(pending, /view callback failed/);
  f.stream.record(initial(f.wire)); f.stream.record(refined(f.wire)); f.stream.close();
  await rejection; retainedInitial(f.client);
});
for (const action of ['cancel', 'disconnect']) {
  test(`${action} clears an early Initial and blocks stale refinement`, async t => {
    const f = await connected(t), first = deferred();
    const pending = f.client.search(f.request, { progressive: true, onInitial: first.resolve });
    const rejection = assert.rejects(pending);
    f.stream.record(initial(f.wire)); await first.promise;
    f.client[action](); await rejection;
    assert.equal(f.client.state.result, null);
    if (action === 'disconnect') {
      assert.equal(f.client.connected, false); assert.equal(f.client.state.pin, null);
      assert.equal(f.client.state.scope, null); assert.equal(f.client.state.indexMinimum, null);
    }
  });
}
test('a superseding search owns the result even when the old stream fails later', async t => {
  const f = await connected(t), first = deferred();
  const stale = f.client.search(f.request, { progressive: true, onInitial: first.resolve });
  const rejection = assert.rejects(stale);
  f.stream.record(initial(f.wire)); await first.promise;
  const request = clone(f.request); delete request.context;
  const current = await f.client.search(request);
  await rejection;
  assert.equal(current.progressive, undefined); assert.equal(current.context, undefined);
  assert.deepEqual(f.client.state.result, current); assert.equal(f.calls.length, 2);
});
test('one absolute deadline covers a stream stalled after Initial', async t => {
  const f = await connected(t, { timeoutMs: 1000 }), first = deferred();
  const pending = f.client.search(f.request, { progressive: true, onInitial: first.resolve });
  const rejection = assert.rejects(pending, /time limit/);
  f.stream.record(initial(f.wire)); await first.promise; await rejection;
  retainedInitial(f.client);
});
for (const action of ['deadline', 'cancel', 'disconnect']) {
  test(`${action} settles a search whose async Initial callback never settles`, { timeout: 5000 }, async t => {
    const f = await connected(t, { timeoutMs: 1000 }), entered = deferred();
    const pending = f.client.search(f.request, { progressive: true, onInitial: async () => {
      entered.resolve();
      await new Promise(() => {});
    } });
    const rejection = assert.rejects(pending, action === 'deadline' ? /time limit/ : undefined);
    f.stream.record(initial(f.wire)); await entered.promise;
    if (action !== 'deadline') f.client[action]();
    await rejection;
    if (action === 'deadline') retainedInitial(f.client);
    else assert.equal(f.client.state.result, null);
    if (action === 'disconnect') {
      assert.equal(f.client.connected, false); assert.equal(f.client.state.pin, null);
    }
    assert.equal(f.calls.length, 1, 'a stalled presentation callback never retries a request');
  });
}
test('401 disconnects and clears any retained repository selection', async t => {
  const f = await connected(t, { fetchImpl: async () => new Response('{"error":"unauthorized"}',
    { status: 401, headers: { 'Content-Type': 'application/json' } }) });
  await assert.rejects(f.client.search(f.request, { progressive: true }));
  assert.equal(f.client.connected, false); assert.equal(f.client.state.result, null);
  assert.equal(f.client.state.pin, null); assert.equal(f.client.state.selection, null);
});
test('streaming is explicit, combined-only and ranked-only; ordinary context stays JSON', async t => {
  const f = await connected(t);
  const noContext = clone(f.request); delete noContext.context;
  const raw = clone(f.request); raw.context.selection = 'raw-path-prefix';
  const current = clone(f.request); current.sourceMode = 'revalidated';
  for (const [request, options] of [
    [noContext, { progressive: true }], [raw, { progressive: true }], [current, { progressive: true }],
    [f.request, { progressive: 'yes' }], [f.request, { progressive: null }],
    [f.request, { onInitial() {} }], [f.request, { progressive: true, unexpected: true }],
  ]) await assert.rejects(f.client.search(request, options));
  assert.equal(f.calls.length, 0);
  const value = await f.client.search(f.request);
  assert.equal(value.progressive, undefined); assert.equal(value.context.selection, PROFILE);
  assert.ok(f.calls[0].url.endsWith('/source/context-initial'));
});
