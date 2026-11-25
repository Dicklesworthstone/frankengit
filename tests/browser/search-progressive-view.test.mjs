// Real view/controller/transport modules with a deliberately small DOM oracle.
// This exercises behavior and privacy, not visual layout or browser engines.
import test from 'node:test';
import assert from 'node:assert/strict';
import { mount } from '../../crates/fgit-node/src/smart_http/server/browser/search-view.mjs';
import { dom, tick } from './search-dom-fixture.mjs';
import { fixture, streamReply, webcrypto, TOKEN, PROFILE, initial, refined, turn } from './search-progressive-fixtures.mjs';

async function viewFixture(t) {
  const elements = dom(), data = fixture(), stream = streamReply(), calls = [];
  const view = mount(elements.document, { href: 'http://localhost/team/repo.git/ui/search/' },
    { cryptoImpl: webcrypto, urlApi: elements.urlApi, fetchImpl: async (url, options) => {
      calls.push({ url: String(url), body: new URLSearchParams(options.body) });
      stream.attach(options.signal); return stream.response;
    } });
  t.after(() => view.disconnect());
  elements.get('token').value = TOKEN;
  await view.connect();
  assert.match(elements.get('status').textContent, /Read token ready/);
  return { ...elements, ...data, stream, calls, view };
}
function chooseRanked(f) {
  f.get('mode').value = 'initial'; f.get('mode').emit('change');
  f.get('query').value = 'recover'; f.get('initial-symbol-name').value = 'Recover';
  f.get('symbol-match').value = 'prefix'; f.get('initial-symbol-policy').value = 'required';
  f.get('context-enabled').checked = true; f.get('context-enabled').emit('change');
  f.get('context-selection').value = PROFILE; f.get('context-selection').emit('change');
  f.get('context-files').value = '1';
  f.get('progressive-enabled').checked = true; f.get('progressive-enabled').emit('change');
}
async function waitInitial(f) {
  for (let attempt = 0; attempt < 200; attempt++) {
    if (/Initial matches received/.test(f.get('status').textContent)) return;
    if (!f.get('submit-search').disabled) throw new Error(f.get('status').textContent);
    await tick();
  }
  assert.fail('Initial was not displayed while the stream remained open');
}
const contextButtons = f => f.buttons('results').filter(button =>
  /source-context report|Verify all|membership|package/i.test(button.textContent));

test('progressive mode is opt-in and available only for combined ranked hydration', async t => {
  const f = await viewFixture(t);
  assert.equal(f.get('progressive-controls').hidden, true);
  assert.equal(f.get('progressive-enabled').disabled, true);
  assert.equal(f.get('progressive-enabled').checked, false);
  f.get('mode').value = 'initial'; f.get('mode').emit('change');
  f.get('context-enabled').checked = true; f.get('context-enabled').emit('change');
  assert.equal(f.get('progressive-controls').hidden, true, 'raw-path context does not opt into ranking');
  chooseRanked(f);
  assert.equal(f.get('progressive-controls').hidden, false);
  assert.equal(f.get('progressive-enabled').disabled, false);
  f.get('context-selection').value = 'raw-path-prefix'; f.get('context-selection').emit('change');
  assert.equal(f.get('progressive-enabled').checked, false);
  assert.equal(f.get('progressive-controls').hidden, true);
  chooseRanked(f); f.get('mode').value = 'literal'; f.get('mode').emit('change');
  assert.equal(f.get('progressive-enabled').checked, false);
  assert.equal(f.calls.length, 0);
});
test('view displays Initial early, then enables ranked reports only after validated EOF', async t => {
  const f = await viewFixture(t); chooseRanked(f);
  const pending = f.view.search();
  f.stream.record(initial(f.wire)); await waitInitial(f);
  assert.match(f.get('results').textContent, /a\/note\.txt/);
  assert.equal(contextButtons(f).length, 0);
  assert.ok(f.buttons('results').every(button => button.disabled));
  assert.equal(f.get('submit-search').disabled, true);
  assert.equal(f.get('cancel').disabled, false);
  f.stream.record(refined(f.wire)); await turn();
  assert.match(f.get('status').textContent, /Loading ranked source excerpts/);
  assert.equal(contextButtons(f).length, 0, 'a terminal record alone does not enable export');
  f.stream.close(); await pending;
  assert.match(f.get('status').textContent, /Progressive search complete with limited coverage/);
  assert.match(f.get('results').textContent, /4279/);
  assert.match(f.get('results').textContent, /INCOMPLETE CONTEXT/);
  assert.equal(f.get('submit-search').disabled, false);
  assert.equal(f.get('cancel').disabled, true);
  const download = f.buttons('results').find(button => button.textContent === 'Download exact source-context report');
  assert.ok(download); download.click();
  assert.equal(f.document.downloads.length, 1);
  const exported = await [...f.urls.values()][0].text();
  assert.equal(exported.includes(TOKEN), false);
  assert.equal(JSON.parse(exported).context.ranking.selected[0].score_q16, 4279);
  f.get('query').value = 'different'; f.get('query').emit('input');
  assert.equal(f.urls.size, 0); assert.equal(f.get('results').textContent, '');
  assert.equal(download.disabled, true); download.click(); assert.equal(f.document.downloads.length, 1);
});
test('terminal refinement refusal keeps Initial matches and clearly labels absent context', async t => {
  const f = await viewFixture(t); chooseRanked(f);
  const pending = f.view.search();
  f.stream.record(initial(f.wire)); await waitInitial(f);
  f.stream.record({ phase: 'RefinementFailed', code: 'source_context_budget_exceeded' }); f.stream.close();
  await pending;
  assert.match(f.get('status').textContent, /Refinement failed \(source_context_budget_exceeded\)/);
  assert.match(f.get('results').textContent, /Initial matches are retained/);
  assert.match(f.get('results').textContent, /a\/note\.txt/);
  assert.equal(contextButtons(f).length, 0);
  assert.ok(f.buttons('results').some(button => !button.disabled), 'Initial file navigation remains available');
  assert.equal(f.calls.length, 1); assert.equal(f.document.downloads.length, 0);
});
test('late stream corruption discards Refined and labels retained Initial as incomplete', async t => {
  const f = await viewFixture(t); chooseRanked(f);
  const pending = f.view.search();
  f.stream.record(initial(f.wire)); await waitInitial(f);
  f.stream.record(refined(f.wire));
  f.stream.record({ phase: 'RefinementFailed', code: 'unexpected_extra' }); f.stream.close();
  await pending;
  assert.match(f.get('status').textContent, /Refinement stream incomplete/);
  assert.match(f.get('results').textContent, /a\/note\.txt/);
  assert.equal(contextButtons(f).length, 0); assert.equal(f.urls.size, 0);
  assert.equal(f.get('submit-search').disabled, false);
});
for (const action of ['cancel', 'query change', 'disconnect']) {
  test(`${action} clears a displayed Initial and suppresses stale UI completion`, async t => {
    const f = await viewFixture(t); chooseRanked(f);
    const pending = f.view.search();
    f.stream.record(initial(f.wire)); await waitInitial(f);
    if (action === 'query change') { f.get('query').value = 'new query'; f.get('query').emit('input'); }
    else f.view[action]();
    const expectedStatus = f.get('status').textContent;
    await pending;
    assert.equal(f.get('status').textContent, expectedStatus);
    assert.equal(f.get('results').textContent, ''); assert.equal(f.get('file').textContent, '');
    assert.equal(f.urls.size, 0); assert.equal(f.document.downloads.length, 0);
    if (action === 'disconnect') {
      assert.equal(f.get('query').value, ''); assert.equal(f.get('snapshot').textContent, '');
      assert.equal(f.get('progressive-enabled').checked, false);
      assert.equal(f.get('context-enabled').checked, false);
    }
  });
}
