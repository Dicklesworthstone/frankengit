// Actual template, mount workflow and client/WebCrypto. The DOM and HTTP
// boundary are controlled doubles; these are not live-browser/native-CAS tests.
import test from 'node:test';
import assert from 'node:assert/strict';
import { mountPulls } from '../../crates/fgit-node/src/smart_http/server/browser/pulls-view.mjs';
import { fakeDocument, until } from './helpers/pulls-workflow-fixture.mjs';
import { webcrypto, page, row, deferred, head } from './pulls-fixtures.mjs';
import { fixture as candidateFixture } from './pulls-candidate-fixtures.mjs';
import { actor, token, json, observed, labelsReply, labelsTerminal, labelsOutcome } from './pulls-labels-fixtures.mjs';

const descendants = node => [node, ...node.children.flatMap(descendants)];
const writes = calls => calls.filter(call => call.method === 'POST' && /\/labels(?:\/add)?$/.test(call.url.pathname));
const reads = calls => calls.filter(call => call.method === 'GET' && call.url.pathname.endsWith('/labels'));
function button(node, name) {
  const control = descendants(node).find(el => el.tagName === 'BUTTON' && el.textContent === name);
  assert.ok(control, `missing button ${name}`); return control;
}

async function harness({ observation = observed(), read = null, dispatch = null, recover = null, list = null } = {}) {
  const doc = fakeDocument(), calls = [], downloads = [], candidate = candidateFixture(observation.object_format);
  const protect = node => {
    for (const name of ['innerHTML', 'outerHTML']) Object.defineProperty(node, name, {
      set() { throw new Error(`Unsafe markup sink ${name}`); },
    });
    node.insertAdjacentHTML = () => { throw new Error('Unsafe markup insertion'); };
    return node;
  };
  descendants(doc.body).forEach(protect); const create = doc.createElement; doc.createElement = tag => protect(create(tag));
  let app;
  const fetchImpl = async (url, init) => {
    const call = { url: new URL(url), ...init, bytes: init.body === undefined ? null
      : typeof init.body === 'string' ? init.body : await init.body.text() };
    calls.push(call);
    if (url.pathname.endsWith('/outcomes')) return recover ? recover(call, app.client.pending) : json(labelsOutcome());
    if (/\/labels(?:\/add)?$/.test(url.pathname)) return init.method === 'GET'
      ? read ? read(call) : json(labelsReply(observation))
      : dispatch ? dispatch(call, app.client.pending) : json(labelsTerminal(app.client.pending));
    if (url.pathname.endsWith('/inspect')) return json(candidate.inspection);
    if (url.pathname.endsWith('/pulls')) return list ? list(call) : json(page({ object_format: observation.object_format,
      source_head: observation.source_head, snapshot_token: observation.snapshot_token, labels: [], pull_requests: [observation.pull_request] }));
    if (/\/pulls\/[1-9][0-9]*$/.test(url.pathname)) return json(observation);
    throw new Error(`Unexpected fixture request ${url}`);
  };
  app = mountPulls(doc, { fetchImpl, cryptoImpl: webcrypto, downloadImpl: (name, text) => downloads.push({ name, text }) });
  const node = id => { const value = doc.getElementById(id); assert.ok(value, `missing UI control ${id}`); return value; };
  const submit = id => node(id).dispatchEvent(new Event('submit', { cancelable: true }));
  const click = id => node(id).click();
  await app.client.connect(token); await app.loadList(); await app.loadPr(observation.number);
  const loadLabels = async () => {
    click('pr-labels-load');
    await until(() => !node('pr-labels-status').textContent.startsWith('Loading') && !app.client.busy);
  };
  const stage = async (value = 'bug\nreviewed') => {
    node('pr-labels-values').value = value; submit('pr-labels-form');
    await until(() => app.client.pending && !app.client.busy);
  };
  const stageAdd = async (value = 'reviewed') => {
    node('pr-labels-add-values').value = value; submit('pr-labels-add-form');
    await until(() => app.client.pending && !app.client.busy);
  };
  const send = async () => {
    node('confirm').checked = true; node('confirm').dispatchEvent(new Event('change')); click('send');
    await until(() => !app.client.busy && !/^(Labels replacement|Label additions) prepared/.test(node('status').textContent));
  };
  return { ...app, doc, node, submit, click, loadLabels, stage, stageAdd, send, calls, downloads, observation, candidate };
}

for (const format of ['sha1', 'sha256']) {
  test(`${format}: selected labels load separately, freeze their own version and require an explicit send`, async () => {
    const f = await harness({ observation: observed(format) });
    assert.equal(reads(f.calls).length, 0, 'selecting a PR never initiates a label write or extra read');
    assert.match(f.node('pr-list').textContent, /labels: "bug"/);
    assert.equal(f.node('pr-labels-stage').disabled, true);
    await f.loadLabels(); assert.equal(f.node('pr-labels-values').value, 'bug');
    assert.equal(reads(f.calls)[0].url.searchParams.get('expected_head'), f.observation.snapshot_token);
    assert.match(f.node('pr-labels-status').textContent, /labels version 2 · metadata version 9/);
    f.node('pr-number').value = '999'; f.node('expected-version').value = '90'; f.node('confirm').checked = true;
    await f.stage('reviewed\nbug'); const pending = f.client.pending;
    assert.equal(pending.number, 1); assert.equal(pending.action, 'set-labels'); assert.equal(pending.fields.expected_version, 2);
    assert.deepEqual(pending.fields.labels, ['bug', 'reviewed']);
    assert.equal(f.node('confirm').checked, false); assert.equal(f.node('send').disabled, true);
    assert.equal(f.node('pr-labels-stage').disabled, true); assert.equal(writes(f.calls).length, 0);
    f.click('send'); assert.equal(writes(f.calls).length, 0);
    f.node('pr-labels-values').value = 'programmatic edit';
    assert.deepEqual(f.client.pending.fields.labels, ['bug', 'reviewed']);
    await f.send(); assert.equal(f.client.pending, null);
    assert.equal(writes(f.calls).length, 1); assert.equal(writes(f.calls)[0].bytes, 'expected_version=2&label=bug&label=reviewed');
    assert.match(f.node('status').textContent, /Canonical committed.*metadata, branch tips and existing approvals are unchanged/);
    assert.equal(f.node('pr-labels-stage').disabled, true); assert.equal(f.node('pr-labels-load').disabled, true);
    await f.loadPr(1); assert.equal(f.node('pr-labels-load').disabled, false); assert.equal(f.node('pr-labels-stage').disabled, true);
    f.disconnect();
  });
}

test('clearing all labels requires an empty replacement and its own explicit selection before confirmation', async () => {
  const f = await harness(); await f.loadLabels();
  f.node('pr-labels-values').value = ''; f.submit('pr-labels-form');
  await until(() => /explicitly select Clear all labels/.test(f.node('status').textContent));
  assert.equal(f.client.pending, null); assert.equal(writes(f.calls).length, 0);
  f.node('pr-labels-clear').checked = true; f.node('pr-labels-values').value = 'bug'; f.submit('pr-labels-form');
  await new Promise(setImmediate); await until(() => !f.client.busy); assert.equal(f.client.pending, null);
  await f.stage(''); assert.deepEqual(f.client.pending.fields.labels, []);
  await f.send(); assert.equal(writes(f.calls)[0].bytes, 'expected_version=2&clear_labels=true'); f.disconnect();
});

test('untouched labels use zero without borrowing the metadata version', async () => {
  const f = await harness({ observation: observed('sha1', { labels: [], labels_version: 0, labels_actor: null }) });
  await f.loadLabels(); assert.equal(f.node('pr-labels-values').value, '');
  assert.match(f.node('pr-labels-status').textContent, /labels version 0/);
  await f.stage('first label'); assert.equal(f.client.pending.fields.expected_version, 0); await f.send();
  assert.equal(writes(f.calls)[0].bytes, 'expected_version=0&label=first+label'); f.disconnect();
});

test('labels stay inert text including hostile markup and directional controls', async () => {
  const labels = ['<img src=x onerror=alert(1)>', 'bug\u202e'];
  const f = await harness({ observation: observed('sha1', { labels }) }); await f.loadLabels();
  assert.match(f.node('selected').textContent, /<img src=x onerror=alert\(1\)>/);
  assert.doesNotMatch(f.node('selected').textContent, /\u202e/);
  assert.match(f.node('selected').textContent, /\\u202e/);
  assert.equal(f.node('pr-labels-values').value, labels.join('\n'));
  await f.stage(labels.join('\n')); assert.deepEqual(f.client.pending.fields.labels, labels);
  assert.equal(writes(f.calls).length, 0); f.disconnect();
});

test('unsupported legacy label responses disable edits while ordinary PR work stays usable', async () => {
  const observation = observed(); for (const name of ['labels', 'labels_version', 'labels_actor']) delete observation.pull_request[name];
  const f = await harness({ observation, read: () => json({}, 404) });
  assert.match(f.node('pr-labels-status').textContent, /does not include labels/);
  assert.equal(f.node('metadata-stage').disabled, false); assert.equal(f.node('fast-forward-stage').disabled, false);
  await f.loadLabels(); assert.equal(f.node('pr-labels-stage').disabled, true);
  f.submit('pr-labels-form'); await until(() => /Load the selected PR labels/.test(f.node('status').textContent));
  assert.equal(f.client.pending, null); assert.equal(f.node('metadata-stage').disabled, false);
  assert.equal(writes(f.calls).length, 0); f.disconnect();
});

test('closed and merged PR label panels do not rely on a merge button being available', async () => {
  for (const state of ['closed', 'merged']) {
    const observation = observed(); observation.pull_request.state = state;
    if (state === 'merged') observation.pull_request.merge = { ...observation.pull_request.data,
      target_tip_before: observation.pull_request.data.target_tip, base_tip: 'c'.repeat(40), merge_commit: 'd'.repeat(40) };
    const f = await harness({ observation }); assert.equal(f.node('fast-forward-stage').disabled, true);
    await f.loadLabels(); await f.stage(); await f.send();
    assert.match(f.node('status').textContent, /Canonical committed/); f.disconnect();
  }
});

test('a stale labels read clears its draft and refuses replacement until the PR is reloaded', async () => {
  const f = await harness({ read: () => json({}, 409) });
  f.node('pr-labels-values').value = 'unverified draft'; await f.loadLabels();
  assert.equal(f.node('pr-labels-values').value, ''); assert.equal(f.node('pr-labels-stage').disabled, true);
  assert.equal(f.node('pr-labels-load').disabled, true);
  assert.match(f.node('pr-labels-status').textContent, /Reload the PR explicitly/);
  f.submit('pr-labels-form'); await until(() => !f.client.busy);
  assert.equal(f.client.pending, null); assert.equal(writes(f.calls).length, 0); f.disconnect();
});

test('AND label filtering preserves the submitted set and head across paging despite edited inputs', async () => {
  const filters = ['bug', 'needs review'];
  const f = await harness({ list: call => {
    const required = call.url.searchParams.getAll('label'), after = Number(call.url.searchParams.get('after'));
    if (!required.length) return json(page({ labels: [], pull_requests: [observed().pull_request] }));
    assert.deepEqual(required, filters);
    return json(page({ labels: filters, after, next_after: after ? null : 20,
      pull_requests: Array.from({ length: after ? 1 : 20 }, (_, index) => row(after + index + 1,
        { labels: filters, labels_version: 1, labels_actor: actor })) }));
  } });
  f.node('label-filter-values').value = 'needs review\nbug'; f.submit('label-filter');
  await until(() => /Required labels/.test(f.node('pr-list').textContent));
  assert.match(f.node('pr-list').textContent, /Required labels: "bug", "needs review"/);
  f.node('label-filter-values').value = 'unsubmitted replacement';
  button(f.node('list-paging'), 'Next PR page').click();
  await until(() => /#21/.test(f.node('pr-list').textContent));
  const continuation = f.calls.at(-1); assert.deepEqual(continuation.url.searchParams.getAll('label'), filters);
  assert.equal(continuation.url.searchParams.get('expected_head'), head);
  f.node('label-filter-values').value = ''; f.submit('label-filter');
  await until(() => /#1/.test(f.node('pr-list').textContent) && !f.node('pr-list').textContent.includes('Required labels'));
  assert.deepEqual(f.calls.at(-1).url.searchParams.getAll('label'), []);
  assert.equal(f.calls.at(-1).url.searchParams.has('expected_head'), false); f.disconnect();
});

test('invalid filter and editor labels refuse before network or preparing a replacement', async () => {
  const f = await harness(); await f.loadLabels(); const count = f.calls.length;
  for (const value of ['bug\nbug', 'é'.repeat(33), 'bad\x85label']) {
    f.node('label-filter-values').value = value; f.submit('label-filter');
    await new Promise(setImmediate); await until(() => !f.client.busy); assert.equal(f.calls.length, count);
    f.node('pr-labels-values').value = value; f.submit('pr-labels-form');
    await new Promise(setImmediate); await until(() => !f.client.busy); assert.equal(f.client.pending, null);
  }
  f.disconnect(); assert.equal(f.node('label-filter-values').value, '');
});

test('lost label response, exported recovery and explicit retry preserve the original command through view changes', async () => {
  let attempts = 0;
  const dispatch = (_call, pending) => { if (++attempts === 1) throw new Error('reply lost after possible commit');
    return json(labelsTerminal(pending)); };
  const f = await harness({ dispatch }); await f.loadLabels(); await f.stage(); const pending = f.client.pending;
  await f.send(); assert.match(f.node('status').textContent, /Outcome remains unknown/);
  f.click('recover'); await until(() => !f.client.busy && /Labels outcome unknown/.test(f.node('status').textContent));
  assert.equal(attempts, 1); assert.equal(f.client.pending.key, pending.key);
  f.click('receipt-download'); await until(() => f.downloads.length === 1);
  const receipt = f.downloads[0].text; assert.equal(receipt.includes(token), false);
  f.click('new-pr'); assert.equal(f.client.pending.key, pending.key); f.disconnect();
  const restored = await harness({ dispatch });
  restored.node('receipt-import-file').files = [new File([receipt], 'labels.json')]; restored.submit('receipt-import');
  await until(() => restored.client.pending && !restored.client.busy);
  assert.equal(restored.client.pending.key, pending.key); assert.equal(attempts, 1);
  assert.equal(restored.node('confirm').checked, false); await restored.send();
  assert.equal(restored.client.pending, null); assert.equal(attempts, 2);
  assert.equal(writes(f.calls)[0].bytes, writes(restored.calls)[0].bytes);
  assert.equal(writes(f.calls)[0].headers['Idempotency-Key'], writes(restored.calls)[0].headers['Idempotency-Key']);
  restored.disconnect();
});

for (const operation of ['send', 'recover']) {
  test(`in-flight ${operation} cannot lose its terminal to a new selection or repeated detached form submission`, async () => {
    const delayed = deferred(); let started;
    const f = await harness({ dispatch: (_call, pending) => { started = pending; return delayed.promise; },
      recover: (_call, pending) => { started = pending; return delayed.promise; } });
    await f.loadLabels(); await f.stage(); const original = f.client.pending;
    if (operation === 'send') { f.node('confirm').checked = true; f.node('confirm').dispatchEvent(new Event('change')); }
    f.click(operation); await until(() => started);
    f.node('new-pr').dispatchEvent(new Event('click', { cancelable: true }));
    f.node('select-number').value = '2'; f.submit('select-pr'); f.submit('pr-labels-form');
    assert.equal(f.client.pending.key, original.key); assert.match(f.node('selected').textContent, /#1/);
    delayed.resolve(json(operation === 'send' ? labelsTerminal(original) : labelsOutcome('committed')));
    await until(() => !f.client.busy && !f.client.pending);
    assert.match(f.node('status').textContent, /Canonical committed/);
    assert.equal(f.node('pr-labels-stage').disabled, true); f.disconnect();
  });
}

test('disconnect suppresses detached read and write replies while retaining an unresolved publication', async () => {
  for (const writing of [false, true]) {
    const delayed = deferred(); let started;
    const f = await harness({ read: writing ? null : call => { started = call; return delayed.promise; },
      dispatch: call => { started = call; return delayed.promise; } });
    let pending;
    if (writing) {
      await f.loadLabels(); await f.stage(); pending = f.client.pending;
      f.node('confirm').checked = true; f.node('confirm').dispatchEvent(new Event('change')); f.click('send');
    } else f.click('pr-labels-load');
    await until(() => started); f.disconnect();
    delayed.resolve(json(writing ? labelsTerminal(pending) : labelsReply(f.observation)));
    await until(() => !f.client.busy); await new Promise(setImmediate);
    assert.equal(started.signal.aborted, true); assert.equal(f.node('selected').textContent, '');
    assert.equal(f.node('token').value, ''); assert.match(f.node('status').textContent, /Disconnected/);
    assert.equal(f.client.pending?.key ?? null, pending?.key ?? null);
  }
});

test('labels terminal leaves inspected candidate and metadata selection intact while disabling old label edits', async () => {
  const f = await harness({ observation: observed('sha1', { version: 1 }) });
  await f.client.inspect(1, f.candidate.fields, f.candidate.bundle); const candidate = f.client.candidate;
  await f.loadLabels(); await f.stage(); await f.send();
  assert.deepEqual(f.client.candidate, candidate);
  assert.equal(f.node('expected-version').value, '1'); assert.equal(f.node('fast-forward-stage').disabled, false);
  assert.equal(f.node('pr-labels-stage').disabled, true); f.disconnect();
});

for (const format of ['sha1', 'sha256']) {
  test(format + ': the separate additions form needs no labels read and prepares only additions before explicit confirmation', async () => {
    const f = await harness({ observation: observed(format) });
    assert.equal(f.node('pr-labels-add-stage').disabled, false);
    assert.equal(f.node('pr-labels-add-values').value, '');
    assert.equal(f.node('pr-labels-stage').disabled, true);
    f.node('pr-number').value = '999'; f.node('expected-version').value = '90';
    f.node('pr-labels-values').value = 'replacement'; f.node('pr-labels-clear').checked = true;
    f.node('confirm').checked = true; await f.stageAdd('triage + &\nreviewed');
    const pending = f.client.pending;
    assert.equal(pending.number, 1); assert.equal(pending.action, 'add-labels');
    assert.deepEqual(pending.fields, { object_format: format, labels: ['reviewed', 'triage + &'] });
    assert.equal(reads(f.calls).length, 0); assert.equal(writes(f.calls).length, 0);
    assert.equal(f.node('confirm').checked, false); assert.equal(f.node('send').disabled, true);
    assert.equal(f.node('pr-labels-add-stage').disabled, true); assert.equal(f.node('pr-labels-stage').disabled, true);
    f.click('send'); assert.equal(writes(f.calls).length, 0);
    f.node('pr-labels-add-values').value = 'changed after preparation';
    assert.deepEqual(f.client.pending.fields.labels, ['reviewed', 'triage + &']);
    const priorLabels = f.node('pr-labels-status').textContent;
    await f.send();
    assert.equal(writes(f.calls).length, 1);
    assert.equal(writes(f.calls)[0].url.pathname.endsWith('/pulls/1/labels/add'), true);
    assert.equal(writes(f.calls)[0].bytes, 'label=reviewed&label=triage+%2B+%26');
    assert.equal(reads(f.calls).length, 0, 'terminal publication never silently reads a later label set');
    assert.equal(f.node('pr-labels-status').textContent, priorLabels, 'historical additions do not replace snapshot labels');
    assert.match(f.node('status').textContent, /This receipt records the requested additions.*Reload the PR to observe its current labels/);
    assert.equal(f.node('pr-labels-add-stage').disabled, true); assert.equal(f.node('pr-labels-load').disabled, true);
    await f.loadPr(1);
    assert.equal(f.node('pr-labels-add-stage').disabled, false); assert.equal(f.node('pr-labels-stage').disabled, true);
    f.disconnect();
  });
}

test('empty, duplicate, oversized and control-containing addition drafts never stage or send', async () => {
  const f = await harness(), before = f.calls.length;
  for (const value of ['', ' ', 'bug\nbug', 'é'.repeat(33), 'bad\u0000label',
    Array.from({ length: 33 }, (_, n) => String(n)).join('\n')]) {
    f.node('pr-labels-add-values').value = value; f.submit('pr-labels-add-form');
    await new Promise(setImmediate); await until(() => !f.client.busy);
    assert.equal(f.client.pending, null); assert.equal(f.calls.length, before);
  }
  f.disconnect();
});

test('addition text remains inert and detached addition forms cannot retarget a later selection', async () => {
  const f = await harness(), value = '<img src=x onerror=alert(1)>\u202e';
  await f.stageAdd(value);
  assert.deepEqual(f.client.pending.fields.labels, [value]);
  assert.match(f.node('pending').textContent, /<img src=x onerror=alert\(1\)>/);
  assert.equal(descendants(f.node('pending')).some(node => node.tagName === 'IMG'), false);
  f.client.discardUnsent();
  const detached = f.node('pr-labels-add-form');
  await f.loadPr(1); detached.dispatchEvent(new Event('submit', { cancelable: true }));
  await until(() => !f.client.busy);
  assert.equal(f.client.pending, null); assert.equal(writes(f.calls).length, 0);
  assert.match(f.node('status').textContent, /Reload and select the intended native PR/); f.disconnect();
});

test('additions work for closed and merged native PRs but remain unavailable for merge-only records', async () => {
  for (const state of ['closed', 'merged']) {
    const observation = observed(); observation.pull_request.state = state;
    if (state === 'merged') observation.pull_request.merge = { ...observation.pull_request.data,
      target_tip_before: observation.pull_request.data.target_tip, base_tip: 'c'.repeat(40), merge_commit: 'd'.repeat(40) };
    const f = await harness({ observation }); assert.equal(f.node('fast-forward-stage').disabled, true);
    await f.stageAdd(); await f.send(); assert.match(f.node('status').textContent, /Canonical committed/);
    assert.equal(reads(f.calls).length, 0); f.disconnect();
    if (state === 'merged') {
      observation.pull_request.data = null; observation.pull_request.merge_only = true;
      const legacy = await harness({ observation });
      assert.equal(legacy.node('pr-labels-add-stage').disabled, true);
      legacy.node('pr-labels-add-values').value = 'reviewed'; legacy.submit('pr-labels-add-form');
      await until(() => !legacy.client.busy);
      assert.equal(legacy.client.pending, null); assert.equal(writes(legacy.calls).length, 0); legacy.disconnect();
    }
  }
});

test('an additions recovery copy keeps exact additions after a lost response and requires confirmation after import', async () => {
  let attempts = 0;
  const dispatch = (_call, pending) => {
    if (++attempts === 1) throw new Error('reply lost after possible commit');
    return json(labelsTerminal(pending));
  };
  const f = await harness({ dispatch }); await f.stageAdd('reviewed'); const pending = f.client.pending;
  await f.send(); assert.match(f.node('status').textContent, /Outcome remains unknown/);
  f.click('recover'); await until(() => !f.client.busy && /Labels outcome unknown/.test(f.node('status').textContent));
  assert.equal(attempts, 1); assert.equal(f.client.pending.key, pending.key);
  f.click('receipt-download'); await until(() => f.downloads.length === 1);
  const receipt = f.downloads[0].text; assert.equal(receipt.includes(token), false); f.disconnect();
  const restored = await harness({ dispatch });
  restored.node('receipt-import-file').files = [new File([receipt], 'label-additions.json')]; restored.submit('receipt-import');
  await until(() => restored.client.pending && !restored.client.busy);
  assert.equal(restored.client.pending.key, pending.key); assert.equal(attempts, 1);
  assert.equal(restored.node('confirm').checked, false); restored.click('send'); assert.equal(attempts, 1);
  await restored.send(); assert.equal(restored.client.pending, null); assert.equal(attempts, 2);
  assert.equal(writes(f.calls)[0].bytes, writes(restored.calls)[0].bytes);
  assert.equal(writes(f.calls)[0].headers['Idempotency-Key'], writes(restored.calls)[0].headers['Idempotency-Key']);
  assert.deepEqual(restored.node('pr-labels-values').value, '');
  restored.disconnect();
});

for (const operation of ['send', 'recover']) {
  test('additions ' + operation + ' keeps the inspected candidate and metadata selection while retiring the labels observation', async () => {
    const f = await harness({ observation: observed('sha1', { version: 1 }),
      recover: () => json(labelsOutcome('committed')) });
    await f.client.inspect(1, f.candidate.fields, f.candidate.bundle); const candidate = f.client.candidate;
    await f.loadLabels(); await f.stageAdd();
    if (operation === 'send') await f.send();
    else {
      f.click('recover'); await until(() => !f.client.busy && !f.client.pending);
    }
    assert.deepEqual(f.client.candidate, candidate);
    assert.equal(f.node('expected-version').value, '1'); assert.equal(f.node('fast-forward-stage').disabled, false);
    assert.equal(f.node('pr-labels-add-stage').disabled, true); assert.equal(f.node('pr-labels-stage').disabled, true);
    assert.match(f.node('status').textContent, /Canonical committed.*requested additions/); f.disconnect();
  });
}
