// Actual queue controller/client with DOM and fetch doubles. Native queue
// admission and real-browser behavior require their separate live suites.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { mountQueues } from '../../crates/fgit-node/src/smart_http/server/browser/queues-view.mjs';
import { token, actor, ids, head, hex, json, webcrypto, deferred, row, data, show as prShow } from './pulls-fixtures.mjs';
import { queueFixture } from './queues-candidate-fixtures.mjs';

const html = readFileSync(new URL('../../crates/fgit-node/src/smart_http/server/browser/queues.html', import.meta.url), 'utf8');
const source = readFileSync(new URL('../../crates/fgit-node/src/smart_http/server/browser/queues-view.mjs', import.meta.url), 'utf8');
const refs = (name, value) => ({ [name]: value, [`${name}_hex`]: hex(value) });
function queue(number = 7, extra = {}) {
  return { number, ...refs('target_ref', 'refs/heads/main'), version: 3, entries: [
    { pull_request: 1, ...refs('source_ref', 'refs/heads/topic'), head_tip: 'a'.repeat(40), enqueued_by: actor, priority: 10, enqueued_version: 1 },
    { pull_request: 2, ...refs('source_ref', 'refs/heads/next'), head_tip: 'c'.repeat(40), enqueued_by: actor, priority: 0, enqueued_version: 2 },
  ], order: [1, 2], active_batch: null, ...extra };
}
const page = (extra = {}) => ({ ...ids, type: 'merge_queue_page', source_head: 'head-id', snapshot_token: head,
  after: 0, limit: 20, next_after: null, queues: [queue()], complete: true, ...extra });
const show = (extra = {}) => ({ ...ids, type: 'merge_queue', source_head: 'head-id', snapshot_token: head,
  number: 7, found: true, version: 3, queue: queue(), complete: true, ...extra });
function publication(pending, extra = {}) {
  const f = pending.fields, ref = (name, value) => {
    let text = null;
    try { text = new TextDecoder('utf-8', { fatal: true }).decode(Buffer.from(value, 'hex')); } catch { /* Native byte refs have no text alias. */ }
    return { [name]: text, [`${name}_hex`]: value };
  };
  let action = { name: pending.action };
  if (['enqueue', 'land', 'land-candidate'].includes(pending.action)) action = { ...action, pull_request: f.pull_request,
    expected_pull_request_version: f.expected_pull_request_version, ...ref('source_ref', f.source_ref_hex),
    expected_source_tip: f.expected_source_tip, expected_target_tip: f.expected_target_tip,
    ...(pending.action === 'enqueue' ? { priority: f.priority } : { method: pending.action === 'land-candidate' ? 'merge-commit' : 'fast-forward-only', expected_policy_epoch: f.expected_policy_epoch }),
    ...(pending.action === 'land-candidate' ? { merge_base: f.merge_base, expected_commit: f.expected_commit } : {}) };
  else if (pending.action === 'dequeue') Object.assign(action, { pull_request: f.pull_request, reason: f.reason });
  else action.order = f.entry;
  return { ...ids, object_format: pending.scope.format, type: 'merge_queue_publication', principal_id: actor,
    number: pending.number, ...ref('target_ref', f.target_ref_hex), expected_version: f.expected_version,
    proposed_action: action, tx_id: 'queue-transaction', decision_sequence: 5, outcome: 'committed', committed: true,
    repository_commit_id: 'queue-rcr', refusal_record_id: null, refusal_code: null,
    refs_changed: ['land', 'land-candidate'].includes(pending.action), delivery_acknowledged: null, historical_outcome: true, complete: true, ...extra };
}
const outcome = (extra = {}) => ({ ...ids, type: 'transaction_outcome', principal_id: actor,
  selector: 'transaction', command_index: null, state: 'undecided', terminal: false,
  transaction: { tx_id: 'queue-transaction', seal_id: 'seal', request_schema: 'native-command-v1', canonical_request_digest: { algorithm: 1, hex: 'a'.repeat(64) } },
  decision: null, read_only: true, request_reexecuted: false, absence_proves_non_commit: false, session_completeness_established: false, ...extra });

class Element {
  constructor(tag = 'div') { this.tagName = tag; this.children = []; this.listeners = new Map(); this.value = ''; this.text = ''; this.files = []; this.checked = false; this.disabled = false; }
  set textContent(value) { this.text = String(value); this.children = []; }
  get textContent() { return this.text + this.children.map(child => child.textContent).join(''); }
  set innerHTML(_) { assert.fail('Queue view must not use an executable HTML sink'); }
  append(...children) { this.children.push(...children); }
  replaceChildren(...children) { this.text = ''; this.children = children; }
  addEventListener(name, callback) { const handlers = this.listeners.get(name) ?? []; handlers.push(callback); this.listeners.set(name, handlers); }
  fire(name, extra = {}) {
    const event = { defaultPrevented: false, preventDefault() { this.defaultPrevented = true; }, ...extra };
    for (const handler of this.listeners.get(name) ?? []) handler(event);
    return event;
  }
}
const digests = new Set();
const cryptoImpl = { getRandomValues: value => webcrypto.getRandomValues(value), subtle: { digest(...args) {
  const promise = webcrypto.subtle.digest(...args); digests.add(promise);
  promise.then(() => digests.delete(promise), () => digests.delete(promise)); return promise;
} } };
async function settled() { for (let i = 0; i < 20; i += 1) { await Promise.all([...digests]); await new Promise(setImmediate); } }
function buttons(root) { return root.children.flatMap(child => [...(child.tagName === 'button' ? [child] : []), ...buttons(child)]); }
function click(root, prefix) { const found = buttons(root).find(button => button.textContent.startsWith(prefix)); assert.ok(found, `button ${prefix}`); found.fire('click'); }
function file(input, serialized) { const bytes = new TextEncoder().encode(serialized); input.files = [{ size: bytes.length, arrayBuffer: async () => bytes.buffer }]; }
function harness(respond = () => null) {
  const nodes = Object.fromEntries([...html.matchAll(/<([a-z]+)\b[^>]*\bid="([^"]+)"[^>]*>/g)].map(match => {
    const node = new Element(match[1]); node.value = /\bvalue="([^"]*)"/.exec(match[0])?.[1] ?? ''; return [match[2], node];
  }));
  const lifecycle = new Element(), document = { getElementById: id => nodes[id], createElement: tag => new Element(tag), defaultView: lifecycle };
  const calls = [], downloads = [];
  let app;
  const fetchImpl = async (url, options) => {
    const call = { url: String(url), ...options }; calls.push(call);
    const response = await respond(call, app); if (response !== null && response !== undefined) return response;
    const parsed = new URL(url), path = parsed.pathname;
    if (path.endsWith('/queues')) return json(page({ after: Number(parsed.searchParams.get('after')), limit: Number(parsed.searchParams.get('limit')) }));
    if (path.endsWith('/queues/7')) return json(show());
    if (/\/pulls\/[0-9]+$/.test(path)) {
      const number = Number(path.split('/').at(-1));
      return json(prShow({ number, pull_request: row(number, { version: 4 }) }));
    }
    if (path.endsWith('/outcomes')) return json(outcome());
    if (options.method === 'POST' && app.client.pending) return json(publication(app.client.pending));
    throw new Error(`Unexpected queue test request ${path}`);
  };
  app = mountQueues(document, { href: 'https://forge.example/team/repo.git/ui/queues/', fetchImpl, cryptoImpl,
    downloadImpl: (name, contents) => downloads.push({ name, contents }) });
  const connect = async (secret = token) => { nodes.token.value = secret; nodes.connection.fire('submit'); await settled(); };
  const open = async () => { click(nodes['queue-list'], 'Queue #7'); await settled(); };
  const action = async value => { nodes['queue-action'].value = value; nodes['queue-action'].fire('change'); await settled(); };
  const enqueue = async () => {
    await action('enqueue');
    nodes['pull-number'].value = '3'; nodes['pull-version'].value = '4'; nodes['source-ref'].value = 'refs/heads/other';
    nodes['source-tip'].value = 'd'.repeat(40); nodes['target-tip'].value = 'b'.repeat(40); nodes.priority.value = '8';
    nodes['queue-change'].fire('submit'); await settled();
  };
  const send = async () => { nodes.confirm.checked = true; nodes.confirm.fire('change'); nodes.send.fire('click'); await settled(); };
  return { nodes, app, calls, downloads, lifecycle, connect, open, action, enqueue, send };
}

test('shipped page mounts all controls with scoped static paths and an inert snapshot-bound queue', async () => {
  const h = harness(); await h.connect();
  assert.equal(h.nodes.token.value, ''); assert.equal(h.app.client.connected, true);
  assert.match(h.nodes['queue-list'].textContent, /Queue #7.*refs\/heads\/main/);
  assert.match(h.nodes['queue-list'].textContent, /head PR #1/);
  assert.equal(h.calls.length, 1); assert.equal(h.calls[0].method, 'GET');
  assert.equal(h.calls[0].headers['Idempotency-Key'], undefined);
  assert.equal(h.calls[0].credentials, 'omit'); assert.equal(h.calls[0].redirect, 'error');
  assert.ok(html.includes('href="./browser.css"')); assert.ok(html.includes('src="./queues-view.mjs"'));
  assert.equal(html.includes('value="pause"'), false); assert.equal(source.includes('innerHTML'), false);
  await h.open();
  assert.equal(new URL(h.calls[1].url).searchParams.get('expected_head'), head);
  assert.match(h.nodes.selected.textContent, /1\. PR #1 · queue head/);
  assert.match(h.nodes.selected.textContent, /2\. PR #2/);
  assert.match(h.nodes.selected.textContent, new RegExp('a'.repeat(40)));
  assert.equal(h.nodes['queue-version'].value, '3'); assert.equal(h.nodes['queue-order'].value, '1\n2');
});

test('queue paging retains its exact head and cursor instead of refreshing implicitly', async () => {
  let lists = 0;
  const h = harness(call => new URL(call.url).pathname.endsWith('/queues') ? json(++lists === 1
    ? page({ limit: 5, queues: [1, 4, 7, 11, 20].map(number => queue(number)), next_after: 20 })
    : page({ limit: 5, after: 20, queues: [], next_after: null })) : null);
  h.nodes['page-limit'].value = '5'; await h.connect(); click(h.nodes.paging, 'Next queue page'); await settled();
  const query = new URL(h.calls.at(-1).url).searchParams;
  assert.equal(query.get('after'), '20'); assert.equal(query.get('expected_head'), head); assert.equal(query.get('limit'), '5');
  assert.match(h.nodes['queue-list'].textContent, /No queues/); assert.equal(h.app.page.head, head);
});

test('stale and hidden queue responses never remain selected or provide a landing head', async () => {
  for (const response of [() => json(show({ snapshot_token: `alg:1:${'e'.repeat(64)}` })),
    () => json(show({ found: false, queue: null, version: 0 }), 404), () => json({}, 403)]) {
    const h = harness(call => new URL(call.url).pathname.endsWith('/queues/7') ? response() : null);
    await h.connect(); await h.open();
    assert.equal(h.app.selected?.row ?? null, null); assert.doesNotMatch(h.nodes.selected.textContent, /queue head/);
    await h.action('land'); h.nodes['queue-change'].fire('submit'); await settled();
    assert.equal(h.app.client.pending, null); assert.equal(h.calls.length, 2);
  }
});

test('read-only PR loading pins the queue snapshot and renders hostile titles as inert text', async () => {
  const h = harness(call => /\/pulls\/3\?/.test(call.url) ? json(prShow({ number: 3, pull_request: row(3, {
    version: 4, data: data({ title: '<img onerror=alert(1)>\u202e' }),
  }) })) : null);
  await h.connect(); await h.open(); h.nodes['pull-number'].value = '3'; h.nodes['load-pull'].fire('click'); await settled();
  assert.equal(new URL(h.calls.at(-1).url).searchParams.get('expected_head'), head);
  assert.equal(h.calls.at(-1).headers['Idempotency-Key'], undefined); assert.equal(h.app.client.pending, null);
  assert.equal(h.nodes['pull-version'].value, '4'); assert.equal(h.nodes['source-ref'].value, 'refs/heads/topic');
  assert.match(h.nodes['pull-observation'].textContent, /<img onerror=alert\(1\)>\\u\{202e\}/);
  assert.doesNotMatch(h.nodes['pull-observation'].textContent, /\u202e/);
});

test('manual exact enqueue remains usable without a PR-read grant and never auto-sends', async () => {
  const h = harness(call => new URL(call.url).pathname.includes('/pulls/') ? json({}, 403) : null);
  await h.connect(); await h.open(); h.nodes['pull-number'].value = '3'; h.nodes['load-pull'].fire('click'); await settled();
  assert.equal(h.app.client.connected, true); const before = h.calls.length;
  await h.enqueue(); assert.equal(h.calls.length, before); assert.equal(h.app.client.pending.action, 'enqueue');
  assert.equal(h.app.client.pending.fields.expected_version, 3); assert.equal(h.app.client.pending.fields.expected_pull_request_version, 4);
  assert.equal(h.app.client.pending.fields.priority, 8); assert.equal(h.nodes.send.disabled, true);
  h.nodes.send.fire('click'); await settled(); assert.equal(h.calls.length, before); assert.match(h.nodes.status.textContent, /confirm/);
  h.nodes['source-tip'].value = 'e'.repeat(40); await h.send();
  const form = new URLSearchParams(await h.calls.at(-1).body.text());
  assert.equal(form.get('expected_source_tip'), 'd'.repeat(40)); assert.equal(form.get('expected_incarnation'), ids.repository_incarnation);
  assert.equal(form.get('principal'), null); assert.match(h.nodes.status.textContent, /Canonical committed · enqueue/);
  assert.match(h.nodes.status.textContent, /does not land a PR/); assert.equal(h.app.client.pending, null);
});

test('creating an absent queue requires an explicit target and version zero', async () => {
  const h = harness(call => new URL(call.url).pathname.endsWith('/queues/99')
    ? json(show({ number: 99, found: false, version: 0, queue: null }), 404) : null);
  await h.connect(); h.nodes['show-number'].value = '99'; h.nodes['show-form'].fire('submit'); await settled();
  assert.equal(h.nodes['queue-number'].value, '99'); assert.equal(h.nodes['queue-version'].value, '0');
  assert.equal(h.nodes['target-ref'].value, '');
  await h.enqueue(); assert.equal(h.app.client.pending, null);
  h.nodes['target-ref'].value = 'refs/heads/main'; await h.enqueue();
  assert.equal(h.app.client.pending.number, 99); assert.equal(h.app.client.pending.fields.expected_version, 0);
  assert.equal(h.calls.length, 2);
});

test('dequeue requires an explicit reason and reordering requires the entire selected membership', async () => {
  const h = harness(); await h.connect(); await h.open();
  h.nodes['queue-number'].value = '99'; h.nodes['queue-version'].value = '1'; h.nodes['target-ref'].value = 'refs/heads/manual';
  click(h.nodes.selected, 'Prepare removal of PR #2');
  assert.equal(h.nodes['queue-number'].value, '7'); assert.equal(h.nodes['queue-version'].value, '3');
  assert.equal(h.nodes['target-ref'].value, 'refs/heads/main');
  assert.equal(h.nodes['dequeue-number'].value, '2'); assert.equal(h.nodes['dequeue-reason'].value, '');
  h.nodes['queue-change'].fire('submit'); await settled(); assert.equal(h.app.client.pending, null); assert.match(h.nodes.status.textContent, /reason/);
  h.nodes['dequeue-reason'].value = 'withdrawn'; h.nodes['queue-change'].fire('submit'); await settled();
  assert.equal(h.app.client.pending.fields.reason, 'withdrawn'); assert.equal(h.app.client.pending.fields.pull_request, 2);
  h.nodes.discard.fire('click'); await settled(); await h.action('reorder');
  for (const order of ['1', '1\n1', '2\n3']) {
    h.nodes['queue-order'].value = order; h.nodes['queue-change'].fire('submit'); await settled();
    assert.equal(h.app.client.pending, null); assert.match(h.nodes.status.textContent, /every selected queue member/);
  }
  h.nodes['queue-order'].value = '2\n1'; h.nodes['queue-change'].fire('submit'); await settled();
  assert.deepEqual(h.app.client.pending.fields.entry, [2, 1]); assert.equal(h.calls.length, 2);
  await h.send(); assert.deepEqual(new URLSearchParams(await h.calls.at(-1).body.text()).getAll('entry'), ['2', '1']);
  assert.match(h.nodes.status.textContent, /Canonical committed · reorder/);
});

test('fast-forward landing fixes the observed head and requires exact PR and policy inputs', async () => {
  const h = harness(); await h.connect(); await h.open(); h.nodes['queue-number'].value = '99';
  click(h.nodes.selected, 'Prepare fast-forward landing');
  assert.equal(h.nodes['queue-number'].value, '7');
  assert.equal(h.nodes['queue-action'].value, 'land'); assert.equal(h.nodes['pull-number'].value, '1');
  assert.equal(h.nodes['pull-version'].value, ''); assert.equal(h.nodes['target-tip'].value, '');
  assert.equal(h.nodes['policy-epoch'].value, ''); assert.equal(h.nodes.priority.disabled, true);
  h.nodes['load-pull'].fire('click'); await settled(); assert.equal(h.nodes['pull-version'].value, '4');
  h.nodes['queue-change'].fire('submit'); await settled(); assert.equal(h.app.client.pending, null);
  h.nodes['policy-epoch'].value = '9'; h.nodes['pull-number'].value = '2';
  h.nodes['queue-change'].fire('submit'); await settled(); assert.equal(h.app.client.pending, null); assert.match(h.nodes.status.textContent, /queue head/);
  h.nodes['pull-number'].value = '1'; h.nodes['queue-change'].fire('submit'); await settled();
  assert.equal(h.app.client.pending.action, 'land'); assert.equal(h.app.client.pending.fields.expected_policy_epoch, 9);
  assert.equal(h.calls.length, 3); assert.match(h.nodes.status.textContent, /No branch has moved/);
  await h.send(); const form = new URLSearchParams(await h.calls.at(-1).body.text());
  assert.ok(h.calls.at(-1).url.endsWith('/queues/7/land')); assert.equal(form.get('priority'), null);
  assert.equal(form.get('expected_policy_epoch'), '9'); assert.equal(form.get('expected_source_tip'), 'a'.repeat(40));
  assert.match(h.nodes.status.textContent, /Canonical committed · land/);
  assert.match(h.nodes.status.textContent, /target update and PR merge together/);
});

test('native byte references remain exact through queue display, manual enqueue and publication', async () => {
  const target = hex('refs/heads/') + 'ff', native = queue(7, { target_ref: null, target_ref_hex: target });
  const h = harness(call => {
    const path = new URL(call.url).pathname;
    if (path.endsWith('/queues')) return json(page({ queues: [native] }));
    if (path.endsWith('/queues/7')) return json(show({ queue: native }));
    return null;
  });
  await h.connect(); await h.open();
  assert.equal(h.nodes['target-kind'].value, 'hex'); assert.equal(h.nodes['target-ref'].value, target);
  assert.match(h.nodes.selected.textContent, /Native reference bytes/);
  await h.enqueue(); assert.equal(h.app.client.pending.fields.target_ref_hex, target); await h.send();
  assert.equal(new URLSearchParams(await h.calls.at(-1).body.text()).get('target_ref_hex'), target);
  assert.equal(h.app.client.pending, null); assert.match(h.nodes.status.textContent, /Canonical committed/);
});

test('a changed target, moved queued PR, or busy queue cannot become a prepared landing', async () => {
  for (const mode of ['target', 'source', 'batch']) {
    const h = harness(call => {
      if (mode === 'batch' && new URL(call.url).pathname.endsWith('/queues/7')) return json(show({ queue: queue(7, { active_batch: 'f'.repeat(64) }) }));
      if (mode === 'source' && new URL(call.url).pathname.endsWith('/pulls/1')) return json(prShow({ pull_request: row(1, { data: data({ source_tip: 'e'.repeat(40) }) }) }));
      return null;
    });
    await h.connect(); await h.open(); await h.action('land');
    if (mode === 'target') h.nodes['target-ref'].value = 'refs/heads/other';
    h.nodes['load-pull'].fire('click'); await settled(); h.nodes['policy-epoch'].value = '9';
    h.nodes['queue-change'].fire('submit'); await settled(); assert.equal(h.app.client.pending, null);
    assert.equal(h.calls.some(call => call.method === 'POST'), false);
  }
});

test('a native terminal refusal settles visibly while malformed successes retain original custody', async () => {
  for (const mode of ['refusal', 'malformed']) {
    const h = harness((call, app) => call.method === 'POST' ? mode === 'refusal'
      ? json(publication(app.client.pending, { outcome: 'refused', committed: false, repository_commit_id: null,
        refusal_record_id: 'refusal', refusal_code: 'Conflict', refs_changed: false }), 409)
      : json(publication(app.client.pending, { expected_version: 55 })) : null);
    await h.connect(); await h.open(); await h.enqueue(); const key = h.app.client.pending.key; await h.send();
    if (mode === 'refusal') { assert.equal(h.app.client.pending, null); assert.match(h.nodes.status.textContent, /Canonical refused/); }
    else { assert.equal(h.app.client.pending.key, key); assert.match(h.nodes.status.textContent, /Outcome remains unknown/); }
  }
});

test('response loss keeps body and key across edits, private receipt export, reload and explicit retry', async () => {
  const h = harness(call => call.method === 'POST' ? Promise.reject(new TypeError('response lost')) : null);
  await h.connect(); await h.open(); await h.enqueue(); await h.send();
  const pending = h.app.client.pending, first = h.calls.at(-1);
  assert.equal(pending.state, 'unknown'); assert.equal(h.nodes.discard.disabled, true);
  assert.equal(h.calls.filter(call => call.method === 'POST').length, 1);
  h.nodes['receipt-download'].fire('click'); await settled(); const receipt = h.downloads[0].contents;
  assert.equal(receipt.includes(token), false); assert.equal(h.nodes.prepare.disabled, true);
  const restored = harness(); await restored.connect(); const before = restored.calls.length;
  file(restored.nodes['receipt-import-file'], receipt); restored.nodes['receipt-import'].fire('submit'); await settled();
  assert.equal(restored.calls.length, before); assert.equal(restored.app.client.pending.key, pending.key);
  assert.equal(restored.nodes.confirm.checked, false); assert.equal(restored.nodes.send.disabled, true);
  restored.nodes['source-tip'].value = 'e'.repeat(40); await restored.send();
  const retry = restored.calls.at(-1);
  assert.equal(retry.url, first.url); assert.equal(retry.headers['Idempotency-Key'], first.headers['Idempotency-Key']);
  assert.equal(await retry.body.text(), await first.body.text()); assert.equal(restored.app.client.pending, null);
});

test('recovery-only connection imports under a rotated credential and never reads or sends', async () => {
  const original = harness(); await original.connect(); await original.open(); await original.enqueue();
  original.nodes['receipt-download'].fire('click'); await settled(); const receipt = original.downloads[0].contents;
  const next = harness(); next.nodes['recovery-only'].checked = true; next.nodes['original-principal'].value = actor;
  await next.connect('d'.repeat(64)); assert.equal(next.calls.length, 0); assert.equal(next.app.client.recoveryOnly, true);
  file(next.nodes['receipt-import-file'], receipt); next.nodes['receipt-import'].fire('submit'); await settled();
  assert.equal(next.calls.length, 0); assert.equal(next.nodes.send.disabled, true); assert.equal(next.nodes.prepare.disabled, true);
  assert.equal(next.nodes.refresh.disabled, true); assert.equal(next.nodes.discard.disabled, true);
  next.nodes.confirm.checked = true; next.nodes.send.fire('click'); await settled(); assert.equal(next.calls.length, 0);
  next.nodes.recover.fire('click'); await settled();
  assert.equal(next.calls.length, 1); assert.ok(next.calls[0].url.endsWith('/outcomes')); assert.equal(next.calls[0].body, undefined);
  assert.equal(next.calls[0].headers.Authorization, `Bearer ${'d'.repeat(64)}`);
  assert.equal(next.calls[0].headers['Idempotency-Key'], original.app.client.pending.key);
  assert.equal(next.app.client.pending.state, 'undecided'); assert.match(next.nodes.status.textContent, /Outcome remains unknown/);
});

test('known recovery outcome clears custody without ever resending queue metadata', async () => {
  const h = harness(call => new URL(call.url).pathname.endsWith('/outcomes') ? json(outcome({ state: 'committed', terminal: true,
    decision: { kind: 'committed', decision_sequence: 5, repository_commit_id: 'queue-rcr' } })) : null);
  await h.connect(); await h.open(); await h.enqueue(); h.nodes.recover.fire('click'); await settled();
  assert.equal(h.app.client.pending, null); assert.equal(h.calls.filter(call => call.method === 'POST').length, 1);
  assert.ok(h.calls.at(-1).url.endsWith('/outcomes')); assert.equal(h.calls.at(-1).body, undefined);
  assert.match(h.nodes.status.textContent, /Canonical committed · enqueue/);
});

test('disconnect erases private displays and late reads while keeping unresolved request custody', async () => {
  const late = deferred(); let delay = false;
  const h = harness(call => delay && new URL(call.url).pathname.endsWith('/queues') ? late.promise : null);
  await h.connect(); await h.open(); await h.enqueue(); const key = h.app.client.pending.key;
  delay = true; h.nodes['list-form'].fire('submit'); await settled(); h.lifecycle.fire('pagehide');
  late.resolve(json(page())); await settled();
  assert.equal(h.app.client.connected, false); assert.equal(h.app.client.pending.key, key);
  assert.equal(h.nodes.selected.textContent, ''); assert.equal(h.nodes['queue-list'].textContent, '');
  for (const field of ['token', 'source-tip', 'target-tip', 'source-ref', 'queue-order']) assert.equal(h.nodes[field].value, '');
  assert.match(h.nodes.pending.textContent, /Reconnect/); assert.doesNotMatch(h.nodes.pending.textContent, /refs\/heads\/other/);
  assert.equal(h.lifecycle.fire('beforeunload').defaultPrevented, true);
});

test('a cancelled PR read cannot overwrite manually changed queue selection', async () => {
  const late = deferred();
  const h = harness(call => new URL(call.url).pathname.endsWith('/pulls/3') ? late.promise : null);
  await h.connect(); await h.open(); h.nodes['pull-number'].value = '3'; h.nodes['load-pull'].fire('click'); await settled();
  h.nodes['target-ref'].value = 'refs/heads/manual';
  late.resolve(json(prShow({ number: 3, pull_request: row(3) }))); await settled();
  assert.equal(h.nodes['target-ref'].value, 'refs/heads/manual'); assert.equal(h.nodes['pull-version'].value, '');
  assert.match(h.nodes.status.textContent, /selection changed/);
});

test('receipt restoration refuses oversize and malformed UTF-8 files before client interpretation', async () => {
  const h = harness(); await h.connect();
  h.nodes['receipt-import-file'].files = [{ size: 24 * 1024 * 1024 + 1, arrayBuffer() { assert.fail('oversize receipt read'); } }];
  h.nodes['receipt-import'].fire('submit'); await settled(); assert.equal(h.app.client.pending, null);
  h.nodes['receipt-import-file'].files = [{ size: 1, arrayBuffer: async () => Uint8Array.of(255).buffer }];
  h.nodes['receipt-import'].fire('submit'); await settled(); assert.equal(h.app.client.pending, null); assert.equal(h.calls.length, 1);
});

async function candidateDraft(h) {
  await h.connect(); await h.open(); await h.action('land-candidate');
  h.nodes['load-pull'].fire('click'); await settled();
  h.nodes['policy-epoch'].value = '1'; h.nodes['candidate-author'].value = 'Test <test@example.invalid>';
  h.nodes['candidate-committer'].value = 'Test <test@example.invalid>'; h.nodes['candidate-timestamp'].value = '1';
  h.nodes['candidate-message'].value = 'Exact candidate\n';
}
function candidateHarness(f = queueFixture(), extra = () => null) {
  return harness(async (call, app) => {
    const result = await extra(call, app); if (result !== null && result !== undefined) return result;
    if (new URL(call.url).pathname.endsWith('/prepare')) return f.prepared();
    if (new URL(call.url).pathname.endsWith('/inspect')) return json(f.inspection);
    return null;
  });
}
test('queue page executes candidate preparation, displays every native hunk as inert text and stages before explicit send', async () => {
  const f = queueFixture(), before = 'before\n', after = '<script>inert</script>\n';
  f.inspection.comparison.entries = [
    { path_hex: hex('a<script>.txt'), kind: 'modified', before: { mode: 33188, oid: 'c'.repeat(40) }, after: { mode: 33188, oid: 'd'.repeat(40) },
      content: { type: 'text', algorithm: 'myers', additions: 1, deletions: 1, before_bytes: before.length, after_bytes: after.length,
        hunks: [{ old: { byte_start: 0, byte_end: before.length, line_start: 1, line_count: 1 }, new: { byte_start: 0, byte_end: after.length, line_start: 1, line_count: 1 },
          before_hex: hex(before), after_hex: hex(after) }] } },
    { path_hex: hex('binary'), kind: 'modified', before: { mode: 33188, oid: 'c'.repeat(40) }, after: { mode: 33188, oid: 'd'.repeat(40) },
      content: { type: 'binary', before_bytes: 2, after_bytes: 3, body_included: false } },
  ];
  f.inspection.comparison.entry_count = 2;
  const h = candidateHarness(f); await candidateDraft(h);
  assert.equal(h.nodes.prepare.disabled, true); assert.equal(h.nodes['candidate-fields'].hidden, false);
  h.nodes['candidate-prepare'].fire('click'); await settled();
  assert.equal(h.app.client.candidateReady, true); assert.equal(h.app.client.pending, null); assert.equal(h.nodes.prepare.disabled, false);
  assert.match(h.nodes['candidate-report'].textContent, /a<script>\.txt/); assert.ok(h.nodes['candidate-report'].textContent.includes(after));
  assert.match(h.nodes['candidate-report'].textContent, /Hunk 1/); assert.match(h.nodes['candidate-report'].textContent, /Binary content: 2 → 3/);
  assert.equal(h.calls.filter(call => call.headers['Idempotency-Key']).length, 0);
  h.nodes['candidate-bundle-download'].fire('click'); await settled();
  h.nodes['candidate-inspection-download'].fire('click'); await settled();
  h.nodes['candidate-review-download'].fire('click'); await settled();
  assert.deepEqual(h.downloads[0].contents, f.bundle);
  assert.equal(JSON.parse(h.downloads[1].contents).preparation.landing.command_form, f.commandForm);
  assert.equal(JSON.parse(h.downloads[2].contents).schema, 'frankengit-browser-candidate-v1');
  h.nodes['queue-change'].fire('submit'); await settled();
  assert.equal(h.app.client.pending.action, 'land-candidate'); assert.equal(h.calls.filter(call => call.headers['Idempotency-Key']).length, 0);
  h.nodes['receipt-download'].fire('click'); await settled(); assert.equal(JSON.parse(h.downloads.at(-1).contents).request.command_form, f.commandForm);
  await h.send(); assert.equal(h.app.client.pending, null); assert.match(h.nodes.status.textContent, /atomic|target update and PR merge together/);
});

test('editing candidate metadata clears inspected authority while retained landing bytes and key survive', async () => {
  const h = candidateHarness(); await candidateDraft(h); h.nodes['candidate-prepare'].fire('click'); await settled();
  h.nodes['queue-change'].fire('submit'); await settled(); const pending = h.app.client.pending;
  h.nodes['candidate-message'].value = 'Different'; h.nodes['candidate-message'].fire('input'); await settled();
  assert.equal(h.app.client.candidateReady, false); assert.equal(h.nodes['candidate-section'].hidden, true); assert.equal(h.nodes.prepare.disabled, true);
  assert.equal(h.app.client.pending.key, pending.key); assert.equal(h.app.client.pending.body, pending.body);
  h.app.disconnect(); assert.equal(h.app.client.pending.key, pending.key); assert.equal(h.nodes['candidate-message'].value, '');
});

test('conflicts remain a read-only stop and a failed full inspection never exposes candidate staging', async () => {
  for (const kind of ['conflict', 'incomplete']) {
    const f = queueFixture(), h = candidateHarness(f, call => {
      const path = new URL(call.url).pathname;
      if (kind === 'conflict' && path.endsWith('/prepare')) return json({ ...f.metadata, state: 'conflicted', merge_base: f.landingFields.merge_base,
        candidate: null, bundle: null, landing: null, conflicts: [{ path_hex: '61ff', kind: 'binary', base: null, ours: null, theirs: null }] }, 409);
      if (kind === 'incomplete' && path.endsWith('/inspect')) return json({ ...f.inspection, all_changed_paths: false });
      return null;
    });
    await candidateDraft(h); h.nodes['candidate-prepare'].fire('click'); await settled();
    assert.equal(h.app.client.candidateReady, false); assert.equal(h.nodes.prepare.disabled, true); assert.equal(h.app.client.pending, null);
    if (kind === 'conflict') { assert.match(h.nodes['candidate-report'].textContent, /Path bytes: 61ff/); assert.equal(h.calls.some(call => call.url.endsWith('/inspect')), false); }
    else assert.match(h.nodes.status.textContent, /incomplete/);
  }
});

test('cancelling candidate preparation and editing during native inspection reject late view installation', async () => {
  for (const cancel of ['button', 'edit']) {
    const f = queueFixture(), late = deferred(), h = candidateHarness(f, call => call.url.endsWith('/inspect') ? late.promise : null);
    await candidateDraft(h); h.nodes['candidate-prepare'].fire('click'); await settled();
    const call = h.calls.at(-1); assert.ok(call.url.endsWith('/inspect'));
    if (cancel === 'button') h.nodes['cancel-read'].fire('click');
    else { h.nodes['candidate-message'].value = 'Edited during read'; h.nodes['candidate-message'].fire('input'); }
    assert.equal(call.signal.aborted, true); late.resolve(json(f.inspection)); await settled();
    assert.equal(h.app.client.candidateReady, false); assert.equal(h.nodes['candidate-section'].hidden, true); assert.equal(h.app.client.pending, null);
    assert.equal(h.nodes.refresh.disabled, false); assert.equal(h.nodes['candidate-prepare'].disabled, false);
    if (cancel === 'button') assert.match(h.nodes.status.textContent, /Read cancelled/);
  }
});

test('obsolete candidate completion refreshes controls without clearing a newer read or disconnected state', async () => {
  for (const next of ['read', 'disconnect']) {
    const f = queueFixture(), inspection = deferred(), queued = deferred(); let blockQueue = false;
    const h = candidateHarness(f, call => {
      if (call.url.endsWith('/inspect')) return inspection.promise;
      if (blockQueue && new URL(call.url).pathname.endsWith('/queues/7')) return queued.promise;
      return null;
    });
    await candidateDraft(h); h.nodes['candidate-prepare'].fire('click'); await settled();
    h.nodes['cancel-read'].fire('click');
    if (next === 'disconnect') h.app.disconnect();
    else { blockQueue = true; h.nodes['show-number'].value = '7'; h.nodes['show-form'].fire('submit'); await settled(); }
    const status = h.nodes.status.textContent;
    inspection.resolve(json(f.inspection)); await settled();
    assert.equal(h.app.client.candidateReady, false); assert.equal(h.nodes.status.textContent, status);
    assert.equal(h.nodes.refresh.disabled, true);
    if (next === 'read') {
      assert.equal(h.nodes['cancel-read'].disabled, false);
      queued.resolve(json(show())); await settled();
      assert.equal(h.nodes.refresh.disabled, false); assert.equal(h.nodes['cancel-read'].disabled, true);
    } else {
      assert.equal(h.app.client.connected, false); assert.equal(h.nodes['candidate-prepare'].disabled, true);
      assert.equal(h.nodes['cancel-read'].disabled, true);
    }
  }
});
