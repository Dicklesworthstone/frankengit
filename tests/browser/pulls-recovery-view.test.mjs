// Actual PR page/client modules with inert DOM and HTTP test doubles. These
// tests are not native engine, real browser layout, or live server acceptance.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { webcrypto } from 'node:crypto';
import { mountPulls } from '../../crates/fgit-node/src/smart_http/server/browser/pulls-view.mjs';
import { rootFor, utf8 } from '../../crates/fgit-node/src/smart_http/server/browser/pulls-core.mjs';
import { digest } from '../../crates/fgit-node/src/smart_http/server/browser/pulls-candidate.mjs';
import { base64, requestBody, requestKey } from '../../crates/fgit-node/src/smart_http/server/browser/pulls-actions.mjs';

const html = readFileSync(new URL('../../crates/fgit-node/src/smart_http/server/browser/pulls.html', import.meta.url), 'utf8');
const HREF = 'https://forge.example/repo.git/ui/pulls/';
const ORIGINAL = '1'.repeat(64), ROTATED = '2'.repeat(64), PRINCIPAL = 'a'.repeat(32), OTHER = 'b'.repeat(32);
const scope = algorithm => ({ tenant: 'tenant', repository: 'repo', incarnation: 'incarnation', format: algorithm });
const identity = algorithm => ({ schema_version: 1, tenant_id: 'tenant', repository_id: 'repo', repository_incarnation: 'incarnation', object_format: algorithm });
const response = (value, status = 200) => new Response(JSON.stringify(value), { status, headers: { 'Content-Type': 'application/json' } });
const page = algorithm => ({ ...identity(algorithm), type: 'pull_request_page', source_head: 'rcr/page', snapshot_token: `alg:2:${'d'.repeat(64)}`,
  after: 0, limit: 20, next_after: null, pull_requests: [] });
const metadata = algorithm => ({ object_format: algorithm, expected_version: 0, source_ref: 'refs/heads/topic', target_ref: 'refs/heads/main',
  source_tip: 'a'.repeat(algorithm === 'sha1' ? 40 : 64), target_tip: 'b'.repeat(algorithm === 'sha1' ? 40 : 64), title: 'Original PR', body: 'Original bytes\n' });
function outcome(state = 'key_not_observed', algorithm = 'sha1', overrides = {}) {
  const terminal = ['committed', 'refused'].includes(state);
  return { ...identity(algorithm), type: 'transaction_outcome', selector: 'transaction', command_index: null,
    read_only: true, request_reexecuted: false, absence_proves_non_commit: false, session_completeness_established: false,
    principal_id: PRINCIPAL, state, terminal, transaction: state === 'undecided' || terminal
      ? { tx_id: 'tx/original', seal_id: 'seal/original', request_schema: 'request/v1', canonical_request_digest: { algorithm: 2, hex: 'ab'.repeat(32) } } : null,
    decision: !terminal ? null : state === 'committed' ? { kind: state, decision_sequence: 4, repository_commit_id: 'rcr/original' }
      : { kind: state, decision_sequence: 4, refusal_record_id: 'refusal/original', code: 'policy_refused', code_point: 7 }, ...overrides };
}
async function originalReceipt(algorithm = 'sha1', action = 'open') {
  const number = 7, nonce = '3'.repeat(32), selected = scope(algorithm), m = metadata(algorithm);
  let fields = m, bundle = null;
  if (action === 'comment') fields = { object_format: algorithm, expected_version: 3, body: 'Original comment' };
  if (action === 'merge') {
    fields = { object_format: algorithm, source_ref: m.source_ref, target_ref: m.target_ref, source_tip: m.source_tip, target_tip: m.target_tip,
      pull_request_version: 2, policy_epoch: 1, merge_base: 'c'.repeat(m.source_tip.length), candidate_commit: 'd'.repeat(m.source_tip.length), required_reviewer: [OTHER] };
    bundle = Uint8Array.of(0, 13, 255, 10); // Opaque saved upload, never resubmitted or claimed to be a verified Git bundle.
  }
  const fingerprint = await digest(utf8.encode(ORIGINAL), webcrypto), body = requestBody(action, fields, bundle, nonce);
  const key = await requestKey(rootFor(HREF), fingerprint, selected, number, action, nonce, body, webcrypto);
  return JSON.stringify({ schema: 'frankengit-pr-retry-v1', origin: rootFor(HREF).origin, route: rootFor(HREF).route,
    request: { number, action, fields: body.fields, scope: selected, fingerprint, nonce, key,
      bundle_base64: bundle === null ? null : base64(bundle), observedTx: null, observedPrincipal: null } });
}
class Element {
  constructor(tag = 'div') { this.tagName = tag; this.children = []; this.listeners = new Map(); this.value = ''; this.text = ''; this.files = []; this.checked = false; this.disabled = false; }
  set textContent(value) { this.text = String(value); this.children = []; }
  get textContent() { return this.text + this.children.map(child => child.textContent).join(''); }
  set innerHTML(_) { throw new Error('Unsafe HTML sink'); }
  append(...children) { this.children.push(...children); }
  replaceChildren(...children) { this.text = ''; this.children = children; }
  addEventListener(name, fn) { const entries = this.listeners.get(name) ?? []; entries.push(fn); this.listeners.set(name, entries); }
  fire(name, event = {}) { const ev = { preventDefault() {}, ...event }; for (const fn of this.listeners.get(name) ?? []) fn(ev); return ev; }
}
const digests = new Set();
const cryptoImpl = { getRandomValues: value => webcrypto.getRandomValues(value), subtle: { digest(...args) {
  const pending = webcrypto.subtle.digest(...args); digests.add(pending);
  pending.then(() => digests.delete(pending), () => digests.delete(pending)); return pending;
} } };
async function settled() { for (let i = 0; i < 20; i++) { await Promise.all([...digests]); await new Promise(setImmediate); } }
function harness(respond = () => null, algorithm = 'sha1') {
  const nodes = Object.fromEntries(Array.from(html.matchAll(/id="([^"]+)"/g), m => [m[1], new Element()]));
  const lifecycle = new Element(), doc = { getElementById: id => nodes[id], createElement: tag => new Element(tag), defaultView: lifecycle };
  const calls = [], downloads = []; let app;
  app = mountPulls(doc, { href: HREF, cryptoImpl, downloadImpl: (name, content) => downloads.push({ name, content }),
    fetchImpl: async (url, options) => {
      calls.push({ url, ...options }); const supplied = await respond(calls.at(-1), app);
      if (supplied !== null && supplied !== undefined) return supplied;
      if (url.pathname.endsWith('/outcomes')) return response(outcome('key_not_observed', algorithm));
      if (url.pathname.endsWith('/pulls')) return response(page(algorithm));
      throw new Error('Unexpected request');
    } });
  const choose = (recoveryOnly, principal = PRINCIPAL) => {
    nodes['recovery-only'].checked = recoveryOnly; nodes['original-principal'].value = principal; nodes['recovery-only'].fire('change');
  };
  const connect = async (token = ROTATED, recoveryOnly = true, principal = PRINCIPAL) => {
    choose(recoveryOnly, principal); nodes.token.value = token; nodes.connection.fire('submit'); await settled();
  };
  const restore = async serialized => {
    const bytes = utf8.encode(serialized); nodes['receipt-import-file'].value = 'receipt.json';
    nodes['receipt-import-file'].files = [{ size: bytes.length, arrayBuffer: async () => bytes.buffer }];
    nodes['receipt-import'].fire('submit'); await settled();
  };
  const click = async id => { nodes[id].fire('click'); await settled(); };
  const stage = async () => {
    nodes['pr-number'].value = '7'; nodes['metadata-action'].value = 'open';
    for (const [name, value] of Object.entries(metadata(algorithm))) nodes[name.replaceAll('_', '-')].value = String(value);
    nodes.metadata.fire('submit'); await settled();
  };
  return { app, nodes, lifecycle, calls, downloads, choose, connect, restore, click, stage };
}
function assertRestricted(h) {
  for (const id of ['refresh', 'select-number', 'select-load', 'new-pr', 'metadata-stage', 'candidate-import-file', 'candidate-import-submit',
    'prepare-candidate', 'resolve-candidate', 'review-stage', 'merge-stage', 'comment-stage', 'send', 'confirm', 'discard']) assert.equal(h.nodes[id].disabled, true, id);
  assert.match(h.nodes['connection-mode'].textContent, /RECOVERY ONLY/);
}

for (const algorithm of ['sha1', 'sha256']) for (const action of ['open', 'comment', 'merge']) {
  test(`${algorithm} ${action}: page reload restores and recovers an original receipt without PR reads or sends`, async () => {
    let state = 'key_not_observed';
    const serialized = await originalReceipt(algorithm, action), original = JSON.parse(serialized);
    const h = harness(() => response(outcome(state, algorithm)), algorithm);
    await h.connect(); assert.equal(h.calls.length, 0); assert.equal(h.nodes.token.value, ''); assertRestricted(h);
    assert.equal(h.nodes['receipt-import-file'].disabled, false); assert.equal(h.nodes['receipt-import-submit'].disabled, false);
    await h.restore(serialized); assert.equal(h.calls.length, 0);
    assert.equal(h.nodes['receipt-import-file'].value, ''); assert.equal(h.app.client.pending.key, original.request.key);
    assert.equal(h.nodes.recover.disabled, false); assert.equal(h.nodes['receipt-download'].disabled, false); assertRestricted(h);
    assert.match(h.nodes.status.textContent, /outcome lookup only/);
    await h.click('receipt-download'); assert.deepEqual(JSON.parse(h.downloads[0].content), original);
    assert.equal(h.downloads[0].content.includes(ROTATED), false);
    await h.click('recover'); assert.match(h.nodes.status.textContent, /Outcome unknown.*Absence never proves non-commit/);
    assert.ok(h.app.client.pending); assertRestricted(h);
    state = 'committed'; await h.click('recover'); assert.match(h.nodes.status.textContent, /Canonical committed.*reconnect explicitly/);
    assert.equal(h.app.client.pending, null); assertRestricted(h); assert.equal(h.calls.length, 2);
    for (const call of h.calls) {
      assert.equal(call.url.href, 'https://forge.example/repo.git/api/v1/outcomes'); assert.equal(call.body, undefined);
      assert.equal(call.headers['Idempotency-Key'], original.request.key); assert.equal(call.headers.Authorization, `Bearer ${ROTATED}`);
    }
  });
}

test('checkbox selection changes form requirements but cannot silently switch an active connection', async () => {
  const h = harness();
  assert.equal(h.nodes['original-principal'].disabled, true); assert.equal(h.nodes['original-principal'].required, false);
  await h.connect(ORIGINAL, false); assert.equal(h.calls.length, 1); assert.equal(h.app.client.recoveryOnly, false);
  h.choose(true); assert.equal(h.nodes['original-principal'].disabled, false); assert.equal(h.nodes['original-principal'].required, true);
  assert.equal(h.app.client.recoveryOnly, false); assert.match(h.nodes['connection-mode'].textContent, /only when Connect/);
  await h.connect(); h.choose(false); assert.equal(h.app.client.recoveryOnly, true); assertRestricted(h);
});

test('disabled controls also refuse synthetic submit and click events before touching transport', async () => {
  const h = harness(); await h.connect(); await h.restore(await originalReceipt());
  const key = h.app.client.pending.key;
  for (const [id, event] of [['refresh', 'click'], ['select-pr', 'submit'], ['new-pr', 'click'], ['metadata', 'submit'], ['prepare', 'submit'],
    ['candidate-import', 'submit'], ['resolution', 'submit'], ['comment-form', 'submit'], ['review', 'submit'], ['merge', 'submit'], ['discard', 'click'], ['send', 'click']]) {
    h.nodes.confirm.checked = true; h.nodes[id].fire(event); await settled();
    assert.equal(h.calls.length, 0, id); assert.equal(h.app.client.pending.key, key, id); assertRestricted(h);
  }
});

test('wrong-principal terminal responses remain unknown and preserve the original receipt', async () => {
  const h = harness(() => response(outcome('committed', 'sha1', { principal_id: OTHER })));
  await h.connect(); const original = await originalReceipt(); await h.restore(original);
  await h.click('recover');
  assert.match(h.nodes.status.textContent, /selected original principal.*Outcome remains unknown/);
  assert.doesNotMatch(h.nodes.status.textContent, /Canonical committed|recover or retry/);
  assert.equal(h.app.client.pending.key, JSON.parse(original).request.key); assertRestricted(h);
});

test('revocation disconnects but retains downloadable original recovery bytes', async () => {
  const h = harness(() => response({}, 401)); await h.connect(); const saved = await originalReceipt(); await h.restore(saved);
  await h.click('recover'); assert.equal(h.app.client.connected, false); assert.ok(h.app.client.pending);
  assert.equal(h.nodes.recover.disabled, true); assert.equal(h.nodes.send.disabled, true);
  assert.equal(h.nodes['receipt-download'].disabled, false); assert.match(h.nodes['connection-mode'].textContent, /Disconnected/);
  await h.click('receipt-download'); assert.deepEqual(JSON.parse(h.downloads.at(-1).content), JSON.parse(saved));
});

test('a retained lost-response request reconnects under the explicit original principal', async () => {
  const h = harness(call => {
    if (call.url.pathname.endsWith('/open')) throw new Error('Response lost');
    if (call.url.pathname.endsWith('/outcomes')) return response(outcome('committed'));
  });
  await h.connect(ORIGINAL, false); await h.stage(); assert.ok(h.app.client.pending);
  h.nodes.confirm.checked = true; h.nodes.confirm.fire('change'); await h.click('send');
  const key = h.app.client.pending.key; assert.match(h.nodes.status.textContent, /Outcome remains unknown/);
  await h.connect(ROTATED, false); assert.equal(h.app.client.connected, false); assert.ok(h.app.client.pending);
  await h.connect(ROTATED, true); assertRestricted(h); assert.equal(h.app.client.pending.key, key);
  await h.click('recover'); assert.equal(h.app.client.pending, null);
  assert.equal(h.calls.filter(call => call.url.pathname.endsWith('/open')).length, 1);
  assert.equal(h.calls.filter(call => call.url.pathname.endsWith('/pulls')).length, 1);
  assert.equal(h.calls.at(-1).headers['Idempotency-Key'], key);
});

test('invalid principal selection cannot leave an old credential active or publish a new request', async () => {
  const h = harness(); await h.connect(ORIGINAL, false); await h.stage(); const key = h.app.client.pending.key;
  await h.connect(ROTATED, true, 'not-the-original-principal');
  assert.equal(h.app.client.connected, false); assert.equal(h.app.client.pending.key, key); assert.equal(h.nodes.token.value, '');
  assert.match(h.nodes.status.textContent, /Invalid principal/); assert.equal(h.calls.length, 1);
});

test('terminal refusal stays lookup-only until an explicit normal reconnect', async () => {
  const h = harness(call => call.url.pathname.endsWith('/outcomes') ? response(outcome('refused')) : null);
  await h.connect(); await h.restore(await originalReceipt()); await h.click('recover');
  assert.match(h.nodes.status.textContent, /Canonical refused.*policy_refused/); assertRestricted(h);
  h.choose(false); await h.click('refresh'); assert.equal(h.calls.length, 1);
  await h.connect(ROTATED, false); assert.equal(h.app.client.recoveryOnly, false); assert.equal(h.nodes.refresh.disabled, false);
  assert.equal(h.calls.at(-1).method, 'GET'); assert.match(h.nodes['connection-mode'].textContent, /Ordinary connection/);
});

test('disconnect fences an in-flight receipt import without losing a selected credential boundary', async () => {
  const h = harness(); await h.connect(); const bytes = utf8.encode(await originalReceipt()); let release;
  h.nodes['receipt-import-file'].files = [{ size: bytes.length, arrayBuffer: () => new Promise(resolve => { release = resolve; }) }];
  h.nodes['receipt-import'].fire('submit'); await settled(); h.app.disconnect(); release(bytes.buffer); await settled();
  assert.equal(h.app.client.pending, null); assert.equal(h.app.client.connected, false); assert.equal(h.calls.length, 0);
  assert.match(h.nodes.status.textContent, /Disconnected/); assert.equal(h.nodes['receipt-import-file'].value, '');
});

test('disconnect fences a late terminal response but keeps the original key and unload warning', async () => {
  let release; const h = harness(() => new Promise(resolve => { release = resolve; }));
  await h.connect(); await h.restore(await originalReceipt()); const key = h.app.client.pending.key;
  h.nodes.recover.fire('click'); await settled(); const leaving = h.lifecycle.fire('beforeunload'); assert.equal(leaving.returnValue, '');
  h.app.disconnect(); release(response(outcome('committed'))); await settled();
  assert.equal(h.app.client.pending.key, key); assert.equal(h.app.client.connected, false);
  assert.match(h.nodes.status.textContent, /Disconnected/); assert.doesNotMatch(h.nodes.status.textContent, /Canonical/);
});

test('ordinary connection still loads PRs, stages locally and publishes only after confirmation', async () => {
  const h = harness(call => call.url.pathname.endsWith('/open') ? response({ ...identity('sha1'), type: 'pull_request_publication', action: 'open',
    principal_id: PRINCIPAL, tx_id: 'tx/open', decision_sequence: 1, outcome: 'committed', delivery_acknowledged: null,
    number: 7, expected_version: 0, repository_commit_id: 'rcr/open', refusal_record_id: null, refusal_code: null, refusal_code_point: null }) : null);
  await h.connect(ORIGINAL, false); assert.equal(h.nodes.refresh.disabled, false);
  await h.stage(); assert.equal(h.calls.length, 1); assert.equal(h.nodes.send.disabled, true);
  await h.click('send'); assert.equal(h.calls.length, 1); assert.match(h.nodes.status.textContent, /confirm/);
  h.nodes.confirm.checked = true; h.nodes.confirm.fire('change'); assert.equal(h.nodes.send.disabled, false);
  await h.click('send'); assert.equal(h.calls.length, 2); assert.equal(h.app.client.pending, null);
  assert.match(h.nodes.status.textContent, /Canonical committed/); assert.equal(h.app.client.recoveryOnly, false);
});
