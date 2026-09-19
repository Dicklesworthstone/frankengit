// DOM and transport test doubles, not live browser or native pack verification.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { mountPulls, displayBytes, displayText, renderInspection, DISPLAY_BYTES } from '../../crates/fgit-node/src/smart_http/server/browser/pulls-view.mjs';
import { token, actor, reviewer, page, row, show, reviews, reviewRow, head, data, json, webcrypto, deferred, hex } from './pulls-fixtures.mjs';
import { fixture, terminal, recovered } from './pulls-candidate-fixtures.mjs';

const root = '../../crates/fgit-node/src/smart_http/server/browser/';
const html = readFileSync(new URL(`${root}pulls.html`, import.meta.url), 'utf8');
const f = fixture();
class Element {
  constructor(tag = 'div') { this.tagName = tag; this.children = []; this.listeners = new Map(); this.value = ''; this.text = ''; this.files = []; this.checked = false; this.disabled = false; }
  set textContent(value) { this.text = String(value); this.children = []; }
  get textContent() { return this.text + this.children.map(child => child.textContent).join(''); }
  set innerHTML(_) { throw new Error('Unsafe HTML sink'); }
  append(...children) { this.children.push(...children); }
  replaceChildren(...children) { this.text = ''; this.children = children; }
  addEventListener(name, fn) { const entries = this.listeners.get(name) ?? []; entries.push(fn); this.listeners.set(name, entries); }
  fire(name, event = {}) {
    const ev = { preventDefault() {}, ...event }; for (const fn of this.listeners.get(name) ?? []) fn(ev); return ev;
  }
}
// Await actual WebCrypto jobs rather than assuming a fixed number of event-loop
// turns is enough. Deliberately unresolved network responses remain independent.
const digests = new Set();
const cryptoImpl = { getRandomValues: value => webcrypto.getRandomValues(value), subtle: { digest(...args) {
  const pending = webcrypto.subtle.digest(...args); digests.add(pending);
  pending.then(() => digests.delete(pending), () => digests.delete(pending)); return pending;
} } };
async function settled() {
  for (let i = 0; i < 20; i += 1) { await Promise.all([...digests]); await new Promise(setImmediate); }
}
function findButton(element, prefix) {
  for (const child of element.children) {
    if (child.tagName === 'button' && child.textContent.startsWith(prefix)) return child;
    const nested = findButton(child, prefix); if (nested) return nested;
  }
  return null;
}
function click(element, prefix) { const button = findButton(element, prefix); assert.ok(button, `button ${prefix}`); button.fire('click'); }
function fileInput(input, text) { const bytes = new TextEncoder().encode(text); input.files = [{ size: bytes.length, arrayBuffer: async () => bytes.buffer }]; }
function harness(respond = () => null) {
  const nodes = Object.fromEntries(Array.from(html.matchAll(/id="([^"]+)"/g), match => [match[1], new Element()]));
  nodes['metadata-action'].value = 'open'; nodes['object-format'].value = 'sha1'; nodes['review-action'].value = 'approve';
  const lifecycle = new Element(), document = { getElementById: id => nodes[id], createElement: tag => new Element(tag), defaultView: lifecycle };
  const calls = [], downloads = [];
  let app;
  const fetcher = async (url, options) => {
    const call = { url: String(url), ...options }; calls.push(call);
    const result = await respond(call, app); if (result !== null && result !== undefined) return result;
    const path = new URL(url).pathname;
    if (path.endsWith('/pulls')) return json(page());
    if (path.endsWith('/pulls/1')) return json(show());
    if (path.endsWith('/reviews')) return json(reviews());
    if (path.endsWith('/prepare')) return new Response(f.mixed(), { headers: { 'Content-Type': f.type } });
    if (path.endsWith('/inspect')) return json(f.inspection);
    if (path.endsWith('/outcomes')) return json(recovered());
    throw new Error(`Unexpected test request ${path}`);
  };
  app = mountPulls(document, { href: 'https://forge.example/team/repo.git/ui/pulls/', fetchImpl: fetcher, cryptoImpl,
    downloadImpl: (name, text) => downloads.push({ name, text }) });
  const connect = async (secret = token) => { nodes.token.value = secret; nodes.connection.fire('submit'); await settled(); };
  const open = async () => { click(nodes['pr-list'], '#1'); await settled(); };
  const prepare = async () => {
    nodes['policy-epoch'].value = '1'; nodes.author.value = 'Test <test@example.invalid>'; nodes.committer.value = 'Test <test@example.invalid>';
    nodes.timestamp.value = '1'; nodes.message.value = 'Exact candidate\n'; nodes.prepare.fire('submit'); await settled();
  };
  const stageReview = async () => { nodes['review-version'].value = '0'; nodes.reason.value = 'I inspected the exact candidate.'; nodes.review.fire('submit'); await settled(); };
  return { nodes, app, calls, downloads, document, lifecycle, connect, open, prepare, stageReview };
}

test('all required controls mount from the actual HTML and no native form submits by default', async () => {
  const h = harness(); await h.connect();
  assert.equal(h.nodes.token.value, ''); assert.equal(h.app.client.connected, true);
  assert.match(h.nodes['pr-list'].textContent, /#1 · open/);
  assert.equal(h.calls.length, 1); assert.equal(h.calls[0].method, 'GET');
  assert.equal(h.calls[0].headers.Authorization, `Bearer ${token}`);
  assert.equal(h.calls[0].credentials, 'omit'); assert.equal(h.calls[0].redirect, 'error');
  assert.equal(h.calls[0].mode, 'same-origin'); assert.equal(h.calls[0].cache, 'no-store');
  assert.equal(h.nodes['review-stage'].disabled, true); assert.equal(h.nodes.send.disabled, true);
  assert.ok(html.includes('form id="merge"'));
});
test('PR selection retains the list snapshot and renders hostile metadata as text', async () => {
  const title = '<img src=x onerror=alert(1)>', body = '<script>credential()</script>\u202e';
  const h = harness(call => new URL(call.url).pathname.endsWith('/pulls/1') ? json(show({ pull_request: row(1, { data: data({ title, body }) }) })) : null);
  await h.connect(); await h.open();
  assert.equal(new URL(h.calls[1].url).searchParams.get('expected_head'), head);
  assert.match(h.nodes.selected.textContent, /<img src=x onerror=alert\(1\)>/);
  assert.match(h.nodes.selected.textContent, /<script>credential\(\)<\/script>\\u202e/);
  assert.equal(h.nodes.body.value, body); assert.equal(h.nodes['expected-version'].value, '1');
  assert.equal(h.calls.some(call => call.headers['Idempotency-Key']), false);
});
test('list pagination and review pagination keep the exact selected snapshot', async () => {
  let lists = 0, reviewPages = 0;
  const rows = Array.from({ length: 20 }, (_, i) => row(i + 1));
  const reviewRows = Array.from({ length: 20 }, (_, i) => reviewRow({ reviewer: (i + 1).toString(16).padStart(32, '0') }));
  const h = harness(call => {
    const url = new URL(call.url);
    if (url.pathname.endsWith('/pulls')) return json(++lists === 1 ? page({ pull_requests: rows, next_after: 20 }) : page({ after: 20, pull_requests: [] }));
    if (url.pathname.endsWith('/reviews')) return json(++reviewPages === 1 ? reviews({ reviews: reviewRows, next_after: reviewRows.at(-1).reviewer })
      : reviews({ after: reviewRows.at(-1).reviewer, reviews: [] }));
    return null;
  });
  await h.connect(); await h.open();
  h.nodes['reviews-load'].fire('click'); await settled(); click(h.nodes['review-paging'], 'Next review page'); await settled();
  const reviewCall = h.calls.at(-1); assert.equal(new URL(reviewCall.url).searchParams.get('after'), reviewRows.at(-1).reviewer);
  assert.equal(new URL(reviewCall.url).searchParams.get('expected_head'), head);
  assert.equal(h.nodes['required-reviewers'].value, '', 'no implicit reviewer selection');
  click(h.nodes['list-paging'], 'Next PR page'); await settled();
  assert.equal(new URL(h.calls.at(-1).url).searchParams.get('expected_head'), head);
  assert.equal(new URL(h.calls.at(-1).url).searchParams.get('after'), '20');
});
test('moved snapshot refuses visibly without retaining a misleading selected PR', async () => {
  const h = harness(call => new URL(call.url).pathname.endsWith('/pulls/1') ? json(show({ snapshot_token: `alg:1:${'f'.repeat(64)}` })) : null);
  await h.connect(); await h.open();
  assert.match(h.nodes.status.textContent, /Snapshot moved/); assert.equal(h.nodes.selected.textContent, '');
  assert.equal(h.nodes['prepare-candidate'].disabled, true);
});
test('prepare then inspect are reads and do not expose review controls until native inspection succeeds', async () => {
  const inspected = deferred(); const h = harness(call => new URL(call.url).pathname.endsWith('/inspect') ? inspected.promise : null);
  await h.connect(); await h.open(); await h.prepare();
  assert.equal(h.app.client.candidate, null); assert.equal(h.nodes['review-stage'].disabled, true);
  inspected.resolve(json(f.inspection)); await settled();
  assert.equal(h.app.client.candidate.fields.candidate_commit, f.fields.candidate_commit);
  assert.equal(h.nodes['review-stage'].disabled, false); assert.match(h.nodes.candidate.textContent, /No objects staged/);
  assert.equal(h.calls.some(call => call.headers['Idempotency-Key']), false);
});
test('review submission requires separate preparation and explicit confirmation', async () => {
  const h = harness((call, app) => new URL(call.url).pathname.endsWith('/approve') ? json(terminal(app.client.pending)) : null);
  await h.connect(); await h.open(); await h.prepare(); const before = h.calls.length;
  await h.stageReview(); assert.equal(h.calls.length, before); assert.equal(h.app.client.pending.action, 'approve');
  const key = h.app.client.pending.key; h.nodes.reason.value = 'edited later';
  h.nodes.send.fire('click'); await settled(); assert.equal(h.calls.length, before); assert.match(h.nodes.status.textContent, /confirm/);
  h.nodes.confirm.checked = true; h.nodes.confirm.fire('change'); assert.equal(h.nodes.send.disabled, false);
  h.nodes.send.fire('click'); await settled();
  assert.equal(h.calls.length, before + 1); assert.equal(h.calls.at(-1).headers['Idempotency-Key'], key);
  assert.ok((await h.calls.at(-1).body.text()).includes('reason=I+inspected+the+exact+candidate.'));
  assert.equal(h.app.client.pending, null); assert.equal(h.app.client.candidate, null);
  assert.match(h.nodes.status.textContent, /Canonical committed/); assert.equal(h.nodes.confirm.checked, false);
});
test('lost merge reply preserves the exact candidate and requirements across retry', async () => {
  let sends = 0;
  const h = harness((call, app) => {
    if (new URL(call.url).pathname.endsWith('/merge')) { if (++sends === 1) throw new Error('Connection lost'); return json(terminal(app.client.pending)); }
    return null;
  });
  await h.connect(); await h.open(); await h.prepare(); h.nodes['required-reviewers'].value = reviewer;
  h.nodes.merge.fire('submit'); await settled(); assert.equal(h.app.client.pending.action, 'merge');
  const before = h.calls.length;
  h.nodes.confirm.checked = true; h.nodes.send.fire('click'); await settled();
  assert.equal(h.app.client.pending.sent, true); assert.match(h.nodes.status.textContent, /Outcome remains unknown/);
  assert.equal(h.calls.length, before + 1, 'no automatic retry'); assert.equal(h.nodes.discard.disabled, true);
  h.nodes['required-reviewers'].value = '5'.repeat(32); h.nodes.confirm.checked = true; h.nodes.send.fire('click'); await settled();
  const [first, second] = h.calls.slice(-2);
  assert.equal(first.headers['Idempotency-Key'], second.headers['Idempotency-Key']);
  assert.deepEqual(await first.body.arrayBuffer(), await second.body.arrayBuffer());
  assert.match(h.nodes.status.textContent, /Canonical committed/);
});
test('explicit nonterminal outcome recovery sends no mutation body and cannot discard the original', async () => {
  const h = harness(); await h.connect(); await h.open(); await h.prepare(); await h.stageReview();
  const original = h.app.client.pending.key; h.nodes.recover.fire('click'); await settled();
  const call = h.calls.at(-1); assert.match(call.url, /\/outcomes$/); assert.equal(call.body, undefined);
  assert.equal(call.headers['Idempotency-Key'], original); assert.match(h.nodes.status.textContent, /Outcome unknown \(undecided\)/);
  assert.equal(h.app.client.pending.observedTx, 'transaction-1'); assert.equal(h.nodes.discard.disabled, true);
});
test('native HTTP 409 terminal refusal is not confused with an unknown conflict error', async () => {
  const h = harness((call, app) => new URL(call.url).pathname.endsWith('/update') ? json(terminal(app.client.pending, {
    outcome: 'refused', repository_commit_id: null, refusal_record_id: 'refusal-1', refusal_code: 'Conflict', refusal_code_point: 7 }), 409) : null);
  await h.connect(); await h.open(); const before = h.calls.length;
  h.nodes.metadata.fire('submit'); await settled(); assert.equal(h.calls.length, before);
  h.nodes.confirm.checked = true; h.nodes.send.fire('click'); await settled();
  assert.equal(h.app.client.pending, null); assert.match(h.nodes.status.textContent, /Canonical refused/);
});
test('recovery receipt import binds original token and exact request without sending it', async () => {
  const h = harness(); await h.connect(); await h.open(); h.nodes.metadata.fire('submit'); await settled();
  h.nodes['receipt-download'].fire('click'); await settled(); const receipt = h.downloads[0].text;
  assert.equal(receipt.includes(token), false); assert.equal(h.nodes.discard.disabled, true);
  const next = harness(); await next.connect(); const before = next.calls.length;
  fileInput(next.nodes['receipt-import-file'], receipt); next.nodes['receipt-import'].fire('submit'); await settled();
  assert.equal(next.calls.length, before); assert.equal(next.app.client.pending.key, h.app.client.pending.key);
  assert.equal(next.nodes.confirm.checked, false); assert.equal(next.nodes.send.disabled, true);
  const other = harness(); await other.connect('d'.repeat(64)); fileInput(other.nodes['receipt-import-file'], receipt);
  other.nodes['receipt-import'].fire('submit'); await settled(); assert.equal(other.app.client.pending, null);
  assert.match(other.nodes.status.textContent, /original credential/);
});
test('shared candidate import is reinspected before review, and never grants authority from the receipt alone', async () => {
  const h = harness(); await h.connect(); await h.open(); await h.prepare(); h.nodes['candidate-download'].fire('click'); await settled();
  const receipt = h.downloads[0].text; assert.equal(receipt.includes(token), false);
  const next = harness(); await next.connect(); const before = next.calls.length;
  fileInput(next.nodes['candidate-import-file'], receipt); next.nodes['candidate-import'].fire('submit'); await settled();
  assert.equal(next.calls.length, before + 1); assert.match(next.calls.at(-1).url, /\/inspect$/);
  assert.equal(next.calls.at(-1).headers['Idempotency-Key'], undefined);
  assert.equal(next.app.client.candidate.fields.candidate_commit, f.fields.candidate_commit);
  assert.equal(next.app.client.pending, null); assert.equal(next.nodes['review-stage'].disabled, false);
});
test('changing preparation inputs rejects late native results instead of reviving a stale candidate', async () => {
  const pending = deferred(); const h = harness(call => new URL(call.url).pathname.endsWith('/prepare') ? pending.promise : null);
  await h.connect(); await h.open(); await h.prepare();
  h.nodes['policy-epoch'].value = '2'; h.nodes.prepare.fire('input');
  pending.resolve(new Response(f.mixed(), { headers: { 'Content-Type': f.type } })); await settled();
  assert.equal(h.app.client.candidate, null); assert.equal(h.nodes.candidate.textContent, '');
  assert.equal(h.calls.some(call => call.url.endsWith('/inspect')), false);
});
test('disconnect clears private views and a late PR response cannot restore them', async () => {
  const pending = deferred(); const h = harness(call => new URL(call.url).pathname.endsWith('/pulls/1') ? pending.promise : null);
  await h.connect(); await h.open(); h.app.disconnect(); pending.resolve(json(show())); await settled();
  assert.equal(h.app.client.connected, false); assert.equal(h.nodes.selected.textContent, ''); assert.equal(h.nodes.body.value, '');
  assert.match(h.nodes.status.textContent, /Disconnected/); assert.equal(h.calls.at(-1).signal.aborted, true);
});
test('current credential rejection clears private views; stale rejection cannot clear a new connection', async () => {
  const pending = deferred(); let shows = 0;
  const h = harness(call => new URL(call.url).pathname.endsWith('/pulls/1') && ++shows === 1 ? pending.promise : null);
  await h.connect(); await h.open(); h.app.disconnect(); await h.connect('d'.repeat(64));
  pending.resolve(new Response('', { status: 401 })); await settled();
  assert.equal(h.app.client.connected, true); assert.match(h.nodes['pr-list'].textContent, /#1/);
  const current = harness(call => new URL(call.url).pathname.endsWith('/reviews') ? new Response('', { status: 401 }) : null);
  await current.connect(); await current.open(); current.nodes['reviews-load'].fire('click'); await settled();
  assert.equal(current.app.client.connected, false); assert.equal(current.nodes.body.value, ''); assert.equal(current.nodes.selected.textContent, '');
});
test('recovery-only credentials can import a receipt despite forbidden PR listing', async () => {
  const h = harness(); await h.connect(); await h.open(); h.nodes.metadata.fire('submit'); await settled();
  h.nodes['receipt-download'].fire('click'); await settled();
  const next = harness(call => new URL(call.url).pathname.endsWith('/pulls') ? new Response('', { status: 403 }) : null);
  await next.connect(); assert.equal(next.app.client.connected, true);
  fileInput(next.nodes['receipt-import-file'], h.downloads[0].text); next.nodes['receipt-import'].fire('submit'); await settled();
  assert.ok(next.app.client.pending); next.nodes.recover.fire('click'); await settled();
  assert.match(next.nodes.status.textContent, /Outcome unknown/);
});
test('lifecycle warns about a saved request and clears credentials without claiming rollback', async () => {
  const h = harness(); await h.connect(); await h.open(); h.nodes.metadata.fire('submit'); await settled();
  let warned = false; h.lifecycle.fire('beforeunload', { preventDefault() { warned = true; } }); assert.equal(warned, true);
  h.nodes.reason.value = 'private'; h.lifecycle.fire('pagehide');
  assert.equal(h.nodes.reason.value, ''); assert.equal(h.nodes.body.value, ''); assert.equal(h.app.client.connected, false);
  assert.ok(h.app.client.pending); assert.equal(h.nodes['receipt-download'].disabled, false);
  assert.match(h.nodes.status.textContent, /does not prove non-commit/);
});
test('byte paths and control characters are represented, not converted into DOM authority', () => {
  assert.equal(displayBytes('61ff'), 'a\\xff'); assert.equal(displayBytes('efbbbf61'), '\ufeffa');
  assert.equal(displayText('<script>\u202e'), '<script>\\u202e'); assert.equal(displayBytes('00'), '\\u0000');
});
test('inspection distinguishes binary and object-only changes and preserves every path label', () => {
  const h = harness(), report = structuredClone(f.inspection);
  report.comparison.entries = [
    { path_hex: '61ff', kind: 'modified', before: null, after: null, content: { type: 'binary', before_bytes: 3, after_bytes: 4 } },
    { path_hex: hex('<img>'), kind: 'type_changed', before: null, after: null, content: { type: 'object_only' } },
  ];
  renderInspection(h.document, h.nodes.candidate, report);
  assert.match(h.nodes.candidate.textContent, /a\\xff/); assert.match(h.nodes.candidate.textContent, /Binary change: 3 → 4 bytes/);
  assert.match(h.nodes.candidate.textContent, /not an empty text diff/); assert.match(h.nodes.candidate.textContent, /<img>/);
});
test('large text display is explicitly clipped while the full validated report remains downloadable', async () => {
  const h = harness(), report = structuredClone(f.inspection);
  const old = '61'.repeat(DISPLAY_BYTES + 1);
  report.comparison.entries = [{ path_hex: '61', kind: 'modified', before: null, after: null,
    content: { type: 'text', algorithm: 'Myers', additions: 1, deletions: 1, hunks: [{ old: { byte_start: 0, byte_end: DISPLAY_BYTES + 1 },
      new: { byte_start: 0, byte_end: 1 }, before_hex: old, after_hex: '62' }] } }];
  assert.equal(renderInspection(h.document, h.nodes.candidate, report).clipped, true);
  assert.match(h.nodes.candidate.textContent, /DISPLAY CLIPPED/); assert.equal(report.comparison.entries[0].content.hunks[0].before_hex.length, old.length);
});
test('asset module imports and HTML resources resolve within the declared PR static allowlist', () => {
  const rust = readFileSync(new URL(`${root}pulls.rs`, import.meta.url), 'utf8');
  for (const file of ['pulls.mjs', 'pulls-core.mjs', 'pulls-candidate.mjs', 'pulls-actions.mjs', 'pulls-view.mjs', 'pulls-resolution.mjs', 'pulls-resolution-view.mjs', 'pulls.css']) {
    assert.ok(rust.includes(`b"/ui/${file}"`));
    if (file.endsWith('.mjs')) {
      const source = readFileSync(new URL(`${root}${file}`, import.meta.url), 'utf8');
      for (const match of source.matchAll(/from '\.\/([^']+)'/g)) assert.ok(rust.includes(`b"/ui/${match[1]}"`));
      for (const sink of ['innerHTML', 'outerHTML', 'insertAdjacentHTML', 'localStorage', 'sessionStorage', 'eval(']) assert.ok(!source.includes(sink), `${file}: ${sink}`);
    }
  }
  assert.ok(rust.includes('profile.allow_pulls')); assert.ok(!rust.includes('profile.allow_source'));
  assert.ok(html.includes('src="../pulls-view.mjs"')); assert.ok(!html.includes('<script>'));
});

test('selecting a byte-only PR cannot leave another PR metadata proposal under it', async () => {
  let requests = 0;
  const h = harness(call => {
    if (new URL(call.url).pathname.endsWith('/pulls/1') && ++requests > 1) return json(show({ pull_request: row(1, {
      data: data({ source_ref: null, source_ref_hex: hex('refs/heads/topic') + 'ff' }) }) }));
    return null;
  });
  await h.connect(); await h.open(); assert.equal(h.nodes.title.value, 'Title 🦀'); await h.open();
  assert.equal(h.nodes.title.value, ''); assert.equal(h.nodes['pr-number'].value, '');
  assert.match(h.nodes.selected.textContent, /Byte-only refs/); assert.equal(h.nodes['prepare-candidate'].disabled, true);
});
test('oversized receipt files are rejected before their bytes are read', async () => {
  const h = harness(); await h.connect(); let read = false;
  h.nodes['receipt-import-file'].files = [{ size: 25 * 1024 * 1024, async arrayBuffer() { read = true; throw new Error('must not read'); } }];
  const before = h.calls.length; h.nodes['receipt-import'].fire('submit'); await settled();
  assert.equal(read, false); assert.equal(h.calls.length, before); assert.match(h.nodes.status.textContent, /24 MiB/);
});
test('disconnect during receipt file reading cannot trigger inspection under a replacement credential', async () => {
  const h = harness(); await h.connect(); await h.open(); await h.prepare(); h.nodes['candidate-download'].fire('click'); await settled();
  const text = h.downloads[0].text, bytes = new TextEncoder().encode(text), read = deferred();
  h.nodes['candidate-import-file'].files = [{ size: bytes.length, arrayBuffer: () => read.promise }];
  h.nodes['candidate-import'].fire('submit'); await settled(); h.app.disconnect(); await h.connect('d'.repeat(64));
  const before = h.calls.length; read.resolve(bytes.buffer); await settled();
  assert.equal(h.calls.length, before); assert.equal(h.app.client.candidate, null); assert.match(h.nodes['pr-list'].textContent, /#1/);
});
test('a prepared candidate remains tied to its own PR when imported while another PR is selected', async () => {
  const h = harness(); await h.connect(); await h.open(); await h.prepare();
  const receipt = h.app.client.exportCandidate();
  // Candidate import is allowed without selecting its PR metadata; its own
  // inspected number is displayed and used, never an editable number field.
  h.nodes['pr-number'].value = '999'; fileInput(h.nodes['candidate-import-file'], receipt);
  h.nodes['candidate-import'].fire('submit'); await settled();
  h.nodes['required-reviewers'].value = reviewer; h.nodes.merge.fire('submit'); await settled();
  assert.equal(h.app.client.pending.number, 1); assert.match(h.nodes.pending.textContent, /for PR #1/);
});
