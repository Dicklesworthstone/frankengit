// Actual PR shell/client orchestration with DOM and HTTP doubles, not live
// browser or canonical-storage evidence.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { mountPulls } from '../../crates/fgit-node/src/smart_http/server/browser/pulls-view.mjs';
import { token, page, row, data, json, webcrypto, deferred } from './pulls-fixtures.mjs';
import { checksHead, checkLabel, checkRow, observation, checks, unavailable } from './pulls-checks-fixtures.mjs';

const root = '../../crates/fgit-node/src/smart_http/server/browser/';
const html = readFileSync(new URL(`${root}pulls.html`, import.meta.url), 'utf8');
class Element {
  constructor(tag = 'div') { this.tagName = tag; this.children = []; this.listeners = new Map(); this.value = ''; this.text = ''; this.files = []; this.checked = false; this.disabled = false; }
  set textContent(value) { this.text = String(value); this.children = []; }
  get textContent() { return this.text + this.children.map(child => child.textContent).join(''); }
  set innerHTML(_) { throw new Error('Unsafe HTML sink'); }
  append(...children) { this.children.push(...children); }
  replaceChildren(...children) { this.text = ''; this.children = children; }
  addEventListener(name, fn) { const entries = this.listeners.get(name) ?? []; entries.push(fn); this.listeners.set(name, entries); }
  fire(name) { for (const fn of this.listeners.get(name) ?? []) fn({ preventDefault() {} }); }
}
const digests = new Set();
const cryptoImpl = { getRandomValues: value => webcrypto.getRandomValues(value), subtle: { digest(...args) {
  const pending = webcrypto.subtle.digest(...args); digests.add(pending);
  pending.then(() => digests.delete(pending), () => digests.delete(pending)); return pending;
} } };
async function settled() { for (let i = 0; i < 20; i += 1) { await Promise.all([...digests]); await new Promise(setImmediate); } }
function button(node, prefix) {
  for (const child of node.children) {
    if (child.tagName === 'button' && child.textContent.startsWith(prefix)) return child;
    const result = button(child, prefix); if (result) return result;
  }
  return null;
}
function click(node, prefix) { const target = button(node, prefix); assert.ok(target, `missing button ${prefix}`); target.fire('click'); }
function descendants(node) { return [node, ...node.children.flatMap(descendants)]; }
function harness(respond = () => json(checks()), shown = observation()) {
  const nodes = Object.fromEntries(Array.from(html.matchAll(/id="([^"]+)"/g), match => [match[1], new Element()]));
  nodes['metadata-action'].value = 'open'; nodes['object-format'].value = 'sha1'; nodes['review-action'].value = 'approve';
  const lifecycle = new Element(), document = { getElementById: id => nodes[id], createElement: tag => new Element(tag), defaultView: lifecycle };
  const calls = [];
  const app = mountPulls(document, { href: 'https://forge.example/team/repo.git/ui/pulls/', cryptoImpl, downloadImpl() {},
    fetchImpl: async (url, init) => {
      const call = { url: String(url), ...init }; calls.push(call);
      const path = new URL(url).pathname;
      if (path.endsWith('/pulls')) return json(page({ snapshot_token: checksHead }));
      if (path.endsWith('/pulls/1')) return json(shown.reply);
      if (path.endsWith('/checks')) return respond(call);
      throw new Error(`Unexpected request ${path}`);
    } });
  const open = async () => { nodes.token.value = token; nodes.connection.fire('submit'); await settled(); click(nodes['pr-list'], '#1'); await settled(); };
  const load = async () => { click(nodes.selected, 'Load checks at this snapshot'); await settled(); };
  return { nodes, app, calls, document, open, load };
}

test('selected PR exposes explicit checks read without changing snapshot or granting authority', async () => {
  const h = harness(); await h.open();
  assert.equal(h.calls.length, 2, 'selecting a PR does not implicitly fetch workflow observations');
  assert.match(h.nodes.selected.textContent, /Checks have not been loaded/);
  const snapshot = h.nodes.snapshot.textContent; await h.load();
  assert.equal(h.calls.length, 3); assert.equal(h.nodes.snapshot.textContent, snapshot);
  const request = h.calls.at(-1), url = new URL(request.url);
  assert.equal(url.searchParams.get('expected_head'), checksHead); assert.equal(request.method, 'GET');
  assert.equal(request.body, undefined); assert.equal(request.headers['Idempotency-Key'], undefined);
  assert.match(h.nodes.selected.textContent, /test · action_required/);
  assert.match(h.nodes.selected.textContent, /Independent verification is still required/);
  assert.match(h.nodes.selected.textContent, new RegExp(checkRow().evidence_sha256));
  assert.equal(h.app.client.pending, null); assert.equal(h.app.client.candidate, null);
  assert.equal(h.nodes['merge-stage'].disabled, true); assert.equal(h.nodes.send.disabled, true);
});

test('check pagination retains exact head and replaces the page without touching PR metadata', async () => {
  const rows = Array.from({ length: 20 }, (_, i) => checkRow({ id: checkLabel(i + 1), job: `job-${i + 1}` }));
  let pages = 0;
  const h = harness(() => json(++pages === 1 ? checks({ checks: rows, next_after: rows.at(-1).id, complete: false })
    : checks({ after: rows.at(-1).id, checks: [checkRow({ id: checkLabel(21), job: 'last-job', conclusion: 'failure' })] })));
  await h.open(); const proposal = h.nodes.title.value; await h.load();
  assert.match(h.nodes.selected.textContent, /More observations remain/);
  click(h.nodes.selected, 'Next checks page'); await settled();
  const url = new URL(h.calls.at(-1).url);
  assert.equal(url.searchParams.get('after'), rows.at(-1).id); assert.equal(url.searchParams.get('expected_head'), checksHead);
  assert.match(h.nodes.selected.textContent, /last-job · failure/); assert.doesNotMatch(h.nodes.selected.textContent, /job-1 ·/);
  assert.equal(button(h.nodes.selected, 'Next checks page'), null);
  assert.equal(h.nodes.title.value, proposal); assert.equal(h.nodes['required-reviewers'].value, '');
});

test('a stale source withholds observations and never claims no observation was published', async () => {
  const h = harness(() => json(checks({ source_current: false, checks: [] }))); await h.open(); await h.load();
  assert.match(h.nodes.selected.textContent, /STALE SOURCE: observations are withheld/);
  assert.match(h.nodes.selected.textContent, /Refresh the PR metadata explicitly/);
  assert.doesNotMatch(h.nodes.selected.textContent, /No published workflow observations exist/);
  assert.doesNotMatch(h.nodes.selected.textContent, /All observations after/);
  assert.equal(button(h.nodes.selected, 'Next checks page'), null);
});

test('current empty checks and undisclosed checks have distinct deliberate states', async () => {
  const empty = harness(() => json(checks({ checks: [] }))); await empty.open(); await empty.load();
  assert.match(empty.nodes.selected.textContent, /No published workflow observations exist for this exact/);
  assert.match(empty.nodes.selected.textContent, /does not mean checks passed/);
  const hidden = harness(() => json(unavailable(), 404)); await hidden.open(); await hidden.load();
  assert.match(hidden.nodes.selected.textContent, /Checks unavailable: this PR or its recorded source/);
  assert.doesNotMatch(hidden.nodes.selected.textContent, /No published workflow observations exist/);
  assert.match(hidden.nodes.selected.textContent, /#1 · open/);
});

test('snapshot refusal and malformed subject clear prior check rows while retaining selected PR', async () => {
  for (const response of [() => new Response('', { status: 409 }),
    () => json(checks({ source_tip: 'f'.repeat(40), checks: [checkRow({ job: 'forged-job' })] }))]) {
    let reads = 0;
    const h = harness(() => ++reads === 1 ? json(checks()) : response());
    await h.open(); await h.load(); assert.match(h.nodes.selected.textContent, /test · action_required/);
    const snapshot = h.nodes.snapshot.textContent; await h.load();
    assert.equal(h.nodes.snapshot.textContent, snapshot); assert.match(h.nodes.selected.textContent, /#1 · open/);
    assert.match(h.nodes.selected.textContent, /Checks unavailable/);
    assert.doesNotMatch(h.nodes.selected.textContent, /test · action_required|forged-job/);
    assert.equal(button(h.nodes.selected, 'Next checks page'), null);
  }
});

test('hostile job strings are rendered as inert text with directional controls escaped', async () => {
  const job = '<img src=x onerror=credential()>\u202e';
  const h = harness(() => json(checks({ checks: [checkRow({ job })] }))); await h.open(); await h.load();
  assert.match(h.nodes.selected.textContent, /<img src=x onerror=credential\(\)>\\u202e/);
  assert.equal(descendants(h.nodes.selected).some(node => ['img', 'script', 'iframe'].includes(node.tagName)), false);
  assert.equal(h.nodes.selected.textContent.includes(token), false);
});

test('byte-only refs remain eligible for checks without editable ref conversion', async () => {
  const bytes = data().source_ref_hex + 'ff';
  const selected = observation({ pull_request: row(1, { data: data({ source_ref: null, source_ref_hex: bytes }) }) });
  const h = harness(() => json(checks({ source_ref_hex: bytes })), selected); await h.open(); await h.load();
  assert.match(h.nodes.selected.textContent, /test · action_required/);
  assert.ok(h.nodes.selected.textContent.includes(bytes)); assert.equal(h.nodes['prepare-candidate'].disabled, true);
});

test('disconnect prevents late checks from restoring private views or overwriting the new state', async () => {
  const pending = deferred(), h = harness(() => pending.promise); await h.open(); await h.load();
  assert.match(h.nodes.selected.textContent, /Loading observations/); const request = h.calls.at(-1);
  h.app.disconnect(); pending.resolve(json(checks())); await settled();
  assert.equal(request.signal.aborted, true); assert.equal(h.nodes.selected.textContent, '');
  assert.equal(h.nodes.snapshot.textContent, ''); assert.equal(h.app.client.connected, false);
  assert.match(h.nodes.status.textContent, /Disconnected/);
});

test('credential rejection clears private views instead of presenting a check result', async () => {
  const h = harness(() => new Response('', { status: 401 })); await h.open(); await h.load();
  assert.equal(h.app.client.connected, false); assert.equal(h.nodes.selected.textContent, '');
  assert.equal(h.nodes.title.value, ''); assert.match(h.nodes.status.textContent, /Credential rejected/);
});

test('the checks module is served within the existing PR asset profile and has no unsafe sinks', () => {
  const rust = readFileSync(new URL(`${root}pulls.rs`, import.meta.url), 'utf8');
  const source = readFileSync(new URL(`${root}pulls-checks.mjs`, import.meta.url), 'utf8');
  assert.ok(rust.includes('b"/ui/pulls-checks.mjs"'));
  for (const match of source.matchAll(/from '\.\/([^']+)'/g)) assert.ok(rust.includes(`b"/ui/${match[1]}"`));
  for (const sink of ['innerHTML', 'outerHTML', 'insertAdjacentHTML', 'localStorage', 'sessionStorage', 'eval(']) assert.ok(!source.includes(sink));
});
