// Real PR-shell orchestration with DOM/HTTP doubles. Native canonical storage
// and live browser execution are separate verification lanes.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { mountPulls } from '../../crates/fgit-node/src/smart_http/server/browser/pulls-view.mjs';
import { CHECK_LOG_PREVIEW_BYTES } from '../../crates/fgit-node/src/smart_http/server/browser/pulls-check-evidence.mjs';
import { token, page, json, webcrypto, deferred } from './pulls-fixtures.mjs';
import { checks, checkLabel } from './pulls-checks-fixtures.mjs';
import { evidenceFixture, evidenceToken, report, step } from './pulls-checks-evidence-fixtures.mjs';

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
const descendants = node => [node, ...node.children.flatMap(descendants)];
const buttons = (node, prefix) => descendants(node).filter(child => child.tagName === 'button' && child.textContent.startsWith(prefix));
function click(node, prefix, index = 0) {
  const target = buttons(node, prefix)[index]; assert.ok(target, `missing button ${prefix}`); assert.equal(target.disabled, false, `disabled ${prefix}`); target.fire('click'); return target;
}
const digests = new Set();
const cryptoImpl = { getRandomValues: value => webcrypto.getRandomValues(value), subtle: { digest(...args) {
  const pending = webcrypto.subtle.digest(...args); digests.add(pending);
  pending.then(() => digests.delete(pending), () => digests.delete(pending)); return pending;
} } };
async function settled() { for (let index = 0; index < 20; index += 1) { await Promise.all([...digests]); await new Promise(setImmediate); } }
function harness(fixture = evidenceFixture(), { respond = () => json(fixture.reply), listing = fixture.prior.reply } = {}) {
  const nodes = Object.fromEntries(Array.from(html.matchAll(/id="([^"]+)"/g), match => [match[1], new Element()]));
  nodes['metadata-action'].value = 'open'; nodes['object-format'].value = 'sha1'; nodes['review-action'].value = 'approve';
  const lifecycle = new Element(), document = { getElementById: id => nodes[id], createElement: tag => new Element(tag), defaultView: lifecycle };
  const calls = [], downloads = [];
  const app = mountPulls(document, { href: 'https://forge.example/team/repo.git/ui/pulls/', cryptoImpl,
    downloadImpl(name, contents, type) { downloads.push({ name, bytes: Buffer.from(contents), type }); },
    fetchImpl: async (url, init) => {
      const call = { url: String(url), ...init }; calls.push(call); const path = new URL(url).pathname;
      if (path.endsWith('/pulls')) return json(page({ snapshot_token: fixture.selected.head }));
      if (path.endsWith('/pulls/1')) return json(fixture.selected.reply);
      if (path.endsWith('/checks')) return json(listing);
      if (path.endsWith('/checks/evidence')) return respond(call);
      throw new Error(`Unexpected request ${path}`);
    } });
  const open = async () => { nodes.token.value = token; nodes.connection.fire('submit'); await settled(); click(nodes['pr-list'], '#1'); await settled(); };
  const load = async () => { click(nodes.selected, 'Load checks at this snapshot'); await settled(); };
  const credential = () => descendants(nodes.selected).find(node => node.tagName === 'input' && node.type === 'password');
  const connectEvidence = async () => { credential().value = evidenceToken; click(nodes.selected, 'Connect evidence credential'); await settled(); };
  const loadEvidence = async (index = 0) => { click(nodes.selected, 'Load evidence and logs', index); await settled(); };
  return { nodes, app, calls, downloads, lifecycle, open, load, credential, connectEvidence, loadEvidence };
}

test('selected canonical check opens real retained logs and exact downloads through a separate scoped credential', async () => {
  const fixture = evidenceFixture(), h = harness(fixture); await h.open(); await h.load();
  assert.equal(h.calls.length, 3, 'metadata and checks do not implicitly retrieve evidence');
  assert.match(h.nodes.selected.textContent, /both pulls-read and artifact-read/);
  assert.equal(buttons(h.nodes.selected, 'Load evidence and logs')[0].disabled, true);
  const snapshot = h.nodes.snapshot.textContent; await h.connectEvidence();
  assert.equal(h.credential().value, ''); assert.equal(h.calls.length, 3, 'credential selection does not silently load logs');
  await h.loadEvidence();
  assert.match(h.nodes.selected.textContent, /Canonical evidence verified/); assert.match(h.nodes.selected.textContent, /running tests/);
  assert.match(h.nodes.selected.textContent, /assertion failed/); assert.match(h.nodes.selected.textContent, /published conclusion remains failure/);
  assert.equal(h.calls.at(-1).headers.Authorization, `Bearer ${evidenceToken}`);
  assert.equal(h.calls[2].headers.Authorization, `Bearer ${token}`); assert.equal(h.nodes.snapshot.textContent, snapshot);
  assert.equal(h.app.client.pending, null); assert.equal(h.app.client.candidate, null); assert.equal(h.nodes['merge-stage'].disabled, true);
  click(h.nodes.selected, 'Download exact check evidence'); await settled();
  assert.deepEqual(h.downloads[0].bytes, fixture.bytes); assert.equal(h.downloads[0].type, 'application/octet-stream');
  click(h.nodes.selected, 'Download step 1 stdout'); await settled();
  assert.deepEqual(h.downloads[1].bytes, Buffer.from(fixture.report.jobs[0].steps[0].stdout_hex, 'hex'));
  assert.ok(h.downloads.every(download => !download.name.includes(evidenceToken) && !download.bytes.includes(evidenceToken)));
  assert.equal(h.nodes.selected.textContent.includes(evidenceToken), false);
});

test('opaque canonical evidence remains downloadable without inventing stdout or upgrading action_required', async () => {
  const fixture = evidenceFixture({ report: null, raw: Buffer.from('original opaque evidence'), check: { conclusion: 'action_required' } });
  const h = harness(fixture); await h.open(); await h.load(); await h.connectEvidence(); await h.loadEvidence();
  assert.match(h.nodes.selected.textContent, /no supported retained-log view/);
  assert.match(h.nodes.selected.textContent, /published conclusion remains action_required/);
  assert.equal(buttons(h.nodes.selected, 'Download step').length, 0);
  click(h.nodes.selected, 'Download exact check evidence'); await settled(); assert.deepEqual(h.downloads[0].bytes, fixture.bytes);
});

test('preview clipping and incomplete capture stay distinct while stream download preserves retained bytes', async () => {
  const output = Buffer.from('x'.repeat(CHECK_LOG_PREVIEW_BYTES + 123));
  const fixture = evidenceFixture({ report: report({ jobs: [{ id: 'test', outcome: 'failed',
    steps: [step({ stdout_hex: output.toString('hex'), output_complete: false, workspace_retained: true })], failure: null }] }) });
  const h = harness(fixture); await h.open(); await h.load(); await h.connectEvidence(); await h.loadEvidence();
  assert.match(h.nodes.selected.textContent, /INCOMPLETE OUTPUT/); assert.match(h.nodes.selected.textContent, /Preview clipped to 65536 bytes/);
  assert.match(h.nodes.selected.textContent, /capture completeness is unchanged/);
  assert.equal(h.nodes.selected.textContent.includes('x'.repeat(CHECK_LOG_PREVIEW_BYTES + 1)), false);
  click(h.nodes.selected, 'Download step 1 stdout'); await settled(); assert.deepEqual(h.downloads[0].bytes, output);
  assert.match(h.nodes.selected.textContent, /INCOMPLETE OUTPUT/);
});

test('hostile names, terminal controls, binary bytes and repository HTML remain inert text', async () => {
  const fixture = evidenceFixture({ report: report({ jobs: [{ id: 'test', outcome: 'failed', steps: [step({
    name: '<img src=x onerror=credential()>\u202e', stdout_hex: Buffer.from('<script>credential()</script>\u001b[31m\u0000').toString('hex'),
    stderr_hex: 'ff000a' })], failure: { detail: '<iframe src=evil>\u202e', workspace_retained: false } }] }) });
  const h = harness(fixture); await h.open(); await h.load(); await h.connectEvidence(); await h.loadEvidence();
  assert.match(h.nodes.selected.textContent, /<img src=x onerror=credential\(\)>\\u202e/);
  assert.match(h.nodes.selected.textContent, /<script>credential\(\)<\/script>\\u001b\[31m\\u0000/);
  assert.match(h.nodes.selected.textContent, /\\xff\\x00/);
  assert.equal(descendants(h.nodes.selected).some(node => ['script', 'img', 'iframe'].includes(node.tagName)), false);
});

test('a changed digest clears earlier logs and disables downloads without replacing the PR snapshot', async () => {
  const fixture = evidenceFixture(); let reads = 0;
  const h = harness(fixture, { respond: () => json(++reads === 1 ? fixture.reply : { ...fixture.reply, evidence_hex: '00' + fixture.reply.evidence_hex.slice(2) }) });
  await h.open(); await h.load(); await h.connectEvidence(); await h.loadEvidence();
  const snapshot = h.nodes.snapshot.textContent; assert.match(h.nodes.selected.textContent, /running tests/);
  await h.loadEvidence(); assert.match(h.nodes.selected.textContent, /Evidence unavailable/);
  assert.doesNotMatch(h.nodes.selected.textContent, /running tests|assertion failed|Canonical evidence verified/);
  assert.equal(buttons(h.nodes.selected, 'Download exact check evidence')[0].disabled, true);
  assert.equal(h.nodes.snapshot.textContent, snapshot); assert.equal(h.app.client.connected, true); assert.equal(h.downloads.length, 0);
});

for (const status of [401, 403]) test(`HTTP ${status} clears the entire evidence session while the independent PR connection remains usable`, async () => {
  const first = evidenceFixture(), second = evidenceFixture({ check: { id: checkLabel(2) } });
  const listing = checks({ checks: [first.check, second.check] });
  const h = harness(first, { listing, respond: call => new URL(call.url).searchParams.get('check') === first.check.id
    ? json(first.reply) : new Response('', { status }) });
  await h.open(); await h.load(); await h.connectEvidence(); await h.loadEvidence(0);
  const oldDownload = buttons(h.nodes.selected, 'Download exact check evidence')[0];
  const oldStream = buttons(h.nodes.selected, 'Download step 1 stdout')[0];
  h.credential().value = evidenceToken;
  assert.match(h.nodes.selected.textContent, /running tests/); await h.loadEvidence(1);
  assert.match(h.nodes.selected.textContent, status === 401 ? /Evidence credential rejected or revoked/ : /Evidence access refused/);
  assert.equal(h.credential().value, '');
  assert.doesNotMatch(h.nodes.selected.textContent, /running tests|Canonical evidence verified/);
  assert.ok(buttons(h.nodes.selected, 'Load evidence and logs').every(button => button.disabled));
  assert.ok(buttons(h.nodes.selected, 'Download exact check evidence').every(button => button.disabled));
  assert.equal(h.app.client.connected, true); assert.match(h.nodes.selected.textContent, /#1 · open/);
  oldDownload.fire('click'); await settled(); oldStream.fire('click'); await settled();
  assert.equal(h.downloads.length, 0, 'retained callbacks cannot export cleared evidence or streams');
  await h.load(); assert.match(h.nodes.selected.textContent, /test · failure/);
});

test('disconnecting only evidence aborts an in-flight read and prevents late output from restoring the view', async () => {
  const fixture = evidenceFixture(), pending = deferred(), h = harness(fixture, { respond: () => pending.promise });
  await h.open(); await h.load(); await h.connectEvidence(); await h.loadEvidence();
  const request = h.calls.at(-1); assert.match(h.nodes.selected.textContent, /Reading and verifying/);
  click(h.nodes.selected, 'Disconnect evidence'); pending.resolve(json(fixture.reply)); await settled();
  assert.equal(request.signal.aborted, true); assert.match(h.nodes.selected.textContent, /Evidence disconnected/);
  assert.doesNotMatch(h.nodes.selected.textContent, /running tests|Canonical evidence verified/);
  assert.equal(buttons(h.nodes.selected, 'Download exact check evidence')[0].disabled, true); assert.equal(h.app.client.connected, true);
});

test('PR disconnect and pagehide abort pending evidence and clear its credential with all repository views', async () => {
  for (const action of ['disconnect', 'pagehide']) {
    const fixture = evidenceFixture(), pending = deferred(), h = harness(fixture, { respond: () => pending.promise });
    await h.open(); await h.load(); await h.connectEvidence(); await h.loadEvidence();
    const input = h.credential(), request = h.calls.at(-1); input.value = evidenceToken;
    if (action === 'disconnect') h.app.disconnect(); else h.lifecycle.fire('pagehide');
    pending.resolve(json(fixture.reply)); await settled();
    assert.equal(input.value, ''); assert.equal(request.signal.aborted, true); assert.equal(h.nodes.selected.textContent, '');
    assert.equal(h.app.client.connected, false); assert.equal(h.downloads.length, 0);
  }
});

test('late 401 and 403 from an old PR connection cannot clear replacement evidence views', async () => {
  for (const status of [401, 403]) {
    const fixture = evidenceFixture(), pending = deferred(); let reads = 0;
    const h = harness(fixture, { respond: () => ++reads === 1 ? pending.promise : json(fixture.reply) });
    await h.open(); await h.load(); await h.connectEvidence(); await h.loadEvidence();
    const oldRequest = h.calls.at(-1); h.app.disconnect();
    await h.open(); await h.load(); await h.connectEvidence(); await h.loadEvidence();
    assert.match(h.nodes.selected.textContent, /Canonical evidence verified/);
    pending.resolve(new Response('', { status })); await settled();
    assert.equal(oldRequest.signal.aborted, true); assert.equal(h.app.client.connected, true);
    assert.match(h.nodes.selected.textContent, /Canonical evidence verified/);
    assert.doesNotMatch(h.nodes.selected.textContent, /Evidence credential rejected or revoked|Evidence access refused/);
    click(h.nodes.selected, 'Download exact check evidence'); await settled();
    assert.deepEqual(h.downloads[0].bytes, fixture.bytes);
  }
});

test('reselecting a PR disposes retained evidence and old download callbacks cannot expose it', async () => {
  const h = harness(); await h.open(); await h.load(); await h.connectEvidence(); await h.loadEvidence();
  const oldDownload = buttons(h.nodes.selected, 'Download exact check evidence')[0], oldInput = h.credential();
  oldInput.value = evidenceToken; await h.app.loadPr(1); await h.load();
  assert.equal(oldInput.value, ''); assert.equal(h.credential().value, '');
  assert.match(h.nodes.selected.textContent, /Evidence is disconnected/);
  assert.equal(buttons(h.nodes.selected, 'Load evidence and logs')[0].disabled, true);
  oldDownload.fire('click'); await settled(); assert.equal(h.downloads.length, 0);
  assert.doesNotMatch(h.nodes.selected.textContent, /Canonical evidence verified|running tests/);
});

test('checks reload clears prior outputs while retaining the separately selected credential', async () => {
  const h = harness(); await h.open(); await h.load(); await h.connectEvidence(); await h.loadEvidence();
  assert.match(h.nodes.selected.textContent, /running tests/); await h.load();
  assert.doesNotMatch(h.nodes.selected.textContent, /Canonical evidence verified|running tests/);
  assert.equal(buttons(h.nodes.selected, 'Load evidence and logs')[0].disabled, false);
  await h.loadEvidence(); assert.match(h.nodes.selected.textContent, /running tests/);
});

test('evidence assets are served by the PR profile and no output is sent to an active HTML sink or persistence', () => {
  const rust = readFileSync(new URL(`${root}pulls.rs`, import.meta.url), 'utf8');
  const source = readFileSync(new URL(`${root}pulls-check-evidence.mjs`, import.meta.url), 'utf8');
  assert.ok(rust.includes('b"/ui/pulls-check-evidence.mjs"'));
  for (const match of source.matchAll(/from '\.\/([^']+)'/g)) assert.ok(rust.includes(`b"/ui/${match[1]}"`));
  for (const sink of ['innerHTML', 'outerHTML', 'insertAdjacentHTML', 'localStorage', 'sessionStorage', 'eval(']) assert.ok(!source.includes(sink));
});
