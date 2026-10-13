// View unit tests with an explicit native-client peer, not native-server or
// real-browser evidence. The production entrypoint loads the shared client.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { mountProtection, protectionClientHref, referenceLabel } from '../../crates/fgit-node/src/smart_http/server/browser/protection-view.mjs';
const browser = new URL('../../crates/fgit-node/src/smart_http/server/browser/', import.meta.url);
const html = readFileSync(new URL('protection.html', browser), 'utf8');
const script = readFileSync(new URL('protection-view.mjs', browser), 'utf8');
const actor = '11'.repeat(16), reviewer = '22'.repeat(16), token = 'a'.repeat(64);
const hex = text => Buffer.from(text).toString('hex');
const snapshot = () => ({ scope: { tenant: '33'.repeat(16), repository: '44'.repeat(16), incarnation: '55'.repeat(16), format: 'sha256' },
  head: `alg:1:${'aa'.repeat(32)}`, version: '9007199254740993', epoch: '18446744073709551614',
  policy: { administrators: [actor], branches: [{ reference_hex: hex('refs/heads/main'), required_reviewers: [reviewer] }] } });
class Element {
  constructor(tag) { this.tagName = tag; this.children = []; this.value = ''; this.disabled = false; this.checked = false; this.listeners = new Map(); this._text = ''; }
  set textContent(value) { this._text = String(value); this.children = []; }
  get textContent() { return this._text + this.children.map(child => child.textContent).join(''); }
  append(...children) { this.children.push(...children); }
  replaceChildren(...children) { this.children = children; this._text = ''; }
  addEventListener(type, callback) { this.listeners.set(type, callback); }
  async fire(type) { return this.listeners.get(type)?.({ preventDefault() {} }); }
}
function harness(overrides = {}) {
  const elements = new Map([...html.matchAll(/\bid="([^"]+)"/g)].map(match => [match[1], new Element('control')]));
  const events = new Element('window'), calls = [];
  const client = { connected: false, selected: null,
    async connect(value, principal) { calls.push(['connect', value, principal]); this.connected = true; },
    async inspect() { calls.push(['inspect']); this.selected = snapshot(); return this.selected; },
    disconnect() { calls.push(['disconnect']); this.connected = false; this.selected = null; }, ...overrides };
  const doc = { getElementById: id => elements.get(id), createElement: tag => new Element(tag), defaultView: events };
  const mounted = mountProtection(doc, { client });
  const get = id => elements.get(`protection-${id}`);
  const connect = async () => { get('token').value = token; get('actor').value = actor; return get('connect').fire('submit'); };
  return { get, doc, events, client, calls, mounted, connect };
}
function deferred() { let resolve, reject; const promise = new Promise((a, b) => { resolve = a; reject = b; }); return { resolve, reject, promise }; }

test('standalone page binds the existing client to exactly the same repository API root', () => {
  for (const origin of ['https://forge.example', 'http://127.0.0.1:8123', 'http://localhost:8123', 'http://[::1]:8123']) {
    assert.equal(protectionClientHref(`${origin}/tenant/repo.git/ui/protection/`), `${origin}/tenant/repo.git/ui/pulls/`);
  }
});
for (const href of ['https://forge.example/ui/protection/', 'https://forge.example/repo.git/ui/pulls/',
  'https://forge.example/repo.git/ui/protection', 'https://forge.example/repo.git/ui/protection/?token=secret',
  'https://forge.example/repo.git/ui/protection/#secret', 'https://user:secret@forge.example/repo.git/ui/protection/',
  'http://forge.example/repo.git/ui/protection/', 'file:///repo.git/ui/protection/',
  'https://forge.example/repo%2fgit/ui/protection/', 'https://forge.example//repo.git/ui/protection/']) {
  test(`standalone scope refuses ${href}`, () => assert.throws(() => protectionClientHref(href)));
}
test('inspection preserves complete full-width counters and all native identities', async () => {
  const h = harness(); assert.equal(h.get('reload').disabled, true); await h.connect();
  assert.deepEqual(h.calls, [['connect', token, actor], ['inspect']]);
  assert.equal(h.get('token').value, ''); assert.equal(h.get('reload').disabled, false);
  for (const exact of [snapshot().head, snapshot().version, snapshot().epoch, snapshot().scope.repository]) assert.ok(h.get('snapshot').textContent.includes(exact));
  assert.ok(h.get('policy').textContent.includes(reviewer));
  assert.match(h.get('status').textContent, /No transaction/);
});
test('uninstalled policy is inspectable but cannot bootstrap through this page', async () => {
  const h = harness({ async inspect() { return { ...snapshot(), version: '0', epoch: '1', policy: null }; } });
  await h.connect(); assert.match(h.get('policy').textContent, /local-only/);
});
test('disabled protection retains policy administrators rather than pretending uninstalled', async () => {
  const h = harness({ async inspect() { const s = snapshot(); s.policy.branches = []; return s; } });
  await h.connect(); assert.match(h.get('policy').textContent, /administrators retained/);
  assert.ok(h.get('policy').textContent.includes(actor));
});
test('byte-only and hostile-looking references remain inert with exact bytes available', async () => {
  const encoded = hex('refs/heads/<script>\u202e') + 'ff';
  const h = harness({ async inspect() { const s = snapshot(); s.policy.branches[0].reference_hex = encoded; return s; } });
  await h.connect(); assert.ok(h.get('policy').textContent.includes(encoded));
  assert.match(h.get('policy').textContent, /Non-UTF-8/);
  assert.equal(referenceLabel(hex('refs/heads/<script>\u202e')), 'refs/heads/<script>\\u{202e}');
});
test('inspection failures clear old policy and never invent a new snapshot', async () => {
  const h = harness(); await h.connect();
  h.client.inspect = async () => { throw new Error('Native protection scope refused.'); };
  await h.mounted.inspect(); assert.equal(h.get('snapshot').textContent, '');
  assert.equal(h.get('policy').textContent, ''); assert.match(h.get('status').textContent, /refused/);
});
test('credential failure does not perform a policy read and clears token input', async () => {
  const h = harness({ async connect() { throw new Error('Credential rejected.'); } });
  await h.connect(); assert.equal(h.get('token').value, ''); assert.deepEqual(h.calls, []);
  assert.match(h.get('status').textContent, /rejected/);
});
test('disconnect fences late success and erases displayed repository information', async () => {
  const pending = deferred(), h = harness({ async inspect() { return pending.promise; } });
  const work = h.connect(); await Promise.resolve(); h.mounted.disconnect(); pending.resolve(snapshot()); await work;
  assert.equal(h.get('snapshot').textContent, ''); assert.equal(h.get('policy').textContent, '');
  assert.equal(h.get('actor').value, ''); assert.match(h.get('status').textContent, /^Disconnected/);
});
test('pagehide fences late failure without displaying its stale response', async () => {
  const pending = deferred(), h = harness({ async inspect() { return pending.promise; } });
  const work = h.connect(); await Promise.resolve(); await h.events.fire('pagehide'); pending.reject(new Error('stale secret')); await work;
  assert.equal(h.get('snapshot').textContent, ''); assert.doesNotMatch(h.get('status').textContent, /stale secret/);
});
test('repeated inspection while busy does not start concurrent native reads', async () => {
  const pending = deferred(); let reads = 0;
  const h = harness({ async inspect() { reads++; return pending.promise; } });
  const work = h.connect(); await Promise.resolve(); await h.mounted.inspect(); assert.equal(reads, 1);
  pending.resolve(snapshot()); await work; assert.equal(h.get('reload').disabled, false);
});
test('markup and native route include every independent asset without broadening PR/source permissions', () => {
  const route = readFileSync(new URL('protection.rs', browser), 'utf8');
  const router = readFileSync(new URL('../browser.rs', browser), 'utf8');
  assert.match(route, /profile\.config\.http_protection_admin_enabled\(\)/);
  assert.doesNotMatch(route, /profile\.allow_(?:source|pull_requests|issues)/);
  for (const asset of ['protection-view.mjs', 'pulls-actions.mjs', 'pulls-core.mjs', 'pulls-candidate.mjs', 'browser.css']) assert.ok(route.includes(`/ui/protection/${asset}`));
  assert.ok(router.includes('protection::serve(profile, request, trailing, writer)?'));
  assert.match(script, /await import\('\.\/pulls-actions\.mjs'\)/);
  assert.doesNotMatch(script, /mountPullRequests|innerHTML|localStorage|sessionStorage|document\.write/);
  assert.doesNotMatch(html, /<script>/);
  assert.match(html, /type="password"/);
});
