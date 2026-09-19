// DOM/fetch contract tests, not a substitute for Chromium or live-node testing.
import test from 'node:test';
import assert from 'node:assert/strict';
import { mount, hex } from '../../crates/fgit-node/src/smart_http/server/browser/browser.mjs';

class Element {
  constructor(tag = 'div') { this.tagName = tag; this.children = []; this.listeners = new Map(); this.value = ''; this.text = ''; }
  set textContent(text) { this.text = String(text); this.children = []; }
  get textContent() { return this.text + this.children.map(child => child.textContent).join(''); }
  set innerHTML(_) { throw new Error('Unsafe markup sink'); }
  append(...children) { this.children.push(...children); }
  replaceChildren(...children) { this.text = ''; this.children = children; }
  addEventListener(name, fn) { this.listeners.set(name, fn); }
  fire(name) { this.listeners.get(name)?.({ preventDefault() {} }); }
}
const identity = { schema_version: 1, object_format: 'sha1', read_only: true, transaction_created: false,
  published: false, snapshot_token: `alg:1:${'b'.repeat(64)}`, source_commit: 'a'.repeat(40) };
const tree = (entries = [], extra = {}) => ({ ...identity, type: 'source_tree', path_hex: null,
  next_after_hex: null, entries, ...extra });
const json = value => new Response(JSON.stringify(value), { headers: { 'Content-Type': 'application/json' } });
function deferred() { let resolve; const promise = new Promise(r => { resolve = r; }); return { promise, resolve }; }
async function settled() { for (let i = 0; i < 12; i += 1) await new Promise(setImmediate); }
function buttons(root) { return root.children.flatMap(child => [...(child.tagName === 'button' ? [child] : []), ...buttons(child)]); }
function click(root, text) { const found = buttons(root).find(button => button.textContent === text); assert.ok(found, `button ${text}`); found.fire('click'); }
function harness(respond) {
  const names = ['connection', 'token', 'reference', 'format', 'disconnect', 'status', 'snapshot', 'breadcrumbs', 'content', 'paging', 'search', 'needle', 'search-case'];
  const elements = Object.fromEntries(names.map(name => [name, new Element()]));
  elements.reference.value = 'refs/heads/main'; elements.format.value = 'sha1'; elements['search-case'].value = 'exact';
  const lifecycle = new Element();
  const document = { getElementById: name => elements[name], createElement: tag => new Element(tag), defaultView: lifecycle };
  const calls = [];
  const fetcher = (url, options) => { calls.push({ url: String(url), ...options }); return respond(calls.length, options); };
  const client = mount(document, new URL('https://forge.example/team/repo.git/ui/'), fetcher);
  const connect = (token = 'c'.repeat(64)) => { elements.token.value = token; elements.connection.fire('submit'); };
  return { elements, calls, client, lifecycle, connect };
}

test('mount sends only scoped same-origin read requests and never interprets names as HTML', async () => {
  const name = '<img src=x onerror=alert(1)>';
  const h = harness(() => json(tree([{ name_hex: hex(new TextEncoder().encode(name)), kind: 'file' }])));
  h.connect(); await settled();
  assert.equal(h.calls[0].url, 'https://forge.example/team/repo.git/api/v1/source/tree');
  assert.equal(h.calls[0].headers.Authorization, `Bearer ${'c'.repeat(64)}`);
  assert.equal(h.calls[0].credentials, 'omit'); assert.equal(h.calls[0].redirect, 'error');
  assert.equal(h.calls[0].mode, 'same-origin'); assert.equal(h.calls[0].cache, 'no-store');
  assert.equal(h.elements.token.value, '');
  assert.equal(h.calls[0].body.has('path_hex'), false);
  assert.ok(h.elements.content.textContent.includes(name));
  assert.ok(h.elements.snapshot.textContent.includes(identity.source_commit));
});

test('directory pagination carries exact pinned head and commit, never an idempotency key', async () => {
  const h = harness(n => json(n === 1 ? tree([{ name_hex: '61ff', kind: 'file' }], { next_after_hex: '61ff' }) : tree()));
  h.connect(); await settled(); click(h.elements.paging, 'Next directory page'); await settled();
  assert.equal(h.calls[1].body.get('after_hex'), '61ff');
  assert.equal(h.calls[1].body.get('expected_head'), identity.snapshot_token);
  assert.equal(h.calls[1].body.get('expected_commit'), identity.source_commit);
  assert.equal(h.calls[1].headers['Idempotency-Key'], undefined);
});

test('invalid-UTF8 directory names navigate by original bytes, not display labels', async () => {
  const h = harness(n => json(n === 1 ? tree([{ name_hex: '61ff', kind: 'directory' }]) : tree([], { path_hex: '61ff' })));
  h.connect(); await settled(); click(h.elements.content, 'a\\xff'); await settled();
  assert.equal(h.calls[1].body.get('path_hex'), '61ff');
});

test('file ranges keep their snapshot; symbolic links are previewed without following targets', async () => {
  const h = harness(n => {
    if (n === 1) return json(tree([{ name_hex: '6c696e6b', kind: 'symlink' }]));
    const offset = n === 2 ? 0 : 65536;
    const bytes = new Uint8Array(n === 2 ? 65536 : 1).fill(65);
    return json({ ...identity, type: 'source_blob', path_hex: '6c696e6b', kind: 'symlink',
      total_bytes: 65537, offset, returned_bytes: bytes.length, next_offset: n === 2 ? 65536 : null,
      content_hex: hex(bytes), symlink_followed: false });
  });
  h.connect(); await settled(); click(h.elements.content, 'link'); await settled();
  assert.match(h.elements.content.textContent, /did not follow the link/);
  click(h.elements.paging, 'Next byte range'); await settled();
  assert.equal(h.calls[2].body.get('offset'), '65536');
  assert.equal(h.calls[2].body.get('expected_commit'), identity.source_commit);
});

test('search uses the pinned source snapshot and labels truncated results as partial', async () => {
  const h = harness(n => json(n === 1 ? tree() : { ...identity, type: 'source_search', profile: 'literal-bytes-v1',
    completion: 'match_limit', complete: false, returned_matches: 1,
    matches: [{ path_hex: '61ff', byte_offset: 0, line: 1, byte_column: 1, match_length: 1,
      excerpt_offset: 0, excerpt_hex: '3c7363726970743e' }] }));
  h.connect(); await settled(); h.elements.needle.value = '<'; h.elements.search.fire('submit'); await settled();
  assert.match(h.calls[1].url, /\/source\/search$/);
  assert.equal(h.calls[1].body.get('needle_hex'), '3c');
  assert.equal(h.calls[1].body.get('expected_head'), identity.snapshot_token);
  assert.match(h.elements.content.textContent, /results are partial/);
  assert.match(h.elements.content.textContent, /<script>/);
});

test('disconnect aborts an active read and stale completion cannot resurrect repository data', async () => {
  const pending = deferred(); const h = harness(() => pending.promise);
  h.connect(); h.client.disconnect(); pending.resolve(json(tree([{ name_hex: '736563726574', kind: 'file' }])));
  await settled(); assert.equal(h.calls[0].signal.aborted, true);
  assert.equal(h.elements.content.textContent, ''); assert.equal(h.elements.snapshot.textContent, '');
  assert.match(h.elements.status.textContent, /Disconnected/);
});

test('late 401 from an old request cannot revoke a newer token or erase its result', async () => {
  const pending = deferred(); const h = harness(n => n === 1 ? pending.promise : json(tree()));
  h.connect(); h.connect('d'.repeat(64)); await settled();
  pending.resolve(new Response('', { status: 401 })); await settled();
  assert.ok(h.elements.snapshot.textContent.includes(identity.source_commit));
  assert.match(h.elements.status.textContent, /Read complete/);
  h.elements.connection.fire('submit'); await settled();
  assert.equal(h.calls[2].headers.Authorization, `Bearer ${'d'.repeat(64)}`);
});

test('current 401 clears private data and requires reauthentication', async () => {
  const h = harness(() => new Response('', { status: 401 })); h.connect(); await settled();
  assert.match(h.elements.status.textContent, /Token rejected or revoked/);
  h.elements.connection.fire('submit'); await settled(); assert.equal(h.calls.length, 1);
  assert.equal(h.elements.content.textContent, '');
});

test('moved snapshots fail visibly instead of silently mixing directory pages', async () => {
  const h = harness(n => json(n === 1 ? tree([{ name_hex: '61', kind: 'directory' }])
    : tree([], { path_hex: '61', source_commit: 'd'.repeat(40) })));
  h.connect(); await settled(); click(h.elements.content, 'a'); await settled();
  assert.match(h.elements.status.textContent, /Snapshot changed/);
  assert.equal(h.elements.content.textContent, '');
});

test('pagehide clears query text, pending reads and visible private data', async () => {
  const h = harness(() => json(tree())); h.connect(); await settled();
  h.elements.needle.value = 'private query'; h.lifecycle.fire('pagehide');
  assert.equal(h.elements.needle.value, ''); assert.equal(h.elements.snapshot.textContent, '');
  h.elements.search.fire('submit'); assert.match(h.elements.status.textContent, /Open a reference/);
});
