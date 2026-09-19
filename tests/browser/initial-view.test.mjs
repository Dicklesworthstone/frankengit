// DOM/File/HTTP contract tests. This does not run a browser or native Rust node.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { InitialSourceClient } from '../../crates/fgit-node/src/smart_http/server/browser/initial.mjs';
import { mountInitialEditor, readInitialFile } from '../../crates/fgit-node/src/smart_http/server/browser/initial-view.mjs';
import { FILE_LIMIT } from '../../crates/fgit-node/src/smart_http/server/browser/source-edit-patch.mjs';
import { utf8, hex } from '../../crates/fgit-node/src/smart_http/server/browser/pulls-core.mjs';
import { fixture, file, metadata, crypto, token, href } from './initial-fixtures.mjs';
const assets = new URL('../../crates/fgit-node/src/smart_http/server/browser/', import.meta.url);
const html = readFileSync(new URL('initial.html', assets), 'utf8');
class Element {
  children = []; listeners = new Map(); value = ''; disabled = false; checked = false; files = []; ownText = '';
  constructor(tag) { this.tagName = tag.toUpperCase(); }
  set textContent(value) { this.ownText = String(value); this.children = []; }
  get textContent() { return this.ownText + this.children.map(child => child.textContent ?? String(child)).join(''); }
  addEventListener(kind, fn) { this.listeners.set(kind, [...(this.listeners.get(kind) ?? []), fn]); }
  replaceChildren(...children) { this.children = children; this.ownText = ''; }
  append(...children) { this.children.push(...children); }
  async fire(kind = 'click') {
    if (kind === 'click' && this.disabled) return;
    for (const fn of this.listeners.get(kind) ?? []) await fn({ preventDefault() {}, target: this });
  }
}
function documentFixture() {
  const nodes = new Map([...html.matchAll(/<(\w+)[^>]*\bid="([^"]+)"[^>]*>/g)].map(m => [m[2], new Element(m[1])]));
  const defaults = { branch: 'refs/heads/main', format: 'sha1', 'path-kind': 'utf8', 'file-mode': '100644', 'input-kind': 'text', 'line-endings': 'lf' };
  for (const [id, value] of Object.entries(defaults)) nodes.get(id).value = value;
  return { nodes, getElementById: id => nodes.get(id), createElement: tag => new Element(tag) };
}
function upload(bytes) { return { size: bytes.length, async arrayBuffer() { return bytes.slice().buffer; } }; }
async function setup(algorithm = 'sha1', files = [file()]) {
  const f = await fixture(algorithm, files), doc = documentFixture();
  const client = new InitialSourceClient({ href, fetchImpl: f.fetchImpl, cryptoImpl: crypto });
  const events = { callbacks: new Map(), addEventListener(kind, fn) { this.callbacks.set(kind, fn); } };
  let saved;
  const app = mountInitialEditor(doc, { client, events, saveReceipt: value => { saved = value; } });
  const el = id => doc.getElementById(id);
  el('token').value = token; await el('connect').fire(); el('format').value = algorithm;
  for (const [id, value] of Object.entries(metadata)) el(id).value = String(value);
  return { f, app, client, el, events, saved: () => saved };
}
async function queue(s, entry = s.f.files[0]) {
  s.el('path-kind').value = 'hex'; s.el('path').value = entry.path_hex; await s.el('path').fire('input');
  s.el('file-mode').value = entry.mode.toString(8); s.el('input-kind').value = 'upload';
  s.el('file').files = [upload(entry.bytes)]; await s.el('file').fire('change'); await s.el('queue').fire();
}
async function prepare(s) {
  for (const entry of s.f.files) await queue(s, entry);
  s.el('expected-absent').checked = true; await s.el('expected-absent').fire('input');
  await s.el('prepare').fire();
}
async function stage(s) { await prepare(s); await s.el('stage').fire(); assert(s.client.pending); }
for (const algorithm of ['sha1', 'sha256']) {
  test(`${algorithm}: browser bootstraps initial history without an existing read and requires separate send confirmation`, async () => {
    const s = await setup(algorithm); assert.equal(s.el('token').value, ''); assert.equal(s.f.calls.length, 0);
    assert(s.el('prepare').disabled); await prepare(s);
    assert.equal(s.client.candidate.fields.candidate_commit, s.f.plan.commit);
    assert(s.el('candidate').textContent.includes(s.f.plan.tree)); assert(s.el('candidate').textContent.includes('"parents": []'));
    assert.deepEqual(s.f.calls.map(c => c.endpoint), ['source/initial/prepare']);
    await s.el('stage').fire(); assert(s.client.pending); assert.equal(s.f.calls.length, 1);
    assert(s.el('branch').disabled); assert(s.el('queue').disabled);
    await s.el('send').fire(); assert.equal(s.f.calls.length, 1); assert.match(s.el('status').textContent, /Confirm/);
    s.el('confirm-send').checked = true; await s.el('send').fire();
    assert.equal(s.f.calls.at(-1).endpoint, 'source/initial/apply'); assert.equal(s.client.pending, null);
    assert.equal(s.app.queued.length, 0); assert.equal(s.el('candidate').textContent, '');
    assert.match(s.el('status').textContent, /Canonical committed.*Default branch unchanged/);
  });
}
test('a queued draft never treats an unchecked absence precondition as permission to create', async () => {
  const s = await setup(); await queue(s); assert(s.el('prepare').disabled);
  await s.el('prepare').fire(); assert.equal(s.f.calls.length, 0);
  s.el('expected-absent').checked = true; await s.el('expected-absent').fire('input'); assert.equal(s.el('prepare').disabled, false);
});
for (const field of ['branch', 'format', 'message', 'timestamp', 'expected-head', 'expected-absent']) {
  test(`changing ${field} invalidates the verified root candidate rather than refreshing it`, async () => {
    const s = await setup(); await prepare(s); assert(s.client.candidate);
    await s.el(field).fire('input'); assert.equal(s.client.candidate, null); assert(s.el('stage').disabled);
    assert.equal(s.el('candidate').textContent, ''); assert.equal(s.app.queued.length, 1);
    assert.deepEqual(s.f.calls.map(c => c.endpoint), ['source/initial/prepare']);
  });
}
test('candidate fields displayed in the browser cannot mutate the frozen publication command', async () => {
  const s = await setup(); await stage(s); const key = s.client.pending.key;
  s.el('branch').value = 'refs/heads/other'; await s.el('branch').fire('input');
  s.el('message').value = 'different'; await s.el('message').fire('input');
  s.el('confirm-send').checked = true; await s.el('send').fire();
  assert.equal(s.f.calls.at(-1).headers['idempotency-key'], key);
  assert.match(new TextDecoder().decode(s.f.calls.at(-1).body), /refs%2Fheads%2Fmain/);
  assert.equal(s.client.pending, null);
});
test('queued exact upload bytes preserve non-UTF-8, CRLF, empty files and executable mode', async () => {
  const entries = [{ path_hex: 'ff2ffe', bytes: new Uint8Array([255,13,10,254]), mode: 0o100755 }, file('empty', '')];
  const s = await setup('sha256', entries); await prepare(s);
  assert.deepEqual(s.app.queued, entries); assert.equal(s.client.candidate.files.length, 2);
  assert.equal(s.client.candidate.preparation.root_tree, s.f.plan.tree);
  assert.match(s.el('files').textContent, /Non-UTF-8 bytes/);
  const copy = s.app.queued; copy[0].bytes[0] = 0; assert.equal(s.app.queued[0].bytes[0], 255);
});
for (const [ending, expected] of [['lf', 'a\nb\nc\n'], ['crlf', 'a\r\nb\r\nc\r\n']]) {
  test(`new text files use explicit ${ending} line endings without altering uploaded data`, async () => {
    const s = await setup(); s.el('path').value = 'hello'; s.el('file-text').value = 'a\r\nb\rc\n'; s.el('line-endings').value = ending;
    await s.el('queue').fire(); assert.deepEqual(s.app.queued[0].bytes, utf8.encode(expected)); assert.equal(s.f.calls.length, 0);
  });
}
test('oversized File and inconsistent content lengths refuse before any candidate or network call', async () => {
  const s = await setup(); s.el('path').value = 'huge'; s.el('input-kind').value = 'upload'; let reads = 0;
  s.el('file').files = [{ size: FILE_LIMIT + 1, async arrayBuffer() { reads++; throw new Error('must not read'); } }];
  await s.el('queue').fire(); assert.equal(reads, 0); assert.equal(s.app.queued.length, 0); assert.match(s.el('status').textContent, /byte limit/);
  await assert.rejects(readInitialFile({ size: 2, async arrayBuffer() { return new ArrayBuffer(3); } }, 3), /length changed/);
  await assert.rejects(readInitialFile({ size: 2, async arrayBuffer() { reads++; } }, 3, () => false), /selection changed/);
  assert.equal(reads, 0); assert.equal(s.f.calls.length, 0);
});
for (const cause of ['disconnect', 'selection']) test(`late file read after ${cause} cannot populate an initial draft`, async () => {
  const s = await setup(); s.el('path').value = 'file'; s.el('input-kind').value = 'upload';
  let release; s.el('file').files = [{ size: 3, arrayBuffer() { return new Promise(r => { release = r; }); } }];
  const work = s.el('queue').fire(); assert(release);
  if (cause === 'disconnect') await s.el('disconnect').fire();
  else { s.el('file').files = [upload(utf8.encode('new'))]; await s.el('file').fire('change'); }
  release(utf8.encode('old').buffer); await work;
  assert.equal(s.app.queued.length, 0); assert.equal(s.client.candidate, null); assert.equal(s.f.calls.length, 0);
});
test('explicit replacement is local, while overlapping paths refuse without damaging the queued files', async () => {
  const s = await setup(); await queue(s, file('a', 'old')); await queue(s, file('a', 'new', 0o100755));
  assert.equal(s.app.queued.length, 1); assert.deepEqual(s.app.queued[0].bytes, utf8.encode('new'));
  await queue(s, file('a/b', 'bad')); assert.equal(s.app.queued.length, 1); assert.match(s.el('status').textContent, /overlap/i);
  const remove = s.el('files').children[0].children[1]; await remove.fire(); assert.equal(s.app.queued.length, 0); assert(s.el('prepare').disabled);
});
test('NUL and unsupported modes refuse locally, rather than silently producing an empty or regular file', async () => {
  const s = await setup(); await queue(s, file('x', '\0')); assert.equal(s.app.queued.length, 0);
  s.el('file-mode').value = '120000'; await s.el('queue').fire(); assert.equal(s.app.queued.length, 0);
  assert.equal(s.f.calls.length, 0);
});
test('cancel during native preparation cannot render a returned candidate or publish anything', async () => {
  const s = await setup(); await queue(s); s.el('expected-absent').checked = true; await s.el('expected-absent').fire('input');
  let release, reached; const entered = new Promise(r => { reached = r; });
  s.f.config.prepare = () => new Promise(r => { release = r; reached(); });
  const work = s.el('prepare').fire(); await entered; assert.equal(s.el('cancel').disabled, false); await s.el('cancel').fire(); release(); await work;
  assert.equal(s.client.candidate, null); assert.equal(s.el('candidate').textContent, ''); assert.equal(s.app.queued.length, 1);
  assert.equal(s.f.calls.length, 1); assert(s.el('stage').disabled);
});
test('lost publication replies retain exact recovery responsibility and require confirmation again', async () => {
  const s = await setup(); await stage(s); const original = s.client.pending; s.f.config.lose = true;
  s.el('confirm-send').checked = true; await s.el('send').fire(); assert.equal(s.client.pending.key, original.key);
  assert.match(s.el('status').textContent, /Outcome unknown/); assert(s.el('discard').disabled); assert.equal(s.el('confirm-send').checked, false);
  const calls = s.f.calls.length; s.f.config.lose = false; await s.el('send').fire(); assert.equal(s.f.calls.length, calls);
  s.el('confirm-send').checked = true; await s.el('send').fire(); assert.equal(s.client.pending, null);
});
test('a connection loss after the native request began cannot reinterpret the publication as discarded', async () => {
  const s = await setup(); await stage(s); let release, reached; const entered = new Promise(r => { reached = r; });
  s.f.config.publish = () => new Promise(r => { release = r; reached(); }); s.el('confirm-send').checked = true;
  const work = s.el('send').fire(); await entered; await s.el('disconnect').fire(); release(); await work;
  assert(s.client.pending?.sent); assert.equal(s.client.connected, false); assert.equal(s.app.queued.length, 0);
  assert.equal(s.el('candidate').textContent, ''); assert.match(s.el('status').textContent, /Outcome unknown/);
});
for (const outcome of ['key_not_observed', 'committed', 'refused']) test(`browser recovery ${outcome} sends no mutation body and uses the exact original key`, async () => {
  const s = await setup(); await stage(s); const key = s.client.pending.key; s.f.config.outcome = outcome;
  await s.el('recover').fire(); const call = s.f.calls.at(-1);
  assert.equal(call.endpoint, 'outcomes'); assert.equal(call.body, undefined); assert.equal(call.headers['idempotency-key'], key);
  if (outcome === 'key_not_observed') { assert(s.client.pending); assert.match(s.el('status').textContent, /Absence does not prove non-commit/); }
  else { assert.equal(s.client.pending, null); assert.equal(s.app.queued.length, 0); assert.match(s.el('status').textContent, /Recovered canonical/); }
});
test('saving and restoring a token-free request does not execute it or refresh branch absence', async () => {
  const s = await setup(); await stage(s); const p = s.client.pending; await s.el('save').fire(); const saved = s.saved();
  assert(saved); assert(!saved.includes(token)); assert(s.el('discard').disabled);
  const other = await setup(); other.el('receipt').files = [upload(utf8.encode(saved))]; await other.el('restore').fire();
  assert.equal(other.f.calls.length, 0); assert.equal(other.client.pending.key, p.key); assert.equal(other.el('confirm-send').checked, false);
  assert.match(other.el('status').textContent, /restored, not executed/);
  await other.el('send').fire(); assert.equal(other.f.calls.length, 0);
});
test('page exit clears the token and file bytes but warns for both drafts and unresolved requests', async () => {
  const s = await setup(); await queue(s);
  const e = { prevented: false, preventDefault() { this.prevented = true; }, returnValue: null };
  s.events.callbacks.get('beforeunload')(e); assert(e.prevented);
  await prepare(s); await s.el('stage').fire(); const key = s.client.pending.key;
  s.events.callbacks.get('pagehide')(); assert.equal(s.client.connected, false); assert.equal(s.app.queued.length, 0);
  assert.equal(s.el('file-text').value, ''); assert.equal(s.el('candidate').textContent, ''); assert.equal(s.el('token').value, '');
  assert.equal(s.client.pending.key, key); e.prevented = false; s.events.callbacks.get('beforeunload')(e); assert(e.prevented);
});
test('untrusted path and content previews remain inert DOM text', async () => {
  const s = await setup(); await queue(s, file('<svg onload=bad()>', '<script>bad()</script>'));
  assert(s.el('files').textContent.includes('<script>bad()</script>'));
  assert.equal(s.el('files').children[0].children[0].children[1].tagName, 'PRE');
  const script = readFileSync(new URL('initial-view.mjs', assets), 'utf8');
  for (const forbidden of ['innerHTML', 'localStorage', 'sessionStorage', 'document.write']) assert(!script.includes(forbidden));
  assert(!html.includes('<script>')); assert(!html.includes('onclick='));
});
test('the source-only static handler exposes the complete transitive module graph, not PR/data API routes', () => {
  const rust = readFileSync(new URL('initial.rs', assets), 'utf8');
  const routes = new Set([...rust.matchAll(/b"\/ui\/initial\/([^"]*)"/g)].map(m => m[1]));
  const visited = new Set(), todo = ['initial-view.mjs'];
  while (todo.length) {
    const name = todo.pop(); if (visited.has(name)) continue; visited.add(name); assert(routes.has(name), name);
    const code = readFileSync(new URL(name, assets), 'utf8');
    for (const match of code.matchAll(/from\s+['"]\.\/([^'"]+)['"]/g)) todo.push(match[1]);
  }
  assert.equal(visited.size, 8); assert(rust.includes('profile.allow_source')); assert(!rust.includes('profile.allow_pulls'));
  assert(rust.includes('request.method != "GET"')); assert(rust.includes('request.target.contains(\'?\')'));
  assert(rust.includes('request.expect_continue')); assert(rust.includes('Content-Length'));
  assert(routes.has('')); assert(readFileSync(new URL('../browser.rs', assets), 'utf8').includes('initial::serve(profile, request, trailing, writer)?'));
});
