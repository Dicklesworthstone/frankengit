// Hand-written DOM/File doubles, not live browser or native-node evidence.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { TagClient } from '../../crates/fgit-node/src/smart_http/server/browser/tags.mjs';
import { mountTags, displayBytes } from '../../crates/fgit-node/src/smart_http/server/browser/tags-view.mjs';
import { fixture, crypto, token, href, hex, source, existing, deferred, objectId } from './tags-fixtures.mjs';
const base = new URL('../../crates/fgit-node/src/smart_http/server/browser/', import.meta.url);
const html = readFileSync(new URL('tags.html', base), 'utf8');
class Element {
  constructor(tag = 'div') { this.tag = tag; this.value = ''; this.checked = false; this.disabled = false; this.files = []; this.children = []; this.listeners = new Map(); this.ownText = ''; }
  set textContent(value) { this.ownText = String(value); this.children = []; }
  get textContent() { return this.ownText + this.children.map(x => x.textContent).join(''); }
  append(...nodes) { this.children.push(...nodes); }
  replaceChildren(...nodes) { this.ownText = ''; this.children = nodes; }
  addEventListener(name, callback) { if (!this.listeners.has(name)) this.listeners.set(name, []); this.listeners.get(name).push(callback); }
  async fire(name, event = { preventDefault() {} }) { await Promise.all((this.listeners.get(name) ?? []).map(fn => fn(event))); return event; }
  click() { this.clicked = true; }
  remove() { this.removed = true; }
}
function ui(f = fixture(), saveImpl = () => {}, cryptoImpl = crypto) {
  const elements = new Map([...html.matchAll(/id="([^"]+)"/g)].map(m => [m[1], new Element()]));
  const document = { body: new Element('body'), getElementById: id => { assert(elements.has(id), `missing DOM id ${id}`); return elements.get(id); }, createElement: tag => new Element(tag) };
  const window = new Element('window'); window.location = { href }; const urls = [], revoked = [], timers = [];
  window.URL = { createObjectURL: b => { urls.push(b); return `blob:test-${urls.length}`; }, revokeObjectURL: u => revoked.push(u) };
  window.setTimeout = fn => { timers.push(fn); };
  const client = new TagClient({ href, fetchImpl: f.fetchImpl, cryptoImpl });
  const mounted = mountTags(document, window, client, saveImpl), get = id => elements.get(id);
  for (const [id, value] of Object.entries({ token, format: f.algorithm, operation: 'annotated', destination: 'refs/tags/new', 'name-encoding': 'text', kind: 'commit', tagger: 'Author <a@b>', timestamp: '0', message: '<script>not executed</script>\n', 'message-encoding': 'text' })) get(id).value = value;
  async function load() { await get('connection').fire('submit'); await get('load').fire('click'); get('source').value = source; get('tag').value = existing; }
  async function prepare() { await load(); await get('prepare').fire('click'); assert(client.pending, get('status').textContent); }
  return { f, client, get, window, document, mounted, load, prepare, urls, revoked, timers };
}
test('connecting alone performs no ref lookup and clears the password field', async () => {
  const u = ui(); await u.get('connection').fire('submit'); assert.equal(u.f.calls.length, 0); assert.equal(u.get('token').value, ''); assert(u.client.connected);
});
for (const algorithm of ['sha1', 'sha256']) test(`${algorithm}: annotated UI requires separate confirmation and sends the saved version after editor changes`, async () => {
  const u = ui(fixture(algorithm)); await u.prepare(); const key = u.client.pending.key;
  assert.equal(u.f.calls.length, 1); assert(u.get('send').disabled);
  await u.get('send').fire('click'); assert.equal(u.f.calls.length, 1); assert.match(u.get('status').textContent, /Confirm/);
  u.get('confirm').checked = true; await u.get('confirm').fire('change'); assert(!u.get('send').disabled);
  u.get('tagger').value = 'Changed <c@b>'; await u.get('tagger').fire('input'); assert(!u.get('confirm').checked); assert.equal(u.client.pending.key, key);
  u.get('confirm').checked = true; await u.get('send').fire('click'); assert.equal(u.client.pending, null);
  assert.equal(new URLSearchParams(u.f.calls.at(-1).body).get('tagger'), 'Author <a@b>');
});
test('deletion targets the direct tag, not the peeled commit', async () => {
  const u = ui(); await u.load(); await u.get('inspect').fire('click');
  u.get('operation').value = 'delete'; await u.get('prepare').fire('click');
  assert.equal(u.client.pending.expected_object, u.f.tag); assert.notEqual(u.f.tag, u.f.commit); assert.equal(u.client.pending.new_object, null);
});
test('non-UTF8 tag names and message bytes can be created without loss', async () => {
  const u = ui(); await u.load(); u.get('destination').value = hex('refs/tags/v') + 'ff'; u.get('name-encoding').value = 'hex'; u.get('message').value = 'ff0d0a78'; u.get('message-encoding').value = 'hex';
  await u.get('prepare').fire('click'); assert(u.client.pending); assert.equal(u.client.pending.fields.message_hex, 'ff0d0a78'); assert.equal(u.client.pending.fields.ref_hex, hex('refs/tags/v') + 'ff');
});
test('CRLF is an explicit message choice and no newline is appended', async () => {
  const u = ui(); await u.load(); u.get('message').value = 'first\nlast'; u.get('message-encoding').value = 'crlf'; await u.get('prepare').fire('click');
  assert.equal(u.client.pending.fields.message_hex, hex('first\r\nlast'));
});
test('hostile tag bodies are text, signatures are not trusted, and original verified bytes can be saved', async () => {
  const f = fixture(), saved = [], row = f.inspection.annotations[0];
  const body = Buffer.from(`object ${f.commit}\ntype commit\ntag v1\n\n<script>bad</script>\n\u202e deceptive\n`), id = objectId(body, 'sha1');
  Object.assign(row, { object_id: id, body_bytes: body.length, body_hex: hex(body), signature: 'opaque_unverifiable' });
  f.refs[1].object_id = id; f.inspection.object_id = id;
  const u = ui(f, (...args) => saved.push(args)); await u.load(); await u.get('inspect').fire('click');
  assert.match(u.get('inspection').textContent, /NOT authenticated/); assert.match(u.get('inspection').textContent, /<script>bad<\/script>/); assert.match(u.get('inspection').textContent, /\\u202e/);
  const button = u.get('inspection').children[1].children[2]; await button.fire('click'); assert.deepEqual(Buffer.from(saved[0][1]), body);
  await u.get('disconnect').fire('click'); await button.fire('click'); assert.equal(saved.length, 1);
});
test('a lost reply leaves exact request recovery enabled and cannot be discarded', async () => {
  const u = ui(); await u.prepare(); const key = u.client.pending.key; u.f.config.lose = true; u.get('confirm').checked = true; await u.get('send').fire('click');
  assert.match(u.get('status').textContent, /Outcome unknown/); assert.equal(u.client.pending.key, key); assert(u.get('discard').disabled); assert(!u.get('recover').disabled);
  await u.get('recover').fire('click'); assert.match(u.get('status').textContent, /unknown/); assert.equal(u.f.calls.at(-1).body, undefined);
});
test('retry file saves without token and restores without any reference lookup or send', async () => {
  const saved = [], u = ui(fixture(), (...args) => saved.push(args)); await u.prepare(); await u.get('save').fire('click');
  assert(!saved[0][1].includes(token)); assert(u.client.pending.exported); assert(u.get('discard').disabled);
  const next = ui(u.f); next.get('token').value = token; await next.get('connection').fire('submit'); const count = u.f.calls.length;
  next.get('receipt').files = [{ size: Buffer.byteLength(saved[0][1]), text: async () => saved[0][1] }]; await next.get('restore').fire('click');
  assert(next.client.pending); assert.equal(u.f.calls.length, count); assert(!next.get('confirm').checked);
});
test('oversized recovery files refuse before file contents are read', async () => {
  const u = ui(); await u.get('connection').fire('submit'); let reads = 0;
  u.get('receipt').files = [{ size: 262145, text: async () => { reads++; return '{}'; } }]; await u.get('restore').fire('click'); assert.equal(reads, 0); assert.match(u.get('status').textContent, /256 KiB/);
});
for (const action of ['disconnect', 'replace']) test(`${action} during receipt I/O cannot restore stale request bytes`, async () => {
  const u = ui(); await u.prepare(); const receipt = u.client.exportReceipt(), next = ui(u.f); await next.get('connection').fire('submit');
  const d = deferred(); next.get('receipt').files = [{ size: receipt.length, text: () => d.promise }]; const work = next.get('restore').fire('click');
  if (action === 'disconnect') await next.get('disconnect').fire('click');
  else { next.get('receipt').files = []; await next.get('receipt').fire('change'); }
  d.resolve(receipt); await work; assert.equal(next.client.pending, null);
});
test('cancelled network work cannot resurrect the tag inspector', async () => {
  const u = ui(); await u.load(); const d = deferred(); u.f.config.inspect = () => d.promise;
  const work = u.get('inspect').fire('click'); await u.get('cancel').fire('click'); d.resolve(); await work;
  assert.equal(u.client.inspection, null); assert.equal(u.get('inspection').textContent, ''); assert.match(u.get('status').textContent, /cancelled/);
});
test('editor changes during preview hashing invalidate the unfinished preview', async () => {
  const d = deferred(); let block = false;
  const delayed = { getRandomValues: a => crypto.getRandomValues(a), subtle: { digest: async (...args) => { if (block) await d.promise; return crypto.subtle.digest(...args); } } };
  const u = ui(fixture(), () => {}, delayed); await u.load(); block = true; const work = u.get('prepare').fire('click');
  u.get('message').value = 'changed'; await u.get('message').fire('input'); d.resolve(); await work; assert.equal(u.client.pending, null);
});
test('failed downloads retain exported request responsibility', async () => {
  const u = ui(fixture(), () => { throw new Error('save failed'); }); await u.prepare(); await u.get('save').fire('click');
  assert.match(u.get('status').textContent, /save failed/); assert(u.client.pending.exported); assert(u.get('discard').disabled);
});
test('page exit clears credentials but warns and retains unresolved requests', async () => {
  const u = ui(); await u.prepare(); let prevented = false; await u.window.fire('beforeunload', { preventDefault() { prevented = true; } }); assert(prevented);
  const key = u.client.pending.key; await u.window.fire('pagehide'); assert(!u.client.connected); assert.equal(u.client.pending.key, key); assert.equal(u.get('message').value, '');
});
test('download object URLs are released after use and immediately on disconnect', async () => {
  const u = ui(fixture(), null); await u.prepare(); await u.get('save').fire('click'); assert.equal(u.urls.length, 1);
  u.timers[0](); assert.equal(u.revoked.length, 1); await u.get('save').fire('click'); assert.equal(u.urls.length, 2);
  await u.get('disconnect').fire('click'); assert.equal(u.revoked.length, 2);
});
test('display preserves byte-only names and visibly escapes directional controls', () => {
  assert.equal(displayBytes('ff'), 'hex:ff'); assert.match(displayBytes(hex('\u202ehello')), /\\u202ehello/);
  assert.match(displayBytes(hex('long'), 2), /Preview: 2 of 4/);
});
test('every transitive browser import is served by the source-gated static module', () => {
  const rust = readFileSync(new URL('tags.rs', base), 'utf8'), seen = new Set();
  function visit(name) {
    if (seen.has(name)) return; seen.add(name); assert(rust.includes(`b"/ui/tags/${name}"`), `missing route: ${name}`);
    const source = readFileSync(new URL(name, base), 'utf8');
    for (const m of source.matchAll(/from '\.\/([^']+)'/g)) visit(m[1]);
  }
  visit('tags-view.mjs'); assert.equal(seen.size, 6); assert(rust.includes('profile.allow_source'));
  assert(!html.includes('<script>')); assert(!readFileSync(new URL('tags-view.mjs', base), 'utf8').includes('innerHTML'));
});
test('prepared metadata visibly escapes bidi and exposes an annotation preview', async () => {
  const u = ui(); await u.load(); u.get('tagger').value = 'Name\u202e <a@b>'; await u.get('prepare').fire('click');
  assert(u.client.pending); assert(!u.get('pending').textContent.includes('\u202e')); assert.match(u.get('pending').textContent, /\\u202e/);
  assert.match(u.get('pending').textContent, /annotation_preview/); assert.match(u.get('pending').textContent, /object /);
});
test('a detached download control cannot save a replaced tag inspection', async () => {
  const saved = [], u = ui(fixture(), (...args) => saved.push(args)); await u.load(); await u.get('inspect').fire('click');
  const button = u.get('inspection').children[1].children[2]; await u.get('load').fire('click'); await button.fire('click'); assert.equal(saved.length, 0);
});
