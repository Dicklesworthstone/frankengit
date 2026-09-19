import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { ReplayClient } from '../../crates/fgit-node/src/smart_http/server/browser/replay.mjs';
import { mountReplay, collectResolutions, readChosenFile, displayText } from '../../crates/fgit-node/src/smart_http/server/browser/replay-view.mjs';
import { FILE_LIMIT } from '../../crates/fgit-node/src/smart_http/server/browser/replay-protocol.mjs';
import { RECEIPT_LIMIT } from '../../crates/fgit-node/src/smart_http/server/browser/pulls-actions.mjs';
import { fixture, token, crypto, href, deferred, upload } from './replay-fixtures.mjs';
const base = new URL('../../crates/fgit-node/src/smart_http/server/browser/', import.meta.url);
const html = readFileSync(new URL('replay.html', base), 'utf8');
class Element {
  children = []; listeners = new Map(); value = ''; disabled = false; checked = false; files = []; ownText = '';
  constructor(tag) { this.tagName = tag.toUpperCase(); }
  set textContent(value) { this.ownText = String(value); this.children = []; }
  get textContent() { return this.ownText + this.children.map(child => child.textContent ?? String(child)).join(''); }
  addEventListener(kind, fn) { this.listeners.set(kind, [...(this.listeners.get(kind) ?? []), fn]); }
  replaceChildren(...children) { this.children = children; this.ownText = ''; }
  append(...children) { this.children.push(...children); }
  click() { return this.fire(); }
  async fire(kind = 'click') {
    if (kind === 'click' && this.disabled) return;
    for (const fn of this.listeners.get(kind) ?? []) await fn({ preventDefault() {}, target: this });
  }
}
function documentFixture() {
  const nodes = new Map([...html.matchAll(/<(\w+)[^>]*\bid="([^"]+)"[^>]*>/g)].map(m => [m[2], new Element(m[1])]));
  for (const [id, value] of Object.entries({ target: 'refs/heads/main', source: 'refs/heads/topic', format: 'sha1', direction: 'cherry-pick' })) nodes.get(id).value = value;
  return { nodes, getElementById: id => nodes.get(id), createElement: tag => new Element(tag) };
}
async function setup({ algorithm = 'sha1', direction = 'cherry-pick', state = 'clean', selected = true, downloads = false } = {}) {
  const f = await fixture(algorithm); f.config.state = state;
  const doc = documentFixture(), client = new ReplayClient({ href, cryptoImpl: crypto, fetchImpl: f.fetchImpl });
  const events = { callbacks: new Map(), addEventListener(k, fn) { this.callbacks.set(k, fn); } };
  const revoked = [], jobs = []; let saved, made = 0;
  const options = { client, events, urls: { createObjectURL() { return `blob:test/${++made}`; }, revokeObjectURL(value) { revoked.push(value); } }, schedule: fn => jobs.push(fn) };
  if (!downloads) options.saveReceipt = value => { saved = value; };
  const app = mountReplay(doc, options), el = id => doc.getElementById(id);
  el('token').value = token; await el('connect').fire(); el('format').value = algorithm; el('direction').value = direction;
  if (selected) await el('select').fire();
  for (const [key, value] of Object.entries(f.input())) el(key).value = String(value);
  return { f, doc, client, app, el, events, saved: () => saved, revoked, jobs };
}
const prepared = async options => { const s = await setup(options); await s.el('prepare').fire(); return s; };
const file = bytes => ({ size: bytes.length, async arrayBuffer() { return Uint8Array.from(bytes).buffer; } });
function chooseUpload(row, bytes, mode = '100755') { row.choice.value = 'file'; row.mode.value = mode; row.inputKind.value = 'upload'; row.file.files = [file(bytes)]; }
for (const algorithm of ['sha1', 'sha256']) for (const direction of ['cherry-pick', 'revert']) test(`${algorithm} ${direction}: UI connects, inspects and requires separate publication confirmation`, async () => {
  const s = await prepared({ algorithm, direction });
  assert.equal(s.el('token').value, ''); assert(s.client.candidate); assert(s.el('selection').textContent.includes(s.f.base));
  assert(s.el('candidate').textContent.includes(s.client.candidate.fields.candidate_commit));
  await s.el('stage').fire(); assert(s.client.pending); assert.equal(s.client.pending.sent, false);
  await s.el('send').fire(); assert(!s.f.calls.some(x => x.path === 'source/apply'));
  assert.match(s.el('status').textContent, /Confirm/);
  s.el('confirm').checked = true; await s.el('send').fire(); assert.equal(s.f.calls.at(-1).path, 'source/apply');
  assert.equal(s.client.pending, null); assert.match(s.el('status').textContent, /Canonical committed/);
  assert.equal(s.el('candidate').textContent, ''); assert.equal(s.el('confirm').checked, false);
});
for (const direction of ['cherry-pick', 'revert']) test(`${direction}: conflict controls have no default resolution and label the actual sides`, async () => {
  const s = await prepared({ direction, state: 'conflicted' });
  const [row] = s.app.conflictControls; assert.equal(row.choice.value, ''); assert(s.el('stage').disabled);
  const before = s.f.calls.length; await s.el('resolve').fire(); assert.equal(s.f.calls.length, before); assert.match(s.el('status').textContent, /every conflict/);
  assert.match(s.el('conflicts').textContent, direction === 'revert' ? /selected parent \(undo side\)/ : /selected commit \(apply side\)/);
  chooseUpload(row, [0, 255, 13, 10]); await row.choice.fire('change'); await s.el('resolve').fire();
  assert.equal(s.client.report.state, 'resolved'); assert(s.client.candidate); assert.equal(s.app.conflictControls.length, 0);
  assert.deepEqual([...upload(s.f.calls.find(x => x.path.endsWith('/resolve'))).files.get('file_0')], [0, 255, 13, 10]);
  assert(!s.f.calls.some(x => x.path === 'source/apply'));
});
test('UI retains explicit merge mainline and accepts genuine root replay without manufacturing a parent', async () => {
  const s = await setup(); s.el('mainline').value = '2'; await s.el('prepare').fire(); assert.equal(s.client.report.selected_mainline, 2);
  s.f.config.root = true; s.el('mainline').value = ''; await s.el('mainline').fire('input'); await s.el('prepare').fire();
  assert.equal(s.client.report.selected_parent, null); assert(s.client.candidate);
});
test('no-change result offers no stage or publish path', async () => {
  const s = await prepared({ state: 'no_change' }); assert.equal(s.client.candidate, null); assert(s.el('stage').disabled);
  assert.match(s.el('status').textContent, /no tree change/); await s.el('stage').fire(); assert.equal(s.client.pending, null);
});
test('same-branch revert reads its snapshot once', async () => {
  const s = await setup({ selected: false, direction: 'revert' }); s.el('source').value = s.el('target').value;
  await s.el('select').fire(); assert.equal(s.f.calls.length, 1); await s.el('prepare').fire(); assert(s.client.candidate);
});
for (const id of ['message', 'mainline', 'direction', 'timestamp']) test(`editing ${id} invalidates replay but keeps the selected snapshot`, async () => {
  const s = await prepared(); await s.el(id).fire('input'); assert.equal(s.client.candidate, null);
  assert.equal(s.client.report, null); assert(s.client.selection); assert(s.el('stage').disabled); assert.equal(s.el('candidate').textContent, '');
});
for (const id of ['target', 'source', 'format']) test(`changing ${id} invalidates both branch selection and candidate`, async () => {
  const s = await prepared(); await s.el(id).fire('change'); assert.equal(s.client.selection, null); assert.equal(s.client.candidate, null);
  assert.equal(s.el('selection').textContent, ''); assert(s.el('prepare').disabled);
});
test('pending publication cannot be replaced by editor changes and supports save/disconnect/restore', async () => {
  const s = await prepared(); await s.el('stage').fire(); const p = s.client.pending;
  assert(s.el('target').disabled); assert(s.el('message').disabled); assert(s.el('prepare').disabled);
  s.el('message').value = 'different'; await s.el('message').fire('input'); assert.deepEqual(s.client.pending, p);
  await s.el('save-receipt').fire(); assert(s.saved()); assert(!s.saved().includes(token)); assert(s.el('discard').disabled);
  await s.el('disconnect').fire(); assert(s.client.pending); assert.equal(s.el('message').value, '');
  const n = await setup({ selected: false }); n.el('receipt-file').files = [file(Buffer.from(s.saved()))];
  const before = n.f.calls.length; await n.el('restore').fire(); assert.equal(n.f.calls.length, before); assert.equal(n.client.pending.key, p.key);
  assert.equal(n.el('confirm').checked, false); await n.el('send').fire(); assert.equal(n.f.calls.length, before);
});
test('lost replies require a fresh explicit confirmation for an unchanged retry', async () => {
  const s = await prepared(); await s.el('stage').fire(); s.f.config.loseApply = true; s.el('confirm').checked = true; await s.el('send').fire();
  const original = s.f.calls.at(-1); assert(s.client.pending); assert.equal(s.el('confirm').checked, false); assert.match(s.el('status').textContent, /Outcome unknown/);
  const count = s.f.calls.length; await s.el('send').fire(); assert.equal(s.f.calls.length, count);
  s.f.config.loseApply = false; s.el('confirm').checked = true; await s.el('send').fire();
  assert.deepEqual(s.f.calls.at(-1).body, original.body); assert.equal(s.f.calls.at(-1).headers['idempotency-key'], original.headers['idempotency-key']);
});
test('bodyless recovery keeps unknown results and clears only a validated canonical decision', async () => {
  const s = await prepared(); await s.el('stage').fire();
  await s.el('recover').fire(); assert(s.client.pending); assert.equal(s.f.calls.at(-1).body, undefined); assert.match(s.el('status').textContent, /still unknown/);
  s.f.config.outcome = 'committed'; await s.el('recover').fire(); assert.equal(s.client.pending, null); assert.match(s.el('status').textContent, /Canonical committed/);
});
test('oversized conflict and receipt files refuse before file reads', async () => {
  const s = await prepared({ state: 'conflicted' }); let reads = 0; const row = s.app.conflictControls[0];
  row.choice.value = 'file'; row.file.files = [{ size: FILE_LIMIT + 1, async arrayBuffer() { reads++; } }];
  await s.el('resolve').fire(); assert.equal(reads, 0); assert.equal(s.client.candidate, null);
  s.el('receipt-file').files = [{ size: RECEIPT_LIMIT + 1, async arrayBuffer() { reads++; } }];
  await s.el('restore').fire(); assert.equal(reads, 0); assert.equal(s.client.pending, null);
});
test('all declared file sizes and aggregate bytes are checked before the first read', async () => {
  let reads = 0;
  const row = (path, size) => ({ path, choice: { value: 'file' }, mode: { value: '100644' }, inputKind: { value: 'upload' },
    file: { files: [{ size, async arrayBuffer() { reads++; return new ArrayBuffer(size); } }] } });
  await assert.rejects(collectResolutions([row('61', 3), row('62', FILE_LIMIT + 1)])); assert.equal(reads, 0);
  await assert.rejects(collectResolutions(Array.from({ length: 5 }, (_, i) => row(`6${i}`, FILE_LIMIT)))); assert.equal(reads, 0);
  await assert.rejects(collectResolutions([]));
});
for (const phase of ['file', 'prepare', 'inspect', 'resolve']) test(`cancel or disconnect during ${phase} cannot restore stale UI state`, async () => {
  const s = await setup({ state: phase === 'resolve' || phase === 'file' ? 'conflicted' : 'clean' }), d = deferred();
  if (phase === 'resolve' || phase === 'file') await s.el('prepare').fire();
  let work;
  if (phase === 'file') {
    const row = s.app.conflictControls[0]; chooseUpload(row, [1]); row.file.files = [{ size: 1, arrayBuffer: () => d.promise }]; work = s.el('resolve').fire();
  } else if (phase === 'resolve') {
    s.app.conflictControls[0].choice.value = 'theirs'; s.f.config.resolve = () => d.promise; work = s.el('resolve').fire();
  } else { s.f.config[phase] = () => d.promise; work = s.el('prepare').fire(); }
  await new Promise(setImmediate); await s.el('disconnect').fire(); d.resolve(new ArrayBuffer(1)); await work;
  assert.equal(s.client.connected, false); assert.equal(s.client.candidate, null); assert.equal(s.el('candidate').textContent, '');
  assert.equal(s.el('conflicts').textContent, ''); assert.equal(s.el('token').value, '');
});
test('changing a conflict file while reading prevents a resolution request', async () => {
  const s = await prepared({ state: 'conflicted' }), d = deferred(), row = s.app.conflictControls[0];
  chooseUpload(row, [1]); row.file.files = [{ size: 1, arrayBuffer: () => d.promise }]; const resolving = s.el('resolve').fire();
  await new Promise(setImmediate); row.file.files = [file([2])]; await row.file.fire('change'); d.resolve(Uint8Array.of(1).buffer); await resolving;
  assert(!s.f.calls.some(x => x.path.endsWith('/resolve'))); assert.equal(s.client.candidate, null);
});
test('file size mismatches and changed selections cannot produce bytes', async () => {
  await assert.rejects(readChosenFile({ size: 2, async arrayBuffer() { return new ArrayBuffer(1); } }, 2));
  await assert.rejects(readChosenFile(file([1]), 2, () => false));
  const d = deferred(); let current = true; const reading = readChosenFile({ size: 1, arrayBuffer: () => d.promise }, 2, () => current);
  current = false; d.resolve(new ArrayBuffer(1)); await assert.rejects(reading);
});
test('text resolution uses explicit newline conversion and supports empty files', async () => {
  const rows = ['lf', 'crlf'].map((kind, i) => ({ path: `6${i}`, choice: { value: 'file' }, mode: { value: '100755' }, inputKind: { value: kind }, text: { value: 'a\r\nb\r' } }));
  const result = await collectResolutions(rows); assert.equal(Buffer.from(result[0].bytes).toString(), 'a\nb\n');
  assert.equal(Buffer.from(result[1].bytes).toString(), 'a\r\nb\r\n'); rows[0].text.value = ''; assert.equal((await collectResolutions([rows[0]]))[0].bytes.length, 0);
  rows[0].text.value = '\0'; await assert.rejects(collectResolutions([rows[0]])); rows[0].text.value = '\ud800'; await assert.rejects(collectResolutions([rows[0]]));
});
test('changing the selected recovery file while it is read never installs stale responsibility', async () => {
  const origin = await prepared(); await origin.el('stage').fire(); const encoded = origin.client.exportReceipt();
  const s = await setup({ selected: false }), d = deferred();
  s.el('receipt-file').files = [{ size: Buffer.byteLength(encoded), arrayBuffer: () => d.promise }]; const reading = s.el('restore').fire();
  await new Promise(setImmediate); await s.el('receipt-file').fire('change'); d.resolve(Uint8Array.from(Buffer.from(encoded)).buffer); await reading;
  assert.equal(s.client.pending, null);
});
test('canonical refusal is not rendered as a successful commit', async () => {
  const s = await prepared(); await s.el('stage').fire(); s.f.config.refuseApply = true; s.el('confirm').checked = true; await s.el('send').fire();
  assert.match(s.el('status').textContent, /Canonical refused/); assert.equal(s.client.pending, null);
});
test('source text and directional controls are inert while exact bytes remain in the candidate', async () => {
  const s = await setup(); s.el('message').value = '<img src=x onerror=evil()>\u202e'; await s.el('prepare').fire(); assert(s.client.candidate);
  assert.equal(displayText('x\u202ey'), 'x\\u{202e}y');
  const script = readFileSync(new URL('replay-view.mjs', base), 'utf8');
  for (const bad of ['innerHTML', 'document.write', 'localStorage', 'sessionStorage']) assert(!script.includes(bad));
  assert(!html.includes('<script>')); assert(!html.includes('onclick='));
});
test('page exit warns only for outstanding publication and clears sensitive views', async () => {
  const s = await prepared(); const e = { prevented: false, preventDefault() { this.prevented = true; } };
  s.events.callbacks.get('beforeunload')(e); assert(!e.prevented); await s.el('stage').fire();
  s.events.callbacks.get('beforeunload')(e); assert(e.prevented); s.events.callbacks.get('pagehide')();
  assert(s.client.pending); assert(!s.client.connected); assert.equal(s.el('message').value, ''); assert.equal(s.app.conflictControls.length, 0);
});
test('download handles are revoked after use and on disconnect without deleting the pending request', async () => {
  const s = await prepared({ downloads: true }); await s.el('stage').fire(); await s.el('save-receipt').fire();
  assert.equal(s.jobs.length, 1); s.jobs[0](); assert.deepEqual(s.revoked, ['blob:test/1']);
  await s.el('save-receipt').fire(); await s.el('disconnect').fire(); assert.deepEqual(s.revoked, ['blob:test/1', 'blob:test/2']); assert(s.client.pending);
});
test('every module in the replay import graph has an exact source-gated asset route', async () => {
  const rust = readFileSync(new URL('replay.rs', base), 'utf8'), visited = new Set();
  async function walk(name) {
    if (visited.has(name)) return; visited.add(name);
    const body = readFileSync(new URL(name, base), 'utf8');
    assert(rust.includes(`b"/ui/replay/${name}"`), `missing route: ${name}`);
    assert(rust.includes(`include_str!("${name}")`), `missing include: ${name}`);
    await import(new URL(name, base));
    for (const m of body.matchAll(/(?:from|import)\s*['"]\.\/([^'"]+)['"]/g)) await walk(m[1]);
  }
  await walk('replay-view.mjs'); assert.equal(visited.size, 8);
  assert(rust.includes('profile.allow_source')); assert(rust.includes('SECURITY'));
  assert(!rust.includes('profile.allow_pulls')); assert(!rust.includes('profile.allow_issues'));
  const routing = readFileSync(new URL('../browser.rs', base), 'utf8');
  assert(routing.includes('mod replay;')); assert(routing.includes('if replay::serve(profile, request, trailing, writer)?'));
  for (const name of ['tags', 'export_verify', 'transfers', 'search', 'branches', 'history', 'initial', 'source_edit', 'pulls']) assert(routing.includes(`if ${name}::serve`));
});
