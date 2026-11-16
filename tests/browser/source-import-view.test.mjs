// Production source controller and DOM handlers against HTTP/DOM/File doubles.
// Tree and blob identities use real hashes; no native node or browser is run.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { SourceEditClient } from '../../crates/fgit-node/src/smart_http/server/browser/source-edit.mjs';
import { mountSourceEditor } from '../../crates/fgit-node/src/smart_http/server/browser/source-edit-view.mjs';
import { FILE_LIMIT, fullFilePatch } from '../../crates/fgit-node/src/smart_http/server/browser/source-edit-patch.mjs';
import { fixture, entry, upload, pathHex, bytes, hex, hash, crypto, token, href } from './source-import-fixtures.mjs';
import { fixture as publicationFixture, metadata, decodeUpload } from './source-edit-fixtures.mjs';

const html = readFileSync(new URL('../../crates/fgit-node/src/smart_http/server/browser/source-edit.html', import.meta.url), 'utf8');
const importControls = ['batch-files', 'directory-files', 'import-prefix', 'import-prefix-kind', 'import-mode', 'import-files', 'import-directory'];
class Element {
  children = []; listeners = new Map(); disabled = false; checked = false; files = []; ownText = ''; current = '';
  constructor(tag, file = false) { this.tagName = tag.toUpperCase(); this.file = file; }
  set value(value) { this.current = String(value); if (this.file && value === '') this.files = []; }
  get value() { return this.current; }
  set textContent(value) { this.ownText = String(value); this.children = []; }
  get textContent() { return this.ownText + this.children.map(child => child.textContent ?? String(child)).join(''); }
  addEventListener(kind, fn) { this.listeners.set(kind, [...(this.listeners.get(kind) ?? []), fn]); }
  replaceChildren(...children) { this.children = children; this.ownText = ''; }
  append(...children) { this.children.push(...children); }
  async fire(kind = 'click', synthetic = false) {
    if (kind === 'click' && this.disabled && !synthetic) return;
    for (const fn of this.listeners.get(kind) ?? []) await fn({ preventDefault() {}, target: this });
  }
}
function documentFixture(algorithm) {
  const nodes = new Map([...html.matchAll(/<(\w+)[^>]*\bid="([^"]+)"[^>]*>/g)]
    .map(match => [match[2], new Element(match[1], match[0].includes('type="file"'))]));
  for (const [id, value] of Object.entries({ branch: 'refs/heads/main', format: algorithm,
    'path-kind': 'utf8', 'change-kind': 'create', 'file-mode': '100644', 'line-endings': 'lf', 'rename-path-kind': 'utf8' })) nodes.get(id).value = value;
  return { getElementById: id => nodes.get(id), createElement: tag => new Element(tag) };
}
async function bindPublication(source, edits) {
  const p = await publicationFixture(source.algorithm, edits, { allowBinary: true });
  const body = bytes(`tree ${p.tree}\nparent ${source.commit}\nauthor Alice <a@example.invalid> 1 +0000\ncommitter Alice <a@example.invalid> 1 +0000\n\nExact source edit\n`);
  const candidate = hash('commit', body, source.algorithm);
  Object.assign(p.prepared, { source_commit: source.commit, source_rcr: source.common.source_rcr, candidate_commit: candidate });
  Object.assign(p.inspection, { source_head: source.common.source_head, snapshot_token: source.common.snapshot_token,
    expected_commit: source.commit, parents: [source.commit], candidate_commit: candidate, candidate_commit_body_hex: hex(body) });
  p.inspection.comparison.before_tree = source.tree;
  Object.assign(p.terminal, { expected_commit: source.commit, candidate_commit: candidate });
  return p;
}
async function setup({ entries = [], algorithm = 'sha1', effects = null } = {}) {
  const f = fixture(entries, algorithm), p = effects ? await bindPublication(f, effects) : null, calls = [];
  const fetchImpl = async (url, options) => {
    const endpoint = new URL(url).pathname.split('/api/v1/')[1];
    calls.push({ endpoint, options });
    if (endpoint === 'source/tree' || endpoint === 'source/blob') return f.fetchImpl(url, options);
    if (!p) throw new Error(`Unexpected publication request ${endpoint}`);
    return p.fetchImpl(url, options);
  };
  const client = new SourceEditClient({ href, cryptoImpl: crypto, fetchImpl }), doc = documentFixture(algorithm);
  const events = { callbacks: new Map(), addEventListener(name, fn) { this.callbacks.set(name, fn); } };
  const saved = [], receipts = [];
  const app = mountSourceEditor(doc, { client, events, saveFile: value => saved.push(value), saveReceipt: value => receipts.push(value) });
  const el = id => doc.getElementById(id);
  el('token').value = token; await el('connect').fire(); await el('select-base').fire();
  for (const [id, value] of Object.entries(metadata)) el(id).value = String(value);
  calls.length = 0; f.calls.length = 0;
  return { f, p, calls, client, doc, app, events, saved, receipts, el };
}
async function choose(s, files, directory = false) {
  const picker = s.el(directory ? 'directory-files' : 'batch-files');
  picker.files = files; await picker.fire('change');
}
async function importFiles(s, files, directory = false) {
  await choose(s, files, directory); await s.el(directory ? 'import-directory' : 'import-files').fire();
}
async function draft(s, path = 'queued.txt', content = 'retained draft\n') {
  s.el('change-kind').value = 'create'; await s.el('change-kind').fire('input');
  s.el('path').value = path; await s.el('path').fire('input');
  s.el('file-text').value = content; await s.el('file-text').fire('input');
}
async function queue(s, path, content) { await draft(s, path, content); await s.el('queue-file').fire(); }
function waitAtNetwork(s) {
  let release, enter;
  const ready = new Promise(resolve => { enter = resolve; });
  s.f.config.wait = () => new Promise(resolve => { release = resolve; enter(); });
  return { ready, release() { s.f.config.wait = null; release(); } };
}
function waitAtFile(file, data) {
  let release, enter;
  const ready = new Promise(resolve => { enter = resolve; });
  file.arrayBuffer = () => { file.reads++; return new Promise(resolve => { release = () => resolve(data.slice().buffer); enter(); }); };
  return { ready, release() { release(); } };
}

for (const algorithm of ['sha1', 'sha256']) {
  test(`${algorithm}: multi-file UI import keeps queued work, exact bytes, modes and unselected files`, async () => {
    const original = [entry('script', '#!/bin/sh\nold\n', 0o100755), entry('same', ''), entry('untouched', 'keep')];
    const s = await setup({ entries: original, algorithm });
    await queue(s, 'queued.txt', 'keep queued'); await draft(s, 'unsubmitted.txt', 'keep typed');
    const incoming = [upload('new.bin', new Uint8Array([0, 255, 13, 10])), upload('script', '#!/bin/sh\nnew\r\n'), upload('same', '')];
    await importFiles(s, incoming);
    assert.equal(s.app.queued.length, 3, s.el('status').textContent);
    const changed = new Map(s.app.queued.map(e => [e.path_hex, e]));
    assert.deepEqual(changed.get(pathHex('queued.txt')).after.bytes, bytes('keep queued'));
    assert.deepEqual(changed.get(pathHex('new.bin')).after.bytes, new Uint8Array([0, 255, 13, 10]));
    assert.equal(changed.get(pathHex('new.bin')).after.mode, 0o100644);
    assert.equal(changed.get(pathHex('script')).after.mode, 0o100755);
    assert.deepEqual(changed.get(pathHex('script')).after.bytes, bytes('#!/bin/sh\nnew\r\n'));
    assert(!changed.has(pathHex('untouched'))); assert(!changed.has(pathHex('same')));
    assert(s.app.queued.every(e => e.after !== null)); assert(incoming.every(f => f.reads === 1));
    assert.match(s.el('import-report').textContent, /1 created, 1 updated, 1 unchanged/);
    assert.match(s.el('import-report').textContent, /Unchanged files.*same/);
    assert.match(s.el('edits').textContent, /modes 100755 → 100755/);
    assert.equal(s.el('file-text').value, 'keep typed'); assert.equal(s.el('path').value, 'unsubmitted.txt');
    await s.el('save-file').fire(); assert.deepEqual(s.saved.at(-1), bytes('keep typed'));
    assert.equal(s.el('batch-files').files.length, 0);
    assert.equal(s.client.candidate, null); assert.equal(s.client.pending, null);
    for (const call of s.f.calls) {
      assert(['source/tree', 'source/blob'].includes(call.endpoint));
      assert.equal(call.command.get('expected_head'), s.f.common.snapshot_token);
      assert.equal(call.command.get('expected_commit'), s.f.commit);
      assert.equal(new Headers(call.options.headers).has('idempotency-key'), false);
    }
  });

  test(`${algorithm}: directory UI import strips one folder and applies an exact destination`, async () => {
    const s = await setup({ algorithm });
    s.el('import-prefix-kind').value = 'hex'; s.el('import-prefix').value = 'ff';
    s.el('import-mode').value = '100755';
    await importFiles(s, [upload('b', 'B', 'project/sub/b'), upload('a', 'A', 'project/a')], true);
    assert.deepEqual(s.app.queued.map(e => e.path_hex), ['ff2f61', 'ff2f7375622f62']);
    assert(s.app.queued.every(e => e.before === null && e.after.mode === 0o100755));
    assert.match(s.el('edits').textContent, /bytes:ff2f61/);
    assert.match(s.el('status').textContent, /2 created, 0 updated, 0 unchanged/);
    assert.equal(s.el('directory-files').files.length, 0);
  });

  test(`${algorithm}: imported changes require native inspection and a separately confirmed publication`, async () => {
    const before = entry('file.txt', 'before\r\n'), after = bytes('after\r\n');
    const effects = [{ path_hex: before.path_hex, before: { bytes: before.bytes, mode: before.mode }, after: { bytes: after, mode: before.mode } },
      { path_hex: pathHex('new.bin'), before: null, after: { bytes: new Uint8Array([0, 255]), mode: 0o100644 } }];
    const s = await setup({ algorithm, entries: [before], effects });
    await importFiles(s, [upload('new.bin', effects[1].after.bytes), upload('file.txt', after)]);
    assert.equal(s.client.candidate, null); assert.equal(s.client.pending, null);
    assert(!s.calls.some(c => c.endpoint === 'source/prepare'));
    await s.el('prepare-edits').fire(); assert(s.client.candidate, s.el('status').textContent);
    const preparation = s.calls.find(c => c.endpoint === 'source/prepare');
    assert.deepEqual(decodeUpload(preparation.options).payload, fullFilePatch(effects, { allowBinary: true }).bytes);
    assert(s.calls.some(c => c.endpoint === 'source/inspect'));
    assert.equal(new Headers(preparation.options.headers).has('idempotency-key'), false);
    await s.el('stage').fire(); assert(s.client.pending);
    for (const name of importControls) assert(s.el(name).disabled, name);
    await s.el('send').fire(); assert(!s.calls.some(c => c.endpoint === 'source/apply'));
    s.el('confirm-send').checked = true; await s.el('send').fire();
    assert.equal(s.calls.filter(c => c.endpoint === 'source/apply').length, 1);
    assert.equal(s.client.pending, null); assert.equal(s.app.queued.length, 0);
    assert.equal(s.el('import-report').textContent, '');
    assert.match(s.el('status').textContent, /Canonical committed/);
  });
}

test('unchanged import remains a no-op unless the mode is explicitly changed', async () => {
  const s = await setup({ entries: [entry('script', '', 0o100755)] });
  await importFiles(s, [upload('script', '')]); assert.equal(s.app.queued.length, 0);
  assert.match(s.el('import-report').textContent, /0 created, 0 updated, 1 unchanged/);
  s.el('import-mode').value = '100644'; await s.el('import-mode').fire('input');
  await importFiles(s, [upload('script', '')]); assert.equal(s.app.queued.length, 1);
  assert.equal(s.app.queued[0].before.mode, 0o100755); assert.equal(s.app.queued[0].after.mode, 0o100644);
  assert.match(s.el('edits').textContent, /modes 100755 → 100644/);
});

test('UTF-8 destination prefixes do not include individual file directory metadata', async () => {
  const s = await setup(); s.el('import-prefix').value = 'nested/新';
  await importFiles(s, [upload('readme', 'text', 'ignored/local/readme')]);
  assert.equal(s.app.queued[0].path_hex, pathHex('nested/新/readme'));
});

test('an unrelated import preserves paired rename removal and the unqueued draft', async () => {
  const s = await setup({ entries: [entry('original', 'old', 0o100755)] });
  s.el('change-kind').value = 'rename'; await s.el('change-kind').fire('input');
  s.el('path').value = 'original'; await s.el('path').fire('input');
  s.el('rename-path').value = 'moved'; await s.el('load-file').fire(); await s.el('queue-file').fire();
  assert.equal(s.app.queued.length, 2);
  await draft(s, 'draft', 'not queued'); await importFiles(s, [upload('added', 'new')]);
  assert.equal(s.app.queued.length, 3); assert.equal(s.el('edits').children.length, 2);
  const row = s.el('edits').children.find(item => item.textContent.includes('Rename '));
  await row.children.find(child => child.tagName === 'BUTTON').fire();
  assert.deepEqual(s.app.queued.map(e => e.path_hex), [pathHex('added')]);
  assert.equal(s.el('file-text').value, 'not queued');
});

for (const [name, file, prefix] of [['same path', 'queued.txt', ''], ['descendant', 'child', 'queued.txt']]) {
  test(`import ${name} collision keeps the existing queued edit and performs no reads`, async () => {
    const s = await setup(); await queue(s, 'queued.txt', 'retain'); const retained = s.app.queued;
    s.el('import-prefix').value = prefix; const selected = upload(file);
    await importFiles(s, [selected]);
    assert.deepEqual(s.app.queued, retained); assert.equal(selected.reads, 0); assert.equal(s.calls.length, 0);
    assert.match(s.el('status').textContent, /Duplicate|overlap/);
  });
}

for (const [name, configure, pattern] of [
  ['traversing prefix', s => { s.el('import-prefix').value = '../outside'; }, /Forbidden|Invalid|path/i],
  ['malformed hex prefix', s => { s.el('import-prefix-kind').value = 'hex'; s.el('import-prefix').value = 'f'; }, /hex|path/i],
  ['unknown prefix encoding', s => { s.el('import-prefix-kind').value = 'guess'; }, /destination bytes/],
  ['unsupported file mode', s => { s.el('import-mode').value = '120000'; }, /mode policy/],
]) test(`${name} refuses in the UI without changing queued or typed work`, async () => {
  const s = await setup(); await queue(s); await draft(s, 'draft', 'keep'); const retained = s.app.queued;
  configure(s); const selected = upload('incoming'); await importFiles(s, [selected]);
  assert.deepEqual(s.app.queued, retained); assert.equal(s.el('file-text').value, 'keep');
  assert.equal(selected.reads, 0); assert.equal(s.calls.length, 0); assert.match(s.el('status').textContent, pattern);
});

test('UI bounds oversized selections before copying their members or reading file content', async () => {
  const s = await setup(); await queue(s); const retained = s.app.queued;
  const oversized = { length: 64, get 0() { assert.fail('must bound the combined count before copying'); } };
  await choose(s, oversized); await s.el('import-files').fire();
  assert.match(s.el('status').textContent, /64-path/); assert.equal(s.calls.length, 0);
  const file = { ...upload('large'), size: FILE_LIMIT + 1 }; await importFiles(s, [file]);
  assert.equal(file.reads, 0); assert.equal(s.calls.length, 0); assert.deepEqual(s.app.queued, retained);
});

test('a browser without directory path metadata refuses instead of flattening the selection', async () => {
  const s = await setup(), file = upload('file'); await importFiles(s, [file], true);
  assert.equal(s.app.queued.length, 0); assert.equal(file.reads, 0); assert.equal(s.calls.length, 0);
});

test('cancel during native inventory preserves queued and typed work and stops local reads', async () => {
  const s = await setup(); await queue(s); await draft(s, 'draft', 'typed'); const retained = s.app.queued;
  const file = upload('incoming'), paused = waitAtNetwork(s); await choose(s, [file]);
  const work = s.el('import-files').fire(); await paused.ready;
  assert(s.el('import-files').disabled); assert.equal(s.el('cancel-import').disabled, false);
  const leaving = { preventDefault() { this.prevented = true; } }; s.events.callbacks.get('beforeunload')(leaving); assert(leaving.prevented);
  await s.el('cancel-import').fire(); paused.release(); await work;
  assert.deepEqual(s.app.queued, retained); assert.equal(s.el('file-text').value, 'typed');
  assert.equal(file.reads, 0); assert.equal(s.client.busy, false); assert(s.el('cancel-import').disabled);
  assert.equal(s.client.candidate, null); assert.equal(s.client.pending, null);
});

test('cancel during a local file read cannot queue a prefix or start another file read', async () => {
  const s = await setup(); await queue(s); const retained = s.app.queued;
  const first = upload('a', 'one'), second = upload('b', 'two'), paused = waitAtFile(first, bytes('one'));
  await choose(s, [first, second]); const work = s.el('import-files').fire(); await paused.ready;
  await s.el('cancel-import').fire(); paused.release(); await work;
  assert.deepEqual(s.app.queued, retained); assert.equal(second.reads, 0);
  assert.equal(s.el('import-report').textContent, ''); assert.match(s.el('status').textContent, /cancel/i);
});

for (const change of ['files', 'prefix', 'mode']) test(`changing ${change} during import rejects late results`, async () => {
  const s = await setup(); await queue(s); const retained = s.app.queued;
  const first = upload('a', 'one'), replacement = upload('replacement', 'two'), paused = waitAtFile(first, bytes('one'));
  await choose(s, [first]); const work = s.el('import-files').fire(); await paused.ready;
  if (change === 'files') await choose(s, [replacement]);
  else {
    const control = s.el(change === 'prefix' ? 'import-prefix' : 'import-mode');
    control.value = change === 'prefix' ? 'other' : '100755'; await control.fire('input');
  }
  paused.release(); await work;
  assert.deepEqual(s.app.queued, retained); assert.equal(replacement.reads, 0);
  assert.equal(s.client.candidate, null); assert.equal(s.client.pending, null);
});

test('disconnect during import clears source, local selectors and drafts before late file completion', async () => {
  const s = await setup(); await queue(s); await draft(s, 'draft', 'private');
  const first = upload('a', 'one'), paused = waitAtFile(first, bytes('one'));
  await choose(s, [first]); const work = s.el('import-files').fire(); await paused.ready;
  await s.el('disconnect').fire(); paused.release(); await work;
  assert.equal(s.client.connected, false); assert.equal(s.app.queued.length, 0);
  assert.equal(s.el('file-text').value, ''); assert.equal(s.el('batch-files').files.length, 0);
  assert.equal(s.el('directory-files').files.length, 0); assert.equal(s.el('import-report').textContent, '');
  for (const id of importControls) assert(s.el(id).disabled, id);
});

for (const code of [404, 409]) test(`HTTP ${code} cannot adopt a partial import or imply absence`, async () => {
  const s = await setup(); await queue(s); const retained = s.app.queued, file = upload('incoming');
  s.f.config.status = code; await importFiles(s, [file]);
  assert.deepEqual(s.app.queued, retained); assert.equal(file.reads, 0);
  assert.equal(s.el('import-report').textContent, ''); assert.equal(s.client.pending, null);
});

test('a later local-file failure preserves all earlier edits instead of queueing a partial import', async () => {
  const s = await setup(); await queue(s); const retained = s.app.queued;
  const first = upload('a'), second = upload('b'); second.arrayBuffer = async () => { throw new Error('local read failed'); };
  await importFiles(s, [first, second]); assert.equal(first.reads, 1);
  assert.deepEqual(s.app.queued, retained); assert.match(s.el('status').textContent, /local read failed/);
  assert.equal(s.client.candidate, null); assert.equal(s.client.pending, null);
});

test('an imported publication with a lost reply retains its original key and disallows another import', async () => {
  const effects = [{ path_hex: pathHex('new'), before: null, after: { bytes: bytes('new'), mode: 0o100644 } }];
  const s = await setup({ effects }); await importFiles(s, [upload('new', 'new')]);
  await s.el('prepare-edits').fire(); await s.el('stage').fire(); assert(s.client.pending, s.el('status').textContent);
  const key = s.client.pending.key; s.p.config.loseApply = true; s.el('confirm-send').checked = true; await s.el('send').fire();
  assert.equal(s.client.pending.key, key); assert.match(s.el('status').textContent, /Outcome unknown/);
  const file = upload('other'), calls = s.calls.length; await choose(s, [file]); await s.el('import-files').fire('click', true);
  assert.equal(file.reads, 0); assert.equal(s.calls.length, calls); assert.equal(s.client.pending.key, key);
  await s.el('save-receipt').fire(); assert(!s.receipts[0].includes(token));
  s.p.config.outcome = 'committed'; await s.el('recover').fire(); assert.equal(s.client.pending, null);
  const lookup = s.calls.at(-1); assert.equal(lookup.endpoint, 'outcomes');
  assert.equal(new Headers(lookup.options.headers).get('idempotency-key'), key);
  assert.equal(s.calls.filter(c => c.endpoint === 'source/apply').length, 1);
});

test('imports require an explicitly selected base even with synthetic button events', async () => {
  const s = await setup(); s.el('branch').value = 'refs/heads/other'; await s.el('branch').fire('input');
  const file = upload('incoming'); await choose(s, [file]); await s.el('import-files').fire('click', true);
  assert.equal(s.client.selection, null); assert.equal(file.reads, 0); assert.equal(s.calls.length, 0);
  assert.equal(s.app.queued.length, 0); assert.match(s.el('status').textContent, /Select a branch base/);
});
