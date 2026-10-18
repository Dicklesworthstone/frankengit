// Actual page markup and production client/view; the DOM and native HTTP peer are test doubles.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { mountHistory } from '../../crates/fgit-node/src/smart_http/server/browser/history-view.mjs';
import { fixture, harness, hex, jsonResponse, token } from './history-compare-fixtures.mjs';
const html = readFileSync(new URL('../../crates/fgit-node/src/smart_http/server/browser/history.html', import.meta.url), 'utf8');
class Element {
  constructor(tag = 'div') { this.tagName = tag; this.children = []; this.events = new Map(); this.value = ''; this.disabled = false; this.text = ''; }
  set textContent(value) { this.text = String(value); this.children = []; }
  get textContent() { return this.text + this.children.map(child => child.textContent).join(''); }
  set innerHTML(_) { throw new Error('Unsafe HTML sink'); }
  append(...children) { this.children.push(...children); }
  replaceChildren(...children) { this.children = children; this.text = ''; }
  addEventListener(name, callback) { this.events.set(name, [...this.events.get(name) ?? [], callback]); }
  async fire(name) { const event = { prevented: false, preventDefault() { this.prevented = true; } }; await Promise.all((this.events.get(name) ?? []).map(fn => fn(event))); return event; }
}
function find(root, label) {
  for (const node of root.children) {
    if (node.tagName === 'button' && node.textContent.startsWith(label)) return node;
    const nested = find(node, label); if (nested) return nested;
  }
  return null;
}
async function click(root, label) { const button = find(root, label); assert.ok(button, label); await button.fire('click'); return button; }
function view(f = fixture(), respond = null) {
  const h = harness(f, respond), nodes = Object.fromEntries([...html.matchAll(/id="history-([^"]+)"/g)].map(match => [match[1], new Element()]));
  Object.assign(nodes.ref, { value: f.afterRef }); nodes.format.value = f.algorithm; nodes.limit.value = '20'; nodes.first.value = '0'; nodes['path-kind'].value = 'text';
  nodes['before-ref'].value = f.beforeRef; nodes['compare-mode'].value = 'direct'; nodes['compare-path-kind'].value = 'text';
  const events = new Element(), downloads = [], files = [];
  const doc = { getElementById: id => nodes[id.replace(/^history-/, '')], createElement: tag => new Element(tag), body: new Element('body') };
  const app = mountHistory(doc, { client: h.client, events, download: value => downloads.push(JSON.parse(value)),
    downloadFile: (name, bytes) => files.push({ name, bytes }) });
  const open = async () => { nodes.token.value = token; const event = await nodes.connect.fire('submit'); assert.equal(event.prevented, true); };
  const compare = () => nodes.compare.fire('submit');
  return { ...h, nodes, events, app, open, compare, downloads, files };
}
for (const algorithm of ['sha1', 'sha256']) {
  test(`${algorithm}: complete compare -> inspect before/after -> download workflow uses the actual page`, async () => {
    const v = view(fixture(algorithm));
    assert.equal(v.nodes['compare-run'].disabled, true); await v.open(); assert.equal(v.nodes.token.value, '');
    assert.equal(v.nodes['compare-run'].disabled, false); const event = await v.compare(); assert.equal(event.prevented, true);
    assert.match(v.nodes.content.textContent, /Reference comparison · direct/);
    assert.match(v.nodes.content.textContent, /src\/file.txt/); assert.ok(v.nodes.content.textContent.includes('before\\u{d}\n'), 'CR is visibly escaped; LF stays a line break');
    const snapshot = v.nodes.snapshot.textContent;
    await click(v.nodes.content, 'Open before file'); assert.match(v.nodes.content.textContent, /Compared before side/);
    assert.match(v.nodes.content.textContent, /Complete blob bytes match/); assert.equal(v.nodes.snapshot.textContent, snapshot);
    assert.equal(find(v.nodes.breadcrumbs, 'Commit root'), null, 'before cannot leak into after-ref ancestry browsing');
    await click(v.nodes.breadcrumbs, 'Back to reference comparison');
    await click(v.nodes.content, 'Download after verified bytes');
    assert.equal(v.files.length, 1); assert.equal(Buffer.from(v.files[0].bytes).toString(), 'after\n');
    assert.equal(v.files[0].name, `frankengit-after-${v.f.afterBlob}.bin`);
    assert.match(v.nodes.status.textContent, /inert bytes/);
    assert.equal(v.calls.every(call => call.headers['Idempotency-Key'] === undefined), true);
  });
}

test('direct vs merge-base is explicit and displayed separately from mergeability', async () => {
  const v = view(); await v.open(); v.nodes['compare-mode'].value = 'merge-base'; await v.compare();
  assert.match(v.nodes.content.textContent, /not a merge result/); assert.ok(v.nodes.content.textContent.includes(v.f.base));
  await click(v.nodes.content, 'Open before file'); const request = v.calls.at(-1).form;
  assert.equal(request.get('at_commit'), v.f.base); assert.equal(request.get('expected_ref_tip'), v.f.before);
});

test('text prefixes preserve spaces; hex prefixes support arbitrary bytes; queries are explicit', async () => {
  let patch = {};
  const f = fixture(), v = view(f, call => {
    if (!call.url.endsWith('/diff')) return null;
    const raw = f.diff({ path_prefixes_hex: call.form.getAll('path_prefix_hex') });
    raw.entries[0].path_hex = patch.path ?? hex(' src /file.txt'); return jsonResponse(raw);
  });
  await v.open(); v.nodes['compare-paths'].value = ' src \n\n'; await v.compare();
  assert.deepEqual(v.calls.at(-1).form.getAll('path_prefix_hex'), [hex(' src ')]); assert.match(v.nodes.content.textContent, /Filtered to 1/);
  v.nodes['compare-path-kind'].value = 'hex'; v.nodes['compare-paths'].value = '7372632fff'; patch.path = '7372632fff'; await v.compare();
  assert.deepEqual(v.calls.at(-1).form.getAll('path_prefix_hex'), ['7372632fff']); assert.match(v.nodes.content.textContent, /Raw hex bytes/);
});

test('pagination renders every changed-path page without issuing another native read', async () => {
  const f = fixture(), entries = Array.from({ length: 60 }, (_, i) => f.entry(`src/${String(i).padStart(3, '0')}.txt`));
  const v = view(f, call => call.url.endsWith('/diff') ? jsonResponse(f.diff({ entries, entry_count: entries.length })) : null);
  await v.open(); await v.compare(); assert.match(v.nodes.content.textContent, /paths 0–25 of 60/);
  assert.equal(v.nodes.content.children.filter(n => n.tagName === 'article').length, 25);
  await click(v.nodes.paging, 'Next changed paths'); assert.match(v.nodes.content.textContent, /paths 25–50 of 60/);
  await click(v.nodes.paging, 'Next changed paths'); assert.match(v.nodes.content.textContent, /paths 50–60 of 60/);
  await click(v.nodes.paging, 'Previous changed paths'); assert.match(v.nodes.content.textContent, /paths 25–50 of 60/);
  assert.equal(v.calls.length, 2); await v.nodes.download.fire('click');
  assert.equal(v.downloads[0].entries.length, 60); assert.equal(JSON.stringify(v.downloads[0]).includes(token), false);
});

test('display clipping keeps the complete validated report downloadable', async () => {
  const f = fixture(), raw = f.diff(), body = Buffer.alloc(150000, 120), changed = Buffer.alloc(150000, 121);
  raw.entries[0].content = { kind: 'text', algorithm: 'Myers', additions: 1, deletions: 1,
    before_bytes: body.length, after_bytes: changed.length, hunks: [{ old: f.lineSpan(body), new: f.lineSpan(changed), before_hex: hex(body), after_hex: hex(changed) }] };
  const v = view(f, call => call.url.endsWith('/diff') ? jsonResponse(raw) : null); await v.open(); await v.compare();
  assert.match(v.nodes.content.textContent, /DISPLAY CLIPPED/); await v.nodes.download.fire('click');
  assert.equal(v.downloads[0].entries[0].content.hunks[0].after_hex.length, 300000);
  assert.ok(v.nodes.content.textContent.length < 200000);
});

test('hunk count clipping does not hide later changed path labels', async () => {
  const f = fixture(), raw = f.diff(), c = raw.entries[0].content;
  c.before_bytes = c.after_bytes = 260;
  c.hunks = Array.from({ length: 130 }, (_, i) => ({ old: { byte_start: i * 2, byte_end: i * 2 + 2, line_start: i, line_count: 1 },
    new: { byte_start: i * 2, byte_end: i * 2 + 2, line_start: i, line_count: 1 }, before_hex: '610a', after_hex: '620a' }));
  raw.entries.push(f.entry('src/last.txt')); raw.entry_count++;
  const v = view(f, call => call.url.endsWith('/diff') ? jsonResponse(raw) : null); await v.open(); await v.compare();
  assert.match(v.nodes.content.textContent, /DISPLAY CLIPPED/); assert.match(v.nodes.content.textContent, /src\/last.txt/);
});

test('source names, messages and hunk bytes remain inert and bidi controls become visible', async () => {
  const f = fixture(), raw = f.diff(); raw.entries[0].path_hex = hex('src/<svg onload=evil>\u202e');
  const bytes = Buffer.from('<script>evil()</script>\u2066'); const c = raw.entries[0].content;
  c.after_bytes = bytes.length; c.hunks[0].new = f.lineSpan(bytes); c.hunks[0].after_hex = hex(bytes);
  const v = view(f, call => call.url.endsWith('/diff') ? jsonResponse(raw) : null); await v.open(); await v.compare();
  assert.match(v.nodes.content.textContent, /<script>evil\(\)<\/script>/); assert.match(v.nodes.content.textContent, /\\u\{202e\}/);
  assert.match(v.nodes.content.textContent, /\\u\{2066\}/); assert.doesNotMatch(v.nodes.content.textContent, /[\u202e\u2066]/u);
});

test('gitlinks are labelled as object-only changes and never get open/download actions', async () => {
  const f = fixture(), raw = f.diff({ entries: [{ path_hex: hex('submodule'), kind: 'added', before: null,
    after: { mode: '160000', object_id: f.tag(f.after) }, content: { kind: 'object_only' } }], entry_count: 1 });
  const v = view(f, call => call.url.endsWith('/diff') ? jsonResponse(raw) : null); await v.open(); await v.compare();
  assert.match(v.nodes.content.textContent, /gitlink identity only; not followed/);
  assert.equal(find(v.nodes.content, 'Open after'), null); assert.equal(find(v.nodes.content, 'Download after'), null);
});

test('binary and symlink downloads are exact inert bytes with safe generated filenames', async () => {
  const f = fixture('sha256', { before: Buffer.from([0, 255, 128]), after: '../../outside\n' });
  const raw = f.diff(); raw.entries[0].before.mode = raw.entries[0].after.mode = '120000';
  raw.entries[0].path_hex = hex('src/<hostile>.sh'); raw.entries[0].content = { kind: 'binary', before_bytes: f.beforeBody.length, after_bytes: f.afterBody.length };
  const v = view(f, call => {
    if (call.url.endsWith('/diff')) return jsonResponse(raw);
    if (call.url.endsWith('/historical-blob')) { const reply = f.historical(call.form); reply.source.kind = 'symlink'; return jsonResponse(reply); }
    return null;
  });
  await v.open(); await v.compare(); assert.match(v.nodes.content.textContent, /Binary payload/);
  await click(v.nodes.content, 'Download before verified bytes'); assert.deepEqual(Buffer.from(v.files[0].bytes), f.beforeBody);
  assert.match(v.files[0].name, /^frankengit-before-[0-9a-f]{64}\.bin$/);
  assert.match(v.nodes.content.textContent, /Symlink payload only; never followed/);
});

test('empty filtered diffs do not claim merge permission or trigger file reads', async () => {
  const f = fixture(), v = view(f, call => call.url.endsWith('/diff') ? jsonResponse(f.diff({ entries: [], entry_count: 0, path_prefixes_hex: [hex('none')] })) : null);
  await v.open(); v.nodes['compare-paths'].value = 'none'; await v.compare();
  assert.match(v.nodes.content.textContent, /No changed paths/); assert.match(v.nodes.content.textContent, /does not grant merge permission/); assert.equal(v.calls.length, 2);
});

test('a malformed reply clears an older comparison and disables its download', async () => {
  let broken = false; const f = fixture(), v = view(f, call => call.url.endsWith('/diff') && broken ? jsonResponse(f.diff({ complete: false })) : null);
  await v.open(); await v.compare(); broken = true; await v.compare();
  assert.equal(v.nodes.content.textContent, ''); assert.equal(v.nodes.download.disabled, true); assert.match(v.nodes.status.textContent, /changed/);
  await v.nodes.download.fire('click'); assert.equal(v.downloads.length, 0);
});

test('synthetic compare without a connection cannot dispatch a request', async () => {
  const v = view(); await v.compare(); assert.equal(v.calls.length, 0); assert.equal(v.nodes.download.disabled, true);
});

test('stale detached controls cannot fetch after cancel or reopen', async () => {
  const v = view(); await v.open(); await v.compare(); const old = find(v.nodes.content, 'Open before');
  v.app.cancel(); const count = v.calls.length; await old.fire('click'); assert.equal(v.calls.length, count);
  assert.equal(v.nodes.content.textContent, ''); await v.app.open(); await old.fire('click'); assert.equal(v.calls.length, count + 1);
});

test('cancel and pagehide fence pending comparisons and downloads', async () => {
  for (const leaving of [false, true]) {
    let finish; const f = fixture(), gate = new Promise(resolve => { finish = resolve; });
    const v = view(f, call => call.url.endsWith('/diff') ? gate : null); await v.open();
    const pending = v.compare();
    if (leaving) await v.events.fire('pagehide'); else v.app.cancel();
    finish(jsonResponse(f.diff())); await pending;
    assert.equal(v.nodes.content.textContent, ''); assert.equal(v.nodes.download.disabled, true); assert.equal(v.files.length, 0);
    if (leaving) { assert.equal(v.client.connected, false); assert.equal(v.nodes['before-ref'].value, ''); }
  }
});

test('a changed complete-file body never produces a download', async () => {
  const f = fixture(), v = view(f, call => {
    if (!call.url.endsWith('/historical-blob')) return null;
    const raw = f.historical(call.form); raw.source.content_hex = hex('xxxxx\n'); return jsonResponse(raw);
  });
  await v.open(); await v.compare(); await click(v.nodes.content, 'Download after verified bytes');
  assert.equal(v.files.length, 0); assert.match(v.nodes.status.textContent, /native object/); assert.equal(v.nodes.download.disabled, true);
});

test('edits during a comparison cannot replace the selected request or its displayed refs', async () => {
  let finish; const f = fixture(), gate = new Promise(resolve => { finish = resolve; });
  const v = view(f, call => call.url.endsWith('/diff') ? gate : null); await v.open(); const pending = v.compare();
  v.nodes.ref.value = 'refs/heads/edited-after'; v.nodes['before-ref'].value = 'refs/heads/edited-before'; v.nodes['compare-mode'].value = 'merge-base';
  finish(jsonResponse(f.diff())); await pending;
  assert.ok(v.nodes.content.textContent.includes(f.beforeRef)); assert.ok(v.nodes.content.textContent.includes(f.afterRef));
  assert.match(v.nodes.content.textContent, /comparison · direct/); assert.doesNotMatch(v.nodes.content.textContent, /edited-before|edited-after/);
});

test('comparison source range paging keeps the before ref, tip and base instead of using the after selection', async () => {
  const f = fixture('sha1', { before: Buffer.alloc(70000, 97) }), raw = f.diff();
  raw.entries[0].content = { kind: 'binary', before_bytes: f.beforeBody.length, after_bytes: f.afterBody.length };
  const v = view(f, call => call.url.endsWith('/diff') ? jsonResponse({ ...raw, mode: 'merge-base', compared_before: f.tag(f.base) }) : null);
  await v.open(); v.nodes['compare-mode'].value = 'merge-base'; await v.compare(); await click(v.nodes.content, 'Open before');
  assert.match(v.nodes.content.textContent, /Partial file range/); await click(v.nodes.paging, 'Next file range');
  const form = v.calls.at(-1).form;
  assert.equal(form.get('ref'), f.beforeRef); assert.equal(form.get('expected_ref_tip'), f.before); assert.equal(form.get('at_commit'), f.base); assert.equal(form.get('offset'), '65536');
  await click(v.nodes.paging, 'Previous file range'); assert.equal(v.calls.at(-1).form.get('offset'), '0');
});
