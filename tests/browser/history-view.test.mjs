// DOM/fetch doubles test the shipped controller and real validators, not a live node.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { mountHistory, bytePreview } from '../../crates/fgit-node/src/smart_http/server/browser/history-view.mjs';
import { fixture, token, crypto, href, bytes, hex, hash, json, deferred } from './history-fixtures.mjs';
const base = '../../crates/fgit-node/src/smart_http/server/browser/';
const html = readFileSync(new URL(`${base}history.html`, import.meta.url), 'utf8');
class Element {
  constructor(tag = 'div') { this.tagName = tag; this.children = []; this.listeners = new Map(); this.value = ''; this.disabled = false; this._text = ''; }
  set textContent(value) { this._text = String(value); this.children = []; }
  get textContent() { return this._text + this.children.map(child => child.textContent).join(''); }
  set innerHTML(_) { assert.fail('Executable HTML sink'); }
  append(...children) { this.children.push(...children); }
  replaceChildren(...children) { this.children = children; this._text = ''; }
  addEventListener(name, handler) { if (!this.listeners.has(name)) this.listeners.set(name, []); this.listeners.get(name).push(handler); }
  async fire(name) { await Promise.all((this.listeners.get(name) ?? []).map(handler => handler({ preventDefault() {} }))); }
}
const descendants = root => [root, ...root.children.flatMap(descendants)];
function buttons(root, label) { return descendants(root).filter(node => node.tagName === 'button' && node.textContent.includes(label)); }
function one(root, label) { const result = buttons(root, label); assert.equal(result.length, 1, `${label}: expected one button`); return result[0]; }
function harness(f = fixture()) {
  const elements = new Map([...html.matchAll(/<([a-z]+)\b[^>]*\bid="([^"]+)"[^>]*>/g)].map(match => {
    const node = new Element(match[1]); node.value = /\bvalue="([^"]*)"/.exec(match[0])?.[1] ?? ''; return [match[2], node];
  }));
  const get = name => { const value = elements.get(`history-${name}`); assert.ok(value, `missing ${name}`); return value; };
  get('format').value = f.algorithm; get('path-kind').value = 'text'; get('ref').value = f.ref;
  const events = new Element('window'), downloads = [], doc = { body: new Element('body'), createElement: tag => new Element(tag), getElementById: id => elements.get(id) };
  const view = mountHistory(doc, { href, fetchImpl: f.fetchImpl, cryptoImpl: crypto, events, download: data => downloads.push(data) });
  return { ...view, get, f, downloads, events, elements,
    async connect() { get('token').value = token; await get('connect').fire('submit'); },
    async blame() { get('path-kind').value = 'hex'; get('path').value = f.path; await get('blame').fire('click'); },
  };
}
for (const algorithm of ['sha1', 'sha256']) {
  test(`${algorithm}: connect displays checked history and clears the credential input`, async () => {
    const h = harness(fixture(algorithm)); await h.connect();
    assert.equal(h.get('token').value, ''); assert.equal(h.get('log').disabled, false);
    assert.ok(h.get('content').textContent.includes(h.f.tip.object_id)); assert.ok(h.get('snapshot').textContent.includes(h.f.head));
    assert.match(h.get('content').textContent, /author identities are not authenticated/);
    assert.equal(h.f.calls[0].endpoint, 'log'); assert.equal(h.f.calls[0].options.method, 'POST');
  });
  test(`${algorithm}: history -> old tree -> exact old file retains current ref selection`, async () => {
    const h = harness(fixture(algorithm)); await h.connect();
    await buttons(h.get('content'), 'Browse this commit tree')[1].fire('click');
    assert.equal(h.f.calls.at(-1).form.get('at_commit'), h.f.base.object_id);
    await one(h.get('content'), '[hex:66696c65]').fire('click');
    assert.equal(h.f.calls.at(-1).endpoint, 'historical-blob');
    assert.ok(h.get('content').textContent.includes('one\\u{d}\ntwo'));
    assert.ok(h.get('snapshot').textContent.includes(h.f.tip.object_id));
    assert.equal(h.client.selection.tip, h.f.tip.object_id);
  });
  test(`${algorithm}: blame origin navigation verifies the attributed historical bytes`, async () => {
    const h = harness(fixture(algorithm)); await h.connect(); await h.blame();
    assert.match(h.get('content').textContent, /Complete-file blob identity checked/);
    await one(h.get('content'), `Verify origin ${h.f.base.object_id.slice(0, 12)}:1`).fire('click');
    assert.match(h.get('status').textContent, /Exact attributed origin bytes checked/);
    assert.equal(h.f.calls.at(-1).form.get('offset'), '5'); assert.equal(h.f.calls.at(-1).form.get('limit'), '3');
    assert.ok(h.get('content').textContent.includes('two'));
    await one(h.get('content'), 'Open origin file from beginning').fire('click');
    assert.equal(h.f.calls.at(-1).form.get('offset'), '0'); assert.equal(h.f.calls.at(-1).form.get('at_commit'), h.f.base.object_id);
  });
}
test('history continuation retains the applied path, limit and snapshot after form edits', async () => {
  const h = harness(); await h.connect(); h.get('limit').value = '1'; h.get('path').value = 'file';
  await h.get('query').fire('submit'); h.get('limit').value = '100'; h.get('path').value = 'other'; h.get('ref').value = 'refs/heads/other';
  await one(h.get('paging'), 'Next history page').fire('click');
  const form = h.f.calls.at(-1).form;
  assert.equal(form.get('path_hex'), h.f.path); assert.equal(form.get('limit'), '1'); assert.equal(form.get('after'), '1');
  assert.equal(form.get('expected_head'), h.f.head); assert.equal(form.get('ref'), h.f.ref);
  assert.match(h.get('content').textContent, /Exact path history: file/);
});
test('narrow blame ranges do not claim complete-file verification', async () => {
  const h = harness(); await h.connect(); h.get('first').value = '1'; h.get('end').value = '2'; await h.blame();
  assert.match(h.get('content').textContent, /Partial range: no complete-file blob hash claim/);
  assert.equal(h.f.calls.at(-1).form.get('line_start'), '1'); assert.equal(h.f.calls.at(-1).form.get('line_end'), '2');
});
test('raw path bytes survive directory labels and historical navigation', async () => {
  const h = harness(fixture('sha1', '66ff')); await h.connect(); await h.historical('tree', h.f.base.object_id);
  assert.match(h.get('content').textContent, /Raw hex bytes/);
  await one(h.get('content'), '[hex:66ff]').fire('click'); assert.equal(h.f.calls.at(-1).form.get('path_hex'), '66ff');
});
test('directory and file continuations retain original historical coordinates', async () => {
  const h = harness(); await h.connect();
  h.f.config.mutate = (value, call) => { if (call.endpoint === 'historical-tree' && !call.form.has('after_hex')) value.source.next_after_hex = h.f.path; };
  await h.historical('tree', h.f.base.object_id, null, { limit: 1 });
  await one(h.get('paging'), 'Next directory page').fire('click');
  assert.equal(h.f.calls.at(-1).form.get('after_hex'), h.f.path); assert.equal(h.f.calls.at(-1).form.get('at_commit'), h.f.base.object_id);
  h.f.config.mutate = null; await h.historical('blob', h.f.base.object_id, h.f.path, { limit: 3 });
  assert.match(h.get('content').textContent, /Bytes \[0, 3\) of 8/);
  await one(h.get('paging'), 'Next file range').fire('click');
  assert.equal(h.f.calls.at(-1).form.get('offset'), '3'); assert.equal(h.f.calls.at(-1).form.get('limit'), '3');
  assert.equal(h.f.calls.at(-1).form.get('expected_ref_tip'), h.f.tip.object_id);
});
test('historical symlinks display payloads and gitlinks cannot be followed', async () => {
  const h = harness(); await h.connect();
  h.f.config.mutate = value => { value.source.entries[0].kind = 'gitlink'; };
  await h.historical('tree', h.f.base.object_id);
  assert.match(h.get('content').textContent, /gitlink not followed/); assert.equal(buttons(h.get('content'), '[hex:').length, 0);
  h.f.config.mutate = value => { value.source.kind = 'symlink'; };
  await h.historical('blob', h.f.base.object_id, h.f.path);
  assert.match(h.get('content').textContent, /Symlink payload only; never followed/);
});
test('hostile commit text and directional controls remain inert text, not HTML', async () => {
  const h = harness();
  h.f.config.mutate = value => {
    const row = value.commits[0], body = Buffer.concat([Buffer.from(row.body_hex, 'hex'), bytes('<img src=x onerror=alert(1)>\u202e')]);
    row.body_hex = hex(body); row.object_id = hash('commit', body); value.source_commit = row.object_id;
  };
  await h.connect(); const content = h.get('content');
  assert.ok(content.textContent.includes('<img src=x onerror=alert(1)>')); assert.ok(content.textContent.includes('\\u{202e}'));
  assert.ok(!descendants(content).some(node => ['img', 'script', 'iframe'].includes(node.tagName)));
});
test('clipped previews say so and downloading retains the complete validated response', async () => {
  assert.match(bytePreview(hex(bytes('abcdefgh')), 3), /Preview clipped at 3 of 8 bytes/);
  const h = harness(); await h.connect(); await h.get('download').fire('click');
  assert.equal(h.downloads.length, 1); const raw = JSON.parse(h.downloads[0]); assert.equal(raw.commits[0].body_hex, h.f.tip.body_hex);
  assert.ok(!h.downloads[0].includes(token)); h.disconnect(); await h.get('download').fire('click'); assert.equal(h.downloads.length, 1);
});
test('an empty path result is not called an empty repository', async () => {
  const h = harness(); await h.connect(); h.get('path').value = 'absent'; await h.get('query').fire('submit');
  assert.match(h.get('content').textContent, /0 matching-path commits/); assert.match(h.get('content').textContent, /No matching commits/);
  assert.ok(!h.get('content').textContent.includes('empty repository'));
});
test('bad forms and native conflicts clear stale views rather than showing fake results', async () => {
  const h = harness(); await h.connect(); h.get('path').value = '../secret'; await h.get('blame').fire('click');
  assert.equal(h.get('content').textContent, ''); assert.equal(h.f.calls.length, 1); assert.match(h.get('status').textContent, /Invalid repository path/);
  h.get('path').value = 'file'; h.get('first').value = '1.5'; await h.get('blame').fire('click'); assert.equal(h.f.calls.length, 1);
  h.f.config.respond = () => json({}, 409); await h.log({});
  assert.equal(h.get('content').textContent, ''); assert.match(h.get('status').textContent, /conflict/); assert.equal(h.get('download').disabled, true);
});
test('origin byte disagreement is an error, not an apparently successful source view', async () => {
  const h = harness(); await h.connect(); await h.blame();
  h.f.config.mutate = value => { value.source.content_hex = hex(bytes('bad')); };
  await one(h.get('content'), `Verify origin ${h.f.base.object_id.slice(0, 12)}:1`).fire('click');
  assert.match(h.get('status').textContent, /does not reproduce/); assert.equal(h.get('content').textContent, '');
});
test('cancelled or replaced reads cannot resurrect stale UI', async () => {
  const h = harness(); await h.connect(); const pending = deferred(); h.f.config.respond = () => pending.promise;
  const reading = h.log({}); await h.get('cancel').fire('click'); pending.resolve(json(h.f.log(new URLSearchParams()))); await reading;
  assert.match(h.get('status').textContent, /Read cancelled/); assert.equal(h.get('content').textContent, '');
  assert.equal(h.client.selection.tip, h.f.tip.object_id);
  const later = deferred(); h.f.config.respond = () => later.promise; const old = h.log({});
  h.f.config.respond = null; await h.log({ path_hex: '616273656e74' }); later.resolve(json(h.f.log(new URLSearchParams()))); await old;
  assert.match(h.get('content').textContent, /No matching commits/);
});
test('pagehide and current auth refusal clear private selection and inputs', async () => {
  const h = harness(); await h.connect(); h.get('path').value = 'private/file'; await h.events.fire('pagehide');
  for (const id of ['token', 'path', 'ref']) assert.equal(h.get(id).value, '');
  assert.equal(h.get('snapshot').textContent, ''); assert.equal(h.get('content').textContent, ''); assert.equal(h.client.connected, false);
  h.get('ref').value = h.f.ref; await h.connect(); h.get('path').value = 'private';
  h.f.config.respond = () => json({}, 401); await h.log({}); assert.equal(h.client.connected, false);
  assert.equal(h.get('path').value, ''); assert.equal(h.get('snapshot').textContent, '');
});
test('detached buttons from an obsolete view cannot trigger another network read', async () => {
  const h = harness(); await h.connect(); const old = buttons(h.get('content'), 'Browse this commit tree')[0];
  await h.log({ path_hex: '616273656e74' }); const count = h.f.calls.length; await old.fire('click'); assert.equal(h.f.calls.length, count);
});
test('shipped HTML, static routes and all imported modules are wired without executable interpolation', () => {
  const rust = readFileSync(new URL(`${base}history.rs`, import.meta.url), 'utf8');
  for (const name of ['history.mjs', 'history-data.mjs', 'history-view.mjs', 'pulls-core.mjs', 'pulls-candidate.mjs']) {
    assert.ok(rust.includes(`/ui/history/${name}`)); assert.ok(rust.includes(`include_str!("${name}")`));
  }
  assert.ok(html.includes('src="./history-view.mjs"')); assert.ok(html.includes('href="../browser.css"'));
  assert.ok(!html.includes('<script>'));
  for (const name of ['history.mjs', 'history-data.mjs', 'history-view.mjs']) {
    const script = readFileSync(new URL(`${base}${name}`, import.meta.url), 'utf8');
    for (const forbidden of ['innerHTML', 'localStorage', 'sessionStorage', 'document.write']) assert.ok(!script.includes(forbidden));
    for (const imported of script.matchAll(/from '\.\/([^']+)'/g)) assert.ok(rust.includes(`/ui/history/${imported[1]}`));
  }
  const parent = readFileSync(new URL(`${base}../browser.rs`, import.meta.url), 'utf8');
  assert.ok(parent.includes('mod history;')); assert.ok(parent.includes('history::serve(profile, request, trailing, writer)?'));
  assert.ok(rust.includes('profile.allow_source')); assert.ok(!rust.includes('profile.allow_receive'));
});

test('large verified blame results use bounded local row pages without widening the native read', async () => {
  const f = fixture(), content = bytes('new\n'.repeat(201)), blob = hash('blob', content);
  const tree = hash('tree', Buffer.concat([bytes('100644 file\0'), Buffer.from(blob, 'hex')]));
  const body = bytes(`tree ${tree}\nparent ${f.base.object_id}\nauthor A <a@invalid> 1 +0000\ncommitter A <a@invalid> 1 +0000\n\nlarge blame fixture\n`);
  Object.assign(f.tip, { tree, object_id: hash('commit', body), body_hex: hex(body) }); f.common.source_commit = f.tip.object_id;
  f.config.mutate = (value, call) => {
    if (call.endpoint !== 'blame') return;
    Object.assign(value, { blob, tree, total_lines: 201, first_line: 0, end_line: 201, content_byte_start: 0, content_hex: hex(content),
      origins: [structuredClone(f.tip)], lines: Array.from({ length: 201 }, (_, line) => ({ line, byte_start: line * 4, byte_end: (line + 1) * 4,
        origin_commit: f.tip.object_id, origin_blob: blob, origin_line: line, origin_byte_start: line * 4, origin_byte_end: (line + 1) * 4 })) });
  };
  const h = harness(f); await h.connect(); await h.blame();
  assert.equal(buttons(h.get('content'), 'Verify origin').length, 200); const requests = f.calls.length;
  await one(h.get('paging'), 'Next blame rows').fire('click');
  assert.equal(buttons(h.get('content'), 'Verify origin').length, 1); assert.equal(f.calls.length, requests);
  assert.match(h.get('status').textContent, /Displaying 200–201 of 201/);
  await one(h.get('paging'), 'Previous blame rows').fire('click'); assert.equal(buttons(h.get('content'), 'Verify origin').length, 200);
});
