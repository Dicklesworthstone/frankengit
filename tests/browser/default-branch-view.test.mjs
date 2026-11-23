import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { DEFAULT_BRANCH_RECEIPT_LIMIT } from '../../crates/fgit-node/src/smart_http/server/browser/default-branch.mjs';
import { readDefaultBranchReceipt } from '../../crates/fgit-node/src/smart_http/server/browser/default-branch-view.mjs';
import { token, hex, tip, observation, page, row, publication, outcome, json, view, html, deferred } from './default-branch-fixtures.mjs';

for (const algorithm of ['sha1', 'sha256']) test(algorithm + ': controller previews exact expectations and sends only after separate confirmation', async () => {
  const s = view(); await s.ready(algorithm); assert.equal(s.calls.length, 2); assert.equal(s.get('token').value, '');
  assert.ok(s.get('snapshot').textContent.includes('existing default branch')); await s.get('prepare').fire();
  const pending = s.client.pending; assert.equal(s.calls.length, 2); assert.equal(s.get('selected').disabled, true);
  for (const value of [pending.key, hex('refs/heads/main'), hex('refs/heads/topic'), tip(algorithm, 'b')]) assert.ok(s.get('pending').textContent.includes(value));
  await s.get('send').fire(); assert.equal(s.calls.length, 2); assert.match(s.get('status').textContent, /Confirm/);
  s.responses.push(json(publication(pending))); s.get('confirm-send').checked = true; await s.get('send').fire();
  assert.equal(s.calls.length, 3); assert.equal(s.client.pending, null); assert.equal(s.client.observed, null);
  assert.equal(s.get('confirm-send').checked, false); assert.match(s.get('status').textContent, /Canonical committed/);
  assert.match(s.get('status').textContent, /original decision/); assert.match(s.get('terminal').textContent, /rcr-original/);
});

test('absent and unborn defaults are displayed distinctly and never default to main', async () => {
  for (const absent of [true, false]) {
    const s = view(); await s.ready('sha1', observation('sha1', { default_reference_hex: absent ? null : hex('refs/heads/not-created'), tip: null, unborn: !absent }));
    assert.match(s.get('snapshot').textContent, absent ? /absent symbolic target/ : /named unborn target/);
    await s.get('prepare').fire(); const p = s.client.pending;
    assert.equal(p.command.expected_default_hex ?? null, absent ? null : hex('refs/heads/not-created'));
    assert.equal(p.command.expect_no_default ?? false, absent);
  }
});

test('hostile and byte-only branch names remain inert and raw-byte candidates work in the view', async () => {
  const raw = { ref: null, ref_hex: hex('refs/heads/z') + 'ff', object_id: tip('sha1', 'd') };
  const rows = [row('refs/heads/<script>'), row('refs/heads/a\u202eb'), raw];
  const s = view(); await s.ready('sha1', observation(), page('sha1', { refs: rows }));
  assert.ok(s.get('refs').textContent.includes('<script>')); assert.ok(s.get('refs').textContent.includes('\\u202e'));
  assert.ok(!s.get('refs').textContent.includes('\u202e')); assert.ok(s.get('refs').textContent.includes(raw.ref_hex));
  assert.equal(s.get('refs').children.every(child => child.tagName === 'LI'), true);
  s.get('selected').value = raw.ref_hex; await s.get('selected').fire('change'); await s.get('prepare').fire();
  assert.equal(s.client.pending.command.reference_hex, raw.ref_hex);
  assert.equal(s.client.pending.command.expected_tip, raw.object_id); assert.ok(s.get('pending').textContent.includes(raw.ref_hex));
});

test('selection changes clear confirmation and a frozen request cannot be replaced by edited controls', async () => {
  const s = view(); await s.ready(); s.get('confirm-send').checked = true;
  await s.get('selected').fire('change'); assert.equal(s.get('confirm-send').checked, false);
  await s.get('prepare').fire(); const p = s.client.pending;
  s.get('selected').value = hex('refs/heads/main'); await s.get('prepare').fire();
  assert.equal(s.client.pending.key, p.key); assert.match(s.get('status').textContent, /original saved request/);
  s.get('confirm-send').checked = true; s.responses.push(json(publication(p))); await s.get('send').fire();
  assert.equal(new URLSearchParams(s.calls.at(-1).body).get('reference_hex'), hex('refs/heads/topic'));
});

test('an uncertain send keeps the frozen request and requires fresh confirmation for an identical retry', async () => {
  const s = view(); await s.ready(); await s.get('prepare').fire(); const p = s.client.pending;
  s.responses.push(new Error('lost response')); s.get('confirm-send').checked = true; await s.get('send').fire();
  assert.equal(s.client.pending.key, p.key); assert.match(s.get('status').textContent, /Outcome unknown/);
  assert.equal(s.get('confirm-send').checked, false); assert.equal(s.get('send').textContent, 'Retry unchanged request');
  await s.get('send').fire(); assert.equal(s.calls.length, 3);
  s.responses.push(json(publication(p))); s.get('confirm-send').checked = true; await s.get('send').fire();
  assert.equal(s.calls[2].body, s.calls[3].body); assert.equal(s.calls[2].headers['Idempotency-Key'], s.calls[3].headers['Idempotency-Key']);
});

test('empty visible branch listings permit observation but never fabricate a selectable candidate', async () => {
  const s = view(); await s.ready('sha1', observation('sha1', { default_reference_hex: null, tip: null }), page('sha1', { refs: [] }));
  assert.equal(s.get('selected').value, ''); assert.equal(s.get('prepare').disabled, true);
  assert.match(s.get('page-state').textContent, /0 branches/); await s.get('prepare').fire();
  assert.equal(s.client.pending, null); assert.equal(s.calls.length, 2);
});

test('recovery receipts restore without network reads or automatic sending and cannot be discarded as unsent', async () => {
  const a = view(); await a.ready(); await a.get('prepare').fire(); const p = a.client.pending;
  await a.get('save').fire(); assert.ok(a.saved()); assert.ok(!a.saved().includes(token)); assert.equal(a.get('discard').disabled, true);
  const s = view(); s.get('token').value = token; await s.get('connect').fire();
  s.get('receipt-file').files = [new Blob([a.saved()])]; await s.get('restore').fire();
  assert.equal(s.calls.length, 0); assert.equal(s.client.pending.key, p.key); assert.equal(s.get('confirm-send').checked, false);
  assert.match(s.get('status').textContent, /without sending/); assert.equal(s.get('discard').disabled, true);
  s.responses.push(json(outcome(p, 'committed'))); await s.get('recover').fire();
  assert.equal(s.calls.length, 1); assert.match(s.calls[0].url, /\/outcomes$/); assert.equal(s.calls[0].body, undefined);
  assert.equal(s.client.pending, null); assert.match(s.get('status').textContent, /Canonical committed/);
});

test('cancel and page exit clear private observations while retaining outstanding recovery responsibility', async () => {
  for (const action of ['cancel', 'disconnect', 'pagehide']) {
    const s = view(); await s.ready(); await s.get('prepare').fire(); const p = s.client.pending;
    s.get('confirm-send').checked = true;
    if (action === 'pagehide') await s.events.fire('pagehide'); else await s.get(action).fire();
    assert.equal(s.client.pending.key, p.key); assert.equal(s.client.observed, null); assert.equal(s.get('refs').textContent, '');
    assert.equal(s.get('confirm-send').checked, false);
    if (action !== 'cancel') { assert.equal(s.client.connected, false); assert.ok(!s.get('pending').textContent.includes(p.key)); assert.equal(s.get('token').value, ''); }
  }
});

test('a cancelled late read never restores repository content or stale status', async () => {
  const s = view(); s.get('token').value = token; await s.get('connect').fire();
  const gate = deferred(); s.responses.push(() => gate.promise);
  const reading = s.get('load').fire(); await Promise.resolve(); await s.get('disconnect').fire();
  gate.resolve(json(observation())); await reading;
  assert.equal(s.client.observed, null); assert.equal(s.get('refs').textContent, ''); assert.match(s.get('status').textContent, /Disconnected/);
});

for (const operation of ['send', 'recover']) test('clearing an observation during ' + operation + ' cannot hide its terminal or lose recovery responsibility', async () => {
  const s = view(); await s.ready(); await s.get('prepare').fire();
  const p = s.client.pending, gate = deferred(); s.responses.push(() => gate.promise);
  s.get('confirm-send').checked = true;
  const running = s.get(operation).fire(); await Promise.resolve();
  assert.equal(s.get('cancel').disabled, true); await s.get('cancel').fire();
  assert.equal(s.client.pending.key, p.key); assert.equal(s.calls.at(-1).signal.aborted, false);
  gate.resolve(json(operation === 'send' ? publication(p) : outcome(p))); await running;
  assert.equal(s.client.pending, null); assert.equal(s.get('cancel').disabled, false);
  assert.match(s.get('terminal').textContent, /rcr-original/); assert.match(s.get('status').textContent, /Canonical committed/);
});

test('failed pins remove candidate choices and cannot silently follow a moved snapshot', async () => {
  const s = view(); await s.ready();
  s.responses.push(json(observation()), json(page('sha1', { snapshot_token: 'alg:1:' + 'f'.repeat(64) })));
  await s.get('load').fire();
  assert.equal(s.client.observed, null); assert.equal(s.get('selected').value, ''); assert.equal(s.get('prepare').disabled, true);
  assert.match(s.get('status').textContent, /Snapshot moved/); assert.equal(s.calls.length, 4);
});

test('current credential rejection clears visible data but keeps any original pending command', async () => {
  const s = view(); await s.ready(); await s.get('prepare').fire(); const p = s.client.pending;
  s.responses.push(json({ error: 'unauthorized' }, 401)); s.get('confirm-send').checked = true; await s.get('send').fire();
  assert.equal(s.client.connected, false); assert.equal(s.client.pending.key, p.key); assert.equal(s.get('refs').textContent, '');
  assert.ok(!s.get('pending').textContent.includes(p.key)); assert.match(s.get('status').textContent, /Outcome unknown/);
});

test('receipt intake is bounded before I/O and rejects stale, truncated or non-UTF8 files', async () => {
  let reads = 0;
  for (const size of [0, -1, NaN, 1.5, DEFAULT_BRANCH_RECEIPT_LIMIT + 1]) {
    await assert.rejects(readDefaultBranchReceipt({ size, arrayBuffer() { reads += 1; } }));
  }
  assert.equal(reads, 0);
  await assert.rejects(readDefaultBranchReceipt({ size: 2, async arrayBuffer() { return new ArrayBuffer(1); } }));
  await assert.rejects(readDefaultBranchReceipt(new Blob([new Uint8Array([255])])));
  let current = true;
  await assert.rejects(readDefaultBranchReceipt({ size: 1, async arrayBuffer() { current = false; return new ArrayBuffer(1); } }, () => current));
});

test('receipt file chosen before disconnect cannot become a late restored request', async () => {
  const a = view(); await a.ready(); await a.get('prepare').fire(); await a.get('save').fire();
  const bytes = new TextEncoder().encode(a.saved()), gate = deferred(), s = view();
  s.get('token').value = token; await s.get('connect').fire();
  s.get('receipt-file').files = [{ size: bytes.length, arrayBuffer: () => gate.promise }];
  const restoring = s.get('restore').fire(); await Promise.resolve(); await s.get('disconnect').fire();
  gate.resolve(bytes.buffer); await restoring;
  assert.equal(s.client.pending, null); assert.equal(s.calls.length, 0); assert.match(s.get('status').textContent, /Disconnected/);
});

test('leaving a pending request warns and the shell states the separate native administrator boundary', async () => {
  const s = view(); await s.ready(); let warned = false;
  s.events.listeners.get('beforeunload')({ preventDefault() { warned = true; } }); assert.equal(warned, false);
  await s.get('prepare').fire(); s.events.listeners.get('beforeunload')({ preventDefault() { warned = true; } }); assert.equal(warned, true);
  assert.match(html, /default-branch-write/); assert.match(html, /installed current administrator policy/); assert.match(html, /Initial administrator setup is local/);
  assert.ok(!html.includes('<script>'));
  for (const name of ['default-branch.mjs', 'default-branch-view.mjs']) {
    const source = readFileSync(new URL('../../crates/fgit-node/src/smart_http/server/browser/' + name, import.meta.url), 'utf8');
    for (const prohibited of ['innerHTML', 'localStorage', 'sessionStorage', 'document.write']) assert.ok(!source.includes(prohibited));
  }
});
