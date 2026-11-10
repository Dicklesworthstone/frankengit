import test from 'node:test';
import assert from 'node:assert/strict';
import { writeFile, readFile, readdir, rm, rename, mkdir, chmod, symlink, link } from 'node:fs/promises';
import { join } from 'node:path';
import { exportDiscussionArchive, inspectDiscussionArchive, readDiscussionArchive }
  from '../../scripts/lib/forge-discussion-archive.mjs';
import { recordDigest } from '../../scripts/lib/forge-operator-io.mjs';
import { fixture, data, event, actor, other, head, token, encode, noRoot, mutateRoot } from './discussion-archive-fixture.mjs';

test('real HTTP capture retains every action, raw comment and final lock/close state at one head', async t => {
  const f = await fixture(t), result = await exportDiscussionArchive(f.options);
  assert.deepEqual([result.discussions, result.events, result.pages, result.requests], [2, 13, 15, 15]);
  assert.equal(result.complete, true); assert.equal(result.canonical_backup, false);
  assert.equal(result.restore_authority, false); assert.equal(result.mutation_submitted, false);
  const view = await readDiscussionArchive({ workdir: f.options.workdir, confirm: result.archive_sha256 });
  assert.equal(view.archive.archive_sha256, result.archive_sha256);
  assert.equal(view.archive.network_accessed, false); assert.equal(view.archive.local_read_only, true);
  assert.deepEqual(view.records, data().map(row => ({ snapshot: row.discussion, events: row.events })));
  assert.ok(view.records[0].snapshot.locked); assert.equal(view.records[0].snapshot.state, 'closed');
  assert.equal(f.calls.length, 15);
  for (const name of await readdir(f.options.workdir)) assert.ok(!(await readFile(join(f.options.workdir, name), 'utf8')).includes(token));
  assert.deepEqual(f.calls.filter(row => row.url.pathname.endsWith('/discussions')).map(row => row.url.searchParams.get('after')), ['0', '1']);
  assert.deepEqual(f.calls.filter(row => row.url.pathname.endsWith('/discussions/1')).map(row => row.url.searchParams.get('after_version')),
    Array.from({ length: 12 }, (_, index) => String(index)));
});
test('an empty discussion namespace produces a complete one-page archive', async t => {
  const f = await fixture(t, { items: [] }), result = await exportDiscussionArchive(f.options);
  assert.deepEqual([result.discussions, result.events, result.pages], [0, 0, 1]);
  assert.deepEqual((await readDiscussionArchive({ workdir: f.options.workdir, confirm: result.archive_sha256 })).records, []);
});
test('explicit initial head is sent on every read and repeated captures have identical commitments', async t => {
  const f = await fixture(t), first = await exportDiscussionArchive({ ...f.options, head });
  const second = await exportDiscussionArchive({ ...f.options, head, workdir: join(f.parent, 'second') });
  assert.ok(f.calls.every(row => row.url.searchParams.get('expected_head') === head));
  assert.equal(first.archive_sha256, second.archive_sha256);
});
for (const state of ['open', 'closed']) for (const locked of [false, true]) {
  test(`final ${state}/locked=${locked} survives replay across individual event pages`, async t => {
    const item = data()[1]; item.discussion.number = 1;
    if (state === 'closed') item.events.push(event(item.events.length + 1, other, 'close'));
    if (locked) item.events.push(event(item.events.length + 1, other, 'lock'));
    Object.assign(item.discussion, { state, locked, version: item.events.length });
    const f = await fixture(t, { items: [item] }), result = await exportDiscussionArchive(f.options);
    const { records } = await readDiscussionArchive({ workdir: f.options.workdir, confirm: result.archive_sha256 });
    assert.deepEqual(records[0], { snapshot: item.discussion, events: item.events });
  });
}
for (const [name, actions, final, pattern] of [
  ['comment while locked', ['lock', 'comment'], { locked: true, comments: 1 }, /comment_while_locked/],
  ['repeat lock', ['lock', 'lock'], { locked: true }, /invalid_lock_transition/],
  ['unlock while unlocked', ['unlock'], {}, /invalid_lock_transition/],
  ['repeat close', ['close', 'close'], { state: 'closed' }, /invalid_state_transition/],
  ['reopen while open', ['reopen'], {}, /invalid_state_transition/],
]) test(`cross-page replay rejects ${name} even when single-page schemas permit it`, async t => {
  const item = data()[1]; item.discussion.number = 1;
  for (const name of actions) item.events.push(event(item.events.length + 1, other, name,
    name === 'comment' ? { body: 'Invalid transition' } : {}));
  Object.assign(item.discussion, final, { version: item.events.length });
  const f = await fixture(t, { items: [item] });
  await assert.rejects(exportDiscussionArchive(f.options), pattern); await noRoot(f.options);
});
for (const [name, change, pattern] of [
  ['foreign repository', b => { b.repository_id = '9'.repeat(32); }, /identity changed/],
  ['wrong namespace', b => { b.scope = 'repository_issues'; }, /profile/],
  ['mixed snapshot', (b, n) => { if (n === 2) b.snapshot_token = 'alg:2:' + '7'.repeat(64); }, /snapshot moved/i],
  ['mixed source head', (b, n) => { if (n === 2) b.source_head = 'other-head'; }, /source_head_changed/],
  ['missing listed discussion', (b, n) => { if (n === 2) { b.found = false; b.discussion = null; b.events = []; b.next_after_version = null; } }, /list_history_disagreement/],
  ['version gap', (b, n) => { if (n === 3) b.events[0].version++; }, /version gap/],
  ['truncated history', (b, n) => { if (n === 2) b.next_after_version = null; }, /Incomplete discussion history/],
  ['changed listed state', (b, n) => { if (n === 2) b.discussion.title += '!'; }, /list_history_disagreement/],
  ['wrong comment count', b => { if (b.type === 'discussion_page') b.discussions[0].comments = 0; else b.discussion.comments = 0; }, /history_state_disagreement/],
  ['wrong lock state', b => { if (b.type === 'discussion_page') b.discussions[0].locked = false; else b.discussion.locked = false; }, /history_state_disagreement/],
  ['wrong final body', (b, n) => { if (n === 5) b.events[0].action.body = 'substitution'; }, /history_state_disagreement/],
  ['wrong opening actor', (b, n) => { if (n === 2) b.events[0].actor = other; }, /history_state_disagreement/],
  ['invalid continuation', b => { if (b.type === 'discussion_page' && b.after > 0) b.discussions[0].number = 1; }, /ordering/],
]) test(`${name} refuses without publishing a complete root`, async t => {
  const f = await fixture(t, { change }); await assert.rejects(exportDiscussionArchive(f.options), pattern); await noRoot(f.options);
});
for (const status of [401, 403, 404, 409, 413, 429, 503]) test(`HTTP ${status} never becomes an empty archive or automatic retry`, async t => {
  const f = await fixture(t, { handle: async (_req, res) => {
    res.writeHead(status, { 'Content-Type': 'application/json' }); res.end('{}'); return true;
  } });
  await assert.rejects(exportDiscussionArchive(f.options)); assert.equal(f.calls.length, 1); await noRoot(f.options);
});
for (const [option, value, pattern] of [
  ['maxRequests', 2, /request_limit/], ['maxDiscussions', 1, /discussion_limit/],
  ['maxEvents', 11, /event_limit/], ['maxReadBytes', 1, /read_limit/], ['maxArchiveBytes', 1, /archive_limit/],
]) test(`${option} limits the whole archive rather than accepting a prefix`, async t => {
  const f = await fixture(t); await assert.rejects(exportDiscussionArchive({ ...f.options, [option]: value }), pattern);
  await noRoot(f.options);
  if (option === 'maxRequests') assert.equal(f.calls.length, 2);
  if (option === 'maxEvents') assert.equal(f.calls.length, 1, 'declared history must be bounded before its first request');
});
test('exact byte/request budgets succeed while a one-byte-short archive budget refuses', async t => {
  const f = await fixture(t), captured = await exportDiscussionArchive(f.options);
  const size = captured.data_bytes + (await readFile(join(f.options.workdir, 'archive.json'))).length;
  const options = { ...f.options, maxRequests: captured.requests, maxReadBytes: captured.read_bytes, maxArchiveBytes: size, head };
  assert.equal((await exportDiscussionArchive({ ...options, workdir: join(f.parent, 'exact') })).complete, true);
  await assert.rejects(exportDiscussionArchive({ ...options, workdir: join(f.parent, 'short'), maxArchiveBytes: size - 1 }), /archive_limit/);
});
test('large escaped bodies refuse oversized pages and work with smaller complete pages', async t => {
  const body = '\u0001'.repeat(64 * 1024), item = data()[1]; item.discussion.number = 1;
  item.events = [event(1, other, 'open', { title: item.discussion.title, body }),
    event(2, other, 'comment', { body }), event(3, other, 'edit', { body })];
  Object.assign(item.discussion, { version: 3, body, comments: 1 });
  const f = await fixture(t, { items: [item] });
  await assert.rejects(exportDiscussionArchive({ ...f.options, pageSize: 3 }), /read_limit/); await noRoot(f.options);
  const result = await exportDiscussionArchive({ ...f.options, head, workdir: join(f.parent, 'small') });
  assert.equal(result.events, 3); assert.equal(result.pages, 4);
  assert.equal((await readDiscussionArchive({ workdir: result.workdir, confirm: result.archive_sha256 })).records[0].events[1].action.body, body);
});
test('offline inspection works after the source and original credential disappear without changing files', async t => {
  const f = await fixture(t), result = await exportDiscussionArchive(f.options);
  const names = await readdir(result.workdir), before = await Promise.all(names.map(name => readFile(join(result.workdir, name))));
  await rm(f.options.tokenFile); f.server.closeAllConnections();
  await new Promise(resolve => f.server.close(resolve));
  const checked = await inspectDiscussionArchive({ workdir: result.workdir, confirm: result.archive_sha256 });
  assert.equal(checked.network_accessed, false); assert.equal(checked.local_read_only, true);
  assert.equal(checked.complete, true); assert.equal(f.calls.length, 15);
  for (const [index, name] of names.entries()) assert.deepEqual(await readFile(join(result.workdir, name)), before[index]);
});
test('independent root pin is required before inspection accepts any page', async t => {
  const f = await fixture(t); await exportDiscussionArchive(f.options);
  await assert.rejects(inspectDiscussionArchive({ workdir: f.options.workdir, confirm: '0'.repeat(64) }), /pin_mismatch/);
});
for (const what of ['changed', 'missing', 'extra', 'symlink', 'hardlink', 'public']) test(`offline ${what} page refuses`, async t => {
  const f = await fixture(t), result = await exportDiscussionArchive(f.options), path = join(result.workdir, 'page-000002.json');
  if (what === 'changed') await writeFile(path, '{}\n');
  if (what === 'missing') await rm(path);
  if (what === 'extra') await writeFile(join(result.workdir, 'unexpected'), '{}', { mode: 0o600 });
  if (what === 'symlink') { const target = join(f.parent, 'saved'); await rename(path, target); await symlink(target, path); }
  if (what === 'hardlink') await link(path, join(f.parent, 'linked'));
  if (what === 'public') await chmod(path, 0o644);
  await assert.rejects(inspectDiscussionArchive({ workdir: result.workdir, confirm: result.archive_sha256 }));
});
for (const [name, edit] of [
  ['page order', m => { [m.pages[1], m.pages[2]] = [m.pages[2], m.pages[1]]; }],
  ['discussion count', m => { m.discussion_count--; }], ['event count', m => { m.event_count--; }],
  ['source head', m => { m.source_head = 'different'; }], ['page size', m => { m.page_size++; }],
]) test(`recomputed manifest hashes cannot conceal changed ${name}`, async t => {
  const f = await fixture(t); await exportDiscussionArchive(f.options);
  const confirm = await mutateRoot(f.options, edit);
  await assert.rejects(inspectDiscussionArchive({ workdir: f.options.workdir, confirm }));
});
test('recomputed page/root hashes do not conceal a cross-page history/state contradiction', async t => {
  const f = await fixture(t); await exportDiscussionArchive(f.options);
  const path = join(f.options.workdir, 'page-000005.json'), page = JSON.parse(await readFile(path));
  page.events[0].action.body = 'Replaced body'; const bytes = encode(page); await writeFile(path, bytes);
  const confirm = await mutateRoot(f.options, m => {
    m.pages[4][2] = recordDigest(bytes); m.data_bytes += bytes.length - m.pages[4][3]; m.pages[4][3] = bytes.length;
  });
  await assert.rejects(readDiscussionArchive({ workdir: f.options.workdir, confirm }), /history_state_disagreement/);
});
test('noncanonical duplicate-key root refuses even under its newly supplied hash', async t => {
  const f = await fixture(t); await exportDiscussionArchive(f.options);
  const path = join(f.options.workdir, 'archive.json');
  const bytes = Buffer.from((await readFile(path, 'utf8')).replace('"page_size":1', '"page_size":2,"page_size":1'));
  await writeFile(path, bytes);
  await assert.rejects(inspectDiscussionArchive({ workdir: f.options.workdir, confirm: recordDigest(bytes) }), /encoding/);
});
test('existing and competing destinations never overwrite or trigger a second successful acquisition', async t => {
  const f = await fixture(t), results = await Promise.allSettled([exportDiscussionArchive(f.options), exportDiscussionArchive(f.options)]);
  assert.equal(results.filter(row => row.status === 'fulfilled').length, 1); assert.equal(f.calls.length, 15);
  await assert.rejects(exportDiscussionArchive(f.options), /record_exists/); assert.equal(f.calls.length, 15);
});
test('pre-cancellation creates no archive directory and starts no read', async t => {
  const f = await fixture(t), stop = new AbortController(); stop.abort();
  await assert.rejects(exportDiscussionArchive({ ...f.options, signal: stop.signal })); assert.equal(f.calls.length, 0);
  await assert.rejects(readdir(f.options.workdir), { code: 'ENOENT' });
});
test('cancellation drains a real stalled body and never seals the incomplete capture', async t => {
  const stop = new AbortController(); let closed;
  const closure = new Promise(resolve => { closed = resolve; });
  const f = await fixture(t, { handle: async (req, res) => {
    req.on('close', closed); res.writeHead(200, { 'Content-Type': 'application/json' }); res.write('{');
    setTimeout(() => stop.abort(), 20); return true;
  } });
  await assert.rejects(exportDiscussionArchive({ ...f.options, signal: stop.signal }));
  await Promise.race([closure, new Promise((_, reject) => setTimeout(() => reject(new Error('HTTP not drained')), 2000).unref())]);
  assert.equal(f.calls.length, 1); await noRoot(f.options);
});
test('whole-operation deadline terminates a stalled response without a new head or retry', async t => {
  const f = await fixture(t, { handle: async (_req, res) => {
    res.writeHead(200, { 'Content-Type': 'application/json' }); res.write('{'); return true;
  } });
  await assert.rejects(exportDiscussionArchive({ ...f.options, timeoutMs: 100 })); await noRoot(f.options);
  assert.ok(f.calls.length <= 1);
});
test('directory replacement between pages refuses before saving into substituted custody', async t => {
  const f = await fixture(t, { change: async (_b, n, { parent }) => {
    if (n === 2) { await rename(join(parent, 'archive'), join(parent, 'original')); await mkdir(join(parent, 'archive'), { mode: 0o700 }); }
  } });
  await assert.rejects(exportDiscussionArchive(f.options), /directory_changed_or_unsafe/); await noRoot(f.options);
  assert.deepEqual(await readdir(f.options.workdir), []);
});
test('the entire capture is read back before root publication, including earlier pages', async t => {
  const f = await fixture(t, { change: async (_body, n, { parent }) => {
    if (n === 15) await writeFile(join(parent, 'archive', 'page-000002.json'), '{}\n');
  } });
  await assert.rejects(exportDiscussionArchive(f.options), /page_commitment/); await noRoot(f.options);
});
test('closed option/profile grammar fails before filesystem or credential access', async () => {
  const base = { workdir: '/not-present/output', href: 'https://forge.example/repo/ui/discussions/',
    tenant: '1'.repeat(32), repository: '2'.repeat(32), tokenFile: '/not-present/token' };
  for (const more of [{ pageSize: 0 }, { maxRequests: 8193 }, { maxDiscussions: 0 }, { maxEvents: -1 },
    { unknown: true }, { head: 'bad' }, { href: 'https://forge.example/repo/ui/issues/' },
    { href: 'http://forge.example/repo/ui/discussions/' }, { href: base.href + '?token=x' }]) {
    await assert.rejects(exportDiscussionArchive({ ...base, ...more }), error => error.code !== 'ENOENT');
  }
  await assert.rejects(inspectDiscussionArchive({ workdir: base.workdir, confirm: '0'.repeat(64), tokenFile: base.tokenFile }), /fields/);
});
