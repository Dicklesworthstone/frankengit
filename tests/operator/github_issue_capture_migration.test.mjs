import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, writeFile, readFile, readdir, rename, mkdir, rm, symlink, link, lstat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { captureGithubIssueMigration as run } from '../../scripts/lib/github-issue-capture-migration.mjs';
import { createGithubIssueCaptureSession, captureGithubIssues, parseCapture, issueImportSteps } from '../../scripts/lib/github-issue-source.mjs';
import { issueInventoryBytes, INVENTORY_SCHEMA } from '../../scripts/lib/github-issue-inventory.mjs';
import { recordDigest } from '../../scripts/lib/forge-operator-io.mjs';
import { repository, repositoryId, issueId, issue, json, githubPeer } from './fixtures/github_capture_source.mjs';

async function fixture(t, count = 2, size = 1, extra = {}) {
  const root = await mkdtemp(join(tmpdir(), 'fg-capture-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const inventoryFile = join(root, 'original.json'), workdir = join(root, 'captures');
  const inventory = { schema: INVENTORY_SCHEMA, consistency: 'two-equal-observations-not-atomic',
    source: { repository, repository_id: repositoryId }, batch_size: size,
    issues: Array.from({ length: count }, (_, i) => ({ number: i + 1, id: issueId(i + 1) })),
    excluded_pull_requests: [{ number: count + 1, issue_id: issueId(count + 1) }], complete: true };
  const bytes = issueInventoryBytes(inventory); await writeFile(inventoryFile, bytes, { mode: 0o600 });
  return { root, inventory, initial: { operation: 'start', workdir, inventoryFile, inventorySha256: recordDigest(bytes), ...extra } };
}
const resume = value => ({ operation: 'resume', workdir: value.workdir, confirm: value.session_sha256 });
const status = value => ({ ...resume(value), operation: 'status' });
async function missing(path) { await assert.rejects(lstat(path), { code: 'ENOENT' }); }
const selection = n => ({ repository, numbers: [n], expectedSelection: { source: { repository, repository_id: repositoryId }, issues: [{ number: n, id: issueId(n) }] } });

for (const comments of [0, 1, 101]) test(`shared captures preserve original bytes, ${comments} comments`, async () => {
  const peer = githubPeer({ comments }), session = createGithubIssueCaptureSession({ fetchImpl: peer.fetchImpl });
  try {
    for (const n of [1, 2]) {
      const standalone = await captureGithubIssues({ ...selection(n), fetchImpl: githubPeer({ comments }).fetchImpl });
      const shared = await session.capture(selection(n));
      assert.deepEqual(shared.bytes, standalone.bytes); assert.equal(shared.sha256, recordDigest(shared.bytes));
      assert.equal(shared.capture.source.repository_id, repositoryId);
      assert.equal(shared.capture.issues[0].id, issueId(n));
      assert.ok(issueImportSteps(parseCapture(shared.bytes)).length >= 1);
    }
    assert.equal(session.statistics().requests, comments > 100 ? 16 : 12);
  } finally { session.close(); }
  await assert.rejects(session.capture(selection(1)), /capture_session_closed/);
});

test('complete capture feeds exact pinned sources and survives lost external inventory', async t => {
  const f = await fixture(t, 5, 2), peer = githubPeer();
  const result = await run({ ...f.initial, fetchImpl: peer.fetchImpl, offset: 100 });
  assert.equal(result.complete, true); assert.equal(result.total_batches, 3); assert.equal(result.captured_batches, 3);
  assert.equal(result.steps, 12); assert.equal(result.requests, 26); assert.equal(result.native_mutation_submitted, false);
  const sources = JSON.parse(await readFile(result.sources.path));
  assert.equal(recordDigest(await readFile(result.sources.path)), result.sources.sha256);
  assert.equal(sources.schema, 'frankengit-github-issue-migration-sources-v1'); assert.equal(sources.offset, 100);
  assert.deepEqual(sources.captures.map(r => r.batch), [1, 2, 3]);
  for (const row of sources.captures) assert.equal(recordDigest(await readFile(row.path)), row.sha256);
  await rm(f.initial.inventoryFile);
  const observed = await run(status(result)); assert.equal(observed.complete, true); assert.equal(observed.network_accessed, false);
  const repeated = await run({ ...resume(result), fetchImpl: () => assert.fail('completed source must not be fetched again') });
  assert.equal(repeated.newly_captured_batches, 0); assert.deepEqual(repeated.sources, result.sources);
});

test('resume captures only missing batches; no rediscovery or recapture of changed old bodies', async t => {
  const f = await fixture(t, 3), first = await run({ ...f.initial, fetchImpl: githubPeer().fetchImpl, maxBatches: 1 });
  assert.equal(first.complete, false); assert.equal(first.next_batch, 2); assert.equal(first.requests, 6);
  await missing(join(first.workdir, 'sources.json'));
  const original = (await readdir(first.workdir)).find(n => n.startsWith('capture-'));
  const bytes = await readFile(join(first.workdir, original));
  const peer = githubPeer({ before: async ({ path }) => { assert.ok(!path.endsWith('/1') && !path.endsWith('/1/comments')); } });
  const done = await run({ ...resume(first), fetchImpl: peer.fetchImpl });
  assert.equal(done.complete, true); assert.equal(done.newly_captured_batches, 2); assert.equal(done.requests, 12);
  assert.deepEqual(await readFile(join(first.workdir, original)), bytes);
});

test('whole request limit retains completed prefix and can resume with its original pin', async t => {
  const f = await fixture(t), peer = githubPeer(); let progress;
  await assert.rejects(run({ ...f.initial, fetchImpl: peer.fetchImpl, maxRequests: 6 }), e => {
    assert.equal(e.code, 'github_import_request_limit'); progress = e.capture_progress;
    return progress.captured_batches === 1 && progress.requests === 6;
  });
  assert.equal(peer.calls.length, 6); await missing(join(progress.workdir, 'sources.json'));
  assert.equal((await run({ ...resume(progress), fetchImpl: githubPeer().fetchImpl })).complete, true);
});

test('one shared byte budget and exact boundary across batches', async t => {
  const one = await captureGithubIssues({ ...selection(1), fetchImpl: githubPeer().fetchImpl });
  const two = await captureGithubIssues({ ...selection(2), fetchImpl: githubPeer().fetchImpl });
  const a = await fixture(t), b = await fixture(t);
  const result = await run({ ...a.initial, fetchImpl: githubPeer().fetchImpl, maxReadBytes: one.read_bytes + two.read_bytes });
  assert.equal(result.complete, true);
  await assert.rejects(run({ ...b.initial, fetchImpl: githubPeer().fetchImpl, maxReadBytes: one.read_bytes }), e =>
    e.code === 'github_import_read_bytes' && e.capture_progress.captured_batches === 1);
});

test('source retry allowance does not reset between batches', async t => {
  const f = await fixture(t); let limited = 0;
  const peer = githubPeer({ before: async ({ ordinal }) => {
    if ([1, 8].includes(ordinal)) { limited++; return new Response('{}', { status: 429, headers: { 'Retry-After': '0' } }); }
  } });
  await assert.rejects(run({ ...f.initial, fetchImpl: peer.fetchImpl, maxSourceRetries: 1 }), e =>
    e.code === 'github_import_source_http' && e.capture_progress.captured_batches === 1 && e.capture_progress.source_retries === 1);
  assert.equal(limited, 2); assert.equal(peer.calls.length, 8);
});

test('aggregate capture and native step ceilings have permitted exact twins', async t => {
  const one = await captureGithubIssues({ ...selection(1), fetchImpl: githubPeer().fetchImpl });
  const two = await captureGithubIssues({ ...selection(2), fetchImpl: githubPeer().fetchImpl });
  const f = await fixture(t), g = await fixture(t), h = await fixture(t);
  assert.equal((await run({ ...f.initial, maxCaptureBytes: one.bytes.length + two.bytes.length,
    maxSteps: 5, fetchImpl: githubPeer().fetchImpl })).complete, true);
  await assert.rejects(run({ ...g.initial, maxCaptureBytes: one.bytes.length, fetchImpl: githubPeer().fetchImpl }), e =>
    e.code.endsWith('_capacity') && e.capture_progress.captured_batches === 1);
  await assert.rejects(run({ ...h.initial, maxSteps: 4, fetchImpl: githubPeer().fetchImpl }), e =>
    e.code.endsWith('_capacity') && e.capture_progress.captured_batches === 1);
});

test('cross-batch duplicate comment identities refuse complete publication', async t => {
  const f = await fixture(t);
  await assert.rejects(run({ ...f.initial, fetchImpl: githubPeer({ duplicate: true }).fetchImpl }), e =>
    e.code.endsWith('_duplicate_comment') && e.capture_progress.captured_batches === 1);
  await missing(join(f.initial.workdir, 'sources.json'));
});

for (const kind of ['repository', 'issue', 'second-pass']) test(`source ${kind} substitution refuses before any usable capture`, async t => {
  const f = await fixture(t, 1);
  const peer = githubPeer({ before: async ({ ordinal, path }) => {
    if (kind === 'repository' && ordinal === 1) return json({ id: '42', full_name: repository });
    if (kind === 'issue' && ordinal === 2) return json({ ...issue(1), id: '42' });
    if (kind === 'second-pass' && ordinal === 5) return json({ ...issue(1), body: 'Changed' });
  } });
  await assert.rejects(run({ ...f.initial, fetchImpl: peer.fetchImpl }), e => e.capture_progress.captured_batches === 0);
  assert.equal(peer.calls.length, kind === 'repository' ? 1 : kind === 'issue' ? 2 : 6);
  await missing(join(f.initial.workdir, 'sources.json'));
});

test('one selected read credential persists across resumptions, never as token bytes', async t => {
  const f = await fixture(t), tokenFile = join(f.root, 'github-token');
  await writeFile(tokenFile, 'ghp_original\n', { mode: 0o600 });
  const value = await run({ ...f.initial, tokenFile, maxBatches: 1, fetchImpl: githubPeer().fetchImpl });
  const header = await readFile(join(value.workdir, 'session.json'), 'utf8'); assert.ok(!header.includes('ghp_original'));
  await writeFile(tokenFile, 'ghp_changed\n'); let calls = 0;
  await assert.rejects(run({ ...resume(value), tokenFile, fetchImpl: () => { calls++; } }), /source_credential_changed/);
  assert.equal(calls, 0); assert.equal((await run(status(value))).captured_batches, 1);
  await writeFile(tokenFile, 'ghp_original\n');
  assert.equal((await run({ ...resume(value), tokenFile, fetchImpl: githubPeer().fetchImpl })).complete, true);
});

for (const defect of ['body', 'symlink', 'hardlink', 'gap', 'unknown', 'sources', 'inventory']) test(`damaged ${defect} custody refuses before network work`, async t => {
  const f = await fixture(t), value = await run({ ...f.initial, maxBatches: 1, fetchImpl: githubPeer().fetchImpl });
  const name = (await readdir(value.workdir)).find(n => n.startsWith('capture-')), path = join(value.workdir, name);
  if (defect === 'body') await writeFile(path, '{}\n');
  if (defect === 'symlink') { await rename(path, join(f.root, 'saved')); await symlink(join(f.root, 'saved'), path); }
  if (defect === 'hardlink') await link(path, join(f.root, 'alias'));
  if (defect === 'gap') await rename(path, join(value.workdir, name.replace('000001', '000002')));
  if (defect === 'unknown') await writeFile(join(value.workdir, 'scratch'), 'x');
  if (defect === 'sources') await writeFile(join(value.workdir, 'sources.json'), '{}\n', { mode: 0o600 });
  if (defect === 'inventory') await writeFile(join(value.workdir, 'inventory.json'), '{}\n');
  let calls = 0; await assert.rejects(run({ ...resume(value), fetchImpl: () => { calls++; } })); assert.equal(calls, 0);
});

test('cancelled source attempt retains identity and never produces a capture prefix', async t => {
  const f = await fixture(t), stop = new AbortController(); let progress;
  const peer = githubPeer({ before: async ({ ordinal }) => { if (ordinal === 3) stop.abort(); } });
  await assert.rejects(run({ ...f.initial, signal: stop.signal, fetchImpl: peer.fetchImpl }), e => { progress = e.capture_progress; return e.name === 'AbortError'; });
  assert.equal(progress.captured_batches, 0); assert.ok(progress.session_sha256);
  await missing(join(progress.workdir, 'capture.owner'));
  assert.equal((await run({ ...resume(progress), fetchImpl: githubPeer().fetchImpl })).complete, true);
});

test('a pre-cancelled operation creates nothing and sends nothing', async t => {
  const f = await fixture(t); const stop = new AbortController(); stop.abort();
  await assert.rejects(run({ ...f.initial, signal: stop.signal, fetchImpl: () => assert.fail() }), { name: 'AbortError' });
  await missing(f.initial.workdir);
});

test('whole deadline includes source reads and drains body ownership', async t => {
  const f = await fixture(t); let cancelled = false;
  const peer = githubPeer({ before: async () => new Response(new ReadableStream({ cancel() { cancelled = true; } }),
    { headers: { 'Content-Type': 'application/json' } }) });
  await assert.rejects(run({ ...f.initial, timeoutMs: 100, fetchImpl: peer.fetchImpl }), { name: 'AbortError' });
  assert.equal(cancelled, true); await missing(join(f.initial.workdir, 'capture.owner'));
});

test('concurrent source sessions cannot own the same capture directory', async t => {
  const f = await fixture(t, 1); let entered, unpause;
  const ready = new Promise(r => { entered = r; }), gate = new Promise(r => { unpause = r; });
  const peer = githubPeer({ before: async ({ ordinal }) => { if (ordinal === 1) { entered(); await gate; } } });
  const active = run({ ...f.initial, fetchImpl: peer.fetchImpl }); await ready;
  const confirm = recordDigest(await readFile(join(f.initial.workdir, 'session.json')));
  const view = await run({ operation: 'status', workdir: f.initial.workdir, confirm }); assert.equal(view.owner_present_at_read, true);
  await assert.rejects(run({ operation: 'resume', workdir: f.initial.workdir, confirm, fetchImpl: () => assert.fail() }), { code: 'EEXIST' });
  unpause(); assert.equal((await active).complete, true);
});

test('changed root is not written through or cleaned as the original owner', async t => {
  const f = await fixture(t, 1); const displaced = join(f.root, 'original'); let changed = false;
  const peer = githubPeer({ before: async () => {
    if (!changed) { changed = true; await rename(f.initial.workdir, displaced); await mkdir(f.initial.workdir, { mode: 0o700 }); }
  } });
  await assert.rejects(run({ ...f.initial, fetchImpl: peer.fetchImpl }), /directory_changed/);
  assert.deepEqual(await readdir(f.initial.workdir), []); assert.ok((await lstat(join(displaced, 'capture.owner'))).isDirectory());
});

test('replacement owner is never deleted, even after complete capture', async t => {
  const f = await fixture(t, 1); let changed = false;
  const peer = githubPeer({ before: async () => {
    if (!changed) { changed = true; await rename(join(f.initial.workdir, 'capture.owner'), join(f.root, 'original-owner')); await mkdir(join(f.initial.workdir, 'capture.owner'), { mode: 0o700 }); }
  } });
  await assert.rejects(run({ ...f.initial, fetchImpl: peer.fetchImpl }), e => /directory_changed/.test(e.message) && e.capture_progress.complete);
  assert.ok((await lstat(join(f.initial.workdir, 'capture.owner'))).isDirectory());
});

test('capture session rejects overlap without cancelling its admitted capture', async () => {
  let enter, release; const ready = new Promise(r => enter = r), gate = new Promise(r => release = r);
  const peer = githubPeer({ before: async ({ ordinal }) => { if (ordinal === 1) { enter(); await gate; } } });
  const session = createGithubIssueCaptureSession({ fetchImpl: peer.fetchImpl });
  try {
    const first = session.capture(selection(1)); await ready;
    await assert.rejects(session.capture(selection(2)), /concurrent_capture/);
    release(); assert.ok((await first).bytes.length); assert.equal(peer.calls.length, 6);
  } finally { session.close(); }
});

test('a failed source session cannot reset or continue its budget', async () => {
  const peer = githubPeer(); const session = createGithubIssueCaptureSession({ fetchImpl: peer.fetchImpl, maxRequests: 1 });
  try {
    await assert.rejects(session.capture(selection(1)), /request_limit/);
    await assert.rejects(session.capture(selection(1)), /capture_session_closed/);
    assert.equal(peer.calls.length, 1);
  } finally { session.close(); }
});

for (const values of [{ maxRequests: 0 }, { maxRequests: 4097 }, { maxSteps: 0 }, { maxCaptureBytes: 67108865 },
  { maxBatches: 129 }, { offset: -1 }, { timeoutMs: 300001 }, { nativeToken: 'forbidden' }, { inventorySha256: '0'.repeat(64) }]) {
  test(`invalid selection/budget ${JSON.stringify(values)} refuses before directory creation`, async t => {
    const f = await fixture(t); await assert.rejects(run({ ...f.initial, ...values, fetchImpl: () => assert.fail() }));
    await missing(f.initial.workdir);
  });
}

test('empty, too many batches, overflow and wrong pin are never runnable sessions', async t => {
  for (const [count, extra] of [[0, {}], [129, {}], [1, { offset: Number.MAX_SAFE_INTEGER }]]) {
    const f = await fixture(t, count, 1, extra);
    await assert.rejects(run({ ...f.initial, fetchImpl: () => assert.fail() })); await missing(f.initial.workdir);
  }
});
