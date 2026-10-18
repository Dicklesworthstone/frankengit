import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile, writeFile, rm, lstat, readdir, symlink, link, chmod, rename } from 'node:fs/promises';
import { join } from 'node:path';
import { renameSync, mkdirSync, writeFileSync } from 'node:fs';
import { prepareGithubIssueImport, inspectPreparedGithubIssueImport } from '../../scripts/lib/github-issue-import.mjs';
import { prepareGithubIssueMigration, MIGRATION_LIMITS } from '../../scripts/lib/github-issue-migration.mjs';
import { recordDigest } from '../../scripts/lib/forge-operator-io.mjs';
import { fixture, source, token, change, requestFile, batchDir } from './github-migration-fixture.mjs';

async function absent(path) { await assert.rejects(lstat(path), { code: 'ENOENT' }); }
async function noNetwork(t) {
  const original = globalThis.fetch; let calls = 0;
  globalThis.fetch = async () => { calls++; throw new Error('network forbidden'); };
  t.after(() => { globalThis.fetch = original; assert.equal(calls, 0); });
}
async function requestBytes(root) {
  let bytes = 0;
  for (const name of await readdir(root)) if (name.startsWith('batch-')) {
    for (const file of await readdir(join(root, name))) if (file.endsWith('.request.json')) bytes += (await lstat(join(root, name, file))).size;
  }
  return bytes;
}
test('complete inventory prepares original native batches offline and survives removal of every external source', async t => {
  await noNetwork(t); const f = await fixture(t), prepared = await f.prepare();
  assert.equal(prepared.batches, 3); assert.equal(prepared.issues, 6); assert.equal(prepared.steps, 15);
  assert.deepEqual(prepared.source, source); assert.equal(prepared.excluded_pull_requests, 1);
  assert.equal(prepared.mutation_submitted, false); assert.equal(prepared.atomic_migration, false);
  const first = await readFile(requestFile(f.workdir, 1));
  const request = JSON.parse(first).receipt.request;
  assert.equal(request.number, 101); assert.equal(request.action, 'open');
  assert.match(request.key, /^fgui-[0-9a-f]{32}-[0-9a-f]{64}$/);
  assert.ok(request.fields.body.includes('18446744073709551615'));
  assert.equal(first.includes(token), false);
  for (const path of [f.options.inventoryFile, ...f.captures.map(c => c.path)]) await rm(path);
  const result = await f.inspect(prepared.plan_sha256);
  assert.equal(result.steps, 15); assert.equal(result.network_accessed, false);
  assert.equal(result.request_bytes, await requestBytes(f.workdir));
  assert.deepEqual(await readFile(requestFile(f.workdir, 1)), first);
  for (const row of result.batches) {
    const verified = await inspectPreparedGithubIssueImport({ ...f.common, workdir: batchDir(f.workdir, row.batch), confirm: row.plan_sha256 });
    assert.equal(verified.plan_sha256, row.plan_sha256); assert.equal(verified.source_sha256, row.capture_sha256);
    assert.equal(verified.offset, 100); assert.equal(verified.network_accessed, false);
  }
});
test('input descriptor order canonicalizes without changing fixed batch membership', async t => {
  await noNetwork(t); const f = await fixture(t);
  const prepared = await f.prepare({ captures: [...f.captures].reverse() });
  const inspected = await f.inspect(prepared.plan_sha256);
  assert.deepEqual(inspected.batches.map(r => r.batch), [1, 2, 3]);
});
test('all source bytes and selection descriptors are owned before preparation callbacks', async t => {
  await noNetwork(t); const f = await fixture(t), original = await readFile(f.captures[2].path);
  const raw = { ...f.options, captures: f.captures.map(x => ({ ...x })) };
  raw.onProgress = () => {
    writeFileSync(f.captures[2].path, '{}\n');
    raw.captures[2].path = '/missing'; raw.captures[2].sha256 = '0'.repeat(64); raw.offset = 999;
  };
  const result = await prepareGithubIssueMigration(raw);
  assert.deepEqual(await readFile(join(f.workdir, 'capture-000003.json')), original);
  assert.equal((await f.inspect(result.plan_sha256)).offset, 100);
});
for (const [name, extra] of [
  ['duplicate batch', f => ({ captures: [f.captures[0], f.captures[0], f.captures[2]] })],
  ['missing final batch', f => ({ captures: f.captures.slice(0, 2) })],
  ['missing middle batch', f => ({ captures: [f.captures[0], f.captures[2]] })],
  ['foreign inventory pin', () => ({ inventorySha256: '0'.repeat(64) })],
  ['foreign capture pin', f => ({ captures: f.captures.map((r, i) => i === 2 ? { ...r, sha256: '0'.repeat(64) } : r) })],
  ['overflowing offset', () => ({ offset: Number.MAX_SAFE_INTEGER })],
  ['step ceiling', () => ({ maxSteps: 14 })],
  ['capture byte ceiling', () => ({ maxCaptureBytes: 1 })],
  ['empty captures', () => ({ captures: [] })],
  ['unbounded batches', f => ({ captures: Array.from({ length: 129 }, () => f.captures[0]) })],
  ['unknown option', () => ({ force: true })],
  ['unknown capture field', f => ({ captures: f.captures.map(r => ({ ...r, approved: true })) })],
  ['fractional budget', () => ({ maxSteps: 1.5 })],
  ['raised profile bound', () => ({ maxRequestBytes: MIGRATION_LIMITS.requestBytes + 1 })],
]) test(`preparation refuses ${name} before output or network effects`, async t => {
  await noNetwork(t); const f = await fixture(t);
  await assert.rejects(f.prepare(extra(f))); await absent(f.workdir);
});
for (const name of ['repository', 'repository ID', 'issue ID', 'wrong batch', 'duplicate comment']) test(`complete capture preflight refuses ${name} with a valid file digest`, async t => {
  await noNetwork(t); const f = await fixture(t), target = f.captures[2];
  if (name === 'wrong batch') {
    await writeFile(target.path, await readFile(f.captures[0].path)); target.sha256 = recordDigest(await readFile(target.path));
  } else target.sha256 = await change(target.path, c => {
    if (name === 'repository') c.source.repository = 'other/project';
    if (name === 'repository ID') c.source.repository_id = '41';
    if (name === 'issue ID') c.issues[0].id = '41';
    if (name === 'duplicate comment') {
      const comment = c.issues[0].comments[0]; comment.id = '100';
      comment.html_url = `https://github.com/owner/project/issues/${c.issues[0].number}#issuecomment-100`;
    }
  });
  await assert.rejects(f.prepare()); await absent(f.workdir);
});
test('empty/all-PR inventory is not a successful migration', async t => {
  await noNetwork(t); const f = await fixture(t);
  f.options.inventorySha256 = await change(f.options.inventoryFile, x => { x.issues = []; });
  await assert.rejects(f.prepare(), /batch_coverage/); await absent(f.workdir);
});
test('exact global capture and step budgets permit the same complete population', async t => {
  await noNetwork(t); const f = await fixture(t);
  const captureBytes = (await Promise.all(f.captures.map(async r => (await lstat(r.path)).size))).reduce((a, b) => a + b, 0);
  const result = await f.prepare({ maxCaptureBytes: captureBytes, maxSteps: 15 });
  assert.equal((await f.inspect(result.plan_sha256)).steps, 15);
});
test('aggregate native request ceiling is enforced inside the child writer, not after overspending', async t => {
  await noNetwork(t); const f = await fixture(t);
  const base = await f.prepare(), size = (await f.inspect(base.plan_sha256)).request_bytes;
  const exactRoot = join(f.dir, 'exact'), shortRoot = join(f.dir, 'short');
  const exact = await f.prepare({ workdir: exactRoot, maxRequestBytes: size });
  assert.equal(exact.steps, 15); assert.equal(await requestBytes(exactRoot), size);
  await assert.rejects(f.prepare({ workdir: shortRoot, maxRequestBytes: size - 1 }), /request_byte_limit/);
  assert.ok(await requestBytes(shortRoot) <= size - 1); await absent(join(shortRoot, 'migration.json'));
});
test('ordinary single-batch preparation retains its default budget and inspection uses the same custody verifier', async t => {
  await noNetwork(t); const f = await fixture(t);
  const workdir = join(f.dir, 'single'), prepared = await prepareGithubIssueImport({ ...f.common, workdir, captureFile: f.captures[0].path, offset: 100 });
  const options = { ...f.common, workdir, confirm: prepared.plan_sha256 };
  const result = await inspectPreparedGithubIssueImport(options);
  assert.equal(result.steps, 5); assert.equal(result.mutation_submitted, false);
  await assert.rejects(inspectPreparedGithubIssueImport({ ...options, operation: 'run' }), /inspection_options/);
  await rm(join(workdir, 'step-000004.request.json'));
  await assert.rejects(inspectPreparedGithubIssueImport(options), /request_custody_incomplete/);
});
test('aborted preparation creates no directory', async t => {
  await noNetwork(t); const f = await fixture(t), stop = new AbortController(); stop.abort();
  await assert.rejects(f.prepare({ signal: stop.signal })); await absent(f.workdir);
});
test('interruption retains prepared child keys but never publishes a usable incomplete root', async t => {
  await noNetwork(t); const f = await fixture(t), stop = new AbortController();
  await assert.rejects(f.prepare({ signal: stop.signal, onProgress: () => stop.abort() }));
  assert.ok((await readFile(requestFile(f.workdir, 1))).length); await absent(join(f.workdir, 'migration.json'));
  await assert.rejects(f.prepare(), /operator_record_exists/);
});
test('competing preparations create exactly one complete original request set', async t => {
  await noNetwork(t); const f = await fixture(t);
  const results = await Promise.allSettled([f.prepare(), f.prepare()]);
  assert.equal(results.filter(r => r.status === 'fulfilled').length, 1);
  const winner = results.find(r => r.status === 'fulfilled').value;
  assert.equal((await f.inspect(winner.plan_sha256)).steps, 15);
});
for (const kind of ['symlink', 'hardlink', 'public']) test(`capture custody refuses ${kind} input`, async t => {
  await noNetwork(t); const f = await fixture(t), c = f.captures[2], original = c.path;
  if (kind === 'public') await chmod(c.path, 0o644);
  else { c.path += '.alias'; await (kind === 'symlink' ? symlink(original, c.path) : link(original, c.path)); }
  await assert.rejects(f.prepare()); await absent(f.workdir);
});
for (const kind of ['root pin', 'later request', 'later capture', 'child plan', 'inventory', 'token', 'root mode']) test(`offline inspection refuses changed ${kind} without any network`, async t => {
  await noNetwork(t); const f = await fixture(t), result = await f.prepare(); let confirm = result.plan_sha256;
  if (kind === 'root pin') confirm = '0'.repeat(64);
  if (kind === 'later request') await rm(requestFile(f.workdir, 3));
  if (kind === 'later capture') await writeFile(join(f.workdir, 'capture-000003.json'), '{}\n');
  if (kind === 'child plan') await change(join(batchDir(f.workdir, 3), 'manifest.json'), x => { x.offset++; });
  if (kind === 'inventory') await change(join(f.workdir, 'inventory.json'), x => { x.batch_size++; });
  if (kind === 'token') await writeFile(f.tokenFile, 'd'.repeat(64));
  if (kind === 'root mode') await chmod(f.workdir, 0o755);
  await assert.rejects(f.inspect(confirm));
});
for (const [name, mutate] of [
  ['unknown fields', x => { x.approved = true; }],
  ['batch order', x => { x.batches.reverse(); }],
  ['wrong total', x => { x.step_count++; }],
  ['incomplete batches', x => { x.batches.pop(); }],
  ['wrong offset', x => { x.offset++; }],
  ['invented byte count', x => { x.request_bytes++; }],
]) test(`rehashed but inconsistent migration manifest cannot bypass ${name}`, async t => {
  await noNetwork(t); const f = await fixture(t); await f.prepare();
  const confirm = await change(join(f.workdir, 'migration.json'), mutate);
  await assert.rejects(f.inspect(confirm));
});
test('directory replacement during a callback is detected before a root can be published', async t => {
  await noNetwork(t); const f = await fixture(t); let replaced = false;
  const retained = join(f.dir, 'original');
  const result = f.prepare({ onProgress: () => {
    if (!replaced) { replaced = true; renameSync(f.workdir, retained); mkdirSync(f.workdir, { mode: 0o700 }); }
  } });
  await assert.rejects(result, /directory_changed_or_unsafe/);
  await absent(join(f.workdir, 'migration.json')); await absent(join(retained, 'migration.json'));
  assert.ok((await readFile(requestFile(retained, 1))).length);
});
test('inspection refuses a child directory substituted with a symlink to intact bytes', async t => {
  await noNetwork(t); const f = await fixture(t), result = await f.prepare();
  const original = batchDir(f.workdir, 3), moved = join(f.dir, 'moved');
  await rename(original, moved); await symlink(moved, original);
  await assert.rejects(f.inspect(result.plan_sha256), /directory_changed_or_unsafe/);
});
test('changing credentials between batches cannot publish a mixed-credential migration', async t => {
  await noNetwork(t); const f = await fixture(t); let changed = false;
  await assert.rejects(f.prepare({ onProgress: () => {
    if (!changed) { changed = true; writeFileSync(f.tokenFile, 'd'.repeat(64)); }
  } }), /original_native_credential_required/);
  await absent(join(f.workdir, 'migration.json'));
  assert.ok((await readFile(requestFile(f.workdir, 1))).length);
});
