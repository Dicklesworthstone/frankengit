// Actual capture/compiler, native operator, sockets, private files and child CLI.
// The receiver is explicitly a contract fixture, not native authorization/CAS.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile, writeFile, readdir, lstat, unlink, symlink, chmod } from 'node:fs/promises';
import { join } from 'node:path';
import { fixture, mutations, cli, actor, token, tenant, repository } from './github-import-fixtures.mjs';
import { IssueClient } from '../../crates/fgit-node/src/smart_http/server/browser/issues.mjs';
import { prepareGithubIssueImport } from '../../scripts/lib/github-issue-import.mjs';
import { captureBytes } from '../../scripts/lib/github-issue-source.mjs';
import { importArguments } from '../../scripts/import_github_issues.mjs';
const json = path => readFile(path, 'utf8').then(JSON.parse);
const pause = ms => new Promise(resolve => setTimeout(resolve, ms));
async function waitFor(predicate) {
  for (let n = 0; n < 300; n++) { if (await predicate()) return; await pause(10); }
  assert.fail('test observation deadline exceeded');
}

test('preparation is network-free, private, root-last and preserves the exact source and number map', async t => {
  const f = await fixture(t);
  assert.equal(f.calls.length, 0); assert.equal(f.prepared.mutation_submitted, false);
  assert.deepEqual(f.prepared.mapping, [{ source: 3, target: 103 }, { source: 5, target: 105 }]);
  assert.equal(f.prepared.steps, 7);
  assert.deepEqual(await readFile(join(f.workdir, 'capture.json')), await readFile(f.captureFile));
  assert.equal((await readFile(join(f.workdir, 'manifest.json'), 'utf8')).includes(token), false);
  assert.equal((await lstat(f.workdir)).mode & 0o077, 0);
  assert.equal((await lstat(join(f.workdir, 'manifest.json'))).mode & 0o077, 0);
  await assert.rejects(prepareGithubIssueImport({ ...f.common, captureFile: f.captureFile, offset: 100 }), { code: 'EEXIST' });
});

test('the complete import publishes attributed issues, ordered comments and final closed state', async t => {
  const f = await fixture(t); const result = await f.run();
  assert.equal(result.complete, true); assert.equal(result.committed_observed, 7); assert.equal(result.next_step, 7);
  assert.equal(result.atomic_batch, false); assert.equal(result.absence_proves_non_commit, false);
  assert.deepEqual(mutations(f).map(c => [c.url.pathname.split('/').at(-1), new URLSearchParams(c.body).get('expected_version')]),
    [['open', '0'], ['comment', '1'], ['comment', '2'], ['close', '3'], ['open', '0'], ['comment', '1'], ['comment', '2']]);
  assert.equal(f.rows.get(103).issue.state, 'closed'); assert.equal(f.rows.get(105).issue.state, 'open');
  assert.equal(f.rows.get(103).issue.opened_by, actor); assert.deepEqual(f.rows.get(103).issue.assignees, []);
  assert.match(f.rows.get(103).issue.body, /original-source-author/);
  assert.ok(f.rows.get(103).events[1].action.body.endsWith('Exact source comment 1\r\n%26=+'));
  const entries = await readdir(f.workdir);
  assert.equal(entries.filter(n => n.endsWith('.terminal.json')).length, 7); assert.equal(entries.includes('sender.lock'), false);
  const before = mutations(f).length; const again = await f.run();
  assert.equal(again.complete, true); assert.equal(again.mutation_calls, 0); assert.equal(mutations(f).length, before);
  assert.equal(f.calls.filter(c => c.url.pathname.endsWith('/outcomes')).length, 21);
});

test('a bounded mutation prefix resumes from native outcomes, not a mutable success cursor', async t => {
  const f = await fixture(t);
  const first = await f.run({ maxMutations: 2 });
  assert.equal(first.complete, false); assert.equal(first.stop_reason, 'mutation_limit'); assert.equal(first.next_step, 2);
  const second = await f.run({ maxMutations: 2 });
  assert.equal(second.next_step, 4); assert.equal(second.mutation_calls, 2); assert.equal(mutations(f).length, 4);
  assert.equal((await f.run()).complete, true); assert.equal(mutations(f).length, 7);
});

test('read-only status neither prepares nor sends a fresh command', async t => {
  const f = await fixture(t), before = await readdir(f.workdir);
  const result = await f.run({ operation: 'status' });
  assert.equal(result.stop_reason, 'not_started_locally'); assert.equal(result.mutation_calls, 0);
  assert.equal(f.calls.length, 1); assert.ok(f.calls[0].url.pathname.endsWith('/outcomes'));
  assert.equal(f.calls[0].body, ''); assert.deepEqual(await readdir(f.workdir), before);
});

test('lost committed response is recovered without repeating a comment or consulting GitHub', async t => {
  let lost = false;
  const f = await fixture(t, { after: async call => {
    if (call.url.pathname.endsWith('/comment') && !lost) { lost = true; call.reply.destroy(); return true; }
    return false;
  } });
  await assert.rejects(f.run(), e => e.import_progress.committed_observed === 1 && e.import_progress.next_step === 1);
  assert.equal(f.rows.get(103).issue.comments, 1);
  await unlink(f.captureFile); // The prepared copy, not the original path, owns restart.
  const result = await f.run(); assert.equal(result.complete, true); assert.equal(mutations(f).length, 7);
  assert.equal(f.rows.get(103).issue.comments, 2);
});

test('unobserved original requires explicit exact retry and retains its first key and bytes', async t => {
  let drop = true;
  const f = await fixture(t, { before: async call => {
    if (call.url.pathname.endsWith('/open') && drop) { drop = false; call.reply.destroy(); return true; }
    return false;
  } });
  await assert.rejects(f.run()); const original = await readFile(f.file(0, 'request'));
  const status = await f.run(); assert.equal(status.stop_reason, 'unresolved_original_request');
  assert.equal(mutations(f).length, 1); assert.equal(f.rows.size, 0);
  const retried = await f.run({ retryUnresolved: true }); assert.equal(retried.complete, true);
  const calls = mutations(f); assert.equal(calls[0].key, calls[1].key); assert.equal(calls[0].body, calls[1].body);
  assert.deepEqual(await readFile(f.file(0, 'request')), original); assert.equal(calls.length, 8);
});

test('canonical refusal halts the batch and remains refused after restart', async t => {
  let raced = false;
  const f = await fixture(t, { before: async (call, { rows }) => {
    if (call.url.pathname.endsWith('/comment') && !raced) { raced = true; rows.get(103).issue.version++; }
    return false;
  } });
  const first = await f.run(); assert.equal(first.stop_reason, 'terminal_refusal'); assert.equal(first.committed_observed, 1);
  const saved = await json(f.file(1, 'terminal')); assert.equal(saved.result.outcome, 'refused');
  const second = await f.run({ retryUnresolved: true }); assert.equal(second.stop_reason, 'terminal_refusal');
  assert.equal(mutations(f).length, 2); assert.equal(f.rows.has(105), false);
});

test('occupied target number never overwrites or reopens an existing issue', async t => {
  const f = await fixture(t);
  f.rows.set(103, { issue: { number: 103, version: 1, title: 'Someone else', body: '', labels: [], state: 'open',
    comments: 0, opened_by: actor, last_actor: actor, assignees: [] },
    events: [{ version: 1, actor, action: { name: 'open', title: 'Someone else', body: '', labels: [] } }] });
  const rejected = await f.run(); assert.equal(rejected.stop_reason, 'terminal_refusal');
  assert.equal(f.rows.get(103).issue.title, 'Someone else'); assert.equal(f.rows.get(103).issue.version, 1);
  const again = await f.run(); assert.equal(again.stop_reason, 'terminal_refusal'); assert.equal(mutations(f).length, 1);
  assert.equal((await json(f.file(0, 'terminal'))).result.outcome, 'refused');
});

for (const field of ['confirm', 'href', 'tenant', 'repository']) test(`independent ${field} mismatch refuses before network access`, async t => {
  const f = await fixture(t);
  const value = field === 'href' ? f.common.href.replace('repo.git', 'other.git') : 'f'.repeat(field === 'confirm' ? 64 : 32);
  await assert.rejects(f.run({ [field]: value }), /plan_mismatch/); assert.equal(f.calls.length, 0);
});

test('a replacement native token cannot silently become a new mutation namespace', async t => {
  const f = await fixture(t);
  await writeFile(f.common.tokenFile, '1'.repeat(64), { mode: 0o600 });
  await assert.rejects(f.run(), /original_native_credential_required/); assert.equal(f.calls.length, 0);
});

test('changed capture and manifest bytes cannot silently recompile a different import', async t => {
  const f = await fixture(t);
  const path = join(f.workdir, 'capture.json'), old = await readFile(path);
  await writeFile(path, Buffer.from(old.toString().replace('Source 3', 'Changed3')));
  await assert.rejects(f.run(), /source_package_changed/); assert.equal(f.calls.length, 0);
  await writeFile(path, old);
  const manifest = join(f.workdir, 'manifest.json'); await writeFile(manifest, (await readFile(manifest)).toString().replace('"offset":100', '"offset":200'));
  await assert.rejects(f.run(), /plan_mismatch/); assert.equal(f.calls.length, 0);
});

test('a saved request naming another comment or key body is refused before outcome lookup', async t => {
  let drop = true;
  const f = await fixture(t, { before: async call => {
    if (call.url.pathname.endsWith('/open') && drop) { drop = false; call.reply.destroy(); return true; } return false;
  } });
  await assert.rejects(f.run()); const path = f.file(0, 'request'), value = await json(path);
  value.receipt.request.fields.title = 'different';
  await writeFile(path, JSON.stringify(value) + '\n'); const before = f.calls.length;
  await assert.rejects(f.run({ retryUnresolved: true }), /request_plan_mismatch/); assert.equal(f.calls.length, before);
});

test('previously observed terminal cannot regress to absence or another transaction', async t => {
  const f = await fixture(t); await f.run({ maxMutations: 1 });
  const [key, original] = [...f.outcomes][0];
  f.outcomes.delete(key); await assert.rejects(f.run({ retryUnresolved: true }), /terminal_observation_regressed/);
  f.outcomes.set(key, { ...original, tx_id: 'substituted-transaction' });
  await assert.rejects(f.run(), /terminal_observation_regressed/); assert.equal(mutations(f).length, 1);
});

test('lost original request custody never creates a replacement key', async t => {
  const f = await fixture(t); await f.run({ maxMutations: 1 });
  await unlink(f.file(0, 'request'));
  await assert.rejects(f.run({ retryUnresolved: true }), /custody_incomplete/); assert.equal(mutations(f).length, 1);
});

test('known request and retained terminal hashes must still agree', async t => {
  const f = await fixture(t); await f.run({ maxMutations: 1 });
  const path = f.file(0, 'terminal'), value = await json(path); value.request_sha256 = '0'.repeat(64);
  await writeFile(path, JSON.stringify(value) + '\n'); const before = f.calls.length;
  await assert.rejects(f.run(), /terminal_record_mismatch/); assert.equal(f.calls.length, before);
});

test('concurrent sender is refused while status can inspect the pending original', async t => {
  let reached = false, release;
  const gate = new Promise(resolve => { release = resolve; });
  const f = await fixture(t, { after: async call => { if (!reached) { reached = true; await gate; } return false; } });
  const first = f.run();
  try {
    await waitFor(() => reached); await assert.rejects(f.run(), /sender_lock_retained/);
    const observed = await f.run({ operation: 'status' }); assert.equal(observed.committed_observed, 1); assert.equal(observed.stop_reason, 'not_started_locally');
  } finally { release(); await first; }
  assert.equal((await first).complete, true); assert.equal(mutations(f).length, 7);
});

test('cancellation after a terminal saves it before stopping and restart does not duplicate it', async t => {
  const f = await fixture(t), stop = new AbortController();
  await assert.rejects(f.run({ signal: stop.signal, onProgress: () => stop.abort() }), e =>
    e.import_progress.committed_observed === 1 && e.observed_terminal?.outcome === 'committed');
  assert.equal((await json(f.file(0, 'terminal'))).result.outcome, 'committed');
  assert.equal(mutations(f).length, 1); assert.equal((await f.run()).complete, true); assert.equal(mutations(f).length, 7);
});

test('retained terminal survives a failed local observation write', async t => {
  const f = await fixture(t, { after: async call => {
    if (call.url.pathname.endsWith('/open')) await writeFile(f.file(0, 'terminal'), '{', { mode: 0o600 });
    return false;
  } });
  await assert.rejects(f.run(), e => e.observed_terminal?.outcome === 'committed' && e.import_progress.complete === false);
  assert.equal(f.rows.get(103).issue.version, 1); assert.equal(mutations(f).length, 1);
  await assert.rejects(f.run()); assert.equal(mutations(f).length, 1);
});

test('whole-operation timeout stops a stalled response and preserves its original request', async t => {
  const f = await fixture(t, { after: async () => true });
  await assert.rejects(f.run({ timeoutMs: 1000 }), e => e.import_progress.next_step === 0);
  assert.ok((await json(f.file(0, 'request'))).receipt.request.key);
  assert.equal((await f.run({ operation: 'status' })).committed_observed, 1);
});

test('unsafe manifest permissions and symlink receipts refuse without network effects', async t => {
  const f = await fixture(t), manifest = join(f.workdir, 'manifest.json');
  await chmod(manifest, 0o644); await assert.rejects(f.run(), /private_owner/); assert.equal(f.calls.length, 0);
  await chmod(manifest, 0o600); await f.run({ maxMutations: 1 });
  const path = f.file(0, 'request'), saved = await readFile(path); await unlink(path);
  const other = join(f.dir, 'other-request'); await writeFile(other, saved, { mode: 0o600 }); await symlink(other, path);
  const before = f.calls.length; await assert.rejects(f.run()); assert.equal(f.calls.length, before);
});

test('actual CLI sends the prepared plan and status retains completion without sending', async t => {
  const f = await fixture(t); const run = await cli(f, 'run').result;
  assert.equal(run.code, 0, run.stderr); assert.equal(JSON.parse(run.stdout).complete, true);
  const status = await cli(f, 'status').result;
  assert.equal(status.code, 0, status.stderr); assert.equal(JSON.parse(status.stdout).mutation_calls, 0);
  assert.equal(mutations(f).length, 7);
  assert.throws(() => importArguments(['status', '--retry-unresolved']), /option/);
});

test('SIGKILL retains sender ownership but a fresh status process can recover the committed original', async t => {
  let reached = false;
  const f = await fixture(t, { after: async () => { reached = true; return true; } });
  const running = cli(f, 'run'); t.after(() => running.child.kill('SIGKILL'));
  await waitFor(() => reached); running.child.kill('SIGKILL');
  const stopped = await running.result; assert.equal(stopped.signal, 'SIGKILL');
  assert.ok((await lstat(join(f.workdir, 'sender.lock'))).isFile());
  const again = await cli(f, 'run', ['--retry-unresolved']).result;
  assert.equal(again.code, 2); assert.match(again.stderr, /sender_lock_retained/);
  const status = await cli(f, 'status').result;
  assert.equal(status.code, 1, status.stderr); assert.equal(JSON.parse(status.stdout).committed_observed, 1);
  assert.equal(mutations(f).length, 1);
});

test('an observer failure after the final decision preserves complete publication knowledge', async t => {
  const f = await fixture(t);
  await assert.rejects(f.run({ onProgress: event => { if (event.index === 6) throw new Error('observer failed'); } }), e =>
    e.import_progress.complete === true && e.import_progress.committed_observed === 7 && e.observed_terminal?.index === 6);
  assert.equal((await f.run({ operation: 'status' })).complete, true); assert.equal(mutations(f).length, 7);
});

test('SIGTERM stops waiting without deleting the original request or claiming rollback', async t => {
  let reached = false;
  const f = await fixture(t, { after: async () => { reached = true; return true; } });
  const running = cli(f, 'run'); t.after(() => running.child.kill('SIGKILL'));
  await waitFor(() => reached); running.child.kill('SIGTERM'); const stopped = await running.result;
  assert.equal(stopped.code, 2); assert.equal(stopped.signal, null);
  assert.ok((await json(f.file(0, 'request'))).receipt.request.key);
  assert.equal((await readdir(f.workdir)).includes('sender.lock'), false);
  const status = await cli(f, 'status').result;
  assert.equal(JSON.parse(status.stdout).committed_observed, 1); assert.equal(mutations(f).length, 1);
});

test('broken stdout after complete publication reports the completed result separately', async t => {
  let running;
  const f = await fixture(t, { after: async call => {
    if (call.url.pathname.endsWith('/105/comment') && new URLSearchParams(call.body).get('expected_version') === '2') running.child.stdout.destroy();
    return false;
  } });
  running = cli(f, 'run'); const result = await running.result;
  assert.equal(result.code, 2); const report = JSON.parse(result.stderr);
  assert.equal(JSON.parse(report.completed_result).complete, true); assert.equal(mutations(f).length, 7);
  assert.equal((await f.run({ operation: 'status' })).complete, true);
});

test('transient pre-publication read failure does not strand an otherwise untouched batch', async t => {
  let failed = false;
  const f = await fixture(t, { before: async (call, { send }) => {
    if (!failed && (call.method === 'GET' || call.url.pathname.endsWith('/outcomes'))) {
      failed = true; send(call.reply, { error: 'unavailable' }, 503); return true;
    }
    return false;
  } });
  await assert.rejects(f.run()); assert.equal(mutations(f).length, 0);
  assert.equal((await f.run()).complete, true); assert.equal(mutations(f).length, 7);
});

test('every exact request and its original key are sealed before any destination access', async t => {
  const f = await fixture(t), manifest = await json(join(f.workdir, 'manifest.json'));
  assert.equal(f.calls.length, 0); assert.equal(manifest.request_sha256.length, 7);
  const originals = await Promise.all(Array.from({ length: 7 }, (_, i) => readFile(f.file(i, 'request'))));
  assert.equal(manifest.request_bytes, originals.reduce((n, b) => n + b.length, 0));
  assert.equal(new Set(originals.map(bytes => JSON.parse(bytes).receipt.request.key)).size, 7);
  await f.run();
  for (const [index, original] of originals.entries()) assert.deepEqual(await readFile(f.file(index, 'request')), original);
});

test('offline scope is only a reply constraint, never an authenticated view or permission', async () => {
  let requests = 0;
  const client = new IssueClient({ href: 'https://forge.example/repo.git/ui/issues/', fetchImpl: async () => { requests++; throw new Error('unexpected fetch'); } });
  await client.connect(token); const binding = { tenant, repository };
  await client.stage(3, 0, 'open', { title: 'Offline proposal', body: '', labels: [] }, binding);
  binding.tenant = '0'.repeat(32);
  assert.equal(requests, 0); assert.equal(client.binding, null);
  assert.deepEqual(client.pending.binding, { tenant, repository });
  client.disconnect(); assert.ok(client.pending); assert.equal(client.connected, false);
});

test('invalid offline bindings cannot create a prepared request', async () => {
  const client = new IssueClient({ href: 'https://forge.example/repo.git/ui/issues/' }); await client.connect(token);
  for (const scope of [{}, { tenant }, { tenant, repository, principal: actor }, { tenant: tenant.toUpperCase(), repository }, []]) {
    await assert.rejects(client.stage(3, 0, 'open', { title: 'x', body: '' }, scope)); assert.equal(client.pending, null);
  }
  await client.stage(3, 0, 'open', { title: 'x', body: '' }, { tenant, repository });
  assert.ok(client.pending); client.disconnect();
});

test('offline expected scope cannot override an observed repository identity', async t => {
  const f = await fixture(t), client = new IssueClient({ href: f.common.href }); await client.connect(token);
  await client.read(103, { limit: 1 });
  await assert.rejects(client.stage(103, 0, 'open', { title: 'x', body: '' }, { tenant: '0'.repeat(32), repository }), /differs/);
  assert.equal(client.pending, null); assert.deepEqual(client.binding, { tenant, repository }); client.disconnect();
});

test('offline prepared requests still refuse a foreign publication response and retain the original for recovery', async t => {
  let wrong = false;
  const f = await fixture(t, { after: async (call, { terminal, send }) => {
    if (!wrong) { wrong = true; send(call.reply, { ...terminal, tenant_id: '0'.repeat(32) }); return true; } return false;
  } });
  await assert.rejects(f.run(), /identity/);
  assert.equal((await readdir(f.workdir)).some(name => name.endsWith('.terminal.json')), false);
  assert.equal((await f.run()).complete, true); assert.equal(mutations(f).length, 7);
});

test('a missing or corrupted later prepared request is refused before any earlier mutation', async t => {
  const f = await fixture(t), path = f.file(6, 'request'), original = await readFile(path);
  await unlink(path); await assert.rejects(f.run(), /custody_incomplete/); assert.equal(f.calls.length, 0);
  await writeFile(path, original, { mode: 0o600 }); const request = await json(path);
  request.receipt.request.key = request.receipt.request.key.replace(/.$/, request.receipt.request.key.endsWith('0') ? '1' : '0');
  await writeFile(path, JSON.stringify(request) + '\n');
  await assert.rejects(f.run(), /prepared_request_changed/); assert.equal(f.calls.length, 0);
});


test('preparation refuses a valid native command that cannot fit its exact retry receipt', async t => {
  const f = await fixture(t, { prepare: false, numbers: [3] });
  const capture = await json(f.captureFile); capture.issues[0].body = '\u0001'.repeat(62000);
  await writeFile(f.captureFile, captureBytes(capture));
  await assert.rejects(prepareGithubIssueImport({ ...f.common, captureFile: f.captureFile, offset: 100 }), /receipt_limit/);
  await assert.rejects(lstat(join(f.workdir, 'manifest.json')), { code: 'ENOENT' });
  assert.equal(f.calls.length, 0);
});
