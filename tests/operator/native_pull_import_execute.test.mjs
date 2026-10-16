import test from 'node:test';
import assert from 'node:assert/strict';
import { join } from 'node:path';
import { readFile, writeFile, unlink, rm, mkdir, readdir, stat } from 'node:fs/promises';
import { preparePullImport } from '../../scripts/lib/native-pull-import.mjs';
import { executePullImport } from '../../scripts/lib/native-pull-import-execute.mjs';
import { encode, digest } from '../../scripts/lib/forge-pull-archive-store.mjs';
import { importFixture, row, TOKEN } from './native-pull-import-fixture.mjs';

async function migration(t, settings = {}, selection = {}) {
  const f = await importFixture(t, settings);
  const p = await preparePullImport({ ...f.prepare, selection: { ...f.selection, ...selection } });
  const raw = { workdir: f.workdir, confirm: p.plan_sha256 };
  return { ...f, prepared: p, raw, run: (more = {}) => executePullImport({ ...raw, operation: 'run', tokenFile: f.tokenFile, ...more }),
    recover: (more = {}) => executePullImport({ ...raw, operation: 'recover', tokenFile: f.tokenFile, ...more }),
    status: () => executePullImport({ ...raw, operation: 'status' }) };
}
const sends = f => f.requests.filter(r => r.path.startsWith('/dest/') && !r.path.endsWith('/outcomes'));
const lookups = f => f.requests.filter(r => r.path.endsWith('/outcomes'));
const attempt = (f, i, file = 'started.json') => join(f.workdir, 'journal', `attempt-${String(i).padStart(6, '0')}`, file);

for (const format of ['sha1', 'sha256']) test(`whole import executes each original request once: ${format}`, async t => {
  const f = await migration(t, { format }), before = f.requests.length;
  const result = await f.run(); assert.equal(result.complete, true); assert.equal(result.state, 'complete');
  assert.equal(result.committed_steps, 11); assert.equal(result.new_operations, 11); assert.equal(result.mutations_dispatched, 11);
  assert.equal(f.requests.length - before, 33); assert.equal(new Set(sends(f).map(r => r.key)).size, 11);
  assert.equal(f.pulls.get('100').fields.body, f.rows[0].data.body); assert.equal(f.pulls.get('101').state, 'closed');
  assert(sends(f).every(r => /\/(open|comments|close)$/.test(r.path)));
  assert.equal(result.approvals_imported, false); assert.equal(result.refs_changed, false);
  const count = f.requests.length; await rm(f.archiveDir, { recursive: true }); await unlink(f.tokenFile);
  const completed = await executePullImport({ ...f.raw, operation: 'run' });
  assert.equal(completed.complete, true); assert.equal(completed.network_accessed, false); assert.equal(completed.new_operations, 0);
  assert.equal((await f.status()).journal_sha256, completed.journal_sha256); assert.equal(f.requests.length, count);
});
test('operation allowance spans the full plan and repeated runs retain original keys', async t => {
  const f = await migration(t); let result, count = 0;
  do { result = await f.run({ maxOperations: 2 }); assert(result.new_operations <= 2); count++; } while (!result.complete);
  assert.equal(count, 6); assert.equal(sends(f).length, 11); assert.equal(lookups(f).length, 22);
});
test('lost mutation reply recovers its committed original key without a duplicate POST', async t => {
  let lost = false; const f = await migration(t, { drop: () => { if (lost) return false; lost = true; return true; } });
  const first = await f.run(); assert.equal(first.state, 'pending'); assert.equal(first.current.action, 'open'); assert.equal(sends(f).length, 1);
  const key = first.current.key, resumed = await f.run(); assert.equal(resumed.complete, true);
  assert.equal(sends(f).filter(r => r.key === key).length, 1); assert.equal(sends(f).length, 11);
});
test('unknown send is recovery-only until its exact original key is explicitly retried', async t => {
  let block = true; const f = await migration(t, { beforeDestination: ({ request, req }) => {
    if (block && request.path.endsWith('/open')) { req.socket.destroy(); return false; }
  } });
  const first = await f.run(), original = sends(f)[0]; assert.equal(first.state, 'pending'); assert.equal(f.outcomes.size, 0);
  const second = await f.run(); assert.equal(second.state, 'pending'); assert.equal(second.current.outcome, 'key_not_observed');
  assert.equal(sends(f).length, 1); const before = f.requests.length;
  await assert.rejects(f.run({ retryKey: 'other-key' }), /retry_original_pending_key/); assert.equal(f.requests.length, before);
  block = false;
  const done = await f.run({ retryKey: first.current.key }); assert.equal(done.complete, true);
  assert.deepEqual(sends(f).slice(0, 2).map(r => [r.key, r.body]), [[original.key, original.body], [original.key, original.body]]);
  assert.equal(sends(f).length, 12); assert.equal(f.pulls.size, 2);
});
test('explicit retry consent cannot spill into a later unresolved request', async t => {
  const blocked = new Set(); let releaseOpen = false;
  const f = await migration(t, { beforeDestination: ({ request, req }) => {
    if (!request.path.endsWith('/outcomes') && (!releaseOpen || request.path.endsWith('/comments'))) { blocked.add(request.key); req.socket.destroy(); return false; }
  } });
  const first = await f.run(); releaseOpen = true;
  const next = await f.run({ retryKey: first.current.key }); assert.equal(next.state, 'pending'); assert.equal(next.current.action, 'comment');
  const key = next.current.key, n = sends(f).length;
  await assert.rejects(f.run({ retryKey: first.current.key }), /retry_original_pending_key/);
  await f.run(); assert.equal(sends(f).length, n); assert.equal(sends(f).filter(r => r.key === key).length, 1);
});
test('recovery never starts an unattempted operation', async t => {
  const f = await migration(t), count = f.requests.length;
  const result = await f.recover(); assert.equal(result.state, 'ready'); assert.equal(result.network_accessed, false); assert.equal(f.requests.length, count);
});
test('read-only recovery stops after resolving one attempted operation', async t => {
  let drop = true; const f = await migration(t, { drop: () => { const v = drop; drop = false; return v; } });
  await f.run(); const result = await f.recover(); assert.equal(result.committed_steps, 1); assert.equal(result.state, 'ready');
  assert.equal(result.mutations_dispatched, 0); assert.equal(sends(f).length, 1); assert.equal(result.new_operations, 1);
  assert.equal((await f.run()).complete, true);
});
test('publication survives a failed confirmation lookup and forbids a repeat send', async t => {
  let published = false, blocked = true;
  const f = await migration(t, { mutate: (request, res, result) => {
    if (!request.path.endsWith('/outcomes')) published = true;
    else if (published && blocked) { res.destroy(); return false; }
  } });
  const first = await f.run(); assert.equal(first.current.publication, 'committed'); assert.equal(first.committed_steps, 0);
  const retry = await f.run({ retryKey: first.current.key }); assert.equal(retry.state, 'pending'); assert.equal(sends(f).length, 1);
  blocked = false; assert.equal((await f.run()).complete, true); assert.equal(sends(f).length, 11);
});
test('native refusal stops the plan and does not remap or regenerate a key', async t => {
  const f = await migration(t, { refuse: ({ action }) => action === 'comment' });
  const first = await f.run(); assert.equal(first.state, 'refused'); assert.equal(first.committed_steps, 1); assert.equal(sends(f).length, 2);
  const count = f.requests.length, again = await f.run(); assert.equal(again.state, 'refused'); assert.equal(again.network_accessed, false);
  await assert.rejects(f.run({ retryKey: first.current.key }), /retry_original_pending_key/); assert.equal(f.requests.length, count);
});
test('destination PR number collision refuses open without modifying the existing object', async t => {
  const f = await migration(t); f.pulls.set('100', { fields: { title: 'existing' }, version: 1, state: 'open', comments: [] });
  const r = await f.run(); assert.equal(r.state, 'refused'); assert.equal(r.committed_steps, 0); assert.equal(sends(f).length, 1);
  assert.equal(f.pulls.get('100').fields.title, 'existing'); assert(!f.pulls.has('101'));
});
test('wrong credential cannot send and status needs no credential', async t => {
  const f = await migration(t), count = f.requests.length; await writeFile(f.tokenFile, 'aa'.repeat(32));
  await assert.rejects(f.run(), /original_credential_required/); assert.equal(f.requests.length, count);
  const r = await f.status(); assert.equal(r.state, 'ready'); assert.equal(r.network_accessed, false); assert.equal(r.attempts, 0);
});
test('rotated credential recovers the original principal but cannot send a successor', async t => {
  const rotated = 'ab'.repeat(32); let drop = true;
  const f = await migration(t, { tokens: [TOKEN, rotated], drop: () => { const v = drop; drop = false; return v; } });
  await f.run(); await writeFile(f.tokenFile, rotated); const recovered = await f.recover(); assert.equal(recovered.committed_steps, 1);
  const count = f.requests.length; await assert.rejects(f.run(), /original_credential_required/); assert.equal(f.requests.length, count);
  await writeFile(f.tokenFile, TOKEN); assert.equal((await f.run()).complete, true);
});
for (const [name, mutate] of [
  ['changed plan', async f => { const p = join(f.workdir, 'manifest.json'), m = JSON.parse(await readFile(p)); m.step_count--; await writeFile(p, encode(m)); }],
  ['changed future request', async f => { const p = join(f.workdir, 'requests', 'step-000011', 'intent.json'); await writeFile(p, '{}'); }],
  ['changed copied archive', async f => { await writeFile(join(f.workdir, 'archive', 'page-000001.json'), '{}'); }],
]) test(`complete preflight refuses ${name} before any destination request`, async t => {
  const f = await migration(t); await mutate(f); const count = f.requests.length;
  await assert.rejects(f.run()); assert.equal(f.requests.length, count);
});
for (const [name, mutate] of [
  ['partial reservation', async f => writeFile(attempt(f, 1), '{')],
  ['partial observation', async f => writeFile(attempt(f, 1, 'result.json'), '{')],
  ['wrong observation key', async f => { const p = attempt(f, 1, 'result.json'), r = JSON.parse(await readFile(p)); r.record.key = 'wrong'; await writeFile(p, encode(r)); }],
  ['wrong attempt hash', async f => { const p = attempt(f, 1, 'result.json'), r = JSON.parse(await readFile(p)); r.attempt_sha256 = '0'.repeat(64); await writeFile(p, encode(r)); }],
  ['wrong step binding', async f => { const p = attempt(f, 1), r = JSON.parse(await readFile(p)); r.step_index = 1; await writeFile(p, encode(r)); }],
  ['unknown journal file', async f => writeFile(join(f.workdir, 'journal', 'unknown'), 'x')],
  ['gap in attempts', async f => mkdir(join(f.workdir, 'journal', 'attempt-000003'), { mode: 0o700 })],
]) test(`corrupt ${name} refuses without publication or repair`, async t => {
  const f = await migration(t); await f.run({ maxOperations: 1 }); await mutate(f); const count = f.requests.length;
  await assert.rejects(f.run()); await assert.rejects(f.status()); assert.equal(f.requests.length, count);
});
test('empty reservation refuses instead of guessing it proves no send', async t => {
  const f = await migration(t), count = f.requests.length;
  await mkdir(join(f.workdir, 'journal', 'attempt-000001'), { mode: 0o700 });
  await assert.rejects(f.run(), /incomplete_reservation/); assert.equal(f.requests.length, count);
});
test('missing result after a committed request is recovered using its saved reservation', async t => {
  const f = await migration(t); const first = await f.run({ maxOperations: 1 }); const key = sends(f)[0].key;
  await unlink(attempt(f, 1, 'result.json')); const status = await f.status(); assert.equal(status.state, 'pending'); assert.equal(status.unsettled_attempts, 1);
  const result = await f.run(); assert.equal(result.complete, true); assert.equal(sends(f).filter(r => r.key === key).length, 1);
});
test('pre-cancellation performs no work, mid-send cancellation settles its journal', async t => {
  const stop = new AbortController(); let stall = false;
  const f = await migration(t, { mutate: (request, res) => {
    if (stall && !request.path.endsWith('/outcomes')) { res.writeHead(200, { 'content-type': 'application/json' }); res.write('{'); setTimeout(() => stop.abort(), 25); return false; }
  } });
  const before = new AbortController(); before.abort(); const count = f.requests.length;
  await assert.rejects(f.run({ signal: before.signal })); assert.equal(f.requests.length, count);
  stall = true; const first = await f.run({ signal: stop.signal }); assert.equal(first.state, 'pending');
  assert.equal((await f.status()).attempts, 1); stall = false;
  assert.equal((await f.run()).complete, true); assert.equal(sends(f).length, 11);
});
test('one operation deadline includes all requests, not a timeout reset for each step', async t => {
  const f = await migration(t, { mutate: async () => { await new Promise(r => setTimeout(r, 200)); } });
  const result = await f.run({ timeoutMs: 2000 }); assert.equal(result.complete, false); assert(sends(f).length < 11);
  assert.equal((await f.status()).complete, false);
});
test('concurrent runners never automatically publish the same request twice', async t => {
  const f = await migration(t);
  const results = await Promise.allSettled([f.run({ maxOperations: 2 }), f.run({ maxOperations: 2 })]);
  assert(results.some(r => r.status === 'fulfilled'));
  assert.equal(new Set(sends(f).map(r => r.key)).size, sends(f).length);
  assert.equal((await f.run()).complete, true); assert.equal(sends(f).length, 11);
});
test('per-step attempts remain bounded across repeated unresolved recovery invocations', async t => {
  const f = await migration(t, { beforeDestination: ({ request, req }) => { if (!request.path.endsWith('/outcomes')) { req.socket.destroy(); return false; } } });
  for (let i = 0; i < 32; i++) assert.equal((await f.run()).state, 'pending');
  const count = f.requests.length; await assert.rejects(f.run(), /attempt_limit/); assert.equal(f.requests.length, count); assert.equal(sends(f).length, 1);
});
test('empty migration completes offline without a token', async t => {
  const f = await migration(t, { rows: [] }); await unlink(f.tokenFile);
  const r = await executePullImport({ ...f.raw, operation: 'run' }); assert.equal(r.complete, true); assert.equal(r.new_operations, 0);
});
test('status is read-only and reports retained outcomes without HTTP', async t => {
  const f = await migration(t); await f.run({ maxOperations: 1 }); const p = attempt(f, 1, 'result.json');
  const before = await stat(p, { bigint: true }), count = f.requests.length;
  const r = await f.status(), after = await stat(p, { bigint: true });
  assert.equal(r.committed_steps, 1); assert.equal(r.local_read_only, true); assert.equal(f.requests.length, count);
  for (const key of ['mtimeNs', 'ctimeNs', 'size', 'ino']) assert.equal(before[key], after[key]);
});
test('explicit retry of an unstarted or completed key refuses', async t => {
  const f = await migration(t), intent = JSON.parse(await readFile(join(f.workdir, 'requests', 'step-000001', 'intent.json')));
  await assert.rejects(f.run({ retryKey: intent.key }), /retry_original_pending_key/);
  await f.run(); await assert.rejects(f.run({ retryKey: intent.key }), /retry_original_pending_key/);
});

test('default operation budget pauses a whole 21-PR migration and keeps every key', async t => {
  const f = await migration(t, { rows: Array.from({ length: 21 }, (_, i) => row(i + 1)) });
  assert.equal(f.prepared.steps, 105);
  const first = await f.run(); assert.equal(first.new_operations, 100); assert.equal(first.committed_steps, 100); assert.equal(first.complete, false);
  const second = await f.run(); assert.equal(second.new_operations, 5); assert.equal(second.complete, true);
  assert.equal(f.pulls.size, 21); assert.equal(sends(f).length, 105); assert.equal(new Set(sends(f).map(r => r.key)).size, 105);
});
test('a late weaker concurrent recovery cannot roll back a committed observation', async t => {
  let enteredResolve, releaseOpen, readResolve, releaseRead, opened = false;
  const entered = new Promise(r => enteredResolve = r), openGate = new Promise(r => releaseOpen = r);
  const readCaptured = new Promise(r => readResolve = r), readGate = new Promise(r => releaseRead = r);
  t.after(() => { releaseOpen(); releaseRead(); });
  const f = await migration(t, {
    beforeDestination: async ({ request }) => { if (request.path.endsWith('/100/open')) { opened = true; enteredResolve(); await openGate; } },
    mutate: async (request, _res, result) => { if (opened && request.path.endsWith('/outcomes') && result.state === 'key_not_observed') { readResolve(); await readGate; } },
  });
  const send = f.run({ maxOperations: 1 }); await entered;
  const recover = f.recover(); await readCaptured; releaseOpen();
  const committed = await send; assert.equal(committed.committed_steps, 1);
  releaseRead(); const late = await recover; assert.equal(late.committed_steps, 1);
  assert.equal((await f.status()).committed_steps, 1); assert.equal(sends(f).length, 1);
  assert.equal((await f.run()).complete, true);
});
test('conflicting valid terminal observations stop journal replay before network', async t => {
  const f = await migration(t); await f.run({ maxOperations: 1 });
  const original = await readFile(attempt(f, 1, 'result.json'));
  await unlink(attempt(f, 1, 'result.json')); await f.recover();
  await writeFile(attempt(f, 1, 'result.json'), original, { mode: 0o600 });
  const p = attempt(f, 2, 'result.json'), result = JSON.parse(await readFile(p));
  result.record.outcome.transaction.tx_id = 'another-valid-opaque-transaction';
  result.record.outcome.decision.repository_commit_id = 'another-valid-rcr';
  await writeFile(p, encode(result)); const count = f.requests.length;
  await assert.rejects(f.run(), /outcome_regressed_or_conflicted/); assert.equal(f.requests.length, count);
});
test('rotated recovery must still identify the original independently selected principal', async t => {
  const rotated = 'ab'.repeat(32); let lose = true, corrupt = false;
  const f = await migration(t, { tokens: [TOKEN, rotated], drop: () => { const r = lose; lose = false; return r; },
    mutate: (request, _res, result) => { if (corrupt && request.path.endsWith('/outcomes')) result.principal_id = 'fe'.repeat(16); } });
  await f.run(); await writeFile(f.tokenFile, rotated); corrupt = true;
  const refused = await f.recover(); assert.equal(refused.state, 'pending'); assert.equal(refused.current.last_error.code, 'outcome_scope_or_semantics_changed');
  assert.equal(sends(f).length, 1); corrupt = false;
  assert.equal((await f.recover()).committed_steps, 1); assert.equal(sends(f).length, 1);
});

test('changed destination branch tips cause native refusal without an implicit refresh', async t => {
  const f = await migration(t), branch = f.rows[0].data.source_ref;
  f.refs.set(branch, 'f'.repeat(40));
  const r = await f.run(); assert.equal(r.state, 'refused'); assert.equal(r.committed_steps, 0);
  assert.equal(sends(f).length, 1); assert.equal(new URLSearchParams(sends(f)[0].body).get('source_tip'), 'a'.repeat(40));
  assert.equal(f.refs.get(branch), 'f'.repeat(40)); assert.equal(f.pulls.size, 0);
});
