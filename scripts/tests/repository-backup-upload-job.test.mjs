// Real files, Ed25519 and loopback TLS. Payloads are opaque operator fixtures,
// not native fg archives, remote durability proof or independent failure domains.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile, writeFile, mkdir, unlink, lstat, readdir, rename, link, chmod } from 'node:fs/promises';
import { generateKeyPairSync } from 'node:crypto';
import { join } from 'node:path';
import { sealRepositoryBackupUploadJob as seal, runRepositoryBackupUploadJob as run,
  repositoryBackupUploadJobOptions as options, MAX_BACKUP_UPLOAD_TARGETS,
  MAX_BACKUP_UPLOAD_TOTAL_BYTES } from '../lib/repository-backup-upload-job.mjs';
import { tlsFixture, DATA, NOW } from './backup-download-fixture.mjs';

async function fixture(t, format = 'sha256') {
  const f = await tlsFixture(t); await f.sign(DATA, { object_format: format });
  const jobDirectory = join(f.root, 'jobs'); await mkdir(jobDirectory, { mode: 0o700 });
  const objects = new Map(), events = []; let intercept;
  f.setHandler(async (req, res) => {
    const path = new URL(req.url, f.url).pathname; events.push({ method: req.method, path, url: req.url });
    if (intercept && await intercept(req, res, path)) return;
    if (req.method === 'GET') {
      const bytes = objects.get(path); res.writeHead(bytes ? 200 : 404, { 'content-length': bytes?.length ?? 0 }); res.end(bytes); return;
    }
    assert.equal(req.method, 'PUT'); assert.equal(req.headers['if-none-match'], '*');
    if (objects.has(path)) { res.writeHead(412, { 'content-length': 0 }); res.end(); return; }
    try { const parts = []; for await (const part of req) parts.push(part); objects.set(path, Buffer.concat(parts)); res.writeHead(201, { 'content-length': 0 }); res.end(); }
    catch { res.destroy(); }
  });
  const origin = new URL(f.url).origin;
  const targets = ['one', 'two'].map(name => ({ target: Object.fromEntries(['archive', 'approval'].map(kind => [kind, {
    get: `${origin}/${name}/${kind}?SECRET=original-read`, put: `${origin}/${name}/${kind}?SECRET=original-write` }])), caFile: f.caFile }));
  const policy = { ...f.options.policy, object_format: format };
  const base = { trustedLocal: true, trustKey: f.trustKey, policy, targets, maximumBytes: DATA.length, timeoutMs: 5000, now: NOW };
  const sealing = { ...base, jobDirectory, input: f.local, approval: f.approval, maximumTotalBytes: 3 * DATA.length };
  const running = receipt => ({ ...base, intent: receipt.job.intent, maximumTotalBytes: 6 * DATA.length });
  const order = options(sealing, 'seal').targets;
  return { ...f, jobDirectory, objects, events, targets, policy, base, sealing, running, order,
    intercept(fn) { intercept = fn; } };
}
async function refusal(promise, expected) {
  let error; try { await promise; } catch (caught) { error = caught; }
  assert.ok(error, `expected ${expected}`); if (expected) assert.equal(error.code, expected);
  assert.ok(!JSON.stringify(error).includes('SECRET'), 'capabilities are not diagnostic data'); return error;
}
const remotePath = (row, kind) => new URL(row.target[kind].get).pathname;
const puts = f => f.events.filter(event => event.method === 'PUT');
function refreshed(rows) {
  return [...rows].reverse().map(row => ({ ...row, target: Object.fromEntries(Object.entries(row.target).map(([kind, pair]) => [kind,
    Object.fromEntries(Object.entries(pair).map(([method, text]) => { const url = new URL(text); url.search = '?SECRET=refreshed-' + method; return [method, url.href]; }))])) }));
}

for (const format of ['sha1', 'sha256']) test(`${format}: seal retains original bytes and approval; run survives source/control loss with refreshed capabilities`, async t => {
  const f = await fixture(t, format), original = await readFile(f.approval), sealed = await seal(f.sealing);
  assert.equal(f.events.length, 0); assert.equal(sealed.source_custody_retained, true);
  assert.equal(sealed.snapshot.streaming.total_payload_bytes_read, String(3 * DATA.length));
  const manifest = await readFile(sealed.job.intent, 'utf8');
  assert.ok(!manifest.includes('SECRET')); assert.ok(!manifest.includes('https://'));
  assert.deepEqual(await readFile(sealed.snapshot.candidate.input), DATA);
  assert.deepEqual(await readFile(sealed.snapshot.candidate.approval), original);
  const newKey = join(f.root, 'independently-supplied-key.pem'); await writeFile(newKey, await readFile(f.trustKey));
  await unlink(f.local); await unlink(f.approval); await unlink(f.trustKey);
  const result = await run({ ...f.running(sealed), trustKey: newKey, targets: refreshed(f.targets) });
  assert.equal(result.state, 'complete'); assert.equal(result.completed_targets.length, 2);
  assert.equal(result.streaming.total_payload_bytes, String(6 * DATA.length));
  assert.ok(!JSON.stringify(result).includes('SECRET'));
  for (const row of f.order) {
    assert.deepEqual(f.objects.get(remotePath(row, 'archive')), DATA);
    assert.deepEqual(f.objects.get(remotePath(row, 'approval')), original);
  }
  assert.equal(result.native_content_verified, false); assert.equal(result.failure_domain_independence_verified, false);
});

test('equivalent seal retries and capability renewal preserve the exact immutable intent and inode', async t => {
  const f = await fixture(t), first = await seal(f.sealing), prior = await lstat(first.job.intent);
  const second = await seal({ ...f.sealing, targets: refreshed(f.targets) });
  assert.equal(second.job.intent, first.job.intent); assert.equal((await lstat(first.job.intent)).ino, prior.ino);
  assert.equal(second.snapshot.streaming.total_payload_bytes_read, String(2 * DATA.length));
  assert.equal(f.events.length, 0);
});
test('a complete explicit rerun rechecks all remote objects and sends no further PUT', async t => {
  const f = await fixture(t), sealed = await seal(f.sealing), first = await run(f.running(sealed));
  f.events.length = 0;
  const again = await run({ ...f.running(sealed), targets: refreshed(f.targets) });
  assert.deepEqual(again.job, first.job); assert.equal(puts(f).length, 0);
  assert.equal(f.events.length, 6); assert.equal(again.streaming.total_payload_bytes, String(4 * DATA.length));
  assert.ok(again.completed_targets.every(row => row.result.disposition.archive === 'reused'));
});
test('a lost second-target approval response preserves completed first target and permits exact restart', async t => {
  const f = await fixture(t), sealed = await seal(f.sealing);
  const lost = remotePath(f.order[1], 'approval'); let cut = true;
  f.intercept(async (req, res, path) => {
    if (cut && req.method === 'PUT' && path === lost) {
      cut = false; const parts = []; for await (const part of req) parts.push(part);
      f.objects.set(path, Buffer.concat(parts)); req.socket.destroy(); return true;
    }
  });
  const error = await refusal(run(f.running(sealed)), 'backup_upload_transport');
  assert.equal(error.upload_job.completed_targets.length, 1); assert.equal(error.publication_state, 'approval_put_unknown');
  assert.equal(error.upload_job.active_target, f.order[1].target_id);
  assert.equal(error.upload_job.streaming.total_payload_bytes, String(6 * DATA.length));
  assert.equal(error.completed_result, undefined);
  const before = puts(f).length; const again = await run({ ...f.running(sealed), targets: refreshed(f.targets) });
  assert.equal(again.state, 'complete'); assert.equal(puts(f).length, before);
});
test('conflicting late remote state refuses rather than trusting a previous complete job receipt', async t => {
  const f = await fixture(t), sealed = await seal(f.sealing); await run(f.running(sealed));
  f.objects.set(remotePath(f.order[0], 'archive'), Buffer.alloc(DATA.length, 1));
  const before = puts(f).length;
  const error = await refusal(run(f.running(sealed)), 'backup_upload_digest');
  assert.equal(error.upload_job.completed_targets.length, 0); assert.equal(puts(f).length, before);
});
test('archive retention refuses a short aggregate seal budget before publishing snapshot or intent', async t => {
  const f = await fixture(t);
  await refusal(seal({ ...f.sealing, maximumTotalBytes: 3 * DATA.length - 1 }), 'backup_upload_job_budget');
  assert.deepEqual(await readdir(f.jobDirectory), []); assert.equal(f.events.length, 0);
});
test('aggregate run budget reserves every fresh target before opening any network connection', async t => {
  const f = await fixture(t), sealed = await seal(f.sealing);
  await refusal(run({ ...f.running(sealed), maximumTotalBytes: 6 * DATA.length - 1 }), 'backup_upload_job_budget');
  assert.equal(f.events.length, 0); assert.equal(f.objects.size, 0);
});
test('a lower policy floor cannot be smuggled into a valid retained job; a stronger accepted floor works', async t => {
  const f = await fixture(t); f.sealing.policy = { ...f.policy, minimum_head_generation: '4' };
  const sealed = await seal(f.sealing);
  await refusal(run(f.running(sealed)), 'backup_upload_job_policy_mismatch'); assert.equal(f.events.length, 0);
  const accepted = await run({ ...f.running(sealed), policy: { ...f.policy, minimum_head_generation: '5' } });
  assert.equal(accepted.completed_targets.length, 2);
});
test('a different independent key and an expired approval both refuse before network work', async t => {
  const f = await fixture(t), sealed = await seal(f.sealing);
  const other = generateKeyPairSync('ed25519').publicKey, path = join(f.root, 'other.pem');
  await writeFile(path, other.export({ type: 'spki', format: 'pem' }));
  await refusal(run({ ...f.running(sealed), trustKey: path }), 'backup_untrusted_signer');
  await refusal(run({ ...f.running(sealed), now: NOW + 2 * 86400000 }), 'backup_approval_expired');
  assert.equal(f.events.length, 0);
});
test('a differently serialized valid approval cannot replace the retained original envelope', async t => {
  const f = await fixture(t), sealed = await seal(f.sealing), path = sealed.snapshot.candidate.approval;
  const changed = JSON.stringify(JSON.parse(await readFile(path, 'utf8')), null, 2) + '\n';
  await writeFile(path, changed);
  await refusal(run(f.running(sealed)), 'backup_upload_job_checkpoint_mismatch'); assert.equal(f.events.length, 0);
});
test('retained archive corruption is detected before remote publication', async t => {
  const f = await fixture(t), sealed = await seal(f.sealing);
  await writeFile(sealed.snapshot.candidate.input, Buffer.alloc(DATA.length, 7));
  await refusal(run(f.running(sealed)), 'backup_upload_source_digest'); assert.equal(f.events.length, 0);
});
test('the sealed target set cannot be changed, omitted or extended through renewed capabilities', async t => {
  const f = await fixture(t), sealed = await seal(f.sealing), altered = structuredClone(f.targets);
  for (const method of ['get', 'put']) altered[0].target.archive[method] = altered[0].target.archive[method].replace('/archive?', '/elsewhere?');
  await refusal(run({ ...f.running(sealed), targets: altered }), 'backup_upload_job_target_mismatch');
  await refusal(run({ ...f.running(sealed), targets: f.targets.slice(0, 1) }), 'backup_upload_job_target_mismatch');
  assert.equal(f.events.length, 0);
});
test('unknown options, duplicate logical objects and oversized target sets refuse without file access', async () => {
  const target = { archive: { get: 'https://example.com/a?read', put: 'https://example.com/a?write' },
    approval: { get: 'https://example.com/b?read', put: 'https://example.com/b?write' } };
  const raw = { trustedLocal: true, jobDirectory: '/missing/job', input: '/missing/source', approval: '/missing/approval',
    trustKey: '/missing/key', policy: { tenant_id: '1'.repeat(32), repository_id: '2'.repeat(32), incarnation_id: '3'.repeat(32),
      object_format: 'sha1', minimum_head_generation: '1' }, targets: [{ target }] };
  await refusal(seal({ ...raw, targets: [{ target }, { target }] }), 'backup_upload_job_target_alias');
  await refusal(seal({ ...raw, targets: Array(MAX_BACKUP_UPLOAD_TARGETS + 1).fill({ target }) }), 'backup_upload_job_targets');
  await refusal(seal({ ...raw, force: true }), 'backup_upload_job_options');
  await refusal(seal({ ...raw, trustedLocal: false }), 'backup_upload_job_options');
  await refusal(seal({ ...raw, maximumTotalBytes: MAX_BACKUP_UPLOAD_TOTAL_BYTES + 1 }), 'backup_upload_job_budget');
});
test('private retained files refuse hard-link aliases and unsafe permissions', async t => {
  const f = await fixture(t), sealed = await seal(f.sealing), archive = sealed.snapshot.candidate.input;
  await link(archive, join(f.root, 'alias'));
  await refusal(run(f.running(sealed)), 'backup_upload_job_file_links'); await unlink(join(f.root, 'alias'));
  await chmod(archive, 0o644);
  await refusal(run(f.running(sealed)), 'backup_upload_job_private_owner'); assert.equal(f.events.length, 0);
});
test('intent byte tampering refuses before any external effects', async t => {
  const f = await fixture(t), sealed = await seal(f.sealing);
  await writeFile(sealed.job.intent, (await readFile(sealed.job.intent, 'utf8')) + ' ');
  await refusal(run(f.running(sealed)), 'backup_upload_job_intent_hash'); assert.equal(f.events.length, 0);
});
test('mutable targets and policy are captured before the first asynchronous step', async t => {
  const f = await fixture(t), raw = { ...f.sealing, policy: { ...f.policy }, targets: structuredClone(f.targets) };
  const pending = seal(raw); raw.policy.minimum_head_generation = '9999999999999999999'; raw.targets[0].target.archive.get = 'http://invalid';
  const sealed = await pending; const result = await run(f.running(sealed));
  assert.equal(result.state, 'complete');
});
test('source corruption after one target completes preserves that receipt and prevents the next target', async t => {
  const f = await fixture(t), sealed = await seal(f.sealing); let changed = false;
  const error = await refusal(run({ ...f.running(sealed), async onProgress(event) {
    if (event.phase === 'target_complete' && !changed) { changed = true; await writeFile(sealed.snapshot.candidate.input, Buffer.alloc(DATA.length, 8)); }
  } }), 'backup_upload_job_file_changed');
  assert.equal(error.upload_job.completed_targets.length, 1);
  assert.equal(f.objects.has(remotePath(f.order[1], 'archive')), false);
});
test('directory replacement at a publication callback refuses without publishing the approval', async t => {
  const f = await fixture(t), sealed = await seal(f.sealing); let changed = false;
  await refusal(run({ ...f.running(sealed), async onProgress(event) {
    if (!changed && event.phase === 'target_progress' && event.target_phase === 'archive_verified') {
      changed = true; await rename(f.jobDirectory, f.jobDirectory + '-saved'); await mkdir(f.jobDirectory, { mode: 0o700 });
    }
  } }));
  assert.equal(f.objects.has(remotePath(f.order[0], 'approval')), false);
});
test('cancellation after the first target retains completed work and prevents additional publication', async t => {
  const f = await fixture(t), sealed = await seal(f.sealing), controller = new AbortController();
  const error = await refusal(run({ ...f.running(sealed), signal: controller.signal,
    onProgress(event) { if (event.phase === 'target_complete') controller.abort(); } }), 'backup_cancelled');
  assert.equal(error.upload_job.completed_targets.length, 1); assert.equal(error.completed_result, undefined);
  assert.equal(f.objects.has(remotePath(f.order[1], 'archive')), false);
  assert.equal((await run(f.running(sealed))).state, 'complete');
});
test('post-completion cancellation cannot revoke all confirmed remote readbacks', async t => {
  const f = await fixture(t), sealed = await seal(f.sealing), controller = new AbortController();
  const result = await run({ ...f.running(sealed), signal: controller.signal,
    onProgress(event) { if (event.phase === 'target_complete' && event.completed_targets === 2) controller.abort(); } });
  assert.equal(result.state, 'complete'); assert.equal(result.cancellation_requested, true);
});
test('a final observer failure retains a complete job result, including both target receipts', async t => {
  const f = await fixture(t), sealed = await seal(f.sealing);
  const error = await refusal(run({ ...f.running(sealed), onProgress(event) {
    if (event.phase === 'target_complete' && event.completed_targets === 2) throw Object.assign(new Error('observer'), { code: 'observer' });
  } }), 'observer');
  assert.equal(error.completed_result.state, 'complete'); assert.equal(error.completed_result.completed_targets.length, 2);
  assert.equal(error.publication_state, 'complete');
});
test('callback-owned completion fields cannot impersonate a completed upload', async t => {
  const f = await fixture(t), sealed = await seal(f.sealing);
  const error = await refusal(run({ ...f.running(sealed), onProgress(event) {
    if (event.phase === 'target_progress' && event.target_phase === 'source_verified') {
      throw Object.assign(new Error('callback'), { code: 'callback', completed_result: {
        type: 'repository_backup_upload', state: 'complete', streaming: { total_payload_bytes: String(3 * DATA.length) },
      } });
    }
  } }), 'callback');
  assert.equal(error.completed_result, undefined); assert.equal(error.upload_job.completed_targets.length, 0);
  assert.equal(error.publication_state, 'source_verified'); assert.equal(f.events.length, 0);
  assert.equal(error.upload_job.streaming.total_payload_bytes, String(DATA.length));
});
test('callback-owned completion fields cannot claim that an unsealed snapshot is a published job', async t => {
  const f = await fixture(t);
  const error = await refusal(seal({ ...f.sealing, onProgress(event) {
    if (event.phase === 'snapshot_retained') throw Object.assign(new Error('callback'), {
      code: 'callback', completed_result: { type: 'repository_backup_upload_job_sealed', state: 'complete' },
    });
  } }), 'callback');
  assert.equal(error.completed_result, undefined); assert.ok(error.snapshot);
  assert.equal((await readdir(f.jobDirectory)).some(name => name.startsWith('upload-job-')), false);
});
test('a failed seal delivery retains the published immutable job and its source custody', async t => {
  const f = await fixture(t);
  const error = await refusal(seal({ ...f.sealing, onProgress(event) {
    if (event.phase === 'job_sealed') throw Object.assign(new Error('delivery'), { code: 'delivery' });
  } }), 'delivery');
  assert.equal(error.completed_result.type, 'repository_backup_upload_job_sealed');
  assert.equal((await run(f.running(error.completed_result))).state, 'complete');
});

test('changing a captured TLS CA after one completion preserves that receipt and blocks the next target', async t => {
  const f = await fixture(t), sealed = await seal(f.sealing), original = await readFile(f.caFile);
  const changed = Buffer.from(original); changed[0] ^= 1;
  const error = await refusal(run({ ...f.running(sealed), async onProgress(event) {
    if (event.phase === 'target_complete' && event.completed_targets === 1) await writeFile(f.caFile, changed);
  } }), 'backup_upload_job_file_changed');
  assert.equal(error.upload_job.completed_targets.length, 1);
  assert.equal(error.upload_job.completed_targets[0].result.state, 'complete');
  assert.deepEqual(f.objects.get(remotePath(f.order[0], 'approval')), await readFile(sealed.snapshot.candidate.approval));
  assert.equal(f.events.some(event => event.path === remotePath(f.order[1], 'archive')
    || event.path === remotePath(f.order[1], 'approval')), false);
});
