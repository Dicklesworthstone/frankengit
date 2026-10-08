import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile, writeFile, access, readdir, lstat } from 'node:fs/promises';
import { join } from 'node:path';
import { spawn, spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { recoverGitBundle } from '../../scripts/lib/source-recovery.mjs';
import { harness, readFixture } from './fixtures/native-recovery-harness.mjs';
const marker = '.frankengit-source-recovery.json';
const absent = async path => assert.rejects(access(path), { code: 'ENOENT' });

for (const format of ['sha1', 'sha256']) test(`native ${format} recovery publishes HEAD last and resumes exactly`, async t => {
  const h = await harness(t, format), phases = [];
  const result = await recoverGitBundle(h.bytes, h.destination, h.request, { ...h.options,
    onProgress: async e => { phases.push(e.phase); if (e.phase === 'before_publication') await absent(join(h.destination, 'HEAD')); } });
  assert.equal(result.state, 'complete');
  assert.equal(result.verification.verifier_backend, 'native-fg');
  assert.equal(result.native_authority_restored, false);
  assert.equal(result.forge_state_restored, false);
  assert.ok(phases.indexOf('staged:HEAD') < phases.indexOf('published'));
  const packNames = await readdir(join(h.destination, 'objects/pack'));
  assert.equal(packNames.length, 2);
  const index = await readFile(join(h.destination, 'objects/pack', packNames.find(name => name.endsWith('.idx'))));
  assert.deepEqual(index, await readFixture(format, 'idx'));
  assert.equal(await readFile(join(h.destination, 'HEAD'), 'utf8'), 'ref: refs/heads/main\n');
  assert.equal((await lstat(h.destination)).mode & 0o077, 0);
  const resumed = await recoverGitBundle(h.bytes, h.destination, h.request, { ...h.options, resume: true });
  assert.equal(resumed.already_published, true);
  assert.equal(resumed.plan_sha256, result.plan_sha256);
  assert.equal(resumed.appended_bytes, 0);
});

test('cancellation retains exact stage; explicit resume finishes without overwrite', async t => {
  const h = await harness(t), controller = new AbortController();
  await assert.rejects(recoverGitBundle(h.bytes, h.destination, h.request, { ...h.options,
    signal: controller.signal, onProgress(e) { if (e.phase === 'staged:config') controller.abort(); } }),
  error => error.state === 'staging' && error.code === 'recovery_cancelled');
  await absent(join(h.destination, 'HEAD'));
  const original = await readFile(join(h.destination, marker));
  const resumed = await recoverGitBundle(h.bytes, h.destination, h.request, { ...h.options, resume: true });
  assert.equal(resumed.state, 'complete'); assert.equal(resumed.already_published, false);
  assert.ok(resumed.reused_bytes > 0);
  assert.deepEqual(await readFile(join(h.destination, marker)), original);
});

test('cancellation after HEAD does not abandon finalization or roll back', async t => {
  const h = await harness(t), controller = new AbortController();
  const result = await recoverGitBundle(h.bytes, h.destination, h.request, { ...h.options,
    signal: controller.signal, onProgress(e) { if (e.phase === 'published') controller.abort(); } });
  assert.equal(result.state, 'complete'); assert.equal(result.cancellation_requested, true);
  await absent(join(h.destination, '.frankengit-source-recovery-head'));
  await absent(join(h.destination, '.frankengit-source-recovery.lock'));
});

test('invalid native selection/refusal never creates destination or imports legacy module', async t => {
  const h = await harness(t);
  for (const options of [{ nativeFg: undefined }, { nativeFg: null }, { nativeFg: 'fg' },
    { ...h.options, verificationLimits: {} }]) {
    await assert.rejects(recoverGitBundle(h.bytes, h.destination, h.request, options));
    await absent(h.destination);
  }
  await h.configure({ mode: 'refuse' });
  await assert.rejects(recoverGitBundle(h.bytes, h.destination, h.request, h.options), /native_verification_refused/);
  await absent(h.destination);
});

test('changed resume constraints refuse without altering retained bytes', async t => {
  const h = await harness(t), controller = new AbortController();
  await assert.rejects(recoverGitBundle(h.bytes, h.destination, h.request, { ...h.options, signal: controller.signal,
    onProgress(e) { if (e.phase === 'staged:config') controller.abort(); } }));
  const original = await readFile(join(h.destination, marker));
  await assert.rejects(recoverGitBundle(h.bytes, h.destination, { ...h.request,
    expectations: { object_format: 'sha1' } }, { ...h.options, resume: true }));
  assert.deepEqual(await readFile(join(h.destination, marker)), original);
  await absent(join(h.destination, 'HEAD'));
  await absent(join(h.destination, '.frankengit-source-recovery-owners'));
});

test('tampered staged metadata refuses without truncation or HEAD publication', async t => {
  const h = await harness(t), tampered = Buffer.from('not the original config');
  await assert.rejects(recoverGitBundle(h.bytes, h.destination, h.request, { ...h.options,
    async onProgress(e) { if (e.phase === 'before_publication') await writeFile(join(h.destination, 'config'), tampered); } }));
  await absent(join(h.destination, 'HEAD'));
  await assert.rejects(recoverGitBundle(h.bytes, h.destination, h.request, { ...h.options, resume: true }));
  assert.deepEqual(await readFile(join(h.destination, 'config')), tampered);
});

test('competing publishers cannot replace the same destination', async t => {
  const h = await harness(t);
  const outcomes = await Promise.allSettled([1, 2].map(() => recoverGitBundle(h.bytes, h.destination, h.request, h.options)));
  assert.equal(outcomes.filter(o => o.status === 'fulfilled').length, 1);
  assert.equal(outcomes.filter(o => o.status === 'rejected').length, 1);
  assert.equal(await readFile(join(h.destination, 'HEAD'), 'utf8'), 'ref: refs/heads/main\n');
});

for (const phase of ['staged:config', 'published']) test(`SIGKILL at ${phase} retains a resumable exact operation`, async t => {
  const h = await harness(t);
  const module = new URL('../../scripts/lib/source-recovery.mjs', import.meta.url).href;
  const worker = `import {recoverGitBundle} from ${JSON.stringify(module)};
    const bytes=Buffer.from(${JSON.stringify(h.bytes.toString('hex'))},'hex');
    await recoverGitBundle(bytes,${JSON.stringify(h.destination)},${JSON.stringify(h.request)},
      {nativeFg:${JSON.stringify(h.fg)},async onProgress(e){ if(e.phase===${JSON.stringify(phase)}) {
        process.stdout.write('PAUSED\\n'); await new Promise(()=>{setInterval(()=>{},1000)}); } }});`;
  const child = spawn(process.execPath, ['--input-type=module', '-e', worker], { stdio: ['ignore', 'pipe', 'pipe'] });
  const closed = new Promise(resolve => child.once('close', (code, signal) => resolve({ code, signal })));
  t.after(async () => { child.kill('SIGKILL'); await closed; });
  let errors = ''; child.stderr.on('data', chunk => { errors += chunk; });
  await new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(Error(`worker did not pause: ${errors}`)), 10000);
    child.once('error', reject);
    child.stdout.once('data', chunk => { clearTimeout(timer); assert.match(chunk.toString(), /PAUSED/); resolve(); });
    child.once('close', () => { clearTimeout(timer); reject(Error(`worker exited: ${errors}`)); });
  });
  await assert.rejects(recoverGitBundle(h.bytes, h.destination, h.request, { ...h.options, resume: true }), /recovery_owner_active/);
  child.kill('SIGKILL'); assert.equal((await closed).signal, 'SIGKILL');
  if (phase === 'staged:config') await absent(join(h.destination, 'HEAD'));
  const result = await recoverGitBundle(h.bytes, h.destination, h.request, { ...h.options, resume: true });
  assert.equal(result.state, 'complete'); assert.equal(result.already_published, phase === 'published');
  assert.equal(await readFile(join(h.destination, 'HEAD'), 'utf8'), 'ref: refs/heads/main\n');
});

for (const format of ['sha1', 'sha256']) test(`pinned Git 2.47.3 reads the recovered ${format} fixture`, async t => {
  const git = '/usr/bin/git';
  if (spawnSync(git, ['--version'], { encoding: 'utf8' }).stdout?.trim() !== 'git version 2.47.3') {
    t.skip('exact pinned Git 2.47.3 oracle unavailable'); return;
  }
  const h = await harness(t, format);
  await recoverGitBundle(h.bytes, h.destination, h.request, h.options);
  const env = { PATH: '/usr/bin:/bin', HOME: h.root, GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: '/dev/null', GIT_ALLOW_PROTOCOL: 'file' };
  const run = args => { const r = spawnSync(git, ['--git-dir', h.destination, ...args], { env, encoding: 'utf8', timeout: 10000 });
    assert.equal(r.status, 0, r.stderr); return r.stdout; };
  run(['fsck', '--strict']);
  assert.equal(run(['show', 'HEAD:a.txt']), 'alpha changed\n');
  assert.equal(run(['symbolic-ref', 'HEAD']).trim(), 'refs/heads/main');
  assert.equal(run(['rev-parse', 'refs/tags/v1^{}']), run(['rev-parse', 'HEAD']));
});

test('actual native fg recovery integration', { skip: !process.env.FG_NATIVE_BIN && 'no built native fg supplied' }, async t => {
  const h = await harness(t);
  const result = await recoverGitBundle(h.bytes, h.destination, h.request, { nativeFg: process.env.FG_NATIVE_BIN });
  assert.equal(result.state, 'complete');
  assert.equal(result.verification.object_graph_verified, true);
});
