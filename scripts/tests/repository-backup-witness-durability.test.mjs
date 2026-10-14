// Real witness files and signatures with narrowly injected filesystem failures.
// The native peer in recoveryFixture is a contract fixture, not Rust fg.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import { constants } from 'node:fs';
import { syncBuiltinESMExports } from 'node:module';
import { join } from 'node:path';
import { withRepositoryBackupWitness } from '../lib/repository-backup-witness.mjs';
import { recoverRepositoryBackup } from '../lib/repository-backup-recovery.mjs';
import { recoveryFixture, DATA } from './backup-recovery-fixture.mjs';

const error = code => Object.assign(new Error(code), { code });
const missing = path => assert.rejects(fs.lstat(path), { code: 'ENOENT' });
async function remember(f, envelope, policy = f.options.policy) {
  return withRepositoryBackupWitness(f.witness, f.trustKey, policy, {}, async witness => {
    await witness.observe(envelope); return witness.snapshot();
  });
}

// Patch only the witness operation. Every opened handle remains a real OS file;
// errors are injected at one named boundary and all exports are restored.
function inject(root, fault, controller) {
  const original = { open: fs.open, rename: fs.rename, unlink: fs.unlink };
  const handles = [], state = join(root, 'witness.json');
  let renamed = false, reads = 0, hits = 0;
  const temporary = path => String(path).startsWith(join(root, '.witness-')) && String(path).endsWith('.tmp');
  fs.open = async (path, ...args) => {
    if (String(path) === state && ++reads === 2 && fault === 'precheck') { hits++; throw error('EIO'); }
    if (temporary(path) && fault === 'create') { hits++; throw error('ENOSPC'); }
    const file = await original.open(path, ...args); handles.push(file);
    if (temporary(path) && (args[0] & constants.O_CREAT)) {
      const write = file.writeFile.bind(file), sync = file.sync.bind(file), close = file.close.bind(file);
      if (['write', 'cleanup'].includes(fault)) file.writeFile = async bytes => {
        await write(bytes.subarray(0, 7)); hits++; throw error('ENOSPC');
      };
      if (fault === 'sync') file.sync = async () => { hits++; throw error('EIO'); };
      if (fault === 'cancel') file.sync = async () => { await sync(); hits++; controller.abort(); };
      if (fault === 'close') file.close = async () => { await close(); hits++; throw error('EIO'); };
    }
    if (String(path) === root && fault === 'directory_sync') {
      const sync = file.sync.bind(file);
      file.sync = async () => { if (renamed) { hits++; throw error('EIO'); } return sync(); };
    }
    return file;
  };
  fs.rename = async (from, to) => {
    if (temporary(from) && String(to) === state) {
      if (fault === 'rename_before') { hits++; throw error('EIO'); }
      const value = await original.rename(from, to); renamed = true;
      if (fault === 'rename_after') { hits++; throw error('EIO'); }
      return value;
    }
    return original.rename(from, to);
  };
  fs.unlink = async path => {
    if (temporary(path) && fault === 'cleanup') throw error('EACCES');
    return original.unlink(path);
  };
  syncBuiltinESMExports();
  return { restore() { Object.assign(fs, original); syncBuiltinESMExports(); },
    check() { assert(hits > 0, `fault ${fault} reached`); assert(handles.every(file => file.fd === -1), 'all owned descriptors closed'); } };
}

for (const fault of ['precheck', 'create', 'write', 'sync', 'rename_before', 'rename_after', 'directory_sync', 'close', 'cleanup', 'cancel']) {
  test(`failed ${fault} of a newer checkpoint keeps a blocking witness lease`, async t => {
    const f = await recoveryFixture(t), old = await fs.readFile(f.approval);
    await remember(f, old); const before = await fs.readFile(join(f.witness, 'witness.json'));
    const newer = (await f.sign(DATA, { head_generation: '18446744073709551615' })).envelope;
    const controller = new AbortController(), injected = inject(f.witness, fault, controller);
    let caught;
    try {
      await withRepositoryBackupWitness(f.witness, f.trustKey, f.options.policy, { signal: controller.signal }, async w => w.observe(newer));
    } catch (e) { caught = e; }
    finally { injected.restore(); }
    injected.check(); assert(caught, 'persistence failure returned');
    assert.equal(caught.code, fault === 'cancel' ? 'backup_cancelled' : ['create', 'write', 'cleanup'].includes(fault) ? 'ENOSPC' : 'EIO');
    assert.equal(caught.witness_lock_retained, true);
    await fs.lstat(join(f.witness, '.witness-lock'));
    if (!['rename_after', 'directory_sync', 'close'].includes(fault)) assert.deepEqual(await fs.readFile(join(f.witness, 'witness.json')), before);
    if (fault === 'rename_after') assert.equal(caught.witness_publication_state, 'publication_unknown');
    if (fault === 'cleanup') assert.equal(caught.witness_cleanup_error, 'EACCES');
    // A fresh operation cannot exploit the old on-disk state after the failed
    // update, even when both the old signature and original bytes are valid.
    await fs.writeFile(f.approval, old);
    await assert.rejects(recoverRepositoryBackup(f.verifyOptions()), { code: 'backup_witness_locked' });
    assert.equal(f.requests.length, 0); assert.deepEqual(await f.events(), []);
  });
}

test('failed conflict retention blocks later selection of either same-generation statement', async t => {
  const f = await recoveryFixture(t), old = await fs.readFile(f.approval); await remember(f, old);
  const conflict = (await f.sign(Buffer.alloc(DATA.length, 0x22))).envelope;
  const injected = inject(f.witness, 'sync'); let caught;
  try { await remember(f, conflict); } catch (e) { caught = e; } finally { injected.restore(); }
  injected.check(); assert.equal(caught.witness_lock_retained, true);
  for (const envelope of [old, conflict]) await assert.rejects(remember(f, envelope), { code: 'backup_witness_locked' });
});

test('failed independent floor increase cannot be reopened with the prior weaker floor', async t => {
  const f = await recoveryFixture(t), old = await fs.readFile(f.approval); await remember(f, old);
  const injected = inject(f.witness, 'sync'); let caught, invoked = false;
  try { await withRepositoryBackupWitness(f.witness, f.trustKey, { ...f.options.policy, minimum_head_generation: '2' }, {}, async () => { invoked = true; }); }
  catch (e) { caught = e; } finally { injected.restore(); }
  injected.check(); assert.equal(invoked, false); assert.equal(caught.witness_lock_retained, true);
  await assert.rejects(remember(f, old), { code: 'backup_witness_locked' });
});

test('a caller catching failed persistence cannot turn its poisoned lease into success', async t => {
  const f = await recoveryFixture(t), old = await fs.readFile(f.approval); await remember(f, old);
  const newer = (await f.sign(DATA, { head_generation: '9007199254740994' })).envelope;
  const injected = inject(f.witness, 'sync'); let caught;
  try { await withRepositoryBackupWitness(f.witness, f.trustKey, f.options.policy, {}, async w => {
    await assert.rejects(w.observe(newer), { code: 'EIO' });
    assert.throws(() => w.require(JSON.parse(Buffer.from(JSON.parse(old).payload, 'base64'))), { code: 'backup_witness_not_live' });
    return { state: 'complete' };
  }); } catch (e) { caught = e; } finally { injected.restore(); }
  injected.check(); assert.equal(caught.code, 'EIO'); assert.equal(caught.witness_lock_retained, true);
});

test('invalid signature does not poison the witness or prevent an ordinary valid retry', async t => {
  const f = await recoveryFixture(t), old = await fs.readFile(f.approval); await remember(f, old);
  const invalid = JSON.parse(old), bytes = Buffer.from(invalid.signatures[0].sig, 'base64'); bytes[0] ^= 1;
  invalid.signatures[0].sig = bytes.toString('base64');
  await assert.rejects(remember(f, Buffer.from(JSON.stringify(invalid))), { code: 'backup_invalid_signature' });
  await missing(join(f.witness, '.witness-lock')); await remember(f, old);
});

test('an unavailable archive after successful retention releases ownership but retains the high-water evidence', async t => {
  const f = await recoveryFixture(t), old = await fs.readFile(f.approval);
  await f.sign(DATA, { head_generation: '9007199254740994' });
  f.setHandler((_, res) => { res.writeHead(404); res.end(); });
  await assert.rejects(recoverRepositoryBackup(f.verifyOptions()), { code: 'backup_download_no_source' });
  await missing(join(f.witness, '.witness-lock')); await fs.writeFile(f.approval, old);
  await assert.rejects(recoverRepositoryBackup(f.verifyOptions()), { code: 'backup_below_witness' });
  assert.equal(f.requests.length, 1); assert.deepEqual(await f.events(), []);
});

test('native recovery cannot accept an older valid archive after losing a newer witness write', async t => {
  const f = await recoveryFixture(t), old = await fs.readFile(f.approval); await remember(f, old);
  const newer = (await f.sign(DATA, { head_generation: '9007199254740994' })).envelope;
  const injected = inject(f.witness, 'sync');
  try { await assert.rejects(remember(f, newer), { code: 'EIO' }); } finally { injected.restore(); }
  await fs.writeFile(f.approval, old);
  // This assertion reached a successful native-schema verification on the
  // pre-fix implementation: disk still held old state and its lease was gone.
  await assert.rejects(recoverRepositoryBackup(f.verifyOptions()), { code: 'backup_witness_locked' });
  assert.equal(f.requests.length, 0); assert.deepEqual(await f.events(), []);
});

test('an unawaited owned observation is drained into durable state before release', async t => {
  const f = await recoveryFixture(t), old = await fs.readFile(f.approval); await remember(f, old);
  const newer = (await f.sign(DATA, { head_generation: '9007199254740994' })).envelope;
  const result = await withRepositoryBackupWitness(f.witness, f.trustKey, f.options.policy, {}, w => {
    w.observe(newer).catch(() => {}); return 'action returned';
  });
  assert.equal(result, 'action returned'); await missing(join(f.witness, '.witness-lock'));
  await fs.writeFile(f.approval, old);
  await assert.rejects(recoverRepositoryBackup(f.verifyOptions()), { code: 'backup_below_witness' });
  assert.equal(f.requests.length, 0);
});

test('failure while draining an unawaited observation retains its blocking lease', async t => {
  const f = await recoveryFixture(t), old = await fs.readFile(f.approval); await remember(f, old);
  const newer = (await f.sign(DATA, { head_generation: '9007199254740994' })).envelope;
  const injected = inject(f.witness, 'sync'); let caught;
  try { await withRepositoryBackupWitness(f.witness, f.trustKey, f.options.policy, {}, w => {
    w.observe(newer).catch(() => {}); return 'not a persistence receipt';
  }); } catch (e) { caught = e; } finally { injected.restore(); }
  injected.check(); assert.equal(caught.code, 'EIO'); assert.equal(caught.witness_lock_retained, true);
  await assert.rejects(remember(f, old), { code: 'backup_witness_locked' });
});

test('a new CLI process cannot bypass the lease after failed witness synchronization', async t => {
  const f = await recoveryFixture(t), old = await fs.readFile(f.approval); await remember(f, old);
  const newer = (await f.sign(DATA, { head_generation: '9007199254740994' })).envelope;
  const injected = inject(f.witness, 'sync');
  try { await assert.rejects(remember(f, newer), { code: 'EIO' }); } finally { injected.restore(); }
  await fs.writeFile(f.approval, old);
  const { spawn } = await import('node:child_process');
  const { fileURLToPath } = await import('node:url');
  const args = ['verify', '--cache-directory', f.destination, '--approval', f.approval, '--trust-key', f.trustKey,
    '--witness', f.witness, '--fg', f.fg, '--trusted-local', '--verification-instance', '11', '--sources', f.sourceFile, '--ca-file', f.caFile,
    ...Object.entries(f.options.policy).flatMap(([key, value]) => ['--' + key.replaceAll('_', '-'), value])];
  const child = spawn(process.execPath, [fileURLToPath(new URL('../recover_repository_backup.mjs', import.meta.url)), ...args], { stdio: ['ignore', 'pipe', 'pipe'] });
  let stdout = '', stderr = '';
  child.stdout.on('data', chunk => { stdout += chunk; }); child.stderr.on('data', chunk => { stderr += chunk; });
  const done = new Promise((resolve, reject) => { child.once('error', reject); child.once('close', code => resolve(code)); });
  const timeout = setTimeout(() => child.kill('SIGKILL'), 5000);
  let status;
  try { status = await done; } finally { clearTimeout(timeout); }
  assert.equal(status, 1, stderr); assert.equal(stdout, '');
  assert.equal(JSON.parse(stderr).code, 'backup_witness_locked'); assert.equal(f.requests.length, 0); assert.deepEqual(await f.events(), []);
});

test('actual CLI persistence refusal reports its retained lease and publication boundary', async t => {
  const f = await recoveryFixture(t), old = await fs.readFile(f.approval); await remember(f, old);
  await f.sign(DATA, { head_generation: '9007199254740994' });
  // Fault preload is test-only, in the child process; the production CLI has no
  // injectable storage adapter, success receipt or fault option.
  const preload = join(f.root, 'test-only-witness-sync-fault.mjs');
  await fs.writeFile(preload, `import fs from 'node:fs/promises';
import { constants } from 'node:fs';
import { syncBuiltinESMExports } from 'node:module';
const original = fs.open;
fs.open = async (path, ...args) => {
  const file = await original(path, ...args);
  if (String(path).startsWith(${JSON.stringify(join(f.witness, '.witness-'))}) && String(path).endsWith('.tmp') && (args[0] & constants.O_CREAT))
    file.sync = async () => { throw Object.assign(new Error('EIO'), { code: 'EIO' }); };
  return file;
};
syncBuiltinESMExports();\n`, { mode: 0o600 });
  const { spawn } = await import('node:child_process'), { fileURLToPath } = await import('node:url');
  const args = ['verify', '--cache-directory', f.destination, '--approval', f.approval, '--trust-key', f.trustKey,
    '--witness', f.witness, '--fg', f.fg, '--trusted-local', '--verification-instance', '11',
    ...Object.entries(f.options.policy).flatMap(([key, value]) => ['--' + key.replaceAll('_', '-'), value])];
  const child = spawn(process.execPath, ['--import', preload, fileURLToPath(new URL('../recover_repository_backup.mjs', import.meta.url)), ...args],
    { stdio: ['ignore', 'pipe', 'pipe'] });
  let stdout = '', stderr = '';
  child.stdout.on('data', chunk => { stdout += chunk; }); child.stderr.on('data', chunk => { stderr += chunk; });
  const done = new Promise((resolve, reject) => { child.once('error', reject); child.once('close', code => resolve(code)); });
  const timeout = setTimeout(() => child.kill('SIGKILL'), 5000);
  let status;
  try { status = await done; } finally { clearTimeout(timeout); }
  assert.equal(status, 1, stderr); assert.equal(stdout, '');
  const report = JSON.parse(stderr);
  assert.equal(report.code, 'EIO'); assert.equal(report.witness_lock_retained, true);
  assert.equal(report.witness_publication_state, 'not_published'); assert.equal(report.exit_code, 1);
  await fs.lstat(join(f.witness, '.witness-lock')); assert.equal(f.requests.length, 0); assert.deepEqual(await f.events(), []);
});

test('drain failure retains a returned consumer result without reporting successful persistence', async t => {
  const f = await recoveryFixture(t), old = await fs.readFile(f.approval); await remember(f, old);
  const newer = (await f.sign(DATA, { head_generation: '9007199254740994' })).envelope;
  const result = { state: 'complete', type: 'TEST_ONLY_CONSUMER_RESULT_NOT_NATIVE_RECEIPT' };
  const injected = inject(f.witness, 'sync'); let caught;
  try { await withRepositoryBackupWitness(f.witness, f.trustKey, f.options.policy, {}, w => {
    w.observe(newer).catch(() => {}); return result;
  }); } catch (e) { caught = e; } finally { injected.restore(); }
  injected.check(); assert.equal(caught.code, 'EIO'); assert.equal(caught.witness_lock_retained, true);
  assert.equal(caught.completed_result, result); assert.equal(caught.state, 'complete');
  await assert.rejects(remember(f, old), { code: 'backup_witness_locked' });
});
