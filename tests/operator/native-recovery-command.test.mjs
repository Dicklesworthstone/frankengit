// Real command, Ed25519 and filesystem ownership; the native-report child is
// deliberately fake. This is not a Rust/native-compatibility execution claim.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync } from 'node:crypto';
import { readFile, writeFile, access, readdir, mkdir, cp, symlink } from 'node:fs/promises';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawn } from 'node:child_process';
import { harness, head } from './fixtures/native-recovery-harness.mjs';
import { signSourceBackup } from '../../scripts/lib/source-attestation.mjs';
import { recoverGitBundle } from '../../scripts/lib/source-recovery.mjs';
const command = fileURLToPath(new URL('../../scripts/recover_git_bundle.mjs', import.meta.url));
const sha = bytes => createHash('sha256').update(bytes).digest('hex');
const absent = path => assert.rejects(access(path), { code: 'ENOENT' });
const iso = time => new Date(Math.floor(time / 1000) * 1000).toISOString().replace('.000Z', 'Z');
const markerName = '.frankengit-source-recovery.json';

async function invoke(h, extra = [], options = {}) {
  const input = options.input ?? join(h.root, 'source.bundle');
  if (!options.input) await writeFile(input, h.bytes);
  const args = options.args ?? [input, h.destination, '--head', 'refs/heads/main', '--native-fg', h.fg, ...extra];
  const child = spawn(process.execPath, [options.command ?? command, ...args], {
    cwd: options.cwd ?? h.root, stdio: ['ignore', 'pipe', 'pipe'],
    env: { ...process.env, NODE_OPTIONS: '', PATH: '/nonexistent-test-path' },
  });
  let stdout = '', stderr = '';
  const timer = setTimeout(() => child.kill('SIGKILL'), 12000);
  child.stdout.on('data', chunk => { stdout += chunk; if (stdout.length > 2 ** 20) child.kill('SIGKILL'); });
  child.stderr.on('data', chunk => { stderr += chunk; if (stderr.length > 2 ** 20) child.kill('SIGKILL'); });
  const result = await new Promise((resolve, reject) => {
    child.once('error', reject);
    child.once('close', (code, signal) => resolve({ code, signal, stdout, stderr }));
  }).finally(() => clearTimeout(timer));
  assert.equal(result.signal, null, `command killed: ${stderr}`);
  const text = result.code === 0 ? stdout : stderr;
  result.report = options.help ? null : JSON.parse(text);
  return result;
}
async function approval(h, metadata = {}) {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const privatePem = privateKey.export({ format: 'pem', type: 'pkcs8' });
  const publicPem = publicKey.export({ format: 'pem', type: 'spki' });
  const policy = { repository: 'owner/project', sequence: '18446744073709551615', ...metadata };
  const signed = await signSourceBackup(h.bytes, Buffer.from(privatePem), policy);
  const envelope = join(h.root, 'approval.json'), key = join(h.root, 'trusted.pem');
  await writeFile(envelope, signed.envelope, { mode: 0o600 });
  await writeFile(key, publicPem, { mode: 0o600 });
  return { envelope, key, privatePem, signed,
    args: ['--attestation', envelope, '--trust-key', key, '--repository', policy.repository,
      '--minimum-sequence', policy.sequence] };
}
async function sentinelCommand(h) {
  const root = join(h.root, 'isolated');
  await mkdir(join(root, 'scripts'), { recursive: true });
  await cp(new URL('../../scripts/lib/', import.meta.url), join(root, 'scripts/lib'), { recursive: true });
  await cp(command, join(root, 'scripts/recover_git_bundle.mjs'));
  const browser = join(root, 'crates/fgit-node/src/smart_http/server/browser');
  await mkdir(browser, { recursive: true });
  for (const name of ['bundle-verify.mjs', 'transfers-protocol.mjs']) {
    await writeFile(join(browser, name), "throw Object.assign(new Error('legacy_decoder_loaded'), {code:'legacy_decoder_loaded'});\n");
  }
  return join(root, 'scripts/recover_git_bundle.mjs');
}

for (const format of ['sha1', 'sha256']) test(`actual CLI restores ${format} without Git/PATH or legacy decoder`, async t => {
  const h = await harness(t, format), isolated = await sentinelCommand(h);
  const result = await invoke(h, ['--expect-sha256', sha(h.bytes)], { command: isolated });
  assert.equal(result.code, 0, result.stderr);
  assert.equal(result.report.state, 'complete');
  assert.equal(result.report.verification.verifier_backend, 'native-fg');
  assert.equal(result.report.verification.object_format, format);
  assert.equal(result.report.forge_state_restored, false);
  assert.equal(result.report.native_authority_restored, false);
  assert.equal(await readFile(join(h.destination, 'HEAD'), 'utf8'), 'ref: refs/heads/main\n');
  const calls = await h.calls();
  assert.equal(calls.length, 1);
  assert.deepEqual(calls[0].slice(0, 2), ['bundle', 'verify']);
  assert.ok(calls[0].includes('--recovery-head-hex'));
});

test('signed native recovery reauthenticates exact full-width policy for completed resume', async t => {
  const h = await harness(t), a = await approval(h);
  const first = await invoke(h, a.args);
  assert.equal(first.code, 0, first.stderr);
  assert.equal(first.report.source_attestation.signature_verified, true);
  assert.equal(first.report.source_attestation.minimum_sequence, '18446744073709551615');
  assert.equal(first.report.verification.origin_authenticated, false);
  const marker = JSON.parse(await readFile(join(h.destination, markerName), 'utf8'));
  assert.equal(marker.approval_sha256, sha(Buffer.from(JSON.stringify(first.report.source_attestation))));
  const resumed = await invoke(h, ['--resume', ...a.args]);
  assert.equal(resumed.code, 0, resumed.stderr);
  assert.equal(resumed.report.already_published, true);
  assert.equal(resumed.report.plan_sha256, first.report.plan_sha256);
  assert.equal(resumed.report.appended_bytes, 0);
  assert.equal((await h.calls()).some(args => args.includes(a.key) || args.includes(a.envelope)), false);
});

for (const change of ['omit-approval', 'lower-floor', 'different-key']) test(`signed native resume refuses ${change}`, async t => {
  const h = await harness(t), a = await approval(h);
  assert.equal((await invoke(h, a.args)).code, 0);
  const before = await readFile(join(h.destination, markerName));
  const originalHead = await readFile(join(h.destination, 'HEAD'));
  let args = [...a.args];
  if (change === 'omit-approval') args = [];
  if (change === 'lower-floor') args[args.indexOf('--minimum-sequence') + 1] = '1';
  if (change === 'different-key') {
    const { publicKey } = generateKeyPairSync('ed25519');
    await writeFile(a.key, publicKey.export({ format: 'pem', type: 'spki' }));
  }
  const result = await invoke(h, ['--resume', ...args]);
  assert.notEqual(result.code, 0);
  assert.equal(result.report.state, 'existing_unknown');
  assert.deepEqual(await readFile(join(h.destination, markerName)), before);
  assert.deepEqual(await readFile(join(h.destination, 'HEAD')), originalHead);
  await absent(join(h.destination, '.frankengit-source-recovery-owners'));
});

for (const change of ['key', 'signature', 'artifact', 'repository', 'sequence']) test(`bad signed ${change} refuses before native process or destination`, async t => {
  const h = await harness(t), a = await approval(h, { sequence: '9' });
  const input = join(h.root, 'signed.bundle'); await writeFile(input, h.bytes);
  const args = [...a.args];
  if (change === 'key') {
    const { publicKey } = generateKeyPairSync('ed25519');
    await writeFile(a.key, publicKey.export({ format: 'pem', type: 'spki' }));
  }
  if (change === 'signature') {
    const value = JSON.parse(a.signed.envelope); value.signatures[0].sig = Buffer.alloc(64).toString('base64');
    await writeFile(a.envelope, JSON.stringify(value));
  }
  if (change === 'artifact') { const changed = Buffer.from(h.bytes); changed[100] ^= 1; await writeFile(input, changed); }
  if (change === 'repository') args[args.indexOf('--repository') + 1] = 'foreign/project';
  if (change === 'sequence') args[args.indexOf('--minimum-sequence') + 1] = '10';
  const result = await invoke(h, args, { input });
  assert.notEqual(result.code, 0);
  assert.equal(result.report.state, 'not_created');
  assert.equal((await h.calls()).length, 0);
  await absent(h.destination);
});

test('source path change after native snapshot selection never changes signed recovery bytes', async t => {
  const h = await harness(t), a = await approval(h);
  const input = join(h.root, 'signed.bundle'); await writeFile(input, h.bytes);
  await h.configure({ mutateSource: input });
  const result = await invoke(h, a.args, { input });
  assert.equal(result.code, 0, result.stderr);
  assert.equal((await readFile(input, 'utf8')), 'changed after native snapshot selection');
  const name = (await readdir(join(h.destination, 'objects/pack'))).find(path => path.endsWith('.pack'));
  assert.deepEqual(await readFile(join(h.destination, 'objects/pack', name)), h.bytes.subarray(128));
});

test('approval expiring during native verification prevents destination creation', async t => {
  const h = await harness(t);
  const expires = Math.floor(Date.now() / 1000) * 1000 + 3000;
  const a = await approval(h, { expires_at: iso(expires) });
  await h.configure({ delayMs: expires - Date.now() + 100 });
  const result = await invoke(h, a.args);
  assert.notEqual(result.code, 0); assert.equal(result.report.code, 'attestation_expired');
  assert.equal((await h.calls()).length, 1);
  await absent(h.destination);
});

test('native operation deadline cancels and reaps the verifier without a destination', async t => {
  const h = await harness(t, 'sha1', { mode: 'hang' });
  const result = await invoke(h, ['--native-timeout-secs', '1']);
  assert.notEqual(result.code, 0); await absent(h.destination);
  const pid = Number(await readFile(join(h.root, 'pid'), 'utf8'));
  assert.throws(() => process.kill(pid, 0), { code: 'ESRCH' });
});

test('unsigned native source refuses symlinks without invoking fg', async t => {
  const h = await harness(t), source = join(h.root, 'input'), link = join(h.root, 'link');
  await writeFile(source, h.bytes); await symlink(source, link);
  assert.notEqual((await invoke(h, [], { input: link })).code, 0);
  assert.equal((await h.calls()).length, 0); await absent(h.destination);
});

for (const flags of [
  ['--native-fg', 'relative-fg'], ['--native-timeout-secs', '0'], ['--native-timeout-secs', '301'],
  ['--native-timeout-secs', '01'], ['--native-timeout-secs', '-1'],
  ['--native-timeout-secs', '1', '--native-timeout-secs', '2'], ['--native-fg'],
  ['--attestation', 'absent.json'], ['--expect-format', 'sha512'],
  ['--expect-ref', 'refs/heads/main=1234'], ['--exact-refs'],
]) test(`native CLI grammar refuses before source I/O: ${flags.join(' ')}`, async t => {
  const h = await harness(t);
  const args = [join(h.root, 'does-not-exist'), h.destination, '--head', 'refs/heads/main'];
  if (!flags.includes('--native-fg')) args.push('--native-fg', h.fg);
  const result = await invoke(h, [], { args: [...args, ...flags] });
  assert.notEqual(result.code, 0); assert.notEqual(result.report.code, 'ENOENT');
  assert.equal((await h.calls()).length, 0); await absent(h.destination);
});

test('native timeout requires native selection and help needs no decoder or input', async t => {
  const h = await harness(t), isolated = await sentinelCommand(h);
  const args = ['missing', h.destination, '--head', 'refs/heads/main', '--native-timeout-secs', '1'];
  const invalid = await invoke(h, [], { command: isolated, args });
  assert.equal(invalid.report.code, 'native_fg_required_for_timeout');
  const help = await invoke(h, [], { command: isolated, args: ['--help'], help: true });
  assert.equal(help.code, 0); assert.match(help.stdout, /--native-fg/);
  assert.equal((await h.calls()).length, 0);
});

test('default legacy dispatch remains explicit and native refusal cannot fall back', async t => {
  const h = await harness(t), isolated = await sentinelCommand(h);
  const legacy = await invoke(h, [], { command: isolated, args: ['missing', h.destination, '--head', 'refs/heads/main'] });
  assert.equal(legacy.report.code, 'legacy_decoder_loaded'); // Import sentinel, not a Git-semantic test.
  await h.configure({ mode: 'refuse' });
  const refused = await invoke(h, [], { command: isolated });
  assert.equal(refused.report.code, 'native_verification_refused');
  await absent(h.destination);
});

test('literal path separator preserves dash-prefixed filenames', async t => {
  const h = await harness(t); await writeFile(join(h.root, '--native-fg'), h.bytes);
  const result = await invoke(h, [], { args: ['--head', 'refs/heads/main', '--native-fg', h.fg, '--', '--native-fg', h.destination] });
  assert.equal(result.code, 0, result.stderr);
});

for (const resume of [false, true]) test(`effect-time approval guard refuses HEAD after readback (resume=${resume})`, async t => {
  const h = await harness(t);
  if (resume) {
    const controller = new AbortController();
    await assert.rejects(recoverGitBundle(h.bytes, h.destination, h.request, { ...h.options, signal: controller.signal,
      onProgress(e) { if (e.phase === 'staged:config') controller.abort(); } }));
  }
  let guarded = false;
  await assert.rejects(recoverGitBundle(h.bytes, h.destination, h.request, { ...h.options, resume,
    onProgress(e) { if (e.phase === 'publication_ready') { guarded = true; throw Object.assign(new Error('approval_expired'), { code: 'approval_expired' }); } } }),
  error => error.code === 'approval_expired' && error.state === 'staging');
  assert.equal(guarded, true); await absent(join(h.destination, 'HEAD'));
});

for (const resume of [false, true]) test(`post-publication observer failure still finalizes (resume=${resume})`, async t => {
  const h = await harness(t);
  if (resume) {
    const controller = new AbortController();
    await assert.rejects(recoverGitBundle(h.bytes, h.destination, h.request, { ...h.options, signal: controller.signal,
      onProgress(e) { if (e.phase === 'staged:config') controller.abort(); } }));
  }
  await assert.rejects(recoverGitBundle(h.bytes, h.destination, h.request, { ...h.options, resume,
    onProgress(e) { if (e.phase === 'published') throw Object.assign(new Error('observer_failure'), { code: 'observer_failure' }); } }),
  error => error.code === 'observer_failure' && ['published', 'complete'].includes(error.state));
  assert.equal(await readFile(join(h.destination, 'HEAD'), 'utf8'), 'ref: refs/heads/main\n');
  await absent(join(h.destination, '.frankengit-source-recovery-head'));
  const completed = await recoverGitBundle(h.bytes, h.destination, h.request, { ...h.options, resume: true });
  assert.equal(completed.already_published, true);
});

test('expired signed resume does not hide or alter an already-published HEAD', async t => {
  const h = await harness(t), issued = Date.now() - 10000, expires = Date.now() - 1000;
  const a = await approval(h);
  assert.equal((await invoke(h, a.args)).code, 0);
  const before = await readFile(join(h.destination, 'HEAD'));
  const saved = await readFile(join(h.destination, markerName));
  // A formerly valid, now expired independently signed approval. The command
  // must refuse current approval before even consulting an existing target.
  const expired = await signSourceBackup(h.bytes, Buffer.from(a.privatePem), {
    repository: 'owner/project', sequence: '18446744073709551615', issued_at: iso(issued), expires_at: iso(expires),
  }, { now: issued });
  await writeFile(a.envelope, expired.envelope);
  const result = await invoke(h, ['--resume', ...a.args]);
  assert.equal(result.report.code, 'attestation_expired');
  assert.equal(result.report.state, 'existing_unknown');
  assert.equal((await h.calls()).length, 1);
  assert.deepEqual(await readFile(join(h.destination, 'HEAD')), before);
  assert.deepEqual(await readFile(join(h.destination, markerName)), saved);
});

test('native resume reports uncertainty when the verifier is missing', async t => {
  const h = await harness(t);
  assert.equal((await invoke(h)).code, 0);
  const before = await readFile(join(h.destination, 'HEAD'));
  const result = await invoke(h, [], { args: [join(h.root, 'source.bundle'), h.destination,
    '--head', 'refs/heads/main', '--native-fg', join(h.root, 'missing-fg'), '--resume'] });
  assert.equal(result.report.state, 'existing_unknown');
  assert.equal(result.report.code, 'native_verifier_start_failed');
  assert.deepEqual(await readFile(join(h.destination, 'HEAD')), before);
});
