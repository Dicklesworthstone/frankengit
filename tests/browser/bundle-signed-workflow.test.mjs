// Actual signed verifier/recovery commands and real files. Installed Git is an
// independent consumer in tests only; the commands run with no Git on PATH.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile, writeFile, lstat, mkdir, symlink } from 'node:fs/promises';
import { generateKeyPairSync } from 'node:crypto';
import { join } from 'node:path';
import { fork } from 'node:child_process';
import { once } from 'node:events';
import { readAuthenticatedSourceBackup } from '../../scripts/lib/source-attestation.mjs';
import { SourceAttestationOptions } from '../../scripts/lib/source-attestation-options.mjs';
import { recoverGitBundle } from '../../scripts/lib/source-recovery.mjs';
import { withSignedFixture, cli, git, repository, sequence, headHex, absent, treeSnapshot } from './bundle-signed-fixtures.mjs';
const success = result => { assert.equal(result.status, 0, result.stderr); assert.equal(result.stderr, ''); return JSON.parse(result.stdout); };
function refused(result, code, state = null) {
  assert.equal(result.status, 1, result.stderr); assert.equal(result.stdout, '');
  const value = JSON.parse(result.stderr); assert.equal(value.error ?? value.code, code);
  if (state !== null) assert.equal(value.state, state); return value;
}
function verify(f, args = [], path = f.input) { return cli('verify_git_bundle.mjs', [path, ...f.authArgs, ...args]); }
function recover(f, args = [], destination = f.destination) { return cli('recover_git_bundle.mjs', [f.input, destination, '--head', 'refs/heads/main', ...f.authArgs, ...args]); }
function gitOk(f, args) { const r = git(f, args); assert.equal(r.status, 0, String(r.stderr)); return r.stdout; }
for (const format of ['sha1', 'sha256']) {
  test(`${format}: signed verification requires both detached approval and full native closure`, () => withSignedFixture(async f => {
    const result = success(verify(f)); assert.equal(result.object_closure_verified, true);
    assert.equal(result.source_attestation.signature_verified, true); assert.equal(result.source_attestation.statement.artifact.sha256, f.sha256);
    assert.equal(result.source_attestation.statement.sequence, sequence); assert.equal(result.source_attestation.repository, repository);
    for (const key of ['signatures_verified', 'author_identity_verified', 'forge_state_verified']) assert.equal(result[key], false, 'Git-native claims must not be relabeled by source approval');
    assert.equal(await absent(f.destination), true); assert.deepEqual(await readFile(f.input), f.bundle);
  }, format));
  test(`${format}: actual signed recovery is fsck-clean and cloneable without a Git subprocess in the command`, () => withSignedFixture(async f => {
    const signedByCli = join(f.directory, 'cli.dsse.json');
    success(cli('attest_git_bundle.mjs', ['sign', f.input, signedByCli, '--key', f.privateKey, '--repository', repository, '--sequence', sequence]));
    f.authArgs[1] = signedByCli;
    const result = success(recover(f)); assert.equal(result.state, 'complete');
    assert.equal(result.source_attestation.signature_verified, true); assert.equal(result.verification.object_closure_verified, true);
    assert.equal(result.forge_state_restored, false); assert.equal(result.native_authority_restored, false);
    gitOk(f, ['-C', f.destination, 'fsck', '--strict']);
    assert.equal(gitOk(f, ['-C', f.destination, 'rev-parse', 'HEAD']).toString().trim(), f.ids.tip);
    assert.equal(gitOk(f, ['-C', f.destination, 'rev-parse', 'refs/tags/release']).toString().trim(), f.ids.tag);
    for (const name of ['binary', 'text', 'link']) assert.deepEqual(gitOk(f, ['-C', f.destination, 'cat-file', 'blob', f.ids[name]]), f.byName[name].body);
    const clone = join(f.directory, 'clone'); gitOk(f, ['clone', '--quiet', '--no-checkout', '--no-hardlinks', f.destination, clone]);
    assert.equal(gitOk(f, ['-C', clone, 'rev-parse', 'HEAD']).toString().trim(), f.ids.tip);
    const marker = await readFile(join(f.destination, '.frankengit-source-recovery.json'), 'utf8');
    assert(!marker.includes('PUBLIC KEY')); assert(!marker.includes('signature_verified')); // saved reports never choose trust
  }, format));
  test(`${format}: a signed checksum-valid but incomplete backup is rejected before destination creation`, () => withSignedFixture(async f => {
    success(cli('attest_git_bundle.mjs', ['check', f.input, f.envelope, '--trust-key', f.publicKey, '--repository', repository, '--minimum-sequence', sequence]));
    refused(verify(f), 'missing_reachable_object'); refused(recover(f), 'missing_reachable_object', 'not_created');
    assert.equal(await absent(f.destination), true);
  }, format, { missing: 'binary' }));
  test(`${format}: explicit caller ref/hash constraints remain additional requirements, never overwritten by a signature`, () => withSignedFixture(async f => {
    const pins = ['--expect-format', format, '--expect-ref', `refs/heads/main=${f.ids.tip}`, '--expect-ref', `refs/tags/release=${f.ids.tag}`, '--exact-refs', '--expect-sha256', f.sha256];
    assert.equal(success(verify(f, pins)).caller_expectations_matched, true);
    const wrong = [...pins]; wrong[3] = `refs/heads/main=${'a'.repeat(format === 'sha1' ? 40 : 64)}`;
    refused(verify(f, wrong), 'expected_ref_mismatch'); refused(recover(f, wrong), 'expected_ref_mismatch');
    assert.equal(await absent(f.destination), true);
    const wrongHash = [...pins]; wrongHash[wrongHash.length - 1] = 'f'.repeat(64);
    refused(verify(f, wrongHash), 'expected_artifact_mismatch'); refused(recover(f, wrongHash), 'expected_artifact_mismatch');
    const result = success(recover(f, pins)); assert.equal(result.verification.caller_expectations_matched, true); assert.equal(result.source_attestation.signature_verified, true);
  }, format));
  test(`${format}: resume reauthenticates and can accept a newer approval for the exact same recovery plan`, () => withSignedFixture(async f => {
    const first = success(recover(f)), head = await lstat(join(f.destination, 'HEAD'));
    const before = await treeSnapshot(f.destination);
    f.authArgs[f.authArgs.length - 1] = '43';
    refused(recover(f, ['--resume']), 'attestation_below_sequence_floor', 'existing_unknown');
    assert.deepEqual(await treeSnapshot(f.destination), before);
    await f.resign({ sequence: '43' });
    const resumed = success(recover(f, ['--resume']));
    assert.equal(resumed.already_published, true); assert.equal(resumed.resumed, true); assert.equal(resumed.appended_bytes, 0);
    assert.equal(resumed.plan_sha256, first.plan_sha256); assert.equal((await lstat(join(f.destination, 'HEAD'))).ino, head.ino);
    assert.equal(resumed.source_attestation.statement.sequence, '43'); gitOk(f, ['-C', f.destination, 'fsck', '--strict']);
  }, format));
}
for (const [label, corrupt, code] of [
  ['wrong key', async f => { const key = generateKeyPairSync('ed25519').publicKey.export({ format: 'pem', type: 'spki' }); await writeFile(f.publicKey, key); }, 'attestation_key_hint_mismatch'],
  ['wrong repository', async f => { f.authArgs[5] = 'other/source'; }, 'attestation_repository_mismatch'],
  ['rollback', async f => { await f.resign({ sequence: '41' }); }, 'attestation_below_sequence_floor'],
  ['expired approval', async f => { await f.resign({ issued_at: '2020-01-01T00:00:00Z', expires_at: '2020-01-02T00:00:00Z' }, { now: Date.parse('2020-01-01T00:00:01Z') }); }, 'attestation_expired'],
  ['same-size substitution', async f => { const body = Buffer.from(f.bundle); body[body.length - 1] ^= 1; await writeFile(f.input, body); }, 'attestation_artifact_mismatch'],
  ['corrupt signature', async f => { const value = JSON.parse(await readFile(f.envelope, 'utf8')); const sig = Buffer.from(value.signatures[0].sig, 'base64'); sig[0] ^= 1; value.signatures[0].sig = sig.toString('base64'); await writeFile(f.envelope, JSON.stringify(value)); }, 'invalid_attestation_signature'],
  ['malformed envelope', async f => { await writeFile(f.envelope, '{'); }, 'invalid_attestation_envelope'],
]) {
  test(`signed commands refuse ${label}, never fall back or create a destination`, () => withSignedFixture(async f => {
    await corrupt(f); refused(verify(f), code); refused(recover(f), code, 'not_created'); assert.equal(await absent(f.destination), true);
  }));
  test(`signed resume refuses ${label} without changing an already published repository`, () => withSignedFixture(async f => {
    success(recover(f)); const before = await treeSnapshot(f.destination);
    await corrupt(f); refused(recover(f, ['--resume']), code, 'existing_unknown');
    assert.deepEqual(await treeSnapshot(f.destination), before);
  }));
}
test('signed arbitrary bytes are authentic but cannot masquerade as valid Git', () => withSignedFixture(async f => {
  await writeFile(f.input, 'genuine operator-approved opaque bytes'); await f.resign();
  const checked = success(cli('attest_git_bundle.mjs', ['check', f.input, f.envelope, '--trust-key', f.publicKey, '--repository', repository, '--minimum-sequence', sequence]));
  assert.equal(checked.signature_verified, true); assert.equal(checked.object_closure_verified, false);
  const vr = verify(f), rr = recover(f); assert.equal(vr.status, 1); assert.equal(rr.status, 1);
  assert.equal(vr.stdout, ''); assert.equal(rr.stdout, ''); assert.equal(await absent(f.destination), true);
}));
test('malformed, missing or partial attestation groups fail before any bundle or destination access', () => withSignedFixture(async f => {
  const groups = [['--attestation', f.envelope], ['--trust-key', f.publicKey], ['--repository', repository], ['--minimum-sequence', sequence]];
  for (let mask = 1; mask < 15; mask++) {
    const args = groups.filter((_, i) => mask & (1 << i)).flat();
    refused(cli('verify_git_bundle.mjs', ['absent.bundle', ...args]), 'complete_attestation_options_required');
    refused(cli('recover_git_bundle.mjs', ['absent.bundle', f.destination, '--head', 'refs/heads/main', ...args]), 'complete_attestation_options_required');
  }
  const malformed = [
    [...f.authArgs, '--trust-key', f.publicKey], [...f.authArgs.slice(0, -1), '01'], [...f.authArgs.slice(0, -1), '0'],
    [...f.authArgs.slice(0, -1), '18446744073709551616'], [...f.authArgs.slice(0, -1)],
  ];
  for (const args of malformed) {
    const a = cli('verify_git_bundle.mjs', ['absent.bundle', ...args]), b = cli('recover_git_bundle.mjs', ['absent.bundle', f.destination, '--head', 'refs/heads/main', ...args]);
    for (const r of [a, b]) { assert.equal(r.status, 1); assert.equal(r.stdout, ''); assert.notEqual(JSON.parse(r.stderr).error ?? JSON.parse(r.stderr).code, 'ENOENT'); }
  }
  assert.equal(await absent(f.destination), true);
}));
test('a missing sidecar is a hard failure even though unsigned verification would succeed', () => withSignedFixture(async f => {
  assert.equal(success(cli('verify_git_bundle.mjs', [f.input])).object_closure_verified, true);
  f.authArgs[1] = join(f.directory, 'absent.json');
  refused(verify(f), 'ENOENT'); refused(recover(f), 'ENOENT'); assert.equal(await absent(f.destination), true);
}));
test('signature verification occurs before opening the bundle, including resume', () => withSignedFixture(async f => {
  f.authArgs[5] = 'different/source';
  refused(verify(f, [], join(f.directory, 'absent.bundle')), 'attestation_repository_mismatch');
  f.input = join(f.directory, 'absent.bundle');
  refused(recover(f), 'attestation_repository_mismatch'); refused(recover(f, ['--resume']), 'attestation_repository_mismatch', 'existing_unknown');
}));
test('authenticating a bundle does not override explicit HEAD or existing-destination protection', () => withSignedFixture(async f => {
  const missingHead = cli('recover_git_bundle.mjs', [f.input, f.destination, ...f.authArgs]);
  refused(missingHead, 'explicit_branch_head_required'); assert.equal(await absent(f.destination), true);
  const unknownHead = cli('recover_git_bundle.mjs', [f.input, f.destination, '--head', 'refs/heads/absent', ...f.authArgs]);
  refused(unknownHead, 'recovery_head_not_advertised'); assert.equal(await absent(f.destination), true);
  await mkdir(f.destination); const before = await treeSnapshot(f.destination);
  refused(recover(f), 'EEXIST'); assert.deepEqual(await treeSnapshot(f.destination), before);
}));
test('final-component symlinks for bundle, approval and trusted key are refused before restore', () => withSignedFixture(async f => {
  for (const [label, original, modify] of [
    ['bundle', f.input, alias => { f.input = alias; }], ['signature', f.envelope, alias => { f.authArgs[1] = alias; }], ['key', f.publicKey, alias => { f.authArgs[3] = alias; }],
  ]) {
    const alias = join(f.directory, `${label}.link`); await symlink(original, alias); const prior = f.input, oldArgs = [...f.authArgs]; modify(alias);
    refused(verify(f), 'ELOOP'); refused(recover(f), 'ELOOP'); assert.equal(await absent(f.destination), true);
    f.input = prior; f.authArgs = oldArgs;
  }
}));
test('signed recovery supports byte-valued HEAD without using reference names as paths', () => withSignedFixture(async f => {
  const result = success(cli('recover_git_bundle.mjs', [f.input, f.destination, '--head-hex', f.branch.toString('hex'), ...f.authArgs]));
  assert.equal(result.head_ref_hex, f.branch.toString('hex')); assert.equal(result.source_attestation.signature_verified, true);
  assert.deepEqual(await readFile(join(f.destination, 'HEAD')), Buffer.concat([Buffer.from('ref: '), f.branch, Buffer.from('\n')]));
  gitOk(f, ['-C', f.destination, 'fsck', '--strict']);
}, 'sha1', { branch: Buffer.concat([Buffer.from('refs/heads/'), Buffer.from([255])]) }));
test('existing unsigned invocations keep the original report and do not discover a nearby sidecar', () => withSignedFixture(async f => {
  await writeFile(f.envelope, 'invalid sidecar deliberately next to bundle');
  const verified = success(cli('verify_git_bundle.mjs', [f.input])); assert(!Object.hasOwn(verified, 'source_attestation'));
  const result = success(cli('recover_git_bundle.mjs', [f.input, f.destination, '--head', 'refs/heads/main']));
  assert.equal(result.state, 'complete'); assert(!Object.hasOwn(result, 'source_attestation'));
}));
test('literal option-looking paths after -- remain filenames, not signature configuration', () => withSignedFixture(async f => {
  await writeFile(join(f.directory, '--attestation'), f.bundle);
  const v = success(cli('verify_git_bundle.mjs', ['--', '--attestation'], { cwd: f.directory }));
  assert(!Object.hasOwn(v, 'source_attestation'));
  const r = success(cli('recover_git_bundle.mjs', ['--head', 'refs/heads/main', '--', '--attestation', 'literal.git'], { cwd: f.directory }));
  assert.equal(r.state, 'complete'); assert(!Object.hasOwn(r, 'source_attestation'));
}));
test('shared option parser owns its values and cannot consume another option value', () => {
  const group = new SourceAttestationOptions(), args = ['--attestation', 'one', '--trust-key', 'two', '--repository', repository, '--minimum-sequence', sequence];
  for (let i = 0; i < args.length; i += 2) assert.equal(group.take(args, i), i + 1);
  const result = group.finish(); args.fill('mutated'); assert.equal(result.envelope, 'one'); assert.equal(result.policy.minimum_sequence, sequence);
  assert(Object.isFrozen(result)); assert(Object.isFrozen(result.policy));
  const fresh = new SourceAttestationOptions(); assert.equal(fresh.take(['--head', '--attestation'], 0), 0); assert.equal(fresh.finish(), null);
});
test('a returned display record cannot extend approval lifetime while Git work is in progress', () => withSignedFixture(async f => {
  const current = Date.now(), issued = new Date(Math.floor(current / 1000) * 1000).toISOString().replace('.000Z', 'Z');
  const expires = new Date(Math.floor(current / 1000) * 1000 + 10000).toISOString().replace('.000Z', 'Z');
  await f.resign({ issued_at: issued, expires_at: expires });
  const signed = await readAuthenticatedSourceBackup(f.input, f.envelope, f.publicKey, { repository, minimum_sequence: sequence });
  signed.authentication.statement.expires_at = null;
  const original = Date.now;
  try { Date.now = () => Date.parse(expires); assert.throws(() => signed.checkCurrent(), e => e.code === 'attestation_expired'); }
  finally { Date.now = original; }
}));
test('expired approval after decoding refuses before destination creation; published work still finalizes', () => withSignedFixture(async f => {
  const now = Date.now(), expires = new Date(Math.floor(now / 1000) * 1000 + 10000).toISOString().replace('.000Z', 'Z');
  await f.resign({ expires_at: expires });
  const signed = await readAuthenticatedSourceBackup(f.input, f.envelope, f.publicKey, { repository, minimum_sequence: sequence });
  const original = Date.now;
  try {
    await assert.rejects(recoverGitBundle(signed.bytes, f.destination, { head_ref_hex: headHex }, { onProgress(event) {
      if (event.phase === 'verified') { Date.now = () => Date.parse(expires); signed.checkCurrent(); }
    } }), e => e.code === 'attestation_expired' && e.state === 'not_created');
  } finally { Date.now = original; }
  assert.equal(await absent(f.destination), true);
  try {
    const result = await recoverGitBundle(signed.bytes, f.destination, { head_ref_hex: headHex }, { onProgress(event) {
      if (event.phase === 'verified' || event.phase === 'before_publication') signed.checkCurrent();
      if (event.phase === 'published') Date.now = () => Date.parse(expires);
    } });
    assert.equal(result.state, 'complete'); assert.throws(() => signed.checkCurrent(), e => e.code === 'attestation_expired');
  } finally { Date.now = original; }
}));
async function killedRecovery(f, phase) {
  const child = fork(new URL('./bundle-signed-recovery-child.mjs', import.meta.url), [f.input, f.envelope, f.publicKey, repository, sequence, f.destination, headHex, phase, 'fresh'],
    { stdio: ['ignore', 'pipe', 'pipe', 'ipc'], env: { ...process.env, PATH: '/nonexistent' } });
  let stderr = ''; child.stderr.on('data', chunk => { stderr += chunk; });
  const exit = once(child, 'exit');
  try {
    const ready = await new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error(`child timeout: ${stderr}`)), 10000);
      child.once('message', value => { clearTimeout(timer); value.ready ? resolve(value) : reject(new Error(JSON.stringify(value))); });
      child.once('exit', (code, signal) => { clearTimeout(timer); reject(new Error(`child exited early ${code}/${signal}: ${stderr}`)); });
      child.once('error', error => { clearTimeout(timer); reject(error); });
    });
    assert(child.kill('SIGKILL')); const ended = await exit; assert.equal(ended[1], 'SIGKILL'); return ready;
  } finally {
    if (child.exitCode === null && child.signalCode === null) { child.kill('SIGKILL'); await exit; }
  }
}
for (const format of ['sha1', 'sha256']) for (const phase of ['partial-pack', 'before_publication', 'published']) {
  test(`${format}: signed CLI resumes real process death at ${phase}, rechecks trust, and preserves source identity`, () => withSignedFixture(async f => {
    const reached = await killedRecovery(f, phase); const hadHead = !await absent(join(f.destination, 'HEAD'));
    assert.equal(hadHead, phase === 'published');
    if (phase === 'partial-pack') assert(reached.written > 0 && reached.written < reached.total);
    const before = await treeSnapshot(f.destination);
    f.authArgs[f.authArgs.length - 1] = '43'; refused(recover(f, ['--resume']), 'attestation_below_sequence_floor', 'existing_unknown');
    assert.deepEqual(await treeSnapshot(f.destination), before); f.authArgs[f.authArgs.length - 1] = sequence;
    const result = success(recover(f, ['--resume'])); assert.equal(result.resumed, true); assert.equal(result.already_published, hadHead);
    assert.equal(result.source_attestation.signature_verified, true); assert.equal(result.verification.object_closure_verified, true);
    assert(result.reused_bytes > 0); if (phase === 'partial-pack') assert(result.appended_bytes > 0);
    gitOk(f, ['-C', f.destination, 'fsck', '--strict']);
    assert.equal(gitOk(f, ['-C', f.destination, 'rev-parse', 'HEAD']).toString().trim(), f.ids.tip);
  }, format, { large: true }));
}
