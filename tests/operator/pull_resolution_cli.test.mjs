// Actual CLI/private-file workflows with independent Git objects and explicit
// native-schema HTTP peers. This is not a running Rust forge or policy oracle.
import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn, execFileSync } from 'node:child_process';
import { once } from 'node:events';
import { mkdtemp, chmod, writeFile, readFile, mkdir, lstat, symlink, link, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { run } from '../../scripts/fg_pull_candidate.mjs';
import { capturePullCandidate, candidateCanonical, candidateHash, RESOLUTION_CHOICE_BYTES } from '../../scripts/operator/pull_candidate_capture.mjs';
import { saveCandidatePackage, loadCandidatePackage } from '../../scripts/operator/pull_candidate_files.mjs';
import { preparePull, pullEnvelope } from '../../scripts/operator/pull_command.mjs';
import { resolutionPeer, TOKEN } from './pull_resolution_fixture.mjs';

const CLI = resolve('scripts/fg_pull_candidate.mjs');
async function local(t, p, { ca } = {}) {
  const root = await mkdtemp(join(tmpdir(), 'fg-resolve-cli-')); await chmod(root, 0o700);
  t.after(() => rm(root, { recursive: true, force: true }));
  const paths = { root, source: join(root, 'original'), output: join(root, 'resolved'), token: join(root, 'token'),
    choices: join(root, 'choices.json'), draft: join(root, 'draft.json'), selection: join(root, 'selection.json') };
  const captured = await capturePullCandidate(p.input, TOKEN, ca ? { ca } : {});
  paths.saved = await saveCandidatePackage(paths.source, captured.capture);
  await writeFile(paths.token, TOKEN + '\n', { mode: 0o600 });
  await writeFile(paths.choices, candidateCanonical(p.choices), { mode: 0o600 });
  paths.original = await readFile(join(paths.source, 'capture.json'));
  return paths;
}
function launch(t, args, { brokenOutput = false } = {}) {
  const child = spawn(process.execPath, [CLI, ...args], { stdio: ['ignore', 'pipe', 'pipe'] });
  let out = '', err = '', complete = false;
  const timer = setTimeout(() => child.kill('SIGKILL'), 15000);
  t.after(() => { if (!complete) child.kill('SIGKILL'); });
  if (brokenOutput) child.stdout.destroy();
  else child.stdout.on('data', chunk => { out += chunk; if (out.length > 20 * 1024 * 1024) child.kill('SIGKILL'); });
  child.stderr.on('data', chunk => { err += chunk; if (err.length > 20 * 1024 * 1024) child.kill('SIGKILL'); });
  const result = once(child, 'close').then(([code, signal]) => { complete = true; clearTimeout(timer); return { code, signal, out, err }; });
  return { child, result };
}
const cli = (t, args, options) => launch(t, args, options).result;
const resolveArgs = f => ['resolve', '--package', f.source, '--sha256', f.saved.sha256, '--choices', f.choices,
  '--token-file', f.token, '--output-dir', f.output];
async function unchanged(f) { assert.deepEqual(await readFile(join(f.source, 'capture.json')), f.original); }
async function noOutput(f) { await assert.rejects(lstat(f.output), { code: 'ENOENT' }); await unchanged(f); }
async function reached(promise) {
  let timer;
  try { await Promise.race([promise, new Promise((_, reject) => timer = setTimeout(() => reject(new Error('peer not reached')), 8000))]); }
  finally { clearTimeout(timer); }
}

for (const algorithm of ['sha1', 'sha256']) for (const method of ['merge-commit', 'squash']) {
  for (const choice of ['base', 'ours', 'theirs', 'delete', 'file']) {
    test(`${algorithm} ${method} ${choice}: executable resolve -> private inspection -> unchanged preparer`, async t => {
      const p = await resolutionPeer(t, { algorithm, method, choice }), f = await local(t, p);
      const sent = await cli(t, resolveArgs(f)); assert.equal(sent.code, 0, sent.err);
      const receipt = JSON.parse(sent.out); assert.equal(receipt.state, 'resolved'); assert.equal(receipt.published, false);
      assert.equal(receipt.source_package_sha256, f.saved.sha256); assert.equal(receipt.usage.requests, 2);
      assert.equal(sent.out.includes(TOKEN), false); assert.equal(p.requests.length, 5);
      assert.equal(p.requests[3].url, '/repo.git/api/v1/pulls/7/resolve');
      assert.equal(p.requests[4].url, '/repo.git/api/v1/pulls/7/inspect');
      const pkg = await loadCandidatePackage(f.output, receipt.sha256);
      assert.equal(pkg.artifact.fields.candidate_commit, p.f.candidate); assert.deepEqual(pkg.bundle, p.f.bundle);
      assert.equal(pkg.capture.resolution.choices[0].choice, choice);
      assert.equal((await lstat(f.output)).mode & 0o777, 0o700);
      assert.equal((await lstat(pkg.bundle_path)).mode & 0o777, 0o600);
      const inspected = await cli(t, ['inspect', '--package', f.output, '--sha256', receipt.sha256]);
      assert.equal(inspected.code, 0, inspected.err);
      assert.deepEqual(JSON.parse(inspected.out).capture, pkg.capture); assert.equal(p.requests.length, 5);
      const selection = { action: 'approve', principal_id: '00000000000000000000000000000001',
        candidate_commit: p.f.candidate, reason: 'Inspected the explicitly resolved candidate.' };
      await writeFile(f.selection, candidateCanonical(selection), { mode: 0o600 });
      const drafted = await cli(t, ['draft', '--package', f.output, '--sha256', receipt.sha256,
        '--choices', f.selection, '--output', f.draft]);
      assert.equal(drafted.code, 0, drafted.err); assert.equal(p.requests.length, 5);
      const draft = JSON.parse(await readFile(f.draft, 'utf8'));
      assert.equal(draft.fields.expected_version, '2'); assert.equal(draft.fields.policy_epoch, '3');
      const intent = preparePull(draft, TOKEN, pkg.bundle), envelope = pullEnvelope(intent, pkg.bundle);
      assert.equal(intent.fields.candidate_commit, p.f.candidate); assert.ok(envelope.body.includes(pkg.bundle));
      assert.equal(intent.fields.source_tip, p.f.source); assert.equal(intent.fields.target_tip, p.f.target);
      await unchanged(f);
    });
  }
}
test('resolved squash package drafts exact merge requirements, not retained review authority', async t => {
  const p = await resolutionPeer(t, { algorithm: 'sha256', method: 'squash', choice: 'file', bytes: Buffer.from([0, 255, 10]), mode: '100755' });
  const f = await local(t, p), result = await cli(t, resolveArgs(f)); assert.equal(result.code, 0, result.err);
  const receipt = JSON.parse(result.out), pkg = await loadCandidatePackage(f.output, receipt.sha256);
  const selection = { action: 'merge', principal_id: '4'.repeat(32), candidate_commit: p.f.candidate,
    method: 'squash', required_reviewers: ['00000000000000000000000000000001'] };
  await writeFile(f.selection, candidateCanonical(selection), { mode: 0o600 });
  const drafted = await cli(t, ['draft', '--package', f.output, '--sha256', receipt.sha256, '--choices', f.selection, '--output', f.draft]);
  assert.equal(drafted.code, 0, drafted.err);
  const draft = JSON.parse(await readFile(f.draft, 'utf8')), intent = preparePull(draft, TOKEN, pkg.bundle);
  assert.equal(intent.fields.method, 'squash'); assert.deepEqual(intent.fields.required_reviewers, selection.required_reviewers);
  assert.equal(pkg.capture.review_pages[0].reviews[0].decision, 'request-changes');
  assert.equal(pkg.capture.preparation.merge_authorized, false); assert.equal(p.requests.length, 5);
});
test('a 1 MiB replacement survives the larger bounded choices envelope and offline revalidation', async t => {
  const bytes = Buffer.alloc(1024 * 1024, 0xff), p = await resolutionPeer(t, { choice: 'file', bytes, mode: '100755' }), f = await local(t, p);
  assert.ok((await lstat(f.choices)).size > 2 * 1024 * 1024);
  const result = await cli(t, resolveArgs(f)); assert.equal(result.code, 0, result.err);
  const value = await loadCandidatePackage(f.output, JSON.parse(result.out).sha256);
  assert.equal(value.capture.resolution.choices[0].content_hex, bytes.toString('hex'));
  assert.ok(p.requests[3].body.includes(bytes)); await unchanged(f);
});
for (const kind of ['wrong-pin', 'corrupt-original', 'public-token', 'symlink-token', 'hardlink-choices', 'public-choices', 'duplicate-json', 'malformed-choices', 'oversized-choices', 'existing-output']) {
  test(`${kind} refuses before resolution I/O or output publication`, async t => {
    const p = await resolutionPeer(t), f = await local(t, p);
    if (kind === 'wrong-pin') f.saved.sha256 = 'f'.repeat(64);
    if (kind === 'corrupt-original') await writeFile(join(f.source, 'capture.json'), '{partial');
    if (kind === 'public-token') await chmod(f.token, 0o644);
    if (kind === 'symlink-token') { await symlink(f.token, join(f.root, 'alias')); f.token = join(f.root, 'alias'); }
    if (kind === 'hardlink-choices') await link(f.choices, join(f.root, 'other'));
    if (kind === 'public-choices') await chmod(f.choices, 0o644);
    if (kind === 'duplicate-json') await writeFile(f.choices, '[{"path_hex":"61","choice":"base","choice":"theirs"}]');
    if (kind === 'malformed-choices') await writeFile(f.choices, '{}');
    if (kind === 'oversized-choices') await writeFile(f.choices, Buffer.alloc(2 * RESOLUTION_CHOICE_BYTES + 64 * 1024 + 1, 32));
    if (kind === 'existing-output') { await mkdir(f.output, { mode: 0o700 }); await writeFile(join(f.output, 'owner.txt'), 'unchanged'); }
    const result = await cli(t, resolveArgs(f)); assert.equal(result.code, 2, result.err); assert.equal(p.requests.length, 3);
    if (kind === 'existing-output') assert.equal(await readFile(join(f.output, 'owner.txt'), 'utf8'), 'unchanged');
    else await assert.rejects(lstat(f.output), { code: 'ENOENT' });
    if (kind !== 'corrupt-original') await unchanged(f);
  });
}
for (const extra of [['--force', 'true'], ['--method', 'squash'], ['--endpoint', 'https://elsewhere.invalid/repo.git'],
  ['--max-review-pages', '2'], ['--max-wire-bytes', '0'], ['--token-file', 'duplicate']]) {
  test(`resolve has no broadened option: ${extra.join(' ')}`, async t => {
    const p = await resolutionPeer(t), f = await local(t, p);
    assert.equal((await cli(t, [...resolveArgs(f), ...extra])).code, 2); assert.equal(p.requests.length, 3); await noOutput(f);
  });
}
for (const phase of ['resolve', 'inspect']) test(`lost ${phase} response yields no resolved package or automatic retry`, async t => {
  const p = await resolutionPeer(t, { handle(r, res) { if (r.url.endsWith('/' + phase)) { res.destroy(); return true; } } });
  const f = await local(t, p), result = await cli(t, resolveArgs(f)); assert.equal(result.code, 3, result.err);
  assert.equal(p.requests.length, phase === 'resolve' ? 4 : 5); await noOutput(f);
});
for (const signal of ['SIGTERM', 'SIGKILL']) test(`${signal} during resolution leaves the original package intact`, async t => {
  let admitted; const observed = new Promise(resolve => admitted = resolve);
  const p = await resolutionPeer(t, { handle(r) { if (r.url.endsWith('/resolve')) { admitted(); return true; } } });
  const f = await local(t, p), child = launch(t, resolveArgs(f)); await reached(observed); child.child.kill(signal);
  const result = await child.result;
  if (signal === 'SIGTERM') assert.equal(result.code, 3, result.err); else assert.equal(result.signal, signal);
  assert.equal(p.requests.length, 4); await noOutput(f);
  const inspected = await cli(t, ['inspect', '--package', f.source, '--sha256', f.saved.sha256]);
  assert.equal(inspected.code, 0, inspected.err); assert.equal(p.requests.length, 4);
});
test('a stalled final inspection spends one deadline and does not save a prefix', async t => {
  const p = await resolutionPeer(t, { handle(r) { return r.url.endsWith('/inspect'); } }), f = await local(t, p);
  const result = await cli(t, [...resolveArgs(f), '--timeout-ms', '300']); assert.equal(result.code, 3, result.err);
  assert.equal(JSON.parse(result.err).code, 'candidate_timeout'); assert.equal(p.requests.length, 5); await noOutput(f);
});
test('competing output creators never replace the winning resolved package', async t => {
  const p = await resolutionPeer(t), f = await local(t, p);
  const results = await Promise.all([cli(t, resolveArgs(f)), cli(t, resolveArgs(f))]);
  assert.equal(results.filter(r => r.code === 0).length, 1);
  assert.ok(results.filter(r => r.code !== 0).every(r => [2, 3].includes(r.code)));
  const winner = JSON.parse(results.find(r => r.code === 0).out), pkg = await loadCandidatePackage(f.output, winner.sha256);
  assert.deepEqual(pkg.bundle, p.f.bundle); await unchanged(f);
});
test('broken executable stdout preserves the fully synchronized resolved package and its hash', async t => {
  const p = await resolutionPeer(t), f = await local(t, p), result = await cli(t, resolveArgs(f), { brokenOutput: true });
  assert.equal(result.code, 3, result.err);
  const error = JSON.parse(result.err); assert.equal(error.completed.state, 'resolved'); assert.equal(error.published, false);
  assert.equal(result.err.includes(TOKEN), false);
  const pkg = await loadCandidatePackage(f.output, error.completed.sha256); assert.deepEqual(pkg.bundle, p.f.bundle); await unchanged(f);
});
test('an awaited output failure retains the completed package in the diagnostic', async t => {
  const p = await resolutionPeer(t), f = await local(t, p); let diagnostic = '';
  const code = await run(resolveArgs(f), { output: async () => { throw new Error('closed'); }, errorOutput: async text => { diagnostic = text; } });
  assert.equal(code, 3); const receipt = JSON.parse(diagnostic).completed;
  assert.equal(receipt.sha256, candidateHash(await readFile(join(f.output, 'manifest.json'))));
  await loadCandidatePackage(f.output, receipt.sha256); await unchanged(f);
});
test('TLS resolution requires a trusted certificate with matching hostname', async t => {
  const dir = await mkdtemp(join(tmpdir(), 'fg-resolution-tls-')); await chmod(dir, 0o700);
  t.after(() => rm(dir, { recursive: true, force: true }));
  for (const [name, alt] of [['local', 'IP:127.0.0.1'], ['wrong', 'DNS:elsewhere.invalid']]) {
    execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', join(dir, name + '.key'),
      '-out', join(dir, name + '.crt'), '-days', '1', '-subj', '/CN=' + name, '-addext', 'subjectAltName=' + alt], { stdio: 'ignore', timeout: 10000 });
  }
  const cert = await readFile(join(dir, 'local.crt')), key = await readFile(join(dir, 'local.key'));
  const p = await resolutionPeer(t, { tls: { key, cert } }), f = await local(t, p, { ca: cert });
  const refused = await cli(t, resolveArgs(f)); assert.equal(refused.code, 3); assert.equal(p.requests.length, 3); await noOutput(f);
  const caFile = join(f.root, 'ca.pem'); await writeFile(caFile, cert, { mode: 0o600 });
  const accepted = await cli(t, [...resolveArgs(f), '--ca-file', caFile]); assert.equal(accepted.code, 0, accepted.err);
  await loadCandidatePackage(f.output, JSON.parse(accepted.out).sha256);
  // Rebinding a fully valid local read capture to this test-only wrong-name
  // endpoint lets the resolution phase exercise real hostname verification.
  const wrongCert = await readFile(join(dir, 'wrong.crt')), wrongKey = await readFile(join(dir, 'wrong.key'));
  const bad = await resolutionPeer(t, { tls: { key: wrongKey, cert: wrongCert } });
  const original = JSON.parse(f.original); original.request.endpoint = bad.input.endpoint;
  const source = await saveCandidatePackage(join(f.root, 'wrong-source'), original);
  const path = join(f.root, 'wrong-ca.pem'); await writeFile(path, wrongCert, { mode: 0o600 });
  const selected = { ...f, source: source.path, saved: source, output: join(f.root, 'wrong-output') };
  const mismatch = await cli(t, [...resolveArgs(selected), '--ca-file', path]); assert.equal(mismatch.code, 3);
  assert.equal(bad.requests.length, 0); await assert.rejects(lstat(selected.output), { code: 'ENOENT' });
});
