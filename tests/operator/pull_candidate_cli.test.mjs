// Actual CLI processes and private files. HTTP reports are native-schema peers,
// not an executed Rust server, while bundle bytes come from the existing Git oracle.
import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn, execFileSync } from 'node:child_process';
import { once } from 'node:events';
import { mkdtemp, writeFile, readFile, chmod, mkdir, lstat, readdir, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { run } from '../../scripts/fg_pull_candidate.mjs';
import { loadCandidatePackage, saveCandidateJson } from '../../scripts/operator/pull_candidate_files.mjs';
import { candidateCanonical, candidateHash } from '../../scripts/operator/pull_candidate_capture.mjs';
import { preparePull, pullEnvelope } from '../../scripts/operator/pull_command.mjs';
import { candidatePeer, TOKEN, REVIEWER } from './pull_candidate_fixture.mjs';
const CLI = resolve('scripts/fg_pull_candidate.mjs'), ACTOR = 'e'.repeat(32);
async function files(t, input) {
  const root = await mkdtemp(join(tmpdir(), 'fg-candidate-cli-')); await chmod(root, 0o700);
  t.after(() => rm(root, { recursive: true, force: true }));
  const f = { root, input: join(root, 'input.json'), token: join(root, 'token'), package: join(root, 'candidate'),
    choices: join(root, 'choices.json'), output: join(root, 'draft.json') };
  await writeFile(f.input, candidateCanonical(input), { mode: 0o600 }); await writeFile(f.token, TOKEN + '\n', { mode: 0o600 }); return f;
}
function launch(t, args, { brokenOutput = false } = {}) {
  const child = spawn(process.execPath, [CLI, ...args], { stdio: ['ignore', 'pipe', 'pipe'] });
  let out = '', err = '', done = false;
  const timer = setTimeout(() => child.kill('SIGKILL'), 12000);
  t.after(() => { if (!done) child.kill('SIGKILL'); });
  if (brokenOutput) child.stdout.destroy();
  else child.stdout.on('data', c => { out += c; if (out.length > 20 * 1024 * 1024) child.kill('SIGKILL'); });
  child.stderr.on('data', c => { err += c; if (err.length > 1024 * 1024) child.kill('SIGKILL'); });
  const result = once(child, 'close').then(([code, signal]) => { done = true; clearTimeout(timer); return { code, signal, out, err }; });
  return { child, result };
}
const cli = (t, args, options) => launch(t, args, options).result;
const captureArgs = f => ['capture', '--input', f.input, '--token-file', f.token, '--output-dir', f.package];
const inspectArgs = (f, sha) => ['inspect', '--package', f.package, '--sha256', sha];
const draftArgs = (f, sha) => ['draft', '--package', f.package, '--sha256', sha, '--choices', f.choices, '--output', f.output];
async function choices(f, p, action = 'approve', actor = REVIEWER) {
  const value = { action, principal_id: actor, candidate_commit: p.fixture.candidate,
    ...(action === 'merge' ? { method: p.fixture.method, required_reviewers: [REVIEWER] } : { reason: 'Reviewed exact bytes.\n🦀' }) };
  await writeFile(f.choices, candidateCanonical(value), { mode: 0o600 }); return value;
}
async function captured(t, p) {
  const f = await files(t, p.input), r = await cli(t, captureArgs(f)); assert.equal(r.code, 0, r.err);
  return { ...f, receipt: JSON.parse(r.out) };
}
for (const algorithm of ['sha1', 'sha256']) for (const method of ['merge-commit', 'squash']) {
  test(`${algorithm} ${method}: native acquisition to offline inspection and preparer-compatible drafts`, async t => {
    const p = await candidatePeer(t, { algorithm, method, reviewCount: 51 }), f = await captured(t, p);
    assert.equal(f.receipt.published, false); assert.equal(f.receipt.usage.requests, 5);
    assert.equal(f.receipt.state, 'clean'); const before = p.requests.length;
    const inspected = await cli(t, inspectArgs(f, f.receipt.sha256)); assert.equal(inspected.code, 0, inspected.err);
    const data = JSON.parse(inspected.out); assert.equal(data.capture.inspection.candidate_commit, `${algorithm}:${p.fixture.candidate}`);
    assert.equal(data.capture.inspection.comparison.entries[0].path_hex.endsWith('ff'), true);
    assert.equal(inspected.out.includes(TOKEN), false);
    for (const action of ['approve', 'request-changes', 'merge']) {
      const actor = action === 'merge' ? ACTOR : (51).toString(16).padStart(32, '0');
      await choices(f, p, action, actor); const selected = { ...f, output: join(f.root, `${action}.json`) };
      const drafted = await cli(t, draftArgs(selected, f.receipt.sha256)); assert.equal(drafted.code, 0, drafted.err);
      const report = JSON.parse(drafted.out), bytes = await readFile(selected.output), input = JSON.parse(bytes);
      assert.equal(report.package_sha256, f.receipt.sha256); assert.equal(report.sha256, candidateHash(bytes));
      assert.equal(report.bundle_path, f.receipt.bundle_path); assert.equal(report.published, false);
      const intent = preparePull(input, TOKEN, await readFile(report.bundle_path));
      assert.equal(intent.fields.candidate_commit, p.fixture.candidate); assert.equal(intent.fields.policy_epoch, '3');
      assert.equal(intent.fields.pull_request_version, '9'); assert.equal(intent.scope.principal_id, actor);
      if (action !== 'merge') assert.equal(intent.fields.expected_version, '2');
      const envelope = pullEnvelope(intent, p.fixture.bundle); assert.ok(envelope.body.includes(p.fixture.bundle));
      assert.equal((await lstat(selected.output)).mode & 0o777, 0o600); assert.equal((await lstat(selected.output)).nlink, 1);
      assert.equal(drafted.out.includes(TOKEN), false);
    }
    assert.equal(p.requests.length, before, 'inspection/drafting and preparation are offline');
  });
}
for (const state of ['conflicted', 'already_up_to_date']) test(`${state}: saved typed report, inspectable but never draftable`, async t => {
  const p = await candidatePeer(t, { state }), f = await files(t, p.input), result = await cli(t, captureArgs(f));
  assert.equal(result.code, 1, result.err); const receipt = JSON.parse(result.out);
  assert.equal(receipt.bundle_path, null); assert.equal(receipt.state, state); assert.equal(receipt.published, false);
  assert.equal((await cli(t, inspectArgs(f, receipt.sha256))).code, 0);
  await choices(f, p); const draft = await cli(t, draftArgs(f, receipt.sha256)); assert.equal(draft.code, 2, draft.err);
  await assert.rejects(lstat(f.output), { code: 'ENOENT' }); assert.equal(p.requests.length, 3);
});
for (const field of ['input', 'token']) test(`private ${field} rejected before network`, async t => {
  const p = await candidatePeer(t), f = await files(t, p.input); await chmod(f[field], 0o644);
  const result = await cli(t, captureArgs(f)); assert.equal(result.code, 2); assert.equal(p.requests.length, 0);
  assert.equal(result.err.includes(TOKEN), false);
});
for (const raw of ['{"number":1,"number":2}', '{"number":9007199254740993}', '{broken', 'x'.repeat(512 * 1024 + 1)]) {
  test(`invalid capture input ${raw.slice(0, 60)} stops before networking`, async t => {
    const p = await candidatePeer(t), f = await files(t, p.input); await writeFile(f.input, raw);
    const result = await cli(t, captureArgs(f)); assert.equal(result.code, 2); assert.equal(p.requests.length, 0);
  });
}
test('capture refuses an existing or interrupted output before requesting credentials or network work', async t => {
  const p = await candidatePeer(t), f = await files(t, p.input);
  await mkdir(f.package, { mode: 0o700 }); await writeFile(join(f.package, 'capture.json'), '{partial', { mode: 0o600 });
  const result = await cli(t, captureArgs(f)); assert.equal(result.code, 2); assert.equal(p.requests.length, 0);
  assert.equal(await readFile(join(f.package, 'capture.json'), 'utf8'), '{partial');
});
test('concurrent capture commands have one new-slot winner without replacing its bytes', async t => {
  const p = await candidatePeer(t), f = await files(t, p.input);
  const results = await Promise.all([cli(t, captureArgs(f)), cli(t, captureArgs(f))]);
  assert.equal(results.filter(r => r.code === 0).length, 1);
  const winner = JSON.parse(results.find(r => r.code === 0).out);
  const loaded = await loadCandidatePackage(f.package, winner.sha256); assert.deepEqual(loaded.bundle, p.fixture.bundle);
  assert.ok([2, 3].includes(results.find(r => r.code !== 0).code));
});
test('review page limit refuses the entire read; explicitly larger bound succeeds', async t => {
  const p = await candidatePeer(t, { reviewCount: 51 }), f = await files(t, p.input);
  const bad = await cli(t, [...captureArgs(f), '--max-review-pages', '1']); assert.equal(bad.code, 3);
  assert.equal(p.requests.length, 2); await assert.rejects(lstat(f.package), { code: 'ENOENT' });
  const good = await cli(t, [...captureArgs(f), '--max-review-pages', '2']); assert.equal(good.code, 0, good.err);
});
test('one operation deadline refuses a stalled inspection, without a successful package prefix', async t => {
  const p = await candidatePeer(t, { handle(r) { return r.url.endsWith('/inspect'); } }), f = await files(t, p.input);
  const result = await cli(t, [...captureArgs(f), '--timeout-ms', '400']);
  assert.equal(result.code, 3); assert.equal(JSON.parse(result.err).code, 'candidate_timeout');
  assert.equal(p.requests.length, 4); await assert.rejects(lstat(f.package), { code: 'ENOENT' });
});
for (const signal of ['SIGTERM', 'SIGKILL']) test(`${signal} during capture cannot publish a completed package`, async t => {
  let ready; const reached = new Promise(resolve => ready = resolve);
  const p = await candidatePeer(t, { handle(r) { if (r.url.endsWith('/inspect')) { ready(); return true; } } }), f = await files(t, p.input);
  const operation = launch(t, captureArgs(f)); await reached; operation.child.kill(signal); const result = await operation.result;
  if (signal === 'SIGKILL') assert.equal(result.signal, signal); else assert.equal(result.code, 3);
  await assert.rejects(lstat(f.package), { code: 'ENOENT' }); assert.equal(p.requests.length, 4);
});
test('closed stdout after capture preserves a complete package and its identity in the error receipt', async t => {
  const p = await candidatePeer(t), f = await files(t, p.input), result = await cli(t, captureArgs(f), { brokenOutput: true });
  assert.equal(result.code, 3); const error = JSON.parse(result.err); assert.equal(error.completed.path, f.package);
  assert.equal(error.completed.state, 'clean'); assert.deepEqual((await loadCandidatePackage(f.package, error.completed.sha256)).bundle, p.fixture.bundle);
  assert.equal(result.err.includes(TOKEN), false);
});
test('wrong pins, changed candidate choice, and missing bundles refuse draft before output', async t => {
  const p = await candidatePeer(t), f = await captured(t, p); await choices(f, p); const count = p.requests.length;
  assert.equal((await cli(t, draftArgs(f, '0'.repeat(64)))).code, 2);
  const bad = await choices(f, p); bad.candidate_commit = '0'.repeat(40); await writeFile(f.choices, candidateCanonical(bad));
  assert.equal((await cli(t, draftArgs(f, f.receipt.sha256))).code, 2);
  await choices(f, p); await rm(f.receipt.bundle_path);
  assert.equal((await cli(t, draftArgs(f, f.receipt.sha256))).code, 2);
  assert.equal(p.requests.length, count); await assert.rejects(lstat(f.output), { code: 'ENOENT' });
});
test('existing draft is never overwritten, including a concurrent creator', async t => {
  const p = await candidatePeer(t), f = await captured(t, p); await choices(f, p);
  await writeFile(f.output, 'existing', { mode: 0o600 });
  assert.equal((await cli(t, draftArgs(f, f.receipt.sha256))).code, 2);
  assert.equal(await readFile(f.output, 'utf8'), 'existing');
  const destination = join(f.root, 'raced.json'), one = { writer: 1 }, two = { writer: 2 };
  const results = await Promise.allSettled([saveCandidateJson(destination, one), saveCandidateJson(destination, two)]);
  assert.equal(results.filter(r => r.status === 'fulfilled').length, 1);
  const result = JSON.parse(await readFile(destination, 'utf8')); assert.ok([1, 2].includes(result.writer));
});
test('closed stdout after drafting preserves the complete sender input', async t => {
  const p = await candidatePeer(t), f = await captured(t, p); await choices(f, p);
  const result = await cli(t, draftArgs(f, f.receipt.sha256), { brokenOutput: true }); assert.equal(result.code, 3);
  const error = JSON.parse(result.err), bytes = await readFile(f.output);
  assert.equal(error.completed.sha256, candidateHash(bytes)); assert.equal(error.completed.path, f.output);
  assert.equal(preparePull(JSON.parse(bytes), TOKEN, p.fixture.bundle).fields.expected_version, '2');
});
for (const extras of [['--force', 'true'], ['--method', 'squash'], ['--timeout-ms', '0'], ['--timeout-ms', '300001'],
  ['--max-review-pages', '9'], ['--max-wire-bytes', '67108865'], ['--input', 'duplicate']]) test(`closed capture grammar ${extras.join(' ')}`, async t => {
  const p = await candidatePeer(t), f = await files(t, p.input), result = await cli(t, [...captureArgs(f), ...extras]);
  assert.equal(result.code, 2); assert.equal(p.requests.length, 0);
});
test('offline commands reject credentials and endpoint/CA overrides', async t => {
  const p = await candidatePeer(t), f = await captured(t, p); await choices(f, p); const count = p.requests.length;
  for (const args of [inspectArgs(f, f.receipt.sha256), draftArgs(f, f.receipt.sha256)]) for (const flag of ['token-file', 'ca-file', 'endpoint']) {
    assert.equal((await cli(t, [...args, `--${flag}`, f.token])).code, 2);
  }
  assert.equal(p.requests.length, count);
});
test('in-process output failure carries completed receipt without printing arbitrary exceptions', async t => {
  const p = await candidatePeer(t), f = await files(t, p.input); let error = '';
  const code = await run(captureArgs(f), { output: async () => { throw new Error(TOKEN); }, errorOutput: async text => { error += text; } });
  assert.equal(code, 3); assert.equal(error.includes(TOKEN), false);
  const receipt = JSON.parse(error).completed; assert.deepEqual((await loadCandidatePackage(receipt.path, receipt.sha256)).bundle, p.fixture.bundle);
});

for (const name of ['loopback', 'wrong-host']) test(`CLI private CA: ${name}`, async t => {
  const f = await files(t, {}), certPath = join(f.root, 'ca.pem'), keyPath = join(f.root, 'key.pem');
  execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', keyPath,
    '-out', certPath, '-days', '1', '-subj', '/CN=fixture.invalid', '-addext',
    `subjectAltName=${name === 'loopback' ? 'IP:127.0.0.1' : 'DNS:wrong.invalid'}`], { timeout: 15000, stdio: 'ignore' });
  await chmod(certPath, 0o600); const p = await candidatePeer(t, { tls: { cert: await readFile(certPath), key: await readFile(keyPath) } });
  await writeFile(f.input, candidateCanonical(p.input));
  const untrusted = await cli(t, captureArgs(f)); assert.equal(untrusted.code, 3); assert.equal(p.requests.length, 0);
  const trusted = await cli(t, [...captureArgs(f), '--ca-file', certPath]);
  if (name === 'loopback') { assert.equal(trusted.code, 0, trusted.err); assert.equal(p.requests.length, 4); }
  else { assert.equal(trusted.code, 3); assert.equal(p.requests.length, 0); }
});
