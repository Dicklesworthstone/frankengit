import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn, execFileSync } from 'node:child_process';
import { createServer as httpsServer } from 'node:https';
import { mkdtemp, rm, writeFile, readFile, access } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { Writable } from 'node:stream';
import { main } from '../../scripts/fg_source_edit.mjs';
import { peer, TOKEN, PRINCIPAL } from './source_edit_fixture.mjs';
const script = fileURLToPath(new URL('../../scripts/fg_source_edit.mjs', import.meta.url));
function start(args, closeOutput = false) {
  const child = spawn(process.execPath, [script, ...args], { stdio: ['ignore', 'pipe', 'pipe'] });
  let out = '', err = ''; child.stdout.on('data', b => out += b); child.stderr.on('data', b => err += b);
  if (closeOutput) child.stdout.destroy();
  const result = new Promise((resolve, reject) => { child.on('error', reject); child.on('close', (code, signal) => resolve({ code, signal, out, err })); });
  return { child, result };
}
const run = args => start(args).result;
async function local(t, format = 'sha1') {
  const f = await peer(t, format), dir = await mkdtemp(join(tmpdir(), 'fg-source-edit-cli-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const files = { selection: join(dir, 'selection.json'), patch: join(dir, 'patch'), token: join(dir, 'token'), candidate: join(dir, 'candidate'), journal: join(dir, 'journal') };
  for (const [path, bytes] of [[files.selection, JSON.stringify(f.request)], [files.patch, f.patch], [files.token, TOKEN]]) await writeFile(path, bytes, { mode: 0o600 });
  const prepare = ['prepare', '--selection', files.selection, '--patch-file', files.patch, '--token-file', files.token, '--output', files.candidate];
  async function stage() {
    const result = await run(prepare); assert.equal(result.code, 0, result.err); const saved = JSON.parse(result.out);
    const args = ['stage', '--candidate', files.candidate, '--sha256', saved.manifest_sha256, '--principal', PRINCIPAL,
      '--confirm-candidate', f.candidate, '--journal', files.journal];
    const staging = await run(args); assert.equal(staging.code, 0, staging.err); const receipt = JSON.parse(staging.out);
    return { saved, receipt, stageArgs: args, publicationArgs: ['--journal', files.journal, '--request-sha256', receipt.request_sha256] };
  }
  const terminal = () => ({ type: 'source_publication', schema_version: 1, ...f.request.scope, principal_id: PRINCIPAL,
    ref: f.request.ref, ref_hex: Buffer.from(f.request.ref).toString('hex'), expected_commit: f.base, candidate_commit: f.candidate,
    tx_id: 'fixture-tx', outcome: 'committed', decision_sequence: 5, decision_record: 'fixture-rcr', refusal_code: null, delivery_acknowledged: null });
  const outcome = () => ({ type: 'transaction_outcome', schema_version: 1, tenant_id: f.request.scope.tenant_id, repository_id: f.request.scope.repository_id,
    repository_incarnation: f.request.scope.repository_incarnation, principal_id: PRINCIPAL,
    selector: 'transaction', command_index: null, state: 'committed', terminal: true,
    transaction: { tx_id: 'fixture-tx', seal_id: 'fixture-seal', request_schema: 'fixture-schema', canonical_request_digest: { algorithm: 2, hex: '6'.repeat(64) } },
    decision: { kind: 'committed', decision_sequence: 5, repository_commit_id: 'fixture-rcr' }, read_only: true, request_reexecuted: false,
    absence_proves_non_commit: false, session_completeness_established: false });
  const send = (res, value) => { res.writeHead(200, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(value)); };
  return { ...f, dir, files, prepare, stage, terminal, outcome, send };
}
for (const format of ['sha1', 'sha256']) test(`${format}: real executable prepares, inspects, stages, applies and reopens without another write`, async t => {
  const f = await local(t, format), { saved, publicationArgs } = await f.stage();
  const inspected = await run(['inspect', '--candidate', f.files.candidate, '--sha256', saved.manifest_sha256]);
  assert.equal(inspected.code, 0, inspected.err); assert.equal(JSON.parse(inspected.out).candidate_commit, f.candidate);
  assert.deepEqual(f.calls.map(c => c.operation), ['prepare', 'inspect']);
  f.control.handler = (_req, res, call) => f.send(res, call.operation === 'apply' ? f.terminal() : f.outcome());
  const applied = await run(['apply', ...publicationArgs, '--token-file', f.files.token]);
  assert.equal(applied.code, 0, applied.err); assert.equal(JSON.parse(applied.out).decision.outcome, 'committed');
  const count = f.calls.length; await rm(f.files.candidate, { recursive: true }); await rm(f.files.token);
  const status = await run(['status', ...publicationArgs]); assert.equal(status.code, 0, status.err);
  assert.equal(JSON.parse(status.out).decision.outcome, 'committed'); assert.equal(f.calls.length, count);
});
test('stage requires the independently confirmed candidate and has no mutation route', async t => {
  const f = await local(t), prepared = await run(f.prepare); assert.equal(prepared.code, 0, prepared.err);
  const saved = JSON.parse(prepared.out), args = ['stage', '--candidate', f.files.candidate, '--sha256', saved.manifest_sha256,
    '--principal', PRINCIPAL, '--confirm-candidate', 'f'.repeat(40), '--journal', f.files.journal];
  const refused = await run(args); assert.equal(refused.code, 2); await assert.rejects(access(f.files.journal));
  assert.deepEqual(f.calls.map(c => c.operation), ['prepare', 'inspect']);
});
for (const signal of ['SIGKILL', 'SIGTERM']) test(`${signal} after transmission retains one owner and a new executable only looks up its original key`, async t => {
  const f = await local(t), { receipt, publicationArgs } = await f.stage();
  let resolveSeen; const seen = new Promise(r => resolveSeen = r);
  f.control.handler = async (_req, res, call) => {
    if (call.operation === 'apply') { resolveSeen(); return; }
    assert.equal(call.operation, 'outcomes'); assert.equal(call.body.length, 0); assert.equal(call.headers['idempotency-key'], receipt.key);
    f.send(res, f.outcome());
  };
  const action = start(['apply', ...publicationArgs, '--token-file', f.files.token]);
  await seen; action.child.kill(signal); const stopped = await action.result;
  if (signal === 'SIGKILL') assert.equal(stopped.signal, signal); else assert.equal(stopped.code, 3);
  const refused = await run(['apply', ...publicationArgs, '--token-file', f.files.token]); assert.notEqual(refused.code, 0);
  assert.equal(f.calls.filter(c => c.operation === 'apply').length, 1);
  const recovered = await run(['recover', ...publicationArgs, '--token-file', f.files.token]); assert.equal(recovered.code, 0, recovered.err);
  assert.equal(JSON.parse(recovered.out).decision.outcome, 'committed');
});
test('two executable instances cannot send the staged mutation twice', async t => {
  const f = await local(t), { publicationArgs } = await f.stage();
  f.control.handler = async (_req, res) => { await new Promise(r => setTimeout(r, 60)); f.send(res, f.terminal()); };
  const args = ['apply', ...publicationArgs, '--token-file', f.files.token];
  const outputs = await Promise.all([run(args), run(args)]);
  assert.ok(outputs.some(r => r.code === 0)); assert.equal(f.calls.filter(c => c.operation === 'apply').length, 1);
});
test('lost stdout retains the settled terminal and recover does not resubmit', async t => {
  const f = await local(t), { publicationArgs } = await f.stage();
  f.control.handler = (_req, res) => f.send(res, f.terminal());
  let diagnostics = '';
  const stdout = new Writable({ write(_chunk, _encoding, done) { done(Object.assign(new Error('broken output'), { code: 'EPIPE' })); } });
  const stderr = new Writable({ write(chunk, _encoding, done) { diagnostics += chunk; done(); } });
  const result = await main(['apply', ...publicationArgs, '--token-file', f.files.token], { stdout, stderr });
  assert.equal(result, 4); assert.equal(JSON.parse(diagnostics).retained_result.decision.outcome, 'committed');
  const count = f.calls.length, recovered = await run(['recover', ...publicationArgs, '--token-file', f.files.token]);
  assert.equal(recovered.code, 0, recovered.err); assert.equal(f.calls.length, count);
});
test('closed command grammar never turns offline inspection into dispatch', async t => {
  const f = await local(t), { publicationArgs } = await f.stage();
  const count = f.calls.length;
  for (const args of [['status', ...publicationArgs, '--token-file', f.files.token], ['apply', ...publicationArgs, '--force', 'true'],
    ['recover', ...publicationArgs, '--endpoint', f.request.endpoint, '--token-file', f.files.token],
    ['apply', ...publicationArgs, '--token-file', f.files.token, '--timeout-ms', '0']]) {
    assert.equal((await run(args)).code, 2);
  }
  assert.equal(f.calls.length, count);
});
test('a retained request must be intact before reading a rotated credential can send anything', async t => {
  const f = await local(t), { publicationArgs } = await f.stage();
  await writeFile(join(f.files.journal, 'candidate', 'candidate.bundle'), 'changed');
  assert.equal((await run(['apply', ...publicationArgs, '--token-file', f.files.token])).code, 2);
  assert.equal(f.calls.filter(c => c.operation === 'apply').length, 0);
});
test('certificate-verified HTTPS preparation succeeds only with the explicit private trust root', async t => {
  const f = await local(t), keyPath = join(f.dir, 'tls-key.pem'), certPath = join(f.dir, 'tls-cert.pem');
  execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', keyPath, '-out', certPath,
    '-days', '1', '-subj', '/CN=127.0.0.1', '-addext', 'subjectAltName=IP:127.0.0.1'], { stdio: 'ignore' });
  const cert = await readFile(certPath); await writeFile(certPath, cert, { mode: 0o600 });
  // openssl chooses certificate mode independently; enforce the CLI's private profile.
  const { chmod } = await import('node:fs/promises'); await chmod(certPath, 0o600);
  const server = httpsServer({ key: await readFile(keyPath), cert }, async (req, res) => {
    for await (const _chunk of req) {};
    if (req.url.endsWith('/prepare')) { const p = f.frame(); res.writeHead(200, { 'Content-Type': p.type }); res.end(p.bytes); }
    else f.send(res, f.inspection);
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => { server.closeAllConnections(); return new Promise(r => server.close(r)); });
  await writeFile(f.files.selection, JSON.stringify({ ...f.request, endpoint: `https://127.0.0.1:${server.address().port}/repo.git` }));
  const refused = await run(f.prepare); assert.equal(refused.code, 2); await assert.rejects(access(f.files.candidate));
  const allowed = await run([...f.prepare, '--ca-file', certPath]); assert.equal(allowed.code, 0, allowed.err);
});
