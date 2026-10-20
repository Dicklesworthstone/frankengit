// Real operator processes, private files and sockets; no mocked transport.
import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtemp, rm, writeFile, readFile, access } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { Writable } from 'node:stream';
import { main } from '../../scripts/fg_source_edit.mjs';
import { evidencePeer, TOKEN, PRINCIPAL } from './source_edit_evidence_fixture.mjs';
const script = fileURLToPath(new URL('../../scripts/fg_source_edit.mjs', import.meta.url));
function start(args) {
  const child = spawn(process.execPath, [script, ...args], { stdio: ['ignore', 'pipe', 'pipe'] });
  let out = '', err = ''; child.stdout.on('data', b => out += b); child.stderr.on('data', b => err += b);
  const result = new Promise((resolve, reject) => { child.once('error', reject); child.once('close', (code, signal) => resolve({ code, signal, out, err })); });
  return { child, result };
}
const run = args => start(args).result;
const send = (res, value) => { res.writeHead(200, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(value)); };
async function local(t, format = 'sha1', scenario = 'text') {
  const f = await evidencePeer(t, format, scenario), dir = await mkdtemp(join(tmpdir(), 'fg-evidence-cli-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const files = Object.fromEntries(['selection', 'package', 'expect', 'patch', 'token', 'candidate', 'journal'].map(n => [n, join(dir, n)]));
  for (const [name, bytes] of [['selection', JSON.stringify(f.request)], ['package', f.evidence.package_bytes],
    ['expect', JSON.stringify(f.expected)], ['patch', f.patchBytes], ['token', TOKEN]]) await writeFile(files[name], bytes, { mode: 0o600 });
  const prepare = ['prepare-verified', '--selection', files.selection, '--package', files.package, '--expect', files.expect,
    '--patch-file', files.patch, '--token-file', files.token, '--output', files.candidate];
  const stage = async () => {
    const prepared = await run(prepare); assert.equal(prepared.code, 0, prepared.err); const saved = JSON.parse(prepared.out);
    const staged = await run(['stage', '--candidate', files.candidate, '--sha256', saved.manifest_sha256,
      '--principal', PRINCIPAL, '--confirm-candidate', f.candidate, '--journal', files.journal]);
    assert.equal(staged.code, 0, staged.err); const receipt = JSON.parse(staged.out);
    return { saved, receipt, args: ['--journal', files.journal, '--request-sha256', receipt.request_sha256] };
  };
  const publication = () => ({ type: 'source_publication', schema_version: 1, ...f.request.scope, principal_id: PRINCIPAL,
    ref: f.request.ref, ref_hex: Buffer.from(f.request.ref).toString('hex'), expected_commit: f.base, candidate_commit: f.candidate,
    tx_id: 'evidence-tx', outcome: 'committed', decision_sequence: 7, decision_record: 'evidence-rcr', refusal_code: null, delivery_acknowledged: null });
  const outcome = () => ({ type: 'transaction_outcome', schema_version: 1, tenant_id: f.request.scope.tenant_id, repository_id: f.request.scope.repository_id,
    repository_incarnation: f.request.scope.repository_incarnation, principal_id: PRINCIPAL,
    selector: 'transaction', command_index: null, state: 'committed', terminal: true,
    transaction: { tx_id: 'evidence-tx', seal_id: 'evidence-seal', request_schema: 'evidence-schema', canonical_request_digest: { algorithm: 2, hex: '6'.repeat(64) } },
    decision: { kind: 'committed', decision_sequence: 7, repository_commit_id: 'evidence-rcr' }, read_only: true, request_reexecuted: false,
    absence_proves_non_commit: false, session_completeness_established: false });
  return { ...f, dir, files, prepare, stage, publication, outcome };
}
for (const format of ['sha1', 'sha256']) test(`${format}: executable carries independent evidence from preparation through one-shot apply and reopen`, async t => {
  const f = await local(t, format), { saved, receipt, args } = await f.stage();
  assert.equal(saved.source_verification.preimages_verified, true);
  assert.equal(saved.source_package.sha256, saved.source_verification.package_sha256);
  assert.deepEqual(receipt.source_verification, saved.source_verification);
  for (const name of ['package', 'expect', 'selection', 'patch']) await rm(f.files[name]);
  const inspection = await run(['inspect', '--candidate', f.files.candidate, '--sha256', saved.manifest_sha256]);
  assert.equal(inspection.code, 0, inspection.err);
  assert.deepEqual(JSON.parse(inspection.out).source_verification, saved.source_verification);
  await rm(f.files.candidate, { recursive: true });
  f.control.handler = (_req, res, call) => {
    assert.equal(call.operation, 'apply'); assert.equal(call.headers['idempotency-key'], receipt.key); send(res, f.publication());
  };
  const applied = await run(['apply', ...args, '--token-file', f.files.token]); assert.equal(applied.code, 0, applied.err);
  assert.deepEqual(JSON.parse(applied.out).source_verification, saved.source_verification);
  await rm(f.files.token);
  const count = f.calls.length, status = await run(['status', ...args]); assert.equal(status.code, 0, status.err);
  assert.deepEqual(JSON.parse(status.out).source_verification, saved.source_verification);
  assert.equal(f.calls.length, count); assert.deepEqual(f.calls.map(c => c.operation), ['prepare', 'inspect', 'apply']);
});
for (const scenario of ['raw', 'binary']) test(`${scenario}: CLI preserves byte paths and honest after-body verification limits`, async t => {
  const f = await local(t, 'sha256', scenario), result = await run(f.prepare);
  assert.equal(result.code, 0, result.err); const saved = JSON.parse(result.out);
  const loaded = await run(['inspect', '--candidate', f.files.candidate, '--sha256', saved.manifest_sha256]);
  assert.equal(loaded.code, 0, loaded.err);
  const data = JSON.parse(loaded.out);
  assert.deepEqual(data.paths_hex, [f.pathHex]);
  assert.deepEqual(data.source_verification.unverified_after_paths_hex, scenario === 'binary' ? [f.pathHex] : []);
  assert.equal(data.source_verification.bundle_objects_independently_verified, false);
});
test('CLI rejects a genuine unreported Git tree change before saving any candidate', async t => {
  const f = await local(t, 'sha1', 'hidden'), result = await run(f.prepare);
  assert.equal(result.code, 2); assert.equal(JSON.parse(result.err).code, 'source_edit_unreported_tree_effect');
  await assert.rejects(access(f.files.candidate)); assert.deepEqual(f.calls.map(c => c.operation), ['prepare', 'inspect']);
});
for (const name of ['package', 'expect']) test(`invalid ${name} input refuses with no HTTP or candidate directory`, async t => {
  const f = await local(t); await writeFile(f.files[name], '{}');
  const result = await run(f.prepare); assert.equal(result.code, 2);
  assert.equal(f.calls.length, 0); await assert.rejects(access(f.files.candidate));
});
for (const signal of ['SIGTERM', 'SIGKILL']) test(`${signal} after sending retains evidence and original-key-only recovery`, async t => {
  const f = await local(t), { saved, receipt, args } = await f.stage();
  let signalSeen; const seen = new Promise(r => signalSeen = r);
  f.control.handler = (_req, res, call) => {
    if (call.operation === 'apply') { signalSeen(); return; }
    assert.equal(call.operation, 'outcomes'); assert.equal(call.body.length, 0); assert.equal(call.headers['idempotency-key'], receipt.key);
    send(res, f.outcome());
  };
  const action = start(['apply', ...args, '--token-file', f.files.token]); await seen; action.child.kill(signal);
  const stopped = await action.result;
  if (signal === 'SIGKILL') assert.equal(stopped.signal, signal); else assert.equal(stopped.code, 3);
  assert.equal((await run(['apply', ...args, '--token-file', f.files.token])).code, 2);
  const recovered = await run(['recover', ...args, '--token-file', f.files.token]); assert.equal(recovered.code, 0, recovered.err);
  assert.deepEqual(JSON.parse(recovered.out).source_verification, saved.source_verification);
  assert.deepEqual(f.calls.map(c => c.operation), ['prepare', 'inspect', 'apply', 'outcomes']);
});
test('lost stdout after verified export retains its evidence-bound manifest receipt', async t => {
  const f = await local(t); let diagnostics = '';
  const stdout = new Writable({ write(_data, _encoding, done) { done(Object.assign(new Error('output lost'), { code: 'EPIPE' })); } });
  const stderr = new Writable({ write(data, _encoding, done) { diagnostics += data; done(); } });
  assert.equal(await main(f.prepare, { stdout, stderr }), 4);
  const receipt = JSON.parse(diagnostics).retained_result;
  assert.equal(receipt.source_verification.exact_tree_effects_verified, true);
  const inspected = await run(['inspect', '--candidate', f.files.candidate, '--sha256', receipt.manifest_sha256]);
  assert.equal(inspected.code, 0, inspected.err); assert.deepEqual(JSON.parse(inspected.out).source_verification, receipt.source_verification);
});
test('two verified exporters cannot replace the winning independently pinned candidate', async t => {
  const f = await local(t), results = await Promise.all([run(f.prepare), run(f.prepare)]);
  assert.equal(results.filter(r => r.code === 0).length, 1);
  const saved = JSON.parse(results.find(r => r.code === 0).out);
  const inspected = await run(['inspect', '--candidate', f.files.candidate, '--sha256', saved.manifest_sha256]);
  assert.equal(inspected.code, 0, inspected.err);
  assert.deepEqual(JSON.parse(inspected.out).source_verification, saved.source_verification);
});
test('corrupt journal evidence blocks executable dispatch without losing the original request', async t => {
  const f = await local(t), { args } = await f.stage();
  const root = await readFile(join(f.files.journal, 'request.json'));
  await writeFile(join(f.files.journal, 'candidate', 'source-package.json'), '{}');
  const result = await run(['apply', ...args, '--token-file', f.files.token]); assert.equal(result.code, 2);
  await assert.rejects(access(join(f.files.journal, 'dispatch')));
  assert.deepEqual(await readFile(join(f.files.journal, 'request.json')), root);
  assert.deepEqual(f.calls.map(c => c.operation), ['prepare', 'inspect']);
});
