// Real files, HTTP and CLI processes. Stored plans/native replies are explicit
// contract fixtures, not Rust evidence verification, admission or CAS proof.
import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { once as eventOnce } from 'node:events';
import { mkdtemp, mkdir, writeFile, readFile, readdir, rm, lstat, chmod } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawn } from 'node:child_process';
import { Writable } from 'node:stream';
import { once as execute } from '../../scripts/operator/workflow_watch.mjs';
import { configuration, recover, status, once } from '../../scripts/operator/workflow_check_publish.mjs';
import { encode, sha256, jobKey } from '../../scripts/operator/workflow_check_protocol.mjs';
import { recoveryScope, recoveryRecord, recoveredTerminal } from '../../scripts/operator/workflow_check_outcome.mjs';
import { main } from '../../scripts/fg_workflow_checks.mjs';

const token = 'a'.repeat(64), hex = text => Buffer.from(text).toString('hex');
const cli = new URL('../../scripts/fg_workflow_checks.mjs', import.meta.url).pathname;
const save = (path, value) => writeFile(path, encode(value), { mode: 0o600 });
const json = async path => JSON.parse(await readFile(path, 'utf8'));
async function fixture(t, format = 'sha1', count = 1) {
  const root = await mkdtemp(join(tmpdir(), 'fg-outcome-job-')); t.after(() => rm(root, { recursive: true, force: true }));
  for (const name of ['store', 'watch', 'runs', 'publication', 'credentials']) await mkdir(join(root, name), { mode: 0o700 });
  const fg = join(root, 'fg');
  await writeFile(fg, `#!${process.execPath}\nthrow new Error('No native execution is permitted by this recovery fixture');\n`, { mode: 0o700 });
  const config = configuration({ schema: 'frankengit-workflow-check-publisher-v1', principal_id: '5'.repeat(32), state_directory: join(root, 'publication'),
    watch: { schema: 'frankengit-workflow-watch-v1', fg, storage_root: join(root, 'store'), tenant_id: '1'.repeat(32), repository_id: '2'.repeat(32),
      repository_incarnation: '3'.repeat(32), object_format: format, ref_hex: hex('refs/heads/main'), workflow_directory_hex: hex('.github/workflows'),
      input_prefixes_hex: [hex('.github')], event: 'push', state_directory: join(root, 'watch'), run_parent: join(root, 'runs'), max_runs: 16,
      trust: 'selected-branch-host-execution' } });
  const id = sha256(Buffer.from('original-watched-commit')), binding = sha256(encode(config));
  const jobs = Array.from({ length: count }, (_, index) => {
    const job = { directory: join(config.watch.run_parent, `dispatch-${id.slice(0, 32)}`, `workflow-${String(index + 1).padStart(32, '0')}`),
      journal_id: '6'.repeat(64), minimum_pin: `1024:${'7'.repeat(64)}`, batch_sha256: sha256(Buffer.from(`batch-${index}`)), fact_index: index,
      job: `job-${index}`, source_commit: 'b'.repeat(format === 'sha1' ? 40 : 64), run_id: '8'.repeat(64), attempt_id: '9'.repeat(64),
      graph_root: 'c'.repeat(64), evidence_sha256: sha256(Buffer.from(`evidence-${index}`)), conclusion: 'action_required' };
    job.key = jobKey(binding, id, job); return job;
  });
  const plan = { schema: 'frankengit-workflow-check-plan-v1', binding_sha256: binding, watch_id: id,
    intent_sha256: sha256(Buffer.from('original-intent')), report_sha256: sha256(Buffer.from('original-report')), jobs };
  const path = (kind, index = 0) => join(config.state_directory, `${kind}-${id}-${String(index).padStart(3, '0')}.json`);
  const planPath = join(config.state_directory, `plan-${id}.json`);
  await save(join(config.state_directory, 'binding.json'), config); await save(planPath, plan);
  for (let index = 0; index < count; index++) await save(path('started', index), { schema: 'frankengit-workflow-check-start-v1', request_sha256: sha256(encode(jobs[index])) });
  const watchFile = join(root, 'watch.json'), tokenFile = join(root, 'credentials/token');
  await save(watchFile, config.watch); await writeFile(tokenFile, `${token}\n`, { mode: 0o600 });
  return { root, config, id, jobs, plan, path, planPath, watchFile, tokenFile };
}
function outcome(f, job = f.jobs[0], state = 'committed') {
  const terminal = ['committed', 'refused'].includes(state), present = terminal || state === 'undecided';
  return { type: 'transaction_outcome', schema_version: 1, ...recoveryScope(f.config), selector: 'transaction', command_index: null,
    state, terminal, transaction: present ? { tx_id: `tx-${sha256(job.key)}`, seal_id: `seal-${sha256(job.key)}`, request_schema: 'receive-admission-v1',
      canonical_request_digest: { algorithm: 2, hex: sha256(encode(job)) } } : null,
    decision: !terminal ? null : state === 'committed' ? { kind: state, decision_sequence: '18446744073709551615', repository_commit_id: `rcr-${sha256(job.key)}` }
      : { kind: state, decision_sequence: '18446744073709551615', code: 'EvidenceStale', code_point: 1, refusal_record_id: `refusal-${sha256(job.key)}` },
    read_only: true, request_reexecuted: false, absence_proves_non_commit: false, session_completeness_established: false };
}
async function peer(t, f, handler = null) {
  const calls = [], sockets = new Set();
  const server = http.createServer((req, res) => {
    let body = ''; req.on('data', bytes => body += bytes);
    req.on('end', async () => {
      const job = f.jobs.find(job => job.key === req.headers['idempotency-key']);
      const call = { method: req.method, url: req.url, headers: req.headers, body, job }; calls.push(call);
      try {
        assert.ok(job); assert.equal(req.method, 'POST'); assert.equal(req.url, '/repo.git/api/v1/outcomes'); assert.equal(body, '');
        const value = handler ? await handler(call, res) : outcome(f, job);
        if (value === undefined) return;
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(value).replaceAll('"decision_sequence":"18446744073709551615"', '"decision_sequence":18446744073709551615'));
      } catch (error) { res.destroy(error); }
    });
  });
  server.on('connection', socket => { sockets.add(socket); socket.once('close', () => sockets.delete(socket)); });
  server.listen(0, '127.0.0.1'); await eventOnce(server, 'listening');
  t.after(async () => { for (const socket of sockets) socket.destroy(); await new Promise(resolve => server.close(resolve)); });
  return { address: `http://127.0.0.1:${server.address().port}/repo.git`, calls };
}
const nativeTerminal = (f, index = 0, state = 'committed') => {
  const job = f.jobs[index], value = recoveredTerminal(recoveryRecord(outcome(f, job, state), f.config, job));
  const { observation_source, ...fields } = value;
  return { ...fields, schema: 'frankengit-workflow-check-terminal-v1', check_id: `check/${'0'.repeat(52)}` };
};
async function remoteBinding(f, address) {
  await save(join(f.config.state_directory, 'recovery-binding.json'), { schema: 'frankengit-workflow-check-recovery-binding-v1',
    publisher_binding_sha256: sha256(encode(f.config)), endpoint: address });
}
function argumentsFor(f, address, operation = 'recover', extras = []) {
  return [operation, '--watch-config', f.watchFile, '--state', f.config.state_directory, '--principal-id', f.config.principal_id,
    '--trusted-local', ...(operation === 'recover' ? ['--endpoint', address, '--token-file', f.tokenFile] : []), ...extras];
}
function child(t, args) {
  const processChild = spawn(process.execPath, [cli, ...args], { stdio: ['ignore', 'pipe', 'pipe'] });
  let stdout = '', stderr = ''; processChild.stdout.on('data', b => stdout += b); processChild.stderr.on('data', b => stderr += b);
  const done = new Promise((resolve, reject) => { processChild.once('error', reject); processChild.once('close', (code, signal) => resolve({ code, signal, stdout, stderr })); });
  t.after(async () => { if (processChild.exitCode === null && processChild.signalCode === null) processChild.kill('SIGKILL'); await done; });
  return { process: processChild, done };
}

for (const format of ['sha1', 'sha256']) for (const state of ['committed', 'refused']) {
  test(`${format}: ${state} recovers without native files, executable or source and leaves the sender lock intact`, async t => {
    const f = await fixture(t, format), server = await peer(t, f, call => outcome(f, call.job, state));
    const plan = await readFile(f.planPath), started = await readFile(f.path('started'));
    await mkdir(join(f.config.state_directory, 'owner.lock'), { mode: 0o700 });
    const owner = await lstat(join(f.config.state_directory, 'owner.lock'));
    for (const path of [f.config.watch.fg, f.config.watch.run_parent, f.config.watch.storage_root, f.config.watch.state_directory]) await rm(path, { recursive: true, force: true });
    const events = [], result = await recover(f.config, server.address, token, { onObservation: event => events.push(event) });
    assert.equal(result.runs[0][state], 1); assert.equal(result.runs[0].unknown, 0);
    assert.equal(result.lookups, 1); assert.equal(result.process_containment_asserted, false); assert.equal(events[0].check_id, null);
    assert.equal(events[0].decision.decision_sequence, '18446744073709551615');
    assert.equal((await status(f.config)).owner_present, true);
    assert.equal((await lstat(join(f.config.state_directory, 'owner.lock'))).ino, owner.ino);
    assert.deepEqual(await readFile(f.planPath), plan); assert.deepEqual(await readFile(f.path('started')), started);
    assert.equal((await json(f.path('observed'))).reply.state, state);
    assert.equal((await recover(f.config, server.address, 'b'.repeat(64))).lookups, 0); assert.equal(server.calls.length, 1);
  });
}

test('a fresh resume skips a recovered request rather than invoking the native publisher', async t => {
  const f = await fixture(t), server = await peer(t, f);
  await recover(f.config, server.address, token);
  const result = await once(f.config, { resume: true });
  assert.equal(result.publications, 0); assert.equal(result.runs[0].committed, 1);
});
for (const state of ['key_not_observed', 'seal_not_observed', 'undecided']) {
  test(`${state} retains unknown publication and never permits an automatic resend`, async t => {
    const f = await fixture(t), server = await peer(t, f, call => outcome(f, call.job, state));
    assert.equal((await recover(f.config, server.address, token)).runs[0].unknown, 1);
    await assert.rejects(once(f.config), /unresolved/);
    assert.equal(server.calls.length, 1); assert.ok((await readdir(f.config.state_directory)).includes(f.path('started').split('/').at(-1)));
  });
}
test('first transaction and terminal evidence survive restart as distinct create-only records', async t => {
  const f = await fixture(t); let state = 'undecided'; const server = await peer(t, f, call => outcome(f, call.job, state));
  await recover(f.config, server.address, token); const first = await readFile(f.path('observed'));
  state = 'committed'; await recover(f.config, server.address, 'b'.repeat(64));
  assert.deepEqual(await readFile(f.path('observed')), first); assert.equal((await json(f.path('recovered'))).reply.state, state);
  assert.equal((await status(f.config)).runs[0].committed, 1);
  assert.equal(server.calls[1].headers.authorization, `Bearer ${'b'.repeat(64)}`);
  assert.equal(server.calls[0].headers['idempotency-key'], server.calls[1].headers['idempotency-key']);
});
for (const change of ['absent', 'transaction', 'seal', 'digest']) {
  test(`a later ${change} conflict cannot erase first-transaction evidence`, async t => {
    const f = await fixture(t); let changed = false;
    const server = await peer(t, f, call => {
      const value = outcome(f, call.job, !changed ? 'undecided' : change === 'absent' ? 'key_not_observed' : 'committed');
      if (changed && change !== 'absent') {
        if (change === 'transaction') value.transaction.tx_id = 'foreign-tx';
        if (change === 'seal') value.transaction.seal_id = 'foreign-seal';
        if (change === 'digest') value.transaction.canonical_request_digest.hex = 'd'.repeat(64);
      }
      return value;
    });
    await recover(f.config, server.address, token); const before = await readFile(f.path('observed')); changed = true;
    await assert.rejects(recover(f.config, server.address, token), /regressed|conflicted/);
    assert.deepEqual(await readFile(f.path('observed')), before); assert.equal((await status(f.config)).runs[0].unknown, 1);
  });
}
for (const name of ['tenant_id', 'repository_id', 'repository_incarnation', 'principal_id']) {
  test(`mismatched ${name} refuses and a valid later lookup still works`, async t => {
    const f = await fixture(t); let mismatch = true;
    const server = await peer(t, f, call => ({ ...outcome(f, call.job), ...(mismatch ? { [name]: 'f'.repeat(32) } : {}) }));
    await assert.rejects(recover(f.config, server.address, token), /scope_or_semantics/); assert.equal((await status(f.config)).runs[0].unknown, 1);
    mismatch = false; assert.equal((await recover(f.config, server.address, token)).runs[0].committed, 1);
  });
}
test('bounded multi-job recovery preserves all original keys across independent invocations', async t => {
  const f = await fixture(t, 'sha256', 3), server = await peer(t, f);
  const first = await recover(f.config, server.address, token, { maxLookups: 1 });
  assert.equal(first.lookups, 1); assert.equal(first.limit_reached, true); assert.equal(first.runs[0].unknown, 2);
  const second = await recover(f.config, server.address, token); assert.equal(second.lookups, 2); assert.equal(second.runs[0].committed, 3);
  assert.deepEqual(server.calls.map(call => call.headers['idempotency-key']), f.jobs.map(job => job.key));
});
test('a prepared but never-started job is not looked up or accidentally submitted', async t => {
  const f = await fixture(t, 'sha1', 2), server = await peer(t, f); await rm(f.path('started', 1));
  const result = await recover(f.config, server.address, token);
  assert.equal(result.lookups, 1); assert.equal(result.runs[0].pending, 1); assert.equal(result.runs[0].unknown, 0);
  assert.equal(server.calls[0].headers['idempotency-key'], f.jobs[0].key);
});
test('changing the retained endpoint refuses before sending credentials or keys', async t => {
  const f = await fixture(t), first = await peer(t, f, call => outcome(f, call.job, 'key_not_observed')), second = await peer(t, f);
  await recover(f.config, first.address, token);
  await assert.rejects(recover(f.config, second.address, token), /endpoint changed/); assert.equal(second.calls.length, 0);
});
test('tampered plans and orphaned receipts refuse before any network request', async t => {
  const f = await fixture(t), server = await peer(t, f); const saved = await readFile(f.planPath);
  const changed = structuredClone(f.plan); changed.jobs[0].source_commit = 'f'.repeat(40); await save(f.planPath, changed);
  await assert.rejects(recover(f.config, server.address, token), /request changed/); assert.equal(server.calls.length, 0);
  await writeFile(f.planPath, saved);
  await remoteBinding(f, server.address); await save(f.path('observed'), recoveryRecord(outcome(f), f.config, f.jobs[0])); await rm(f.path('started'));
  await assert.rejects(recover(f.config, server.address, token), /start responsibility/); assert.equal(server.calls.length, 0);
});
test('retained native and recovered decisions must agree; no synthetic check-specific receipt is written', async t => {
  const f = await fixture(t), server = await peer(t, f);
  await remoteBinding(f, server.address); await save(f.path('observed'), recoveryRecord(outcome(f), f.config, f.jobs[0]));
  const terminal = nativeTerminal(f); await save(f.path('terminal'), terminal);
  assert.equal((await status(f.config)).runs[0].committed, 1);
  terminal.repository_commit_id = 'conflicting-record'; await save(f.path('terminal'), terminal);
  await assert.rejects(status(f.config), /contradicts/); assert.equal(server.calls.length, 0);
});
test('a native terminal written during an outcome read is reconciled before persistence', async t => {
  const f = await fixture(t), server = await peer(t, f, async call => { await save(f.path('terminal'), nativeTerminal(f)); return outcome(f, call.job); });
  assert.equal((await recover(f.config, server.address, token)).runs[0].committed, 1);
  assert.equal((await json(f.path('terminal'))).check_id, `check/${'0'.repeat(52)}`);
  assert.equal(Object.hasOwn((await json(f.path('observed'))).reply, 'check_id'), false);
});
test('a conflicting concurrent native terminal is preserved and reported, not overwritten', async t => {
  const f = await fixture(t), local = { ...nativeTerminal(f), tx_id: 'a-different-native-tx' };
  const server = await peer(t, f, async call => { await save(f.path('terminal'), local); return outcome(f, call.job); });
  await assert.rejects(recover(f.config, server.address, token), /contradicts/);
  assert.deepEqual(await json(f.path('terminal')), local);
  await assert.rejects(readFile(f.path('observed')), error => error.code === 'ENOENT');
});
test('failed output observer retains the completed job and next invocation reads only the remainder', async t => {
  const f = await fixture(t, 'sha1', 2), server = await peer(t, f);
  await assert.rejects(recover(f.config, server.address, token, { onObservation() { throw new Error('output lost'); } }), error => error.retained_terminal?.outcome === 'committed');
  assert.equal((await status(f.config)).runs[0].committed, 1);
  assert.equal((await recover(f.config, server.address, token)).lookups, 1); assert.equal(server.calls.length, 2);
});
test('receipt persistence failure still exposes the known terminal and never submits another key', async t => {
  const f = await fixture(t, 'sha1', 2), server = await peer(t, f, async call => { await mkdir(f.path('observed'), { mode: 0o700 }); return outcome(f, call.job); });
  await assert.rejects(recover(f.config, server.address, token), error => error.retained_terminal?.outcome === 'committed');
  assert.equal(server.calls.length, 1); assert.ok(await readFile(f.path('started')));
});
test('simultaneous recovery owners are excluded without touching the native sender lock', async t => {
  const f = await fixture(t); let release, arrived;
  const seen = new Promise(resolve => arrived = resolve), held = new Promise(resolve => release = resolve);
  const server = await peer(t, f, async call => { arrived(); await held; return outcome(f, call.job); });
  await mkdir(join(f.config.state_directory, 'owner.lock'), { mode: 0o700 });
  const first = recover(f.config, server.address, token); await seen;
  await assert.rejects(recover(f.config, server.address, token), error => error.code === 'EEXIST');
  release(); await first; assert.equal(server.calls.length, 1); assert.equal((await status(f.config)).owner_present, true);
});
test('whole-operation deadline applies across lookups, not once per job', async t => {
  const f = await fixture(t, 'sha1', 2), server = await peer(t, f, async call => { await new Promise(resolve => setTimeout(resolve, 100)); return outcome(f, call.job); });
  await assert.rejects(recover(f.config, server.address, token, { timeoutMs: 30 }), /timeout/); assert.equal(server.calls.length, 1);
  assert.equal((await status(f.config)).runs[0].unknown, 2);
});
test('cancellation after a validated terminal saves it and stops before the next job', async t => {
  const f = await fixture(t, 'sha1', 2), server = await peer(t, f), controller = new AbortController();
  const result = await recover(f.config, server.address, token, { signal: controller.signal, onObservation() { controller.abort(); } });
  assert.equal(result.stopped, true); assert.equal(result.runs[0].committed, 1); assert.equal(result.runs[0].unknown, 1);
  assert.equal(server.calls.length, 1);
});
test('CLI recovery uses a private token file and exits with the native terminal state', async t => {
  const f = await fixture(t), server = await peer(t, f); await rm(f.config.watch.fg);
  const result = await child(t, argumentsFor(f, server.address)).done;
  assert.equal(result.code, 0, result.stderr); assert.equal(result.signal, null);
  const lines = result.stdout.trim().split('\n').map(JSON.parse); assert.equal(lines.at(-1).runs[0].committed, 1);
  assert.equal(result.stdout.includes(token), false); assert.equal(result.stderr.includes(token), false); assert.equal(result.stdout.includes(f.jobs[0].key), false);
});
test('CLI rejects publication flags, missing scopes, unsafe token files and malformed credentials before HTTP', async t => {
  const f = await fixture(t), server = await peer(t, f);
  for (const args of [argumentsFor(f, server.address, 'recover', ['--max-publications', '1']),
    argumentsFor(f, server.address, 'recover', ['--key', 'new-key']), argumentsFor(f, server.address, 'resume', ['--endpoint', server.address])]) {
    assert.equal((await child(t, args).done).code, 2);
  }
  await chmod(f.tokenFile, 0o644); assert.equal((await child(t, argumentsFor(f, server.address)).done).code, 2);
  await chmod(f.tokenFile, 0o600); await writeFile(f.tokenFile, `${token} `); assert.equal((await child(t, argumentsFor(f, server.address)).done).code, 2);
  assert.equal(server.calls.length, 0);
});
test('SIGTERM cancels an active recovery socket and retains unknown work for a later original-key read', async t => {
  const f = await fixture(t); let arrived, silent = true; const seen = new Promise(resolve => arrived = resolve);
  const server = await peer(t, f, call => { arrived(); return silent ? undefined : outcome(f, call.job); });
  const first = child(t, argumentsFor(f, server.address)); await seen; first.process.kill('SIGTERM');
  const stopped = await first.done; assert.equal(stopped.code, 3, stopped.stderr); assert.equal((await status(f.config)).runs[0].unknown, 1);
  silent = false; assert.equal((await child(t, argumentsFor(f, server.address)).done).code, 0); assert.equal(server.calls.length, 2);
});
test('SIGKILL retains only the recovery owner lock; offline status works and no lock is stolen', async t => {
  const f = await fixture(t); let arrived; const seen = new Promise(resolve => arrived = resolve);
  const server = await peer(t, f, () => { arrived(); }); const first = child(t, argumentsFor(f, server.address));
  await seen; first.process.kill('SIGKILL'); assert.equal((await first.done).signal, 'SIGKILL');
  assert.ok((await lstat(join(f.config.state_directory, 'recovery.lock'))).isDirectory());
  assert.equal((await status(f.config)).runs[0].unknown, 1);
  assert.equal((await status(f.config)).recovery_owner_present, true);
  assert.notEqual((await child(t, argumentsFor(f, server.address)).done).code, 0); assert.equal(server.calls.length, 1);
});
test('CLI broken output after recovery does not turn a known commit into rollback', async t => {
  const f = await fixture(t), server = await peer(t, f); let errors = '';
  const stdout = new Writable({ write(_chunk, _encoding, done) { done(new Error('broken stdout')); } });
  const stderr = new Writable({ write(chunk, _encoding, done) { errors += chunk; done(); } });
  const exit = await main(argumentsFor(f, server.address), { stdout, stderr });
  assert.equal(exit, 4); assert.equal((await status(f.config)).runs[0].committed, 1); assert.match(errors, /retained_terminal/);
});

for (const format of ['sha1', 'sha256']) test(`${format}: actual watcher/publisher custody with a lost reply recovers without its native files`, async t => {
  const f = await fixture(t, format), watch = f.config.watch;
  // Start from empty publication custody, not the seeded plan used by unit cases.
  for (const name of await readdir(f.config.state_directory)) await rm(join(f.config.state_directory, name));
  const publisherPeer = new URL('./fixtures/workflow_check_native.mjs', import.meta.url).href;
  const watcherPeer = new URL('./fixtures/workflow_watch_native.mjs', import.meta.url).href;
  await writeFile(watch.fg, `#!${process.execPath}\nimport { handle } from ${JSON.stringify(publisherPeer)};\nif (!await handle(process.argv.slice(2))) await import(${JSON.stringify(watcherPeer)});\n`, { mode: 0o700 });
  const control = { tenant: watch.tenant_id, repository: watch.repository_id, incarnation: watch.repository_incarnation, format,
    ref_hex: watch.ref_hex, commit: 'a'.repeat(format === 'sha1' ? 40 : 64), source_head: 'fixture-head', snapshot: `alg:2:${'4'.repeat(64)}`, drop_publication: true };
  await save(join(watch.storage_root, 'control.json'), control);
  const runResult = await execute(watch), report = await json(join(runResult.native_directory, 'report.json'));
  const run = report.runs[0], directory = Buffer.from(run.run_directory_hex, 'hex').toString();
  const identity = Object.fromEntries(Object.entries(run).filter(([key]) => !['type', 'succeeded', 'workspaces_closed', 'request_interrupted', 'execution'].includes(key)));
  const marker = encode({ type: 'trusted_workflow_attempt', ...identity, state: 'started', execution_plan: { ...run.execution, succeeded: false, jobs: [] } });
  await writeFile(join(directory, 'attempt.json'), marker, { mode: 0o600 });
  const job = run.execution.jobs[0];
  const entry = { batch_sha256: sha256(encode([run.run_id, 0])), body_bytes: 256, ordinal: 0, delivery: 'pending', delivery_receipt_sha256: null,
    run_sha256: sha256(Buffer.from(run.run_id)), attempt_sha256: '6'.repeat(64), authority_basis_sha256: control.snapshot.slice(6),
    object_format: format, source_commit: run.executed_commit, workflow_graph_sha256: 'c'.repeat(64), trust_domain: 'trusted-local-owner',
    profile: { name: 'trusted-local-foreground-v1', source_sha256: 'b'.repeat(64), step_timeout_nanos: run.execution.step_timeout_millis * 1000000,
      run_timeout_nanos: run.execution.run_timeout_millis * 1000000, stream_bytes: run.execution.stream_bytes, total_output_bytes: run.execution.total_output_bytes },
    facts: [{ job: job.id, status: 'completed', conclusion: 'action_required', evidence_sha256: sha256(encode(job)), logical_millis: 0 }] };
  await save(join(directory, 'custody.json'), { store: watch.storage_root, incarnation: watch.repository_incarnation, ref_hex: watch.ref_hex,
    conclusions: { [job.id]: 'action_required' }, history: { type: 'workflow_custody_history', schema_version: 1,
      authoritative_check: false, execution_retried: false, execution_completion: 'not_asserted', evidence_payloads_included: false,
      scope: { tenant: watch.tenant_id, repository: watch.repository_id, journal_id: sha256(marker) }, snapshot: `1024:${'7'.repeat(64)}`,
      retained_batches: 1, pending_batches: 1, next_after: null, entries: [entry] } });
  await assert.rejects(once(f.config), error => error.publication_unknown);
  const planName = (await readdir(f.config.state_directory)).find(name => name.startsWith('plan-'));
  const planBytes = await readFile(join(f.config.state_directory, planName)), plan = JSON.parse(planBytes);
  f.jobs = plan.jobs;
  const original = await json(join(watch.storage_root, `decision-${sha256(f.jobs[0].key)}.json`));
  const calls = (await readFile(join(watch.storage_root, 'calls.ndjson'), 'utf8')).trim().split('\n').map(JSON.parse);
  assert.deepEqual(calls.map(args => args[0] === 'refs' ? 'refs' : args[1]), ['refs', 'dispatch', 'recover', 'publish']);
  const server = await peer(t, f, call => {
    const value = outcome(f, call.job, original.outcome);
    value.transaction.tx_id = original.tx_id; value.decision.repository_commit_id = original.repository_commit_id;
    return value;
  });
  for (const path of [watch.fg, watch.storage_root, watch.run_parent, watch.state_directory]) await rm(path, { recursive: true, force: true });
  await mkdir(join(f.config.state_directory, 'owner.lock'), { mode: 0o700 });
  const result = await child(t, argumentsFor(f, server.address)).done;
  assert.equal(result.code, 0, result.stderr);
  assert.equal((await status(f.config)).runs[0].committed, 1); assert.equal((await status(f.config)).owner_present, true);
  assert.deepEqual(await readFile(join(f.config.state_directory, planName)), planBytes);
  assert.equal(server.calls.length, 1); assert.equal(server.calls[0].headers['idempotency-key'], f.jobs[0].key);
  assert.equal((await child(t, argumentsFor(f, server.address)).done).code, 0);
  assert.equal(server.calls.length, 1, 'durably recovered transaction is never read or published again by ordinary recovery');
});

test('CLI reports known terminal plus recovery-lock cleanup failure separately from rollback', async t => {
  const f = await fixture(t), server = await peer(t, f); let errors = '';
  const stdout = new Writable({ write(chunk, _encoding, done) {
    if (String(chunk).includes('workflow_check_outcome_observed')) {
      writeFile(join(f.config.state_directory, 'recovery.lock/held'), 'fixture cleanup blocker').then(() => done(), done);
    } else done();
  } });
  const stderr = new Writable({ write(chunk, _encoding, done) { errors += chunk; done(); } });
  const exit = await main(argumentsFor(f, server.address), { stdout, stderr });
  assert.equal(exit, 4, errors);
  const diagnostic = JSON.parse(errors); assert.equal(diagnostic.retained_recovery.runs[0].committed, 1);
  const local = await status(f.config); assert.equal(local.runs[0].committed, 1); assert.equal(local.recovery_owner_present, true);
  assert.equal(server.calls.length, 1);
});
