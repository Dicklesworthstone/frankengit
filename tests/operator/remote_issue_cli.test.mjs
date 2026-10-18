// Real operator processes/private files plus an explicit native HTTP contract
// peer. Does not claim native Rust execution or filesystem power-loss safety.
import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn, execFileSync } from 'node:child_process';
import { writeFileSync } from 'node:fs';
import { createServer } from 'node:http';
import { mkdtemp, readFile, writeFile, chmod, mkdir, stat, readdir, symlink, link, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { resolve, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { prepareIssue, issueCanonical, parseIssueJson } from '../../scripts/operator/remote_issue.mjs';
import { saveIssueIntent, loadIssueIntent, readIssuePrivate, saveIssueRecord } from '../../scripts/operator/issue_files.mjs';
import { runIssueCli } from '../../scripts/remote_issue.mjs';
const cli = fileURLToPath(new URL('../../scripts/remote_issue.mjs', import.meta.url));
const token = 'ab'.repeat(32), rotated = 'cd'.repeat(32);
const scope = { tenant_id: '11'.repeat(16), repository_id: '22'.repeat(16),
  repository_incarnation: '33'.repeat(16), principal_id: '44'.repeat(16) };
const transaction = { tx_id: 'tx:fixture', seal_id: 'seal:fixture', request_schema: 'issue-fixture-v1',
  canonical_request_digest: { algorithm: 1, hex: 'ef'.repeat(32) } };
const wire = value => JSON.stringify(value, (key, value) =>
  ['number', 'expected_version', 'decision_sequence'].includes(key) && typeof value === 'string' ? JSON.rawJSON(value) : value);
function spawnCli(args) {
  const child = spawn(process.execPath, [cli, ...args], { stdio: ['ignore', 'pipe', 'pipe'], timeout: 5000, killSignal: 'SIGKILL' });
  let stdout = '', stderr = '';
  child.stdout.on('data', bytes => { stdout += bytes; }); child.stderr.on('data', bytes => { stderr += bytes; });
  const done = new Promise((resolve, reject) => {
    child.on('error', reject); child.once('close', (code, signal) => resolve({ code, signal, stdout, stderr,
      value: stdout.trim().startsWith('{') ? JSON.parse(stdout) : null }));
  });
  return { child, done };
}
const invoke = args => spawnCli(args).done;
async function fixture(t, options = {}) {
  const directory = await mkdtemp(join(tmpdir(), 'fg-remote-issue-')), slot = join(directory, 'request');
  await chmod(directory, 0o700);
  t.after(() => rm(directory, { recursive: true, force: true }));
  const tokenFile = join(directory, 'token'), rotatedFile = join(directory, 'rotated');
  await writeFile(tokenFile, token + '\n', { mode: 0o600 }); await writeFile(rotatedFile, rotated, { mode: 0o600 });
  const calls = [], sockets = new Set(); let state = null;
  const outcome = () => ({ type: 'transaction_outcome', schema_version: 1, ...scope, selector: 'transaction', command_index: null,
    state: state ?? 'key_not_observed', terminal: ['committed', 'refused'].includes(state), transaction: state ? transaction : null,
    decision: state === 'committed' ? { kind: state, decision_sequence: '18446744073709551615', repository_commit_id: 'rcr:fixture' }
      : state === 'refused' ? { kind: state, decision_sequence: '18446744073709551615', code: 'ExpectedVersionMismatch', code_point: 7, refusal_record_id: 'refusal:fixture' } : null,
    read_only: true, request_reexecuted: false, absence_proves_non_commit: false, session_completeness_established: false });
  const server = createServer((request, response) => {
    let body = ''; request.setEncoding('utf8'); request.on('data', value => { body += value; }); request.on('end', () => {
      const call = { path: request.url, headers: request.headers, body }; calls.push(call);
      const recovering = request.url.endsWith('/outcomes');
      if (![token, rotated].some(value => request.headers.authorization === `Bearer ${value}`)) { response.writeHead(401); response.end('denied'); return; }
      let reply;
      if (recovering) reply = outcome();
      else {
        state = options.refuse ? 'refused' : 'committed'; const pieces = request.url.split('/'), form = new URLSearchParams(body);
        reply = { type: 'issue_publication', schema_version: 1, tenant_id: scope.tenant_id, repository_id: scope.repository_id,
          principal_id: scope.principal_id, number: pieces.at(-2), expected_version: form.get('expected_version'), action: pieces.at(-1),
          tx_id: transaction.tx_id, outcome: state, decision_sequence: '18446744073709551615',
          repository_commit_id: state === 'committed' ? 'rcr:fixture' : null,
          refusal_record_id: state === 'refused' ? 'refusal:fixture' : null,
          refusal_code: state === 'refused' ? 'ExpectedVersionMismatch' : null, delivery_acknowledged: null };
      }
      if (options.handle?.({ recovering, request, response, call, reply })) return;
      const bytes = wire(reply); response.writeHead(!recovering && options.refuse ? 409 : 200,
        { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(bytes) }); response.end(bytes);
    });
  });
  server.on('connection', socket => { sockets.add(socket); socket.on('close', () => sockets.delete(socket)); });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(async () => { for (const socket of sockets) socket.destroy(); await new Promise(resolve => server.close(resolve)); });
  const input = { endpoint: `http://127.0.0.1:${server.address().port}/repo.git`, scope, number: '7', expected_version: '2',
    action: 'comment', fields: { body: ' exact\r\n💡 <script>inert</script> \u202e ' } };
  const inputFile = join(directory, 'input.json'); await writeFile(inputFile, issueCanonical(input), { mode: 0o600 });
  const prepare = () => invoke(['prepare', '--input', inputFile, '--token-file', tokenFile, '--request-dir', slot]);
  const sendArgs = key => ['send', '--request-dir', slot, '--token-file', tokenFile, '--confirm-key', key];
  const recoverArgs = ['recover', '--request-dir', slot, '--token-file', rotatedFile];
  return { directory, slot, tokenFile, rotatedFile, input, inputFile, calls, prepare, sendArgs, recoverArgs,
    setState: value => { state = value; } };
}

test('prepare/inspect persist the exact token-free request without contacting any API', async t => {
  const f = await fixture(t), prepared = await f.prepare(); assert.equal(prepared.code, 0);
  assert.equal(prepared.value.network_contacted, false); assert.equal(f.calls.length, 0);
  const bytes = await readFile(join(f.slot, 'intent.json')), intent = await loadIssueIntent(f.slot);
  assert.equal(intent.key, prepared.value.key); assert(bytes.equals(Buffer.from(issueCanonical(intent))));
  assert(!bytes.includes(Buffer.from(token))); assert.equal(intent.fields.body, f.input.fields.body);
  assert.equal((await stat(f.slot)).mode & 0o777, 0o700); assert.equal((await stat(join(f.slot, 'intent.json'))).mode & 0o777, 0o600);
  const inspected = await invoke(['inspect', '--request-dir', f.slot]); assert.equal(inspected.code, 0);
  assert.deepEqual(inspected.value.intent, intent); assert(!inspected.stdout.includes('\u202e')); assert.equal(f.calls.length, 0);
});
test('send confirms one publication and saves an atomic record; retained terminal suppresses resend', async t => {
  const f = await fixture(t), prepared = await f.prepare(), record = join(f.directory, 'outcome.json');
  const result = await invoke([...f.sendArgs(prepared.value.key), '--record', record]); assert.equal(result.code, 0);
  assert.equal(result.value.outcome.decision.decision_sequence, '18446744073709551615');
  assert.deepEqual(JSON.parse(await readFile(record, 'utf8')), result.value); assert.equal((await stat(record)).nlink, 1);
  assert.equal((await stat(record)).mode & 0o777, 0o600);
  const again = await invoke([...f.sendArgs(prepared.value.key), '--known', record]); assert.equal(again.code, 0);
  assert.equal(again.value.dispatched_this_call, false); assert.equal(f.calls.filter(call => !call.path.endsWith('/outcomes')).length, 1);
  assert.deepEqual(await readdir(f.slot), ['intent.json']);
});
test('native refusal exit is distinct from local rejection and unknown transport', async t => {
  const f = await fixture(t, { refuse: true }), p = await f.prepare(), result = await invoke(f.sendArgs(p.value.key));
  assert.equal(result.code, 1); assert.equal(result.value.outcome.state, 'refused');
});
test('empty outcome is incomplete, not no-op success or non-commit certificate', async t => {
  const f = await fixture(t); await f.prepare(); const result = await invoke(f.recoverArgs);
  assert.equal(result.code, 3); assert.equal(result.value.outcome.terminal, false);
  assert.equal(result.value.absence_proves_non_commit, false); assert.equal(f.calls.length, 1); assert.equal(f.calls[0].body, '');
});
test('mismatched confirmation and rotated mutation credentials fail before any API', async t => {
  const f = await fixture(t), p = await f.prepare();
  const wrong = await invoke(f.sendArgs('another')); assert.equal(wrong.code, 2);
  const args = f.sendArgs(p.value.key); args[args.indexOf('--token-file') + 1] = f.rotatedFile;
  assert.equal((await invoke(args)).code, 2); assert.equal(f.calls.length, 0);
});
test('lost reply across processes recovers without changing the request or repeating its effect', async t => {
  const f = await fixture(t, { handle: ({ recovering, response }) => { if (recovering) return false; response.destroy(); return true; } });
  const p = await f.prepare(), before = await readFile(join(f.slot, 'intent.json'));
  const failed = await invoke(f.sendArgs(p.value.key)); assert.equal(failed.code, 3); assert.equal(failed.value.outcome_unknown, true);
  const recovered = await invoke(f.recoverArgs); assert.equal(recovered.code, 0); assert.equal(recovered.value.outcome.state, 'committed');
  assert.equal(recovered.value.dispatched_this_call, false); assert((await readFile(join(f.slot, 'intent.json'))).equals(before));
  assert.equal(f.calls.filter(call => !call.path.endsWith('/outcomes')).length, 1);
});
for (const signal of ['SIGKILL', 'SIGTERM']) test(`${signal} after dispatch retains exact recovery identity across restart`, async t => {
  let child;
  const f = await fixture(t, { handle: ({ recovering }) => { if (recovering) return false; child.kill(signal); return true; } });
  const p = await f.prepare(), run = spawnCli(f.sendArgs(p.value.key)); child = run.child;
  const stopped = await run.done;
  if (signal === 'SIGKILL') assert.equal(stopped.signal, signal); else assert.equal(stopped.code, 3);
  const recovered = await invoke(f.recoverArgs); assert.equal(recovered.code, 0); assert.equal(recovered.value.key, p.value.key);
  assert.equal(f.calls.filter(call => !call.path.endsWith('/outcomes')).length, 1);
});
test('closed stdout cannot erase a saved result or turn retry into another mutation', async t => {
  const f = await fixture(t), p = await f.prepare(), record = join(f.directory, 'saved.json');
  const run = spawnCli([...f.sendArgs(p.value.key), '--record', record]); run.child.stdout.destroy();
  const lost = await run.done; assert.equal(lost.code, 3);
  assert.equal(JSON.parse(await readFile(record, 'utf8')).outcome.state, 'committed');
  const recovered = await invoke(f.recoverArgs); assert.equal(recovered.code, 0);
  assert.equal(f.calls.filter(call => !call.path.endsWith('/outcomes')).length, 1);
});
test('existing output is refused before networking and never overwritten', async t => {
  const f = await fixture(t), p = await f.prepare(), record = join(f.directory, 'saved.json');
  await writeFile(record, 'keep', { mode: 0o600 });
  const result = await invoke([...f.sendArgs(p.value.key), '--record', record]); assert.equal(result.code, 2);
  assert.equal(f.calls.length, 0); assert.equal(await readFile(record, 'utf8'), 'keep');
});
test('saved outcome from another command cannot supply a recovery pin', async t => {
  const f = await fixture(t), p = await f.prepare(), result = await invoke(f.sendArgs(p.value.key));
  const record = join(f.directory, 'wrong.json'); result.value.key += 'other'; await writeFile(record, issueCanonical(result.value), { mode: 0o600 });
  const count = f.calls.length, failed = await invoke([...f.recoverArgs, '--known', record]);
  assert.equal(failed.code, 2); assert.equal(f.calls.length, count);
});
test('retained terminal regression refuses instead of dispatching again', async t => {
  const f = await fixture(t), p = await f.prepare(), record = join(f.directory, 'saved.json');
  assert.equal((await invoke([...f.sendArgs(p.value.key), '--record', record])).code, 0);
  f.setState(null); const result = await invoke([...f.sendArgs(p.value.key), '--known', record]); assert.equal(result.code, 3);
  assert.equal(f.calls.filter(call => !call.path.endsWith('/outcomes')).length, 1);
});
test('prepare never replaces a saved slot or resets its key', async t => {
  const f = await fixture(t), p = await f.prepare(), bytes = await readFile(join(f.slot, 'intent.json'));
  assert.equal((await f.prepare()).code, 2); assert((await readFile(join(f.slot, 'intent.json'))).equals(bytes));
  assert.equal((await loadIssueIntent(f.slot)).key, p.value.key); assert.equal(f.calls.length, 0);
});
for (const kind of ['empty', 'truncated', 'tampered']) test(`interrupted ${kind} slot is not reconstructed or discarded`, async t => {
  const f = await fixture(t);
  if (kind === 'empty') await mkdir(f.slot, { mode: 0o700 });
  else {
    await f.prepare(); const path = join(f.slot, 'intent.json');
    if (kind === 'truncated') await writeFile(path, '{');
    else { const value = JSON.parse(await readFile(path, 'utf8')); value.fields.body = 'changed'; await writeFile(path, issueCanonical(value)); }
  }
  assert.equal((await invoke(f.recoverArgs)).code, 2); assert.equal(f.calls.length, 0); assert((await stat(f.slot)).isDirectory());
});
for (const kind of ['public-file', 'public-directory', 'symlink', 'hardlink', 'fifo']) test(`private inputs refuse ${kind}`, async t => {
  const f = await fixture(t), target = join(f.directory, 'unsafe');
  if (kind === 'public-file') { await writeFile(target, 'x', { mode: 0o644 }); }
  else if (kind === 'public-directory') { await chmod(f.directory, 0o755); await writeFile(target, 'x', { mode: 0o600 }); }
  else if (kind === 'symlink') await symlink(f.tokenFile, target);
  else if (kind === 'hardlink') await link(f.tokenFile, target);
  else execFileSync('mkfifo', ['-m', '600', target]);
  await assert.rejects(readIssuePrivate(target));
});
test('directory aliases and worktree request placement refuse', async t => {
  const f = await fixture(t), alias = `${f.directory}-alias`;
  await symlink(f.directory, alias); t.after(() => rm(alias));
  await assert.rejects(readIssuePrivate(join(alias, 'token')));
  await writeFile(join(f.directory, '.git'), 'gitdir: elsewhere', { mode: 0o600 });
  await assert.rejects(saveIssueIntent(f.slot, prepareIssue(f.input, token)), /worktree/);
  await assert.rejects(saveIssueRecord(join(f.directory, 'record.json'), {}), /worktree/);
});
test('record publication preserves complete content and refuses every overwrite', async t => {
  const f = await fixture(t), target = join(f.directory, 'record.json'), value = { exact: 'x'.repeat(64000) };
  await saveIssueRecord(target, value); assert.deepEqual(parseIssueJson(await readIssuePrivate(target)), value);
  await assert.rejects(saveIssueRecord(target, {})); assert.deepEqual(parseIssueJson(await readIssuePrivate(target)), value);
  assert.equal((await readdir(f.directory)).filter(name => name.endsWith('.staged')).length, 0);
});
test('oversized private file is refused without reading an unbounded body', async t => {
  const f = await fixture(t); await writeFile(join(f.directory, 'big'), 'x'.repeat(100));
  await chmod(join(f.directory, 'big'), 0o600); await assert.rejects(readIssuePrivate(join(f.directory, 'big'), 64), /limit/);
});
for (const args of [[], ['send'], ['recover', '--confirm-key', 'x'], ['prepare', '--token', token],
  ['inspect', '--request-dir', '/tmp/a', '--request-dir', '/tmp/b'], ['send', '--timeout-ms', '0'],
  ['inspect', '--request-dir', '/tmp/x', '--unknown', 'x']]) test('CLI rejects incomplete or widened invocation', async () => {
  const result = await invoke(args); assert.equal(result.code, 2); assert(!result.stdout.includes(token));
});
test('help and pre-cancelled direct entry have explicit outcomes', async () => {
  const help = await invoke(['--help']); assert.equal(help.code, 0); assert.match(help.stdout, /prepare/);
  const controller = new AbortController(); controller.abort();
  const result = await runIssueCli(['--help'], { signal: controller.signal }); assert.equal(result.exitCode, 3);
});


test('record-publication race preserves both the competing file and the already confirmed terminal', async t => {
  let record;
  const f = await fixture(t, { handle: ({ recovering }) => {
    if (!recovering) writeFileSync(record, 'competing record', { mode: 0o600 });
    return false;
  } });
  record = join(f.directory, 'raced.json'); const p = await f.prepare();
  const result = await invoke([...f.sendArgs(p.value.key), '--record', record]);
  assert.equal(result.code, 3); assert.equal(result.value.native_result.outcome.state, 'committed');
  assert.equal(result.value.dispatched_this_call, true); assert.equal(result.value.outcome_unknown, false);
  assert.equal(await readFile(record, 'utf8'), 'competing record');
  assert.equal((await invoke(f.recoverArgs)).code, 0);
});
