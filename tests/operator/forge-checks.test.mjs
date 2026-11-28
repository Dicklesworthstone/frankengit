// Real sockets, private files and CLI processes; the peer simulates native API
// responses. These tests do not execute native admission or a Rust workflow.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { mkdtemp, writeFile, readFile, readdir, rm, lstat, chmod, symlink } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { checkArguments, runCheckCommand } from '../../scripts/forge_checks.mjs';
import { checkReadOptions, runCheckRead } from '../../scripts/lib/forge-check-reader.mjs';
import { Transport } from '../../crates/fgit-node/src/smart_http/server/browser/pulls-core.mjs';
import { CheckEvidenceClient } from '../../crates/fgit-node/src/smart_http/server/browser/pulls-check-evidence.mjs';
import { runNativeProcess } from '../../scripts/lib/native-process-owner.mjs';
import { listenForFetch } from './fetch_listener_helper.mjs';
import { token, ids, row, data, page, show, hex, webcrypto } from '../browser/pulls-fixtures.mjs';
import { checks, checkLabel, observation, checksHead, unavailable } from '../browser/pulls-checks-fixtures.mjs';
import { evidenceFixture, evidenceToken, report, step, toleratedReport } from '../browser/pulls-checks-evidence-fixtures.mjs';

const cli = fileURLToPath(new URL('../../scripts/forge_checks.mjs', import.meta.url));
const agentToken = 'fgagent_' + 'e'.repeat(64), agentEvidence = 'fgagent_' + 'f'.repeat(64);
const child = args => runNativeProcess(process.execPath, [cli, ...args], { timeoutMs: 10000, stdoutLimit: 8 * 1024 * 1024 });
async function peer(t, algorithm = 'sha1') {
  const root = await mkdtemp(join(tmpdir(), 'fg-check-read-'));
  const tokenFile = join(root, 'token'), evidenceTokenFile = join(root, 'evidence-token');
  await writeFile(tokenFile, token, { mode: 0o600 }); await writeFile(evidenceTokenFile, evidenceToken, { mode: 0o600 });
  const f = { root, tokenFile, evidenceTokenFile, algorithm, calls: [], rows: [], records: [], evidence: new Map(),
    sourceCurrent: true, transform() {}, fault: null,
    grants: new Map([[token, ['metadata', 'feedback']], [evidenceToken, ['evidence']],
      [agentToken, ['metadata', 'feedback']], [agentEvidence, ['evidence']]]) };
  f.addPull = (n, extra = {}) => {
    const raw = hex('refs/heads/topic-') + 'ff';
    const value = row(n, { data: data({ object_format: algorithm, source_ref: null, source_ref_hex: raw,
      source_tip: 'a'.repeat(algorithm === 'sha1' ? 40 : 64), target_tip: 'b'.repeat(algorithm === 'sha1' ? 40 : 64),
      title: 'CI failure', body: 'literal\u202e text' }), ...extra });
    f.rows.push(value); return value;
  };
  f.addPull(1);
  f.selected = () => observation({ object_format: algorithm, pull_request: f.rows.find(value => value.number === 1) });
  f.addCheck = (n, recorded = report(), changes = {}) => {
    const value = evidenceFixture({ selected: f.selected(), report: recorded,
      check: { id: checkLabel(n), run_id: n.toString(16).padStart(64, '0'), ...changes } });
    f.records.push(value.check); f.records.sort((a, b) => a.id < b.id ? -1 : 1);
    f.evidence.set(value.check.id, value); return value;
  };
  f.addCheck(1);
  const server = createServer(async (req, res) => {
    try {
      let body = ''; for await (const bytes of req) body += bytes;
      const url = new URL(req.url, 'http://127.0.0.1'), call = { path: url.pathname, query: url.searchParams,
        method: req.method, body, headers: req.headers }; f.calls.push(call);
      const send = (value, status = 200) => {
        f.transform(value, call);
        const bytes = Buffer.from(JSON.stringify(value));
        res.writeHead(status, { 'Content-Type': 'application/json', 'Content-Length': bytes.length }); res.end(bytes);
      };
      const route = url.pathname.split('/api/v1/')[1];
      const need = route?.endsWith('/checks/evidence') ? 'evidence' : route?.endsWith('/checks') ? 'feedback' : 'metadata';
      const grants = f.grants.get(req.headers.authorization?.replace(/^Bearer /, ''));
      if (!grants) return send({}, 401);
      if (!grants.includes(need)) return send({}, 403);
      if (f.fault && await f.fault({ req, res, call, send, route })) return;
      if (req.method !== 'GET' || body || req.headers['idempotency-key']) return send({}, 400);
      const head = url.searchParams.get('expected_head');
      if (head !== null && head !== checksHead) return send({}, 409);
      if (route === 'pulls') {
        const after = Number(url.searchParams.get('after')), limit = Number(url.searchParams.get('limit'));
        const all = f.rows.filter(value => value.number > after), rows = all.slice(0, limit);
        return send(page({ object_format: algorithm, snapshot_token: checksHead, after, limit,
          pull_requests: structuredClone(rows), next_after: all.length > rows.length ? rows.at(-1).number : null }));
      }
      const match = /^pulls\/([1-9][0-9]*)(?:\/(checks(?:\/evidence)?))?$/.exec(route ?? '');
      if (!match) return send({}, 404);
      const n = Number(match[1]), selected = f.rows.find(value => value.number === n);
      if (!match[2]) return send(show({ object_format: algorithm, snapshot_token: checksHead, number: n,
        found: Boolean(selected), pull_request: selected ? structuredClone(selected) : null }), selected ? 200 : 404);
      if (!selected) return send({ ...unavailable(), object_format: algorithm, number: String(n) }, 404);
      if (match[2] === 'checks/evidence') {
        const value = f.evidence.get(url.searchParams.get('check'));
        if (!value || !f.sourceCurrent || head === null) return send({}, 404);
        return send(structuredClone(value.reply));
      }
      const after = url.searchParams.get('after'), limit = Number(url.searchParams.get('limit'));
      const all = f.sourceCurrent ? f.records.filter(value => after === null || value.id > after) : [];
      const rows = all.slice(0, limit), next = all.length > rows.length ? rows.at(-1).id : null;
      return send(checks({ object_format: algorithm, number: String(n), pull_request_version: String(selected.version),
        source_ref_hex: selected.data.source_ref_hex, target_ref_hex: selected.data.target_ref_hex,
        source_tip: selected.data.source_tip, target_tip: selected.data.target_tip,
        source_current: f.sourceCurrent, after, limit, checks: structuredClone(rows), next_after: next, complete: next === null }));
    } catch (error) { res.destroy(error); }
  });
  const port = await listenForFetch(server);
  f.href = 'http://127.0.0.1:' + port + '/repository/ui/pulls/';
  f.options = (operation = 'checks', extra = {}) => ({ operation, href: f.href, tenant: ids.tenant_id,
    repository: ids.repository_id, tokenFile, ...(operation === 'list' ? {} : { number: 1 }), ...extra });
  f.disclose = (operation = 'evidence', extra = {}) => f.options(operation, { head: checksHead,
    checkId: f.records[0].id, expectedSha256: f.records[0].evidence_sha256,
    expectedBytes: Number(f.records[0].evidence_bytes), evidenceTokenFile, ...extra });
  f.flags = operation => [operation, '--url', f.href, '--tenant-id', ids.tenant_id,
    '--repository-id', ids.repository_id, '--token-file', tokenFile];
  f.discloseFlags = operation => [...f.flags(operation), '--number', '1', '--check', f.records[0].id,
    '--expected-head', checksHead, '--expected-sha256', f.records[0].evidence_sha256,
    '--expected-bytes', f.records[0].evidence_bytes, '--evidence-token-file', evidenceTokenFile];
  t.after(async () => { server.closeAllConnections(); await new Promise(resolve => server.close(resolve));
    await rm(root, { recursive: true, force: true }); });
  return f;
}

test('strict CLI grammar rejects missing evidence pins, duplicate and inapplicable fields before I/O', async t => {
  const f = await peer(t), valid = f.discloseFlags('evidence');
  assert.equal(checkArguments(valid).checkId, f.records[0].id);
  for (const invalid of [valid.slice(0, -2), [...valid, '--expected-bytes', '1'],
    [...f.flags('checks'), '--number', '1', '--after', checkLabel(1)],
    [...f.flags('show'), '--number', '1', '--limit', '1'], [...f.flags('list'), '--number', '1'],
    [...f.flags('list'), '--limit', '01'], [...f.flags('list'), '--max-pages', '101'],
    [...valid, '--step', '0'], [...f.discloseFlags('log'), '--step', '0', '--stream', 'stderr'],
    [...f.flags('show'), '--number', '1', '--token', token], [...f.flags('show'), '--number', '1', '--trusted-local']]) {
    assert.throws(() => checkArguments(invalid));
  }
  assert.throws(() => checkReadOptions(f.disclose('evidence', { expectedBytes: '5' })));
  assert.throws(() => checkReadOptions(f.disclose('evidence', { href: 'http://external.invalid/repository/ui/pulls/' })));
  assert.equal(f.calls.length, 0);
});

test('sponsored read opt-in is closed to metadata/checks, with all default profiles unchanged', async () => {
  let requests = 0;
  const options = { href: 'https://forge.example/repository/ui/pulls/', cryptoImpl: webcrypto,
    fetchImpl: async () => { requests++; throw new Error('unexpected network'); } };
  await assert.rejects(new Transport(options).connect(agentToken));
  await assert.rejects(new CheckEvidenceClient(options).connect(agentEvidence));
  assert.throws(() => new Transport({ ...options, sponsoredRead: true }));
  assert.throws(() => new Transport({ ...options, sponsoredRead: true, pullReadOnly: true, checkEvidenceOnly: true }));
  const client = new Transport({ ...options, pullReadOnly: true, sponsoredRead: true });
  await client.connect(agentToken);
  const attempts = [
    ['pulls/1/open', { method: 'POST', key: 'key', read: false, body: 'title=x', statuses: [200, 409] }],
    ['outcomes', { method: 'POST', key: 'key', read: false }], ['artifacts/' + 'a'.repeat(64), {}],
    ['pulls/1/checks/evidence?check=' + encodeURIComponent(checkLabel(1)) + '&expected_head=' + checksHead, {}],
    ['pulls/1', { method: 'POST', statuses: [200, 404] }],
    ['pulls/1', { body: 'secret', statuses: [200, 404] }],
    ['pulls/1', { key: 'key', statuses: [200, 404] }],
    ['pulls?after=1&limit=20', {}], ['pulls?limit=20&limit=1', {}],
    ['pulls/1?render=html_safe', { statuses: [200, 404] }], ['pulls/1/checks?limit=20', { statuses: [200, 404] }],
  ];
  for (const [path, o] of attempts) await assert.rejects(client.request(path, o));
  assert.throws(() => client.restrictToRecovery({ key: 'key', principal: '1'.repeat(32) }));
  await assert.rejects(client.connect(agentToken, null, { key: 'key', principal: '1'.repeat(32) }));
  const evidence = new Transport({ ...options, checkEvidenceOnly: true, sponsoredRead: true });
  await evidence.connect(agentEvidence);
  await assert.rejects(evidence.request('pulls/1', { statuses: [200, 404] }));
  await assert.rejects(evidence.request('artifacts/' + 'a'.repeat(64)));
  assert.equal(requests, 0); client.disconnect(); evidence.disconnect();
});

for (const algorithm of ['sha1', 'sha256']) {
  test('PR list/show and checks resume at exact native coordinates in ' + algorithm, async t => {
    const f = await peer(t, algorithm); f.addPull(2); f.addCheck(2); f.addCheck(3);
    f.transform = value => {
      if (value.type === 'pull_request_page' || value.type === 'pull_request') {
        value.secret_extension = 'untrusted';
        for (const row of value.pull_requests ?? (value.pull_request ? [value.pull_request] : [])) {
          row.secret_extension = 'untrusted'; row.data.body_rendered = '<img src=x>';
        }
      }
    };
    const first = await runCheckCommand([...f.flags('list'), '--limit', '1']);
    assert.equal(first.exitCode, 4);
    const partial = JSON.parse(first.text); assert.equal(partial.pages[0].pull_requests[0].data.source_ref, null);
    assert.equal(partial.pages[0].pull_requests[0].data.source_ref_hex.endsWith('ff'), true);
    assert.equal(first.text.includes('secret_extension'), false); assert.equal(first.text.includes('body_rendered'), false);
    assert.equal(first.text.includes('\u202e'), false); assert.equal(first.text.includes('\\u202e'), true);
    const rest = await runCheckCommand([...f.flags('list'), '--limit', '1', '--after', '1', '--expected-head', partial.snapshot_token]);
    assert.equal(rest.exitCode, 0); assert.equal(JSON.parse(rest.text).pages[0].pull_requests[0].number, 2);
    const detail = await runCheckRead(f.options('show', { head: checksHead, incarnation: ids.repository_incarnation, objectFormat: algorithm }));
    assert.equal(detail.pull_request.data.object_format, algorithm);
    const prefix = await runCheckRead(f.options('checks', { limit: 1 }));
    assert.equal(prefix.complete, false); assert.equal(prefix.pages[0].checks[0].id, checkLabel(1));
    const resumed = await runCheckRead(f.options('checks', { head: prefix.continuation.expected_head,
      after: prefix.continuation.after, limit: 1, maxPages: 2 }));
    assert.equal(resumed.complete, true); assert.deepEqual(resumed.pages.flatMap(p => p.checks.map(c => c.id)), [checkLabel(2), checkLabel(3)]);
    assert.ok(f.calls.every(c => c.method === 'GET' && !c.body && !c.headers['idempotency-key']));
    assert.ok(f.calls.every(c => c.headers['user-agent'] === 'frankengit-agent (+https://github.com/Dicklesworthstone/frankengit)'));
    assert.deepEqual((await readdir(f.root)).sort(), ['evidence-token', 'token']);
  });

  test('exact evidence, binary log and zero-byte log export in ' + algorithm, async t => {
    const f = await peer(t, algorithm);
    f.records = []; f.evidence.clear();
    const bytes = Buffer.from([0, 255, 254, 13, 10, 27, 91, 50, 74]);
    const recorded = report({ jobs: [{ id: 'test', outcome: 'failed', failure: null,
      steps: [step({ stdout_hex: bytes.toString('hex'), stderr_hex: '', output_complete: false })] }] });
    const original = f.addCheck(1, recorded);
    const output = join(f.root, 'evidence.bin');
    const evidence = await runCheckRead(f.disclose('evidence', { output }));
    assert.deepEqual(await readFile(output), original.bytes);
    assert.equal(evidence.report.jobs[0].steps[0].stdout_hex, bytes.toString('hex'));
    assert.equal(evidence.check.conclusion, 'failure'); assert.equal(evidence.merge_permission, null);
    assert.equal(evidence.independent_execution_verified, false);
    for (const stream of ['stdout', 'stderr']) {
      const destination = join(f.root, stream);
      const saved = await runCheckRead(f.disclose('log', { step: 0, stream, output: destination }));
      assert.deepEqual(await readFile(destination), stream === 'stdout' ? bytes : Buffer.alloc(0));
      assert.equal(saved.log.output_complete, false); assert.equal(saved.log.outcome, 'failed');
      assert.equal(saved.log.exit_code, 1); assert.equal((await lstat(destination)).mode & 0o777, 0o600);
      assert.equal((await lstat(destination)).nlink, 1); assert.equal(saved.export.executable_mode_applied, false);
    }
    assert.ok(f.calls.filter(c => c.path.endsWith('/checks/evidence')).every(c => c.headers.authorization === 'Bearer ' + evidenceToken));
    assert.ok(f.calls.filter(c => !c.path.endsWith('/checks/evidence')).every(c => c.headers.authorization === 'Bearer ' + token));
    assert.equal((await readdir(f.root)).some(name => name.includes('.writing-')), false);
  });
}

test('sponsored feedback and evidence use separate explicit grants and live revocation', async t => {
  const f = await peer(t);
  await writeFile(f.tokenFile, agentToken, { mode: 0o600 }); await writeFile(f.evidenceTokenFile, agentEvidence, { mode: 0o600 });
  const result = await runCheckRead(f.disclose()); assert.equal(result.evidence_matches_selected_check, true);
  assert.ok(f.calls.filter(c => c.path.endsWith('/checks/evidence')).every(c => c.headers.authorization === 'Bearer ' + agentEvidence));
  f.grants.set(agentEvidence, ['feedback']);
  await assert.rejects(runCheckRead(f.disclose('evidence', { output: join(f.root, 'revoked') })), error => error.status === 403);
  f.grants.delete(agentToken);
  await assert.rejects(runCheckRead(f.options()), error => error.status === 401);
  assert.deepEqual((await readdir(f.root)).sort(), ['evidence-token', 'token']);
});

test('unknown evidence downloads exactly but has no invented step/log interpretation', async t => {
  const f = await peer(t), raw = Buffer.from([0, 255, 23, 42]);
  const value = evidenceFixture({ selected: f.selected(), report: null, raw });
  f.records = [value.check]; f.evidence = new Map([[value.check.id, value]]);
  const result = await runCheckRead(f.disclose('evidence', { output: join(f.root, 'opaque') }));
  assert.equal(result.report, null); assert.deepEqual(await readFile(result.export.output), raw);
  await assert.rejects(runCheckRead(f.disclose('log', { step: 0, stream: 'stdout', output: join(f.root, 'invented') })), /retained_step_unavailable/);
  assert.equal((await readdir(f.root)).includes('invented'), false);
});

test('tolerated failures and legacy action-required conclusions keep their exact meaning', async t => {
  const f = await peer(t);
  f.records = []; f.evidence.clear(); f.addCheck(1, toleratedReport(), { conclusion: 'action_required' });
  const result = await runCheckRead(f.disclose('log', { step: 0, stream: 'stderr', output: join(f.root, 'tolerated') }));
  assert.equal(result.check.conclusion, 'action_required'); assert.equal(result.log.observed_job_outcome, 'succeeded');
  assert.equal(result.log.outcome, 'failed'); assert.equal(result.log.outcome_tolerated, true);
  assert.equal(result.log.exit_code, 1); assert.equal(result.independent_execution_verified, false);
});

test('exact pin mismatch refuses before evidence disclosure, and later corruption never creates output', async t => {
  const f = await peer(t), output = join(f.root, 'bad');
  for (const change of [{ expectedSha256: '0'.repeat(64) }, { expectedBytes: 1 }]) {
    await assert.rejects(runCheckRead(f.disclose('evidence', { output, ...change })), /evidence_pin_mismatch/);
  }
  assert.equal(f.calls.some(c => c.path.endsWith('/checks/evidence')), false);
  const corruptions = [
    reply => { reply.evidence_hex = '00' + reply.evidence_hex.slice(2); },
    reply => { reply.report.json += ' '; },
    reply => { reply.report.offset++; },
    reply => { reply.page.repository_incarnation = '9'.repeat(32); },
    reply => { reply.page.source_head = 'moved'; },
    reply => { reply.page.checks[0].id = checkLabel(2); },
  ];
  for (const corrupt of corruptions) {
    f.transform = value => { if (value.type === 'pull_request_check_evidence') corrupt(value); };
    await assert.rejects(runCheckRead(f.disclose('evidence', { output })));
    assert.equal((await readdir(f.root)).includes('bad'), false);
  }
});

test('later-page identity, source or cursor failures do not emit partial success', async t => {
  const f = await peer(t); f.addPull(2); f.addCheck(2);
  for (const mutate of [r => { r.source_head = 'changed'; }, r => { r.snapshot_token = 'alg:2:' + '8'.repeat(64); },
    r => { r.repository_incarnation = '9'.repeat(32); }, r => { r.next_after = r.after; }]) {
    f.transform = reply => { if (reply.type === 'pull_request_page' && reply.after === 1) mutate(reply); };
    await assert.rejects(runCheckRead(f.options('list', { limit: 1, maxPages: 2 })));
  }
  f.transform = reply => { if (reply.type === 'pull_request_checks' && reply.after !== null) {
    reply.source_current = false; reply.checks = []; reply.next_after = null; reply.complete = true;
  } };
  await assert.rejects(runCheckRead(f.options('checks', { limit: 1, maxPages: 2 })), /source_state_changed/);
  f.transform = () => {};
  f.fault = ({ route, call, send }) => route === 'pulls/1/checks' && call.query.has('after') ? (send({}, 403), true) : false;
  await assert.rejects(runCheckRead(f.options('checks', { limit: 1, maxPages: 2 })), error => error.status === 403);
});

test('missing PR, stale source and selection page budget retain distinct results', async t => {
  const f = await peer(t);
  const missing = await runCheckRead(f.options('checks', { number: 2 }));
  assert.equal(missing.found, false); assert.equal(missing.complete, true); assert.deepEqual(missing.pages, []);
  assert.equal(f.calls.some(c => c.path.endsWith('/pulls/2/checks')), false);
  f.sourceCurrent = false;
  const stale = await runCheckRead(f.options()); assert.equal(stale.source_current, false);
  assert.deepEqual(stale.pages[0].checks, []); assert.equal(stale.merge_permission, null);
  await assert.rejects(runCheckRead(f.disclose()), /selected_check_unavailable/);
  f.sourceCurrent = true; const next = f.addCheck(2);
  await assert.rejects(runCheckRead(f.disclose('evidence', { checkId: next.check.id, expectedSha256: next.check.evidence_sha256,
    expectedBytes: Number(next.check.evidence_bytes), limit: 1, maxPages: 1 })), /selection_page_budget/);
  assert.equal(f.calls.some(c => c.path.endsWith('/checks/evidence')), false);
  const selected = await runCheckRead(f.disclose('evidence', { checkId: next.check.id, expectedSha256: next.check.evidence_sha256,
    expectedBytes: Number(next.check.evidence_bytes), after: checkLabel(1), limit: 1, maxPages: 1 }));
  assert.equal(selected.check.id, next.check.id);
});

test('private file preconditions and occupied outputs refuse before any HTTP request', async t => {
  const f = await peer(t), output = join(f.root, 'occupied'); await writeFile(output, 'keep', { mode: 0o600 });
  await assert.rejects(runCheckRead(f.disclose('evidence', { output })), /record_exists/);
  await assert.rejects(runCheckRead(f.disclose('evidence', { output: f.tokenFile })), /separate_output/);
  const alias = join(f.root, 'alias'); await symlink(f.tokenFile, alias);
  await assert.rejects(runCheckRead(f.options('show', { tokenFile: alias })));
  await chmod(f.tokenFile, 0o644); await assert.rejects(runCheckRead(f.options('show')), /private_owner/);
  await chmod(f.tokenFile, 0o600); await chmod(f.root, 0o755);
  await assert.rejects(runCheckRead(f.disclose('evidence', { output: join(f.root, 'public') })), /private_owner/);
  await chmod(f.root, 0o700);
  assert.equal(f.calls.length, 0); assert.equal(await readFile(output, 'utf8'), 'keep');
});

test('cancellation and output budgets after verification have no file publication', async t => {
  const f = await peer(t), output = join(f.root, 'cancelled'), stop = new AbortController();
  await assert.rejects(runCheckRead(f.disclose('evidence', { output, signal: stop.signal,
    onProgress: event => { if (event.phase === 'evidence_verified') stop.abort(); } })), /cancelled_or_deadline/);
  await assert.rejects(runCheckRead(f.disclose('evidence', { output, maxOutputBytes: 1 })), /output_limit/);
  assert.equal((await readdir(f.root)).includes('cancelled'), false);
  assert.equal((await readdir(f.root)).some(name => name.includes('.writing-')), false);
});

test('an output created concurrently is preserved; staged bytes do not overwrite it', async t => {
  const f = await peer(t), output = join(f.root, 'race');
  f.fault = async ({ route }) => {
    if (route.endsWith('/checks/evidence')) await writeFile(output, 'other owner', { flag: 'wx', mode: 0o600 });
    return false;
  };
  await assert.rejects(runCheckRead(f.disclose('evidence', { output })), error => error.code === 'EEXIST' && error.output_may_exist);
  assert.equal(await readFile(output, 'utf8'), 'other owner');
  assert.equal((await readdir(f.root)).some(name => name.includes('.writing-')), false);
});

test('redirects, incomplete JSON and response limits fail closed', async t => {
  const f = await peer(t);
  const faults = [
    ({ res }) => { res.writeHead(302, { Location: f.href }); res.end(); return true; },
    ({ res }) => { res.writeHead(200, { 'Content-Type': 'text/html' }); res.end('<h1>secret</h1>'); return true; },
    ({ res }) => { res.writeHead(200, { 'Content-Type': 'application/json', 'Content-Length': '8388609' }); res.end('{}'); return true; },
    ({ res }) => { res.writeHead(200, { 'Content-Type': 'application/json' }); res.end('{"incomplete":'); return true; },
  ];
  for (const fault of faults) { f.fault = fault; await assert.rejects(runCheckRead(f.options('show', { timeoutMs: 1000 }))); }
});

test('CLI reports bounded continuation and exports with exact byte integrity and no secret output', async t => {
  const f = await peer(t); f.addCheck(2);
  const prefix = await child([...f.flags('checks'), '--number', '1', '--limit', '1']);
  assert.equal(prefix.code, 4); assert.equal(JSON.parse(prefix.stdout.toString()).complete, false);
  const output = join(f.root, 'cli.log');
  const saved = await child([...f.discloseFlags('log'), '--step', '0', '--stream', 'stderr', '--output', output]);
  assert.equal(saved.code, 0, saved.stderr.toString());
  assert.equal(await readFile(output, 'utf8'), 'assertion failed\n');
  const text = saved.stdout.toString() + saved.stderr.toString();
  assert.equal(text.includes(token), false); assert.equal(text.includes(evidenceToken), false);
  assert.equal(JSON.parse(saved.stdout.toString()).check.conclusion, 'failure');
});

test('CLI deadline and SIGTERM cancel owned HTTP work without creating a download', async t => {
  const f = await peer(t), output = join(f.root, 'interrupted');
  f.fault = ({ route }) => route.endsWith('/checks/evidence');
  const timed = await child([...f.discloseFlags('evidence'), '--output', output, '--timeout-ms', '300']);
  assert.equal(timed.code, 2); assert.equal(timed.stdout.length, 0);
  assert.equal(JSON.parse(timed.stderr.toString()).mutation_submitted, false);
  let reached; const waiting = new Promise(resolve => { reached = resolve; });
  f.fault = ({ route }) => { if (route.endsWith('/checks/evidence')) { reached(); return true; } return false; };
  const process = spawn(globalThis.process.execPath, [cli, ...f.discloseFlags('evidence'), '--output', output], { stdio: ['ignore', 'pipe', 'pipe'] });
  const stdout = [], stderr = []; process.stdout.on('data', b => stdout.push(b)); process.stderr.on('data', b => stderr.push(b));
  t.after(() => { if (process.exitCode === null) process.kill('SIGKILL'); });
  const deadline = setTimeout(() => process.kill('SIGKILL'), 5000);
  await waiting; process.kill('SIGTERM'); const [code, signal] = await once(process, 'close'); clearTimeout(deadline);
  assert.equal(code, 2); assert.equal(signal, null); assert.equal(Buffer.concat(stdout).length, 0);
  assert.equal(JSON.parse(Buffer.concat(stderr).toString()).mutation_submitted, false);
  assert.equal((await readdir(f.root)).includes('interrupted'), false);
});

test('a verified file survives failed CLI stdout delivery', async t => {
  const f = await peer(t), output = join(f.root, 'retained-after-output-error');
  const proc = spawn(process.execPath, [cli, ...f.discloseFlags('log'), '--step', '0', '--stream', 'stderr', '--output', output],
    { stdio: ['ignore', 'pipe', 'pipe'] });
  const diagnostics = []; proc.stderr.on('data', bytes => diagnostics.push(bytes));
  proc.stdout.destroy();
  t.after(() => { if (proc.exitCode === null) proc.kill('SIGKILL'); });
  const deadline = setTimeout(() => proc.kill('SIGKILL'), 5000);
  const [code, signal] = await once(proc, 'close'); clearTimeout(deadline);
  assert.equal(code, 2); assert.equal(signal, null);
  assert.equal(await readFile(output, 'utf8'), 'assertion failed\n');
  const error = JSON.parse(Buffer.concat(diagnostics).toString());
  assert.equal(error.operation_completed, true); assert.equal(error.output_may_exist, true); assert.equal(error.output, output);
  assert.equal((await readdir(f.root)).some(name => name.includes('.writing-')), false);
});
