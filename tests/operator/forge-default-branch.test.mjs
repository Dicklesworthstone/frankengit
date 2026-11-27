// Production CLI/client/private custody over real sockets; the peer simulates native responses.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { createHash } from 'node:crypto';
import { mkdtemp, readFile, writeFile, readdir, rm, chmod, lstat } from 'node:fs/promises';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { defaultBranchArguments, runDefaultBranchCommand } from '../../scripts/forge_default_branch.mjs';
import { runDefaultBranchOperation, defaultBranchOperatorOptions } from '../../scripts/lib/forge-default-branch-operator.mjs';
import { runNativeProcess } from '../../scripts/lib/native-process-owner.mjs';
import { listenForFetch } from './fetch_listener_helper.mjs';
import { token, actor, metadata, tip, hex, publication, outcome } from '../browser/default-branch-fixtures.mjs';

const tenant = metadata().tenant_id, repository = metadata().repository_id;
const mutations = f => f.calls.filter(call => call.method === 'POST' && call.path.endsWith('/api/v1/default-branch'));
const cli = fileURLToPath(new URL('../../scripts/forge_default_branch.mjs', import.meta.url));
const processCommand = args => runNativeProcess(process.execPath, [cli, ...args], { timeoutMs: 15000, stdoutLimit: 1024 * 1024 });
async function fixture(t, algorithm = 'sha1') {
  const root = await mkdtemp(join(tmpdir(), 'fg-default-operator-')), tokenFile = join(root, 'token');
  await writeFile(tokenFile, token, { mode: 0o600 });
  const f = { root, tokenFile, algorithm, calls: [], decisions: new Map(), generation: 1,
    current: hex('refs/heads/main'), rows: new Map(), allowRead: true, allowWrite: true, allowOutcome: true,
    beforePublish: null, afterPublish: null, transform() {}, fault: null };
  f.add = (name, value = 'b', raw = false) => {
    const ref_hex = raw ? name : hex(name);
    let ref = null;
    try { ref = new TextDecoder('utf-8', { fatal: true }).decode(Buffer.from(ref_hex, 'hex')); } catch {}
    f.rows.set(ref_hex, { ref, ref_hex, object_id: tip(algorithm, value).split(':')[1] });
    return ref_hex;
  };
  f.add('refs/heads/main', 'a'); f.add('refs/heads/topic', 'b');
  f.head = () => 'alg:1:' + f.generation.toString(16).padStart(64, '0');
  f.sourceHead = () => 'source-' + f.generation;
  f.scope = () => ({ tenant, repository, incarnation: metadata().repository_incarnation, format: algorithm });
  const server = createServer(async (req, res) => {
    try {
      let body = ''; for await (const bytes of req) body += bytes;
      const url = new URL(req.url, 'http://127.0.0.1'), key = req.headers['idempotency-key'];
      const call = { method: req.method, path: url.pathname, query: url.searchParams, body, key,
        authorization: req.headers.authorization, userAgent: req.headers['user-agent'] }; f.calls.push(call);
      const send = (value, status = 200) => {
        f.transform(value, call); res.writeHead(status, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(value));
      };
      if (req.headers.authorization !== 'Bearer ' + token) return send({}, 401);
      if (f.fault && await f.fault({ req, res, call, send })) return;
      if (call.path.endsWith('/outcomes')) {
        if (!f.allowOutcome) return send({}, 403);
        const d = f.decisions.get(key), source = d?.pending.source ?? { scope: f.scope(), principal: actor };
        const value = outcome({ source }, d?.wire.outcome ?? 'key_not_observed');
        if (d) {
          value.transaction.tx_id = d.wire.tx_id;
          value.transaction.seal_id = 'seal-' + createHash('sha256').update(key).digest('hex');
          value.decision.decision_sequence = d.wire.decision_sequence;
          if (d.wire.outcome === 'committed') value.decision.repository_commit_id = d.wire.repository_commit_id;
          else { value.decision.code = d.wire.code; value.decision.refusal_record_id = d.wire.refusal_record_id; }
        }
        return send(value);
      }
      if (req.method === 'GET' && call.path.endsWith('/default-branch')) {
        if (!f.allowRead) return send({}, 403);
        if (url.searchParams.has('expected_head') && url.searchParams.get('expected_head') !== f.head()) return send({}, 409);
        const selected = f.rows.get(f.current);
        return send({ ...metadata(algorithm), type: 'default_branch', principal_id: actor, source_head: f.sourceHead(),
          snapshot_token: f.head(), default_reference_hex: f.current, tip: selected?.object_id ?? null,
          unborn: f.current !== null && !selected, read_only: true, transaction_created: false, published: false });
      }
      if (req.method === 'POST' && call.path.endsWith('/source/refs')) {
        if (!f.allowRead) return send({}, 403);
        const params = new URLSearchParams(body);
        if (params.get('expected_head') !== f.head()) return send({}, 409);
        const after = params.get('after'), limit = Number(params.get('limit'));
        const all = [...f.rows.values()].filter(row => after === null || row.ref_hex > after).sort((a, b) => a.ref_hex.localeCompare(b.ref_hex));
        const refs = all.slice(0, limit);
        return send({ ...metadata(algorithm), type: 'source_refs', namespace: 'branches', cursor_encoding: 'hex',
          source_head: f.sourceHead(), snapshot_token: f.head(), after, limit, refs,
          next_after: all.length > refs.length ? refs.at(-1).ref_hex : null,
          read_only: true, transaction_created: false, published: false, direct_refs_only: true });
      }
      if (req.method !== 'POST' || !call.path.endsWith('/default-branch') || !key) return send({}, 404);
      if (!f.allowWrite) return send({}, 403);
      const oldDecision = f.decisions.get(key);
      if (oldDecision) {
        if (oldDecision.body !== body) return send({}, 409);
        return send(oldDecision.wire, oldDecision.wire.outcome === 'committed' ? 200 : 409);
      }
      if (f.beforePublish) await f.beforePublish({ call, res });
      const params = new URLSearchParams(body), old = params.get('expected_default_hex');
      const target = params.get('reference_hex'), expectedTip = params.get('expected_tip');
      const command = { ...(old === null ? { expect_no_default: true } : { expected_default_hex: old }),
        reference_hex: target, expected_tip: algorithm + ':' + expectedTip };
      const pending = { source: { scope: f.scope(), principal: actor }, command };
      const accepted = old === f.current && f.rows.get(target)?.object_id === expectedTip;
      const sequence = f.decisions.size + 1;
      const wire = publication(pending, accepted ? 'committed' : 'refused', { tx_id: 'tx-' + sequence,
        decision_sequence: sequence, ...(accepted ? { repository_commit_id: 'rcr-' + sequence } : { refusal_record_id: 'refusal-' + sequence }) });
      f.decisions.set(key, { body, pending, wire });
      if (accepted && f.current !== target) { f.current = target; f.generation++; }
      if (f.afterPublish && await f.afterPublish({ call, res, wire })) return;
      return send(wire, accepted ? 200 : 409);
    } catch (error) { res.destroy(error); }
  });
  const port = await listenForFetch(server);
  f.href = 'http://127.0.0.1:' + port + '/repository/ui/default-branch/';
  f.connection = { href: f.href, tenant, repository, tokenFile };
  f.operation = (patch = {}) => ({ ...f.connection, operation: 'set-default', record: join(root, 'request.json'),
    expectedDefaultHex: hex('refs/heads/main'), referenceHex: hex('refs/heads/topic'), expectedTip: tip(algorithm, 'b'), ...patch });
  f.flags = (operation, record = null) => [operation, '--url', f.href, '--tenant-id', tenant, '--repository-id', repository,
    '--token-file', tokenFile, ...(record === null ? [] : ['--record', record])];
  t.after(async () => { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); await rm(root, { recursive: true, force: true }); });
  return f;
}

test('CLI requires an exact old symbolic target and typed new tip, with closed read/recovery grammars', async t => {
  const f = await fixture(t), record = join(f.root, 'record');
  const base = [...f.flags('set-default', record), '--ref', 'refs/heads/topic', '--expected-tip', tip()];
  const args = [...base, '--expected-default', 'refs/heads/main'];
  assert.equal(defaultBranchArguments(args).expectedDefaultHex, hex('refs/heads/main'));
  assert.equal(defaultBranchArguments([...base, '--expect-no-default']).expectNoDefault, true);
  for (const invalid of [base, [...args, '--expect-no-default'], [...args, '--ref-hex', hex('refs/heads/topic')],
    [...args, '--expected-default-hex', hex('refs/heads/main')], [...base, '--expect-no-default', '--expect-no-default'],
    [...f.flags('set-default', record), '--ref', 'refs/heads/topic', '--expected-default', 'refs/heads/main', '--expected-tip', 'a'.repeat(40)],
    [...args, '--principal', actor], [...args, '--max-pages', '22'], [...f.flags('show'), '--record', record],
    [...f.flags('show'), '--limit', '1'], [...f.flags('list'), '--after-hex', hex('refs/heads/main')],
    [...f.flags('list'), '--limit', '01'], [...f.flags('status', record), '--expected-tip', tip()],
    [...f.flags('retry', record), '--expect-no-default']]) assert.throws(() => defaultBranchArguments(invalid));
  assert.throws(() => defaultBranchOperatorOptions({ ...f.operation(), referenceHex: hex('refs/tags/v1') }));
  assert.equal(f.calls.length, 0);
});

for (const algorithm of ['sha1', 'sha256']) test('exact byte-name selection publishes through private custody in ' + algorithm, async t => {
  const f = await fixture(t, algorithm), raw = f.add(hex('refs/heads/release-') + 'ff', 'c', true);
  const o = f.operation({ referenceHex: raw, expectedTip: tip(algorithm, 'c') });
  const originalRefs = JSON.stringify([...f.rows]);
  f.beforePublish = ({ call }) => {
    const record = JSON.parse(readFileSync(o.record));
    assert.equal(record.schema, 'frankengit-default-branch-operator-v1');
    assert.equal(record.receipt.key, call.key); assert.match(call.key, /^fgdefault1-/);
    assert.equal(record.receipt.command.reference_hex, raw);
    const form = new URLSearchParams(call.body);
    assert.equal(form.get('reference_hex'), raw); assert.equal(form.get('expected_default_hex'), hex('refs/heads/main'));
    assert.equal(form.get('expected_tip'), 'c'.repeat(algorithm === 'sha1' ? 40 : 64));
  };
  const result = await runDefaultBranchOperation(o);
  assert.equal(result.state, 'terminal_observed'); assert.equal(result.result.outcome, 'committed');
  assert.equal(result.result.headChanged, true); assert.equal(f.current, raw);
  assert.equal(JSON.stringify([...f.rows]), originalRefs);
  const bytes = await readFile(o.record);
  assert.equal(bytes.includes(token), false); assert.equal((await lstat(o.record)).mode & 0o777, 0o600);
  assert.equal(JSON.parse(bytes).receipt.fingerprint, createHash('sha256').update(token).digest('hex'));
  assert.ok(f.calls.every(call => call.authorization === 'Bearer ' + token &&
    call.userAgent === 'frankengit-agent (+https://github.com/Dicklesworthstone/frankengit)'));
});

test('show reads only the default; list resumes byte cursors at the exact head and strips extensions', async t => {
  const f = await fixture(t), raw = f.add(hex('refs/heads/a-') + 'ff', 'c', true);
  f.transform = reply => {
    reply.private_extension = 'untrusted';
    for (const row of reply.refs ?? []) row.private_extension = 'untrusted';
  };
  const show = await runDefaultBranchCommand(f.flags('show'));
  assert.equal(show.exitCode, 0); assert.equal(f.calls.length, 1); assert.equal(f.calls[0].method, 'GET');
  assert.equal(JSON.parse(show.text).tip, tip()); assert.equal(show.text.includes('private_extension'), false);
  const prefix = await runDefaultBranchCommand([...f.flags('list'), '--limit', '1']);
  assert.equal(prefix.exitCode, 4);
  const first = JSON.parse(prefix.text);
  assert.equal(first.pages[0].refs[0].ref, null); assert.equal(first.continuation.after_hex, raw);
  const before = f.calls.length;
  const rest = await runDefaultBranchCommand([...f.flags('list'), '--limit', '1', '--max-pages', '2',
    '--after-hex', raw, '--expected-head', first.continuation.expected_head]);
  assert.equal(rest.exitCode, 0);
  assert.deepEqual(JSON.parse(rest.text).pages.flatMap(page => page.refs.map(row => row.ref)), ['refs/heads/main', 'refs/heads/topic']);
  assert.equal(rest.text.includes('private_extension'), false);
  assert.equal(f.calls[before].query.get('expected_head'), first.snapshot_token);
  assert.ok(f.calls.slice(before + 1).every(call => new URLSearchParams(call.body).get('expected_head') === first.snapshot_token));
  assert.deepEqual(await readdir(f.root), ['token']); assert.equal(mutations(f).length, 0);
});

test('absent and named-unborn defaults remain different exact preconditions', async t => {
  const f = await fixture(t); f.current = hex('refs/heads/unborn');
  const show = JSON.parse((await runDefaultBranchCommand(f.flags('show'))).text);
  assert.equal(show.unborn, true); assert.equal(show.tip, null); assert.equal(show.default_reference_hex, f.current);
  const absent = f.operation({ expectNoDefault: true }); delete absent.expectedDefaultHex;
  await assert.rejects(runDefaultBranchOperation(absent), error => error.code === 'default_branch_operator_expected_default_moved');
  assert.equal(mutations(f).length, 0); assert.deepEqual(await readdir(f.root), ['token']);
  assert.equal((await runDefaultBranchOperation(f.operation({ expectedDefaultHex: f.current }))).result.outcome, 'committed');
  f.current = null; f.generation++;
  const empty = JSON.parse((await runDefaultBranchCommand(f.flags('show'))).text);
  assert.equal(empty.unborn, false); assert.equal(empty.default_reference_hex, null);
  const choose = f.operation({ expectNoDefault: true, record: join(f.root, 'absent.json') }); delete choose.expectedDefaultHex;
  assert.equal((await runDefaultBranchOperation(choose)).result.outcome, 'committed');
  assert.equal(new URLSearchParams(mutations(f).at(-1).body).get('expect_no_default'), 'true');
});

test('stale user expectations refuse before custody; a race after selection remains an original terminal refusal', async t => {
  const f = await fixture(t);
  for (const patch of [{ expectedDefaultHex: hex('refs/heads/other') }, { expectedTip: tip('sha1', 'c') },
    { expectedTip: tip('sha256', 'b') }, { referenceHex: hex('refs/heads/missing') }]) {
    await assert.rejects(runDefaultBranchOperation(f.operation(patch)), error => error.operator_state === 'not_submitted');
  }
  assert.deepEqual(await readdir(f.root), ['token']); assert.equal(mutations(f).length, 0);
  f.beforePublish = () => { f.current = hex('refs/heads/other'); f.generation++; };
  const result = await runDefaultBranchOperation(f.operation());
  assert.equal(result.result.outcome, 'refused'); const bytes = await readFile(f.operation().record);
  f.beforePublish = null;
  const retry = await runDefaultBranchOperation({ ...f.connection, operation: 'retry', record: f.operation().record });
  assert.equal(retry.result.outcome, 'refused'); assert.equal(retry.mutation_submitted, false);
  assert.equal(mutations(f).length, 1); assert.deepEqual(await readFile(f.operation().record), bytes);
});

test('interruption after the custody barrier is recoverable without rereading or refreshing either expectation', async t => {
  const f = await fixture(t), o = f.operation(), stop = new AbortController();
  await assert.rejects(runDefaultBranchOperation({ ...o, signal: stop.signal, onProgress: ({ phase }) => {
    if (phase === 'receipt_saved') stop.abort();
  } }), error => error.operator_state === 'recorded_unknown' && error.record_sha256 !== null);
  assert.equal(mutations(f).length, 0);
  const bytes = await readFile(o.record), saved = JSON.parse(bytes).receipt;
  const status = await runDefaultBranchOperation({ ...f.connection, operation: 'status', record: o.record });
  assert.equal(status.state, 'unresolved'); assert.equal(status.absence_proves_non_commit, false);
  f.allowRead = false;
  const retry = await runDefaultBranchOperation({ ...f.connection, operation: 'retry', record: o.record });
  assert.equal(retry.result.outcome, 'committed'); assert.equal(retry.mutation_submitted, true);
  assert.equal(mutations(f)[0].key, saved.key); assert.deepEqual(await readFile(o.record), bytes);
  assert.equal(f.calls.filter(call => call.method === 'GET').length, 1);
});

test('fresh-process response loss recovers the first decision after later HEAD changes and never repeats the write', async t => {
  const f = await fixture(t), record = f.operation().record;
  f.afterPublish = ({ res }) => { res.destroy(); return true; };
  const lost = await processCommand([...f.flags('set-default', record), '--ref', 'refs/heads/topic',
    '--expected-default', 'refs/heads/main', '--expected-tip', tip('sha1', 'b')]);
  assert.equal(lost.code, 2); assert.equal(lost.stdout.length, 0);
  assert.equal(JSON.parse(lost.stderr).state, 'submitted_unknown');
  const bytes = await readFile(record), key = JSON.parse(bytes).receipt.key;
  f.afterPublish = null; f.current = hex('refs/heads/later'); f.generation++; f.allowRead = false; f.allowWrite = false;
  for (const operation of ['status', 'retry']) {
    const result = await processCommand(f.flags(operation, record));
    assert.equal(result.code, 0, result.stderr.toString());
    assert.equal(JSON.parse(result.stdout).result.tx, f.decisions.get(key).wire.tx_id);
    assert.equal(JSON.parse(result.stdout).mutation_submitted, false); assert.equal(result.stdout.includes(token), false);
  }
  assert.equal(mutations(f).length, 1); assert.deepEqual(await readFile(record), bytes);
  assert.equal(f.current, hex('refs/heads/later'));
});

test('records, credentials and repository identity cannot be substituted during recovery', async t => {
  const f = await fixture(t), o = f.operation(); await runDefaultBranchOperation(o);
  const bytes = await readFile(o.record), calls = f.calls.length;
  await assert.rejects(runDefaultBranchOperation(o), error => error.code === 'operator_record_exists');
  await writeFile(f.tokenFile, 'cd'.repeat(32));
  await assert.rejects(runDefaultBranchOperation({ ...f.connection, operation: 'retry', record: o.record }));
  await writeFile(f.tokenFile, token);
  await assert.rejects(runDefaultBranchOperation({ ...f.connection, operation: 'status', record: o.record, repository: 'f'.repeat(32) }));
  const changed = JSON.parse(bytes); changed.receipt.command.expected_tip = tip('sha1', 'd');
  await writeFile(o.record, JSON.stringify(changed) + '\n');
  await assert.rejects(runDefaultBranchOperation({ ...f.connection, operation: 'retry', record: o.record }));
  assert.equal(f.calls.length, calls);
  await writeFile(o.record, bytes);
  assert.equal((await runDefaultBranchOperation({ ...f.connection, operation: 'status', record: o.record })).result.outcome, 'committed');
});

test('sponsored credentials and unsafe private custody refuse beside an allowed ordinary-token request', async t => {
  const f = await fixture(t), o = f.operation();
  await writeFile(f.tokenFile, 'fgagent_' + 'a'.repeat(64));
  await assert.rejects(runDefaultBranchOperation(o));
  await writeFile(f.tokenFile, token); await chmod(f.tokenFile, 0o644);
  await assert.rejects(runDefaultBranchOperation(o), error => error.code === 'operator_private_owner_required');
  await chmod(f.tokenFile, 0o600); await chmod(f.root, 0o755);
  await assert.rejects(runDefaultBranchOperation(o), error => error.code === 'operator_private_owner_required');
  assert.equal(f.calls.length, 0); await chmod(f.root, 0o700);
  assert.equal((await runDefaultBranchOperation(o)).result.outcome, 'committed');
});

test('bounded selection finds later candidates and refuses without a guessed tip or partial inventory', async t => {
  const f = await fixture(t);
  for (let i = 0; i < 101; i++) f.add('refs/heads/a-' + String(i).padStart(3, '0'));
  const o = f.operation({ maxPages: 1 });
  await assert.rejects(runDefaultBranchOperation(o), error => error.code === 'default_branch_operator_selection_page_limit');
  assert.equal(mutations(f).length, 0); assert.deepEqual(await readdir(f.root), ['token']);
  const result = await runDefaultBranchOperation({ ...o, maxPages: 2 });
  assert.equal(result.result.outcome, 'committed');
  const pages = f.calls.filter(call => call.path.endsWith('/source/refs'));
  assert.equal(pages.length, 3); assert.ok(pages.every(call => new URLSearchParams(call.body).get('expected_head') === 'alg:1:' + '1'.padStart(64, '0')));
});

test('a malformed later page, moved head or revoked read never yields a successful prefix', async t => {
  const f = await fixture(t);
  for (const mode of ['head', 'identity', 'order', 'source']) {
    f.transform = (reply, call) => {
      if (!call.path.endsWith('/source/refs') || !new URLSearchParams(call.body).has('after')) return;
      if (mode === 'head') reply.snapshot_token = 'alg:1:' + 'e'.repeat(64);
      if (mode === 'identity') reply.repository_id = 'f'.repeat(32);
      if (mode === 'order') reply.refs[0].ref_hex = reply.after;
      if (mode === 'source') reply.source_head = 'substituted';
    };
    await assert.rejects(runDefaultBranchOperation({ ...f.connection, operation: 'list', limit: 1, maxPages: 2 }),
      error => error.operator_state === 'read_incomplete');
  }
  f.transform = () => {};
  await assert.rejects(runDefaultBranchOperation({ ...f.connection, operation: 'list', limit: 1, maxPages: 2,
    onProgress: () => { f.allowRead = false; } }), error => error.status === 403 && error.operator_state === 'read_incomplete');
  f.allowRead = true;
  const pinned = f.head(); f.generation++;
  await assert.rejects(runDefaultBranchOperation({ ...f.connection, operation: 'show', head: pinned }),
    error => error.status === 409);
  assert.equal(mutations(f).length, 0);
});

test('output, cancellation, deadline and redirect bounds retain failure state without hidden mutations', async t => {
  const f = await fixture(t);
  await assert.rejects(runDefaultBranchOperation({ ...f.connection, operation: 'show', maxOutputBytes: 32 }),
    error => error.code === 'default_branch_operator_output_limit');
  const stop = new AbortController(), before = f.calls.length;
  await assert.rejects(runDefaultBranchOperation({ ...f.connection, operation: 'list', limit: 1, maxPages: 2,
    signal: stop.signal, onProgress: () => stop.abort() }),
  error => error.code === 'default_branch_operator_cancelled_or_deadline');
  assert.equal(f.calls.length, before + 2);
  f.fault = ({ res }) => { res.writeHead(302, { Location: '/untrusted' }); res.end(); return true; };
  await assert.rejects(runDefaultBranchOperation({ ...f.connection, operation: 'show' }));
  assert.equal(f.calls.some(call => call.path === '/untrusted'), false);
  f.fault = () => true;
  await assert.rejects(runDefaultBranchOperation({ ...f.connection, operation: 'show', timeoutMs: 50 }),
    error => error.operator_state === 'read_incomplete');
  assert.equal(mutations(f).length, 0);
});
