// Real HTTP, private files and CLI processes; schema peers are not native authority.
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, writeFile, readFile, rm, chmod, symlink, link } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { capturePullReviews } from '../../scripts/operator/pull_review_snapshot.mjs';
import { preparePull } from '../../scripts/operator/pull_command.mjs';
import { tokenValue, syncRequest } from '../../scripts/operator/pull_sync_transport.mjs';
import { discover, hash } from '../../scripts/operator/pull_sync_plan.mjs';
import { loadPlan } from '../../scripts/operator/pull_sync_custody.mjs';
import { credential } from '../../scripts/fg_pull_sync.mjs';
import { run as runReview } from '../../scripts/fg_pull_review.mjs';
import { runNativeProcess } from '../../scripts/lib/native-process-owner.mjs';
import { peer as reviewPeer } from './pull_review_snapshot_fixture.mjs';
import { fixture as syncPeer, TOKEN, ROTATED } from './fixtures/pull_sync_native.mjs';

const AGENT = 'fgagent_' + TOKEN, ROTATED_AGENT = 'fgagent_' + ROTATED;
const REVIEW_CLI = fileURLToPath(new URL('../../scripts/fg_pull_review.mjs', import.meta.url));
const SYNC_CLI = fileURLToPath(new URL('../../scripts/fg_pull_sync.mjs', import.meta.url));
async function files(t) {
  const root = await mkdtemp(join(tmpdir(), 'fg-pull-agent-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  return { root, token: join(root, 'token'), selection: join(root, 'selection.json'),
    capture: join(root, 'capture.json'), destination: join(root, 'destination.json'), state: join(root, 'state') };
}
const privateFile = (path, bytes) => writeFile(path, bytes, { mode: 0o600 });
const captureArgs = f => ['capture', '--input', f.selection, '--token-file', f.token, '--output', f.capture];
async function review(args) {
  let out = '', err = '';
  const code = await runReview(args, { output(text) { out += text; }, errorOutput(text) { err += text; } });
  return { code, out, err };
}
async function child(t, script, args) {
  const result = await runNativeProcess(process.execPath, [script, ...args], { timeoutMs: 15000,
    stdoutLimit: 1024 * 1024, stderrLimit: 1024 * 1024, signal: t.signal });
  return { code: result.code, out: result.stdout.toString(), err: result.stderr.toString() };
}

for (const [name, token] of [['ordinary', TOKEN], ['sponsored', AGENT]]) for (const suffix of ['', '\n']) {
  test(name + ' review capture CLI accepts exact token bytes' + (suffix ? ' with one LF' : ''), async t => {
    const p = await reviewPeer(t), f = await files(t);
    await privateFile(f.selection, JSON.stringify(p.selected)); await privateFile(f.token, token + suffix);
    const result = await child(t, REVIEW_CLI, captureArgs(f));
    assert.equal(result.code, 0, result.err);
    const bytes = await readFile(f.capture, 'utf8'), capture = JSON.parse(bytes);
    assert.equal(capture.complete, true); assert.equal(capture.merge_authorized, false);
    assert.equal(p.requests.length, 2);
    for (const request of p.requests) {
      assert.equal(request.headers.authorization, 'Bearer ' + token);
      assert.equal(request.method, 'GET'); assert.equal(request.body.length, 0);
    }
    assert.equal((bytes + result.out + result.err).includes(token), false);
    assert.equal(await credential(f.token), token);
  });
}
for (const format of ['sha1', 'sha256']) {
  test(format + ' sponsored capture keeps the complete bearer on every pinned review page', async t => {
    const p = await reviewPeer(t, { format });
    const capture = await capturePullReviews(p.selected, AGENT, { pageLimit: 1 });
    assert.equal(capture.review_pages.length, 3); assert.equal(p.requests.length, 4);
    for (const request of p.requests) assert.equal(request.headers.authorization, 'Bearer ' + AGENT);
    for (const request of p.requests.slice(1)) assert.equal(request.url.searchParams.get('expected_head'), capture.pull.snapshot_token);
  });
}

test('both token readers reject BOM, malformed encodings and oversized files before HTTP', async t => {
  const p = await reviewPeer(t), f = await files(t);
  await privateFile(f.selection, JSON.stringify(p.selected));
  const malformed = ['', TOKEN.slice(1), TOKEN + 'a', AGENT.slice(0, -1), AGENT + 'a',
    'FGAGENT_' + TOKEN, 'fgagent_' + 'A'.repeat(64), '\ufeff' + TOKEN, '\ufeff' + AGENT,
    ' ' + TOKEN, TOKEN + ' ', TOKEN + '\r\n', AGENT + '\r\n', TOKEN + '\n\n', AGENT + '\n\n',
    TOKEN + '\0', 'Bearer ' + TOKEN, Buffer.concat([Buffer.from(TOKEN), Buffer.from([0xff])]),
    Buffer.from([0xff]), 'fgagent_' + '雪'.repeat(32)];
  for (const [index, bytes] of malformed.entries()) {
    await privateFile(f.token, bytes);
    await assert.rejects(credential(f.token), undefined, 'sync token case ' + index);
    const result = await review(captureArgs(f)); assert.equal(result.code, 2, 'capture token case ' + index);
    assert.equal((result.out + result.err).includes(TOKEN), false);
  }
  assert.equal(p.requests.length, 0); await assert.rejects(readFile(f.capture));
});

for (const kind of ['public', 'symlink', 'hardlink', 'directory']) {
  test('sponsored private token ' + kind + ' refusal is unchanged in both operators', async t => {
    const p = await reviewPeer(t), f = await files(t);
    await privateFile(f.selection, JSON.stringify(p.selected)); await privateFile(f.token, AGENT + '\n');
    if (kind === 'public') await chmod(f.token, 0o644);
    if (kind === 'symlink') { const alias = join(f.root, 'alias'); await symlink(f.token, alias); f.token = alias; }
    if (kind === 'hardlink') await link(f.token, join(f.root, 'other-name'));
    if (kind === 'directory') f.token = f.root;
    await assert.rejects(credential(f.token));
    assert.equal((await review(captureArgs(f))).code, 2); assert.equal(p.requests.length, 0);
    await assert.rejects(readFile(f.capture));
  });
}

test('direct capture and sync reject malformed bearer values without opening a request', async t => {
  const p = await reviewPeer(t);
  assert.equal(tokenValue(TOKEN), TOKEN); assert.equal(tokenValue(AGENT), AGENT);
  for (const value of [null, {}, Buffer.from(AGENT), '', AGENT + '\n', '\ufeff' + TOKEN,
    '\ufeff' + AGENT, 'FGAGENT_' + TOKEN, 'fgagent_' + 'A'.repeat(64), AGENT + '\0']) {
    assert.throws(() => tokenValue(value), /invalid_sync_credential/);
    await assert.rejects(capturePullReviews(p.selected, value), /invalid_review_credential/);
    await assert.rejects(syncRequest(p.selected.endpoint, value, { kind: 'pulls', after: 0, head: null }), /invalid_sync_credential/);
  }
  assert.equal(p.requests.length, 0);
});

for (const format of ['sha1', 'sha256']) for (const refused of [false, true]) {
  test(format + ' sponsored sync recovers a lost ' + (refused ? 'refused' : 'committed') + ' reply with a rotated bearer', async t => {
    const p = await syncPeer(t, format, 1, { tokens: [AGENT, ROTATED_AGENT] }), f = await files(t);
    await mkdir(f.state, { mode: 0o700 }); await privateFile(f.destination, JSON.stringify(p.dest));
    await privateFile(f.token, AGENT + '\n');
    const discovery = ['--destination', f.destination, '--token-file', f.token, '--pr', '1'];
    const inspected = await child(t, SYNC_CLI, ['inspect', ...discovery]); assert.equal(inspected.code, 0, inspected.err);
    assert.equal(JSON.parse(inspected.out).changes.length, 1); assert.equal(p.decisions.size, 0);
    const prepared = await child(t, SYNC_CLI, ['prepare', ...discovery, '--state', f.state]);
    assert.equal(prepared.code, 0, prepared.err);
    const plan = await loadPlan(f.state), original = await readFile(join(f.state, 'plan.json'));
    assert.equal(plan.credential_sha256, hash(AGENT)); assert.notEqual(plan.credential_sha256, hash(TOKEN));
    assert.equal(original.includes(Buffer.from(AGENT)), false); assert.equal(p.decisions.size, 0);
    assert.ok(p.calls.every(call => call.headers.authorization === 'Bearer ' + AGENT));
    const controls = ['--state', f.state, '--endpoint', p.dest.endpoint, '--token-file', f.token];
    const callsBefore = p.calls.length;
    for (const other of [TOKEN, ROTATED_AGENT]) {
      await privateFile(f.token, other);
      const denied = await child(t, SYNC_CLI, ['send', ...controls, '--confirm', plan.plan_sha256]);
      assert.equal(denied.code, 2, denied.err); assert.match(denied.err, /original_credential/);
      assert.equal(p.calls.length, callsBefore);
    }
    await privateFile(f.token, AGENT); p.state.drop = true; p.state.refuse = refused;
    const sent = await child(t, SYNC_CLI, ['send', ...controls, '--confirm', plan.plan_sha256]);
    assert.equal(sent.code, 3, sent.err); assert.equal(JSON.parse(sent.err).publication_unknown, true);
    assert.equal(p.decisions.size, 1);
    await privateFile(f.token, ROTATED_AGENT + '\n');
    const recovered = await child(t, SYNC_CLI, ['recover', ...controls]);
    assert.equal(recovered.code, refused ? 1 : 0, recovered.err);
    const result = JSON.parse(recovered.out.trim().split('\n').at(-1));
    assert.equal(result.jobs[0].state, refused ? 'refused' : 'committed');
    const updates = p.calls.filter(call => call.path.endsWith('/update'));
    const lookups = p.calls.filter(call => call.path.endsWith('/outcomes'));
    assert.equal(updates.length, 1); assert.equal(lookups.length, 1);
    assert.equal(updates[0].headers.authorization, 'Bearer ' + AGENT);
    assert.equal(lookups[0].headers.authorization, 'Bearer ' + ROTATED_AGENT);
    assert.equal(lookups[0].headers['idempotency-key'], plan.requests[0].key);
    assert.equal(updates[0].headers['idempotency-key'], plan.requests[0].key); assert.equal(lookups[0].body, '');
    assert.deepEqual(await readFile(join(f.state, 'plan.json')), original);
    for (const output of [inspected, prepared, sent, recovered]) {
      assert.equal((output.out + output.err).includes(AGENT), false);
      assert.equal((output.out + output.err).includes(ROTATED_AGENT), false);
    }
  });
}

for (const route of ['pulls', 'reviews']) {
  test('sponsored capture preserves server authorization refusal for ' + route, async t => {
    const p = await reviewPeer(t, { handle(record, response) {
      if (route === 'pulls' || record.url.pathname.endsWith('/reviews')) {
        response.writeHead(403); response.end(); return true;
      }
    } });
    await assert.rejects(capturePullReviews(p.selected, AGENT), error => error.code === 'review_http_refused' && error.status === 403);
    assert.equal(p.requests.length, route === 'pulls' ? 1 : 2);
    assert.ok(p.requests.every(request => request.headers.authorization === 'Bearer ' + AGENT && request.method === 'GET'));
  });
}
for (const route of ['pulls', 'source/refs']) {
  test('sponsored sync preserves independent server read refusal for ' + route, async t => {
    const p = await syncPeer(t, 'sha1', 1, { tokens: [AGENT] });
    p.state.hook = (call, _request, response) => {
      if (call.path.endsWith('/' + route)) { response.writeHead(403); response.end(); return true; }
    };
    await assert.rejects(discover(p.dest, AGENT, 'all-open'), error => error.code === 'sync_http_refused' && error.status === 403);
    assert.equal(p.calls.length, route === 'pulls' ? 1 : 2); assert.equal(p.decisions.size, 0);
    assert.ok(p.calls.every(call => call.headers.authorization === 'Bearer ' + AGENT));
  });
}
test('accepting sponsored read and sync tokens does not enable candidate review or merge operations', async t => {
  const p = await reviewPeer(t);
  for (const action of ['approve', 'request-changes', 'withdraw', 'merge', 'fast-forward', 'rebase']) {
    assert.throws(() => preparePull({ action }, AGENT), /agent_metadata_operation_unsupported/);
    await assert.rejects(syncRequest(p.selected.endpoint, AGENT, { kind: action }), /unsupported_sync_operation/);
  }
  assert.equal(p.requests.length, 0);
});
