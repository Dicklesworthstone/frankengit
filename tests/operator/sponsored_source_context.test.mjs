// Real clients, private files and processes over controlled schema peers.
// These tests do not authenticate a native Rust source grant or label digest.
import test from 'node:test';
import assert from 'node:assert/strict';
import { writeFile, readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { acquire, validate } from '../../scripts/operator/source_context.mjs';
import { continueCapture } from '../../scripts/operator/source_context_continue.mjs';
import { createSession, reserveSessionStep, acquireSessionStep, runSessionStep, recoverSessionStep } from '../../scripts/operator/source_context_session.mjs';
import { loadBundle } from '../../scripts/operator/source_context_export.mjs';
import { runNativeProcess } from '../../scripts/lib/native-process-owner.mjs';
import { input, report, peer, json, TOKEN, withReadLabels } from './source_context_fixtures.mjs';
import { fixture } from './source_context_continue_fixtures.mjs';

const AGENT = 'fgagent_' + 'a'.repeat(64), PRINCIPAL = '8'.repeat(32);
const HOST = 'http-sponsored-agent-source-read-credential';
const BUDGET = { queries: 1, work: 16777216, payload_bytes: 33554432, source_bytes: 67108864, excerpt_bytes: 1048576 };
function labelled(raw) {
  const result = withReadLabels(raw);
  Object.assign(result.retrieval.authorization, { host: HOST, principal: PRINCIPAL });
  return result;
}
const cli = (file, args, signal) => runNativeProcess(process.execPath,
  [fileURLToPath(new URL('../../scripts/' + file, import.meta.url)), ...args],
  { timeoutMs: 10000, stdoutLimit: 1024 * 1024, stderrLimit: 1024 * 1024, signal });

for (const format of ['sha1', 'sha256']) {
  test(`${format}: sponsored source labels stay opaque, detached and read-only`, () => {
    const q = input(format), raw = labelled(report(q)), before = structuredClone(raw);
    const summary = validate(raw, q);
    assert.equal(summary.authorization.host, HOST); assert.equal(summary.authorization.principal, PRINCIPAL);
    assert.equal(summary.authorization.reusable_capability, false);
    assert.equal(summary.authority_verified, false); assert.equal(summary.agent_context_packet, false);
    assert.deepEqual(raw, before);
    for (const mutate of [a => { a.host = 'http-agent'; }, a => { a.principal = null; },
      a => { a.principal = '0'.repeat(32); }, a => { a.scope = 'sparse'; },
      a => { a.reusable_capability = true; }, a => { a.sponsor = PRINCIPAL; }]) {
      const bad = structuredClone(raw); mutate(bad.retrieval.authorization);
      assert.throws(() => validate(bad, q));
    }
  });
  test(`${format}: exact sponsored bearer reaches the existing context route once`, async t => {
    const q = input(format), raw = labelled(report(q)), p = await peer(t, (_req, res) => json(res, raw));
    const capture = await acquire(p.endpoint, AGENT, q);
    assert.equal(p.calls.length, 1); const call = p.calls[0];
    assert.equal(call.headers.authorization, 'Bearer ' + AGENT);
    assert.equal(call.headers['idempotency-key'], undefined); assert.equal(call.headers.cookie, undefined);
    assert.equal(call.url, '/team/repo.git/api/v1/source/context-initial');
    assert.equal(capture.summary.authorization.host, HOST);
    assert.ok(!JSON.stringify(capture).includes(AGENT));
  });
  test(`${format}: rotated sponsored continuation preserves source pins and the parent bundle`, async t => {
    const f = await fixture(t, input(format)); f.state.decorate = labelled;
    const result = await continueCapture(f.bundle, f.receipt.manifest_sha256, AGENT, { terms: ['untrusted'] });
    assert.equal(f.p.calls.length, 1); const form = new URLSearchParams(f.p.calls[0].body);
    assert.equal(form.get('expected_head'), f.capture.summary.source.snapshot_token);
    assert.equal(form.get('minimum_lexical_number'), f.capture.summary.lexical_checkpoint.number);
    assert.deepEqual(result.capture.summary.source, f.capture.summary.source);
    assert.equal(result.capture.summary.authorization.host, HOST);
    assert.deepEqual(await f.readParent(), f.originalBytes);
    await assert.rejects(continueCapture(f.bundle, f.receipt.manifest_sha256, AGENT,
      { terms: ['recover'], limits: { context_radius_bytes: 129 } }), /budget_widened/);
    assert.equal(f.p.calls.length, 1);
  });
  test(`${format}: private capture and continuation CLIs accept the native token and existing line endings`, async t => {
    const f = await fixture(t, input(format)); f.state.decorate = labelled;
    const query = join(f.root, 'query'), followup = join(f.root, 'followup'), token = join(f.root, 'token');
    await writeFile(query, JSON.stringify(input(format)), { mode: 0o600 });
    await writeFile(followup, '{"terms":["untrusted"]}', { mode: 0o600 });
    for (const [i, suffix] of ['', '\n', '\r\n'].entries()) {
      await writeFile(token, AGENT + suffix, { mode: 0o600 });
      const output = join(f.root, 'capture-' + i);
      const captured = await cli('fg_source_context.mjs', ['capture', '--endpoint', f.p.endpoint,
        '--query-file', query, '--token-file', token, '--output', output], t.signal);
      assert.equal(captured.code, 0, captured.stderr.toString());
      const receipt = JSON.parse(captured.stdout), saved = await loadBundle(output, receipt.manifest_sha256);
      assert.equal(saved.capture.summary.authorization.host, HOST);
      assert.ok(!(await readFile(join(output, 'capture.json'), 'utf8')).includes(AGENT));
      const continued = await cli('fg_source_context.mjs', ['continue', '--bundle', output,
        '--expected-sha256', receipt.manifest_sha256, '--followup-file', followup, '--token-file', token,
        '--output', join(f.root, 'continued-' + i)], t.signal);
      assert.equal(continued.code, 0, continued.stderr.toString());
    }
    assert.equal(f.p.calls.length, 6);
    for (const malformed of [AGENT + '\n\n', AGENT + ' ', 'FGAGENT_' + 'a'.repeat(64), 'fgagent_' + 'A'.repeat(64)]) {
      await writeFile(token, malformed);
      const rejected = await cli('fg_source_context.mjs', ['capture', '--endpoint', f.p.endpoint,
        '--query-file', query, '--token-file', token, '--output', join(f.root, 'must-not-exist')], t.signal);
      assert.equal(rejected.code, 2); assert.equal(f.p.calls.length, 6);
    }
  });
}

for (const mode of ['run', 'dispatch', 'cli-step', 'cli-dispatch']) {
  test(`sponsored ${mode} retains the one-shot session reservation and source evidence`, async t => {
    const f = await fixture(t); f.state.decorate = labelled;
    const root = join(f.root, 'session'), created = await createSession(root, f.bundle, f.receipt.manifest_sha256, BUDGET);
    const token = join(f.root, 'token'), followup = join(f.root, 'followup');
    await writeFile(token, AGENT + '\r\n', { mode: 0o600 });
    await writeFile(followup, '{"terms":["untrusted"]}', { mode: 0o600 });
    let result;
    if (mode === 'run') result = await runSessionStep(root, created.session_sha256, created.tip_sha256,
      { terms: ['untrusted'] }, AGENT);
    else if (mode === 'cli-step') {
      const child = await cli('fg_context_session.mjs', ['step', '--session', root, '--session-sha256', created.session_sha256,
        '--tip-sha256', created.tip_sha256, '--followup-file', followup, '--token-file', token], t.signal);
      assert.equal(child.code, 0, child.stderr.toString()); result = JSON.parse(child.stdout);
    } else {
      const reservation = await reserveSessionStep(root, created.session_sha256, created.tip_sha256, { terms: ['untrusted'] });
      let staged;
      if (mode === 'dispatch') staged = await acquireSessionStep(root, created.session_sha256, created.tip_sha256,
        reservation.request_sha256, AGENT);
      else {
        const child = await cli('fg_context_session.mjs', ['dispatch', '--session', root, '--session-sha256', created.session_sha256,
          '--tip-sha256', created.tip_sha256, '--request-sha256', reservation.request_sha256, '--token-file', token], t.signal);
        assert.equal(child.code, 3, child.stderr.toString()); staged = JSON.parse(child.stdout);
      }
      result = await recoverSessionStep(root, created.session_sha256, created.tip_sha256,
        reservation.request_sha256, staged.candidate_sha256);
    }
    assert.equal(result.reserved.queries, 1); assert.equal(f.p.calls.length, 1);
    const saved = await loadBundle(result.latest_bundle, result.latest_manifest_sha256);
    assert.equal(saved.capture.summary.authorization.host, HOST);
    for (const name of ['request.json', 'terminal.json']) {
      assert.ok(!(await readFile(join(root, 'steps/0001', name), 'utf8')).includes(AGENT));
    }
    assert.deepEqual(await f.readParent(), f.originalBytes);
  });
}

test('sponsored HTTP refusal and cancellation settle one read without retry or credential fallback', async t => {
  const refused = await peer(t, (_req, res) => { res.writeHead(403); res.end('refused'); });
  await assert.rejects(acquire(refused.endpoint, AGENT, input()), { code: 'context_http_refused', status: 403 });
  assert.equal(refused.calls.length, 1);
  let started; const ready = new Promise(resolve => { started = resolve; });
  const p = await peer(t, (_req, res) => { res.writeHead(200, { 'Content-Type': 'application/json' }); res.write('{'); started(); });
  const stop = new AbortController();
  const pending = acquire(p.endpoint, AGENT, input(), { signal: stop.signal, timeoutMs: 2000 }).then(
    value => ({ value }), error => ({ error }));
  assert.deepEqual(await Promise.race([ready.then(() => 'started'), pending]), 'started');
  stop.abort(); const result = await pending;
  assert.equal(result.error.code, 'context_cancelled'); assert.equal(p.calls.length, 1);
  for (const bad of ['fgagent_' + 'A'.repeat(64), AGENT + '\n', 'fgagent_' + 'a'.repeat(63)]) {
    await assert.rejects(acquire(p.endpoint, bad, input()), { code: 'invalid_source_read_token' });
  }
  assert.equal(p.calls.length, 1);
  assert.equal((await acquire(refused.endpoint, TOKEN, input()).catch(e => e)).status, 403);
});
