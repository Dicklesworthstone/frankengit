// Production clients, private bundles and real sockets with explicit schema
// peers. These tests do not execute Rust or authenticate remote authority.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { acquire, sha256 } from '../../scripts/operator/source_context.mjs';
import { continueCapture, continuationQuery } from '../../scripts/operator/source_context_continue.mjs';
import { loadBundle, publishBundle, inspectBundle } from '../../scripts/operator/source_context_export.mjs';
import { createSession, runSessionStep, inspectSession, assembleSessionContext,
  reserveSessionStep, recoverSessionStep, SESSION_PROFILE }
  from '../../scripts/operator/source_context_session.mjs';
import { exportSessionContext, inspectSessionContextExport }
  from '../../scripts/operator/source_context_session_export.mjs';
import { fixture, input, TOKEN } from './source_context_continue_fixtures.mjs';
import { withRevalidatedSources } from './source_context_revalidated_fixtures.mjs';

const MODE = 'current-native-v1';
const budget = { queries: 2, work: 2 * 16777216, payload_bytes: 2 * 33554432,
  source_bytes: 2 * 67108864, excerpt_bytes: 2 * 262144 };
const setup = (t, format) => fixture(t, input(format, { index_source: MODE }),
  { decorate: raw => withRevalidatedSources(raw) });

for (const format of ['sha1', 'sha256']) {
  test(`${format}: revalidated continuation retains original index provenance and the current source pin`, async t => {
    const f = await setup(t, format), summary = f.capture.summary;
    assert.notEqual(summary.current_source.snapshot_token, summary.index_sources.lexical.snapshot_token);
    assert.equal(f.receipt.index_source, MODE);
    assert.deepEqual(f.receipt.index_sources, summary.index_sources);
    const text = await readFile(join(f.bundle, 'context.txt'), 'utf8');
    assert.ok(text.includes(JSON.stringify(summary.current_source)));
    assert.ok(text.includes(JSON.stringify(summary.index_sources)));

    const prepared = continuationQuery(summary, { terms: ['untrusted'] });
    assert.equal(prepared.index_source, MODE);
    assert.equal(prepared.expected_head, summary.source.snapshot_token);
    assert.deepEqual(prepared.minimum_lexical, summary.lexical_checkpoint);
    const { capture } = await continueCapture(f.bundle, f.receipt.manifest_sha256, TOKEN, { terms: ['untrusted'] });
    assert.deepEqual(capture.summary.source, summary.source);
    assert.deepEqual(capture.summary.index_sources, summary.index_sources);
    const form = new URLSearchParams(f.p.calls[0].body);
    assert.equal(form.get('index_source'), MODE);
    assert.equal(form.get('expected_head'), summary.current_source.snapshot_token);
    assert.notEqual(form.get('expected_head'), summary.index_sources.lexical.snapshot_token);
    assert.equal(form.get('minimum_lexical_number'), summary.lexical_checkpoint.number);
    const saved = await publishBundle(join(f.root, 'followup'), capture);
    const restored = await loadBundle(saved.bundle, saved.manifest_sha256);
    assert.deepEqual(restored.capture.summary, capture.summary);
    assert.deepEqual((await inspectBundle(saved.bundle, saved.manifest_sha256)).index_sources, summary.index_sources);
    assert.deepEqual(await f.readParent(), f.originalBytes);
  });

  test(`${format}: durable session exports retain each query's original sources and cumulative reservations`, async t => {
    const f = await setup(t, format), root = join(f.root, 'session');
    const created = await createSession(root, f.bundle, f.receipt.manifest_sha256, budget);
    const completed = await runSessionStep(root, created.session_sha256, created.tip_sha256,
      { terms: ['untrusted'] }, TOKEN);
    assert.equal(completed.reserved.queries, 1);
    assert.equal(completed.reserved.work, 16777216);
    assert.equal(completed.history[0].state, 'captured');
    const material = await assembleSessionContext(root, created.session_sha256, completed.tip_sha256);
    assert.equal(material.value.context.queries.length, 2);
    assert.deepEqual(material.value.context.source, f.capture.summary.source);
    for (const captured of material.value.context.queries) {
      assert.equal(captured.query.index_source, MODE);
      assert.equal(captured.evidence.index_source, MODE);
      assert.deepEqual(captured.evidence.current_source, f.capture.summary.current_source);
      assert.deepEqual(captured.evidence.index_sources, f.capture.summary.index_sources);
    }
    assert.ok(material.text.toString().includes('"index_sources"'));
    const output = join(f.root, 'union');
    const exported = await exportSessionContext(root, created.session_sha256, completed.tip_sha256, output);
    const replay = await inspectSessionContextExport(root, created.session_sha256,
      completed.tip_sha256, output, exported.manifest_sha256);
    assert.equal(replay.replay_verified, true);
    assert.deepEqual((await inspectSession(root, created.session_sha256, completed.tip_sha256)).reserved, completed.reserved);
    assert.deepEqual(await f.readParent(), f.originalBytes);
  });

  test(`${format}: metadata movement requires a new capture and cannot silently advance a saved session`, async t => {
    const f = await setup(t, format), root = join(f.root, 'session');
    const created = await createSession(root, f.bundle, f.receipt.manifest_sha256, budget);
    f.state.decorate = raw => withRevalidatedSources(raw, { currentDigit: 'e' });
    await assert.rejects(continueCapture(f.bundle, f.receipt.manifest_sha256, TOKEN,
      { terms: ['recover'] }), /context_source_snapshot_changed/);
    const refused = await runSessionStep(root, created.session_sha256, created.tip_sha256,
      { terms: ['recover'] }, TOKEN);
    assert.equal(refused.type, 'source_context_session_refused');
    const state = await inspectSession(root, created.session_sha256, refused.tip_sha256);
    assert.deepEqual(state.source, f.capture.summary.source);
    assert.equal(state.reserved.queries, 1);
    assert.equal(state.history[0].state, 'read_refused');
    assert.equal(state.latest_manifest_sha256, f.receipt.manifest_sha256);
    const fresh = await acquire(f.p.endpoint, TOKEN, input(format, { index_source: MODE }));
    assert.notEqual(fresh.summary.source.snapshot_token, f.capture.summary.source.snapshot_token);
    assert.equal(fresh.summary.source.source_commit, f.capture.summary.source.source_commit);
    assert.deepEqual(fresh.summary.index_sources, f.capture.summary.index_sources);
    assert.equal(f.p.calls.length, 3);
    assert.deepEqual(await f.readParent(), f.originalBytes);
  });

  test(`${format}: a matching head cannot conceal a changed current forge position on follow-up or session acquisition`, async t => {
    const f = await setup(t, format), root = join(f.root, 'session');
    const created = await createSession(root, f.bundle, f.receipt.manifest_sha256, budget);
    f.state.decorate = raw => {
      const next = withRevalidatedSources(raw);
      next.retrieval.current_source.forge_position_root = `alg:2:${'4'.repeat(64)}`;
      if (Object.hasOwn(next.retrieval, 'forge_position_root')) {
        next.retrieval.forge_position_root = next.retrieval.current_source.forge_position_root;
      }
      return next;
    };
    await assert.rejects(continueCapture(f.bundle, f.receipt.manifest_sha256, TOKEN,
      { terms: ['recover'] }), /context_followup_source_changed/);
    const refused = await runSessionStep(root, created.session_sha256, created.tip_sha256,
      { terms: ['recover'] }, TOKEN);
    assert.equal(refused.type, 'source_context_session_refused');
    const state = await inspectSession(root, created.session_sha256, refused.tip_sha256);
    assert.deepEqual(state.source, f.capture.summary.source);
    assert.equal(state.reserved.queries, 1);
    assert.equal(state.latest_manifest_sha256, f.receipt.manifest_sha256);
    assert.deepEqual(await f.readParent(), f.originalBytes);
  });
}

test('recovery refuses an internally valid candidate whose complete current source differs from its parent', async t => {
  const f = await setup(t, 'sha256'), root = join(f.root, 'session');
  const created = await createSession(root, f.bundle, f.receipt.manifest_sha256, budget);
  const followup = { terms: ['untrusted'] };
  const reserved = await reserveSessionStep(root, created.session_sha256, created.tip_sha256, followup);
  f.state.decorate = raw => {
    const next = withRevalidatedSources(raw);
    next.retrieval.current_source.forge_position_root = `alg:2:${'4'.repeat(64)}`;
    if (Object.hasOwn(next.retrieval, 'forge_position_root')) {
      next.retrieval.forge_position_root = next.retrieval.current_source.forge_position_root;
    }
    return next;
  };
  const capture = await acquire(f.p.endpoint, TOKEN, continuationQuery(f.capture.summary, followup));
  assert.deepEqual(capture.summary.source, f.capture.summary.source);
  assert.notDeepEqual(capture.summary.current_source, f.capture.summary.current_source);
  const step = join(root, 'steps', '0001');
  await writeFile(join(step, 'started.json'), `${JSON.stringify({ schema: `${SESSION_PROFILE}/started`,
    request_sha256: reserved.request_sha256 })}\n`, { mode: 0o600, flag: 'wx' });
  const saved = await publishBundle(join(step, 'bundle'), capture);
  const candidate = Buffer.from(`${JSON.stringify({ schema: `${SESSION_PROFILE}/candidate`,
    request_sha256: reserved.request_sha256, manifest_sha256: saved.manifest_sha256,
    capture_sha256: saved.capture_sha256, text_sha256: saved.text_sha256 })}\n`);
  await writeFile(join(step, 'candidate.json'), candidate, { mode: 0o600, flag: 'wx' });
  await assert.rejects(recoverSessionStep(root, created.session_sha256, created.tip_sha256,
    reserved.request_sha256, sha256(candidate)), /context_session_capture_changed/);
  await assert.rejects(readFile(join(step, 'terminal.json')), { code: 'ENOENT' });
  assert.equal(f.p.calls.length, 1);
  assert.deepEqual(await f.readParent(), f.originalBytes);
});

test('a follow-up cannot replace its inherited index mode or select ranked revalidation', async t => {
  const f = await setup(t, 'sha1');
  for (const index_source of [null, 'current-native-v1', 'current-native-v2']) {
    await assert.rejects(continueCapture(f.bundle, f.receipt.manifest_sha256, TOKEN,
      { terms: ['recover'], index_source }), /invalid_context_followup_fields/);
  }
  await assert.rejects(continueCapture(f.bundle, f.receipt.manifest_sha256, TOKEN,
    { terms: ['recover'], selection: 'context-weighted-rrf-q16-v1' }), /unsupported_context_selection/);
  assert.equal(f.p.calls.length, 0);
  assert.deepEqual(await f.readParent(), f.originalBytes);
});
