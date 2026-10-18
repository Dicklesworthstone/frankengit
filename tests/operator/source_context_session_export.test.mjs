// Complete production replay/export/CLI modules, real private files and HTTP
// sockets. The existing HTTP peer is a native-schema fixture, not Rust fg.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile, writeFile, readdir, lstat, chmod, symlink } from 'node:fs/promises';
import { watch } from 'node:fs';
import { join, resolve } from 'node:path';
import { spawn } from 'node:child_process';
import { fixture, input, TOKEN } from './source_context_continue_fixtures.mjs';
import { hex } from './source_context_fixtures.mjs';
import { symbolInput, assemble } from './source_context_symbols_fixtures.mjs';
import { sha256 } from '../../scripts/operator/source_context.mjs';
import { createSession, runSessionStep, inspectSession, reserveSessionStep, acquireSessionStep,
  recoverSessionStep, assembleSessionContext } from '../../scripts/operator/source_context_session.mjs';
import { exportSessionContext, inspectSessionContextExport } from '../../scripts/operator/source_context_session_export.mjs';

const file = (path, bytes) => ({ path: Buffer.from(path), bytes: Buffer.from(bytes) });
const FILES = [file('a/alpha.txt', 'alpha only\r\n'), file('b/beta.txt', 'beta only\n'),
  file('src/shared.rs', 'alpha beta gamma delta\n')];
const BUDGET = { queries: 8, work: 8 * 16777216, payload_bytes: 8 * 33554432,
  source_bytes: 8 * 67108864, excerpt_bytes: 8 * 1048576 };
async function setup(t, format = 'sha1', q = null, settings = {}) {
  const f = await fixture(t, q ?? input(format, { terms: ['alpha'], limits: { context_radius_bytes: 3 } }), { files: FILES, ...settings });
  const session = join(f.root, 'session'), created = await createSession(session, f.bundle, f.receipt.manifest_sha256, BUDGET);
  return { ...f, session, created, rootHash: created.session_sha256, tip: created.tip_sha256 };
}
async function step(f, terms, extra = {}) {
  const result = await runSessionStep(f.session, f.rootHash, f.tip, { terms, ...extra }, TOKEN);
  assert.ok(result.tip_sha256); f.tip = result.tip_sha256; return result;
}
async function tree(path) {
  const entries = [];
  async function visit(dir) {
    for (const name of (await readdir(dir)).sort()) {
      const item = join(dir, name), st = await lstat(item);
      if (st.isDirectory()) await visit(item);
      else entries.push([item.slice(path.length), sha256(await readFile(item)), st.mode & 0o777]);
    }
  }
  await visit(path); return entries;
}
const exportAt = (f, output = join(f.root, 'union'), limits = {}, options = {}) => exportSessionContext(f.session, f.rootHash, f.tip, output, limits, options);
const inspectAt = (f, result, tip = f.tip) => inspectSessionContextExport(f.session, f.rootHash, tip, result.output, result.manifest_sha256);
const CLI = resolve('scripts/fg_context_session.mjs');
async function cli(f, operation, tail = [], { lostOutput = false } = {}) {
  const args = [CLI, operation, '--session', f.session, '--session-sha256', f.rootHash, '--tip-sha256', f.tip, ...tail];
  const child = spawn(process.execPath, args, { stdio: ['ignore', 'pipe', 'pipe'] });
  const out = [], err = [];
  if (lostOutput) child.stdout.destroy(); else child.stdout.on('data', b => out.push(b));
  child.stderr.on('data', b => err.push(b));
  const timer = setTimeout(() => child.kill('SIGKILL'), 10000);
  const result = await new Promise((resolve, reject) => {
    child.once('error', reject); child.once('close', (code, signal) => resolve({ code, signal }));
  }).finally(() => clearTimeout(timer));
  return { ...result, stdout: Buffer.concat(out).toString(), stderr: Buffer.concat(err).toString() };
}

for (const format of ['sha1', 'sha256']) {
  test(`${format}: settled follow-ups export one deduplicated context with exact query provenance`, async t => {
    const f = await setup(t, format);
    for (const word of ['beta', 'gamma', 'delta']) await step(f, [word]);
    const before = await tree(f.session), calls = f.p.calls.length;
    const material = await assembleSessionContext(f.session, f.rootHash, f.tip);
    const view = material.value.context;
    assert.equal(view.query_count, 4); assert.equal(view.returned_files, 3);
    assert.deepEqual(view.queries.map(q => q.query.terms), [['alpha'], ['beta'], ['gamma'], ['delta']]);
    assert.ok(view.deduplicated_excerpt_bytes > 0);
    const shared = view.files.find(row => row.path_hex === hex('src/shared.rs'));
    assert.equal(shared.excerpts.length, 1); assert.equal(shared.excerpts[0].untrusted_bytes_hex, hex(FILES[2].bytes));
    assert.equal(shared.complete_blob_hash_verified, true); assert.deepEqual(shared.query_sequences, [0, 1, 2, 3]);
    assert.equal(material.value.session.reserved_at_tip.queries, 3);
    assert.equal(material.value.session.tip_sha256, f.tip); assert.equal(material.value.session.later_steps_not_examined, true);
    assert.ok(view.queries.every(row => row.evidence.lexical_checkpoint.number === '7'));
    const saved = await exportAt(f), checked = await inspectAt(f, saved);
    assert.equal(checked.replay_verified, true); assert.equal(saved.captured_queries, 4);
    assert.equal(saved.network_requests, 0); assert.equal(saved.aggregate_coverage_claimed, false);
    assert.equal(saved.manifest_sha256, sha256(await readFile(join(saved.output, 'manifest.json'))));
    assert.deepEqual(JSON.parse(await readFile(join(saved.output, 'context.json'))), material.value);
    assert.ok((await readFile(join(saved.output, 'context.txt'))).equals(material.text));
    assert.equal((await lstat(saved.output)).mode & 0o777, 0o700);
    for (const name of ['context.json', 'context.txt', 'manifest.json']) assert.equal((await lstat(join(saved.output, name))).mode & 0o777, 0o600);
    assert.deepEqual(await tree(f.session), before); assert.deepEqual(await f.readParent(), f.originalBytes);
    assert.equal(f.p.calls.length, calls);
  });
  test(`${format}: actual CLI export and replay inspection need no token or reachable server`, async t => {
    const f = await setup(t, format); await step(f, ['beta']);
    f.state.hang = true; const calls = f.p.calls.length;
    const output = join(f.root, 'cli-union'), run = await cli(f, 'export', ['--output', output]);
    assert.equal(run.code, 0, run.stderr); const result = JSON.parse(run.stdout);
    assert.equal(result.captured_queries, 2); assert.equal(result.network_requests, 0);
    const checked = await cli(f, 'inspect-export', ['--output', output, '--export-sha256', result.manifest_sha256]);
    assert.equal(checked.code, 0, checked.stderr); assert.equal(JSON.parse(checked.stdout).replay_verified, true);
    assert.equal(f.p.calls.length, calls);
    assert.equal(JSON.stringify(result).includes(TOKEN), false);
  });
  test(`${format}: historical prefix stays byte-identical after later queries and interrupted work`, async t => {
    const f = await setup(t, format); await step(f, ['beta']); const retainedTip = f.tip;
    const saved = await exportAt(f), body = await readFile(join(saved.output, 'context.json'));
    await step(f, ['gamma']);
    const reserved = await reserveSessionStep(f.session, f.rootHash, f.tip, { terms: ['delta'] });
    assert.ok(reserved.request_sha256);
    const checked = await inspectAt(f, saved, retainedTip); assert.equal(checked.captured_queries, 2);
    const material = await assembleSessionContext(f.session, f.rootHash, retainedTip);
    assert.ok(material.json.equals(body)); assert.equal(material.value.session.reserved_at_tip.queries, 1);
    const status = await inspectSession(f.session, f.rootHash, retainedTip);
    assert.equal(status.tip_sha256, f.tip); assert.equal(status.reserved.queries, 3); assert.equal(status.pending.state, 'reserved');
  });
}

test('base-only export is explicit, even when the session has later captures', async t => {
  const f = await setup(t); const initial = await assembleSessionContext(f.session, f.rootHash, f.rootHash);
  await step(f, ['beta']); const again = await assembleSessionContext(f.session, f.rootHash, f.rootHash);
  assert.ok(initial.json.equals(again.json)); assert.equal(again.value.context.query_count, 1);
  assert.equal(again.value.session.reserved_at_tip.queries, 0);
});
test('refused steps retain history and full reservations but never contribute fake source', async t => {
  const f = await setup(t); await step(f, ['beta']);
  f.state.status = 503; const refused = await step(f, ['gamma']); assert.equal(refused.type, 'source_context_session_refused');
  f.state.status = 200; await step(f, ['delta']);
  const material = await assembleSessionContext(f.session, f.rootHash, f.tip);
  assert.deepEqual(material.value.context.queries.map(q => q.sequence), [0, 1, 3]);
  assert.deepEqual(material.value.session.history.map(h => h.state), ['captured', 'read_refused', 'captured']);
  assert.equal(material.refused_steps, 1); assert.equal(material.value.session.reserved_at_tip.queries, 3);
  assert.ok(material.text.includes(Buffer.from('"state":"read_refused"')));
  assert.ok(material.text.includes(Buffer.from('"reserved_at_tip":{"queries":3')));
  const run = await cli(f, 'export', ['--output', join(f.root, 'refused-prefix')]);
  assert.equal(run.code, 3, run.stderr); assert.equal(JSON.parse(run.stdout).refused_steps, 1);
});
test('an unacknowledged candidate is not a captured terminal and cannot select an export tip', async t => {
  const f = await setup(t); const reserved = await reserveSessionStep(f.session, f.rootHash, f.tip, { terms: ['beta'] });
  const staged = await acquireSessionStep(f.session, f.rootHash, f.tip, reserved.request_sha256, TOKEN);
  const before = await inspectSession(f.session, f.rootHash, f.tip);
  assert.equal(before.pending.state, 'candidate');
  assert.equal((await assembleSessionContext(f.session, f.rootHash, f.tip)).value.context.query_count, 1);
  await assert.rejects(assembleSessionContext(f.session, f.rootHash, staged.candidate_sha256), /checkpoint_unavailable/);
  const recovered = await recoverSessionStep(f.session, f.rootHash, f.tip, staged.request_sha256, staged.candidate_sha256);
  assert.equal((await assembleSessionContext(f.session, f.rootHash, recovered.tip_sha256)).value.context.query_count, 2);
});
test('the same individually accepted partial captures conflict when their overlapping bytes disagree', async t => {
  const files = [file('source.rs', 'alpha   beta      gamma\n')];
  const f = await setup(t, 'sha1', null, { files });
  f.state.decorate = raw => {
    // Offset 6 lies in shared surrounding whitespace, not either matched token
    // or its immediate boundary. Both partial captures are accepted separately.
    const e = raw.files[0].excerpts[0], bytes = Buffer.from(e.untrusted_bytes_hex, 'hex');
    bytes[6 - e.byte_offset] = 88; e.untrusted_bytes_hex = hex(bytes); return raw;
  };
  const completed = await step(f, ['beta']); assert.equal(completed.history[0].state, 'captured');
  await assert.rejects(exportAt(f), /context_union_overlap_conflict/);
  await assert.rejects(lstat(join(f.root, 'union')), e => e.code === 'ENOENT');
});
test('raw bytes, empty files and required symbols retain their evidence', async t => {
  const files = [file(Buffer.from('ff2e7273', 'hex'), 'pub fn Recover() {}\r\n'), file('Recover.rs', '')];
  const q = symbolInput('sha256', { terms: ['Recover'] });
  const f = await setup(t, 'sha256', q, { files, declarations: [{ path: files[0].path, name: 'Recover', at: 7 }] });
  await step(f, ['Recover']); const m = await assembleSessionContext(f.session, f.rootHash, f.tip);
  assert.equal(m.value.context.files.length, 2); assert.equal(m.value.context.files[0].source_bytes, 0);
  assert.ok(m.value.context.files[0].complete_blob_hash_verified);
  assert.equal(m.value.context.queries[1].evidence.symbols.state, 'available');
  assert.equal(m.value.context.queries[1].query.minimum_symbol.number, '4');
  assert.ok(m.value.context.files[1].anchors.some(a => a.channel === 'symbol' && a.query_sequences.length === 2));
});
test('per-query omissions and partial hydration survive consolidation unchanged', async t => {
  const f = await setup(t, 'sha1', input('sha1', { terms: ['alpha'], limits: { context_max_files: 1 } }));
  await step(f, ['beta']); const m = await assembleSessionContext(f.session, f.rootHash, f.tip);
  assert.equal(m.all_captured_queries_complete, false); assert.equal(Object.hasOwn(m.value.context, 'complete'), false);
  assert.ok(m.value.context.queries.every(q => q.evidence.omitted_files === 1));
  const run = await cli(f, 'export', ['--output', join(f.root, 'partial')]);
  assert.equal(run.code, 3, run.stderr); assert.equal(JSON.parse(run.stdout).all_captured_queries_complete, false);
});
test('narrowed follow-up scopes never relabel the earlier broader captured paths', async t => {
  const f = await setup(t); await step(f, ['beta'], { prefixes_hex: [hex('src')] });
  const m = await assembleSessionContext(f.session, f.rootHash, f.tip);
  assert.deepEqual(m.value.context.queries[0].query.prefixes_hex, []);
  assert.deepEqual(m.value.context.queries[1].query.prefixes_hex, [hex('src')]);
  assert.ok(m.value.context.files.some(f => f.path_hex === hex('a/alpha.txt')));
  assert.equal(m.value.context.authority_verified, false); assert.equal(m.value.context.aggregate_coverage_claimed, false);
});
test('exact export caps succeed and insufficient caps refuse before creating any output', async t => {
  const f = await setup(t); await step(f, ['beta']);
  const full = await assembleSessionContext(f.session, f.rootHash, f.tip), view = full.value.context;
  const limits = { max_files: view.returned_files, max_excerpt_bytes: view.excerpt_bytes };
  assert.equal((await exportAt(f, join(f.root, 'exact'), limits)).excerpt_bytes, view.excerpt_bytes);
  for (const [name, requested] of [['bytes', { ...limits, max_excerpt_bytes: view.excerpt_bytes - 1 }],
    ['files', { ...limits, max_files: view.returned_files - 1 }], ['metadata', { max_metadata_bytes: 1 }], ['encoding', { max_output_bytes: 1 }]]) {
    const output = join(f.root, name); await assert.rejects(exportAt(f, output, requested));
    await assert.rejects(lstat(output), e => e.code === 'ENOENT');
  }
});
for (const name of ['session.json', 'base/capture.json', 'steps/0001/request.json', 'steps/0001/candidate.json', 'steps/0001/terminal.json']) {
  test(`corrupt selected ${name} withholds the entire export`, async t => {
    const f = await setup(t); await step(f, ['beta']);
    await writeFile(join(f.session, name), '{}'); await assert.rejects(exportAt(f));
    await assert.rejects(lstat(join(f.root, 'union')), e => e.code === 'ENOENT');
  });
}
test('a corrupt later suffix cannot change a checked old prefix, while ordinary status still refuses it', async t => {
  const f = await setup(t); await step(f, ['beta']); const selected = f.tip;
  const old = await assembleSessionContext(f.session, f.rootHash, selected);
  await step(f, ['gamma']); await writeFile(join(f.session, 'steps/0002/terminal.json'), '{}');
  assert.ok((await assembleSessionContext(f.session, f.rootHash, selected)).json.equals(old.json));
  await assert.rejects(inspectSession(f.session, f.rootHash, selected));
});
for (const name of ['context.json', 'context.txt']) test(`offline inspection detects ${name} changes even with rewritten local payload hashes`, async t => {
  const f = await setup(t); const saved = await exportAt(f);
  const payload = join(saved.output, name); await writeFile(payload, 'forged source\n');
  await assert.rejects(inspectAt(f, saved), /payload_changed/);
  const path = join(saved.output, 'manifest.json'), m = JSON.parse(await readFile(path));
  const row = m.files.find(r => r.name === name), bytes = await readFile(payload); row.bytes = bytes.length; row.sha256 = sha256(bytes);
  const encoded = Buffer.from(`${JSON.stringify(m)}\n`); await writeFile(path, encoded);
  await assert.rejects(inspectAt(f, { ...saved, manifest_sha256: sha256(encoded) }), /manifest_changed/);
});
test('exports from another session/tip and wrong independent pins are refused', async t => {
  const f = await setup(t); const saved = await exportAt(f);
  await assert.rejects(inspectAt(f, { ...saved, manifest_sha256: '0'.repeat(64) }), /manifest_changed/);
  await step(f, ['beta']); await assert.rejects(inspectAt(f, saved), /manifest_changed/);
  await assert.rejects(exportSessionContext(f.session, '0'.repeat(64), f.tip, join(f.root, 'wrong')), /manifest_changed/);
  await assert.rejects(assembleSessionContext(f.session, f.rootHash, '0'.repeat(64)), /checkpoint_unavailable/);
});
test('concurrent real CLI exporters create one result and preserve the winning bytes', async t => {
  const f = await setup(t); await step(f, ['beta']); const output = join(f.root, 'contended');
  const runs = await Promise.all([cli(f, 'export', ['--output', output]), cli(f, 'export', ['--output', output])]);
  assert.deepEqual(runs.map(r => r.code).sort(), [0, 2]);
  const saved = JSON.parse(runs.find(r => r.code === 0).stdout);
  assert.equal((await inspectAt(f, saved)).replay_verified, true);
  const before = await tree(output); assert.equal((await cli(f, 'export', ['--output', output])).code, 2);
  assert.deepEqual(await tree(output), before);
});
test('private custody and in-session destination rules apply before publication', async t => {
  const f = await setup(t);
  await assert.rejects(exportAt(f, join(f.session, 'export')), /inside_session/);
  const alias = join(f.root, 'alias'); await symlink(f.session, alias);
  await assert.rejects(exportAt(f, join(alias, 'export')));
  await chmod(join(f.session, 'base/capture.json'), 0o644); await assert.rejects(exportAt(f));
  await assert.rejects(lstat(join(f.root, 'union')), e => e.code === 'ENOENT');
});
test('cancellation before publication withholds output, cancellation after directory claim drains the exact export', async t => {
  const f = await setup(t), stopped = new AbortController(); stopped.abort();
  await assert.rejects(exportAt(f, join(f.root, 'stopped'), {}, { signal: stopped.signal }));
  await assert.rejects(lstat(join(f.root, 'stopped')), e => e.code === 'ENOENT');
  const late = new AbortController(), output = join(f.root, 'draining');
  const watcher = watch(f.root, (_event, name) => { if (name?.toString() === 'draining') late.abort(); });
  try {
    const saved = await exportAt(f, output, {}, { signal: late.signal }); assert.equal(late.signal.aborted, true);
    assert.equal((await inspectAt(f, saved)).replay_verified, true);
  } finally { watcher.close(); }
});
test('actual CLI preserves a committed export receipt after stdout closes', async t => {
  const f = await setup(t); const run = await cli(f, 'export', ['--output', join(f.root, 'lost-stdout')], { lostOutput: true });
  assert.equal(run.code, 4, run.stderr);
  const error = JSON.parse(run.stderr); assert.equal(error.retained_result.type, 'source_context_session_export');
  assert.equal((await inspectAt(f, error.retained_result)).replay_verified, true);
});
test('CLI refuses network credentials, unbounded selectors and missing pins on offline commands', async t => {
  const f = await setup(t), calls = f.p.calls.length;
  for (const tail of [['--token-file', join(f.root, 'token')], ['--ca-file', join(f.root, 'ca')], ['--force', 'true'],
    ['--endpoint', f.p.endpoint], ['--export-limits-file', 'relative']]) {
    const result = await cli(f, 'export', ['--output', join(f.root, 'bad'), ...tail]); assert.equal(result.code, 2);
  }
  assert.equal((await cli(f, 'inspect-export', ['--output', join(f.root, 'missing')])).code, 2);
  assert.equal(f.p.calls.length, calls);
});
test('CLI export limit file narrows only export capacity, never the session reservation ledger', async t => {
  const f = await setup(t); await step(f, ['beta']); const before = await tree(f.session);
  const path = join(f.root, 'export-limits.json'); await writeFile(path, JSON.stringify({ max_files: 1 }), { mode: 0o600 });
  const failed = await cli(f, 'export', ['--output', join(f.root, 'small'), '--export-limits-file', path]);
  assert.equal(failed.code, 2); assert.match(failed.stderr, /context_union_file_limit/);
  await writeFile(path, JSON.stringify({ max_files: 3 }));
  assert.equal((await cli(f, 'export', ['--output', join(f.root, 'enough'), '--export-limits-file', path])).code, 0);
  assert.deepEqual(await tree(f.session), before);
});

test('an optional unavailable base remains visible after a later query obtains a symbol generation', async t => {
  const files = [file('Recover.rs', 'pub fn Recover() {}\n')];
  const declarations = [{ path: files[0].path, name: 'Recover', at: 7 }];
  const q = symbolInput('sha1', { terms: ['Recover'], symbols: { name: 'Recover', policy: 'optional' } });
  const f = await setup(t, 'sha1', q, { files, declarations, decorate: (raw, selected) => {
    raw.retrieval.symbols = { state: 'unavailable', reason: 'uninitialized', result: null };
    raw.retrieval.generation_vector.symbols = null;
    return assemble(raw, selected, files);
  } });
  f.state.decorate = r => r;
  await step(f, ['Recover']);
  const material = await assembleSessionContext(f.session, f.rootHash, f.tip);
  assert.equal(material.value.context.query_count, 2);
  const [base, later] = material.value.context.queries;
  assert.equal(base.evidence.symbols.state, 'unavailable'); assert.equal(base.evidence.symbols.reason, 'uninitialized');
  assert.equal(later.evidence.symbols.state, 'available'); assert.equal(later.evidence.symbols.generation.number, '4');
  assert.equal(base.evidence.complete, false); assert.equal(later.evidence.complete, true);
  assert.equal(material.all_captured_queries_complete, false);
  const saved = await exportAt(f); assert.equal((await inspectAt(f, saved)).all_captured_queries_complete, false);
});
test('native per-channel omission catalogs survive replay and are not replaced by a combined coverage claim', async t => {
  const omission = { path_hex: hex('zz-large.bin'), blob: '9'.repeat(40), source_bytes: 11, reason: 'file_bytes', limit: 10 };
  const f = await setup(t, 'sha1', null, { decorate: (raw, selected) => {
    for (const channel of [raw.retrieval.content, raw.retrieval.path]) Object.assign(channel, {
      schema_version: 2, index_profile: 'ascii-word-postings-omissions-v1', coverage_complete: false,
      omissions: [structuredClone(omission)], omitted_files: 1, omitted_source_bytes: 11,
    });
    return assemble(raw, selected, FILES);
  } });
  await step(f, ['beta']);
  const material = await assembleSessionContext(f.session, f.rootHash, f.tip);
  for (const row of material.value.context.queries) for (const channel of ['content', 'path']) {
    assert.deepEqual(row.evidence[channel].omissions, [omission]);
    assert.equal(row.evidence[channel].coverage_complete, false);
    assert.equal(row.evidence.retrieval_complete, false);
  }
  assert.equal(material.value.context.aggregate_coverage_claimed, false);
  assert.equal(material.all_captured_queries_complete, false);
  const saved = await exportAt(f); assert.equal((await inspectAt(f, saved)).all_captured_queries_complete, false);
});
test('each query keeps its actual generation even when same-source maintenance advances the index', async t => {
  const f = await setup(t);
  f.state.decorate = r => {
    const newer = { index_token: `alg:2:${'8'.repeat(64)}`, index_number: '18446744073709551615' };
    r.retrieval.generation_vector.lexical = newer;
    for (const channel of [r.retrieval.content, r.retrieval.path]) Object.assign(channel, newer,
      { selected_index_token: newer.index_token, selected_index_number: newer.index_number });
    return r;
  };
  await step(f, ['beta']);
  const material = await assembleSessionContext(f.session, f.rootHash, f.tip);
  assert.deepEqual(material.value.context.queries.map(q => q.evidence.lexical_generation.number), ['7', '18446744073709551615']);
  assert.equal(material.value.context.queries[1].query.minimum_lexical.number, '7');
  assert.equal(material.value.context.queries[1].evidence.lexical_checkpoint.number, '18446744073709551615');
  const saved = await exportAt(f); assert.equal((await inspectAt(f, saved)).replay_verified, true);
});
