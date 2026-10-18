import test from 'node:test';
import assert from 'node:assert/strict';
import { acquire, query, command, validate, parse, endpoint, LIMITS } from '../../scripts/operator/source_context.mjs';
import { input, report, peer, json, TOKEN, hex } from './source_context_fixtures.mjs';

for (const format of ['sha1', 'sha256']) {
  test(`${format}: native joined retrieval and hydration are consumed with one closed read`, async t => {
    const q = input(format), raw = report(q), p = await peer(t, (_req, res) => json(res, raw));
    const result = await acquire(p.endpoint, TOKEN, q);
    assert.equal(p.calls.length, 1); const call = p.calls[0];
    assert.equal(call.url, '/team/repo.git/api/v1/source/context-initial'); assert.equal(call.method, 'POST');
    assert.equal(call.headers.authorization, `Bearer ${TOKEN}`); assert.equal(call.headers['idempotency-key'], undefined);
    assert.equal(call.headers.cookie, undefined); assert.equal(call.headers['accept-encoding'], 'identity');
    const form = new URLSearchParams(call.body); assert.equal(form.get('object_format'), format); assert.deepEqual(form.getAll('term_hex'), [hex('recover')]);
    assert.equal(result.summary.returned_files, 1); assert.equal(result.summary.complete, true);
    assert.deepEqual(result.summary.full_blob_hash_verified_paths, [hex('src/recover.rs')]);
    assert.equal(result.summary.authority_verified, false); assert.equal(result.summary.agent_context_packet, false);
    assert.ok(!JSON.stringify(result).includes(TOKEN));
  });
  test(`${format}: independently selected source and lexical checkpoint are retained`, async t => {
    const raw = report(input(format)), q = input(format, { expected_head: raw.retrieval.snapshot_token,
      expected_commit: raw.retrieval.source_commit, minimum_lexical: { token: raw.retrieval.generation_vector.lexical.index_token, number: '7' } });
    const p = await peer(t, (_req, res) => json(res, raw)); const capture = await acquire(p.endpoint, TOKEN, q);
    const fields = new URLSearchParams(p.calls[0].body);
    assert.equal(fields.get('expected_head'), q.expected_head); assert.equal(fields.get('expected_commit'), q.expected_commit.slice(format.length + 1));
    assert.equal(fields.get('minimum_lexical_number'), '7'); assert.equal(capture.summary.lexical_checkpoint.number, '7');
    await assert.rejects(acquire(p.endpoint, TOKEN, { ...q, expected_commit: 'e'.repeat(format === 'sha1' ? 40 : 64) }), /snapshot_changed/);
  });
  test(`${format}: corrupted complete source is refused, not downloaded`, async t => {
    const q = input(format), raw = report(q); raw.files[0].excerpts[0].untrusted_bytes_hex = raw.files[0].excerpts[0].untrusted_bytes_hex.replace('666e', '686e');
    const p = await peer(t, (_req, res) => json(res, raw)); await assert.rejects(acquire(p.endpoint, TOKEN, q), /blob_hash_mismatch/);
  });
}

test('literal byte scope, canonical words, copies and budgets are normalized before network work', () => {
  const original = input('sha1', { terms: ['RECOVER', 'recover'], prefixes_hex: [hex('src'), hex('src')] });
  const selected = query(original); original.terms[0] = 'changed'; original.scope.tenant_id = 'e'.repeat(32);
  assert.deepEqual(selected.terms, ['recover']); assert.deepEqual(selected.prefixes_hex, [hex('src')]); assert.equal(selected.scope.tenant_id, '1'.repeat(32));
  for (const patch of [{ terms: ['not words'] }, { terms: [] }, { terms: ['a'.repeat(129)] }, { force: true }, { symbol: 'Secret' },
    { prefixes_hex: [hex('../host')] }, { prefixes_hex: [hex('src/.Git/private')] }, { limits: { context_max_files: 0 } },
    { limits: { context_radius_bytes: -1 } }, { limits: { max_work: 1 } }, { expected_commit: '0'.repeat(40) },
    { minimum_lexical: { token: `alg:2:${'a'.repeat(64)}`, number: '18446744073709551616' } }]) assert.throws(() => command(input('sha1', patch)));
});

test('raw non-UTF-8 paths, source NULs, CRLF and missing final LF remain exact data', async t => {
  const q = input('sha1', { prefixes_hex: ['ff'] }), raw = report(q, [{ path: Buffer.from('ff2f7265636f766572', 'hex'), bytes: Buffer.from('recover\0\r\n<script>') }]);
  const p = await peer(t, (_req, res) => json(res, raw)); const capture = await acquire(p.endpoint, TOKEN, q);
  assert.equal(capture.native_response.files[0].path_hex, 'ff2f7265636f766572');
  assert.equal(capture.native_response.files[0].excerpts[0].untrusted_bytes_hex, hex('recover\0\r\n<script>'));
});

test('path-only matches use a file preamble rather than path offsets, including empty files', () => {
  const q = input('sha1', { limits: { context_radius_bytes: 0 } });
  const raw = report(q, [{ path: Buffer.from('deep/recover/empty'), bytes: Buffer.alloc(0) }, { path: Buffer.from('deep/recover/other'), bytes: Buffer.from('ABCD') }]);
  const result = validate(raw, q); assert.equal(result.excerpt_bytes, 2);
  assert.equal(raw.files[1].excerpts[0].byte_offset, 0); assert.equal(raw.files[1].excerpts[0].untrusted_bytes_hex, hex('AB'));
  assert.deepEqual(result.full_blob_hash_verified_paths, [hex('deep/recover/empty')]);
});

test('overlapping content windows merge, zero radius is respected, and partial hashes are not claimed', () => {
  const q = input('sha1', { terms: ['one', 'two'], limits: { context_radius_bytes: 0 } });
  const raw = report(q, [{ path: Buffer.from('f'), bytes: Buffer.from('x one two y') }]);
  assert.equal(raw.files[0].excerpts.length, 2); assert.equal(validate(raw, q).full_blob_hash_verified_paths.length, 0);
  const wide = { ...q, limits: { context_radius_bytes: 2 } }, joined = report(wide, [{ path: Buffer.from('f'), bytes: Buffer.from('x one two y') }]);
  assert.equal(joined.files[0].excerpts.length, 1); assert.equal(validate(joined, wide).full_blob_hash_verified_paths.length, 1);
});

test('file-count truncation is explicit and does not silently drop selected hydration failures', () => {
  const q = input('sha1', { limits: { context_max_files: 1 } }), raw = report(q, [
    { path: Buffer.from('a'), bytes: Buffer.from('recover') }, { path: Buffer.from('b'), bytes: Buffer.from('recover') }]);
  const result = validate(raw, q); assert.equal(result.complete, false); assert.equal(result.candidate_files, 2); assert.equal(result.omitted_files, 1);
  const missing = structuredClone(raw); missing.files = []; assert.throws(() => validate(missing, q), /selection/);
});

test('retrieval result-limit exhaustion is not a complete context even after hydrating every returned hit', () => {
  const q = input('sha1', { limits: { max_results_per_channel: 1 } }), raw = report(q, [
    { path: Buffer.from('a'), bytes: Buffer.from('recover') }, { path: Buffer.from('b'), bytes: Buffer.from('recover') }]);
  assert.equal(raw.omitted_files, 0); assert.equal(validate(raw, q).complete, false);
});

test('complete empty search is distinct from unavailable, omitted or incomplete search', async t => {
  const q = input(), raw = report(q, [{ path: Buffer.from('file'), bytes: Buffer.from('nothing') }]);
  assert.equal(validate(raw, q).returned_files, 0); assert.equal(validate(raw, q).complete, true);
  const p = await peer(t, (_req, res) => { res.writeHead(409, { 'Content-Type': 'application/json' }); res.end('{"error":"source_index_stale"}'); });
  await assert.rejects(acquire(p.endpoint, TOKEN, q), e => e.status === 409); assert.equal(p.calls.length, 1);
});

const corruptions = {
  tenant: r => r.retrieval.tenant_id = 'e'.repeat(32), incarnation: r => r.retrieval.repository_incarnation = 'e'.repeat(32),
  authority: r => r.read_only = false, trust: r => r.source_material_untrusted = false,
  native_profile: r => r.profile = 'agent_context_packet', query: r => r.retrieval.path.terms_hex = [hex('other')],
  scope: r => r.retrieval.path.ref_hex = hex('refs/heads/private'), snapshot: r => r.retrieval.path.snapshot_token = `alg:2:${'e'.repeat(64)}`,
  generation: r => r.retrieval.path.index_number++, work: r => r.retrieval.completed_work_units++,
  retained: r => r.retrieval.retained_result_bytes++, document: r => r.retrieval.path.hits[0].document_id++,
  source_total: r => r.source_bytes_read++, excerpt_total: r => r.excerpt_bytes++,
  file_share: r => r.source_file_limit++, missing_anchor: r => r.files[0].anchors.pop(),
  foreign_blob: r => r.files[0].blob = 'e'.repeat(40), file_order: r => r.files[0].path_hex = hex('other'),
  missing_window: r => r.files[0].excerpts = [], range_offset: r => r.files[0].excerpts[0].byte_offset++,
  partial_success: r => r.files.pop(), budget_echo: r => r.context_radius_bytes++,
  false_omission: r => r.omitted_files++, forbidden_symbols: r => r.retrieval.symbols = { state: 'available', result: {} },
  false_complete: r => r.complete = false, extra_window: r => r.files[0].excerpts.push(r.files[0].excerpts[0]),
  source_changed: r => r.retrieval.content.source_rcr = 'foreign-record', oversized_hit: r => r.retrieval.content.hits[0].content_bytes = LIMITS.file + 1,
};
for (const [name, change] of Object.entries(corruptions)) test(`native context corruption refuses: ${name}`, () => {
  const q = input(), raw = report(q); change(raw); assert.throws(() => validate(raw, q));
});

test('omission inventory is retained and prevents a complete-coverage claim', () => {
  const q = input(), raw = report(q), omissions = [{ path_hex: hex('large'), blob: 'e'.repeat(40), source_bytes: 100, reason: 'file_bytes', limit: 50 }];
  for (const c of [raw.retrieval.content, raw.retrieval.path]) Object.assign(c, { schema_version: 2, index_profile: 'ascii-word-postings-omissions-v1',
    coverage_complete: false, omitted_files: 1, omitted_source_bytes: 100, omissions: structuredClone(omissions) });
  raw.retrieval.retained_result_bytes += 2 * (5 + 96); raw.retrieval.complete = raw.complete = false;
  assert.equal(validate(raw, q).complete, false);
  const bad = structuredClone(raw); bad.retrieval.path.omissions[0].blob = 'f'.repeat(40); assert.throws(() => validate(bad, q));
});

test('maintenance may advance observed checkpoints without rewriting the queried generation', () => {
  const q = input(), raw = report(q);
  raw.retrieval.path.selected_index_number = 9; raw.retrieval.path.selected_index_token = `alg:2:${'e'.repeat(64)}`;
  assert.equal(validate(raw, q).lexical_checkpoint.number, '9'); assert.equal(validate(raw, q).lexical_generation.number, '7');
  raw.retrieval.content.selected_index_number = 9; assert.throws(() => validate(raw, q), /conflicting/);
});

test('full u64 index identities survive numeric JSON without rounding', () => {
  const q = input(), raw = report(q);
  for (const c of [raw.retrieval.content, raw.retrieval.path]) { c.index_number = c.selected_index_number = '18446744073709551615'; c.hits[0].document_id = '18446744073709551615'; }
  raw.retrieval.generation_vector.lexical.index_number = '18446744073709551615';
  const wire = JSON.stringify(raw).replaceAll('"18446744073709551615"', '18446744073709551615');
  assert.equal(validate(parse(Buffer.from(wire)), q).lexical_generation.number, '18446744073709551615');
  assert.throws(() => parse(Buffer.from(wire.replaceAll('18446744073709551615', '18446744073709551616'))));
});

for (const status of [301, 302, 401, 403, 404, 413, 429, 500, 503]) test(`HTTP ${status} never redirects, retries or returns empty context`, async t => {
  const p = await peer(t, (_req, res) => { res.writeHead(status, { Location: '/other' }); res.end('rejected'); });
  await assert.rejects(acquire(p.endpoint, TOKEN, input()), e => e.status === status); assert.equal(p.calls.length, 1);
});

test('query and credential failures happen before a connection', async t => {
  const p = await peer(t, (_req, res) => json(res, report()));
  for (const token of ['', TOKEN.toUpperCase().replace('9', 'A'), TOKEN + '0', TOKEN + '\r\nX: y']) await assert.rejects(acquire(p.endpoint, token, input()));
  await assert.rejects(acquire(p.endpoint, TOKEN, input('sha1', { force: true })));
  await assert.rejects(acquire(p.endpoint, TOKEN, input(), { method: 'POST', key: 'key' }));
  assert.equal(p.calls.length, 0);
});

test('ambiguous endpoints and plaintext DNS names are not accepted', () => {
  for (const url of ['http://localhost/r.git', 'http://example.org/r.git', 'https://x/r.git?token=x', 'https://u:p@x/r.git',
    'https://x/r.git/', 'https://x/a/../r.git', 'https://x/r.git#x', 'ftp://x/r.git', 'https://x//r.git']) assert.throws(() => endpoint(url), url);
  assert.equal(endpoint('https://forge.example/team/r.git'), 'https://forge.example/team/r.git');
});

test('decoded JSON must be UTF-8, bounded, exact integers and supported records', () => {
  for (const bytes of [Buffer.from([255]), Buffer.from('\ufeff{}'), Buffer.from('{'), Buffer.from('{"n":9007199254740993}'),
    Buffer.alloc(LIMITS.response + 1), Buffer.from('{"index_number":1.5}')]) assert.throws(() => parse(bytes));
  for (const value of [null, [], {}, { type: 'source_context_initial' }]) assert.throws(() => validate(value, input()));
});

test('cancellation closes the active read; no prefix or retry is returned', async t => {
  let started; const ready = new Promise(r => { started = r; });
  const p = await peer(t, (_req, res) => { res.writeHead(200, { 'Content-Type': 'application/json' }); res.write('{'); started(); });
  const stop = new AbortController(), pending = acquire(p.endpoint, TOKEN, input(), { signal: stop.signal });
  await ready; stop.abort(); await assert.rejects(pending, /cancelled/); assert.equal(p.calls.length, 1);
});

test('one total deadline bounds a silent peer', async t => {
  const p = await peer(t, () => {}); const before = performance.now();
  await assert.rejects(acquire(p.endpoint, TOKEN, input(), { timeoutMs: 50 }), /deadline/);
  assert.ok(performance.now() - before < 2000); assert.equal(p.calls.length, 1);
});

for (const [name, handler] of [
  ['wrong media', (_req, res) => { res.writeHead(200, { 'Content-Type': 'text/html' }); res.end('{}'); }],
  ['compressed wire', (_req, res) => { res.writeHead(200, { 'Content-Type': 'application/json', 'Content-Encoding': 'gzip' }); res.end('{}'); }],
  ['oversized framing', (_req, res) => { res.writeHead(200, { 'Content-Type': 'application/json', 'Content-Length': String(LIMITS.response + 1) }); res.flushHeaders(); }],
  ['truncated response', (_req, res) => { res.writeHead(200, { 'Content-Type': 'application/json', 'Content-Length': '100' }); res.end('{}'); }],
]) test(`response refusal: ${name}`, async t => {
  const p = await peer(t, handler); await assert.rejects(acquire(p.endpoint, TOKEN, input(), { timeoutMs: 300 })); assert.equal(p.calls.length, 1);
});

test('caller mutation after acquisition cannot substitute scope or source limits', async t => {
  const q = input(), raw = report(q), p = await peer(t, (_req, res) => json(res, raw));
  const running = acquire(p.endpoint, TOKEN, q); q.scope.repository_id = 'e'.repeat(32); q.terms[0] = 'secret';
  const result = await running; assert.equal(result.summary.query.terms[0], 'recover'); assert.equal(result.summary.source.repository_id, '2'.repeat(32));
});

test('verified private-CA TLS succeeds; untrusted and wrong-name certificates refuse without downgrade', async t => {
  const { createServer } = await import('node:https');
  const { mkdtemp, readFile, rm } = await import('node:fs/promises');
  const { tmpdir } = await import('node:os'); const { join } = await import('node:path');
  const { spawnSync } = await import('node:child_process');
  const root = await mkdtemp(join(tmpdir(), 'fg-context-tls-')); t.after(() => rm(root, { recursive: true, force: true }));
  const key = join(root, 'key.pem'), cert = join(root, 'cert.pem');
  const generated = spawnSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1', '-subj', '/CN=localhost',
    '-addext', 'subjectAltName=DNS:localhost', '-keyout', key, '-out', cert], { encoding: 'utf8', timeout: 10000 });
  assert.equal(generated.status, 0, generated.error?.message ?? generated.stderr);
  let requests = 0;
  const server = createServer({ key: await readFile(key), cert: await readFile(cert) }, (req, res) => {
    requests++; req.resume(); req.on('end', () => json(res, report()));
  });
  server.on('tlsClientError', () => {});
  await new Promise(resolve => server.listen(0, resolve)); t.after(() => new Promise(resolve => server.close(resolve)));
  const port = server.address().port, address = `https://localhost:${port}/repo.git`, ca = await readFile(cert);
  assert.equal((await acquire(address, TOKEN, input(), { ca })).summary.complete, true);
  await assert.rejects(acquire(address, TOKEN, input()), /transport_unavailable/);
  await assert.rejects(acquire(`https://127.0.0.1:${port}/repo.git`, TOKEN, input(), { ca }), /transport_unavailable/);
  assert.equal(requests, 1);
});

test('scope and decode budgets can fail a valid native response without returning partial material', async t => {
  const raw = report(), q = input('sha1', { limits: { context_max_source_bytes: 8, context_max_excerpt_bytes: 8 } });
  raw.context_max_source_bytes = raw.context_max_excerpt_bytes = 8; raw.source_file_limit = 8;
  const p = await peer(t, (_req, res) => json(res, raw)); await assert.rejects(acquire(p.endpoint, TOKEN, q));
  assert.equal(p.calls.length, 1);
});

test('already cancelled acquisition does not contact the source', async t => {
  const p = await peer(t, (_req, res) => json(res, report())), controller = new AbortController(); controller.abort();
  await assert.rejects(acquire(p.endpoint, TOKEN, input(), { signal: controller.signal })); assert.equal(p.calls.length, 0);
});
