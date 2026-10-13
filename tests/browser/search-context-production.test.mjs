// Complete production CodeSearch -> Transport -> Initial/context validators ->
// full-blob verification, with real Fetch/WebCrypto/HTTP sockets. Responses are
// explicit native-schema peers from independent operator fixtures, NOT Rust fg.
// No production import is replaced, copied into a harness, or prevalidated.
import test from 'node:test';
import assert from 'node:assert/strict';
import { webcrypto } from 'node:crypto';
import { CodeSearch } from '../../crates/fgit-node/src/smart_http/server/browser/search.mjs';
import { contextReport } from '../../crates/fgit-node/src/smart_http/server/browser/search-context.mjs';
import { input, report, peer, json, TOKEN, hex } from '../operator/source_context_fixtures.mjs';
import { symbolInput, nativeSymbols, FILES, DECLARATIONS } from '../operator/source_context_symbols_fixtures.mjs';
import { nativeRanked, PROFILE, CORPUS, DECLARATIONS as RANK_DECLARATIONS } from '../operator/source_context_ranking_fixtures.mjs';

const clone = value => structuredClone(value);
const bare = value => value.slice(value.indexOf(':') + 1);
function query(q, ranked = false) {
  const limits = q.limits ?? {}, browser = { mode: 'initial', termsHex: q.terms.map(hex), prefixesHex: q.prefixes_hex ?? [],
    context: { selection: ranked ? PROFILE : 'raw-path-prefix' } };
  for (const [wire, name] of [['max_results_per_channel', 'maxMatches'], ['max_work', 'maxWork'],
    ['max_payload_bytes', 'maxPayloadBytes'], ['max_result_bytes', 'maxResultBytes']]) {
    if (Object.hasOwn(limits, wire)) browser[name] = limits[wire];
  }
  for (const [wire, name] of [['context_max_files', 'maxFiles'], ['context_radius_bytes', 'radiusBytes'],
    ['context_max_source_bytes', 'maxSourceBytes'], ['context_max_excerpt_bytes', 'maxExcerptBytes']]) {
    if (Object.hasOwn(limits, wire)) browser.context[name] = limits[wire];
  }
  if (q.symbols) browser.symbol = { nameHex: hex(q.symbols.name), match: q.symbols.match ?? 'exact',
    kinds: q.symbols.kinds ?? [], policy: q.symbols.policy ?? 'optional' };
  return browser;
}
async function fixture(t, { format = 'sha1', ranked = false, symbols = false, unavailable = null,
  files = symbols ? FILES : CORPUS, declarations = DECLARATIONS, limits = {}, override = {} } = {}) {
  const q = symbols ? symbolInput(format, { limits, ...override }) : input(format, { limits, ...override });
  let wire = ranked ? nativeRanked(q, files, declarations, unavailable)
    : symbols ? nativeSymbols(q, files, declarations, unavailable) : report(q, files);
  let intercept = null;
  const { endpoint, calls } = await peer(t, async (request, response, received) => {
    if (intercept && await intercept(request, response, received)) return;
    if (request.url.endsWith('/source/context-initial')) return json(response, wire);
    if (request.url.endsWith('/source/search-initial')) return json(response, wire.retrieval);
    if (request.url.endsWith('/source/blob')) {
      const form = new URLSearchParams(received.body), path = form.get('path_hex'), offset = Number(form.get('offset'));
      const file = files.find(file => hex(file.path) === path);
      assert.ok(file, 'only an explicitly returned fixture file is requested');
      const bytes = Buffer.from(file.bytes), end = Math.min(offset + 65536, bytes.length);
      const hit = [...wire.retrieval.content.hits, ...wire.retrieval.path.hits,
        ...(wire.retrieval.symbols.result?.matches ?? [])].find(hit => hit.path_hex === path);
      return json(response, { ...wire.retrieval.content, type: 'source_blob', path_hex: path, offset,
        symlink_followed: false, kind: 'file', object_id: hit.blob, total_bytes: bytes.length,
        content_hex: hex(bytes.subarray(offset, end)), returned_bytes: end - offset,
        next_offset: end === bytes.length ? null : end });
    }
    response.writeHead(404); response.end();
  });
  const client = new CodeSearch({ href: `${endpoint}/ui/search/`, cryptoImpl: webcrypto });
  t.after(() => client.disconnect()); await client.connect(TOKEN, q.reference, format);
  return { client, calls, q, request: query(q, ranked), files,
    get wire() { return wire; }, set wire(value) { wire = value; }, set intercept(value) { intercept = value; } };
}
function noResultOrCheckpoint(client) {
  assert.equal(client.state.result, null); assert.equal(client.state.pin, null); assert.equal(client.state.scope, null);
  assert.equal(client.state.indexMinimum, null); assert.equal(client.state.symbolMinimum, null);
}
for (const format of ['sha1', 'sha256']) for (const ranked of [false, true]) {
  test(`complete production graph accepts native qualified IDs (${format}, ranked=${ranked})`, async t => {
    const f = await fixture(t, { format, ranked, symbols: true, files: CORPUS, declarations: RANK_DECLARATIONS,
      limits: { context_max_files: 1 } });
    const original = clone(f.wire), result = await f.client.search(f.request);
    assert.equal(f.calls.length, 1); assert.deepEqual(f.wire, original, 'normalization never mutates wire receipts');
    assert.equal(result.context.files.length, 1); assert.equal(result.context.omittedFiles, 1);
    const expected = ranked ? CORPUS[1] : CORPUS[0];
    assert.equal(result.context.files[0].pathHex, hex(expected.path));
    assert.equal(result.context.files[0].blob, bare(original.files[0].blob));
    assert.equal(result.context.files[0].excerpts[0].bytesHex, hex(expected.bytes));
    assert.equal(result.context.complete, false); assert.equal(result.complete, true);
    assert.deepEqual(f.client.state.result, result);
    const sent = f.calls[0], form = new URLSearchParams(sent.body);
    assert.equal(sent.url, '/team/repo.git/api/v1/source/context-initial'); assert.equal(sent.method, 'POST');
    assert.equal(sent.headers.authorization, `Bearer ${TOKEN}`); assert.equal(sent.headers['idempotency-key'], undefined);
    assert.equal(form.get('object_format'), format); assert.equal(form.get('ref'), 'refs/heads/main');
    assert.deepEqual(form.getAll('term_hex'), [hex('recover')]); assert.equal(form.get('symbol_name_hex'), hex('Recover'));
    assert.equal(form.get('context_max_files'), '1'); assert.equal(form.get('context_selection'), ranked ? PROFILE : null);
    if (ranked) {
      const winner = result.context.ranking.selected[0];
      assert.equal(winner.score_q16, 4279); assert.deepEqual(winner.contributions.map(c => c.score_q16), [1057, 1074, 2148]);
      assert.equal(winner.blob, result.context.files[0].blob);
    }
    const exported = JSON.parse(contextReport(result));
    assert.equal(JSON.stringify(exported).includes(TOKEN), false);
    assert.equal(exported.context.files[0].blob, result.context.files[0].blob);
  });
}
for (const format of ['sha1', 'sha256']) {
  test(`full production pipeline retains legacy bare IDs (${format})`, async t => {
    const f = await fixture(t, { format, ranked: true });
    // Existing accepted wire spelling remains supported alongside native Display.
    for (const c of [f.wire.retrieval.content, f.wire.retrieval.path]) for (const h of c.hits) h.blob = bare(h.blob);
    for (const row of [...f.wire.files, ...f.wire.ranking.selected]) row.blob = bare(row.blob);
    assert.equal((await f.client.search(f.request)).context.files.length, 2);
  });
  test(`full-file navigation verifies native identity and all channels (${format})`, async t => {
    const f = await fixture(t, { format, symbols: true });
    const result = await f.client.search(f.request);
    for (const channel of ['content', 'path', 'symbols']) {
      const file = await f.client.openInitial(channel, 0);
      assert.equal(file.blobVerified, true); assert.equal(file.coverageVerified, false);
      assert.deepEqual(Buffer.from(file.bytes), FILES[0].bytes); assert.equal(file.initialChannel, channel);
      assert.deepEqual(file.pin, result.pin); assert.deepEqual(file.generationVector, result.vector);
      if (channel === 'symbols') assert.equal(file.symbolNameVerified, true);
      else assert.equal(file.wordSpansVerified, true);
    }
    assert.equal(f.calls.length, 4);
    for (const call of f.calls.slice(1)) {
      const body = new URLSearchParams(call.body);
      assert.equal(call.url, '/team/repo.git/api/v1/source/blob');
      assert.equal(body.get('expected_head'), result.pin.head); assert.equal(body.get('expected_commit'), result.pin.commit);
      assert.equal(call.headers['idempotency-key'], undefined);
    }
  });
}

test('path-only, byte-only and empty sources keep native bounds and byte coordinates', async t => {
  const files = [ { path: Buffer.from('ff2f7265636f7665722e7273', 'hex'), bytes: Buffer.from([0, 255, 60, 62]) },
    { path: Buffer.from('empty/recover.rs'), bytes: Buffer.alloc(0) } ];
  const f = await fixture(t, { files, limits: { context_radius_bytes: 0 } });
  const result = await f.client.search(f.request);
  assert.equal(result.content.hits.length, 0); assert.equal(result.path.hits.length, 2);
  assert.equal(result.context.files[0].sourceBytes, 0); assert.equal(result.context.files[0].excerpts[0].bytesHex, '');
  assert.equal(result.context.files[1].pathHex, hex(files[0].path));
  assert.equal(result.context.files[1].excerpts[0].bytesHex, '00ff');
  const file = await f.client.openInitial('path', 1);
  assert.equal(file.blobVerified, true); assert.deepEqual(Buffer.from(file.bytes), files[0].bytes);
});

test('no-match hydration returns an explicit empty result; disabled hydration stays index-only', async t => {
  const f = await fixture(t, { files: [{ path: Buffer.from('note.txt'), bytes: Buffer.from('Nothing to select.\n') }] });
  const result = await f.client.search(f.request);
  assert.equal(result.context.complete, true); assert.deepEqual(result.context.files, []);
  assert.equal(result.context.sourceBlobsRead, 0);
  const { context, ...indexOnly } = f.request;
  const second = await f.client.search(indexOnly);
  assert.equal(second.context, undefined); assert.equal(f.calls.length, 2);
  assert.equal(f.calls[1].url, '/team/repo.git/api/v1/source/search-initial');
  assert.equal([...new URLSearchParams(f.calls[1].body).keys()].some(key => key.startsWith('context_')), false);
});

test('fresh reads carry both validated generations and exact original source', async t => {
  const f = await fixture(t, { symbols: true });
  const original = await f.client.search(f.request);
  const content = f.wire.retrieval.content, path = f.wire.retrieval.path;
  path.selected_index_number = 9; path.selected_index_token = `alg:2:${'f'.repeat(64)}`;
  await f.client.search(f.request);
  const sent = new URLSearchParams(f.calls[1].body);
  assert.equal(sent.get('expected_head'), original.pin.head); assert.equal(sent.get('expected_commit'), original.pin.commit);
  assert.equal(sent.get('minimum_lexical_number'), '7'); assert.equal(sent.get('minimum_symbol_number'), '4');
  assert.equal(f.client.state.indexMinimum.number, 9);
  content.selected_index_number = 9; content.selected_index_token = path.selected_index_token;
  await f.client.search(f.request); // Both child observations satisfy the retained floor.
  assert.equal(new URLSearchParams(f.calls[2].body).get('minimum_lexical_number'), '9');
  assert.equal(content.index_number, 7, 'the queried generation is not rewritten by head observation');
});

for (const reason of ['uninitialized', 'stale']) {
  test(`optional unavailable declarations are explicit, not fabricated (${reason})`, async t => {
    const f = await fixture(t, { ranked: true, symbols: true, unavailable: reason,
      override: { symbols: { name: 'Recover', match: 'prefix', policy: 'optional' } } });
    const result = await f.client.search(f.request);
    assert.equal(result.symbols.state, 'unavailable'); assert.equal(result.complete, false);
    assert.equal(result.context.complete, false); assert.equal(result.vector.symbols, null);
    assert.equal(f.client.state.symbolMinimum, null);
    await assert.rejects(f.client.openInitial('symbols', 0)); assert.equal(f.calls.length, 1);
  });
}

const corruptIds = {
  'wrong hash domain': (value, format) => `${format === 'sha1' ? 'sha256' : 'sha1'}:${bare(value)}`,
  'wrong digest': (_, format) => `${format}:${'8'.repeat(format === 'sha1' ? 40 : 64)}`,
  'all zero': (_, format) => `${format}:${'0'.repeat(format === 'sha1' ? 40 : 64)}`,
  'upper case': value => value.toUpperCase(), 'short digest': value => value.slice(0, -1),
  'double domain': (value, format) => `${format}:${value}`, 'non-string': () => 7,
};
for (const location of ['files', 'ranking']) for (const [name, change] of Object.entries(corruptIds)) {
  test(`${location}: ${name} cannot install any result or checkpoint`, async t => {
    const format = location === 'files' ? 'sha1' : 'sha256';
    const f = await fixture(t, { format, ranked: true });
    const row = location === 'files' ? f.wire.files[0] : f.wire.ranking.selected[0];
    row.blob = change(row.blob, format);
    await assert.rejects(f.client.search(f.request), /Source context/);
    assert.equal(f.calls.length, 1); noResultOrCheckpoint(f.client);
  });
}
for (const [name, corrupt] of Object.entries({
  'inner profile': r => { r.retrieval.profile = 'invented'; },
  'inner hash domain': r => { r.retrieval.content.hits[0].blob = `sha256:${'a'.repeat(64)}`; },
  'inner scope': r => { r.retrieval.path.repository_id = '9'.repeat(32); },
  'inner source pin': r => { r.retrieval.path.source_commit = `sha1:${'1'.repeat(40)}`; },
  'inner vector': r => { r.retrieval.generation_vector.lexical.index_number++; },
  'inner retained accounting': r => { r.retrieval.retained_result_bytes++; },
  'outer byte accounting': r => { r.source_bytes_read++; },
  'outer selection': r => { r.ranking.selected.reverse(); },
  'outer excerpt': r => { r.files[0].excerpts[0].untrusted_bytes_hex = '00'; },
})) {
  test(`${name}: the real validators reject before state installation`, async t => {
    const f = await fixture(t, { ranked: true }); corrupt(f.wire);
    await assert.rejects(f.client.search(f.request)); noResultOrCheckpoint(f.client); assert.equal(f.calls.length, 1);
  });
}

test('failed hydration cannot poison previously validated pins or generation floors', async t => {
  const f = await fixture(t, { symbols: true, ranked: true });
  await f.client.search(f.request); const before = f.client.state;
  for (const child of [f.wire.retrieval.content, f.wire.retrieval.path]) child.selected_index_number = 99;
  f.wire.files[0].blob = `sha1:${'0'.repeat(40)}`;
  await assert.rejects(f.client.search(f.request));
  assert.equal(f.client.state.result, null); assert.deepEqual(f.client.state.pin, before.pin);
  assert.deepEqual(f.client.state.indexMinimum, before.indexMinimum); assert.deepEqual(f.client.state.symbolMinimum, before.symbolMinimum);
  assert.equal(f.calls.length, 2);
});

test('multi-page full-blob verification preserves exact snapshot and byte identity', async t => {
  const bytes = Buffer.concat([Buffer.from('recover\n'), Buffer.alloc(140000, 32)]);
  const f = await fixture(t, { format: 'sha256', files: [{ path: Buffer.from('recover.txt'), bytes }] });
  const result = await f.client.search(f.request), file = await f.client.openInitial('content', 0);
  assert.equal(file.blobVerified, true); assert.deepEqual(Buffer.from(file.bytes), bytes);
  assert.equal(f.calls.length, 4);
  assert.deepEqual(f.calls.slice(1).map(c => Number(new URLSearchParams(c.body).get('offset'))), [0, 65536, 131072]);
  for (const call of f.calls.slice(1)) assert.equal(new URLSearchParams(call.body).get('expected_head'), result.pin.head);
});

for (const failure of ['bytes', 'snapshot']) {
  test(`full-file navigation refuses changed ${failure} instead of authenticating an excerpt`, async t => {
    const f = await fixture(t); const result = await f.client.search(f.request);
    f.intercept = (_, response, received) => {
      if (!received.url.endsWith('/source/blob')) return false;
      const hit = result.content.hits[0], data = Buffer.from(f.files[0].bytes);
      if (failure === 'bytes') data[data.length - 1] ^= 1;
      const raw = { ...f.wire.retrieval.content, type: 'source_blob', path_hex: hit.pathHex, offset: 0,
        symlink_followed: false, kind: 'file', object_id: `sha1:${hit.blob}`, total_bytes: data.length,
        content_hex: hex(data), returned_bytes: data.length, next_offset: null };
      if (failure === 'snapshot') raw.snapshot_token = `alg:2:${'e'.repeat(64)}`;
      json(response, raw); return true;
    };
    await assert.rejects(f.client.openInitial('content', 0), failure === 'bytes' ? /blob identity/ : /snapshot changed/);
    assert.equal(f.calls.length, 2); assert.deepEqual(f.client.state.pin, result.pin);
  });
}
