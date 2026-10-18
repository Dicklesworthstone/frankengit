// Explicit native-schema / already-validated Initial fixtures. These unit tests
// are not a live Rust server, authorization test, or authenticity proof.
import test from 'node:test';
import assert from 'node:assert/strict';
import { CONTEXT_DEFAULTS, CONTEXT_PROFILE, contextLimits, splitContextQuery, contextCommand,
  contextReply, joinInitialContext } from '../../crates/fgit-node/src/smart_http/server/browser/search-context.mjs';
import { fixture, check, limitsFor, hex, copy, oid } from './search-context-fixtures.mjs';
for (const algorithm of ['sha1', 'sha256']) test(`deduplicates all three native channels (${algorithm}), retaining exact evidence`, () => {
  const f = fixture(algorithm), saved = copy(f);
  const result = check(f);
  assert.deepEqual(copy(f), saved);
  assert.equal(result.files.length, 1); assert.equal(result.candidateFiles, 1);
  assert.equal(result.sourceBytesRead, 18); assert.equal(result.excerptBytes, 18);
  assert.equal(result.files[0].blob, oid(f.bytes, algorithm));
  assert.deepEqual(result.files[0].anchors.map(a => a.channel), ['content', 'path', 'symbol']);
  assert.equal(result.files[0].excerpts[0].bytesHex, hex(f.bytes));
  assert.equal(result.sourceMaterialUntrusted, true); assert.equal('verified' in result, false);
});
test('explicit options have separate defaults and preserve a zero radius', () => {
  assert.deepEqual(contextLimits(), CONTEXT_DEFAULTS);
  assert.equal(contextLimits({ radiusBytes: 0 }).radiusBytes, 0);
  const input = { mode: 'initial', termsHex: [hex('thing')], context: { maxFiles: 2 } }, original = copy(input);
  const separated = splitContextQuery(input);
  assert.equal(separated.limits.maxFiles, 2); assert.equal('context' in separated.input, false); assert.deepEqual(input, original);
  assert.equal(splitContextQuery({ mode: 'initial' }).limits, null);
  assert.throws(() => splitContextQuery({ mode: 'literal', context: {} }));
});
for (const [name, value] of [['maxFiles', 0], ['maxFiles', 33], ['radiusBytes', -1], ['radiusBytes', 4097],
  ['maxSourceBytes', 0], ['maxSourceBytes', 67108865], ['maxExcerptBytes', 0], ['maxExcerptBytes', 1048577],
  ['maxFiles', 1.5], ['maxFiles', '2'], ['radiusBytes', null], ['maxFiles', NaN], ['maxFiles', Infinity]]) {
  test(`refuses invalid option ${name}=${String(value)}`, () => assert.throws(() => contextLimits({ [name]: value })));
}
test('rejects unsupported option shapes, without silently opting into defaults', () => {
  for (const value of [null, true, [], 'defaults', { force: true }, { maxFiles: undefined }]) assert.throws(() => contextLimits(value));
});
test('context command preserves repeated Initial terms, pins, and both checkpoint floors', () => {
  const base = 'object_format=sha1&ref=refs%2Fheads%2Fmain&term_hex=61&term_hex=62&expected_head=alg%3A2%3Aabc&expected_commit=0123&minimum_lexical_number=18446744073709551615&minimum_symbol_number=7';
  const p = new URLSearchParams(contextCommand(base, { radiusBytes: 0, maxFiles: 2 }));
  assert.deepEqual(p.getAll('term_hex'), ['61', '62']); assert.equal(p.get('expected_head'), 'alg:2:abc');
  assert.equal(p.get('minimum_lexical_number'), '18446744073709551615');
  assert.equal(p.get('minimum_symbol_number'), '7'); assert.equal(p.get('context_radius_bytes'), '0');
  for (const field of ['context_max_files', 'context_radius_bytes', 'context_max_source_bytes', 'context_max_excerpt_bytes']) {
    assert.throws(() => contextCommand(`${base}&${field}=1`, {}));
  }
});
test('the join validates exactly the nested receipt once before admitting context', () => {
  const f = fixture(); let calls = 0;
  const result = joinInitialContext(f.reply, raw => { calls++; assert.equal(raw, f.reply.retrieval); return f.retrieval; }, {});
  assert.equal(calls, 1); assert.equal(result.vector, f.retrieval.vector); assert.equal(result.context.files.length, 1);
  assert.throws(() => joinInitialContext(f.reply, () => { throw new Error('native source moved'); }, {}), /native source moved/);
  f.reply.source_bytes_read++;
  assert.throws(() => joinInitialContext(f.reply, () => f.retrieval, {}), /accounting/);
  assert.equal('context' in f.retrieval, false);
});
const changes = {
  'schema version': f => { f.reply.schema_version = 2; },
  'unknown profile': f => { f.reply.profile = 'context-v2'; },
  'mutation': f => { f.reply.transaction_created = true; },
  'trusted-source claim': f => { f.reply.source_material_untrusted = false; },
  'false read-only': f => { f.reply.read_only = false; },
  'missing field': f => { delete f.reply.selection; },
  'unsupported field': f => { f.reply.published = true; },
  'reordered selection': f => { f.reply.selection = 'ranked'; },
  'wrong radius echo': f => { f.reply.context_radius_bytes = 0; },
  'wrong candidate count': f => { f.reply.candidate_files++; },
  'wrong returned count': f => { f.reply.returned_files = 0; },
  'wrong omitted count': f => { f.reply.omitted_files++; },
  'wrong decode count': f => { f.reply.source_blobs_read++; },
  'source byte total': f => { f.reply.source_bytes_read++; },
  'excerpt byte total': f => { f.reply.excerpt_bytes--; },
  'wrong per-file share': f => { f.reply.source_file_limit++; },
  'unexplained incomplete result': f => { f.reply.complete = false; },
  'partial hydrated prefix': f => { f.reply.files = []; },
  'injected unrelated path': f => { f.reply.files[0].path_hex = hex('private/key'); },
  'wrong blob identity': f => { f.reply.files[0].blob = 'f'.repeat(40); },
  'wrong source length': f => { f.reply.files[0].source_bytes++; },
  'missing anchor': f => { f.reply.files[0].anchors.pop(); },
  'reordered anchors': f => { f.reply.files[0].anchors.reverse(); },
  'path offset used as content': f => { f.reply.files[0].anchors[1].channel = 'content'; },
  'changed anchor coordinate': f => { f.reply.files[0].anchors[0].byte_offset++; },
  'unknown anchor field': f => { f.reply.files[0].anchors[0].trusted = true; },
  'excerpt shifted': f => { f.reply.files[0].excerpts[0].byte_offset++; },
  'excerpt truncated': f => { f.reply.files[0].excerpts[0].untrusted_bytes_hex = hex('pub struct Thing;'); },
  'excerpt uppercase encoding': f => { f.reply.files[0].excerpts[0].untrusted_bytes_hex = hex(f.bytes).toUpperCase(); },
  'excerpt invalid encoding': f => { f.reply.files[0].excerpts[0].untrusted_bytes_hex = 'xx'; },
  'unrequested second excerpt': f => { f.reply.files[0].excerpts.push(copy(f.reply.files[0].excerpts[0])); },
  'mismatched content anchor': f => { f.reply.files[0].excerpts[0].untrusted_bytes_hex = hex('pub struct Thang;\n'); },
  'changed visible word boundary': f => { f.reply.files[0].excerpts[0].untrusted_bytes_hex = hex('pub struct Thingx\n'); },
  'wrong symbol case': f => { f.reply.files[0].excerpts[0].untrusted_bytes_hex = hex('pub struct thing;\n'); },
  'inconsistent channel blob': f => { f.retrieval.path.hits[0].blob = 'b'.repeat(40); },
  'inconsistent channel size': f => { f.retrieval.path.hits[0].contentBytes++; },
};
for (const [name, change] of Object.entries(changes)) test(`rejects ${name}`, () => { const f = fixture(); change(f); assert.throws(() => check(f)); });
test('lexical anchors allow native ASCII case folding, without a symbol request', () => {
  const f = fixture(); f.retrieval.symbols = { state: 'not_requested' }; f.reply.files[0].anchors.pop();
  f.reply.files[0].excerpts[0].untrusted_bytes_hex = hex('pub struct thing;\n');
  assert.equal(check(f).files.length, 1);
});
test('zero radius returns just source matches, while path anchors keep path offsets', () => {
  const f = fixture(); const limits = limitsFor(f, { radiusBytes: 0 });
  f.reply.files[0].excerpts = [{ byte_offset: 11, untrusted_bytes_hex: hex('Thing') }]; f.reply.excerpt_bytes = 5;
  assert.deepEqual(check(f, limits).files[0].excerpts, [{ offset: 11, bytesHex: hex('Thing') }]);
});
for (const bytes of [Buffer.alloc(0), Buffer.from([0, 255, 128, 10, 60])]) test(`path-only preamble preserves ${bytes.length ? 'binary' : 'empty'} source bytes`, () => {
  const f = fixture(), blob = oid(bytes, 'sha1');
  f.retrieval.content.hits = []; f.retrieval.symbols = { state: 'not_requested' };
  Object.assign(f.retrieval.path.hits[0], { blob, contentBytes: bytes.length });
  Object.assign(f.reply.files[0], { blob, source_bytes: bytes.length,
    anchors: [{ channel: 'path', byte_offset: 4, byte_length: 5 }],
    excerpts: [{ byte_offset: 0, untrusted_bytes_hex: hex(bytes.subarray(0, 2)) }] });
  f.reply.source_bytes_read = bytes.length; f.reply.excerpt_bytes = Math.min(bytes.length, 2);
  const limits = limitsFor(f, { radiusBytes: 0 });
  assert.equal(check(f, limits).files[0].excerpts[0].bytesHex, hex(bytes.subarray(0, 2)));
});
test('all candidates are counted, but only the raw-path prefix is hydrated', () => {
  const f = fixture();
  const later = copy(f.retrieval.content.hits[0]); later.pathHex = hex('z/thing.rs'); later.blob = 'b'.repeat(40);
  f.retrieval.content.hits.unshift(later); // Native channel order need not be raw path order.
  f.reply.candidate_files = 2; f.reply.omitted_files = 1; f.reply.complete = false;
  const limits = limitsFor(f, { maxFiles: 1 }); const result = check(f, limits);
  assert.equal(result.files[0].pathHex, hex('src/thing.rs')); assert.equal(result.omittedFiles, 1); assert.equal(result.complete, false);
  f.reply.files[0].path_hex = later.pathHex; assert.throws(() => check(f, limits));
});
test('two selected paths have fixed, non-borrowable source shares', () => {
  const f = fixture(), second = copy(f.retrieval.content.hits[0]); second.pathHex = hex('z/thing.rs');
  f.retrieval.content.hits.push(second); const file = copy(f.reply.files[0]); file.path_hex = second.pathHex;
  file.anchors = [file.anchors[0]]; f.reply.files.push(file);
  Object.assign(f.reply, { candidate_files: 2, returned_files: 2, source_blobs_read: 2, source_bytes_read: 36, excerpt_bytes: 36 });
  const limits = limitsFor(f, { maxSourceBytes: 36 }); assert.equal(check(f, limits).sourceFileLimit, 18);
  const smaller = limitsFor(f, { maxSourceBytes: 35 }); assert.throws(() => check(f, smaller));
});
test('symbol-only paths are hydrated even without lexical hits', () => {
  const f = fixture(); f.retrieval.content.hits = []; f.retrieval.path.hits = [];
  f.reply.files[0].anchors = [f.reply.files[0].anchors[2]];
  assert.equal(check(f).files[0].sourceBytes, 18);
});
test('missing optional symbols and partial coverage stay incomplete after hydration', () => {
  for (const symbols of [{ state: 'unavailable', reason: 'stale', result: null }, { state: 'not_requested' }]) {
    const f = fixture(); f.retrieval.complete = false; f.retrieval.symbols = symbols;
    f.reply.complete = false; f.reply.files[0].anchors.pop();
    assert.equal(check(f).complete, false); f.reply.complete = true; assert.throws(() => check(f));
  }
});
test('no matches preserves native no-read accounting and the empty-selection share', () => {
  const f = fixture(); f.retrieval.content.hits = []; f.retrieval.path.hits = []; f.retrieval.symbols = { state: 'not_requested' };
  Object.assign(f.reply, { candidate_files: 0, returned_files: 0, omitted_files: 0, source_blobs_read: 0, source_bytes_read: 0, excerpt_bytes: 0, files: [] });
  const limits = limitsFor(f, { maxSourceBytes: 17 }); assert.equal(check(f, limits).sourceFileLimit, 17);
  f.reply.source_blobs_read = 1; assert.throws(() => check(f, limits));
});
test('source and excerpt exhaustion refuse the whole hydration, not a shortened success', () => {
  for (const limit of [{ maxSourceBytes: 17 }, { maxExcerptBytes: 17 }]) {
    const f = fixture(), limits = limitsFor(f, limit); assert.throws(() => check(f, limits));
  }
});
test('cancellation checkpoints can interrupt before or during validation without mutation', () => {
  const f = fixture(), saved = copy(f); let total = 0;
  contextReply(f.reply, f.retrieval, {}, () => total++);
  for (const stop of [1, 5, Math.floor(total / 2), total]) {
    let calls = 0; assert.throws(() => contextReply(f.reply, f.retrieval, {}, () => {
      if (++calls === stop) throw new Error('cancelled');
    }), /cancelled/);
    assert.deepEqual(copy(f), saved);
  }
});

test('an explicitly undefined or null context field never silently enables blob reads', () => {
  for (const context of [undefined, null, false]) assert.throws(() => splitContextQuery({ mode: 'initial', context }));
});
for (const radius of [0, 1, 2]) test(`source windows have native gap/adjacency merging at radius ${radius}`, () => {
  const f = fixture(), bytes = Buffer.from('aa bb cc'), blob = oid(bytes, 'sha1');
  f.retrieval.content.query.termsHex = [hex('aa'), hex('cc')]; f.retrieval.path.hits = []; f.retrieval.symbols = { state: 'not_requested' };
  Object.assign(f.retrieval.content.hits[0], { blob, contentBytes: bytes.length,
    spans: [{ queryIndex: 0, offset: 0, length: 2 }, { queryIndex: 1, offset: 6, length: 2 }] });
  const excerpts = radius === 0 ? [{ byte_offset: 0, untrusted_bytes_hex: hex('aa') }, { byte_offset: 6, untrusted_bytes_hex: hex('cc') }]
    : radius === 1 ? [{ byte_offset: 0, untrusted_bytes_hex: hex('aa ') }, { byte_offset: 5, untrusted_bytes_hex: hex(' cc') }]
      : [{ byte_offset: 0, untrusted_bytes_hex: hex('aa bb cc') }];
  Object.assign(f.reply.files[0], { blob, source_bytes: bytes.length,
    anchors: [{ channel: 'content', byte_offset: 0, byte_length: 2 }, { channel: 'content', byte_offset: 6, byte_length: 2 }], excerpts });
  Object.assign(f.reply, { source_bytes_read: bytes.length, excerpt_bytes: radius === 0 ? 4 : radius === 1 ? 6 : 8 });
  const limits = limitsFor(f, { radiusBytes: radius });
  assert.equal(check(f, limits).files[0].excerpts.length, radius === 2 ? 1 : 2);
});
for (const radius of [0, 1, 2]) test(`raw identifiers verify exactly the visible prefix at radius ${radius}`, () => {
  const f = fixture(), bytes = Buffer.from('pub struct r#Thing;\n'), blob = oid(bytes, 'sha1');
  f.retrieval.content.hits = []; f.retrieval.path.hits = [];
  Object.assign(f.retrieval.symbols.result.hits[0], { blob, offset: 13, rawIdentifier: true });
  const start = 13 - radius, end = Math.min(bytes.length, 18 + radius);
  Object.assign(f.reply.files[0], { blob, source_bytes: bytes.length,
    anchors: [{ channel: 'symbol', byte_offset: 13, byte_length: 5 }],
    excerpts: [{ byte_offset: start, untrusted_bytes_hex: hex(bytes.subarray(start, end)) }] });
  Object.assign(f.reply, { source_bytes_read: bytes.length, excerpt_bytes: end - start });
  const limits = limitsFor(f, { radiusBytes: radius }); assert.equal(check(f, limits).files.length, 1);
  if (radius) {
    const excerpt = f.reply.files[0].excerpts[0]; excerpt.untrusted_bytes_hex = '21' + excerpt.untrusted_bytes_hex.slice(2);
    assert.throws(() => check(f, limits), /raw identifier/);
  }
});
test('non-UTF-8 path bytes remain byte-exact across every channel', () => {
  const f = fixture(), path = Buffer.concat([Buffer.from('src/'), Buffer.from([255]), Buffer.from('thing.rs')]);
  for (const channel of ['content', 'path']) f.retrieval[channel].hits[0].pathHex = hex(path);
  f.retrieval.symbols.result.hits[0].pathHex = hex(path);
  f.retrieval.path.hits[0].spans[0].offset = 5; f.reply.files[0].path_hex = hex(path); f.reply.files[0].anchors[1].byte_offset = 5;
  assert.equal(check(f).files[0].pathHex, hex(path));
});
for (const number of [4, 5]) test(`${number * 26} disjoint windows ${number === 4 ? 'fit' : 'exceed'} the native 128-window ceiling`, () => {
  const f = fixture(), words = Array.from({ length: 26 }, (_, i) => `t${String(i).padStart(2, '0')}`);
  const bytes = Buffer.from(words.join(' ')), blob = oid(bytes, 'sha1');
  const spans = words.map((_, queryIndex) => ({ queryIndex, offset: queryIndex * 4, length: 3 }));
  f.retrieval.content.query.termsHex = words.map(hex); f.retrieval.path.hits = []; f.retrieval.symbols = { state: 'not_requested' };
  f.retrieval.content.hits = Array.from({ length: number }, (_, i) => ({ pathHex: hex(`src/${i}.rs`), blob,
    contentBytes: bytes.length, spans: copy(spans) }));
  f.reply.files = f.retrieval.content.hits.map(hit => ({ path_hex: hit.pathHex, blob, source_bytes: bytes.length,
    anchors: spans.map(span => ({ channel: 'content', byte_offset: span.offset, byte_length: 3 })),
    excerpts: words.map((word, i) => ({ byte_offset: i * 4, untrusted_bytes_hex: hex(word) })) }));
  Object.assign(f.reply, { candidate_files: number, returned_files: number, source_blobs_read: number,
    source_bytes_read: number * bytes.length, excerpt_bytes: number * 26 * 3 });
  const limits = limitsFor(f, { radiusBytes: 0 });
  if (number === 4) assert.equal(check(f, limits).files.length, 4);
  else assert.throws(() => check(f, limits), /window budget/);
});
