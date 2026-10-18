// The pure projection's inputs are explicit validated-loader projections, not
// substitute storage/search services. Real session replay is tested separately.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mergeContextExcerpts, MERGE_LIMITS, MERGE_PROFILE, mergeLimits } from '../../scripts/operator/source_context_merge.mjs';
const hex = value => Buffer.from(value).toString('hex');
const git = (bytes, format) => createHash(format).update(`blob ${bytes.length}\0`).update(bytes).digest('hex');
function entry(sequence = 0, format = 'sha1', files = []) {
  return { sequence, manifest_sha256: String(sequence % 10).repeat(64), capture_sha256: 'b'.repeat(64),
    source: { tenant_id: '1'.repeat(32), repository_id: '2'.repeat(32), repository_incarnation: '3'.repeat(32),
      object_format: format, reference: 'refs/heads/main', snapshot_token: `alg:2:${'4'.repeat(64)}`,
      source_rcr: 'record:one', source_commit: '5'.repeat(format === 'sha1' ? 40 : 64), root_tree: '6'.repeat(format === 'sha1' ? 40 : 64) },
    query: { terms: ['recover'], prefixes_hex: [], symbols: { name: 'Recover', policy: 'required' } },
    evidence: { complete: false, retrieval_complete: false, omitted_files: 2,
      lexical_checkpoint: { token: `alg:2:${'7'.repeat(64)}`, number: '18446744073709551615' },
      symbols: { state: 'unavailable', reason: 'stale' }, omissions: [{ reason: 'file_bytes', path_hex: hex('large.rs') }] }, files };
}
function file(name, bytes, ranges, format = 'sha1', anchors = []) {
  bytes = Buffer.from(bytes);
  return { path_hex: hex(name), blob: `${format}:${git(bytes, format)}`, source_bytes: bytes.length, anchors,
    excerpts: ranges.map(([from, to]) => ({ byte_offset: from, untrusted_bytes_hex: hex(bytes.subarray(from, to)) })) };
}
const code = expected => error => error.code === expected;
for (const format of ['sha1', 'sha256']) {
  test(`${format}: touching/overlapping excerpts become one exact full hashed blob`, () => {
    const bytes = Buffer.from('pub fn Recover() {}\r\n');
    const entries = [entry(0, format, [file('src/lib.rs', bytes, [[0, 11]], format)]),
      entry(1, format, [file('src/lib.rs', bytes, [[7, 16]], format)]),
      entry(3, format, [file('src/lib.rs', bytes, [[16, bytes.length]], format)])];
    const { view, text, json, json_sha256, text_sha256 } = mergeContextExcerpts(entries);
    assert.equal(view.schema, MERGE_PROFILE); assert.equal(view.returned_files, 1);
    assert.equal(view.input_excerpt_bytes, bytes.length + 4); assert.equal(view.excerpt_bytes, bytes.length);
    assert.equal(view.deduplicated_excerpt_bytes, 4);
    const merged = view.files[0]; assert.equal(merged.complete_blob_hash_verified, true);
    assert.equal(merged.excerpts[0].untrusted_bytes_hex, hex(bytes));
    assert.deepEqual(merged.query_sequences, [0, 1, 3]);
    assert.deepEqual(merged.excerpts[0].contributions.map(r => r.sequence), [0, 1, 3]);
    assert.deepEqual(view.queries.map(q => q.evidence), entries.map(q => q.evidence));
    assert.equal(view.queries[0].evidence.lexical_checkpoint.number, '18446744073709551615');
    assert.equal(view.aggregate_coverage_claimed, false); assert.equal(view.authority_verified, false);
    assert.equal(view.agent_context_packet, false); assert.equal(Object.hasOwn(view, 'complete'), false);
    assert.deepEqual(JSON.parse(json), view);
    assert.equal(createHash('sha256').update(json).digest('hex'), json_sha256);
    assert.equal(createHash('sha256').update(text).digest('hex'), text_sha256);
    assert.ok(text.includes(Buffer.from('pub fn Recover() {}\\r\\n')));
  });
  test(`${format}: independent files sort by raw bytes, identical blobs do not conflate paths`, () => {
    const bytes = Buffer.from('same\n'), a = file('a.rs', bytes, [[0, bytes.length]], format),
      raw = file(Buffer.from([255, 46, 114, 115]), bytes, [[0, bytes.length]], format);
    const result = mergeContextExcerpts([entry(0, format, [raw]), entry(1, format, [a])]).view;
    assert.deepEqual(result.files.map(f => f.path_hex), [a.path_hex, raw.path_hex]);
    assert.equal(result.returned_files, 2); assert.equal(result.deduplicated_excerpt_bytes, 0);
    assert.deepEqual(result.files.map(f => f.query_sequences), [[1], [0]]);
  });
  test(`${format}: holes remain holes and repeated identical excerpts retain query provenance`, () => {
    const bytes = Buffer.from('0123456789');
    const original = file('a.rs', bytes, [[1, 3], [6, 9]], format);
    const { view } = mergeContextExcerpts([entry(0, format, [original]), entry(2, format, [structuredClone(original)])]);
    assert.equal(view.files[0].complete_blob_hash_verified, false);
    assert.deepEqual(view.files[0].excerpts.map(w => [w.byte_offset, w.untrusted_bytes_hex]), [[1, hex('12')], [6, hex('678')]]);
    assert.equal(view.deduplicated_excerpt_bytes, 5);
    for (const w of view.files[0].excerpts) assert.deepEqual(w.contributions.map(c => c.sequence), [0, 2]);
  });
  test(`${format}: empty path-only files survive dedup and verify the empty native blob`, () => {
    const empty = file('Recover.rs', Buffer.alloc(0), [[0, 0]], format,
      [{ channel: 'path', byte_offset: 0, byte_length: 7 }]);
    const { view } = mergeContextExcerpts([entry(0, format, [empty]), entry(1, format, [structuredClone(empty)])]);
    assert.equal(view.files.length, 1); assert.equal(view.excerpt_bytes, 0);
    assert.equal(view.files[0].excerpts.length, 1); assert.equal(view.files[0].complete_blob_hash_verified, true);
    assert.deepEqual(view.files[0].anchors[0].query_sequences, [0, 1]);
  });
  test(`${format}: inconsistent overlapping bytes reject the entire view, never choose a winner`, () => {
    const bytes = Buffer.from('0123456789'), a = file('a.rs', bytes, [[0, 6]], format), b = file('a.rs', bytes, [[4, 9]], format);
    b.excerpts[0].untrusted_bytes_hex = hex('x5678');
    assert.throws(() => mergeContextExcerpts([entry(0, format, [a]), entry(1, format, [b])]), code('context_union_overlap_conflict'));
    b.excerpts[0].untrusted_bytes_hex = hex('45678');
    assert.equal(mergeContextExcerpts([entry(0, format, [a]), entry(1, format, [b])]).view.excerpt_bytes, 9);
  });
  test(`${format}: collectively full false bytes cannot inherit individual partial-blob non-proofs`, () => {
    const bytes = Buffer.from('0123456789'), a = file('a.rs', bytes, [[0, 5]], format), b = file('a.rs', bytes, [[5, 10]], format);
    b.excerpts[0].untrusted_bytes_hex = hex('5678X');
    assert.throws(() => mergeContextExcerpts([entry(0, format, [a]), entry(1, format, [b])]), code('context_union_complete_blob_mismatch'));
  });
}
for (const field of ['tenant_id', 'repository_id', 'repository_incarnation', 'reference', 'snapshot_token', 'source_rcr', 'source_commit', 'root_tree']) {
  test(`a changed ${field} never merges into the original source`, () => {
    const a = entry(), b = entry(1);
    b.source[field] = ['tenant_id', 'repository_id', 'repository_incarnation'].includes(field) ? '8'.repeat(32)
      : ['source_commit', 'root_tree'].includes(field) ? '8'.repeat(40) : 'other';
    assert.throws(() => mergeContextExcerpts([a, b]), code('context_union_source_changed'));
  });
}
test('native format cannot change inside one view', () => {
  assert.throws(() => mergeContextExcerpts([entry(), entry(1, 'sha256')]), code('context_union_source_changed'));
});
for (const field of ['blob', 'source_bytes']) test(`same path with conflicting ${field} is refused`, () => {
  const a = file('a.rs', 'hello', [[0, 2]]), b = structuredClone(a);
  b[field] = field === 'blob' ? '9'.repeat(40) : 6;
  assert.throws(() => mergeContextExcerpts([entry(0, 'sha1', [a]), entry(1, 'sha1', [b])]), code('context_union_file_conflict'));
});
test('anchor dedup retains channel and all query identities, including different coordinate spaces', () => {
  const anchors = [{ channel: 'symbol', byte_offset: 0, byte_length: 3 }, { channel: 'content', byte_offset: 0, byte_length: 3 },
    { channel: 'path', byte_offset: 1, byte_length: 2 }];
  const a = file('abc.rs', 'abcdef', [[0, 3]], 'sha1', anchors);
  const { view } = mergeContextExcerpts([entry(0, 'sha1', [a]), entry(2, 'sha1', [structuredClone(a)])]);
  assert.deepEqual(view.files[0].anchors.map(a => a.channel), ['content', 'path', 'symbol']);
  assert.ok(view.files[0].anchors.every(a => a.query_sequences.join() === '0,2'));
});
test('limits are union limits: exact merged byte count succeeds where duplicate input is larger', () => {
  const a = file('a.rs', 'abcdef', [[0, 4]]), entries = [entry(0, 'sha1', [a]), entry(1, 'sha1', [structuredClone(a)])];
  const result = mergeContextExcerpts(entries, { max_files: 1, max_excerpt_bytes: 4 });
  assert.equal(result.view.input_excerpt_bytes, 8); assert.equal(result.view.excerpt_bytes, 4);
  assert.throws(() => mergeContextExcerpts(entries, { max_excerpt_bytes: 3 }), code('context_union_excerpt_limit'));
  const b = entry(2, 'sha1', [file('b.rs', 'other', [[0, 2]])]);
  assert.throws(() => mergeContextExcerpts([...entries, b], { max_files: 1 }), code('context_union_file_limit'));
  assert.equal(mergeContextExcerpts([...entries, b], { max_files: 2 }).view.returned_files, 2);
});
test('metadata and encoded output ceilings refuse, not clip source or query evidence', () => {
  const entries = [entry(0, 'sha1', [file('a.rs', 'abcdef', [[0, 4]])])];
  const metadata = Buffer.byteLength(JSON.stringify({ query: entries[0].query, evidence: entries[0].evidence }));
  assert.equal(mergeContextExcerpts(entries, { max_metadata_bytes: metadata }).view.queries.length, 1);
  assert.throws(() => mergeContextExcerpts(entries, { max_metadata_bytes: metadata - 1 }), code('context_union_metadata_limit'));
  assert.throws(() => mergeContextExcerpts(entries, { max_output_bytes: 1 }), code('context_union_output_limit'));
});
test('closed limits reject unknown dimensions, negative and inflated bounds', () => {
  for (const value of [null, [], { unknown: 1 }, { max_files: 0 }, { max_files: 545 },
    { max_excerpt_bytes: MERGE_LIMITS.max_excerpt_bytes + 1 }]) assert.throws(() => mergeLimits(value));
});
test('source objects, returned views and inputs are detached; arbitrary projection fields do not escape', () => {
  const a = entry(0, 'sha1', [file('a.rs', 'abcdef', [[0, 3]])]);
  a.unexpected = 'not retained'; a.files[0].evil = 'not retained';
  const first = mergeContextExcerpts([a]), copy = Buffer.from(first.json);
  a.source.source_rcr = 'changed'; a.query.terms[0] = 'changed'; a.files[0].excerpts[0].untrusted_bytes_hex = hex('xxx');
  assert.ok(first.json.equals(copy)); assert.equal(first.view.queries[0].query.terms[0], 'recover');
  assert.equal(first.json.includes(Buffer.from('not retained')), false);
  first.view.source.source_rcr = 'caller changed'; assert.ok(first.json.equals(copy));
});
test('terminal/bidi/Markdown/HTML bytes stay inert quoted strings and binary stays hex', () => {
  const bytes = Buffer.from('![x](https://invalid/)\n</script>\u202e\u001b[2J\r\n');
  const binary = Buffer.from([255, 0, 10]);
  const { text } = mergeContextExcerpts([entry(0, 'sha1', [file('a.rs', bytes, [[0, bytes.length]]), file('b.rs', binary, [[0, binary.length]])])]);
  assert.equal(text.includes(Buffer.from('\u202e')), false); assert.equal(text.includes(Buffer.from([27])), false);
  assert.ok(text.includes(Buffer.from('\\u202e'))); assert.ok(text.includes(Buffer.from('\\u001b')));
  assert.ok(text.includes(Buffer.from('"encoding":"hex","untrusted_source":"ff000a"')));
});
for (const [name, mutate] of [
  ['duplicate sequence', e => e[1].sequence = 0], ['missing base', e => e[0].sequence = 1],
  ['bad pin', e => e[0].manifest_sha256 = 'no'], ['too many queries', e => e.push(...Array(17).fill(e[1]))],
  ['traversal', e => e[0].files[0].path_hex = hex('../a')], ['zero blob', e => e[0].files[0].blob = '0'.repeat(40)],
  ['out-of-range excerpt', e => e[0].files[0].excerpts[0].byte_offset = 100],
  ['touching native windows', e => e[0].files[0].excerpts.push({ byte_offset: 3, untrusted_bytes_hex: hex('def') })],
  ['unknown anchor', e => e[0].files[0].anchors = [{ channel: 'authority', byte_offset: 0, byte_length: 1 }]],
  ['bad anchor extent', e => e[0].files[0].anchors = [{ channel: 'content', byte_offset: 5, byte_length: 5 }]],
]) test(`invalid projection ${name} refuses`, () => {
  const e = [entry(0, 'sha1', [file('a.rs', 'abcdef', [[0, 3]])]), entry(1)]; mutate(e);
  assert.throws(() => mergeContextExcerpts(e));
});
test('empty captured result remains distinct from no captures', () => {
  const r = mergeContextExcerpts([entry()]).view;
  assert.equal(r.returned_files, 0); assert.equal(r.query_count, 1); assert.equal(r.excerpt_bytes, 0);
  assert.equal(r.queries[0].evidence.complete, false);
  assert.throws(() => mergeContextExcerpts([]));
});
test('cancellation interrupts assembly and withholds JSON and text together', () => {
  const entries = [entry(0, 'sha1', [file('a.rs', 'abcdef', [[0, 3]])]), entry(1, 'sha1', [file('a.rs', 'abcdef', [[1, 4]])])];
  let probes = 0; mergeContextExcerpts(entries, {}, () => probes++); assert.ok(probes > 10);
  for (const stop of [1, 5, probes - 1, probes]) {
    let n = 0; assert.throws(() => mergeContextExcerpts(entries, {}, () => { if (++n === stop) throw new Error('stop'); }), /stop/);
  }
});
