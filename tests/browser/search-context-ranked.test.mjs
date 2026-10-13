// Decoder tests use native-schema examples and prevalidated Initial results.
// HTTP, native authorization and the shared Initial parser are not exercised.
import test from 'node:test';
import assert from 'node:assert/strict';
import { contextCommand, contextLimits, contextReply, joinInitialContext } from '../../crates/fgit-node/src/smart_http/server/browser/search-context.mjs';
import { copy, hex } from './search-context-fixtures.mjs';
import { PROFILE, rankedFixture, contribution, ranking } from './search-context-ranked-fixtures.mjs';
const check = f => contextReply(f.reply, f.retrieval, f.limits);
for (const format of ['sha1', 'sha256']) test(`native fixed-point corroborated late path wins (${format})`, () => {
  const f = rankedFixture(format), original = copy(f), result = check(f);
  assert.deepEqual(copy(f), original);
  assert.equal(result.files[0].pathHex, hex('z/Thing.rs'));
  assert.equal(result.selection, PROFILE); assert.equal(result.candidateFiles, 2); assert.equal(result.omittedFiles, 1);
  assert.equal(result.complete, false); assert.equal(result.ranking.selected[0].score_q16, 4279);
  assert.deepEqual(result.ranking, f.reply.ranking);
  assert.equal(result.files[0].anchors.length, 3);
  result.ranking.selected[0].contributions[0].score_q16 = 1;
  assert.equal(f.reply.ranking.selected[0].contributions[0].score_q16, 1057);
});
test('ranked requests explicitly select the native profile without changing ordinary request bytes', () => {
  const original = 'ref=refs%2Fheads%2Fmain&term_hex=61&term_hex=62&minimum_lexical_number=18446744073709551615';
  const before = contextCommand(original, {});
  assert.equal(before, original + '&context_max_files=8&context_radius_bytes=128&context_max_source_bytes=67108864&context_max_excerpt_bytes=262144');
  assert.equal(contextLimits({}).selection, 'raw-path-prefix');
  const body = new URLSearchParams(contextCommand(original, { selection: PROFILE, radiusBytes: 0 }));
  assert.equal(body.get('context_selection'), PROFILE); assert.deepEqual(body.getAll('term_hex'), ['61', '62']);
  assert.equal(body.get('minimum_lexical_number'), '18446744073709551615'); assert.equal(body.get('context_radius_bytes'), '0');
  for (const selection of ['ranked', 'rrf', '', undefined, 1, null]) assert.throws(() => contextLimits({ selection }));
  for (const selection of [PROFILE, 'raw-path-prefix']) {
    assert.throws(() => contextCommand(original + '&context_selection=' + selection, {}));
    assert.throws(() => contextCommand(original + '&context_selection=' + selection, { selection: PROFILE }));
  }
});
test('canonical file order remains raw-path ascending rather than selected relevance order', () => {
  const f = rankedFixture('sha1', 2), result = check(f);
  assert.deepEqual(result.files.map(file => file.pathHex), [hex('00.txt'), hex('z/Thing.rs')]);
  assert.deepEqual(result.ranking.selected.map(file => file.path_hex), [hex('z/Thing.rs'), hex('00.txt')]);
  assert.equal(result.complete, true);
  f.reply.files.reverse(); assert.throws(() => check(f));
});
test('the default profile still selects alphabetically and cannot silently adopt ranked selection', () => {
  const f = rankedFixture('sha1', 2); f.limits.maxFiles = 1; f.limits.selection = 'raw-path-prefix';
  f.reply.context_max_files = 1; f.reply.selection = 'raw-path-prefix'; delete f.reply.ranking;
  f.reply.files.pop(); Object.assign(f.reply, { returned_files: 1, omitted_files: 1, source_blobs_read: 1,
    source_bytes_read: 18, excerpt_bytes: 18, complete: false });
  assert.equal(check(f).files[0].pathHex, hex('00.txt'));
  f.limits.selection = PROFILE; assert.throws(() => check(f));
});
test('duplicate declarations neither multiply a score nor displace document ranks', () => {
  const f = rankedFixture(), expected = check(f);
  f.retrieval.symbols.result.hits = Array.from({ length: 100 }, () => copy(f.retrieval.symbols.result.hits[0]));
  assert.deepEqual(check(f), expected);
  f.retrieval.symbols.result.hits[50].blob = 'b'.repeat(40);
  assert.throws(() => check(f), /identit/);
});
test('identities in omitted or repeated paths must still agree', () => {
  const f = rankedFixture();
  const earlier = copy(f.retrieval.content.hits[0]); earlier.blob = 'b'.repeat(40);
  f.retrieval.content.hits.splice(1, 0, earlier);
  assert.throws(() => check(f), /identit/);
});
test('wrong-format or zero object identities cannot be ranked', () => {
  for (const format of ['sha1', 'sha256']) for (const invalid of ['0'.repeat(format === 'sha1' ? 40 : 64), 'a'.repeat(format === 'sha1' ? 64 : 40)]) {
    const f = rankedFixture(format); f.retrieval.content.hits[0].blob = invalid;
    assert.throws(() => check(f));
  }
});
test('channel order is checked before deduplication or scoring; no local repair-sort', () => {
  const f = rankedFixture(); f.retrieval.content.hits.reverse(); assert.throws(() => check(f), /order/);
});
test('empty results carry an empty ranking without reading any blob', () => {
  const f = rankedFixture();
  f.retrieval.content.hits = []; f.retrieval.path.hits = []; f.retrieval.symbols = { state: 'not_requested' };
  Object.assign(f.reply, { files: [], candidate_files: 0, returned_files: 0, omitted_files: 0,
    source_blobs_read: 0, source_bytes_read: 0, excerpt_bytes: 0, complete: true, ranking: ranking([]) });
  assert.deepEqual(check(f).files, []); assert.deepEqual(check(f).ranking.selected, []);
});
test('absent symbol evidence is never upgraded by ranking', () => {
  const f = rankedFixture(); f.retrieval.symbols = { state: 'unavailable', reason: 'no-generation' };
  f.retrieval.complete = false;
  f.reply.files[0].anchors.pop(); f.reply.ranking.selected[0].score_q16 = 2131;
  f.reply.ranking.selected[0].contributions.pop();
  assert.equal(check(f).complete, false); assert.equal(check(f).ranking.selected[0].score_q16, 2131);
});
test('raw-byte tie-breaking does not decode or locale-sort non-UTF-8 paths', () => {
  const f = rankedFixture(), low = hex(Buffer.from('raw\xfe/thing.rs', 'latin1')), high = hex(Buffer.from('raw\xff/thing.rs', 'latin1'));
  f.retrieval.content.hits = [f.retrieval.content.hits[1]]; f.retrieval.content.hits[0].pathHex = high;
  f.retrieval.path.hits[0].pathHex = low; f.retrieval.path.hits[0].spans[0].offset = 5;
  f.retrieval.symbols = { state: 'not_requested' }; const file = f.reply.files[0]; file.path_hex = low;
  file.anchors = [{ channel: 'path', byte_offset: 5, byte_length: 5 }];
  f.reply.ranking = ranking([{ position: 1, path_hex: low, blob: file.blob, score_q16: 1074,
    contributions: [contribution('path', 1, 1, 1074)] }]);
  assert.equal(check(f).files[0].pathHex, low);
  f.reply.files[0].path_hex = high; f.reply.ranking.selected[0].path_hex = high;
  assert.throws(() => check(f));
});
const invalid = {
  'missing ranking': f => { delete f.reply.ranking; },
  'null ranking': f => { f.reply.ranking = null; },
  'selection downgrade': f => { f.reply.selection = 'raw-path-prefix'; },
  'profile': f => { f.reply.ranking.profile = 'relevance'; },
  'rank constant': f => { f.reply.ranking.rank_constant = 59; },
  'score scale': f => { f.reply.ranking.score_scale = 65535; },
  'input order': f => { f.reply.ranking.input_order = 'score'; },
  'tie-break': f => { f.reply.ranking.tie_break = 'utf8'; },
  'unreturned candidate claim': f => { f.reply.ranking.ranked_over = 'all-files'; },
  'semantic-relevance claim': f => { f.reply.ranking.semantic_relevance = true; },
  'extra evidence': f => { f.reply.ranking.authorization = true; },
  'missing selected': f => { delete f.reply.ranking.selected; },
  'omitted winner': f => { f.reply.ranking.selected.pop(); },
  'duplicate winner': f => { f.reply.ranking.selected.push(copy(f.reply.ranking.selected[0])); },
  'position': f => { f.reply.ranking.selected[0].position = 2; },
  'path': f => { f.reply.ranking.selected[0].path_hex = hex('00.txt'); },
  'blob': f => { f.reply.ranking.selected[0].blob = 'b'.repeat(40); },
  'score': f => { f.reply.ranking.selected[0].score_q16++; },
  'fractional score': f => { f.reply.ranking.selected[0].score_q16 += 0.5; },
  'missing contribution': f => { f.reply.ranking.selected[0].contributions.pop(); },
  'duplicate contribution': f => { f.reply.ranking.selected[0].contributions.push(copy(f.reply.ranking.selected[0].contributions[0])); },
  'contribution ordering': f => { f.reply.ranking.selected[0].contributions.reverse(); },
  'invented channel': f => { f.reply.ranking.selected[0].contributions[0].channel = 'semantic'; },
  'distinct-document rank': f => { f.reply.ranking.selected[0].contributions[0].document_rank = 1; },
  'channel weight': f => { f.reply.ranking.selected[0].contributions[0].weight = 2; },
  'contribution score': f => { f.reply.ranking.selected[0].contributions[0].score_q16++; },
  'unknown contribution field': f => { f.reply.ranking.selected[0].contributions[0].trust = 'verified'; },
  'missing selected field': f => { delete f.reply.ranking.selected[0].score_q16; },
  'ranking without hydration': f => { f.reply.files = []; },
};
for (const [name, mutate] of Object.entries(invalid)) test(`ranked context refuses ${name}`, () => {
  const f = rankedFixture(); mutate(f); assert.throws(() => check(f));
});
test('cancellation during rank validation cannot return a successful prefix', () => {
  const f = rankedFixture(); let completed = 0;
  contextReply(f.reply, f.retrieval, f.limits, () => completed++);
  for (let cancel = 1; cancel <= completed; cancel++) {
    let calls = 0;
    assert.throws(() => contextReply(f.reply, f.retrieval, f.limits, () => { if (++calls === cancel) throw new Error('cancelled'); }), /cancelled/);
  }
});
test('ranked validation uses the nested Initial result exactly once and does not mutate it', () => {
  const f = rankedFixture(), original = copy(f.retrieval); let calls = 0;
  const result = joinInitialContext(f.reply, raw => { assert.equal(raw, f.reply.retrieval); calls++; return f.retrieval; }, f.limits);
  assert.equal(calls, 1); assert.equal(result.context.selection, PROFILE); assert.deepEqual(f.retrieval, original);
});
