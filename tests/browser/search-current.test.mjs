// Tests execute the actual presentation validators. They do not simulate a
// native authority store, prove a signed root, or claim HTTP/browser E2E.
import test from 'node:test';
import assert from 'node:assert/strict';
import { compareCounters, currentSources, sourceMode, wireCounter } from '../../crates/fgit-node/src/smart_http/server/browser/search-current.mjs';

const clone = structuredClone;
const token = byte => `alg:2:${byte.repeat(64)}`;
function fixture(format = 'sha1') {
  const width = format === 'sha1' ? 40 : 64;
  const scope = { tenant: '1'.repeat(32), repository: '2'.repeat(32), incarnation: '3'.repeat(32), format };
  const pin = { head: token('a'), sourceHead: 'current-authority-id', rcr: 'current-rcr-id', commit: 'b'.repeat(width), tree: 'c'.repeat(width) };
  const current = { tenant_id: scope.tenant, repository_id: scope.repository,
    repository_incarnation: scope.incarnation, object_format: format, ref_hex: '726566732f68656164732f6d61696e',
    source_head: pin.sourceHead, snapshot_token: pin.head, source_rcr: pin.rcr,
    forge_position_root: token('d'), source_commit: pin.commit, root_tree: pin.tree };
  const indexed = { ...current, source_head: 'original-authority-id', snapshot_token: token('e'),
    source_rcr: 'original-rcr-id', forge_position_root: token('f') };
  return { source: { scope, pin }, reply: { ref_hex: current.ref_hex, source_mode: 'revalidated',
    distinct_provenance: true, current_source: current, indexed_source: indexed } };
}

const parse = f => currentSources(f.reply, f.source);

test('default stays exact; revalidation requires a closed explicit mode', () => {
  assert.equal(sourceMode(undefined), 'exact');
  assert.equal(sourceMode('exact'), 'exact');
  assert.equal(sourceMode('revalidated'), 'revalidated');
  for (const value of [null, true, 1, '', 'latest', 'Revalidated', 'revalidated ', {}, []]) {
    assert.throws(() => sourceMode(value));
  }
});

test('revalidated u64 boundary twins retain every original decimal digit', () => {
  for (const value of ['1', '9', '10', '9007199254740991', '9007199254740992', '9007199254740993', '18446744073709551615']) {
    assert.equal(wireCounter(value, 'revalidated'), value);
    assert.equal(JSON.parse(JSON.stringify({ value })).value, value);
  }
  assert.throws(() => wireCounter('0', 'revalidated'));
  assert.equal(wireCounter('0', 'revalidated', 0), '0');
  assert.throws(() => wireCounter('18446744073709551616', 'revalidated'));
});

test('new wire profile refuses rounded numbers, BigInts and noncanonical text', () => {
  for (const value of [1, 9007199254740993, 1n, null, undefined, NaN, Infinity, {}, [],
    '', '00', '01', '-1', '+1', ' 1', '1 ', '1\n', '1.0', '1e3', '١', '1'.repeat(100_000)]) {
    assert.throws(() => wireCounter(value, 'revalidated'));
  }
});

test('exact profile keeps safe integers and does not silently adopt string semantics', () => {
  for (const value of [1, 10, Number.MAX_SAFE_INTEGER]) assert.equal(wireCounter(value, 'exact'), value);
  for (const value of ['1', 0, -1, 0.5, Number.MAX_SAFE_INTEGER + 1, NaN, Infinity, null]) {
    assert.throws(() => wireCounter(value, 'exact'));
  }
  assert.throws(() => wireCounter(1, 'latest'));
});

test('retained checkpoints compare numerically across exact and string profiles', () => {
  const ordered = ['0', '1', '2', '9', '10', '100', '9007199254740991', '9007199254740992', '9007199254740993', '18446744073709551615'];
  for (let a = 0; a < ordered.length; a++) {
    for (let b = 0; b < ordered.length; b++) {
      assert.equal(compareCounters(ordered[a], ordered[b]), Math.sign(a - b));
    }
  }
  assert.equal(compareCounters('10', 9), 1);
  assert.equal(compareCounters(9, '10'), -1);
  assert.equal(compareCounters('9007199254740991', Number.MAX_SAFE_INTEGER), 0);
  for (const invalid of [true, 1n, '01', '-1', -1, NaN, Number.MAX_SAFE_INTEGER + 1]) {
    assert.throws(() => compareCounters(invalid, 1));
    assert.throws(() => compareCounters(1, invalid));
  }
});

for (const format of ['sha1', 'sha256']) {
  test(`${format}: metadata-only changes keep independent current and original provenance`, () => {
    const f = fixture(format), before = clone(f), value = parse(f);
    assert.deepEqual(f, before);
    assert.deepEqual(value.current, f.reply.current_source);
    assert.deepEqual(value.indexed, f.reply.indexed_source);
    assert.equal(value.distinct, true);
    assert.equal(value.current.source_commit, value.indexed.source_commit);
    assert.notEqual(value.current.source_rcr, value.indexed.source_rcr);
    f.reply.indexed_source = clone(f.reply.current_source);
    f.reply.distinct_provenance = false;
    assert.equal(parse(f).distinct, false);
  });
}

test('bare tree or repository equality cannot hide a different native source', () => {
  for (const field of ['tenant_id', 'repository_id', 'repository_incarnation', 'object_format', 'ref_hex', 'source_commit', 'root_tree']) {
    const f = fixture();
    f.reply.indexed_source[field] = field === 'object_format' ? 'sha256' : '9'.repeat(40);
    assert.throws(() => parse(f), field);
  }
  const f = fixture();
  f.reply.current_source.source_commit = 'sha256:' + 'b'.repeat(64);
  f.reply.indexed_source.source_commit = f.reply.current_source.source_commit;
  assert.throws(() => parse(f));
});

test('nested current coordinates must join to the separately pinned flat source', () => {
  for (const field of Object.keys(fixture().source.scope)) {
    const f = fixture();
    f.source.scope[field] = 'foreign';
    assert.throws(() => parse(f), field);
  }
  for (const field of Object.keys(fixture().source.pin)) {
    const f = fixture();
    f.source.pin[field] = 'foreign';
    assert.throws(() => parse(f), field);
  }
  const f = fixture();
  f.reply.ref_hex = '726566732f68656164732f6f74686572';
  assert.throws(() => parse(f));
});

test('same head refuses contradictory display identity, RCR or forge roots', () => {
  const f = fixture();
  f.reply.indexed_source = clone(f.reply.current_source);
  f.reply.distinct_provenance = false;
  assert.doesNotThrow(() => parse(f));
  for (const field of ['snapshot_token', 'source_head', 'source_rcr', 'forge_position_root']) {
    const changed = clone(f);
    changed.reply.indexed_source[field] = field === 'snapshot_token' ? token('e') : 'changed';
    changed.reply.distinct_provenance = true;
    assert.throws(() => parse(changed), field);
  }
});

test('distinct-provenance labels are computed from the records, not trusted', () => {
  for (const wrong of [false, 'true', 1, null, undefined]) {
    const f = fixture(); f.reply.distinct_provenance = wrong;
    assert.throws(() => parse(f));
  }
  const f = fixture(); f.reply.indexed_source = clone(f.reply.current_source);
  assert.throws(() => parse(f));
  f.reply.distinct_provenance = false;
  assert.doesNotThrow(() => parse(f));
  for (const mode of [undefined, 'exact', 'latest', null]) {
    const changed = clone(f); changed.reply.source_mode = mode;
    assert.throws(() => parse(changed));
  }
});

test('missing, extra, oversized and control-bearing source records are rejected', () => {
  for (const side of ['current_source', 'indexed_source']) {
    for (const field of Object.keys(fixture().reply[side])) {
      const f = fixture(); delete f.reply[side][field];
      assert.throws(() => parse(f), `${side}.${field}`);
    }
    for (const bad of [null, [], {}, false, 'source']) {
      const f = fixture(); f.reply[side] = bad;
      assert.throws(() => parse(f));
    }
    for (const bad of ['', ' ', 'x'.repeat(257), 'é'.repeat(129), 'bad\u001b', 'bad\0', '\ud800']) {
      const f = fixture(); f.reply[side].source_rcr = bad;
      assert.throws(() => parse(f));
    }
    const f = fixture(); f.reply[side].authority = 'injected';
    assert.throws(() => parse(f));
  }
});

test('original snapshot tokens retain algorithm, width, nonzero and lowercase checks', () => {
  for (const bad of ['alg:0:aa', 'alg:65536:aa', 'alg:02:aa', 'alg:2:AABB', 'alg:2:abc',
    'alg:2:' + '0'.repeat(64), 'alg:2:' + 'a'.repeat(130)]) {
    const f = fixture(); f.reply.indexed_source.snapshot_token = bad;
    assert.throws(() => parse(f));
  }
});

test('continuations must retain both complete provenances, not just current commit', () => {
  const f = fixture(), previous = { sources: parse(f) };
  assert.deepEqual(currentSources(f.reply, f.source, previous), previous.sources);
  for (const side of ['current', 'indexed']) {
    for (const field of Object.keys(previous.sources[side])) {
      const changed = clone(previous); changed.sources[side][field] = 'substituted';
      assert.throws(() => currentSources(f.reply, f.source, changed), `${side}.${field}`);
    }
  }
  assert.throws(() => currentSources(f.reply, f.source, {}));
});

test('returned provenance owns its records and remains JSON round-trippable', () => {
  const f = fixture(), value = parse(f), saved = clone(value);
  f.reply.indexed_source.source_rcr = 'caller mutation';
  f.reply.current_source.source_head = 'caller mutation';
  assert.deepEqual(value, saved);
  assert.deepEqual(JSON.parse(JSON.stringify(value)), saved);
  value.current.source_head = 'UI mutation';
  assert.equal(value.indexed.source_head, saved.indexed.source_head);
});
