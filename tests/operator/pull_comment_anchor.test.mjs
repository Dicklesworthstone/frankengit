// Native structural contract checks; immutable-tree/source verification remains
// the Rust admission owner's responsibility, not a claim made by these tests.
import test from 'node:test';
import assert from 'node:assert/strict';
import { normalizePullCommentAnchor, pullCommentAnchorFields, PullAnchorError }
  from '../../scripts/operator/pull_comment_anchor.mjs';

const hex = value => Buffer.from(value).toString('hex');
const profile = 'frankengit.source-comment.myers-lines.v1';
function selection(format = 'sha1', extra = {}) {
  const bytes = format === 'sha1' ? 20 : 32;
  return { profile, pull_request_version: '18446744073709551615',
    source_ref_hex: hex(Buffer.from('refs/heads/topic\xff', 'latin1')),
    target_ref_hex: hex('refs/heads/main'), source_tip: '11'.repeat(bytes), target_tip: '22'.repeat(bytes),
    compared_base: '22'.repeat(bytes), comparison: 'direct', path_hex: hex(Buffer.from('src/\xfe.rs', 'latin1')),
    side: 'after', blob: '33'.repeat(bytes), mode: '100644', byte_start: '0', byte_end: '6',
    line_start: '0', line_count: '2', ...extra };
}
function refuses(value, format = 'sha1', options) {
  assert.throws(() => normalizePullCommentAnchor(value, format, options), PullAnchorError);
}

for (const format of ['sha1', 'sha256']) {
  test(`${format} exact raw coordinates flatten to the native form without a profile or predecessor`, () => {
    const input = selection(format), original = structuredClone(input);
    const anchor = normalizePullCommentAnchor(input, format);
    assert.deepEqual(anchor, original); assert.notEqual(anchor, input);
    input.path_hex = hex('later.rs'); assert.equal(anchor.path_hex, original.path_hex);
    assert.deepEqual([...new URLSearchParams(pullCommentAnchorFields(anchor, format))], [
      ['anchor_pull_request_version', '18446744073709551615'],
      ['anchor_source_ref_hex', '726566732f68656164732f746f706963ff'],
      ['anchor_target_ref_hex', '726566732f68656164732f6d61696e'],
      ['anchor_source_tip', original.source_tip], ['anchor_target_tip', original.target_tip],
      ['anchor_compared_base', original.target_tip], ['anchor_comparison', 'direct'],
      ['anchor_path_hex', '7372632ffe2e7273'], ['anchor_side', 'after'], ['anchor_blob', original.blob],
      ['anchor_mode', '100644'], ['anchor_byte_start', '0'], ['anchor_byte_end', '6'],
      ['anchor_line_start', '0'], ['anchor_line_count', '2'],
    ]);
  });
  test(`${format} native typed OIDs match only the exact configured domain`, () => {
    const anchor = selection(format), wire = structuredClone(anchor);
    for (const name of ['source_tip', 'target_tip', 'compared_base', 'blob']) wire[name] = `${format}:${anchor[name]}`;
    assert.deepEqual(normalizePullCommentAnchor(wire, format, { wire: true }), anchor);
    refuses(wire, format);
    for (const name of ['source_tip', 'target_tip', 'compared_base', 'blob']) {
      for (const value of ['0'.repeat(anchor[name].length), 'A'.repeat(anchor[name].length),
        `${format === 'sha1' ? 'sha256' : 'sha1'}:${anchor[name]}`, `${format}:${anchor[name]}00`]) {
        refuses({ ...wire, [name]: value }, format, { wire: true });
      }
    }
    refuses(anchor, format === 'sha1' ? 'sha256' : 'sha1');
  });
  test(`${format} direct and merge-base anchors retain independent side and mode selections`, () => {
    const direct = selection(format), other = '44'.repeat(format === 'sha1' ? 20 : 32);
    refuses({ ...direct, compared_base: other }, format);
    const merge = { ...direct, comparison: 'merge_base', compared_base: other };
    for (const side of ['before', 'after']) for (const mode of ['100644', '100755', '120000']) {
      const selected = { ...merge, side, mode };
      assert.deepEqual(normalizePullCommentAnchor(selected, format), selected);
    }
    for (const change of [{ comparison: 'merge-base' }, { comparison: 'remapped' }, { side: 'both' },
      { mode: '160000' }, { mode: '40000' }, { mode: '0100644' }, { mode: 100644 }]) refuses({ ...direct, ...change }, format);
  });
}

test('the complete anchor is required and must not contain read-time status or supplied authority', () => {
  const anchor = selection();
  for (const name of Object.keys(anchor)) { const missing = { ...anchor }; delete missing[name]; refuses(missing); }
  for (const value of [null, [], {}, { ...anchor, profile: `${profile}.later` }, { ...anchor, anchor_status: 'exact' },
    { ...anchor, expected_version: '0' }, { ...anchor, actor: '11'.repeat(16) }, { ...anchor, excerpt_hex: '61' },
    { ...anchor, [Symbol('extra')]: 'hidden' }]) refuses(value);
  let touched = false;
  refuses(Object.defineProperty({ ...anchor }, 'path_hex', { get() { touched = true; return anchor.path_hex; } }));
  assert.equal(touched, false);
  assert.deepEqual(normalizePullCommentAnchor(Object.assign(Object.create(null), anchor), 'sha1'), anchor);
  refuses(anchor, 'sha1', { wire: null });
  assert.throws(() => pullCommentAnchorFields({ ...anchor, byte_end: '0' }, 'sha1'), PullAnchorError);
});

test('canonical u64 metadata versions remain independent of bounded byte and line coordinates', () => {
  for (const version of ['1', '9007199254740993', '18446744073709551615']) {
    const anchor = selection('sha1', { pull_request_version: version });
    assert.equal(normalizePullCommentAnchor(anchor, 'sha1').pull_request_version, version);
  }
  for (const version of ['0', '18446744073709551616', '-1', '01', '1e3', 1, null]) {
    refuses(selection('sha1', { pull_request_version: version }));
  }
  for (const name of ['byte_start', 'byte_end', 'line_start', 'line_count']) {
    for (const value of ['01', '-1', '1.0', '1e2', '', 1, null, '18446744073709551616']) refuses(selection('sha1', { [name]: value }));
  }
});

test('whole-line structural ranges permit exact bounds and reject adjacent invalid selections', () => {
  const bounded = selection('sha1', { byte_start: '983040', byte_end: '1048576', line_start: '1', line_count: '128' });
  assert.deepEqual(normalizePullCommentAnchor(bounded, 'sha1'), bounded);
  for (const change of [{ byte_start: '983039' }, { byte_end: '1048577' }, { line_count: '129' },
    { line_count: '0' }, { byte_start: '1048576' }, { line_start: '983041' }]) refuses({ ...bounded, ...change });
  const lastByte = selection('sha1', { byte_start: '1048575', byte_end: '1048576', line_start: '1048575', line_count: '1' });
  assert.deepEqual(normalizePullCommentAnchor(lastByte, 'sha1'), lastByte);
  const first = selection('sha1', { byte_end: '1', line_count: '1' });
  assert.deepEqual(normalizePullCommentAnchor(first, 'sha1'), first);
  refuses({ ...first, line_count: '2' });
  refuses({ ...first, line_start: '1' });
  const next = { ...first, byte_start: '1', byte_end: '2', line_start: '1' };
  assert.deepEqual(normalizePullCommentAnchor(next, 'sha1'), next);
  refuses({ ...next, line_start: '0' });
  refuses({ ...next, byte_end: '1' });
});

test('raw Git ref bytes obey native names and the 1024-byte bound without Unicode conversion', () => {
  const exact = `refs/heads/${'a'.repeat(1013)}`;
  assert.equal(Buffer.byteLength(exact), 1024);
  assert.equal(normalizePullCommentAnchor(selection('sha1', { source_ref_hex: hex(exact) }), 'sha1').source_ref_hex, hex(exact));
  for (const raw of [exact + 'a', 'refs/heads/', 'refs/tags/topic', '/refs/heads/topic', 'refs/heads/a//b',
    'refs/heads/a..b', 'refs/heads/a@{b', 'refs/heads/.topic', 'refs/heads/topic.lock/sub', 'refs/heads/topic.',
    'refs/heads/to pic', 'refs/heads/topic\0', 'refs/heads/topic\x7f', 'refs/heads/a\\b']) {
    refuses(selection('sha1', { source_ref_hex: hex(raw) }));
  }
  refuses(selection('sha1', { source_ref_hex: hex('refs/heads/main') }));
  for (const value of ['', '0', 'GG', '726566732F68656164732F61']) refuses(selection('sha1', { source_ref_hex: value }));
  const raw = Buffer.from('refs/heads/\x80\xff', 'latin1');
  assert.equal(normalizePullCommentAnchor(selection('sha1', { source_ref_hex: hex(raw) }), 'sha1').source_ref_hex, hex(raw));
});

test('raw paths retain source bytes with exact length and depth boundaries', () => {
  for (const raw of ['x'.repeat(4096), Array(64).fill('x').join('/'), '.github/workflows/check.yml',
    'src/a..b', 'src/a\\b', Buffer.from('src/\xff\r\n', 'latin1')]) {
    const path_hex = hex(raw);
    assert.equal(normalizePullCommentAnchor(selection('sha1', { path_hex }), 'sha1').path_hex, path_hex);
  }
  for (const raw of ['', 'x'.repeat(4097), Array(65).fill('x').join('/'), '/x', 'x/', 'x//y',
    '.', '..', 'x/./y', 'x/../y', 'x\0y']) refuses(selection('sha1', { path_hex: hex(raw) }));
  for (const path_hex of ['FF', '1', '0z']) refuses(selection('sha1', { path_hex }));
});
