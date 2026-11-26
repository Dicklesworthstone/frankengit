import test from 'node:test';
import assert from 'node:assert/strict';
import { activityPage } from '../../crates/fgit-node/src/smart_http/server/browser/activity.mjs';

const grants = ['issues_read', 'pulls_read', 'discussions_read', 'reviews_read'];
const event = { cursor: '9007199254740993:2', repository_sequence: '9007199254740993', event_index: '2',
  tx_id: 'tx:collaboration', policy_epoch: '18446744073709551615', aggregate: 'discussion:1',
  aggregate_version: '1', kind: 81, event_frame_hex: '00ffabcd' };
const page = (extra = {}) => ({ type: 'forge_event_page', schema_version: 1,
  tenant_id: 'tenant', repository_id: 'repository', repository_incarnation: 'incarnation',
  object_format: 'sha1', source_head: 'head:first', snapshot_token: 'alg:1:' + 'ab'.repeat(32),
  read_only: true, disclosure_profile: 'collaboration-v2', issues_read: false, pulls_read: false,
  discussions_read: true, reviews_read: false, omits_other_event_families: true,
  cursor_discloses_repository_activity: true, events: [event], next_after: null,
  resume_after: event.cursor, has_more: false, complete: true, ...extra });

for (const format of ['sha1', 'sha256']) for (let mask = 1; mask < 16; mask++) {
  test(`${format}: collaboration accepts exact independent grant set ${mask}`, () => {
    const raw = page({ object_format: format, ...Object.fromEntries(grants.map((name, bit) => [name, Boolean(mask & (1 << bit))])) });
    const observed = activityPage(raw);
    assert.deepEqual(observed, raw);
    assert.equal(observed.schema_version, 1, 'profile evolution does not change the native envelope');
    assert.equal(observed.events[0].event_frame_hex, '00ffabcd', 'canonical bytes remain opaque and exact');
    assert.equal(observed.events[0].repository_sequence, '9007199254740993');
    observed.events[0].event_frame_hex = 'ffff';
    assert.equal(raw.events[0].event_frame_hex, '00ffabcd', 'the retained observation does not alias the input');
  });
}
test('collaboration requires at least one grant and all four explicit booleans', () => {
  assert.throws(() => activityPage(page(Object.fromEntries(grants.map(name => [name, false])))));
  for (const name of grants) {
    const missing = page(); delete missing[name];
    assert.throws(() => activityPage(missing), name);
    for (const value of [null, 0, 1, 'true', undefined]) assert.throws(() => activityPage(page({ [name]: value })), name);
  }
});
test('v1 retains its exact field shape and never acquires collaboration grants implicitly', () => {
  const original = page({ disclosure_profile: 'issues-pulls-v1', issues_read: true });
  delete original.discussions_read; delete original.reviews_read;
  assert.deepEqual(activityPage(original), original);
  assert.throws(() => activityPage({ ...original, discussions_read: false }));
  assert.throws(() => activityPage({ ...original, reviews_read: false }));
  assert.throws(() => activityPage({ ...original, disclosure_profile: 'collaboration-v2' }));
});
test('changing the disclosure profile requires reconnect even when existing grants match', () => {
  const raw = page({ issues_read: true, discussions_read: false });
  const v1Scope = { tenant_id: raw.tenant_id, repository_id: raw.repository_id,
    repository_incarnation: raw.repository_incarnation, object_format: raw.object_format,
    issues_read: true, pulls_read: false };
  assert.throws(() => activityPage(raw, { previous: v1Scope }), error => error.clearActivity === true);
  const previous = page({ issues_read: true });
  const v1 = { ...raw, disclosure_profile: 'issues-pulls-v1' }; delete v1.discussions_read; delete v1.reviews_read;
  assert.throws(() => activityPage(v1, { previous }), error => error.clearActivity === true);
});
for (const name of grants) test(`collaboration scope change clears prior observations: ${name}`, () => {
  const previous = page(Object.fromEntries(grants.map(name => [name, true])));
  const changed = { ...previous, [name]: false };
  assert.throws(() => activityPage(changed, { previous }), error => error.clearActivity === true);
});
test('v2 keeps filtered cursor progress, exact snapshot pins and bounded pages', () => {
  const raw = page({ events: [], next_after: event.cursor, resume_after: event.cursor, has_more: true, complete: false });
  assert.equal(activityPage(raw, { previous: raw, expectedHead: raw.snapshot_token }).has_more, true);
  assert.throws(() => activityPage(raw, { after: event.cursor }), /continuation|watermark/);
  assert.throws(() => activityPage(raw, { expectedHead: 'alg:1:' + 'cd'.repeat(32) }), /snapshot moved/);
  const extra = { ...event, cursor: '9007199254740993:3', event_index: '3' };
  assert.throws(() => activityPage(page({ events: [event, extra], resume_after: extra.cursor }), { limit: 1 }), /bound/);
});
test('unknown profiles, extra fields and invented envelope versions remain refusals', () => {
  for (const disclosure_profile of ['', null, 'collaboration-v3', 'Issues-Pulls-V1']) {
    assert.throws(() => activityPage(page({ disclosure_profile })));
  }
  assert.throws(() => activityPage(page({ schema_version: 2 })));
  assert.throws(() => activityPage(page({ workflow_checks_read: true })));
});
