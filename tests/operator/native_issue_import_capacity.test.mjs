// Source compiler boundaries, using owned archive-view fixtures. These do not
// claim an HTTP/Rust archive or native publication capacity measurement.
import test from 'node:test';
import assert from 'node:assert/strict';
import { partitionNativeIssueArchive, parseNativeIssueCapture, nativeIssueImportSteps, nativeCaptureBytes }
  from '../../scripts/lib/native-issue-source.mjs';
import { fixtureIssues, snapshot, encode, head, actor } from './native_issue_transfer_helper.mjs';
function view(count) {
  return { archive: { complete: true, canonical_backup: false, issues: count,
    href: 'https://fixture.invalid/repository/ui/issues/', tenant_id: '1'.repeat(32), repository_id: '2'.repeat(32),
    snapshot_token: head, source_head: 'fixture-source-head', archive_sha256: 'a'.repeat(64) },
    records: fixtureIssues(count).map(row => ({ snapshot: snapshot(row), comments: row.events.filter(e => e.action.name === 'comment')
      .map(e => ({ version: e.version, actor: e.actor, body: e.action.body })) })) };
}
test('4096 issues partition completely in deterministic canonical membership order', () => {
  const v = view(4096), first = partitionNativeIssueArchive(v, 100000), second = partitionNativeIssueArchive(v, 100000);
  assert.equal(first.length, 41); assert.equal(first.at(-1).issues.length, 96);
  assert.deepEqual(first.map(b => b.sha256), second.map(b => b.sha256));
  assert.deepEqual(first.flatMap(b => b.issues.map(r => r.number)), Array.from({ length: 4096 }, (_, i) => i + 1));
  assert.equal(first.reduce((n, b) => n + b.steps, 0), 4096 + 2 * Math.ceil(4096 / 3));
  for (const part of first) {
    assert.ok(part.bytes.length <= 1024 * 1024);
    const steps = nativeIssueImportSteps(parseNativeIssueCapture(part.bytes), 100000);
    assert.equal(steps.length, part.steps); assert.ok(encode(steps).length <= 1024 * 1024);
  }
});
test('source issue ceiling and complete population checks refuse, never truncate', () => {
  assert.throws(() => partitionNativeIssueArchive(view(4097)), /source issue count/);
  const v = view(3); v.archive.issues = 2;
  assert.throws(() => partitionNativeIssueArchive(v), /archive_view/);
  v.archive.issues = 3; v.archive.complete = false;
  assert.throws(() => partitionNativeIssueArchive(v), /archive_view/);
});
function discussionView(comments) {
  const v = view(25);
  for (const record of v.records) {
    record.snapshot = { ...record.snapshot, version: comments + 1, state: 'open',
      opened_by: actor, last_actor: actor, comments, assignees: [] };
    record.comments = Array.from({ length: comments }, (_, i) => ({ version: i + 2, actor, body: 'discussion' }));
  }
  return v;
}
test('10000 destination commands fit exactly; 10001-plus refuses before a partial partition is returned', () => {
  const v = discussionView(399), parts = partitionNativeIssueArchive(v);
  assert.equal(parts.reduce((n, b) => n + b.steps, 0), 10000);
  assert.equal(parts.flatMap(b => b.issues).length, 25);
  v.records.at(-1).comments.push({ version: 401, actor, body: 'one too many' });
  v.records.at(-1).snapshot.version++; v.records.at(-1).snapshot.comments++;
  assert.throws(() => partitionNativeIssueArchive(v), /step_limit/);
});
test('indivisible oversized discussions refuse rather than dropping or relocating comments', () => {
  const v = view(1), r = v.records[0]; r.snapshot.version = 2002; r.snapshot.comments = 2001;
  r.comments = Array.from({ length: 2001 }, (_, i) => ({ version: i + 2, actor, body: 'discussion' }));
  assert.throws(() => partitionNativeIssueArchive(v), /comment_limit/);
});
test('strict native source codecs reject ambiguous buffers, counters, ordering and hidden fields', () => {
  const original = parseNativeIssueCapture(partitionNativeIssueArchive(view(3))[0].bytes);
  const failures = [
    value => { value.issues[0].comments[0].version = 1; },
    value => { value.issues[0].comments.push({ ...value.issues[0].comments[0] }); value.issues[0].snapshot.comments++; },
    value => { value.issues.reverse(); },
    value => { value.issues[0].snapshot.comments++; },
    value => { value.source.permission = 'writer'; },
    value => { value.issues[0].snapshot.assignees = ['non-principal']; },
    value => { value.issues[0].snapshot.number = 9; }
  ];
  for (const change of failures) { const value = structuredClone(original); change(value); assert.throws(() => nativeCaptureBytes(value)); }
  const bytes = nativeCaptureBytes(original);
  const shared = new Uint8Array(new SharedArrayBuffer(bytes.length)); shared.set(bytes);
  assert.throws(() => parseNativeIssueCapture(shared), /capture_bytes/);
  assert.throws(() => parseNativeIssueCapture(Buffer.concat([Buffer.from([239,187,191]), bytes])), /JSON|encoding/);
  assert.throws(() => parseNativeIssueCapture(Buffer.from(bytes.toString().replace('"number":1', '"number":1e0'))), /encoding/);
});
test('provenance fencing cannot close early on source metadata and retains complete source body', () => {
  const v = view(1); v.archive.href = 'https://fixture.invalid/a~~~~b/ui/issues/';
  v.records[0].snapshot.body = 'body <script>\r\n\u202e exact';
  const part = partitionNativeIssueArchive(v)[0], capture = parseNativeIssueCapture(part.bytes);
  const steps = nativeIssueImportSteps(capture);
  assert.ok(steps[0].fields.body.includes('\n~~~~~json\n'));
  assert.ok(steps[0].fields.body.endsWith(v.records[0].snapshot.body));
  assert.deepEqual(steps.map(s => s.action), ['open', 'comment', 'close']);
});
