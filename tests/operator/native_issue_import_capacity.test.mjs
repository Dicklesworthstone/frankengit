// Source compiler boundaries, using owned archive-view fixtures. These do not
// claim an HTTP/Rust archive or native publication capacity measurement.
import test from 'node:test';
import assert from 'node:assert/strict';
import { partitionNativeIssueArchive, parseNativeIssueCapture, nativeIssueImportSteps, nativeCaptureBytes,
  NATIVE_CAPTURE_SCHEMA, NATIVE_CAPTURE_SCHEMA_V2 }
  from '../../scripts/lib/native-issue-source.mjs';
import { fixtureIssues, snapshot, encode, head, actor } from './native_issue_transfer_helper.mjs';
function view(count) {
  return { archive: { complete: true, canonical_backup: false, issues: count,
    href: 'https://fixture.invalid/repository/ui/issues/', tenant_id: '1'.repeat(32), repository_id: '2'.repeat(32),
    snapshot_token: head, source_head: 'fixture-source-head', archive_sha256: 'a'.repeat(64) },
    records: fixtureIssues(count).map(row => ({ snapshot: snapshot(row), comments: row.events.filter(e => e.action.name === 'comment')
      .map(e => ({ version: e.version, actor: e.actor, body: e.action.body })) })) };
}
test('null membership preserves capture bytes while native targets explicitly refuse migration', () => {
  const original=view(3), expected=partitionNativeIssueArchive(original);
  const unassigned=structuredClone(original);
  for (const row of unassigned.records) row.snapshot.milestone=null;
  assert.deepEqual(partitionNativeIssueArchive(unassigned).map(part=>part.bytes),expected.map(part=>part.bytes));
  assert.ok(unassigned.records.every(row=>Object.hasOwn(row.snapshot,'milestone')));
  const assigned=structuredClone(original); assigned.records[0].snapshot.milestone=7;
  assert.throws(()=>partitionNativeIssueArchive(assigned),/milestones_unsupported/);
  const capture=parseNativeIssueCapture(expected[0].bytes); capture.issues[0].snapshot.milestone=7;
  assert.throws(()=>nativeCaptureBytes(capture),/milestones_unsupported/);
});
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

test('capture dialects have distinct strict lock fields and canonical bytes', () => {
  const v = view(3), original = structuredClone(v);
  v.records[0].snapshot.locked = true;
  const part = partitionNativeIssueArchive(v)[0], capture = parseNativeIssueCapture(part.bytes);
  assert.equal(capture.schema, NATIVE_CAPTURE_SCHEMA_V2);
  assert.deepEqual(capture.issues.map(row => row.snapshot.locked), [true, false, false]);
  assert.deepEqual(nativeCaptureBytes(capture), part.bytes);
  assert.deepEqual(v.records.slice(1), original.records.slice(1));
  assert.equal(v.records[0].snapshot.locked, true);
  for (const bad of [null, 'true', 'false', 0, 1, undefined, [], {}]) {
    const changed = structuredClone(capture); changed.issues[0].snapshot.locked = bad;
    assert.throws(() => nativeCaptureBytes(changed), /Invalid issue lock state/);
  }
  const missing = structuredClone(capture); delete missing.issues[0].snapshot.locked;
  assert.throws(() => nativeCaptureBytes(missing), /fields/);
  const inherited = structuredClone(capture);
  Object.setPrototypeOf(inherited.issues[0].snapshot, { locked: true });
  delete inherited.issues[0].snapshot.locked;
  assert.throws(() => nativeCaptureBytes(inherited), /fields/);
  const reordered = structuredClone(capture), state = reordered.issues[0].snapshot;
  reordered.issues[0].snapshot = { locked: state.locked, ...state };
  assert.throws(() => nativeCaptureBytes(reordered), /encoding/);
  const duplicate = part.bytes.toString().replace('"locked":true', '"locked":false,"locked":true');
  assert.throws(() => parseNativeIssueCapture(Buffer.from(duplicate)), /encoding/);
  for (const schema of ['frankengit-native-issue-capture-v0', 'frankengit-native-issue-capture-v3',
    'frankengit-github-issue-capture-v1']) {
    assert.throws(() => nativeCaptureBytes({ ...capture, schema }), /schema/);
  }
  const legacy = structuredClone(capture); legacy.schema = NATIVE_CAPTURE_SCHEMA;
  assert.throws(() => nativeCaptureBytes(legacy), /fields/, 'v1 cannot carry an ignored moderation coordinate');
  for (const issue of legacy.issues) delete issue.snapshot.locked;
  assert.deepEqual(parseNativeIssueCapture(nativeCaptureBytes(legacy)), legacy);
  assert.ok(nativeIssueImportSteps(legacy).every(step => step.action !== 'lock'));
});

test('locked discussions remain indivisible within every batch envelope', () => {
  const v = view(100);
  for (const row of v.records) {
    row.snapshot.state = 'closed'; row.snapshot.locked = true;
    row.snapshot.comments = 20; row.snapshot.version = 23;
    row.comments = Array.from({ length: 20 }, (_, index) => ({ version: index + 2, actor, body: 'discussion' }));
  }
  const before = structuredClone(v), parts = partitionNativeIssueArchive(v, 1000);
  assert.ok(parts.length > 1);
  assert.equal(parts.reduce((sum, part) => sum + part.steps, 0), 2300);
  assert.deepEqual(parts.flatMap(part => part.issues.map(row => row.number)), Array.from({ length: 100 }, (_, index) => index + 1));
  for (const part of parts) {
    const capture = parseNativeIssueCapture(part.bytes), steps = nativeIssueImportSteps(capture, 1000);
    assert.ok(part.bytes.length <= 1024 * 1024);
    assert.ok(encode(steps).length <= 1024 * 1024);
    assert.ok(steps.length <= 2200); assert.equal(steps.length, part.steps);
    assert.ok(capture.issues.length <= 100);
    assert.ok(capture.issues.reduce((sum, row) => sum + row.comments.length, 0) <= 2000);
    for (const issue of capture.issues) {
      const commands = steps.filter(step => step.number === issue.number + 1000);
      assert.deepEqual(commands.map(step => step.action), ['open', ...Array(20).fill('comment'), 'close', 'lock']);
      assert.deepEqual(commands.map(step => step.expected_version), Array.from({ length: 23 }, (_, index) => index));
      assert.deepEqual(commands.at(-1).fields, {});
    }
  }
  assert.deepEqual(v, before);
  // A standalone capture must honor the same command limit even though its
  // small raw source fits; it cannot bypass the partitioner's child envelope.
  const all = { ...parseNativeIssueCapture(parts[0].bytes),
    issues: parts.flatMap(part => parseNativeIssueCapture(part.bytes).issues) };
  assert.ok(nativeCaptureBytes(all).length <= 1024 * 1024);
  assert.throws(() => nativeIssueImportSteps(all), /native_plan_steps/);
});

test('locks count toward the whole migration limit and never require source predecessor refresh', () => {
  const v = discussionView(398);
  for (const row of v.records) { row.snapshot.locked = true; row.snapshot.version++; }
  const parts = partitionNativeIssueArchive(v);
  assert.equal(parts.reduce((sum, part) => sum + part.steps, 0), 10000);
  for (const part of parts) {
    const steps = nativeIssueImportSteps(parseNativeIssueCapture(part.bytes));
    assert.equal(steps.filter(step => step.action === 'lock').length, part.issues.length);
  }
  v.records[0].snapshot.state = 'closed'; v.records[0].snapshot.version++;
  assert.throws(() => partitionNativeIssueArchive(v), /step_limit/);
});
