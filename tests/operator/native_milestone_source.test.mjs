// Pure versioned source/compiler contracts plus fully verified archive input.
// No destination commands are sent by these tests.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readIssueArchive } from '../../scripts/lib/forge-issue-archive.mjs';
import { parseNativeIssueCapture, nativeCaptureBytes, nativeIssueImportSteps,
  partitionNativeIssueArchive, NATIVE_CAPTURE_SCHEMA_V3 }
  from '../../scripts/lib/native-issue-source.mjs';
import { parseNativeMilestoneMap, validateNativeMilestoneMap, nativeMilestoneCaptureBytes,
  parseNativeMilestoneCapture, nativeMilestoneImportSteps, partitionNativeIssueArchiveWithMilestones,
  NATIVE_MILESTONE_MAP_SCHEMA, NATIVE_MILESTONE_CAPTURE_SCHEMA }
  from '../../scripts/lib/native-milestone-source.mjs';
import { setupMilestones, actor, encode } from './native_milestone_transfer_helper.mjs';

const mappings = [{ source: 1, destination: 70 }, { source: 2, destination: 5 }, { source: 3, destination: 800 }];
async function archive(t, options) {
  const f = await setupMilestones(t, { pageSize: 100, ...options });
  return { ...f, view: await readIssueArchive({ workdir: f.archiveDir, confirm: f.archive.archive_sha256 }) };
}

test('v3 compiles all mapped milestone opens before issue membership and source-closed milestones last', async t => {
  const f = await archive(t), before = f.src.calls.length;
  const mapBytes = encode({ schema: NATIVE_MILESTONE_MAP_SCHEMA, mappings });
  assert.deepEqual(parseNativeMilestoneMap(mapBytes), mappings);
  const batches = partitionNativeIssueArchiveWithMilestones(f.view, { offset: 1000, milestoneMap: mappings });
  assert.deepEqual(batches.map(batch => [batch.kind, batch.phase, batch.steps]),
    [['milestone', 'open', 3], ['issue', 'issues', 10], ['milestone', 'close', 1]]);
  const opened = parseNativeMilestoneCapture(batches[0].bytes), issues = parseNativeIssueCapture(batches[1].bytes);
  const closed = parseNativeMilestoneCapture(batches[2].bytes);
  assert.equal(opened.schema, NATIVE_MILESTONE_CAPTURE_SCHEMA);
  assert.equal(issues.schema, NATIVE_CAPTURE_SCHEMA_V3); assert.deepEqual(issues.milestone_map, mappings);
  assert.deepEqual(nativeMilestoneCaptureBytes(opened), batches[0].bytes);
  assert.deepEqual(nativeCaptureBytes(issues), batches[1].bytes);
  const opens = nativeMilestoneImportSteps(opened), commands = nativeIssueImportSteps(issues, 1000);
  assert.deepEqual(opens.map(step => [step.number, step.expected_version, step.action]),
    [[70, 0, 'open'], [5, 0, 'open'], [800, 0, 'open']]);
  assert.deepEqual(opens.map(step => step.fields.due_at), [253402300799, null, 1]);
  for (const [index, step] of opens.entries()) {
    assert.ok(step.fields.body.endsWith(f.view.milestones[index].snapshot.body));
    assert.ok(step.fields.body.includes('attribution only'));
    assert.ok(step.fields.body.includes(`"source_opened_by":"${actor}"`));
    assert.ok(step.fields.body.includes(`"source_version":${f.view.milestones[index].snapshot.version}`));
  }
  const selected = commands.filter(step => step.action === 'set-milestone');
  assert.deepEqual(selected.map(step => [step.number, step.fields]), [
    [1001, { milestone: 70, expected_milestone_version: 1 }],
    [1003, { milestone: 5, expected_milestone_version: 1 }],
  ]);
  assert.deepEqual(commands.filter(step => step.number === 1001).map(step => step.action),
    ['open', 'comment', 'set-milestone', 'close', 'lock']);
  assert.deepEqual(commands.filter(step => step.number === 1001).map(step => step.expected_version), [0, 1, 2, 3, 4]);
  assert.deepEqual(commands.filter(step => step.number === 1002).map(step => step.action), ['open', 'comment']);
  assert.ok(commands.find(step => step.number === 1002 && step.action === 'open').fields.body.includes('"source_milestone":null'));
  assert.deepEqual(closed.milestones.map(row => [row.source_number, row.destination_number]), [[1, 70]]);
  assert.deepEqual(nativeMilestoneImportSteps(closed).map(step => [step.number, step.expected_version, step.action, step.fields]),
    [[70, 1, 'close', {}]]);
  assert.equal(f.src.calls.length, before, 'partition and compilation are entirely offline');
  assert.throws(() => partitionNativeIssueArchive(f.view, 1000), /milestone_profile_required/);
});

test('mapping requires exact source coverage, unique destination IDs and canonical bounded bytes', async t => {
  const { view } = await archive(t);
  for (const bad of [mappings.slice(0, 2), [...mappings, { source: 4, destination: 801 }],
    [{ source: 1, destination: 70 }, { source: 2, destination: 70 }, { source: 3, destination: 800 }],
    [mappings[1], mappings[0], mappings[2]], [{ source: 1, destination: 0 }],
    [{ source: 1, destination: Number.MAX_SAFE_INTEGER + 1 }]]) {
    assert.throws(() => partitionNativeIssueArchiveWithMilestones(view, { milestoneMap: bad }));
  }
  assert.deepEqual(validateNativeMilestoneMap(mappings, view.milestones), mappings);
  const bytes = encode({ schema: NATIVE_MILESTONE_MAP_SCHEMA, mappings });
  assert.throws(() => parseNativeMilestoneMap(Buffer.from(JSON.stringify(JSON.parse(bytes), null, 2) + '\n')), /encoding/);
  assert.throws(() => parseNativeMilestoneMap(encode({ mappings, schema: NATIVE_MILESTONE_MAP_SCHEMA })), /encoding/);
  assert.throws(() => parseNativeMilestoneMap(encode({ schema: NATIVE_MILESTONE_MAP_SCHEMA, mappings, ignored: true })), /fields/);
  assert.throws(() => parseNativeMilestoneMap(new Uint8Array(new SharedArrayBuffer(bytes.length))), /capture_bytes/);
});

test('v3 capture rejects missing membership mappings and milestone captures reject wrong phase or lossy due dates', async t => {
  const { view } = await archive(t);
  const batches = partitionNativeIssueArchiveWithMilestones(view, { milestoneMap: mappings });
  const issue = parseNativeIssueCapture(batches[1].bytes);
  const missing = structuredClone(issue); missing.milestone_map = missing.milestone_map.slice(1);
  assert.throws(() => nativeCaptureBytes(missing), /milestone_mapping_missing/);
  const unknown = structuredClone(issue); unknown.issues[0].snapshot.milestone = 99;
  assert.throws(() => nativeCaptureBytes(unknown), /milestone_mapping_missing/);
  const legacy = structuredClone(issue); legacy.schema = 'frankengit-native-issue-capture-v2'; delete legacy.milestone_map;
  assert.throws(() => nativeCaptureBytes(legacy), /milestones_unsupported/);
  const open = parseNativeMilestoneCapture(batches[0].bytes);
  const close = structuredClone(open); close.phase = 'close';
  assert.throws(() => nativeMilestoneCaptureBytes(close), /close_phase/);
  for (const due of [-1, 253402300800, 0.5, '42']) {
    const invalid = structuredClone(open); invalid.milestones[0].snapshot.due_at = due;
    assert.throws(() => nativeMilestoneCaptureBytes(invalid));
  }
  const wrong = structuredClone(open); wrong.milestones[0].snapshot.number = 4;
  assert.throws(() => nativeMilestoneCaptureBytes(wrong), /milestone_identity/);
  const overflow = structuredClone(open); overflow.milestones[0].snapshot.body = 'x'.repeat(64 * 1024);
  assert.throws(() => nativeMilestoneImportSteps(overflow), /body/i, 'provenance expansion never truncates original content');
});

test('milestone-only migration includes unreferenced aggregates and rejects a wholly empty migration', async t => {
  const { view } = await archive(t, { rows: [] });
  const batches = partitionNativeIssueArchiveWithMilestones(view, { milestoneMap: mappings });
  assert.deepEqual(batches.map(batch => [batch.kind, batch.phase, batch.steps]), [['milestone', 'open', 3], ['milestone', 'close', 1]]);
  assert.deepEqual(parseNativeMilestoneCapture(batches[0].bytes).milestones.map(row => row.source_number), [1, 2, 3]);
  const empty = await archive(t, { rows: [], milestones: [] });
  assert.throws(() => partitionNativeIssueArchiveWithMilestones(empty.view, { milestoneMap: [] }), /empty_migration/);
  const issueOnly = await archive(t, { milestones: [], rows: [{ number: 1, events: [{ version: 1, actor,
    action: { name: 'open', title: 'Unassigned', body: '', labels: [] } }] }] });
  const issueBatches = partitionNativeIssueArchiveWithMilestones(issueOnly.view, { milestoneMap: [] });
  assert.equal(issueBatches.length, 1); assert.equal(issueBatches[0].kind, 'issue');
  assert.deepEqual(parseNativeIssueCapture(issueBatches[0].bytes).milestone_map, []);
});

test('milestone partitions retain whole captures, complete source order and both phase boundaries', async t => {
  const { view: original } = await archive(t, { rows: [] });
  // A pure compiler capacity fixture. Only the initial source identity comes
  // from the verified archive; this is not described as a native read proof.
  const count = 101, snapshot = original.milestones[0].snapshot;
  const milestones = Array.from({ length: count }, (_, i) => ({ snapshot: { ...snapshot,
    number: i + 1, version: 2, title: `Release ${i + 1}`, body: '', state: 'closed', open_issues: 0, closed_issues: 0 }, events: [] }));
  const view = { archive: { ...original.archive, milestones: count }, records: [], milestones };
  const map = milestones.map(row => ({ source: row.snapshot.number, destination: row.snapshot.number + 500 }));
  const batches = partitionNativeIssueArchiveWithMilestones(view, { milestoneMap: map });
  assert.deepEqual(batches.map(batch => [batch.phase, batch.steps]), [['open', 100], ['open', 1], ['close', 100], ['close', 1]]);
  for (const phase of ['open', 'close']) assert.deepEqual(batches.filter(batch => batch.phase === phase)
    .flatMap(batch => parseNativeMilestoneCapture(batch.bytes).milestones.map(row => row.source_number)),
  Array.from({ length: count }, (_, i) => i + 1));
  assert.ok(batches.every(batch => batch.bytes.length <= 1024 * 1024));
});
