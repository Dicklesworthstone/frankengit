import test from 'node:test';
import assert from 'node:assert/strict';
import { compileSourceReplacements, RUN_DELTA_REPLACEMENT_PROFILE, REPLACEMENT_PROFILE } from '../../scripts/operator/source_edit_replacements.mjs';
import { planBinaryMember, planBinaryRunMember, BINARY_RUN_LIMITS } from '../../scripts/operator/source_edit_binary_delta.mjs';
import { change } from './source_edit_binary_fixture.mjs';
import { coldOracle } from './source_edit_delta_fixture.mjs';

function pair(size = 800000) {
  const before = Buffer.alloc(size, 97); before[0] = 0;
  const after = Buffer.from(before); after[64] = 98; after[size - 100] = 99;
  return { before, after };
}

for (const format of ['sha1', 'sha256']) test(`${format}: distant binary edits fit without raising the patch ceiling`, () => {
  const { before, after } = pair(), rows = [change(format, 'asset.bin', before, after)];
  assert.throws(() => compileSourceReplacements(format, rows, { binary: 'literal' }), /patch_limit/);
  assert.throws(() => compileSourceReplacements(format, rows, { binary: 'delta' }), /patch_limit/);
  const result = compileSourceReplacements(format, rows, { binary: 'delta-runs' });
  assert.equal(result.profile, RUN_DELTA_REPLACEMENT_PROFILE);
  assert.equal(result.delta_members, 2); assert.equal(result.literal_members, 0);
  assert.ok(result.aligned_copy_regions >= 4); assert.ok(result.patch.length < 1024);
  coldOracle(format, rows, result.patch);
  coldOracle(format, rows, result.patch, true);
  assert.deepEqual(compileSourceReplacements(format, rows,
    { binary: 'delta-runs', maxPatchBytes: result.patch.length }).patch, result.patch);
  assert.throws(() => compileSourceReplacements(format, rows,
    { binary: 'delta-runs', maxPatchBytes: result.patch.length - 1 }), /patch_limit/);
});

test('multi-region planner never costs more than the existing delta plan', () => {
  const { before, after } = pair(200000);
  const legacy = planBinaryMember(before, after, () => {});
  const selected = planBinaryRunMember(before, after, () => {});
  assert.ok(selected.cost.bytes <= legacy.cost.bytes);
  assert.ok(selected.cost.records <= legacy.cost.records);
  assert.ok(selected.aligned_copy_regions > 0);
});

test('existing default/text bytes remain unchanged and profile selection is closed', () => {
  const rows = [change('sha1', 'a', 'old\n', 'new\n')];
  assert.deepEqual(compileSourceReplacements('sha1', rows, { binary: 'delta-runs' }).patch,
    compileSourceReplacements('sha1', rows).patch);
  assert.equal(compileSourceReplacements('sha1', rows).profile, REPLACEMENT_PROFILE);
  for (const binary of ['auto', 'delta-runs-v2', 'Delta-runs', true, null])
    assert.throws(() => compileSourceReplacements('sha1', rows, { binary }), /binary_profile/);
});

test('explicit region exhaustion refuses instead of falling back to legacy output', () => {
  const size = 17 * (BINARY_RUN_LIMITS.maxCopyRegions + 1);
  const before = Buffer.alloc(size), after = Buffer.from(before);
  for (let at = 16; at < size; at += 17) { before[at] = 1; after[at] = 2; }
  assert.throws(() => planBinaryRunMember(before, after, () => {}), /regions_limit/);
  assert.doesNotThrow(() => planBinaryMember(before, after, () => {}));
});

test('cancellation checkpoints interrupt long same-offset scans', () => {
  const { before, after } = pair(1048576);
  let visits = 0;
  assert.throws(() => planBinaryRunMember(before, after, () => {
    if (++visits === 5) throw new Error('cancelled');
  }), /cancelled/);
  assert.equal(visits, 5);
});
