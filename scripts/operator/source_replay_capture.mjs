// Create-only local custody of both replay bases. Nothing here changes a native
// publication journal, contacts an endpoint, or interprets absence as non-commit.
import { mkdir, lstat } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { replaySourceChanges, reviewedHash, fail, SOURCE_REPLAY_PROFILE } from './source_replay.mjs';
import { canonical, sha256, SOURCE_PACKAGE_BYTES, CHANGES_INPUT_BYTES } from './source_changes.mjs';
import { fields, parse, clock } from './source_edit_wire.mjs';
import { absolute, directory, readPrivate, writeNew, syncDirectory } from './workflow_watch_io.mjs';

export const REPLAY_CAPTURE_SCHEMA = 'frankengit-source-replay-capture-v1';
export const REPLAY_MANIFEST_BYTES = 32768;
export const REPLAY_PAYLOAD_LIMITS = Object.freeze({
  'original-source.json': SOURCE_PACKAGE_BYTES, 'original-expected.json': 131072,
  'changes.json': CHANGES_INPUT_BYTES, 'source.json': SOURCE_PACKAGE_BYTES, 'expected.json': 131072,
  'original-draft.json': 262144, 'patch.diff': 1048576, 'draft.json': 262144, 'replay.json': 16384,
});
export async function absentReplayOutput(path) {
  await directory(dirname(absolute(path)));
  try { await lstat(path); fail('source_replay_output_exists'); } catch (e) { if (e.code !== 'ENOENT') throw e; }
}
function payloads(replay) {
  const result = { 'original-source.json': replay.original.packageBytes, 'original-expected.json': canonical(replay.original.expected),
    'changes.json': canonical(replay.next.changes), 'source.json': replay.next.packageBytes, 'expected.json': canonical(replay.next.expected),
    'original-draft.json': canonical(replay.previousDraft.manifest), 'patch.diff': replay.draft.bytes,
    'draft.json': canonical(replay.draft.manifest), 'replay.json': canonical(replay.receipt) };
  for (const [name, bytes] of Object.entries(result)) if (bytes.length > REPLAY_PAYLOAD_LIMITS[name]) fail('source_replay_capture_limit');
  return result;
}
function manifestFor(replay, bodies) {
  return { schema: REPLAY_CAPTURE_SCHEMA, profile: SOURCE_REPLAY_PROFILE,
    original_draft_sha256: replay.receipt.original_draft_sha256,
    draft_sha256: replay.receipt.draft_sha256, replay_sha256: sha256(bodies['replay.json']),
    payloads: Object.keys(REPLAY_PAYLOAD_LIMITS).map(name => ({ name, bytes: bodies[name].length, sha256: sha256(bodies[name]) })) };
}
function saved(path, hash, replay) {
  return { type: 'source_replay_capture', directory: path, capture_sha256: hash, ...replay.receipt };
}
export async function captureSourceReplay(output, packageBytes, expected, changes, nextPackageBytes, nextExpected, options) {
  fields(options, ['confirmDraftSha256', 'signal', 'timeoutMs'], ['confirmDraftSha256']);
  const time = clock({ signal: options.signal, timeoutMs: options.timeoutMs }); absolute(output); time.check();
  // The core captures both bases synchronously before any awaited filesystem
  // work. Only verified owned inputs can become the fixed replay payloads.
  const replay = await replaySourceChanges(packageBytes, expected, changes, nextPackageBytes, nextExpected,
    { confirmDraftSha256: options.confirmDraftSha256, signal: time.signal, timeoutMs: time.remaining() });
  time.check(); await absentReplayOutput(output); time.check();
  const bodies = payloads(replay), root = canonical(manifestFor(replay, bodies));
  if (root.length > REPLAY_MANIFEST_BYTES) fail('source_replay_capture_limit');
  const result = saved(output, sha256(root), replay);
  time.check(); await mkdir(output, { mode: 0o700 });
  try {
    await syncDirectory(dirname(output));
    for (const [name, bytes] of Object.entries(bodies)) {
      time.check(); await writeNew(join(output, name), bytes);
      if (!bytes.equals(await readPrivate(join(output, name), REPLAY_PAYLOAD_LIMITS[name]))) fail('source_replay_output_changed');
    }
    time.check();
    // The last-written root names complete immutable payloads. Drain this begun
    // publication/readback on a late stop; a lost reply never implies absence.
    await writeNew(join(output, 'manifest.json'), root);
    if (!root.equals(await readPrivate(join(output, 'manifest.json'), REPLAY_MANIFEST_BYTES))) fail('source_replay_output_changed');
    await syncDirectory(output); await syncDirectory(dirname(output));
    return { ...result, stop_requested: time.signal?.aborted ?? false };
  } catch (error) { error.publication_unconfirmed = result; throw error; }
}
export async function loadSourceReplay(path, expectedHash, options = {}) {
  fields(options, ['signal', 'timeoutMs'], []);
  const time = clock(options); absolute(path); reviewedHash(expectedHash); time.check(); await directory(path);
  const root = await readPrivate(join(path, 'manifest.json'), REPLAY_MANIFEST_BYTES); time.check();
  if (sha256(root) !== expectedHash) fail('source_replay_capture_changed');
  const manifest = parse(root, REPLAY_MANIFEST_BYTES);
  fields(manifest, ['schema', 'profile', 'original_draft_sha256', 'draft_sha256', 'replay_sha256', 'payloads']);
  if (manifest.schema !== REPLAY_CAPTURE_SCHEMA || manifest.profile !== SOURCE_REPLAY_PROFILE ||
      !Array.isArray(manifest.payloads) || manifest.payloads.length !== Object.keys(REPLAY_PAYLOAD_LIMITS).length) fail('source_replay_capture_schema');
  reviewedHash(manifest.original_draft_sha256); const bodies = {};
  for (const [i, name] of Object.keys(REPLAY_PAYLOAD_LIMITS).entries()) {
    time.check(); const row = manifest.payloads[i]; fields(row, ['name', 'bytes', 'sha256']);
    if (row.name !== name) fail('source_replay_capture_inventory');
    const bytes = await readPrivate(join(path, name), REPLAY_PAYLOAD_LIMITS[name]); time.check();
    if (bytes.length !== row.bytes || sha256(bytes) !== row.sha256) fail('source_replay_capture_changed');
    bodies[name] = bytes;
  }
  const json = name => parse(bodies[name], REPLAY_PAYLOAD_LIMITS[name]);
  const replay = await replaySourceChanges(bodies['original-source.json'], json('original-expected.json'), json('changes.json'),
    bodies['source.json'], json('expected.json'), { confirmDraftSha256: manifest.original_draft_sha256,
      signal: time.signal, timeoutMs: time.remaining() });
  time.check(); const rebuilt = payloads(replay);
  // File hashes are custody, not verification. Recompute BOTH standard drafts,
  // patch bytes and the replay decision even when every local hash was rewritten.
  for (const name of Object.keys(REPLAY_PAYLOAD_LIMITS)) if (!rebuilt[name].equals(bodies[name])) fail('source_replay_regeneration_mismatch');
  if (!canonical(manifestFor(replay, rebuilt)).equals(root)) fail('source_replay_regeneration_mismatch');
  time.check(); return { ...replay, saved: saved(path, expectedHash, replay) };
}
