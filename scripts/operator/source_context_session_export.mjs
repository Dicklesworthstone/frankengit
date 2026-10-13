// Offline, create-only materialization of a verified immutable session prefix.
// Full replay, not hashes alone, regenerates the exported context on inspection.
import { constants } from 'node:fs';
import { mkdir, open } from 'node:fs/promises';
import { dirname, join, relative } from 'node:path';
import { fail, sha256 } from './source_context.mjs';
import { absolute, absentBundle, privateDirectory, readPrivate } from './source_context_export.mjs';
import { assembleSessionContext } from './source_context_session.mjs';
import { mergeLimits, MERGE_LIMITS } from './source_context_merge.mjs';

const PROFILE = 'frankengit-context-session-export-v1', MANIFEST_BYTES = 4096;
const encode = value => Buffer.from(`${JSON.stringify(value)}\n`);
function clock(options) {
  if (!options || typeof options !== 'object' || Array.isArray(options) ||
      Object.keys(options).some(k => !['signal', 'timeoutMs'].includes(k))) fail('invalid_context_session_options');
  const signal = options.signal, timeout = options.timeoutMs ?? 30000;
  if (signal !== undefined && !(signal instanceof AbortSignal) || !Number.isSafeInteger(timeout) || timeout < 1 || timeout > 300000) fail('invalid_context_session_options');
  const started = performance.now(), check = () => {
    signal?.throwIfAborted(); if (performance.now() - started >= timeout) fail('context_deadline_exceeded');
  };
  const remaining = () => { check(); const n = Math.floor(timeout - (performance.now() - started)); if (n < 1) fail('context_deadline_exceeded'); return n; };
  check(); return { signal, check, remaining };
}
function hash(value) {
  if (typeof value !== 'string' || !/^[0-9a-f]{64}$/.test(value)) fail('context_union_pin_required');
  return value;
}
function paths(output, root) {
  absolute(output); absolute(root);
  if (output === root || relative(root, output).split('/')[0] !== '..') fail('context_union_output_inside_session');
}
function manifest(material) {
  return { schema: PROFILE, session_sha256: material.session_sha256, tip_sha256: material.tip_sha256,
    limits: material.value.context.limits, files: [
      { name: 'context.json', bytes: material.json.length, sha256: material.json_sha256 },
      { name: 'context.txt', bytes: material.text.length, sha256: material.text_sha256 }],
    source_material_untrusted: true, authority_verified: false, agent_context_packet: false, aggregate_coverage_claimed: false };
}
function receipt(output, material, bytes) {
  const view = material.value.context;
  return { type: 'source_context_session_export', output, manifest_sha256: sha256(bytes),
    session_sha256: material.session_sha256, tip_sha256: material.tip_sha256,
    selected_terminal_prefix_only: true, later_steps_not_examined: true,
    json_sha256: material.json_sha256, text_sha256: material.text_sha256,
    captured_queries: view.query_count, returned_files: view.returned_files,
    input_excerpt_bytes: view.input_excerpt_bytes, excerpt_bytes: view.excerpt_bytes,
    deduplicated_excerpt_bytes: view.deduplicated_excerpt_bytes,
    all_captured_queries_complete: material.all_captured_queries_complete, refused_steps: material.refused_steps,
    authority_verified: false, agent_context_packet: false, source_material_untrusted: true,
    aggregate_coverage_claimed: false, acquisition_retried: false, network_requests: 0 };
}
async function sync(path) {
  const handle = await open(path, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
  try { await handle.sync(); } finally { await handle.close(); }
}
async function write(path, bytes) {
  const handle = await open(path, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
  try { await handle.writeFile(bytes); await handle.sync(); } finally { await handle.close(); }
}
export async function exportSessionContext(root, sessionHash, tipHash, output, limits = {}, options = {}) {
  const time = clock(options); paths(output, root); hash(sessionHash); hash(tipHash);
  const chosen = mergeLimits(limits);
  await absentBundle(output); time.check();
  const material = await assembleSessionContext(root, sessionHash, tipHash, chosen, { signal: time.signal, timeoutMs: time.remaining() });
  const bytes = encode(manifest(material)), completed = receipt(output, material, bytes);
  if (bytes.length > MANIFEST_BYTES) fail('context_union_manifest_limit');
  time.check();
  // Exact bytes and hashes exist before the first effect. Once directory
  // publication begins, drain write/sync/readback even after late cancellation.
  await mkdir(output, { mode: 0o700 });
  try {
    await privateDirectory(output); await sync(dirname(output));
    for (const [name, payload] of [['context.json', material.json], ['context.txt', material.text]]) {
      await write(join(output, name), payload);
      if (!(await readPrivate(join(output, name), MERGE_LIMITS.max_output_bytes)).equals(payload)) fail('context_union_readback_changed');
    }
    await write(join(output, 'manifest.json'), bytes);
    if (!(await readPrivate(join(output, 'manifest.json'), MANIFEST_BYTES)).equals(bytes)) fail('context_union_readback_changed');
    await sync(output); await sync(dirname(output));
    return completed;
  } catch (error) { error.context_export_unconfirmed = completed; throw error; }
}
export async function inspectSessionContextExport(root, sessionHash, tipHash, output, expectedManifest, options = {}) {
  const time = clock(options); paths(output, root); hash(sessionHash); hash(tipHash); hash(expectedManifest);
  const bytes = await readPrivate(join(output, 'manifest.json'), MANIFEST_BYTES, time.check);
  if (sha256(bytes) !== expectedManifest) fail('context_union_manifest_changed');
  let stored;
  try { stored = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)); }
  catch { fail('context_union_manifest_invalid'); }
  if (!stored || typeof stored !== 'object' || Array.isArray(stored) ||
      stored.schema !== PROFILE || stored.session_sha256 !== sessionHash || stored.tip_sha256 !== tipHash) fail('context_union_manifest_changed');
  const limits = mergeLimits(stored.limits);
  // Regenerate from the pinned ledger prefix, not a parseable detached export
  // or the session's latest numeric budget summary. Later steps are irrelevant.
  const material = await assembleSessionContext(root, sessionHash, tipHash, limits, { signal: time.signal, timeoutMs: time.remaining() });
  if (!encode(manifest(material)).equals(bytes)) fail('context_union_manifest_changed');
  for (const [name, expected] of [['context.json', material.json], ['context.txt', material.text]]) {
    const actual = await readPrivate(join(output, name), MERGE_LIMITS.max_output_bytes, time.check);
    if (!actual.equals(expected)) fail('context_union_payload_changed');
  }
  time.check();
  return { ...receipt(output, material, bytes), type: 'source_context_session_export_inspection', read_only: true, replay_verified: true };
}
