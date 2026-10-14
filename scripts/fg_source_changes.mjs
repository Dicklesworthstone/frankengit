#!/usr/bin/env node
// Explicit authoring, not an autonomous executor or repository publication tool.
import { pathToFileURL } from 'node:url';
import { dirname, join } from 'node:path';
import { lstat, mkdir } from 'node:fs/promises';
import { absolute, directory, readPrivate, writeNew, syncDirectory } from './operator/workflow_watch_io.mjs';
import { buildSourceChanges, canonical, sha256, fail, SOURCE_PACKAGE_BYTES, CHANGES_INPUT_BYTES } from './operator/source_changes.mjs';
import { prepareSourceChanges, verifySourceChangeCandidate } from './operator/source_changes_prepare.mjs';
import { saveSourceEdit, loadSourceEdit } from './operator/source_edit_publish.mjs';
import { clock, parse } from './operator/source_edit_wire.mjs';

const USAGE = `node scripts/fg_source_changes.mjs draft --package PRIVATE_PACKAGE --expect PRIVATE_EXPECTATION
  --changes PRIVATE_CHANGES --output ABSENT_PRIVATE_DIRECTORY
node scripts/fg_source_changes.mjs prepare --package PRIVATE_PACKAGE --expect PRIVATE_EXPECTATION
  --changes PRIVATE_CHANGES --selection PRIVATE_NATIVE_SELECTION --token-file PRIVATE_TOKEN
  --confirm-draft-sha256 REVIEWED_DRAFT_HASH --output ABSENT_CANDIDATE_DIRECTORY [--ca-file PRIVATE_PEM]
node scripts/fg_source_changes.mjs inspect-candidate --package PRIVATE_PACKAGE --expect PRIVATE_EXPECTATION
  --changes PRIVATE_CHANGES --candidate PRIVATE_CANDIDATE_DIRECTORY --sha256 CANDIDATE_MANIFEST_HASH
  --confirm-draft-sha256 REVIEWED_DRAFT_HASH

Every command accepts --timeout-ms 1..300000 (default 30000).
Draft creates private patch.diff and manifest.json without network work. Review
both files and retain the returned manifest hash before preparation. Preparation
regenerates the exact draft before I/O, invokes native prepare/inspect, and checks
all reported old/new blob identities and modes against locally intended effects.
Native selection uses the existing source-edit schema, with only EFFECT paths;
explicit no-op paths remain in the draft but are not native change targets.
Inspect-candidate regenerates and checks offline; it accepts no credential.
The standard saved candidate is consumed by fg_source_edit.mjs stage/apply/recover,
which separately requires principal/candidate consent and owns original-key recovery.
This command never publishes repository state, invents a new base, retries,
extracts files, runs source, or calls Git. Explicit create operations require an
executable choice and absence proved by the package's committed parent trees.
Missing parent evidence refuses; there is no overwrite or implicit proof fetch.
NUL-bearing binary edits are not supported.
Exit 0: complete result; 2: refusal; 3: cancelled before local publication;
4: a local output or result may exist; inspect its retained location and hashes.`;
function options(args) {
  if (!Array.isArray(args) || args.length > 23 || args.length % 2 !== 1 ||
      args.some(a => typeof a !== 'string' || Buffer.byteLength(a) > 4096)) fail('source_changes_cli_arguments');
  const op = args[0], common = ['--package', '--expect', '--changes'];
  const profiles = {
    draft: [[...common, '--output'], []],
    prepare: [[...common, '--selection', '--token-file', '--confirm-draft-sha256', '--output'], ['--ca-file']],
    'inspect-candidate': [[...common, '--candidate', '--sha256', '--confirm-draft-sha256'], []],
  };
  if (!Object.hasOwn(profiles, op)) fail('source_changes_cli_operation');
  const [required, extra] = profiles[op], allowed = [...required, ...extra, '--timeout-ms'], f = new Map();
  for (let i = 1; i < args.length; i += 2) {
    const key = args[i], value = args[i + 1];
    if (!allowed.includes(key) || f.has(key) || !value || value.startsWith('--')) fail('source_changes_cli_option');
    f.set(key, value);
  }
  if (required.some(k => !f.has(k))) fail('source_changes_cli_option');
  const timeout = f.get('--timeout-ms') ?? '30000';
  if (!/^[1-9][0-9]{0,5}$/.test(timeout) || Number(timeout) > 300000) fail('source_changes_cli_timeout');
  for (const [key, value] of f) {
    if (key === '--timeout-ms') continue;
    if (['--sha256', '--confirm-draft-sha256'].includes(key)) {
      if (!/^[0-9a-f]{64}$/.test(value)) fail('source_changes_confirmation');
    } else absolute(value);
  }
  return { op, f, timeout: Number(timeout) };
}
async function absent(path) {
  await directory(dirname(absolute(path)));
  try { await lstat(path); fail('source_changes_destination_exists'); }
  catch (error) { if (error.code !== 'ENOENT') throw error; }
}
async function privateFile(path, max, check) {
  check(); await directory(dirname(absolute(path))); const bytes = await readPrivate(path, max); check(); return bytes;
}
async function saveDraft(path, draft, check) {
  const bytes = canonical(draft.manifest);
  if (bytes.length > 256 * 1024) fail('source_changes_manifest_limit');
  const receipt = { type: 'source_change_draft_saved', directory: path, manifest_sha256: sha256(bytes),
    patch_sha256: draft.manifest.patch_sha256, source_commit: draft.manifest.source_commit,
    object_format: draft.manifest.object_format, effect_count: draft.manifest.effects.length,
    no_op_count: draft.manifest.no_op_paths_hex.length, remote_mutation_attempted: false,
    ...(draft.manifest.creation_preconditions ? { created_path_count: draft.manifest.creation_preconditions.paths.length } : {}) };
  await absent(path); check(); await mkdir(path, { mode: 0o700 });
  try {
    // Once this output slot is owned, drain writes/sync/readback after a stop.
    // Never delete or reuse interrupted slots, or claim late cancellation is absence.
    await syncDirectory(dirname(path));
    await writeNew(join(path, 'patch.diff'), draft.bytes);
    if (!draft.bytes.equals(await readPrivate(join(path, 'patch.diff'), 1048576))) fail('source_changes_output_changed');
    await writeNew(join(path, 'manifest.json'), bytes);
    if (!bytes.equals(await readPrivate(join(path, 'manifest.json'), 256 * 1024))) fail('source_changes_output_changed');
    await syncDirectory(path); await syncDirectory(dirname(path)); return receipt;
  } catch (error) { error.publication_unconfirmed = receipt; throw error; }
}
async function emit(stream, value) {
  const bytes = Buffer.from(`${JSON.stringify(value)}\n`);
  if (bytes.length > 65536) fail('source_changes_output_limit');
  await new Promise((resolve, reject) => {
    let done = false;
    const finish = error => { if (done) return; done = true; clearTimeout(timer);
      if (!error) stream.removeListener('error', onError); error ? reject(error) : resolve(); };
    const onError = error => finish(error), timer = setTimeout(() => {
      const error = new Error('source_changes_output_timeout'); finish(error); stream.destroy(error);
    }, 10000);
    stream.once('error', onError);
    try { stream.write(bytes, error => finish(error)); } catch (error) { finish(error); }
  });
}
export async function main(args, { stdout = process.stdout, stderr = process.stderr } = {}) {
  const stop = new AbortController(), abort = () => stop.abort();
  process.on('SIGTERM', abort); process.on('SIGINT', abort);
  let result;
  try {
    if (args.length === 1 && args[0] === '--help') { await emit(stdout, { usage: USAGE }); return 0; }
    const { op, f, timeout } = options(args), time = clock({ timeoutMs: timeout, signal: stop.signal });
    if (typeof process.getuid !== 'function') fail('source_changes_posix_required');
    if (f.has('--output')) await absent(f.get('--output'));
    const expected = parse(await privateFile(f.get('--expect'), 128 * 1024, time.check), 128 * 1024);
    const changes = parse(await privateFile(f.get('--changes'), CHANGES_INPUT_BYTES, time.check), CHANGES_INPUT_BYTES);
    const bytes = await privateFile(f.get('--package'), SOURCE_PACKAGE_BYTES, time.check);
    const local = () => ({ timeoutMs: time.remaining(), signal: stop.signal });
    if (op === 'draft') {
      const draft = await buildSourceChanges(bytes, expected, changes, { check: time.check, signal: stop.signal });
      result = await saveDraft(f.get('--output'), draft, time.check);
    } else if (op === 'inspect-candidate') {
      const loaded = await loadSourceEdit(f.get('--candidate'), f.get('--sha256'), time.check);
      const checked = await verifySourceChangeCandidate(bytes, expected, changes, loaded.capture, loaded.bundle,
        { ...local(), confirmDraftSha256: f.get('--confirm-draft-sha256') }); time.check();
      result = { type: 'source_change_candidate_inspection', directory: f.get('--candidate'),
        manifest_sha256: f.get('--sha256'), binding: checked.binding, read_only: true, remote_mutation_attempted: false };
    } else {
      const selection = parse(await privateFile(f.get('--selection'), 512 * 1024, time.check), 512 * 1024);
      const tokenBytes = await privateFile(f.get('--token-file'), 66, time.check); let token;
      try {
        if (!/^[0-9a-f]{64}(?:\r?\n)?$/.test(tokenBytes.toString('utf8'))) fail('source_changes_credential');
        token = tokenBytes.subarray(0, 64).toString('ascii');
      } finally { tokenBytes.fill(0); }
      const ca = f.has('--ca-file') ? await privateFile(f.get('--ca-file'), 131072, time.check) : undefined;
      const checked = await prepareSourceChanges(bytes, expected, changes, selection, token,
        { ...local(), ca, confirmDraftSha256: f.get('--confirm-draft-sha256') }); time.check();
      result = { ...await saveSourceEdit(f.get('--output'), checked.capture, checked.bundle, local()),
        binding: checked.binding, read_metrics: checked.metrics, remote_mutation_attempted: false };
    }
    await emit(stdout, { ...result, stop_requested: stop.signal.aborted }); return 0;
  } catch (error) {
    const code = typeof error.code === 'string' && /^source_(?:changes|edit)_[a-z0-9_]{1,80}$/.test(error.code)
      ? error.code : 'source_changes_cli_refused';
    try { await emit(stderr, { type: 'source_changes_error', code, remote_mutation_attempted: false,
      ...(result ? { retained_result: result } : error.publication_unconfirmed ? { publication_unconfirmed: error.publication_unconfirmed } : {}) }); }
    catch { /* Keep any owned output and its original identities. */ }
    return result || error.publication_unconfirmed ? 4 : stop.signal.aborted ? 3 : 2;
  } finally { process.removeListener('SIGTERM', abort); process.removeListener('SIGINT', abort); }
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) process.exitCode = await main(process.argv.slice(2));
