#!/usr/bin/env node
// Explicit source preparation and one-shot publication; never guess a new base.
import { pathToFileURL } from 'node:url';
import { dirname } from 'node:path';
import { absolute, directory, readPrivate } from './operator/workflow_watch_io.mjs';
import { captureSourceEdit, oid } from './operator/source_edit_candidate.mjs';
import { captureVerifiedSourceEdit, SOURCE_PACKAGE_BYTES, SOURCE_EXPECTED_BYTES } from './operator/source_edit_from_package.mjs';
import { parse, fail, clock } from './operator/source_edit_wire.mjs';
import { saveSourceEdit, saveVerifiedSourceEdit, loadSourceEdit, stageSourceApply, dispatchSourceApply, recoverSourceApply, inspectSourceApply } from './operator/source_edit_publish.mjs';

const USAGE = `node scripts/fg_source_edit.mjs prepare --selection PRIVATE_JSON --patch-file PRIVATE_PATCH
  --token-file PRIVATE_TOKEN --output ABSENT_CANDIDATE_DIRECTORY [--ca-file PRIVATE_PEM]
node scripts/fg_source_edit.mjs prepare-verified --selection PRIVATE_JSON --package PRIVATE_SOURCE_PACKAGE
  --expect PRIVATE_INDEPENDENT_SELECTION --patch-file PRIVATE_PATCH --token-file PRIVATE_TOKEN
  --output ABSENT_CANDIDATE_DIRECTORY [--ca-file PRIVATE_PEM]
node scripts/fg_source_edit.mjs inspect --candidate PRIVATE_DIRECTORY --sha256 MANIFEST_HASH
node scripts/fg_source_edit.mjs stage --candidate PRIVATE_DIRECTORY --sha256 MANIFEST_HASH
  --principal ORIGINAL_PRINCIPAL_HEX --confirm-candidate NATIVE_COMMIT --journal ABSENT_PRIVATE_DIRECTORY
node scripts/fg_source_edit.mjs apply --journal PRIVATE_DIRECTORY --request-sha256 RETAINED_HASH
  --token-file PRIVATE_TOKEN [--ca-file PRIVATE_PEM]
node scripts/fg_source_edit.mjs recover --journal PRIVATE_DIRECTORY --request-sha256 RETAINED_HASH
  --token-file PRIVATE_RECOVERY_TOKEN [--ca-file PRIVATE_PEM]
node scripts/fg_source_edit.mjs status --journal PRIVATE_DIRECTORY --request-sha256 RETAINED_HASH

All commands accept --timeout-ms 1..300000 (default 30000). Paths are normalized
absolute owner-private paths. Inspect the saved capture.json before stage/apply.
prepare uses native exact-patch and bundle inspection without publication.
prepare-verified retains source evidence and checks candidate preimages/tree effects.
stage records the candidate, original principal and recovery key before apply.
apply submits ONCE. Uncertain replies require recover, never a fresh key or base.
recover only observes the original key; missing outcomes never permit resend.
Exit 0: successful preparation/inspection/staging or committed terminal;
2: refusal/error; 3: unresolved outcome; 4: retained result/output uncertainty.
No PR, checkout, Git subprocess, token persistence, force, redirect or retry.`;
function options(args) {
  if (!Array.isArray(args) || args.length > 23 || args.some(a => typeof a !== 'string' || Buffer.byteLength(a) > 4096)) fail('source_edit_cli_arguments');
  const op = args[0], profiles = {
    prepare: [['--selection', '--patch-file', '--token-file', '--output'], ['--ca-file']],
    'prepare-verified': [['--selection', '--package', '--expect', '--patch-file', '--token-file', '--output'], ['--ca-file']],
    inspect: [['--candidate', '--sha256'], []],
    stage: [['--candidate', '--sha256', '--principal', '--confirm-candidate', '--journal'], []],
    apply: [['--journal', '--request-sha256', '--token-file'], ['--ca-file']],
    recover: [['--journal', '--request-sha256', '--token-file'], ['--ca-file']],
    status: [['--journal', '--request-sha256'], []],
  };
  if (!Object.hasOwn(profiles, op)) fail('source_edit_cli_operation');
  const [required, extra] = profiles[op], allowed = [...required, ...extra, '--timeout-ms'], f = new Map();
  for (let i = 1; i < args.length; i += 2) {
    const flag = args[i], value = args[i + 1];
    if (!allowed.includes(flag) || f.has(flag) || !value || value.startsWith('--')) fail('source_edit_cli_option');
    f.set(flag, value);
  }
  if (required.some(k => !f.has(k))) fail('source_edit_cli_option');
  const timeout = f.get('--timeout-ms') ?? '30000';
  if (!/^[1-9][0-9]{0,5}$/.test(timeout) || Number(timeout) > 300000) fail('source_edit_cli_timeout');
  for (const [k, value] of f) {
    if (['--selection', '--package', '--expect', '--patch-file', '--token-file', '--output', '--candidate', '--journal', '--ca-file'].includes(k)) absolute(value);
    if (['--sha256', '--request-sha256'].includes(k) && !/^[0-9a-f]{64}$/.test(value)) fail('source_edit_pin');
  }
  return { op, f, timeout: Number(timeout) };
}
async function privateFile(path, max, check) {
  check(); await directory(dirname(absolute(path))); const bytes = await readPrivate(path, max); check(); return bytes;
}
async function emit(stream, value) {
  const bytes = Buffer.from(`${JSON.stringify(value)}\n`); if (bytes.length > 65536) fail('source_edit_cli_output_limit');
  await new Promise((resolve, reject) => {
    let done = false;
    const finish = error => { if (done) return; done = true; clearTimeout(timer); if (!error) stream.removeListener('error', onError); error ? reject(error) : resolve(); };
    const onError = error => finish(error), timer = setTimeout(() => {
      const e = new Error('source_edit_output_timeout'); stream.destroy(e); finish(e);
    }, 10000);
    stream.once('error', onError);
    try { stream.write(bytes, finish); } catch (error) { finish(error); }
  });
}
function exit(result) {
  if (result.decision?.outcome === 'refused') return 2;
  if (result.type === 'source_apply_pending' && result.state !== 'terminal') return 3;
  return 0;
}
export async function main(args, { stdout = process.stdout, stderr = process.stderr } = {}) {
  const stop = new AbortController(), abort = () => stop.abort();
  process.on('SIGTERM', abort); process.on('SIGINT', abort);
  let result, location;
  try {
    if (args.length === 1 && args[0] === '--help') { await emit(stdout, { usage: USAGE }); return 0; }
    const { op, f, timeout } = options(args), time = clock({ timeoutMs: timeout, signal: stop.signal });
    location = f.get('--journal') ?? f.get('--output') ?? f.get('--candidate');
    const local = () => ({ timeoutMs: time.remaining(), signal: stop.signal });
    const json = async path => parse(await privateFile(path, 512 * 1024, time.check), 512 * 1024);
    if (op === 'inspect') {
      const loaded = await loadSourceEdit(f.get('--candidate'), f.get('--sha256'), time.check);
      result = { type: 'source_edit_inspection', directory: location, manifest_sha256: loaded.manifest_sha256,
        candidate_commit: loaded.candidate_commit, source_commit: loaded.capture.request.expected_commit,
        paths_hex: loaded.capture.request.paths_hex, native_bundle_validation_observed: true,
        bundle_objects_independently_verified: false, publication_authorized: false, read_only: true,
        ...(loaded.source_verification ? { source_verification: loaded.source_verification } : {}) };
    } else if (op === 'stage') {
      const loaded = await loadSourceEdit(f.get('--candidate'), f.get('--sha256'), time.check);
      if (oid(f.get('--confirm-candidate'), loaded.capture.request.scope.object_format) !== loaded.candidate_commit) fail('source_edit_candidate_confirmation');
      result = await stageSourceApply(f.get('--journal'), f.get('--candidate'), f.get('--sha256'), f.get('--principal'), local());
    } else if (op === 'status') result = await inspectSourceApply(f.get('--journal'), f.get('--request-sha256'), local());
    else {
      const tokenBytes = await privateFile(f.get('--token-file'), 66, time.check); let token;
      try {
        if (!/^[0-9a-f]{64}(?:\r?\n)?$/.test(tokenBytes.toString('utf8'))) fail('source_edit_credential');
        token = tokenBytes.subarray(0, 64).toString('ascii');
      } finally { tokenBytes.fill(0); }
      const ca = f.has('--ca-file') ? await privateFile(f.get('--ca-file'), 131072, time.check) : undefined;
      if (op === 'prepare' || op === 'prepare-verified') {
        const selection = await json(f.get('--selection'));
        let evidence = null;
        if (op === 'prepare-verified') {
          const expected = parse(await privateFile(f.get('--expect'), SOURCE_EXPECTED_BYTES, time.check), SOURCE_EXPECTED_BYTES);
          const packageBytes = await privateFile(f.get('--package'), SOURCE_PACKAGE_BYTES, time.check);
          evidence = { package_bytes: packageBytes, expected };
        }
        const patch = await privateFile(f.get('--patch-file'), 1048576, time.check);
        const network = { ...local(), ...(ca ? { ca } : {}) };
        const value = evidence ? await captureVerifiedSourceEdit(selection, patch, token, evidence, network)
          : await captureSourceEdit(selection, patch, token, network);
        result = evidence ? await saveVerifiedSourceEdit(f.get('--output'), value.capture, value.bundle, value.source_evidence, local())
          : await saveSourceEdit(f.get('--output'), value.capture, value.bundle, local());
        result.metrics = value.metrics;
        if (evidence) result.source_package = {
          sha256: value.source_verification.package_sha256, commit: value.source_verification.commit,
          paths: value.source_verification.verified_paths, authority_verified: false, publication_authorized: false };
      } else {
        const network = { ...local(), ...(ca ? { ca } : {}) };
        result = op === 'apply' ? await dispatchSourceApply(f.get('--journal'), f.get('--request-sha256'), token, network)
          : await recoverSourceApply(f.get('--journal'), f.get('--request-sha256'), token, network);
      }
    }
    await emit(stdout, result); return exit(result);
  } catch (error) {
    try { await emit(stderr, { type: 'source_edit_error', code: error.code ?? 'source_edit_operation_failed', location: location ?? null,
      ...(result ? { retained_result: result } : {}), ...(error.retained_request ? { retained_request: error.retained_request } : {}),
      ...(error.publication_unconfirmed ? { publication_unconfirmed: error.publication_unconfirmed } : {}), submission_retried: false }); }
    catch { /* Original files and independently retained hashes still identify custody. */ }
    return result || error.publication_unconfirmed ? 4 : error.retained_request ? 3 : 2;
  } finally { process.removeListener('SIGTERM', abort); process.removeListener('SIGINT', abort); }
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) process.exitCode = await main(process.argv.slice(2));
