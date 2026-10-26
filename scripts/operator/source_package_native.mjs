// Optional authority-proof gate for the existing portable package owner. The
// Rust engine owns proof decoding and Git semantics; no fallback is permitted.
import { createHash } from 'node:crypto';
import { constants } from 'node:fs';
import { chmod, lstat, mkdtemp, open, readFile, realpath, readdir, rmdir, unlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { executable, parseJson, readPrivate } from './workflow_watch_io.mjs';
import { runNativeProcess } from '../lib/native-process-owner.mjs';

const fail = code => { throw Object.assign(new Error(code), { code }); };
const same = (a, b) => ['dev', 'ino', 'size', 'mode', 'uid', 'mtimeMs', 'ctimeMs'].every(k => a[k] === b[k]);
export async function prepareNativePackageRead(fg, plan, maximumRequests, check) {
  if (plan.selected.expected_head === null) throw new Error('Native capture requires an independently retained head.');
  const endpoint = new URL(plan.selected.endpoint);
  if (endpoint.protocol !== 'http:' || !['127.0.0.1', '[::1]'].includes(endpoint.hostname)) {
    throw new Error('Native capture requires numeric-loopback HTTP.');
  }
  if (plan.cost.blobRequests + plan.files.length > maximumRequests) throw new Error('Native proof request budget exceeded before reads.');
  check(); await executable(fg); check();
  const identity = await lstat(fg);
  if (identity.size > 256 * 1024 * 1024) fail('native_source_proof_executable_limit');
  const bytes = await readFile(fg); check();
  if (bytes.length !== identity.size || !same(identity, await lstat(fg))) fail('native_source_proof_executable_changed');
  return { fg, identity, digest: createHash('sha256').update(bytes).digest('hex') };
}
export async function verifyNativePackageRead(native, plan, value, verified, token, deadline, signal, check) {
  check();
  if (typeof token !== 'string' || !/^[0-9a-f]{64}$/.test(token)) fail('native_source_proof_invalid_token');
  const created = await mkdtemp(join(tmpdir(), 'fg-package-native-'));
  let scratch, identity;
  try { scratch = await realpath(created); await chmod(scratch, 0o700); identity = await lstat(scratch); }
  catch (error) { error.nativeScratch = created; throw error; }
  const allowed = new Set(['token']);
  const tokenFile = join(scratch, 'token'); let retain = false, problem, report;
  async function guard() {
    const current = await lstat(scratch);
    if (!current.isDirectory() || current.dev !== identity.dev || current.ino !== identity.ino ||
        current.uid !== process.getuid() || (current.mode & 0o777) !== 0o700) fail('native_source_proof_scratch_changed');
  }
  try {
    await writeFile(tokenFile, token, { flag: 'wx', mode: 0o600 });
    const blobs = new Map(value.blobs.map(row => [row.oid, row.bytesHex]));
    for (let at = 0; at < plan.files.length; at++) {
      check(); await guard();
      if (!same(native.identity, await lstat(native.fg))) fail('native_source_proof_executable_changed');
      const wanted = plan.files[at], member = verified.files[at], name = `blob-${at}`, output = join(scratch, name);
      allowed.add(name);
      const remaining = Math.floor(deadline - performance.now()); check();
      const result = await runNativeProcess(native.fg, ['--timeout-secs', String(Math.max(1, Math.ceil(remaining / 1000))),
        'verify-read', '--url', plan.selected.endpoint, '--trusted-head', plan.selected.expected_head,
        '--ref', plan.selected.ref, '--path-hex', wanted.pathHex, '--token-file', tokenFile, '--output', output],
      { timeoutMs: Math.max(1, remaining), signal, stdoutLimit: 65536, stderrLimit: 65536 });
      check(); await guard();
      if (result.code !== 0 || result.signal !== null) {
        const error = Object.assign(new Error('native_source_proof_refused'), { code: 'native_source_proof_refused' });
        try {
          const diagnostic = parseJson(result.stderr, 65536);
          if (diagnostic.type === 'verified_read_error' && diagnostic.schema_version === 1 &&
              typeof diagnostic.code === 'string' && /^[a-z_]{1,64}$/.test(diagnostic.code)) error.nativeCode = diagnostic.code;
        } catch { /* Unrecognized output never supplies verification evidence. */ }
        throw error;
      }
      let actual;
      try { actual = parseJson(result.stdout, 65536); } catch { fail('native_source_proof_invalid_report'); }
      const fields = ['type', 'schema_version', 'verified', 'output_state', 'source_head', 'source_commit', 'object_id', 'kind', 'bytes', 'output'];
      if (!actual || typeof actual !== 'object' || Array.isArray(actual) || Object.keys(actual).length !== fields.length ||
          fields.some(k => !Object.hasOwn(actual, k)) || actual.type !== 'verified_blob' || actual.schema_version !== 1 ||
          actual.verified !== true || actual.output_state !== 'published' || actual.source_head !== plan.selected.expected_head ||
          actual.source_commit !== plan.independent.commit || actual.object_id !== wanted.blob || actual.kind !== member.kind ||
          actual.bytes !== wanted.sourceBytes || actual.output !== output || result.stderr.length !== 0) fail('native_source_proof_invalid_report');
      const file = await open(output, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
      try {
        const stat = await file.stat();
        if (!stat.isFile() || stat.uid !== process.getuid() || stat.nlink !== 1 || stat.size !== wanted.sourceBytes) fail('native_source_proof_output_changed');
        await file.chmod(0o600);
      } finally { await file.close(); }
      const body = await readPrivate(output, wanted.sourceBytes); check();
      if (body.toString('hex') !== blobs.get(wanted.blob)) fail('native_source_proof_content_mismatch');
    }
    check();
    if (!same(native.identity, await lstat(native.fg))) fail('native_source_proof_executable_changed');
    report = { profile: 'native-pinned-head-capture-v1', verified_at_capture: true,
      head: plan.selected.expected_head, binary_sha256: native.digest, files: plan.files.length,
      proofs_retained_in_package: false, independent_build_attested: false };
  } catch (error) {
    problem = error; retain = error.code === 'native_process_containment_failed';
  } finally {
    if (!retain) {
      try {
        await guard();
        const names = await readdir(scratch);
        // Unknown files or changed ownership are retained, never recursive GC.
        if (names.some(name => !allowed.has(name))) fail('native_source_proof_unknown_scratch');
        for (const name of names) {
          await guard(); const path = join(scratch, name), stat = await lstat(path);
          if (!stat.isFile() || stat.uid !== process.getuid() || stat.nlink !== 1) fail('native_source_proof_scratch_changed');
          await unlink(path);
        }
        await guard(); await rmdir(scratch);
      } catch (cleanup) { problem ??= cleanup; retain = true; }
    }
    if (retain) { problem ??= Object.assign(new Error('native_source_proof_cleanup_failed'), { code: 'native_source_proof_cleanup_failed' }); problem.nativeScratch = scratch; }
  }
  if (problem) throw problem;
  return report;
}
