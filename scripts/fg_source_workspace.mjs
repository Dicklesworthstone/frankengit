#!/usr/bin/env node
// Explicit local materialization. No credentials, network, execution or checkout.
import { pathToFileURL } from 'node:url';
import { dirname } from 'node:path';
import { absolute, directory, readPrivate } from './operator/workflow_watch_io.mjs';
import { createSourceWorkspace, expandSourceWorkspace, inspectSourceWorkspace, lifetime, pin, fail,
  SOURCE_PACKAGE_BYTES, WORKSPACE_LIMITS } from './operator/source_workspace.mjs';
import { captureWorkspaceChanges, inspectWorkspaceChangeCapture } from './operator/source_workspace_changes.mjs';
import { parse } from './operator/source_edit_wire.mjs';
const USAGE = `node scripts/fg_source_workspace.mjs create --package PRIVATE_PACKAGE
  --expect PRIVATE_INDEPENDENT_EXPECTATION --output ABSENT_DIRECTORY
node scripts/fg_source_workspace.mjs expand --workspace PRIVATE_DIRECTORY --sha256 RETAINED_ROOT_HASH
  --package PRIVATE_ADDITIONAL_PACKAGE --expect PRIVATE_ADDITIONAL_EXPECTATION --output ABSENT_DIRECTORY
node scripts/fg_source_workspace.mjs status --workspace PRIVATE_DIRECTORY --sha256 RETAINED_ROOT_HASH
node scripts/fg_source_workspace.mjs capture --workspace PRIVATE_DIRECTORY --sha256 RETAINED_ROOT_HASH
  --paths PRIVATE_PATH_SELECTION --output ABSENT_CAPTURE_DIRECTORY
node scripts/fg_source_workspace.mjs inspect-capture --capture PRIVATE_CAPTURE_DIRECTORY --sha256 CAPTURE_HASH

All commands accept --timeout-ms 1..300000 (default 30000). Inputs and output
parents must be real owner-private POSIX directories. Source/expected inputs are
bounded owner-private regular files; the independent expectation is never chosen
from the package. Create re-verifies every selected commit/tree/blob, saves the
immutable inputs and materializes only those paths below files/. Keep the returned
workspace_sha256 independently. Expand verifies additional source at the SAME commit,
preserves originally selected edits/deletions/modes and creates a new workspace.
It never changes the original or copies unselected local files. Occupied newly
selected paths refuse. Keep the NEW workspace hash; this is not a branch refresh.
Edit files/ with your own trusted tools; no tool
is run here. Status checks the original inputs and reads only originally selected
paths. It does not discover other local files or attest an atomic filesystem view.
Capture requires {paths_hex:[...]} with every intended local path. Include
byte_profile:"binary-safe-v1" in that selection to capture arbitrary file bytes.
Use patch_profile:"trim-common-lines-v1" for edge trimming, or
patch_profile:"bounded-line-hunks-v1" to separate distant edits.
The default remains NUL-free with full-file patches. The explicitly selected profile is bound into
the captured changes and reviewed draft. It records
only those files as exact replacements, deletes or proved-absent creations; no
rename inference or directory scan occurs. Saved captures contain source.json,
expected.json, changes.json, patch.diff and draft.json for the existing authoring
CLI. Inspect-capture recomputes them without requiring the original workspace.
Binary-safe capture retains the existing byte, path, line and time limits.
No overwrite, recursive scan, symlink, hardlink, credential, network, Git command,
source execution, permission grant or repository mutation. Interrupted output
slots are retained. Exit 0: complete; 2: refusal; 3: cancelled before output;
4: a local output/result may exist: retain and inspect the reported root hash.`;
function options(args) {
  if (!Array.isArray(args) || args.length % 2 !== 1 || args.length > 13 ||
      args.some(a => typeof a !== 'string' || Buffer.byteLength(a) > 4096)) fail('source_workspace_arguments');
  const op = args[0], required = op === 'create' ? ['--package', '--expect', '--output']
    : op === 'expand' ? ['--workspace', '--sha256', '--package', '--expect', '--output']
    : op === 'status' ? ['--workspace', '--sha256']
    : op === 'capture' ? ['--workspace', '--sha256', '--paths', '--output']
    : op === 'inspect-capture' ? ['--capture', '--sha256'] : null;
  if (!required) fail('source_workspace_operation');
  const f = new Map();
  for (let i = 1; i < args.length; i += 2) {
    const key = args[i], value = args[i + 1];
    if (![...required, '--timeout-ms'].includes(key) || f.has(key) || !value || value.startsWith('--')) fail('source_workspace_option');
    f.set(key, value);
    if (key === '--sha256') pin(value); else if (key !== '--timeout-ms') absolute(value);
  }
  if (required.some(k => !f.has(k))) fail('source_workspace_option');
  const timeout = f.get('--timeout-ms') ?? '30000';
  if (!/^[1-9][0-9]{0,5}$/.test(timeout) || Number(timeout) > 300000) fail('source_workspace_timeout');
  return { op, f, timeout: Number(timeout) };
}
async function privateFile(path, max, time) {
  time.check(); await directory(dirname(path)); const bytes = await readPrivate(path, max); time.check(); return bytes;
}
async function emit(stream, value) {
  const bytes = Buffer.from(`${JSON.stringify(value)}\n`);
  if (bytes.length > 131072) fail('source_workspace_output_limit');
  await new Promise((resolve, reject) => {
    let done = false;
    const finish = error => { if (done) return; done = true; clearTimeout(timer);
      if (!error) stream.removeListener('error', onError); error ? reject(error) : resolve(); };
    const onError = error => finish(error), timer = setTimeout(() => {
      const error = new Error('source_workspace_output_timeout'); finish(error); stream.destroy(error);
    }, 10000);
    stream.once('error', onError);
    try { stream.write(bytes, finish); } catch (error) { finish(error); }
  });
}
export async function main(args, { stdout = process.stdout, stderr = process.stderr } = {}) {
  const controller = new AbortController(), abort = () => controller.abort();
  process.on('SIGTERM', abort); process.on('SIGINT', abort);
  let result;
  try {
    if (args.length === 1 && args[0] === '--help') { await emit(stdout, { usage: USAGE }); return 0; }
    const { op, f, timeout } = options(args), time = lifetime({ timeoutMs: timeout, signal: controller.signal });
    if (op === 'create' || op === 'expand') {
      const expected = parse(await privateFile(f.get('--expect'), WORKSPACE_LIMITS.expectedBytes, time), WORKSPACE_LIMITS.expectedBytes);
      const bytes = await privateFile(f.get('--package'), SOURCE_PACKAGE_BYTES, time);
      const local = { check: time.check, signal: controller.signal, timeoutMs: time.remaining() };
      result = op === 'create' ? await createSourceWorkspace(f.get('--output'), bytes, expected, local)
        : await expandSourceWorkspace(f.get('--workspace'), f.get('--sha256'), bytes, expected, f.get('--output'), local);
    } else if (op === 'capture') {
      const selection = parse(await privateFile(f.get('--paths'), WORKSPACE_LIMITS.expectedBytes, time), WORKSPACE_LIMITS.expectedBytes);
      result = await captureWorkspaceChanges(f.get('--workspace'), f.get('--sha256'), selection, f.get('--output'),
        { check: time.check, signal: controller.signal, timeoutMs: time.remaining() });
    } else if (op === 'inspect-capture') {
      result = await inspectWorkspaceChangeCapture(f.get('--capture'), f.get('--sha256'), { check: time.check, timeoutMs: time.remaining() });
    } else result = await inspectSourceWorkspace(f.get('--workspace'), f.get('--sha256'), { check: time.check, timeoutMs: time.remaining() });
    await emit(stdout, result); return 0;
  } catch (error) {
    const retained = result ?? error.publication_unconfirmed;
    try { await emit(stderr, { type: 'source_workspace_error', code: /^source_[a-z0-9_]{1,90}$/.test(error.code ?? '') ? error.code : 'source_workspace_refused',
      source_executed: false, network_attempted: false, repository_changed: false,
      ...(retained ? { retained_result: retained } : {}) }); } catch { /* Keep owned files and the original error. */ }
    return retained ? 4 : controller.signal.aborted ? 3 : 2;
  } finally { process.removeListener('SIGTERM', abort); process.removeListener('SIGINT', abort); }
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) process.exitCode = await main(process.argv.slice(2));
