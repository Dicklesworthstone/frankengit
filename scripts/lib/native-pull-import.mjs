// FG-049: root-last native PR migration preparation. Existing remote_pull owns
// every request key, command, authorization check and eventual native outcome.
import { mkdir, opendir, lstat } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { isDeepStrictEqual } from 'node:util';
import { PULL_LIMITS, preparePull, pullCanonical, pullHash, pullFields, parsePullJson,
  pullTokenFingerprint } from '../operator/pull_command.mjs';
import { savePullIntent, loadPullIntent, readPullToken, privatePullDirectory } from '../operator/pull_files.mjs';
import { directory, encode, digest, exact, lifetime, pageName, pin, readPrivate,
  safePath, syncDirectory, writeNew } from './forge-pull-archive-store.mjs';
import { readPullImportSource } from './native-pull-import-source.mjs';
import { compilePullImport, pullImportSelection, importFail, IMPORT_SCHEMA } from './native-pull-import-plan.mjs';

export const importSlot = i => `step-${String(i + 1).padStart(6, '0')}`;
const MANIFEST_LIMIT = 1024 * 1024;
async function inventory(root, names, check) {
  const expected = new Set(names);
  for await (const entry of await opendir(root)) { check(); if (!expected.delete(entry.name)) importFail('unexpected_file'); }
  if (expected.size) importFail('missing_file');
}
function options(raw, preparing) {
  const required = preparing ? ['workdir', 'archiveDir', 'archiveConfirm', 'selection', 'tokenFile'] : ['workdir', 'confirm'];
  pullFields(raw, [...required, 'timeoutMs', 'signal'], required);
  const o = { ...raw, workdir: safePath(raw.workdir) };
  if (preparing) {
    o.archiveDir = safePath(raw.archiveDir); o.archiveConfirm = pin(raw.archiveConfirm);
    o.selection = pullImportSelection(raw.selection); o.tokenFile = safePath(raw.tokenFile);
  } else o.confirm = pin(raw.confirm);
  return o;
}
async function contents(root, manifest, life, sealed, synchronize) {
  const identity = await directory(root); await privatePullDirectory(root);
  await inventory(root, ['archive', 'requests', 'journal', ...(sealed ? ['manifest.json'] : [])], life.check);
  await directory(join(root, 'journal')); await directory(join(root, 'requests'));
  const source = await readPullImportSource({ workdir: join(root, 'archive'), confirm: manifest.archive_sha256,
    maxBytes: manifest.selection.max_source_bytes, timeoutMs: life.timeout, signal: life.signal });
  const compiled = compilePullImport(source, manifest.selection);
  if (!isDeepStrictEqual(compiled.selection, manifest.selection) || compiled.steps.length !== manifest.step_count ||
      digest(encode(compiled.steps)) !== manifest.steps_sha256 || !Array.isArray(manifest.request_sha256) ||
      manifest.request_sha256.length !== compiled.steps.length) importFail('plan_changed');
  await inventory(join(root, 'requests'), compiled.steps.map((_, i) => importSlot(i)), life.check);
  const intents = []; let bytes = 0;
  for (const [i, step] of compiled.steps.entries()) {
    life.check(); await directory(root, identity);
    const slot = join(root, 'requests', importSlot(i));
    await inventory(slot, ['intent.json'], life.check);
    const intent = await loadPullIntent(slot, { sync: synchronize });
    const text = pullCanonical(intent); bytes += Buffer.byteLength(text);
    if (bytes > manifest.selection.max_request_bytes || pullHash(text) !== pin(manifest.request_sha256[i]) ||
        intent.endpoint !== compiled.selection.endpoint || !isDeepStrictEqual(intent.scope, compiled.selection.scope) ||
        intent.number !== step.number || intent.action !== step.action || intent.body !== step.body ||
        !isDeepStrictEqual(intent.fields, step.fields) || intent.credential_fingerprint !== manifest.credential_fingerprint) importFail('request_changed');
    intents.push(intent);
  }
  if (bytes !== manifest.request_bytes) importFail('request_bytes');
  life.check(); await directory(root, identity);
  return { root, identity, manifest, source, compiled, intents };
}
function checkedManifest(m) {
  exact(m, ['schema', 'selection', 'archive_sha256', 'credential_fingerprint', 'step_count', 'steps_sha256', 'request_sha256', 'request_bytes']);
  if (m.schema !== IMPORT_SCHEMA) importFail('schema');
  pullImportSelection(m.selection); pin(m.archive_sha256); pin(m.credential_fingerprint); pin(m.steps_sha256);
  if (!Number.isSafeInteger(m.step_count) || m.step_count < 0 || m.step_count > m.selection.max_steps ||
      !Number.isSafeInteger(m.request_bytes) || m.request_bytes < 0 || m.request_bytes > m.selection.max_request_bytes) importFail('manifest_limit');
  return m;
}
export async function loadPullImport(workdir, confirm, life, synchronize = false) {
  const root = safePath(workdir); pin(confirm); life.check(); const identity = await directory(root);
  const bytes = await readPrivate(join(root, 'manifest.json'), MANIFEST_LIMIT, synchronize, life.check);
  if (digest(bytes) !== confirm) importFail('plan_pin_mismatch');
  const m = checkedManifest(parsePullJson(bytes));
  if (!encode(m).equals(bytes)) importFail('manifest_encoding');
  const loaded = await contents(root, m, life, true, synchronize);
  await directory(root, identity); return { ...loaded, planSha256: confirm };
}
export function pullImportSummary(loaded) {
  return { type: 'native_pull_import_prepared', schema_version: 1, workdir: loaded.root,
    plan_sha256: loaded.planSha256, archive_sha256: loaded.manifest.archive_sha256,
    destination: loaded.manifest.selection.endpoint, scope: loaded.manifest.selection.scope,
    steps: loaded.intents.length, request_bytes: loaded.manifest.request_bytes,
    mapping: loaded.compiled.mapping, mutation_submitted: false, atomic_batch: false,
    canonical_restore: false, approvals_imported: false, refs_changed: false };
}
export async function inspectPullImport(raw) {
  const o = options(raw, false), life = lifetime(o);
  try { return { ...pullImportSummary(await loadPullImport(o.workdir, o.confirm, life)), network_accessed: false }; }
  finally { life.close(); }
}
export async function preparePullImport(raw) {
  const o = options(raw, true), life = lifetime(o); let created = false, planSha256 = null;
  try {
    life.check(); await privatePullDirectory(dirname(o.workdir));
    try { await lstat(o.workdir); importFail('workdir_exists'); } catch (e) { if (e.code !== 'ENOENT') throw e; }
    const source = await readPullImportSource({ workdir: o.archiveDir, confirm: o.archiveConfirm,
      maxBytes: o.selection.max_source_bytes, timeoutMs: life.timeout, signal: life.signal });
    const compiled = compilePullImport(source, o.selection); life.check();
    const token = await readPullToken(o.tokenFile), fingerprint = pullTokenFingerprint(token);
    // Compile and validate the whole population before generating a request key.
    // All keys/receipts and their total size are checked before creating any slot.
    const intents = []; let requestBytes = 0;
    for (const step of compiled.steps) {
      life.check(); const { number, action, fields } = step;
      const intent = preparePull({ endpoint: o.selection.endpoint, scope: o.selection.scope, number, action, fields }, token);
      requestBytes += Buffer.byteLength(pullCanonical(intent));
      if (requestBytes > o.selection.max_request_bytes) importFail('request_limit');
      intents.push(intent);
    }
    const m = checkedManifest({ schema: IMPORT_SCHEMA, selection: compiled.selection, archive_sha256: source.archiveSha256,
      credential_fingerprint: fingerprint, step_count: intents.length, steps_sha256: digest(encode(compiled.steps)),
      request_sha256: intents.map(intent => pullHash(pullCanonical(intent))), request_bytes: requestBytes });
    const manifestBytes = encode(m); planSha256 = digest(manifestBytes);
    if (manifestBytes.length > MANIFEST_LIMIT) importFail('manifest_limit');
    life.check(); await mkdir(o.workdir, { mode: 0o700 }); created = true;
    await syncDirectory(dirname(o.workdir)); const identity = await directory(o.workdir);
    for (const name of ['archive', 'requests', 'journal']) await mkdir(join(o.workdir, name), { mode: 0o700 });
    await syncDirectory(o.workdir);
    for (const [i, bytes] of source.pages.entries()) {
      life.check(); await directory(o.workdir, identity); await writeNew(join(o.workdir, 'archive', pageName(i)), bytes);
    }
    await writeNew(join(o.workdir, 'archive', 'archive.json'), source.manifestBytes);
    for (const [i, intent] of intents.entries()) {
      life.check(); await directory(o.workdir, identity);
      await savePullIntent(join(o.workdir, 'requests', importSlot(i)), intent);
    }
    const loaded = await contents(o.workdir, m, life, false, true);
    life.check(); await directory(o.workdir, identity); await writeNew(join(o.workdir, 'manifest.json'), manifestBytes);
    return { ...pullImportSummary({ ...loaded, planSha256 }), network_accessed: false };
  } catch (cause) {
    const error = cause instanceof Error ? cause : new Error('pull_import_interrupted');
    error.import_progress = { workdir: o.workdir, directory_created: created, plan_sha256: planSha256,
      preparation_complete: false, mutation_submitted: false }; throw error;
  } finally { life.close(); }
}
