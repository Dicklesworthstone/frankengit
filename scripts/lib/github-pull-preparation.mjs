// FG-049: restartable OFFLINE request preparation. The output is an unchanged
// GitHub PR import job; only its existing sender can submit native mutations.
import { mkdir, opendir, lstat, rename, open } from 'node:fs/promises';
import { constants } from 'node:fs';
import { dirname, join } from 'node:path';
import { randomBytes, createHmac } from 'node:crypto';
import { performance } from 'node:perf_hooks';
import { isDeepStrictEqual } from 'node:util';
import { pullFields, preparePullWithIdentity, pullCanonical, pullHash, pullTokenFingerprint }
  from '../operator/pull_command.mjs';
import { privatePullDirectory, readPullToken, loadPullIntent, savePullIntent } from '../operator/pull_files.mjs';
import { operatorPath, readPrivateOperatorFile, readSynchronizedOperatorRecord, saveOperatorRecord }
  from './forge-operator-io.mjs';
import { parseGithubPullCapture, encodeGithubPulls as encode, pullSourceNumber as integer }
  from './github-pull-source.mjs';
import { compileGithubPullImport, githubPullImportSelection, GITHUB_PULL_IMPORT_SCHEMA }
  from './github-pull-import-plan.mjs';

const SCHEMA = 'frankengit-github-pull-preparation-v1', FILE_LIMIT = 1024 * 1024;
const fail = code => { const e = new Error(`github_pull_preparation_${code}`); e.code = e.message; throw e; };
const stepName = i => `step-${String(i + 1).padStart(6, '0')}`;
const pin = v => { if (typeof v !== 'string' || !/^[0-9a-f]{64}$/.test(v)) fail('pin'); return v; };
const path = v => { if (operatorPath(v) !== v) fail('absolute_path'); return v; };
function lifetime(raw) {
  const timeout = integer(raw.timeoutMs ?? 300000, 1, 300000);
  if (raw.signal !== undefined && !(raw.signal instanceof AbortSignal)) fail('signal');
  const stop = new AbortController(), signal = raw.signal ? AbortSignal.any([raw.signal, stop.signal]) : stop.signal;
  const deadline = performance.now() + timeout, timer = setTimeout(() => stop.abort(), timeout);
  return { signal, check() { if (performance.now() >= deadline) stop.abort(); signal.throwIfAborted(); },
    close() { clearTimeout(timer); stop.abort(); } };
}
async function directory(root, expected = null) {
  await privatePullDirectory(root); const id = await lstat(root, { bigint: true });
  if (expected && (id.dev !== expected.dev || id.ino !== expected.ino)) fail('directory_changed');
  return id;
}
async function sync(root) {
  const file = await open(root, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
  try { await file.sync(); } finally { await file.close(); }
}
async function names(root, maximum, life) {
  const out = [];
  for await (const entry of await opendir(root)) {
    life.check(); if (out.length === maximum) fail('inventory_limit'); out.push(entry.name);
  }
  return out.sort();
}
async function inventory(root, expected, life) {
  if (!isDeepStrictEqual(await names(root, expected.length + 1, life), [...expected].sort())) fail('inventory');
}
async function present(file) {
  try { await lstat(file); return true; } catch (e) { if (e.code !== 'ENOENT') throw e; return false; }
}
async function read(file, life, synchronize = false) {
  return (synchronize ? readSynchronizedOperatorRecord : readPrivateOperatorFile)(file, FILE_LIMIT, life.check);
}
function command(compiled, seed, fingerprint, index) {
  const { number, action, fields } = compiled.steps[index];
  // The random seed is selected once, before any output request exists. Restarts
  // never call the random-key constructor for an already selected operation.
  const nonce = createHmac('sha256', Buffer.from(seed, 'hex'))
    .update('frankengit/github-pull-preparation/nonce/v1\0')
    .update(compiled.captureSha256).update('\0').update(String(index)).digest('hex').slice(0, 32);
  return preparePullWithIdentity({ endpoint: compiled.selection.endpoint, scope: compiled.selection.scope,
    number, action, fields }, { nonce, credential_fingerprint: fingerprint });
}
function render(capture, selection, seed, fingerprint, check) {
  pin(seed); pin(fingerprint); check();
  const compiled = compileGithubPullImport(capture, selection), hashes = []; let bytes = 0;
  for (let i = 0; i < compiled.steps.length; i++) {
    check(); const text = pullCanonical(command(compiled, seed, fingerprint, i));
    bytes += Buffer.byteLength(text);
    if (bytes > compiled.selection.max_request_bytes) fail('request_capacity');
    hashes.push(pullHash(text));
  }
  const manifest = { schema: GITHUB_PULL_IMPORT_SCHEMA, selection: compiled.selection,
    capture_sha256: compiled.captureSha256, credential_fingerprint: fingerprint,
    step_count: compiled.steps.length, steps_sha256: compiled.stepsSha256,
    request_sha256: hashes, request_bytes: bytes };
  if (encode(manifest).length > FILE_LIMIT) fail('manifest_limit');
  return { compiled, manifest };
}
async function guard(loaded) {
  for (const [name, id] of loaded.ids) await directory(join(loaded.root, name), id);
}
async function verifySlot(root, expected, life, synchronize) {
  const id = await directory(root); await inventory(root, ['intent.json'], life);
  life.check(); const actual = await loadPullIntent(root, { sync: synchronize });
  if (pullCanonical(actual) !== pullCanonical(expected)) fail('request_changed');
  await directory(root, id); life.check();
}
async function load(root, confirm, life, synchronize) {
  path(root); pin(confirm); life.check();
  const ids = new Map();
  for (const name of ['', 'import', 'import/requests', 'import/journal', 'pending']) ids.set(name, await directory(join(root, name)));
  await inventory(root, ['preparation.json', 'import', 'pending'], life);
  const selectedBytes = await read(join(root, 'preparation.json'), life, synchronize);
  if (pullHash(selectedBytes) !== confirm) fail('pin_mismatch');
  const selected = JSON.parse(new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(selectedBytes));
  pullFields(selected, ['schema', 'nonce_seed', 'manifest']);
  if (selected.schema !== SCHEMA || !encode(selected).equals(selectedBytes)) fail('encoding');
  const captureBytes = await read(join(root, 'import/capture.json'), life, synchronize);
  const expected = render(parseGithubPullCapture(captureBytes), selected.manifest.selection,
    selected.nonce_seed, selected.manifest.credential_fingerprint, life.check);
  if (!isDeepStrictEqual(selected.manifest, expected.manifest)) fail('plan_changed');
  const sealed = await present(join(root, 'import/manifest.json'));
  await inventory(join(root, 'import'), ['capture.json', 'requests', 'journal', ...(sealed ? ['manifest.json'] : [])], life);
  // Do not build or complete requests after somebody has started executing an
  // unfinished child. A sealed job's journal belongs to its existing executor.
  if (!sealed) await inventory(join(root, 'import/journal'), [], life);
  const slots = await names(join(root, 'import/requests'), expected.manifest.step_count + 1, life);
  if (slots.length > expected.manifest.step_count || slots.some((n, i) => n !== stepName(i))) fail('request_gap');
  const loaded = { root, confirm, ids, selected, ...expected, count: slots.length, pending: false, sealed };
  for (let i = 0; i < slots.length; i++) {
    await guard(loaded);
    await verifySlot(join(root, 'import/requests', slots[i]), command(expected.compiled, selected.nonce_seed,
      selected.manifest.credential_fingerprint, i), life, synchronize);
  }
  const pending = await names(join(root, 'pending'), 2, life);
  if (pending.length) {
    if (sealed || slots.length === expected.manifest.step_count || !isDeepStrictEqual(pending, ['request'])) fail('pending_inventory');
    await verifySlot(join(root, 'pending/request'), command(expected.compiled, selected.nonce_seed,
      selected.manifest.credential_fingerprint, slots.length), life, synchronize);
    loaded.pending = true;
  }
  if (sealed) {
    if (slots.length !== expected.manifest.step_count) fail('incomplete');
    if (!(await read(join(root, 'import/manifest.json'), life, synchronize)).equals(encode(expected.manifest))) fail('manifest_changed');
  }
  life.check(); await guard(loaded); return loaded;
}
function summary(loaded, added = 0) {
  return { type: 'github_pull_preparation', workdir: loaded.root, preparation_sha256: loaded.confirm,
    import_workdir: join(loaded.root, 'import'), plan_sha256: pullHash(encode(loaded.manifest)),
    capture_sha256: loaded.manifest.capture_sha256, steps: loaded.manifest.step_count,
    prepared_steps: loaded.count, new_steps: added, request_bytes: loaded.manifest.request_bytes,
    pending_step: loaded.pending ? loaded.count + 1 : null,
    state: loaded.sealed ? 'prepared' : 'paused', preparation_complete: loaded.sealed,
    network_accessed: false, mutation_submitted: false, execution_complete: false };
}
export async function beginGithubPullPreparation(raw) {
  const required = ['workdir', 'captureFile', 'captureConfirm', 'selection', 'tokenFile'];
  pullFields(raw, [...required, 'timeoutMs', 'signal'], required);
  const o = { ...raw, workdir: path(raw.workdir), captureFile: path(raw.captureFile),
    captureConfirm: pin(raw.captureConfirm), tokenFile: path(raw.tokenFile), selection: githubPullImportSelection(raw.selection) };
  const life = lifetime(o); let created = false, confirm = null;
  try {
    life.check(); await directory(dirname(o.workdir));
    if (await present(o.workdir)) fail('exists');
    await privatePullDirectory(dirname(o.captureFile));
    const captureBytes = await read(o.captureFile, life);
    if (pullHash(captureBytes) !== o.captureConfirm) fail('capture_pin');
    const capture = parseGithubPullCapture(captureBytes);
    const fingerprint = pullTokenFingerprint(await readPullToken(o.tokenFile)); life.check();
    // Full encoded intent overhead, not just form bodies, is checked before
    // random identity selection or creation of any output directory/key slot.
    render(capture, o.selection, '0'.repeat(64), fingerprint, life.check);
    const seed = randomBytes(32).toString('hex'), prepared = render(capture, o.selection, seed, fingerprint, life.check);
    const bytes = encode({ schema: SCHEMA, nonce_seed: seed, manifest: prepared.manifest });
    if (bytes.length > FILE_LIMIT) fail('plan_limit'); confirm = pullHash(bytes);
    await mkdir(o.workdir, { mode: 0o700 }); created = true; await sync(dirname(o.workdir));
    const identity = await directory(o.workdir);
    for (const name of ['import', 'import/requests', 'import/journal', 'pending']) await mkdir(join(o.workdir, name), { mode: 0o700 });
    await sync(join(o.workdir, 'import')); await sync(o.workdir);
    await saveOperatorRecord(join(o.workdir, 'import/capture.json'), captureBytes, life.check);
    await directory(o.workdir, identity);
    await saveOperatorRecord(join(o.workdir, 'preparation.json'), bytes, life.check);
    return summary(await load(o.workdir, confirm, life, true));
  } catch (cause) {
    const e = cause instanceof Error ? cause : new Error('github_pull_preparation_interrupted');
    e.preparation_progress = { workdir: o.workdir, directory_created: created, preparation_sha256: confirm,
      preparation_complete: false, mutation_submitted: false }; throw e;
  } finally { life.close(); }
}
export async function resumeGithubPullPreparation(raw) {
  pullFields(raw, ['workdir', 'confirm', 'maxRequests', 'timeoutMs', 'signal'], ['workdir', 'confirm']);
  const o = { ...raw, workdir: path(raw.workdir), confirm: pin(raw.confirm), maxRequests: integer(raw.maxRequests ?? 100, 1, 8192) };
  const life = lifetime(o); let loaded, added = 0;
  try {
    loaded = await load(o.workdir, o.confirm, life, true);
    if (loaded.sealed) return summary(loaded);
    while (loaded.count < loaded.manifest.step_count && added < o.maxRequests) {
      life.check(); await guard(loaded);
      const expected = command(loaded.compiled, loaded.selected.nonce_seed, loaded.manifest.credential_fingerprint, loaded.count);
      const pending = join(o.workdir, 'pending/request');
      if (!loaded.pending) await savePullIntent(pending, expected);
      // Cancellation during a bounded local write leaves the complete staged
      // original request available for the next invocation, never a new key.
      await verifySlot(pending, expected, { check() {} }, true);
      life.check(); await guard(loaded);
      // Every final slot is published as a complete nonempty directory. POSIX
      // rename cannot replace a competing nonempty request slot.
      await rename(pending, join(o.workdir, 'import/requests', stepName(loaded.count)));
      await sync(join(o.workdir, 'pending')); await sync(join(o.workdir, 'import/requests'));
      loaded.count++; loaded.pending = false; added++;
    }
    // Reread the whole retained prefix before reporting progress or publishing
    // the ordinary v1 root. This also notices a competing preparer's work.
    loaded = await load(o.workdir, o.confirm, life, true);
    if (!loaded.sealed && loaded.count === loaded.manifest.step_count) {
      life.check(); await guard(loaded);
      await saveOperatorRecord(join(o.workdir, 'import/manifest.json'), encode(loaded.manifest), life.check);
      loaded = await load(o.workdir, o.confirm, life, true);
    }
    return summary(loaded, added);
  } catch (cause) {
    const e = cause instanceof Error ? cause : new Error('github_pull_preparation_interrupted');
    e.preparation_progress = { workdir: o.workdir, preparation_sha256: o.confirm, preparation_verified: Boolean(loaded),
      new_steps: added, preparation_complete: false, mutation_submitted: false }; throw e;
  } finally { life.close(); }
}
export async function inspectGithubPullPreparation(raw) {
  pullFields(raw, ['workdir', 'confirm', 'timeoutMs', 'signal'], ['workdir', 'confirm']);
  const o = { ...raw, workdir: path(raw.workdir), confirm: pin(raw.confirm) }, life = lifetime(o);
  try { return { ...summary(await load(o.workdir, o.confirm, life, false)), local_read_only: true }; }
  finally { life.close(); }
}
