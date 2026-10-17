// Persistent original-key import/fetch. Immutable reservations fence uncertain
// uploads; recovery never needs the payload or invents replacement request keys.
import { mkdir, opendir, lstat } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { lookupOutcome } from './transaction_outcome.mjs';
import { BUNDLE_REMOTE_LIMITS as L, fields, fail, encode, hash, pin, selection, canonical,
  prepareBundleRequest, checkedRequest, checkBundle, outcomeBinding, mergeObservation } from './remote_bundle_protocol.mjs';
import { absolute, directory, privateRoot, inventory, absent, syncDirectory, readPrivate,
  writeNew, readToken, lifetime } from './remote_bundle_files.mjs';
import { postBundle } from './remote_bundle_http.mjs';

const slot = n => `attempt-${String(n).padStart(6, '0')}`;
const codeOf = e => typeof e?.code === 'string' && /^[a-z_]{1,128}$/.test(e.code) ? e.code : 'remote_bundle_interrupted';
async function optional(path, maximum, life, sync) {
  try { return await readPrivate(path, maximum, life.check, sync); }
  catch (e) { if (e.code === 'ENOENT') return null; throw e; }
}
async function load(workdir, confirm, life, sync = false, payload = false) {
  const root = absolute(workdir); pin(confirm); life.check(); await privateRoot(root);
  const identity = await directory(root);
  const bytes = await readPrivate(join(root, 'intent.json'), L.intent, life.check, sync);
  if (hash(bytes) !== confirm) fail('intent_pin'); const request = checkedRequest(canonical(bytes));
  let present = true;
  try { await lstat(join(root, 'repository.bundle')); } catch (e) { if (e.code !== 'ENOENT') throw e; present = false; }
  await inventory(root, ['intent.json', 'attempts', ...(present ? ['repository.bundle'] : [])], life.check);
  const journal = join(root, 'attempts'), journalId = await directory(journal), names = [];
  for await (const e of await opendir(journal)) {
    life.check(); if (!/^attempt-[0-9]{6}$/.test(e.name) || names.length >= L.attempts) fail('attempt_limit'); names.push(e.name);
  }
  names.sort(); if (names.some((name, i) => name !== slot(i + 1))) fail('journal_gap');
  let previous = confirm, unsettled = 0, observation = { outcome: null, publication: null };
  for (const [i, name] of names.entries()) {
    life.check(); await directory(root, identity); await directory(journal, journalId);
    const attempt = join(journal, name), attemptId = await directory(attempt);
    const startBytes = await readPrivate(join(attempt, 'started.json'), 1024, life.check, sync);
    const start = canonical(startBytes); fields(start, ['schema', 'intent_sha256', 'key', 'sequence', 'previous_sha256', 'mode']);
    if (start.schema !== 'frankengit-bundle-attempt-v1' || start.intent_sha256 !== confirm || start.key !== request.key ||
        start.sequence !== i + 1 || start.previous_sha256 !== previous || !['send', 'recover'].includes(start.mode)) fail('reservation_changed');
    previous = hash(startBytes);
    const raw = await optional(join(attempt, 'result.json'), L.result, life, sync);
    await inventory(attempt, ['started.json', ...(raw ? ['result.json'] : [])], life.check);
    if (!raw) unsettled++;
    else {
      const r = canonical(raw); fields(r, ['schema', 'started_sha256', 'dispatched', 'error', 'observation']);
      if (r.schema !== 'frankengit-bundle-attempt-result-v1' || r.started_sha256 !== previous || typeof r.dispatched !== 'boolean' ||
          start.mode === 'recover' && r.dispatched || r.error !== null && (typeof r.error !== 'string' || !/^[a-z_]{1,128}$/.test(r.error))) fail('result_changed');
      if (r.error === null && r.observation?.outcome === null) fail('empty_result');
      observation = mergeObservation(observation, r.observation, request);
    }
    await directory(attempt, attemptId);
  }
  let bundle = null;
  if (payload) { bundle = await readPrivate(join(root, 'repository.bundle'), L.bundle, life.check, sync); checkBundle(request, bundle); }
  life.check(); await directory(root, identity); await directory(journal, journalId);
  return { root, identity, journalId, request, confirm, observation, attempts: names.length, unsettled, previous, bundle, payloadPresent: present };
}
function summary(state) {
  const terminal = state.observation.outcome?.terminal === true;
  return { type: 'remote_bundle_job', schema_version: 1, workdir: state.root, intent_sha256: state.confirm,
    key: state.request.key, operation: state.request.selection.operation, selection: state.request.selection,
    bundle: state.request.bundle, payload_present: state.payloadPresent, attempts: state.attempts,
    unsettled_attempts: state.unsettled, observation: state.observation,
    state: terminal ? state.observation.outcome.state : state.attempts ? 'unresolved' : 'ready',
    complete: terminal && state.observation.outcome.state === 'committed',
    canonical_restore: false, forge_state_imported: false, default_branch_changed: false };
}
export async function prepareRemoteBundle(raw) {
  fields(raw, ['workdir', 'selection', 'bundleFile', 'bundleConfirm', 'tokenFile', 'timeoutMs', 'signal'],
    ['workdir', 'selection', 'bundleFile', 'bundleConfirm', 'tokenFile']);
  const root = absolute(raw.workdir), selected = selection(raw.selection), source = absolute(raw.bundleFile),
    expected = pin(raw.bundleConfirm), tokenPath = absolute(raw.tokenFile), life = lifetime(raw);
  let created = false, confirm = null;
  try {
    await privateRoot(dirname(root)); await absent(root); life.check();
    const bundle = await readPrivate(source, L.bundle, life.check);
    if (hash(bundle) !== expected) fail('bundle_pin');
    const token = await readToken(tokenPath, life.check), request = prepareBundleRequest(selected, bundle, token);
    const bytes = encode(request); if (bytes.length > L.intent) fail('intent_limit'); confirm = hash(bytes);
    life.check(); await mkdir(root, { mode: 0o700 }); created = true; await syncDirectory(dirname(root));
    const identity = await directory(root);
    await mkdir(join(root, 'attempts'), { mode: 0o700 }); await syncDirectory(root);
    await writeNew(join(root, 'repository.bundle'), bundle);
    life.check(); await directory(root, identity); await writeNew(join(root, 'intent.json'), bytes);
    const loaded = await load(root, confirm, life, true, true);
    return { ...summary(loaded), native_bundle_validated: false, network_accessed: false, mutation_submitted: false };
  } catch (e) {
    e.bundle_progress = { workdir: root, directory_created: created, intent_sha256: confirm, complete: false }; throw e;
  } finally { life.close(); }
}
export async function inspectRemoteBundle(raw) {
  fields(raw, ['workdir', 'confirm', 'verifyPayload', 'timeoutMs', 'signal'], ['workdir', 'confirm']);
  if (raw.verifyPayload !== undefined && typeof raw.verifyPayload !== 'boolean') fail('options');
  const life = lifetime(raw);
  try { return { ...summary(await load(raw.workdir, raw.confirm, life, false, raw.verifyPayload ?? false)),
    network_accessed: false, local_read_only: true, payload_verified: raw.verifyPayload === true }; }
  finally { life.close(); }
}
export async function runRemoteBundle(raw) {
  fields(raw, ['workdir', 'confirm', 'operation', 'tokenFile', 'retryKey', 'timeoutMs', 'signal', 'caFile'], ['workdir', 'confirm']);
  const operation = raw.operation ?? 'run'; if (!['run', 'recover'].includes(operation)) fail('operation');
  if (raw.retryKey !== undefined && (typeof raw.retryKey !== 'string' || operation !== 'run')) fail('retry');
  const root = absolute(raw.workdir), confirm = pin(raw.confirm), life = lifetime(raw);
  let state, dispatched = false, network = false;
  try {
    state = await load(root, confirm, life, true);
    const request = state.request;
    if (raw.retryKey !== undefined && raw.retryKey !== request.key) fail('retry_key');
    if (state.observation.outcome?.terminal || operation === 'recover' && state.attempts === 0)
      return { ...summary(state), network_accessed: false, mutation_submitted: false };
    if (state.attempts >= L.attempts) fail('attempt_limit');
    const sending = operation === 'run' && !state.observation.publication && (state.attempts === 0 || raw.retryKey === request.key);
    const token = await readToken(absolute(raw.tokenFile), life.check);
    if (sending && hash(Buffer.from(token)) !== request.credential_sha256) fail('original_credential');
    const ca = raw.caFile === undefined ? undefined : await readPrivate(absolute(raw.caFile), 128 * 1024, life.check);
    // Recovery deliberately needs only the original intent, not the bundle.
    const bundle = sending ? await readPrivate(join(root, 'repository.bundle'), L.bundle, life.check, true) : null;
    if (sending) checkBundle(request, bundle);
    life.check(); await directory(root, state.identity); await directory(join(root, 'attempts'), state.journalId);
    const attempt = join(root, 'attempts', slot(state.attempts + 1));
    await mkdir(attempt, { mode: 0o700 }); await syncDirectory(join(root, 'attempts'));
    const attemptId = await directory(attempt);
    const start = encode({ schema: 'frankengit-bundle-attempt-v1', intent_sha256: confirm, key: request.key,
      sequence: state.attempts + 1, previous_sha256: state.previous, mode: sending ? 'send' : 'recover' });
    await writeNew(join(attempt, 'started.json'), start);
    let observed = state.observation, error = null;
    const binding = outcomeBinding(request.selection.scope);
    const lookup = () => lookupOutcome(request.selection.endpoint, token, { ...binding, key: request.key },
      { timeoutMs: life.remaining(), signal: life.signal, ca, known: observed.outcome });
    try {
      life.check(); network = true;
      const outcome = await lookup(); observed = mergeObservation(observed, { outcome, publication: null }, request);
      if (sending && !observed.outcome.terminal && !observed.publication) {
        const timeoutMs = life.remaining(); dispatched = true;
        const pub = await postBundle(request, bundle, token, { timeoutMs, signal: life.signal, ca });
        observed = mergeObservation(observed, { outcome: null, publication: pub }, request);
        const after = await lookup(); observed = mergeObservation(observed, { outcome: after, publication: null }, request);
        if (!observed.outcome.terminal) fail('confirmation_incomplete');
      }
    } catch (e) { error = codeOf(e); }
    // Already received evidence is drained after cancellation, not discarded.
    // A failed/torn write leaves this reservation unresolved for original-key recovery.
    await directory(root, state.identity); await directory(attempt, attemptId);
    const result = encode({ schema: 'frankengit-bundle-attempt-result-v1', started_sha256: hash(start), dispatched, error, observation: observed });
    if (result.length > L.result) fail('result_limit');
    await writeNew(join(attempt, 'result.json'), result);
    // No renewed network deadline. Status on the next invocation does a complete
    // journal read; this receipt owns the exact observation just retained here.
    state = { ...state, observation: observed, attempts: state.attempts + 1 };
    return { ...summary(state), network_accessed: network, mutation_submitted: dispatched, error };
  } catch (e) {
    e.bundle_progress = { workdir: root, intent_sha256: confirm, selection_verified: Boolean(state),
      key: state?.request.key ?? null, network_accessed: network, mutation_submitted: dispatched, complete: false }; throw e;
  } finally { life.close(); }
}
