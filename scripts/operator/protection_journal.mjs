// Bounded custody of one immutable intent, one may-have-sent marker, one first
// transaction observation and one terminal observation. None is server authority.
import { lstat, mkdir, rmdir, unlink } from 'node:fs/promises';
import { join } from 'node:path';
import { randomBytes } from 'node:crypto';
import { ProtectionError, canonical, parseJson, verifyObservation, extendsObservation, publicationPreflight,
  publishIntent, recoverIntent, validateIntent, endpoint } from './review_protection.mjs';
import { privateDirectory, readPrivate, createPrivate, loadIntent, syncDirectory } from './protection_files.mjs';
const fail = code => { throw new ProtectionError(code); };
async function optional(path, maximum = 64 * 1024) {
  try { return await readPrivate(path, maximum); }
  catch (error) { if (error.code === 'ENOENT') return null; throw error; }
}
async function readObservation(path, intent, terminal) {
  const bytes = await optional(path);
  if (bytes === null) return null;
  const selected = verifyObservation(parseJson(bytes), intent);
  if (!bytes.equals(Buffer.from(canonical(selected.record))) || selected.summary.tx_id === null ||
      (terminal && !selected.summary.terminal)) fail('invalid_retained_observation');
  return selected;
}
async function retained(directory, intent) {
  const known = await readObservation(join(directory, 'known.json'), intent, false);
  const terminal = await readObservation(join(directory, 'terminal.json'), intent, true);
  if (terminal) extendsObservation(terminal, known);
  return { known, terminal };
}
async function sameIntent(directory, intent) {
  if ((await loadIntent(directory)).intent_sha256 !== intent.intent_sha256) fail('intent_changed_during_operation');
}
async function keep(path, selected, intent, terminal) {
  try { await createPrivate(path, canonical(selected.record)); }
  catch (error) {
    if (error.code !== 'EEXIST') throw error;
    const previous = await readObservation(path, intent, terminal);
    if (!previous) throw error;
    extendsObservation(selected, previous);
  }
}
async function remember(directory, intent, selected) {
  await sameIntent(directory, intent);
  const previous = await retained(directory, intent);
  extendsObservation(selected, previous.terminal ?? previous.known);
  if (selected.summary.tx_id !== null) await keep(join(directory, 'known.json'), selected, intent, false);
  if (selected.summary.terminal) await keep(join(directory, 'terminal.json'), selected, intent, true);
}
function failure(error, selected = null, uncertain = true) {
  const output = error instanceof ProtectionError ? error : new ProtectionError('local_observation_or_cleanup_failure');
  output.outcomeUnknown = selected?.summary.terminal ? false : uncertain;
  if (selected) output.observation = selected;
  return output;
}
async function acquire(directory, intent) {
  const path = join(directory, '.send-lock');
  try { await mkdir(path, { mode: 0o700 }); }
  catch (error) { if (error.code === 'EEXIST') throw new ProtectionError('send_lock_held_no_automatic_stealing', { outcomeUnknown: true }); throw error; }
  const metadata = await lstat(path), owner = canonical({ intent_sha256: intent.intent_sha256, nonce: randomBytes(16).toString('hex'), pid: process.pid });
  // An interrupted lock initialization stays blocking. It grants no permission
  // to guess whether a previous external publication did or did not commit.
  await createPrivate(join(path, 'owner.json'), owner); await syncDirectory(directory);
  return async () => {
    const current = await lstat(path), bytes = await readPrivate(join(path, 'owner.json'), 4096);
    if (current.dev !== metadata.dev || current.ino !== metadata.ino || !bytes.equals(Buffer.from(owner))) fail('send_lock_owner_changed');
    await unlink(join(path, 'owner.json')); await rmdir(path); await syncDirectory(directory);
  };
}
export async function sendSavedIntent(path, token, { expectedEndpoint, confirmation, retry = false,
  signal, timeoutMs = 30_000, observe = async () => {} } = {}) {
  if (typeof retry !== 'boolean') fail('invalid_retry_choice');
  const directory = await privateDirectory(path);
  const intent = publicationPreflight(await loadIntent(directory), token, expectedEndpoint, confirmation);
  const release = await acquire(directory, intent);
  let selected = null, error = null, mayHaveSent = false, saved = false, dispatched = false;
  try {
    const old = await retained(directory, intent);
    if (old.terminal) { selected = old.terminal; saved = true; }
    else {
      const marker = canonical({ schema: 'frankengit-review-protection-may-have-sent-v1', intent_sha256: intent.intent_sha256 });
      const markerPath = join(directory, 'attempt.json'), previous = await optional(markerPath, 4096);
      if (previous !== null) {
        mayHaveSent = true;
        if (!previous.equals(Buffer.from(marker))) fail('attempt_marker_mismatch');
        if (!retry) fail('explicit_retry_required');
      }
      if (signal?.aborted) fail('cancelled');
      if (previous === null) await createPrivate(markerPath, marker);
      // Responsibility is synced before the socket exists. Failure from here
      // preserves the marker, original bytes and key; it is never rollback.
      mayHaveSent = true;
      await observe('before_send', { intent_sha256: intent.intent_sha256 });
      await sameIntent(directory, intent);
      if (signal?.aborted) fail('cancelled');
      const latest = await retained(directory, intent);
      if (latest.terminal) { selected = latest.terminal; saved = true; }
      else {
        dispatched = true;
        selected = await publishIntent(intent, token, { expectedEndpoint, confirmation, known: (latest.known ?? old.known)?.record ?? null, timeoutMs, signal });
        // A validated terminal wins over a subsequent cancellation. Persist it
        // and drain local custody before reporting; never turn it into unknown.
        await observe('terminal_observed', { intent_sha256: intent.intent_sha256, state: selected.summary.state });
        await remember(directory, intent, selected); saved = true;
      }
    }
  } catch (cause) { error = failure(cause, selected, mayHaveSent); }
  try { await release(); } catch (cause) { error = failure(error ?? cause, selected, mayHaveSent); }
  if (error) throw error;
  return { ...selected, local_observation_synced: saved, mutation_request_sent: dispatched };

}
export async function recoverSavedIntent(path, token, { expectedEndpoint, signal, timeoutMs = 30_000, observe = async () => {} } = {}) {
  const directory = await privateDirectory(path), intent = validateIntent(await loadIntent(directory));
  if (endpoint(expectedEndpoint) !== intent.endpoint) fail('independent_endpoint_pin_mismatch');
  // Read-only server lookups do not acquire or steal a possibly killed sender's
  // lock. All local observations are create-only and independently revalidated.
  let selected = null;
  try {
    const old = await retained(directory, intent);
    selected = await recoverIntent(intent, token, { expectedEndpoint, known: (old.terminal ?? old.known)?.record ?? null, timeoutMs, signal });
    await observe('outcome_observed', { intent_sha256: intent.intent_sha256, state: selected.summary.state });
    await remember(directory, intent, selected);
    return { ...selected, local_observation_synced: selected.summary.tx_id !== null, request_reexecuted: false };
  } catch (cause) { throw failure(cause, selected); }
}
