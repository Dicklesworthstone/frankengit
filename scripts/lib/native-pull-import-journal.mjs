// Append-only operator observations, not forge authority. Every possible send is
// fenced by a synchronized original-key reservation before networking starts.
import { mkdir, opendir } from 'node:fs/promises';
import { join } from 'node:path';
import { isDeepStrictEqual } from 'node:util';
import { pullCanonical, pullOutcomeScope, parsePullJson } from '../operator/pull_command.mjs';
import { PULL_RECORD_LIMIT, validatePullRecord } from '../operator/pull_files.mjs';
import { validateOutcomeReply } from '../operator/transaction_outcome.mjs';
import { directory, digest, encode, exact, readPrivate, syncDirectory, writeNew } from './forge-pull-archive-store.mjs';
import { PULL_IMPORT_LIMITS as L, importFail } from './native-pull-import-plan.mjs';

const START_SCHEMA = 'frankengit-pull-import-attempt-v1', RESULT_SCHEMA = 'frankengit-pull-import-observation-v1';
const START_LIMIT = 1024, RESULT_LIMIT = PULL_RECORD_LIMIT + 1024, MAX_ATTEMPTS = 32768;
// Only a reader-created snapshot can seed an incremental read. Files or caller
// fields cannot supply cached terminal evidence. Cache entries own detached data.
const snapshots = new WeakMap();
const name = i => `attempt-${String(i + 1).padStart(6, '0')}`;
const rank = outcome => outcome === null ? -1 : ['key_not_observed', 'seal_not_observed', 'undecided', 'committed', 'refused'].indexOf(outcome.state);
const empty = () => ({ attempts: 0, outcome: null, publication: null, unsettled: 0, error: null });
async function optional(path, maximum, synchronize, check) {
  try { return await readPrivate(path, maximum, synchronize, check); }
  catch (e) { if (e.code !== 'ENOENT') throw e; return null; }
}
function observation(state, record, intent) {
  const previous = state.outcome, next = record.outcome;
  if (previous && next) {
    // Concurrent original-key reads can finish out of order. Preserve the
    // stronger compatible observation, but never erase contradictory evidence.
    const [weaker, stronger] = rank(previous) <= rank(next) ? [previous, next] : [next, previous];
    validateOutcomeReply(stronger, pullOutcomeScope(intent.scope), weaker);
  }
  if (next && rank(next) >= rank(previous)) state.outcome = next;
  if (record.publication) {
    if (state.publication && !isDeepStrictEqual(state.publication, record.publication)) importFail('publication_conflict');
    state.publication = record.publication;
  }
  if (state.outcome?.terminal && state.publication) {
    validatePullRecord({ ...record, outcome: state.outcome, publication: state.publication }, intent);
  }
  state.error = record.error;
}
export async function readImportJournal(loaded, life, synchronize = false, prior = null) {
  const path = join(loaded.root, 'journal'), identity = await directory(path);
  const cached = prior === null ? null : snapshots.get(prior);
  if (prior !== null && (!cached || cached.root !== loaded.root || cached.plan !== loaded.planSha256 ||
      cached.identity.dev !== identity.dev || cached.identity.ino !== identity.ino || cached.synchronize !== synchronize)) importFail('journal_snapshot');
  await directory(loaded.root, loaded.identity);
  const names = [], maximum = Math.min(MAX_ATTEMPTS, loaded.intents.length * L.attempts);
  for await (const entry of await opendir(path)) {
    life.check();
    if (!/^attempt-[0-9]{6}$/.test(entry.name) || names.length >= maximum) importFail('journal_inventory');
    names.push(entry.name);
  }
  names.sort(); if (names.some((v, i) => v !== name(i))) importFail('journal_gap');
  if (cached && names.length < cached.entries.length) importFail('journal_regressed');
  const states = loaded.intents.map(empty), commitments = [], entries = [];
  let bytes = 0, reserved = 0, previous = loaded.planSha256, lastStep = 0;
  for (let i = 0; i < names.length; i++) {
    life.check(); await directory(path, identity); await directory(loaded.root, loaded.identity);
    const slot = join(path, names[i]), retained = cached?.entries[i];
    let startBytes, start, raw, result, slotIdentity;
    if (retained) {
      // A verified immutable observation remains an observation even if another
      // local process later damages its file. New invocations always reread all
      // custody; this invocation owns the already authenticated prefix bytes.
      ({ startBytes, start, raw, result, slotIdentity } = structuredClone(retained));
    } else {
      slotIdentity = await directory(slot);
      startBytes = await optional(join(slot, 'started.json'), START_LIMIT, synchronize, life.check);
      if (!startBytes) importFail('incomplete_reservation');
      start = parsePullJson(startBytes, { maximum: START_LIMIT });
      raw = null; result = null;
    }
    if (!retained || raw === null) {
      await directory(slot, slotIdentity);
      const allowed = new Set(['started.json', 'result.json']);
      for await (const entry of await opendir(slot)) if (!allowed.delete(entry.name)) importFail('journal_file');
      raw = await optional(join(slot, 'result.json'), RESULT_LIMIT, synchronize, life.check);
      if (raw) result = parsePullJson(raw, { maximum: RESULT_LIMIT });
      await directory(slot, slotIdentity);
    }
    exact(start, ['schema', 'plan_sha256', 'sequence', 'step_index', 'key', 'mode', 'previous_sha256']);
    if (!encode(start).equals(Buffer.from(startBytes)) || start.schema !== START_SCHEMA || start.plan_sha256 !== loaded.planSha256 ||
        start.sequence !== i + 1 || start.previous_sha256 !== previous || !Number.isSafeInteger(start.step_index) ||
        start.step_index < lastStep || start.step_index > lastStep + (i === 0 ? 0 : 1) ||
        start.step_index >= loaded.intents.length || !['send', 'recover', 'retry'].includes(start.mode)) importFail('attempt_binding');
    const index = start.step_index, intent = loaded.intents[index], state = states[index];
    if (start.key !== intent.key || (start.mode === 'send') !== (state.attempts === 0) || ++state.attempts > L.attempts) importFail('attempt_key_or_mode');
    lastStep = index; previous = digest(startBytes); bytes += startBytes.length;
    if (raw) {
      exact(result, ['schema', 'attempt_sha256', 'record']);
      if (!encode(result).equals(Buffer.from(raw)) || result.schema !== RESULT_SCHEMA || result.attempt_sha256 !== previous) importFail('observation_binding');
      const record = validatePullRecord(result.record, intent);
      if (start.mode === 'recover' && record.dispatched) importFail('recovery_dispatched');
      observation(state, record, intent); bytes += raw.length;
    } else { state.unsettled++; reserved += RESULT_LIMIT; }
    if (bytes + reserved > L.recordBytes) importFail('journal_byte_limit');
    commitments.push({ attempt_sha256: previous, result_sha256: raw ? digest(raw) : null });
    entries.push({ startBytes, start, raw, result, slotIdentity: { dev: slotIdentity.dev, ino: slotIdentity.ino } });
  }
  let current = 0;
  while (current < states.length && states[current].outcome?.state === 'committed') current++;
  if (states.slice(current + 1).some(s => s.attempts)) importFail('journal_crossed_unresolved_step');
  life.check(); await directory(path, identity); await directory(loaded.root, loaded.identity);
  const journal = { path, identity, states, current, attempts: names.length, maximum, bytes, reserved,
    previous, journalSha256: digest(encode(commitments)) };
  snapshots.set(journal, { root: loaded.root, plan: loaded.planSha256, synchronize,
    identity: { dev: identity.dev, ino: identity.ino }, entries: structuredClone(entries) });
  return journal;
}
export async function reserveImportAttempt(loaded, journal, mode, life) {
  const index = journal.current, state = journal.states[index], intent = loaded.intents[index];
  if (!intent || journal.attempts >= journal.maximum || state.attempts >= L.attempts) importFail('attempt_limit');
  if (journal.bytes + journal.reserved + START_LIMIT + RESULT_LIMIT > L.recordBytes) importFail('journal_byte_limit');
  life.check(); await directory(loaded.root, loaded.identity); await directory(journal.path, journal.identity);
  const slot = join(journal.path, name(journal.attempts));
  // One exclusive slot also arbitrates competing runners. An existing slot is
  // not removed, repaired or stolen, including after a stopped process.
  try { await mkdir(slot, { mode: 0o700 }); } catch (e) { if (e.code === 'EEXIST') importFail('concurrent_runner'); throw e; }
  await syncDirectory(journal.path); const identity = await directory(slot);
  const start = { schema: START_SCHEMA, plan_sha256: loaded.planSha256, sequence: journal.attempts + 1,
    step_index: index, key: intent.key, mode, previous_sha256: journal.previous };
  const bytes = encode(start); if (bytes.length > START_LIMIT) importFail('attempt_limit');
  await writeNew(join(slot, 'started.json'), bytes);
  await directory(slot, identity); await directory(journal.path, journal.identity); await directory(loaded.root, loaded.identity);
  return { slot, identity, sha256: digest(bytes), index, intent, mode };
}
export async function saveImportObservation(loaded, journal, attempt, value) {
  const record = validatePullRecord(value, attempt.intent);
  const bytes = encode({ schema: RESULT_SCHEMA, attempt_sha256: attempt.sha256, record });
  if (Buffer.byteLength(pullCanonical(record)) > PULL_RECORD_LIMIT || bytes.length > RESULT_LIMIT) importFail('observation_limit');
  // Preserve a received terminal even if cancellation arrived during cleanup.
  // No signal check discards this result; the caller drains local responsibility.
  await directory(loaded.root, loaded.identity); await directory(journal.path, journal.identity); await directory(attempt.slot, attempt.identity);
  await writeNew(join(attempt.slot, 'result.json'), bytes);
  await directory(attempt.slot, attempt.identity); await directory(loaded.root, loaded.identity);
}
