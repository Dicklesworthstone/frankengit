// Bounded whole-plan composition over the unchanged native sender/outcome reader.
// A lost reply fences the original request; normal run can only recover it.
import { performance } from 'node:perf_hooks';
import { pullFields, pullTokenFingerprint } from '../operator/pull_command.mjs';
import { readPullToken, readPullPrivate, pullRecord } from '../operator/pull_files.mjs';
import { submitPull, recoverPull } from '../operator/remote_pull.mjs';
import { lifetime, number, pin, safePath } from './forge-pull-archive-store.mjs';
import { loadPullImport } from './native-pull-import.mjs';
import { PULL_IMPORT_LIMITS as L, importFail } from './native-pull-import-plan.mjs';
import { readImportJournal, reserveImportAttempt, saveImportObservation } from './native-pull-import-journal.mjs';

function options(raw) {
  const required = ['workdir', 'confirm', 'operation'];
  pullFields(raw, [...required, 'tokenFile', 'caFile', 'retryKey', 'maxOperations', 'timeoutMs', 'signal'], required);
  if (!['run', 'recover', 'status'].includes(raw.operation) ||
      (raw.operation !== 'run' && raw.retryKey !== undefined) ||
      (raw.operation === 'status' && ['tokenFile', 'caFile', 'maxOperations'].some(k => raw[k] !== undefined))) importFail('execution_options');
  if (raw.retryKey !== undefined && (typeof raw.retryKey !== 'string' || !/^[\x21-\x7e]{1,256}$/.test(raw.retryKey))) importFail('retry_key');
  return { ...raw, workdir: safePath(raw.workdir), confirm: pin(raw.confirm),
    maxOperations: number(raw.maxOperations ?? 100, 1, L.steps, 'operation_limit') };
}
function summary(loaded, journal, operations, dispatched, network, kind) {
  const index = journal.current, current = journal.states[index], intent = loaded.intents[index];
  const complete = index === loaded.intents.length;
  return { type: `${kind}_pull_import_progress`, schema_version: 1, workdir: loaded.root,
    plan_sha256: loaded.planSha256, ...(kind === 'native'
      ? { archive_sha256: loaded.manifest.archive_sha256 } : { capture_sha256: loaded.manifest.capture_sha256 }),
    journal_sha256: journal.journalSha256, steps: loaded.intents.length, committed_steps: index,
    attempts: journal.attempts, journal_bytes: journal.bytes, reserved_result_bytes: journal.reserved,
    unsettled_attempts: journal.states.reduce((n, s) => n + s.unsettled, 0),
    state: complete ? 'complete' : current.outcome?.state === 'refused' ? 'refused' : current.attempts ? 'pending' : 'ready',
    current: intent ? { step: index + 1, number: intent.number, action: intent.action, key: intent.key,
      attempts: current.attempts, outcome: current.outcome?.state ?? null, publication: current.publication?.outcome ?? null,
      last_error: current.error, may_have_submitted: current.attempts > 0 } : null,
    complete, new_operations: operations, mutations_dispatched: dispatched, network_accessed: network,
    mutation_submitted: dispatched > 0, atomic_batch: false, canonical_restore: false, approvals_imported: false, refs_changed: false };
}
export async function executePullImport(raw) {
  return executePreparedPullImport(raw, loadPullImport, 'native');
}
// Source adapters are repository code, never a field in a capture, request or
// CLI argument. Both profiles share the original sender and reservation journal.
export async function executePreparedPullImport(raw, loader, kind) {
  if (typeof loader !== 'function' || !['native', 'github'].includes(kind)) importFail('source_adapter');
  const o = options(raw), life = lifetime(o), deadline = performance.now() + life.timeout;
  let loaded, journal, operations = 0, dispatched = 0, network = false, token = null, ca;
  const remaining = () => {
    life.check(); const timeoutMs = Math.ceil(deadline - performance.now());
    if (timeoutMs <= 0) importFail('deadline'); return { timeoutMs, signal: life.signal, ...(ca ? { ca } : {}) };
  };
  try {
    loaded = await loader(o.workdir, o.confirm, life, o.operation !== 'status');
    journal = await readImportJournal(loaded, life, o.operation !== 'status');
    const first = loaded.intents[journal.current];
    if (o.retryKey !== undefined && (!first || first.key !== o.retryKey ||
        !journal.states[journal.current].attempts || journal.states[journal.current].outcome?.terminal)) importFail('retry_original_pending_key');
    if (o.operation === 'status') return { ...summary(loaded, journal, 0, 0, false, kind), local_read_only: true };
    while (journal.current < loaded.intents.length && operations < o.maxOperations) {
      life.check(); const state = journal.states[journal.current];
      if (state.outcome?.state === 'refused' || (o.operation === 'recover' && state.attempts === 0)) break;
      const intent = loaded.intents[journal.current];
      const mode = state.attempts === 0 ? 'send' : o.retryKey === intent.key ? 'retry' : 'recover';
      if (token === null) {
        safePath(o.tokenFile); token = await readPullToken(o.tokenFile);
        if (o.caFile !== undefined) { safePath(o.caFile); ca = await readPullPrivate(o.caFile, 128 * 1024); }
      }
      // A rotated token may recover the explicitly retained original principal,
      // but never sends under a different idempotency namespace.
      if (mode !== 'recover' && pullTokenFingerprint(token) !== loaded.manifest.credential_fingerprint) importFail('original_credential_required');
      remaining();
      const attempt = await reserveImportAttempt(loaded, journal, mode, life);
      let result = null, failure = null;
      try {
        const config = { ...remaining(), known: state.outcome, publication: state.publication };
        operations++; network = true;
        result = await (mode === 'recover' ? recoverPull(intent, token, config)
          : submitPull(intent, token, { ...config, confirmKey: intent.key }));
      } catch (error) { failure = error; }
      const record = pullRecord(intent, result, failure); if (record.dispatched) dispatched++;
      await saveImportObservation(loaded, journal, attempt, record);
      // Re-read concurrent observations and retain the strongest compatible
      // outcome. A stale nonterminal read must not erase a committed decision.
      // Final local receipt handling still finishes after an external stop.
      const settle = { ...life, check() {} };
      journal = await readImportJournal(loaded, settle, true, journal);
      if (failure || !result.outcome.terminal || o.operation === 'recover') break;
    }
    return summary(loaded, journal, operations, dispatched, network, kind);
  } catch (cause) {
    const error = cause instanceof Error ? cause : new Error('pull_import_interrupted');
    error.import_progress = { workdir: o.workdir, plan_sha256: o.confirm, plan_verified: Boolean(loaded),
      journal_sha256: journal?.journalSha256 ?? null, new_operations: operations, mutations_dispatched: dispatched,
      complete: false, outcome_unknown: true }; throw error;
  } finally { life.close(); }
}
