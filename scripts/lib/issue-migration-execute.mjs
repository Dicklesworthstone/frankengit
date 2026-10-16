// FG-049: execute the complete pinned migration using the existing batch importer.
// Original child requests remain the only retry custody. This coordinator neither
// derives replacement keys nor treats local progress as repository authority.
import { constants as F } from 'node:fs';
import { open, lstat, realpath, unlink } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { createHash } from 'node:crypto';

export function createIssueMigrationExecutor(backend, kind) {
if (!['github', 'native'].includes(kind)) throw new Error('issue_migration_adapter');
const ROOT_BYTES = 256 * 1024, MAX_BATCHES = 128, MAX_STEPS = 10000;
const encode = value => Buffer.from(JSON.stringify(value) + '\n');
const digest = value => createHash('sha256').update(value).digest('hex');
const fail = code => { const error = new Error(`${kind}_migration_${code}`); error.code = `${kind}_migration_${code}`; throw error; };
const integer = (value, min, max, name) => {
  if (!Number.isSafeInteger(value) || value < min || value > max) fail(name);
  return value;
};
function pin(value) {
  if (typeof value !== 'string' || !/^[0-9a-f]{64}$/.test(value)) fail('pin');
  return value;
}
function path(value) {
  if (typeof value !== 'string' || !value || Buffer.byteLength(value) > 4096 ||
      /[\x00-\x1f\x7f\uD800-\uDFFF]/u.test(value) || resolve(value) !== value) fail('absolute_path');
  return value;
}
async function rootIdentity(root, expected) {
  const stat = await lstat(root, { bigint: true });
  if (typeof process.getuid !== 'function' || !stat.isDirectory() || stat.uid !== BigInt(process.getuid()) ||
      (stat.mode & 0o077n) !== 0n || await realpath(root) !== root ||
      (expected && (stat.dev !== expected.dev || stat.ino !== expected.ino))) fail('directory_changed_or_unsafe');
  return stat;
}
async function syncDirectory(root) {
  const file = await open(root, F.O_RDONLY | F.O_DIRECTORY | F.O_NOFOLLOW);
  try { await file.sync(); } finally { await file.close(); }
}
async function rootPin(root, expected, check) {
  check();
  const name = join(root, 'migration.json'), file = await open(name, F.O_RDONLY | F.O_NOFOLLOW | F.O_NONBLOCK);
  try {
    const before = await file.stat();
    if (!before.isFile() || before.uid !== process.getuid() || (before.mode & 0o077) ||
        before.nlink !== 1 || before.size < 1 || before.size > ROOT_BYTES) fail('root_file');
    const bytes = Buffer.alloc(before.size + 1); let length = 0;
    while (length < bytes.length) {
      check();
      const read = await file.read(bytes, length, bytes.length - length, length);
      if (!read.bytesRead) break;
      length += read.bytesRead;
    }
    const after = await file.stat(), selected = await lstat(name);
    if (length !== before.size || before.size !== after.size || before.mtimeMs !== after.mtimeMs ||
        before.ctimeMs !== after.ctimeMs || before.dev !== selected.dev || before.ino !== selected.ino ||
        digest(bytes.subarray(0, length)) !== expected) fail('pin_mismatch');
  } finally { await file.close(); }
}
async function ownerPresent(root) {
  try { await lstat(join(root, 'migration.sender.lock')); return true; }
  catch (error) { if (error.code === 'ENOENT') return false; throw error; }
}
async function senderLock(root, identity, plan) {
  await rootIdentity(root, identity);
  const name = join(root, 'migration.sender.lock'); let file;
  try { file = await open(name, F.O_RDWR | F.O_CREAT | F.O_EXCL | F.O_NOFOLLOW, 0o600); }
  catch (error) { if (error.code === 'EEXIST') fail('sender_lock_retained'); throw error; }
  let selected;
  try {
    selected = await file.stat();
    await file.writeFile(encode({ schema: `frankengit-${kind}-issue-migration-sender-v1`, plan_sha256: plan }));
    await file.sync(); await syncDirectory(root); await rootIdentity(root, identity);
  } catch (error) { await file.close(); throw error; } // Keep a suspect lock, never steal it.
  return async () => {
    try {
      await rootIdentity(root, identity);
      const current = await lstat(name);
      if (!current.isFile() || current.dev !== selected.dev || current.ino !== selected.ino) fail('sender_lock_changed');
      await unlink(name); await syncDirectory(root);
    } finally { await file.close(); }
  };
}
function lifetime(milliseconds, parent) {
  const stop = new AbortController(), signal = parent ? AbortSignal.any([parent, stop.signal]) : stop.signal;
  const deadline = performance.now() + milliseconds;
  const timer = setTimeout(() => stop.abort(new Error(`${kind}_migration_deadline`)), milliseconds);
  const check = () => {
    if (performance.now() >= deadline) stop.abort(new Error(`${kind}_migration_deadline`));
    signal.throwIfAborted();
  };
  return { signal, check, remaining() { check(); return Math.max(1, Math.min(300000, Math.floor(deadline - performance.now()))); },
    close() { clearTimeout(timer); stop.abort(); } };
}
function inspection(value, confirm) {
  if (value?.type !== `${kind}_issue_migration_verified` || value.plan_sha256 !== confirm ||
      value.network_accessed !== false || value.mutation_submitted !== false || value.atomic_migration !== false ||
      !Array.isArray(value.batches)) fail('inspection_result');
  integer(value.batches.length, 1, MAX_BATCHES, 'batch_count');
  integer(value.steps, 1, MAX_STEPS, 'step_count');
  const owned = structuredClone(value); let steps = 0, bytes = 0;
  for (const [index, row] of owned.batches.entries()) {
    if (row.batch !== index + 1) fail('batch_coverage');
    pin(row.plan_sha256); pin(row.capture_sha256);
    steps += integer(row.steps, 1, 2200, 'step_count');
    bytes += integer(row.request_bytes, 1, 16 * 1024 * 1024, 'request_bytes');
  }
  if (steps !== value.steps || bytes !== value.request_bytes || bytes > 128 * 1024 * 1024) fail('inspection_totals');
  return owned;
}
function childProgress(value, row, operation, allowance, partial = false) {
  if (value?.type !== `${kind}_issue_import_progress` || value.plan_sha256 !== row.plan_sha256 ||
      value.operation !== operation || value.atomic_batch !== false || value.absence_proves_non_commit !== false) fail('batch_result');
  const committed = integer(value.committed_observed, 0, row.steps, 'batch_committed');
  const calls = integer(value.mutation_calls, 0, operation === 'status' ? 0 : Math.min(allowance, row.steps), 'batch_mutations');
  const next = integer(value.next_step, 0, row.steps, 'batch_next_step');
  if (value.total_steps !== row.steps && !(partial && value.total_steps === undefined && !committed && !calls && !next)) fail('batch_total');
  if (next !== committed || typeof value.complete !== 'boolean' ||
      value.complete !== (committed === row.steps) ||
      ![null, 'all_committed', 'not_started_locally', 'unresolved_original_request', 'mutation_limit', 'terminal_refusal'].includes(value.stop_reason) ||
      (value.complete && value.stop_reason !== 'all_committed') ||
      (!value.complete && (value.stop_reason === 'all_committed' || (!partial && value.stop_reason === null)))) fail('batch_progress');
  if (value.refusal !== undefined && value.stop_reason !== 'terminal_refusal') fail('batch_refusal');
  if (value.stop_reason === 'terminal_refusal' && (value.refusal?.outcome !== 'refused' ||
      typeof value.refusal.tx !== 'string' || !value.refusal.tx || value.refusal.tx.length > 256 ||
      value.refusal.rcr !== null || typeof value.refusal.refusal !== 'string' || !value.refusal.refusal || value.refusal.refusal.length > 256)) fail('batch_refusal');
  return { batch: row.batch, plan_sha256: row.plan_sha256, total_steps: row.steps,
    committed_observed: committed, mutation_calls: calls, next_step: next,
    complete: value.complete, stop_reason: value.stop_reason,
    ...(value.refusal ? { refusal: structuredClone(value.refusal) } : {}) };
}
function notify(callback, value) {
  const result = callback(Object.freeze(structuredClone(value)));
  if (result && typeof result.then === 'function') {
    // The batch API has a synchronous reporting contract. Do not detach an async
    // consumer and continue submitting mutations behind its failed output.
    Promise.resolve(result).catch(() => {});
    fail('progress_must_be_synchronous');
  }
}

// Only the existing batch boundary is injected in tests. Production imports the
// actual complete-plan inspector, native connection validator and batch runner.
function buildExecutor(backend) {
  for (const key of ['connectionOptions', 'inspect', 'runBatch']) if (typeof backend?.[key] !== 'function') fail('backend');
  return async function run(raw) {
    const allowed = ['operation', 'workdir', 'confirm', 'href', 'tenant', 'repository', 'tokenFile',
      'timeoutMs', 'signal', 'onProgress', 'maxMutations', 'retryUnresolved'];
    if (!raw || typeof raw !== 'object' || Array.isArray(raw) || Object.keys(raw).some(key => !allowed.includes(key)) ||
        !['run', 'status'].includes(raw.operation)) fail('execution_options');
    const timeout = integer(raw.timeoutMs ?? 300000, 1, 3600000, 'deadline');
    const selected = backend.connectionOptions({ ...raw, timeoutMs: Math.min(timeout, 300000) });
    const o = { ...selected, workdir: path(raw.workdir), confirm: pin(raw.confirm), operation: raw.operation,
      maxMutations: integer(raw.maxMutations ?? 100, 1, MAX_STEPS, 'mutation_budget'), retryUnresolved: raw.retryUnresolved ?? false };
    if (typeof o.retryUnresolved !== 'boolean' || (o.operation === 'status' && (o.retryUnresolved || raw.maxMutations !== undefined)) ||
        (o.signal !== undefined && !(o.signal instanceof AbortSignal)) || typeof o.onProgress !== 'function') fail('execution_options');
    const life = lifetime(timeout, o.signal);
    const summary = { type: `${kind}_issue_migration_progress`, schema_version: 1, plan_sha256: o.confirm,
      operation: o.operation, batches: [], total_batches: null, total_steps: null,
      committed_observed: 0, mutation_calls: 0, mutation_count_complete: true, complete: false, stop_reason: null,
      remote_read_only: o.operation === 'status', atomic_migration: false, canonical_snapshot: false,
      absence_proves_non_commit: false, owner_present: false };
    let release, failure, active, childOperation, allowance, verified, identity;
    const summarize = () => {
      summary.committed_observed = summary.batches.reduce((n, row) => n + row.committed_observed, 0);
      summary.mutation_calls = summary.batches.reduce((n, row) => n + row.mutation_calls, 0);
      summary.complete = summary.total_batches !== null && summary.batches.length === summary.total_batches && summary.batches.every(row => row.complete);
      if (summary.complete) summary.stop_reason = 'all_committed';
      return structuredClone(summary);
    };
    const connection = () => ({ href: o.href, tenant: o.tenant, repository: o.repository,
      tokenFile: o.tokenFile, signal: life.signal, timeoutMs: life.remaining() });
    try {
      life.check(); identity = await rootIdentity(o.workdir); await rootPin(o.workdir, o.confirm, life.check);
      summary.owner_present = await ownerPresent(o.workdir);
      if (o.operation === 'run') release = await senderLock(o.workdir, identity, o.confirm);
      verified = inspection(await backend.inspect({ ...connection(), workdir: o.workdir, confirm: o.confirm }), o.confirm);
      summary.total_batches = verified.batches.length; summary.total_steps = verified.steps;
      // Pin every child directory before any outcome query or mutation. Request,
      // credential and complete population validation belong to the real inspector.
      const children = new Map();
      for (const row of verified.batches) {
        life.check(); children.set(row.batch, await rootIdentity(join(o.workdir, `batch-${String(row.batch).padStart(6, '0')}`)));
      }
      for (const row of verified.batches) {
        life.check(); await rootIdentity(o.workdir, identity); await rootPin(o.workdir, o.confirm, life.check);
        const workdir = join(o.workdir, `batch-${String(row.batch).padStart(6, '0')}`);
        await rootIdentity(workdir, children.get(row.batch)); life.check();
        allowance = o.maxMutations - summary.mutation_calls;
        // At a depleted mutation budget, read-only recovery may still establish
        // completion. It must not turn a zero allowance into a child's default.
        childOperation = o.operation === 'run' && allowance > 0 ? 'run' : 'status';
        active = row;
        const result = await backend.runBatch({ ...connection(), workdir, confirm: row.plan_sha256,
          operation: childOperation, ...(childOperation === 'run' ? { maxMutations: Math.min(allowance, 2200), retryUnresolved: o.retryUnresolved } : {}),
          onProgress: event => {
            if (event?.outcome !== 'committed') fail('step_progress');
            integer(event.index, 0, row.steps - 1, 'step_index');
            notify(o.onProgress, { ...event, phase: 'step_committed', batch: row.batch, plan_sha256: o.confirm });
          } });
        const observed = childProgress(result, row, childOperation, Math.min(allowance, 2200));
        summary.batches.push(observed); active = null; summarize();
        // Keep the validated result even when a later custody/output check fails.
        await rootIdentity(o.workdir, identity); await rootIdentity(workdir, children.get(row.batch));
        notify(o.onProgress, { phase: 'batch_observed', ...observed });
        if (!observed.complete && o.operation === 'run') {
          summary.stop_reason = childOperation === 'status' && observed.stop_reason === 'not_started_locally'
            ? 'mutation_limit' : observed.stop_reason;
          break;
        }
      }
      summarize();
      if (!summary.complete && summary.stop_reason === null) summary.stop_reason = summary.batches.some(row => row.stop_reason === 'terminal_refusal')
        ? 'terminal_refusal' : summary.batches.some(row => row.stop_reason === 'unresolved_original_request') ? 'unresolved_original_request' : 'not_started_locally';
    } catch (cause) {
      failure = cause instanceof Error ? cause : new Error(`${kind}_migration_execution_failed`);
      if (active && failure.import_progress) {
        try { summary.batches.push(childProgress(failure.import_progress, active, childOperation, Math.min(allowance, 2200), true)); }
        catch (invalid) { summary.mutation_count_complete = false; failure.batch_progress_error = invalid.message; }
      }
      if (active && !failure.import_progress) summary.mutation_count_complete = false;
      summary.stop_reason ??= 'operation_failed';
      if (active && failure.observed_terminal) failure.migration_observed_terminal = { batch: active.batch, ...failure.observed_terminal };
    } finally {
      summarize();
      if (release) try { await release(); } catch (error) {
        if (failure) failure.migration_cleanup_error = error.message;
        else failure = error;
      }
      life.close();
    }
    if (failure) { failure.migration_progress = summarize(); throw failure; }
    return summarize();
  };
}

return buildExecutor(backend);
}
