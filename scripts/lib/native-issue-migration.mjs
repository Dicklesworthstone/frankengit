// Native issue DATA migration. The archive supplies input, never write authority.
// All native commands, keys and outcomes remain in the shared import engine.
import { constants as F } from 'node:fs';
import { mkdir, open, lstat, realpath, opendir } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { readIssueArchive } from './forge-issue-archive.mjs';
import { partitionNativeIssueArchive, parseNativeIssueCapture, nativeIssueImportSteps } from './native-issue-source.mjs';
import { prepareNativeIssueImport, inspectPreparedNativeIssueImport, runNativeIssueImport } from './native-issue-import.mjs';
import { createIssueMigrationExecutor } from './issue-migration-execute.mjs';
import { issueConnectionOptions } from './forge-issue-operator.mjs';
import { operatorError, operatorPath, privateRecordPath, absentRecord, readPrivateOperatorFile,
  readSynchronizedOperatorRecord, saveOperatorRecord, recordDigest } from './forge-operator-io.mjs';

const SCHEMA = 'frankengit-native-issue-migration-v1';
const L = Object.freeze({ batches: 128, steps: 10000, captureBytes: 64 * 1024 * 1024, requestBytes: 128 * 1024 * 1024 });
const encode = value => Buffer.from(JSON.stringify(value) + '\n');
const same = (a, b) => encode(a).equals(encode(b));
const fail = code => { throw operatorError(`native_migration_${code}`); };
const stem = n => String(n).padStart(6, '0');
const batchPath = (root, n) => join(root, `batch-${stem(n)}`);
const capturePath = (root, n) => join(root, `capture-${stem(n)}.json`);
function fields(value, allowed, required = allowed) {
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
      Object.keys(value).some(k => !allowed.includes(k)) || required.some(k => !Object.hasOwn(value, k))) fail('fields');
}
function integer(n, min, max, label) {
  if (!Number.isSafeInteger(n) || n < min || n > max) fail(label);
  return n;
}
function pin(value) { if (typeof value !== 'string' || !/^[0-9a-f]{64}$/.test(value)) fail('pin'); return value; }
function options(raw, prepare) {
  const required = ['workdir', 'href', 'tenant', 'repository', 'tokenFile'];
  const extra = prepare ? ['archiveDir', 'archiveSha256', 'offset', 'maxSteps', 'maxCaptureBytes', 'maxRequestBytes'] : ['confirm'];
  fields(raw, [...required, 'timeoutMs', 'signal', 'onProgress', ...extra], [...required, ...(prepare ? ['archiveDir', 'archiveSha256'] : ['confirm'])]);
  const o = issueConnectionOptions({ ...raw, timeoutMs: raw.timeoutMs ?? 300000 });
  o.workdir = operatorPath(raw.workdir);
  if (prepare) {
    o.archiveDir = operatorPath(raw.archiveDir); o.archiveSha256 = pin(raw.archiveSha256);
    o.offset = integer(raw.offset ?? 0, 0, Number.MAX_SAFE_INTEGER, 'offset');
    for (const [key, max] of [['maxSteps', L.steps], ['maxCaptureBytes', L.captureBytes], ['maxRequestBytes', L.requestBytes]]) {
      o[key] = integer(raw[key] ?? max, 1, max, key);
    }
  } else o.confirm = pin(raw.confirm);
  return o;
}
function lifetime(o) {
  const stop = new AbortController(), signal = o.signal ? AbortSignal.any([o.signal, stop.signal]) : stop.signal;
  const deadline = performance.now() + o.timeoutMs, timer = setTimeout(() => stop.abort(), o.timeoutMs);
  const check = () => { if (performance.now() >= deadline) stop.abort(); signal.throwIfAborted(); };
  return { signal, check, remaining() { check(); return Math.max(1, Math.floor(deadline - performance.now())); },
    close() { clearTimeout(timer); stop.abort(); } };
}
async function directory(root, expected) {
  const stat = await lstat(root, { bigint: true });
  if (typeof process.getuid !== 'function' || !stat.isDirectory() || stat.uid !== BigInt(process.getuid()) ||
      (stat.mode & 0o077n) || await realpath(root) !== root ||
      (expected && (stat.dev !== expected.dev || stat.ino !== expected.ino))) fail('directory_changed_or_unsafe');
  return stat;
}
async function syncDirectory(root) {
  const file = await open(root, F.O_RDONLY | F.O_DIRECTORY | F.O_NOFOLLOW);
  try { await file.sync(); } finally { await file.close(); }
}
function separate(root, input) {
  if (root === input || root.startsWith(input + '/') || input.startsWith(root + '/')) fail('overlapping_paths');
}
function connection(o, life) {
  return { href: o.href, tenant: o.tenant, repository: o.repository, tokenFile: o.tokenFile,
    signal: life.signal, timeoutMs: life.remaining() };
}
function child(o, life, n, confirm) {
  return { ...connection(o, life), workdir: batchPath(o.workdir, n), confirm };
}
function checkChild(result, source, row, offset) {
  if (result.type !== 'native_issue_import_verified' || result.plan_sha256 !== row.plan_sha256 ||
      result.source_sha256 !== row.capture_sha256 || result.offset !== offset || result.steps !== row.steps ||
      result.request_bytes !== row.request_bytes || !same(result.source, source) || !same(result.issues, row.issues)) fail('child_mismatch');
}
function notify(callback, value) {
  const result = callback(Object.freeze(value));
  if (result && typeof result.then === 'function') {
    Promise.resolve(result).catch(() => {}); fail('progress_must_be_synchronous');
  }
}
export async function prepareNativeIssueMigration(raw) {
  const o = options(raw, true), life = lifetime(o);
  let created = false, prepared = 0, expectedPin = null;
  try {
    life.check();
    if (await privateRecordPath(o.workdir) !== o.workdir) fail('path_alias');
    await absentRecord(o.workdir);
    separate(o.workdir, o.archiveDir); separate(o.workdir, o.tokenFile);
    separate(o.workdir, await realpath(o.archiveDir)); separate(o.workdir, await realpath(o.tokenFile));
    const view = await readIssueArchive({ workdir: o.archiveDir, confirm: o.archiveSha256,
      timeoutMs: life.remaining(), signal: life.signal });
    life.check();
    const parts = partitionNativeIssueArchive(view, o.offset);
    const steps = parts.reduce((n, row) => n + row.steps, 0), bytes = parts.reduce((n, row) => n + row.bytes.length, 0);
    if (steps > o.maxSteps || bytes > o.maxCaptureBytes) fail('source_budget');
    // All source semantics and native forms validate before any request key exists.
    const source = parseNativeIssueCapture(parts[0].bytes).source;
    life.check(); await mkdir(o.workdir, { mode: 0o700 }); created = true;
    await syncDirectory(dirname(o.workdir)); const identity = await directory(o.workdir);
    const batches = []; let requestBytes = 0;
    for (const [index, part] of parts.entries()) {
      life.check(); await directory(o.workdir, identity);
      const n = index + 1, captureFile = capturePath(o.workdir, n);
      await saveOperatorRecord(captureFile, part.bytes, life.check);
      const remaining = o.maxRequestBytes - requestBytes;
      if (remaining < 1) fail('request_budget');
      const preparedChild = await prepareNativeIssueImport({ ...connection(o, life),
        workdir: batchPath(o.workdir, n), captureFile, offset: o.offset, maxRequestBytes: Math.min(remaining, 16 * 1024 * 1024) });
      const verified = await inspectPreparedNativeIssueImport(child(o, life, n, preparedChild.plan_sha256));
      const row = { batch: n, capture_sha256: part.sha256, plan_sha256: preparedChild.plan_sha256,
        steps: part.steps, request_bytes: verified.request_bytes, issues: part.issues };
      checkChild(verified, source, row, o.offset); batches.push(row); requestBytes += row.request_bytes; prepared++;
      notify(o.onProgress, { phase: 'batch_prepared', batch: n, steps: part.steps });
      life.check(); await directory(o.workdir, identity);
    }
    // A changed credential/child cannot pass merely because an earlier pass did.
    for (const row of batches) {
      life.check(); await directory(o.workdir, identity);
      const retained = await readPrivateOperatorFile(capturePath(o.workdir, row.batch), 1024 * 1024, life.check);
      if (recordDigest(retained) !== row.capture_sha256) fail('capture_mismatch');
      checkChild(await inspectPreparedNativeIssueImport(child(o, life, row.batch, row.plan_sha256)), source, row, o.offset);
    }
    const manifest = { schema: SCHEMA, href: o.href, tenant: o.tenant, repository: o.repository, source,
      offset: o.offset, issue_count: view.archive.issues, comment_count: view.records.reduce((n, r) => n + r.comments.length, 0),
      capture_bytes: bytes, request_bytes: requestBytes, step_count: steps, batches };
    const encoded = encode(manifest); expectedPin = recordDigest(encoded);
    if (encoded.length > 256 * 1024) fail('root_bytes');
    life.check(); await directory(o.workdir, identity);
    await saveOperatorRecord(join(o.workdir, 'migration.json'), encoded, life.check);
    return { type: 'native_issue_migration_prepared', plan_sha256: expectedPin, workdir: o.workdir,
      archive_sha256: o.archiveSha256, issues: manifest.issue_count, comments: manifest.comment_count,
      batches: batches.length, steps, offset: o.offset, network_accessed: false, mutation_submitted: false,
      canonical_restore: false, atomic_migration: false };
  } catch (cause) {
    const error = cause instanceof Error ? cause : operatorError('native_migration_preparation_failed');
    error.migration_preparation = { workdir: o.workdir, directory_created: created, prepared_batches: prepared,
      expected_plan_sha256: expectedPin, mutation_submitted: false, preserve_custody: created };
    throw error;
  } finally { life.close(); }
}
export async function inspectNativeIssueMigration(raw) {
  const o = options(raw, false), life = lifetime(o);
  try {
    life.check(); const identity = await directory(o.workdir);
    separate(o.workdir, o.tokenFile); separate(o.workdir, await realpath(o.tokenFile));
    const bytes = await readSynchronizedOperatorRecord(join(o.workdir, 'migration.json'), 256 * 1024, life.check);
    if (recordDigest(bytes) !== o.confirm) fail('pin_mismatch');
    const m = JSON.parse(new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes));
    fields(m, ['schema', 'href', 'tenant', 'repository', 'source', 'offset', 'issue_count', 'comment_count', 'capture_bytes', 'request_bytes', 'step_count', 'batches']);
    if (!encode(m).equals(bytes) || m.schema !== SCHEMA || m.href !== o.href || m.tenant !== o.tenant || m.repository !== o.repository) fail('root_mismatch');
    integer(m.offset, 0, Number.MAX_SAFE_INTEGER, 'offset'); integer(m.issue_count, 1, 4096, 'issues');
    integer(m.comment_count, 0, L.steps, 'comments'); integer(m.step_count, 1, L.steps, 'steps');
    integer(m.capture_bytes, 1, L.captureBytes, 'capture_bytes'); integer(m.request_bytes, 1, L.requestBytes, 'request_bytes');
    if (!Array.isArray(m.batches)) fail('batches'); integer(m.batches.length, 1, L.batches, 'batches');
    const expected = new Set(['migration.json', 'migration.sender.lock']);
    for (let n = 1; n <= m.batches.length; n++) { expected.add(`batch-${stem(n)}`); expected.add(`capture-${stem(n)}.json`); }
    for await (const entry of await opendir(o.workdir)) { life.check(); if (!expected.has(entry.name)) fail('unexpected_file'); }
    let captured = 0, requests = 0, steps = 0, issues = 0, comments = 0, previous = 0;
    for (const [index, row] of m.batches.entries()) {
      fields(row, ['batch', 'capture_sha256', 'plan_sha256', 'steps', 'request_bytes', 'issues']);
      if (row.batch !== index + 1) fail('batch_order'); pin(row.capture_sha256); pin(row.plan_sha256);
      integer(row.steps, 1, 2200, 'steps'); integer(row.request_bytes, 1, 16 * 1024 * 1024, 'request_bytes');
      life.check(); await directory(o.workdir, identity); await directory(batchPath(o.workdir, row.batch));
      const rawCapture = await readPrivateOperatorFile(capturePath(o.workdir, row.batch), 1024 * 1024, life.check);
      if (recordDigest(rawCapture) !== row.capture_sha256) fail('capture_mismatch');
      const capture = parseNativeIssueCapture(rawCapture);
      if (!same(capture.source, m.source) || !same(capture.issues.map(({ number, id }) => ({ number, id })), row.issues) ||
          nativeIssueImportSteps(capture, m.offset).length !== row.steps) fail('population_mismatch');
      for (const issue of capture.issues) {
        integer(issue.number, previous + 1, Number.MAX_SAFE_INTEGER, 'issue_order'); previous = issue.number;
        issues++; comments += issue.comments.length;
      }
      captured += rawCapture.length; requests += row.request_bytes; steps += row.steps;
      if (captured > m.capture_bytes || requests > m.request_bytes || steps > m.step_count || issues > m.issue_count || comments > m.comment_count) fail('totals');
      checkChild(await inspectPreparedNativeIssueImport(child(o, life, row.batch, row.plan_sha256)), m.source, row, m.offset);
    }
    if (captured !== m.capture_bytes || requests !== m.request_bytes || steps !== m.step_count || issues !== m.issue_count || comments !== m.comment_count) fail('totals');
    life.check(); await directory(o.workdir, identity);
    return { type: 'native_issue_migration_verified', plan_sha256: o.confirm, source: m.source, offset: m.offset,
      issues, comments, steps, batches: m.batches, request_bytes: requests, network_accessed: false,
      mutation_submitted: false, canonical_restore: false, atomic_migration: false };
  } finally { life.close(); }
}
export const runNativeIssueMigration = createIssueMigrationExecutor({ connectionOptions: issueConnectionOptions,
  inspect: inspectNativeIssueMigration, runBatch: runNativeIssueImport }, 'native');
