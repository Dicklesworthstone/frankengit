// FG-049: compose the shipped issue importer across one complete pinned inventory.
// This directory owns original request custody, never repository truth. No GitHub
// read, native mutation, replacement key or implicit retry occurs in preparation.
import { constants } from 'node:fs';
import { open, lstat, mkdir, realpath } from 'node:fs/promises';
import { dirname, join, sep } from 'node:path';
import { issueConnectionOptions } from './forge-issue-operator.mjs';
import { prepareGithubIssueImport, inspectPreparedGithubIssueImport } from './github-issue-import.mjs';
import { parseCapture, issueImportSteps, CAPTURE_LIMIT } from './github-issue-source.mjs';
import { parseIssueInventory, INVENTORY_LIMIT } from './github-issue-inventory.mjs';
import { operatorError, operatorPath, privateRecordPath, absentRecord, readPrivateOperatorFile,
  readSynchronizedOperatorRecord, saveOperatorRecord, recordDigest } from './forge-operator-io.mjs';

export const MIGRATION_SCHEMA = 'frankengit-github-issue-migration-v1';
export const MIGRATION_LIMITS = Object.freeze({ batches: 128, captureBytes: 64 * 1024 * 1024,
  requestBytes: 128 * 1024 * 1024, steps: 10000 });
const MANIFEST_LIMIT = 256 * 1024;
const encode = value => Buffer.from(JSON.stringify(value) + '\n');
const fail = code => { throw operatorError(`github_migration_${code}`); };
const same = (a, b) => encode(a).equals(encode(b));
const batchName = n => `batch-${String(n).padStart(6, '0')}`;
const captureName = n => `capture-${String(n).padStart(6, '0')}.json`;
function integer(value, minimum, maximum, name) {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) fail(name);
  return value;
}
function pin(value) {
  if (typeof value !== 'string' || !/^[0-9a-f]{64}$/.test(value)) fail('pin');
  return value;
}
function fields(value, names, required = names) {
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
      Object.keys(value).some(k => !names.includes(k)) || required.some(k => !Object.hasOwn(value, k))) fail('fields');
}
function options(raw, preparing) {
  const common = ['workdir', 'href', 'tenant', 'repository', 'tokenFile', 'timeoutMs', 'signal', 'onProgress'];
  const extra = preparing ? ['inventoryFile', 'inventorySha256', 'captures', 'offset', 'maxCaptureBytes', 'maxRequestBytes', 'maxSteps'] : ['confirm'];
  fields(raw, [...common, ...extra], ['workdir', 'href', 'tenant', 'repository', 'tokenFile', ...(preparing ? ['inventoryFile', 'inventorySha256', 'captures'] : ['confirm'])]);
  const o = issueConnectionOptions({ ...raw, timeoutMs: raw.timeoutMs ?? 300000 });
  o.workdir = operatorPath(raw.workdir);
  if (preparing) {
    o.inventoryFile = operatorPath(raw.inventoryFile); o.inventorySha256 = pin(raw.inventorySha256);
    o.offset = integer(raw.offset ?? 0, 0, Number.MAX_SAFE_INTEGER, 'offset');
    o.maxCaptureBytes = integer(raw.maxCaptureBytes ?? MIGRATION_LIMITS.captureBytes, 1, MIGRATION_LIMITS.captureBytes, 'capture_budget');
    o.maxRequestBytes = integer(raw.maxRequestBytes ?? MIGRATION_LIMITS.requestBytes, 1, MIGRATION_LIMITS.requestBytes, 'request_budget');
    o.maxSteps = integer(raw.maxSteps ?? MIGRATION_LIMITS.steps, 1, MIGRATION_LIMITS.steps, 'step_budget');
    if (!Array.isArray(raw.captures)) fail('captures');
    integer(raw.captures.length, 1, MIGRATION_LIMITS.batches, 'batch_count');
    // Copy all caller-selected paths, pins and batch ordinals before any await.
    o.captures = raw.captures.map(row => {
      fields(row, ['batch', 'path', 'sha256']);
      return { batch: integer(row.batch, 1, MIGRATION_LIMITS.batches, 'batch'), path: operatorPath(row.path), sha256: pin(row.sha256) };
    }).sort((a, b) => a.batch - b.batch);
    if (o.captures.some((row, i) => row.batch !== i + 1)) fail('batch_coverage');
  } else o.confirm = pin(raw.confirm);
  return o;
}
function lifetime(o) {
  const stop = new AbortController(), signal = o.signal ? AbortSignal.any([o.signal, stop.signal]) : stop.signal;
  const deadline = performance.now() + o.timeoutMs, timer = setTimeout(() => stop.abort(), o.timeoutMs);
  return { signal, check: () => { if (performance.now() >= deadline) stop.abort(); signal.throwIfAborted(); },
    close: () => { clearTimeout(timer); stop.abort(); } };
}
async function syncDirectory(path) {
  const file = await open(path, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
  try { await file.sync(); } finally { await file.close(); }
}
async function rootIdentity(root, expected = null) {
  const stat = await lstat(root, { bigint: true });
  if (typeof process.getuid !== 'function' || !stat.isDirectory() || stat.uid !== BigInt(process.getuid()) ||
      (stat.mode & 0o077n) !== 0n || await realpath(root) !== root ||
      (expected && (stat.dev !== expected.dev || stat.ino !== expected.ino))) fail('directory_changed_or_unsafe');
  return stat;
}
function separate(root, path) {
  if (path === root || path.startsWith(root + sep)) fail('input_inside_migration');
}
async function readPinned(path, digest, maximum, check) {
  const bytes = await readPrivateOperatorFile(path, maximum, check);
  if (recordDigest(bytes) !== digest) fail('pin_mismatch');
  return bytes;
}
function population(inventory, count) {
  const batches = Math.ceil(inventory.issues.length / inventory.batch_size);
  if (batches < 1 || batches > MIGRATION_LIMITS.batches || batches !== count) fail('batch_coverage');
}
function batchIssues(inventory, batch) {
  return inventory.issues.slice((batch - 1) * inventory.batch_size, batch * inventory.batch_size);
}
function validateCapture(inventory, batch, bytes, offset, comments) {
  const capture = parseCapture(bytes), identities = capture.issues.map(({ number, id }) => ({ number, id }));
  if (!same(capture.source, inventory.source) || !same(identities, batchIssues(inventory, batch))) fail('capture_membership');
  for (const issue of capture.issues) for (const comment of issue.comments) {
    if (comments.has(comment.id)) fail('duplicate_comment');
    comments.add(comment.id);
  }
  return issueImportSteps(capture, offset).length;
}
function childOptions(o, life, root, batch, confirm) {
  return { workdir: join(root, batchName(batch)), href: o.href, tenant: o.tenant, repository: o.repository,
    tokenFile: o.tokenFile, timeoutMs: o.timeoutMs, signal: life.signal, confirm };
}
function checkChild(child, inventory, row, offset) {
  if (child.source_sha256 !== row.capture_sha256 || child.offset !== offset || child.steps !== row.steps ||
      child.request_bytes !== row.request_bytes || !same(child.source, inventory.source) ||
      !same(child.issues, batchIssues(inventory, row.batch))) fail('prepared_batch_mismatch');
}

export async function prepareGithubIssueMigration(raw) {
  const o = options(raw, true), life = lifetime(o); let root = o.workdir, created = false, prepared = 0;
  try {
    life.check(); root = await privateRecordPath(root); await absentRecord(root);
    for (const path of [o.inventoryFile, o.tokenFile, ...o.captures.map(r => r.path)]) {
      separate(root, path); separate(root, await realpath(path)); life.check();
    }
    const inventoryBytes = await readPinned(o.inventoryFile, o.inventorySha256, INVENTORY_LIMIT, life.check);
    const inventory = parseIssueInventory(inventoryBytes); population(inventory, o.captures.length);
    const inputs = [], comments = new Set(); let captureBytes = 0, steps = 0;
    // Complete semantic preflight before creating a directory or any native key.
    for (const row of o.captures) {
      const bytes = await readPinned(row.path, row.sha256, CAPTURE_LIMIT, life.check);
      captureBytes += bytes.length;
      if (captureBytes > o.maxCaptureBytes) fail('capture_budget');
      const count = validateCapture(inventory, row.batch, bytes, o.offset, comments); steps += count;
      if (steps > o.maxSteps) fail('step_budget');
      inputs.push({ row, bytes, steps: count }); life.check();
    }
    await mkdir(root, { mode: 0o700 }); created = true;
    await syncDirectory(dirname(root)); const identity = await rootIdentity(root);
    await saveOperatorRecord(join(root, 'inventory.json'), inventoryBytes, life.check);
    const batches = []; let requestBytes = 0;
    for (const input of inputs) {
      life.check(); await rootIdentity(root, identity);
      const { row, bytes } = input, captureFile = join(root, captureName(row.batch));
      await saveOperatorRecord(captureFile, bytes, life.check);
      const remaining = o.maxRequestBytes - requestBytes;
      if (remaining < 1) fail('request_budget');
      const child = childOptions(o, life, root, row.batch, undefined);
      delete child.confirm;
      const result = await prepareGithubIssueImport({ ...child, captureFile, offset: o.offset,
        maxRequestBytes: Math.min(remaining, 16 * 1024 * 1024) });
      const verified = await inspectPreparedGithubIssueImport({ ...child, confirm: result.plan_sha256 });
      const retained = { batch: row.batch, capture_sha256: row.sha256, plan_sha256: result.plan_sha256,
        steps: input.steps, request_bytes: verified.request_bytes };
      checkChild(verified, inventory, retained, o.offset);
      requestBytes += verified.request_bytes; batches.push(retained); prepared++;
      o.onProgress(Object.freeze({ phase: 'batch_prepared', batch: row.batch, steps: input.steps }));
      life.check(); await rootIdentity(root, identity);
    }
    // Revalidate ALL children with the original token before publishing the root.
    // Partial preparations retain their files, but never become a runnable session.
    for (const row of batches) {
      const verified = await inspectPreparedGithubIssueImport(childOptions(o, life, root, row.batch, row.plan_sha256));
      checkChild(verified, inventory, row, o.offset);
    }
    await rootIdentity(root, identity); life.check();
    const manifest = { schema: MIGRATION_SCHEMA, href: o.href, tenant: o.tenant, repository: o.repository,
      inventory_sha256: o.inventorySha256, offset: o.offset, capture_bytes: captureBytes,
      request_bytes: requestBytes, step_count: steps, batches };
    const bytes = encode(manifest);
    if (bytes.length > MANIFEST_LIMIT) fail('manifest_bytes');
    const saved = await saveOperatorRecord(join(root, 'migration.json'), bytes, life.check);
    return { type: 'github_issue_migration_prepared', workdir: root, plan_sha256: saved.sha256,
      inventory_sha256: o.inventorySha256, source: inventory.source, issues: inventory.issues.length,
      excluded_pull_requests: inventory.excluded_pull_requests.length, batches: batches.length, steps,
      offset: o.offset, mutation_submitted: false, atomic_migration: false };
  } catch (cause) {
    const error = cause instanceof Error ? cause : operatorError('github_migration_failed');
    error.migration_preparation = { workdir: root, directory_created: created, prepared_batches: prepared,
      mutation_submitted: false, preserve_custody: created };
    throw error;
  } finally { life.close(); }
}

async function loadMigration(o, life) {
  life.check(); const root = o.workdir, identity = await rootIdentity(root);
  separate(root, o.tokenFile); separate(root, await realpath(o.tokenFile));
  const bytes = await readSynchronizedOperatorRecord(join(root, 'migration.json'), MANIFEST_LIMIT, life.check);
  if (recordDigest(bytes) !== o.confirm) fail('pin_mismatch');
  const m = JSON.parse(new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes));
  fields(m, ['schema', 'href', 'tenant', 'repository', 'inventory_sha256', 'offset', 'capture_bytes', 'request_bytes', 'step_count', 'batches']);
  if (!encode(m).equals(bytes) || m.schema !== MIGRATION_SCHEMA || m.href !== o.href || m.tenant !== o.tenant || m.repository !== o.repository) fail('manifest_mismatch');
  pin(m.inventory_sha256); integer(m.offset, 0, Number.MAX_SAFE_INTEGER, 'offset');
  integer(m.capture_bytes, 1, MIGRATION_LIMITS.captureBytes, 'capture_budget');
  integer(m.request_bytes, 1, MIGRATION_LIMITS.requestBytes, 'request_budget');
  integer(m.step_count, 1, MIGRATION_LIMITS.steps, 'step_budget');
  if (!Array.isArray(m.batches)) fail('batches');
  integer(m.batches.length, 1, MIGRATION_LIMITS.batches, 'batch_count');
  const inventory = parseIssueInventory(await readPinned(join(root, 'inventory.json'), m.inventory_sha256, INVENTORY_LIMIT, life.check));
  population(inventory, m.batches.length);
  let captureBytes = 0, requestBytes = 0, steps = 0; const comments = new Set();
  for (const [i, row] of m.batches.entries()) {
    fields(row, ['batch', 'capture_sha256', 'plan_sha256', 'steps', 'request_bytes']);
    if (row.batch !== i + 1) fail('batch_coverage');
    pin(row.capture_sha256); pin(row.plan_sha256);
    integer(row.steps, 1, 2200, 'step_budget'); integer(row.request_bytes, 1, 16 * 1024 * 1024, 'request_budget');
    const capture = await readPinned(join(root, captureName(row.batch)), row.capture_sha256, CAPTURE_LIMIT, life.check);
    captureBytes += capture.length; requestBytes += row.request_bytes; steps += row.steps;
    if (captureBytes > m.capture_bytes || requestBytes > m.request_bytes || steps > m.step_count) fail('total_mismatch');
    if (validateCapture(inventory, row.batch, capture, m.offset, comments) !== row.steps) fail('total_mismatch');
    await rootIdentity(join(root, batchName(row.batch)));
    const verified = await inspectPreparedGithubIssueImport(childOptions(o, life, root, row.batch, row.plan_sha256));
    checkChild(verified, inventory, row, m.offset); life.check(); await rootIdentity(root, identity);
  }
  if (captureBytes !== m.capture_bytes || requestBytes !== m.request_bytes || steps !== m.step_count) fail('total_mismatch');
  return { root, identity, manifest: m, inventory };
}
export async function inspectGithubIssueMigration(raw) {
  const o = options(raw, false), life = lifetime(o);
  try {
    const { manifest, inventory } = await loadMigration(o, life);
    return { type: 'github_issue_migration_verified', plan_sha256: o.confirm,
      inventory_sha256: manifest.inventory_sha256, source: inventory.source, issues: inventory.issues.length,
      excluded_pull_requests: inventory.excluded_pull_requests.length, offset: manifest.offset,
      batches: manifest.batches, steps: manifest.step_count, request_bytes: manifest.request_bytes,
      network_accessed: false, mutation_submitted: false, atomic_migration: false };
  } finally { life.close(); }
}
