// FG-049 source acquisition only. Original inventory selection and completed
// captures survive restarts; no native request, principal or retry key is created.
import { constants } from 'node:fs';
import { lstat, mkdir, open, opendir, realpath, rmdir } from 'node:fs/promises';
import { dirname, join, sep } from 'node:path';
import { createGithubIssueCaptureSession, parseCapture, issueImportSteps, CAPTURE_LIMIT } from './github-issue-source.mjs';
import { parseIssueInventory, selectIssueInventoryBatch, INVENTORY_LIMIT } from './github-issue-inventory.mjs';
import { operatorError, operatorPath, privateRecordPath, absentRecord, recordDigest,
  readPrivateOperatorFile, readSynchronizedOperatorRecord, saveOperatorRecord } from './forge-operator-io.mjs';

const SCHEMA = 'frankengit-github-issue-capture-session-v1';
const LIMITS = Object.freeze({ batches: 128, captureBytes: 64 * 1024 * 1024, steps: 10000 });
const HEADER_LIMIT = 8192, SOURCES_LIMIT = 1024 * 1024;
const encode = value => Buffer.from(JSON.stringify(value) + '\n');
const fail = code => { throw operatorError(`github_capture_migration_${code}`); };
const equal = (a, b) => encode(a).equals(encode(b));
function fields(value, names, required = names) {
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
      Object.keys(value).some(key => !names.includes(key)) || required.some(key => !Object.hasOwn(value, key))) fail('fields');
}
function integer(value, min, max) {
  if (!Number.isSafeInteger(value) || value < min || value > max) fail('budget');
  return value;
}
function pin(value) {
  if (typeof value !== 'string' || !/^[0-9a-f]{64}$/.test(value)) fail('pin');
  return value;
}
function options(raw) {
  const op = raw?.operation;
  if (!['start', 'resume', 'status'].includes(op)) fail('operation');
  const common = ['operation', 'workdir', 'timeoutMs', 'signal'];
  const network = ['tokenFile', 'maxBatches', 'maxReadBytes', 'maxRequests', 'maxSourceRetries', 'fetchImpl'];
  const selection = ['inventoryFile', 'inventorySha256', 'offset', 'maxCaptureBytes', 'maxSteps'];
  fields(raw, [...common, ...(op === 'status' ? [] : network), ...(op === 'start' ? selection : ['confirm'])],
    ['operation', 'workdir', ...(op === 'start' ? ['inventoryFile', 'inventorySha256'] : ['confirm'])]);
  const o = { operation: op, workdir: operatorPath(raw.workdir), timeoutMs: integer(raw.timeoutMs ?? 300000, 1, 300000), signal: raw.signal };
  if (o.signal !== undefined && !(o.signal instanceof AbortSignal)) fail('signal');
  if (op !== 'status') {
    o.tokenFile = raw.tokenFile === undefined || raw.tokenFile === null ? null : operatorPath(raw.tokenFile);
    o.maxBatches = integer(raw.maxBatches ?? 8, 1, LIMITS.batches);
    o.maxReadBytes = integer(raw.maxReadBytes ?? 64 * 1024 * 1024, 1, 256 * 1024 * 1024);
    o.maxRequests = integer(raw.maxRequests ?? 4096, 1, 4096);
    o.maxSourceRetries = integer(raw.maxSourceRetries ?? 0, 0, 10);
    o.fetchImpl = raw.fetchImpl ?? globalThis.fetch;
    if (typeof o.fetchImpl !== 'function') fail('fetch');
  }
  if (op === 'start') {
    o.inventoryFile = operatorPath(raw.inventoryFile); o.inventorySha256 = pin(raw.inventorySha256);
    o.offset = integer(raw.offset ?? 0, 0, Number.MAX_SAFE_INTEGER);
    o.maxCaptureBytes = integer(raw.maxCaptureBytes ?? LIMITS.captureBytes, 1, LIMITS.captureBytes);
    o.maxSteps = integer(raw.maxSteps ?? LIMITS.steps, 1, LIMITS.steps);
  } else o.confirm = pin(raw.confirm);
  return o;
}
function lifetime(o) {
  const stop = new AbortController(), signal = o.signal ? AbortSignal.any([o.signal, stop.signal]) : stop.signal;
  const end = performance.now() + o.timeoutMs, timer = setTimeout(() => stop.abort(), o.timeoutMs);
  const check = () => { if (performance.now() >= end) stop.abort(); signal.throwIfAborted(); };
  return { signal, check, remaining() { check(); return Math.max(1, Math.floor(end - performance.now())); },
    close() { clearTimeout(timer); stop.abort(); } };
}
async function directory(path, expected = null) {
  const stat = await lstat(path, { bigint: true });
  if (typeof process.getuid !== 'function' || !stat.isDirectory() || stat.uid !== BigInt(process.getuid()) ||
      (stat.mode & 0o777n) !== 0o700n || await realpath(path) !== path ||
      (expected && (stat.dev !== expected.dev || stat.ino !== expected.ino))) fail('directory_changed');
  return stat;
}
async function syncDirectory(path) {
  const fd = await open(path, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
  try { await fd.sync(); } finally { await fd.close(); }
}
function separate(root, path) {
  if (path === root || path.startsWith(root + sep)) fail('input_inside_capture');
}
async function token(o, root, check) {
  if (o.tokenFile === null) return { value: null, fingerprint: null };
  separate(root, o.tokenFile); separate(root, await realpath(o.tokenFile)); check();
  const bytes = await readPrivateOperatorFile(o.tokenFile, 256, check);
  try {
    if (bytes.some(byte => byte > 127)) fail('token');
    const match = /^([A-Za-z0-9_]{1,255})(?:\n)?$(?![\s\S])/.exec(bytes.toString('ascii'));
    if (!match) fail('token');
    return { value: match[1], fingerprint: recordDigest(Buffer.from(`frankengit/github-source-credential/v1\0${match[1]}`)) };
  } finally { bytes.fill(0); }
}
function totalBatches(inventory) {
  return integer(Math.ceil(inventory.issues.length / inventory.batch_size), 1, LIMITS.batches);
}
async function initialize(o, life) {
  life.check();
  const root = await privateRecordPath(o.workdir);
  // Do not allow a parent alias to change the persisted absolute source paths.
  if (root !== o.workdir) fail('directory_changed');
  await absentRecord(root);
  separate(root, o.inventoryFile); separate(root, await realpath(o.inventoryFile));
  const bytes = await readPrivateOperatorFile(o.inventoryFile, INVENTORY_LIMIT, life.check);
  if (recordDigest(bytes) !== o.inventorySha256) fail('pin_mismatch');
  const inventory = parseIssueInventory(bytes); totalBatches(inventory);
  if (inventory.issues.length > o.maxSteps || inventory.issues.some(row => !Number.isSafeInteger(row.number + o.offset))) fail('budget');
  const credential = await token(o, root, life.check);
  const header = { schema: SCHEMA, workdir: root, inventory_sha256: o.inventorySha256,
    credential_sha256: credential.fingerprint, offset: o.offset, max_capture_bytes: o.maxCaptureBytes, max_steps: o.maxSteps };
  life.check(); await mkdir(root, { mode: 0o700 }); await syncDirectory(dirname(root));
  const identity = await directory(root);
  await saveOperatorRecord(join(root, 'inventory.json'), bytes, life.check);
  await directory(root, identity);
  const saved = await saveOperatorRecord(join(root, 'session.json'), encode(header), life.check);
  await directory(root, identity);
  return saved.sha256;
}
async function entries(root) {
  const result = [], dir = await opendir(root);
  for await (const entry of dir) {
    if (result.length === LIMITS.batches + 4) fail('entry_limit');
    result.push(entry.name);
  }
  return result.sort();
}
function canonical(bytes) {
  const value = JSON.parse(new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes));
  if (!encode(value).equals(bytes)) fail('noncanonical');
  return value;
}
function account(bytes, inventory, header, batch, counts) {
  const selection = selectIssueInventoryBatch(inventory, header.inventory_sha256, batch), capture = parseCapture(bytes);
  if (!equal(selection.source, capture.source) || !equal(selection.issues, capture.issues.map(({ number, id }) => ({ number, id })))) fail('membership_changed');
  const steps = issueImportSteps(capture, header.offset).length;
  if (counts.bytes + bytes.length > header.max_capture_bytes || counts.steps + steps > header.max_steps) fail('capacity');
  for (const issue of capture.issues) for (const comment of issue.comments) {
    if (counts.comments.has(comment.id)) fail('duplicate_comment');
    counts.comments.add(comment.id);
  }
  counts.bytes += bytes.length; counts.steps += steps;
}
function sourceSelection(selected) {
  return { schema: 'frankengit-github-issue-migration-sources-v1',
    inventory: { path: join(selected.root, 'inventory.json'), sha256: selected.header.inventory_sha256 },
    captures: selected.captures, offset: selected.header.offset,
    maxSteps: selected.header.max_steps, maxCaptureBytes: selected.header.max_capture_bytes };
}
async function load(o, life) {
  life.check(); const root = o.workdir, identity = await directory(root);
  const read = o.operation === 'status' ? readPrivateOperatorFile : readSynchronizedOperatorRecord;
  const bytes = await read(join(root, 'session.json'), HEADER_LIMIT, life.check);
  if (recordDigest(bytes) !== o.confirm) fail('pin_mismatch');
  const header = canonical(bytes);
  fields(header, ['schema', 'workdir', 'inventory_sha256', 'credential_sha256', 'offset', 'max_capture_bytes', 'max_steps']);
  if (header.schema !== SCHEMA || header.workdir !== root) fail('session_changed');
  pin(header.inventory_sha256); if (header.credential_sha256 !== null) pin(header.credential_sha256);
  integer(header.offset, 0, Number.MAX_SAFE_INTEGER); integer(header.max_capture_bytes, 1, LIMITS.captureBytes); integer(header.max_steps, 1, LIMITS.steps);
  const raw = await read(join(root, 'inventory.json'), INVENTORY_LIMIT, life.check);
  if (recordDigest(raw) !== header.inventory_sha256) fail('inventory_changed');
  const inventory = parseIssueInventory(raw), total = totalBatches(inventory), captures = [];
  const files = await entries(root), counts = { bytes: 0, steps: 0, comments: new Set() };
  for (const name of files) {
    if (['inventory.json', 'session.json', 'capture.owner', 'sources.json'].includes(name)) continue;
    const match = /^capture-([0-9]{6})-([0-9a-f]{64})\.json$/.exec(name);
    if (!match || Number(match[1]) !== captures.length + 1 || captures.length === total) fail('custody_gap_or_unknown_file');
    const batch = captures.length + 1, path = join(root, name), bytes = await read(path, CAPTURE_LIMIT, life.check);
    if (recordDigest(bytes) !== match[2]) fail('capture_changed');
    account(bytes, inventory, header, batch, counts);
    captures.push({ batch, path, sha256: match[2] });
    life.check(); await directory(root, identity);
  }
  const selected = { root, identity, header, inventory, total, captures, counts, sources: null, ownerPresent: files.includes('capture.owner') };
  if (selected.ownerPresent) await directory(join(root, 'capture.owner'));
  if (files.includes('sources.json')) {
    const bytes = await read(join(root, 'sources.json'), SOURCES_LIMIT, life.check);
    if (captures.length !== total || !bytes.equals(encode(sourceSelection(selected)))) fail('sources_changed');
    selected.sources = { path: join(root, 'sources.json'), sha256: recordDigest(bytes) };
  }
  life.check(); await directory(root, identity); return selected;
}
async function owner(root, identity) {
  await directory(root, identity);
  const path = join(root, 'capture.owner'); await mkdir(path, { mode: 0o700 });
  const lockId = await directory(path); await syncDirectory(root);
  return async () => {
    await directory(root, identity); await directory(path, lockId);
    await rmdir(path); await syncDirectory(root);
  };
}
function summary(o, selected, stats = { requests: 0, read_bytes: 0, source_retries: 0 }, captured = 0) {
  return { type: 'github_issue_migration_capture', schema_version: 1, operation: o.operation,
    workdir: o.workdir, session_sha256: o.confirm, inventory_sha256: selected.header.inventory_sha256,
    source: selected.inventory.source, total_batches: selected.total, captured_batches: selected.captures.length,
    newly_captured_batches: captured, next_batch: selected.captures.length < selected.total ? selected.captures.length + 1 : null,
    capture_bytes: selected.counts.bytes, steps: selected.counts.steps, sources: selected.sources,
    complete: selected.sources !== null, owner_present_at_read: selected.ownerPresent,
    network_accessed: stats.requests > 0, ...stats, native_mutation_submitted: false,
    source_authenticity_proved: false, atomic_snapshot: false };
}

export async function captureGithubIssueMigration(raw) {
  const o = options(raw), life = lifetime(o);
  let selected, session, release, result, failure, captured = 0;
  try {
    if (o.operation === 'start') o.confirm = await initialize(o, life);
    selected = await load(o, life);
    if (o.operation === 'status') return summary(o, selected);
    release = await owner(selected.root, selected.identity);
    // Re-read under ownership: no stale prefix can authorize recapturing a batch.
    selected = await load(o, life);
    if (!selected.sources) {
      if (selected.captures.length < selected.total) {
        const credential = await token(o, selected.root, life.check);
        if (credential.fingerprint !== selected.header.credential_sha256) fail('source_credential_changed');
        session = createGithubIssueCaptureSession({ token: credential.value, signal: life.signal,
          timeoutMs: life.remaining(), maxReadBytes: o.maxReadBytes, maxRequests: o.maxRequests,
          maxSourceRetries: o.maxSourceRetries, fetchImpl: o.fetchImpl });
      }
      while (selected.captures.length < selected.total && captured < o.maxBatches) {
        life.check(); const batch = selected.captures.length + 1;
        const chosen = selectIssueInventoryBatch(selected.inventory, selected.header.inventory_sha256, batch);
        const capturedSource = await session.capture({ repository: chosen.source.repository, numbers: chosen.numbers,
          expectedSelection: { source: chosen.source, issues: chosen.issues } });
        await directory(selected.root, selected.identity); life.check();
        // Validate aggregate native-text/count constraints before any capture file.
        // A digest in its immutable filename commits each retained batch without
        // a mutable cursor or a second per-batch publication window.
        const counts = { ...selected.counts, comments: new Set(selected.counts.comments) };
        account(capturedSource.bytes, selected.inventory, selected.header, batch, counts);
        const path = join(selected.root, `capture-${String(batch).padStart(6, '0')}-${capturedSource.sha256}.json`);
        await saveOperatorRecord(path, capturedSource.bytes, life.check);
        await directory(selected.root, selected.identity);
        selected.captures.push({ batch, path, sha256: capturedSource.sha256 }); selected.counts = counts; captured++;
      }
      if (selected.captures.length === selected.total) {
        // All saved bytes are verified again before the complete handoff appears.
        selected = await load(o, life);
        await directory(selected.root, selected.identity); life.check();
        const saved = await saveOperatorRecord(join(selected.root, 'sources.json'), encode(sourceSelection(selected)), life.check);
        selected.sources = { path: saved.path, sha256: saved.sha256 };
      }
    }
    result = summary(o, selected, session?.statistics(), captured);
  } catch (cause) { failure = cause instanceof Error ? cause : operatorError('github_capture_migration_failed'); }
  finally {
    session?.close();
    if (release && failure?.code !== 'github_import_source_cleanup') {
      try { await release(); } catch (error) { failure ??= error; }
    }
    life.close();
  }
  if (failure) {
    failure.capture_progress = selected ? summary(o, selected, session?.statistics(), captured)
      : { workdir: o.workdir, session_sha256: o.confirm ?? null, native_mutation_submitted: false, preserve_custody: true };
    throw failure;
  }
  return result;
}
