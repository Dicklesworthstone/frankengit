// FG-049 destination execution through the shipped issue operator. This private
// journal is retry custody, never forge authority or a substitute issue store.
import { constants } from 'node:fs';
import { open, lstat, mkdir, realpath, unlink } from 'node:fs/promises';
import { dirname, basename, join } from 'node:path';
import { IssueClient, mutationRequest, natural, MAX_RECEIPT_BYTES } from '../../crates/fgit-node/src/smart_http/server/browser/issues.mjs';
import { issueConnectionOptions, connectIssueToken, runIssueOperation } from './forge-issue-operator.mjs';
import { parseCapture, issueImportSteps, CAPTURE_LIMIT } from './github-issue-source.mjs';
import { operatorError, operatorPath, privateRecordPath, readPrivateOperatorFile,
  readSynchronizedOperatorRecord, saveOperatorRecord, recordDigest } from './forge-operator-io.mjs';

const SCHEMA = 'frankengit-github-issue-import-v1', LIMIT = 256 * 1024;
const RECORD_BYTES_LIMIT = 16 * 1024 * 1024;
const encode = value => Buffer.from(JSON.stringify(value) + '\n');
const fail = code => { throw operatorError(`github_import_${code}`); };
const hash = value => typeof value === 'string' && /^[0-9a-f]{64}$/.test(value);
const exact = (value, names) => value && typeof value === 'object' && !Array.isArray(value) &&
  Object.keys(value).length === names.length && names.every(name => Object.hasOwn(value, name));
function options(raw, preparing) {
  const allowed = ['workdir', 'href', 'tenant', 'repository', 'tokenFile', 'timeoutMs', 'signal', 'onProgress',
    ...(preparing ? ['captureFile', 'offset'] : ['operation', 'confirm', 'retryUnresolved', 'maxMutations'])];
  if (!raw || typeof raw !== 'object' || Array.isArray(raw) || Object.keys(raw).some(k => !allowed.includes(k))) fail('destination_options');
  const o = issueConnectionOptions({ ...raw, timeoutMs: raw.timeoutMs ?? 300000 });
  o.workdir = operatorPath(raw.workdir);
  if (preparing) {
    o.captureFile = operatorPath(raw.captureFile); o.offset = natural(raw.offset ?? 0, 'number offset');
  } else {
    if (!['run', 'status'].includes(o.operation) || !hash(o.confirm)) fail('confirmation_required');
    o.retryUnresolved = raw.retryUnresolved ?? false;
    if (typeof o.retryUnresolved !== 'boolean' || (o.operation === 'status' && o.retryUnresolved)) fail('explicit_retry_only');
    o.maxMutations = natural(raw.maxMutations ?? 100, 'mutation limit', 1, 2200);
  }
  return o;
}
function lifetime(o) {
  const stop = new AbortController(), signal = o.signal ? AbortSignal.any([o.signal, stop.signal]) : stop.signal;
  const timer = setTimeout(() => stop.abort(), o.timeoutMs);
  return { signal, check: () => signal.throwIfAborted(), close: () => { clearTimeout(timer); stop.abort(); } };
}
async function directory(path) {
  const stat = await lstat(path);
  if (typeof process.getuid !== 'function' || !stat.isDirectory() || stat.uid !== process.getuid() || (stat.mode & 0o077)) fail('private_workdir_required');
  return join(await realpath(dirname(path)), basename(path));
}
async function synchronizeDirectory(path) {
  const fd = await open(path, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
  try { await fd.sync(); } finally { await fd.close(); }
}
async function tokenFingerprint(path, check) {
  const bytes = await readPrivateOperatorFile(path, 65, check);
  try {
    const token = bytes.toString('ascii').replace(/\n$/, '');
    if (bytes.some(b => b > 127) || !/^[0-9a-f]{64}$/.test(token)) fail('native_token');
    return recordDigest(Buffer.from(token));
  } finally { bytes.fill(0); }
}
function canonical(bytes) {
  const value = JSON.parse(new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes));
  if (!encode(value).equals(bytes)) fail('journal_encoding');
  return value;
}
async function optional(path, maximum, check) {
  try { return await readPrivateOperatorFile(path, maximum, check); }
  catch (error) { if (error.code === 'ENOENT') return null; throw error; }
}
async function saveExact(path, bytes) {
  try { await saveOperatorRecord(path, bytes); }
  catch (error) {
    if (error.code !== 'EEXIST') throw error;
    const current = await readSynchronizedOperatorRecord(path, LIMIT);
    if (!current.equals(bytes)) fail('observation_conflict');
  }
}
export async function prepareGithubIssueImport(raw) {
  const o = options(raw, true), life = lifetime(o);
  try {
    const bytes = await readPrivateOperatorFile(o.captureFile, CAPTURE_LIMIT, life.check);
    const source = parseCapture(bytes), steps = issueImportSteps(source, o.offset);
    const fingerprint = await tokenFingerprint(o.tokenFile, life.check);
    const workdir = await privateRecordPath(o.workdir); life.check();
    // The new directory is the create-only arbitration point. Partial preparation
    // is retained; no reader can run it until the final manifest has synced.
    await mkdir(workdir, { mode: 0o700 }); await synchronizeDirectory(dirname(workdir));
    await saveOperatorRecord(join(workdir, 'capture.json'), bytes, life.check);
    const requests = []; let requestBytes = 0;
    for (const [index, step] of steps.entries()) {
      life.check();
      const client = new IssueClient({ href: o.href, timeoutMs: o.timeoutMs });
      try {
        await connectIssueToken(client, o, life.check);
        await client.stage(step.number, step.expected_version, step.action, step.fields,
          { tenant: o.tenant, repository: o.repository });
        const exported = client.exportReceipt();
        if (Buffer.byteLength(exported) > MAX_RECEIPT_BYTES) fail('receipt_limit');
        const receipt = JSON.parse(exported);
        if (receipt.request.credential_fingerprint !== fingerprint) fail('native_credential_changed');
        const record = encode({ schema: 'frankengit-issue-operator-v1', href: o.href,
          tenant: o.tenant, repository: o.repository, receipt });
        requestBytes += record.length;
        if (requestBytes > RECORD_BYTES_LIMIT) fail('request_byte_limit');
        const saved = await saveOperatorRecord(join(workdir, `step-${String(index).padStart(6, '0')}.request.json`), record, life.check);
        requests.push(saved.sha256);
      } finally { client.disconnect(); }
    }
    const manifest = { schema: SCHEMA, href: o.href, tenant: o.tenant, repository: o.repository,
      credential_fingerprint: fingerprint, source_sha256: recordDigest(bytes),
      steps_sha256: recordDigest(encode(steps)), offset: o.offset, step_count: steps.length,
      request_sha256: requests, request_bytes: requestBytes };
    const saved = await saveOperatorRecord(join(workdir, 'manifest.json'), encode(manifest), life.check);
    return { type: 'github_issue_import_prepared', workdir, plan_sha256: saved.sha256,
      source: source.source, steps: steps.length, mapping: source.issues.map(issue => ({ source: issue.number, target: issue.number + o.offset })),
      mutation_submitted: false, atomic_batch: false };
  } finally { life.close(); }
}
async function load(o, check) {
  const root = await directory(o.workdir);
  const bytes = await readSynchronizedOperatorRecord(join(root, 'manifest.json'), LIMIT, check);
  const digest = recordDigest(bytes), m = canonical(bytes);
  if (digest !== o.confirm || !exact(m, ['schema', 'href', 'tenant', 'repository', 'credential_fingerprint',
    'source_sha256', 'steps_sha256', 'offset', 'step_count', 'request_sha256', 'request_bytes']) || m.schema !== SCHEMA ||
    m.href !== o.href || m.tenant !== o.tenant || m.repository !== o.repository ||
    !hash(m.credential_fingerprint) || !hash(m.source_sha256) || !hash(m.steps_sha256)) fail('plan_mismatch');
  const sourceBytes = await readPrivateOperatorFile(join(root, 'capture.json'), CAPTURE_LIMIT, check);
  if (recordDigest(sourceBytes) !== m.source_sha256) fail('source_package_changed');
  const capture = parseCapture(sourceBytes), steps = issueImportSteps(capture, m.offset);
  if (steps.length !== m.step_count || recordDigest(encode(steps)) !== m.steps_sha256 ||
      !Array.isArray(m.request_sha256) || m.request_sha256.length !== steps.length ||
      m.request_sha256.some(value => !hash(value)) || !Number.isSafeInteger(m.request_bytes) ||
      m.request_bytes < 1 || m.request_bytes > RECORD_BYTES_LIMIT) fail('step_plan_changed');
  if (await tokenFingerprint(o.tokenFile, check) !== m.credential_fingerprint) fail('original_native_credential_required');
  const selected = { root, digest, manifest: m, capture, steps }; let total = 0;
  // Validate the complete immutable request set before the first network call.
  // No missing or changed later request can be silently replaced after a prefix.
  for (const [index, step] of steps.entries()) {
    const record = await optional(join(root, `step-${String(index).padStart(6, '0')}.request.json`), MAX_RECEIPT_BYTES * 2, check);
    if (!record) fail('request_custody_incomplete');
    total += record.length;
    if (total > RECORD_BYTES_LIMIT || requestRecord(record, selected, step) !== m.request_sha256[index]) fail('prepared_request_changed');
  }
  if (total !== m.request_bytes) fail('request_byte_count');
  return selected;
}
async function senderLock(root, digest) {
  const path = join(root, 'sender.lock');
  let fd;
  try { fd = await open(path, constants.O_RDWR | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600); }
  catch (error) { if (error.code === 'EEXIST') fail('sender_lock_retained'); throw error; }
  let identity;
  try { identity = await fd.stat(); await fd.writeFile(encode({ plan_sha256: digest })); await fd.sync(); await synchronizeDirectory(root); }
  catch (error) { await fd.close(); throw error; } // Suspect lock remains blocking.
  return async () => {
    try {
      const current = await lstat(path);
      if (!current.isFile() || current.dev !== identity.dev || current.ino !== identity.ino) fail('sender_lock_changed');
      await unlink(path); await synchronizeDirectory(root);
    } finally { await fd.close(); }
  };
}
function requestRecord(bytes, selected, step) {
  const value = canonical(bytes), p = value.receipt?.request;
  const expected = mutationRequest(step.number, step.expected_version, step.action, step.fields);
  const m = selected.manifest;
  if (!exact(value, ['schema', 'href', 'tenant', 'repository', 'receipt']) || value.schema !== 'frankengit-issue-operator-v1' ||
      value.href !== m.href || value.tenant !== m.tenant || value.repository !== m.repository ||
      !p || p.number !== expected.number || p.expected_version !== expected.expected_version || p.action !== expected.action ||
      p.body !== expected.body || !encode(p.fields).equals(encode(expected.fields)) ||
      p.credential_fingerprint !== m.credential_fingerprint || !exact(p.binding, ['tenant', 'repository']) ||
      p.binding.tenant !== m.tenant || p.binding.repository !== m.repository) fail('request_plan_mismatch');
  // The existing operator additionally verifies the original receipt's key/body
  // commitment before any outcome query or resend. No parallel key codec here.
  return recordDigest(bytes);
}
function terminal(value) {
  if (!value || !['committed', 'refused'].includes(value.outcome) || typeof value.tx !== 'string' || !value.tx ||
      value.tx.length > 256 || (value.outcome === 'committed'
        ? typeof value.rcr !== 'string' || !value.rcr || value.refusal !== null
        : value.rcr !== null || typeof value.refusal !== 'string' || !value.refusal)) fail('invalid_terminal');
  return { outcome: value.outcome, tx: value.tx, rcr: value.rcr, refusal: value.refusal };
}
function decisionRecord(bytes, selected, index, requestDigest) {
  const value = canonical(bytes);
  if (!exact(value, ['schema', 'plan_sha256', 'index', 'request_sha256', 'result']) ||
      value.schema !== `${SCHEMA}/terminal` || value.plan_sha256 !== selected.digest ||
      value.index !== index || value.request_sha256 !== requestDigest ||
      !encode(value.result).equals(encode(terminal(value.result)))) fail('terminal_record_mismatch');
  return value;
}
export async function runGithubIssueImport(raw) {
  const o = options(raw, false), life = lifetime(o);
  let release = null, error = null, observedTerminal = null;
  const summary = { type: 'github_issue_import_progress', plan_sha256: o.confirm, operation: o.operation,
    committed_observed: 0, mutation_calls: 0, next_step: 0, complete: false, stop_reason: null,
    atomic_batch: false, absence_proves_non_commit: false };
  try {
    const selected = await load(o, life.check);
    summary.total_steps = selected.steps.length; summary.source = selected.capture.source;
    if (o.operation === 'run') release = await senderLock(selected.root, selected.digest);
    for (const [index, step] of selected.steps.entries()) {
      life.check(); observedTerminal = null; summary.next_step = index;
      const stem = join(selected.root, `step-${String(index).padStart(6, '0')}`);
      const record = `${stem}.request.json`, decision = `${stem}.terminal.json`, started = `${stem}.started.json`;
      const expectedStart = encode({ schema: `${SCHEMA}/started`, plan_sha256: selected.digest, index });
      const start = await optional(started, LIMIT, life.check), saved = await optional(record, MAX_RECEIPT_BYTES * 2, life.check);
      const known = await optional(decision, LIMIT, life.check);
      if (start && !start.equals(expectedStart)) fail('start_record_mismatch');
      if (!saved) fail('request_custody_incomplete');
      const requestDigest = requestRecord(saved, selected, step);
      if (requestDigest !== selected.manifest.request_sha256[index]) fail('prepared_request_changed');
      const retained = known ? decisionRecord(known, selected, index, requestDigest) : null;
      const invoke = operation => runIssueOperation({ operation, href: o.href, tenant: o.tenant,
        repository: o.repository, tokenFile: o.tokenFile, record, signal: life.signal, timeoutMs: o.timeoutMs });
      let result = await invoke('status');
      if (retained && (result.state !== 'terminal_observed' || !encode(terminal(result.result)).equals(encode(retained.result)))) fail('terminal_observation_regressed');
      if (result.state !== 'terminal_observed') {
        if (o.operation === 'status' || (start && !o.retryUnresolved)) {
          summary.stop_reason = start ? 'unresolved_original_request' : 'not_started_locally'; break;
        }
        if (summary.mutation_calls >= o.maxMutations) { summary.stop_reason = 'mutation_limit'; break; }
        life.check();
        // The exact key/body already belongs to the root-last prepared plan.
        // Mark local dispatch responsibility before asking the shipped operator
        // to query once more and, only if still undecided, send those bytes.
        if (!start) await saveOperatorRecord(started, expectedStart, life.check);
        summary.mutation_calls++;
        result = await invoke('retry');
      }
      if (result.state !== 'terminal_observed') { summary.stop_reason = 'unresolved_original_request'; break; }
      observedTerminal = { index, ...terminal(result.result) };
      // A parsed terminal survives later cancellation. Persist its identity and
      // original receipt hash before considering another mutation.
      const current = await readSynchronizedOperatorRecord(record, MAX_RECEIPT_BYTES * 2);
      const observedDigest = requestRecord(current, selected, step);
      if (result.record_sha256 !== observedDigest || (requestDigest !== null && requestDigest !== observedDigest)) fail('request_changed_after_observation');
      const entry = { schema: `${SCHEMA}/terminal`, plan_sha256: selected.digest, index,
        request_sha256: observedDigest, result: terminal(result.result) };
      await saveExact(decision, encode(entry));
      if (entry.result.outcome === 'refused') { summary.stop_reason = 'terminal_refusal'; summary.refusal = entry.result; break; }
      summary.committed_observed++; summary.next_step = index + 1;
      o.onProgress(Object.freeze({ index, number: step.number, action: step.action, outcome: 'committed', tx: entry.result.tx }));
    }
    summary.complete = summary.committed_observed === selected.steps.length;
    if (summary.complete) summary.stop_reason = 'all_committed';
  } catch (cause) { error = cause instanceof Error ? cause : operatorError('github_import_failed'); }
  finally {
    if (summary.total_steps !== undefined && summary.committed_observed === summary.total_steps) {
      summary.complete = true; summary.stop_reason = 'all_committed';
    }
    if (release) try { await release(); } catch (cleanup) { error ??= cleanup; }
    life.close();
  }
  if (error) {
    error.import_progress = { ...summary };
    if (observedTerminal) error.observed_terminal = observedTerminal;
    throw error;
  }
  return summary;
}
