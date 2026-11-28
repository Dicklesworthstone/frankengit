// Remote PR observations and exact canonical workflow evidence. This consumer
// grants no execution, review, merge, artifact-namespace or mutation authority.
import { PullClient } from '../../crates/fgit-node/src/smart_http/server/browser/pulls.mjs';
import { CheckEvidenceClient, CHECK_EVIDENCE_LIMIT } from '../../crates/fgit-node/src/smart_http/server/browser/pulls-check-evidence.mjs';
import { checkId } from '../../crates/fgit-node/src/smart_http/server/browser/pulls-checks.mjs';
import { integer, snapshot, format } from '../../crates/fgit-node/src/smart_http/server/browser/pulls-core.mjs';
import { connectIssueToken, issueOperatorFetch } from './forge-issue-operator.mjs';
import { operatorError, operatorJson, operatorPath, privateRecordPath, absentRecord, recordDigest } from './forge-operator-io.mjs';
import { publishArtifactStream } from '../operator/workflow_artifact_download.mjs';

const OUTPUT_LIMIT = 8 * 1024 * 1024;
const fail = code => { throw operatorError('forge_check_' + code); };
const disclosure = operation => operation === 'evidence' || operation === 'log';
const own = (value, fields) => Object.fromEntries(fields.filter(key => Object.hasOwn(value, key)).map(key => [key, value[key]]));
const digest = value => {
  if (typeof value !== 'string' || !/^[0-9a-f]{64}$/.test(value)) fail('evidence_digest');
  return value;
};

export function checkReadOptions(raw) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw) || !['list', 'show', 'checks', 'evidence', 'log'].includes(raw.operation)) fail('operation');
  const common = ['operation', 'href', 'tenant', 'repository', 'incarnation', 'objectFormat', 'tokenFile', 'timeoutMs', 'signal', 'onProgress', 'head', 'maxOutputBytes'];
  const page = ['after', 'limit', 'maxPages'];
  const evidence = ['evidenceTokenFile', 'checkId', 'expectedSha256', 'expectedBytes', 'output'];
  const allowed = [...common, ...(raw.operation === 'list' ? page : ['number']),
    ...(raw.operation === 'checks' || disclosure(raw.operation) ? page : []),
    ...(disclosure(raw.operation) ? evidence : []), ...(raw.operation === 'log' ? ['step', 'stream'] : [])];
  if (Object.keys(raw).some(key => !allowed.includes(key))) fail('options');
  const o = { ...raw, timeoutMs: raw.timeoutMs ?? 30000, onProgress: raw.onProgress ?? (() => {}) };
  for (const field of ['tenant', 'repository', ...(raw.incarnation === undefined ? [] : ['incarnation'])]) {
    if (typeof o[field] !== 'string' || !/^[0-9a-f]{32}$/.test(o[field])) fail('identity');
  }
  if (o.objectFormat !== undefined) format(o.objectFormat);
  if (typeof o.href !== 'string' || o.href.length > 4096 || /[\u0000-\u0020\u007f-\u009f\uD800-\uDFFF]/u.test(o.href) ||
      new URL(o.href).href !== o.href) fail('url');
  // The shipped client owns HTTPS/loopback, repository routes and URL authority.
  new PullClient({ href: o.href, timeoutMs: o.timeoutMs, pullReadOnly: true, sponsoredRead: true });
  if ((o.signal !== undefined && !(o.signal instanceof AbortSignal)) || typeof o.onProgress !== 'function') fail('lifetime');
  o.tokenFile = operatorPath(o.tokenFile);
  o.head = raw.head ?? null; if (o.head !== null) snapshot(o.head);
  o.maxOutputBytes = integer(raw.maxOutputBytes ?? OUTPUT_LIMIT, 'output budget', 1, OUTPUT_LIMIT);
  if (o.operation !== 'list') integer(o.number, 'PR number', 1);
  if (o.operation !== 'show') {
    o.limit = integer(raw.limit ?? (disclosure(o.operation) ? 100 : 20), 'page size', 1, 100);
    o.maxPages = integer(raw.maxPages ?? (disclosure(o.operation) ? 10 : 1), 'page budget', 1, 100);
    o.after = raw.after ?? (o.operation === 'list' ? 0 : null);
    if (o.operation === 'list') integer(o.after, 'PR cursor');
    else if (o.after !== null) checkId(o.after);
    if (o.after !== null && o.after !== 0 && o.head === null) fail('continuation_snapshot_required');
  }
  if (disclosure(o.operation)) {
    if (o.head === null || !/^alg:2:[0-9a-f]{64}$/.test(o.head)) fail('evidence_snapshot_required');
    checkId(o.checkId); digest(o.expectedSha256);
    o.expectedBytes = integer(o.expectedBytes, 'expected evidence bytes', 1, CHECK_EVIDENCE_LIMIT);
    o.evidenceTokenFile = operatorPath(o.evidenceTokenFile);
    if (o.output !== undefined) o.output = operatorPath(o.output);
    if (o.output === o.tokenFile || o.output === o.evidenceTokenFile) fail('separate_output_required');
    if (o.operation === 'log') {
      integer(o.step, 'step index', 0, 511);
      if (!['stdout', 'stderr'].includes(o.stream) || o.output === undefined) fail('log_selection');
    }
  }
  return o;
}

// Native decoders admit optional presentation extensions on PR metadata. Emit
// only checked fields; never forward rendered HTML or unvalidated server prose.
function pullRow(row) {
  if (row === null) return null;
  const result = own(row, ['number', 'version', 'state', 'opened_by', 'last_metadata_actor', 'merge_only', 'labels', 'labels_version', 'labels_actor']);
  result.data = row.data === null ? null : own(row.data, ['object_format', 'source_ref', 'source_ref_hex',
    'target_ref', 'target_ref_hex', 'source_tip', 'target_tip', 'title', 'body']);
  result.merge = row.merge === null ? null : own(row.merge, ['object_format', 'source_ref', 'source_ref_hex',
    'target_ref', 'target_ref_hex', 'source_tip', 'target_tip_before', 'base_tip', 'merge_commit']);
  return result;
}
function binding(selected, o) {
  const scope = selected.binding;
  if (scope.tenant !== o.tenant || scope.repository !== o.repository ||
      (o.incarnation !== undefined && scope.incarnation !== o.incarnation) ||
      (o.objectFormat !== undefined && scope.format !== o.objectFormat)) fail('repository_mismatch');
  return { tenant_id: scope.tenant, repository_id: scope.repository, repository_incarnation: scope.incarnation,
    object_format: scope.format, snapshot_token: selected.head, source_head: selected.reply.source_head };
}
function bounded(result, o) {
  if (Buffer.byteLength(operatorJson(result)) > o.maxOutputBytes) fail('output_limit');
  return result;
}
function base(o, selected) {
  return { type: 'forge_pull_check_read', schema_version: 1, operation: o.operation, href: o.href,
    ...binding(selected, o), read_only: true, mutation_submitted: false };
}
function continuation(o, head, next) {
  return next === null ? null : { operation: o.operation, expected_head: head, after: next, limit: o.limit,
    ...(o.operation === 'list' ? {} : { number: o.number }) };
}
function progress(o, life, phase, extra = {}) {
  o.onProgress(Object.freeze({ phase, ...extra })); life.check();
}

async function list(o, client, life) {
  const pages = []; let after = o.after, head = o.head, source = null, selected, next = null, bytes = 0;
  while (pages.length < o.maxPages) {
    selected = await client.list({ after, limit: o.limit, head }); life.check(); binding(selected, o);
    if (source !== null && selected.reply.source_head !== source) fail('source_head_changed');
    head = selected.head; source = selected.reply.source_head; next = selected.reply.next_after;
    const page = { after, limit: o.limit, pull_requests: selected.reply.pull_requests.map(pullRow), next_after: next };
    bytes += Buffer.byteLength(operatorJson(page)); if (bytes > o.maxOutputBytes) fail('output_limit');
    pages.push(page); progress(o, life, 'page_checked', { pages: pages.length, next_after: next });
    if (next === null) break;
    if (next <= after) fail('cursor_stalled');
    after = next;
  }
  return bounded({ ...base(o, selected), complete: next === null, stop_reason: next === null ? 'exhausted' : 'page_budget',
    initial_after: o.after, page_count: pages.length, continuation: continuation(o, head, next), pages }, o);
}

async function checks(o, client, selected, life, locate = false) {
  const pages = []; let after = o.after, next = null, bytes = 0, sourceCurrent = null;
  while (pages.length < o.maxPages) {
    const page = await client.checks(o.number, selected, { after, limit: o.limit }); life.check(); binding(page, o);
    // A disappeared subject after a successful show is a changed disclosure,
    // not a complete empty checks result for that earlier PR observation.
    if (!page.reply.found) fail('selected_subject_unavailable');
    if (sourceCurrent !== null && page.reply.source_current !== sourceCurrent) fail('source_state_changed');
    sourceCurrent = page.reply.source_current;
    next = page.reply.next_after;
    if (next !== null && after !== null && next <= after) fail('cursor_stalled');
    bytes += Buffer.byteLength(operatorJson(page.reply)); if (bytes > o.maxOutputBytes) fail('output_limit');
    pages.push(structuredClone(page.reply)); progress(o, life, 'page_checked', { pages: pages.length, next_after: next });
    if (locate) {
      const check = page.reply.checks.find(row => row.id === o.checkId);
      if (check) {
        if (check.evidence_sha256 !== o.expectedSha256 || check.evidence_bytes !== String(o.expectedBytes)) fail('evidence_pin_mismatch');
        return { page, check };
      }
      if (!page.reply.source_current || next === null || page.reply.checks.some(row => row.id > o.checkId)) fail('selected_check_unavailable');
    }
    if (next === null) break;
    after = next;
  }
  if (locate) fail('selection_page_budget');
  return bounded({ ...base(o, selected), number: o.number, found: true, pull_request: pullRow(selected.reply.pull_request),
    scope: 'trusted_workflow_observations', merge_permission: null, source_current: pages[0].source_current,
    complete: next === null, stop_reason: next === null ? 'exhausted' : 'page_budget', initial_after: o.after,
    page_count: pages.length, continuation: continuation(o, selected.head, next), pages }, o);
}

export async function runCheckRead(raw) {
  const o = checkReadOptions(raw), stop = new AbortController();
  const signal = o.signal ? AbortSignal.any([o.signal, stop.signal]) : stop.signal;
  const deadline = performance.now() + o.timeoutMs, timer = setTimeout(() => stop.abort(), o.timeoutMs);
  const life = { check() { if (signal.aborted || performance.now() >= deadline) fail('cancelled_or_deadline'); } };
  const options = { href: o.href, timeoutMs: o.timeoutMs, sponsoredRead: true,
    fetchImpl: (url, init) => issueOperatorFetch(url, init, signal) };
  const client = new PullClient({ ...options, pullReadOnly: true });
  let evidenceClient, exportAttempted = false, output = null, retainedBytes;
  try {
    life.check();
    if (o.output !== undefined) {
      output = await privateRecordPath(o.output); life.check();
      if (output === o.tokenFile || output === o.evidenceTokenFile) fail('separate_output_required');
      await absentRecord(output); life.check();
    }
    await connectIssueToken(client, o, life.check);
    if (o.operation === 'list') return await list(o, client, life);
    const selected = await client.show(o.number, o.head); life.check(); binding(selected, o);
    progress(o, life, 'subject_checked');
    if (o.operation === 'show' || !selected.reply.found) {
      if (disclosure(o.operation)) fail('selected_subject_unavailable');
      return bounded({ ...base(o, selected), number: o.number, found: selected.reply.found,
        pull_request: pullRow(selected.reply.pull_request), complete: true,
        ...(o.operation === 'checks' ? { source_current: null, scope: 'trusted_workflow_observations',
          merge_permission: null, pages: [], page_count: 0, continuation: null } : {}) }, o);
    }
    if (o.operation === 'checks') return await checks(o, client, selected, life);
    const prior = await checks(o, client, selected, life, true);
    // A separate explicit file selects evidence disclosure. Do not reuse the PR
    // credential automatically; native grants may be narrower than this reader.
    evidenceClient = new CheckEvidenceClient(options);
    await connectIssueToken(evidenceClient, { ...o, tokenFile: o.evidenceTokenFile }, life.check);
    const evidence = await evidenceClient.read(o.number, selected, prior.page, o.checkId); life.check();
    if (evidence.check.evidence_sha256 !== o.expectedSha256 || evidence.bytes.length !== o.expectedBytes) fail('evidence_pin_mismatch');
    retainedBytes = evidence.bytes;
    const result = { ...base(o, selected), number: o.number, found: true, pull_request: pullRow(selected.reply.pull_request),
      complete: true, scope: 'trusted_workflow_observations', merge_permission: null, check: evidence.check,
      evidence_matches_selected_check: true, independent_execution_verified: false };
    let bytes = evidence.bytes;
    if (o.operation === 'log') {
      const job = evidence.report?.jobs[0], step = job?.steps.find(row => row.index === o.step);
      if (!step) fail('retained_step_unavailable');
      bytes = Buffer.from(step[o.stream + '_hex'], 'hex');
      result.log = { step_index: o.step, stream: o.stream, job: job.id, observed_job_outcome: job.outcome,
        ...own(step, ['name', 'script', 'outcome', 'exit_code', 'output_complete', 'workspace_retained', 'continue_on_error', 'outcome_tolerated']) };
    } else result.report = evidence.report;
    if (output !== null) result.export = { output, kind: o.operation === 'log' ? 'step_stream' : 'canonical_evidence',
      payload_bytes: bytes.length, payload_sha256: recordDigest(bytes), executable_mode_applied: false };
    bounded(result, o); // Refuse a report envelope that cannot be delivered before creating a file.
    progress(o, life, 'evidence_verified');
    if (output !== null) {
      // The shared publisher stages only these already verified bytes, checks
      // their digest/length again, fsyncs, and links into a new name atomically.
      // It supports zero-byte streams and never overwrites or applies execute bits.
      exportAttempted = true;
      await publishArtifactStream(output, result.export, [Buffer.from(bytes)], life.check);
      // A completed file publication wins over a later cancellation. The CLI's
      // output owner may still fail, but it must never remove or replace the file.
    }
    return result;
  } catch (cause) {
    const error = cause instanceof Error ? cause : operatorError('forge_check_read_failed');
    error.output = output; error.output_may_exist = exportAttempted;
    throw error;
  } finally {
    retainedBytes?.fill(0); clearTimeout(timer); client.disconnect(); evidenceClient?.disconnect();
  }
}
