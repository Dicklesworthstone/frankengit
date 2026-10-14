// Acquire an inspectable, snapshot-pinned native candidate without publication.
// Reuse complete browser protocol validators; do not implement another Git
// planner, bundle decoder, diff algorithm, review gate or authority model.
import { createHash, webcrypto } from 'node:crypto';
import { performance } from 'node:perf_hooks';
import { decimal, integer, principal, format, text, snapshot, showReply, reviewsReply, subject, matchSubject, pinned,
  form, oid, utf8 } from '../../crates/fgit-node/src/smart_http/server/browser/pulls-core.mjs';
import { preparationCommand, preparationReply, inspectionReply, multipart, makeBoundary, findBytes,
  METADATA_LIMIT, PREPARATION_LIMIT, BUNDLE_LIMIT } from '../../crates/fgit-node/src/smart_http/server/browser/pulls-candidate.mjs';
import { CandidateError, candidateFail, candidateKeys, candidateEndpoint, candidateToken, candidateJson,
  candidateRequest, CANDIDATE_IO_LIMITS } from './pull_candidate_io.mjs';
import { resolutionUpload, verifyResolutionResult, RESOLUTION_FILE_LIMIT } from '../../crates/fgit-node/src/smart_http/server/browser/pulls-resolution.mjs';
export { CandidateError, candidateJson, CANDIDATE_IO_LIMITS } from './pull_candidate_io.mjs';
export const CANDIDATE_CAPTURE_SCHEMA = 'frankengit-pull-candidate-capture-v1';
export const RESOLVED_CAPTURE_SCHEMA = 'frankengit-pull-resolved-candidate-capture-v1';
// Includes raw path bytes. Hex retention has its own enclosing capture limit.
export const RESOLUTION_CHOICE_BYTES = 4 * 1024 * 1024;
export function candidateResolutionChoices(input) {
  if (!Array.isArray(input) || !input.length || input.length > 128) candidateFail('invalid_candidate_resolution_choices');
  let bytes = 0;
  const choices = Array.from(input, value => {
    const file = value?.choice === 'file';
    candidateKeys(value, ['path_hex', 'choice', ...(file ? ['mode', 'content_hex'] : [])]);
    if (typeof value.path_hex !== 'string' || !value.path_hex.length || value.path_hex.length > 8192 ||
        value.path_hex.length % 2 || !/^[0-9a-f]+$/.test(value.path_hex) ||
        !['base', 'ours', 'theirs', 'delete', 'file'].includes(value.choice)) candidateFail('invalid_candidate_resolution_choice');
    const result = { path_hex: value.path_hex, choice: value.choice };
    bytes += value.path_hex.length / 2;
    if (file) {
      if (!['100644', '100755'].includes(value.mode) || typeof value.content_hex !== 'string' ||
          value.content_hex.length > 2 * RESOLUTION_FILE_LIMIT || value.content_hex.length % 2 ||
          !/^[0-9a-f]*$/.test(value.content_hex)) candidateFail('invalid_candidate_resolution_file');
      bytes += value.content_hex.length / 2;
      result.mode = value.mode; result.content_hex = value.content_hex;
    }
    if (bytes > RESOLUTION_CHOICE_BYTES) candidateFail('candidate_resolution_content_limit');
    return result;
  }).sort((a, b) => a.path_hex < b.path_hex ? -1 : a.path_hex > b.path_hex ? 1 : 0);
  if (choices.some((row, i) => i && row.path_hex === choices[i - 1].path_hex)) candidateFail('duplicate_candidate_resolution_path');
  return choices;
}
function resolutionFiles(choices) {
  return choices.map(({ content_hex, ...row }) => content_hex === undefined ? row
    : { ...row, bytes: new Uint8Array(Buffer.from(content_hex, 'hex')) });
}
export const candidateHash = bytes => createHash('sha256').update(bytes).digest('hex');
export const candidateCanonical = value => `${JSON.stringify(value, null, 2).replace(
  /[\u007f-\u009f\u061c\u200e\u200f\u2028-\u202e\u2066-\u2069]/gu,
  c => `\\u${c.codePointAt(0).toString(16).padStart(4, '0')}`)}\n`;
function scope(value) {
  candidateKeys(value, ['tenant_id', 'repository_id', 'repository_incarnation', 'object_format']);
  return { tenant_id: principal(value.tenant_id), repository_id: principal(value.repository_id),
    repository_incarnation: principal(value.repository_incarnation), object_format: format(value.object_format) };
}
const sharedScope = value => ({ tenant: value.tenant_id, repository: value.repository_id, incarnation: value.repository_incarnation, format: value.object_format });
export function candidateInput(value) {
  candidateKeys(value, ['endpoint', 'scope', 'number', 'metadata', 'method', 'expected_head'],
    ['endpoint', 'scope', 'number', 'metadata', 'method']);
  const endpoint = candidateEndpoint(value.endpoint), selected = scope(value.scope);
  const number = String(decimal(value.number, 'candidate PR number', 1));
  candidateKeys(value.metadata, ['author', 'committer', 'timestamp', 'message']);
  const metadata = {};
  for (const name of ['author', 'committer']) {
    metadata[name] = text(value.metadata[name], 1024, name, true);
    const match = /^([^<>\r\n]+) <([^<>\r\n]+)>$/.exec(metadata[name]);
    if (!match || !match[1].trim()) candidateFail('invalid_candidate_commit_identity');
  }
  metadata.timestamp = String(decimal(value.metadata.timestamp, 'candidate timestamp', 1));
  metadata.message = text(value.metadata.message, 64 * 1024, 'candidate message');
  if (!metadata.message.trim() || !['merge-commit', 'squash'].includes(value.method)) candidateFail('invalid_candidate_metadata_or_method');
  const expected_head = value.expected_head == null ? null : snapshot(value.expected_head);
  return { endpoint, scope: selected, number, metadata, method: value.method, expected_head };
}
function discovery(request, pull, pages, complete = true) {
  const number = Number(request.number), binding = sharedScope(request.scope);
  const selected = showReply(pull, number, { head: request.expected_head, scope: binding }), row = selected.reply.pull_request;
  if (!pull.found || row?.state !== 'open' || !row.data) candidateFail('candidate_requires_open_pull_request');
  // Byte-only refs remain valid readable PR data, but the native preparation
  // form is UTF-8. Never replacement-decode them or select a different branch.
  if (row.data.source_ref === null || row.data.target_ref === null) candidateFail('candidate_requires_utf8_branch_form');
  if (!Array.isArray(pages) || !pages.length || pages.length > CANDIDATE_IO_LIMITS.reviewPages) candidateFail('candidate_review_page_limit');
  let after = null, epoch = null;
  const reviews = [];
  for (let index = 0; index < pages.length; index++) {
    const page = pages[index];
    reviewsReply(page, number, { after, limit: CANDIDATE_IO_LIMITS.reviewPageSize, head: selected.head, scope: binding });
    if (!page.found || page.source_head !== pull.source_head || page.pull_request_version !== row.version ||
        (epoch !== null && epoch !== page.policy_epoch)) candidateFail('candidate_discovery_snapshot_changed');
    epoch = page.policy_epoch;
    reviews.push(...page.reviews);
    after = page.next_after;
    if (after === null && index !== pages.length - 1) candidateFail('candidate_reviews_after_completion');
  }
  if (complete && after !== null) candidateFail('candidate_review_page_limit');
  const fields = subject({ object_format: request.scope.object_format, pull_request_version: row.version, policy_epoch: epoch,
    source_ref: row.data.source_ref, target_ref: row.data.target_ref,
    source_tip: oid(row.data.source_tip, binding.format), target_tip: oid(row.data.target_tip, binding.format) });
  for (const review of reviews) if (review.freshness === 'current') matchSubject(review.subject, fields, number, binding.format);
  return { binding, head: selected.head, fields, reviews, after };
}
function metadataFor(request) { return { ...request.metadata, timestamp: Number(request.metadata.timestamp) }; }
function sameHead(reply, observed, request) {
  pinned(reply, sharedScope(request.scope), observed.snapshot_token);
  if (reply.source_head !== observed.source_head) candidateFail('candidate_snapshot_changed');
}
function strictPreparation(response) {
  if (/^application\/json(?:\s*;|$)/i.test(response.type)) return candidateJson(response.value, METADATA_LIMIT);
  // Locate only the JSON part for strict duplicate/numeric intake checks. The
  // existing preparationReply remains the complete binary/MIME validator.
  const match = /^multipart\/mixed; boundary=(fg-prepare-[0-9a-f]{48}-[0-9a-f])$/.exec(response.type);
  if (!match) candidateFail('invalid_candidate_mime');
  const bytes = response.value, start = findBytes(bytes, utf8.encode('\r\n\r\n'), 0, Math.min(bytes.length, 1024));
  if (start < 0) candidateFail('invalid_candidate_mime');
  const end = findBytes(bytes, utf8.encode(`\r\n--${match[1]}\r\n`), start + 4,
    Math.min(bytes.length, start + 4 + METADATA_LIMIT + 100));
  if (end < 0) candidateFail('invalid_candidate_mime');
  return candidateJson(bytes.subarray(start + 4, end), METADATA_LIMIT);
}
function boundedCapture(capture) {
  const bytes = Buffer.from(candidateCanonical(capture));
  if (bytes.length > CANDIDATE_IO_LIMITS.capture) candidateFail('candidate_capture_limit');
  return candidateJson(bytes, CANDIDATE_IO_LIMITS.capture);
}
// Reconstruct only MIME framing around retained native metadata and bytes for
// offline revalidation by the SAME parser. This is not a fabricated new server
// observation. The capture digest binds retained reports; authority is still remote.
function retainedPreparation(metadata, bundle, status) {
  const bytes = Buffer.from(JSON.stringify(metadata));
  if (bytes.length > METADATA_LIMIT) candidateFail('candidate_metadata_limit');
  if (bundle === null) return { status, type: 'application/json', value: bytes };
  if (!(bundle instanceof Uint8Array) || !bundle.length || bundle.length > BUNDLE_LIMIT) candidateFail('candidate_bundle_limit');
  const digest = candidateHash(bundle).slice(0, 48);
  for (let attempt = 0; attempt < 16; attempt++) {
    const boundary = `fg-prepare-${digest}-${attempt.toString(16)}`, marker = Buffer.from(`--${boundary}`);
    if (bytes.includes(marker) || Buffer.from(bundle.buffer, bundle.byteOffset, bundle.byteLength).includes(marker)) continue;
    return { status, type: `multipart/mixed; boundary=${boundary}`, value: Buffer.concat([
      Buffer.from(`--${boundary}\r\nContent-Type: application/json; charset=utf-8\r\nContent-Disposition: inline; name="metadata"\r\n\r\n`), bytes,
      Buffer.from(`\r\n--${boundary}\r\nContent-Type: application/x-git-bundle\r\nContent-Disposition: attachment; name="bundle"; filename="candidate.bundle"\r\n\r\n`),
      Buffer.from(bundle), Buffer.from(`\r\n--${boundary}--\r\n`),
    ]) };
  }
  candidateFail('candidate_boundary_collision');
}
function checkPreparationShape(metadata) {
  candidateKeys(metadata, ['type', 'schema_version', 'tenant_id', 'repository_id', 'repository_incarnation', 'object_format',
    'source_head', 'snapshot_token', 'profile', 'method', 'read_only', 'objects_staged', 'transaction_created', 'published',
    'merge_authorized', 'subject', 'state', 'candidate', 'bundle', 'conflicts', ...(metadata.state === 'conflicted' ? ['merge_base'] : []),
    ...(metadata.state === 'resolved' ? ['resolution_profile', 'resolutions'] : [])]);
  if (['clean', 'resolved'].includes(metadata.state)) {
    candidateKeys(metadata.candidate, ['merge_base', 'commit', 'tree', 'new_object_count']);
    candidateKeys(metadata.bundle, ['bytes', 'sha256']);
    integer(metadata.candidate.new_object_count, 'candidate objects', 1, 10000);
  }
}
export async function validateCandidateCapture(input, suppliedBundle = null) {
  try {
    const resolved = input?.schema === RESOLVED_CAPTURE_SCHEMA;
    candidateKeys(input, ['schema', 'request', 'pull', 'review_pages', 'preparation_status', 'preparation', 'inspection',
      ...(resolved ? ['resolution'] : [])]);
    const capture = boundedCapture(input), request = candidateInput(capture.request);
    if ((!resolved && capture.schema !== CANDIDATE_CAPTURE_SCHEMA) || JSON.stringify(request) !== JSON.stringify(capture.request)) candidateFail('invalid_candidate_capture');
    // Copy before the first async digest: caller edits cannot change validation.
    if (suppliedBundle !== null && (!(suppliedBundle instanceof Uint8Array) || suppliedBundle.length > BUNDLE_LIMIT)) candidateFail('candidate_bundle_limit');
    const bundle = suppliedBundle === null ? null : Buffer.from(suppliedBundle);
    const observed = discovery(request, capture.pull, capture.review_pages);
    let resolution = null;
    if (resolved) {
      candidateKeys(capture.resolution, ['preparation', 'choices']);
      if (capture.resolution.preparation?.state !== 'conflicted') candidateFail('original_candidate_conflicts_required');
      const choices = candidateResolutionChoices(capture.resolution.choices);
      if (JSON.stringify(choices) !== JSON.stringify(capture.resolution.choices)) candidateFail('noncanonical_candidate_resolution_choices');
      // Revalidate the original conflict observation using the unchanged v1 path.
      // It cannot contain another resolution or a nested chain of prior captures.
      await validateCandidateCapture({ schema: CANDIDATE_CAPTURE_SCHEMA, request, pull: capture.pull,
        review_pages: capture.review_pages, preparation_status: 409,
        preparation: capture.resolution.preparation, inspection: null });
      resolution = await resolutionUpload(capture.resolution.preparation, observed.fields, metadataFor(request),
        resolutionFiles(choices), webcrypto, request.method);
    }
    checkPreparationShape(capture.preparation);
    const prepared = await preparationReply(retainedPreparation(capture.preparation, bundle, capture.preparation_status), Number(request.number),
      observed.fields, observed.binding, webcrypto, resolved, request.method);
    sameHead(prepared.metadata, capture.pull, request);
    if (resolution) verifyResolutionResult(prepared.metadata, resolution.expected);
    if (prepared.artifact === null) {
      if (bundle !== null || capture.inspection !== null) candidateFail('candidate_material_without_candidate');
    } else {
      candidateKeys(capture.inspection, ['type', 'schema_version', 'tenant_id', 'repository_id', 'repository_incarnation', 'object_format',
        'source_head', 'snapshot_token', 'read_only', 'objects_staged', 'transaction_created', 'published', 'merge_authorized',
        'all_changed_paths', 'binary_bodies_included', 'comparison_profile', 'context_lines', 'subject', 'merge_base',
        'candidate_commit', 'parents', 'prerequisites', 'candidate_commit_body_hex', 'bundle', 'comparison']);
      await inspectionReply(capture.inspection, prepared.artifact, webcrypto);
      sameHead(capture.inspection, capture.pull, request);
      if (oid(capture.inspection.comparison.after_tree, observed.binding.format) !== oid(prepared.metadata.candidate.tree, observed.binding.format)) {
        candidateFail('candidate_tree_report_changed');
      }
    }
    return { capture, bundle, artifact: prepared.artifact, reviews: observed.reviews };
  } catch (error) { if (error instanceof CandidateError) throw error; candidateFail('invalid_candidate_capture'); }
}
export async function capturePullCandidate(input, token, options = {}) {
  let phase = 'validation';
  try {
    const request = candidateInput(input); candidateToken(token);
    candidateKeys(options, ['timeoutMs', 'signal', 'ca', 'maxWireBytes', 'maxReviewPages'], []);
    const timeout = integer(options.timeoutMs ?? 30000, 'candidate timeout', 1, 300000), signal = options.signal;
    if (signal !== undefined && !(signal instanceof AbortSignal)) candidateFail('invalid_candidate_signal');
    const ca = options.ca === undefined ? undefined : Buffer.isBuffer(options.ca) && options.ca.length > 0 && options.ca.length <= 128 * 1024
      ? Buffer.from(options.ca) : candidateFail('invalid_candidate_ca');
    const maxWire = integer(options.maxWireBytes ?? CANDIDATE_IO_LIMITS.wire, 'candidate total response bytes', 1, CANDIDATE_IO_LIMITS.wire);
    const maxPages = integer(options.maxReviewPages ?? CANDIDATE_IO_LIMITS.reviewPages, 'candidate review pages', 1, CANDIDATE_IO_LIMITS.reviewPages);
    const deadline = performance.now() + timeout; let wire = 0, requests = 0;
    const checkpoint = () => {
      if (signal?.aborted) candidateFail('candidate_cancelled');
      const remaining = Math.ceil(deadline - performance.now());
      if (remaining <= 0) candidateFail('candidate_timeout');
      return remaining;
    };
    const exchange = async operation => {
      const remaining = checkpoint();
      if (wire >= maxWire) candidateFail('candidate_wire_budget');
      requests++;
      const result = await candidateRequest(request.endpoint, token, operation,
        { timeoutMs: remaining, signal, ca, maximum: Math.min(PREPARATION_LIMIT, maxWire - wire) });
      wire += result.value.length; checkpoint(); return result;
    };
    phase = 'discovery';
    const number = Number(request.number);
    const shown = await exchange({ kind: 'show', number, head: request.expected_head });
    const pull = candidateJson(shown.value);
    const selected = showReply(pull, number, { head: request.expected_head, scope: sharedScope(request.scope) });
    if (shown.status !== 200 || !pull.found || pull.pull_request?.state !== 'open') candidateFail('candidate_requires_open_pull_request');
    const pages = []; let observed;
    do {
      if (pages.length === maxPages) candidateFail('candidate_review_page_limit');
      const response = await exchange({ kind: 'reviews', number, head: selected.head, after: observed?.after ?? null });
      if (response.status !== 200) candidateFail('candidate_reviews_unavailable');
      pages.push(candidateJson(response.value)); observed = discovery(request, pull, pages, false);
    } while (observed.after !== null);
    phase = 'preparation';
    const command = preparationCommand(observed.fields, metadataFor(request), request.method);
    // Explicit method and profile: never rely on a server default changing.
    const response = await exchange({ kind: 'prepare', number, body: form({ ...command, method: request.method, profile: 'path-merge-v1' }) });
    const metadata = strictPreparation(response); checkPreparationShape(metadata);
    const prepared = await preparationReply(response, number, observed.fields, observed.binding, webcrypto, false, request.method);
    checkpoint(); sameHead(metadata, pull, request);
    let inspection = null;
    if (prepared.artifact) {
      phase = 'inspection';
      const command = form(prepared.artifact.fields);
      const upload = multipart(command, prepared.artifact.bundle, makeBoundary(command, prepared.artifact.bundle, webcrypto));
      const response = await exchange({ kind: 'inspect', number, body: upload.bytes, type: upload.contentType });
      inspection = candidateJson(response.value);
      await inspectionReply(inspection, prepared.artifact, webcrypto); checkpoint(); sameHead(inspection, pull, request);
    }
    phase = 'validation';
    const capture = { schema: CANDIDATE_CAPTURE_SCHEMA, request, pull, review_pages: pages,
      preparation_status: response.status, preparation: metadata, inspection };
    const checked = await validateCandidateCapture(capture, prepared.artifact?.bundle ?? null); checkpoint();
    return { capture: checked.capture, bundle: checked.bundle, usage: { requests, response_bytes: wire } };
  } catch (error) {
    throw new CandidateError(error instanceof CandidateError ? error.code : 'candidate_validation_failed',
      { phase, status: error instanceof CandidateError ? error.status : null });
  }
}

// Resolve one retained conflict set. This is a read-side construction operation:
// publication still requires a separate inspected-candidate command and consent.
export async function resolvePullCandidate(input, inputChoices, token, options = {}) {
  let phase = 'validation';
  try {
    candidateToken(token);
    candidateKeys(options, ['timeoutMs', 'signal', 'ca', 'maxWireBytes'], []);
    const timeout = integer(options.timeoutMs ?? 30000, 'resolution timeout', 1, 300000), signal = options.signal;
    if (signal !== undefined && !(signal instanceof AbortSignal)) candidateFail('invalid_candidate_signal');
    const ca = options.ca === undefined ? undefined : Buffer.isBuffer(options.ca) && options.ca.length > 0 && options.ca.length <= 128 * 1024
      ? Buffer.from(options.ca) : candidateFail('invalid_candidate_ca');
    const maxWire = integer(options.maxWireBytes ?? CANDIDATE_IO_LIMITS.wire, 'resolution response bytes', 1, CANDIDATE_IO_LIMITS.wire);
    const deadline = performance.now() + timeout;
    const checkpoint = () => {
      if (signal?.aborted) candidateFail('candidate_cancelled');
      const remaining = Math.ceil(deadline - performance.now());
      if (remaining <= 0) candidateFail('candidate_timeout');
      return remaining;
    };
    checkpoint();
    // Detach JSON choices and the complete original view before the first await.
    const choices = candidateResolutionChoices(inputChoices);
    const checked = await validateCandidateCapture(input); checkpoint();
    const original = checked.capture, request = original.request;
    if (original.schema !== CANDIDATE_CAPTURE_SCHEMA || original.preparation.state !== 'conflicted') candidateFail('original_candidate_conflicts_required');
    const observed = discovery(request, original.pull, original.review_pages);
    const selected = await resolutionUpload(original.preparation, observed.fields, metadataFor(request),
      resolutionFiles(choices), webcrypto, request.method); checkpoint();
    let wire = 0, requests = 0;
    const exchange = async operation => {
      const remaining = checkpoint();
      if (wire >= maxWire) candidateFail('candidate_wire_budget');
      requests++;
      const result = await candidateRequest(request.endpoint, token, operation,
        { timeoutMs: remaining, signal, ca, maximum: Math.min(PREPARATION_LIMIT, maxWire - wire) });
      wire += result.value.length; checkpoint(); return result;
    };
    phase = 'resolution';
    const response = await exchange({ kind: 'resolve', number: Number(request.number), body: selected.bytes, type: selected.contentType });
    const metadata = strictPreparation(response); checkPreparationShape(metadata);
    const prepared = await preparationReply(response, Number(request.number), observed.fields, observed.binding, webcrypto, true, request.method);
    checkpoint(); sameHead(metadata, original.pull, request); verifyResolutionResult(metadata, selected.expected);
    phase = 'inspection';
    const command = form(prepared.artifact.fields);
    const upload = multipart(command, prepared.artifact.bundle, makeBoundary(command, prepared.artifact.bundle, webcrypto));
    const inspected = await exchange({ kind: 'inspect', number: Number(request.number), body: upload.bytes, type: upload.contentType });
    const inspection = candidateJson(inspected.value);
    phase = 'validation';
    const capture = { schema: RESOLVED_CAPTURE_SCHEMA, request, pull: original.pull, review_pages: original.review_pages,
      preparation_status: response.status, preparation: metadata, inspection,
      resolution: { preparation: original.preparation, choices } };
    const result = await validateCandidateCapture(capture, prepared.artifact.bundle); checkpoint();
    return { capture: result.capture, bundle: result.bundle, usage: { requests, response_bytes: wire } };
  } catch (error) {
    throw new CandidateError(error instanceof CandidateError ? error.code : 'candidate_resolution_failed',
      { phase, status: error instanceof CandidateError ? error.status : null });
  }
}
