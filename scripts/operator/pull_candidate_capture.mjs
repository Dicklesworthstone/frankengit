// Acquire an inspectable, snapshot-pinned native candidate without publication.
// Reuse complete browser protocol validators; do not implement another Git
// planner, bundle decoder, diff algorithm, review gate or authority model.
import { createHash, webcrypto } from 'node:crypto';
import { performance } from 'node:perf_hooks';
import { decimal, integer, principal, format, text, snapshot, showReply, reviewsReply, subject, subjectReferences, matchSubject, pinned,
  form, oid, utf8 } from '../../crates/fgit-node/src/smart_http/server/browser/pulls-core.mjs';
import { preparationCommand, preparationReply, inspectionReply, multipart, makeBoundary, findBytes,
  METADATA_LIMIT, PREPARATION_LIMIT, BUNDLE_LIMIT } from '../../crates/fgit-node/src/smart_http/server/browser/pulls-candidate.mjs';
import { CandidateError, candidateFail, candidateKeys, candidateEndpoint, candidateToken, candidateJson,
  candidateRequest, CANDIDATE_IO_LIMITS } from './pull_candidate_io.mjs';
import { resolutionUpload, verifyResolutionResult, RESOLUTION_FILE_LIMIT } from '../../crates/fgit-node/src/smart_http/server/browser/pulls-resolution.mjs';
import { rebasePreparationCommand, rebasePreparationReply, rebaseInspectionReply } from '../../crates/fgit-node/src/smart_http/server/browser/pulls-rebase.mjs';
import { candidateCommitMatches, rebaseCommitterMatches } from './pull_candidate_commit.mjs';
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
  if (!['merge-commit', 'squash', 'rebase'].includes(value.method)) candidateFail('invalid_candidate_metadata_or_method');
  const rebase = value.method === 'rebase';
  candidateKeys(value.metadata, rebase ? ['upstream', 'committer', 'timestamp', 'empty'] : ['author', 'committer', 'timestamp', 'message']);
  const metadata = {};
  if (rebase) metadata.upstream = oid(value.metadata.upstream, selected.object_format);
  for (const name of rebase ? ['committer'] : ['author', 'committer']) {
    metadata[name] = text(value.metadata[name], 1024, name, true);
    const match = /^([^<>\r\n]+) <([^<>\r\n]+)>$/.exec(metadata[name]);
    if (!match || !match[1].trim()) candidateFail('invalid_candidate_commit_identity');
  }
  metadata.timestamp = String(decimal(value.metadata.timestamp, 'candidate timestamp', 1));
  if (rebase) {
    if (!['stop', 'drop', 'keep'].includes(value.metadata.empty)) candidateFail('invalid_candidate_empty_policy');
    metadata.empty = value.metadata.empty;
  } else {
    metadata.message = text(value.metadata.message, 64 * 1024, 'candidate message');
    if (!metadata.message.trim()) candidateFail('invalid_candidate_metadata_or_method');
  }
  const expected_head = value.expected_head == null ? null : snapshot(value.expected_head);
  return { endpoint, scope: selected, number, metadata, method: value.method, expected_head };
}
function discovery(request, pull, pages, complete = true) {
  const number = Number(request.number), binding = sharedScope(request.scope);
  const selected = showReply(pull, number, { head: request.expected_head, scope: binding }), row = selected.reply.pull_request;
  if (!pull.found || row?.state !== 'open' || !row.data) candidateFail('candidate_requires_open_pull_request');
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
    ...subjectReferences(row.data),
    source_tip: oid(row.data.source_tip, binding.format), target_tip: oid(row.data.target_tip, binding.format) });
  for (const review of reviews) if (review.freshness === 'current') matchSubject(review.subject, fields, number, binding.format);
  return { binding, head: selected.head, fields, reviews, after };
}
function metadataFor(request) { return { ...request.metadata, timestamp: Number(request.metadata.timestamp) }; }
function nativePreparationCommand(request, fields) {
  return request.method === 'rebase' ? rebasePreparationCommand(fields, metadataFor(request))
    : { ...preparationCommand(fields, metadataFor(request), request.method), method: request.method, profile: 'path-merge-v1' };
}
function nativePreparationReply(response, request, observed, resolved = false) {
  return request.method === 'rebase'
    ? rebasePreparationReply(response, Number(request.number), nativePreparationCommand(request, observed.fields),
      observed.binding, webcrypto, observed.head)
    : preparationReply(response, Number(request.number), observed.fields, observed.binding, webcrypto, resolved, request.method);
}
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
function checkPreparationShape(metadata, method = 'merge-commit') {
  const common = ['type', 'schema_version', 'tenant_id', 'repository_id', 'repository_incarnation', 'object_format',
    'source_head', 'snapshot_token', 'profile', 'method', 'read_only', 'objects_staged', 'transaction_created', 'published',
    'merge_authorized', 'subject', 'state', 'bundle', 'conflicts'];
  if (method === 'rebase') {
    candidateKeys(metadata, [...common, 'merge_base', 'committer', 'timestamp', 'empty_policy',
      'original_authors_preserved', 'original_messages_preserved', 'original_signatures_copied', 'author_identity_verified',
      'series_complete', 'provisional_steps', 'candidate_commit', 'root_tree', 'stopped_commit', 'step_count', 'steps',
      ...(metadata.state === 'clean' ? ['generated_objects', 'pack_objects', 'borrowed_objects'] : [])]);
    if (metadata.original_authors_preserved !== true || metadata.original_messages_preserved !== true ||
        metadata.original_signatures_copied !== false || metadata.author_identity_verified !== false) candidateFail('candidate_rebase_preservation_changed');
    if (!Array.isArray(metadata.steps) || metadata.steps.length > 256) candidateFail('candidate_rebase_steps_required');
    for (const step of metadata.steps) {
      candidateKeys(step, ['original', 'rewritten', 'tree', 'kind']);
      if (oid(step.original, metadata.object_format) === oid(metadata.merge_base, metadata.object_format)) {
        candidateFail('candidate_rebase_original_outside_suffix');
      }
    }
    if (metadata.stopped_commit !== null && oid(metadata.stopped_commit, metadata.object_format) === oid(metadata.merge_base, metadata.object_format)) {
      candidateFail('candidate_rebase_original_outside_suffix');
    }
    if (metadata.state === 'clean') {
      candidateKeys(metadata.bundle, ['bytes', 'sha256']);
      for (const key of ['generated_objects', 'pack_objects', 'borrowed_objects']) integer(metadata[key], key, 0, 10000);
      if (!metadata.generated_objects || !metadata.pack_objects || metadata.borrowed_objects > metadata.pack_objects) candidateFail('candidate_rebase_object_accounting');
    }
    return;
  }
  candidateKeys(metadata, [...common, 'candidate', ...(metadata.state === 'conflicted' ? ['merge_base'] : []),
    ...(metadata.state === 'resolved' ? ['resolution_profile', 'resolutions'] : [])]);
  if (['clean', 'resolved'].includes(metadata.state)) {
    candidateKeys(metadata.candidate, ['merge_base', 'commit', 'tree', 'new_object_count']);
    candidateKeys(metadata.bundle, ['bytes', 'sha256']);
    integer(metadata.candidate.new_object_count, 'candidate objects', 1, 10000);
  }
}
async function checkInspection(inspection, artifact, preparation, request) {
  const common = ['type', 'schema_version', 'tenant_id', 'repository_id', 'repository_incarnation', 'object_format',
    'source_head', 'snapshot_token', 'read_only', 'objects_staged', 'transaction_created', 'published', 'merge_authorized',
    'all_changed_paths', 'binary_bodies_included', 'comparison_profile', 'context_lines', 'subject', 'merge_base',
    'candidate_commit', 'prerequisites', 'bundle'];
  if (request.method === 'rebase') {
    candidateKeys(inspection, [...common, 'profile', 'scope', 'method', 'complete', 'all_rewritten_commits',
      'replay_equivalence_verified', 'commit_count', 'source_comparison', 'commits']);
    await rebaseInspectionReply(inspection, artifact, webcrypto);
    const algorithm = artifact.scope.format;
    const retained = preparation.steps.filter(step => step.kind !== 'dropped_empty');
    if (retained.length !== inspection.commits.length || preparation.pack_objects !== inspection.bundle.pack_objects) {
      candidateFail('candidate_rebase_series_changed');
    }
    // Inspecting only the last tree is insufficient: all original-to-rewritten
    // steps must join the exact complete native parent chain and every diff.
    let index = 0, tree = oid(inspection.commits[0].comparison.before_tree, algorithm);
    for (const step of preparation.steps) {
      const nextTree = oid(step.tree, algorithm);
      if (step.kind === 'dropped_empty') {
        if (nextTree !== tree) candidateFail('candidate_rebase_dropped_tree_changed');
        continue;
      }
      const commit = inspection.commits[index++];
      candidateKeys(commit, ['commit', 'parent', 'tree', 'commit_hex', 'comparison']);
      if (oid(step.rewritten, algorithm) !== oid(commit.commit, algorithm) || nextTree !== oid(commit.tree, algorithm)) {
        candidateFail('candidate_rebase_series_changed');
      }
      if (!rebaseCommitterMatches(commit.commit_hex, request.metadata)) candidateFail('candidate_rebase_committer_changed');
      tree = nextTree;
    }
    if (tree !== oid(preparation.root_tree, algorithm)) candidateFail('candidate_tree_report_changed');
    return;
  }
  candidateKeys(inspection, [...common, 'parents', 'candidate_commit_body_hex', 'comparison']);
  await inspectionReply(inspection, artifact, webcrypto);
  if (!candidateCommitMatches({ bodyHex: inspection.candidate_commit_body_hex, format: artifact.scope.format,
    tree: oid(preparation.candidate.tree, artifact.scope.format), targetTip: artifact.fields.target_tip,
    sourceTip: artifact.fields.source_tip, method: request.method, metadata: request.metadata })) {
    candidateFail('candidate_commit_metadata_or_tree_changed');
  }
  if (oid(inspection.comparison.after_tree, artifact.scope.format) !== oid(preparation.candidate.tree, artifact.scope.format)) {
    candidateFail('candidate_tree_report_changed');
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
      if (request.method === 'rebase') candidateFail('candidate_rebase_resolution_requires_original_commit_recipes');
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
    checkPreparationShape(capture.preparation, request.method);
    const prepared = await nativePreparationReply(retainedPreparation(capture.preparation, bundle, capture.preparation_status), request, observed, resolved);
    sameHead(prepared.metadata, capture.pull, request);
    if (resolution) verifyResolutionResult(prepared.metadata, resolution.expected);
    if (prepared.artifact === null) {
      if (bundle !== null || capture.inspection !== null) candidateFail('candidate_material_without_candidate');
    } else {
      await checkInspection(capture.inspection, prepared.artifact, prepared.metadata, request);
      sameHead(capture.inspection, capture.pull, request);
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
    const command = nativePreparationCommand(request, observed.fields);
    // Explicit method and profile: never rely on a server default changing.
    const response = await exchange({ kind: request.method === 'rebase' ? 'prepare-rebase' : 'prepare', number, body: form(command) });
    const metadata = strictPreparation(response); checkPreparationShape(metadata, request.method);
    const prepared = await nativePreparationReply(response, request, observed);
    checkpoint(); sameHead(metadata, pull, request);
    let inspection = null;
    if (prepared.artifact) {
      phase = 'inspection';
      const command = form(prepared.artifact.fields);
      const upload = multipart(command, prepared.artifact.bundle, makeBoundary(command, prepared.artifact.bundle, webcrypto));
      const response = await exchange({ kind: request.method === 'rebase' ? 'inspect-rebase' : 'inspect', number, body: upload.bytes, type: upload.contentType });
      inspection = candidateJson(response.value);
      await checkInspection(inspection, prepared.artifact, metadata, request); checkpoint(); sameHead(inspection, pull, request);
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
    if (request.method === 'rebase') candidateFail('candidate_rebase_resolution_requires_original_commit_recipes');
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
