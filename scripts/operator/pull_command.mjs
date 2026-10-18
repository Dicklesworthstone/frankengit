// Exact remote PR commands and receipts. These are client consistency checks,
// not Git semantics, native transaction identities, or publication authority.
import { createHash, randomBytes } from 'node:crypto';
import { outcomeEndpoint, outcomeScope } from './transaction_outcome.mjs';

export const PULL_LIMITS = Object.freeze({ form: 256 * 1024, reply: 32 * 1024, intent: 1024 * 1024, bundle: 16 * 1024 * 1024 });
export const PULL_ACTIONS = Object.freeze(['open', 'update', 'close', 'reopen', 'comment', 'fast-forward']);
// Keep the original form-only list stable for existing consumers. Candidate
// operations are a distinct profile with independently bound bundle bytes.
export const PULL_REVIEW_ACTIONS = Object.freeze(['approve', 'request-changes', 'withdraw', 'merge']);
export const isPullReview = action => PULL_REVIEW_ACTIONS.includes(action);
const REVIEW_SCHEMA = 'frankengit-remote-pull-candidate-intent-v1';
const U64 = 18446744073709551615n, SCHEMA = 'frankengit-remote-pull-intent-v1';
const COUNTERS = ['number', 'expected_version', 'pull_request_version', 'comment_version', 'decision_sequence', 'policy_epoch', 'review_expected_version'];
export class PullError extends Error {
  constructor(code, { phase = 'validation', dispatched = false, publication = null, status = null } = {}) {
    super(code); this.name = 'PullError'; this.code = code; this.phase = phase;
    this.dispatched = dispatched; this.publication = publication; this.status = status; this.outcomeUnknown = true;
  }
}
export const failPull = code => { throw new PullError(code); };
export const pullHash = value => createHash('sha256').update(value).digest('hex');
export const pullCanonical = value => `${JSON.stringify(value, null, 2).replace(
  /[\u007f-\u009f\u061c\u200e\u200f\u2028-\u202e\u2066-\u2069]/gu,
  c => `\\u${c.codePointAt(0).toString(16).padStart(4, '0')}`)}\n`;
export function pullFields(value, names, required = names) {
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
      ![Object.prototype, null].includes(Object.getPrototypeOf(value)) ||
      Object.keys(value).some(name => !names.includes(name)) || required.some(name => !Object.hasOwn(value, name)) ||
      Object.values(Object.getOwnPropertyDescriptors(value)).some(d => !Object.hasOwn(d, 'value'))) failPull('invalid_pull_fields');
  return value;
}
export function pullU64(value, minimum = 0n, maximum = U64) {
  if (typeof value !== 'string' || !/^(0|[1-9][0-9]{0,19})$/.test(value) ||
      BigInt(value) < minimum || BigInt(value) > maximum) failPull('invalid_pull_u64');
  return value;
}
function text(value, maximum, single = false) {
  if (typeof value !== 'string' || value.length > maximum || Buffer.byteLength(value) > maximum ||
      /[\uD800-\uDFFF]/u.test(value) || value.includes('\0') ||
      (single && (!value.trim() || /[\u0000-\u001f\u007f-\u009f]/u.test(value)))) failPull('invalid_pull_text');
  return value;
}
function opaque(value) { text(value, 256, true); if (/\s/u.test(value)) failPull('invalid_pull_identity'); return value; }
function hash(value) { if (typeof value !== 'string' || !/^[0-9a-f]{64}$/.test(value)) failPull('invalid_pull_digest'); return value; }
export function pullTokenFingerprint(value) { return pullHash(hash(value)); }
function branch(value) {
  text(value, 1024, true);
  // HTTP forms admit UTF-8 refs only; never lossy-decode a native byte-only ref.
  if (!value.startsWith('refs/heads/') || /[\x00-\x20\x7f~^:?*\[\\]/u.test(value) ||
      value.includes('..') || value.includes('@{') || value.endsWith('.') ||
      value.split('/').some(part => !part || part.startsWith('.') || part.endsWith('.lock'))) failPull('invalid_pull_branch');
  return value;
}
function oid(value, format, wire = false) {
  if (typeof value !== 'string') failPull('invalid_pull_oid');
  const raw = wire && value.startsWith(`${format}:`) ? value.slice(format.length + 1) : value;
  if (!new RegExp(`^[0-9a-f]{${format === 'sha1' ? 40 : 64}}$`).test(raw) || /^0+$/.test(raw)) failPull('invalid_pull_oid');
  return raw;
}
export function pullScope(value) {
  pullFields(value, ['tenant_id', 'repository_id', 'repository_incarnation', 'principal_id', 'object_format']);
  if (!['sha1', 'sha256'].includes(value.object_format)) failPull('invalid_pull_format');
  return { ...pullOutcomeScope(value), object_format: value.object_format };
}
export function pullOutcomeScope(value) {
  return outcomeScope(Object.fromEntries(['tenant_id', 'repository_id', 'repository_incarnation', 'principal_id'].map(k => [k, value[k]])));
}
// A bounded lexical pass refuses duplicate/escaped-equivalent keys and deep
// containers. JSON.parse still owns syntax; raw native u64 tokens never round.
export function parsePullJson(bytes, { wire = false, maximum = PULL_LIMITS.intent } = {}) {
  if (!Buffer.isBuffer(bytes) || !Number.isSafeInteger(maximum) || maximum < 1 || maximum > PULL_LIMITS.intent ||
      bytes.length > maximum || typeof wire !== 'boolean') failPull('pull_json_limit');
  try {
    const source = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes), stack = [];
    let nodes = 0;
    for (let i = 0; i < source.length; i++) {
      const c = source[i];
      if (c === '{' || c === '[') {
        if (++nodes > 16384 || stack.length >= 16) failPull('pull_json_structure_limit');
        stack.push({ type: c, keys: new Set() });
      } else if (c === '}' || c === ']') {
        if (stack.pop()?.type !== (c === '}' ? '{' : '[')) failPull('invalid_pull_json');
      } else if (c === '"') {
        const start = i++;
        for (; i < source.length && source[i] !== '"'; i++) if (source[i] === '\\') i++;
        if (i >= source.length || ++nodes > 16384) failPull('pull_json_structure_limit');
        let next = i + 1; while (next < source.length && /[\x20\t\r\n]/.test(source[next])) next++;
        if (source[next] === ':') {
          const current = stack.at(-1), key = JSON.parse(source.slice(start, i + 1));
          if (current?.type !== '{' || current.keys.has(key)) failPull('duplicate_pull_json_key');
          current.keys.add(key);
        }
      }
    }
    if (stack.length) failPull('invalid_pull_json');
    return JSON.parse(source, (key, value, context) => {
      if (typeof value !== 'number') return value;
      if (!/^(0|[1-9][0-9]*)$/.test(context?.source ?? '')) failPull('invalid_pull_json_number');
      if (wire && COUNTERS.includes(key)) return pullU64(context.source);
      if (!Number.isSafeInteger(value)) failPull('unsafe_pull_json_number');
      return value;
    });
  } catch (error) { if (error instanceof PullError) throw error; failPull('invalid_pull_json'); }
}
export function pullCommand(number, action, input, format) {
  pullU64(number, 1n);
  if (isPullReview(action)) return candidateCommand(number, action, input, format);
  if (!PULL_ACTIONS.includes(action) || !['sha1', 'sha256'].includes(format)) failPull('unsupported_pull_command');
  const ff = action === 'fast-forward', comment = action === 'comment';
  const names = comment ? ['expected_version', 'body'] :
    [ff ? 'pull_request_version' : 'expected_version', 'source_ref', 'target_ref', 'source_tip', 'target_tip', ...(ff ? [] : ['title', 'body'])];
  pullFields(input, names);
  const versionName = ff ? 'pull_request_version' : 'expected_version';
  const version = pullU64(input[versionName], ff ? 1n : 0n, U64 - 1n);
  if (!ff && !comment && (action === 'open') !== (version === '0')) failPull('invalid_pull_action_version');
  const normalized = { [versionName]: version };
  if (!comment) {
    for (const side of ['source', 'target']) normalized[`${side}_ref`] = branch(input[`${side}_ref`]);
    for (const side of ['source', 'target']) normalized[`${side}_tip`] = oid(input[`${side}_tip`], format);
    if (normalized.source_ref === normalized.target_ref || (ff && normalized.source_tip === normalized.target_tip)) failPull('invalid_pull_coordinates');
  }
  if (!ff) {
    if (!comment) normalized.title = text(input.title, 256, true);
    normalized.body = text(input.body, 64 * 1024);
    if (comment && !normalized.body.trim()) failPull('empty_pull_comment');
  }
  const body = new URLSearchParams(comment ? normalized : { object_format: format, ...normalized }).toString();
  if (body.length > (ff ? 8192 : PULL_LIMITS.form)) failPull('pull_form_limit');
  return { number, action, fields: normalized, body };
}
function intentFor(input) {
  const scope = pullScope(input.scope), command = pullCommand(input.number, input.action, input.fields, scope.object_format);
  if (typeof input.nonce !== 'string' || !/^[0-9a-f]{32}$/.test(input.nonce)) failPull('invalid_pull_nonce');
  const review = isPullReview(input.action);
  if (input.action === 'merge' && command.fields.required_reviewers.includes(scope.principal_id)) failPull('pull_submitter_cannot_review_merge');
  const basis = { schema: review ? REVIEW_SCHEMA : SCHEMA, endpoint: outcomeEndpoint(input.endpoint), scope, ...command,
    nonce: input.nonce, credential_fingerprint: hash(input.credential_fingerprint),
    ...(review ? { bundle: candidateBundle(input.action, input.bundle) } : {}) };
  const result = { ...basis, key: `${review ? 'fgpc1' : 'fgp1'}-${basis.nonce}-${pullHash(JSON.stringify(basis))}` };
  if (Buffer.byteLength(pullCanonical(result)) > PULL_LIMITS.intent) failPull('pull_intent_limit');
  return result;
}
export function preparePull(input, token, bundle = null) {
  pullFields(input, ['endpoint', 'scope', 'number', 'action', 'fields']);
  const payload = isPullReview(input.action) && input.action !== 'withdraw';
  if (!payload && bundle !== null) failPull('unexpected_pull_bundle');
  const descriptor = payload ? pullBundleDescriptor(bundle) : null;
  const intent = intentFor({ ...input, nonce: randomBytes(16).toString('hex'),
    credential_fingerprint: pullTokenFingerprint(token), ...(isPullReview(input.action) ? { bundle: descriptor } : {}) });
  // A boundary collision refuses preparation rather than silently changing a
  // saved nonce/key later. No Git object, pack or policy is decoded here.
  if (payload) checkBoundary(intent, bundle);
  return intent;
}
export function validatePullIntent(value) {
  pullFields(value, ['schema', 'endpoint', 'scope', 'number', 'action', 'fields', 'body', 'nonce', 'credential_fingerprint', 'key',
    ...(isPullReview(value?.action) ? ['bundle'] : [])]);
  const result = intentFor(value);
  if (value.schema !== result.schema || value.body !== result.body || value.key !== result.key ||
      JSON.stringify(value.fields) !== JSON.stringify(result.fields)) failPull('pull_intent_changed');
  return result;
}
export function validatePullPublication(value, input, status) {
  const intent = validatePullIntent(input), ff = intent.action === 'fast-forward', comment = intent.action === 'comment', review = isPullReview(intent.action);
  const names = ['type', 'schema_version', ...Object.keys(intent.scope), ...(review ? [] : ['number']), 'action', 'tx_id', 'outcome', 'decision_sequence',
    'repository_commit_id', 'refusal_record_id', 'refusal_code', 'refusal_code_point', 'delivery_acknowledged',
    ...(review ? ['subject', 'merge_base', 'candidate_commit', 'required_reviewers', 'review_expected_version', ...(intent.action === 'merge' ? ['method'] : [])]
      : ff ? ['pull_request_version', 'source_ref', 'source_ref_hex', 'target_ref', 'target_ref_hex', 'source_tip', 'target_tip']
      : ['expected_version', ...(comment ? ['comment_version', 'refs_changed'] : [])])];
  pullFields(value, names);
  const committed = value.outcome === 'committed', f = intent.fields;
  if (value.type !== (review ? (intent.action === 'merge' ? 'reviewed_merge_publication' : 'candidate_review_publication')
        : ff ? 'fast_forward_merge_publication' : comment ? 'pull_request_comment_publication' : 'pull_request_publication') ||
      value.schema_version !== 1 || Object.keys(intent.scope).some(key => value[key] !== intent.scope[key]) ||
      (!review && value.number !== intent.number) || value.action !== intent.action || !['committed', 'refused'].includes(value.outcome) ||
      status !== (committed ? 200 : 409) || value.delivery_acknowledged !== null) failPull('pull_publication_mismatch');
  const version = ff ? 'pull_request_version' : 'expected_version';
  if (review) checkCandidatePublication(value, intent);
  if (!review && value[version] !== f[version]) failPull('pull_publication_version');
  if (ff) for (const side of ['source', 'target']) {
    if (value[`${side}_ref`] !== f[`${side}_ref`] || value[`${side}_ref_hex`] !== Buffer.from(f[`${side}_ref`]).toString('hex') ||
        oid(value[`${side}_tip`], intent.scope.object_format, true) !== f[`${side}_tip`]) failPull('pull_publication_coordinates');
  }
  if (comment && (value.refs_changed !== false || value.comment_version !== (committed ? String(BigInt(f.expected_version) + 1n) : null))) failPull('pull_comment_receipt');
  opaque(value.tx_id); pullU64(value.decision_sequence, 1n);
  if (committed) {
    opaque(value.repository_commit_id);
    if (value.refusal_record_id !== null || value.refusal_code !== null || value.refusal_code_point !== null) failPull('pull_publication_conflict');
  } else {
    opaque(value.refusal_record_id); opaque(value.refusal_code);
    if (value.repository_commit_id !== null || !Number.isSafeInteger(value.refusal_code_point) ||
        value.refusal_code_point < 0 || value.refusal_code_point > 65535) failPull('pull_publication_conflict');
  }
  return structuredClone(value);
}

// Candidate commands name an exact reviewed artifact. The native engine still
// checks the bundle, Git closure, current source, policy and independent votes.
function candidateCommand(number, action, input, format) {
  if (!['sha1', 'sha256'].includes(format)) failPull('invalid_pull_format');
  const merge = action === 'merge';
  pullFields(input, ['pull_request_version', 'policy_epoch', 'source_ref', 'target_ref', 'source_tip', 'target_tip',
    'merge_base', 'candidate_commit', ...(merge ? ['required_reviewers', 'method'] : ['expected_version', 'reason'])]);
  const f = { pull_request_version: pullU64(input.pull_request_version, 1n, U64 - 1n), policy_epoch: pullU64(input.policy_epoch, 1n) };
  for (const side of ['source', 'target']) f[`${side}_ref`] = branch(input[`${side}_ref`]);
  if (f.source_ref === f.target_ref) failPull('invalid_pull_coordinates');
  for (const name of ['source_tip', 'target_tip', 'merge_base', 'candidate_commit']) f[name] = oid(input[name], format);
  if (merge) {
    if (!['merge-commit', 'squash'].includes(input.method)) failPull('explicit_reviewed_merge_method_required');
    if (!Array.isArray(input.required_reviewers) || !input.required_reviewers.length || input.required_reviewers.length > 32) failPull('invalid_pull_reviewers');
    f.required_reviewers = Array.from(input.required_reviewers, id => {
      if (typeof id !== 'string' || !/^[0-9a-f]{32}$/.test(id)) failPull('invalid_pull_reviewers');
      return id;
    }).sort();
    if (new Set(f.required_reviewers).size !== f.required_reviewers.length) failPull('invalid_pull_reviewers');
    f.method = input.method;
  } else {
    f.expected_version = pullU64(input.expected_version, action === 'withdraw' ? 1n : 0n, U64 - 1n);
    f.reason = text(input.reason, 4096);
    if (!f.reason.trim()) failPull('empty_pull_review_reason');
  }
  const form = new URLSearchParams({ object_format: format });
  for (const [name, value] of Object.entries(f)) {
    if (name === 'required_reviewers') for (const id of value) form.append('required_reviewer', id);
    else form.append(name, value);
  }
  const body = form.toString();
  if (body.length > PULL_LIMITS.form) failPull('pull_form_limit');
  return { number, action, fields: f, body };
}
function candidateBundle(action, value) {
  if (action === 'withdraw') {
    if (value !== null) failPull('unexpected_pull_bundle');
    return null;
  }
  pullFields(value, ['size', 'sha256']);
  if (!Number.isSafeInteger(value.size) || value.size < 1 || value.size > PULL_LIMITS.bundle) failPull('pull_bundle_limit');
  return { size: value.size, sha256: hash(value.sha256) };
}
export function pullBundleDescriptor(bytes) {
  if (!Buffer.isBuffer(bytes) || !bytes.length || bytes.length > PULL_LIMITS.bundle ||
      (typeof SharedArrayBuffer !== 'undefined' && bytes.buffer instanceof SharedArrayBuffer)) failPull('pull_bundle_limit');
  return { size: bytes.length, sha256: pullHash(bytes) };
}
function boundary(intent) { return `fg-pull-candidate-${intent.nonce}`; }
function checkBoundary(intent, bytes) {
  if (bytes.includes(Buffer.from(`--${boundary(intent)}`)) || intent.body.includes(`--${boundary(intent)}`)) failPull('pull_bundle_boundary_collision');
}
export function validatePullBundle(input, bytes) {
  const intent = validatePullIntent(input);
  if (!isPullReview(intent.action) || intent.bundle === null) failPull('unexpected_pull_bundle');
  const observed = pullBundleDescriptor(bytes);
  if (observed.size !== intent.bundle.size || observed.sha256 !== intent.bundle.sha256) failPull('pull_bundle_changed');
  checkBoundary(intent, bytes);
  return Buffer.from(bytes); // Detach before asynchronous work can see caller edits.
}
export function pullEnvelope(input, bundle = null) {
  const intent = validatePullIntent(input);
  if (!isPullReview(intent.action) || intent.bundle === null) {
    if (bundle !== null) failPull('unexpected_pull_bundle');
    return { contentType: 'application/x-www-form-urlencoded', body: Buffer.from(intent.body) };
  }
  const bytes = validatePullBundle(intent, bundle), marker = boundary(intent);
  return { contentType: `multipart/form-data; boundary=${marker}`, body: Buffer.concat([
    Buffer.from(`--${marker}\r\nContent-Disposition: form-data; name="command"\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\n${intent.body}\r\n--${marker}\r\nContent-Disposition: form-data; name="bundle"; filename="candidate.bundle"\r\nContent-Type: application/x-git-bundle\r\n\r\n`),
    bytes, Buffer.from(`\r\n--${marker}--\r\n`),
  ]) };
}
function checkCandidatePublication(value, intent) {
  const f = intent.fields, s = value.subject, merge = intent.action === 'merge', format = intent.scope.object_format;
  pullFields(s, ['number', 'pull_request_version', 'policy_epoch', 'source_ref', 'source_ref_hex', 'target_ref', 'target_ref_hex', 'source_tip', 'target_tip']);
  if (s.number !== intent.number || s.pull_request_version !== f.pull_request_version || s.policy_epoch !== f.policy_epoch ||
      value.review_expected_version !== (merge ? null : f.expected_version)) failPull('pull_review_subject_changed');
  for (const side of ['source', 'target']) {
    if (s[`${side}_ref`] !== f[`${side}_ref`] || s[`${side}_ref_hex`] !== Buffer.from(f[`${side}_ref`]).toString('hex') ||
        oid(s[`${side}_tip`], format, true) !== f[`${side}_tip`]) failPull('pull_review_subject_changed');
  }
  for (const name of ['merge_base', 'candidate_commit']) if (oid(value[name], format, true) !== f[name]) failPull('pull_review_candidate_changed');
  if (merge ? value.method !== f.method || JSON.stringify(value.required_reviewers) !== JSON.stringify(f.required_reviewers)
    : value.required_reviewers !== null) failPull('pull_merge_requirements_changed');
}
