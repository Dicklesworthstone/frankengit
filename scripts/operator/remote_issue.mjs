// Authenticated operator peer for native issues, not a server or identity store.
// The original-key outcome client remains the only recovery implementation.
import { createHash, randomBytes } from 'node:crypto';
import { request as httpRequest } from 'node:http';
import { request as httpsRequest } from 'node:https';
import { performance } from 'node:perf_hooks';
import { lookupOutcome, outcomeEndpoint, outcomeScope, validateOutcomeReply, OutcomeError } from './transaction_outcome.mjs';

export const ISSUE_LIMITS = Object.freeze({ form: 256 * 1024, reply: 16 * 1024, intent: 512 * 1024,
  body: 64 * 1024, title: 256, labels: 32, assignees: 16 });
const MAX_U64 = 18446744073709551615n;
const ACTIONS = ['open', 'edit', 'comment', 'append-comment', 'close', 'reopen', 'assign', 'unassign'];
const INTENT = 'frankengit-remote-issue-intent-v1';
const ID = /^[0-9a-f]{32}$/, HASH = /^[0-9a-f]{64}$/;
export class IssueError extends Error {
  constructor(code, { status = null, phase = 'validation', dispatched = false, publication = null } = {}) {
    super(code); this.name = 'IssueError'; this.code = code; this.status = status;
    this.phase = phase; this.dispatched = dispatched; this.publication = publication;
    // A failed invocation says nothing about earlier attempts of a saved key.
    this.outcomeUnknown = true;
  }
}
const fail = code => { throw new IssueError(code); };
export const issueHash = bytes => createHash('sha256').update(bytes).digest('hex');
export const issueCanonical = value => `${JSON.stringify(value, null, 2).replace(
  /[\u007f-\u009f\u061c\u200e\u200f\u2028-\u202e\u2066-\u2069]/gu,
  c => `\\u${c.codePointAt(0).toString(16).padStart(4, '0')}`)}\n`;
function record(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
      ![Object.prototype, null].includes(Object.getPrototypeOf(value))) fail('invalid_issue_record');
  return value;
}
function fields(value, names, required = names) {
  record(value);
  if (Object.keys(value).some(name => !names.includes(name)) || required.some(name => !Object.hasOwn(value, name)) ||
      Object.values(Object.getOwnPropertyDescriptors(value)).some(d => !Object.hasOwn(d, 'value'))) fail('invalid_issue_fields');
  return value;
}
export function issueU64(value, minimum = 0n, maximum = MAX_U64) {
  if (typeof value !== 'string' || !/^(0|[1-9][0-9]{0,19})$/.test(value) ||
      BigInt(value) < minimum || BigInt(value) > maximum) fail('invalid_issue_u64');
  return value;
}
function text(value, maximum, single = false) {
  if (typeof value !== 'string' || value.length > maximum || Buffer.byteLength(value) > maximum ||
      /[\uD800-\uDFFF]/u.test(value) || value.includes('\0') ||
      (single && (!value.trim() || /[\u0000-\u001f\u007f-\u009f]/u.test(value)))) fail('invalid_issue_text');
  return value;
}
function opaque(value) { text(value, 256, true); if (/\s/u.test(value)) fail('invalid_issue_identity'); return value; }
function identity(value) { if (typeof value !== 'string' || !ID.test(value)) fail('invalid_issue_principal'); return value; }
function digest(value) { if (typeof value !== 'string' || !HASH.test(value)) fail('invalid_issue_digest'); return value; }
export function issueTokenFingerprint(token) { digest(token); return issueHash(token); }
function list(value, maximum, check) {
  if (!Array.isArray(value) || value.length > maximum) fail('issue_list_limit');
  const result = Array.from(value, check).sort((a, b) => Buffer.compare(Buffer.from(a), Buffer.from(b)));
  if (new Set(result).size !== result.length) fail('duplicate_issue_value');
  return result;
}
// JSON.parse owns JSON syntax. This bounded lexical pass additionally refuses
// duplicate (including escaped-equivalent) keys and excessive nesting before
// the reviver runs. It never rewrites repository text or parses a Git format.
export function parseIssueJson(bytes, { wire = false, maximum = ISSUE_LIMITS.intent } = {}) {
  if (!Buffer.isBuffer(bytes) || !Number.isSafeInteger(maximum) || maximum < 1 || maximum > ISSUE_LIMITS.intent ||
      bytes.length > maximum || typeof wire !== 'boolean') fail('issue_json_limit');
  try {
    const source = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes), stack = [];
    let nodes = 0;
    for (let i = 0; i < source.length; i++) {
      const c = source[i];
      if (c === '{' || c === '[') {
        if (++nodes > 16384 || stack.length >= 16) fail('issue_json_structure_limit');
        stack.push({ type: c, keys: new Set() });
      } else if (c === '}' || c === ']') {
        if (stack.pop()?.type !== (c === '}' ? '{' : '[')) fail('invalid_issue_json');
      } else if (c === '"') {
        const start = i++;
        for (; i < source.length && source[i] !== '"'; i++) if (source[i] === '\\') i++;
        if (i >= source.length || ++nodes > 16384) fail('issue_json_structure_limit');
        let next = i + 1; while (/[\x20\t\r\n]/.test(source[next] ?? '') && next < source.length) next++;
        if (source[next] === ':') {
          const current = stack.at(-1), key = JSON.parse(source.slice(start, i + 1));
          if (current?.type !== '{' || current.keys.has(key)) fail('duplicate_issue_json_key');
          current.keys.add(key);
        }
      }
    }
    if (stack.length) fail('invalid_issue_json');
    return JSON.parse(source, (key, value, context) => {
      if (typeof value !== 'number') return value;
      if (!/^(0|[1-9][0-9]*)$/.test(context?.source ?? '')) fail('invalid_issue_json_number');
      if (wire && ['number', 'expected_version', 'decision_sequence'].includes(key)) return issueU64(context.source);
      if (!Number.isSafeInteger(value)) fail('unsafe_issue_json_number');
      return value;
    });
  } catch (error) { if (error instanceof IssueError) throw error; fail('invalid_issue_json'); }
}
export function issueCommand(number, version, action, input) {
  issueU64(number, 1n);
  const append = action === 'append-comment';
  // Explicit local null means the native form carries NO predecessor field.
  // Never reinterpret a strict saved request by discarding its version.
  if (append) { if (version !== null) fail('append_issue_version_forbidden'); }
  else issueU64(version, 0n, MAX_U64 - 1n);
  if (!ACTIONS.includes(action) || (!append && (action === 'open') !== (version === '0'))) fail('invalid_issue_action_or_version');
  const names = ['open', 'edit'].includes(action) ? ['title', 'body', 'labels']
    : ['comment', 'append-comment'].includes(action) ? ['body'] : ['assign', 'unassign'].includes(action) ? ['assignees'] : [];
  fields(input, names, action === 'open' ? ['title', 'body'] : action === 'edit' ? [] : names);
  const normalized = {};
  if (Object.hasOwn(input, 'title')) normalized.title = text(input.title, ISSUE_LIMITS.title, true);
  if (Object.hasOwn(input, 'body')) normalized.body = text(input.body, ISSUE_LIMITS.body);
  if (Object.hasOwn(input, 'labels')) normalized.labels = list(input.labels, ISSUE_LIMITS.labels, label => text(label, 64, true));
  if (action === 'open') normalized.labels ??= [];
  if (Object.hasOwn(input, 'assignees')) normalized.assignees = list(input.assignees, ISSUE_LIMITS.assignees, identity);
  if ((action === 'edit' && !Object.keys(normalized).length) || (['comment', 'append-comment'].includes(action) && !normalized.body.trim()) ||
      (['assign', 'unassign'].includes(action) && !normalized.assignees.length)) fail('empty_issue_change');
  const form = new URLSearchParams(append ? {} : { expected_version: version });
  for (const name of ['title', 'body']) if (Object.hasOwn(normalized, name)) form.append(name, normalized[name]);
  if (normalized.labels) {
    for (const label of normalized.labels) form.append('label', label);
    if (action === 'edit' && !normalized.labels.length) form.append('clear_labels', 'true');
  }
  for (const person of normalized.assignees ?? []) form.append('assignee', person);
  const body = form.toString(); if (body.length > ISSUE_LIMITS.form) fail('issue_form_limit');
  return { number, expected_version: version, action, fields: normalized, body };
}
function intentFor(value) {
  const command = issueCommand(value.number, value.expected_version, value.action, value.fields);
  const basis = { schema: INTENT, endpoint: outcomeEndpoint(value.endpoint), scope: outcomeScope(value.scope),
    ...command, nonce: identity(value.nonce), credential_fingerprint: digest(value.credential_fingerprint) };
  const key = `fgi1-${basis.nonce}-${issueHash(JSON.stringify(basis))}`;
  const intent = { ...basis, key };
  if (Buffer.byteLength(issueCanonical(intent)) > ISSUE_LIMITS.intent) fail('issue_intent_limit');
  return intent;
}
// Generates a client idempotency key, NOT a native transaction or seal identity.
export function prepareIssue(value, token) {
  fields(value, ['endpoint', 'scope', 'number', 'expected_version', 'action', 'fields']);
  return intentFor({ ...value, nonce: randomBytes(16).toString('hex'), credential_fingerprint: issueTokenFingerprint(token) });
}
export function validateIssueIntent(value) {
  fields(value, ['schema', 'endpoint', 'scope', 'number', 'expected_version', 'action', 'fields', 'body', 'nonce', 'credential_fingerprint', 'key']);
  const normalized = intentFor(value);
  if (value.schema !== INTENT || value.key !== normalized.key || value.body !== normalized.body ||
      JSON.stringify(value.fields) !== JSON.stringify(normalized.fields)) fail('issue_intent_changed');
  return normalized;
}
export function validateIssuePublication(value, intent, status) {
  fields(value, ['type', 'schema_version', 'tenant_id', 'repository_id', 'principal_id', 'number', 'expected_version', 'action',
    'tx_id', 'outcome', 'decision_sequence', 'repository_commit_id', 'refusal_record_id', 'refusal_code', 'delivery_acknowledged']);
  if (value.type !== 'issue_publication' || value.schema_version !== 1 ||
      ['tenant_id', 'repository_id', 'principal_id'].some(key => value[key] !== intent.scope[key]) ||
      value.number !== intent.number || value.expected_version !== intent.expected_version || value.action !== intent.action ||
      !['committed', 'refused'].includes(value.outcome) || status !== (value.outcome === 'committed' ? 200 : 409) ||
      value.delivery_acknowledged !== null) fail('issue_publication_mismatch');
  opaque(value.tx_id); issueU64(value.decision_sequence, 1n);
  if (value.outcome === 'committed') {
    opaque(value.repository_commit_id);
    if (value.refusal_record_id !== null || value.refusal_code !== null) fail('issue_publication_conflict');
  } else {
    opaque(value.refusal_record_id); opaque(value.refusal_code);
    if (value.repository_commit_id !== null) fail('issue_publication_conflict');
  }
  return structuredClone(value);
}
function optionsFor(options, send) {
  fields(options, ['timeoutMs', 'signal', 'ca', 'known', ...(send ? ['confirmKey'] : [])], []);
  const timeoutMs = options.timeoutMs ?? 30000;
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 300000 ||
      (options.signal !== undefined && !(options.signal instanceof AbortSignal))) fail('invalid_issue_transport_options');
  const ca = options.ca === undefined ? undefined : Buffer.isBuffer(options.ca) && options.ca.length > 0 && options.ca.length <= 128 * 1024
    ? Buffer.from(options.ca) : fail('invalid_issue_ca');
  return { ...options, timeoutMs, ca };
}
function issueFailure(error, phase, dispatched, publication = null) {
  return new IssueError(error instanceof IssueError || error instanceof OutcomeError ? error.code : 'issue_operation_unavailable',
    { status: error instanceof IssueError || error instanceof OutcomeError ? error.status : null, phase, dispatched, publication });
}
function postIssue(intent, token, options) {
  return new Promise((resolve, reject) => {
    let request, response, result, error, closed = false, finishing = false, delivered = false, timer;
    const signal = options.signal;
    const deliver = () => { if (delivered) return; delivered = true; error ? reject(error) : resolve(result); };
    const finish = (failure, value) => {
      if (finishing) return;
      finishing = true; error = failure; result = value; clearTimeout(timer); signal?.removeEventListener('abort', abort);
      response?.destroy(); request?.destroy(); if (!request || closed) deliver();
    };
    const abort = () => finish(new IssueError('issue_cancelled'));
    if (signal?.aborted) { abort(); return; }
    try {
      const url = new URL(`${intent.endpoint}/api/v1/issues/${intent.number}/${intent.action}`);
      request = (url.protocol === 'https:' ? httpsRequest : httpRequest)(url, {
        method: 'POST', agent: false, maxHeaderSize: 16 * 1024, rejectUnauthorized: true, ...(options.ca ? { ca: options.ca } : {}),
        headers: { Authorization: `Bearer ${token}`, 'Idempotency-Key': intent.key, Accept: 'application/json',
          'User-Agent': 'frankengit-agent (+https://github.com/Dicklesworthstone/frankengit)',
          'Content-Type': 'application/x-www-form-urlencoded', 'Content-Length': String(Buffer.byteLength(intent.body)),
          'Accept-Encoding': 'identity', Connection: 'close', 'Cache-Control': 'no-store' },
      });
      request.once('close', () => { closed = true; if (!finishing) finish(new IssueError('issue_response_incomplete')); else deliver(); });
      request.on('error', () => finish(new IssueError('issue_transport_unavailable')));
      request.once('response', incoming => {
        response = incoming;
        if (![200, 409].includes(incoming.statusCode)) { finish(new IssueError('issue_http_refused', { status: incoming.statusCode })); return; }
        const names = incoming.rawHeaders.filter((_, i) => i % 2 === 0).map(key => key.toLowerCase())
          .filter(key => ['content-type', 'content-length', 'content-encoding'].includes(key));
        const declared = incoming.headers['content-length'];
        if (new Set(names).size !== names.length || !/^application\/json(?:\s*;|$)/i.test(incoming.headers['content-type'] ?? '') ||
            (incoming.headers['content-encoding'] ?? 'identity').toLowerCase() !== 'identity') {
          finish(new IssueError('issue_response_encoding')); return;
        }
        if (declared !== undefined && (!/^(0|[1-9][0-9]*)$/.test(declared) || BigInt(declared) > BigInt(ISSUE_LIMITS.reply))) {
          finish(new IssueError('issue_response_limit')); return;
        }
        const chunks = []; let size = 0;
        incoming.on('error', () => finish(new IssueError('issue_response_incomplete')));
        incoming.on('data', chunk => {
          if (finishing) return;
          size += chunk.length;
          if (size > ISSUE_LIMITS.reply || chunks.length >= ISSUE_LIMITS.reply) finish(new IssueError('issue_response_limit'));
          else chunks.push(chunk);
        });
        incoming.once('end', () => {
          if (finishing) return;
          if (!incoming.complete || (declared !== undefined && BigInt(declared) !== BigInt(size))) {
            finish(new IssueError('issue_response_incomplete')); return;
          }
          try { finish(null, validateIssuePublication(parseIssueJson(Buffer.concat(chunks, size), { wire: true, maximum: ISSUE_LIMITS.reply }), intent, incoming.statusCode)); }
          catch (failure) { finish(failure); }
        });
      });
      signal?.addEventListener('abort', abort, { once: true });
      timer = setTimeout(() => finish(new IssueError('issue_timeout')), options.timeoutMs);
      if (signal?.aborted) abort(); else request.end(intent.body);
    } catch { finish(new IssueError('issue_transport_unavailable')); }
  });
}
function report(intent, outcome, dispatched, publication = null) {
  return { type: 'remote_issue_result', schema_version: 1, endpoint: intent.endpoint, key: intent.key,
    number: intent.number, expected_version: intent.expected_version, action: intent.action,
    dispatched_this_call: dispatched, outcome, publication, absence_proves_non_commit: false, delivery_acknowledged: null };
}
export async function recoverIssue(value, token, options = {}) {
  const intent = validateIssueIntent(value), checked = optionsFor(options, false);
  issueTokenFingerprint(token); // Rotation may look up, never resend the original command.
  try {
    const outcome = await lookupOutcome(intent.endpoint, token, { ...intent.scope, key: intent.key }, checked);
    return report(intent, outcome, false);
  } catch (error) { throw issueFailure(error, 'recovery', false); }
}
export async function submitIssue(value, token, options = {}) {
  const intent = validateIssueIntent(value), checked = optionsFor(options, true);
  if (checked.confirmKey !== intent.key) fail('confirm_original_issue_key');
  if (issueTokenFingerprint(token) !== intent.credential_fingerprint) fail('original_issue_credential_required');
  const started = performance.now(), known = checked.known == null ? null : validateOutcomeReply(checked.known, intent.scope);
  let phase = 'preflight', dispatched = false, publication = null;
  const remaining = () => {
    if (checked.signal?.aborted) fail('issue_cancelled');
    const milliseconds = Math.floor(checked.timeoutMs - (performance.now() - started));
    if (milliseconds < 1) fail('issue_timeout');
    return milliseconds;
  };
  const lookup = previous => lookupOutcome(intent.endpoint, token, { ...intent.scope, key: intent.key },
    { signal: checked.signal, ca: checked.ca, known: previous, timeoutMs: remaining() });
  try {
    // Also checks the authenticated principal and repository incarnation before
    // dispatch. This is not an atomic incarnation condition on the issue POST.
    const before = await lookup(known);
    if (before.terminal) return report(intent, before, false);
    phase = 'publication'; const timeoutMs = remaining(); dispatched = true;
    publication = await postIssue(intent, token, { ...checked, timeoutMs });
    // Issue v1 receipts lack incarnation. Confirm via the original key rather
    // than claiming that an issue POST alone supplied an incarnation binding.
    phase = 'confirmation';
    const after = await lookup(before), decision = after.decision;
    if (!after.terminal || after.transaction.tx_id !== publication.tx_id || after.state !== publication.outcome ||
        decision.decision_sequence !== publication.decision_sequence ||
        (decision.repository_commit_id ?? null) !== publication.repository_commit_id ||
        (decision.refusal_record_id ?? null) !== publication.refusal_record_id ||
        (decision.code ?? null) !== publication.refusal_code) fail('issue_confirmation_mismatch');
    return report(intent, after, true, publication);
  } catch (error) { throw issueFailure(error, phase, dispatched, publication); }
}
