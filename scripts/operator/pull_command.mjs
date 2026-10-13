// Exact remote PR commands and receipts. These are client consistency checks,
// not Git semantics, native transaction identities, or publication authority.
import { createHash, randomBytes } from 'node:crypto';
import { outcomeEndpoint, outcomeScope } from './transaction_outcome.mjs';

export const PULL_LIMITS = Object.freeze({ form: 256 * 1024, reply: 32 * 1024, intent: 1024 * 1024 });
export const PULL_ACTIONS = Object.freeze(['open', 'update', 'close', 'reopen', 'comment', 'fast-forward']);
const U64 = 18446744073709551615n, SCHEMA = 'frankengit-remote-pull-intent-v1';
const COUNTERS = ['number', 'expected_version', 'pull_request_version', 'comment_version', 'decision_sequence'];
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
  const basis = { schema: SCHEMA, endpoint: outcomeEndpoint(input.endpoint), scope, ...command,
    nonce: input.nonce, credential_fingerprint: hash(input.credential_fingerprint) };
  const result = { ...basis, key: `fgp1-${basis.nonce}-${pullHash(JSON.stringify(basis))}` };
  if (Buffer.byteLength(pullCanonical(result)) > PULL_LIMITS.intent) failPull('pull_intent_limit');
  return result;
}
export function preparePull(input, token) {
  pullFields(input, ['endpoint', 'scope', 'number', 'action', 'fields']);
  return intentFor({ ...input, nonce: randomBytes(16).toString('hex'), credential_fingerprint: pullTokenFingerprint(token) });
}
export function validatePullIntent(value) {
  pullFields(value, ['schema', 'endpoint', 'scope', 'number', 'action', 'fields', 'body', 'nonce', 'credential_fingerprint', 'key']);
  const result = intentFor(value);
  if (value.schema !== SCHEMA || value.body !== result.body || value.key !== result.key ||
      JSON.stringify(value.fields) !== JSON.stringify(result.fields)) failPull('pull_intent_changed');
  return result;
}
export function validatePullPublication(value, input, status) {
  const intent = validatePullIntent(input), ff = intent.action === 'fast-forward', comment = intent.action === 'comment';
  const names = ['type', 'schema_version', ...Object.keys(intent.scope), 'number', 'action', 'tx_id', 'outcome', 'decision_sequence',
    'repository_commit_id', 'refusal_record_id', 'refusal_code', 'refusal_code_point', 'delivery_acknowledged',
    ...(ff ? ['pull_request_version', 'source_ref', 'source_ref_hex', 'target_ref', 'target_ref_hex', 'source_tip', 'target_tip']
      : ['expected_version', ...(comment ? ['comment_version', 'refs_changed'] : [])])];
  pullFields(value, names);
  const committed = value.outcome === 'committed', f = intent.fields;
  if (value.type !== (ff ? 'fast_forward_merge_publication' : comment ? 'pull_request_comment_publication' : 'pull_request_publication') ||
      value.schema_version !== 1 || Object.keys(intent.scope).some(key => value[key] !== intent.scope[key]) ||
      value.number !== intent.number || value.action !== intent.action || !['committed', 'refused'].includes(value.outcome) ||
      status !== (committed ? 200 : 409) || value.delivery_acknowledged !== null) failPull('pull_publication_mismatch');
  const version = ff ? 'pull_request_version' : 'expected_version';
  if (value[version] !== f[version]) failPull('pull_publication_version');
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
