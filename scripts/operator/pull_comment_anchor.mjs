// Structural checks for exact original PR source coordinates. Native admission
// independently verifies the recorded trees, comparison and whole source lines.
export const PULL_COMMENT_ANCHOR_PROFILE = 'frankengit.source-comment.myers-lines.v1';
export const PULL_COMMENT_ANCHOR_FIELDS = Object.freeze(['pull_request_version', 'source_ref_hex', 'target_ref_hex',
  'source_tip', 'target_tip', 'compared_base', 'comparison', 'path_hex', 'side', 'blob', 'mode',
  'byte_start', 'byte_end', 'line_start', 'line_count']);
const U64 = 18446744073709551615n, BLOB_BYTES = 1048576n, SPAN_BYTES = 65536n, LINES = 128n;

export class PullAnchorError extends Error {
  constructor(code) { super(code); this.name = 'PullAnchorError'; this.code = code; }
}
const fail = code => { throw new PullAnchorError(code); };
function fields(value, names, required = names) {
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
      ![Object.prototype, null].includes(Object.getPrototypeOf(value))) fail('invalid_pull_anchor_fields');
  const keys = Reflect.ownKeys(value);
  if (keys.some(key => !names.includes(key)) || required.some(key => !Object.hasOwn(value, key)) ||
      Object.values(Object.getOwnPropertyDescriptors(value)).some(d => !Object.hasOwn(d, 'value'))) fail('invalid_pull_anchor_fields');
}
function counter(value, minimum = 0n, maximum = U64) {
  if (typeof value !== 'string' || !/^(0|[1-9][0-9]{0,19})$/.test(value) ||
      BigInt(value) < minimum || BigInt(value) > maximum) fail('invalid_pull_anchor_counter');
  return value;
}
function rawHex(value, maximum, code) {
  if (typeof value !== 'string' || !value.length || value.length > maximum * 2 ||
      value.length % 2 !== 0 || !/^[0-9a-f]+$/.test(value)) fail(code);
  return Buffer.from(value, 'hex');
}
function reference(value) {
  // Latin-1 is a one-byte mapping used only for ASCII rule checks. Never decode
  // or re-encode the native reference as UTF-8; non-UTF-8 names remain exact.
  const raw = rawHex(value, 1024, 'invalid_pull_anchor_ref').toString('latin1');
  if (!raw.startsWith('refs/heads/') || /[\x00-\x20\x7f~^:?*\[\\]/.test(raw) ||
      raw.includes('..') || raw.includes('@{') || raw.endsWith('.') ||
      raw.split('/').some(part => !part || part.startsWith('.') || part.endsWith('.lock'))) fail('invalid_pull_anchor_ref');
  return value;
}
function path(value) {
  const raw = rawHex(value, 4096, 'invalid_pull_anchor_path').toString('latin1'), parts = raw.split('/');
  if (raw.includes('\0') || parts.length > 64 ||
      parts.some(part => !part || part === '.' || part === '..')) fail('invalid_pull_anchor_path');
  return value;
}
function oid(value, format, wire) {
  if (typeof value !== 'string') fail('invalid_pull_anchor_oid');
  const raw = wire && value.startsWith(`${format}:`) ? value.slice(format.length + 1) : value;
  if (!new RegExp(`^[0-9a-f]{${format === 'sha1' ? 40 : 64}}$`).test(raw) || /^0+$/.test(raw)) fail('invalid_pull_anchor_oid');
  return raw;
}

// Local counters are canonical decimal strings, including values above the
// JavaScript safe-integer range. A wire parser must preserve native u64 tokens
// before calling this function. wire permits the producer's typed Git OIDs.
/** @param {{ wire?: boolean }} options */
export function normalizePullCommentAnchor(value, objectFormat, options = {}) {
  fields(options, ['wire'], []);
  const wire = options.wire === undefined ? false : options.wire;
  if (typeof wire !== 'boolean') fail('invalid_pull_anchor_options');
  if (!['sha1', 'sha256'].includes(objectFormat)) fail('invalid_pull_anchor_format');
  fields(value, ['profile', ...PULL_COMMENT_ANCHOR_FIELDS]);
  if (value.profile !== PULL_COMMENT_ANCHOR_PROFILE) fail('invalid_pull_anchor_profile');
  const anchor = { profile: PULL_COMMENT_ANCHOR_PROFILE,
    pull_request_version: counter(value.pull_request_version, 1n),
    source_ref_hex: reference(value.source_ref_hex), target_ref_hex: reference(value.target_ref_hex) };
  if (anchor.source_ref_hex === anchor.target_ref_hex) fail('invalid_pull_anchor_ref');
  for (const name of ['source_tip', 'target_tip', 'compared_base']) anchor[name] = oid(value[name], objectFormat, wire);
  if (!['direct', 'merge_base'].includes(value.comparison) ||
      (value.comparison === 'direct' && anchor.compared_base !== anchor.target_tip)) fail('invalid_pull_anchor_comparison');
  anchor.comparison = value.comparison;
  anchor.path_hex = path(value.path_hex);
  if (!['before', 'after'].includes(value.side)) fail('invalid_pull_anchor_side');
  anchor.side = value.side;
  anchor.blob = oid(value.blob, objectFormat, wire);
  if (!['100644', '100755', '120000'].includes(value.mode)) fail('invalid_pull_anchor_mode');
  anchor.mode = value.mode;
  anchor.byte_start = counter(value.byte_start, 0n, BLOB_BYTES - 1n);
  anchor.byte_end = counter(value.byte_end, BigInt(anchor.byte_start) + 1n, BLOB_BYTES);
  anchor.line_start = counter(value.line_start, 0n, BigInt(anchor.byte_start));
  anchor.line_count = counter(value.line_count, 1n, LINES);
  const bytes = BigInt(anchor.byte_end) - BigInt(anchor.byte_start), lines = BigInt(anchor.line_count);
  if (bytes > SPAN_BYTES || lines > bytes || (anchor.byte_start === '0') !== (anchor.line_start === '0') ||
      BigInt(anchor.line_start) + lines > BLOB_BYTES) fail('invalid_pull_anchor_range');
  return anchor;
}

// The fixed profile is implied by the native event kind. The HTTP producer
// accepts these fifteen fields and rejects a caller-supplied anchor_profile.
export function pullCommentAnchorFields(value, objectFormat) {
  const anchor = normalizePullCommentAnchor(value, objectFormat);
  return Object.fromEntries(PULL_COMMENT_ANCHOR_FIELDS.map(name => [`anchor_${name}`, anchor[name]]));
}
