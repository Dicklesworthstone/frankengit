// Native tag bytes and read reports, never signature or publication authority.
import { fail, keys, record, integer, text, format, oid, hex, unhex, utf8, form, pinned,
  binding, principal, opaque } from './pulls-core.mjs';
export const TAG_LIMITS = Object.freeze({ max_tags: 32, max_object_bytes: 512 * 1024, max_total_bytes: 2 * 1024 * 1024 });
export const RETRY_LIMIT = 256 * 1024;
const kinds = ['commit', 'tree', 'blob', 'tag'];
export const decode = bytes => new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes);
export function nativeRef(value, prefix = 'refs/') {
  const bytes = unhex(value, 4096), raw = Array.from(bytes, b => String.fromCharCode(b)).join('');
  if (!raw.startsWith(prefix) || raw.length <= prefix.length || bytes.some(b => b <= 32 || b === 127) ||
      /[~^:?*\[\\]/.test(raw) || raw.includes('..') || raw.includes('@{') || raw.endsWith('.') ||
      raw.split('/').some(p => !p || p.startsWith('.') || p.endsWith('.lock'))) fail('Invalid native reference.');
  return bytes;
}
export function refInput(value, rawHex = false) {
  const encoded = rawHex ? value : hex(utf8.encode(text(value, 4096, 'reference')));
  nativeRef(encoded, 'refs/tags/'); return encoded;
}
export function tagFields(operation, input) {
  const extra = { lightweight: ['target'], annotated: ['target', 'target_kind', 'tagger', 'timestamp', 'message_hex'], delete: ['expected_object'] };
  if (!Object.hasOwn(extra, operation)) fail('Unsupported tag operation.');
  keys(input, ['object_format', 'ref_hex', ...extra[operation]]);
  const result = { object_format: format(input.object_format), ref_hex: input.ref_hex };
  nativeRef(result.ref_hex, 'refs/tags/');
  if (operation === 'delete') result.expected_object = oid(input.expected_object, result.object_format);
  else result.target = oid(input.target, result.object_format);
  if (operation === 'annotated') {
    if (!kinds.includes(input.target_kind)) fail('Explicit native target kind is required.');
    const tagger = text(input.tagger, 1024, 'tagger'), at = tagger.lastIndexOf(' <');
    const person = tagger.slice(0, at), email = tagger.slice(at + 2, -1);
    if (at < 0 || !person.trim() || /[<>]/.test(person) || !tagger.endsWith('>') || !email || /[<>]/.test(email) || /[\x00-\x1f\x7f]/.test(tagger)) fail('Invalid explicit tagger identity.');
    const message = unhex(input.message_hex, 64 * 1024);
    if (message.includes(0)) fail('Native tag creation does not accept NUL in messages.');
    Object.assign(result, { target_kind: input.target_kind, tagger,
      timestamp: integer(input.timestamp, 'tag timestamp'), message_hex: input.message_hex });
  }
  form(result); return result;
}
function concat(...parts) {
  const result = new Uint8Array(parts.reduce((n, p) => n + p.length, 0)); let offset = 0;
  for (const part of parts) { result.set(part, offset); offset += part.length; } return result;
}
export async function tagObjectId(body, algorithm, crypto) {
  format(algorithm);
  const bytes = concat(utf8.encode(`tag ${body.length}\0`), body);
  return hex(new Uint8Array(await crypto.subtle.digest(algorithm === 'sha1' ? 'SHA-1' : 'SHA-256', bytes)));
}
export async function tagPlan(operation, input, crypto) {
  const fields = tagFields(operation, input);
  if (operation !== 'annotated') return { fields, body_hex: null,
    expected_object: fields.expected_object ?? null, new_object: fields.target ?? null };
  const body = concat(utf8.encode(`object ${fields.target}\ntype ${fields.target_kind}\ntag `),
    nativeRef(fields.ref_hex, 'refs/tags/').subarray(10),
    utf8.encode(`\ntagger ${fields.tagger} ${fields.timestamp} +0000\n\n`), unhex(fields.message_hex));
  return { fields, body_hex: hex(body), expected_object: null,
    new_object: await tagObjectId(body, fields.object_format, crypto) };
}
export function tagRefPage(reply, query, scope) {
  const selected = pinned(reply, scope, query.expected_head ?? null);
  if (reply.type !== 'source_refs' || selected.binding.format !== query.object_format || reply.namespace !== 'all' ||
      reply.after !== (query.after ?? null) || reply.limit !== query.limit || reply.direct_refs_only !== true ||
      reply.read_only !== true || reply.transaction_created !== false || reply.published !== false ||
      !Array.isArray(reply.refs) || reply.refs.length > query.limit) fail('Invalid tag/source reference page.');
  let previous = query.after === undefined ? '' : hex(utf8.encode(query.after));
  for (const row of reply.refs) {
    record(row); const bytes = nativeRef(row.ref_hex); oid(row.object_id, query.object_format);
    let decoded = null; try { decoded = decode(bytes); } catch {}
    if (row.ref !== decoded || row.ref_hex <= previous) fail('Reference bytes, order or cursor changed.');
    previous = row.ref_hex;
  }
  if (reply.next_after !== null) {
    text(reply.next_after, 4096, 'cursor'); nativeRef(hex(utf8.encode(reply.next_after)));
    if (reply.refs.length !== query.limit || previous !== hex(utf8.encode(reply.next_after))) fail('Incomplete reference continuation.');
  }
  return selected;
}
// Bind the identity and target edges to original tag bodies. The final peeled
// object's existence/kind and signature classification remain native claims.
export async function tagInspection(reply, expected, crypto, checkpoint = () => {}) {
  pinned(reply, expected.scope, expected.head); nativeRef(reply.ref_hex, 'refs/tags/');
  if (reply.type !== 'source_tag' || reply.ref_hex !== expected.ref_hex || reply.object_id !== expected.object_id ||
      reply.read_only !== true || reply.transaction_created !== false || reply.published !== false ||
      reply.signature_verified !== false || reply.tagger_is_authenticated_principal !== false ||
      !kinds.slice(0, 3).includes(reply.peeled_kind) || !Array.isArray(reply.annotations) ||
      reply.annotations.length > TAG_LIMITS.max_tags || reply.annotation_count !== reply.annotations.length) fail('Invalid pinned tag inspection.');
  let target = oid(reply.object_id, expected.scope.format), total = 0; const seen = new Set();
  for (let i = 0; i < reply.annotations.length; i++) {
    checkpoint(); const annotation = record(reply.annotations[i]);
    const bytes = unhex(annotation.body_hex, TAG_LIMITS.max_object_bytes);
    total += bytes.length;
    if (total > TAG_LIMITS.max_total_bytes || annotation.body_bytes !== bytes.length || annotation.object_id !== target || seen.has(target) ||
        annotation.signature_verified !== false || !['absent', 'opaque_unverifiable'].includes(annotation.signature)) fail('Invalid or excessive tag annotation.');
    seen.add(target);
    const following = i + 1 === reply.annotations.length ? reply.peeled_kind : 'tag';
    oid(annotation.target, expected.scope.format);
    const prefix = utf8.encode(`object ${annotation.target}\ntype ${following}\ntag `);
    const nameEnd = bytes.indexOf(10, prefix.length);
    if (annotation.target_kind !== following || bytes.length <= prefix.length || prefix.some((b, n) => bytes[n] !== b) ||
        nameEnd <= prefix.length || !bytes.some((b, n) => n >= nameEnd && b === 10 && bytes[n + 1] === 10)) fail('Annotation target or kind differs from its original bytes.');
    const actual = await tagObjectId(bytes, expected.scope.format, crypto); checkpoint();
    if (actual !== target) fail('Native tag object hash mismatch.'); target = annotation.target;
  }
  if (target !== oid(reply.peeled_object, expected.scope.format) || seen.has(target)) fail('Broken or cyclic tag chain.');
  checkpoint(); return reply;
}
export function tagPublication(reply, pending, status) {
  binding(reply, pending.scope); principal(reply.principal_id); opaque(reply.tx_id);
  integer(reply.decision_sequence, 'decision sequence', 1);
  if (reply.type !== 'tag_publication' || reply.operation !== pending.operation || reply.ref_hex !== pending.fields.ref_hex ||
      reply.expected_object !== pending.expected_object || reply.new_object !== pending.new_object || reply.force !== false ||
      reply.forge_transition !== false || reply.signature_verified !== false || reply.tagger_is_authenticated_principal !== false ||
      reply.atomic !== true || reply.terminal !== true || !['committed', 'refused'].includes(reply.outcome) ||
      status !== (reply.outcome === 'committed' ? 200 : 409)) fail('Response is not the matching native tag decision.');
  if (pending.observedTx && pending.observedTx !== reply.tx_id) fail('Tag transaction changed.');
  if (pending.observedPrincipal && pending.observedPrincipal !== reply.principal_id) fail('Tag principal changed.');
  if (reply.outcome === 'committed') {
    opaque(reply.repository_commit_id);
    if ('code' in reply || 'code_point' in reply || 'refusal_record_id' in reply) fail('Conflicting tag decisions.');
  } else {
    opaque(reply.code); opaque(reply.refusal_record_id); integer(reply.code_point, 'refusal code', 0, 65535);
    if ('repository_commit_id' in reply) fail('Conflicting tag decisions.');
  }
  return { terminal: true, outcome: reply.outcome, tx: reply.tx_id, principal: reply.principal_id,
    rcr: reply.repository_commit_id ?? null, refusal: reply.code ?? null };
}
