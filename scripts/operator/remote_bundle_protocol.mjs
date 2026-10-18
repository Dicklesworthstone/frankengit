// FG-058 / FG-049: opaque bundle interchange through native admission. This
// client never parses Git objects, derives a native seal, or authorizes refs.
import { createHash, randomBytes } from 'node:crypto';
import { isDeepStrictEqual } from 'node:util';
import { outcomeEndpoint, outcomeScope, validateOutcomeReply } from './transaction_outcome.mjs';

export const BUNDLE_REMOTE_LIMITS = Object.freeze({ bundle: 64 * 1024 * 1024, intent: 1024 * 1024,
  form: 256 * 1024, reply: 16384, result: 65536, attempts: 32 });
export const encode = value => Buffer.from(`${JSON.stringify(value)}\n`);
export const hash = bytes => createHash('sha256').update(bytes).digest('hex');
export const fail = code => { const e = new Error(`remote_bundle_${code}`); e.code = e.message; throw e; };
export function fields(value, names, required = names) {
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
      ![Object.prototype, null].includes(Object.getPrototypeOf(value)) ||
      Object.keys(value).some(k => !names.includes(k)) || required.some(k => !Object.hasOwn(value, k)) ||
      Object.values(Object.getOwnPropertyDescriptors(value)).some(d => !Object.hasOwn(d, 'value'))) fail('fields');
  return value;
}
export function bounded(value, min, max) {
  if (!Number.isSafeInteger(value) || value < min || value > max) fail('limit'); return value;
}
export function pin(value) { if (typeof value !== 'string' || !/^[0-9a-f]{64}$/.test(value)) fail('pin'); return value; }
export function format(value) { if (!['sha1', 'sha256'].includes(value)) fail('format'); return value; }
export function scope(value) {
  fields(value, ['tenant_id', 'repository_id', 'repository_incarnation', 'principal_id', 'object_format']);
  return { ...outcomeBinding(value), object_format: format(value.object_format) };
}
export const outcomeBinding = value => outcomeScope(Object.fromEntries(
  ['tenant_id', 'repository_id', 'repository_incarnation', 'principal_id'].map(k => [k, value[k]])));
function reference(value, destination) {
  if (typeof value !== 'string' || !/^(?:[0-9a-f]{2}){1,4096}$/.test(value)) fail('ref');
  const raw = Buffer.from(value, 'hex').toString('latin1');
  if (!raw.startsWith('refs/') || /[\x00-\x20\x7f~^:?*\[\\]/.test(raw) || raw.includes('..') ||
      raw.includes('@{') || raw.endsWith('.') || raw.split('/').some(p => !p || p.startsWith('.') || p.endsWith('.lock')) ||
      destination && !/^refs\/(heads|remotes|tags)\/.+/.test(raw)) fail('ref');
  return value;
}
export function selection(value) {
  fields(value, ['endpoint', 'scope', 'operation', 'mappings'], ['endpoint', 'scope', 'operation']);
  if (!['import', 'fetch'].includes(value.operation)) fail('operation');
  const selected = scope(value.scope), mappings = value.mappings ?? [];
  if (!Array.isArray(mappings)) fail('mappings');
  bounded(mappings.length, value.operation === 'fetch' ? 1 : 0, value.operation === 'fetch' ? 64 : 0);
  const seen = new Set(), normalized = mappings.map(m => {
    fields(m, ['source_hex', 'destination_hex', 'expected_old']);
    const source_hex = reference(m.source_hex, false), destination_hex = reference(m.destination_hex, true);
    const old = m.expected_old;
    if (old !== 'absent' && (typeof old !== 'string' ||
        !new RegExp(`^[0-9a-f]{${selected.object_format === 'sha1' ? 40 : 64}}$`).test(old) || /^0+$/.test(old))) fail('lease');
    if (seen.has(destination_hex)) fail('duplicate_destination'); seen.add(destination_hex);
    return { source_hex, destination_hex, expected_old: old };
  });
  return { endpoint: outcomeEndpoint(value.endpoint), scope: selected, operation: value.operation, mappings: normalized };
}
function requestFor(s, descriptor, credential, nonce) {
  fields(descriptor, ['bytes', 'sha256']); bounded(descriptor.bytes, 1, BUNDLE_REMOTE_LIMITS.bundle); pin(descriptor.sha256);
  pin(credential); if (typeof nonce !== 'string' || !/^[0-9a-f]{32}$/.test(nonce)) fail('nonce');
  const body = new URLSearchParams({ object_format: s.scope.object_format, artifact_sha256: descriptor.sha256 });
  for (const m of s.mappings) body.append('mapping', `${m.source_hex}:${m.destination_hex}:${m.expected_old}`);
  if (Buffer.byteLength(body.toString()) > BUNDLE_REMOTE_LIMITS.form) fail('form_limit');
  const basis = { schema: 'frankengit-remote-bundle-intent-v1', selection: s, bundle: { ...descriptor },
    credential_sha256: credential, nonce, body: body.toString() };
  return { ...basis, key: `fgbundle1-${nonce}-${hash(encode(basis))}` };
}
export function prepareBundleRequest(raw, bytes, token) {
  pin(token);
  if (!Buffer.isBuffer(bytes) || bytes.buffer instanceof SharedArrayBuffer) fail('bundle');
  const r = requestFor(selection(raw), { bytes: bytes.length, sha256: hash(bytes) }, hash(Buffer.from(token)), randomBytes(16).toString('hex'));
  multipart(r, bytes); return r;
}
export function checkedRequest(value) {
  fields(value, ['schema', 'selection', 'bundle', 'credential_sha256', 'nonce', 'body', 'key']);
  const r = requestFor(selection(value.selection), value.bundle, value.credential_sha256, value.nonce);
  if (!encode(r).equals(encode(value))) fail('intent_changed'); return r;
}
export function checkBundle(request, bytes) {
  if (!Buffer.isBuffer(bytes) || bytes.buffer instanceof SharedArrayBuffer || bytes.length !== request.bundle.bytes ||
      hash(bytes) !== request.bundle.sha256) fail('bundle_changed');
}
export function multipart(request, bytes) {
  checkBundle(request, bytes);
  const boundary = `fg-remote-bundle-${request.nonce}`;
  if (bytes.includes(Buffer.from(`--${boundary}`))) fail('multipart_collision');
  const before = Buffer.from(`--${boundary}\r\nContent-Disposition: form-data; name="command"\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\n${request.body}\r\n--${boundary}\r\nContent-Disposition: form-data; name="bundle"; filename="repository.bundle"\r\nContent-Type: application/x-git-bundle\r\n\r\n`);
  const after = Buffer.from(`\r\n--${boundary}--\r\n`);
  return { contentType: `multipart/form-data; boundary=${boundary}`, parts: [before, bytes, after] };
}
// The wire's decision_sequence remains an exact decimal u64, never a rounded JS
// number. Canonical local records additionally reject any alternate encoding.
export function parse(bytes, maximum = BUNDLE_REMOTE_LIMITS.intent, wire = false) {
  bounded(maximum, 1, BUNDLE_REMOTE_LIMITS.intent);
  if (!Buffer.isBuffer(bytes) || bytes.length > maximum || typeof wire !== 'boolean') fail('json_limit');
  const source = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes), stack = [];
  let nodes = 0;
  for (let i = 0; i < source.length; i++) {
    const c = source[i];
    if (c === '{' || c === '[') { if (++nodes > 65536 || stack.length >= 16) fail('json_structure'); stack.push({ type: c, keys: new Set() }); }
    else if (c === '}' || c === ']') { if (stack.pop()?.type !== (c === '}' ? '{' : '[')) fail('json_structure'); }
    else if (c === '"') {
      const start = i++;
      for (; i < source.length && source[i] !== '"'; i++) if (source[i] === '\\') i++;
      if (i >= source.length || ++nodes > 65536) fail('json_structure');
      let next = i + 1; while (next < source.length && /[\x20\t\r\n]/.test(source[next])) next++;
      if (source[next] === ':') {
        const current = stack.at(-1), key = JSON.parse(source.slice(start, i + 1));
        if (current?.type !== '{' || current.keys.has(key)) fail('duplicate_json_key'); current.keys.add(key);
      }
    }
  }
  if (stack.length) fail('json_structure');
  return JSON.parse(source, (key, value, ctx) => {
    if (typeof value !== 'number') return value;
    if (!/^(0|[1-9][0-9]*)$/.test(ctx.source)) fail('json_number');
    if (wire && key === 'decision_sequence') return sequence(ctx.source);
    return bounded(value, 0, Number.MAX_SAFE_INTEGER);
  });
}
export function canonical(bytes, maximum) { const value = parse(bytes, maximum); if (!encode(value).equals(bytes)) fail('encoding'); return value; }
function sequence(value) {
  if (typeof value !== 'string' || !/^[1-9][0-9]{0,19}$/.test(value) || BigInt(value) > 18446744073709551615n) fail('sequence'); return value;
}
function opaque(value) {
  if (typeof value !== 'string' || !value || Buffer.byteLength(value) > 256 || /[\s\x00-\x1f\x7f-\x9f\uD800-\uDFFF]/u.test(value)) fail('identity');
}
export function publication(value, request, status) {
  const s = request.selection.scope;
  fields(value, ['type', 'schema_version', 'operation', ...Object.keys(s), 'tx_id', 'decision_sequence', 'command_count',
    'outcome', 'decision', 'atomic', 'terminal', 'forge_state_imported', 'default_branch_changed', 'receipt_confirms_transport_revalidation']);
  if (value.type !== 'source_bundle_publication' || value.schema_version !== 1 || Object.keys(s).some(k => s[k] !== value[k]) ||
      value.operation !== request.selection.operation || value.atomic !== true || value.terminal !== true ||
      value.forge_state_imported !== false || value.default_branch_changed !== false || value.receipt_confirms_transport_revalidation !== false ||
      !['committed', 'refused'].includes(value.outcome) || status !== (value.outcome === 'committed' ? 200 : 409)) fail('publication');
  bounded(value.command_count, 1, 4096);
  if (request.selection.operation === 'fetch' && value.command_count !== request.selection.mappings.length) fail('mapping_count');
  opaque(value.tx_id); sequence(value.decision_sequence);
  const d = fields(value.decision, value.outcome === 'committed' ? ['repository_commit_id'] : ['code', 'code_point', 'refusal_record_id']);
  if (value.outcome === 'committed') opaque(d.repository_commit_id);
  else { opaque(d.code); opaque(d.refusal_record_id); bounded(d.code_point, 0, 65535); }
  return structuredClone(value);
}
export function mergeObservation(previous, next, request) {
  fields(next, ['outcome', 'publication']);
  const binding = outcomeBinding(request.selection.scope);
  const outcome = next.outcome === null ? null : validateOutcomeReply(next.outcome, binding);
  const pub = next.publication === null ? null : publication(next.publication, request, next.publication.outcome === 'committed' ? 200 : 409);
  let selected = previous.outcome;
  if (outcome) {
    if (!selected) selected = outcome;
    else {
      try { selected = validateOutcomeReply(outcome, binding, selected); }
      catch { validateOutcomeReply(selected, binding, outcome); } // Only a compatible weaker observation may arrive late.
    }
  }
  if (previous.publication && pub && !isDeepStrictEqual(previous.publication, pub)) fail('publication_conflict');
  const result = { outcome: selected, publication: previous.publication ?? pub };
  const p = result.publication, o = result.outcome;
  if (p && o?.transaction && o.transaction.tx_id !== p.tx_id) fail('transaction_conflict');
  if (p && o?.terminal && (o.state !== p.outcome || o.decision.decision_sequence !== p.decision_sequence ||
      !isDeepStrictEqual(Object.fromEntries(Object.entries(o.decision).filter(([k]) => !['kind', 'decision_sequence'].includes(k))), p.decision))) fail('terminal_conflict');
  return result;
}
