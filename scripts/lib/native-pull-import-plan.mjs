// Deterministic PR portability compilation over an independently pinned archive.
// Only open/comment/close are emitted. Source votes and actors remain attribution.
import { pullFields, pullScope, pullU64, pullCommand, pullHash } from '../operator/pull_command.mjs';
import { outcomeEndpoint } from '../operator/transaction_outcome.mjs';
import { branch, oid } from '../../crates/fgit-node/src/smart_http/server/browser/pulls-core.mjs';

export const PULL_IMPORT_LIMITS = Object.freeze({ steps: 8192, sourceBytes: 64 * 1024 * 1024,
  requestBytes: 64 * 1024 * 1024, recordBytes: 32 * 1024 * 1024, attempts: 32 });
export const IMPORT_SCHEMA = 'frankengit-native-pull-import-v1';
export const importFail = code => { const e = new Error(`pull_import_${code}`); e.code = e.message; throw e; };
const bounded = (n, max) => {
  if (!Number.isSafeInteger(n) || n < 1 || n > max) importFail('limit'); return n;
};
export function pullImportSelection(raw) {
  const required = ['endpoint', 'scope', 'number_start'];
  pullFields(raw, [...required, 'merged', 'ref_map', 'max_steps', 'max_source_bytes', 'max_request_bytes'], required);
  const endpoint = outcomeEndpoint(raw.endpoint), scope = pullScope(raw.scope);
  const number_start = pullU64(raw.number_start, 1n), merged = raw.merged ?? 'refuse', refs = raw.ref_map ?? [];
  if (!['refuse', 'as-closed'].includes(merged) || !Array.isArray(refs) || refs.length > 8192) importFail('selection');
  const ref_map = [], seen = new Set();
  for (const item of refs) {
    pullFields(item, ['source_hex', 'destination']);
    if (typeof item.source_hex !== 'string' || !/^(?:[0-9a-f]{2}){1,1024}$/.test(item.source_hex) || seen.has(item.source_hex)) importFail('ref_mapping');
    seen.add(item.source_hex); ref_map.push({ source_hex: item.source_hex, destination: branch(item.destination) });
  }
  ref_map.sort((a, b) => a.source_hex < b.source_hex ? -1 : a.source_hex > b.source_hex ? 1 : 0);
  return { endpoint, scope, number_start, merged, ref_map,
    max_steps: bounded(raw.max_steps ?? PULL_IMPORT_LIMITS.steps, PULL_IMPORT_LIMITS.steps),
    max_source_bytes: bounded(raw.max_source_bytes ?? PULL_IMPORT_LIMITS.sourceBytes, PULL_IMPORT_LIMITS.sourceBytes),
    max_request_bytes: bounded(raw.max_request_bytes ?? PULL_IMPORT_LIMITS.requestBytes, PULL_IMPORT_LIMITS.requestBytes) };
}
function chunks(text) {
  // Validated native UTF-8 text; split only between complete code points. Retain
  // CRLF, BOM and EOF bytes. The per-part hash names the original whole body.
  const bytes = Buffer.from(text), result = []; let start = 0;
  do {
    let end = Math.min(start + 48 * 1024, bytes.length);
    while (end < bytes.length && (bytes[end] & 0xc0) === 0x80) end--;
    result.push(bytes.subarray(start, end).toString('utf8')); start = end;
  } while (start < bytes.length);
  return result;
}
export function compilePullImport(source, rawSelection) {
  const s = pullImportSelection(rawSelection), m = source.manifest;
  if (m.object_format !== s.scope.object_format) importFail('hash_domain_change');
  if (m.tenant_id === s.scope.tenant_id && m.repository_id === s.scope.repository_id &&
      m.repository_incarnation === s.scope.repository_incarnation) importFail('same_repository');
  if (source.bytes > s.max_source_bytes) importFail('source_limit');
  const refs = new Map(s.ref_map.map(r => [r.source_hex, r.destination])), used = new Set(), destinations = new Map();
  const steps = [], mapping = []; let encodedBytes = 0;
  function ref(data, side) {
    const bytes = data[`${side}_ref_hex`];
    const value = refs.has(bytes) ? (used.add(bytes), refs.get(bytes)) : data[`${side}_ref`];
    if (value === null) importFail('byte_only_ref_needs_mapping');
    branch(value);
    if (destinations.has(value) && destinations.get(value) !== bytes) importFail('ref_mapping_alias');
    destinations.set(value, bytes); return value;
  }
  function add(sourceNumber, number, action, fields) {
    if (steps.length >= s.max_steps) importFail('step_limit');
    const command = pullCommand(number, action, fields, s.scope.object_format);
    encodedBytes += Buffer.byteLength(command.body);
    if (encodedBytes > s.max_request_bytes) importFail('request_limit');
    steps.push({ source_number: sourceNumber, ...command });
  }
  for (const [i, entry] of source.entries.entries()) {
    const row = entry.row, data = row.data, target = String(BigInt(s.number_start) + BigInt(i));
    pullU64(target, 1n);
    if (!data || row.merge_only) importFail('merge_only_metadata_unavailable');
    if (row.state === 'merged' && s.merged !== 'as-closed') importFail('merged_requires_closed_consent');
    const fields = { source_ref: ref(data, 'source'), target_ref: ref(data, 'target'),
      source_tip: oid(data.source_tip, s.scope.object_format), target_tip: oid(data.target_tip, s.scope.object_format),
      title: data.title, body: data.body };
    mapping.push({ source: row.number, destination: target, source_state: row.state,
      destination_state: row.state === 'open' ? 'open' : 'closed' });
    add(row.number, target, 'open', { expected_version: '0', ...fields });
    let discussion = 0;
    const comment = body => add(row.number, target, 'comment', { expected_version: String(discussion++), body });
    const provenance = { archive_sha256: source.archiveSha256, href: m.href, tenant_id: m.tenant_id,
      repository_id: m.repository_id, repository_incarnation: m.repository_incarnation,
      snapshot_token: m.snapshot_token, source_head: m.source_head, source_number: row.number,
      metadata_version: row.version, source_state: row.state, opened_by: row.opened_by,
      last_metadata_actor: row.last_metadata_actor, source_ref_hex: data.source_ref_hex,
      target_ref_hex: data.target_ref_hex, source_tip: data.source_tip, target_tip: data.target_tip,
      merge: row.merge, destination_state: row.state === 'open' ? 'open' : 'closed' };
    comment(`Imported PR provenance. Source identities are attribution only; no approval or merge authority is imported.\n\n${JSON.stringify(provenance)}`);
    const attributed = (kind, metadata, text) => {
      const parts = chunks(text), sha256 = pullHash(Buffer.from(text));
      for (const [part, body] of parts.entries()) {
        const header = { source_number: row.number, kind, ...metadata, body_sha256: sha256, part: part + 1, parts: parts.length };
        comment(`Imported ${kind} observation (not a destination review or approval).\n${JSON.stringify(header)}\n\n${body}`);
      }
    };
    for (const c of entry.comments) attributed('comment', { version: c.version, actor: c.actor }, c.body);
    for (const r of entry.reviews) {
      const { reason, ...metadata } = r; attributed('review', metadata, reason);
    }
    if (row.state !== 'open') add(row.number, target, 'close', { expected_version: '1', ...fields });
  }
  if (used.size !== refs.size) importFail('unused_ref_mapping');
  return { selection: s, steps, mapping, encodedBytes };
}
