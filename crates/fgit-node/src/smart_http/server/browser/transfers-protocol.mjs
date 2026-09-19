// Portable Git bytes, not a repository capsule or client-side object admission.
import { fail, keys, record, integer, hex, unhex, utf8, format, oid, binding, pinned,
  opaque, principal, form } from './pulls-core.mjs';
import { digest, BUNDLE_LIMIT } from './pulls-candidate.mjs';
export { BUNDLE_LIMIT };
export const HEADER_LIMIT = 256 * 1024, REF_LIMIT = 1024, MAPPING_LIMIT = 64;
export const EXPORT_HEADERS = Object.freeze(['x-fgit-bundle-profile', 'x-fgit-object-format', 'x-fgit-tenant',
  'x-fgit-repository', 'x-fgit-repository-incarnation', 'x-fgit-source-head', 'x-fgit-snapshot',
  'x-fgit-artifact-sha256', 'x-fgit-read-only']);
export function bundleRef(value) {
  const bytes = unhex(value, 4096), raw = Array.from(bytes, b => String.fromCharCode(b)).join('');
  if (!raw.startsWith('refs/') || bytes.some(b => b <= 32 || b === 127) || /[~^:?*\[\\]/.test(raw) ||
      raw.includes('..') || raw.includes('@{') || raw.endsWith('.') ||
      raw.split('/').some(p => !p || p.startsWith('.') || p.endsWith('.lock'))) fail('Invalid bundle reference bytes.');
  return value;
}
function ascii(bytes) {
  if (bytes.some(b => b > 127)) fail('Non-ASCII bundle control record.');
  return Array.from(bytes, b => String.fromCharCode(b)).join('');
}
// Parse the small advertised-ref envelope and verify the pack trailer. Never
// inflate objects or pretend a transport checksum authenticates Git closure.
export async function inspectBundle(input, crypto, checkpoint = () => {}) {
  if (!(input instanceof Uint8Array) || !input.length || input.length > BUNDLE_LIMIT) fail('Choose a nonempty bundle of at most 16 MiB.');
  const bytes = input.slice(); checkpoint(); let cursor = 0, records = 0, capability = false, algorithm = 'sha1', head = null;
  const line = () => {
    const start = cursor, end = Math.min(bytes.length, HEADER_LIMIT);
    while (cursor < end && bytes[cursor] !== 10) cursor++;
    if (cursor === end) fail('Bundle header exceeds 256 KiB or is truncated.');
    return bytes.subarray(start, cursor++);
  };
  const signature = ascii(line());
  if (!['# v2 git bundle', '# v3 git bundle'].includes(signature)) fail('Unsupported Git bundle signature.');
  const refs = new Map();
  while (true) {
    checkpoint(); const row = line(); if (!row.length) break;
    if (row[0] === 64) {
      if (signature !== '# v3 git bundle' || capability || records) fail('Misplaced or duplicate bundle capability.');
      const value = ascii(row);
      if (!['@object-format=sha1', '@object-format=sha256'].includes(value)) fail('Unsupported bundle capability or filter.');
      algorithm = value.slice('@object-format='.length); capability = true; continue;
    }
    if (row[0] === 45) fail('This full-bundle HTTP profile does not accept prerequisites.');
    if (++records > REF_LIMIT) fail('Bundle exceeds 1024 advertised references.');
    const width = algorithm === 'sha1' ? 40 : 64;
    if (row.length <= width + 1 || row[width] !== 32) fail('Invalid bundle reference record.');
    const id = oid(ascii(row.subarray(0, width)).toLowerCase(), algorithm), name = row.subarray(width + 1);
    if (hex(name) === '48454144') { if (head !== null) fail('Duplicate HEAD advertisement.'); head = id; }
    else {
      const path = bundleRef(hex(name)); if (refs.has(path)) fail('Duplicate bundle reference.');
      refs.set(path, { ref_hex: path, object_id: id });
    }
  }
  if (!refs.size) fail('Bundle has no direct refs.');
  if (head !== null && ![...refs.values()].some(r => r.ref_hex.startsWith(hex(utf8.encode('refs/heads/'))) && r.object_id === head)) fail('Detached or unadvertised bundle HEAD.');
  const pack = bytes.subarray(cursor), width = algorithm === 'sha1' ? 20 : 32;
  if (pack.length < 12 + width || ascii(pack.subarray(0, 4)) !== 'PACK') fail('Truncated or missing native pack.');
  const header = new DataView(pack.buffer, pack.byteOffset, 12);
  if (header.getUint32(4) !== 2) fail('This browser profile requires pack version 2.');
  checkpoint();
  const actual = hex(new Uint8Array(await crypto.subtle.digest(algorithm === 'sha1' ? 'SHA-1' : 'SHA-256', pack.subarray(0, -width))));
  checkpoint(); if (actual !== hex(pack.subarray(-width))) fail('Native pack trailer checksum mismatch.');
  const sha256 = await digest(bytes, crypto); checkpoint();
  return { bytes, summary: { object_format: algorithm, bytes: bytes.length, sha256, header_bytes: cursor,
    declared_pack_objects: header.getUint32(8), pack_checksum_verified: true, objects_verified: false,
    advertised_head: head, refs: [...refs.values()].sort((a, b) => a.ref_hex < b.ref_hex ? -1 : 1) } };
}
export function transferCommand(operation, summary, input = []) {
  if (!['import', 'fetch'].includes(operation)) fail('Unsupported bundle publication operation.');
  if (!Array.isArray(input)) fail('Mappings must be an explicit array.');
  const fields = { object_format: format(summary.object_format), artifact_sha256: summary.sha256 };
  if (!/^[0-9a-f]{64}$/.test(fields.artifact_sha256)) fail('Invalid artifact commitment.');
  let updates;
  if (operation === 'import') {
    if (input.length || summary.refs.length > MAPPING_LIMIT) fail('Import requires no mappings and at most 64 direct refs; use an explicit fetch subset.');
    updates = summary.refs.map(r => ({ source_hex: r.ref_hex, destination_hex: r.ref_hex, expected_old: null, new_commit: r.object_id }));
  } else {
    if (!input.length || input.length > MAPPING_LIMIT) fail('Select 1 through 64 explicit fetch mappings.');
    const destinations = new Set(), sources = new Map(summary.refs.map(r => [r.ref_hex, r.object_id]));
    updates = input.map(row => {
      keys(row, ['source_hex', 'destination_hex', 'expected_old']);
      const source = bundleRef(row.source_hex), destination = bundleRef(row.destination_hex);
      if (!sources.has(source)) fail('Mapping source is not advertised by this bundle.');
      if (destinations.has(destination)) fail('Duplicate mapped destination.'); destinations.add(destination);
      return { source_hex: source, destination_hex: destination,
        expected_old: row.expected_old === null ? null : oid(row.expected_old, fields.object_format), new_commit: sources.get(source) };
    }).sort((a, b) => a.destination_hex < b.destination_hex ? -1 : 1);
    fields.mapping = updates.map(r => `${r.source_hex}:${r.destination_hex}:${r.expected_old ?? 'absent'}`);
  }
  form(fields); return { fields, updates, count: updates.length };
}
export function exportIdentity(response, selected) {
  const h = record(response.headers);
  if (response.status !== 200 || response.type !== 'application/x-git-bundle' || h['x-fgit-bundle-profile'] !== 'full-v1' || h['x-fgit-read-only'] !== 'true') fail('Response is not a read-only native full bundle.');
  const observed = pinned({ schema_version: 1, tenant_id: h['x-fgit-tenant'], repository_id: h['x-fgit-repository'],
    repository_incarnation: h['x-fgit-repository-incarnation'], object_format: h['x-fgit-object-format'],
    source_head: h['x-fgit-source-head'], snapshot_token: h['x-fgit-snapshot'] }, selected.scope, selected.head);
  if (!/^[0-9a-f]{64}$/.test(h['x-fgit-artifact-sha256'])) fail('Missing export artifact commitment.');
  return { scope: observed.binding, head: observed.head, sha256: h['x-fgit-artifact-sha256'] };
}
export function transferPublication(reply, pending, status) {
  binding(reply, pending.scope); principal(reply.principal_id); opaque(reply.tx_id);
  integer(reply.decision_sequence, 'decision sequence', 1);
  if (reply.type !== 'source_bundle_publication' || reply.operation !== pending.operation || reply.command_count !== pending.count ||
      reply.atomic !== true || reply.terminal !== true || reply.forge_state_imported !== false || reply.default_branch_changed !== false ||
      reply.receipt_confirms_transport_revalidation !== false || !['committed', 'refused'].includes(reply.outcome) ||
      status !== (reply.outcome === 'committed' ? 200 : 409)) fail('Response is not the matching atomic bundle decision.');
  const decision = record(reply.decision);
  if (pending.observedTx && reply.tx_id !== pending.observedTx) fail('Bundle transaction changed.');
  if (pending.observedPrincipal && reply.principal_id !== pending.observedPrincipal) fail('Bundle principal changed.');
  if (reply.outcome === 'committed') {
    opaque(decision.repository_commit_id);
    if ('code' in decision || 'code_point' in decision || 'refusal_record_id' in decision) fail('Contradictory bundle decision.');
  } else {
    opaque(decision.refusal_record_id); opaque(decision.code); integer(decision.code_point, 'refusal code', 0, 65535);
    if ('repository_commit_id' in decision) fail('Contradictory bundle decision.');
  }
  return { terminal: true, outcome: reply.outcome, tx: reply.tx_id, principal: reply.principal_id,
    rcr: decision.repository_commit_id ?? null, refusal: decision.code ?? null, deliveryAcknowledged: null };
}
