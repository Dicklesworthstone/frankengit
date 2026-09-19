// Portable Git bytes, not a repository capsule or client-side object admission.
import { fail, keys, record, integer, hex, unhex, utf8, format, oid, binding, pinned,
  opaque, principal, form, rootFor, snapshot as snapshotToken } from './pulls-core.mjs';
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

// A full export must match every visible direct ref, not merely a sampled ref
// or a self-consistent pack checksum. All pages compare the selected head.
export async function exportInventory(transport, selection, checkpoint = () => {}) {
  const selected = structuredClone(selection), refs = []; let after = null, sourceHead = null, bytes = 0;
  do {
    checkpoint();
    const query = { object_format: selected.scope.format, namespace: 'all', limit: 100, expected_head: selected.head };
    if (after !== null) query.after = after;
    const { value: page } = await transport.request('source/refs', { method: 'POST', body: form(query), maximum: 1024 * 1024 });
    checkpoint(); pinned(page, selected.scope, selected.head);
    if (page.type !== 'source_refs' || page.namespace !== 'all' || page.after !== after || page.limit !== 100 ||
        page.read_only !== true || page.transaction_created !== false || page.published !== false ||
        page.direct_refs_only !== true || !Array.isArray(page.refs) || page.refs.length > 100 ||
        (sourceHead !== null && page.source_head !== sourceHead)) fail('Invalid full-export reference page.');
    sourceHead = page.source_head;
    for (const row of page.refs) {
      record(row); const name = bundleRef(row.ref_hex); bytes += name.length / 2;
      let decoded = null;
      try { decoded = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(unhex(name, 4096)); } catch {}
      if (row.ref !== decoded || (refs.length && refs.at(-1).ref_hex >= name) ||
          refs.length === REF_LIMIT || bytes > HEADER_LIMIT) fail('Invalid, repeated or oversized export inventory.');
      refs.push({ ref_hex: name, object_id: oid(row.object_id, selected.scope.format) });
    }
    if (page.next_after !== null) {
      if (typeof page.next_after !== 'string') fail('Unrepresentable export continuation.');
      const cursor = bundleRef(hex(utf8.encode(page.next_after)));
      if (page.refs.length !== 100 || refs.at(-1)?.ref_hex !== cursor || refs.length >= REF_LIMIT) fail('Incomplete or oversized export inventory.');
    }
    after = page.next_after;
  } while (after !== null);
  if (!refs.length) fail('The selected snapshot has no direct refs to export.');
  checkpoint(); return { refs, source_head: sourceHead };
}
export const EXPORT_MANIFEST_LIMIT = 1024 * 1024;
const manifestKeys = (value, names) => {
  keys(value, names); if (Object.keys(value).length !== names.length) fail('Incomplete export manifest.');
};
export function exportManifest(root, summary) {
  if (summary.snapshot_refs_checked !== true) fail('Export with a complete reference inventory before saving a manifest.');
  const { scope, snapshot, source_head, snapshot_refs_checked, ...bundle } = summary;
  const value = { type: 'frankengit-export-manifest-v1', schema_version: 1, origin: root.origin, route: root.route,
    scope, snapshot, source_head, snapshot_refs_checked, bundle, forge_state_included: false, independently_authenticated: false };
  const encoded = JSON.stringify(value, null, 2);
  if (utf8.encode(encoded).length > EXPORT_MANIFEST_LIMIT) fail('Export manifest exceeds 1 MiB.');
  return encoded;
}
export async function verifyExportManifest(input, encoded, crypto, checkpoint = () => {}) {
  if (typeof encoded !== 'string' || encoded.length > EXPORT_MANIFEST_LIMIT || utf8.encode(encoded).length > EXPORT_MANIFEST_LIMIT) fail('Export manifest exceeds 1 MiB.');
  const saved = JSON.parse(encoded);
  manifestKeys(saved, ['type', 'schema_version', 'origin', 'route', 'scope', 'snapshot', 'source_head',
    'snapshot_refs_checked', 'bundle', 'forge_state_included', 'independently_authenticated']);
  if (saved.type !== 'frankengit-export-manifest-v1' || saved.schema_version !== 1 || saved.snapshot_refs_checked !== true ||
      saved.forge_state_included !== false || saved.independently_authenticated !== false) fail('Unsupported export manifest claims.');
  manifestKeys(saved.scope, ['tenant', 'repository', 'incarnation', 'format']);
  for (const name of ['tenant', 'repository', 'incarnation']) opaque(saved.scope[name]);
  format(saved.scope.format); opaque(saved.source_head);
  // Reuse the existing route validator; no URL in a manifest is ever fetched.
  const root = rootFor(`${saved.origin}${saved.route}/ui/transfers/`, '/ui/transfers/');
  if (root.origin !== saved.origin || root.route !== saved.route) fail('Invalid export provenance route.');
  snapshotToken(saved.snapshot); checkpoint();
  const { summary } = await inspectBundle(input, crypto, checkpoint);
  if (summary.object_format !== saved.scope.format) fail('Manifest hash domain changed.');
  manifestKeys(saved.bundle, Object.keys(summary));
  for (const name of Object.keys(summary)) {
    if (name !== 'refs') { if (saved.bundle[name] !== summary[name]) fail(`Export manifest mismatch: ${name}.`); continue; }
    if (!Array.isArray(saved.bundle.refs) || saved.bundle.refs.length !== summary.refs.length) fail('Export manifest ref set changed.');
    for (let i = 0; i < summary.refs.length; i++) {
      const row = saved.bundle.refs[i]; manifestKeys(row, ['ref_hex', 'object_id']);
      if (row.ref_hex !== summary.refs[i].ref_hex || row.object_id !== summary.refs[i].object_id) fail('Export manifest ref identity changed.');
    }
  }
  checkpoint();
  // Matching bytes and an unsigned record do not authenticate its origin,
  // establish currentness, or repeat the original server-side inventory read.
  return { manifest: saved, live_snapshot_rechecked: false, independently_authenticated: false, objects_verified: false };
}
