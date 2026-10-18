// Explicit declaration descriptors model the native wire schema; no Rust parser
// or native node is simulated. Tests independently supply declaration locations.
import { createHash } from 'node:crypto';
import { input, report, defaults, hex } from './source_context_fixtures.mjs';
export { input, hex };
export const symbolInput = (format = 'sha1', patch = {}) => input(format, {
  symbols: { name: 'Recover', match: 'prefix', policy: 'required' }, ...patch,
});
export const FILES = [
  { path: Buffer.from('a/Recover.rs'), bytes: Buffer.from('pub fn Recover() {}\r\npub fn RecoverLater() {}\n') },
  { path: Buffer.from('docs/note.txt'), bytes: Buffer.from('Recover is untrusted data.\n') },
  { path: Buffer.from('ff2e7273', 'hex'), bytes: Buffer.from('pub fn RecoverRaw() {}\n') },
];
export const DECLARATIONS = [
  { path: FILES[0].path, name: 'Recover', at: 7 },
  { path: FILES[0].path, name: 'RecoverLater', at: 28 },
  { path: FILES[2].path, name: 'RecoverRaw', at: 7 },
];
export function nativeSymbols(q = symbolInput(), files = FILES, declarations = DECLARATIONS, unavailable = null) {
  const response = report(q, files), r = response.retrieval, limits = { ...defaults, ...q.limits };
  const options = { match: 'exact', policy: 'optional', kinds: [], ...q.symbols };
  const format = q.scope.object_format;
  if (unavailable !== null) {
    r.symbols = { state: 'unavailable', reason: unavailable, result: null };
  } else {
    const rows = declarations.filter(d => (options.match === 'exact' ? d.name === options.name : d.name.startsWith(options.name)) &&
      (!options.kinds.length || options.kinds.includes(d.kind ?? 'function')) &&
      (!q.prefixes_hex?.length || q.prefixes_hex.some(p => hex(d.path) === p || hex(d.path).startsWith(`${p}2f`))))
      .map(d => {
        const f = files.find(f => hex(f.path) === hex(d.path)), bytes = Buffer.from(f.bytes), prefix = bytes.subarray(0, d.at);
        const start = prefix.lastIndexOf(10) + 1, next = bytes.indexOf(10, d.at), end = next < 0 ? bytes.length : next;
        const blob = createHash(format).update(`blob ${bytes.length}\0`).update(bytes).digest('hex');
        return { name_hex: hex(d.name), kind: d.kind ?? 'function', raw_identifier: d.raw ?? false,
          path_hex: hex(d.path), blob: `${format}:${blob}`, byte_offset: d.at,
          line: prefix.filter(b => b === 10).length + 1, byte_column: d.at - start + 1, match_length: d.name.length,
          excerpt_hex: hex(bytes.subarray(start, end)), excerpt_offset: start, match_truncated_in_excerpt: false };
      }).sort((a, b) => a.path_hex < b.path_hex ? -1 : a.path_hex > b.path_hex ? 1 : a.byte_offset - b.byte_offset);
    const matches = rows.slice(0, limits.max_results_per_channel), complete = matches.length === rows.length;
    const source = Object.fromEntries(['tenant_id', 'repository_id', 'repository_incarnation', 'object_format', 'ref', 'ref_hex',
      'read_only', 'transaction_created', 'snapshot_token', 'source_rcr', 'source_commit', 'root_tree'].map(k => [k, r[k]]));
    const rust = files.filter(f => hex(f.path).endsWith('2e7273'));
    r.generation_vector.symbols = { index_token: `alg:2:${'e'.repeat(64)}`, index_number: 4 };
    r.symbols = { state: 'available', result: { ...source, ...r.generation_vector.symbols,
      type: 'source_search_symbols_index', schema_version: 1, profile: 'rust-declaration-heads-v1',
      index_profile: 'rust-declaration-tables-v1', authority_class: 'deterministic-derived',
      compiler_resolved: false, macro_expansion: false, cfg_evaluated: false, source_head: 'fixture-head', published: false,
      source_blobs_read: 0, source_bytes_read: 0, name_hex: hex(options.name), match: options.match,
      complete, completion: complete ? 'complete' : 'match_limit', max_matches: limits.max_results_per_channel,
      returned_matches: matches.length, indexed_files: rust.length, indexed_declarations: declarations.length,
      indexed_source_bytes: rust.reduce((n, f) => n + f.bytes.length, 0), unsupported_language_files: files.length - rust.length,
      non_regular_entries: 0, tables_read: new Set(matches.map(m => m.path_hex)).size, payload_bytes_read: 128 + matches.length * 50,
      max_work: 16777216, work_units: matches.length + 1, kinds: [...new Set(options.kinds)].sort(),
      path_prefix_hex: [...new Set(q.prefixes_hex ?? [])].sort(), matches } };
  }
  return assemble(response, q, files);
}
export function assemble(response, q, files, selectedPaths = null) {
  const r = response.retrieval, limits = { ...defaults, ...q.limits }, symbol = r.symbols.state === 'available' ? r.symbols.result : null;
  const coverage = [r.content, r.path, ...(symbol ? [symbol] : [])].every(c => c.coverage_complete !== false);
  r.complete = coverage && r.content.complete && r.path.complete && (symbol ? symbol.complete : r.symbols.state === 'not_requested');
  r.retained_result_bytes = [r.content, r.path].reduce((n, c) => n + c.hits.reduce((m, h) => m + h.path_hex.length / 2 + 24 * h.spans.length + 64, 0)
    + (c.omissions ?? []).reduce((m, o) => m + o.path_hex.length / 2 + 96, 0), 0);
  if (symbol) r.retained_result_bytes += symbol.matches.reduce((n, h) => n + h.path_hex.length / 2 + h.name_hex.length / 2 + h.excerpt_hex.length / 2 + 96, 0)
    + (symbol.omissions ?? []).reduce((n, o) => n + o.path_hex.length / 2 + 96, 0);
  r.completed_payload_bytes_read = r.content.payload_bytes_read + r.path.payload_bytes_read + (symbol?.payload_bytes_read ?? 0);
  r.completed_work_units = r.content.work_units + r.path.work_units + (symbol?.work_units ?? 0);
  const union = [...new Set([...r.content.hits, ...r.path.hits, ...(symbol?.matches ?? [])].map(h => h.path_hex))].sort();
  const selected = (selectedPaths ?? union.slice(0, limits.context_max_files)).slice().sort();
  response.files = selected.map(path => {
    const f = files.find(f => hex(f.path) === path), bytes = Buffer.from(f.bytes), anchors = [];
    for (const channel of ['content', 'path']) for (const hit of r[channel].hits.filter(h => h.path_hex === path))
      for (const span of hit.spans) anchors.push({ channel, byte_offset: span.byte_offset, byte_length: span.byte_length });
    for (const h of symbol?.matches.filter(h => h.path_hex === path) ?? []) anchors.push({ channel: 'symbol', byte_offset: h.byte_offset, byte_length: h.match_length });
    const ordered = [...new Map(anchors.map(a => [JSON.stringify(a), a])).values()].sort((a, b) =>
      a.channel.localeCompare(b.channel, 'en') || a.byte_offset - b.byte_offset || a.byte_length - b.byte_length);
    const windows = ordered.filter(a => a.channel !== 'path').map(a => [Math.max(0, a.byte_offset - limits.context_radius_bytes),
      Math.min(bytes.length, a.byte_offset + a.byte_length + limits.context_radius_bytes)]).sort((a, b) => a[0] - b[0] || a[1] - b[1]);
    if (!windows.length) windows.push([0, Math.min(bytes.length, Math.max(limits.context_radius_bytes, 1) * 2)]);
    const merged = [];
    for (const w of windows) { if (merged.length && w[0] <= merged.at(-1)[1]) merged.at(-1)[1] = Math.max(merged.at(-1)[1], w[1]); else merged.push([...w]); }
    return { path_hex: path, blob: `${q.scope.object_format}:${createHash(q.scope.object_format).update(`blob ${bytes.length}\0`).update(bytes).digest('hex')}`,
      source_bytes: bytes.length, anchors: ordered, excerpts: merged.map(([from, to]) => ({ byte_offset: from, untrusted_bytes_hex: hex(bytes.subarray(from, to)) })) };
  });
  Object.assign(response, { complete: r.complete && union.length === selected.length,
    candidate_files: union.length, returned_files: selected.length, omitted_files: union.length - selected.length, source_blobs_read: selected.length,
    source_bytes_read: response.files.reduce((n, f) => n + f.source_bytes, 0),
    excerpt_bytes: response.files.reduce((n, f) => n + f.excerpts.reduce((sum, e) => sum + e.untrusted_bytes_hex.length / 2, 0), 0),
    source_file_limit: Math.min(8388608, Math.floor(limits.context_max_source_bytes / Math.max(1, selected.length))) });
  return response;
}
