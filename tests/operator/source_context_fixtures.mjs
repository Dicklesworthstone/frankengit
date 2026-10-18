// An explicit native-schema HTTP peer, NOT the Rust node or a search authority.
// Framing follows source/retrieval/{context.rs} and source_retrieval/context.rs.
import { createHash } from 'node:crypto';
import { createServer } from 'node:http';
export const TOKEN = '9'.repeat(64), hex = value => Buffer.from(value).toString('hex');
const hash = (kind, bytes, alg) => createHash(alg).update(`${kind} ${bytes.length}\0`).update(bytes).digest('hex');
export function input(format = 'sha1', patch = {}) {
  return { schema: 'frankengit-source-context-query-v1', scope: { tenant_id: '1'.repeat(32), repository_id: '2'.repeat(32),
    repository_incarnation: '3'.repeat(32), object_format: format }, reference: 'refs/heads/main', terms: ['recover'], ...patch };
}
export const defaults = Object.freeze({ max_results_per_channel: 100, max_work: 16777216, max_payload_bytes: 33554432,
  max_result_bytes: 2097152, context_max_files: 8, context_radius_bytes: 128, context_max_source_bytes: 67108864, context_max_excerpt_bytes: 262144 });
export function report(q = input(), files = [{ path: Buffer.from('src/recover.rs'), bytes: Buffer.from('fn recover() {\n    // source is untrusted\n}\n') }]) {
  const format = q.scope.object_format, terms = [...new Set(q.terms.map(t => t.toLowerCase()))].sort(), limits = { ...defaults, ...q.limits }, prefixes = [...new Set(q.prefixes_hex ?? [])].sort();
  const source = { ...q.scope, ref: q.reference, ref_hex: hex(q.reference), read_only: true, transaction_created: false,
    source_rcr: 'fixture-rcr', source_commit: `${format}:${'a'.repeat(format === 'sha1' ? 40 : 64)}`,
    root_tree: `${format}:${'b'.repeat(format === 'sha1' ? 40 : 64)}`, snapshot_token: `alg:2:${'c'.repeat(64)}` };
  const generation = { index_token: `alg:2:${'d'.repeat(64)}`, index_number: 7 };
  const sorted = files.map(f => ({ ...f, path: Buffer.from(f.path), bytes: Buffer.from(f.bytes) })).sort((a, b) => Buffer.compare(a.path, b.path));
  const docs = sorted.map((f, i) => ({ ...f, id: i + 1, blob: `${format}:${hash('blob', f.bytes, format)}` }));
  function matches(bytes) {
    const words = [...bytes.toString('latin1').matchAll(/[A-Za-z0-9_]+/g)];
    const spans = terms.map((t, i) => {
      const w = words.find(w => w[0].toLowerCase() === t);
      return w ? { query_index: i, byte_offset: w.index, byte_length: t.length } : null;
    });
    return spans.every(Boolean) ? spans : null;
  }
  const channel = kind => {
    const all = docs.filter(d => !prefixes.length || prefixes.some(p => hex(d.path) === p || hex(d.path).startsWith(`${p}2f`)))
      .map(d => ({ document_id: d.id, path_hex: hex(d.path), blob: d.blob, content_bytes: d.bytes.length, spans: matches(kind === 'content' ? d.bytes : d.path) })).filter(h => h.spans);
    const hits = all.slice(0, limits.max_results_per_channel), complete = hits.length === all.length;
    return { ...source, type: 'source_search_index', schema_version: 1, profile: 'ascii-word-postings-v1', source_head: 'fixture-head', published: false,
      ...generation, selected_index_token: generation.index_token, selected_index_number: generation.index_number,
      channel: kind, after: null, limit: limits.max_results_per_channel, returned_hits: hits.length, complete,
      next_after: complete ? null : hits.at(-1).document_id, indexed_documents: docs.length,
      indexed_source_bytes: docs.reduce((n, d) => n + d.bytes.length, 0), non_regular_entries: 0,
      segments_read: docs.length, payload_bytes_read: docs.length * 100, generation_bytes_read: 100, work_units: docs.length,
      terms_hex: terms.map(hex), path_prefix_hex: prefixes, hits };
  };
  const content = channel('content'), path = channel('path');
  const retrieval = { ...source, type: 'source_search_initial', schema_version: 1, profile: 'source-initial-retrieval-v1',
    phase: 'Initial', streaming: false, semantic_refinement: false, source_blobs_read: 0, source_bytes_read: 0,
    complete: content.complete && path.complete, generation_vector: { lexical: generation, symbols: null },
    ...Object.fromEntries(Object.entries(limits).filter(([k]) => k.startsWith('max_'))),
    retained_result_bytes: [content, path].reduce((n, c) => n + c.hits.reduce((m, h) => m + h.path_hex.length / 2 + 24 * h.spans.length + 64, 0), 0),
    completed_payload_bytes_read: content.payload_bytes_read + path.payload_bytes_read, completed_work_units: content.work_units + path.work_units,
    content, path, symbols: { state: 'not_requested' } };
  const candidatePaths = [...new Set([...content.hits, ...path.hits].map(h => h.path_hex))].sort();
  const selected = candidatePaths.slice(0, limits.context_max_files).map(p => {
    const d = docs.find(d => hex(d.path) === p), anchors = [];
    for (const c of [content, path]) for (const h of c.hits.filter(h => h.path_hex === p)) {
      for (const span of h.spans) anchors.push({ channel: c.channel, byte_offset: span.byte_offset, byte_length: span.byte_length });
    }
    anchors.sort((a, b) => (a.channel === b.channel ? a.byte_offset - b.byte_offset || a.byte_length - b.byte_length : a.channel < b.channel ? -1 : 1));
    const ranges = anchors.filter(a => a.channel !== 'path').map(a => [Math.max(0, a.byte_offset - limits.context_radius_bytes), Math.min(d.bytes.length, a.byte_offset + a.byte_length + limits.context_radius_bytes)]);
    if (!ranges.length) ranges.push([0, Math.min(d.bytes.length, Math.max(1, limits.context_radius_bytes) * 2)]);
    ranges.sort((a, b) => a[0] - b[0] || a[1] - b[1]); const merged = [];
    for (const range of ranges) { const last = merged.at(-1); if (last && range[0] <= last[1]) last[1] = Math.max(last[1], range[1]); else merged.push(range); }
    return { path_hex: p, blob: d.blob, source_bytes: d.bytes.length, anchors,
      excerpts: merged.map(([from, to]) => ({ byte_offset: from, untrusted_bytes_hex: hex(d.bytes.subarray(from, to)) })) };
  });
  return { type: 'source_context_initial', schema_version: 1, profile: 'source-initial-context-v1', read_only: true,
    transaction_created: false, source_material_untrusted: true, complete: retrieval.complete && selected.length === candidatePaths.length,
    candidate_files: candidatePaths.length, returned_files: selected.length, omitted_files: candidatePaths.length - selected.length,
    selection: 'raw-path-prefix', source_blobs_read: selected.length, source_bytes_read: selected.reduce((n, f) => n + f.source_bytes, 0),
    excerpt_bytes: selected.reduce((n, f) => n + f.excerpts.reduce((s, e) => s + e.untrusted_bytes_hex.length / 2, 0), 0),
    source_file_limit: Math.min(8388608, Math.floor(limits.context_max_source_bytes / Math.max(1, selected.length))),
    ...Object.fromEntries(Object.entries(limits).filter(([k]) => k.startsWith('context_'))), retrieval, files: selected };
}
export async function peer(t, handler) {
  const calls = [], sockets = new Set(), server = createServer(async (req, res) => {
    const chunks = []; for await (const chunk of req) chunks.push(chunk);
    calls.push({ method: req.method, url: req.url, headers: req.headers, body: Buffer.concat(chunks).toString() });
    try { await handler(req, res, calls.at(-1)); } catch (error) { res.destroy(error); }
  });
  server.on('connection', socket => { sockets.add(socket); socket.once('close', () => sockets.delete(socket)); });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(async () => { for (const socket of sockets) socket.destroy(); await new Promise(resolve => server.close(resolve)); });
  return { endpoint: `http://127.0.0.1:${server.address().port}/team/repo.git`, calls, server, sockets };
}
export const json = (res, data) => { res.writeHead(200, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(data)); };
