// Native-shaped HTTP double, NOT the Rust index or authority implementation.
// A deliberately simple independent tokenizer supplies fixture postings.
import { createHash, webcrypto } from 'node:crypto';
export const crypto = webcrypto, token = '7'.repeat(64), href = 'https://forge.example/repo.git/ui/search/';
export const hex = bytes => Buffer.from(bytes).toString('hex');
export const json = (value, status = 200) => new Response(JSON.stringify(value), { status, headers: { 'Content-Type': 'application/json' } });
export const deferred = () => { let resolve; const promise = new Promise(r => { resolve = r; }); return { promise, resolve }; };
export function nativeHash(bytes, algorithm) { return createHash(algorithm).update(`blob ${bytes.length}\0`).update(bytes).digest('hex'); }
export function words(bytes) {
  const found = new Map();
  for (const match of Buffer.from(bytes).toString('latin1').matchAll(/[A-Za-z0-9_]+/g)) {
    const term = hex(match[0].toLowerCase()); if (!found.has(term)) found.set(term, match.index);
  }
  return found;
}
export function fixture(algorithm = 'sha1', documents = [
  { path: Buffer.from('src/alpha.txt'), bytes: Buffer.from('ALPHA beta\nalpha again\0\xff') },
  { path: Buffer.from('src/beta.txt'), bytes: Buffer.from('alpha BETA\r\n') },
  { path: Buffer.from('src/gamma.txt'), bytes: Buffer.from('beta alpha') },
]) {
  const width = algorithm === 'sha1' ? 40 : 64;
  const common = { schema_version: 1, tenant_id: '1'.repeat(32), repository_id: '2'.repeat(32), repository_incarnation: '3'.repeat(32),
    object_format: algorithm, ref: 'refs/heads/main', ref_hex: hex('refs/heads/main'), source_head: 'authority-head',
    snapshot_token: `alg:2:${'4'.repeat(64)}`, source_rcr: 'source-rcr', source_commit: 'a'.repeat(width), root_tree: 'b'.repeat(width),
    read_only: true, transaction_created: false, published: false };
  const docs = documents.map((d, i) => ({ ...d, documentId: d.documentId ?? i + 1, blob: nativeHash(d.bytes, algorithm) }));
  const index = { token: `alg:2:${'5'.repeat(64)}`, number: 7 };
  const config = { query: null, blob: null, fail: null, selected: { ...index } }, calls = [];
  function reply(p) {
    const terms = [...new Set(p.getAll('term_hex').map(t => hex(Buffer.from(t, 'hex').toString('ascii').toLowerCase())))].sort();
    const prefixes = p.getAll('path_prefix_hex'), channel = p.get('channel'), after = p.has('after') ? Number(p.get('after')) : null, limit = Number(p.get('limit'));
    const rows = docs.flatMap(d => {
      const path = hex(d.path), w = words(channel === 'path' ? d.path : d.bytes);
      if (after !== null && d.documentId <= after || !terms.every(t => w.has(t)) ||
          prefixes.length && !prefixes.some(p => path === p || path.startsWith(p + '2f'))) return [];
      return [{ document_id: d.documentId, path_hex: path, blob: d.blob, content_bytes: d.bytes.length,
        spans: terms.map((t, i) => ({ query_index: i, byte_offset: w.get(t), byte_length: t.length / 2 })) }];
    });
    const hits = rows.slice(0, limit), complete = rows.length <= limit;
    return { ...common, type: 'source_search_index', profile: 'ascii-word-postings-v1', channel, terms_hex: terms, path_prefix_hex: prefixes,
      index_token: index.token, index_number: index.number, selected_index_token: config.selected.token, selected_index_number: config.selected.number,
      after, limit, returned_hits: hits.length, complete, next_after: complete ? null : hits.at(-1).document_id,
      indexed_documents: docs.length, indexed_source_bytes: docs.reduce((n, d) => n + d.bytes.length, 0), non_regular_entries: 2,
      segments_read: docs.length ? 1 : 0, payload_bytes_read: 256, generation_bytes_read: 128, work_units: 32, hits };
  }
  async function fetchImpl(url, options) {
    const path = new URL(url).pathname.split('/api/v1/')[1], params = new URLSearchParams(options.body);
    const call = { path, params, ...options, headers: Object.fromEntries(new Headers(options.headers)) }; calls.push(call);
    if (config.fail) return config.fail(call);
    if (path === 'source/search-index') { const r = reply(params); await config.query?.(r, call); return json(r); }
    if (path === 'source/blob') {
      const d = docs.find(d => hex(d.path) === params.get('path_hex')); if (!d) return json({}, 404);
      const offset = Number(params.get('offset')), end = Math.min(d.bytes.length, offset + Number(params.get('limit')));
      const r = { ...common, type: 'source_blob', object_id: d.blob, path_hex: hex(d.path), kind: d.kind ?? 'file', symlink_followed: false,
        offset, total_bytes: d.bytes.length, returned_bytes: end - offset, next_offset: end === d.bytes.length ? null : end, content_hex: hex(d.bytes.subarray(offset, end)) };
      await config.blob?.(r, call); return json(r);
    }
    throw new Error(`Unexpected index fixture route ${path}`);
  }
  return { algorithm, common, docs, index, config, calls, fetchImpl, reply };
}
