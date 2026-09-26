// Source-derived native HTTP wire fixtures, not execution of the Rust server.
// Drive the actual browser controller, validators and WebCrypto file verifier.
import { createHash, webcrypto } from 'node:crypto';
export { webcrypto };
export const hex = value => Buffer.from(value).toString('hex');
export const utf8 = text => Buffer.from(text, 'utf8');
export const token = 'a'.repeat(64), href = 'https://forge.invalid/r.git/ui/search/';
export const selected = format => ({ reference: 'refs/heads/main', format });
export function fixture(format = 'sha1', { name = 'Thing', raw = false, prefix = '// café\r\n', path = utf8('src/thing.rs'), body: supplied } = {}) {
  const body = supplied ?? utf8(`${prefix}pub struct ${raw ? 'r#' : ''}${name} {}\n`);
  const blob = createHash(format).update(utf8(`blob ${body.length}\0`)).update(body).digest('hex');
  const offset = body.indexOf(utf8(`${name} {`)), before = body.subarray(0, offset);
  const line = before.filter(b => b === 10).length + 1, start = before.lastIndexOf(10) + 1;
  const excerpt = body.subarray(start, Math.min(body.indexOf(10, offset) < 0 ? body.length : body.indexOf(10, offset), start + 416));
  const source = { schema_version: 1, tenant_id: '1'.repeat(32), repository_id: '2'.repeat(32), repository_incarnation: '3'.repeat(32),
    object_format: format, ref: 'refs/heads/main', ref_hex: hex('refs/heads/main'), source_head: 'source-head-A',
    snapshot_token: `alg:2:${'4'.repeat(64)}`, source_rcr: 'source-rcr-A',
    source_commit: '5'.repeat(format === 'sha1' ? 40 : 64), root_tree: '6'.repeat(format === 'sha1' ? 40 : 64),
    read_only: true, transaction_created: false, published: false };
  const row = { name_hex: hex(name), kind: 'struct', raw_identifier: raw, path_hex: hex(path), blob, byte_offset: offset,
    line, byte_column: offset - start + 1, match_length: utf8(name).length, excerpt_hex: hex(excerpt), excerpt_offset: start,
    match_truncated_in_excerpt: false };
  const reply = { ...source, type: 'source_search_symbols_index', profile: 'rust-declaration-heads-v1',
    index_profile: 'rust-declaration-tables-v1', authority_class: 'deterministic-derived',
    compiler_resolved: false, macro_expansion: false, cfg_evaluated: false, source_blobs_read: 0, source_bytes_read: 0,
    index_token: `alg:2:${'7'.repeat(64)}`, index_number: 1, name_hex: hex(name), match: 'exact', complete: true, completion: 'complete',
    max_matches: 100, returned_matches: 1, indexed_files: 1, indexed_declarations: 1, indexed_source_bytes: body.length,
    unsupported_language_files: 1, non_regular_entries: 2, tables_read: 1, payload_bytes_read: 1024,
    max_work: 16 * 1024 * 1024, work_units: 20, kinds: [], path_prefix_hex: [], matches: [row] };
  const file = offset => {
    const content = body.subarray(offset, offset + 65536), end = offset + content.length;
    return { ...source, type: 'source_blob', path_hex: row.path_hex, offset, kind: 'file', object_id: blob,
      symlink_followed: false, total_bytes: body.length, content_hex: hex(content), returned_bytes: content.length,
      next_offset: end < body.length ? end : null };
  };
  return { body, blob, source, row, reply, file, input: { mode: 'symbols', nameHex: hex(name) } };
}
export function response(value, status = 200) {
  const text = JSON.stringify(value);
  return new Response(text, { status, headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(text).toString() } });
}
export function transport(f, intercept = () => null) {
  const calls = [];
  const fetchImpl = async (url, options) => {
    const fields = new URLSearchParams(options.body);
    const call = { url: url.href, options, fields }; calls.push(call);
    const override = await intercept(call);
    if (override) return override;
    if (url.pathname.endsWith('/source/search-symbols-index')) {
      const reply = structuredClone(f.reply);
      for (const key of ['name_hex', 'match']) reply[key] = fields.get(key);
      for (const key of ['max_matches', 'max_work']) reply[key] = Number(fields.get(key));
      reply.kinds = fields.getAll('kind'); reply.path_prefix_hex = fields.getAll('path_prefix_hex');
      return response(reply);
    }
    if (url.pathname.endsWith('/source/blob')) return response(f.file(Number(fields.get('offset'))));
    throw new Error(`Unexpected request ${url.pathname}`);
  };
  return { calls, options: { href, fetchImpl, cryptoImpl: webcrypto } };
}
export function deferred() { let resolve; const promise = new Promise(r => { resolve = r; }); return { promise, resolve }; }
