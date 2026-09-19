// HTTP fixtures only. Native Git OIDs are computed independently with node:crypto;
// these fixtures are not evidence that the Rust node executed the requests.
import { createHash, webcrypto } from 'node:crypto';
export const ROOT = '../../crates/fgit-node/src/smart_http/server/browser/';
export const TOKEN = 'a'.repeat(64);
export const HREF = 'https://forge.example/repo.git/ui/search/';
export const hex = bytes => Buffer.from(bytes).toString('hex');
export const bytes = value => Buffer.from(value, 'hex');
export const blobId = (body, algorithm) => createHash(algorithm).update(`blob ${body.length}\0`).update(body).digest('hex');
export const encode = value => hex(Buffer.from(value));
export const response = (value, status = 200, headers = {}) => {
  const body = JSON.stringify(value);
  return new Response(body, { status, headers: { 'Content-Type': 'application/json', 'Content-Length': String(Buffer.byteLength(body)), ...headers } });
};
export function fixture(algorithm = 'sha1', entries = [['src/code.rs', 'éNeedle needle\r\nfn choose() {}\n'], ['src2/private', 'needle\n']]) {
  const files = entries.map(([path, data]) => ({ path: Buffer.isBuffer(path) ? path : Buffer.from(path),
    body: Buffer.isBuffer(data) ? data : Buffer.from(data), kind: 'file' }));
  for (const file of files) { file.pathHex = hex(file.path); file.id = blobId(file.body, algorithm); }
  files.sort((a, b) => a.pathHex.localeCompare(b.pathHex));
  const width = algorithm === 'sha1' ? 40 : 64;
  const identity = { schema_version: 1, tenant_id: '1'.repeat(32), repository_id: '2'.repeat(32), repository_incarnation: 'incarnation-one',
    object_format: algorithm, ref: 'refs/heads/main', ref_hex: encode('refs/heads/main'), source_head: 'head-one', snapshot_token: `alg:1:${'ab'.repeat(32)}`,
    source_rcr: 'rcr-one', source_commit: 'c'.repeat(width), root_tree: 'd'.repeat(width), read_only: true, transaction_created: false, published: false };
  const calls = [];
  let intercept = null;
  function match(file, start, length) {
    let line = 1, lineStart = 0;
    for (let i = 0; i < start; i++) if (file.body[i] === 10) { line++; lineStart = i + 1; }
    const excerptOffset = Math.max(lineStart, start - 80), matchEnd = start + length;
    let end = Math.min(file.body.length, start + Math.min(length, 256) + 80);
    const lf = file.body.indexOf(10, excerptOffset); if (lf >= 0) end = Math.min(end, lf);
    return { path_hex: file.pathHex, blob: file.id, byte_offset: start, line, byte_column: start - lineStart + 1,
      match_length: length, excerpt_offset: excerptOffset, excerpt_hex: hex(file.body.subarray(excerptOffset, end)),
      match_truncated_in_excerpt: matchEnd > end };
  }
  function reply(url, init) {
    const params = new URLSearchParams(init.body), mode = url.pathname.split('/').at(-1), max = Number(params.get('max_matches') ?? 100);
    const prefixes = [...new Set(params.getAll('path_prefix_hex'))].sort();
    const selected = files.filter(f => !prefixes.length || prefixes.some(p => f.pathHex === p || f.pathHex.startsWith(`${p}2f`)));
    if (mode === 'blob') {
      const file = files.find(f => f.pathHex === params.get('path_hex'));
      if (!file) return { type: 'source_error', code: 'not_found' };
      const offset = Number(params.get('offset')), limit = Number(params.get('limit'));
      const body = file.body.subarray(offset, offset + limit), end = offset + body.length;
      return { ...identity, type: 'source_blob', path_hex: file.pathHex, object_id: file.id, kind: file.kind,
        total_bytes: file.body.length, offset, returned_bytes: body.length, content_hex: hex(body),
        next_offset: end < file.body.length ? end : null, symlink_followed: false };
    }
    const stats = { files_selected: selected.length, files_read: selected.length,
      bytes_read: selected.reduce((n, f) => n + f.body.length, 0), non_regular_entries: 0 };
    stats.bytes_searched = stats.bytes_read;
    const base = { ...identity, ...stats, max_matches: max, case: params.get('case') };
    const fold = b => params.get('case') === 'ascii-insensitive' && b >= 65 && b <= 90 ? b + 32 : b;
    function group(needle, index) {
      const value = bytes(needle), matches = [];
      for (const file of selected) for (let i = 0; i + value.length <= file.body.length; i++) {
        if (value.every((b, j) => fold(b) === fold(file.body[i + j]))) {
          const hit = match(file, i, value.length); delete hit.match_truncated_in_excerpt; matches.push(hit);
        }
      }
      return { query_index: index, needle_hex: needle, completion: matches.length > max ? 'match_limit' : 'complete',
        complete: matches.length <= max, returned_matches: Math.min(max, matches.length), matches: matches.slice(0, max) };
    }
    if (mode === 'search-batch') {
      const needles = params.getAll('needle_hex');
      return { ...base, type: 'source_search_batch', profile: 'literal-bytes-batch-v1', shared_scan: true,
        query_count: needles.length, path_prefixes_hex: prefixes, results: needles.map(group) };
    }
    if (mode === 'search-regex') {
      // Fixture profiles intentionally do not interpret arbitrary regexes.
      const pattern = bytes(params.get('pattern_hex')).toString();
      const matches = [];
      let lines = 0;
      for (const file of selected) {
        let start = 0;
        while (start < file.body.length) {
          const lf = file.body.indexOf(10, start), end = lf < 0 ? file.body.length : lf;
          lines++;
          if (pattern === '.*') matches.push(match(file, start, end - start));
          else if (pattern === '^$' && start === end) matches.push(match(file, start, 0));
          else if (pattern === 'fn.*' && file.body.subarray(start, end).includes(Buffer.from('fn'))) {
            const at = file.body.indexOf('fn', start); matches.push(match(file, at, end - at));
          }
          start = lf < 0 ? file.body.length : lf + 1;
        }
      }
      return { ...base, type: 'source_search_regex', profile: 'byte-regex-lines-v1', match_policy: 'leftmost-longest-per-line',
        pattern_hex: params.get('pattern_hex'), max_steps: Number(params.get('max_steps')), vm_steps: Math.min(stats.bytes_read, Number(params.get('max_steps'))),
        program_states: 4, lines_searched: lines, path_prefix_hex: prefixes, completion: matches.length > max ? 'match_limit' : 'complete',
        complete: matches.length <= max, returned_matches: Math.min(max, matches.length), matches: matches.slice(0, max) };
    }
    return { ...base, ...group(params.get('needle_hex'), 0), type: 'source_search', profile: 'literal-bytes-v1' };
  }
  async function fetchImpl(url, init) {
    calls.push({ url: url.href, ...init });
    const value = reply(url, init);
    return intercept ? intercept(value, url, init) : response(value);
  }
  return { algorithm, identity, files, calls, match, reply, fetchImpl, setIntercept(fn) { intercept = fn; },
    options: { href: HREF, fetchImpl, cryptoImpl: webcrypto } };
}
export const literal = (extra = {}) => ({ mode: 'literal', needlesHex: [encode('needle')], ...extra });
export const batch = (extra = {}) => ({ mode: 'batch', needlesHex: [encode('needle'), encode('absent')], ...extra });
export const regex = (pattern = 'fn.*', extra = {}) => ({ mode: 'regex', patternHex: encode(pattern), ...extra });
