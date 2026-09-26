// Closed native search contracts. Search coverage and regex evaluation are server
// claims; full-file navigation independently checks bytes against the native OID.
import { binding, copy, fail, format, form, hex, integer, keys, oid, opaque, record, snapshot, text, unhex, utf8 } from './pulls-core.mjs';

export const FILE_LIMIT = 8 * 1024 * 1024;
export const TOTAL_LIMIT = 64 * 1024 * 1024;
export const STEP_LIMIT = 64 * 1024 * 1024;
export const PAGE_BYTES = 64 * 1024;
const ROW_LIMIT = 4096;
const RETAINED_LIMIT = 2 * 1024 * 1024;
export const same = (a, b) => a.length === b.length && a.every((v, i) => v === b[i]);
const folded = byte => byte >= 65 && byte <= 90 ? byte + 32 : byte;

export function byteInput(value, encoding, maximum) {
  if (encoding === 'hex') { unhex(value, maximum); return value; }
  if (encoding !== 'utf8' || typeof value !== 'string' || value.length > maximum || /[\uD800-\uDFFF]/u.test(value)) fail('Invalid byte input.');
  const bytes = utf8.encode(value);
  if (bytes.length > maximum) fail('UTF-8 input exceeds the byte limit.');
  return hex(bytes);
}
export function pathHex(value) {
  const bytes = unhex(value, 4096);
  if (!bytes.length || bytes.includes(0)) fail('Invalid repository path.');
  let start = 0;
  for (let end = 0; end <= bytes.length; end += 1) {
    if (end < bytes.length && bytes[end] !== 47) continue;
    const part = bytes.subarray(start, end);
    if (!part.length || (part.length === 1 && part[0] === 46) ||
        (part.length === 2 && part[0] === 46 && part[1] === 46) ||
        same(Array.from(part, folded), [46, 103, 105, 116])) fail('Invalid repository path component.');
    start = end + 1;
  }
  return value;
}
export function selection(reference, algorithm) {
  format(algorithm); text(reference, 1024, 'reference', true);
  if (!reference.startsWith('refs/') || /[\s~^:?*\[\\]/u.test(reference) || reference.includes('..') || reference.includes('@{') ||
      reference.endsWith('.') || reference.split('/').some(part => !part || part.startsWith('.') || part.endsWith('.lock'))) fail('Enter a full native reference.');
  return { reference, format: algorithm };
}
export function query(input) {
  keys(input, ['mode', 'needlesHex', 'patternHex', 'case', 'prefixesHex', 'maxMatches', 'maxBytes', 'maxFileBytes', 'maxSteps']);
  const mode = input.mode ?? 'literal';
  if (!['literal', 'batch', 'regex'].includes(mode)) fail('Unsupported search mode.');
  const matchCase = input.case ?? 'exact';
  if (!['exact', 'ascii-insensitive'].includes(matchCase)) fail('Unsupported byte case mode.');
  let needles = [], pattern = null;
  if (mode === 'regex') {
    if (input.needlesHex !== undefined) fail('Regex uses a pattern, not literal needles.');
    pattern = input.patternHex;
    if (!unhex(pattern, 256).length) fail('Enter a nonempty byte regex.');
    // Never run a user pattern through JavaScript RegExp: semantics and work
    // guarantees belong to the native bounded engine, not this browser VM.
  } else {
    if (input.patternHex !== undefined || input.maxSteps !== undefined) fail('Inapplicable literal-search field.');
    if (!Array.isArray(input.needlesHex) || input.needlesHex.length < 1 ||
        input.needlesHex.length > (mode === 'literal' ? 1 : 32)) fail('Supply one literal or 1–32 batch needles.');
    needles = input.needlesHex.map(value => {
      const bytes = unhex(value, 256);
      if (!bytes.length || bytes.includes(10)) fail('Literals must be nonempty and cannot contain LF.');
      return value;
    });
  }
  const prefixes = input.prefixesHex ?? [];
  if (!Array.isArray(prefixes) || prefixes.length > 128) fail('Too many path prefixes.');
  let prefixBytes = 0;
  for (const prefix of prefixes) { pathHex(prefix); prefixBytes += prefix.length / 2; }
  if (prefixBytes > 32 * 1024) fail('Path prefixes exceed the shared byte limit.');
  return { mode, needlesHex: needles, patternHex: pattern, case: matchCase,
    prefixesHex: [...new Set(prefixes)].sort(),
    maxMatches: integer(input.maxMatches ?? 100, 'match limit', 1, ROW_LIMIT),
    maxBytes: integer(input.maxBytes ?? TOTAL_LIMIT, 'source bytes', 1, TOTAL_LIMIT),
    maxFileBytes: integer(input.maxFileBytes ?? FILE_LIMIT, 'file bytes', 1, FILE_LIMIT),
    maxSteps: mode === 'regex' ? integer(input.maxSteps ?? STEP_LIMIT, 'VM steps', 1, STEP_LIMIT) : null };
}
export function fields(selected, pin = null) {
  const result = { object_format: selected.format, ref: selected.reference };
  if (pin) Object.assign(result, { expected_head: pin.head, expected_commit: pin.commit });
  return result;
}
export function searchCommand(selected, pin, q) {
  const values = { ...fields(selected, pin), case: q.case, path_prefix_hex: q.prefixesHex,
    max_matches: q.maxMatches, max_bytes: q.maxBytes, max_file_bytes: q.maxFileBytes };
  if (q.mode === 'regex') Object.assign(values, { pattern_hex: q.patternHex, max_steps: q.maxSteps });
  else values.needle_hex = q.needlesHex;
  return { path: `source/${{ literal: 'search', batch: 'search-batch', regex: 'search-regex' }[q.mode]}`, body: form(values) };
}
export function coordinates(reply, selected, previousScope = null, previousPin = null) {
  const scope = binding(reply, previousScope);
  if (scope.format !== selected.format || reply.ref !== selected.reference || reply.ref_hex !== hex(utf8.encode(selected.reference)) ||
      reply.read_only !== true || reply.transaction_created !== false || reply.published !== false) fail('Wrong source selection or non-read response.');
  const pin = { head: snapshot(reply.snapshot_token), sourceHead: opaque(reply.source_head), rcr: opaque(reply.source_rcr),
    commit: oid(reply.source_commit, selected.format), tree: oid(reply.root_tree, selected.format) };
  if (previousPin && Object.keys(pin).some(key => pin[key] !== previousPin[key])) fail('Source snapshot changed. Refresh explicitly; never combine views.');
  return { scope, pin };
}
function literalEquals(bytes, needle, matchCase) {
  return bytes.length === needle.length && bytes.every((byte, i) =>
    (matchCase === 'exact' ? byte === needle[i] : folded(byte) === folded(needle[i])));
}
function row(raw, q, needle, algorithm) {
  record(raw); pathHex(raw.path_hex);
  if (q.prefixesHex.length && !q.prefixesHex.some(prefix => raw.path_hex === prefix || raw.path_hex.startsWith(`${prefix}2f`))) fail('Result escaped the requested path scope.');
  const blob = oid(raw.blob, algorithm), offset = integer(raw.byte_offset, 'match offset', 0, q.maxFileBytes);
  const length = integer(raw.match_length, 'match length', 0, q.maxFileBytes - offset);
  const line = integer(raw.line, 'line', 1, q.maxFileBytes + 1);
  const column = integer(raw.byte_column, 'byte column', 1, offset + 1);
  const lineStart = offset - column + 1;
  if (line > lineStart + 1) fail('Impossible source line coordinates.');
  const excerptOffset = integer(raw.excerpt_offset, 'excerpt offset', lineStart, offset);
  const excerpt = unhex(raw.excerpt_hex, 416), end = offset + length, excerptEnd = excerptOffset + excerpt.length;
  if (excerptEnd > q.maxFileBytes || offset > excerptEnd || excerpt.includes(10)) fail('Invalid source excerpt.');
  if (q.mode === 'regex') {
    if (raw.match_truncated_in_excerpt !== (end > excerptEnd)) fail('Incorrect regex excerpt truncation.');
  } else if (end > excerptEnd || !literalEquals(excerpt.subarray(offset - excerptOffset, end - excerptOffset), unhex(needle, 256), q.case)) {
    fail('Search excerpt does not contain the requested literal.');
  }
  return { pathHex: raw.path_hex, blob, offset, length, line, column, excerptOffset,
    excerptHex: raw.excerpt_hex, truncated: end > excerptEnd };
}
export function searchReply(reply, selected, q, previousScope = null, previousPin = null) {
  const source = coordinates(reply, selected, previousScope, previousPin);
  const types = { literal: ['source_search', 'literal-bytes-v1'], batch: ['source_search_batch', 'literal-bytes-batch-v1'], regex: ['source_search_regex', 'byte-regex-lines-v1'] };
  if (reply.type !== types[q.mode][0] || reply.profile !== types[q.mode][1] || reply.case !== q.case || reply.max_matches !== q.maxMatches) fail('Unsupported search response or query echo.');
  const stats = {
    filesSelected: integer(reply.files_selected, 'selected files', 0, 20_000),
    filesRead: integer(reply.files_read, 'files read', 0, 20_000),
    bytesRead: integer(reply.bytes_read, 'bytes read', 0, q.maxBytes),
    bytesSearched: integer(reply.bytes_searched, 'bytes searched', 0, q.maxBytes),
    nonRegular: integer(reply.non_regular_entries, 'non-regular entries', 0, 50_000),
  };
  if (stats.filesRead > stats.filesSelected || stats.bytesSearched > stats.bytesRead ||
      (stats.filesRead === 0 && (stats.bytesRead !== 0 || stats.bytesSearched !== 0))) fail('Inconsistent shared search counters.');
  let rawGroups;
  if (q.mode === 'batch') {
    if (reply.shared_scan !== true || reply.query_count !== q.needlesHex.length || !Array.isArray(reply.results) ||
        reply.results.length !== q.needlesHex.length || !Array.isArray(reply.path_prefixes_hex) || !same(reply.path_prefixes_hex, q.prefixesHex)) fail('Invalid batch shape or prefix echo.');
    rawGroups = reply.results;
  } else {
    if (q.mode === 'regex') {
      if (reply.match_policy !== 'leftmost-longest-per-line' || reply.pattern_hex !== q.patternHex || reply.max_steps !== q.maxSteps ||
          !Array.isArray(reply.path_prefix_hex) || !same(reply.path_prefix_hex, q.prefixesHex)) fail('Invalid native regex profile or echo.');
      stats.steps = integer(reply.vm_steps, 'VM work', 0, q.maxSteps);
      stats.states = integer(reply.program_states, 'program states', 1, 512);
      stats.lines = integer(reply.lines_searched, 'searched lines', 0, stats.bytesSearched);
    }
    rawGroups = [reply];
  }
  let total = 0, retained = 0;
  const blobs = new Map();
  const groups = rawGroups.map((group, index) => {
    record(group);
    const needle = q.mode === 'regex' ? null : q.needlesHex[index];
    if (q.mode === 'batch' && (group.query_index !== index || group.needle_hex !== needle)) fail('Batch query order or bytes changed.');
    if (!['complete', 'match_limit'].includes(group.completion) || group.complete !== (group.completion === 'complete') ||
        !Array.isArray(group.matches) || group.matches.length > q.maxMatches || group.returned_matches !== group.matches.length ||
        (group.completion === 'match_limit' && group.matches.length !== q.maxMatches)) fail('Invalid search completion or result count.');
    if (group.complete && (stats.filesRead !== stats.filesSelected || stats.bytesSearched !== stats.bytesRead)) fail('Incomplete scan labeled complete.');
    if (q.mode === 'regex' && (group.matches.length > stats.lines || (!group.complete && stats.lines <= group.matches.length))) fail('Regex lookahead is missing.');
    let previous = null;
    const matches = group.matches.map(raw => {
      if (++total > ROW_LIMIT) fail('Aggregate match limit exceeded.');
      const match = row(raw, q, needle, selected.format);
      if (!stats.filesRead || !stats.bytesRead || match.offset + match.length > stats.bytesRead ||
          (previous && (match.pathHex < previous.pathHex || (match.pathHex === previous.pathHex &&
            (match.offset <= previous.offset || match.line < previous.line || (q.mode === 'regex' && match.line === previous.line)))))) fail('Invalid match ordering or work counters.');
      if (blobs.has(match.pathHex) && blobs.get(match.pathHex) !== match.blob) fail('One path has conflicting blob identities.');
      blobs.set(match.pathHex, match.blob); previous = match;
      retained += (match.pathHex.length + match.excerptHex.length) / 2;
      if (retained > RETAINED_LIMIT) fail('Aggregate path/excerpt byte limit exceeded.');
      return match;
    });
    return { queryIndex: index, needleHex: needle, complete: group.complete, completion: group.completion, matches };
  });
  if (blobs.size > stats.filesRead) fail('Matched files exceed the read count.');
  return { ...source, query: copy(q), stats, groups, totalMatches: total };
}
export function filePage(reply, selected, result, hit, offset, total = null) {
  coordinates(reply, selected, result.scope, result.pin);
  if (reply.type !== 'source_blob' || reply.path_hex !== hit.pathHex || reply.offset !== offset || reply.symlink_followed !== false ||
      !['file', 'executable'].includes(reply.kind) || oid(reply.object_id, selected.format) !== hit.blob) fail('File is not the selected regular search result.');
  const count = integer(reply.total_bytes, 'complete file bytes', 0, result.query.maxFileBytes);
  if (total !== null && count !== total) fail('File size changed between pages.');
  if (offset > count) fail('File page starts past EOF.');
  const bytes = unhex(reply.content_hex, PAGE_BYTES), end = offset + bytes.length;
  if (bytes.length !== Math.min(PAGE_BYTES, count - offset) || reply.returned_bytes !== bytes.length || reply.next_offset !== (end < count ? end : null)) fail('Incomplete or inconsistent file page.');
  return { bytes, total: count, next: reply.next_offset, kind: reply.kind };
}
export async function verifyFile(bytes, hit, q, groupIndex, algorithm, cryptoImpl, checkpoint) {
  checkpoint();
  const header = utf8.encode(`blob ${bytes.length}\0`), framed = new Uint8Array(header.length + bytes.length);
  framed.set(header); framed.set(bytes, header.length);
  const digest = hex(new Uint8Array(await cryptoImpl.subtle.digest(algorithm === 'sha1' ? 'SHA-1' : 'SHA-256', framed)));
  checkpoint();
  if (digest !== hit.blob) fail('Native blob identity verification failed.');
  const end = hit.offset + hit.length;
  if (end > bytes.length || !same(bytes.subarray(hit.excerptOffset, hit.excerptOffset + hit.excerptHex.length / 2), unhex(hit.excerptHex, 416))) fail('Search excerpt differs from the verified file.');
  let line = 1, start = 0;
  for (let i = 0; i < hit.offset; i += 1) {
    if (i % 4096 === 0) checkpoint();
    if (bytes[i] === 10) { line += 1; start = i + 1; }
  }
  if (line !== hit.line || hit.offset - start + 1 !== hit.column || bytes.subarray(hit.offset, end).includes(10) ||
      (hit.offset === bytes.length && (!bytes.length || bytes.at(-1) === 10))) fail('Match line or byte coordinates differ from the verified file.');
  if (q.mode === 'symbols') {
    // Verify bytes and coordinates, NOT Rust syntax, macro expansion, name
    // resolution or completeness. Prefix queries still verify the FULL name.
    const name = unhex(hit.nameHex, 128);
    const asciiWord = b => (b >= 48 && b <= 57) || (b >= 65 && b <= 90) || (b >= 97 && b <= 122) || b === 95;
    const raw = hit.offset >= 2 && bytes[hit.offset - 2] === 114 && bytes[hit.offset - 1] === 35;
    const start = hit.offset - (raw ? 2 : 0);
    if (!name.length || !same(bytes.subarray(hit.offset, end), name) || hit.length !== name.length ||
        raw !== hit.rawIdentifier || asciiWord(bytes[end]) || (start > 0 && asciiWord(bytes[start - 1]))) {
      fail('Declaration name bytes or raw-identifier boundaries differ from the verified file.');
    }
    checkpoint();
    return { blobVerified: true, coordinatesVerified: true, symbolNameVerified: true,
      declarationEvaluatedBy: 'native-server', coverageVerified: false };
  }
  if (q.mode !== 'regex' && !literalEquals(bytes.subarray(hit.offset, end), unhex(q.needlesHex[groupIndex], 256), q.case)) fail('Verified source does not contain the literal.');
  checkpoint();
  return { blobVerified: true, coordinatesVerified: true, literalVerified: q.mode !== 'regex', regexEvaluatedBy: q.mode === 'regex' ? 'native-server' : null };
}
