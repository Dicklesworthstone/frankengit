// Persisted ASCII-word results, not a scan accelerator or index-write API.
// Generation tokens are opaque native claims, not authenticated roots here.
import { copy, fail, form, hex, integer, keys, oid, record, snapshot, unhex, utf8 } from './pulls-core.mjs';
import { coordinates, fields, FILE_LIMIT, pathHex, same } from './search-data.mjs';
import { compareCounters, currentSources, sourceMode, wireCounter } from './search-current.mjs';
export const INDEX_WORK = 16 * 1024 * 1024, INDEX_PAYLOAD = 32 * 1024 * 1024;
export const INDEX_PAGE = 100;
const word = b => (b >= 48 && b <= 57) || (b >= 65 && b <= 90) || (b >= 97 && b <= 122) || b === 95;
const fold = b => b >= 65 && b <= 90 ? b + 32 : b;
const string = bytes => Array.from(bytes, b => String.fromCharCode(fold(b))).join('');

export function indexQuery(input) {
  keys(input, ['mode', 'sourceMode', 'channel', 'termsHex', 'prefixesHex', 'maxMatches', 'maxWork', 'maxPayloadBytes', 'maxFileBytes']);
  const mode = sourceMode(input.sourceMode);
  if (input.mode !== 'indexed' || !['content', 'path'].includes(input.channel)) fail('Select an indexed content or path channel.');
  if (!Array.isArray(input.termsHex) || !input.termsHex.length || input.termsHex.length > 32) fail('Supply 1–32 whole ASCII words.');
  const terms = input.termsHex.map(value => {
    const bytes = unhex(value, 128);
    if (!bytes.length || !bytes.every(word)) fail('Indexed terms are whole ASCII alphanumeric/underscore words, not patterns.');
    return hex(Uint8Array.from(bytes, fold));
  });
  const prefixes = input.prefixesHex ?? [];
  if (!Array.isArray(prefixes) || prefixes.length > 128) fail('Too many index path prefixes.');
  let size = 0;
  for (const prefix of prefixes) {
    pathHex(prefix); const bytes = unhex(prefix, 4096);
    if (bytes.filter(b => b === 47).length >= 64 || (size += bytes.length) > 32 * 1024) fail('Indexed path scope exceeds its bounds.');
  }
  return { mode: 'indexed', ...(mode === 'revalidated' ? { sourceMode: mode } : {}), channel: input.channel, termsHex: [...new Set(terms)].sort(), prefixesHex: [...new Set(prefixes)].sort(),
    maxMatches: integer(input.maxMatches ?? INDEX_PAGE, 'indexed page limit', 1, INDEX_PAGE),
    maxWork: integer(input.maxWork ?? INDEX_WORK, 'index work', 1, INDEX_WORK),
    maxPayloadBytes: integer(input.maxPayloadBytes ?? INDEX_PAYLOAD, 'index payload bytes', 1, INDEX_PAYLOAD),
    maxFileBytes: integer(input.maxFileBytes ?? FILE_LIMIT, 'file byte limit', 1, FILE_LIMIT) };
}
function activation(token, number, mode) {
  snapshot(token);
  if (!/:[0-9a-f]{64}$/.test(token) || /^0+$/.test(token.split(':')[2])) fail('Invalid index identity.');
  return { token, number: mode === 'revalidated' ? wireCounter(number, mode) : integer(number, 'index generation number', 1) };
}
function atLeast(observed, floor) {
  if (!floor) return;
  const order = compareCounters(observed.number, floor.number);
  if (order < 0 || (order === 0 && observed.token !== floor.token)) fail('Index checkpoint regressed or changed identity.');
}
export function indexCommand(selected, pin, q, previous = null, minimum = null) {
  const values = { ...fields(selected, pin), channel: q.channel, term_hex: q.termsHex,
    path_prefix_hex: q.prefixesHex, limit: q.maxMatches, max_work: q.maxWork, max_payload_bytes: q.maxPayloadBytes };
  if (sourceMode(q.sourceMode) === 'revalidated') values.source_mode = 'revalidated';
  if (previous) {
    if (sourceMode(previous.query.sourceMode) !== sourceMode(q.sourceMode)) fail('Indexed continuation changed source mode.');
    if (!pin || previous.nextAfter === null) fail('No pinned indexed continuation remains.');
    Object.assign(values, { index_token: previous.index.token, index_number: previous.index.number, after: previous.nextAfter });
  }
  if (minimum) Object.assign(values, { minimum_index_token: minimum.token, minimum_index_number: minimum.number });
  return form(values);
}
// One scalar scan reproduces all FIRST token spans together. It never runs a
// user pattern, fetches source, builds a server index or claims search coverage.
export function verifyWordSpans(bytes, q, spans, checkpoint = () => {}) {
  const wanted = new Map(q.termsHex.map((term, i) => [string(unhex(term, 128)), i]));
  const found = new Map(); let start = -1;
  for (let at = 0; at <= bytes.length; at++) {
    if ((at & 4095) === 0) checkpoint();
    if (at < bytes.length && word(bytes[at])) { if (start < 0) start = at; continue; }
    if (start < 0) continue;
    if (at - start <= 128) {
      const index = wanted.get(string(bytes.subarray(start, at)));
      if (index !== undefined && !found.has(index)) found.set(index, start);
    }
    start = -1;
  }
  if (spans.length !== q.termsHex.length || spans.some((s, i) => s.queryIndex !== i || found.get(i) !== s.offset || s.length !== q.termsHex[i].length / 2)) fail('Indexed spans do not reproduce the first complete words.');
  checkpoint();
}
export function indexReply(reply, selected, q, scope = null, pin = null, previous = null, minimum = null) {
  const source = coordinates(reply, selected, scope, pin);
  const mode = sourceMode(q.sourceMode), revalidated = mode === 'revalidated';
  if (previous && sourceMode(previous.query.sourceMode) !== mode) fail('Indexed continuation changed source mode.');
  const sources = revalidated ? currentSources(reply, source, previous) : null;
  if (reply.type !== (revalidated ? 'source_search_index_current' : 'source_search_index') ||
      reply.profile !== (revalidated ? 'source-lexical-revalidated-v1' : 'ascii-word-postings-v1') || reply.channel !== q.channel ||
      !Array.isArray(reply.terms_hex) || !same(reply.terms_hex, q.termsHex) ||
      !Array.isArray(reply.path_prefix_hex) || !same(reply.path_prefix_hex, q.prefixesHex) ||
      reply.after !== (previous?.nextAfter ?? null) || reply.limit !== q.maxMatches ||
      !Array.isArray(reply.hits) || reply.hits.length > q.maxMatches || reply.returned_hits !== reply.hits.length ||
      typeof reply.complete !== 'boolean') fail('Invalid indexed result or normalized query echo.');
  if (reply.next_after !== null) wireCounter(reply.next_after, mode);
  const index = activation(reply.index_token, reply.index_number, mode), selectedIndex = activation(reply.selected_index_token, reply.selected_index_number, mode);
  atLeast(selectedIndex, index); atLeast(selectedIndex, minimum);
  if (previous && (index.token !== previous.index.token || index.number !== previous.index.number)) fail('Indexed continuation switched generations.');
  const stats = { documents: integer(reply.indexed_documents, 'indexed documents', 0, 20_000),
    sourceBytes: integer(reply.indexed_source_bytes, 'indexed source bytes', 0, 64 * 1024 * 1024),
    nonRegular: integer(reply.non_regular_entries, 'excluded entries', 0, 50_000),
    segments: integer(reply.segments_read, 'read segments', 0, 20_000),
    payloadBytes: integer(reply.payload_bytes_read, 'index payload bytes', 0, q.maxPayloadBytes),
    generationBytes: integer(reply.generation_bytes_read, 'generation bytes'),
    work: integer(reply.work_units, 'index work', 0, q.maxWork) };
  if (stats.documents < reply.hits.length || (!stats.documents && (stats.sourceBytes || stats.segments)) ||
      (reply.hits.length && (!stats.segments || !stats.payloadBytes)) ||
      (previous && ['documents', 'sourceBytes', 'nonRegular'].some(k => stats[k] !== previous.stats[k]))) fail('Indexed corpus or work counters changed.');
  let lastId = previous?.nextAfter ?? 0, lastPath = previous?.hits.at(-1)?.pathHex ?? '', retained = 0;
  const hits = reply.hits.map(raw => {
    record(raw); pathHex(raw.path_hex);
    const id = revalidated ? wireCounter(raw.document_id, mode) : integer(raw.document_id, 'absolute document ID', 1);
    const path = unhex(raw.path_hex, 4096);
    if (compareCounters(id, lastId) <= 0 || raw.path_hex <= lastPath || path.filter(b => b === 47).length >= 64 ||
        (q.prefixesHex.length && !q.prefixesHex.some(p => raw.path_hex === p || raw.path_hex.startsWith(`${p}2f`)))) fail('Indexed path order, cursor or scope changed.');
    lastId = id; lastPath = raw.path_hex;
    const contentBytes = integer(raw.content_bytes, 'indexed file bytes', 0, FILE_LIMIT), blob = oid(raw.blob, selected.format);
    if (contentBytes > stats.sourceBytes || !Array.isArray(raw.spans) || raw.spans.length !== q.termsHex.length) fail('Incomplete indexed document.');
    const bound = q.channel === 'content' ? contentBytes : path.length;
    const spans = raw.spans.map((s, i) => {
      record(s); const offset = integer(s.byte_offset, 'term offset', 0, bound), length = integer(s.byte_length, 'term length', 1, 128);
      if (s.query_index !== i || length !== q.termsHex[i].length / 2 || offset + length > bound) fail('Indexed word span changed.');
      return { queryIndex: i, offset, length };
    });
    retained += path.length + spans.length * 24 + 64;
    if (retained > 2 * 1024 * 1024) fail('Indexed result byte budget exceeded.');
    if (q.channel === 'path') verifyWordSpans(path, q, spans);
    return { documentId: id, pathHex: raw.path_hex, blob, contentBytes, spans };
  });
  if ((previous && !hits.length) || (reply.complete ? reply.next_after !== null : (!hits.length || hits.length !== q.maxMatches || reply.next_after !== lastId))) fail('Invalid indexed completion or continuation.');
  const seen = (previous?.seen ?? 0) + hits.length;
  if (seen > stats.documents || (!reply.complete && seen >= stats.documents)) fail('Indexed page exceeds the corpus.');
  return { ...source, ...(sources ? { sources } : {}), query: copy(q), index, selectedIndex, stats, hits, complete: reply.complete, nextAfter: reply.next_after, seen };
}
export async function verifyIndexedFile(bytes, hit, q, algorithm, crypto, checkpoint) {
  checkpoint();
  if (bytes.length !== hit.contentBytes) fail('Indexed file length changed.');
  const prefix = utf8.encode(`blob ${bytes.length}\0`), framed = new Uint8Array(prefix.length + bytes.length);
  framed.set(prefix); framed.set(bytes, prefix.length);
  const actual = hex(new Uint8Array(await crypto.subtle.digest(algorithm === 'sha1' ? 'SHA-1' : 'SHA-256', framed)));
  checkpoint(); if (actual !== hit.blob) fail('Indexed file native blob identity mismatch.');
  verifyWordSpans(q.channel === 'path' ? unhex(hit.pathHex, 4096) : bytes, q, hit.spans, checkpoint);
  return { blobVerified: true, wordSpansVerified: true, coverageVerified: false, channel: q.channel };
}
