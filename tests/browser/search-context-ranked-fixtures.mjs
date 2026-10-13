// Fixed native-schema examples, not a live Rust service. The 4279 score and its
// contributions mirror ranked/tests.rs at 9da3ef87 (cf01e7a3 blob).
import { fixture, copy, hex, limitsFor } from './search-context-fixtures.mjs';
export const PROFILE = 'context-weighted-rrf-q16-v1';
export const contribution = (channel, document_rank, weight, score_q16) => ({ channel, document_rank, weight, score_q16 });
export const ranking = selected => ({ profile: PROFILE, rank_constant: 60, score_scale: 65536,
  input_order: 'raw-path-distinct-documents', tie_break: 'raw-path-ascending',
  ranked_over: 'returned-channel-hits', semantic_relevance: false, selected });
export function rankedFixture(format = 'sha1', maxFiles = 1) {
  const f = fixture(format), pathHex = hex('z/Thing.rs'), firstPath = hex('00.txt');
  for (const key of ['content', 'path']) f.retrieval[key].hits[0].pathHex = pathHex;
  f.retrieval.path.hits[0].spans[0].offset = 2;
  f.retrieval.symbols.result.hits[0].pathHex = pathHex;
  f.retrieval.symbols.result.hits.push(copy(f.retrieval.symbols.result.hits[0]));
  const first = copy(f.retrieval.content.hits[0]); first.pathHex = firstPath;
  f.retrieval.content.hits.unshift(first);
  const last = f.reply.files[0]; last.path_hex = pathHex; last.anchors[1].byte_offset = 2;
  f.reply.selection = PROFILE;
  f.reply.ranking = ranking([{ position: 1, path_hex: pathHex, blob: last.blob, score_q16: 4279,
    contributions: [contribution('content', 2, 1, 1057), contribution('path', 1, 1, 1074), contribution('symbol', 1, 2, 2148)] }]);
  if (maxFiles === 2) {
    const low = copy(last); low.path_hex = firstPath; low.anchors = [low.anchors[0]];
    f.reply.files.unshift(low);
    f.reply.ranking.selected.push({ position: 2, path_hex: firstPath, blob: low.blob,
      score_q16: 1074, contributions: [contribution('content', 1, 1, 1074)] });
  }
  Object.assign(f.reply, { candidate_files: 2, returned_files: maxFiles, omitted_files: 2 - maxFiles,
    source_blobs_read: maxFiles, source_bytes_read: 18 * maxFiles, excerpt_bytes: 18 * maxFiles, complete: maxFiles === 2 });
  f.limits = limitsFor(f, { maxFiles });
  f.limits.selection = PROFILE;
  return f;
}
