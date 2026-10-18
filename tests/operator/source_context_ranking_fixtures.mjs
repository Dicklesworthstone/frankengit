// Independent BigInt arithmetic oracle over explicit native-schema peers.
// No production ranking helper is imported. These fixtures are not a Rust node.
import { report, defaults } from './source_context_fixtures.mjs';
import { nativeSymbols, assemble, hex } from './source_context_symbols_fixtures.mjs';
export const PROFILE = 'context-weighted-rrf-q16-v1';
export const CODE = Buffer.from('pub fn Recover() {}\npub fn RecoverAgain() {}\n');
export const CORPUS = [
  { path: Buffer.from('a/note.txt'), bytes: Buffer.from('Recover is mentioned here.\n') },
  { path: Buffer.from('z/Recover.rs'), bytes: CODE },
];
export const DECLARATIONS = [
  { path: CORPUS[1].path, name: 'Recover', at: 7 },
  { path: CORPUS[1].path, name: 'RecoverAgain', at: CODE.indexOf('RecoverAgain') },
];
export function oracle(retrieval) {
  const entries = { content: retrieval.content.hits, path: retrieval.path.hits,
    symbol: retrieval.symbols.state === 'available' ? retrieval.symbols.result.matches : [] };
  const positions = Object.fromEntries(Object.entries(entries).map(([c, hits]) => [c, [...new Set(hits.map(h => h.path_hex))].sort()]));
  const identities = new Map(Object.values(entries).flat().map(h => [h.path_hex, h.blob]));
  return [...identities].map(([path_hex, blob]) => {
    const contributions = Object.keys(entries).filter(c => positions[c].includes(path_hex)).map(channel => {
      const document_rank = positions[channel].indexOf(path_hex) + 1, weight = channel === 'symbol' ? 2 : 1;
      return { channel, document_rank, weight, score_q16: Number(BigInt(weight) * 65536n / (60n + BigInt(document_rank))) };
    });
    return { path_hex, blob, score_q16: contributions.reduce((n, c) => n + c.score_q16, 0), contributions };
  }).sort((a, b) => a.score_q16 !== b.score_q16 ? b.score_q16 - a.score_q16 : Buffer.compare(Buffer.from(a.path_hex, 'hex'), Buffer.from(b.path_hex, 'hex')));
}
export function rank(response, q, files) {
  const limits = { ...defaults, ...q.limits };
  const selected = oracle(response.retrieval).slice(0, limits.context_max_files).map((r, i) => ({ position: i + 1, ...r }));
  assemble(response, q, files, selected.map(s => s.path_hex));
  response.selection = PROFILE;
  response.ranking = { profile: PROFILE, rank_constant: 60, score_scale: 65536,
    input_order: 'raw-path-distinct-documents', tie_break: 'raw-path-ascending',
    ranked_over: 'returned-channel-hits', semantic_relevance: false, selected };
  return response;
}
export function nativeRanked(q, files = CORPUS, declarations = DECLARATIONS, unavailable = null) {
  const base = q.symbols ? nativeSymbols(q, files, declarations, unavailable) : report(q, files);
  return rank(base, q, files);
}
export { hex };
