// Source-coordinate projections of the native revalidated Initial wire shape.
// No search hits, ranking, generation evidence or authorization is fabricated;
// these fixtures exercise independent source-byte proof/package consumers only.
const fields = ['tenant_id', 'repository_id', 'repository_incarnation', 'object_format',
  'ref', 'ref_hex', 'snapshot_token', 'source_head', 'source_rcr', 'forge_position_root',
  'source_commit', 'root_tree'];
export function revalidatedProjection(input, { symbols = false } = {}) {
  const context = structuredClone(input), retrieval = context.retrieval;
  const current = Object.fromEntries(fields.map(key => [key, retrieval[key]]));
  const head = token => `frankengit/authority-head/v1/v1.0/${token.slice(0, token.lastIndexOf(':'))}/${token.slice(token.lastIndexOf(':') + 1)}`;
  current.source_head = head(current.snapshot_token);
  current.forge_position_root ??= `alg:2:${'7'.repeat(64)}`;
  const lexical = { ...current, source_head: head(`alg:2:${'5'.repeat(64)}`),
    snapshot_token: `alg:2:${'5'.repeat(64)}`, source_rcr: 'fixture-lexical-rcr',
    forge_position_root: `alg:2:${'8'.repeat(64)}` };
  const symbol = { ...current, source_head: head(`alg:2:${'6'.repeat(64)}`),
    snapshot_token: `alg:2:${'6'.repeat(64)}`, source_rcr: 'fixture-symbol-rcr',
    forge_position_root: `alg:2:${'9'.repeat(64)}` };
  Object.assign(context, { profile: 'source-initial-context-revalidated-v1',
    index_source: 'current-native-v1', selection: 'raw-path-prefix' });
  Object.assign(retrieval, { profile: 'source-initial-revalidated-v1', index_source: 'current-native-v1',
    current_source: current, index_sources: { lexical, symbols: symbols ? symbol : null },
    symbols: symbols ? { state: 'available', result: { ...symbol, schema_version: 1,
      type: 'source_search_symbols_index', profile: 'rust-declaration-heads-v1',
      read_only: true, transaction_created: false, published: false } } : { state: 'not_requested' } });
  // Joined native retrievals carry the selected coordinates at the top but do
  // not pretend to be a standalone read envelope with publication/head fields.
  delete retrieval.source_head; delete retrieval.published; delete retrieval.forge_position_root;
  for (const channel of ['content', 'path']) retrieval[channel] = { ...lexical,
    schema_version: 1, type: 'source_search_index', profile: 'ascii-word-postings-v1', channel,
    read_only: true, transaction_created: false, published: false };
  return context;
}
