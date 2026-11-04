// Native wire-schema examples only, never a Rust index, authority or label oracle.
// Git blobs still use the existing fixture's independent native object hashes.
import { withReadLabels } from './source_context_fixtures.mjs';

const SOURCE_FIELDS = ['tenant_id', 'repository_id', 'repository_incarnation', 'object_format', 'ref', 'ref_hex',
  'source_head', 'snapshot_token', 'source_rcr', 'forge_position_root', 'source_commit', 'root_tree'];
function position(source, digest) {
  const result = Object.fromEntries(SOURCE_FIELDS.map(k => [k, source[k]]));
  Object.assign(result, { snapshot_token: `alg:2:${digest}`,
    source_head: `frankengit/authority-head/v1/v1.0/alg:2/${digest}`,
    source_rcr: `frankengit/rcr/v1/v1.0/alg:2/${digest}`, forge_position_root: `alg:2:${digest}` });
  return result;
}
function envelope(value, source, current = false) {
  for (const k of SOURCE_FIELDS) {
    if (k !== 'forge_position_root' && (!current || k !== 'source_head')) value[k] = source[k];
  }
}

// Retain actual original generations, query rows, labels and exact excerpts.
// The three source positions differ only in repository metadata; the selected
// native commit/tree remain identical. Ordinary strict fixtures stay untouched.
export function withRevalidatedSources(original, { currentDigit = 'f', lexicalDigit = null, symbolDigit = '6' } = {}) {
  for (const digit of [currentDigit, ...(lexicalDigit === null ? [] : [lexicalDigit]), symbolDigit]) {
    if (typeof digit !== 'string' || !/^[1-9a-f]$/.test(digit)) throw new Error('invalid fixture position digit');
  }
  const context = Object.hasOwn(original.retrieval, 'authorization') ? structuredClone(original) : withReadLabels(original);
  const r = context.retrieval;
  const lexical = position(r.content, lexicalDigit === null ? r.content.snapshot_token.split(':')[2] : lexicalDigit.repeat(64));
  const current = position(r, currentDigit.repeat(64));
  const symbols = r.symbols.state === 'available' ? position(r.symbols.result, symbolDigit.repeat(64)) : null;
  envelope(r.content, lexical); envelope(r.path, lexical);
  if (symbols) envelope(r.symbols.result, symbols);
  envelope(r, current, true);
  Object.assign(context, { profile: 'source-initial-context-revalidated-v1', index_source: 'current-native-v1' });
  Object.assign(r, { profile: 'source-initial-revalidated-v1', index_source: 'current-native-v1', current_source: current,
    index_sources: { lexical, symbols } });
  return context;
}
