// Source-only projection shared by context acquisition, byte proofs and selected
// packages. These are checked server claims, not authority or index verification.
// Original index coordinates never become a replacement current-source receipt.
export const CURRENT_INDEX_SOURCE = 'current-native-v1';
const SOURCE_FIELDS = ['tenant_id', 'repository_id', 'repository_incarnation', 'object_format',
  'ref', 'ref_hex', 'source_head', 'snapshot_token', 'source_rcr', 'forge_position_root', 'source_commit', 'root_tree'];
const ENVELOPE_FIELDS = SOURCE_FIELDS.filter(k => k !== 'forge_position_root');
const JOIN_FIELDS = ENVELOPE_FIELDS.filter(k => k !== 'source_head');
const NATIVE_FIELDS = ['tenant_id', 'repository_id', 'repository_incarnation', 'object_format',
  'ref', 'ref_hex', 'source_commit', 'root_tree'];
const reject = code => { throw Object.assign(new Error(code), { code }); };

// null keeps the old strict path, including legacy source-only proof inputs.
// Current records are bounded, detached copies of the full native source_json
// shape. Callers still enforce independent expected scope/head/commit and their
// own query, generation, label, membership, byte and resource requirements.
export function contextProvenance(context, fail = reject, check = () => {}) {
  const record = value => {
    if (!value || typeof value !== 'object' || Array.isArray(value)) fail('invalid_context_provenance');
    return value;
  };
  const keys = (value, names) => {
    record(value);
    if (Object.keys(value).length !== names.length || names.some(k => !Object.hasOwn(value, k))) fail('invalid_context_provenance_fields');
  };
  const opaque = value => {
    if (typeof value !== 'string' || !value || Buffer.byteLength(value) > 256 || /[\s\x00-\x1f\x7f]/u.test(value)) fail('invalid_context_provenance_identity');
  };
  const digest = (value, nonzero = false) => {
    if (typeof value !== 'string' || !/^alg:[1-9][0-9]{0,4}:[0-9a-f]{64}$/.test(value) ||
        Number(value.split(':')[1]) > 65535 || nonzero && /^0+$/.test(value.split(':')[2])) fail('invalid_context_provenance_identity');
  };
  const source = value => {
    check(); keys(value, SOURCE_FIELDS);
    for (const k of ['tenant_id', 'repository_id', 'repository_incarnation']) {
      if (typeof value[k] !== 'string' || !/^[0-9a-f]{32}$/.test(value[k])) fail('invalid_context_provenance_identity');
    }
    if (!['sha1', 'sha256'].includes(value.object_format)) fail('invalid_context_provenance_format');
    if (typeof value.ref !== 'string' || !value.ref.startsWith('refs/') || Buffer.byteLength(value.ref) > 1024 ||
        /[\x00-\x20\x7f~^:?*\[\\\uD800-\uDFFF]/u.test(value.ref) || value.ref.includes('..') || value.ref.includes('@{') ||
        value.ref.endsWith('.') || value.ref.split('/').some(p => !p || p.startsWith('.') || p.endsWith('.lock')) ||
        value.ref_hex !== Buffer.from(value.ref).toString('hex')) fail('invalid_context_provenance_reference');
    for (const k of ['source_commit', 'root_tree']) {
      const raw = typeof value[k] === 'string' && value[k].startsWith(`${value.object_format}:`)
        ? value[k].slice(value.object_format.length + 1) : value[k];
      if (typeof raw !== 'string' || !new RegExp(`^[0-9a-f]{${value.object_format === 'sha1' ? 40 : 64}}$`).test(raw) || /^0+$/.test(raw)) fail('invalid_context_provenance_object');
    }
    opaque(value.source_head); opaque(value.source_rcr);
    digest(value.snapshot_token, true); digest(value.forge_position_root);
    const [, algorithm, bytes] = value.snapshot_token.split(':');
    if (!value.source_head.startsWith('frankengit/authority-head/v1/') ||
        !value.source_head.endsWith(`/alg:${algorithm}/${bytes}`)) fail('context_provenance_head_changed');
    return Object.fromEntries(SOURCE_FIELDS.map(k => [k, value[k]]));
  };
  const sameFields = (value, selected, fields) => {
    record(value);
    if (fields.some(k => value[k] !== selected[k])) fail('context_provenance_source_changed');
  };
  const read = value => {
    record(value);
    if (value.read_only !== true || value.transaction_created !== false ||
        Object.hasOwn(value, 'published') && value.published !== false) fail('context_provenance_not_read_only');
  };
  const channel = (value, selected, kind) => {
    check(); read(value); sameFields(value, selected, ENVELOPE_FIELDS);
    const symbol = kind === 'symbol';
    if (![1, 2].includes(value.schema_version) || value.published !== false ||
        value.type !== (symbol ? 'source_search_symbols_index' : 'source_search_index') ||
        value.profile !== (symbol ? 'rust-declaration-heads-v1' : 'ascii-word-postings-v1') ||
        (!symbol && value.channel !== kind) ||
        Object.hasOwn(value, 'forge_position_root') && value.forge_position_root !== selected.forge_position_root) fail('context_provenance_channel_changed');
  };

  check(); read(context);
  const r = record(context.retrieval); read(r);
  if (context.type !== 'source_context_initial' || context.schema_version !== 1 || context.source_material_untrusted !== true ||
      r.type !== 'source_search_initial' || r.schema_version !== 1) fail('unsupported_native_context');
  const current = context.profile === 'source-initial-context-revalidated-v1';
  if (!current) {
    if (context.profile !== 'source-initial-context-v1' || r.profile !== 'source-initial-retrieval-v1' ||
        [context, r].some(v => ['index_source', 'current_source', 'index_sources'].some(k => Object.hasOwn(v, k)))) fail('unsupported_native_context');
    check(); return null;
  }
  if (context.index_source !== CURRENT_INDEX_SOURCE || r.index_source !== CURRENT_INDEX_SOURCE ||
      r.profile !== 'source-initial-revalidated-v1') fail('unsupported_index_source');
  if (context.selection !== 'raw-path-prefix' || Object.hasOwn(context, 'ranking')) fail('unsupported_context_selection');
  if (Object.hasOwn(context, 'current_source') || Object.hasOwn(context, 'index_sources')) fail('invalid_context_provenance_fields');
  const selected = source(r.current_source);
  sameFields(r, selected, JOIN_FIELDS);
  for (const k of ['source_head', 'forge_position_root']) {
    if (Object.hasOwn(r, k) && r[k] !== selected[k]) fail('context_provenance_source_changed');
  }
  keys(r.index_sources, ['lexical', 'symbols']);
  const lexical = source(r.index_sources.lexical);
  sameFields(lexical, selected, NATIVE_FIELDS);
  channel(r.content, lexical, 'content'); channel(r.path, lexical, 'path');
  const symbol = record(r.symbols); let symbols = null;
  if (symbol.state === 'available') {
    keys(symbol, ['state', 'result']);
    symbols = source(r.index_sources.symbols);
    sameFields(symbols, selected, NATIVE_FIELDS);
    channel(symbol.result, symbols, 'symbol');
  } else {
    if (r.index_sources.symbols !== null) fail('context_provenance_symbol_changed');
    if (symbol.state === 'not_requested') keys(symbol, ['state']);
    else if (symbol.state === 'unavailable') {
      keys(symbol, ['state', 'reason', 'result']);
      if (symbol.result !== null || !['uninitialized', 'stale'].includes(symbol.reason)) fail('context_provenance_symbol_changed');
    } else fail('context_provenance_symbol_changed');
  }
  const positions = [selected, lexical, ...(symbols ? [symbols] : [])];
  for (let i = 0; i < positions.length; i++) for (let j = i + 1; j < positions.length; j++) {
    const a = positions[i], b = positions[j];
    if ((a.snapshot_token === b.snapshot_token || a.source_head === b.source_head) &&
        ['source_head', 'snapshot_token', 'source_rcr', 'forge_position_root'].some(k => a[k] !== b[k])) fail('context_provenance_head_changed');
  }
  check(); return { mode: CURRENT_INDEX_SOURCE, current: selected, lexical, symbols };
}
