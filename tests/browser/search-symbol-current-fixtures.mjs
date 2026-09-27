// Native-format wrapper from source/symbols/indexed/current.rs. This is an
// injected HTTP fixture, not a live Rust-node or authenticated-authority proof.
import { fixture, transport, response } from './search-symbol-fixtures.mjs';
export { fixture, selected, token, href, hex, utf8, webcrypto, response, deferred } from './search-symbol-fixtures.mjs';
export function currentFixture(format = 'sha1', options = {}) {
  const f = fixture(format, options);
  const names = ['tenant_id', 'repository_id', 'repository_incarnation', 'object_format', 'ref', 'ref_hex',
    'source_head', 'snapshot_token', 'source_rcr', 'source_commit', 'root_tree'];
  const indexed = { ...Object.fromEntries(names.map(name => [name, f.source[name]])), forge_position_root: 'forge-A' };
  const current = { ...indexed, source_head: 'source-head-B', snapshot_token: `alg:2:${'8'.repeat(64)}`,
    source_rcr: 'source-rcr-B', forge_position_root: 'forge-B' };
  const wrapper = () => ({ type: 'source_search_symbols_index_revalidated', schema_version: 1, source_mode: 'revalidated',
    read_only: true, transaction_created: false, published: false,
    current_source: structuredClone(current), indexed_source: structuredClone(indexed), result: structuredClone(f.reply) });
  return { ...f, current, indexed, wrapper, currentInput: { ...f.input, sourceMode: 'revalidated' },
    currentFile: offset => ({ ...f.file(offset), ...current }) };
}
export function currentTransport(f, intercept = () => null) {
  return transport(f, async call => {
    const overridden = await intercept(call);
    if (overridden) return overridden;
    if (call.url.endsWith('/source/search-symbols-index') && call.fields.get('source_mode') === 'revalidated') {
      const reply = f.wrapper();
      for (const key of ['name_hex', 'match']) reply.result[key] = call.fields.get(key);
      for (const key of ['max_matches', 'max_work']) reply.result[key] = Number(call.fields.get(key));
      reply.result.kinds = call.fields.getAll('kind'); reply.result.path_prefix_hex = call.fields.getAll('path_prefix_hex');
      return response(reply);
    }
    if (call.url.endsWith('/source/blob')) return response(f.currentFile(Number(call.fields.get('offset'))));
    return null;
  });
}
