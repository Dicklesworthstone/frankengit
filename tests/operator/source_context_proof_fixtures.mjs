// Native context wire projection for byte-proof tests only. Retrieval ranking,
// query results and coverage are deliberately not simulated or authenticated.
import { fixture, token, hex } from './fixtures/source_archive_native.mjs';
export { token, hex };
export const definitions = [
  { path: 'src/main.rs', kind: 'executable', data: Buffer.from('/* preamble */\r\npub fn Verify() { /* untrusted */ }\n') },
  { path: Buffer.from('src/\xff.rs', 'latin1'), data: Buffer.from('pub struct Other;\n') },
  { path: 'elsewhere/many/ignored', data: Buffer.alloc(200000, 9) },
];
export async function setup(t, format = 'sha1', defs = definitions) {
  const f = await fixture(t, { format, definitions: defs });
  const files = [...f.repo.files].filter(([path]) => !path.startsWith(hex('elsewhere/'))).map(([path, row]) => {
    const from = Math.min(4, row.data.length), end = Math.min(from + 9, row.data.length);
    return { path_hex: path, blob: `${format}:${row.id}`, source_bytes: row.data.length, anchors: [],
      excerpts: [{ byte_offset: from, untrusted_bytes_hex: hex(row.data.subarray(from, end)) }] };
  }).sort((a, b) => a.path_hex < b.path_hex ? -1 : 1);
  const context = { type: 'source_context_initial', schema_version: 1, profile: 'source-initial-context-v1',
    read_only: true, transaction_created: false, source_material_untrusted: true, returned_files: files.length, files,
    retrieval: { type: 'source_search_initial', schema_version: 1, profile: 'source-initial-retrieval-v1',
      ...f.repo.scope, ref: f.selection.ref, ref_hex: hex(f.selection.ref), snapshot_token: f.repo.snapshot,
      source_commit: `${format}:${f.repo.commit}`, root_tree: `${format}:${f.repo.root.id}`, source_rcr: 'fixture-rcr',
      read_only: true, transaction_created: false } };
  return { ...f, context };
}
export const bytes = value => Buffer.from(`${JSON.stringify(value)}\n`);
