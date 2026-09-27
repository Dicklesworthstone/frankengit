// Complete native graphs for the real transfer client; not a simulated verifier.
import { objectId, bundle, literalDelta } from './bundle-verify-fixtures.mjs';
import { TransferClient } from '../../crates/fgit-node/src/smart_http/server/browser/transfers.mjs';
import { crypto, token, page, binary, json } from './export-integrity-fixtures.mjs';
export function completeBundle(format = 'sha1', { omit = null, file = Buffer.from('file\0bytes\r\n'), delta = null, refCount = 1 } = {}) {
  const blob = { kind: 'blob', body: Buffer.from(file) }, blobId = objectId('blob', blob.body, format);
  const tree = { kind: 'tree', body: Buffer.concat([Buffer.from('100644 file\0'), Buffer.from(blobId, 'hex')]) };
  const treeId = objectId('tree', tree.body, format);
  const commit = { kind: 'commit', body: Buffer.from(`tree ${treeId}\nauthor Test <t@invalid> 1700000000 +0000\ncommitter Test <t@invalid> 1700000000 +0000\n\nfixture\n`) };
  const tip = objectId('commit', commit.body, format);
  let records = [blob, tree, commit].filter(value => value.kind !== omit);
  if (delta && !omit) {
    const base = { kind: 'blob', body: Buffer.from('base') };
    records = [base, { type: delta, base: 0, baseId: objectId('blob', base.body, format), body: literalDelta(base.body, blob.body) }, tree, commit];
  }
  const rows = Array.from({ length: refCount }, (_, n) => ({ ref: n === 0 ? 'refs/heads/main' : `refs/tags/tag-${String(n).padStart(4, '0')}`, object_id: tip }))
    .map(row => ({ ...row, ref_hex: Buffer.from(row.ref).toString('hex') }));
  const bytes = new Uint8Array(bundle(records, format, { refs: rows.map(row => ({ name: row.ref, id: row.object_id })) }));
  return { bytes, rows, tip, blobId, treeId, records, format };
}
export async function connectedTransfer(fixture = completeBundle(), { customize = () => null, cryptoImpl = crypto } = {}) {
  const calls = [];
  const client = new TransferClient({ href: 'https://forge.invalid/r.git/ui/transfers/', cryptoImpl,
    fetchImpl: async (url, init) => {
      const path = new URL(url).pathname.split('/api/v1/')[1], fields = new URLSearchParams(init.body);
      calls.push({ path, ...init });
      const override = await customize(path, fields, init); if (override) return override;
      if (path === 'source/refs') {
        const after = fields.get('after'), limit = Number(fields.get('limit'));
        const rows = fixture.rows.filter(row => after === null || row.ref > after).slice(0, limit);
        const more = rows.length && fixture.rows.at(-1).ref !== rows.at(-1).ref;
        return json(page(fixture.format, rows, { after, limit, next_after: more ? rows.at(-1).ref : null }));
      }
      if (path === 'source/bundle/export') return binary(fixture.bytes, fixture.format);
      throw new Error(`Unexpected API request: ${path}`);
    } });
  await client.connect(token); await client.select(fixture.format); return { client, calls, fixture };
}
