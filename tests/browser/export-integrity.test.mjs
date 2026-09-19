import test from 'node:test';
import assert from 'node:assert/strict';
import { TransferClient } from '../../crates/fgit-node/src/smart_http/server/browser/transfers.mjs';
import { exportInventory, verifyExportManifest, EXPORT_MANIFEST_LIMIT, REF_LIMIT, HEADER_LIMIT }
  from '../../crates/fgit-node/src/smart_http/server/browser/transfers-protocol.mjs';
import { crypto, token, head, oid, row, page, bundle, binary, json, deferred, hex, encode } from './export-integrity-fixtures.mjs';
const href = 'https://forge.invalid/r.git/ui/transfers/';
async function ready(algorithm = 'sha1', customize = null, cryptoImpl = crypto) {
  const calls = [], input = bundle(algorithm);
  const client = new TransferClient({ href, cryptoImpl, fetchImpl: async (url, init) => {
    const path = new URL(url).pathname.split('/api/v1/')[1]; calls.push({ path, ...init });
    const fields = new URLSearchParams(typeof init.body === 'string' ? init.body : '');
    if (customize) { const result = await customize(path, fields, input, init); if (result) return result; }
    if (path === 'source/refs') return json(page(algorithm, fields.get('limit') === '1' ? [] : [row('refs/heads/main', algorithm)], { limit: Number(fields.get('limit')) }));
    if (path === 'source/bundle/export') return binary(input, algorithm);
    throw new Error('Unexpected write');
  } });
  await client.connect(token); await client.select(algorithm); return { client, input, calls };
}
for (const algorithm of ['sha1', 'sha256']) {
  test(`${algorithm}: complete snapshot export has a token-free offline-checkable manifest`, async () => {
    const { client, calls, input } = await ready(algorithm); await client.exportBundle({ verifyInventory: true });
    const manifest = client.exportManifest(); assert(!manifest.includes(token));
    const report = await verifyExportManifest(input, manifest, crypto);
    assert.equal(report.live_snapshot_rechecked, false); assert.equal(report.objects_verified, false);
    assert.equal(report.manifest.bundle.sha256, client.exported.sha256);
    assert.equal(report.manifest.snapshot, head); assert.equal(report.manifest.snapshot_refs_checked, true);
    assert.deepEqual(calls.map(c => c.path), ['source/refs', 'source/refs', 'source/bundle/export']);
    for (const call of calls.slice(1)) {
      assert.equal(new URLSearchParams(call.body).get('expected_head'), head);
      assert.equal(call.headers['Idempotency-Key'], undefined); assert.equal(call.method, 'POST');
    }
    const copy = client.exportBytes(); copy.fill(0); assert.deepEqual(client.exportBytes(), input);
  });
  test(`${algorithm}: a checksum-valid but incomplete or substituted ref set cannot be saved`, async () => {
    for (const inventory of [[row('refs/heads/missing', algorithm)], [row('refs/heads/main', algorithm), row('refs/tags/extra', algorithm)]]) {
      const { client } = await ready(algorithm, (path, fields) => path === 'source/refs' && fields.get('limit') === '100' ? json(page(algorithm, inventory)) : null);
      await assert.rejects(client.exportBundle({ verifyInventory: true })); assert.equal(client.exported, null); assert.throws(() => client.exportManifest());
    }
  });
  test(`${algorithm}: lossless non-UTF-8 final refs do not become text aliases`, async () => {
    const native = { ref: null, ref_hex: hex(encode('refs/tags/')) + 'ff', object_id: oid(algorithm) };
    const input = bundle(algorithm, [native]);
    const { client } = await ready(algorithm, (path, fields) => path === 'source/bundle/export' ? binary(input, algorithm) :
      path === 'source/refs' && fields.get('limit') === '100' ? json(page(algorithm, [native])) : null);
    await client.exportBundle({ verifyInventory: true });
    assert.equal((await verifyExportManifest(input, client.exportManifest(), crypto)).manifest.bundle.refs[0].ref_hex, native.ref_hex);
  });
}
test('sample-only legacy export cannot claim a complete ref inventory', async () => {
  const { client, calls } = await ready(); await client.exportBundle();
  assert.equal(calls.length, 2); assert.throws(() => client.exportManifest());
});
for (const [field, value] of Object.entries({ namespace: 'branches', after: 'refs/heads/other', limit: 1, read_only: false,
  transaction_created: true, published: true, direct_refs_only: false, repository_incarnation: 'other', source_head: null, snapshot_token: 'invalid' })) {
  test(`inventory rejects changed ${field}`, async () => {
    const { client, calls } = await ready('sha1', (path, fields) => path === 'source/refs' && fields.get('limit') === '100' ? json(page('sha1', undefined, { [field]: value })) : null);
    await assert.rejects(client.exportBundle({ verifyInventory: true })); assert.equal(client.exported, null);
    assert(!calls.some(c => c.path === 'source/bundle/export'));
  });
}
for (const [name, modify] of [
  ['ref text alias', rows => { rows[0].ref = 'refs/heads/other'; }],
  ['zero oid', rows => { rows[0].object_id = '0'.repeat(40); }],
  ['duplicate row', rows => rows.push(rows[0])],
  ['invalid name', rows => { rows[0].ref_hex = hex(encode('refs/heads/../a')); }],
]) test(`inventory rejects ${name}`, async () => {
  const rows = [row('refs/heads/main')]; modify(rows);
  const { client } = await ready('sha1', (path, fields) => path === 'source/refs' && fields.get('limit') === '100' ? json(page('sha1', rows)) : null);
  await assert.rejects(client.exportBundle({ verifyInventory: true }));
});
test('all pages remain tied to one head and raw byte order', async () => {
  const rows = Array.from({ length: 101 }, (_, i) => row(`refs/heads/a${String(i).padStart(3, '0')}`)); const calls = [];
  const selected = { scope: { tenant: 'tenant', repository: 'repository', incarnation: 'incarnation', format: 'sha1' }, head };
  const transport = { request: async (_path, init) => {
    const f = new URLSearchParams(init.body); calls.push(f);
    return { value: calls.length === 1 ? page('sha1', rows.slice(0, 100), { next_after: rows[99].ref }) : page('sha1', rows.slice(100), { after: rows[99].ref }) };
  } };
  assert.equal((await exportInventory(transport, selected)).refs.length, 101);
  assert.equal(calls[1].get('expected_head'), head); assert.equal(calls[1].get('after'), rows[99].ref);
});
for (const field of ['repository_incarnation', 'snapshot_token', 'source_head']) test(`later inventory page cannot change ${field}`, async () => {
  const rows = Array.from({ length: 100 }, (_, i) => row(`refs/heads/a${String(i).padStart(3, '0')}`)); let n = 0;
  const { client } = await ready('sha1', (path, fields) => {
    if (path !== 'source/refs' || fields.get('limit') !== '100') return null;
    return json(++n === 1 ? page('sha1', rows, { next_after: rows[99].ref }) : page('sha1', [row('refs/heads/z')], { after: rows[99].ref, [field]: 'other' }));
  }); await assert.rejects(client.exportBundle({ verifyInventory: true }));
});
test('inventory with only ref-count budget progress refuses rather than claiming exhaustion', async () => {
  let n = 0;
  const { client, calls } = await ready('sha1', (path, fields) => {
    if (path !== 'source/refs' || fields.get('limit') !== '100') return null;
    const rows = Array.from({ length: 100 }, () => row(`refs/heads/a${String(n++).padStart(5, '0')}`));
    return json(page('sha1', rows, { after: fields.get('after'), next_after: rows.at(-1).ref }));
  }); await assert.rejects(client.exportBundle({ verifyInventory: true }));
  assert(calls.length <= Math.ceil(REF_LIMIT / 100) + 1); assert(!calls.some(c => c.path === 'source/bundle/export'));
});
test('inventory byte budgets, dishonest cursors and empty exports are explicit refusals', async () => {
  for (const rows of [[], Array.from({ length: 100 }, (_, i) => row(`refs/heads/a${i.toString().padStart(3, '0')}${'x'.repeat(4000)}`))]) {
    const { client } = await ready('sha1', (path, fields) => path === 'source/refs' && fields.get('limit') === '100' ? json(page('sha1', rows)) : null);
    await assert.rejects(client.exportBundle({ verifyInventory: true }));
  }
  const { client } = await ready('sha1', (path, fields) => path === 'source/refs' && fields.get('limit') === '100' ? json(page('sha1', undefined, { next_after: 'refs/heads/main' })) : null);
  await assert.rejects(client.exportBundle({ verifyInventory: true }));
});
test('export head text must also agree with the pinned inventory receipt', async () => {
  const { client } = await ready('sha1', (path, _fields, input) => path === 'source/bundle/export' ? binary(input, 'sha1', { 'x-fgit-source-head': 'another head' }) : null);
  await assert.rejects(client.exportBundle({ verifyInventory: true })); assert.equal(client.exported, null);
});
test('lost/cancelled inventory reads cannot trigger an export or restore stale downloads', async () => {
  const gate = deferred(), arrived = deferred();
  const { client, calls } = await ready('sha1', async (path, fields) => {
    if (path === 'source/refs' && fields.get('limit') === '100') { arrived.resolve(); await gate.promise; return json(page()); }
  }); const pending = client.exportBundle({ verifyInventory: true }); await arrived.promise; client.disconnect(); gate.resolve();
  await assert.rejects(pending); assert(!calls.some(c => c.path === 'source/bundle/export')); assert.equal(client.exported, null);
});
for (const [name, change] of [
  ['manifest schema', r => { r.schema_version = 2; }], ['untrusted extra field', r => { r.token = 'x'; }],
  ['missing scope', r => { delete r.scope.incarnation; }], ['wrong format', r => { r.scope.format = 'sha256'; }],
  ['invented authentication', r => { r.independently_authenticated = true; }], ['forge backup claim', r => { r.forge_state_included = true; }],
  ['ref omission', r => { r.bundle.refs = []; }], ['ref target', r => { r.bundle.refs[0].object_id = 'c'.repeat(40); }],
  ['digest', r => { r.bundle.sha256 = '0'.repeat(64); }], ['pack count', r => { r.bundle.declared_pack_objects++; }],
  ['object proof', r => { r.bundle.objects_verified = true; }], ['origin injection', r => { r.origin += '/evil'; }],
  ['extra ref property', r => { r.bundle.refs[0].granted = true; }],
]) test(`offline manifest rejects ${name}`, async () => {
  const { client, input } = await ready(); await client.exportBundle({ verifyInventory: true });
  const m = JSON.parse(client.exportManifest()); change(m); await assert.rejects(verifyExportManifest(input, JSON.stringify(m), crypto));
});
test('offline verification rejects changed bundle bytes and accepts harmless JSON key order', async () => {
  const { client, input } = await ready(); await client.exportBundle({ verifyInventory: true }); const m = JSON.parse(client.exportManifest());
  m.bundle = Object.fromEntries(Object.entries(m.bundle).reverse());
  assert.equal((await verifyExportManifest(input, JSON.stringify(m), crypto)).objects_verified, false);
  const bad = input.slice(); bad[bad.length - 1] ^= 1; await assert.rejects(verifyExportManifest(bad, JSON.stringify(m), crypto));
  await assert.rejects(verifyExportManifest(input, 'x'.repeat(EXPORT_MANIFEST_LIMIT + 1), crypto));
});
test('offline hashes can be cancelled and do not fetch manifest provenance URLs', async () => {
  const { client, input, calls } = await ready(); await client.exportBundle({ verifyInventory: true }); const n = calls.length;
  const manifest = client.exportManifest(); let checkpoints = 0;
  await assert.rejects(verifyExportManifest(input, manifest, crypto, () => { if (++checkpoints === 3) throw new Error('cancelled'); }));
  assert.equal(calls.length, n);
});
test('a pending import blocks audited export without changing the original request', async () => {
  const { client, input, calls } = await ready(); await client.load(input); await client.stage('import'); const p = client.pending, n = calls.length;
  await assert.rejects(client.exportBundle({ verifyInventory: true })); assert.deepEqual(client.pending, p); assert.equal(calls.length, n);
});
