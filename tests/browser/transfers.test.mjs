import test from 'node:test';
import assert from 'node:assert/strict';
import { TransferClient } from '../../crates/fgit-node/src/smart_http/server/browser/transfers.mjs';
import { Transport } from '../../crates/fgit-node/src/smart_http/server/browser/pulls-core.mjs';
import { inspectBundle, transferCommand, BUNDLE_LIMIT, HEADER_LIMIT, bundleRef } from '../../crates/fgit-node/src/smart_http/server/browser/transfers-protocol.mjs';
import { fixture, bundleBytes, crypto, href, token, head, hex, sha, json, deferred, decodeUpload } from './transfers-fixtures.mjs';
const mapping = () => ({ source_hex: hex('refs/heads/main'), destination_hex: hex('refs/remotes/import/main'), expected_old: null });
async function connected(f) { const c = new TransferClient({ href, fetchImpl: f.fetchImpl, cryptoImpl: crypto }); await c.connect(token); return c; }
async function loaded(f) { const c = await connected(f); await c.select(f.algorithm); await c.load(f.input); return c; }
async function staged(f, operation = 'fetch') { const c = await loaded(f); await c.stage(operation, operation === 'fetch' ? [mapping()] : []); return c; }
for (const algorithm of ['sha1', 'sha256']) {
  test(`${algorithm}: snapshot-bound export retains exact bytes without an idempotency key`, async () => {
    const f = fixture(algorithm), c = await connected(f); await c.select(algorithm);
    const report = await c.exportBundle(); assert.equal(report.sha256, sha(f.input)); assert.deepEqual(c.exportBytes(), f.input);
    assert.equal(report.pack_checksum_verified, true); assert.equal(report.objects_verified, false);
    const request = f.calls.at(-1); assert.equal(request.headers['idempotency-key'], undefined);
    assert.deepEqual(Object.fromEntries(new URLSearchParams(request.body)), { object_format: algorithm, expected_head: head });
    assert.equal(request.credentials, 'omit'); assert.equal(request.redirect, 'error');
    const bytes = c.exportBytes(); bytes[0] = 0; assert.deepEqual(c.exportBytes(), f.input);
  });
  for (const operation of ['import', 'fetch']) test(`${algorithm}: ${operation} freezes exact bundle, digest and leases before one explicit send`, async () => {
    const f = fixture(algorithm), c = await staged(f, operation), p = c.pending;
    assert.equal(f.calls.length, 1); assert.equal(p.sent, false);
    const terminal = await c.send(); assert.equal(terminal.outcome, 'committed'); assert.equal(c.pending, null);
    const call = f.calls.at(-1), upload = decodeUpload(call);
    assert.equal(call.path, `source/bundle/${operation}`); assert.deepEqual(upload.payload, f.input);
    assert.equal(upload.fields.get('artifact_sha256'), sha(f.input)); assert.equal(upload.fields.get('object_format'), algorithm);
    assert.equal(upload.fields.has('force'), false); assert.equal(upload.fields.has('expected_head'), false);
    assert.deepEqual(upload.fields.getAll('mapping'), operation === 'fetch' ? [`${hex('refs/heads/main')}:${hex('refs/remotes/import/main')}:absent`] : []);
    assert.equal(call.headers['idempotency-key'], p.key); assert.equal(terminal.deliveryAcknowledged, null);
  });
  test(`${algorithm}: exact old-tip fetch lease and byte-valued mapping are preserved`, async () => {
    const f = fixture(algorithm), c = await loaded(f), old = 'b'.repeat(algorithm === 'sha1' ? 40 : 64);
    const m = { ...mapping(), destination_hex: hex('refs/remotes/import/') + 'ff', expected_old: old };
    await c.stage('fetch', [m]); m.expected_old = null; await c.send();
    assert.deepEqual(decodeUpload(f.calls.at(-1)).fields.getAll('mapping'), [`${mapping().source_hex}:${m.destination_hex}:${old}`]);
  });
  test(`${algorithm}: lost reply/restart retries original bytes and key without any ref refresh`, async () => {
    const f = fixture(algorithm), c = await staged(f); f.config.lose = true;
    await assert.rejects(c.send(), e => e.outcomeUnknown); const original = f.calls.at(-1), receipt = c.exportReceipt();
    assert(!receipt.includes(token)); c.disconnect(); assert(c.pending);
    const next = await connected(f); const before = f.calls.length; await next.restoreReceipt(receipt);
    assert.equal(f.calls.length, before); assert.equal(next.pending.sent, true);
    f.config.lose = false; await next.send(); assert.equal(f.calls.length, before + 1);
    assert.deepEqual(f.calls.at(-1).body, original.body); assert.equal(f.calls.at(-1).headers['idempotency-key'], original.headers['idempotency-key']);
  });
  test(`${algorithm}: canonical refusal is a terminal refusal, not publication success`, async () => {
    const f = fixture(algorithm), c = await staged(f, 'import'); f.config.refuse = true;
    assert.equal((await c.send()).outcome, 'refused'); assert.equal(c.pending, null);
  });
}
for (const [name, change] of [
  ['artifact hash', r => r.headers['X-Fgit-Artifact-Sha256'] = '0'.repeat(64)],
  ['snapshot', r => r.headers['X-Fgit-Snapshot'] = `alg:1:${'8'.repeat(64)}`],
  ['incarnation', r => r.headers['X-Fgit-Repository-Incarnation'] = '8'.repeat(32)],
  ['format', r => r.headers['X-Fgit-Object-Format'] = 'sha256'],
  ['profile', r => r.headers['X-Fgit-Bundle-Profile'] = 'capsule'],
  ['read-only', r => r.headers['X-Fgit-Read-Only'] = 'false'],
  ['media', r => r.headers['Content-Type'] = 'text/html'],
  ['truncation', r => r.bytes = r.bytes.slice(0, -1)],
  ['wrong checksum', r => r.bytes[r.bytes.length - 1] ^= 1],
]) test(`invalid export ${name} never leaves a downloadable artifact`, async () => {
  const f = fixture(), c = await connected(f); await c.select('sha1'); await c.exportBundle();
  f.config.export = change; await assert.rejects(c.exportBundle()); assert.equal(c.exported, null); assert.throws(() => c.exportBytes());
});
test('headers, duplicate refs, prerequisites, detached HEAD and capabilities are bounded and closed', async () => {
  const id = 'a'.repeat(40), good = `${id} refs/heads/main\n\n`;
  for (const header of ['garbage\n\n', `# v2 git bundle\n@object-format=sha1\n${good}`, `# v3 git bundle\n@filter=blob:none\n${good}`,
    `# v3 git bundle\n@object-format=sha1\n@object-format=sha1\n${good}`, `# v2 git bundle\n-${id} missing\n${good}`,
    `# v2 git bundle\n${id} refs/heads/main\n${id} refs/heads/main\n\n`, `# v2 git bundle\n${id} HEAD\n\n`,
    `# v2 git bundle\n${'b'.repeat(40)} HEAD\n${good}`, `# v2 git bundle\n${id} refs/heads/../secret\n\n`,
    `# v2 git bundle\n${'0'.repeat(40)} refs/heads/main\n\n`, `# v2 git bundle\n${id} refs/heads/main\n${id} HEAD\n${id} HEAD\n\n`]) {
    await assert.rejects(inspectBundle(bundleBytes('sha1', header), crypto));
  }
  await assert.rejects(inspectBundle(new Uint8Array(BUNDLE_LIMIT + 1), crypto));
  await assert.rejects(inspectBundle(bundleBytes('sha1', '# v2 git bundle\n' + 'x'.repeat(HEADER_LIMIT)), crypto));
  await assert.rejects(inspectBundle(bundleBytes().slice(0, 20), crypto));
});
test('ordinary ref order, uppercase OIDs and arbitrary native ref bytes survive header inspection', async () => {
  const id = 'A'.repeat(40), header = Buffer.concat([Buffer.from(`# v2 git bundle\n${id} refs/heads/z\n${id} refs/heads/`), Buffer.from([255]), Buffer.from(`\n${id} refs/heads/a\n\n`)]);
  const plan = await inspectBundle(bundleBytes('sha1', header), crypto);
  assert.equal(plan.summary.refs.length, 3); assert.equal(plan.summary.refs[0].ref_hex, hex('refs/heads/a'));
  assert.equal(plan.summary.refs[2].ref_hex, hex('refs/heads/') + 'ff'); assert.equal(plan.summary.refs[0].object_id, id.toLowerCase());
});
test('load owns bytes before asynchronous hashing; returned summaries cannot change publication', async () => {
  const f = fixture(), c = await connected(f); await c.select('sha1'); const input = f.input.slice(), promise = c.load(input);
  input.fill(0); await promise; c.bundle.refs[0].object_id = 'b'.repeat(40); await c.stage('import');
  c.pending.fields.artifact_sha256 = '0'.repeat(64); await c.send(); assert.deepEqual(decodeUpload(f.calls.at(-1)).payload, f.input);
});
test('invalid replacement bundle clears the prior preparation; hash domains cannot be mixed', async () => {
  const f = fixture(), c = await loaded(f); await assert.rejects(c.load(bundleBytes('sha256'))); assert.equal(c.bundle, null);
  await assert.rejects(c.stage('import')); await assert.rejects(c.load(Uint8Array.of(1))); assert.equal(c.bundle, null);
});
test('fetch requires explicit distinct destinations, advertised sources and absence or exact old OIDs', async () => {
  const { summary } = await inspectBundle(bundleBytes(), crypto);
  for (const rows of [[], [mapping(), mapping()], [{ ...mapping(), source_hex: hex('HEAD') }],
    [{ ...mapping(), source_hex: hex('refs/heads/missing') }], [{ ...mapping(), expected_old: undefined }],
    [{ ...mapping(), expected_old: '0'.repeat(40) }], [{ ...mapping(), force: true }],
    Array.from({ length: 65 }, (_, i) => ({ ...mapping(), destination_hex: hex(`refs/heads/d${i}`) }))]) assert.throws(() => transferCommand('fetch', summary, rows));
  assert.throws(() => transferCommand('import', summary, [mapping()]));
  assert.throws(() => transferCommand('force', summary));
  for (const r of ['', hex('HEAD'), hex('refs/heads/..'), hex('refs/heads/a.lock'), hex('refs/heads/a\0b')]) assert.throws(() => bundleRef(r));
});
test('mapping order is canonical and different source refs may target distinct destinations', async () => {
  const f = fixture(), c = await loaded(f), a = mapping(), b = { ...mapping(), destination_hex: hex('refs/heads/a') };
  await c.stage('fetch', [a, b]); assert.equal(c.pending.updates[0].destination_hex, b.destination_hex);
  await c.send(); assert.equal(decodeUpload(f.calls.at(-1)).fields.getAll('mapping').length, 2);
});
for (const [name, change] of [
  ['wrong operation', r => r.operation = 'import'], ['wrong count', r => r.command_count++],
  ['non-atomic', r => r.atomic = false], ['nonterminal', r => r.terminal = false], ['forge import', r => r.forge_state_imported = true],
  ['default HEAD change', r => r.default_branch_changed = true], ['invented revalidation', r => r.receipt_confirms_transport_revalidation = true],
  ['wrong incarnation', r => r.repository_incarnation = '8'.repeat(32)], ['conflicting decision', r => r.decision.code = 'Refused'],
]) test(`a ${name} receipt cannot discard the original transfer`, async () => {
  const f = fixture(), c = await staged(f); f.config.terminal = change;
  await assert.rejects(c.send(), e => e.outcomeUnknown); assert(c.pending); assert.throws(() => c.discardUnsent());
});
test('generic native errors do not masquerade as terminal decisions', async () => {
  const f = fixture(), original = f.fetchImpl;
  f.fetchImpl = (url, options) => String(url).endsWith('/fetch') ? json({ type: 'source_error', code: 'invalid_or_unsupported_full_bundle' }, 409) : original(url, options);
  const c = await staged(f); await assert.rejects(c.send()); assert(c.pending);
});
for (const [name, change] of [
  ['origin', r => r.origin = 'https://other.example'], ['route', r => r.route = '/other.git'],
  ['target', r => r.mappings[0].destination_hex = hex('refs/heads/other')], ['lease', r => r.mappings[0].expected_old = '8'.repeat(40)],
  ['scope', r => r.scope.incarnation = '8'.repeat(32)], ['nonce', r => r.nonce = '8'.repeat(32)],
  ['bundle bytes', r => r.bundle_base64 = Buffer.from(bundleBytes('sha1', `# v2 git bundle\n${'a'.repeat(40)} refs/heads/other\n\n`)).toString('base64')],
  ['extra field', r => r.force = true],
]) test(`saved transfer cannot change ${name} while retaining the original key`, async () => {
  const f = fixture(), c = await staged(f), r = JSON.parse(c.exportReceipt()); change(r);
  const next = await connected(f); await assert.rejects(next.restoreReceipt(JSON.stringify(r))); assert.equal(next.pending, null);
});
test('import receipts bind the complete advertised ref set', async () => {
  const f = fixture(), c = await staged(f, 'import'), r = JSON.parse(c.exportReceipt()); r.mappings.pop();
  const next = await connected(f); await assert.rejects(next.restoreReceipt(JSON.stringify(r))); assert.equal(next.pending, null);
});
test('only unsent/unexported preparation can be discarded', async () => {
  const f = fixture(), c = await staged(f); c.discardUnsent(); assert.equal(c.pending, null);
  await c.stage('fetch', [mapping()]); c.exportReceipt(); assert.throws(() => c.discardUnsent()); await assert.rejects(c.select('sha1'));
});
test('bodyless recovery retains uncertainty and forbids regression of observed identity', async () => {
  const f = fixture(), c = await staged(f);
  for (const state of ['key_not_observed', 'seal_not_observed', 'undecided']) {
    f.config.outcome = state; assert.equal((await c.recover()).terminal, false); assert(c.pending);
    assert.equal(f.calls.at(-1).path, 'outcomes'); assert.equal(f.calls.at(-1).body, undefined);
  }
  f.config.outcome = 'key_not_observed'; await assert.rejects(c.recover());
  f.config.outcome = 'committed'; f.config.recover = r => r.principal_id = '8'.repeat(32); await assert.rejects(c.recover());
  f.config.recover = null; assert.equal((await c.recover()).outcome, 'committed'); assert.equal(c.pending, null);
  assert(!f.calls.some(c => c.path === 'source/bundle/fetch'));
});
test('disconnect/cancel cannot erase a possibly published transfer or restore old export bytes', async () => {
  const f = fixture(), c = await staged(f); f.config.lose = true; await assert.rejects(c.send()); const before = c.pending;
  c.disconnect(); assert.deepEqual(c.pending, before); assert.equal(c.bundle, null); assert.equal(c.selection, null);
  await assert.rejects(c.connect('8'.repeat(64))); await c.connect(token);
  const other = await connected(f); await other.select('sha1'); const d = deferred(); f.config.export = () => d.promise;
  const exporting = other.exportBundle(); other.disconnect(); d.resolve(); await assert.rejects(exporting); assert.equal(other.exported, null);
});
test('canceling reads does not abort a submitted transfer', async () => {
  const f = fixture(), c = await staged(f), d = deferred(); f.config.terminal = () => d.promise;
  const sending = c.send(); await new Promise(setImmediate); const call = f.calls.at(-1);
  c.cancel(); assert.equal(call.signal.aborted, false); d.resolve(); assert.equal((await sending).outcome, 'committed');
});
test('transfer profile cannot call branch, PR, source-edit or initial-publication routes', async () => {
  for (const suffix of ['/ui/transfers/', '/ui/branches/', '/ui/source/', '/ui/initial/', '/ui/pulls/']) {
    const t = new Transport({ href: href.replace('/ui/transfers/', suffix), pageSuffix: suffix, cryptoImpl: crypto, fetchImpl: () => assert.fail('foreign dispatch') }); await t.connect(token);
    for (const path of suffix === '/ui/transfers/' ? ['source/apply', 'source/initial/apply', 'source/branches/delete', 'pulls/1/merge', 'source/bundle/export?ref=secret', '../outcomes'] : ['source/bundle/import']) await assert.rejects(t.request(path));
  }
});
test('selected response headers are opt-in and bounded; existing response shape stays unchanged', async () => {
  const t = new Transport({ href, pageSuffix: '/ui/transfers/', cryptoImpl: crypto, fetchImpl: () => json({ ok: true }) }); await t.connect(token);
  const r = await t.request('source/refs', { method: 'POST', body: 'x=y' }); assert.deepEqual(Object.keys(r).sort(), ['status', 'type', 'value']);
  for (const headerNames of [['x\r\nsecret'], Array(17).fill('x'), [null]]) await assert.rejects(t.request('source/refs', { headerNames }));
});
test('header selection is captured before awaiting transport', async () => {
  const d = deferred(), names = ['content-type'];
  const t = new Transport({ href, pageSuffix: '/ui/transfers/', cryptoImpl: crypto, fetchImpl: () => d.promise }); await t.connect(token);
  const running = t.request('source/refs', { method: 'POST', body: 'x=y', headerNames: names });
  names.push(...Array(100).fill('x-extra')); d.resolve(json({ ok: true }));
  assert.deepEqual(Object.keys((await running).headers), ['content-type']);
});
test('concurrent search profile retains its read-only restrictions and cannot call transfer routes', async () => {
  const t = new Transport({ href: href.replace('/ui/transfers/', '/ui/search/'), pageSuffix: '/ui/search/', cryptoImpl: crypto,
    fetchImpl: () => json({ ok: true }) }); await t.connect(token);
  for (const path of ['source/search', 'source/search-batch', 'source/search-regex', 'source/blob']) {
    assert.equal((await t.request(path, { method: 'POST', body: 'x=y' })).value.ok, true);
    for (const extra of [{ method: 'GET' }, { key: 'not-a-read' }, { read: false }, { binary: true }, { maximum: 8 * 1024 * 1024 + 1 }]) {
      await assert.rejects(t.request(path, { method: 'POST', body: 'x=y', ...extra }));
    }
  }
  await assert.rejects(t.request('source/bundle/import', { method: 'POST', body: 'x=y' }));
});
