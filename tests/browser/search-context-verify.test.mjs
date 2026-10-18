// Full verification module, WebCrypto and real byte payloads. The read callback
// is an explicit host adapter, not the production Transport or a Rust server.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, webcrypto } from 'node:crypto';
import { verifyContextFiles, CONTEXT_VERIFY_PROFILE } from '../../crates/fgit-node/src/smart_http/server/browser/search-context-verify.mjs';
import { fixture, check as context, copy, hex, oid } from './search-context-fixtures.mjs';
function sample(format = 'sha1') {
  const f = fixture(format);
  Object.assign(f.retrieval.query, { maxFileBytes: 8 * 1024 * 1024 });
  Object.assign(f.retrieval.symbols.result.hits[0], { line: 1, column: 12, excerptOffset: 0, excerptHex: hex(f.bytes.subarray(0, -1)) });
  const result = { ...f.retrieval, context: context(f) };
  const calls = [];
  const read = async (file, charge) => {
    calls.push(file.pathHex);
    for (let i = 0; i < Math.max(1, Math.ceil(f.bytes.length / 65536)); i++) charge();
    return { bytes: new Uint8Array(f.bytes), kind: 'file' };
  };
  return { f, result, calls, read };
}
const run = (s, options = {}, check = () => {}, crypto = webcrypto, read = s.read) => verifyContextFiles(s.result, read, crypto, check, options);
for (const format of ['sha1', 'sha256']) {
  test(`${format}: whole context hash, all channels and exact accounting`, async () => {
    const s = sample(format), before = copy(s.result), result = await run(s);
    assert.equal(result.profile, CONTEXT_VERIFY_PROFILE); assert.equal(result.completeSelectedContext, true);
    assert.equal(result.files.length, 1); assert.equal(result.files[0].blob, oid(s.f.bytes, format));
    assert.equal(result.files[0].lexicalDocuments, 2); assert.equal(result.files[0].declarations, 1);
    assert.equal(result.requests, 1); assert.equal(result.sourceBytesRead, s.f.bytes.length);
    assert.equal(result.excerptBytesVerified, s.f.bytes.length); assert.deepEqual(s.result, before);
    assert.deepEqual(result.generationVector, before.vector);
    for (const key of ['searchCoverageVerified', 'repositoryMembershipVerified', 'declarationSemanticsVerified']) assert.equal(result[key], false);
    assert.equal(result.sourceMaterialUntrusted, true); assert.equal('bytes' in result.files[0], false);
  });
  test(`${format}: content omitted from a zero-radius excerpt is still hashed`, async () => {
    const s = sample(format); s.result.context.files[0].excerpts = [{ offset: 11, bytesHex: hex('Thing') }]; s.result.context.excerptBytes = 5;
    const read = async (file, charge) => { charge(); const bytes = new Uint8Array(s.f.bytes); bytes[0] ^= 1; return { bytes, kind: 'file' }; };
    await assert.rejects(run(s, {}, () => {}, webcrypto, read), /hash mismatch/);
  });
  test(`${format}: immutable caller bytes are owned across asynchronous hashing`, async () => {
    const s = sample(format), actual = new Uint8Array(s.f.bytes), loaded = { bytes: actual, kind: 'file' };
    const crypto = { subtle: { digest: async (alg, framed) => {
      actual.fill(0); loaded.kind = 'symlink'; s.result.context.files[0].blob = 'bad';
      return webcrypto.subtle.digest(alg, framed);
    } } };
    const result = await run(s, {}, () => {}, crypto, async (file, charge) => { charge(); return loaded; });
    assert.equal(result.files[0].kind, 'file'); assert.equal(result.files[0].blob, oid(s.f.bytes, format));
  });
  test(`${format}: two independent files are verified once each, not once per hit`, async () => {
    const s = sample(format), first = s.result.context.files[0], second = copy(first); second.pathHex = hex('src/thing2.rs');
    s.result.context.files.push(second); s.result.context.sourceBlobsRead = 2;
    s.result.context.sourceBytesRead *= 2; s.result.context.excerptBytes *= 2;
    for (const child of [s.result.content, s.result.path, s.result.symbols.result]) {
      const next = copy(child.hits[0]); next.pathHex = second.pathHex; child.hits.push(next);
    }
    // The second raw path's word is thing2, not thing; remove that path witness.
    s.result.path.hits.pop(); second.anchors = second.anchors.filter(a => a.channel !== 'path');
    let digests = 0; const crypto = { subtle: { digest: (...args) => { digests++; return webcrypto.subtle.digest(...args); } } };
    const result = await run(s, {}, () => {}, crypto);
    assert.equal(digests, 2); assert.equal(result.requests, 2); assert.deepEqual(s.calls, [first.pathHex, second.pathHex]);
  });
}
for (const [name, change, pattern] of [
  ['changed excerpt outside the match', s => { s.result.context.files[0].excerpts[0].bytesHex = '78' + s.result.context.files[0].excerpts[0].bytesHex.slice(2); }, /excerpt/],
  ['wrong declaration line', s => { s.result.symbols.result.hits[0].line = 2; }, /coordinates/],
  ['wrong declaration column', s => { s.result.symbols.result.hits[0].column = 11; }, /coordinates/],
  ['false raw identifier', s => { s.result.symbols.result.hits[0].rawIdentifier = true; }, /coordinates/],
  ['wrong full declaration name', s => { s.result.symbols.result.hits[0].nameHex = hex('Other'); }, /excerpt or declaration/],
  ['declaration excerpt differs', s => { s.result.symbols.result.hits[0].excerptHex = hex('pub struct Other;'); }, /excerpt or declaration/],
  ['wrong content first-word span', s => { s.result.content.hits[0].spans[0].offset = 10; s.result.context.files[0].anchors[0].offset = 10; }, /first complete word/],
  ['wrong path first-word span', s => { s.result.path.hits[0].spans[0].offset = 3; s.result.context.files[0].anchors[1].offset = 3; }, /first complete word/],
  ['changed anchor inventory', s => { s.result.context.files[0].anchors.pop(); }, /anchors/],
  ['changed blob domain', s => { s.result.context.files[0].blob = 'sha1:' + s.result.context.files[0].blob; }, /normalized/],
  ['changed source accounting', s => { s.result.context.sourceBytesRead++; }, /accounting/],
  ['changed excerpt accounting', s => { s.result.context.excerptBytes++; }, /accounting/],
  ['duplicate selected file', s => { s.result.context.files.push(copy(s.result.context.files[0])); }, /path order/],
]) test(`rejects ${name}`, async () => { const s = sample(); change(s); await assert.rejects(run(s), pattern); });
for (const [name, limits] of [
  ['one byte under', { maxSourceBytes: 17 }], ['zero requests', { maxRequests: 0 }], ['null bound', { maxSourceBytes: null }],
  ['rounded bound', { maxSourceBytes: 1.5 }], ['unbounded source', { maxSourceBytes: 67108865 }],
  ['unknown parameter', { retries: true }], ['negative bound', { maxRequests: -1 }],
]) test(`preflight ${name} performs no reads`, async () => {
  const s = sample(); await assert.rejects(run(s, limits)); assert.deepEqual(s.calls, []);
});
test('exact byte/request limits permit the complete selection', async () => {
  const s = sample(); const result = await run(s, { maxSourceBytes: s.f.bytes.length, maxRequests: 1 });
  assert.equal(result.sourceBytesRead, s.f.bytes.length); assert.equal(result.requests, 1);
});
for (const kind of ['symlink', 'gitlink', 'tree', null]) test(`refuses non-regular kind ${kind}`, async () => {
  const s = sample(); await assert.rejects(run(s, {}, () => {}, webcrypto, async (f, charge) => { charge(); return { bytes: s.f.bytes, kind }; }), /regular file/);
});
test('executable bytes are verified without executing them', async () => {
  const s = sample(), v = await run(s, {}, () => {}, webcrypto, async (f, charge) => { charge(); return { bytes: s.f.bytes, kind: 'executable' }; });
  assert.equal(v.files[0].kind, 'executable');
});
for (const charges of [0, 2]) test(`refuses ${charges} page charges for one page`, async () => {
  const s = sample(); await assert.rejects(run(s, {}, () => {}, webcrypto, async (f, charge) => {
    for (let i = 0; i < charges; i++) charge(); return { bytes: s.f.bytes, kind: 'file' };
  }), /regular file|budget/);
});
test('no successful prefix after a later file read fails', async () => {
  const s = sample(), second = copy(s.result.context.files[0]); second.pathHex = hex('z/thing.rs');
  s.result.context.files.push(second); s.result.context.sourceBlobsRead = 2; s.result.context.sourceBytesRead *= 2; s.result.context.excerptBytes *= 2;
  for (const child of [s.result.content, s.result.path, s.result.symbols.result]) { const hit = copy(child.hits[0]); hit.pathHex = second.pathHex;
    if (child === s.result.path) hit.spans[0].offset = 2; child.hits.push(hit); }
  second.anchors[1].offset = 2;
  let reads = 0; await assert.rejects(run(s, {}, () => {}, webcrypto, async (f, charge) => { reads++; if (reads === 2) throw Error('source moved'); return s.read(f, charge); }), /source moved/);
  assert.equal(reads, 2); assert.equal('verification' in s.result, false);
});
test('cancellation is checked before I/O and after hashing', async () => {
  const s = sample(); await assert.rejects(run(s, {}, () => { throw Error('cancelled'); }), /cancelled/); assert.equal(s.calls.length, 0);
  let cancelled = false; const crypto = { subtle: { digest: async (...args) => { const digest = await webcrypto.subtle.digest(...args); cancelled = true; return digest; } } };
  await assert.rejects(run(s, {}, () => { if (cancelled) throw Error('cancelled'); }, crypto), /cancelled/);
});
test('an empty selection reports zero checks, never search completeness', async () => {
  const s = sample(); s.result.context.files = []; s.result.context.sourceBlobsRead = 0; s.result.context.sourceBytesRead = 0; s.result.context.excerptBytes = 0;
  const v = await run(s); assert.equal(v.files.length, 0); assert.equal(v.requests, 0); assert.equal(v.searchCoverageVerified, false); assert.equal(s.calls.length, 0);
});
test('multi-page source is budgeted before read and hashed with all bytes', async () => {
  const s = sample(); s.f.bytes = Buffer.concat([s.f.bytes, Buffer.alloc(65536, 32)]);
  const id = oid(s.f.bytes, 'sha1'); s.result.context.files[0].sourceBytes = s.f.bytes.length; s.result.context.files[0].blob = id;
  s.result.context.sourceBytesRead = s.f.bytes.length;
  for (const child of [s.result.content, s.result.path, s.result.symbols.result]) for (const hit of child.hits) { hit.blob = id; if ('contentBytes' in hit) hit.contentBytes = s.f.bytes.length; }
  await assert.rejects(run(s, { maxRequests: 1 }), /budget/); assert.equal(s.calls.length, 0);
  const v = await run(s, { maxRequests: 2 }); assert.equal(v.requests, 2);
  assert.equal(v.files[0].blob, createHash('sha1').update(`blob ${s.f.bytes.length}\0`).update(s.f.bytes).digest('hex'));
});

test('path-only empty source still needs one read and the exact empty Git blob hash', async () => {
  const s = sample(); s.f.bytes = Buffer.alloc(0); const file = s.result.context.files[0];
  file.blob = oid(s.f.bytes, 'sha1'); file.sourceBytes = 0; file.anchors = file.anchors.filter(a => a.channel === 'path');
  file.excerpts = [{ offset: 0, bytesHex: '' }]; s.result.context.sourceBytesRead = 0; s.result.context.excerptBytes = 0;
  s.result.content.hits = []; s.result.symbols = { state: 'not_requested' };
  Object.assign(s.result.path.hits[0], { blob: file.blob, contentBytes: 0 });
  const receipt = await run(s, { maxSourceBytes: 1, maxRequests: 1 });
  assert.equal(receipt.requests, 1); assert.equal(receipt.sourceBytesRead, 0); assert.equal(receipt.files[0].blob, 'e69de29bb2d1d6434b8b29ae775ad8c2e48c5391');
});
test('valid raw declaration names on a later line are verified with their exact coordinates', async () => {
  const s = sample(); s.f.bytes = Buffer.from('// fixture\n\tpub fn r#type() {}\n');
  const at = s.f.bytes.indexOf('type'), file = s.result.context.files[0], id = oid(s.f.bytes, 'sha1');
  Object.assign(file, { pathHex: hex('src/type.rs'), blob: id, sourceBytes: s.f.bytes.length,
    excerpts: [{ offset: 0, bytesHex: hex(s.f.bytes) }], anchors: [
      { channel: 'content', offset: at, length: 4 }, { channel: 'path', offset: 4, length: 4 }, { channel: 'symbol', offset: at, length: 4 }] });
  s.result.context.sourceBytesRead = s.f.bytes.length; s.result.context.excerptBytes = s.f.bytes.length;
  for (const [channel, offset] of [['content', at], ['path', 4]]) {
    s.result[channel].query.termsHex = [hex('type')]; Object.assign(s.result[channel].hits[0], {
      pathHex: file.pathHex, blob: id, contentBytes: s.f.bytes.length, spans: [{ queryIndex: 0, offset, length: 4 }] });
  }
  Object.assign(s.result.symbols.result.hits[0], { pathHex: file.pathHex, blob: id, offset: at, length: 4, nameHex: hex('type'),
    rawIdentifier: true, line: 2, column: at - 11 + 1, excerptOffset: 11, excerptHex: hex(s.f.bytes.subarray(11, -1)) });
  const receipt = await run(s); assert.equal(receipt.files[0].declarations, 1); assert.equal(receipt.files[0].blob, id);
});
