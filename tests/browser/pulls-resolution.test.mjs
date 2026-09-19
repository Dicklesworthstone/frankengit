// Resolution request/response contract tests with mocked native admission.
// This is not a Git pack conformance or live-node test lane.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { PullClient } from '../../crates/fgit-node/src/smart_http/server/browser/pulls.mjs';
import { resolutionUpload, verifyResolutionResult, RESOLUTION_FILE_LIMIT, RESOLUTION_CONTENT_LIMIT } from '../../crates/fgit-node/src/smart_http/server/browser/pulls-resolution.mjs';
import { preparationReply } from '../../crates/fgit-node/src/smart_http/server/browser/pulls-candidate.mjs';
import { fixture, terminal } from './pulls-candidate-fixtures.mjs';
import { token, page, json, options, webcrypto, deferred } from './pulls-fixtures.mjs';
const meta = { author: 'Test <test@example.invalid>', committer: 'Test <test@example.invalid>', timestamp: 1, message: 'Exact candidate\n' };
const h = text => Buffer.from(text).toString('hex');
function conflicts(algorithm = 'sha1', paths = ['a', 'b', 'c', 'd']) {
  const f = fixture(algorithm), size = algorithm === 'sha1' ? 40 : 64;
  const report = { ...f.metadata, state: 'conflicted', merge_base: f.fields.merge_base, candidate: null, bundle: null,
    conflicts: paths.map(path => ({ path_hex: h(path), kind: 'content', base: { mode: 0o100644, oid: '1'.repeat(size) },
      ours: { mode: 0o100755, oid: '2'.repeat(size) }, theirs: { mode: 0o100644, oid: '3'.repeat(size) } })) };
  return { f, report };
}
const sides = report => report.conflicts.map((row, index) => ({ path_hex: row.path_hex, choice: ['base', 'ours', 'theirs', 'delete'][index % 4] }));
function resultFor(f, upload) { return { ...f.metadata, state: 'resolved', resolution_profile: 'exact-path-resolutions-v1', resolutions: structuredClone(upload.expected.rows) }; }
async function clientWith(sample, handler) {
  const calls = []; let client;
  client = new PullClient(options((url, init) => {
    const call = { path: new URL(url).pathname, ...init }; calls.push(call);
    if (call.path.endsWith('/api/v1/pulls')) return json(page({ object_format: sample.f.fields.object_format, pull_requests: [] }));
    if (call.path.endsWith('/prepare')) return json(sample.report, 409);
    return handler(call, client);
  }));
  await client.connect(token); await client.list();
  await client.prepareAndInspect(1, sample.f.selected, meta);
  return { client, calls };
}
for (const algorithm of ['sha1', 'sha256']) test(`${algorithm}: all side choices encode every exact conflict and retain original metadata`, async () => {
  const { f, report } = conflicts(algorithm), choices = sides(report).reverse();
  const upload = await resolutionUpload(report, f.selected, meta, choices, webcrypto);
  assert.equal(upload.contentType, 'application/x-www-form-urlencoded');
  const form = new URLSearchParams(new TextDecoder().decode(upload.bytes));
  assert.deepEqual(form.getAll('resolution'), ['61:base', '62:ours', '63:theirs', '64:delete']);
  assert.equal(form.get('merge_base'), report.merge_base); assert.equal(form.get('timestamp'), '1');
  assert.equal(form.get('source_tip'), f.selected.source_tip); assert.equal(form.get('policy_epoch'), '1');
  assert.equal(form.get('author'), meta.author); assert.equal(form.has('principal'), false);
  verifyResolutionResult(resultFor(f, upload), upload.expected);
  assert.equal(upload.expected.rows.at(-1).result, null);
});
for (const algorithm of ['sha1', 'sha256']) test(`${algorithm}: binary and empty files use native blob identity and octet-stream parts`, async () => {
  const { f, report } = conflicts(algorithm, ['a', Buffer.from([0xff])]);
  const content = new Uint8Array([0, 255, 13, 10, 60, 115, 99, 114, 105, 112, 116, 62]);
  const upload = await resolutionUpload(report, f.selected, meta, [
    { path_hex: '61', choice: 'file', mode: '100755', bytes: content },
    { path_hex: 'ff', choice: 'file', mode: '100644', bytes: new Uint8Array() },
  ], webcrypto);
  assert.match(upload.contentType, /^multipart\/form-data; boundary=fg-resolution-/);
  const body = Buffer.from(upload.bytes), text = body.toString('latin1');
  assert.ok(body.includes(content)); assert.match(text, /name="file_0"\r\nContent-Type: application\/octet-stream/);
  assert.match(text, /name="file_1"\r\nContent-Type: application\/octet-stream/);
  assert.match(text, /resolution=ff%3Afile%3A100644%3Afile_1/); assert.equal(text.includes('filename='), false);
  for (const [index, bytes] of [content, new Uint8Array()].entries()) {
    const expected = createHash(algorithm).update(`blob ${bytes.length}\0`).update(bytes).digest('hex');
    assert.equal(upload.expected.rows[index].result.oid, expected);
  }
  verifyResolutionResult(resultFor(f, upload), upload.expected);
});
const badChoices = [
  ['missing path', rows => rows.slice(1)],
  ['extra path', rows => [...rows, { path_hex: '65', choice: 'delete' }]],
  ['duplicate path', rows => [rows[0], rows[0], ...rows.slice(2)]],
  ['clean path', rows => [{ path_hex: '65', choice: 'ours' }, ...rows.slice(1)]],
  ['unknown choice', rows => [{ ...rows[0], choice: 'automatic' }, ...rows.slice(1)]],
  ['no choice', rows => [{ path_hex: '61' }, ...rows.slice(1)]],
  ['injected principal', rows => [{ ...rows[0], principal: 'admin' }, ...rows.slice(1)]],
  ['ignored side payload', rows => [{ ...rows[0], bytes: new Uint8Array() }, ...rows.slice(1)]],
  ['uppercase path', rows => [{ path_hex: 'FF', choice: 'ours' }, ...rows.slice(1)]],
  ['invalid file mode', rows => [{ path_hex: '61', choice: 'file', mode: '120000', bytes: new Uint8Array() }, ...rows.slice(1)]],
  ['missing file', rows => [{ path_hex: '61', choice: 'file', mode: '100644' }, ...rows.slice(1)]],
  ['string file', rows => [{ path_hex: '61', choice: 'file', mode: '100644', bytes: 'text' }, ...rows.slice(1)]],
  ['oversized file', rows => [{ path_hex: '61', choice: 'file', mode: '100644', bytes: new Uint8Array(RESOLUTION_FILE_LIMIT + 1) }, ...rows.slice(1)]],
];
for (const [name, change] of badChoices) test(`resolution refuses ${name} before any transport`, async () => {
  const { f, report } = conflicts();
  await assert.rejects(resolutionUpload(report, f.selected, meta, change(sides(report)), webcrypto));
});
test('missing sides require explicit deletion, not a silent interpretation of absence', async () => {
  const { f, report } = conflicts('sha1', ['a']); report.conflicts[0].ours = null;
  await assert.rejects(resolutionUpload(report, f.selected, meta, [{ path_hex: '61', choice: 'ours' }], webcrypto), /absent/);
  assert.equal((await resolutionUpload(report, f.selected, meta, [{ path_hex: '61', choice: 'delete' }], webcrypto)).expected.rows[0].result, null);
});
test('native reserved paths, overlapping ancestors and too many conflicts cannot create requests', async () => {
  for (const paths of [['a/.GiT/config'], ['a', 'a-', 'a/b'], Array.from({ length: 129 }, (_, i) => String(i).padStart(3, '0'))]) {
    const { f, report } = conflicts('sha1', paths);
    await assert.rejects(resolutionUpload(report, f.selected, meta, sides(report), webcrypto));
  }
});
test('aggregate content and encoded command ceilings refuse before hashing or upload', async () => {
  const { f, report } = conflicts('sha1', Array.from({ length: 17 }, (_, i) => `file${String(i).padStart(2, '0')}`));
  const bytes = new Uint8Array(RESOLUTION_FILE_LIMIT), choices = report.conflicts.map(row => ({ path_hex: row.path_hex, choice: 'file', mode: '100644', bytes }));
  let hashes = 0; const crypto = { getRandomValues: v => webcrypto.getRandomValues(v), subtle: { digest() { hashes += 1; throw new Error('Must bound before hashing'); } } };
  assert.equal(RESOLUTION_CONTENT_LIMIT, 16 * RESOLUTION_FILE_LIMIT);
  await assert.rejects(resolutionUpload(report, f.selected, meta, choices, crypto), /16 MiB/); assert.equal(hashes, 0);
  const huge = conflicts('sha1', Array.from({ length: 128 }, (_, i) => `${String(i).padStart(3, '0')}${'x'.repeat(4090)}`));
  await assert.rejects(resolutionUpload(huge.report, huge.f.selected, meta, sides(huge.report), crypto), /256 KiB/);
});
test('file and command bytes are frozen before asynchronous hashing', async () => {
  const { f, report } = conflicts('sha1', ['a']), wait = deferred(); let started = false;
  const crypto = { getRandomValues: v => webcrypto.getRandomValues(v), subtle: { async digest(...args) { started = true; await wait.promise; return webcrypto.subtle.digest(...args); } } };
  const bytes = new Uint8Array([0, 255]), choice = { path_hex: '61', choice: 'file', mode: '100755', bytes }, metadata = { ...meta };
  const future = resolutionUpload(report, f.selected, metadata, [choice], crypto); assert.equal(started, true);
  bytes[0] = 99; choice.mode = '100644'; metadata.timestamp = 999; wait.resolve(); const upload = await future;
  assert.ok(Buffer.from(upload.bytes).includes(Buffer.from([0, 255])));
  assert.match(Buffer.from(upload.bytes).toString(), /timestamp=1&/);
  assert.equal(upload.expected.rows[0].result.mode, 0o100755);
  assert.equal(upload.expected.rows[0].result.oid, createHash('sha1').update('blob 2\0').update(Buffer.from([0, 255])).digest('hex'));
});
test('boundary collisions have a bounded failure rather than ambiguous framing', async () => {
  const { f, report } = conflicts('sha1', ['a']); let attempts = 0;
  const crypto = { ...webcrypto, getRandomValues(v) { attempts += 1; return v.fill(0); } };
  const bytes = new TextEncoder().encode(`--fg-resolution-${'0'.repeat(48)}`);
  await assert.rejects(resolutionUpload(report, f.selected, meta, [{ path_hex: '61', choice: 'file', mode: '100644', bytes }], crypto), /collision-free/);
  assert.equal(attempts, 16);
});
for (const name of ['path', 'side', 'choice', 'mode', 'content', 'kind', 'base', 'missing', 'profile', 'subject']) test(`resolved reply must match the submitted ${name}`, async () => {
  const { f, report } = conflicts(), upload = await resolutionUpload(report, f.selected, meta, sides(report), webcrypto);
  const response = resultFor(f, upload), row = response.resolutions[0];
  switch (name) {
    case 'path': row.path_hex = '65'; break; case 'side': row.ours.oid = '9'.repeat(40); break;
    case 'choice': row.choice = 'theirs'; break; case 'mode': row.result.mode = 0o100755; break;
    case 'content': row.result.oid = '9'.repeat(40); break; case 'kind': row.kind = 'binary'; break;
    case 'base': response.candidate = { ...response.candidate, merge_base: '9'.repeat(40) }; break;
    case 'missing': response.resolutions.pop(); break; case 'profile': response.resolution_profile = 'automatic'; break;
    case 'subject': response.subject = { ...response.subject, policy_epoch: 2 }; break;
  }
  assert.throws(() => verifyResolutionResult(response, upload.expected));
});
test('resolved candidates pass explicit native resolution then mandatory inspection before review', async () => {
  const sample = conflicts(), upload = await resolutionUpload(sample.report, sample.f.selected, meta, sides(sample.report), webcrypto);
  const { client, calls } = await clientWith(sample, (call, owner) => {
    if (call.path.endsWith('/resolve')) return new Response(sample.f.mixed(resultFor(sample.f, upload)), { headers: { 'Content-Type': sample.f.type } });
    if (call.path.endsWith('/inspect')) return json(sample.f.inspection);
    return json(terminal(owner.pending));
  });
  assert.ok(client.conflict); assert.equal(client.candidate, null); await assert.rejects(client.stageReview('approve', 0, 'No candidate'));
  const result = await client.resolveAndInspect(sides(sample.report));
  assert.equal(result.metadata.state, 'resolved'); assert.ok(result.inspection); assert.equal(client.conflict, null);
  assert.equal(client.pending, null); assert.equal(calls.length, 4);
  for (const call of calls) assert.equal(call.headers['Idempotency-Key'], undefined);
  assert.equal(new URLSearchParams(await calls[2].body.text()).get('merge_base'), sample.report.merge_base);
  await client.stageReview('approve', 0, 'Reviewed the resolved candidate'); assert.equal(calls.length, 4);
  assert.equal((await client.send()).outcome, 'committed'); assert.equal(client.pending, null);
});
test('failed native resolution preserves the original conflict and does not silently refresh it', async () => {
  const sample = conflicts(), { client, calls } = await clientWith(sample, () => json({ type: 'pull_request_error', code: 'preparation_subject_moved' }, 409));
  const exposed = client.conflict; exposed.subject.policy_epoch = 99;
  await assert.rejects(client.resolveAndInspect(sides(sample.report))); assert.equal(client.candidate, null); assert.equal(client.pending, null);
  assert.equal(client.conflict.subject.policy_epoch, 1);
  await assert.rejects(client.resolveAndInspect(sides(sample.report)));
  const sent = await Promise.all(calls.filter(call => call.path.endsWith('/resolve')).map(async call => call.body.text()));
  assert.equal(sent.length, 2); assert.equal(sent[0], sent[1]);
  assert.equal(calls.filter(call => call.path.endsWith('/prepare')).length, 1);
});
test('wrong resolution report never reaches candidate inspection', async () => {
  const sample = conflicts(), upload = await resolutionUpload(sample.report, sample.f.selected, meta, sides(sample.report), webcrypto);
  const response = resultFor(sample.f, upload); response.resolutions[0].choice = 'ours';
  const { client, calls } = await clientWith(sample, () => new Response(sample.f.mixed(response), { headers: { 'Content-Type': sample.f.type } }));
  await assert.rejects(client.resolveAndInspect(sides(sample.report))); assert.equal(client.candidate, null);
  assert.equal(calls.some(call => call.path.endsWith('/inspect')), false);
});
test('automatic and explicit-resolved results are not interchangeable', async () => {
  const sample = conflicts(), upload = await resolutionUpload(sample.report, sample.f.selected, meta, sides(sample.report), webcrypto);
  await assert.rejects(preparationReply({ status: 200, type: sample.f.type, value: sample.f.mixed(resultFor(sample.f, upload)) }, 1, sample.f.selected, sample.f.artifact.scope, webcrypto));
  await assert.rejects(preparationReply({ status: 200, type: sample.f.type, value: sample.f.mixed() }, 1, sample.f.selected, sample.f.artifact.scope, webcrypto, true));
});
test('disconnect and new selection discard conflict coordinates and prevent stale resolution dispatch', async () => {
  const sample = conflicts(), { client, calls } = await clientWith(sample, () => { throw new Error('unexpected'); });
  client.invalidateCandidate(); await assert.rejects(client.resolveAndInspect(sides(sample.report))); assert.equal(calls.length, 2);
  await client.prepareAndInspect(1, sample.f.selected, meta); client.disconnect();
  assert.equal(client.conflict, null); await assert.rejects(client.resolveAndInspect(sides(sample.report))); assert.equal(calls.length, 3);
});
test('late resolution response cannot select a candidate after conflict invalidation', async () => {
  const sample = conflicts(), upload = await resolutionUpload(sample.report, sample.f.selected, meta, sides(sample.report), webcrypto), wait = deferred();
  const { client, calls } = await clientWith(sample, () => wait.promise);
  const resolving = client.resolveAndInspect(sides(sample.report));
  while (calls.length < 3) await new Promise(setImmediate);
  client.invalidateCandidate(); wait.resolve(new Response(sample.f.mixed(resultFor(sample.f, upload)), { headers: { 'Content-Type': sample.f.type } }));
  await assert.rejects(resolving); assert.equal(client.candidate, null); assert.equal(client.conflict, null); assert.equal(calls.length, 3);
});
