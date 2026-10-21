// Exact result intent is independent input, not a tree accepted from preparation.
// Actual Git supplies the adversarial candidates; HTTP peers are NOT Rust fg.
import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, writeFileSync, rmSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { tmpdir } from 'node:os';
import { pathToFileURL } from 'node:url';
import { captureSourceEdit, validateSourceEdit, editInput, editCoordinates, canonical } from '../../scripts/operator/source_edit_candidate.mjs';
import { parse, upload } from '../../scripts/operator/source_edit_wire.mjs';
import { peer, TOKEN, digest } from './source_edit_fixture.mjs';
const PROFILE = 'frankengit-source-edit-capture-v2';
const pinned = f => ({ ...structuredClone(f.request), expected_result_tree: f.tree });
const capture = f => ({ schema: 'frankengit-source-edit-capture-v1', request: structuredClone(f.request),
  patch_sha256: digest(f.patch), patch_bytes: f.patch.length,
  preparation: structuredClone(f.preparation), inspection: structuredClone(f.inspection) });

// Construct a genuine Git bundle for an entirely different edit at the same
// allowed path, using the identical base/author/time/message. All reported
// objects and review spans agree; only the independently selected result differs.
function substituted(f, format, { data = Buffer.from('WRONG\r\n'), mode = '100644' } = {}) {
  const dir = mkdtempSync(join(tmpdir(), 'fg-result-tree-git-'));
  try {
    const git = (args, input) => execFileSync('git', ['-C', dir, ...args], { input,
      env: { ...process.env, GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: '/dev/null' } });
    const write = (kind, bytes) => git(['hash-object', '-w', '-t', kind, '--stdin'], bytes).toString().trim();
    git(['init', '--quiet', `--object-format=${format}`]);
    const empty = write('tree', Buffer.alloc(0));
    const base = write('commit', Buffer.from(`tree ${empty}\nauthor Example <e@example.invalid> 1 +0000\ncommitter Example <e@example.invalid> 1 +0000\n\nbase\n`));
    assert.equal(base, f.base);
    const blob = write('blob', data), tree = write('tree', Buffer.concat([Buffer.from(`${mode} file\0`), Buffer.from(blob, 'hex')]));
    const m = f.request.metadata;
    const body = Buffer.from(`tree ${tree}\nparent ${base}\nauthor ${m.author} ${m.timestamp} +0000\ncommitter ${m.committer} ${m.timestamp} +0000\n\n${m.message}`);
    const candidate = write('commit', body); git(['update-ref', 'refs/heads/main', candidate]);
    git(['bundle', 'create', join(dir, 'candidate.bundle'), 'refs/heads/main', `^${base}`]);
    const bundle = readFileSync(join(dir, 'candidate.bundle')), value = capture(f);
    Object.assign(value.preparation, { candidate_commit: candidate, root_tree: tree, bundle: { bytes: bundle.length, sha256: digest(bundle) } });
    Object.assign(value.preparation.paths[0], { new_blob: blob, new_mode: parseInt(mode, 8) });
    const view = value.inspection;
    Object.assign(view, { candidate_commit: candidate, bundle_bytes: bundle.length, bundle_sha256: digest(bundle), candidate_commit_body_hex: body.toString('hex') });
    view.comparison.after_tree = tree;
    const row = view.comparison.entries[0]; row.after = { mode: parseInt(mode, 8), oid: blob };
    row.content = data.includes(0) ? { type: 'binary', before_bytes: 0, after_bytes: data.length, body_included: false } : {
      type: 'text', algorithm: 'Myers', additions: data.length ? 1 : 0, deletions: 0, before_bytes: 0, after_bytes: data.length,
      hunks: data.length ? [{ old: { byte_start: 0, byte_end: 0, line_start: 0, line_count: 0 },
        new: { byte_start: 0, byte_end: data.length, line_start: 0, line_count: data.reduce((n, b) => n + Number(b === 10), 0) + Number(data.at(-1) !== 10) },
        before_hex: '', after_hex: data.toString('hex') }] : [],
    };
    return { value, bundle, candidate, tree };
  } finally { rmSync(dir, { recursive: true, force: true }); }
}
function serve(f, value, bundle) {
  f.control.handler = (_req, res, call) => {
    const reply = call.operation === 'prepare' ? f.frame(value.preparation, bundle) :
      { type: 'application/json', bytes: canonical(value.inspection) };
    res.writeHead(200, { 'Content-Type': reply.type }); res.end(reply.bytes);
  };
}

for (const format of ['sha1', 'sha256']) {
  test(`${format}: an independent result root survives acquisition and offline replay`, async t => {
    const f = await peer(t, format), result = await captureSourceEdit(pinned(f), f.patch, TOKEN);
    assert.equal(result.capture.schema, PROFILE);
    assert.equal(result.capture.request.expected_result_tree, f.tree);
    assert.equal(result.candidate_commit, f.candidate);
    assert.deepEqual(result.bundle, f.bundle);
    assert.deepEqual(f.calls.map(c => c.operation), ['prepare', 'inspect']);
    assert.deepEqual(validateSourceEdit(result.capture, result.bundle), {
      capture: result.capture, bundle: result.bundle, candidate_commit: f.candidate,
      native_bundle_validation_observed: true, bundle_objects_independently_verified: false, publication_authorized: false,
    });
    for (const call of f.calls) {
      assert.ok(!call.body.includes(Buffer.from('expected_result_tree')));
      assert.equal(call.headers['idempotency-key'], undefined);
    }
  });
  for (const [name, options] of [
    ['different text', {}], ['different executable mode', { data: Buffer.from('hello\r\n'), mode: '100755' }],
    ['different binary body', { data: Buffer.from('unintended\0bytes') }], ['empty instead of intended file', { data: Buffer.alloc(0) }],
  ]) {
    test(`${format}: reject a fully self-consistent ${name} before inspection`, async t => {
      const f = await peer(t, format), other = substituted(f, format, options);
      assert.notEqual(other.tree, f.tree);
      assert.doesNotThrow(() => validateSourceEdit(other.value, other.bundle), 'not a malformed-report test');
      serve(f, other.value, other.bundle);
      await assert.rejects(captureSourceEdit(pinned(f), f.patch, TOKEN), { code: 'source_edit_result_tree_mismatch' });
      assert.deepEqual(f.calls.map(c => c.operation), ['prepare']);
      const retained = { ...other.value, schema: PROFILE, request: editInput(pinned(f)) };
      assert.throws(() => validateSourceEdit(retained, other.bundle), { code: 'source_edit_result_tree_mismatch' });
    });
  }
  test(`${format}: a truthful tree echo cannot hide an inspection with a different commit`, async t => {
    const f = await peer(t, format), other = substituted(f, format);
    f.control.mutate = (reply, call) => {
      if (call.operation === 'inspect') reply.candidate_commit_body_hex = other.value.inspection.candidate_commit_body_hex;
    };
    await assert.rejects(captureSourceEdit(pinned(f), f.patch, TOKEN), /commit_body/);
    assert.deepEqual(f.calls.map(c => c.operation), ['prepare', 'inspect']);
  });
  test(`${format}: ordinary captures and native uploads retain their previous bytes`, async t => {
    const f = await peer(t, format), ordinary = await captureSourceEdit(f.request, f.patch, TOKEN);
    assert.equal(ordinary.capture.schema, 'frankengit-source-edit-capture-v1');
    assert.ok(!Object.hasOwn(ordinary.capture.request, 'expected_result_tree'));
    assert.deepEqual(canonical(ordinary.capture), canonical(capture(f)));
    assert.deepEqual(editCoordinates(editInput(pinned(f)), f.candidate), editCoordinates(editInput(f.request), f.candidate));
    const a = upload({ ...editCoordinates(editInput(pinned(f))), ...f.request.metadata }, f.patch, 'patch');
    const b = upload({ ...editCoordinates(f.request), ...f.request.metadata }, f.patch, 'patch');
    assert.deepEqual(a, b);
    const bytes = canonical(ordinary.capture), reloaded = validateSourceEdit(parse(bytes, bytes.length), ordinary.bundle);
    assert.deepEqual(canonical(reloaded.capture), bytes);
  });
  test(`${format}: expected root is copied before asynchronous work and cannot be silently replaced`, async t => {
    const f = await peer(t, format), input = pinned(f), original = input.expected_result_tree;
    const pending = captureSourceEdit(input, f.patch, TOKEN);
    input.expected_result_tree = 'f'.repeat(format === 'sha1' ? 40 : 64);
    const result = await pending;
    assert.equal(result.capture.request.expected_result_tree, original);
    const bad = pinned(f); bad.expected_result_tree = 'f'.repeat(format === 'sha1' ? 40 : 64);
    const refused = captureSourceEdit(bad, f.patch, TOKEN); bad.expected_result_tree = f.tree;
    await assert.rejects(refused, { code: 'source_edit_result_tree_mismatch' });
  });
  test(`${format}: persisted v2 replay rejects stripping or downgrading the result constraint`, async t => {
    const f = await peer(t, format), result = await captureSourceEdit(pinned(f), f.patch, TOKEN);
    for (const change of [
      c => { delete c.request.expected_result_tree; },
      c => { c.schema = 'frankengit-source-edit-capture-v1'; },
      c => { c.request.expected_result_tree = 'f'.repeat(format === 'sha1' ? 40 : 64); },
      c => { c.request.expected_result_tree = `${format}:${f.tree}`; },
    ]) {
      const copy = structuredClone(result.capture); change(copy);
      assert.throws(() => validateSourceEdit(copy, result.bundle));
      assert.notEqual(digest(canonical(copy)), digest(canonical(result.capture)));
    }
    const legacy = capture(f); legacy.schema = PROFILE;
    assert.throws(() => validateSourceEdit(legacy, f.bundle));
  });
  test(`${format}: complete output intention remains valid after private-file reopen in a fresh process`, async t => {
    const f = await peer(t, format), result = await captureSourceEdit(pinned(f), f.patch, TOKEN);
    const dir = mkdtempSync(join(tmpdir(), 'fg-result-pin-reopen-'));
    t.after(() => rmSync(dir, { recursive: true, force: true }));
    const body = canonical(result.capture), captureFile = join(dir, 'capture.json'), bundleFile = join(dir, 'candidate.bundle');
    writeFileSync(captureFile, body, { mode: 0o600 }); writeFileSync(bundleFile, result.bundle, { mode: 0o600 });
    const module = pathToFileURL(resolve('scripts/operator/source_edit_candidate.mjs')).href;
    const output = execFileSync(process.execPath, ['--input-type=module', '-e', `
      import { readFileSync } from 'node:fs';
      import { validateSourceEdit, parse, hash } from ${JSON.stringify(module)};
      const [capture, bundle, wanted] = process.argv.slice(1);
      const bytes = readFileSync(capture); if (hash(bytes) !== wanted) throw new Error('changed independent pin');
      const value = validateSourceEdit(parse(bytes, bytes.length), readFileSync(bundle));
      console.log(JSON.stringify({ tree: value.capture.request.expected_result_tree, candidate: value.candidate_commit }));
    `, captureFile, bundleFile, digest(body)]);
    assert.deepEqual(JSON.parse(output), { tree: f.tree, candidate: f.candidate });
    assert.equal(f.calls.length, 2, 'offline child made no extra request');
  });
}
for (const [name, value] of [
  ['null', null], ['boolean', true], ['number', 42], ['empty', ''], ['zero', '0'.repeat(40)],
  ['uppercase', 'A'.repeat(40)], ['foreign width', 'a'.repeat(64)], ['foreign domain', 'sha256:' + 'a'.repeat(64)],
  ['bad prefix', 'tree:' + 'a'.repeat(40)], ['object', {}], ['array', []], ['undefined', undefined],
]) test(`invalid independent ${name} root refuses before any network I/O`, async t => {
  const f = await peer(t), input = { ...f.request, expected_result_tree: value };
  assert.throws(() => editInput(input));
  await assert.rejects(captureSourceEdit(input, f.patch, TOKEN));
  assert.equal(f.calls.length, 0);
});
test('same-domain prefixed roots normalize and retain no caller-owned objects', async t => {
  const f = await peer(t), input = { ...f.request, expected_result_tree: `sha1:${f.tree}` };
  const normalized = editInput(input);
  assert.equal(normalized.expected_result_tree, f.tree);
  const result = await captureSourceEdit(input, f.patch, TOKEN);
  assert.deepEqual(result.capture.request, normalized);
});
test('tree pins cannot authorize out-of-scope paths or publication claims', async t => {
  for (const alter of [r => r.paths[0].path_hex = '6576696c', r => r.objects_staged = true]) {
    const f = await peer(t); f.control.mutate = alter;
    await assert.rejects(captureSourceEdit(pinned(f), f.patch, TOKEN));
    assert.equal(f.calls.length, 1);
  }
});
test('the unchanged aggregate wire budget still has an exact permitted boundary', async t => {
  const f = await peer(t), result = await captureSourceEdit(pinned(f), f.patch, TOKEN);
  await captureSourceEdit(pinned(f), f.patch, TOKEN, { maxWireBytes: result.metrics.response_bytes });
  await assert.rejects(captureSourceEdit(pinned(f), f.patch, TOKEN, { maxWireBytes: result.metrics.response_bytes - 1 }));
});
test('cancellation and bad pins never trigger fallback or a wider second request', async t => {
  const f = await peer(t), stop = new AbortController(); stop.abort();
  await assert.rejects(captureSourceEdit(pinned(f), f.patch, TOKEN, { signal: stop.signal }), /cancelled/);
  assert.equal(f.calls.length, 0);
  const live = new AbortController();
  f.control.mutate = () => live.abort();
  await assert.rejects(captureSourceEdit(pinned(f), f.patch, TOKEN, { signal: live.signal }), /cancelled/);
  assert.ok(f.calls.length <= 1);
});
