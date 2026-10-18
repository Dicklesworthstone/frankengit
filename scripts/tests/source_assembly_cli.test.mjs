// Actual CLI/private-file/HTTP/TLS composition; the server is a native-schema
// peer using Git as an object oracle, not an executed Rust authorization engine.
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, chmod, writeFile, readFile, rm, lstat, symlink } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { Writable } from 'node:stream';
import { main } from '../fg_source_assembly.mjs';
import { loadSourceAssembly } from '../operator/source_assembly_capture.mjs';
import { canonical, sha256 } from '../operator/source_changes.mjs';
import { nativePeer, TOKEN, ROTATED_TOKEN, PRINCIPAL } from './source_changes_native_fixture.mjs';
import { changeFixture, intent, replace, hexPath } from './source_changes_fixture.mjs';
import { contribution } from './source_assembly_fixture.mjs';
const write = async (path, bytes) => { await writeFile(path, bytes, { mode: 0o600 }); await chmod(path, 0o600); };
const missing = path => assert.rejects(lstat(path), { code: 'ENOENT' });
const script = name => fileURLToPath(new URL(`../${name}`, import.meta.url));
async function cli(name, args) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [script(name), ...args], { stdio: ['ignore', 'pipe', 'pipe'] });
    const out = [], err = []; let total = 0;
    const timer = setTimeout(() => { child.kill('SIGKILL'); reject(new Error('assembly CLI deadline')); }, 30000);
    for (const [stream, chunks] of [[child.stdout, out], [child.stderr, err]]) stream.on('data', b => {
      if ((total += b.length) > 262144) { child.kill('SIGKILL'); reject(new Error('assembly output bound')); } else chunks.push(b);
    });
    child.once('error', e => { clearTimeout(timer); reject(e); });
    child.once('close', (code, signal) => { clearTimeout(timer); resolve({ code, signal, stdout: Buffer.concat(out).toString(), stderr: Buffer.concat(err).toString() }); });
  });
}
function ok(result) { assert.equal(result.code, 0, result.stderr); assert.equal(result.signal, null); return JSON.parse(result.stdout); }
async function setup(t, f = changeFixture('sha1', [{ path: 'a', bytes: 'old A\n' }, { path: 'b', bytes: 'old B\n' }, { path: 'context', bytes: 'shared' }]), profiles = {}) {
  const root = await mkdtemp(join(tmpdir(), 'fg-assembly-cli-')); t.after(() => rm(root, { recursive: true, force: true }));
  const inputs = await Promise.all(['a', 'b'].map(id => contribution(f, id, [id, 'context'], { ...intent([replace(id, `${id} NEW\n`)]), ...profiles })));
  const rows = [];
  for (const row of inputs) {
    const paths = { id: row.id, package: join(root, `${row.id}.source.json`), expect: join(root, `${row.id}.expected.json`),
      changes: join(root, `${row.id}.changes.json`), confirm_draft_sha256: row.confirmDraftSha256 };
    await write(paths.package, row.packageBytes); await write(paths.expect, canonical(row.expected)); await write(paths.changes, canonical(row.changes)); rows.push(paths);
  }
  const selection = join(root, 'contributions.json'), output = join(root, 'assembly'); await write(selection, canonical({ contributions: rows }));
  return { root, selection, output, inputs, rows, args: ['capture', '--contributions', selection, '--output', output] };
}
for (const format of ['sha1', 'sha256']) {
  test(`${format}: two editor captures assemble into one packed candidate and original-key recovery`, async t => {
    const binary = format === 'sha256', before = Buffer.from('old\n' + 'common\n'.repeat(30) + 'end\n'); if (binary) before[1] = 0;
    const peer = await nativePeer(format, { files: ['a', 'b', 'context'].map(path => ({ path, bytes: before })), nativePatchBundle: true, tls: binary }); t.after(peer.close);
    const profiles = { patch_profile: 'bounded-line-hunks-v1', ...(binary ? { byte_profile: 'binary-safe-v1' } : {}) };
    const s = await setup(t, peer.fixture, profiles), captures = [], workspaces = [];
    for (const row of s.rows) {
      const workspace = join(s.root, `${row.id}-workspace`), capture = join(s.root, `${row.id}-capture`), paths = join(s.root, `${row.id}-paths.json`);
      const created = ok(await cli('fg_source_workspace.mjs', ['create', '--package', row.package, '--expect', row.expect, '--output', workspace]));
      const after = Buffer.from(before); after[0] = row.id.charCodeAt(0); after[after.length - 3] = 90;
      await write(join(workspace, 'files', row.id), after); await write(paths, canonical({ paths_hex: [hexPath(row.id)], ...profiles }));
      const captured = ok(await cli('fg_source_workspace.mjs', ['capture', '--workspace', workspace, '--sha256', created.workspace_sha256, '--paths', paths, '--output', capture]));
      captures.push(capture); workspaces.push(workspace);
      Object.assign(row, { package: join(capture, 'source.json'), expect: join(capture, 'expected.json'), changes: join(capture, 'changes.json'), confirm_draft_sha256: captured.draft_sha256 });
    }
    await write(s.selection, canonical({ contributions: s.rows }));
    const saved = ok(await cli('fg_source_assembly.mjs', s.args)); assert.equal(saved.contribution_count, 2); assert.equal(saved.effect_count, 2);
    const inspected = ok(await cli('fg_source_assembly.mjs', ['inspect', '--capture', s.output, '--sha256', saved.capture_sha256]));
    assert.equal(inspected.draft_sha256, saved.draft_sha256);
    const target = join(s.root, 'target.json'), token = join(s.root, 'token'), rotated = join(s.root, 'rotated'), ca = join(s.root, 'ca.pem');
    await write(target, canonical(peer.selection([hexPath('a'), hexPath('b')]))); await write(token, TOKEN); await write(rotated, ROTATED_TOKEN);
    if (peer.ca) await write(ca, peer.ca); const net = peer.ca ? ['--ca-file', ca] : [];
    const candidate = join(s.root, 'candidate'), journal = join(s.root, 'journal');
    const inputs = ['--package', join(s.output, 'source.json'), '--expect', join(s.output, 'expected.json'), '--changes', join(s.output, 'changes.json')];
    const wrong = await cli('fg_source_changes.mjs', ['prepare-packed', ...inputs, '--selection', target, '--confirm-draft-sha256', s.rows[0].confirm_draft_sha256,
      '--token-file', token, '--output', candidate, ...net]);
    assert.equal(wrong.code, 2); assert.equal(peer.requests.length, 0); await missing(candidate);
    const consent = ['--confirm-draft-sha256', saved.draft_sha256];
    const prepared = ok(await cli('fg_source_changes.mjs', ['prepare-packed', ...inputs, '--selection', target, ...consent, '--token-file', token, '--output', candidate, ...net]));
    assert.equal(prepared.pack_verification.expected_tree, saved.expected_tree); assert.equal(prepared.pack_verification.packed_objects_independently_verified, true);
    ok(await cli('fg_source_changes.mjs', ['inspect-packed', ...inputs, ...consent, '--candidate', candidate, '--sha256', prepared.manifest_sha256]));
    const staged = ok(await cli('fg_source_changes.mjs', ['stage-packed', ...inputs, '--selection', target, ...consent, '--candidate', candidate, '--sha256', prepared.manifest_sha256,
      '--principal', PRINCIPAL, '--confirm-candidate', prepared.candidate_commit, '--journal', journal]));
    for (const path of [...captures, ...workspaces, s.output, candidate]) await rm(path, { recursive: true }); await rm(s.selection);
    peer.lostApply = true;
    const applied = await cli('fg_source_edit.mjs', ['apply', '--journal', journal, '--request-sha256', staged.request_sha256, '--token-file', token, ...net]);
    assert.equal(applied.code, 3, applied.stderr);
    const recovered = ok(await cli('fg_source_edit.mjs', ['recover', '--journal', journal, '--request-sha256', staged.request_sha256, '--token-file', rotated, ...net]));
    assert.equal(recovered.key, staged.key); assert.equal(recovered.decision.decision_sequence, '18446744073709551615');
    assert.equal(peer.applies, 1); assert.equal(recovered.submission_retried, false); assert.deepEqual(peer.failures, []);
  });
  test(`${format}: assembled source still rejects coherent hidden changes and corrupt candidate packs`, async t => {
    const peer = await nativePeer(format, { files: [{ path: 'a', bytes: 'A' }, { path: 'b', bytes: 'B' }, { path: 'context', bytes: 'C' }], nativePatchBundle: true }); t.after(peer.close);
    const s = await setup(t, peer.fixture), saved = ok(await cli('fg_source_assembly.mjs', s.args));
    const target = join(s.root, 'target'), token = join(s.root, 'token'); await write(target, canonical(peer.selection([hexPath('a'), hexPath('b')]))); await write(token, TOKEN);
    const candidate = join(s.root, 'candidate');
    const args = ['prepare-packed', '--package', join(s.output, 'source.json'), '--expect', join(s.output, 'expected.json'), '--changes', join(s.output, 'changes.json'),
      '--selection', target, '--confirm-draft-sha256', saved.draft_sha256, '--token-file', token, '--output', candidate];
    peer.fault = 'unreported-addition'; assert.equal((await cli('fg_source_changes.mjs', args)).code, 2); await missing(candidate);
    peer.fault = null; peer.transformPack = bytes => { const bad = Buffer.from(bytes); bad[bad.length - 1] ^= 1; return bad; };
    assert.equal((await cli('fg_source_changes.mjs', args)).code, 2); await missing(candidate); assert.equal(peer.applies, 0);
  });
}
test('actual CLI creators race without overwrite; frozen output survives deleting input paths', async t => {
  const s = await setup(t), results = await Promise.all([cli('fg_source_assembly.mjs', s.args), cli('fg_source_assembly.mjs', s.args)]);
  assert.equal(results.filter(r => r.code === 0).length, 1); const saved = ok(results.find(r => r.code === 0));
  for (const row of s.rows) for (const key of ['package', 'expect', 'changes']) await rm(row[key]); await rm(s.selection);
  assert.equal(ok(await cli('fg_source_assembly.mjs', ['inspect', '--capture', s.output, '--sha256', saved.capture_sha256])).capture_sha256, saved.capture_sha256);
});
test('contribution grammar is closed and validated before any referenced file read', async t => {
  const s = await setup(t); s.rows[0].package = join(s.root, 'MISSING'); s.rows[1].token = 'not-a-capability';
  await write(s.selection, canonical({ contributions: s.rows })); const result = await cli('fg_source_assembly.mjs', s.args);
  assert.equal(result.code, 2); assert.equal(JSON.parse(result.stderr).code, 'source_edit_fields'); await missing(s.output);
  for (const extra of [['--token-file', 'secret'], ['--force', 'true'], ['--timeout-ms', '0'], ['--output', join(s.root, 'duplicate')]]) {
    assert.equal((await cli('fg_source_assembly.mjs', [...s.args, ...extra])).code, 2);
  }
});
test('original review mismatch and conflicting selected inputs fail before claiming output', async t => {
  const s = await setup(t), original = s.rows[0].confirm_draft_sha256;
  s.rows[0].confirm_draft_sha256 = '0'.repeat(64); await write(s.selection, canonical({ contributions: s.rows }));
  assert.equal((await cli('fg_source_assembly.mjs', s.args)).code, 2); await missing(s.output);
  s.rows[0].confirm_draft_sha256 = original; s.rows[1] = { ...s.rows[0], id: 'other' }; await write(s.selection, canonical({ contributions: s.rows }));
  const conflict = await cli('fg_source_assembly.mjs', s.args); assert.equal(conflict.code, 2);
  assert.match(conflict.stderr, /write_conflict/); await missing(s.output);
});
test('private input files and normalized paths are mandatory', async t => {
  const s = await setup(t); await chmod(s.rows[0].package, 0o644);
  assert.equal((await cli('fg_source_assembly.mjs', s.args)).code, 2); await missing(s.output); await chmod(s.rows[0].package, 0o600);
  const alias = join(s.root, 'alias'); await symlink(s.selection, alias);
  assert.equal((await cli('fg_source_assembly.mjs', ['capture', '--contributions', alias, '--output', s.output])).code, 2);
  assert.equal((await cli('fg_source_assembly.mjs', ['capture', '--contributions', 'relative', '--output', s.output])).code, 2);
  assert.ok(ok(await cli('fg_source_assembly.mjs', s.args)).capture_sha256);
});
test('lost stdout retains the completed result and an independently reopenable capture', async t => {
  const s = await setup(t); let stderr = '';
  const out = new Writable({ write(_b, _e, callback) { callback(new Error('broken output')); } });
  const err = new Writable({ write(b, _e, callback) { stderr += b; callback(); } });
  const code = await main(s.args, { stdout: out, stderr: err }); assert.equal(code, 4);
  const retained = JSON.parse(stderr).retained_result; assert.equal(retained.directory, s.output);
  assert.equal((await loadSourceAssembly(s.output, retained.capture_sha256)).saved.draft_sha256, retained.draft_sha256);
});
test('SIGTERM cancels blocked receipt output without losing the completed capture', async t => {
  const s = await setup(t), module = new URL('../fg_source_assembly.mjs', import.meta.url).href;
  const code = `import {main} from ${JSON.stringify(module)}; import {Writable} from 'node:stream';
    const stdout=new Writable({write(_b,_e,_cb){process.stderr.write('BLOCKED\\n');}});
    process.exitCode=await main(${JSON.stringify(s.args)}, {stdout,stderr:process.stderr});`;
  const result = await new Promise((resolve, reject) => {
    const child = spawn(process.execPath, ['--input-type=module', '-e', code], { stdio: ['ignore', 'pipe', 'pipe'] });
    let error = '', sent = false; const timer = setTimeout(() => { child.kill('SIGKILL'); reject(new Error('blocked receipt did not drain')); }, 10000);
    child.stdout.resume(); child.stderr.on('data', bytes => { error += bytes; if (!sent && error.includes('BLOCKED\n')) { sent = true; child.kill('SIGTERM'); } });
    child.once('error', reject); child.once('close', (code, signal) => { clearTimeout(timer); resolve({ code, signal, error, sent }); });
  });
  assert.equal(result.sent, true); assert.equal(result.code, 4); assert.equal(result.signal, null);
  const retained = JSON.parse(result.error.split('\n').find(line => line.startsWith('{'))).retained_result;
  assert.ok(await loadSourceAssembly(s.output, retained.capture_sha256));
});
test('help describes fresh combined review and independent offline inspection', async () => {
  const result = ok(await cli('fg_source_assembly.mjs', ['--help']));
  assert.match(result.usage, /2\.\.8/); assert.match(result.usage, /NEW hash/); assert.match(result.usage, /original keys/);
});
