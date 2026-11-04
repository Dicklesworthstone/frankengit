// Real CLI processes, private files and HTTP sockets. The peer validates the
// bearer spelling and source wire contract; it does not simulate native agent
// authentication, canonical grants or repository authority.
import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtemp, chmod, writeFile, readFile, lstat, readdir, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { fixture as packageFixture, peer as packagePeer, sha256 } from '../../scripts/tests/source_package_fixture.mjs';
import { setup as proofFixture, bytes, labelledContext } from './source_context_proof_fixtures.mjs';
import { fixture as archiveFixture } from './fixtures/source_archive_native.mjs';

const SECRET = 'c9'.repeat(32), AGENT = `fgagent_${SECRET}`;
const ROOT = fileURLToPath(new URL('../../', import.meta.url));
const SCRIPTS = {
  package: fileURLToPath(new URL('../../scripts/fg_source_package.mjs', import.meta.url)),
  proof: fileURLToPath(new URL('../../scripts/fg_context_proof.mjs', import.meta.url)),
  archive: fileURLToPath(new URL('../../scripts/fg_source_archive.mjs', import.meta.url)),
};

function run(t, script, args) {
  // Use the same pinned Node executable as the test runner, with no shell.
  const child = spawn(process.execPath, [script, ...args], { cwd: ROOT, stdio: ['ignore', 'pipe', 'pipe'] });
  t.after(() => { if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL'); });
  return new Promise((resolve, reject) => {
    const stdout = [], stderr = []; let size = 0;
    const timer = setTimeout(() => { child.kill('SIGKILL'); reject(new Error('Sponsored source CLI deadline exceeded')); }, 10000);
    for (const [stream, parts] of [[child.stdout, stdout], [child.stderr, stderr]]) stream.on('data', part => {
      size += part.length;
      if (size > 1024 * 1024) { child.kill('SIGKILL'); reject(new Error('Sponsored source CLI output limit exceeded')); }
      else parts.push(part);
    });
    child.once('error', error => { clearTimeout(timer); reject(error); });
    child.once('close', (code, signal) => {
      clearTimeout(timer);
      resolve({ code, signal, stdout: Buffer.concat(stdout).toString(), stderr: Buffer.concat(stderr).toString() });
    });
  });
}
const absent = path => assert.rejects(lstat(path), error => error.code === 'ENOENT');
function noCredential(value, raw = AGENT) {
  const text = Buffer.isBuffer(value) ? value.toString() : String(value);
  for (const secret of [AGENT, SECRET, raw.trim()]) assert.equal(text.includes(secret), false);
}
async function privateOutput(path) {
  const stat = await lstat(path);
  assert.equal(stat.isFile(), true); assert.equal(stat.mode & 0o777, 0o600);
  assert.equal(stat.nlink, 1); assert.equal(stat.uid, process.getuid());
}

async function fixture(t, kind, format = 'sha1') {
  const root = await mkdtemp(join(tmpdir(), 'fg-sponsored-source-cli-'));
  await chmod(root, 0o700); t.after(() => rm(root, { recursive: true, force: true }));
  const tokenFile = join(root, 'credential'), selectionFile = join(root, 'selection.json');
  const output = join(root, kind === 'archive' ? 'source.tar' : `${kind}.json`);
  // Exactly 72 token bytes plus CRLF: this exercises the wider file allowance
  // as well as the closed token parser, rather than only an in-memory API.
  assert.equal(Buffer.byteLength(AGENT), 72);
  await writeFile(tokenFile, `${AGENT}\r\n`, { mode: 0o600 });
  let peer, selection, common, inspect, hashField, count, expectedCommit, expectedHead;
  if (kind === 'package') {
    peer = await packagePeer(t, packageFixture(format), () => {}, { token: AGENT });
    selection = peer.selected; expectedCommit = peer.f.commitId; expectedHead = peer.f.envelope.snapshot_token;
    const context = join(root, 'context.json'), expectation = join(root, 'expect.json');
    await writeFile(context, peer.context, { mode: 0o600 });
    await writeFile(expectation, bytes(peer.expected), { mode: 0o600 });
    common = ['--selection', selectionFile, '--context', context, '--context-sha256', peer.contextHash, '--expect', expectation];
    inspect = hash => ['inspect', ...common, '--package', output, '--package-sha256', hash];
    hashField = 'package_sha256'; count = 4;
  } else if (kind === 'proof') {
    peer = await proofFixture(t, format, undefined, { token: AGENT });
    selection = { ...peer.selection, expected_head: peer.repo.snapshot };
    expectedCommit = peer.repo.commit; expectedHead = peer.repo.snapshot;
    const context = join(root, 'context.json');
    const raw = bytes({ schema: 'frankengit-source-context-capture-v1', endpoint: selection.endpoint,
      native_response: labelledContext(peer.context) });
    await writeFile(context, raw, { mode: 0o600 });
    common = ['--selection', selectionFile, '--context', context, '--context-sha256', sha256(raw)];
    inspect = hash => ['inspect', ...common, '--proof', output, '--proof-sha256', hash];
    hashField = 'proof_sha256'; count = 2;
  } else {
    peer = await archiveFixture(t, { format, token: AGENT });
    selection = { ...peer.selection, expected_head: peer.repo.snapshot };
    expectedCommit = peer.repo.commit; expectedHead = peer.repo.snapshot;
    common = ['--selection', selectionFile, '--layout', 'objects'];
    inspect = hash => ['inspect', '--archive', output, '--sha256', hash];
    hashField = 'archive_sha256'; count = 3;
  }
  await writeFile(selectionFile, bytes(selection), { mode: 0o600 });
  const calls = kind === 'package' ? peer.requests : peer.calls;
  return { root, kind, script: SCRIPTS[kind], tokenFile, selectionFile, output, inspect, hashField, count,
    expectedCommit, expectedHead, calls, capture: ['capture', ...common, '--token-file', tokenFile, '--output', output] };
}

function sourceReads(f) {
  assert.ok(f.calls.length > 0);
  const operations = f.calls.map(call => call.operation ?? call.path.split('/source/')[1]);
  assert.equal(operations[0], 'commit');
  assert.ok(operations.every(operation => ['commit', 'tree', 'blob'].includes(operation)));
  for (const call of f.calls) {
    const headers = call.headers ?? call.req.headers;
    assert.equal(headers.authorization, `Bearer ${AGENT}`);
    assert.equal(headers.cookie, undefined); assert.equal(headers['idempotency-key'], undefined);
    assert.equal(call.form.get('expected_head'), f.expectedHead);
    assert.equal(call.form.get('expected_commit'), f.expectedCommit);
  }
  assert.deepEqual([...f.calls[0].form.keys()].sort(), ['expected_commit', 'expected_head', 'object_format', 'ref']);
}
function verifiedReceipt(f, receipt) {
  if (f.kind === 'package') {
    assert.equal(receipt.verified.commit, f.expectedCommit);
    assert.equal(receipt.verified.selected_file_count, f.count);
    assert.equal(receipt.context_excerpt_bytes_verified, true);
    assert.equal(receipt.search_evidence_verified, false);
    assert.equal(receipt.verified.authorityVerified, false);
  } else if (f.kind === 'proof') {
    assert.equal(receipt.source_commit, f.expectedCommit);
    assert.equal(receipt.verified_file_count, f.count);
    assert.equal(receipt.selected_path_membership_verified, true);
    assert.equal(receipt.excerpt_bytes_verified, true);
    assert.equal(receipt.authority_verified, false); assert.equal(receipt.search_evidence_verified, false);
  } else {
    assert.equal(receipt.source_commit, f.expectedCommit); assert.equal(receipt.files, f.count);
    assert.equal(receipt.native_content_and_paths_verified, true);
    assert.equal(receipt.authority_signatures_verified, false);
  }
}

for (const kind of Object.keys(SCRIPTS)) for (const format of ['sha1', 'sha256']) {
  test(`${kind}/${format}: canonical sponsored token captures a private artifact and verifies it offline`, async t => {
    const f = await fixture(t, kind, format);
    assert.equal((await lstat(f.root)).mode & 0o777, 0o700);
    await privateOutput(f.tokenFile);
    const captured = await run(t, f.script, f.capture);
    assert.equal(captured.code, 0, captured.stderr); assert.equal(captured.signal, null); assert.equal(captured.stderr, '');
    const receipt = JSON.parse(captured.stdout), artifact = await readFile(f.output);
    assert.equal(receipt[f.hashField], sha256(artifact)); verifiedReceipt(f, receipt);
    await privateOutput(f.output); sourceReads(f);
    for (const value of [captured.stdout, captured.stderr, artifact]) noCredential(value);
    const requests = f.calls.length;
    await rm(f.tokenFile);
    if (kind === 'archive') await rm(f.selectionFile);
    const inspected = await run(t, f.script, f.inspect(receipt[f.hashField]));
    assert.equal(inspected.code, 0, inspected.stderr); assert.equal(inspected.stderr, '');
    const offline = JSON.parse(inspected.stdout);
    assert.equal(offline[f.hashField], receipt[f.hashField]); verifiedReceipt(f, offline);
    assert.equal(f.calls.length, requests); assert.deepEqual(await readFile(f.output), artifact);
    noCredential(inspected.stdout); noCredential(inspected.stderr);
    assert.equal((await readdir(f.root)).some(name => name.includes('.writing-')), false);
  });
}

for (const kind of Object.keys(SCRIPTS)) {
  test(`${kind}: malformed, oversized and nonprivate sponsored credentials refuse before network or publication`, async t => {
    const f = await fixture(t, kind);
    for (const raw of [`fgagent_${'c'.repeat(63)}\n`, `fgagent_${'C'.repeat(64)}\n`, `${AGENT}ab\n`]) {
      await writeFile(f.tokenFile, raw);
      const refused = await run(t, f.script, f.capture);
      assert.equal(refused.code, 2, refused.stderr); assert.equal(refused.stdout, '');
      noCredential(refused.stderr, raw);
      assert.equal(f.calls.length, 0); await absent(f.output);
    }
    await writeFile(f.tokenFile, `${AGENT}\r\n`); await chmod(f.tokenFile, 0o644);
    const refused = await run(t, f.script, f.capture);
    assert.equal(refused.code, 2, refused.stderr); assert.equal(refused.stdout, '');
    noCredential(refused.stderr); assert.equal(f.calls.length, 0); await absent(f.output);
    assert.equal((await readdir(f.root)).some(name => name.includes('.writing-')), false);
  });
}
