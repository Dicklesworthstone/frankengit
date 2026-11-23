// Real subprocesses exercise credential custody and the package owner's native
// provider contract. The explicit stand-in does not verify authority or grants;
// the opt-in real-node cases in source_package_native.test.mjs own that evidence.
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, chmod, writeFile, readFile, lstat, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { setTimeout as delay } from 'node:timers/promises';
import { captureSourcePackage, inspectSourcePackage } from '../operator/source_package.mjs';
import { runNativeProcess } from '../lib/native-process-owner.mjs';
import { fixture, peer, sha256 } from './source_package_fixture.mjs';

const AGENT = `fgagent_${'c9'.repeat(32)}`;
const COMMAND = fileURLToPath(new URL('../fg_source_package.mjs', import.meta.url));
const absent = path => assert.rejects(lstat(path), { code: 'ENOENT' });

async function provider(t, format = 'sha1', mode = 'permit') {
  const p = await peer(t, fixture(format), undefined, { token: AGENT });
  const directory = await mkdtemp(join(tmpdir(), 'fg-sponsored-proof-provider-'));
  await chmod(directory, 0o700);
  t.after(() => rm(directory, { recursive: true, force: true }));
  const executable = join(directory, 'provider.mjs'), calls = join(directory, 'calls.jsonl');
  const inputs = { token: AGENT, endpoint: p.selected.endpoint, head: p.selected.expected_head,
    ref: p.selected.ref, commit: p.f.commitId, mode, calls,
    files: p.f.rows.map(row => ({ path: row.pathHex, blob: row.id, bytes: row.bytes.toString('hex'), kind: row.kind })) };
  await writeFile(executable, `#!${process.execPath}
import assert from 'node:assert/strict';
import { readFileSync, lstatSync, writeFileSync, appendFileSync } from 'node:fs';
import { dirname } from 'node:path';
const input = ${JSON.stringify(inputs)};
const args = process.argv.slice(2);
assert.equal(args[0], '--timeout-secs');
assert.ok(Number(args[1]) >= 1);
assert.equal(args[2], 'verify-read');
const pairs = new Map();
for (let at = 3; at < args.length; at += 2) {
  assert.ok(!pairs.has(args[at])); pairs.set(args[at], args[at + 1]);
}
assert.deepEqual([...pairs.keys()].sort(), ['--output', '--path-hex', '--ref', '--token-file', '--trusted-head', '--url']);
assert.equal(pairs.get('--url'), input.endpoint);
assert.equal(pairs.get('--trusted-head'), input.head);
assert.equal(pairs.get('--ref'), input.ref);
assert.ok(args.every(value => !value.includes(input.token)));
const tokenFile = pairs.get('--token-file'), token = readFileSync(tokenFile, 'utf8');
assert.equal(token, input.token);
const stat = lstatSync(tokenFile), scratch = dirname(tokenFile);
assert.ok(stat.isFile()); assert.equal(stat.mode & 0o777, 0o600);
assert.equal(stat.nlink, 1); assert.equal(stat.uid, process.getuid());
assert.equal(lstatSync(scratch).mode & 0o777, 0o700);
appendFileSync(input.calls, JSON.stringify({ scratch, path: pairs.get('--path-hex'), privateCredentialMatched: true }) + '\\n', { mode: 0o600 });
if (input.mode === 'deny') {
  process.stderr.write(JSON.stringify({ type: 'verified_read_error', schema_version: 1, code: 'http_status' }));
  process.exitCode = 2;
} else if (input.mode === 'hold') {
  setInterval(() => {}, 1000);
} else {
  const file = input.files.find(file => file.path === pairs.get('--path-hex'));
  assert.ok(file);
  const output = pairs.get('--output'), body = Buffer.from(file.bytes, 'hex');
  if (input.mode === 'tamper' && body.length) body[0] ^= 1;
  writeFileSync(output, body, { flag: 'wx', mode: 0o600 });
  process.stdout.write(JSON.stringify({ type: 'verified_blob', schema_version: 1, verified: true,
    output_state: 'published', source_head: input.head, source_commit: input.commit,
    object_id: file.blob, kind: file.kind, bytes: body.length, output }) + '\\n');
}
`, { mode: 0o700 });
  return { ...p, directory, executable, calls };
}

async function observed(p) {
  return (await readFile(p.calls, 'utf8')).trim().split('\n').map(JSON.parse);
}
async function retired(p, count) {
  const calls = await observed(p);
  assert.equal(calls.length, count);
  for (const call of calls) {
    assert.equal(call.privateCredentialMatched, true);
    await absent(call.scratch);
  }
  return calls;
}

for (const format of ['sha1', 'sha256']) {
  test(`${format}: sponsored native package capture passes the private bearer and verifies every provider result`, async t => {
    const p = await provider(t, format);
    const result = await captureSourcePackage(p.context, p.contextHash, p.selected, p.expected, AGENT,
      { nativeFg: p.executable });
    const calls = await retired(p, p.f.rows.length);
    assert.deepEqual(calls.map(call => call.path), p.f.rows.map(row => row.pathHex));
    assert.equal(result.receipt.native_read.files, 4, 'empty files also require the native provider');
    assert.equal(result.receipt.native_read.head, p.selected.expected_head);
    assert.equal(result.receipt.native_read.binary_sha256, sha256(await readFile(p.executable)));
    assert.equal(result.receipt.verified.authorityVerified, false, 'the portable package contains no authority proof');
    assert.equal(result.metrics.nativeProofRequests, 4);
    assert.equal(result.receipt.remote_mutation_attempted, false);
    for (const value of [result.bytes.toString(), JSON.stringify(result.receipt), await readFile(p.calls, 'utf8')]) {
      assert.equal(value.includes(AGENT), false);
    }
    const requests = p.requests.length;
    const offline = await inspectSourcePackage(result.bytes, result.receipt.package_sha256,
      p.context, p.contextHash, p.selected, p.expected);
    assert.equal(offline.native_read, undefined);
    assert.equal(p.requests.length, requests);
  });
}

test('a native proof denial prevents CLI package publication without credential fallback', async t => {
  const p = await provider(t, 'sha1', 'deny'), output = join(p.directory, 'package.json');
  const files = {};
  for (const [name, bytes] of Object.entries({ selection: JSON.stringify(p.selected), context: p.context,
    expect: JSON.stringify(p.expected), token: `${AGENT}\r\n` })) {
    files[name] = join(p.directory, name); await writeFile(files[name], bytes, { mode: 0o600 });
  }
  const result = await runNativeProcess(process.execPath, [COMMAND, 'capture', '--selection', files.selection,
    '--context', files.context, '--context-sha256', p.contextHash, '--expect', files.expect,
    '--token-file', files.token, '--output', output, '--native-fg', p.executable],
  { timeoutMs: 10000, stdoutLimit: 65536, stderrLimit: 65536 });
  assert.equal(result.code, 2); assert.equal(result.signal, null); assert.equal(result.stdout.length, 0);
  const diagnostic = JSON.parse(result.stderr);
  assert.equal(diagnostic.phase, 'capture'); assert.equal(diagnostic.native_code, 'http_status');
  assert.equal(diagnostic.remote_mutation_attempted, false);
  assert.equal(result.stderr.includes(Buffer.from(AGENT)), false);
  await absent(output); await retired(p, 1);
  assert.ok(p.requests.length > 0, 'source-read acquisition precedes the independent proof request');
  assert.ok(p.requests.every(call => call.req.headers.authorization === `Bearer ${AGENT}`));
});

test('sponsored native capture rejects mismatched verified bytes and retires private scratch', async t => {
  const p = await provider(t, 'sha256', 'tamper');
  await assert.rejects(captureSourcePackage(p.context, p.contextHash, p.selected, p.expected, AGENT,
    { nativeFg: p.executable }), { code: 'native_source_proof_content_mismatch' });
  await retired(p, 2);
});

test('cancelling a sponsored native proof drains the child before removing its private credential', async t => {
  const p = await provider(t, 'sha1', 'hold'), stop = new AbortController();
  const pending = captureSourcePackage(p.context, p.contextHash, p.selected, p.expected, AGENT,
    { nativeFg: p.executable, signal: stop.signal });
  const refused = assert.rejects(pending, error => error.code === 'native_process_cancelled' || error.name === 'AbortError');
  // Observe an early failure while retaining the awaited assertion below.
  refused.catch(() => {});
  try {
    const deadline = performance.now() + 5000;
    while (performance.now() < deadline) {
      if (await lstat(p.calls).then(() => true, error => { if (error.code === 'ENOENT') return false; throw error; })) break;
      await delay(10);
    }
    assert.equal((await observed(p)).length, 1);
  } finally { stop.abort(); }
  await refused; await retired(p, 1);
});
