// Real child processes and filesystem inputs, with offline cryptographic proofs.
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, writeFile, readFile, rm, mkdir, truncate } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { repository, definitions, expectedFor, packageFor } from './search-context-package-fixture.mjs';
const script = fileURLToPath(new URL('../../scripts/fg_verify_source_package.mjs', import.meta.url));
async function run(argv, cwd) {
  const child = spawn(process.execPath, [script, ...argv], { cwd, stdio: ['ignore', 'pipe', 'pipe'] });
  const out = [], err = []; child.stdout.on('data', b => out.push(b)); child.stderr.on('data', b => err.push(b));
  const code = await new Promise((resolve, reject) => { child.once('error', reject); child.once('close', resolve); });
  return { code, out: Buffer.concat(out).toString(), err: Buffer.concat(err).toString() };
}
async function files(t, format = 'sha1') {
  const dir = await mkdtemp(join(tmpdir(), 'fg-source-package-')); t.after(() => rm(dir, { recursive: true, force: true }));
  const repo = repository(format, definitions), p = join(dir, 'package.json'), e = join(dir, 'expected.json');
  const pkg = packageFor(repo), expected = expectedFor(repo);
  await writeFile(p, JSON.stringify(pkg), { mode: 0o600 }); await writeFile(e, JSON.stringify(expected), { mode: 0o600 });
  return { dir, repo, p, e, pkg, expected, args: ['--package', p, '--expect', e] };
}
for (const format of ['sha1', 'sha256']) test(`CLI verifies offline and preserves all input bytes (${format})`, async t => {
  const f = await files(t, format), before = await readFile(f.p), result = await run(f.args, f.dir);
  assert.equal(result.code, 0); assert.equal(result.err, ''); const checked = JSON.parse(result.out);
  assert.equal(checked.commit, f.repo.commit); assert.equal(checked.files.length, 2); assert.equal(checked.blobBytesVerified, true);
  assert.equal(checked.authorityVerified, false); assert.deepEqual(await readFile(f.p), before);
});
for (const [label, change] of Object.entries({
  'body corruption': f => { f.pkg.blobs[0].bytesHex += '00'; },
  'commit corruption': f => { f.pkg.membership.commit.bodyHex += '00'; },
  'external root mismatch': f => { f.expected.commit = 'f'.repeat(40); },
  'external selection mismatch': f => { f.expected.files.pop(); },
  'saved verification flag': f => { f.pkg.verified = true; },
})) test(`CLI rejects ${label}`, async t => {
  const f = await files(t); change(f);
  await writeFile(f.p, JSON.stringify(f.pkg)); await writeFile(f.e, JSON.stringify(f.expected));
  const result = await run(f.args, f.dir);
  assert.equal(result.code, 1); assert.equal(result.out, ''); assert.match(result.err, /verification failed/);
});
for (const [label, extra] of [['network option', ['--endpoint', 'https://example.invalid']], ['credential option', ['--token', 'secret']],
  ['extraction option', ['--extract', 'output']], ['repeated option', ['--expect', 'other']], ['bad deadline', ['--timeout-ms', '0']]]) {
  test(`CLI refuses ${label}`, async t => { const f = await files(t); assert.equal((await run([...f.args, ...extra], f.dir)).code, 1); });
}
test('CLI never derives its expected selection from a package alone', async t => {
  const f = await files(t); const result = await run(['--package', f.p], f.dir); assert.equal(result.code, 1); assert.equal(result.out, '');
});
test('CLI bounds file inputs before allocation and rejects non-regular files', async t => {
  const f = await files(t); await truncate(f.p, 32 * 1024 * 1024 + 1);
  assert.equal((await run(f.args, f.dir)).code, 1);
  await rm(f.p); await mkdir(f.p); assert.equal((await run(f.args, f.dir)).code, 1);
});
test('CLI handles malformed JSON and invalid UTF-8 without echoing source', async t => {
  const f = await files(t);
  for (const bytes of [Buffer.from('private source'), Buffer.from([255]), Buffer.from('\ufeff{}')]) {
    await writeFile(f.p, bytes); const result = await run(f.args, f.dir);
    assert.equal(result.code, 1); assert.equal(result.out, ''); assert.equal(result.err.includes('private source'), false);
  }
});
test('CLI help is offline and contains the independent-selection requirement', async () => {
  const result = await run(['--help']); assert.equal(result.code, 0); assert.match(result.out, /independently-retained/);
});
