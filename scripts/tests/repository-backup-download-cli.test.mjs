import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { readFile, writeFile, readdir, lstat, chmod, unlink, link } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { join } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { runDownloadCommand, downloadArguments } from '../download_repository_backup.mjs';
import { tlsFixture, DATA } from './backup-download-fixture.mjs';

const CLI = fileURLToPath(new URL('../download_repository_backup.mjs', import.meta.url));
async function fixture(t) {
  const f = await tlsFixture(t), sourceFile = join(f.root, 'signed-urls.json');
  await writeFile(sourceFile, JSON.stringify([f.url]), { mode: 0o600 });
  const args = ['--sources', sourceFile, '--approval', f.approval, '--trust-key', f.trustKey, '--ca-file', f.caFile,
    '--replica-directory', f.destination, '--tenant-id', f.options.policy.tenant_id, '--repository-id', f.options.policy.repository_id,
    '--incarnation-id', f.options.policy.incarnation_id, '--object-format', 'sha256', '--minimum-head-generation', '1',
    '--max-archive-bytes', String(DATA.length), '--timeout-secs', '5'];
  // Test wall clocks may precede/follow the stable core fixture's noon issue time.
  await f.sign(DATA, { issued_at: new Date(Math.floor(Date.now() / 1000) * 1000 - 1000).toISOString().replace('.000Z', 'Z'), expires_at: null }, Date.now());
  return { ...f, sourceFile, args };
}
function launch(t, args, environment = {}) {
  const child = spawn(process.execPath, [CLI, ...args], { env: { ...process.env, ...environment }, stdio: ['ignore', 'pipe', 'pipe'] });
  let out = '', err = ''; child.stdout.setEncoding('utf8'); child.stderr.setEncoding('utf8');
  child.stdout.on('data', s => { out += s; }); child.stderr.on('data', s => { err += s; });
  const exit = new Promise((resolve, reject) => { child.once('error', reject); child.once('close', (code, signal) => resolve({ code, signal, out, err })); });
  t.after(async () => { if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL'); await exit; });
  return { child, exit };
}
async function one(t, args, env) { return launch(t, args, env).exit; }
const records = text => text.trim().split('\n').filter(Boolean).map(s => JSON.parse(s));
function redacted(result) { assert(!result.out.includes('capability-do-not-log')); assert(!result.err.includes('capability-do-not-log')); }
async function partial(f) {
  for (let i = 0; i < 200; i++) {
    for (const name of await readdir(f.destination)) {
      if (name.startsWith('.fg-backup-download-') && (await lstat(join(f.destination, name))).size > 0) return name;
    }
    await delay(5);
  }
  assert.fail('no partial download reached the actual filesystem');
}

test('actual CLI publishes selectable candidate and only redacted bounded milestones', async t => {
  const f = await fixture(t), result = await one(t, [...f.args, '--progress-json']);
  assert.equal(result.code, 0, result.err); const receipt = JSON.parse(result.out);
  assert.deepEqual(await readFile(receipt.candidate.input), DATA); redacted(result);
  assert.deepEqual(records(result.err).map(r => r.phase), ['checkpoint_pinned', 'source_started', 'download_verified']);
  assert.equal(receipt.streaming.total_payload_bytes_read, String(DATA.length * 4));
  assert.equal((await readdir(f.destination)).length, 2);
});

test('actual CLI retries the exact original checkpoint without rewriting completed files', async t => {
  const f = await fixture(t), first = await one(t, f.args); assert.equal(first.code, 0, first.err);
  const a = JSON.parse(first.out), ino = (await lstat(a.candidate.input)).ino;
  const second = await one(t, [...f.args, '--checkpoint', a.checkpoint.approval_sha256, a.checkpoint.trusted_key_id]);
  assert.equal(second.code, 0, second.err); const b = JSON.parse(second.out);
  assert.equal((await lstat(b.candidate.input)).ino, ino); assert.equal(b.publication.disposition.archive, 'reused');
});

test('URL file permissions and hard links refuse before network use', async t => {
  const f = await fixture(t); await chmod(f.sourceFile, 0o644);
  let result = await one(t, f.args); assert.equal(result.code, 1); assert.equal(records(result.err).at(-1).code, 'backup_private_owner_required');
  await chmod(f.sourceFile, 0o600); await link(f.sourceFile, f.sourceFile + '.alias');
  result = await one(t, f.args); assert.equal(result.code, 1); assert.equal(records(result.err).at(-1).code, 'backup_private_key_links');
  assert.equal(f.requests.length, 0); redacted(result);
});

test('malformed URL file and plaintext HTTP refuse with no credentials in diagnostics', async t => {
  const f = await fixture(t); await writeFile(f.sourceFile, 'malformed capability-do-not-log');
  let result = await one(t, f.args); assert.equal(result.code, 1); redacted(result);
  await writeFile(f.sourceFile, JSON.stringify([f.url.replace('https:', 'http:')]));
  result = await one(t, f.args); assert.equal(result.code, 1); assert.equal(records(result.err).at(-1).code, 'backup_download_invalid_url');
  redacted(result); assert.equal(f.requests.length, 0);
});

test('process-wide insecure TLS environment does not override verified HTTPS', async t => {
  const f = await fixture(t), at = f.args.indexOf('--ca-file'), args = f.args.filter((_, i) => i !== at && i !== at + 1);
  const result = await one(t, args, { NODE_TLS_REJECT_UNAUTHORIZED: '0' });
  assert.equal(result.code, 1); assert(result.err.includes('backup_download_tls')); assert.equal(f.requests.length, 0); redacted(result);
});

test('SIGTERM mid-transfer drains network ownership and removes its own partial file', async t => {
  const f = await fixture(t); f.setHandler((_, res) => { res.writeHead(200); res.write(DATA.subarray(0, 70000)); });
  const process = launch(t, f.args); await partial(f); process.child.kill('SIGTERM');
  const result = await process.exit; assert.equal(result.code, 1, result.err);
  assert.equal(records(result.err).at(-1).code, 'backup_cancelled'); assert.deepEqual(await readdir(f.destination), []); redacted(result);
});

test('SIGKILL leaves quarantined partial bytes; an actual CLI restart ignores rather than deletes them', async t => {
  const f = await fixture(t); f.setHandler((_, res) => { res.writeHead(200); res.write(DATA.subarray(0, 70000)); });
  const process = launch(t, f.args), scratch = await partial(f);
  process.child.kill('SIGKILL'); assert.equal((await process.exit).signal, 'SIGKILL');
  const before = await readFile(join(f.destination, scratch)); assert(before.length > 0 && before.length < DATA.length);
  assert.equal((await readdir(f.destination)).filter(n => n.endsWith('.approval.json')).length, 0);
  f.setHandler((_, res) => res.end(DATA));
  const result = await one(t, f.args); assert.equal(result.code, 0, result.err);
  assert.deepEqual(await readFile(join(f.destination, scratch)), before);
  assert.deepEqual(await readFile(JSON.parse(result.out).candidate.input), DATA);
});

test('final output failure preserves the completed publication receipt', async t => {
  const f = await fixture(t), problem = Object.assign(new Error('broken output'), { code: 'EPIPE' });
  await assert.rejects(runDownloadCommand(f.args, { write(_, cb) { cb(problem); } }), asyncError => {
    assert.equal(asyncError, problem); assert.equal(asyncError.download_state, 'complete');
    assert.equal(asyncError.completed_result.state, 'complete'); return true;
  });
  assert.equal((await readdir(f.destination)).filter(n => n.endsWith('.approval.json')).length, 1);
});

test('failed progress delivery refuses before network publication', async t => {
  const f = await fixture(t), problem = Object.assign(new Error('broken progress'), { code: 'ECONNRESET' });
  await assert.rejects(runDownloadCommand([...f.args, '--progress-json'], { write(_, cb) { cb(); } }, { write(_, cb) { cb(problem); } }), e => e === problem);
  assert.equal(f.requests.length, 0); assert.deepEqual(await readdir(f.destination), []);
});

test('CLI grammar rejects unknown, duplicate, missing and inapplicable values before source reads', async t => {
  const f = await fixture(t);
  for (const extra of [['--insecure'], ['--follow-redirects'], ['--approval', f.approval], ['--timeout-secs', '0'], ['--checkpoint', 'x'], ['--max-total-read-bytes', '99999999999999999']]) {
    assert.throws(() => downloadArguments([...f.args, ...extra]));
  }
  assert.equal(f.requests.length, 0);
});

test('help is executable without any approval or sources', async t => {
  const result = await one(t, ['--help']); assert.equal(result.code, 0); assert(result.out.includes('--sources PRIVATE_JSON'));
});

test('actual closed stdout pipe reports confirmed completion instead of rollback', async t => {
  const f = await fixture(t), process = launch(t, f.args); process.child.stdout.destroy();
  const result = await process.exit; assert.equal(result.code, 1, result.err);
  const error = records(result.err).at(-1); assert.equal(error.code, 'EPIPE'); assert.equal(error.download_state, 'complete');
  assert.deepEqual(await readFile(error.completed_result.candidate.input), DATA); redacted(result);
});
