import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createServer } from 'node:http';
import { mkdtemp, writeFile, readFile, readdir, chmod, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { Writable } from 'node:stream';
import { writeArchiveOutput } from '../../scripts/archive_native_issues.mjs';
import { inspectIssueArchive } from '../../scripts/lib/forge-issue-archive.mjs';

const cli = fileURLToPath(new URL('../../scripts/archive_native_issues.mjs', import.meta.url));
const tenant = '1'.repeat(32), repository = '2'.repeat(32), token = 'a'.repeat(64), actor = '3'.repeat(32);
const head = 'alg:2:' + '6'.repeat(64), title = 'CLI source', body = 'retained raw text\n';
async function peer(t, onRequest) {
  const parent = await mkdtemp(join(tmpdir(), 'fg-archive-cli-')); await chmod(parent, 0o700);
  const tokenFile = join(parent, 'token'); await writeFile(tokenFile, token, { mode: 0o600 });
  let calls = 0;
  const server = createServer(async (req, res) => {
    calls++;
    if (onRequest && await onRequest(req, res, calls)) return;
    if (req.method !== 'GET' || req.headers.authorization !== 'Bearer ' + token || req.headers['idempotency-key']) {
      res.writeHead(403); res.end(); return;
    }
    const url = new URL(req.url, 'http://127.0.0.1');
    const limit = Number(url.searchParams.get('limit')), after = Number(url.searchParams.get('after_version') ?? url.searchParams.get('after'));
    if ((calls > 1 && url.searchParams.get('expected_head') !== head) || url.searchParams.has('render')) {
      res.writeHead(409); res.end(); return;
    }
    const issue = { number: 17, version: 2, title, body, labels: [], assignees: [], state: 'open',
      opened_by: actor, last_actor: actor, comments: 1 };
    const header = { schema_version: 1, tenant_id: tenant, repository_id: repository, snapshot_token: head, source_head: 'source-cli' };
    const events = [{ version: 1, actor, action: { name: 'open', title, body, labels: [] } },
      { version: 2, actor, action: { name: 'comment', body: 'Comment <script>is text</script>\u202e' } }];
    const value = url.pathname.endsWith('/issues') ? { type: 'issue_page', ...header, after, limit, issues: [issue], next_after: null }
      : { type: 'issue_history', ...header, found: true, issue, after_version: after, limit,
        events: events.slice(after, after + limit), next_after_version: after + limit < 2 ? after + limit : null };
    res.writeHead(200, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(value));
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(async () => { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); await rm(parent, { recursive: true, force: true }); });
  const workdir = join(parent, 'archive');
  const args = ['export', '--workdir', workdir, '--url', `http://127.0.0.1:${server.address().port}/repo/ui/issues/`,
    '--tenant', tenant, '--repository', repository, '--token-file', tokenFile, '--page-size', '1'];
  return { parent, workdir, tokenFile, args, calls: () => calls };
}
function run(args, { closedOutput = false, started = () => {} } = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [cli, ...args], { stdio: ['ignore', 'pipe', 'pipe'] });
    let stdout = '', stderr = '';
    const timer = setTimeout(() => { child.kill('SIGKILL'); reject(new Error('CLI did not settle')); }, 5000);
    if (closedOutput) child.stdout.destroy();
    else child.stdout.on('data', bytes => { stdout += bytes; if (stdout.length > 65536) child.kill('SIGKILL'); });
    child.stderr.on('data', bytes => { stderr += bytes; if (stderr.length > 65536) child.kill('SIGKILL'); });
    child.once('error', error => { clearTimeout(timer); reject(error); });
    child.once('close', (code, signal) => { clearTimeout(timer); resolve({ code, signal, stdout, stderr }); });
    started(child);
  });
}
function inspectArgs(f, sha) { return ['inspect', '--workdir', f.workdir, '--confirm', sha]; }

test('real export/inspect processes complete the native HTTP-to-offline lifecycle', async t => {
  const f = await peer(t), exported = await run(f.args);
  assert.equal(exported.code, 0, exported.stderr); assert.equal(exported.stderr, '');
  const result = JSON.parse(exported.stdout); assert.equal(result.issues, 1); assert.equal(result.events, 2);
  assert.equal(result.pages, 3); assert.equal(result.complete, true); assert.equal(result.canonical_backup, false);
  await rm(f.tokenFile);
  const inspected = await run(inspectArgs(f, result.archive_sha256));
  assert.equal(inspected.code, 0, inspected.stderr); assert.equal(JSON.parse(inspected.stdout).network_accessed, false);
  assert.equal(f.calls(), 3); assert.ok(!exported.stdout.includes(token));
});
test('CLI request ceiling retains an explicitly incomplete archive', async t => {
  const f = await peer(t), result = await run([...f.args, '--max-requests', '1']);
  assert.equal(result.code, 3); assert.equal(result.stdout, ''); assert.equal(f.calls(), 1);
  assert.equal(JSON.parse(result.stderr).archive_progress.complete, false);
  await assert.rejects(readFile(join(f.workdir, 'archive.json')), { code: 'ENOENT' });
});
test('independent wrong pin refuses offline without source access', async t => {
  const f = await peer(t); assert.equal((await run(f.args)).code, 0);
  const result = await run(inspectArgs(f, '0'.repeat(64))); assert.equal(result.code, 2); assert.equal(f.calls(), 3);
  assert.match(result.stderr, /pin_mismatch/);
});
for (const extra of [['--max-events', '0'], ['--max-issues', '4097'], ['--page-size', '1'], ['--confirm', '0'.repeat(64)], ['--unknown', 'true']]) {
  test('CLI rejects duplicate/inapplicable/out-of-range flag ' + extra.join(' '), async t => {
    const f = await peer(t), result = await run([...f.args, ...extra]);
    assert.equal(result.code, 2); assert.equal(f.calls(), 0);
    await assert.rejects(readdir(f.workdir), { code: 'ENOENT' });
  });
}
test('inspect does not accept a token or network option', async t => {
  const f = await peer(t), result = await run([...inspectArgs(f, '0'.repeat(64)), '--token-file', f.tokenFile]);
  assert.equal(result.code, 2); assert.equal(f.calls(), 0);
});
for (const signal of ['SIGTERM', 'SIGINT']) test(signal + ' drains an active HTTP read and publishes no root', async t => {
  let child;
  const f = await peer(t, async (_req, res) => {
    res.writeHead(200, { 'Content-Type': 'application/json' }); res.write('{');
    child.kill(signal); return true;
  });
  const result = await run(f.args, { started: value => { child = value; } });
  assert.equal(result.code, 3, result.stderr); assert.equal(result.signal, null);
  assert.equal(f.calls(), 1); assert.equal(result.stdout, '');
  await assert.rejects(readFile(join(f.workdir, 'archive.json')), { code: 'ENOENT' });
});
test('SIGKILL leaves only an unsealed prefix; inspection never executes a retry', async t => {
  let child;
  const f = await peer(t, async (_req, res, calls) => {
    if (calls < 2) return false;
    res.writeHead(200, { 'Content-Type': 'application/json' }); res.write('{'); child.kill('SIGKILL'); return true;
  });
  const result = await run(f.args, { started: value => { child = value; } });
  assert.equal(result.signal, 'SIGKILL'); assert.equal(f.calls(), 2);
  const names = await readdir(f.workdir); assert.deepEqual(names, ['page-000001.json']);
  const inspected = await run(inspectArgs(f, '0'.repeat(64)));
  assert.equal(inspected.code, 2); assert.equal(f.calls(), 2); assert.deepEqual(await readdir(f.workdir), names);
});
test('closed real stdout returns output failure while preserving the complete archive and its pin', async t => {
  const f = await peer(t), result = await run(f.args, { closedOutput: true });
  assert.equal(result.code, 4, result.stderr); const retained = JSON.parse(result.stderr).retained_result;
  assert.equal(retained.complete, true); assert.equal(f.calls(), 3);
  assert.equal((await inspectIssueArchive({ workdir: f.workdir, confirm: retained.archive_sha256 })).complete, true);
});
test('expired CLI deadline is not a successful partial export', async t => {
  const f = await peer(t, async (_req, res) => { res.writeHead(200, { 'Content-Type': 'application/json' }); res.write('{'); return true; });
  const result = await run([...f.args, '--timeout-ms', '100']);
  assert.equal(result.code, 3, result.stderr); assert.equal(result.stdout, '');
});
test('bounded output waits for completion, escapes terminal controls and leaves no listener on success', async () => {
  let text = '', finished = false;
  const output = new Writable({ write(chunk, _encoding, callback) { text += chunk; setTimeout(() => { finished = true; callback(); }, 10); } });
  await writeArchiveOutput(output, { message: 'unsafe\u202e\u009btext' });
  assert.equal(finished, true); assert.ok(!/[\u202e\u009b]/u.test(text));
  assert.equal(JSON.parse(text).message, 'unsafe\u202e\u009btext'); assert.equal(output.listenerCount('error'), 0);
});
test('stalled output is bounded rather than reporting completion', async () => {
  const output = new Writable({ write() {} });
  await assert.rejects(writeArchiveOutput(output, { complete: true }, 10), /deadline exceeded/);
  assert.equal(output.destroyed, true);
});
test('help needs no repository, token, network or private files', async () => {
  const result = await run(['--help']); assert.equal(result.code, 0); assert.match(JSON.parse(result.stdout).usage, /inspect/);
});
