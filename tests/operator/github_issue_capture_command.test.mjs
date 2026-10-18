import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { Writable } from 'node:stream';
import { mkdtemp, writeFile, readFile, readdir, rm, lstat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { setTimeout as sleep } from 'node:timers/promises';
import { main, writeJson } from '../../scripts/capture_github_issue_migration.mjs';
import { captureGithubIssueMigration } from '../../scripts/lib/github-issue-capture-migration.mjs';
import { loadGithubIssueMigrationSources } from '../../scripts/lib/github-issue-migration-sources.mjs';
import { issueInventoryBytes, INVENTORY_SCHEMA } from '../../scripts/lib/github-issue-inventory.mjs';
import { recordDigest } from '../../scripts/lib/forge-operator-io.mjs';
import { parseCapture, issueImportSteps } from '../../scripts/lib/github-issue-source.mjs';
import { githubPeer, repository, repositoryId, issueId } from './fixtures/github_capture_source.mjs';

const cli = fileURLToPath(new URL('../../scripts/capture_github_issue_migration.mjs', import.meta.url));
const fixtureModule = new URL('./fixtures/github_capture_source.mjs', import.meta.url).href;
async function setup(t, count = 2) {
  const root = await mkdtemp(join(tmpdir(), 'fg-capture-cli-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const input = join(root, 'inventory.json'), workdir = join(root, 'capture'), preload = join(root, 'peer.mjs'), log = join(root, 'requests');
  const bytes = issueInventoryBytes({ schema: INVENTORY_SCHEMA, consistency: 'two-equal-observations-not-atomic',
    source: { repository, repository_id: repositoryId }, batch_size: 1,
    issues: Array.from({ length: count }, (_, i) => ({ number: i + 1, id: issueId(i + 1) })), excluded_pull_requests: [], complete: true });
  await writeFile(input, bytes, { mode: 0o600 });
  await writeFile(preload, `import { githubPeer } from ${JSON.stringify(fixtureModule)};
import { appendFile, writeFile } from 'node:fs/promises';
const mode = process.env.FG_CAPTURE_TEST_MODE;
globalThis.fetch = githubPeer({ before: async ({ address, ordinal }) => {
  await appendFile(${JSON.stringify(log)}, address + '\\n', { mode: 0o600 });
  if (mode === 'forbid') throw new Error('unexpected_source_access');
  if (mode === 'hold' && ordinal === 7) {
    await writeFile(${JSON.stringify(join(root, 'ready'))}, 'ready', { mode: 0o600 });
    return new Response(new ReadableStream({ cancel() { return writeFile(${JSON.stringify(join(root, 'cancelled'))}, 'cancelled'); } }),
      { headers: { 'Content-Type': 'application/json' } });
  }
} }).fetchImpl;\n`, { mode: 0o600 });
  const args = ['--workdir', workdir, '--inventory', input, '--inventory-sha256', recordDigest(bytes)];
  function child(extra, mode = '') {
    const processChild = spawn(process.execPath, ['--import', pathToFileURL(preload).href, cli, ...extra],
      { env: { ...process.env, FG_CAPTURE_TEST_MODE: mode }, stdio: ['ignore', 'pipe', 'pipe'] });
    const stdout = [], stderr = [];
    processChild.stdout.on('data', b => stdout.push(b)); processChild.stderr.on('data', b => stderr.push(b));
    const done = new Promise((resolve, reject) => {
      const timer = setTimeout(() => { processChild.kill('SIGKILL'); reject(new Error('bounded test child exceeded 10 seconds')); }, 10000);
      processChild.once('error', error => { clearTimeout(timer); reject(error); });
      processChild.once('close', (code, signal) => {
        clearTimeout(timer);
        const decode = chunks => Buffer.concat(chunks).toString('utf8').trim().split('\n').filter(Boolean).map(line => JSON.parse(line));
        try { resolve({ code, signal, stdout: decode(stdout), stderr: decode(stderr) }); } catch (e) { reject(e); }
      });
    });
    t.after(() => processChild.kill('SIGKILL'));
    return { proc: processChild, done };
  }
  return { root, input, workdir, log, args, child };
}
function sink() { let value = ''; return { stream: new Writable({ write(bytes, _encoding, callback) { value += bytes; callback(); } }), rows: () => value.trim().split('\n').filter(Boolean).map(v => JSON.parse(v)) }; }
async function absent(path) { await assert.rejects(lstat(path), { code: 'ENOENT' }); }
async function waitFor(path) {
  const end = performance.now() + 5000;
  while (performance.now() < end) { try { await lstat(path); return; } catch (e) { if (e.code !== 'ENOENT') throw e; } await sleep(5); }
  assert.fail('expected test checkpoint not reached');
}

test('real start/resume/status commands feed the actual migration source loader', async t => {
  const f = await setup(t, 3);
  const initial = await f.child(['start', ...f.args, '--max-batches', '1', '--offset', '100']).done;
  assert.equal(initial.code, 3); assert.equal(initial.stdout.length, 2);
  const ready = initial.stdout[0], prefix = initial.stdout[1];
  assert.equal(ready.type, 'github_issue_capture_session_ready'); assert.equal(ready.requests, 0);
  assert.equal(ready.session_sha256, prefix.session_sha256); assert.equal(prefix.captured_batches, 1);
  await absent(join(f.workdir, 'sources.json')); await rm(f.input);
  const next = ['--workdir', f.workdir, '--confirm', ready.session_sha256];
  const before = await readFile(f.log);
  const observed = await f.child(['status', ...next], 'forbid').done;
  assert.equal(observed.code, 3); assert.deepEqual(await readFile(f.log), before);
  const completed = await f.child(['resume', ...next]).done;
  assert.equal(completed.code, 0); const result = completed.stdout[0];
  const source = await loadGithubIssueMigrationSources(result.sources);
  assert.equal(source.offset, 100); assert.equal(source.captures.length, 3);
  let steps = 0;
  for (const row of source.captures) {
    const bytes = await readFile(row.path); assert.equal(recordDigest(bytes), row.sha256);
    steps += issueImportSteps(parseCapture(bytes), source.offset).length;
  }
  assert.equal(steps, result.steps); assert.equal(source.inventorySha256, prefix.inventory_sha256);
  const completedLog = await readFile(f.log);
  assert.equal((await f.child(['resume', ...next], 'forbid').done).code, 0);
  assert.deepEqual(await readFile(f.log), completedLog);
});

test('prepare is genuinely offline and preserves an independent recovery pin', async t => {
  const f = await setup(t), prepared = await f.child(['prepare', ...f.args], 'forbid').done;
  assert.equal(prepared.code, 0); assert.equal(prepared.stdout[0].operation, 'prepare'); assert.equal(prepared.stdout[0].complete, false);
  await absent(f.log); assert.deepEqual((await readdir(f.workdir)).sort(), ['inventory.json', 'session.json']);
  const capture = await f.child(['resume', '--workdir', f.workdir, '--confirm', prepared.stdout[0].session_sha256]).done;
  assert.equal(capture.code, 0);
});

test('SIGTERM drains a source body and resumes without recapturing completed batches', async t => {
  const f = await setup(t), active = f.child(['start', ...f.args], 'hold'); await waitFor(join(f.root, 'ready'));
  active.proc.kill('SIGTERM'); const stopped = await active.done;
  assert.equal(stopped.code, 3); assert.equal(stopped.stdout[0].type, 'github_issue_capture_session_ready');
  const pin = stopped.stdout[0].session_sha256;
  assert.equal(stopped.stderr[0].capture_progress.captured_batches, 1); await waitFor(join(f.root, 'cancelled'));
  await absent(join(f.workdir, 'capture.owner'));
  const prior = (await readFile(f.log, 'utf8')).trim().split('\n');
  const resumed = await f.child(['resume', '--workdir', f.workdir, '--confirm', pin]).done;
  assert.equal(resumed.code, 0);
  const subsequent = (await readFile(f.log, 'utf8')).trim().split('\n').slice(prior.length);
  assert.ok(subsequent.every(url => !/\/issues\/1(?:\/|$)/.test(url)));
});

test('SIGKILL leaves ownership fenced while offline status remains available', async t => {
  const f = await setup(t), active = f.child(['start', ...f.args], 'hold'); await waitFor(join(f.root, 'ready'));
  active.proc.kill('SIGKILL'); const stopped = await active.done;
  assert.equal(stopped.signal, 'SIGKILL'); const pin = stopped.stdout[0].session_sha256;
  const next = ['--workdir', f.workdir, '--confirm', pin], before = await readFile(f.log);
  const observed = await f.child(['status', ...next], 'forbid').done;
  assert.equal(observed.code, 3); assert.equal(observed.stdout[0].owner_present_at_read, true);
  const refused = await f.child(['resume', ...next], 'forbid').done;
  assert.equal(refused.code, 3); assert.equal(refused.stderr[0].code, 'EEXIST');
  assert.deepEqual(await readFile(f.log), before); assert.ok((await lstat(join(f.workdir, 'capture.owner'))).isDirectory());
});

test('closed stdout before session announcement prevents all source requests', async t => {
  const f = await setup(t), active = f.child(['start', ...f.args]); active.proc.stdout.destroy();
  const result = await active.done; assert.equal(result.code, 4); await absent(f.log);
  assert.ok(result.stderr[0].original_session_sha256); assert.equal(result.stderr[0].capture_progress.captured_batches, 0);
  const recovered = await f.child(['resume', '--workdir', f.workdir, '--confirm', result.stderr[0].original_session_sha256]).done;
  assert.equal(recovered.code, 0);
});

test('failed final output retains a complete result without recapturing', async t => {
  const f = await setup(t, 1), peer = githubPeer(), errorOutput = sink(); const original = globalThis.fetch;
  globalThis.fetch = peer.fetchImpl; t.after(() => { globalThis.fetch = original; });
  let writes = 0;
  const stdout = new Writable({ write(_bytes, _encoding, callback) { if (++writes === 2) callback(new Error('planted-final-output')); else callback(); } });
  const code = await main(['start', ...f.args], { stdout, stderr: errorOutput.stream });
  assert.equal(code, 4); assert.equal(peer.calls.length, 6);
  const progress = errorOutput.rows()[0].capture_progress; assert.equal(progress.complete, true);
  assert.equal((await loadGithubIssueMigrationSources(progress.sources)).captures.length, 1);
});

test('bounded output handles slow and prematurely closed consumers', async () => {
  const stalled = new Writable({ write() {} });
  await assert.rejects(writeJson(stalled, { hello: 'world' }, 20), /output_deadline/);
  const closed = new Writable({ write() { this.destroy(); } });
  await assert.rejects(writeJson(closed, {}, 100), /output_closed/);
  await assert.rejects(writeJson(sink().stream, { body: 'x'.repeat(65536) }), /output_limit/);
});

for (const extra of [['--max-requests', '0'], ['--source-retries', '11'], ['--offset', '-1'], ['--offset', '01'],
  ['--max-batches', '129'], ['--workdir', '/duplicate'], ['--url', 'https://wrong.example/'], ['--token', 'forbidden']]) {
  test(`CLI rejects malformed or unintended authority options ${extra[0]} ${extra[1]}`, async t => {
    const f = await setup(t), result = await f.child(['start', ...f.args, ...extra], 'forbid').done;
    assert.equal(result.code, 2); await absent(f.workdir); await absent(f.log);
  });
}

test('status cannot select source credentials, budgets or new inventory', async t => {
  const f = await setup(t), prepared = await f.child(['prepare', ...f.args]).done;
  for (const extra of [['--token-file', '/not-read'], ['--max-batches', '1'], ['--inventory', '/not-read']]) {
    const result = await f.child(['status', '--workdir', f.workdir, '--confirm', prepared.stdout[0].session_sha256, ...extra], 'forbid').done;
    assert.equal(result.code, 2); await absent(f.log);
  }
});

test('all 128 fixed batches hand off through the actual loader at its exact limit', async t => {
  const f = await setup(t, 128);
  const result = await captureGithubIssueMigration({ operation: 'start', workdir: f.workdir, inventoryFile: f.input,
    inventorySha256: recordDigest(await readFile(f.input)), maxBatches: 128, fetchImpl: githubPeer({ comments: 0 }).fetchImpl });
  assert.equal(result.complete, true); assert.equal(result.captured_batches, 128);
  const selected = await loadGithubIssueMigrationSources(result.sources); assert.equal(selected.captures.length, 128);
  assert.equal((await readdir(f.workdir)).length, 131);
});

test('handoff-incompatible directory names refuse before acquisition', async t => {
  const f = await setup(t); let fetched = false;
  await assert.rejects(captureGithubIssueMigration({ operation: 'start', workdir: f.workdir + '\tbad', inventoryFile: f.input,
    inventorySha256: recordDigest(await readFile(f.input)), fetchImpl: () => { fetched = true; } }), /output_path/);
  assert.equal(fetched, false); await absent(f.workdir + '\tbad');
});

test('a completed capture set can finalize without source access after lost handoff', async t => {
  const f = await setup(t, 1), first = await f.child(['start', ...f.args]).done, result = first.stdout[1];
  // Model the pre-handoff boundary using an exact copy of the existing immutable
  // captures; removing a real published handoff is not an operator recovery rule.
  await rm(result.sources.path);
  const finished = await f.child(['resume', '--workdir', f.workdir, '--confirm', result.session_sha256], 'forbid').done;
  assert.equal(finished.code, 0); assert.equal(finished.stdout[0].network_accessed, false);
  assert.deepEqual(finished.stdout[0].sources, result.sources);
});
