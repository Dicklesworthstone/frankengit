// Actual CLI and private-file execution, with an explicitly substituted GitHub
// HTTP schema fixture. No native authority or live GitHub E2E claim.
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, writeFile, readFile, stat, chmod, symlink, link, rm, access } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawn } from 'node:child_process';
import { setTimeout as sleep } from 'node:timers/promises';
import { importArguments, runGithubImportCommand } from '../../scripts/import_github_issues.mjs';
import { issueInventoryBytes, parseIssueInventory } from '../../scripts/lib/github-issue-inventory.mjs';
import { parseCapture, issueImportSteps } from '../../scripts/lib/github-issue-source.mjs';
import { recordDigest } from '../../scripts/lib/forge-operator-io.mjs';

const script = new URL('../../scripts/import_github_issues.mjs', import.meta.url).pathname;
const preload = new URL('./github-inventory-preload.mjs', import.meta.url).pathname;
const pin = '12'.repeat(32);
async function temporary(t) {
  const root = await mkdtemp(join(tmpdir(), 'fg-inventory-command-'));
  await chmod(root, 0o700); t.after(() => rm(root, { recursive: true, force: true })); return root;
}
function child(args, config = {}, { brokenOutput = false } = {}) {
  const p = spawn(process.execPath, ['--import', preload, script, ...args], { env: {
    PATH: process.env.PATH, FG_INVENTORY_TEST_CASE: JSON.stringify(config),
  }, stdio: ['ignore', 'pipe', 'pipe'] });
  let stdout = '', stderr = '';
  if (brokenOutput) p.stdout.destroy(); else p.stdout.on('data', bytes => { stdout += bytes; });
  p.stderr.on('data', bytes => { stderr += bytes; });
  const result = new Promise((resolve, reject) => {
    p.on('error', reject); p.on('close', (code, signal) => resolve({ code, signal, stdout, stderr }));
  });
  return { process: p, result };
}
const command = (args, config, options) => child(args, config, options).result;
async function inventoryFile(root, { empty = false } = {}) {
  const inventory = { schema: 'frankengit-github-issue-inventory-v1', consistency: 'two-equal-observations-not-atomic',
    source: { repository: 'owner/project', repository_id: '42' }, batch_size: 2,
    issues: empty ? [] : [1, 2, 4, 5].map(number => ({ number, id: String(100000 + number) })),
    excluded_pull_requests: [{ number: 3, issue_id: '100003' }], complete: true };
  const bytes = issueInventoryBytes(inventory), file = join(root, 'inventory.json');
  await writeFile(file, bytes, { mode: 0o600 });
  return { file, bytes, pin: recordDigest(bytes), inventory };
}
const captureArgs = (input, out, batch = '1') => ['capture-batch', '--inventory', input.file,
  '--confirm', input.pin, '--batch', batch, '--out', out];
async function absent(path) { await assert.rejects(access(path), e => e.code === 'ENOENT'); }
async function waitFor(path) {
  for (let n = 0; n < 200; n++) { try { await access(path); return; } catch { await sleep(10); } }
  assert.fail('fixture did not reach its synchronization point');
}

for (const [operation, base] of [
  ['discover', ['discover', '--repository', 'owner/project', '--out', '/absent/out']],
  ['inspect-inventory', ['inspect-inventory', '--inventory', '/absent/file', '--confirm', pin]],
  ['capture-batch', ['capture-batch', '--inventory', '/absent/file', '--confirm', pin, '--batch', '1', '--out', '/absent/out']],
]) {
  test(`${operation}: routes through the original CLI without requiring native publication code`, () => {
    assert.equal(importArguments(base).operation, operation);
  });
  for (const flag of ['--url', '--principal-id', '--idempotency-key', '--retry-unresolved', '--issue']) {
    test(`${operation}: rejects ${flag} before any source or filesystem effects`, async () => {
      await assert.rejects(runGithubImportCommand([...base, flag, '1']), /option/);
    });
  }
}
for (const [flag, value] of [['--batch-size', '0'], ['--batch-size', '101'], ['--batch-size', '01'],
  ['--max-records', '10001'], ['--max-records', '0'], ['--timeout-ms', '0'], ['--timeout-ms', '300001'],
  ['--max-read-bytes', '0'], ['--max-read-bytes', '268435457'], ['--source-retries', '11']]) {
  test(`discovery refuses invalid ${flag}=${value} before looking at output paths`, async () => {
    await assert.rejects(runGithubImportCommand(['discover', '--repository', 'owner/project', '--out', '/absent/out', flag, value]), /github_inventory_/);
  });
}
test('strict command syntax rejects duplicate/missing/mixed/overwide options', () => {
  for (const args of [
    ['discover', '--repository', 'owner/project', '--out', '/out', '--out', '/other'],
    ['discover', '--repository', 'owner/project', '--out'],
    ['discover', '--out', '/out'],
    ['capture-batch', '--inventory', '/in', '--confirm', pin, '--out', '/out'],
    ['capture-batch', '--inventory', '/in', '--confirm', pin, '--out', '/out', '--batch', '1', '--batch-size', '1'],
    ['inspect-inventory', '--inventory', '/in', '--confirm', pin, '--token-file', '/private'],
    ['inspect-inventory', '--inventory', '/in', '--confirm', pin, '--batch', '1.5'],
    ['inspect-inventory', '--inventory', '/in', '--confirm', 'ab'.repeat(32).toUpperCase()],
    ['inspect-inventory', '--inventory', '/in', '--confirm', pin, '--batch', '10001'],
    ['discover', '--repository', 'other/../project', '--out', '/out'],
    ['discover', '--repository', 'owner/project', '--out', '/a\nb'],
  ]) assert.throws(() => importArguments(args));
});
test('same or normalized alias output cannot overwrite inventory or explicit source token', async () => {
  for (const args of [
    ['discover', '--repository', 'owner/project', '--out', '/tmp/file', '--token-file', '/tmp/a/../file'],
    ['capture-batch', '--inventory', '/tmp/file', '--confirm', pin, '--batch', '1', '--out', '/tmp/a/../file'],
  ]) await assert.rejects(runGithubImportCommand(args), /separate_output/);
});

test('actual discover, offline inspect, successive capture-batch and original inspect compose across process restarts', async t => {
  const root = await temporary(t), file = join(root, 'inventory.json'), log = join(root, 'requests.jsonl'), tokenFile = join(root, 'token');
  await writeFile(tokenFile, 'github_pat_fixture\n', { mode: 0o600 });
  const first = await command(['discover', '--repository', 'owner/project', '--out', file, '--batch-size', '2', '--token-file', tokenFile],
    { token: 'github_pat_fixture', log });
  assert.equal(first.code, 0, first.stderr); const discovery = JSON.parse(first.stdout);
  const bytes = await readFile(file), inventory = parseIssueInventory(bytes);
  assert.equal(discovery.sha256, recordDigest(bytes)); assert.equal(discovery.issues, 4); assert.equal(discovery.excluded_pull_requests, 1);
  assert.equal(discovery.total_batches, 2); assert.equal(discovery.mutation_submitted, false);
  assert.equal((await stat(file)).mode & 0o777, 0o600);
  assert.equal(bytes.includes('github_pat_fixture'), false);
  const before = await readFile(log, 'utf8');
  const inspect = await command(['inspect-inventory', '--inventory', file, '--confirm', discovery.sha256], { offline: true, log });
  assert.equal(inspect.code, 0, inspect.stderr);
  assert.deepEqual(JSON.parse(inspect.stdout).inventory, inventory);
  assert.equal(await readFile(log, 'utf8'), before);
  const population = [];
  for (const batch of ['1', '2']) {
    const out = join(root, `capture-${batch}.json`);
    const r = await command(captureArgs({ file, pin: discovery.sha256 }, out, batch), { count: 50, log });
    assert.equal(r.code, 0, r.stderr); const result = JSON.parse(r.stdout), source = parseCapture(await readFile(out));
    assert.equal(result.type, 'github_issue_capture'); assert.equal(result.selection.inventory_sha256, discovery.sha256);
    assert.equal(result.selection.next_batch, batch === '1' ? 2 : null); assert.equal(result.mutation_submitted, false);
    population.push(...source.issues.map(r => r.number));
    const native = await command(['inspect', '--capture', out, '--offset', '100'], { offline: true, log });
    assert.equal(native.code, 0, native.stderr);
    assert.deepEqual(JSON.parse(native.stdout).steps, issueImportSteps(source, 100));
  }
  assert.deepEqual(population, [1, 2, 4, 5]); assert.deepEqual(await readFile(file), bytes);
  const requests = (await readFile(log, 'utf8')).trim().split('\n').map(JSON.parse);
  assert.ok(requests.every(r => r.method === 'GET'));
  assert.ok(requests.every(r => !/issues\/3(\/|$)/.test(r.path)));
});
test('offline inspection of empty populations works but selecting a batch refuses', async t => {
  const root = await temporary(t), input = await inventoryFile(root, { empty: true });
  const r = await command(['inspect-inventory', '--inventory', input.file, '--confirm', input.pin], { offline: true });
  assert.equal(r.code, 0, r.stderr); assert.equal(JSON.parse(r.stdout).total_batches, 0);
  const b = await command(captureArgs(input, join(root, 'capture')), { offline: true });
  assert.equal(b.code, 2); assert.match(b.stderr, /github_inventory_batch/); await absent(join(root, 'capture'));
});
test('the CLI refuses pin substitution and out-of-range batch before reading a missing token', async t => {
  const root = await temporary(t), input = await inventoryFile(root), out = join(root, 'capture');
  for (const [key, batch, code] of [[pin, '1', /pin_mismatch/], [input.pin, '3', /batch/]]) {
    const r = await command([...captureArgs({ ...input, pin: key }, out, batch), '--token-file', join(root, 'missing')], { offline: true });
    assert.equal(r.code, 2); assert.match(r.stderr, code); await absent(out);
  }
});
for (const kind of ['public-file', 'symlink', 'hardlink']) test(`private inventory reader refuses ${kind}`, async t => {
  const root = await temporary(t), input = await inventoryFile(root), bad = join(root, 'bad'), out = join(root, 'capture');
  if (kind === 'public-file') await chmod(input.file, 0o644);
  if (kind === 'symlink') { await symlink(input.file, bad); input.file = bad; }
  if (kind === 'hardlink') { await link(input.file, bad); input.file = bad; }
  const r = await command(captureArgs(input, out), { offline: true });
  assert.equal(r.code, 2); await absent(out);
});
for (const kind of ['existing-file', 'symlink', 'public-parent']) test(`output refusal preserves ${kind} without fetching`, async t => {
  const root = await temporary(t), out = join(root, 'out'), original = Buffer.from('PRESERVE');
  if (kind === 'existing-file') await writeFile(out, original, { mode: 0o600 });
  if (kind === 'symlink') { await writeFile(join(root, 'target'), original, { mode: 0o600 }); await symlink(join(root, 'target'), out); }
  if (kind === 'public-parent') await chmod(root, 0o755);
  const r = await command(['discover', '--repository', 'owner/project', '--out', out], { offline: true });
  assert.equal(r.code, 2); assert.doesNotMatch(r.stderr, /Network forbidden/);
  if (kind !== 'public-parent') assert.deepEqual(await readFile(out), original); else await absent(out);
});
test('source replacement is a capture failure, not a new selection or partially successful output', async t => {
  const root = await temporary(t), input = await inventoryFile(root), out = join(root, 'capture'), log = join(root, 'requests');
  for (const config of [{ repositoryId: '43' }, { replacedIssue: true }]) {
    const r = await command(captureArgs(input, out), { ...config, log });
    assert.equal(r.code, 2); assert.match(r.stderr, /selection_(repository|issue)_changed/);
    await absent(out); assert.deepEqual(await readFile(input.file), input.bytes);
  }
  assert.ok(!(await readFile(log, 'utf8')).includes('/comments'));
});
test('concurrent capture creators have one intact winner and never overwrite it', async t => {
  const root = await temporary(t), input = await inventoryFile(root), out = join(root, 'capture');
  const results = await Promise.all([command(captureArgs(input, out)), command(captureArgs(input, out))]);
  assert.deepEqual(results.map(r => r.code).sort(), [0, 2]);
  assert.equal(parseCapture(await readFile(out)).issues.length, 2);
  const winner = JSON.parse(results.find(r => r.code === 0).stdout);
  assert.equal(recordDigest(await readFile(out)), winner.sha256);
});
test('SIGTERM cancels a delayed source body and creates no successful capture', async t => {
  const root = await temporary(t), input = await inventoryFile(root), out = join(root, 'capture');
  const ready = join(root, 'ready'), cancelled = join(root, 'cancelled');
  const run = child(captureArgs(input, out), { stall: true, ready, cancelled });
  t.after(() => { if (run.process.exitCode === null) run.process.kill('SIGKILL'); });
  await waitFor(ready); run.process.kill('SIGTERM');
  const r = await run.result; assert.equal(r.code, 2); assert.equal(r.signal, null);
  await waitFor(cancelled); await absent(out);
});
test('whole command timeout drains delayed source input without a saved inventory', async t => {
  const root = await temporary(t), out = join(root, 'inventory');
  const ready = join(root, 'ready'), cancelled = join(root, 'cancelled');
  const r = await command(['discover', '--repository', 'owner/project', '--out', out, '--timeout-ms', '100'], { stall: true, ready, cancelled });
  assert.equal(r.code, 2); await waitFor(cancelled); await absent(out);
});
test('genuinely closed stdout preserves the completed capture and returns an error, not a new key or retry', async t => {
  const root = await temporary(t), input = await inventoryFile(root), out = join(root, 'capture');
  const r = await command(captureArgs(input, out), {}, { brokenOutput: true });
  assert.equal(r.code, 2, r.stderr);
  const recovered = parseCapture(await readFile(out)); assert.equal(recovered.issues.length, 2);
  const error = JSON.parse(r.stderr), completed = JSON.parse(error.completed_result);
  assert.equal(completed.sha256, recordDigest(await readFile(out)));
  assert.equal(completed.selection.inventory_sha256, input.pin);
  assert.equal(completed.mutation_submitted, false);
});
test('source error diagnostics and successful files never persist the GitHub credential', async t => {
  const root = await temporary(t), out = join(root, 'inventory'), tokenFile = join(root, 'token');
  const token = 'github_pat_private_fixture'; await writeFile(tokenFile, token, { mode: 0o600 });
  const r = await command(['discover', '--repository', 'owner/project', '--out', out, '--token-file', tokenFile], { fail: true, token });
  assert.equal(r.code, 2); assert.ok(!r.stderr.includes(token)); assert.ok(!r.stderr.includes('SECRET SOURCE DIAGNOSTIC'));
  await absent(out);
});
