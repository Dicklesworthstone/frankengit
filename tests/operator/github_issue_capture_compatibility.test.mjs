// The expected bytes/keys were frozen from unmodified 5ddaab7c before V2.
// Synthetic credentials and deterministic nonces are TEST ONLY. No network.
import test from 'node:test';
import assert from 'node:assert/strict';
import { webcrypto, createHash } from 'node:crypto';
import { mkdtemp, writeFile, readFile, readdir, rm, mkdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { captureBytes, parseCapture, issueImportSteps, CAPTURE_SCHEMA }
  from '../../scripts/lib/github-issue-source.mjs';
import { prepareGithubIssueImport, inspectPreparedGithubIssueImport }
  from '../../scripts/lib/github-issue-import.mjs';
import { captureGithubIssueMigration } from '../../scripts/lib/github-issue-capture-migration.mjs';
import { issueInventoryBytes, INVENTORY_SCHEMA } from '../../scripts/lib/github-issue-inventory.mjs';
import { recordDigest } from '../../scripts/lib/forge-operator-io.mjs';

const { capture, golden } = JSON.parse(await readFile(new URL('./fixtures/github_issue_capture_v1.json', import.meta.url)));
const encode = value => Buffer.from(JSON.stringify(value) + '\n');
async function root(t) {
  const path = await mkdtemp(join(tmpdir(), 'fg-github-v1-'));
  t.after(() => rm(path, { recursive: true, force: true }));
  return path;
}
async function hashesAt(path) {
  const hashes = {};
  for (const name of (await readdir(path)).sort()) hashes[name] = recordDigest(await readFile(join(path, name)));
  return hashes;
}

test('GitHub capture-v1 retains byte-exact commands even when source issues are locked', () => {
  const bytes = captureBytes(capture), steps = issueImportSteps(parseCapture(bytes), 40);
  assert.equal(capture.schema, CAPTURE_SCHEMA); assert.ok(capture.issues.every(row => row.locked));
  assert.deepEqual(bytes, encode(capture)); assert.equal(bytes.length, golden.capture_bytes);
  assert.equal(recordDigest(bytes), golden.capture_sha256);
  assert.equal(encode(steps).length, golden.steps_bytes);
  assert.equal(recordDigest(encode(steps)), golden.steps_sha256);
  assert.deepEqual(steps.map(({ number, expected_version, action }) => ({ number, expected_version, action })),
    golden.requests.map(({ number, expected_version, action }) => ({ number, expected_version, action })));
  assert.equal(steps.some(row => row.action === 'lock'), false, 'legacy compilation must never gain a new mutation');
});

test('prepared GitHub-v1 custody retains every frozen request key, body and plan hash', async t => {
  const dir = await root(t), captureFile = join(dir, 'capture.json'), tokenFile = join(dir, 'token');
  const options = { workdir: join(dir, 'plan'), tokenFile,
    href: 'https://fixture.invalid/destination/ui/issues/', tenant: '4'.repeat(32), repository: '5'.repeat(32) };
  await writeFile(captureFile, encode(capture), { mode: 0o600 });
  await writeFile(tokenFile, createHash('sha256')
    .update('FrankenGit GitHub-v1 public regression token, never a real credential').digest('hex'), { mode: 0o600 });
  const descriptor = Object.getOwnPropertyDescriptor(globalThis, 'crypto'), previousFetch = globalThis.fetch;
  let nonce = 0, finished = false, network = 0;
  Object.defineProperty(globalThis, 'crypto', { configurable: true,
    value: { subtle: webcrypto.subtle, getRandomValues(value) {
      assert.equal(finished, false, 'inspection must not create replacement request keys');
      value.fill(++nonce); return value;
    } } });
  globalThis.fetch = () => { network++; throw new Error('legacy custody must remain offline'); };
  try {
    const plan = await prepareGithubIssueImport({ ...options, captureFile, offset: 40 }); finished = true;
    assert.equal(plan.plan_sha256, golden.plan_sha256); assert.equal(plan.steps, 7); assert.equal(nonce, 7);
    assert.deepEqual(await hashesAt(options.workdir), golden.hashes);
    assert.deepEqual(JSON.parse(await readFile(join(options.workdir, 'manifest.json'))), golden.manifest);
    for (const expected of golden.requests) {
      const { receipt: { request } } = JSON.parse(await readFile(join(options.workdir, expected.name)));
      assert.deepEqual({ name: expected.name, number: request.number, expected_version: request.expected_version,
        action: request.action, key: request.key, body_sha256: recordDigest(Buffer.from(request.body)) }, expected);
    }
    await rm(captureFile);
    for (let attempt = 0; attempt < 2; attempt++) {
      const observed = await inspectPreparedGithubIssueImport({ ...options, confirm: golden.plan_sha256 });
      assert.equal(observed.plan_sha256, golden.plan_sha256); assert.equal(observed.steps, 7);
      assert.equal(observed.source_sha256, golden.capture_sha256); assert.equal(observed.network_accessed, false);
      assert.deepEqual(await hashesAt(options.workdir), golden.hashes);
    }
    assert.equal(nonce, 7); assert.equal(network, 0);
  } finally {
    Object.defineProperty(globalThis, 'crypto', descriptor); globalThis.fetch = previousFetch;
  }
});

test('a pre-upgrade source session resumes only its missing batch in the frozen V1 dialect', async t => {
  const dir = await root(t), workdir = join(dir, 'capture'); await mkdir(workdir, { mode: 0o700 });
  const inventory = { schema: INVENTORY_SCHEMA, consistency: capture.consistency, source: capture.source,
    batch_size: 1, issues: capture.issues.map(({ number, id }) => ({ number, id })), excluded_pull_requests: [], complete: true };
  const inventoryBytes = issueInventoryBytes(inventory), header = {
    schema: 'frankengit-github-issue-capture-session-v1', workdir,
    inventory_sha256: recordDigest(inventoryBytes), credential_sha256: null, offset: 40,
    max_capture_bytes: 64 * 1024 * 1024, max_steps: 10000,
  };
  const first = encode({ ...capture, issues: [capture.issues[0]] });
  const firstName = `capture-000001-${recordDigest(first)}.json`;
  await writeFile(join(workdir, 'inventory.json'), inventoryBytes, { mode: 0o600 });
  await writeFile(join(workdir, 'session.json'), encode(header), { mode: 0o600 });
  await writeFile(join(workdir, firstName), first, { mode: 0o600 });
  const calls = [], row = capture.issues[1];
  const fetchImpl = async address => {
    const url = new URL(address); calls.push(url.pathname);
    const value = url.pathname === '/repos/owner/project' ? { id: capture.source.repository_id, full_name: 'owner/project' }
      : url.pathname === `/repos/owner/project/issues/${row.number}` ? { ...row, comments: row.comment_count }
      : url.pathname === `/repos/owner/project/issues/${row.number}/comments` ? row.comments : assert.fail('completed batch must not be recaptured');
    return new Response(JSON.stringify(value), { headers: { 'Content-Type': 'application/json' } });
  };
  const options = { operation: 'resume', workdir, confirm: recordDigest(encode(header)), fetchImpl };
  const completed = await captureGithubIssueMigration(options);
  assert.equal(completed.complete, true); assert.equal(completed.steps, 7); assert.equal(calls.length, 6);
  assert.equal(completed.newly_captured_batches, 1);
  assert.deepEqual(await readFile(join(workdir, firstName)), first);
  assert.deepEqual(await readFile(join(workdir, 'session.json')), encode(header));
  const sources = JSON.parse(await readFile(completed.sources.path));
  assert.deepEqual(await readFile(sources.captures[1].path), encode({ ...capture, issues: [row] }));
  const again = await captureGithubIssueMigration({ ...options, fetchImpl: () => assert.fail('completed source is offline') });
  assert.equal(again.steps, 7); assert.equal(again.newly_captured_batches, 0);
  assert.deepEqual(again.sources, completed.sources);
});
