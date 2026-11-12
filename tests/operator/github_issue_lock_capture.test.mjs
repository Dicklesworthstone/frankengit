// Source HTTP is an explicit fixture; capture/compilation/custody run unchanged.
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, writeFile, readFile, readdir, rm, rename } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { captureGithubIssues, createGithubIssueCaptureSession, captureBytes, parseCapture,
  issueImportSteps, CAPTURE_SCHEMA, CAPTURE_SCHEMA_V2 }
  from '../../scripts/lib/github-issue-source.mjs';
import { captureGithubIssueMigration } from '../../scripts/lib/github-issue-capture-migration.mjs';
import { issueInventoryBytes, INVENTORY_SCHEMA } from '../../scripts/lib/github-issue-inventory.mjs';
import { recordDigest } from '../../scripts/lib/forge-operator-io.mjs';
import { repository, repositoryId, issueId, issue, json, githubPeer } from './fixtures/github_capture_source.mjs';

function sourcePeer(locked = () => true) {
  return githubPeer({ before: async ({ path, ordinal }) => {
    const match = /\/issues\/(\d+)$/.exec(path);
    if (match) return json({ ...issue(Number(match[1])), locked: locked(Number(match[1]), ordinal) });
  } });
}
async function sourceFixture(t, extra = {}) {
  const root = await mkdtemp(join(tmpdir(), 'fg-github-lock-capture-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const inventory = { schema: INVENTORY_SCHEMA, consistency: 'two-equal-observations-not-atomic',
    source: { repository, repository_id: repositoryId }, batch_size: 1,
    issues: [1, 2].map(number => ({ number, id: issueId(number) })), excluded_pull_requests: [], complete: true };
  const inventoryFile = join(root, 'original.json'), bytes = issueInventoryBytes(inventory);
  await writeFile(inventoryFile, bytes, { mode: 0o600 });
  return { root, options: { operation: 'prepare', workdir: join(root, 'captures'),
    inventoryFile, inventorySha256: recordDigest(bytes), ...extra } };
}

test('new standalone captures default to V2 and compile final moderation independently of open/closed', async () => {
  const peer = sourcePeer(n => n <= 2);
  const captured = await captureGithubIssues({ repository, numbers: [1, 2, 3, 4], fetchImpl: peer.fetchImpl });
  assert.equal(captured.capture.schema, CAPTURE_SCHEMA_V2);
  assert.deepEqual(parseCapture(captured.bytes), captured.capture);
  for (const row of captured.capture.issues) {
    const commands = issueImportSteps(captured.capture, 100).filter(step => step.number === row.number + 100);
    assert.deepEqual(commands.map(step => step.action), ['open', 'comment',
      ...(row.state === 'closed' ? ['close'] : []), ...(row.locked ? ['lock'] : [])]);
    assert.deepEqual(commands.map(step => step.expected_version), commands.map((_, index) => index));
    if (row.locked) assert.deepEqual(commands.at(-1).fields, {});
  }
});

test('V2 strictly validates lock state and dialect instead of coercing or dropping them', async () => {
  const { capture } = await captureGithubIssues({ repository, numbers: [1], fetchImpl: sourcePeer().fetchImpl });
  for (const locked of [undefined, null, 0, 1, 'true', [], {}]) {
    const changed = structuredClone(capture); changed.issues[0].locked = locked;
    assert.throws(() => captureBytes(changed), /issue_state/);
  }
  for (const schema of [undefined, null, 'frankengit-github-issue-capture-v3', CAPTURE_SCHEMA_V2 + ' ']) {
    assert.throws(() => captureBytes({ ...capture, schema }), /capture_schema/);
    assert.throws(() => createGithubIssueCaptureSession({ captureSchema: schema === undefined ? '' : schema,
      fetchImpl: () => assert.fail('invalid profile must not create a source request') }), /capture_schema/);
  }
  const legacy = structuredClone(capture); legacy.schema = CAPTURE_SCHEMA;
  assert.deepEqual(issueImportSteps(legacy).map(step => step.action), ['open', 'comment']);
  assert.equal(issueImportSteps(capture).at(-1).action, 'lock');
});

test('a source lock change between the two observations refuses the complete capture', async () => {
  await assert.rejects(captureGithubIssues({ repository, numbers: [1],
    fetchImpl: sourcePeer((_n, ordinal) => ordinal >= 5).fetchImpl }), /source_changed/);
});

test('new source sessions pin V2 across bounded acquisition, resume and offline inspection', async t => {
  const f = await sourceFixture(t), ready = await captureGithubIssueMigration(f.options);
  const headerBytes = await readFile(join(ready.workdir, 'session.json'));
  assert.equal(JSON.parse(headerBytes).schema, 'frankengit-github-issue-capture-session-v2');
  const resume = { operation: 'resume', workdir: ready.workdir, confirm: ready.session_sha256 };
  const first = await captureGithubIssueMigration({ ...resume, maxBatches: 1, fetchImpl: sourcePeer().fetchImpl });
  assert.equal(first.steps, 3); assert.equal(first.complete, false);
  const name = (await readdir(ready.workdir)).find(name => name.startsWith('capture-'));
  const firstBytes = await readFile(join(ready.workdir, name));
  assert.equal(parseCapture(firstBytes).schema, CAPTURE_SCHEMA_V2);
  const completed = await captureGithubIssueMigration({ ...resume, fetchImpl: sourcePeer().fetchImpl });
  assert.equal(completed.steps, 7); assert.equal(completed.complete, true);
  assert.deepEqual(await readFile(join(ready.workdir, name)), firstBytes);
  assert.deepEqual(await readFile(join(ready.workdir, 'session.json')), headerBytes);
  const sources = JSON.parse(await readFile(completed.sources.path));
  for (const row of sources.captures) {
    const capture = parseCapture(await readFile(row.path));
    assert.equal(capture.schema, CAPTURE_SCHEMA_V2); assert.equal(issueImportSteps(capture).at(-1).action, 'lock');
  }
  const observed = await captureGithubIssueMigration({ ...resume, operation: 'status' });
  assert.equal(observed.steps, 7); assert.equal(observed.network_accessed, false);
});

test('lock commands spend the aggregate acquisition step budget before any complete source handoff', async t => {
  const short = await sourceFixture(t, { maxSteps: 6 }), exact = await sourceFixture(t, { maxSteps: 7 });
  await assert.rejects(captureGithubIssueMigration({ ...short.options, operation: 'start', fetchImpl: sourcePeer().fetchImpl }),
    error => error.code === 'github_capture_migration_capacity' && error.capture_progress.steps === 3);
  assert.ok(!(await readdir(short.options.workdir)).includes('sources.json'));
  const allowed = await captureGithubIssueMigration({ ...exact.options, operation: 'start', fetchImpl: sourcePeer().fetchImpl });
  assert.equal(allowed.complete, true); assert.equal(allowed.steps, 7);
});

test('a valid retained capture in the wrong dialect cannot change a pinned session on resume', async t => {
  const f = await sourceFixture(t);
  const first = await captureGithubIssueMigration({ ...f.options, operation: 'start', maxBatches: 1, fetchImpl: sourcePeer().fetchImpl });
  const name = (await readdir(first.workdir)).find(name => name.startsWith('capture-'));
  const path = join(first.workdir, name), capture = parseCapture(await readFile(path));
  capture.schema = CAPTURE_SCHEMA;
  const bytes = captureBytes(capture), replacement = join(first.workdir, `capture-000001-${recordDigest(bytes)}.json`);
  await writeFile(path, bytes); await rename(path, replacement);
  await assert.rejects(captureGithubIssueMigration({ operation: 'resume', workdir: first.workdir,
    confirm: first.session_sha256, fetchImpl: () => assert.fail('profile mismatch must precede HTTP') }), /capture_profile_changed/);
});

test('per-capture final locks respect both the existing command and byte ceilings', async () => {
  const { capture: template } = await captureGithubIssues({ repository, numbers: [1], fetchImpl: sourcePeer().fetchImpl });
  function large(totalComments) {
    const capture = { ...template, source: { repository: 'a/b', repository_id: '1' }, issues: [] };
    let nextId = 1;
    for (let number = 1; number <= 100; number++) {
      const count = Math.floor(totalComments / 100) + Number(number <= totalComments % 100);
      const date = '2026-10-01T00:00:00Z';
      capture.issues.push({ ...template.issues[0], number, id: String(number),
        html_url: `https://github.com/a/b/issues/${number}`, title: 'x', body: '', state: 'closed',
        state_reason: null, user: null, created_at: date, updated_at: date, closed_at: date,
        labels: [], assignees: [], milestone: null, locked: true, comment_count: count,
        comments: Array.from({ length: count }, () => {
          const id = String(nextId++);
          return { id, html_url: `https://github.com/a/b/issues/${number}#issuecomment-${id}`,
            issue_url: `https://api.github.com/repos/a/b/issues/${number}`, user: null,
            created_at: date, updated_at: date, body: '' };
        }) });
    }
    return capture;
  }
  // Provenance consumes the independent byte budget before 2200 commands can
  // fit. Keep a permitted near-byte-limit twin, and exercise both refusals
  // without weakening either production ceiling.
  const exact = large(1798); captureBytes(exact);
  assert.equal(issueImportSteps(exact).length, 2098);
  const byteOverflow = large(1900); captureBytes(byteOverflow);
  assert.throws(() => issueImportSteps(byteOverflow), /native_plan_bytes/);
  const overflow = large(1901); captureBytes(overflow);
  assert.throws(() => issueImportSteps(overflow), /native_plan_steps/);
});
