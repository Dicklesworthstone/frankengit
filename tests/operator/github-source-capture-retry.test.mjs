// Read-only HTTP contract fixtures exercise the production capture and command.
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { captureGithubIssues } from '../../scripts/lib/github-issue-source.mjs';
import { importArguments } from '../../scripts/import_github_issues.mjs';

const repository = 'owner/project', time = '2026-10-01T10:00:00Z', user = { id: 11, login: 'source-author' };
const base = number => ({ id: 1000 + number, number, html_url: `https://github.com/${repository}/issues/${number}`,
  title: `Issue ${number}`, body: 'Original body\r\n%26 private text', state: 'open', state_reason: null,
  user, created_at: time, updated_at: time, closed_at: null,
  labels: [{ id: 1, name: 'bug', color: 'ABCDEF', description: 'Source label' }],
  assignees: [user], milestone: { id: 2, number: 1, title: 'Release', state: 'open' }, locked: false, comments: 0 });
const comment = (n, id) => ({ id, user, body: `Comment ${id}\n`, created_at: time, updated_at: time,
  html_url: `https://github.com/${repository}/issues/${n}#issuecomment-${id}`,
  issue_url: `https://api.github.com/repos/${repository}/issues/${n}` });
function peer({ issue = base, comments = () => [], modify = () => {}, repoId = 42 } = {}) {
  const calls = [];
  const fetchImpl = async (url, init) => {
    const call = { url: new URL(url), ...init }; calls.push(call);
    let data, headers = { 'Content-Type': 'application/json' };
    if (call.url.pathname === `/repos/${repository}`) data = { id: repoId, full_name: repository };
    else {
      const match = /^\/repos\/owner\/project\/issues\/(\d+)(\/comments)?$/.exec(call.url.pathname);
      assert.ok(match, call.url.href); const n = Number(match[1]);
      if (match[2]) {
        const rows = comments(n), page = Number(call.url.searchParams.get('page'));
        data = rows.slice((page - 1) * 100, page * 100);
        if (page * 100 < rows.length) headers.Link = `<https://api.github.com/repositories/${repoId}/issues/${n}/comments?per_page=100&page=${page + 1}>; rel="next"`;
      } else data = issue(n);
    }
    const raw = { data: structuredClone(data), status: 200, headers }; modify(raw, calls);
    return new Response(JSON.stringify(raw.data), { status: raw.status, headers: raw.headers });
  };
  return { calls, fetchImpl };
}
const capture = (options = {}, source = peer()) => captureGithubIssues({ repository, numbers: [3], ...source, ...options });


test('opt-in source retries preserve exact capture bytes across early and late transient replies', async () => {
  const expected = await capture();
  for (const failureAt of [1, 3, 4, 6]) {
    const p = peer(); let attempts = 0;
    const result = await capture({ maxSourceRetries: 1, fetchImpl: async (...args) => {
      if (++attempts === failureAt) return new Response('private upstream diagnostic', {
        status: 503, headers: { 'Retry-After': '0' },
      });
      return p.fetchImpl(...args);
    } });
    assert.deepEqual(result.bytes, expected.bytes);
    assert.equal(result.sha256, expected.sha256);
    assert.equal(result.source_retries, 1); assert.equal(result.requests, expected.requests + 1);
    assert.equal(result.read_bytes, expected.read_bytes);
  }
});

test('the source retry allowance is shared by both full observations', async () => {
  const p = peer(); let attempts = 0;
  await assert.rejects(capture({ maxSourceRetries: 1, fetchImpl: async (...args) => {
    if ([1, 5].includes(++attempts)) return new Response('limited', { status: 429, headers: { 'Retry-After': '0' } });
    return p.fetchImpl(...args);
  } }), error => error.code === 'github_import_source_http' && error.status === 429);
  assert.equal(attempts, 5);
});

test('retrying a comments continuation neither duplicates comments nor hides changed source data', async () => {
  const makePeer = () => peer({ issue: n => ({ ...base(n), comments: 101 }),
    comments: n => Array.from({ length: 101 }, (_, i) => comment(n, i + 1)) });
  const expected = await capture({}, makePeer()), p = makePeer(); let failed = false;
  const result = await capture({ maxSourceRetries: 1, fetchImpl: async (url, init) => {
    if (!failed && new URL(url).searchParams.get('page') === '2') {
      failed = true; return new Response('', { status: 502, headers: { 'Retry-After': '0' } });
    }
    return p.fetchImpl(url, init);
  } });
  assert.equal(result.source_retries, 1); assert.deepEqual(result.bytes, expected.bytes);
  let reads = 0;
  await assert.rejects(capture({ maxSourceRetries: 2 }, peer({
    issue: n => ({ ...base(n), body: ++reads === 1 ? 'before' : 'after' }),
  })), /source_changed/);
});

test('source retry flags are explicit, bounded and never accepted by native publication commands', () => {
  const args = ['capture', '--repository', repository, '--issue', '3', '--out', '/tmp/new-capture'];
  for (const value of ['0', '10']) assert.equal(importArguments([...args, '--source-retries', value]).values.get('--source-retries'), value);
  for (const value of ['11', '-1', '01', '1.5']) assert.throws(() => importArguments([...args, '--source-retries', value]));
  assert.throws(() => importArguments([...args, '--source-retries', '1', '--source-retries', '2']));
  for (const operation of ['prepare', 'run', 'status', 'inspect']) {
    assert.throws(() => importArguments([operation, '--source-retries', '1']), /github_import_option/);
  }
});

test('capture command persists exact private bytes after a read-only retry and never overwrites them', async t => {
  const { readFile, stat } = await import('node:fs/promises');
  const { runGithubImportCommand } = await import('../../scripts/import_github_issues.mjs');
  const root = await mkdtemp(join(tmpdir(), 'fg-github-retry-')); t.after(() => rm(root, { recursive: true, force: true }));
  const expected = await capture(), p = peer(); let attempts = 0;
  t.mock.method(globalThis, 'fetch', async (...args) => {
    if (++attempts === 1) return new Response('limited', { status: 429, headers: { 'Retry-After': '0' } });
    return p.fetchImpl(...args);
  });
  const path = join(root, 'capture.json');
  const args = ['capture', '--repository', repository, '--issue', '3', '--out', path, '--source-retries', '1'];
  const result = await runGithubImportCommand(args), receipt = JSON.parse(result.text);
  assert.equal(result.exitCode, 0); assert.equal(receipt.source_retries, 1); assert.equal(receipt.requests, 7);
  assert.equal(receipt.mutation_submitted, false); assert.equal(receipt.atomic_source_snapshot, false);
  assert.deepEqual(await readFile(path), expected.bytes); assert.equal((await stat(path)).mode & 0o777, 0o600);
  await assert.rejects(runGithubImportCommand(args), /operator_record_exists/);
  assert.equal(attempts, 7); assert.deepEqual(await readFile(path), expected.bytes);
});

test('capture command refuses an over-deadline retry without saving a usable package', async t => {
  const { lstat } = await import('node:fs/promises');
  const { runGithubImportCommand } = await import('../../scripts/import_github_issues.mjs');
  const root = await mkdtemp(join(tmpdir(), 'fg-github-retry-stop-')); t.after(() => rm(root, { recursive: true, force: true }));
  let requests = 0;
  t.mock.method(globalThis, 'fetch', async () => { requests++; return new Response('', { status: 429, headers: { 'Retry-After': '60' } }); });
  const path = join(root, 'capture.json');
  await assert.rejects(runGithubImportCommand(['capture', '--repository', repository, '--issue', '3', '--out', path,
    '--source-retries', '10', '--timeout-ms', '1000']), error => error.code === 'github_import_source_http');
  assert.equal(requests, 1);
  await assert.rejects(lstat(path), error => error.code === 'ENOENT');
});
