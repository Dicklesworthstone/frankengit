// GitHub HTTP contract fixtures; production capture, parser, compiler and CLI.
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { captureGithubIssues, captureBytes, parseCapture, issueImportSteps, API_VERSION } from '../../scripts/lib/github-issue-source.mjs';
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

test('capture is read-only, deterministic, complete for explicit selections and token-free', async () => {
  const p = peer({ issue: n => ({ ...base(n), comments: 2, state: 'closed', closed_at: time }), comments: n => [comment(n, n * 100 + 10), comment(n, n * 100 + 20)] });
  const result = await capture({ numbers: [3, 1], token: 'github_pat_private' }, p);
  assert.equal(result.capture.issues.length, 2); assert.deepEqual(result.capture.issues.map(i => i.number), [1, 3]);
  assert.equal(result.requests, 10); assert.equal(result.bytes.includes('github_pat_private'), false);
  assert.deepEqual(parseCapture(result.bytes), result.capture);
  for (const c of p.calls) {
    assert.equal(c.method, 'GET'); assert.equal(c.body, undefined); assert.equal(c.redirect, 'error');
    assert.equal(c.headers['X-GitHub-Api-Version'], API_VERSION); assert.equal(c.url.origin, 'https://api.github.com');
    assert.equal(c.headers.Authorization, 'Bearer github_pat_private');
  }
  const steps = issueImportSteps(result.capture, 100);
  assert.deepEqual(steps.map(s => [s.number, s.expected_version, s.action]),
    [[101, 0, 'open'], [101, 1, 'comment'], [101, 2, 'comment'], [101, 3, 'close'],
      [103, 0, 'open'], [103, 1, 'comment'], [103, 2, 'comment'], [103, 3, 'close']]);
  assert.deepEqual(steps[0].fields.labels, ['bug']); assert.ok(steps[0].fields.body.endsWith(base(1).body));
  assert.match(steps[0].fields.body, /attribution only/); assert.equal(Object.hasOwn(steps[0].fields, 'principal'), false);
  assert.equal(steps.some(s => s.action === 'assign'), false);
});

test('pagination accepts GitHub numeric-repository next URLs but never follows server-selected targets', async () => {
  const p = peer({ issue: n => ({ ...base(n), comments: 101 }), comments: n => Array.from({ length: 101 }, (_, i) => comment(n, i + 1)) });
  const result = await capture({}, p); assert.equal(result.capture.issues[0].comments.length, 101);
  assert.equal(p.calls.filter(c => c.url.searchParams.get('page') === '2').length, 2);
  assert.ok(p.calls.every(c => c.url.pathname.startsWith('/repos/owner/project')));
});

for (const [name, modify, code] of [
  ['missing comment', r => { if (Array.isArray(r.data)) r.data = []; }, /incomplete_comments/],
  ['duplicate comment', r => { if (Array.isArray(r.data)) r.data = [r.data[0], r.data[0]]; }, /comment_order/],
  ['foreign comment', r => { if (Array.isArray(r.data)) r.data[0].issue_url += '1'; }, /comment_scope/],
  ['pull request', r => { if (r.data?.number) r.data.pull_request = {}; }, /pull_request_not_supported/],
  ['foreign repository', r => { if (r.data?.full_name) r.data.full_name = 'other/project'; }, /repository_substitution/],
  ['wrong selected issue', r => { if (r.data?.number) r.data.number++; }, /issue_scope/],
  ['native title overflow', r => { if (r.data?.number) r.data.title = 'é'.repeat(129); }, /invalid_title/],
  ['native body overflow after attribution', r => { if (r.data?.number) r.data.body = 'x'.repeat(65536); }, /body|form/i],
]) test(`source capture refuses ${name} instead of producing a partial usable import`, async () => {
  await assert.rejects(capture({}, peer({ issue: n => ({ ...base(n), comments: 1 }), comments: n => [comment(n, 1)], modify })), code);
});

test('edited comment between passes refuses even when issue updated_at stays unchanged', async () => {
  let reads = 0;
  const p = peer({ issue: n => ({ ...base(n), comments: 1 }), comments: n => [{ ...comment(n, 1), body: ++reads === 1 ? 'before' : 'after' }] });
  await assert.rejects(capture({}, p), /source_changed/);
});

test('repository rename/recreation is not hidden by the same path', async () => {
  let count = 0;
  await assert.rejects(capture({}, peer({ modify: r => { if (r.data?.full_name) r.data.id = ++count; } })), /source_changed/);
});

for (const href of ['https://evil.invalid/steal?per_page=100&page=2',
  'https://api.github.com/repos/other/project/issues/3/comments?per_page=100&page=2',
  'https://api.github.com/repos/owner/project/issues/3/comments?per_page=100&page=1',
  'https://api.github.com/repos/owner/project/issues/3/comments?per_page=100&page=2&token=extra']) {
  test(`pagination refuses unsafe or non-progressing continuation ${href}`, async () => {
    const p = peer({ issue: n => ({ ...base(n), comments: 101 }), comments: n => Array.from({ length: 101 }, (_, i) => comment(n, i + 1)),
      modify: r => { if (r.headers.Link) r.headers.Link = `<${href}>; rel="next"`; } });
    await assert.rejects(capture({ token: 'private_source_token' }, p), /pagination/);
    assert.equal(p.calls.length, 3);
  });
}

test('rate-limit refusal exposes only status and bounded retry delay, without retrying', async () => {
  const p = peer({ modify: r => { r.status = 429; r.data = { message: 'SECRET SOURCE TOKEN' }; r.headers['Retry-After'] = '60'; } });
  await assert.rejects(capture({}, p), e => e.status === 429 && e.retry_after_seconds === '60' && !e.message.includes('SECRET'));
  assert.equal(p.calls.length, 1);
});

test('aggregate read budget has an exact inclusive boundary', async () => {
  const first = await capture();
  assert.equal((await capture({ maxReadBytes: first.read_bytes })).read_bytes, first.read_bytes);
  await assert.rejects(capture({ maxReadBytes: first.read_bytes - 1 }), /read_bytes/);
});

test('full-width numeric aliases survive wire parsing without rounding', async () => {
  const p = peer();
  const result = await capture({ fetchImpl: async (...args) => {
    const r = await p.fetchImpl(...args), body = (await r.text()).replace('"id":42', '"id":18446744073709551615');
    return new Response(body, { headers: r.headers });
  } });
  assert.equal(result.capture.source.repository_id, '18446744073709551615');
});

test('fractional or exponent-encoded GitHub identities cannot round into accepted integers', async () => {
  for (const numeric of ['9007199254740991.1', '1e3', '18446744073709551616']) {
    await assert.rejects(capture({ fetchImpl: async () => new Response(`{"id":${numeric},"full_name":"owner/project"}`,
      { headers: { 'Content-Type': 'application/json' } }) }), /identity|numeric/);
  }
});

test('source cancellation and whole-operation deadline also interrupt delayed body reads', async () => {
  let cancelled = 0;
  await assert.rejects(capture({ timeoutMs: 20, fetchImpl: async () => new Response(new ReadableStream({
    start(c) { c.enqueue(Buffer.from('{')); }, cancel() { cancelled++; },
  }), { headers: { 'Content-Type': 'application/json' } }) }));
  assert.equal(cancelled, 1);
  const stop = new AbortController(); stop.abort(); const p = peer();
  await assert.rejects(capture({ signal: stop.signal }, p)); assert.equal(p.calls.length, 0);
});

test('package validation rejects hidden data, altered ordering, unsafe target overflow and truncation', async () => {
  const { capture: source, bytes } = await capture();
  assert.throws(() => captureBytes({ ...source, approval: true }), /noncanonical/);
  assert.throws(() => parseCapture(bytes.subarray(0, bytes.length - 2)));
  assert.throws(() => issueImportSteps(source, Number.MAX_SAFE_INTEGER), /target issue/);
  assert.throws(() => captureBytes({ ...source, issues: [{ ...source.issues[0], id: '01' }] }), /identity/);
});

test('deleted source users and empty source bodies remain attributed without invented actors', async () => {
  const { capture: source } = await capture({}, peer({ issue: n => ({ ...base(n), user: null, body: null }) }));
  assert.equal(source.issues[0].user, null); assert.equal(source.issues[0].body, null);
  assert.match(issueImportSteps(source)[0].fields.body, /"source_author":null/);
});

test('actual command inspects a private package without network or mutation credentials', async t => {
  const root = await mkdtemp(join(tmpdir(), 'fg-github-capture-')); t.after(() => rm(root, { recursive: true, force: true }));
  const { bytes } = await capture(), path = join(root, 'capture.json'); await writeFile(path, bytes, { mode: 0o600 });
  const script = new URL('../../scripts/import_github_issues.mjs', import.meta.url);
  const result = spawnSync(process.execPath, [script.pathname, 'inspect', '--capture', path, '--offset', '100'], { encoding: 'utf8' });
  assert.equal(result.status, 0, result.stderr);
  const out = JSON.parse(result.stdout); assert.equal(out.mutation_submitted, false); assert.equal(out.steps[0].number, 103);
  assert.throws(() => importArguments(['capture', '--repository', repository, '--issue', '01', '--out', path]));
  assert.throws(() => importArguments(['inspect', '--capture', path, '--token-file', path]));
});
