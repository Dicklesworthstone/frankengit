// Read-only HTTP contract tests. These execute the production reader with
// controlled GitHub responses; they are not live-GitHub or native-forge E2E proof.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createGithubSource, githubRetryDelay, githubIdentity, githubRepository,
  API_VERSION, SOURCE_RETRY_LIMIT } from '../../scripts/lib/github-source-http.mjs';

const path = '/repos/owner/project';
const json = (body = '{"id":42}', headers = {}) => new Response(body, { headers: { 'Content-Type': 'application/json', ...headers } });
const limited = (status = 429, headers = {}) => new Response('SECRET ERROR BODY', { status, headers: { 'Retry-After': '0', ...headers } });
async function run(options, fn) {
  const source = createGithubSource(options);
  try { return await fn(source); } finally { source.close(); }
}

test('read lifetime preserves method, destination, version, honest UA and credential isolation', async () => {
  await run({ token: 'github_pat_private', fetchImpl: async (url, request) => {
    assert.equal(url, `https://api.github.com${path}`);
    assert.equal(request.method, 'GET'); assert.equal(request.body, undefined);
    assert.equal(request.redirect, 'error'); assert.equal(request.credentials, 'omit');
    assert.equal(request.headers.Authorization, 'Bearer github_pat_private');
    assert.equal(request.headers['X-GitHub-Api-Version'], API_VERSION);
    assert.match(request.headers['User-Agent'], /^frankengit-issue-import /);
    return json();
  } }, async source => {
    assert.deepEqual((await source.get(path)).value, { id: '42' });
    assert.deepEqual(source.statistics(), { requests: 1, read_bytes: 9, source_retries: 0 });
    assert.equal(JSON.stringify(source.statistics()).includes('private'), false);
  });
});

test('default still refuses a rate limit once with no response-body disclosure', async () => {
  let calls = 0;
  await run({ fetchImpl: async () => { calls++; return limited(429, { 'Retry-After': '60' }); } }, async source => {
    await assert.rejects(source.get(path), e => e.code === 'github_import_source_http' && e.status === 429 &&
      e.retry_after_seconds === '60' && !JSON.stringify(e).includes('SECRET'));
    assert.equal(calls, 1); assert.equal(source.statistics().source_retries, 0);
  });
});

for (const status of [429, 502, 503, 504, 403]) test(`opted-in HTTP ${status} retry completes the same read`, async () => {
  let calls = 0;
  await run({ maxSourceRetries: 1, fetchImpl: async () => ++calls === 1 ? limited(status) : json() }, async source => {
    assert.equal((await source.get(path)).value.id, '42');
    assert.deepEqual(source.statistics(), { requests: 2, read_bytes: 9, source_retries: 1 });
  });
});

for (const status of [400, 401, 403, 404, 422, 500]) test(`HTTP ${status} without a retryable contract never becomes a retry`, async () => {
  let calls = 0;
  await run({ maxSourceRetries: 10, fetchImpl: async () => { calls++; return new Response('', { status }); } }, async source => {
    await assert.rejects(source.get(path), e => e.status === status); assert.equal(calls, 1);
  });
});

test('the retry allowance is global to the whole source lifetime, not reset for each URL', async () => {
  let calls = 0;
  await run({ maxSourceRetries: 1, fetchImpl: async () => ++calls === 2 ? json() : limited() }, async source => {
    await source.get(path);
    await assert.rejects(source.get(`${path}/issues/1`), e => e.status === 429);
    assert.equal(calls, 3); assert.equal(source.statistics().source_retries, 1);
  });
});

test('perpetual throttling stops after exactly the admitted retry count', async () => {
  await run({ maxSourceRetries: 2, fetchImpl: async () => limited() }, async source => {
    await assert.rejects(source.get(path), e => e.status === 429);
    assert.deepEqual(source.statistics(), { requests: 3, read_bytes: 0, source_retries: 2 });
  });
});

test('server delays are honored, not clamped down to the remaining operation budget', async () => {
  let calls = 0;
  await run({ timeoutMs: 1000, maxSourceRetries: 10,
    fetchImpl: async () => { calls++; return limited(429, { 'Retry-After': '3600' }); } }, async source => {
    await assert.rejects(source.get(path), e => e.status === 429 && e.retry_after_seconds === '3600');
    assert.equal(calls, 1); assert.equal(source.statistics().source_retries, 0);
  });
});

test('cancellation interrupts backoff and cannot cause another request', async () => {
  const stop = new AbortController(); let calls = 0;
  await run({ signal: stop.signal, timeoutMs: 5000, maxSourceRetries: 1, fetchImpl: async () => {
    calls++; setTimeout(() => stop.abort(), 15); return limited(429, { 'Retry-After': '1' });
  } }, async source => {
    await assert.rejects(source.get(path), e => e.name === 'AbortError'); assert.equal(calls, 1);
  });
});

test('failed response custody is drained before the retry begins', async () => {
  let calls = 0, cancelled = false;
  await run({ maxSourceRetries: 1, fetchImpl: async () => {
    if (++calls === 2) { assert.equal(cancelled, true); return json(); }
    return new Response(new ReadableStream({ async cancel() {
      await new Promise(resolve => setTimeout(resolve, 10)); cancelled = true;
    } }), { status: 503, headers: { 'Retry-After': '0' } });
  } }, async source => { await source.get(path); assert.equal(calls, 2); });
});

test('a failed cleanup refuses instead of starting an overlapping retry', async () => {
  let calls = 0;
  await run({ maxSourceRetries: 1, fetchImpl: async () => {
    calls++; return new Response(new ReadableStream({ cancel() { throw new Error('SECRET'); } }),
      { status: 429, headers: { 'Retry-After': '0' } });
  } }, async source => {
    await assert.rejects(source.get(path), e => e.code === 'github_import_source_cleanup'); assert.equal(calls, 1);
  });
});

test('the total deadline cancels a pending response body and drains it', async () => {
  let cancelled = 0;
  await run({ timeoutMs: 20, maxSourceRetries: 1, fetchImpl: async () => new Response(new ReadableStream({
    start(controller) { controller.enqueue(Buffer.from('{')); }, cancel() { cancelled++; },
  }), { headers: { 'Content-Type': 'application/json' } }) }, async source => {
    await assert.rejects(source.get(path), e => e.name === 'AbortError');
    assert.equal(cancelled, 1); assert.equal(source.statistics().requests, 1);
  });
});

test('GitHub reset epochs, secondary fallback and transient backoff retain lower bounds', () => {
  const h = values => new Headers(values), now = 100000;
  assert.equal(githubRetryDelay(429, h({}), 0, now), 60000);
  assert.equal(githubRetryDelay(429, h({}), 2, now), 240000);
  assert.equal(githubRetryDelay(503, h({}), 2, now), 4000);
  assert.equal(githubRetryDelay(403, h({ 'X-RateLimit-Remaining': '0', 'X-RateLimit-Reset': '120' }), 0, now), 21000);
  assert.equal(githubRetryDelay(429, h({ 'Retry-After': '30', 'X-RateLimit-Remaining': '0', 'X-RateLimit-Reset': '120' }), 0, now), 30000);
  assert.equal(githubRetryDelay(403, h({ 'X-RateLimit-Remaining': '0', 'X-RateLimit-Reset': '100' }), 0, now), 1000);
  assert.equal(githubRetryDelay(403, h({ 'X-RateLimit-Remaining': '0' }), 0, now), null);
  for (const value of ['-1', '1.5', '1e2', 'secret', '99999999999']) {
    assert.equal(githubRetryDelay(429, h({ 'Retry-After': value }), 0, now), null);
  }
});

test('malformed retry headers cannot be bypassed by opting into retries', async () => {
  let calls = 0;
  await run({ maxSourceRetries: 10, fetchImpl: async () => { calls++; return limited(429, { 'Retry-After': 'secret' }); } }, async source => {
    await assert.rejects(source.get(path), e => e.status === 429 && e.retry_after_seconds === undefined);
    assert.equal(calls, 1);
  });
});

test('JSON decode, media and identity failures are never retried', async () => {
  for (const reply of [() => json('{'), () => json('{"id":1e3}'), () => json('{"number":1.1}'),
    () => json('{"id":18446744073709551616}'), () => new Response('{}'),
    () => json(new Uint8Array([0xff]))]) {
    let calls = 0;
    await run({ maxSourceRetries: 10, fetchImpl: async () => { calls++; return reply(); } }, async source => {
      await assert.rejects(source.get(path)); assert.equal(calls, 1);
    });
  }
});

test('full-width identity survives JSON parsing, while unsafe non-ID integers refuse', async () => {
  await run({ fetchImpl: async () => json('{"id":18446744073709551615,"number":9007199254740991}') }, async source => {
    assert.deepEqual((await source.get(path)).value, { id: '18446744073709551615', number: Number.MAX_SAFE_INTEGER });
  });
  await run({ fetchImpl: async () => json('{"number":9007199254740992}') }, source => assert.rejects(source.get(path), /numeric_wire_value/));
});

test('aggregate read bytes remain an exact inclusive budget across calls', async () => {
  await run({ maxReadBytes: 18, fetchImpl: async () => json() }, async source => {
    await source.get(path); await source.get(path); assert.equal(source.statistics().read_bytes, 18);
    await assert.rejects(source.get(path), /read_bytes/);
  });
  await run({ maxReadBytes: 8, fetchImpl: async () => json() }, source => assert.rejects(source.get(path), /read_bytes/));
});

test('redirected replies and normalized or foreign request paths refuse before disclosure', async () => {
  for (const unsafe of ['https://evil.invalid/', '//evil.invalid/', '/repos/owner/../project',
    '/repos/owner/project#token', '/repos/owner\\project', '/repos/owner/project\n']) {
    let calls = 0;
    await run({ fetchImpl: async () => { calls++; return json(); } }, async source => {
      await assert.rejects(source.get(unsafe), /source_path/); assert.equal(calls, 0);
    });
  }
  for (const changes of [{ redirected: true }, { url: 'https://evil.invalid/' }]) {
    await run({ maxSourceRetries: 1, fetchImpl: async () => {
      const response = json(); for (const [key, value] of Object.entries(changes)) Object.defineProperty(response, key, { value });
      return response;
    } }, source => assert.rejects(source.get(path), /redirect/));
  }
});

test('closed and pre-cancelled lifetimes admit no reads', async () => {
  let calls = 0;
  const source = createGithubSource({ fetchImpl: async () => { calls++; return json(); } }); source.close();
  await assert.rejects(source.get(path)); assert.equal(calls, 0);
  const stop = new AbortController(); stop.abort();
  await run({ signal: stop.signal, fetchImpl: async () => { calls++; return json(); } }, s => assert.rejects(s.get(path)));
  assert.equal(calls, 0);
});

test('one source lifetime admits only one owned in-flight request', async () => {
  let finish;
  await run({ fetchImpl: () => new Promise(resolve => { finish = resolve; }) }, async source => {
    const first = source.get(path);
    await assert.rejects(source.get(path), /concurrent_source_read/);
    finish(json()); await first; assert.equal(source.statistics().requests, 1);
  });
});

test('source option and alias validation refuses unsupported bounds', () => {
  for (const options of [{ maxSourceRetries: -1 }, { maxSourceRetries: SOURCE_RETRY_LIMIT + 1 },
    { maxSourceRetries: 0.5 }, { timeoutMs: 0 }, { timeoutMs: 300001 }, { maxReadBytes: 0 },
    { token: 'a\nsecret' }, { signal: {} }, { fetchImpl: null }]) assert.throws(() => createGithubSource(options));
  assert.equal(githubRepository('owner/project'), 'owner/project');
  assert.equal(githubIdentity('18446744073709551615'), '18446744073709551615');
  for (const value of ['01', 0, -1, Number.MAX_SAFE_INTEGER + 1]) assert.throws(() => githubIdentity(value));
  for (const value of ['owner/..', '../repo', 'owner/repo?token=secret']) assert.throws(() => githubRepository(value));
});
