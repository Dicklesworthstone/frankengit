// GitHub response-schema fixture only. No real GitHub or native server is invoked.
import assert from 'node:assert/strict';
export const repository = 'owner/project';
const time = '2026-10-01T10:00:00Z', user = { id: 11, login: 'source-author' };
export function issue(number, commentCount = 2) {
  const state = number % 2 ? 'open' : 'closed';
  return { id: String(100000 + number), number, url: `https://api.github.com/repos/${repository}/issues/${number}`,
    html_url: `https://github.com/${repository}/issues/${number}`, title: `Issue ${number}`,
    body: 'Source bytes\r\n%26 <script>not executable</script>', state, state_reason: state === 'open' ? null : 'completed',
    user, created_at: time, updated_at: time, closed_at: state === 'open' ? null : time,
    labels: [{ id: '1', name: 'bug', color: 'AbCdEf', description: 'Source label' }], assignees: [user],
    milestone: { id: '2', number: 1, title: 'Release', state: 'open' }, locked: false, comments: commentCount };
}
export function comment(number, ordinal) {
  const id = String(number * 10000 + ordinal + 1);
  return { id, user, body: `Source comment ${ordinal}\n`, created_at: time, updated_at: time,
    html_url: `https://github.com/${repository}/issues/${number}#issuecomment-${id}`,
    issue_url: `https://api.github.com/repos/${repository}/issues/${number}` };
}
export function makePeer({ count = 251, pullEvery = 7, commentCount = 2, repositoryId = '42',
  modify = () => {}, onRequest = () => {} } = {}) {
  const calls = []; let repoReads = 0;
  const rows = Array.from({ length: count }, (_, index) => {
    const number = index + 1, row = issue(number, commentCount);
    if (pullEvery && number % pullEvery === 0) {
      row.html_url = `https://github.com/${repository}/pull/${number}`;
      row.pull_request = { url: `https://api.github.com/repos/${repository}/pulls/${number}` };
    }
    return row;
  });
  const fetchImpl = async (input, init) => {
    const url = new URL(input);
    assert.equal(url.origin, 'https://api.github.com'); assert.equal(init.method, 'GET');
    assert.equal(init.body, undefined); assert.equal(init.redirect, 'error'); assert.equal(init.credentials, 'omit');
    const request = { url, init, repoReads, index: calls.length }; calls.push(request);
    await onRequest(request);
    const headers = { 'Content-Type': 'application/json' }; let value, kind;
    if (url.pathname === `/repos/${repository}`) { kind = 'repository'; repoReads++; value = { id: repositoryId, full_name: repository }; }
    else if (url.pathname === `/repos/${repository}/issues`) {
      kind = 'inventory'; const page = Number(url.searchParams.get('page'));
      assert.equal(url.searchParams.get('state'), 'all');
      assert.equal(url.searchParams.get('sort'), 'created'); assert.equal(url.searchParams.get('direction'), 'asc');
      assert.equal(url.searchParams.get('per_page'), '100');
      value = rows.slice((page - 1) * 100, page * 100);
      if (page * 100 < rows.length) headers.Link = `<https://api.github.com/repositories/${repositoryId}/issues?state=all&sort=created&direction=asc&per_page=100&page=${page + 1}>; rel="next"`;
    } else {
      const match = /^\/repos\/owner\/project\/issues\/([1-9][0-9]*)(\/comments)?$/.exec(url.pathname);
      assert.ok(match, `unexpected read ${url}`); const number = Number(match[1]);
      const selected = rows.find(row => row.number === number); assert.ok(selected, 'selected issue exists');
      if (match[2]) {
        kind = 'comments'; const page = Number(url.searchParams.get('page'));
        value = Array.from({ length: commentCount }, (_, i) => comment(number, i)).slice((page - 1) * 100, page * 100);
        if (page * 100 < commentCount) headers.Link = `<https://api.github.com/repositories/${repositoryId}/issues/${number}/comments?per_page=100&page=${page + 1}>; rel="next"`;
      } else { kind = 'issue'; value = selected; }
    }
    const reply = { value: structuredClone(value), headers, status: 200, url, kind, repoReads, request };
    await modify(reply);
    return new Response(JSON.stringify(reply.value), { status: reply.status, headers: reply.headers });
  };
  return { fetchImpl, calls, rows };
}
