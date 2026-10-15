// Explicit GitHub response-schema peer. This is not a live GitHub service.
import assert from 'node:assert/strict';
export const repository = 'Source/Project';
export const repositoryId = '18446744073709551615';
export const issueId = n => String(9007199254740993n + BigInt(n));
const date = '2026-10-01T00:00:00Z';
export function issue(n, count = 1) {
  return { number: n, id: issueId(n), html_url: `https://github.com/${repository}/issues/${n}`,
    title: `Issue ${n}`, body: 'Original body ~~~ ``` α', state: n % 2 ? 'open' : 'closed',
    state_reason: n % 2 ? null : 'completed', user: { id: '9007199254740993', login: 'source-author' },
    created_at: date, updated_at: date, closed_at: n % 2 ? null : date,
    labels: [{ id: '27', name: 'feature', color: 'aAbB00', description: null }],
    assignees: [], milestone: null, locked: false, comments: count };
}
export function comment(n, index = 0, duplicate = false) {
  const id = String(10000000000000000n + BigInt(duplicate ? index : n * 1000 + index));
  return { id, html_url: `https://github.com/${repository}/issues/${n}#issuecomment-${id}`,
    issue_url: `https://api.github.com/repos/${repository}/issues/${n}`, user: null,
    created_at: date, updated_at: date, body: `Comment ${index} from ${n}` };
}
export function json(value, headers = {}) {
  // Exercise numeric aliases wider than Number.MAX_SAFE_INTEGER on the wire.
  const body = JSON.stringify(value).replace(/"id":"([0-9]+)"/g, '"id":$1');
  return new Response(body, { headers: { 'Content-Type': 'application/json', ...headers } });
}
export function githubPeer({ comments = 1, duplicate = false, before = async () => null } = {}) {
  const calls = [];
  const fetchImpl = async (address, init) => {
    assert.equal(init.method, 'GET'); assert.equal(init.redirect, 'error'); assert.equal(init.credentials, 'omit');
    const url = new URL(address); assert.equal(url.origin, 'https://api.github.com');
    assert.equal(init.headers['X-GitHub-Api-Version'], '2026-03-10');
    const path = url.pathname, request = { address, path, init, ordinal: calls.length + 1 }; calls.push(request);
    const override = await before(request);
    let response = override;
    if (!response) {
      if (path === `/repos/${repository}`) response = json({ id: repositoryId, full_name: repository });
      else {
        const match = new RegExp(`^/repos/${repository}/issues/([1-9][0-9]*)(/comments)?$`).exec(path);
        assert.ok(match, `unexpected path ${path}`); const n = Number(match[1]);
        if (!match[2]) response = json(issue(n, comments));
        else {
          const page = Number(url.searchParams.get('page')); assert.equal(url.searchParams.get('per_page'), '100');
          const first = (page - 1) * 100, length = Math.max(0, Math.min(100, comments - first));
          response = json(Array.from({ length }, (_, i) => comment(n, first + i, duplicate)),
            first + length < comments ? { Link: `<https://api.github.com/repositories/${repositoryId}/issues/${n}/comments?per_page=100&page=${page + 1}>; rel="next"` } : {});
        }
      }
    }
    return response;
  };
  return { calls, fetchImpl };
}
