// Contract doubles, not live-node interoperability evidence. The double
// enforces the one WebIDL rule a plain function stub never does: fetch refuses
// any receiver but the global. Every client stored the platform fetch and
// called it as a method of itself, which Chrome rejects with "Illegal
// invocation" before any request leaves the page; the real-browser suite
// scripts/e2e/suites/forge/browser_markdown_csp.sh found it.
import test from 'node:test';
import assert from 'node:assert/strict';
import { webcrypto } from 'node:crypto';
import { IssueClient } from '../../crates/fgit-node/src/smart_http/server/browser/issues.mjs';
import { Transport } from '../../crates/fgit-node/src/smart_http/server/browser/pulls-core.mjs';
import { HistoryClient } from '../../crates/fgit-node/src/smart_http/server/browser/history.mjs';

const token = 'c'.repeat(64);

function platformFetch() {
  const calls = [];
  const fetchImpl = function (url) {
    if (this !== undefined && this !== globalThis) {
      throw new TypeError("Failed to execute 'fetch' on 'Window': Illegal invocation");
    }
    calls.push(String(url));
    return Promise.resolve(new Response('{"code":"unavailable"}', { status: 503, headers: { 'Content-Type': 'application/json' } }));
  };
  return { fetchImpl, calls };
}

async function refusalOf(operation) {
  try { await operation(); } catch (error) { return error; }
  return null;
}

const clients = [
  ['IssueClient', async fetchImpl => {
    const client = new IssueClient({ href: 'http://127.0.0.1:9/repo.git/ui/issues/', fetchImpl, cryptoImpl: webcrypto });
    await client.connect(token);
    return client.read();
  }],
  ['Transport (pulls, source, search, branches, tags, transfers, replay, rebase, initial)', async fetchImpl => {
    const client = new Transport({ href: 'http://127.0.0.1:9/repo.git/ui/pulls/', fetchImpl, cryptoImpl: webcrypto });
    await client.connect(token);
    return client.request('pulls');
  }],
  ['HistoryClient', async fetchImpl => {
    const client = new HistoryClient({ href: 'http://127.0.0.1:9/repo.git/ui/history/', fetchImpl, cryptoImpl: webcrypto });
    client.connect(token);
    return client.open('refs/heads/main', 'sha1');
  }],
];

for (const [name, exercise] of clients) {
  test(`${name} invokes the platform fetch as a plain call`, async () => {
    const platform = platformFetch();
    const error = await refusalOf(() => exercise(platform.fetchImpl));
    assert.equal(platform.calls.length, 1, `the request must reach fetch; got ${error}`);
    assert.doesNotMatch(String(error), /Illegal invocation/);
  });
}

test('the receiver-checking double itself refuses a method call', () => {
  const platform = platformFetch();
  const holder = { fetch: platform.fetchImpl };
  assert.throws(() => holder.fetch('http://127.0.0.1:9/'), /Illegal invocation/);
  assert.equal(platform.calls.length, 0);
});
