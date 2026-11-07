// Explicit synthetic GitHub source peer, used only by the native migration lane.
// The preload is passed only to source commands; native HTTP uses stock fetch.
import { writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { issueInventoryBytes, INVENTORY_SCHEMA } from '../../lib/github-issue-inventory.mjs';
import { recordDigest } from '../../lib/forge-operator-io.mjs';
import { repository, repositoryId, issue, comment } from '../../../tests/operator/fixtures/github_capture_source.mjs';

if (process.argv.length !== 3) throw new Error('one private output directory required');
const root = process.argv[2], numbers = [1, 2];
const inventory = join(root, 'inventory.json'), preload = join(root, 'source-peer.mjs');
const log = join(root, 'source-requests.ndjson');
const bytes = issueInventoryBytes({ schema: INVENTORY_SCHEMA,
  consistency: 'two-equal-observations-not-atomic', source: { repository, repository_id: repositoryId },
  batch_size: 1, issues: numbers.map(number => ({ number, id: issue(number).id })),
  excluded_pull_requests: [], complete: true });
// This is a reference pin, not an output inventory. The actual discovery CLI
// must create that file from the source observations below.
const fixture = new URL('../../../tests/operator/fixtures/github_capture_source.mjs', import.meta.url).href;
await writeFile(preload, `import assert from 'node:assert/strict';
import { githubPeer, json } from ${JSON.stringify(fixture)};
import { appendFile } from 'node:fs/promises';
globalThis.fetch = githubPeer({ before: async ({ address }) => {
  await appendFile(${JSON.stringify(log)}, JSON.stringify({ address }) + '\\n', { mode: 0o600 });
  const url = new URL(address);
  if (url.pathname === ${JSON.stringify(`/repos/${repository}/issues`)}) {
    assert.deepEqual([...url.searchParams], [['state','all'],['sort','created'],['direction','asc'],['per_page','100'],['page','1']]);
    return json(${JSON.stringify(numbers.map(number => ({ ...issue(number),
      url: `https://api.github.com/repos/${repository}/issues/${number}` })))});
  }
} }).fetchImpl;
`, { mode: 0o600, flag: 'wx' });
console.log(JSON.stringify({ inventory, expected_inventory_sha256: recordDigest(bytes), preload, log, repository,
  issues: numbers.map(number => ({ ...issue(number), comment_body: comment(number).body })) }));
