// Synthetic GitHub INPUT only. This peer supplies no native response/authority.
// Destination commands run separately against the actual Rust node.
import { writeFile, readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { inventoryPeer } from '../../../tests/operator/github-pull-inventory-fixture.mjs';
import { discoverGithubPulls } from '../../lib/github-pull-inventory.mjs';
import { prepareGithubPullCollection, collectGithubPulls } from '../../lib/github-pull-collection.mjs';
import { batchName } from '../../lib/github-pull-collection-store.mjs';
import { parseGithubPullCapture } from '../../lib/github-pull-source.mjs';
import { recordDigest } from '../../lib/forge-operator-io.mjs';

if (process.argv.length !== 5 || process.argv.slice(3).some(s => !/^[0-9a-f]{40}$/.test(s))) {
  throw new Error('private source directory and two SHA-1 fixture tips required');
}
const [root, head, base] = process.argv.slice(2), numbers = [9, 17];
const peer = await inventoryPeer({ after() {} }, { pulls: numbers, records: 1, alter: ({ kind, n, value }) => {
  if (kind === 'pull') {
    value.head.sha = head; value.base.sha = base;
    value.title += ' 雪';
    if (n === 17) { value.state = 'closed'; value.closed_at = value.updated_at; }
  } else if (kind === 'reviews' || kind === 'inline') {
    for (const row of value) { row.commit_id = head; if (kind === 'inline') row.original_commit_id = base; }
  }
} });
try {
  const inventory = await discoverGithubPulls({ ...peer.options, batchSize: 1 });
  const inventoryFile = join(root, 'inventory.json');
  await writeFile(inventoryFile, inventory.bytes, { mode: 0o600, flag: 'wx' });
  const collectionDir = join(root, 'collection');
  const prepared = await prepareGithubPullCollection({ workdir: collectionDir, inventoryFile, inventoryConfirm: inventory.sha256 });
  const collected = await collectGithubPulls({ workdir: collectionDir, confirm: prepared.plan_sha256, fetchImpl: peer.fetchImpl });
  if (!collected.complete || collected.captured_batches !== 2) throw new Error('synthetic source collection incomplete');
  const captures = await Promise.all(numbers.map(async (_, index) => {
    const path = join(collectionDir, 'captures', batchName(index)), bytes = await readFile(path);
    return { path, sha256: recordDigest(bytes), capture: parseGithubPullCapture(bytes) };
  }));
  console.log(JSON.stringify({ source_class: 'synthetic-github-input-only', collection_dir: collectionDir,
    collection_confirm: prepared.plan_sha256, complete_confirm: collected.complete_sha256,
    single_capture: captures[0].path, single_capture_sha256: captures[0].sha256,
    pulls: captures.flatMap(item => item.capture.pulls), source_requests: peer.calls.length }));
} finally { await peer.close(); }
