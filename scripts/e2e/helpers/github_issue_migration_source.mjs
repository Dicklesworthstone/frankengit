// Synthetic source INPUTS only. No GitHub network or native response peer runs.
// The shared fixture supplies GitHub responses to the production capture parser;
// destination execution is performed separately by the real Rust node.
import { writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { sourceCapture } from '../../../tests/operator/github-import-fixtures.mjs';
import { captureBytes } from '../../lib/github-issue-source.mjs';
import { issueInventoryBytes } from '../../lib/github-issue-inventory.mjs';
import { recordDigest } from '../../lib/forge-operator-io.mjs';

if (process.argv.length !== 3) throw new Error('one private output directory required');
const root = process.argv[2], capture = (await sourceCapture()).capture;
for (const issue of capture.issues) {
  issue.title += ' 雪';
  issue.body += '<script>source data only</script> 🦀';
}
const combined = join(root, 'combined.json');
await writeFile(combined, captureBytes(capture), { mode: 0o600, flag: 'wx' });
const captures = [];
for (const [index, issue] of capture.issues.entries()) {
  const bytes = captureBytes({ ...capture, issues: [issue] });
  const path = join(root, `capture-${index + 1}.json`);
  await writeFile(path, bytes, { mode: 0o600, flag: 'wx' });
  captures.push({ batch: index + 1, path, sha256: recordDigest(bytes) });
}
const inventory = join(root, 'inventory.json');
const bytes = issueInventoryBytes({ schema: 'frankengit-github-issue-inventory-v1',
  consistency: 'two-equal-observations-not-atomic', source: capture.source,
  batch_size: 1, issues: capture.issues.map(({ number, id }) => ({ number, id })),
  excluded_pull_requests: [], complete: true });
await writeFile(inventory, bytes, { mode: 0o600, flag: 'wx' });
const selection = Buffer.from(JSON.stringify({ schema: 'frankengit-github-issue-migration-sources-v1',
  inventory: { path: inventory, sha256: recordDigest(bytes) }, captures, offset: 1000 }) + '\n');
const sources = join(root, 'sources.json');
await writeFile(sources, selection, { mode: 0o600, flag: 'wx' });
console.log(JSON.stringify({ sources, sources_sha256: recordDigest(selection), combined,
  issues: capture.issues.map(({ number, title, body, comments, state }) => ({ number, title, body, state,
    comments: comments.map(comment => comment.body) })) }));
