// Exact capture files and a local native-schema peer are test inputs, not GitHub
// snapshots, a running Rust fg server, or proof of repository publication.
// All names, credentials and identities in this helper are synthetic fixtures.
import { mkdtemp, writeFile, readFile, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { captureBytes } from '../../scripts/lib/github-issue-source.mjs';
import { issueInventoryBytes } from '../../scripts/lib/github-issue-inventory.mjs';
import { recordDigest } from '../../scripts/lib/forge-operator-io.mjs';
import { prepareGithubIssueMigration, inspectGithubIssueMigration } from '../../scripts/lib/github-issue-migration.mjs';

export const tenant = 'a'.repeat(32), repository = 'b'.repeat(32), token = 'c'.repeat(64);
export const source = { repository: 'owner/project', repository_id: '18446744073709551615' };
export const encode = value => Buffer.from(JSON.stringify(value) + '\n');
export const batchDir = (root, n) => join(root, `batch-${String(n).padStart(6, '0')}`);
export const requestFile = (root, n, i = 0) => join(batchDir(root, n), `step-${String(i).padStart(6, '0')}.request.json`);
export async function change(path, mutate) {
  const value = JSON.parse(await readFile(path, 'utf8')); mutate(value);
  const bytes = encode(value); await writeFile(path, bytes); return recordDigest(bytes);
}
function issue(number, comments) {
  const time = '2026-10-01T10:00:00Z', user = { id: '11', login: 'source-author' };
  return { number, id: String(18446744073709551000n + BigInt(number)),
    html_url: `https://github.com/owner/project/issues/${number}`, title: `Issue ${number}`, body: 'Original body\r\n%26=+ é',
    state: number % 2 ? 'closed' : 'open', state_reason: number % 2 ? 'completed' : null,
    user, created_at: time, updated_at: time, closed_at: number % 2 ? time : null,
    labels: [{ id: '12', name: 'bug', color: 'abcdef', description: null }], assignees: [], milestone: null,
    locked: false, comment_count: comments, comments: Array.from({ length: comments }, (_, i) => ({
      id: String(number * 100 + i), html_url: `https://github.com/owner/project/issues/${number}#issuecomment-${number * 100 + i}`,
      issue_url: `https://api.github.com/repos/owner/project/issues/${number}`, user, created_at: time, updated_at: time,
      body: `Comment ${number}/${i}\r\nopaque comment text` })) };
}
export async function fixture(t, { batches = 3, batchSize = 2, comments = 1, href = 'http://127.0.0.1:1/repo.git/ui/issues/' } = {}) {
  const dir = await mkdtemp(join(tmpdir(), 'fg-migration-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const inventoryFile = join(dir, 'inventory.json'), tokenFile = join(dir, 'native-token'), workdir = join(dir, 'migration');
  await writeFile(tokenFile, token, { mode: 0o600 });
  const issues = Array.from({ length: batches * batchSize }, (_, i) => issue(i + 1, comments));
  const inventory = { schema: 'frankengit-github-issue-inventory-v1', consistency: 'two-equal-observations-not-atomic',
    source: { ...source }, batch_size: batchSize, issues: issues.map(({ number, id }) => ({ number, id })),
    excluded_pull_requests: [{ number: 999999, issue_id: '999' }], complete: true };
  const inventoryBytes = issueInventoryBytes(inventory); await writeFile(inventoryFile, inventoryBytes, { mode: 0o600 });
  const captures = [];
  for (let i = 0; i < batches; i++) {
    const capture = { schema: 'frankengit-github-issue-capture-v1', consistency: 'two-equal-observations-not-atomic',
      source: { ...source }, issues: issues.slice(i * batchSize, (i + 1) * batchSize) };
    const bytes = captureBytes(capture), path = join(dir, `capture-${i + 1}.json`);
    await writeFile(path, bytes, { mode: 0o600 }); captures.push({ batch: i + 1, path, sha256: recordDigest(bytes) });
  }
  const common = { workdir, href, tenant, repository, tokenFile };
  const options = { ...common, inventoryFile, inventorySha256: recordDigest(inventoryBytes), captures, offset: 100 };
  return { dir, common, options, inventory, captures, workdir, tokenFile,
    prepare: extra => prepareGithubIssueMigration({ ...options, ...extra }),
    inspect: (confirm, extra) => inspectGithubIssueMigration({ ...common, confirm, ...extra }) };
}
