// FG-049: discovery and batch capture feed the existing native import format.
// Nothing here imports native publication code, creates retry keys, or writes to
// GitHub. Inventory pins constrain source selection, not repository authority.
import { discoverGithubIssues, parseIssueInventory, selectIssueInventoryBatch,
  INVENTORY_LIMIT, INVENTORY_RECORD_LIMIT } from './github-issue-inventory.mjs';
import { captureGithubIssues } from './github-issue-source.mjs';
import { githubRepository } from './github-source-http.mjs';
import { operatorError, operatorJson, operatorPath, privateRecordPath, absentRecord,
  readPrivateOperatorFile, saveOperatorRecord, recordDigest } from './forge-operator-io.mjs';

export const INVENTORY_OPERATIONS = Object.freeze(['discover', 'inspect-inventory', 'capture-batch']);
export const INVENTORY_HELP = `Usage: node scripts/import_github_issues.mjs discover
  --repository OWNER/REPO --out NEW_PRIVATE_INVENTORY
  [--batch-size 1..100] [--max-records 1..10000]
  [--token-file PRIVATE_GITHUB_TOKEN] [--timeout-ms 1..300000]
  [--max-read-bytes 1..268435456] [--source-retries 0..10]

Usage: node scripts/import_github_issues.mjs inspect-inventory
  --inventory PRIVATE_FILE --confirm ORIGINAL_INVENTORY_SHA256 [--batch NUMBER]

Usage: node scripts/import_github_issues.mjs capture-batch
  --inventory PRIVATE_FILE --confirm ORIGINAL_INVENTORY_SHA256 --batch NUMBER
  --out NEW_PRIVATE_CAPTURE [--token-file PRIVATE_GITHUB_TOKEN]
  [--timeout-ms 1..300000] [--max-read-bytes 1..268435456] [--source-retries 0..10]

Discover enumerates both issue states and reports pull requests as exclusions.
Keep its SHA-256 independently. The pinned batch size and membership cannot be
changed on capture or retry. Batches are one-based; empty/all-PR inventories have
zero batches. Capture-batch verifies the original repository and issue aliases
before reading comments in each pass. It emits the unchanged capture format for
inspect/prepare/run/status. It does not submit or acknowledge native mutations.
No automatic batching/shrinking occurs when a capture exceeds existing limits.
Inventory membership and each capture are separate two-observation reads, NOT
one atomic migration snapshot. Quiesce source edits. This does not import PRs,
reviews, attachments, source credentials or native source-author permissions.
Once prepare creates native requests, retain that capture and work directory;
never rediscover or recapture to resolve an uncertain native publication.
`;
const fail = code => { throw operatorError(`github_inventory_${code}`); };
function decimal(value, minimum, maximum, name) {
  if (typeof value !== 'string' || !/^(0|[1-9][0-9]*)$/.test(value)) fail(name);
  const n = Number(value);
  if (!Number.isSafeInteger(n) || n < minimum || n > maximum) fail(name);
  return n;
}
const READ_FLAGS = ['--token-file', '--timeout-ms', '--max-read-bytes', '--source-retries'];
export function inventoryArguments(args) {
  if (!Array.isArray(args) || args.length > 31 || args.some(v => typeof v !== 'string' ||
      v.length > 4096 || Buffer.byteLength(v) > 4096 || /[\0\r\n\uD800-\uDFFF]/u.test(v))) fail('arguments');
  const operation = args[0], values = new Map();
  const allowed = operation === 'discover' ? ['--repository', '--out', '--batch-size', '--max-records', ...READ_FLAGS]
    : operation === 'inspect-inventory' ? ['--inventory', '--confirm', '--batch']
    : operation === 'capture-batch' ? ['--inventory', '--confirm', '--batch', '--out', ...READ_FLAGS] : [];
  if (!allowed.length) fail('operation');
  for (let i = 1; i < args.length; i += 2) {
    const flag = args[i], value = args[i + 1];
    if (!allowed.includes(flag) || !value || value.startsWith('--') || values.has(flag)) fail('option');
    values.set(flag, value);
  }
  const required = operation === 'discover' ? ['--repository', '--out'] : operation === 'inspect-inventory'
    ? ['--inventory', '--confirm'] : ['--inventory', '--confirm', '--batch', '--out'];
  if (required.some(flag => !values.has(flag))) fail('required_option');
  if (values.has('--repository')) githubRepository(values.get('--repository'));
  if (values.has('--confirm') && !/^[0-9a-f]{64}$/.test(values.get('--confirm'))) fail('pin');
  for (const [flag, low, high] of [['--batch-size', 1, 100], ['--max-records', 1, INVENTORY_RECORD_LIMIT],
    ['--batch', 1, INVENTORY_RECORD_LIMIT], ['--timeout-ms', 1, 300000], ['--max-read-bytes', 1, 268435456], ['--source-retries', 0, 10]]) {
    if (values.has(flag)) decimal(values.get(flag), low, high, flag.slice(2));
  }
  // Normalize every path before any I/O. Existing private-file readers also
  // enforce descriptor type/owner/alias checks when opening those paths.
  for (const flag of ['--inventory', '--out', '--token-file']) {
    if (values.has(flag)) values.set(flag, operatorPath(values.get(flag)));
  }
  if (values.has('--out') && ['--inventory', '--token-file'].some(flag => values.get(flag) === values.get('--out'))) fail('separate_output');
  return { operation, values, issues: [] };
}

export async function captureGithubIssueBatch({ inventory, expectedSha256, batch, token = null, signal,
  timeoutMs = 300000, maxReadBytes = 64 * 1024 * 1024, maxSourceRetries = 0, fetchImpl = globalThis.fetch } = {}) {
  // Synchronous verification and ownership precede the first network await.
  const selection = selectIssueInventoryBatch(inventory, expectedSha256, batch);
  const result = await captureGithubIssues({ repository: selection.source.repository, numbers: selection.numbers,
    expectedSelection: { source: selection.source, issues: selection.issues },
    token, signal, timeoutMs, maxReadBytes, maxSourceRetries, fetchImpl });
  return { ...result, selection };
}

export async function runGithubInventoryCommand(args, signal) {
  const { operation, values } = inventoryArguments(args);
  const number = (flag, fallback) => Number(values.get(flag) ?? fallback);
  const timeoutMs = number('--timeout-ms', 300000), deadline = performance.now() + timeoutMs;
  const stop = new AbortController(), combined = signal ? AbortSignal.any([signal, stop.signal]) : stop.signal;
  const timer = setTimeout(() => stop.abort(), timeoutMs);
  const check = () => { if (performance.now() >= deadline) stop.abort(); combined.throwIfAborted(); };
  let tokenBytes;
  try {
    check();
    let inventory, selection;
    if (operation !== 'discover') {
      const bytes = await readPrivateOperatorFile(values.get('--inventory'), INVENTORY_LIMIT, check);
      inventory = parseIssueInventory(bytes);
      if (recordDigest(bytes) !== values.get('--confirm')) fail('pin_mismatch');
      if (values.has('--batch')) selection = selectIssueInventoryBatch(inventory, values.get('--confirm'), number('--batch'));
      if (operation === 'inspect-inventory') {
        check(); return { text: operatorJson({ type: 'github_issue_inventory_inspection',
          inventory_sha256: values.get('--confirm'), total_batches: Math.ceil(inventory.issues.length / inventory.batch_size),
          ...(selection ? { selection } : { inventory }), atomic_source_snapshot: false, mutation_submitted: false }), exitCode: 0 };
      }
    }
    const out = await privateRecordPath(values.get('--out')); await absentRecord(out); check();
    if (['--inventory', '--token-file'].some(flag => values.get(flag) === out)) fail('separate_output');
    let token = null;
    if (values.has('--token-file')) {
      tokenBytes = await readPrivateOperatorFile(values.get('--token-file'), 256, check);
      token = new TextDecoder('utf-8', { fatal: true }).decode(tokenBytes).replace(/\n$/, '');
    }
    check();
    const options = { token, signal: combined, timeoutMs: Math.max(1, Math.floor(deadline - performance.now())),
      maxReadBytes: number('--max-read-bytes', 64 * 1024 * 1024), maxSourceRetries: number('--source-retries', 0) };
    const result = operation === 'discover'
      ? await discoverGithubIssues({ ...options, repository: values.get('--repository'),
        batchSize: number('--batch-size', 100), maxRecords: number('--max-records', INVENTORY_RECORD_LIMIT) })
      : await captureGithubIssueBatch({ ...options, inventory, expectedSha256: values.get('--confirm'), batch: selection.batch });
    check(); const saved = await saveOperatorRecord(out, result.bytes, check);
    const common = { path: saved.path, sha256: saved.sha256, requests: result.requests,
      read_bytes: result.read_bytes, source_retries: result.source_retries,
      atomic_source_snapshot: false, mutation_submitted: false };
    if (operation === 'discover') return { text: operatorJson({ type: 'github_issue_inventory', ...common,
      source: result.inventory.source, issues: result.inventory.issues.length,
      excluded_pull_requests: result.inventory.excluded_pull_requests.length,
      batch_size: result.inventory.batch_size, total_batches: result.total_batches }), exitCode: 0 };
    return { text: operatorJson({ type: 'github_issue_capture', ...common,
      source: result.capture.source, issues: result.capture.issues.length,
      comments: result.capture.issues.reduce((n, issue) => n + issue.comments.length, 0),
      selection: result.selection }), exitCode: 0 };
  } finally { tokenBytes?.fill(0); clearTimeout(timer); stop.abort(); }
}
