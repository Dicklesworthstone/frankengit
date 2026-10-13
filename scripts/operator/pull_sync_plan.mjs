// Snapshot-bound tip refresh, NOT source synchronization, merge, or review reuse.
import { createHash, randomBytes } from 'node:crypto';
import { outcomeEndpoint, outcomeScope } from './transaction_outcome.mjs';
import { exactKeys, fail, syncRequest, tokenValue } from './pull_sync_transport.mjs';
import { integer, listReply, showReply, pinned, reference, oid, branch, metadataCommand, hex, utf8, opaque, snapshot }
  from '../../crates/fgit-node/src/smart_http/server/browser/pulls-core.mjs';

export const LIMITS = Object.freeze({ pulls: 4096, changes: 128, pages: 256, metadata: 16 * 1024 * 1024, plan: 20 * 1024 * 1024 });
export const encode = value => Buffer.from(`${JSON.stringify(value)}\n`);
export const hash = bytes => createHash('sha256').update(bytes).digest('hex');
export function destination(value) {
  exactKeys(value, ['endpoint', 'tenant_id', 'repository_id', 'repository_incarnation', 'object_format', 'principal_id']);
  const { endpoint, object_format, ...scope } = value;
  if (!['sha1', 'sha256'].includes(object_format)) fail('invalid_sync_object_format');
  return Object.freeze({ endpoint: outcomeEndpoint(endpoint), ...outcomeScope(scope), object_format });
}
function browserScope(dest) {
  return { tenant: dest.tenant_id, repository: dest.repository_id, incarnation: dest.repository_incarnation, format: dest.object_format };
}
export function selection(value) {
  if (value === 'all-open') return value;
  if (!Array.isArray(value) || !value.length || value.length > LIMITS.changes) fail('select_pr_numbers_or_all_open');
  const out = value.map(number => integer(number, 'PR number', 1)).sort((a, b) => a - b);
  if (new Set(out).size !== out.length) fail('duplicate_selected_pr');
  return out;
}
export function operationContext(options = {}) {
  if (!options || typeof options !== 'object' || Array.isArray(options)) fail('invalid_sync_options');
  options = { ...options };
  if (Object.keys(options).some(key => !['signal', 'timeoutMs', 'ca'].includes(key))) fail('invalid_sync_options');
  if (options.signal !== undefined && !(options.signal instanceof AbortSignal)) fail('invalid_sync_signal');
  const deadline = performance.now() + integer(options.timeoutMs ?? 120000, 'sync operation timeout', 1, 300000);
  const ca = options.ca === undefined ? undefined : Buffer.isBuffer(options.ca) && options.ca.length && options.ca.length <= 128 * 1024
    ? Buffer.from(options.ca) : fail('invalid_sync_ca');
  return { signal: options.signal, ca, remaining() {
    options.signal?.throwIfAborted();
    const remaining = Math.floor(deadline - performance.now());
    if (remaining < 1) fail('sync_operation_timeout');
    return Math.min(remaining, 30000);
  } };
}
function priorFields(row, format) {
  const data = row.data;
  if (data.source_ref === null || data.target_ref === null) fail('sync_byte_only_ref_requires_native_client');
  return metadataCommand('update', { expected_version: row.version, object_format: format,
    source_ref: data.source_ref, target_ref: data.target_ref, source_tip: oid(data.source_tip, format), target_tip: oid(data.target_tip, format),
    title: data.title, body: data.body });
}
function refsPage(reply, dest, head, sourceHead, after) {
  pinned(reply, browserScope(dest), head);
  if (reply.type !== 'source_refs' || reply.namespace !== 'branches' || reply.source_head !== sourceHead || reply.after !== after || reply.limit !== 50 ||
      reply.read_only !== true || reply.transaction_created !== false || reply.published !== false || reply.direct_refs_only !== true ||
      !Array.isArray(reply.refs) || reply.refs.length > 50) fail('invalid_sync_reference_page');
  let previous = after === null ? '' : hex(utf8.encode(after));
  for (const row of reply.refs) {
    exactKeys(row, ['ref', 'ref_hex', 'object_id']); reference(row, 'ref'); oid(row.object_id, dest.object_format);
    // Byte-only unrelated names are data, not a reason to replace the cursor.
    if (!row.ref_hex.startsWith('726566732f68656164732f') || row.ref_hex <= previous) fail('invalid_sync_ref_order');
    previous = row.ref_hex;
  }
  if (reply.next_after !== null && (branch(reply.next_after) === null || reply.refs.length !== 50 ||
      hex(utf8.encode(reply.next_after)) !== previous)) fail('invalid_sync_ref_continuation');
  return reply;
}
export async function discover(dest, token, selected, options = {}) {
  dest = destination(dest); tokenValue(token); selected = selection(selected);
  const cx = operationContext(options), rows = [], scope = browserScope(dest);
  let head = null, sourceHead = null, pages = 0, totalBytes = 0, scanned = 0;
  const request = async operation => {
    if (++pages > LIMITS.pages) fail('sync_discovery_page_limit');
    const reply = await syncRequest(dest.endpoint, token, operation, { signal: cx.signal, ca: cx.ca, timeoutMs: cx.remaining() });
    totalBytes += reply.bytes; if (totalBytes > LIMITS.metadata) fail('sync_discovery_byte_limit');
    cx.remaining(); return reply;
  };
  const observe = page => {
    if (sourceHead !== null && sourceHead !== page.reply.source_head) fail('sync_source_head_changed');
    head = page.head; sourceHead = page.reply.source_head;
  };
  if (selected === 'all-open') {
    let after = 0;
    do {
      const raw = await request({ kind: 'pulls', after, head });
      const page = listReply(raw.value, { after, limit: 50, head, scope }); observe(page);
      scanned += page.reply.pull_requests.length;
      if (scanned > LIMITS.pulls) fail('sync_pull_inventory_limit');
      rows.push(...page.reply.pull_requests.filter(row => row.state === 'open'));
      if (rows.length > LIMITS.changes) fail('sync_open_pr_limit');
      after = page.reply.next_after;
    } while (after !== null);
  } else {
    for (const number of selected) {
      const raw = await request({ kind: 'show', number, head });
      const page = showReply(raw.value, number, { head, scope }); observe(page);
      if (!page.reply.found || raw.status !== 200 || page.reply.pull_request.state !== 'open') fail('selected_sync_pr_not_open');
      rows.push(page.reply.pull_request); scanned++;
    }
  }
  const before = rows.map(row => ({ number: row.number, fields: priorFields(row, dest.object_format) }));
  const needed = new Set(before.flatMap(row => [row.fields.source_ref, row.fields.target_ref])), tips = new Map();
  let after = null;
  while (needed.size > tips.size) {
    const raw = await request({ kind: 'refs', after, head, format: dest.object_format });
    const page = refsPage(raw.value, dest, head, sourceHead, after);
    for (const row of page.refs) if (needed.has(row.ref)) tips.set(row.ref, oid(row.object_id, dest.object_format));
    after = page.next_after;
    if (after === null) break;
  }
  if (needed.size !== tips.size) fail('sync_branch_unavailable_no_changes_prepared');
  const changes = [], unchanged = [];
  for (const row of before) {
    const fields = metadataCommand('update', { ...row.fields, source_tip: tips.get(row.fields.source_ref), target_tip: tips.get(row.fields.target_ref) });
    if (fields.source_tip === row.fields.source_tip && fields.target_tip === row.fields.target_tip) unchanged.push(row.number);
    else changes.push({ number: row.number, before: row.fields, fields });
  }
  cx.remaining();
  return { schema: 'frankengit-pr-sync-discovery-v1', destination: dest, selected, snapshot_token: head, source_head: sourceHead,
    scanned, unchanged, changes, read_only: true, approvals_carried_forward: false };
}
function checkedDiscovery(value) {
  exactKeys(value, ['schema', 'destination', 'selected', 'snapshot_token', 'source_head', 'scanned', 'unchanged', 'changes', 'read_only', 'approvals_carried_forward']);
  if (value.schema !== 'frankengit-pr-sync-discovery-v1' || value.read_only !== true || value.approvals_carried_forward !== false) fail('invalid_sync_discovery');
  const dest = destination(value.destination), selected = selection(value.selected);
  snapshot(value.snapshot_token); opaque(value.source_head); integer(value.scanned, 'scanned PRs', 0, LIMITS.pulls);
  if (!Array.isArray(value.unchanged) || !Array.isArray(value.changes) || value.changes.length + value.unchanged.length > LIMITS.changes) fail('sync_change_limit');
  const seen = new Set();
  const choose = number => {
    integer(number, 'PR number', 1);
    if (seen.has(number) || (selected !== 'all-open' && !selected.includes(number))) fail('sync_selection_changed');
    seen.add(number);
  };
  let prior = 0;
  const unchanged = value.unchanged.map(number => { choose(number); if (number <= prior) fail('sync_pr_order'); prior = number; return number; });
  prior = 0;
  const changes = value.changes.map(row => {
    exactKeys(row, ['number', 'before', 'fields']); choose(row.number);
    if (row.number <= prior) fail('sync_pr_order'); prior = row.number;
    const before = metadataCommand('update', row.before), fields = metadataCommand('update', row.fields);
    if (fields.object_format !== dest.object_format || Object.keys(before).some(key => !['source_tip', 'target_tip'].includes(key) && before[key] !== fields[key]) ||
        (before.source_tip === fields.source_tip && before.target_tip === fields.target_tip)) fail('sync_may_only_refresh_changed_tips');
    return { number: row.number, before, fields };
  });
  if (seen.size > value.scanned || (selected !== 'all-open' && (seen.size !== selected.length || value.scanned !== seen.size))) fail('sync_selection_incomplete');
  return { ...value, destination: dest, selected, unchanged, changes };
}
export function freezePlan(discovery, token, nonce = randomBytes(16).toString('hex')) {
  const checked = checkedDiscovery(discovery); tokenValue(token);
  if (typeof nonce !== 'string' || !/^[0-9a-f]{32}$/.test(nonce)) fail('invalid_sync_nonce');
  const base = { schema: 'frankengit-pr-sync-plan-v1', discovery: checked, credential_sha256: hash(token), nonce };
  const basis = hash(encode(base));
  const requests = checked.changes.map(row => ({ number: row.number, fields: row.fields,
    key: `fgsync1-${nonce}-${hash(encode([basis, row.number, row.fields]))}` }));
  const plan = { ...base, requests };
  if (encode(plan).length > LIMITS.plan) fail('sync_plan_byte_limit');
  return { ...plan, plan_sha256: hash(encode(plan)) };
}
export function validatePlan(value) {
  exactKeys(value, ['schema', 'discovery', 'credential_sha256', 'nonce', 'requests', 'plan_sha256']);
  if (value.schema !== 'frankengit-pr-sync-plan-v1' || typeof value.credential_sha256 !== 'string' || typeof value.nonce !== 'string' || !/^[0-9a-f]{64}$/.test(value.credential_sha256) ||
      !/^[0-9a-f]{32}$/.test(value.nonce) || !Array.isArray(value.requests) || value.requests.length !== value.discovery.changes.length) fail('invalid_sync_plan');
  const base = { schema: value.schema, discovery: checkedDiscovery(value.discovery), credential_sha256: value.credential_sha256, nonce: value.nonce };
  const basis = hash(encode(base));
  const requests = base.discovery.changes.map(row => ({ number: row.number, fields: row.fields,
    key: `fgsync1-${value.nonce}-${hash(encode([basis, row.number, row.fields]))}` }));
  const normalized = { ...base, requests };
  if (hash(encode(normalized)) !== value.plan_sha256 || !encode({ ...normalized, plan_sha256: value.plan_sha256 }).equals(encode(value)) ||
      encode(value).length > LIMITS.plan) fail('sync_plan_integrity_mismatch');
  return structuredClone(value);
}
