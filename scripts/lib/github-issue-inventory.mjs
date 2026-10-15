// FG-049: bounded, read-only repository discovery. GitHub aliases and membership
// are source data, never local principals, publication authority or a snapshot proof.
import { createGithubSource, githubIdentity, githubRepository, GITHUB_API } from './github-source-http.mjs';
import { operatorError, recordDigest } from './forge-operator-io.mjs';

export const INVENTORY_SCHEMA = 'frankengit-github-issue-inventory-v1';
export const INVENTORY_LIMIT = 1024 * 1024;
export const INVENTORY_RECORD_LIMIT = 10000;
const CONSISTENCY = 'two-equal-observations-not-atomic';
const QUERY = Object.freeze({ state: 'all', sort: 'created', direction: 'asc', per_page: '100' });
const fail = code => { throw operatorError(`github_inventory_${code}`); };
const encode = value => Buffer.from(JSON.stringify(value) + '\n');
function integer(value, minimum, maximum, name) {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) fail(name);
  return value;
}
function object(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) fail('object');
  return value;
}
function keys(value, names) {
  object(value);
  if (Object.keys(value).length !== names.length || names.some(name => !Object.hasOwn(value, name))) fail('fields');
}
function identity(row, pull = false) {
  keys(row, ['number', pull ? 'issue_id' : 'id']);
  const number = integer(row.number, 1, Number.MAX_SAFE_INTEGER, 'number');
  const id = githubIdentity(pull ? row.issue_id : row.id);
  return pull ? { number, issue_id: id } : { number, id };
}

// The canonical record deliberately contains no issue bodies or credentials.
// The batch size is identity material: pagination/restarts cannot repartition it.
export function issueInventoryBytes(value) {
  keys(value, ['schema', 'consistency', 'source', 'batch_size', 'issues', 'excluded_pull_requests', 'complete']);
  keys(value.source, ['repository', 'repository_id']);
  if (value.schema !== INVENTORY_SCHEMA || value.consistency !== CONSISTENCY || value.complete !== true ||
      !Array.isArray(value.issues) || !Array.isArray(value.excluded_pull_requests)) fail('schema');
  if (value.issues.length + value.excluded_pull_requests.length > INVENTORY_RECORD_LIMIT) fail('record_limit');
  const ids = new Set(), numbers = new Set();
  function rows(input, pull) {
    let previous = 0;
    return input.map(raw => {
      const row = identity(raw, pull), id = pull ? row.issue_id : row.id;
      if (row.number <= previous || numbers.has(row.number) || ids.has(id)) fail('duplicate_or_order');
      previous = row.number; numbers.add(row.number); ids.add(id); return row;
    });
  }
  const checked = { schema: INVENTORY_SCHEMA, consistency: CONSISTENCY,
    source: { repository: githubRepository(value.source.repository), repository_id: githubIdentity(value.source.repository_id) },
    batch_size: integer(value.batch_size, 1, 100, 'batch_size'),
    issues: rows(value.issues, false), excluded_pull_requests: rows(value.excluded_pull_requests, true), complete: true };
  const bytes = encode(checked);
  if (bytes.length > INVENTORY_LIMIT) fail('bytes');
  if (!encode(value).equals(bytes)) fail('noncanonical');
  return bytes;
}
export function parseIssueInventory(input) {
  if (!(input instanceof Uint8Array) || input.buffer instanceof SharedArrayBuffer || !input.length || input.length > INVENTORY_LIMIT) fail('bytes');
  const bytes = Buffer.from(input);
  const value = JSON.parse(new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes));
  if (!issueInventoryBytes(value).equals(bytes)) fail('noncanonical');
  return value;
}
export function selectIssueInventoryBatch(value, expectedSha256, batch) {
  if (typeof expectedSha256 !== 'string' || !/^[0-9a-f]{64}$/.test(expectedSha256)) fail('pin');
  const bytes = issueInventoryBytes(value);
  if (recordDigest(bytes) !== expectedSha256) fail('pin_mismatch');
  // Own the complete selection before the caller can do asynchronous work.
  const inventory = parseIssueInventory(bytes), total = Math.ceil(inventory.issues.length / inventory.batch_size);
  integer(batch, 1, total, 'batch');
  const issues = inventory.issues.slice((batch - 1) * inventory.batch_size, batch * inventory.batch_size);
  return { inventory_sha256: expectedSha256, batch, total_batches: total,
    next_batch: batch < total ? batch + 1 : null, source: inventory.source, issues,
    numbers: issues.map(row => row.number), excluded_pull_requests: inventory.excluded_pull_requests.length };
}
function query(page) { return new URLSearchParams({ ...QUERY, page: String(page) }).toString(); }
function continuation(header, repository, repositoryId, page) {
  if (header === null || header === '') return false;
  if (typeof header !== 'string' || header.length > 8192) fail('pagination');
  let next = false;
  for (const part of header.split(',')) {
    const match = /^\s*<([^<>]+)>;\s*rel="(next|prev|first|last)"\s*$/.exec(part);
    if (!match) fail('pagination');
    if (match[2] !== 'next') continue;
    if (next) fail('pagination');
    let url;
    try { url = new URL(match[1]); } catch { fail('pagination'); }
    const paths = [`/repos/${repository}/issues`, `/repositories/${repositoryId}/issues`];
    if (url.origin !== GITHUB_API || url.username || url.password || url.hash || !paths.includes(url.pathname) ||
        [...url.searchParams.keys()].length !== 5 || url.searchParams.get('page') !== String(page + 1) ||
        Object.entries(QUERY).some(([key, value]) => url.searchParams.get(key) !== value)) fail('pagination_scope');
    next = true;
  }
  return next;
}
function listed(raw, repository) {
  object(raw);
  const number = integer(raw.number, 1, Number.MAX_SAFE_INTEGER, 'number'), id = githubIdentity(raw.id);
  if (!['open', 'closed'].includes(raw.state)) fail('state');
  const pull = Object.hasOwn(raw, 'pull_request');
  if (raw.url !== `${GITHUB_API}/repos/${repository}/issues/${number}` ||
      raw.html_url !== `https://github.com/${repository}/${pull ? 'pull' : 'issues'}/${number}`) fail('issue_scope');
  if (pull && object(raw.pull_request).url !== `${GITHUB_API}/repos/${repository}/pulls/${number}`) fail('pull_scope');
  return { number, id, pull };
}

export async function discoverGithubIssues({ repository, batchSize = 100, maxRecords = INVENTORY_RECORD_LIMIT,
  token = null, signal, timeoutMs = 300000, maxReadBytes = 64 * 1024 * 1024, maxSourceRetries = 0,
  fetchImpl = globalThis.fetch } = {}) {
  githubRepository(repository); integer(batchSize, 1, 100, 'batch_size');
  integer(maxRecords, 1, INVENTORY_RECORD_LIMIT, 'record_limit');
  const source = createGithubSource({ token, signal, timeoutMs, maxReadBytes, maxSourceRetries, fetchImpl });
  const { get, check } = source;
  async function repositoryIdentity() {
    const raw = object((await get(`/repos/${repository}`)).value);
    const name = githubRepository(raw.full_name);
    if (name.toLowerCase() !== repository.toLowerCase()) fail('repository_substitution');
    return { repository: name, repository_id: githubIdentity(raw.id) };
  }
  async function pass() {
    const selected = await repositoryIdentity(), issues = [], pulls = [], ids = new Set(), numbers = new Set();
    // Even short pages with next links cannot turn the record bound into an
    // unbounded request allowance. An exact-full final page gets one empty probe.
    for (let page = 1; ; page++) {
      check(); if (page > INVENTORY_RECORD_LIMIT / 100 + 1) fail('page_limit');
      const reply = await get(`/repos/${selected.repository}/issues?${query(page)}`);
      if (!Array.isArray(reply.value) || reply.value.length > 100) fail('page');
      for (const raw of reply.value) {
        check();
        if (ids.size === maxRecords) fail('record_limit');
        const row = listed(raw, selected.repository);
        if (ids.has(row.id) || numbers.has(row.number)) fail('duplicate_or_order');
        ids.add(row.id); numbers.add(row.number);
        if (row.pull) pulls.push({ number: row.number, issue_id: row.id });
        else issues.push({ number: row.number, id: row.id });
      }
      const next = continuation(reply.link, selected.repository, selected.repository_id, page);
      if (next && !reply.value.length) fail('empty_continuation');
      if (!next && reply.value.length < 100) break;
      // Construct our own URL. Never follow an opaque server-selected target.
    }
    check();
    if (JSON.stringify(await repositoryIdentity()) !== JSON.stringify(selected)) fail('repository_changed');
    // Transfers and tied creation times need not have increasing issue numbers.
    // Canonicalize the population, never rely on undocumented page tie-breaks.
    issues.sort((a, b) => a.number - b.number); pulls.sort((a, b) => a.number - b.number);
    return { schema: INVENTORY_SCHEMA, consistency: CONSISTENCY, source: selected,
      batch_size: batchSize, issues, excluded_pull_requests: pulls, complete: true };
  }
  try {
    const first = await pass(), bytes = issueInventoryBytes(first);
    const second = issueInventoryBytes(await pass()); check();
    if (!bytes.equals(second)) fail('source_changed');
    return { inventory: first, bytes, sha256: recordDigest(bytes), total_batches: Math.ceil(first.issues.length / batchSize),
      ...source.statistics() };
  } finally { source.close(); }
}
