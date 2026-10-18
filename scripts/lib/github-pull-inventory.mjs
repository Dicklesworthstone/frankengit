// FG-049: repository-wide membership selection over the existing GitHub reader.
// Imported IDs are aliases. Two equal observations are not an atomic snapshot.
import { isDeepStrictEqual } from 'node:util';
import { createGithubSource, githubIdentity, githubRepository, GITHUB_API } from './github-source-http.mjs';
import { captureGithubPulls, pullSourceFields as fields, pullSourceNumber as integer,
  encodeGithubPulls as encode, githubPullFail as fail } from './github-pull-source.mjs';
import { recordDigest } from './forge-operator-io.mjs';

export const GITHUB_PULL_INVENTORY_SCHEMA = 'frankengit-github-pull-inventory-v1';
export const GITHUB_PULL_INVENTORY_LIMITS = Object.freeze({ pulls: 10000, bytes: 1024*1024, batchSize: 100 });
const L = GITHUB_PULL_INVENTORY_LIMITS, CONSISTENCY = 'two-equal-membership-observations-not-atomic';
const QUERY = Object.freeze({ state: 'all', sort: 'created', direction: 'asc', per_page: '100' });
const pin = value => { if (typeof value !== 'string' || !/^[0-9a-f]{64}$/.test(value)) fail('inventory_pin'); return value; };

export function githubPullInventoryBytes(value) {
  fields(value, ['schema', 'consistency', 'source', 'batch_size', 'pulls', 'complete']);
  fields(value.source, ['id', 'full_name']);
  if (value.schema !== GITHUB_PULL_INVENTORY_SCHEMA || value.consistency !== CONSISTENCY ||
      value.complete !== true || !Array.isArray(value.pulls)) fail('inventory_schema');
  integer(value.pulls.length, 0, L.pulls);
  const ids = new Set(); let previous = 0;
  const result = { schema: GITHUB_PULL_INVENTORY_SCHEMA, consistency: CONSISTENCY,
    source: { id: githubIdentity(value.source.id), full_name: githubRepository(value.source.full_name) },
    batch_size: integer(value.batch_size, 1, L.batchSize), pulls: value.pulls.map(row => {
      fields(row, ['number', 'id']);
      const number = integer(row.number, 1), id = githubIdentity(row.id);
      if (number <= previous || ids.has(id)) fail('inventory_order_or_duplicate');
      previous = number; ids.add(id); return { number, id };
    }), complete: true };
  const bytes = encode(result);
  if (bytes.length > L.bytes) fail('inventory_bytes');
  if (!encode(value).equals(bytes)) fail('inventory_noncanonical');
  return bytes;
}
export function parseGithubPullInventory(input) {
  if (!(input instanceof Uint8Array) || input.buffer instanceof SharedArrayBuffer || !input.length || input.length > L.bytes) fail('inventory_bytes');
  const bytes = Buffer.from(input), value = JSON.parse(new TextDecoder('utf-8', { fatal:true, ignoreBOM:true }).decode(bytes));
  if (!githubPullInventoryBytes(value).equals(bytes)) fail('inventory_noncanonical');
  return value;
}
export function selectGithubPullBatch(value, confirm, batch) {
  pin(confirm); const bytes = githubPullInventoryBytes(value);
  if (recordDigest(bytes) !== confirm) fail('inventory_pin_mismatch');
  const inventory = parseGithubPullInventory(bytes), total = Math.ceil(inventory.pulls.length / inventory.batch_size);
  integer(batch, 1, total);
  const first = (batch-1)*inventory.batch_size, pulls = inventory.pulls.slice(first, first+inventory.batch_size);
  return { inventory_sha256:confirm, batch, total_batches:total, next_batch:batch<total?batch+1:null,
    first_index:first, source:inventory.source, pulls, numbers:pulls.map(r => r.number) };
}
function continuation(header, source, page) {
  if (header === null || header === '') return false;
  if (typeof header !== 'string' || header.length > 8192) fail('inventory_pagination');
  const seen = new Set(); let next = false;
  for (const part of header.split(',')) {
    const match = /^\s*<([^<>]+)>;\s*rel="(next|prev|first|last)"\s*$/.exec(part);
    if (!match || seen.has(match[2])) fail('inventory_pagination'); seen.add(match[2]);
    let url; try { url = new URL(match[1]); } catch { fail('inventory_pagination'); }
    const query = url.searchParams;
    if (url.origin !== GITHUB_API || url.username || url.password || url.hash ||
        ![`/repos/${source.full_name}/pulls`,`/repositories/${source.id}/pulls`].includes(url.pathname) ||
        [...query.keys()].length !== 5 || Object.entries(QUERY).some(([k,v]) => query.get(k) !== v) ||
        !/^[1-9][0-9]*$/.test(query.get('page') ?? '')) fail('inventory_pagination_scope');
    const target = integer(Number(query.get('page')), 1, L.pulls/100+1);
    if (match[2] === 'next') { if (target !== page+1) fail('inventory_pagination_sequence'); next = true; }
  }
  return next;
}
function listed(value, source) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) fail('inventory_row');
  const number = integer(value.number, 1), id = githubIdentity(value.id);
  if (!['open','closed'].includes(value.state) || typeof value.draft !== 'boolean' ||
      value.url !== `${GITHUB_API}/repos/${source.full_name}/pulls/${number}` ||
      value.html_url !== `https://github.com/${source.full_name}/pull/${number}` ||
      !value.base?.repo || githubIdentity(value.base.repo.id) !== source.id ||
      value.base.repo.full_name !== source.full_name) fail('inventory_row_scope');
  return { number, id };
}
export async function discoverGithubPulls(raw) {
  fields(raw, ['repository','batchSize','maxPulls','token','signal','timeoutMs','maxReadBytes','maxRequests','fetchImpl'], ['repository']);
  const repository = githubRepository(raw.repository), batchSize = integer(raw.batchSize ?? 25, 1, L.batchSize),
    maxPulls = integer(raw.maxPulls ?? L.pulls, 1, L.pulls);
  const source = createGithubSource({ token:raw.token??null, signal:raw.signal, timeoutMs:raw.timeoutMs??300000,
    maxReadBytes:raw.maxReadBytes??64*1024*1024, maxRequests:raw.maxRequests??4096, fetchImpl:raw.fetchImpl??globalThis.fetch });
  async function identity() {
    const { value } = await source.get(`/repos/${repository}`);
    const selected = { id:githubIdentity(value?.id), full_name:githubRepository(value?.full_name) };
    if (selected.full_name.toLowerCase() !== repository.toLowerCase()) fail('inventory_repository_changed');
    return selected;
  }
  async function observe() {
    const selected = await identity(), pulls = [], ids = new Set(), numbers = new Set();
    for (let page=1; ; page++) {
      source.check(); if (page > Math.ceil(maxPulls/100)+1) fail('inventory_page_limit');
      const query = new URLSearchParams({ ...QUERY, page:String(page) });
      const reply = await source.get(`/repos/${selected.full_name}/pulls?${query}`);
      if (!Array.isArray(reply.value) || reply.value.length > 100) fail('inventory_page');
      for (const value of reply.value) {
        source.check(); if (pulls.length === maxPulls) fail('inventory_pull_limit');
        const row = listed(value, selected);
        if (ids.has(row.id) || numbers.has(row.number)) fail('inventory_order_or_duplicate');
        ids.add(row.id); numbers.add(row.number); pulls.push(row);
      }
      const next = continuation(reply.link, selected, page);
      if (next && reply.value.length !== 100) fail('inventory_incomplete_page');
      if (!next && reply.value.length < 100) break;
      // An exact-full page without a Link is ambiguous; probe the next page.
      // Never follow a server URL, and never stop at a configured record ceiling.
    }
    if (!isDeepStrictEqual(selected, await identity())) fail('inventory_repository_changed');
    // Created-time ties need not be in numeric order. Membership is canonicalized.
    pulls.sort((a,b) => a.number-b.number);
    return { schema:GITHUB_PULL_INVENTORY_SCHEMA, consistency:CONSISTENCY, source:selected,
      batch_size:batchSize, pulls, complete:true };
  }
  try {
    const inventory = await observe(), bytes = githubPullInventoryBytes(inventory);
    const second = githubPullInventoryBytes(await observe()); source.check();
    if (!bytes.equals(second)) fail('inventory_membership_changed');
    return { inventory, bytes, sha256:recordDigest(bytes), total_batches:Math.ceil(inventory.pulls.length/batchSize),
      statistics:source.statistics(), atomic_snapshot:false, mutation_submitted:false };
  } finally { source.close(); }
}
export async function captureGithubPullBatch(raw) {
  fields(raw, ['inventory','confirm','batch','token','signal','timeoutMs','maxReadBytes','maxRequests','fetchImpl'], ['inventory','confirm','batch']);
  const selected = selectGithubPullBatch(raw.inventory, raw.confirm, raw.batch);
  const config = Object.fromEntries(['token','signal','timeoutMs','maxReadBytes','maxRequests','fetchImpl']
    .filter(k => Object.hasOwn(raw,k)).map(k => [k,raw[k]]));
  const captured = await captureGithubPulls({ ...config, repository:selected.source.full_name, numbers:selected.numbers,
    expectedSelection:{source:selected.source,pulls:selected.pulls} });
  return { ...captured, inventory_sha256:selected.inventory_sha256, batch:selected.batch,
    total_batches:selected.total_batches, next_batch:selected.next_batch, first_index:selected.first_index };
}
