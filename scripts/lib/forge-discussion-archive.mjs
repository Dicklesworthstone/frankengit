// Complete standalone-discussion observations through the shipped native API.
// Private root-last files have no mutation, restore or principal authority.
import { constants as F } from 'node:fs';
import { mkdir, open, lstat, realpath, opendir } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { DiscussionClient } from '../../crates/fgit-node/src/smart_http/server/browser/discussions.mjs';
import { natural, snapshotToken } from '../../crates/fgit-node/src/smart_http/server/browser/issues.mjs';
import { operatorError, operatorPath, privateRecordPath, absentRecord, readPrivateOperatorFile,
  saveOperatorRecord, recordDigest, parseOperatorJson } from './forge-operator-io.mjs';
import { DiscussionArchiveWalk, discussionArchiveState, discussionSourceHead }
  from './forge-discussion-archive-protocol.mjs';

export const DISCUSSION_ARCHIVE_SCHEMA = 'frankengit-discussion-read-archive-v1';
export const DISCUSSION_ARCHIVE_LIMITS = Object.freeze({ pages: 8192, discussions: 4096,
  events: 65536, bytes: 64 * 1024 * 1024, pageBytes: 1024 * 1024 });
const L = DISCUSSION_ARCHIVE_LIMITS;
const encode = value => Buffer.from(JSON.stringify(value) + '\n');
const fail = reason => { throw operatorError(`discussion_archive_${reason}`); };
const pageName = index => `page-${String(index + 1).padStart(6, '0')}.json`;
function keys(value, allowed, required = allowed) {
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
      Object.keys(value).some(k => !allowed.includes(k)) || required.some(k => !Object.hasOwn(value, k))) fail('fields');
}
function digest(value) { if (typeof value !== 'string' || !/^[0-9a-f]{64}$/.test(value)) fail('digest'); return value; }
function identifier(value) { if (typeof value !== 'string' || !/^[0-9a-f]{32}$/.test(value)) fail('identity'); return value; }
function location(href) {
  if (typeof href !== 'string' || href.length > 4096 || new URL(href).href !== href) fail('url');
  // The existing native client owns repository routes and HTTPS policy.
  new DiscussionClient({ href }); return href;
}
function canonical(bytes) {
  const value = parseOperatorJson(bytes, 'discussion_archive_json');
  if (!encode(value).equals(bytes)) fail('encoding');
  return value;
}
function lifetime(raw) {
  const timeout = natural(raw.timeoutMs ?? 300000, 'archive deadline', 1, 300000);
  if (raw.signal !== undefined && !(raw.signal instanceof AbortSignal)) fail('signal');
  const stop = new AbortController(), signal = raw.signal ? AbortSignal.any([raw.signal, stop.signal]) : stop.signal;
  const deadline = performance.now() + timeout, timer = setTimeout(() => stop.abort(), timeout);
  return { signal, timeout, check() { if (performance.now() >= deadline) stop.abort(); signal.throwIfAborted(); },
    close() { clearTimeout(timer); stop.abort(); } };
}
async function directory(path, expected = null) {
  const stat = await lstat(path, { bigint: true });
  if (typeof process.getuid !== 'function' || !stat.isDirectory() || stat.uid !== BigInt(process.getuid()) ||
      (stat.mode & 0o077n) !== 0n || await realpath(path) !== path ||
      expected && (stat.dev !== expected.dev || stat.ino !== expected.ino)) fail('directory_changed_or_unsafe');
  return stat;
}
async function syncDirectory(path) {
  const fd = await open(path, F.O_RDONLY | F.O_DIRECTORY | F.O_NOFOLLOW);
  try { await fd.sync(); } finally { await fd.close(); }
}
function manifest(value) {
  keys(value, ['schema', 'href', 'tenant_id', 'repository_id', 'snapshot_token', 'source_head',
    'page_size', 'discussion_count', 'event_count', 'data_bytes', 'pages']);
  if (value.schema !== DISCUSSION_ARCHIVE_SCHEMA) fail('schema');
  location(value.href); identifier(value.tenant_id); identifier(value.repository_id);
  snapshotToken(value.snapshot_token); discussionSourceHead(value.source_head);
  natural(value.page_size, 'archive page size', 1, 100);
  natural(value.discussion_count, 'archive discussions', 0, L.discussions);
  natural(value.event_count, 'archive events', 0, L.events);
  natural(value.data_bytes, 'archive data bytes', 1, L.bytes);
  if (!Array.isArray(value.pages)) fail('pages');
  natural(value.pages.length, 'archive pages', 1, L.pages);
  for (const row of value.pages) {
    if (!Array.isArray(row) || row.length !== 4) fail('page_descriptor');
    if (row[0] !== null) natural(row[0], 'archive discussion number', 1);
    natural(row[1], 'archive cursor'); digest(row[2]); natural(row[3], 'archive page bytes', 1, L.pageBytes);
  }
  return value;
}
async function validateFiles(root, m, life, identity, sealed, collect) {
  const names = new Set(m.pages.map((_, i) => pageName(i)));
  if (sealed) names.add('archive.json');
  for await (const entry of await opendir(root)) {
    life.check(); if (!names.delete(entry.name)) fail('unexpected_file');
  }
  if (names.size) fail('missing_file');
  const walk = new DiscussionArchiveWalk(m, m.page_size, L); let bytes = 0;
  for (const [index, row] of m.pages.entries()) {
    life.check(); await directory(root, identity);
    const raw = await readPrivateOperatorFile(join(root, pageName(index)), L.pageBytes, () => life.check());
    bytes += raw.length;
    if (raw.length !== row[3] || recordDigest(raw) !== row[2] || bytes > m.data_bytes) fail('page_commitment');
    const reply = canonical(raw);
    walk.accept({ number: row[0], after: row[1] }, reply);
    collect?.(reply);
  }
  const state = walk.state;
  if (!state.complete || state.discussions !== m.discussion_count || state.events !== m.event_count || bytes !== m.data_bytes) fail('incomplete');
  await directory(root, identity); life.check();
  return { type: 'forge_discussion_archive', schema_version: 1, archive_sha256: recordDigest(encode(m)),
    href: m.href, tenant_id: m.tenant_id, repository_id: m.repository_id, snapshot_token: m.snapshot_token,
    source_head: m.source_head, discussions: state.discussions, events: state.events, pages: m.pages.length,
    data_bytes: bytes, complete: true, canonical_backup: false, restore_authority: false, mutation_submitted: false };
}
async function readArchive(raw, includeRecords) {
  keys(raw, ['workdir', 'confirm', 'timeoutMs', 'signal'], ['workdir', 'confirm']);
  const root = operatorPath(raw.workdir), expected = digest(raw.confirm), life = lifetime(raw);
  try {
    life.check(); const identity = await directory(root);
    const bytes = await readPrivateOperatorFile(join(root, 'archive.json'), L.pageBytes, () => life.check());
    if (recordDigest(bytes) !== expected) fail('pin_mismatch');
    const m = manifest(canonical(bytes));
    if (m.data_bytes + bytes.length > L.bytes) fail('archive_limit');
    const records = [], byNumber = new Map();
    // No caller receives a prefix or can run callbacks before ALL pages pass.
    const collect = includeRecords ? reply => {
      if (reply.type === 'discussion_page') for (const row of reply.discussions) {
        const record = { snapshot: discussionArchiveState(row), events: [] };
        records.push(record); byNumber.set(row.number, record);
      } else byNumber.get(reply.discussion.number).events.push(...structuredClone(reply.events));
    } : undefined;
    const archive = { ...await validateFiles(root, m, life, identity, true, collect),
      network_accessed: false, local_read_only: true };
    return includeRecords ? { archive, records } : archive;
  } finally { life.close(); }
}
export function inspectDiscussionArchive(raw) { return readArchive(raw, false); }
export function readDiscussionArchive(raw) { return readArchive(raw, true); }

// Count bytes before the shipped client's decoder, under one whole-operation
// deadline. The client constructs these authenticated read URLs; no retry or POST.
function transport(o, life, stats) {
  return async (url, init) => {
    life.check(); if (init.method !== 'GET' || init.body !== undefined) fail('read_only');
    if (stats.requests >= o.maxRequests) fail('request_limit');
    stats.requests++;
    const signal = AbortSignal.any([life.signal, init.signal]);
    const response = await o.fetchImpl(url, { ...init, signal });
    let reader, cancellation, cleanupFailed = false;
    const cancel = () => cancellation ??= Promise.resolve().then(() => (reader ?? response.body)?.cancel())
      .catch(() => { cleanupFailed = true; });
    const abort = () => { void cancel(); };
    try {
      life.check(); signal.throwIfAborted();
      if (response.redirected || response.url && response.url !== String(url)) fail('redirect');
      if (!response.body) fail('response_body');
      reader = response.body.getReader(); signal.addEventListener('abort', abort, { once: true });
      const chunks = []; let size = 0;
      for (;;) {
        signal.throwIfAborted(); const part = await reader.read(); signal.throwIfAborted(); life.check();
        if (part.done) break;
        if (!(part.value instanceof Uint8Array)) fail('response_bytes');
        size += part.value.byteLength; stats.read_bytes += part.value.byteLength;
        if (size > L.pageBytes || stats.read_bytes > o.maxReadBytes) fail('read_limit');
        chunks.push(Buffer.from(part.value));
      }
      return new Response(Buffer.concat(chunks, size), { status: response.status, headers: response.headers });
    } finally {
      signal.removeEventListener('abort', abort); await cancel(); reader?.releaseLock();
      if (cleanupFailed) fail('body_cleanup');
    }
  };
}
export async function exportDiscussionArchive(raw) {
  keys(raw, ['workdir', 'href', 'tenant', 'repository', 'tokenFile', 'head', 'timeoutMs', 'signal',
    'maxRequests', 'maxReadBytes', 'maxArchiveBytes', 'maxDiscussions', 'maxEvents', 'pageSize', 'fetchImpl'],
  ['workdir', 'href', 'tenant', 'repository', 'tokenFile']);
  const o = { ...raw, href: location(raw.href), workdir: operatorPath(raw.workdir), tokenFile: operatorPath(raw.tokenFile),
    tenant: identifier(raw.tenant), repository: identifier(raw.repository), head: raw.head ?? null,
    maxRequests: natural(raw.maxRequests ?? L.pages, 'request budget', 1, L.pages),
    maxReadBytes: natural(raw.maxReadBytes ?? L.bytes, 'read byte budget', 1, L.bytes),
    maxArchiveBytes: natural(raw.maxArchiveBytes ?? L.bytes, 'archive byte budget', 1, L.bytes),
    maxDiscussions: natural(raw.maxDiscussions ?? L.discussions, 'discussion budget', 1, L.discussions),
    maxEvents: natural(raw.maxEvents ?? L.events, 'event budget', 1, L.events),
    pageSize: natural(raw.pageSize ?? 10, 'page size', 1, 100), fetchImpl: raw.fetchImpl ?? globalThis.fetch };
  if (o.head !== null) snapshotToken(o.head);
  if (typeof o.fetchImpl !== 'function') fail('fetch');
  const life = lifetime(o), stats = { requests: 0, read_bytes: 0 };
  let created = false, rootAttempt = false, rootDigest = null;
  const client = new DiscussionClient({ href: o.href, timeoutMs: life.timeout, fetchImpl: transport(o, life, stats) });
  try {
    life.check();
    if (await privateRecordPath(o.workdir) !== o.workdir) fail('path_alias');
    await absentRecord(o.workdir);
    const tokenPath = await realpath(o.tokenFile);
    if (tokenPath === o.workdir || tokenPath.startsWith(o.workdir + '/')) fail('token_inside_archive');
    const token = await readPrivateOperatorFile(o.tokenFile, 65, () => life.check());
    try {
      if (token.some(b => b > 127) || !/^[0-9a-f]{64}\n?$/.test(token.toString('ascii'))) fail('token');
      await client.connect(token.toString('ascii').replace(/\n$/, ''));
    } finally { token.fill(0); }
    life.check(); await mkdir(o.workdir, { mode: 0o700 }); created = true;
    await syncDirectory(dirname(o.workdir)); const identity = await directory(o.workdir);
    const walk = new DiscussionArchiveWalk({ tenant_id: o.tenant, repository_id: o.repository,
      snapshot_token: o.head, source_head: null }, o.pageSize, { discussions: o.maxDiscussions, events: o.maxEvents });
    const pages = []; let dataBytes = 0;
    while (walk.next !== null) {
      life.check(); await directory(o.workdir, identity);
      const request = walk.next;
      const value = await client.read(request.number, { after: request.after, limit: o.pageSize,
        head: walk.state.head, render: false });
      life.check(); walk.accept(request, value.reply);
      const bytes = encode(value.reply); dataBytes += bytes.length;
      if (bytes.length > L.pageBytes || dataBytes > o.maxArchiveBytes) fail('archive_limit');
      await directory(o.workdir, identity);
      const saved = await saveOperatorRecord(join(o.workdir, pageName(pages.length)), bytes, () => life.check());
      pages.push([request.number, request.after, saved.sha256, bytes.length]);
    }
    const state = walk.state;
    const m = manifest({ schema: DISCUSSION_ARCHIVE_SCHEMA, href: o.href, tenant_id: o.tenant,
      repository_id: o.repository, snapshot_token: state.head, source_head: state.source,
      page_size: o.pageSize, discussion_count: state.discussions, event_count: state.events, data_bytes: dataBytes, pages });
    const bytes = encode(m); rootDigest = recordDigest(bytes);
    if (bytes.length > L.pageBytes || dataBytes + bytes.length > o.maxArchiveBytes) fail('archive_limit');
    const result = await validateFiles(o.workdir, m, life, identity, false);
    life.check(); rootAttempt = true;
    await saveOperatorRecord(join(o.workdir, 'archive.json'), bytes, () => life.check());
    return { ...result, workdir: o.workdir, ...stats, network_accessed: stats.requests > 0, local_read_only: false };
  } catch (error) {
    error.archive_progress = { workdir: o.workdir, directory_created: created, root_publication_attempted: rootAttempt,
      expected_archive_sha256: rootDigest, ...stats, complete: false, mutation_submitted: false };
    throw error;
  } finally { client.disconnect(); life.close(); }
}
