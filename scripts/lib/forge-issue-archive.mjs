// Complete native issue/history read snapshots. This package is a portable API
// observation, never an authority checkpoint, mutation receipt or restore grant.
import { constants as F } from 'node:fs';
import { mkdir, open, lstat, realpath, opendir } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { IssueClient, issuePage, issueHistory, issueState, issueAction, natural, snapshotToken }
  from '../../crates/fgit-node/src/smart_http/server/browser/issues.mjs';
import { operatorError, operatorPath, privateRecordPath, readPrivateOperatorFile,
  saveOperatorRecord, recordDigest } from './forge-operator-io.mjs';

export const ISSUE_ARCHIVE_SCHEMA = 'frankengit-issue-read-archive-v1';
export const ISSUE_ARCHIVE_LIMITS = Object.freeze({ pages: 8192, issues: 4096,
  events: 65536, bytes: 64 * 1024 * 1024, pageBytes: 1024 * 1024 });
const L = ISSUE_ARCHIVE_LIMITS;
const encode = value => Buffer.from(JSON.stringify(value) + '\n');
const equal = (a, b) => encode(a).equals(encode(b));
const fail = reason => { throw operatorError(`issue_archive_${reason}`); };
const pageName = index => `page-${String(index + 1).padStart(6, '0')}.json`;
function keys(value, allowed, required = allowed) {
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
      Object.keys(value).some(k => !allowed.includes(k)) || required.some(k => !Object.hasOwn(value, k))) fail('fields');
}
function digest(value) { if (typeof value !== 'string' || !/^[0-9a-f]{64}$/.test(value)) fail('digest'); return value; }
function identifier(value) { if (typeof value !== 'string' || !/^[0-9a-f]{32}$/.test(value)) fail('identity'); return value; }
function sourceHead(value) {
  if (typeof value !== 'string' || !value || Buffer.byteLength(value) > 256 || /[\x00-\x20\x7f\uD800-\uDFFF]/u.test(value)) fail('source_head');
  return value;
}
function location(href) {
  if (typeof href !== 'string' || href.length > 4096 || new URL(href).href !== href) fail('url');
  // Use the shipped client's endpoint/profile validator, including HTTPS policy.
  new IssueClient({ href }); return href;
}
function canonical(bytes) {
  const value = JSON.parse(new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes));
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
      (stat.mode & 0o077n) || await realpath(path) !== path ||
      expected && (stat.dev !== expected.dev || stat.ino !== expected.ino)) fail('directory_changed_or_unsafe');
  return stat;
}
async function syncDirectory(path) {
  const fd = await open(path, F.O_RDONLY | F.O_DIRECTORY | F.O_NOFOLLOW);
  try { await fd.sync(); } finally { await fd.close(); }
}
function stateView(row) {
  issueState(row);
  return { number: row.number, version: row.version, title: row.title, body: row.body, labels: row.labels,
    state: row.state, opened_by: row.opened_by, last_actor: row.last_actor,
    comments: row.comments, assignees: row.assignees ?? [] };
}
// One deterministic traversal is shared by live capture and offline inspection.
// Replay only checks API self-consistency; it cannot authorize native state.
class Walk {
  constructor(scope, limit, caps = L) {
    this.scope = scope; this.limit = limit; this.caps = caps;
    this.head = scope.snapshot_token; this.source = scope.source_head;
    this.next = { number: null, after: 0 }; this.queue = []; this.listNext = null;
    this.issues = 0; this.events = 0; this.folded = null;
  }
  accept(reply) {
    if (this.next === null) fail('extra_page');
    const { number, after } = this.next;
    const options = { after, limit: this.limit, head: this.head,
      binding: { tenant: this.scope.tenant_id, repository: this.scope.repository_id } };
    const checked = number === null ? issuePage(reply, options) : issueHistory(reply, number, options);
    const source = sourceHead(reply.source_head);
    if (this.source !== null && this.source !== source) fail('source_head_changed');
    this.source = source; this.head = checked.head;
    if (number === null) {
      this.issues += reply.issues.length;
      if (this.issues > this.caps.issues) fail('issue_limit');
      this.queue = reply.issues.map(stateView); this.listNext = reply.next_after;
      // Account for declared history before attempting any more network reads.
      const declared = this.queue.reduce((n, row) => n + row.version, this.events);
      if (!Number.isSafeInteger(declared) || declared > this.caps.events) fail('event_limit');
      this.advance(); return;
    }
    const expected = this.queue[0];
    if (!reply.found || !equal(stateView(reply.issue), expected)) fail('list_history_disagreement');
    for (const event of reply.events) {
      const { name, body_rendered: _rendered, ...fields } = event.action;
      const action = issueAction(name, fields);
      if (name === 'open') this.folded = { number, version: 0, title: action.title, body: action.body,
        labels: action.labels, state: 'open', opened_by: event.actor, last_actor: event.actor, comments: 0, assignees: [] };
      const s = this.folded;
      if (!s) fail('missing_open');
      if (name === 'edit') for (const key of ['title', 'body', 'labels']) if (Object.hasOwn(action, key)) s[key] = action[key];
      if (name === 'comment') s.comments++;
      if (name === 'close' || name === 'reopen') s.state = name === 'close' ? 'closed' : 'open';
      if (name === 'assign') s.assignees = [...new Set([...s.assignees, ...action.assignees])].sort();
      if (name === 'unassign') s.assignees = s.assignees.filter(id => !action.assignees.includes(id));
      s.version = event.version; s.last_actor = event.actor; this.events++;
      if (this.events > this.caps.events || s.assignees.length > 16) fail('event_limit');
    }
    if (reply.next_after_version !== null) this.next = { number, after: reply.next_after_version };
    else {
      if (!equal(this.folded, expected)) fail('history_state_disagreement');
      this.queue.shift(); this.folded = null; this.advance();
    }
  }
  advance() {
    this.next = this.queue.length ? { number: this.queue[0].number, after: 0 }
      : this.listNext !== null ? { number: null, after: this.listNext } : null;
  }
}
function manifest(value) {
  keys(value, ['schema', 'href', 'tenant_id', 'repository_id', 'snapshot_token', 'source_head',
    'page_size', 'issue_count', 'event_count', 'data_bytes', 'pages']);
  if (value.schema !== ISSUE_ARCHIVE_SCHEMA) fail('schema');
  location(value.href); identifier(value.tenant_id); identifier(value.repository_id);
  snapshotToken(value.snapshot_token); sourceHead(value.source_head);
  natural(value.page_size, 'archive page size', 1, 100);
  natural(value.issue_count, 'archive issues', 0, L.issues); natural(value.event_count, 'archive events', 0, L.events);
  natural(value.data_bytes, 'archive data bytes', 1, L.bytes);
  if (!Array.isArray(value.pages)) fail('pages');
  natural(value.pages.length, 'archive pages', 1, L.pages);
  for (const row of value.pages) {
    if (!Array.isArray(row) || row.length !== 4) fail('page_descriptor');
    if (row[0] !== null) natural(row[0], 'archive issue number', 1);
    natural(row[1], 'archive cursor'); digest(row[2]); natural(row[3], 'archive page bytes', 1, L.pageBytes);
  }
  return value;
}
async function validateFiles(root, m, life, identity, sealed, collect) {
  const expectedNames = new Set(m.pages.map((_, i) => pageName(i)));
  if (sealed) expectedNames.add('archive.json');
  const dir = await opendir(root); let count = 0;
  for await (const entry of dir) {
    life.check(); if (++count > m.pages.length + Number(sealed) || !expectedNames.delete(entry.name)) fail('unexpected_file');
  }
  if (expectedNames.size) fail('missing_file');
  const walk = new Walk(m, m.page_size); let bytes = 0;
  for (const [index, row] of m.pages.entries()) {
    life.check(); await directory(root, identity);
    if (!equal(walk.next, { number: row[0], after: row[1] })) fail('page_order');
    const raw = await readPrivateOperatorFile(join(root, pageName(index)), L.pageBytes, () => life.check());
    bytes += raw.length;
    if (raw.length !== row[3] || recordDigest(raw) !== row[2] || bytes > m.data_bytes) fail('page_commitment');
    const reply = canonical(raw);
    walk.accept(reply);
    collect?.(reply);
  }
  if (walk.next !== null || walk.issues !== m.issue_count || walk.events !== m.event_count || bytes !== m.data_bytes) fail('incomplete');
  await directory(root, identity); life.check();
  return { type: 'forge_issue_archive', schema_version: 1, archive_sha256: recordDigest(encode(m)),
    href: m.href, tenant_id: m.tenant_id, repository_id: m.repository_id, snapshot_token: m.snapshot_token,
    source_head: m.source_head, issues: walk.issues, events: walk.events, pages: m.pages.length,
    data_bytes: bytes, complete: true, canonical_backup: false, mutation_submitted: false };
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
    // Private collector only. A caller cannot observe a successful prefix or run
    // effects from pages that have not passed the COMPLETE archive traversal.
    const collect = includeRecords ? reply => {
      if (reply.type === 'issue_page') for (const row of reply.issues) {
        const record = { snapshot: stateView(row), comments: [] };
        records.push(record); byNumber.set(row.number, record);
      } else for (const event of reply.events) if (event.action.name === 'comment') {
        byNumber.get(reply.issue.number).comments.push({ version: event.version,
          actor: event.actor, body: event.action.body });
      }
    } : undefined;
    const archive = { ...await validateFiles(root, m, life, identity, true, collect),
      network_accessed: false, local_read_only: true };
    return includeRecords ? { archive, records } : archive;
  } finally { life.close(); }
}
export function inspectIssueArchive(raw) { return readArchive(raw, false); }
// A bounded, owned data view for migration consumers. Original principals remain
// source attribution. This does not restore native history or grant any write.
export function readIssueArchive(raw) { return readArchive(raw, true); }
// Byte/request accounting occurs before the shipped client decodes the reply.
// Only constructed read URLs reach this adapter; no redirect, retry or mutation.
function transport(o, life, stats) {
  return async (url, init) => {
    life.check(); if (init.method !== 'GET' || init.body !== undefined) fail('read_only');
    if (stats.requests >= o.maxRequests) fail('request_limit');
    stats.requests++;
    const signal = AbortSignal.any([life.signal, init.signal]);
    const response = await o.fetchImpl(url, { ...init, signal });
    let reader, cancellation, cleanupFailed = false;
    const cancel = () => cancellation ??= Promise.resolve().then(() => (reader ?? response.body)?.cancel()).catch(() => { cleanupFailed = true; });
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
export async function exportIssueArchive(raw) {
  keys(raw, ['workdir', 'href', 'tenant', 'repository', 'tokenFile', 'head', 'timeoutMs', 'signal',
    'maxRequests', 'maxReadBytes', 'maxArchiveBytes', 'maxIssues', 'maxEvents', 'pageSize', 'fetchImpl'],
  ['workdir', 'href', 'tenant', 'repository', 'tokenFile']);
  const o = { ...raw, href: location(raw.href), workdir: operatorPath(raw.workdir), tokenFile: operatorPath(raw.tokenFile),
    tenant: identifier(raw.tenant), repository: identifier(raw.repository), head: raw.head ?? null,
    maxRequests: natural(raw.maxRequests ?? L.pages, 'request budget', 1, L.pages),
    maxReadBytes: natural(raw.maxReadBytes ?? L.bytes, 'read byte budget', 1, L.bytes),
    maxArchiveBytes: natural(raw.maxArchiveBytes ?? L.bytes, 'archive byte budget', 1, L.bytes),
    maxIssues: natural(raw.maxIssues ?? L.issues, 'issue budget', 1, L.issues),
    maxEvents: natural(raw.maxEvents ?? L.events, 'event budget', 1, L.events),
    pageSize: natural(raw.pageSize ?? 10, 'page size', 1, 100), fetchImpl: raw.fetchImpl ?? globalThis.fetch };
  if (o.head !== null) snapshotToken(o.head);
  if (typeof o.fetchImpl !== 'function') fail('fetch');
  const life = lifetime(o), stats = { requests: 0, read_bytes: 0 }; let created = false, rootAttempt = false, rootDigest = null;
  const client = new IssueClient({ href: o.href, timeoutMs: life.timeout, fetchImpl: transport(o, life, stats) });
  try {
    life.check();
    if (await privateRecordPath(o.workdir) !== o.workdir) fail('path_alias');
    const tokenPath = await realpath(o.tokenFile);
    if (tokenPath === o.workdir || tokenPath.startsWith(o.workdir + '/')) fail('token_inside_archive');
    const token = await readPrivateOperatorFile(o.tokenFile, 65, () => life.check());
    try {
      if (token.some(b => b > 127) || !/^[0-9a-f]{64}\n?$/.test(token.toString('ascii'))) fail('token');
      await client.connect(token.toString('ascii').replace(/\n$/, ''));
    } finally { token.fill(0); }
    life.check(); await mkdir(o.workdir, { mode: 0o700 }); created = true;
    await syncDirectory(dirname(o.workdir)); const identity = await directory(o.workdir);
    const walk = new Walk({ tenant_id: o.tenant, repository_id: o.repository, snapshot_token: o.head, source_head: null },
      o.pageSize, { issues: o.maxIssues, events: o.maxEvents });
    const pages = []; let dataBytes = 0;
    while (walk.next !== null) {
      life.check(); await directory(o.workdir, identity);
      const { number, after } = walk.next;
      const value = await client.read(number, { after, limit: o.pageSize, head: walk.head, render: false });
      life.check(); walk.accept(value.reply);
      const bytes = encode(value.reply); dataBytes += bytes.length;
      if (bytes.length > L.pageBytes || dataBytes > o.maxArchiveBytes) fail('archive_limit');
      await directory(o.workdir, identity);
      const saved = await saveOperatorRecord(join(o.workdir, pageName(pages.length)), bytes, () => life.check());
      pages.push([number, after, saved.sha256, bytes.length]);
    }
    const m = manifest({ schema: ISSUE_ARCHIVE_SCHEMA, href: o.href, tenant_id: o.tenant, repository_id: o.repository,
      snapshot_token: walk.head, source_head: walk.source, page_size: o.pageSize, issue_count: walk.issues,
      event_count: walk.events, data_bytes: dataBytes, pages });
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
