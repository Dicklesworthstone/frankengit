// FG-049: bounded GitHub issue capture and translation into the shipped native
// issue commands. Imported actors are attribution, never local principals.
import { mutationRequest, natural } from '../../crates/fgit-node/src/smart_http/server/browser/issues.mjs';
import { recordDigest, operatorError } from './forge-operator-io.mjs';

export const CAPTURE_SCHEMA = 'frankengit-github-issue-capture-v1';
export const CAPTURE_LIMIT = 1024 * 1024;
export const ISSUE_LIMIT = 100;
export const COMMENT_LIMIT = 2000;
export const API_VERSION = '2026-03-10';
const API = 'https://api.github.com';
const UA = 'frankengit-issue-import (+https://github.com/Dicklesworthstone/frankengit)';
const CONSISTENCY = 'two-equal-observations-not-atomic';
const fail = code => { throw operatorError(`github_import_${code}`); };
const object = v => { if (!v || typeof v !== 'object' || Array.isArray(v)) fail('invalid_object'); return v; };
function text(v, max, name, single = false) {
  if (typeof v !== 'string' || v.length > max || Buffer.byteLength(v) > max || /[\0\uD800-\uDFFF]/u.test(v) ||
      (single && (!v.trim() || /[\u0000-\u001f\u007f-\u009f]/u.test(v)))) fail(`invalid_${name}`);
  return v;
}
export function githubRepository(v) {
  if (typeof v !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9-]{0,38}\/[A-Za-z0-9_.-]{1,100}$/.test(v) ||
      ['.', '..'].includes(v.split('/')[1])) fail('repository');
  return v;
}
function id(v) {
  if (typeof v === 'number') { natural(v, 'GitHub ID', 1); v = String(v); }
  if (typeof v !== 'string' || !/^[1-9][0-9]{0,19}$/.test(v) || BigInt(v) > 18446744073709551615n) fail('identity');
  return v;
}
function actor(v) {
  if (v === null) return null;
  object(v);
  return { id: id(v.id), login: text(v.login, 100, 'login', true) };
}
function timestamp(v, nullable = false) {
  if (nullable && v === null) return null;
  if (typeof v !== 'string' || !/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$/.test(v) ||
      !Number.isFinite(Date.parse(v)) || new Date(v).toISOString() !== v.replace('Z', '.000Z')) fail('timestamp');
  return v;
}
function labels(v) {
  if (!Array.isArray(v) || v.length > 32) fail('labels');
  const rows = v.map(row => {
    object(row);
    if (typeof row.color !== 'string' || !/^[0-9a-fA-F]{6}$/.test(row.color)) fail('label_color');
    return { id: id(row.id), name: text(row.name, 64, 'label', true), color: row.color,
      description: row.description === null ? null : text(row.description, 4096, 'label_description') };
  }).sort((a, b) => Buffer.compare(Buffer.from(a.name), Buffer.from(b.name)));
  if (new Set(rows.map(r => r.name)).size !== rows.length || new Set(rows.map(r => r.id)).size !== rows.length) fail('duplicate_label');
  return rows;
}
function normalizeIssue(raw, repository, expectedNumber) {
  object(raw);
  if (Object.hasOwn(raw, 'pull_request')) fail('pull_request_not_supported');
  if (raw.number !== expectedNumber || raw.html_url !== `https://github.com/${repository}/issues/${expectedNumber}`) fail('issue_scope');
  if (!['open', 'closed'].includes(raw.state) || typeof raw.locked !== 'boolean') fail('issue_state');
  const created = timestamp(raw.created_at), updated = timestamp(raw.updated_at), closed = timestamp(raw.closed_at, true);
  if (created > updated || (raw.state === 'open' && closed !== null) || (raw.state === 'closed' && closed === null)) fail('issue_timestamps');
  if (!Array.isArray(raw.assignees) || raw.assignees.length > 100) fail('assignees');
  const assignees = raw.assignees.map(actor).sort((a, b) => a === null || b === null ? fail('assignee') : (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
  if (assignees.includes(null) || new Set(assignees.map(a => a.id)).size !== assignees.length) fail('assignee');
  let milestone = null;
  if (raw.milestone !== null) {
    const m = object(raw.milestone);
    if (!['open', 'closed'].includes(m.state)) fail('milestone');
    milestone = { id: id(m.id), number: natural(m.number, 'milestone', 1), title: text(m.title, 4096, 'milestone'), state: m.state };
  }
  return { number: expectedNumber, id: id(raw.id), html_url: raw.html_url,
    title: text(raw.title, 256, 'title', true), body: raw.body === null ? null : text(raw.body, 65536, 'body'),
    state: raw.state, state_reason: raw.state_reason == null ? null : text(raw.state_reason, 100, 'state_reason', true),
    user: actor(raw.user), created_at: created, updated_at: updated, closed_at: closed,
    labels: labels(raw.labels), assignees, milestone, locked: raw.locked,
    comment_count: natural(raw.comments, 'comment count', 0, COMMENT_LIMIT) };
}
function normalizeComment(raw, repository, number) {
  object(raw); const identity = id(raw.id);
  if (raw.html_url !== `https://github.com/${repository}/issues/${number}#issuecomment-${identity}` ||
      raw.issue_url !== `${API}/repos/${repository}/issues/${number}`) fail('comment_scope');
  const created = timestamp(raw.created_at), updated = timestamp(raw.updated_at);
  if (created > updated) fail('comment_timestamps');
  return { id: identity, html_url: raw.html_url, issue_url: raw.issue_url, user: actor(raw.user),
    created_at: created, updated_at: updated, body: text(raw.body, 65536, 'comment') };
}
function selectedNumbers(v) {
  if (!Array.isArray(v) || !v.length || v.length > ISSUE_LIMIT) fail('issue_selection');
  const numbers = v.map(n => natural(n, 'selected issue', 1)).sort((a, b) => a - b);
  if (new Set(numbers).size !== numbers.length) fail('duplicate_issue');
  return numbers;
}
function encode(value) { return Buffer.from(JSON.stringify(value) + '\n'); }
export function captureBytes(value) {
  object(value); const source = object(value.source), repository = githubRepository(source.repository);
  const issues = value.issues;
  if (value.schema !== CAPTURE_SCHEMA || value.consistency !== CONSISTENCY || !Array.isArray(issues)) fail('capture_schema');
  const numbers = selectedNumbers(issues.map(v => object(v).number));
  let count = 0; const ids = new Set(), comments = new Set();
  const checked = { schema: CAPTURE_SCHEMA, consistency: CONSISTENCY,
    source: { repository, repository_id: id(source.repository_id) },
    issues: issues.map((row, index) => {
      if (row.number !== numbers[index] || !Array.isArray(row.comments)) fail('capture_order');
      const issue = normalizeIssue({ ...row, comments: row.comment_count }, repository, row.number);
      if (ids.has(issue.id) || row.comments.length !== issue.comment_count) fail('capture_identity_or_count');
      ids.add(issue.id); count += row.comments.length;
      if (count > COMMENT_LIMIT) fail('comment_limit');
      let previous = 0n;
      issue.comments = row.comments.map(raw => {
        const comment = normalizeComment(raw, repository, issue.number), next = BigInt(comment.id);
        if (next <= previous || comments.has(comment.id)) fail('comment_order');
        previous = next; comments.add(comment.id); return comment;
      });
      return issue;
    }) };
  const bytes = encode(checked);
  if (bytes.length > CAPTURE_LIMIT) fail('capture_bytes');
  // Canonical source packages have no hidden fields or alternate representations.
  if (!encode(value).equals(bytes)) fail('noncanonical_capture');
  return bytes;
}
export function parseCapture(bytes) {
  if (!(bytes instanceof Uint8Array) || bytes.length > CAPTURE_LIMIT) fail('capture_bytes');
  const v = JSON.parse(new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes));
  if (!captureBytes(v).equals(Buffer.from(bytes))) fail('noncanonical_capture');
  return v;
}
function provenance(source, issue, comment = null) {
  const row = comment ?? issue;
  const metadata = { source_repository_id: source.repository_id, source_issue_id: issue.id,
    ...(comment ? { source_comment_id: comment.id } : {}), source_author: row.user,
    created_at: row.created_at, updated_at: row.updated_at,
    ...(!comment ? { state: issue.state, state_reason: issue.state_reason, closed_at: issue.closed_at,
      labels: issue.labels, assignees: issue.assignees, milestone: issue.milestone, locked: issue.locked } : {}) };
  const json = JSON.stringify(metadata), runs = json.match(/~+/g) ?? [];
  const fence = '~'.repeat(runs.reduce((n, run) => Math.max(n, run.length + 1), 3));
  return `Imported GitHub snapshot: ${row.html_url}\nSource authors and metadata below are attribution only, not native principals, permissions or audit events.\n\n${fence}json\n${json}\n${fence}\n\n${row.body ?? ''}`;
}
export function issueImportSteps(value, offset = 0) {
  captureBytes(value); natural(offset, 'target number offset');
  const steps = [];
  for (const issue of value.issues) {
    const number = natural(issue.number + offset, 'target issue number', 1);
    const add = (action, fields, source) => {
      const version = action === 'open' ? 0 : steps.at(-1).expected_version + 1;
      const request = mutationRequest(number, version, action, fields);
      steps.push({ source, number, expected_version: version, action, fields: request.fields });
    };
    add('open', { title: issue.title, body: provenance(value.source, issue), labels: issue.labels.map(l => l.name) }, issue.html_url);
    for (const comment of issue.comments) add('comment', { body: provenance(value.source, issue, comment) }, comment.html_url);
    if (issue.state === 'closed') add('close', {}, issue.html_url);
  }
  if (encode(steps).length > CAPTURE_LIMIT) fail('native_plan_bytes');
  return steps;
}
// Do not round GitHub numeric aliases through IEEE-754. This profile requires
// Node's JSON reviver source context; all other numeric fields are safe integers.
function githubJson(bytes) {
  return JSON.parse(new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes), (key, value, context) => {
    if (typeof value !== 'number') return value;
    const raw = context?.source;
    if (typeof raw !== 'string' || !/^(0|[1-9][0-9]*)$/.test(raw)) fail('numeric_wire_value');
    if (key === 'id') return id(raw);
    return natural(value, 'GitHub integer');
  });
}
function continuation(header, repository, repositoryId, number, page) {
  if (!header) return false;
  if (header.length > 8192) fail('pagination');
  let next = false;
  for (const part of header.split(',')) {
    const match = /^\s*<([^<>]+)>;\s*rel="(next|prev|first|last)"\s*$/.exec(part);
    if (!match) fail('pagination');
    if (match[2] !== 'next') continue;
    if (next) fail('pagination');
    const url = new URL(match[1]);
    const paths = [`/repos/${repository}/issues/${number}/comments`, `/repositories/${repositoryId}/issues/${number}/comments`];
    const query = url.searchParams;
    if (url.origin !== API || url.username || url.password || url.hash || !paths.includes(url.pathname) ||
        [...query.keys()].length !== 2 || query.get('per_page') !== '100' || query.get('page') !== String(page + 1)) fail('pagination_scope');
    next = true;
  }
  return next;
}
export async function captureGithubIssues({ repository, numbers, token = null, signal,
  timeoutMs = 300000, maxReadBytes = 64 * 1024 * 1024, fetchImpl = globalThis.fetch } = {}) {
  githubRepository(repository); numbers = selectedNumbers(numbers);
  natural(timeoutMs, 'capture timeout', 1, 300000); natural(maxReadBytes, 'capture read limit', 1, 256 * 1024 * 1024);
  if (token !== null && (typeof token !== 'string' || !/^[A-Za-z0-9_]{1,255}$/.test(token))) fail('token');
  if (signal !== undefined && !(signal instanceof AbortSignal)) fail('signal');
  const stop = new AbortController(), combined = signal ? AbortSignal.any([signal, stop.signal]) : stop.signal;
  const timer = setTimeout(() => stop.abort(), timeoutMs);
  const check = () => combined.throwIfAborted();
  let readBytes = 0, requests = 0;
  async function get(path) {
    check(); if (++requests > 4096) fail('request_limit');
    const url = `${API}${path}`;
    const response = await fetchImpl(url, { method: 'GET', redirect: 'error', credentials: 'omit', cache: 'no-store',
      signal: combined, headers: { Accept: 'application/vnd.github.raw+json', 'X-GitHub-Api-Version': API_VERSION,
        'User-Agent': UA, ...(token === null ? {} : { Authorization: `Bearer ${token}` }) } });
    let reader;
    const cancel = () => { void (reader ?? response.body)?.cancel().catch(() => {}); };
    try {
      check();
      if (response.redirected || (response.url && response.url !== url)) fail('redirect');
      if (response.status !== 200) {
        const error = operatorError('github_import_source_http'); error.status = response.status;
        const after = response.headers.get('Retry-After');
        if (after && /^[0-9]{1,10}$/.test(after)) error.retry_after_seconds = after;
        throw error;
      }
      if (!/^application\/(?:json|vnd\.github(?:\.raw)?\+json)(?:\s*;|$)/i.test(response.headers.get('Content-Type') ?? '') || !response.body) fail('json_media');
      reader = response.body.getReader(); combined.addEventListener('abort', cancel, { once: true });
      const chunks = []; let bytes = 0;
      for (;;) {
        check(); const next = await reader.read(); check(); if (next.done) break;
        bytes += next.value.byteLength; readBytes += next.value.byteLength;
        if (bytes > 8 * 1024 * 1024 || readBytes > maxReadBytes) fail('read_bytes');
        chunks.push(next.value);
      }
      return { value: githubJson(Buffer.concat(chunks, bytes)), link: response.headers.get('Link') };
    } finally { combined.removeEventListener('abort', cancel); cancel(); reader?.releaseLock(); }
  }
  async function pass() {
    const repo = object((await get(`/repos/${repository}`)).value);
    if (githubRepository(repo.full_name).toLowerCase() !== repository.toLowerCase()) fail('repository_substitution');
    const selected = repo.full_name, repositoryId = id(repo.id), issues = []; let total = 0;
    for (const number of numbers) {
      const issue = normalizeIssue((await get(`/repos/${selected}/issues/${number}`)).value, selected, number);
      total += issue.comment_count; if (total > COMMENT_LIMIT) fail('comment_limit');
      const comments = []; let page = 1, previous = 0n;
      do {
        const reply = await get(`/repos/${selected}/issues/${number}/comments?per_page=100&page=${page}`);
        if (!Array.isArray(reply.value) || reply.value.length > 100) fail('comment_page');
        for (const raw of reply.value) {
          const row = normalizeComment(raw, selected, number), next = BigInt(row.id);
          if (next <= previous || comments.length >= issue.comment_count) fail('comment_order_or_count');
          comments.push(row); previous = next;
        }
        const next = continuation(reply.link, selected, repositoryId, number, page);
        if (!next) break;
        if (!reply.value.length || comments.length >= issue.comment_count || page >= 100) fail('pagination_count');
        page++;
      } while (true);
      if (comments.length !== issue.comment_count) fail('incomplete_comments');
      issues.push({ ...issue, comments });
      // Bound retained bytes after each complete issue, not after a whole repo.
      if (encode(issues).length > CAPTURE_LIMIT) fail('capture_bytes');
    }
    return { schema: CAPTURE_SCHEMA, consistency: CONSISTENCY, source: { repository: selected, repository_id: repositoryId }, issues };
  }
  try {
    const first = await pass(), bytes = captureBytes(first);
    issueImportSteps(first); // Refuse unrepresentable native text before saving a usable package.
    const second = captureBytes(await pass()); check();
    if (!bytes.equals(second)) fail('source_changed');
    return { capture: first, bytes, sha256: recordDigest(bytes), requests, read_bytes: readBytes };
  } finally { clearTimeout(timer); stop.abort(); }
}
