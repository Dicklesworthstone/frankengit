// Shared private custody and v1 framing for one-shot and resumable PR capture.
import { constants as F } from 'node:fs';
import { createHash } from 'node:crypto';
import { dirname, join, resolve } from 'node:path';
import { open, lstat, realpath, opendir } from 'node:fs/promises';
import { rootFor, snapshot as nativeSnapshot } from '../../crates/fgit-node/src/smart_http/server/browser/pulls-core.mjs';
import { PullArchiveWalk } from './forge-pull-archive-protocol.mjs';

export const PULL_ARCHIVE_SCHEMA = 'frankengit-pull-read-archive-v1';
export const PULL_ARCHIVE_LIMITS = Object.freeze({ pages: 16384, pulls: 4096,
  reviews: 65536, comments: 65536, bytes: 64 * 1024 * 1024, pageBytes: 1024 * 1024, manifestBytes: 4 * 1024 * 1024 });
const L = PULL_ARCHIVE_LIMITS;
export const encode = value => Buffer.from(`${JSON.stringify(value)}\n`);
export const digest = bytes => createHash('sha256').update(bytes).digest('hex');
export const fail = reason => { const e = new Error(`pull_archive_${reason}`); e.code = `pull_archive_${reason}`; throw e; };
export const number = (value, min, max, name) => { if (!Number.isSafeInteger(value) || value < min || value > max) fail(name); return value; };
export const pin = value => { if (typeof value !== 'string' || !/^[0-9a-f]{64}$/.test(value)) fail('pin'); return value; };
export const id32 = value => { if (typeof value !== 'string' || !/^[0-9a-f]{32}$/.test(value)) fail('identity'); return value; };
export const snapshot = nativeSnapshot;
export function exact(value, names) {
  if (!value || typeof value !== 'object' || Array.isArray(value) || Object.keys(value).length !== names.length || names.some(name => !Object.hasOwn(value, name))) fail('fields');
}
export function safePath(value) {
  if (typeof value !== 'string' || !value || Buffer.byteLength(value) > 4096 || /[\0\r\n\uD800-\uDFFF]/u.test(value) || resolve(value) !== value) fail('path');
  return value;
}
export function location(value) {
  if (typeof value !== 'string' || value.length > 4096 || new URL(value).href !== value || !value.endsWith('/ui/pulls/')) fail('url');
  rootFor(value);
  return value;
}
export function sourceHead(value) {
  if (typeof value !== 'string' || !value || Buffer.byteLength(value) > 256 || /[\x00-\x20\x7f\uD800-\uDFFF]/u.test(value)) fail('source_head');
  return value;
}
export function canonical(bytes) {
  const value = JSON.parse(new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes));
  if (!encode(value).equals(bytes)) fail('encoding');
  return value;
}
export function pageName(index) { return `page-${String(index + 1).padStart(6, '0')}.json`; }
export async function directory(path, expected = null) {
  const stat = await lstat(path, { bigint: true });
  if (typeof process.getuid !== 'function' || !stat.isDirectory() || stat.uid !== BigInt(process.getuid()) ||
      (stat.mode & 0o077n) !== 0n || await realpath(path) !== path ||
      expected && (stat.dev !== expected.dev || stat.ino !== expected.ino)) fail('directory_changed_or_unsafe');
  return stat;
}
export async function syncDirectory(path) {
  const fd = await open(path, F.O_RDONLY | F.O_DIRECTORY | F.O_NOFOLLOW);
  try { await fd.sync(); } finally { await fd.close(); }
}
export async function readPrivate(path, maximum, synchronize = false, check = () => {}) {
  check(); const fd = await open(path, F.O_RDONLY | F.O_NOFOLLOW | F.O_NONBLOCK);
  try {
    const before = await fd.stat({ bigint: true });
    if (!before.isFile() || before.uid !== BigInt(process.getuid()) || (before.mode & 0o077n) !== 0n || before.nlink !== 1n || before.size < 1n || before.size > BigInt(maximum)) fail('private_file');
    const out = Buffer.alloc(Number(before.size)); let at = 0;
    while (at < out.length) { check(); const r = await fd.read(out, at, out.length - at, at); if (!r.bytesRead) fail('file_changed'); at += r.bytesRead; }
    const after = await fd.stat({ bigint: true }), named = await lstat(path, { bigint: true });
    for (const key of ['dev','ino','mode','uid','size','nlink','mtimeNs','ctimeNs']) if (before[key] !== after[key] || after[key] !== named[key]) fail('file_changed');
    if (synchronize) {
      // A different collector may have published readable bytes before finishing
      // its barrier. The resumer owns a fresh synchronization before using them.
      check(); await fd.sync(); await syncDirectory(dirname(path));
      const synced = await fd.stat({ bigint: true }), now = await lstat(path, { bigint: true });
      for (const key of ['dev','ino','mode','uid','size','nlink','mtimeNs','ctimeNs'])
        if (before[key] !== synced[key] || synced[key] !== now[key]) fail('file_changed');
    }
    check(); return out;
  } finally { await fd.close(); }
}
export async function writeNew(path, bytes) {
  const fd = await open(path, F.O_WRONLY | F.O_CREAT | F.O_EXCL | F.O_NOFOLLOW, 0o600);
  try { await fd.writeFile(bytes); await fd.sync(); } finally { await fd.close(); }
  await syncDirectory(dirname(path));
  const check = await readPrivate(path, Math.max(bytes.length, 1));
  if (!check.equals(bytes)) fail('write_readback');
}
export function lifetime(raw) {
  const timeout = number(raw.timeoutMs ?? 300000, 1, 300000, 'deadline');
  if (raw.signal !== undefined && !(raw.signal instanceof AbortSignal)) fail('signal');
  const stop = new AbortController(), signal = raw.signal ? AbortSignal.any([raw.signal, stop.signal]) : stop.signal;
  const timer = setTimeout(() => stop.abort(new Error('pull archive deadline')), timeout);
  return { signal, timeout, check() { signal.throwIfAborted(); }, close() { clearTimeout(timer); stop.abort(); } };
}
export function manifest(value) {
  exact(value, ['schema','href','tenant_id','repository_id','repository_incarnation','object_format','snapshot_token','source_head','page_size','pull_count','review_count','comment_count','data_bytes','pages']);
  if (value.schema !== PULL_ARCHIVE_SCHEMA) fail('schema');
  location(value.href); id32(value.tenant_id); id32(value.repository_id); id32(value.repository_incarnation);
  if (!['sha1','sha256'].includes(value.object_format)) fail('format'); snapshot(value.snapshot_token); sourceHead(value.source_head);
  number(value.page_size, 1, 100, 'page_size'); number(value.pull_count, 0, L.pulls, 'pulls');
  number(value.review_count, 0, L.reviews, 'reviews'); number(value.comment_count, 0, L.comments, 'comments');
  number(value.data_bytes, 1, L.bytes, 'bytes'); if (!Array.isArray(value.pages)) fail('pages'); number(value.pages.length, 1, L.pages, 'pages');
  for (const row of value.pages) {
    exact(row, ['kind','number','cursor','sha256','bytes']);
    if (!['list','show','reviews','comments'].includes(row.kind)) fail('page_kind');
    if (row.kind === 'list') { if (row.number !== null) fail('page_number'); number(row.cursor, 0, Number.MAX_SAFE_INTEGER, 'cursor'); }
    else { number(row.number, 1, Number.MAX_SAFE_INTEGER, 'number'); if (row.kind === 'reviews') { if (row.cursor !== null && (typeof row.cursor !== 'string' || !/^[0-9a-f]{32}$/.test(row.cursor))) fail('cursor'); } else number(row.cursor, 0, Number.MAX_SAFE_INTEGER, 'cursor'); }
    pin(row.sha256); number(row.bytes, 1, L.pageBytes, 'page_bytes');
  }
  return value;
}

export async function validateArchive(root, m, life, identity, sealed = true) {
  const expected = new Set(m.pages.map((_, i) => pageName(i))); if (sealed) expected.add('archive.json');
  for await (const entry of await opendir(root)) { life.check(); if (!expected.delete(entry.name)) fail('unexpected_file'); }
  if (expected.size) fail('missing_file');
  const walk = new PullArchiveWalk({ tenant:m.tenant_id, repository:m.repository_id, pageSize:m.page_size,
    head:m.snapshot_token, source:m.source_head, scope:{ tenant:m.tenant_id, repository:m.repository_id,
      incarnation:m.repository_incarnation, format:m.object_format }, limits:L });
  let bytes = 0;
  for (const [index, desc] of m.pages.entries()) {
    life.check(); await directory(root, identity); const raw = await readPrivate(join(root, pageName(index)), L.pageBytes);
    bytes += raw.length;
    if (raw.length !== desc.bytes || digest(raw) !== desc.sha256 || bytes > m.data_bytes) fail('page_commitment');
    walk.accept(desc, canonical(raw));
  }
  const { pulls, reviews, comments } = walk.finish();
  if (pulls !== m.pull_count || reviews !== m.review_count || comments !== m.comment_count || bytes !== m.data_bytes ||
      bytes + encode(m).length > L.bytes) fail('incomplete');
  life.check(); await directory(root, identity);
  return { type:'forge_pull_archive', schema_version:1, archive_sha256:digest(encode(m)), href:m.href, tenant_id:m.tenant_id,
    repository_id:m.repository_id, repository_incarnation:m.repository_incarnation, object_format:m.object_format,
    snapshot_token:m.snapshot_token, source_head:m.source_head, pulls, reviews, comments, pages:m.pages.length,
    data_bytes:bytes, complete:true, canonical_backup:false, merge_authority:false, mutation_submitted:false };
}


export function archiveOptions(raw) {
  const allowed = ['workdir','href','tenant','repository','tokenFile','head','timeoutMs','signal','pageSize','maxPages','maxPulls','maxReviews','maxComments','maxArchiveBytes'];
  if (!raw || typeof raw !== 'object' || Array.isArray(raw) || Object.keys(raw).some(k => !allowed.includes(k))) fail('options');
  for (const k of ['workdir','href','tenant','repository','tokenFile']) if (!Object.hasOwn(raw,k)) fail('options');
  const o = { ...raw, workdir:safePath(raw.workdir), href:location(raw.href), tokenFile:safePath(raw.tokenFile), tenant:id32(raw.tenant), repository:id32(raw.repository),
    head: raw.head ?? null, pageSize:number(raw.pageSize ?? 10,1,100,'page_size'), maxPages:number(raw.maxPages ?? L.pages,1,L.pages,'pages'),
    maxPulls:number(raw.maxPulls ?? L.pulls,1,L.pulls,'pulls'), maxReviews:number(raw.maxReviews ?? L.reviews,0,L.reviews,'reviews'),
    maxComments:number(raw.maxComments ?? L.comments,0,L.comments,'comments'), maxArchiveBytes:number(raw.maxArchiveBytes ?? L.bytes,1,L.bytes,'bytes') };
  if (o.head !== null) snapshot(o.head);
  return o;
}

export function buildManifest(o, state, pages, dataBytes) {
  const { pulls, reviews, comments, head, source, scope } = state;
  return manifest({schema:PULL_ARCHIVE_SCHEMA,href:o.href,tenant_id:o.tenant,repository_id:o.repository,
    repository_incarnation:scope.incarnation,object_format:scope.format,snapshot_token:head,source_head:source,
    page_size:o.pageSize,pull_count:pulls,review_count:reviews,comment_count:comments,data_bytes:dataBytes,pages});
}
export function archiveResult(root, m) {
  return {type:'forge_pull_archive_exported',workdir:root,archive_sha256:digest(encode(m)),pulls:m.pull_count,
    reviews:m.review_count,comments:m.comment_count,pages:m.pages.length,data_bytes:m.data_bytes,
    snapshot_token:m.snapshot_token,source_head:m.source_head,complete:true,canonical_backup:false,
    merge_authority:false,mutation_submitted:false};
}
export async function sealArchive(root, m, life, identity) {
  manifest(m); const bytes = encode(m);
  if (bytes.length > L.manifestBytes || m.data_bytes + bytes.length > L.bytes) fail('archive_limit');
  await validateArchive(root,m,life,identity,false); life.check();
  await writeNew(join(root,'archive.json'),bytes);
  return archiveResult(root,m);
}
