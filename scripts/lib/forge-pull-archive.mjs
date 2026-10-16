// Complete native pull-request metadata/review/conversation observations at one
// retained repository snapshot. This is portable read custody, never merge authority.
import { constants as F } from 'node:fs';
import { createHash } from 'node:crypto';
import { dirname, join, resolve } from 'node:path';
import { mkdir, open, lstat, realpath, opendir } from 'node:fs/promises';

export const PULL_ARCHIVE_SCHEMA = 'frankengit-pull-read-archive-v1';
export const PULL_ARCHIVE_LIMITS = Object.freeze({ pages: 16384, pulls: 4096,
  reviews: 65536, comments: 65536, bytes: 64 * 1024 * 1024, pageBytes: 1024 * 1024 });
const L = PULL_ARCHIVE_LIMITS;
const encode = value => Buffer.from(`${JSON.stringify(value)}\n`);
const digest = bytes => createHash('sha256').update(bytes).digest('hex');
const fail = reason => { const e = new Error(`pull_archive_${reason}`); e.code = `pull_archive_${reason}`; throw e; };
const number = (value, min, max, name) => { if (!Number.isSafeInteger(value) || value < min || value > max) fail(name); return value; };
const pin = value => { if (typeof value !== 'string' || !/^[0-9a-f]{64}$/.test(value)) fail('pin'); return value; };
const id32 = value => { if (typeof value !== 'string' || !/^[0-9a-f]{32}$/.test(value)) fail('identity'); return value; };
const snapshot = value => { if (typeof value !== 'string' || !/^alg:[1-9][0-9]{0,4}:(?:[0-9a-f]{2}){1,64}$/.test(value)) fail('snapshot'); return value; };
function exact(value, names) {
  if (!value || typeof value !== 'object' || Array.isArray(value) || Object.keys(value).length !== names.length || names.some(name => !Object.hasOwn(value, name))) fail('fields');
}
function safePath(value) {
  if (typeof value !== 'string' || !value || Buffer.byteLength(value) > 4096 || /[\0\r\n\uD800-\uDFFF]/u.test(value) || resolve(value) !== value) fail('path');
  return value;
}
function location(value) {
  if (typeof value !== 'string' || value.length > 4096 || new URL(value).href !== value || !value.endsWith('/ui/pulls/')) fail('url');
  return value;
}
function sourceHead(value) {
  if (typeof value !== 'string' || !value || Buffer.byteLength(value) > 256 || /[\x00-\x20\x7f\uD800-\uDFFF]/u.test(value)) fail('source_head');
  return value;
}
function canonical(bytes) {
  const value = JSON.parse(new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes));
  if (!encode(value).equals(bytes)) fail('encoding');
  return value;
}
function pageName(index) { return `page-${String(index + 1).padStart(6, '0')}.json`; }
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
async function readPrivate(path, maximum) {
  const fd = await open(path, F.O_RDONLY | F.O_NOFOLLOW | F.O_NONBLOCK);
  try {
    const before = await fd.stat({ bigint: true });
    if (!before.isFile() || before.uid !== BigInt(process.getuid()) || (before.mode & 0o077n) !== 0n || before.nlink !== 1n || before.size < 1n || before.size > BigInt(maximum)) fail('private_file');
    const out = Buffer.alloc(Number(before.size)); let at = 0;
    while (at < out.length) { const r = await fd.read(out, at, out.length - at, at); if (!r.bytesRead) fail('file_changed'); at += r.bytesRead; }
    const after = await fd.stat({ bigint: true }), named = await lstat(path, { bigint: true });
    for (const key of ['dev','ino','mode','uid','size','nlink','mtimeNs','ctimeNs']) if (before[key] !== after[key] || after[key] !== named[key]) fail('file_changed');
    return out;
  } finally { await fd.close(); }
}
async function writeNew(path, bytes) {
  const fd = await open(path, F.O_WRONLY | F.O_CREAT | F.O_EXCL | F.O_NOFOLLOW, 0o600);
  try { await fd.writeFile(bytes); await fd.sync(); } finally { await fd.close(); }
  await syncDirectory(dirname(path));
  const check = await readPrivate(path, Math.max(bytes.length, 1));
  if (!check.equals(bytes)) fail('write_readback');
}
function lifetime(raw) {
  const timeout = number(raw.timeoutMs ?? 300000, 1, 300000, 'deadline');
  if (raw.signal !== undefined && !(raw.signal instanceof AbortSignal)) fail('signal');
  const stop = new AbortController(), signal = raw.signal ? AbortSignal.any([raw.signal, stop.signal]) : stop.signal;
  const timer = setTimeout(() => stop.abort(new Error('pull archive deadline')), timeout);
  return { signal, timeout, check() { signal.throwIfAborted(); }, close() { clearTimeout(timer); stop.abort(); } };
}
function descriptor(kind, numberValue, cursor, bytes) {
  return { kind, number: numberValue, cursor, sha256: digest(bytes), bytes: bytes.length };
}
function manifest(value) {
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

async function productionBackend({ href, token, timeoutMs, signal }) {
  const [{ PullClient }, core, comments] = await Promise.all([
    import('../../crates/fgit-node/src/smart_http/server/browser/pulls.mjs'),
    import('../../crates/fgit-node/src/smart_http/server/browser/pulls-core.mjs'),
    import('../../crates/fgit-node/src/smart_http/server/browser/pulls-comments.mjs'),
  ]);
  const client = new PullClient({ href, timeoutMs }); await client.connect(token);
  signal?.addEventListener('abort', () => client.cancelReads(), { once: true });
  return {
    close: () => client.disconnect(),
    list: args => client.list(args), show: (n,h) => client.show(n,h), reviews: (n,args) => client.reviews(n,args), comments: (n,args) => client.comments(n,args),
    validate(kind, reply, ctx) {
      if (kind === 'list') return core.listReply(reply, { after: ctx.cursor, limit: ctx.limit, head: ctx.head, scope: ctx.scope });
      if (kind === 'show') return core.showReply(reply, ctx.number, { head: ctx.head, scope: ctx.scope });
      if (kind === 'reviews') return core.reviewsReply(reply, ctx.number, { after: ctx.cursor, limit: ctx.limit, head: ctx.head, scope: ctx.scope });
      return comments.commentsReply(reply, ctx.number, { after: ctx.cursor, limit: ctx.limit, head: ctx.head, scope: ctx.scope });
    },
  };
}

async function validateArchive(root, m, life, identity, backend, sealed = true) {
  const expected = new Set(m.pages.map((_, i) => pageName(i))); if (sealed) expected.add('archive.json');
  for await (const entry of await opendir(root)) { life.check(); if (!expected.delete(entry.name)) fail('unexpected_file'); }
  if (expected.size) fail('missing_file');
  let scope = null, head = m.snapshot_token, bytes = 0, pulls = 0, reviews = 0, comments = 0;
  const listed = new Set(), shown = new Set();
  for (const [index, desc] of m.pages.entries()) {
    life.check(); await directory(root, identity); const raw = await readPrivate(join(root, pageName(index)), L.pageBytes);
    bytes += raw.length; if (raw.length !== desc.bytes || digest(raw) !== desc.sha256 || bytes > m.data_bytes) fail('page_commitment');
    const reply = canonical(raw), checked = backend.validate(desc.kind, reply, { number: desc.number, cursor: desc.cursor, limit: m.page_size, head, scope });
    if (checked.head !== null) head = checked.head; scope = checked.binding;
    if (desc.kind === 'list') { for (const row of reply.pull_requests) { if (listed.has(row.number)) fail('duplicate_pull'); listed.add(row.number); pulls++; } }
    else if (desc.kind === 'show') { if (!reply.found || shown.has(desc.number)) fail('show_population'); shown.add(desc.number); }
    else if (desc.kind === 'reviews') reviews += reply.reviews.length;
    else comments += reply.comments.length;
    if (pulls > L.pulls || reviews > L.reviews || comments > L.comments) fail('count_limit');
    if (reply.source_head !== null && reply.source_head !== m.source_head) fail('source_head_changed');
  }
  if (listed.size !== shown.size || [...listed].some(n => !shown.has(n)) || pulls !== m.pull_count || reviews !== m.review_count || comments !== m.comment_count || bytes !== m.data_bytes || head !== m.snapshot_token) fail('incomplete');
  return { type:'forge_pull_archive', schema_version:1, archive_sha256:digest(encode(m)), href:m.href, tenant_id:m.tenant_id,
    repository_id:m.repository_id, repository_incarnation:m.repository_incarnation, object_format:m.object_format,
    snapshot_token:m.snapshot_token, source_head:m.source_head, pulls, reviews, comments, pages:m.pages.length,
    data_bytes:bytes, complete:true, canonical_backup:false, merge_authority:false, mutation_submitted:false };
}

export async function inspectPullArchive(raw, injected = null) {
  exact(raw, ['workdir','confirm', ...(raw.timeoutMs === undefined ? [] : ['timeoutMs']), ...(raw.signal === undefined ? [] : ['signal'])]);
  const root = safePath(raw.workdir), expected = pin(raw.confirm), life = lifetime(raw);
  let backend;
  try {
    life.check(); const identity = await directory(root); const bytes = await readPrivate(join(root,'archive.json'), L.pageBytes);
    if (digest(bytes) !== expected) fail('pin_mismatch'); const m = manifest(canonical(bytes));
    backend = injected ?? await productionBackend({ href:m.href, token:'0'.repeat(64), timeoutMs:life.timeout, signal:life.signal }).catch(() => null);
    if (!backend?.validate) fail('validator_unavailable');
    return { ...(await validateArchive(root,m,life,identity,backend,true)), network_accessed:false, local_read_only:true };
  } finally { backend?.close?.(); life.close(); }
}

export async function exportPullArchive(raw, injected = null) {
  const allowed = ['workdir','href','tenant','repository','tokenFile','head','timeoutMs','signal','pageSize','maxPages','maxPulls','maxReviews','maxComments','maxArchiveBytes'];
  if (!raw || typeof raw !== 'object' || Array.isArray(raw) || Object.keys(raw).some(k => !allowed.includes(k))) fail('options');
  for (const k of ['workdir','href','tenant','repository','tokenFile']) if (!Object.hasOwn(raw,k)) fail('options');
  const o = { ...raw, workdir:safePath(raw.workdir), href:location(raw.href), tokenFile:safePath(raw.tokenFile), tenant:id32(raw.tenant), repository:id32(raw.repository),
    head: raw.head ?? null, pageSize:number(raw.pageSize ?? 10,1,100,'page_size'), maxPages:number(raw.maxPages ?? L.pages,1,L.pages,'pages'),
    maxPulls:number(raw.maxPulls ?? L.pulls,1,L.pulls,'pulls'), maxReviews:number(raw.maxReviews ?? L.reviews,0,L.reviews,'reviews'),
    maxComments:number(raw.maxComments ?? L.comments,0,L.comments,'comments'), maxArchiveBytes:number(raw.maxArchiveBytes ?? L.bytes,1,L.bytes,'bytes') };
  if (o.head !== null) snapshot(o.head); const life = lifetime(o); let backend, created=false, rootDigest=null;
  try {
    life.check(); if (await realpath(dirname(o.workdir)) !== dirname(o.workdir)) fail('parent_alias');
    await directory(dirname(o.workdir)); if (await realpath(o.tokenFile) !== o.tokenFile) fail('token_alias');
    try { await lstat(o.workdir); fail('record_exists'); } catch (e) { if (e.code !== 'ENOENT') throw e; }
    const token = await readPrivate(o.tokenFile, 65); let tokenText;
    try { tokenText = token.toString('ascii').replace(/\n$/,''); if (!/^[0-9a-f]{64}$/.test(tokenText)) fail('token'); }
    finally { token.fill(0); }
    backend = injected ?? await productionBackend({ href:o.href, token:tokenText, timeoutMs:life.timeout, signal:life.signal });
    await mkdir(o.workdir,{mode:0o700}); created=true; await syncDirectory(dirname(o.workdir)); const identity=await directory(o.workdir);
    const pages=[]; let dataBytes=0, pulls=0,reviews=0,comments=0, head=o.head, source=null, scope=null, after=0;
    const save = async (kind, numberValue, cursor, checked) => {
      life.check(); const reply=checked.reply, bytes=encode(reply); if (bytes.length>L.pageBytes || ++save.count>o.maxPages) fail('page_limit');
      dataBytes += bytes.length; if (dataBytes > o.maxArchiveBytes) fail('archive_limit');
      if (checked.head !== null) head = checked.head; scope=checked.binding;
      if (reply.source_head !== null) { sourceHead(reply.source_head); if (source !== null && source !== reply.source_head) fail('source_head_changed'); source=reply.source_head; }
      await directory(o.workdir,identity); await writeNew(join(o.workdir,pageName(pages.length)),bytes); pages.push(descriptor(kind,numberValue,cursor,bytes)); return reply;
    }; save.count=0;
    for (;;) {
      const list=await backend.list({after,limit:o.pageSize,head}); const reply=await save('list',null,after,list);
      for (const row of reply.pull_requests) {
        if (++pulls>o.maxPulls) fail('pull_limit'); const n=row.number;
        await save('show',n,0,await backend.show(n,head));
        let reviewer=null; do { const r=await save('reviews',n,reviewer,await backend.reviews(n,{after:reviewer,limit:o.pageSize,head})); reviews+=r.reviews.length; if(reviews>o.maxReviews) fail('review_limit'); reviewer=r.next_after; } while(reviewer!==null);
        let commentAfter=0; do { const c=await save('comments',n,commentAfter,await backend.comments(n,{after:commentAfter,limit:o.pageSize,head,render:false})); comments+=c.comments.length; if(comments>o.maxComments) fail('comment_limit'); commentAfter=c.next_after; } while(commentAfter!==null);
      }
      if (reply.next_after===null) break; after=reply.next_after;
    }
    if (head===null || source===null || !scope) fail('empty_identity');
    if (scope.tenant!==o.tenant || scope.repository!==o.repository) fail('repository_mismatch');
    const m=manifest({schema:PULL_ARCHIVE_SCHEMA,href:o.href,tenant_id:o.tenant,repository_id:o.repository,repository_incarnation:scope.incarnation,
      object_format:scope.format,snapshot_token:head,source_head:source,page_size:o.pageSize,pull_count:pulls,review_count:reviews,comment_count:comments,data_bytes:dataBytes,pages});
    const bytes=encode(m); rootDigest=digest(bytes); if(bytes.length>L.pageBytes || dataBytes+bytes.length>o.maxArchiveBytes) fail('archive_limit');
    await validateArchive(o.workdir,m,life,identity,backend,false); await writeNew(join(o.workdir,'archive.json'),bytes);
    return {type:'forge_pull_archive_exported',workdir:o.workdir,archive_sha256:rootDigest,pulls,reviews,comments,pages:pages.length,data_bytes:dataBytes,
      snapshot_token:head,source_head:source,complete:true,canonical_backup:false,merge_authority:false,mutation_submitted:false};
  } catch (error) { error.archive_progress={workdir:o.workdir,directory_created:created,expected_archive_sha256:rootDigest,complete:false,mutation_submitted:false}; throw error; }
  finally { backend?.close?.(); life.close(); }
}
