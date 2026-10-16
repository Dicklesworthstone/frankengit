// Restartable read custody, not a native mutation or a canonical backup. Selection
// and page/checkpoint slots are immutable. O_EXCL arbitrates concurrent collectors;
// no stale lock is stolen and no damaged file is silently repaired or overwritten.
import { mkdir, lstat, realpath, opendir } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { PullArchiveWalk, createPullArchiveBackend, readPullArchivePage } from './forge-pull-archive-protocol.mjs';
import { PULL_ARCHIVE_LIMITS as L, archiveOptions, encode, digest, fail, number, pin, id32,
  snapshot, sourceHead, exact, safePath, location, canonical, pageName, directory,
  syncDirectory, readPrivate, writeNew, lifetime, buildManifest, sealArchive } from './forge-pull-archive-store.mjs';

const SCHEMA = 'frankengit-pull-capture-v1', PAGE_SCHEMA = 'frankengit-pull-capture-page-v1';
const SELECTION_BYTES = 16384, RECORD_BYTES = 1024;
const FIELDS = ['schema','href','tenant_id','repository_id','repository_incarnation','object_format',
  'snapshot_token','source_head','page_size','max_pages','max_pulls','max_reviews','max_comments',
  'max_archive_bytes','credential_sha256','first_page_sha256'];
function selection(raw) {
  exact(raw,FIELDS); if (raw.schema !== SCHEMA) fail('capture_schema');
  location(raw.href); for (const k of ['tenant_id','repository_id','repository_incarnation']) id32(raw[k]);
  if (!['sha1','sha256'].includes(raw.object_format)) fail('format');
  snapshot(raw.snapshot_token); sourceHead(raw.source_head);
  pin(raw.credential_sha256); pin(raw.first_page_sha256);
  for (const [key,min,max] of [['page_size',1,100],['max_pages',1,L.pages],['max_pulls',1,L.pulls],
    ['max_reviews',0,L.reviews],['max_comments',0,L.comments],['max_archive_bytes',1,L.bytes]]) number(raw[key],min,max,key);
  return raw;
}
const limits = s => ({pages:s.max_pages,pulls:s.max_pulls,reviews:s.max_reviews,comments:s.max_comments});
const options = s => ({href:s.href,tenant:s.tenant_id,repository:s.repository_id,pageSize:s.page_size});
function walker(s) {
  return new PullArchiveWalk({...options(s),head:s.snapshot_token,source:s.source_head,
    scope:{tenant:s.tenant_id,repository:s.repository_id,incarnation:s.repository_incarnation,format:s.object_format},limits:limits(s)});
}
async function credential(path) {
  safePath(path); if (await realpath(path) !== path) fail('token_alias');
  const bytes = await readPrivate(path,65);
  try { const token = bytes.toString('utf8').replace(/\n$/,''); if (!/^[0-9a-f]{64}$/.test(token)) fail('token'); return token; }
  finally { bytes.fill(0); }
}
async function absent(path) {
  try { await lstat(path); fail('record_exists'); } catch (error) { if (error.code !== 'ENOENT') throw error; }
}
async function job(root) {
  const identity = await directory(root), expected = new Set(['selection.json','archive','journal']);
  for await (const entry of await opendir(root)) if (!expected.delete(entry.name)) fail('capture_unexpected_file');
  if (expected.size) fail('capture_missing_file');
  return {root:identity,archive:await directory(join(root,'archive')),journal:await directory(join(root,'journal'))};
}
async function guard(root, ids) {
  await directory(root,ids.root); await directory(join(root,'archive'),ids.archive); await directory(join(root,'journal'),ids.journal);
}
async function inventory(path, maximum, allowRoot, life) {
  const names = []; let sealed = false;
  for await (const entry of await opendir(path)) {
    life.check();
    if (allowRoot && entry.name === 'archive.json') { sealed = true; continue; }
    if (!/^page-[0-9]{6}\.json$/.test(entry.name) || names.length >= maximum) fail('capture_inventory');
    names.push(entry.name);
  }
  names.sort(); if (names.some((name,i) => name !== pageName(i))) fail('capture_gap');
  return {count:names.length,sealed};
}
function pageRecord(index, previous, page) {
  return {schema:PAGE_SCHEMA,sequence:index+1,previous_sha256:previous,page};
}
function pageDescriptor(request, bytes) { return {...request,sha256:digest(bytes),bytes:bytes.length}; }
async function checkpoint(root, index, previous, page) {
  const bytes = encode(pageRecord(index,previous,page));
  if (bytes.length > RECORD_BYTES) fail('capture_record_limit');
  await writeNew(join(root,'journal',pageName(index)),bytes); return digest(bytes);
}
async function load(root, confirm, life, synchronize = false) {
  life.check(); const ids = await job(root);
  const selectedBytes = await readPrivate(join(root,'selection.json'),SELECTION_BYTES,synchronize,life.check);
  if (digest(selectedBytes) !== confirm) fail('capture_pin_mismatch');
  const s = selection(canonical(selectedBytes));
  const data = await inventory(join(root,'archive'),s.max_pages,true,life);
  const records = await inventory(join(root,'journal'),s.max_pages,false,life);
  if (records.count > data.count || data.count > records.count + 1) fail('capture_checkpoint_gap');
  const walk = walker(s), pages = []; let tip = confirm, dataBytes = 0, tail = null;
  for (let i = 0; i < data.count; i++) {
    life.check(); await guard(root,ids);
    const raw = await readPrivate(join(root,'archive',pageName(i)),L.pageBytes,synchronize,life.check);
    const desc = pageDescriptor(walk.request,raw);
    if (i === 0 && desc.sha256 !== s.first_page_sha256) fail('capture_first_page_changed');
    if (i < records.count) {
      const bytes = await readPrivate(join(root,'journal',pageName(i)),RECORD_BYTES,synchronize,life.check);
      const record = canonical(bytes); exact(record,['schema','sequence','previous_sha256','page']);
      exact(record.page,['kind','number','cursor','sha256','bytes']);
      // Fixed encoding commits both the previous checkpoint and exact next request.
      if (!encode(pageRecord(i,tip,desc)).equals(bytes)) fail('capture_page_commitment');
      tip = digest(bytes);
    } else tail = {raw,desc,index:i,previous:tip};
    walk.accept(desc,canonical(raw)); pages.push(desc); dataBytes += raw.length;
    if (dataBytes > s.max_archive_bytes) fail('archive_limit');
  }
  let archiveSha = null;
  if (data.sealed) {
    if (tail) fail('capture_uncommitted_root');
    const m = buildManifest(options(s),walk.finish(),pages,dataBytes), expected = encode(m);
    const bytes = await readPrivate(join(root,'archive','archive.json'),L.manifestBytes,synchronize,life.check);
    if (!bytes.equals(expected) || bytes.length + dataBytes > s.max_archive_bytes) fail('capture_root_mismatch');
    archiveSha = digest(bytes);
  }
  life.check(); await guard(root,ids);
  return {root,confirm,s,ids,walk,pages,dataBytes,tip,tail,records:records.count,archiveSha};
}
function summary(state) {
  const {root,confirm,s,walk,pages,dataBytes,tip,tail,records,archiveSha} = state;
  const {pulls,reviews,comments} = walk.state;
  return {type:'forge_pull_capture',workdir:root,selection_sha256:confirm,checkpoint_sha256:tip,
    archive_workdir:join(root,'archive'),archive_sha256:archiveSha,snapshot_token:s.snapshot_token,
    source_head:s.source_head,tenant_id:s.tenant_id,repository_id:s.repository_id,
    repository_incarnation:s.repository_incarnation,object_format:s.object_format,
    pages:pages.length,checkpointed_pages:records,pulls,reviews,comments,data_bytes:dataBytes,
    uncommitted_tail:tail !== null,ready_to_seal:!archiveSha && !tail && walk.request === null,
    status:archiveSha?'complete':'paused',complete:archiveSha !== null,
    canonical_backup:false,merge_authority:false,mutation_submitted:false};
}
function invocation(raw, resume) {
  const allowed = ['workdir','confirm','timeoutMs','signal',...(resume?['tokenFile','pageBudget']:[])];
  if (!raw || typeof raw !== 'object' || Array.isArray(raw) || Object.keys(raw).some(k => !allowed.includes(k)) ||
      !Object.hasOwn(raw,'workdir') || !Object.hasOwn(raw,'confirm')) fail('capture_options');
  return {root:safePath(raw.workdir),confirm:pin(raw.confirm),budget:resume?number(raw.pageBudget??128,1,L.pages,'page_budget'):0};
}

// Select a source snapshot once and retain the first page, original credential
// fingerprint and all cumulative limits. Never put the token in local custody.
export async function preparePullCapture(raw) {
  const o = archiveOptions(raw), life = lifetime(o); let backend, confirm = null, created = false;
  try {
    life.check(); await directory(dirname(o.workdir)); await absent(o.workdir);
    const token = await credential(o.tokenFile);
    backend = await createPullArchiveBackend({href:o.href,token,timeoutMs:life.timeout,signal:life.signal});
    const walk = new PullArchiveWalk({tenant:o.tenant,repository:o.repository,pageSize:o.pageSize,head:o.head,
      limits:{pages:o.maxPages,pulls:o.maxPulls,reviews:o.maxReviews,comments:o.maxComments}});
    const request = walk.request, reply = (await readPullArchivePage(backend,request,o.pageSize,o.head)).reply;
    life.check(); walk.accept(request,reply); const bytes = encode(reply), first = pageDescriptor(request,bytes);
    if (bytes.length > L.pageBytes || bytes.length > o.maxArchiveBytes) fail('archive_limit');
    const {head,source,scope} = walk.state;
    const s = selection({schema:SCHEMA,href:o.href,tenant_id:o.tenant,repository_id:o.repository,
      repository_incarnation:scope.incarnation,object_format:scope.format,snapshot_token:head,source_head:source,
      page_size:o.pageSize,max_pages:o.maxPages,max_pulls:o.maxPulls,max_reviews:o.maxReviews,max_comments:o.maxComments,
      max_archive_bytes:o.maxArchiveBytes,credential_sha256:digest(Buffer.from(token)),first_page_sha256:first.sha256});
    const selected = encode(s); confirm = digest(selected);
    if (selected.length > SELECTION_BYTES) fail('capture_selection_limit');
    await mkdir(o.workdir,{mode:0o700}); created = true; await syncDirectory(dirname(o.workdir));
    await mkdir(join(o.workdir,'archive'),{mode:0o700}); await mkdir(join(o.workdir,'journal'),{mode:0o700});
    await syncDirectory(o.workdir); life.check(); await writeNew(join(o.workdir,'selection.json'),selected);
    life.check(); await writeNew(join(o.workdir,'archive',pageName(0)),bytes);
    await checkpoint(o.workdir,0,confirm,first);
    return {...summary(await load(o.workdir,confirm,life)),type:'forge_pull_capture_prepared',network_accessed:true,new_requests:1};
  } catch (cause) {
    const error = cause instanceof Error ? cause : new Error('pull_capture_interrupted');
    error.capture_progress = {workdir:o.workdir,directory_created:created,selection_sha256:confirm,complete:false,mutation_submitted:false}; throw error;
  } finally { try { backend?.close(); } finally { life.close(); } }
}

export async function inspectPullCapture(raw) {
  const {root,confirm} = invocation(raw,false), life = lifetime(raw);
  try { return {...summary(await load(root,confirm,life)),network_accessed:false,local_read_only:true,new_requests:0}; }
  finally { life.close(); }
}

export async function resumePullCapture(raw) {
  const {root,confirm,budget} = invocation(raw,true), life = lifetime(raw); let state, backend, requests = 0;
  try {
    state = await load(root,confirm,life,true);
    if (state.archiveSha) return {...summary(state),network_accessed:false,new_requests:0};
    const {s} = state;
    if (state.tail || state.walk.request !== null) {
      // Validate every retained page and checkpoint before reading a credential,
      // connecting, or making any next-page request.
      const token = await credential(raw.tokenFile);
      if (digest(Buffer.from(token)) !== s.credential_sha256) fail('capture_credential_changed');
      backend = await createPullArchiveBackend({href:s.href,token,timeoutMs:life.timeout,signal:life.signal});
    }
    if (state.tail) {
      const tail = state.tail; requests++;
      const reply = (await readPullArchivePage(backend,tail.desc,s.page_size,s.snapshot_token)).reply;
      life.check(); if (!encode(reply).equals(tail.raw)) fail('capture_uncommitted_page_changed');
      await guard(root,state.ids);
      state.tip = await checkpoint(root,tail.index,tail.previous,tail.desc); state.records++; state.tail = null;
    }
    while (state.walk.request !== null && requests < budget) {
      life.check(); if (state.pages.length >= s.max_pages) fail('page_limit');
      const request = state.walk.request; requests++;
      const reply = (await readPullArchivePage(backend,request,s.page_size,s.snapshot_token)).reply;
      life.check(); const bytes = encode(reply), desc = pageDescriptor(request,bytes);
      if (bytes.length > L.pageBytes || state.dataBytes + bytes.length > s.max_archive_bytes) fail('archive_limit');
      if (state.pages.length === 0 && desc.sha256 !== s.first_page_sha256) fail('capture_first_page_changed');
      state.walk.accept(desc,reply); await guard(root,state.ids);
      await writeNew(join(root,'archive',pageName(state.pages.length)),bytes);
      state.tip = await checkpoint(root,state.pages.length,state.tip,desc);
      state.pages.push(desc); state.dataBytes += bytes.length; state.records++;
    }
    if (state.walk.request === null) {
      // Verify the retained journal again, then publish the ordinary v1 archive
      // root only after the shared complete-file validator succeeds.
      state = await load(root,confirm,life,true);
      if (state.tail) fail('capture_uncommitted_root');
      if (!state.archiveSha) {
        const m = buildManifest(options(s),state.walk.finish(),state.pages,state.dataBytes);
        if (encode(m).length + state.dataBytes > s.max_archive_bytes) fail('archive_limit');
        const result = await sealArchive(join(root,'archive'),m,life,state.ids.archive);
        state.archiveSha = result.archive_sha256;
      }
    }
    life.check(); return {...summary(state),network_accessed:requests>0,new_requests:requests};
  } catch (cause) {
    const error = cause instanceof Error ? cause : new Error('pull_capture_interrupted');
    error.capture_progress = {workdir:root,selection_sha256:confirm,selection_verified:Boolean(state),
      checkpoint_sha256:state?.tip??null,new_requests:requests,complete:false,mutation_submitted:false}; throw error;
  } finally { try { backend?.close(); } finally { life.close(); } }
}
