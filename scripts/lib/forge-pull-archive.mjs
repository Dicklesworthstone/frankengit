// Complete, bounded native PR observations. These files never grant authority.
import { dirname, join } from 'node:path';
import { mkdir, lstat, realpath } from 'node:fs/promises';
import { PullArchiveWalk, createPullArchiveBackend, readPullArchivePage } from './forge-pull-archive-protocol.mjs';
import { PULL_ARCHIVE_LIMITS as L, encode, digest, fail, pin, exact, safePath, canonical,
  pageName, directory, syncDirectory, readPrivate, writeNew, lifetime, manifest,
  validateArchive, archiveOptions, buildManifest, sealArchive } from './forge-pull-archive-store.mjs';
export { PULL_ARCHIVE_SCHEMA, PULL_ARCHIVE_LIMITS } from './forge-pull-archive-store.mjs';

export async function inspectPullArchive(raw) {
  exact(raw, ['workdir','confirm', ...(raw.timeoutMs === undefined ? [] : ['timeoutMs']), ...(raw.signal === undefined ? [] : ['signal'])]);
  const root = safePath(raw.workdir), expected = pin(raw.confirm), life = lifetime(raw);
  try {
    life.check(); const identity = await directory(root);
    const bytes = await readPrivate(join(root,'archive.json'), L.manifestBytes);
    if (digest(bytes) !== expected) fail('pin_mismatch'); const m = manifest(canonical(bytes));
    return { ...(await validateArchive(root,m,life,identity,true)), network_accessed:false, local_read_only:true };
  } finally { life.close(); }
}

export async function exportPullArchive(raw, injected = null) {
  const o = archiveOptions(raw); const life = lifetime(o); let backend, created=false, rootDigest=null;
  try {
    life.check(); if (await realpath(dirname(o.workdir)) !== dirname(o.workdir)) fail('parent_alias');
    await directory(dirname(o.workdir)); if (await realpath(o.tokenFile) !== o.tokenFile) fail('token_alias');
    try { await lstat(o.workdir); fail('record_exists'); } catch (e) { if (e.code !== 'ENOENT') throw e; }
    const token = await readPrivate(o.tokenFile, 65); let tokenText;
    try { tokenText = token.toString('utf8').replace(/\n$/,''); if (!/^[0-9a-f]{64}$/.test(tokenText)) fail('token'); }
    finally { token.fill(0); }
    backend = injected ?? await createPullArchiveBackend({ href:o.href, token:tokenText, timeoutMs:life.timeout, signal:life.signal });
    await mkdir(o.workdir,{mode:0o700}); created=true; await syncDirectory(dirname(o.workdir)); const identity=await directory(o.workdir);
    const pages=[]; let dataBytes=0;
    const walk = new PullArchiveWalk({ tenant:o.tenant, repository:o.repository, pageSize:o.pageSize, head:o.head,
      limits:{ pages:o.maxPages, pulls:o.maxPulls, reviews:o.maxReviews, comments:o.maxComments } });
    while (walk.request !== null) {
      life.check(); if (pages.length >= o.maxPages) fail('page_limit');
      const request = walk.request, { kind, number:n, cursor } = request, head=walk.state.head;
      const checked = await readPullArchivePage(backend,request,o.pageSize,head);
      life.check(); const bytes=encode(checked.reply);
      if (bytes.length > L.pageBytes) fail('page_limit');
      if (dataBytes + bytes.length > o.maxArchiveBytes) fail('archive_limit');
      walk.accept(request,checked.reply);
      await directory(o.workdir,identity); await writeNew(join(o.workdir,pageName(pages.length)),bytes);
      pages.push({kind,number:n,cursor,sha256:digest(bytes),bytes:bytes.length}); dataBytes += bytes.length;
    }
    const m = buildManifest(o,walk.finish(),pages,dataBytes), bytes = encode(m);
    rootDigest = digest(bytes);
    if (bytes.length > L.manifestBytes || dataBytes + bytes.length > o.maxArchiveBytes) fail('archive_limit');
    return await sealArchive(o.workdir,m,life,identity);
  } catch (error) { error.archive_progress={workdir:o.workdir,directory_created:created,expected_archive_sha256:rootDigest,complete:false,mutation_submitted:false}; throw error; }
  finally { backend?.close?.(); life.close(); }
}
