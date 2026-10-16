// FG-049: consume the complete native PR read archive, never unverified snippets.
// The returned private bytes are observations, not permission to replay actors.
import { join } from 'node:path';
import { PULL_ARCHIVE_LIMITS as A, canonical, directory, digest, encode, fail, lifetime,
  manifest, number, pageName, pin, readPrivate, safePath, validateArchive }
  from './forge-pull-archive-store.mjs';

export async function readPullImportSource({ workdir, confirm, maxBytes = A.bytes, timeoutMs = 300000, signal }) {
  const root = safePath(workdir), selected = pin(confirm);
  number(maxBytes, 1, A.bytes, 'import_source_limit');
  const life = lifetime({ timeoutMs, ...(signal === undefined ? {} : { signal }) });
  try {
    life.check(); const identity = await directory(root);
    const manifestBytes = await readPrivate(join(root, 'archive.json'), A.manifestBytes, false, life.check);
    if (digest(manifestBytes) !== selected) fail('pin_mismatch');
    const m = manifest(canonical(manifestBytes));
    if (m.data_bytes + manifestBytes.length > maxBytes) fail('import_source_limit');
    await validateArchive(root, m, life, identity);
    // Never reread unchecked bytes after validating a mutable pathname. Each
    // owned page must match the original manifest commitment before release.
    const pages = [], entries = []; let current = null, size = manifestBytes.length;
    for (const [i, d] of m.pages.entries()) {
      life.check(); await directory(root, identity);
      const bytes = await readPrivate(join(root, pageName(i)), A.pageBytes, false, life.check);
      size += bytes.length;
      if (size > maxBytes || bytes.length !== d.bytes || digest(bytes) !== d.sha256) fail('page_commitment');
      const reply = canonical(bytes); pages.push(bytes);
      if (d.kind === 'show') {
        current = { row: reply.pull_request, reviews: [], comments: [] }; entries.push(current);
      } else if (d.kind === 'reviews') current.reviews.push(...reply.reviews);
      else if (d.kind === 'comments') current.comments.push(...reply.comments);
    }
    life.check(); await directory(root, identity);
    if (size !== m.data_bytes + encode(m).length) fail('page_commitment');
    return { manifest: m, manifestBytes, archiveSha256: selected, pages, entries, bytes: size };
  } finally { life.close(); }
}
