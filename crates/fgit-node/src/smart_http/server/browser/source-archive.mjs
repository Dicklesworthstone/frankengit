// A complete, bounded server-produced source archive. These checks bind the
// response to the selected directory; they are not cryptographic tar validation.
export const MAX_SOURCE_ARCHIVE_BYTES = 128 * 1024 * 1024;
const MAX_ARCHIVE_ENTRIES = 100_000;

function integer(value, field, maximum) {
  if (typeof value !== 'string' || value.length > 16 || !/^(0|[1-9][0-9]*)$/.test(value) ||
      !Number.isSafeInteger(Number(value)) || Number(value) > maximum) {
    throw new Error('Invalid or excessive source archive ' + field + '.');
  }
  return Number(value);
}
function objectId(value, format) {
  if (typeof value !== 'string' || !['sha1', 'sha256'].includes(format)) throw new Error('Invalid source archive object identity.');
  const prefix = format + ':', raw = value.startsWith(prefix) ? value.slice(prefix.length) : value;
  if (!new RegExp('^[0-9a-f]{' + (format === 'sha1' ? 40 : 64) + '}$').test(raw) || /^0+$/.test(raw)) {
    throw new Error('Invalid source archive object identity.');
  }
  return raw;
}
export function sourceArchiveMetadata(headers, expected, maximum = MAX_SOURCE_ARCHIVE_BYTES) {
  if (!Number.isSafeInteger(maximum) || maximum < 1 || maximum > MAX_SOURCE_ARCHIVE_BYTES ||
      !expected || !['sha1', 'sha256'].includes(expected.format) ||
      typeof expected.head !== 'string' || !/^alg:[1-9][0-9]{0,4}:(?:[0-9a-f]{2}){16,64}$/.test(expected.head) ||
      Number(expected.head.split(':')[1]) > 65535 || /^0+$/.test(expected.head.split(':')[2])) {
    throw new Error('Source archive requires a selected snapshot and a bounded byte limit.');
  }
  if (!/^application\/x-tar(?:\s*;|$)/i.test(headers.get('Content-Type') ?? '') ||
      !/^attachment;\s*filename=(?:"source\.tar"|source\.tar)$/i.test(headers.get('Content-Disposition') ?? '') ||
      !['', 'identity'].includes((headers.get('Content-Encoding') ?? '').trim().toLowerCase()) ||
      !(headers.get('Cache-Control') ?? '').split(',').some(part => part.trim().toLowerCase() === 'no-store') ||
      headers.get('X-FrankenGit-Archive-Profile') !== 'ustar-source-v1') {
    throw new Error('Unsupported source archive response headers or profile.');
  }
  const bytes = integer(headers.get('Content-Length'), 'length', maximum);
  const entries = integer(headers.get('X-FrankenGit-Archive-Entries'), 'entry count', MAX_ARCHIVE_ENTRIES);
  const gitlinks = integer(headers.get('X-FrankenGit-Archive-Gitlinks'), 'gitlink count', MAX_ARCHIVE_ENTRIES);
  // The closed profile always has its root header and two terminal blocks.
  // This is envelope framing only; it does not authenticate tar entry bytes.
  if (bytes < 1536 || bytes % 512 !== 0 || entries === 0 || gitlinks >= entries) {
    throw new Error('Invalid source archive framing or entry counts.');
  }
  const head = headers.get('X-FrankenGit-Snapshot-Token');
  const commit = objectId(headers.get('X-FrankenGit-Source-Commit'), expected.format);
  const rootTree = objectId(headers.get('X-FrankenGit-Root-Tree'), expected.format);
  const selectedTree = objectId(headers.get('X-FrankenGit-Selected-Tree'), expected.format);
  if (head !== expected.head || commit !== objectId(expected.commit, expected.format) ||
      rootTree !== objectId(expected.rootTree, expected.format) || selectedTree !== objectId(expected.selectedTree, expected.format)) {
    throw new Error('Source archive snapshot or selected directory changed. Reopen the reference.');
  }
  return { format: expected.format, head, commit, rootTree, selectedTree, length: bytes, entries, gitlinks,
    profile: 'ustar-source-v1' };
}

// Allocate only after validating the declared length. One operation owns the
// response reader, all chunks and the caller's original deadline/cancellation.
// Nothing is returned until the complete response has arrived at that same pin.
export async function collectSourceArchive(response, expected,
  { signal = null, checkpoint = () => {}, maxBytes = MAX_SOURCE_ARCHIVE_BYTES } = {}) {
  let reader = null, cancel = null;
  const check = () => { signal?.throwIfAborted(); checkpoint(); };
  try {
    check();
    if (response.status !== 200 || response.redirected) throw new Error('Source archive response was not a direct successful read.');
    const metadata = sourceArchiveMetadata(response.headers, { ...expected }, maxBytes);
    if (!response.body) throw new Error('Empty source archive response.');
    reader = response.body.getReader();
    cancel = () => { void reader.cancel().catch(() => {}); };
    signal?.addEventListener('abort', cancel, { once: true });
    check();
    const bytes = new Uint8Array(metadata.length);
    let offset = 0;
    while (true) {
      const next = await reader.read();
      check();
      if (next.done) break;
      if (!(next.value instanceof Uint8Array) || next.value.byteLength > bytes.length - offset) {
        throw new Error('Source archive exceeded its declared response length.');
      }
      bytes.set(next.value, offset);
      offset += next.value.byteLength;
    }
    if (offset !== metadata.length) throw new Error('Truncated source archive response. No partial download is available.');
    check();
    return { ...metadata, bytes };
  } finally {
    if (cancel) signal?.removeEventListener('abort', cancel);
    if (reader) {
      await reader.cancel().catch(() => {});
      reader.releaseLock();
    } else {
      await response.body?.cancel().catch(() => {});
    }
  }
}
