// A complete, bounded server-produced source archive. These checks bind the
// response to the selected directory and requested encoding; they do not
// cryptographically validate or extract archive entries.
export const MAX_SOURCE_ARCHIVE_BYTES = 128 * 1024 * 1024;

// Cancellation closes local reads immediately. Its underlying cleanup promise
// may never settle, so observe rejection without allowing cleanup to hide the
// original refusal or extend the request deadline. No server write is involved.
export function cancelSourceBody(body) {
  if (body) void body.cancel().catch(() => {});
}

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
  const archiveFormat = expected?.archiveFormat ?? 'tar';
  if (!Number.isSafeInteger(maximum) || maximum < 1 || maximum > MAX_SOURCE_ARCHIVE_BYTES ||
      !expected || !['sha1', 'sha256'].includes(expected.format) ||
      !['tar', 'zip'].includes(archiveFormat) ||
      typeof expected.head !== 'string' || !/^alg:[1-9][0-9]{0,4}:(?:[0-9a-f]{2}){16,64}$/.test(expected.head) ||
      Number(expected.head.split(':')[1]) > 65535 || /^0+$/.test(expected.head.split(':')[2])) {
    throw new Error('Source archive requires a selected snapshot and a bounded byte limit.');
  }
  const zip = archiveFormat === 'zip';
  const profile = zip ? 'zip-store-source-v1' : 'ustar-source-v1';
  const mediaType = zip ? 'application/zip' : 'application/x-tar';
  const filename = zip ? 'source.zip' : 'source.tar';
  const mediaPattern = zip ? /^application\/zip(?:\s*;|$)/i : /^application\/x-tar(?:\s*;|$)/i;
  const dispositionPattern = zip ? /^attachment;\s*filename=(?:"source\.zip"|source\.zip)$/i
    : /^attachment;\s*filename=(?:"source\.tar"|source\.tar)$/i;
  if (!mediaPattern.test(headers.get('Content-Type') ?? '') ||
      !dispositionPattern.test(headers.get('Content-Disposition') ?? '') ||
      !['', 'identity'].includes((headers.get('Content-Encoding') ?? '').trim().toLowerCase()) ||
      !(headers.get('Cache-Control') ?? '').split(',').some(part => part.trim().toLowerCase() === 'no-store') ||
      headers.get('X-FrankenGit-Archive-Profile') !== profile) {
    throw new Error('Unsupported source archive response headers or profile.');
  }
  const bytes = integer(headers.get('Content-Length'), 'length', maximum);
  const maximumEntries = zip ? 65_535 : 100_000;
  const entries = integer(headers.get('X-FrankenGit-Archive-Entries'), 'entry count', maximumEntries);
  const gitlinks = integer(headers.get('X-FrankenGit-Archive-Gitlinks'), 'gitlink count', maximumEntries);
  // Both profiles include source/. TAR additionally has aligned blocks; ZIP
  // includes a local header, central header and end record even when empty.
  // This is envelope framing only, not authentication of member bytes.
  if (bytes < (zip ? 112 : 1536) || (!zip && bytes % 512 !== 0) || entries === 0 || gitlinks >= entries) {
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
    archiveFormat, profile, mediaType, filename };
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
    cancel = () => cancelSourceBody(reader);
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
      cancelSourceBody(reader);
      reader.releaseLock();
    } else {
      cancelSourceBody(response.body);
    }
  }
}
