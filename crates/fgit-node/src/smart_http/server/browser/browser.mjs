// No framework, remote dependencies, HTML interpolation, or persistent credentials.
export const MAX_RESPONSE_BYTES = 8 * 1024 * 1024;
export const MAX_FILE_BYTES = 8 * 1024 * 1024;
const PAGE_BYTES = 64 * 1024;
const encoder = new TextEncoder();
const utf8 = () => new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });

export function unhex(value, maximum = MAX_RESPONSE_BYTES) {
  if (typeof value !== 'string' || value.length % 2 || value.length > maximum * 2 || !/^[0-9a-f]*$/.test(value)) {
    throw new Error('Invalid byte encoding in repository response.');
  }
  return Uint8Array.from(value.match(/../g) ?? [], pair => Number.parseInt(pair, 16));
}
export function hex(bytes) {
  return Array.from(bytes, byte => byte.toString(16).padStart(2, '0')).join('');
}
export function displayBytes(value) {
  const bytes = unhex(value);
  try {
    return utf8().decode(bytes).replace(/[\u0000-\u001f\u007f-\u009f\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069]/gu,
      character => `\\u{${character.codePointAt(0).toString(16)}}`);
  } catch {
    return Array.from(bytes, byte => byte >= 32 && byte <= 126
      ? String.fromCharCode(byte) : `\\x${byte.toString(16).padStart(2, '0')}`).join('');
  }
}
export function pathJoin(parent, name) {
  unhex(parent, 4096);
  const bytes = unhex(name, 4096);
  if (!bytes.length || bytes.includes(0) || bytes.includes(47) || name === '2e' || name === '2e2e') {
    throw new Error('Invalid directory entry name.');
  }
  const result = parent ? `${parent}2f${name}` : name;
  unhex(result, 4096);
  return result;
}
export function safeNumber(value, field) {
  if (!Number.isSafeInteger(value) || value < 0) throw new Error(`Unsupported or invalid ${field}.`);
  return value;
}
export function commitHex(value, format) {
  if (typeof value !== 'string') throw new Error('Missing selected commit.');
  const raw = value.startsWith(`${format}:`) ? value.slice(format.length + 1) : value;
  if (!['sha1', 'sha256'].includes(format) || !new RegExp(`^[0-9a-f]{${format === 'sha1' ? 40 : 64}}$`).test(raw) || /^0+$/.test(raw)) {
    throw new Error('Invalid selected commit.');
  }
  return raw;
}
export function snapshotOf(reply, selection, previous = null) {
  if (!reply || reply.schema_version !== 1 || reply.object_format !== selection.format || reply.read_only !== true ||
      reply.transaction_created !== false || reply.published !== false ||
      typeof reply.snapshot_token !== 'string' || !/^alg:[0-9]+:[0-9a-f]+$/.test(reply.snapshot_token)) {
    throw new Error('Unsupported source response or snapshot.');
  }
  const selected = { head: reply.snapshot_token, commit: commitHex(reply.source_commit, selection.format) };
  if (previous && (previous.head !== selected.head || previous.commit !== selected.commit)) {
    throw new Error('Snapshot changed. Reopen the reference rather than combining pages.');
  }
  return selected;
}

// A snapshot token is a native-server claim, not a locally authenticated root.
// Bind the complete disclosure scope as well as head/commit before using it.
export function sourceBinding(reply, selection, previous = null) {
  const pin = snapshotOf(reply, selection);
  const identity = value => {
    if (typeof value !== 'string' || !value.trim() || encoder.encode(value).length > 256 ||
        /[\u0000-\u001f\u007f-\u009f\uD800-\uDFFF]/u.test(value)) throw new Error('Invalid source identity.');
    return value;
  };
  if (!/^alg:[1-9][0-9]{0,4}:(?:[0-9a-f]{2}){16,64}$/.test(pin.head) ||
      Number(pin.head.split(':')[1]) > 65535 || /^0+$/.test(pin.head.split(':')[2]) ||
      reply.ref !== selection.reference || reply.ref_hex !== hex(encoder.encode(selection.reference))) {
    throw new Error('Source reference or snapshot identity changed.');
  }
  const value = { ...pin, tenant: identity(reply.tenant_id), repository: identity(reply.repository_id),
    incarnation: identity(reply.repository_incarnation), format: selection.format, referenceHex: reply.ref_hex,
    sourceHead: identity(reply.source_head), rcr: identity(reply.source_rcr), tree: commitHex(reply.root_tree, selection.format) };
  if (previous && Object.keys(value).some(key => previous[key] !== value[key])) {
    throw new Error('Repository identity or source snapshot changed. Reopen the reference.');
  }
  return value;
}
function checkedPath(path) {
  const bytes = unhex(path, 4096);
  if (!bytes.length || bytes.includes(0) || bytes[0] === 47 || bytes.at(-1) === 47) throw new Error('Invalid repository file path.');
  let start = 0, depth = 0;
  for (let end = 0; end <= bytes.length; end++) {
    if (end < bytes.length && bytes[end] !== 47) continue;
    const part = bytes.subarray(start, end);
    pathJoin('', hex(part));
    if (++depth > 64 || (part.length === 4 && Array.from(part, b => b >= 65 && b <= 90 ? b + 32 : b).join(',') === '46,103,105,116')) {
      throw new Error('Invalid repository file path component.');
    }
    start = end + 1;
  }
}
export function blobPage(reply, selection, source, path, offset, expected = null) {
  checkedPath(path); safeNumber(offset, 'file offset');
  const binding = sourceBinding(reply, selection, source);
  if (reply.type !== 'source_blob' || reply.path_hex !== path || reply.offset !== offset ||
      reply.symlink_followed !== false || !['file', 'executable', 'symlink'].includes(reply.kind)) {
    throw new Error('Invalid file response.');
  }
  const id = commitHex(reply.object_id, selection.format), total = safeNumber(reply.total_bytes, 'file length');
  if (expected && (id !== expected.id || reply.kind !== expected.kind ||
      (expected.total !== undefined && total !== expected.total))) throw new Error('Selected file identity, kind or length changed.');
  const bytes = unhex(reply.content_hex, PAGE_BYTES), end = offset + bytes.length;
  if (offset > total || !Number.isSafeInteger(end) || reply.returned_bytes !== bytes.length ||
      bytes.length !== Math.min(PAGE_BYTES, total - offset) || reply.next_offset !== (end < total ? end : null)) {
    throw new Error('Invalid file range or continuation.');
  }
  return { source: binding, path, id, kind: reply.kind, total, offset, next: reply.next_offset, bytes };
}
export async function verifyBlob(bytes, format, expected, cryptoImpl = globalThis.crypto, checkpoint = () => {}) {
  checkpoint();
  if (!(bytes instanceof Uint8Array) || bytes.length > MAX_FILE_BYTES) throw new Error('Complete file exceeds the 8 MiB browser verification limit.');
  const id = commitHex(expected, format);
  if (!cryptoImpl?.subtle?.digest) throw new Error('Native blob verification requires WebCrypto.');
  const header = encoder.encode(`blob ${bytes.length}\0`), framed = new Uint8Array(header.length + bytes.length);
  framed.set(header); framed.set(bytes, header.length);
  const actual = hex(new Uint8Array(await cryptoImpl.subtle.digest(format === 'sha1' ? 'SHA-1' : 'SHA-256', framed)));
  checkpoint();
  if (actual !== id) throw new Error('Native blob identity verification failed. No verified bytes are available.');
  return actual;
}


// Read from offset zero under the already selected source and file identity.
// Every page shares the caller's operation deadline; there is no retry, source
// refresh, permission inference, executable materialization or symlink traversal.
export async function collectVerifiedBlob(selection, source, path, expected, read,
  { cryptoImpl = globalThis.crypto, checkpoint = () => {}, maxBytes = MAX_FILE_BYTES } = {}) {
  if (!source || !expected || !Number.isSafeInteger(maxBytes) || maxBytes < 1 || maxBytes > MAX_FILE_BYTES) {
    throw new Error('Complete export requires a pinned source, file identity and bounded byte limit.');
  }
  checkedPath(path);
  const selected = { ...selection }, pinned = { ...source }, identity = { ...expected };
  if (identity.total !== undefined && safeNumber(identity.total, 'file length') > maxBytes) throw new Error('Complete export exceeds its byte limit.');
  commitHex(identity.id, selected.format);
  if (!['file', 'executable', 'symlink'].includes(identity.kind)) throw new Error('Unsupported export entry kind.');
  let output = null, offset = 0;
  for (let pages = 1; pages <= Math.max(1, Math.ceil(maxBytes / PAGE_BYTES)); pages++) {
    checkpoint();
    const reply = await read({ ...sourceFields(selected, pinned, path), offset: String(offset), limit: String(PAGE_BYTES) });
    checkpoint();
    const page = blobPage(reply, selected, pinned, path, offset, identity);
    if (page.total > maxBytes) throw new Error('Complete export exceeds its byte limit.');
    if (output === null) {
      identity.total = page.total;
      output = new Uint8Array(page.total);
    }
    output.set(page.bytes, offset);
    if (page.next === null) {
      await verifyBlob(output, selected.format, page.id, cryptoImpl, checkpoint);
      checkpoint();
      return { source: pinned, path, id: page.id, kind: page.kind, bytes: output, pages,
        blobVerified: true, authorityVerified: false };
    }
    offset = page.next;
  }
  throw new Error('Complete export exceeded its page limit.');
}

// Directory listings disclose kinds, not original mode bytes. Reconstruct only
// canonical Git modes; a legacy spelling must fail its hash, never be normalized
// into a verified claim. API byte-name order differs from Git's directory order.
export const PATH_PROOF_LIMITS = Object.freeze({ maxPages: 128, maxEntries: 12_800, maxBytes: 4 * 1024 * 1024 });
const TREE_MODES = Object.freeze({ file: '100644', executable: '100755', directory: '40000', symlink: '120000', gitlink: '160000' });
function proofEntry(row) {
  if (!row || typeof row !== 'object' || !Object.hasOwn(TREE_MODES, row.kind)) throw new Error('Unsupported tree entry kind.');
  checkedPath(row.name_hex);
  const name = unhex(row.name_hex, 4096);
  if (name.includes(47)) throw new Error('Tree entry must name one immediate child.');
  return { name, nameHex: row.name_hex, kind: row.kind, objectId: row.object_id, mode: TREE_MODES[row.kind] };
}
export async function verifyDirectory(entries, format, expected, cryptoImpl = globalThis.crypto, checkpoint = () => {}) {
  checkpoint();
  const id = commitHex(expected, format);
  if (!Array.isArray(entries) || entries.length > PATH_PROOF_LIMITS.maxEntries) throw new Error('Tree entry budget exceeded.');
  if (!cryptoImpl?.subtle?.digest) throw new Error('Native tree verification requires WebCrypto.');
  let size = 0;
  const names = new Set();
  const rows = entries.map(entry => {
    checkpoint();
    const row = proofEntry(entry), oid = unhex(commitHex(row.objectId, format), 32);
    if (names.has(row.nameHex)) throw new Error('Duplicate tree entry name.');
    names.add(row.nameHex);
    size += row.mode.length + row.name.length + 2 + oid.length;
    if (size > PATH_PROOF_LIMITS.maxBytes) throw new Error('Tree byte budget exceeded.');
    return { ...row, oid, order: row.nameHex + (row.kind === 'directory' ? '2f' : '00') };
  });
  rows.sort((a, b) => a.order < b.order ? -1 : a.order > b.order ? 1 : 0);
  const header = encoder.encode(`tree ${size}\0`), framed = new Uint8Array(header.length + size);
  framed.set(header); let offset = header.length;
  for (const row of rows) {
    checkpoint();
    const mode = encoder.encode(row.mode + ' ');
    framed.set(mode, offset); offset += mode.length;
    framed.set(row.name, offset); offset += row.name.length;
    framed[offset++] = 0; framed.set(row.oid, offset); offset += row.oid.length;
  }
  const actual = hex(new Uint8Array(await cryptoImpl.subtle.digest(format === 'sha1' ? 'SHA-1' : 'SHA-256', framed)));
  checkpoint();
  if (actual !== id) throw new Error('Directory listing does not reproduce its native tree identity; inconsistent data or unsupported original modes.');
  return { id, bytes: size, entries: rows.length };
}
// Verify EVERY containing directory from the selected root, not merely the last
// parent or a server-supplied file ID. All ancestors share one cumulative budget.
// This proves path inclusion relative to that root; it does not authenticate the
// root's association with the commit or an authority head, or confer read grants.
export async function verifyBlobPath(selection, source, path, expected, readTree,
  { cryptoImpl = globalThis.crypto, checkpoint = () => {}, limits = PATH_PROOF_LIMITS } = {}) {
  if (!source || !expected || !limits || typeof limits !== 'object' ||
      Object.keys(limits).some(key => !Object.hasOwn(PATH_PROOF_LIMITS, key))) throw new Error('Path proof requires a pinned source, file and bounded limits.');
  const bounds = { ...PATH_PROOF_LIMITS, ...limits };
  for (const key of Object.keys(bounds)) if (!Number.isSafeInteger(bounds[key]) || bounds[key] < 1 || bounds[key] > PATH_PROOF_LIMITS[key]) throw new Error('Invalid path-proof budget.');
  checkedPath(path);
  const selected = { ...selection }, pinned = { ...source }, wanted = { ...expected };
  const root = commitHex(pinned.tree, selected.format), target = commitHex(wanted.id, selected.format);
  if (!['file', 'executable', 'symlink'].includes(wanted.kind)) throw new Error('Path proof requires a file or symlink target.');
  const rawPath = unhex(path, 4096), components = []; let start = 0;
  for (let i = 0; i <= rawPath.length; i++) if (i === rawPath.length || rawPath[i] === 47) { components.push(hex(rawPath.subarray(start, i))); start = i + 1; }
  let parent = '', treeId = root, pages = 0, count = 0, bytes = 0;
  for (const [depth, name] of components.entries()) {
    const rows = []; let after = null;
    do {
      checkpoint();
      if (pages >= bounds.maxPages) throw new Error('Path-proof page budget exceeded.');
      pages++;
      const reply = await readTree({ ...sourceFields(selected, pinned, parent), limit: '100', ...(after === null ? {} : { after_hex: after }) });
      checkpoint(); sourceBinding(reply, selected, pinned);
      if (reply.type !== 'source_tree' || reply.path_hex !== (parent || null) || reply.after_hex !== after || reply.limit !== 100 ||
          commitHex(reply.object_id, selected.format) !== treeId || !Array.isArray(reply.entries) || reply.entries.length > 100) throw new Error('Path-proof directory selection or page changed.');
      let previous = after;
      for (const entry of reply.entries) {
        checkpoint();
        const row = proofEntry(entry), id = commitHex(row.objectId, selected.format);
        if (previous !== null && row.nameHex <= previous) throw new Error('Path-proof directory ordering changed.');
        previous = row.nameHex;
        if (++count > bounds.maxEntries) throw new Error('Path-proof entry budget exceeded.');
        bytes += row.mode.length + row.name.length + 2 + id.length / 2;
        if (bytes > bounds.maxBytes) throw new Error('Path-proof byte budget exceeded.');
        rows.push({ name_hex: row.nameHex, kind: row.kind, object_id: id });
      }
      if (reply.next_after_hex !== null && (reply.entries.length !== 100 || reply.next_after_hex !== previous)) throw new Error('Path-proof continuation is incomplete.');
      after = reply.next_after_hex;
    } while (after !== null);
    await verifyDirectory(rows, selected.format, treeId, cryptoImpl, checkpoint);
    const child = rows.find(entry => entry.name_hex === name);
    if (!child) throw new Error('Selected path is absent from the verified directory.');
    if (depth + 1 < components.length) {
      if (child.kind !== 'directory') throw new Error('Path proof never traverses symlinks, files or gitlinks.');
      treeId = child.object_id; parent = pathJoin(parent, name);
    } else if (child.object_id !== target || child.kind !== wanted.kind) throw new Error('Selected file is not the verified tree entry.');
  }
  checkpoint();
  return { rootTree: root, path, id: target, kind: wanted.kind, directories: components.length, pages, entries: count, bytes,
    pathVerified: true, authorityVerified: false };
}

// A bounded first history page carries the original selected commit, not a
// caller-addressable object lookup. Hash its EXACT bytes and bind its tree
// header before any path proof. This does not verify signatures, authors or the
// authority head. It deliberately makes no claim about unreturned ancestors.
export const COMMIT_PROOF_LIMITS = Object.freeze({ maxCommits: 4096, maxEdges: 16384,
  maxMetadataBytes: 4 * 1024 * 1024, maxCommitBytes: 64 * 1024, maxReplyBytes: 256 * 1024 });
export async function verifySourceCommit(selection, source, readLog,
  { cryptoImpl = globalThis.crypto, checkpoint = () => {} } = {}) {
  checkpoint();
  if (!selection || !source) throw new Error('Commit verification requires a pinned source.');
  const selected = { ...selection }, pinned = { ...source };
  const id = commitHex(pinned.commit, selected.format), root = commitHex(pinned.tree, selected.format);
  if (pinned.format !== selected.format || pinned.referenceHex !== hex(encoder.encode(selected.reference)) ||
      !pinned.head || !pinned.sourceHead || !pinned.tenant || !pinned.repository || !pinned.incarnation) {
    throw new Error('Incomplete pinned commit source.');
  }
  if (!cryptoImpl?.subtle?.digest) throw new Error('Native commit verification requires WebCrypto.');
  const reply = await readLog({ ...sourceFields(selected, pinned), after: '0', limit: '1',
    max_commits: String(COMMIT_PROOF_LIMITS.maxCommits), max_edges: String(COMMIT_PROOF_LIMITS.maxEdges),
    max_metadata_bytes: String(COMMIT_PROOF_LIMITS.maxMetadataBytes) });
  checkpoint();
  snapshotOf(reply, selected, pinned);
  if (reply.type !== 'source_log' || reply.tenant_id !== pinned.tenant || reply.repository_id !== pinned.repository ||
      reply.repository_incarnation !== pinned.incarnation || reply.source_head !== pinned.sourceHead ||
      reply.ref_hex !== pinned.referenceHex || reply.author_identity_verified !== false ||
      reply.ordering !== 'child-before-parent-native-id-v1' || reply.page_complete !== true ||
      reply.after !== 0 || reply.limit !== 1 || !Number.isSafeInteger(reply.total_commits) ||
      reply.total_commits < 1 || reply.total_commits > COMMIT_PROOF_LIMITS.maxCommits ||
      reply.next_after !== (reply.total_commits > 1 ? 1 : null) || !Array.isArray(reply.commits) || reply.commits.length !== 1) {
    throw new Error('Selected commit history envelope changed.');
  }
  const row = reply.commits[0];
  if (!row || typeof row !== 'object' || Array.isArray(row) || commitHex(row.object_id, selected.format) !== id ||
      commitHex(row.tree, selected.format) !== root || !Array.isArray(row.parents) || row.parents.length > COMMIT_PROOF_LIMITS.maxEdges) {
    throw new Error('Selected commit or root tree changed.');
  }
  const bytes = unhex(row.body_hex, COMMIT_PROOF_LIMITS.maxCommitBytes);
  // Snapshot all mutable response data before WebCrypto yields.
  const parents = row.parents.map(parent => commitHex(parent, selected.format));
  const header = encoder.encode(`commit ${bytes.length}\0`), framed = new Uint8Array(header.length + bytes.length);
  framed.set(header); framed.set(bytes, header.length);
  const actual = hex(new Uint8Array(await cryptoImpl.subtle.digest(selected.format === 'sha1' ? 'SHA-1' : 'SHA-256', framed)));
  checkpoint();
  if (actual !== id) throw new Error('Commit bytes do not reproduce the pinned native commit identity.');
  // Only reference headers are interpreted. Original identity, signature and
  // message bytes stay untouched; continued signature lines are not headers.
  let at = 0, tree = null, separated = false, referenceHeader = false;
  const rawParents = [];
  while (at < bytes.length) {
    checkpoint();
    const end = bytes.indexOf(10, at);
    if (end < 0) break;
    const line = bytes.subarray(at, end);
    if (!line.length) { separated = true; break; }
    const starts = text => Array.from(text, c => c.charCodeAt(0)).every((b, i) => line[i] === b);
    if (line[0] === 32) {
      if (referenceHeader) throw new Error('Continued commit reference header is unsupported.');
    } else {
      const isTree = starts('tree '), isParent = starts('parent ');
      referenceHeader = isTree || isParent;
      if (referenceHeader) {
        const raw = line.subarray(isTree ? 5 : 7);
        if (raw.length !== (selected.format === 'sha1' ? 40 : 64) ||
            !raw.every(b => (b >= 48 && b <= 57) || (b >= 65 && b <= 70) || (b >= 97 && b <= 102))) {
          throw new Error('Invalid native commit reference header.');
        }
        const value = String.fromCharCode(...raw).toLowerCase();
        if (isTree) {
          if (tree !== null || at !== 0) throw new Error('Ambiguous native commit tree.');
          tree = value;
        } else rawParents.push(value);
      }
    }
    at = end + 1;
  }
  if (!separated || tree !== root || rawParents.length !== parents.length ||
      rawParents.some((value, i) => value !== parents[i]) || parents.includes(id)) {
    throw new Error('Commit reference headers disagree with the selected source.');
  }
  checkpoint();
  return { commit: id, rootTree: root, commitBytes: bytes.length,
    commitVerified: true, rootTreeVerified: true, authorityVerified: false, authorIdentityVerified: false };
}

export function sourceFields(selection, snapshot, path = '') {
  if (!['sha1', 'sha256'].includes(selection.format) || !selection.reference.startsWith('refs/')) {
    throw new Error('Choose a full reference and an object format.');
  }
  const fields = { ref: selection.reference, object_format: selection.format };
  if (snapshot) Object.assign(fields, { expected_head: snapshot.head, expected_commit: snapshot.commit });
  if (path) { unhex(path, 4096); fields.path_hex = path; }
  return fields;
}
export function searchFields(selection, snapshot, text, matchCase = 'exact') {
  const bytes = encoder.encode(text);
  if (!bytes.length || bytes.length > 256 || bytes.includes(10) || bytes.includes(13) ||
      !['exact', 'ascii-insensitive'].includes(matchCase)) {
    throw new Error('Enter a nonempty single-line literal query of at most 256 UTF-8 bytes.');
  }
  return { ...sourceFields(selection, snapshot), needle_hex: hex(bytes), case: matchCase, max_matches: '100' };
}
export function searchRows(reply) {
  if (reply.type !== 'source_search' || reply.profile !== 'literal-bytes-v1' ||
      !Array.isArray(reply.matches) || reply.matches.length > 100 || reply.returned_matches !== reply.matches.length ||
      !['complete', 'match_limit'].includes(reply.completion) || reply.complete !== (reply.completion === 'complete')) {
    throw new Error('Invalid source search response.');
  }
  return reply.matches.map(row => {
    const path = unhex(row.path_hex, 4096);
    if (!path.length || path.includes(0) || path[0] === 47 || path.at(-1) === 47) throw new Error('Invalid search path.');
    // Validate each component, but retain the exact original byte path.
    let parent = '';
    const parts = [];
    let start = 0;
    for (let i = 0; i <= path.length; i += 1) {
      if (i === path.length || path[i] === 47) { parts.push(hex(path.slice(start, i))); start = i + 1; }
    }
    for (const part of parts) parent = pathJoin(parent, part);
    const offset = safeNumber(row.byte_offset, 'match offset');
    const line = safeNumber(row.line, 'line number');
    const column = safeNumber(row.byte_column, 'byte column');
    const length = safeNumber(row.match_length, 'match length');
    const excerptOffset = safeNumber(row.excerpt_offset, 'excerpt offset');
    const excerpt = unhex(row.excerpt_hex, 416);
    if (!line || !column || !length || length > 256 || offset < excerptOffset ||
        offset - excerptOffset + length > excerpt.length) throw new Error('Invalid search excerpt.');
    return { path: row.path_hex, name: displayBytes(row.path_hex), offset, line, column,
      excerpt: blobPreview(excerpt, excerptOffset).text };
  });
}
export async function boundedJson(response, maximum = MAX_RESPONSE_BYTES, signal = null) {
  if (!Number.isSafeInteger(maximum) || maximum < 1 || maximum > MAX_RESPONSE_BYTES) throw new Error('Invalid response byte limit.');
  const declared = response.headers.get('Content-Length');
  if (declared !== null && (declared.length > 20 || !/^(0|[1-9][0-9]*)$/.test(declared) || BigInt(declared) > BigInt(maximum))) {
    await response.body?.cancel(); throw new Error('Invalid or excessive API response length.');
  }
  if (!response.body) throw new Error('Empty API response.');
  const reader = response.body.getReader(), chunks = [];
  const cancel = () => { void reader.cancel().catch(() => {}); };
  signal?.addEventListener('abort', cancel, { once: true });
  let count = 0;
  try {
    signal?.throwIfAborted();
    while (true) {
      const next = await reader.read(); signal?.throwIfAborted();
      if (next.done) break;
      count += next.value.byteLength;
      if (count > maximum) throw new Error('API response exceeded the browser byte limit.');
      chunks.push(next.value);
    }
    if (declared !== null && BigInt(declared) !== BigInt(count)) throw new Error('Truncated or inconsistent API response length.');
    const bytes = new Uint8Array(count); let offset = 0;
    for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
    signal?.throwIfAborted();
    return JSON.parse(utf8().decode(bytes));
  } finally {
    signal?.removeEventListener('abort', cancel);
    await reader.cancel().catch(() => {});
    reader.releaseLock();
  }
}
export function blobPreview(bytes, offset) {
  try {
    const text = utf8().decode(bytes);
    // Rendering is textContent even for HTML/SVG. Other control bytes use a hex view.
    if (/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/u.test(text)) throw new Error('bytes');
    return { label: 'UTF-8 byte-range preview', text: text.replace(/[\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069]/gu,
      ch => `\\u{${ch.codePointAt(0).toString(16)}}`) };
  } catch {
    const lines = [];
    for (let i = 0; i < bytes.length; i += 16) {
      const row = bytes.slice(i, i + 16);
      lines.push(`${(offset + i).toString(16).padStart(12, '0')}  ${Array.from(row, b => b.toString(16).padStart(2, '0')).join(' ').padEnd(47)}  ${Array.from(row, b => b >= 32 && b < 127 ? String.fromCharCode(b) : '.').join('')}`);
    }
    return { label: 'Hex preview (binary data or a UTF-8 sequence crossing this page boundary)', text: lines.join('\n') };
  }
}

export function mount(document, location, fetcher = globalThis.fetch, options = {}) {
  const cryptoImpl = options.cryptoImpl ?? globalThis.crypto;
  const urlApi = options.urlApi ?? globalThis.URL;
  const timeoutMs = options.timeoutMs ?? 30_000;
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 300_000) throw new Error('Invalid read timeout.');
  const byId = id => document.getElementById(id);
  const apiRoot = new URL('../api/v1/source/', location.href);
  const pageUrl = new URL(location.href);
  if (apiRoot.origin !== location.origin || !location.pathname.endsWith('/ui/') ||
      !['https:', 'http:'].includes(pageUrl.protocol) || pageUrl.username || pageUrl.password || pageUrl.search || pageUrl.hash ||
      (pageUrl.protocol === 'http:' && !['127.0.0.1', 'localhost', '[::1]'].includes(pageUrl.hostname))) {
    throw new Error('Open the browser at this repository’s /ui/ endpoint.');
  }
  let token = '';
  let selection = null;
  let snapshot = null;
  let boundSource = null;
  let controller = null;
  let generation = 0;
  let downloadUrl = null, verifiedDownload = null;
  const cancelControl = byId('cancel-read');
  const clearDownload = () => {
    if (downloadUrl !== null) { urlApi.revokeObjectURL(downloadUrl); downloadUrl = null; }
    verifiedDownload = null;
  };
  const clear = () => { clearDownload(); ['content', 'paging', 'breadcrumbs', 'snapshot'].forEach(id => byId(id).replaceChildren()); };
  const node = (tag, text = '') => { const element = document.createElement(tag); element.textContent = text; return element; };
  const button = (text, action) => { const view = generation, element = node('button', text); element.type = 'button'; element.addEventListener('click', () => { if (view === generation) action(); }); return element; };
  const status = text => { byId('status').textContent = text; };
  function disconnect() {
    generation += 1;
    controller?.abort(); controller = null;
    token = ''; selection = null; snapshot = null; boundSource = null;
    if (cancelControl) cancelControl.disabled = true;
    byId('token').value = ''; byId('needle').value = ''; clear(); status('Disconnected. Repository data and token discarded.');
  }
  async function request(operation, fields, signal) {
    // This is an intentionally closed read-only operation set, despite POST framing.
    if (!['tree', 'blob', 'search', 'log'].includes(operation)) throw new Error('Unsupported browser operation.');
    signal.throwIfAborted();
    const url = new URL(operation, apiRoot);
    const response = await fetcher(url, {
      method: 'POST', mode: 'same-origin', credentials: 'omit', cache: 'no-store', redirect: 'error', referrerPolicy: 'no-referrer', signal,
      headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/x-www-form-urlencoded', Accept: 'application/json' },
      body: new URLSearchParams(fields),
    });
    if (signal.aborted || response.redirected || (response.url && response.url !== url.href)) {
      await response.body?.cancel(); signal.throwIfAborted(); throw new Error('Repository redirect refused.');
    }
    if (response.status !== 200) {
      await response.body?.cancel();
      if (response.status === 401) {
        const error = new Error('Token rejected or revoked. Enter a valid read token.');
        error.status = 401; throw error;
      }
      if (response.status === 409) throw new Error('The selected snapshot moved or this entry cannot be read. Reopen the reference.');
      if (response.status === 403) throw new Error('This token lacks read scope, or source browsing is disabled.');
      if (response.status === 404) throw new Error('Reference or path unavailable. Hidden refs are not disclosed.');
      if (response.status === 429) throw new Error('Read quota exceeded. Retry after the server’s quota window.');
      throw new Error(`Repository read failed (HTTP ${response.status}). No write was attempted.`);
    }
    if (!/^application\/json(?:\s*;|$)/i.test(response.headers.get('Content-Type') ?? '')) {
      await response.body?.cancel(); throw new Error('Unexpected API content type.');
    }
    return boundedJson(response, operation === 'blob' ? 3 * PAGE_BYTES : operation === 'log' ? COMMIT_PROOF_LIMITS.maxReplyBytes : MAX_RESPONSE_BYTES, signal);
  }
  async function runRead(work) {
    if (!token || !selection) { status('Enter a read-scoped token first.'); return; }
    const current = ++generation;
    controller?.abort(); controller = new AbortController();
    const active = controller;
    const deadline = performance.now() + timeoutMs;
    const timer = setTimeout(() => active.abort(new DOMException('Repository read timed out.', 'TimeoutError')), timeoutMs);
    const checkpoint = () => {
      active.signal.throwIfAborted();
      if (current !== generation) throw new DOMException('Read superseded.', 'AbortError');
      if (performance.now() >= deadline) throw new DOMException('Repository read timed out.', 'TimeoutError');
    };
    const selected = selection;
    const pinned = snapshot;
    clear(); if (cancelControl) cancelControl.disabled = false; status('Reading repository snapshot…');
    try {
      const accepted = await work(selected, pinned, boundSource, active.signal, checkpoint);
      checkpoint();
      snapshot = accepted.snapshot; boundSource = accepted.binding;
      byId('snapshot').textContent = `${selected.reference} · ${selected.format}\nCommit ${snapshot.commit}\nSnapshot ${snapshot.head}`;
      status(accepted.message ?? 'Read complete. All navigation remains pinned to this snapshot.');
    } catch (error) {
      if (current !== generation || error.name === 'AbortError') return;
      if (error.status === 401) disconnect();
      clear(); status(error.message);
    } finally {
      clearTimeout(timer);
      if (controller === active) { controller = null; if (cancelControl) cancelControl.disabled = true; }
    }
  }
  function run(operation, fields, render) {
    return runRead(async (selected, pinned, binding, signal, checkpoint) => {
      const reply = await request(operation, fields, signal);
      checkpoint();
      const observed = snapshotOf(reply, selected, pinned), source = sourceBinding(reply, selected, binding);
      await render(reply, source, checkpoint);
      return { snapshot: observed, binding: source };
    });
  }
  function cancel() {
    generation++; controller?.abort(); controller = null;
    if (cancelControl) cancelControl.disabled = true;
    clear(); status('Read canceled. No partial export or verified download was retained.');
  }
  function exportFile(page, verifyPath = false, verifyCommit = false) {
    const version = generation;
    void runRead(async (selected, pinned, binding, signal, checkpoint) => {
      if (version + 1 !== generation || !pinned || !binding) throw new Error('Reopen the selected file before exporting.');
      const commitProof = verifyCommit ? await verifySourceCommit(selected, page.source, fields => {
        checkpoint(); status('Verifying the original commit and its root tree before reading the path…');
        return request('log', fields, signal);
      }, { cryptoImpl, checkpoint }) : null;
      const proof = verifyPath || verifyCommit ? await verifyBlobPath(selected, page.source, page.path,
        { id: page.id, kind: page.kind }, fields => {
          checkpoint(); status('Verifying complete parent directories against the selected root tree…');
          return request('tree', fields, signal);
        }, { cryptoImpl, checkpoint }) : null;
      const verified = await collectVerifiedBlob(selected, page.source, page.path,
        { id: page.id, kind: page.kind, total: page.total },
        fields => {
          checkpoint(); status(`Reading complete file: ${fields.offset} of ${page.total} bytes. No download is available until verification finishes.`);
          return request('blob', fields, signal);
        }, { cryptoImpl, checkpoint });
      checkpoint();
      const view = generation;
      const download = button('Download verified file bytes', () => {
        if (generation !== view || verifiedDownload !== verified || !token) return;
        try {
          if (downloadUrl === null) downloadUrl = urlApi.createObjectURL(new Blob([verified.bytes], { type: 'application/octet-stream' }));
          const anchor = node('a'); anchor.href = downloadUrl;
          anchor.download = verified.kind === 'symlink' ? 'symlink-target.bin' : 'source.bin';
          anchor.rel = 'noopener'; byId('content').append(anchor); anchor.click(); anchor.remove();
        } catch { clearDownload(); status('Cannot create a download for the verified file.'); }
      });
      const preview = blobPreview(verified.bytes.subarray(0, PAGE_BYTES), 0);
      byId('content').append(node('h2', displayBytes(verified.path)),
        node('p', `Complete native blob verified (${selected.format}): ${verified.id}`),
        node('p', `${verified.bytes.length} bytes verified across ${verified.pages} read${verified.pages === 1 ? '' : 's'}. The download contains the complete file, not just this preview.`),
        node('p', commitProof ? 'Native commit bytes, its root tree, every containing directory and the complete file were verified. Authority signatures and author identity were not verified.' : proof ? 'Both blob bytes and path inclusion in the selected native root tree were verified. This is not an authority signature or verification of the source commit.' : 'This verifies blob bytes against the returned Git identity, not an authority signature or a proof that this path belongs to the tree.'),
        node('pre', preview.text), download);
      if (proof) byId('content').append(node('p', `Path inclusion verified against native root tree ${proof.rootTree}: ${proof.directories} directories, ${proof.pages} pages, ${proof.entries} entries, ${proof.bytes} encoded tree bytes. ${commitProof ? 'The root-to-commit association was verified; authority remains a server claim.' : 'The root-to-commit association and authority remain server claims.'}`));
      if (commitProof) byId('content').append(node('p', `Commit-to-file chain verified from ${commitProof.commit} (${commitProof.commitBytes} original commit bytes). The commit was selected by the server; this is not independent authentication of a branch tip.`));
      if (verified.kind === 'symlink') byId('content').append(node('p', 'Only symbolic-link target bytes are downloaded; no link is followed or created.'));
      verifiedDownload = verified;
      return { snapshot: pinned, binding, message: 'Complete file verified. Download is ready; no repository state was changed.' };
    });
  }
  function breadcrumbs(path) {
    byId('breadcrumbs').append(button('Repository', () => tree('')));
    const bytes = unhex(path, 4096);
    for (let i = 0; i <= bytes.length; i += 1) {
      if (i === bytes.length || bytes[i] === 47) {
        const prefix = hex(bytes.slice(0, i));
        if (prefix) byId('breadcrumbs').append(button(displayBytes(prefix), () => tree(prefix)));
      }
    }
  }
  function tree(path, after = null) {
    if (!selection) return;
    const fields = { ...sourceFields(selection, snapshot, path), limit: '100' };
    if (after !== null) { unhex(after, 4096); fields.after_hex = after; }
    void run('tree', fields, reply => {
      if (reply.type !== 'source_tree' || (reply.path_hex ?? '') !== path || !Array.isArray(reply.entries) || reply.entries.length > 100) {
        throw new Error('Invalid directory response.');
      }
      const table = node('table');
      const header = node('tr'); header.append(node('th', 'Name'), node('th', 'Kind')); table.append(header);
      let previousName = after;
      for (const entry of reply.entries) {
        if (!['directory', 'file', 'executable', 'symlink', 'gitlink'].includes(entry.kind) ||
            (previousName !== null && entry.name_hex <= previousName)) throw new Error('Invalid directory entry ordering or kind.');
        previousName = entry.name_hex;
        const child = pathJoin(path, entry.name_hex);
        const expected = { id: commitHex(entry.object_id, selection.format), kind: entry.kind };
        const row = node('tr'); const name = node('td');
        const action = entry.kind === 'directory' ? () => tree(child)
          : ['file', 'executable', 'symlink'].includes(entry.kind) ? () => blob(child, 0, expected) : null;
        name.append(action ? button(displayBytes(entry.name_hex), action) : node('span', displayBytes(entry.name_hex)));
        row.append(name, node('td', String(entry.kind))); table.append(row);
      }
      if (reply.next_after_hex !== null) {
        unhex(reply.next_after_hex, 4096);
        if (!reply.entries.length || reply.next_after_hex !== reply.entries.at(-1).name_hex || reply.next_after_hex === after) {
          throw new Error('Invalid directory continuation.');
        }
        byId('paging').append(button('Next directory page', () => tree(path, reply.next_after_hex)));
      }
      breadcrumbs(path);
      byId('content').append(table);
      if (!reply.entries.length) byId('content').append(node('p', 'This directory is empty.'));
    });
  }
  function blob(path, offset, expected = null) {
    const selected = selection;
    const fields = { ...sourceFields(selected, snapshot, path), offset: String(offset), limit: String(PAGE_BYTES) };
    void run('blob', fields, async (reply, binding, checkpoint) => {
      const page = blobPage(reply, selected, binding, path, offset, expected);
      const nextExpected = { id: page.id, kind: page.kind, total: page.total };
      const complete = offset === 0 && page.next === null;
      if (complete) await verifyBlob(page.bytes, selected.format, page.id, cryptoImpl, checkpoint);
      checkpoint();
      const parts = unhex(path, 4096); const slash = parts.lastIndexOf(47);
      breadcrumbs(slash < 0 ? '' : hex(parts.slice(0, slash)));
      const preview = blobPreview(page.bytes, offset);
      byId('content').append(node('h2', displayBytes(path)), node('p', `${preview.label} · bytes ${offset}–${offset + page.bytes.length} of ${page.total}`),
        node('p', complete ? `Complete native blob verified (${selected.format}): ${page.id}`
          : `Unverified byte-range preview. Native blob identity requires the complete file: ${page.id}`));
      if (page.kind === 'symlink') byId('content').append(node('p', 'Symbolic link target bytes only. The server did not follow the link.'));
      byId('content').append(node('pre', preview.text));
      const version = generation;
      if (page.total <= MAX_FILE_BYTES) byId('content').append(button('Verify complete file for download', () => {
        if (version === generation) exportFile(page);
      }));
      else byId('content').append(node('p', 'Complete-file download exceeds the 8 MiB browser limit; byte-range previews remain available.'));
      if (page.total <= MAX_FILE_BYTES) byId('content').append(button('Verify path and complete file for download', () => {
        if (version === generation) exportFile(page, true);
      }));
      if (page.total <= MAX_FILE_BYTES) byId('content').append(button('Verify commit, path and complete file for download', () => {
        if (version === generation) exportFile(page, true, true);
      }));
      if (offset) byId('paging').append(button('Previous byte range', () => blob(path, Math.max(0, offset - PAGE_BYTES), nextExpected)));
      if (page.next !== null) byId('paging').append(button('Next byte range', () => blob(path, page.next, nextExpected)));
    });
  }
  byId('connection').addEventListener('submit', event => {
    event.preventDefault();
    const supplied = byId('token').value;
    byId('token').value = '';
    const nextToken = supplied || token;
    if (!/^[0-9a-f]{64}$/.test(nextToken)) { disconnect(); status('Enter the provisioned 64-character lowercase hexadecimal token.'); return; }
    const candidate = { reference: byId('reference').value, format: byId('format').value };
    try { sourceFields(candidate, null); } catch (error) { status(error.message); return; }
    generation += 1; controller?.abort(); snapshot = null; boundSource = null; selection = candidate; token = nextToken;
    tree('');
  });
  byId('search').addEventListener('submit', event => {
    event.preventDefault();
    if (!selection) { status('Open a reference before searching.'); return; }
    let fields;
    try { fields = searchFields(selection, snapshot, byId('needle').value, byId('search-case').value); }
    catch (error) { status(error.message); return; }
    void run('search', fields, reply => {
      const rows = searchRows(reply);
      breadcrumbs('');
      byId('content').append(node('h2', 'Literal search results'));
      if (!reply.complete) {
        const warning = node('p', 'Match limit reached. These results are partial; narrow the query.');
        warning.className = 'warning'; byId('content').append(warning);
      }
      if (!rows.length) byId('content').append(node('p', 'No matches in this snapshot.'));
      for (const row of rows) {
        const result = node('article');
        result.append(button(`${row.name} · line ${row.line}, byte column ${row.column}`,
          () => blob(row.path, Math.floor(row.offset / PAGE_BYTES) * PAGE_BYTES)), node('pre', row.excerpt));
        byId('content').append(result);
      }
    });
  });
  byId('disconnect').addEventListener('click', disconnect);
  cancelControl?.addEventListener('click', cancel);
  for (const id of ['token', 'reference', 'format']) {
    const invalidateConnection = () => {
      generation++; controller?.abort(); controller = null;
      if (id === 'token') token = '';
      selection = null; snapshot = null; boundSource = null;
      if (cancelControl) cancelControl.disabled = true;
      clear(); status('Connection settings changed. Open the reference explicitly before reading.');
    };
    byId(id).addEventListener('input', invalidateConnection);
    byId(id).addEventListener('change', invalidateConnection);
  }
  // Clear secrets and abort fetches before a page can enter the back-forward cache.
  document.defaultView?.addEventListener('pagehide', disconnect);
  return { disconnect, cancel };
}
if (typeof document !== 'undefined') mount(document, window.location);
