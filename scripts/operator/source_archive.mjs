// Complete, commit-bound source acquisition over existing authenticated APIs.
// Derived export only: Git identity is not authorship, authority or freshness proof.
import { createHash } from 'node:crypto';
import { outcomeEndpoint } from './transaction_outcome.mjs';
import { SourceReader, fail, integer, fields } from './source_archive_transport.mjs';

export const ARCHIVE_LIMITS = Object.freeze({ maxEntries: 4096, maxTrees: 1024, maxDepth: 32,
  maxTreeBytes: 4 * 1024 * 1024, maxBlobBytes: 16 * 1024 * 1024, maxTotalBlobBytes: 64 * 1024 * 1024,
  maxRequests: 8192, maxWireBytes: 192 * 1024 * 1024, timeoutMs: 120000 });
export const MODES = Object.freeze({ directory: '40000', file: '100644', executable: '100755', symlink: '120000', gitlink: '160000' });
export const gitHash = (kind, bytes, algorithm) => createHash(algorithm).update(`${kind} ${bytes.length}\0`).update(bytes).digest('hex');
export const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');
export function archiveLimits(options = {}) {
  fields(options, Object.keys(ARCHIVE_LIMITS), []);
  return Object.freeze(Object.fromEntries(Object.entries(ARCHIVE_LIMITS).map(([name, max]) =>
    [name, integer(options[name] ?? max, 1, max, name)])));
}
export function hexBytes(value, maximum, empty = false) {
  if (typeof value !== 'string' || value.length > maximum * 2 || !/^(?:[0-9a-f]{2})*$/.test(value) || (!empty && !value.length)) fail('Invalid native byte encoding.');
  return Buffer.from(value, 'hex');
}
function identity(value) { if (typeof value !== 'string' || !/^[0-9a-f]{32}$/.test(value)) fail('Invalid repository identity.'); return value; }
function opaque(value) {
  if (typeof value !== 'string' || !value || Buffer.byteLength(value) > 256 || /[\s\u0000-\u001f\u007f-\u009f\uD800-\uDFFF]/u.test(value)) fail('Invalid source identity.');
  return value;
}
export function oid(value, algorithm) {
  if (!['sha1', 'sha256'].includes(algorithm)) fail('Unsupported Git object format.');
  const raw = typeof value === 'string' && value.startsWith(`${algorithm}:`) ? value.slice(algorithm.length + 1) : value;
  if (typeof raw !== 'string' || !new RegExp(`^[0-9a-f]{${algorithm === 'sha1' ? 40 : 64}}$`).test(raw) || /^0+$/.test(raw)) fail('Invalid native object identity.');
  return raw;
}
function snapshot(value) { if (typeof value !== 'string' || !/^alg:[1-9][0-9]{0,4}:(?:[0-9a-f]{2}){1,64}$/.test(value) || Number(value.split(':')[1]) > 65535) fail('Invalid snapshot token.'); return value; }
function fullRef(value) {
  if (typeof value !== 'string' || Buffer.byteLength(value) > 1024 || /[\x00-\x20\x7f~^:?*\[\\\uD800-\uDFFF]/u.test(value) ||
      !value.startsWith('refs/') || value.includes('..') || value.includes('@{') || value.endsWith('.') ||
      value.split('/').some(part => !part || part.startsWith('.') || part.endsWith('.lock'))) fail('A complete UTF-8 native reference is required.');
  return value;
}
export function archiveSelection(value) {
  const required = ['endpoint', 'tenant_id', 'repository_id', 'repository_incarnation', 'object_format', 'ref', 'expected_commit'];
  fields(value, [...required, 'expected_head'], required);
  return Object.freeze({ endpoint: outcomeEndpoint(value.endpoint), tenant_id: identity(value.tenant_id), repository_id: identity(value.repository_id),
    repository_incarnation: identity(value.repository_incarnation), object_format: value.object_format, ref: fullRef(value.ref),
    expected_commit: oid(value.expected_commit, value.object_format), expected_head: value.expected_head == null ? null : snapshot(value.expected_head) });
}
function pathBytes(path, depth = ARCHIVE_LIMITS.maxDepth) {
  const bytes = hexBytes(path, 4096), parts = []; let at = 0;
  for (let end = 0; end <= bytes.length; end++) if (end === bytes.length || bytes[end] === 47) {
    const part = bytes.subarray(at, end);
    if (!part.length || part.includes(0) || part.equals(Buffer.from('.')) || part.equals(Buffer.from('..'))) fail('Unsafe native path component.');
    parts.push(part); at = end + 1;
  }
  if (parts.length > depth) fail('Source tree depth budget exceeded.');
  return bytes;
}
function nameBytes(name) {
  const bytes = pathBytes(name);
  if (bytes.includes(47)) fail('Tree entry is not an immediate name.');
  return bytes;
}
function objectRow(row, algorithm) {
  fields(row, ['name_hex', 'object_id', 'kind']); nameBytes(row.name_hex);
  if (!Object.hasOwn(MODES, row.kind)) fail('Unsupported native tree mode.');
  return { name_hex: row.name_hex, object_id: oid(row.object_id, algorithm), kind: row.kind };
}
// Git sorts tree entries as though directory names end in '/'. API pagination
// instead sorts raw names. Restore Git order explicitly before hashing the tree.
export function treeBody(entries, algorithm) {
  const normalized = entries.map(row => objectRow(row, algorithm)), seen = new Set();
  for (const row of normalized) { if (seen.has(row.name_hex)) fail('Duplicate tree name.'); seen.add(row.name_hex); }
  const order = row => Buffer.concat([Buffer.from(row.name_hex, 'hex'), Buffer.from(row.kind === 'directory' ? '/' : '\0')]);
  normalized.sort((a, b) => Buffer.compare(order(a), order(b)));
  return Buffer.concat(normalized.map(row => Buffer.concat([Buffer.from(`${MODES[row.kind]} `),
    Buffer.from(row.name_hex, 'hex'), Buffer.from([0]), Buffer.from(row.object_id, 'hex')])));
}
function treeEntries(body, algorithm) {
  const result = [], width = algorithm === 'sha1' ? 20 : 32;
  for (let at = 0; at < body.length;) {
    const space = body.indexOf(32, at), nul = body.indexOf(0, space + 1);
    if (space < at || space - at > 6 || nul < space || nul + 1 + width > body.length) fail('Invalid captured tree framing.');
    const mode = body.subarray(at, space).toString('ascii'), kind = Object.keys(MODES).find(key => MODES[key] === mode);
    if (!kind) fail('Unsupported captured tree mode.');
    result.push(objectRow({ name_hex: body.subarray(space + 1, nul).toString('hex'), kind,
      object_id: body.subarray(nul + 1, nul + 1 + width).toString('hex') }, algorithm));
    if (result.length > ARCHIVE_LIMITS.maxEntries) fail('Tree entry budget exceeded.');
    at = nul + 1 + width;
  }
  if (!treeBody(result, algorithm).equals(body)) fail('Captured tree is not canonical or ordered.');
  return result.sort((a, b) => a.name_hex < b.name_hex ? -1 : 1);
}
function commitTree(commit, algorithm) {
  fields(commit, ['object_id', 'body_hex']);
  const expected = oid(commit.object_id, algorithm), body = hexBytes(commit.body_hex, 65536);
  if (gitHash('commit', body, algorithm) !== expected) fail('Commit bytes fail native identity verification.');
  const separator = body.indexOf(Buffer.from('\n\n')), headers = body.subarray(0, separator < 0 ? body.length : separator);
  const lines = headers.toString('latin1').split('\n');
  const first = lines[0];
  if (!/^tree [0-9a-fA-F]+$/.test(first)) fail('Commit has no exact first tree header.');
  const tree = oid(first.slice(5).toLowerCase(), algorithm), parents = [];
  for (const line of lines.slice(1)) {
    if (line.startsWith('tree ')) fail('Ambiguous commit tree header.');
    if (line.startsWith('parent ')) parents.push(oid(line.slice(7).toLowerCase(), algorithm));
  }
  if (parents.includes(expected) || parents.length > 16384) fail('Invalid commit ancestry summary.');
  return { tree, parents };
}
function scope(reply, selection, head = null, sourceHead = null) {
  if (!reply || reply.schema_version !== 1 || ['tenant_id', 'repository_id', 'repository_incarnation', 'object_format'].some(key => reply[key] !== selection[key]) ||
      reply.ref_hex !== Buffer.from(selection.ref).toString('hex') || oid(reply.source_commit, selection.object_format) !== selection.expected_commit ||
      reply.read_only !== true || reply.transaction_created !== false || reply.published !== false) fail('Source read changed repository, commit or read-only scope.');
  snapshot(reply.snapshot_token); opaque(reply.source_head);
  if ((head !== null && reply.snapshot_token !== head) || (sourceHead !== null && reply.source_head !== sourceHead) ||
      (Object.hasOwn(reply, 'ref') && reply.ref !== selection.ref)) fail('Source snapshot moved; no implicit refresh.');
}
function add(value, amount, maximum, label) { if (amount > maximum - value) fail(`${label} budget exceeded.`); return value + amount; }

// Validation is also used by the archive writer so mutated/reconstructed public
// captures cannot become a complete export without repeating the original proof.
export function validateCapture(capture, options = {}) {
  const limits = archiveLimits(options);
  fields(capture, ['schema', 'selection', 'snapshot_token', 'source_head', 'source_rcr', 'commit', 'trees', 'files']);
  if (capture.schema !== 'frankengit-source-capture-v1') fail('Unsupported source capture.');
  const selection = archiveSelection(capture.selection), algorithm = selection.object_format;
  snapshot(capture.snapshot_token); opaque(capture.source_head); opaque(capture.source_rcr);
  if (selection.expected_head !== null && selection.expected_head !== capture.snapshot_token) fail('Capture changed its supplied snapshot pin.');
  const { tree } = commitTree(capture.commit, algorithm);
  if (oid(capture.commit.object_id, algorithm) !== selection.expected_commit || !Array.isArray(capture.trees) ||
      !capture.trees.length || capture.trees.length > limits.maxTrees || !Array.isArray(capture.files) || capture.files.length > limits.maxEntries) fail('Incomplete or oversized source capture.');
  const trees = new Map(), files = new Map(); let treeBytes = 0, blobBytes = 0;
  for (const row of capture.trees) {
    fields(row, ['path_hex', 'object_id', 'body_hex']);
    if (row.path_hex !== null) pathBytes(row.path_hex, limits.maxDepth);
    if (trees.has(row.path_hex)) fail('Duplicate captured directory.');
    const body = hexBytes(row.body_hex, limits.maxTreeBytes, true), id = oid(row.object_id, algorithm);
    treeBytes = add(treeBytes, body.length, limits.maxTreeBytes, 'Tree bytes');
    if (gitHash('tree', body, algorithm) !== id) fail('Tree bytes fail native identity verification.');
    trees.set(row.path_hex, { id, entries: treeEntries(body, algorithm) });
  }
  for (const row of capture.files) {
    fields(row, ['path_hex', 'object_id', 'kind', 'bytes']); pathBytes(row.path_hex, limits.maxDepth);
    if (files.has(row.path_hex) || !Buffer.isBuffer(row.bytes) || row.bytes.length > limits.maxBlobBytes ||
        !['file', 'executable', 'symlink'].includes(row.kind)) fail('Invalid captured file.');
    blobBytes = add(blobBytes, row.bytes.length, limits.maxTotalBlobBytes, 'Blob bytes');
    const id = oid(row.object_id, algorithm);
    if (gitHash('blob', row.bytes, algorithm) !== id) fail('Blob bytes fail native identity verification.');
    files.set(row.path_hex, row);
  }
  const queue = [{ path_hex: null, object_id: tree }], entries = [], visited = new Set(), used = new Set();
  for (let index = 0; index < queue.length; index++) {
    const wanted = queue[index], found = trees.get(wanted.path_hex);
    if (!found || found.id !== wanted.object_id || visited.has(wanted.path_hex)) fail('Missing or changed directory membership.');
    visited.add(wanted.path_hex);
    for (const row of found.entries) {
      const path = wanted.path_hex === null ? row.name_hex : `${wanted.path_hex}2f${row.name_hex}`;
      pathBytes(path, limits.maxDepth);
      if (entries.length >= limits.maxEntries) fail('Source entry budget exceeded.');
      entries.push({ path_hex: path, object_id: row.object_id, kind: row.kind });
      if (row.kind === 'directory') { queue.push({ path_hex: path, object_id: row.object_id }); if (queue.length > limits.maxTrees) fail('Directory budget exceeded.'); }
      else if (row.kind !== 'gitlink') {
        const file = files.get(path);
        if (!file || file.object_id !== row.object_id || file.kind !== row.kind) fail('Missing or changed file membership.');
        used.add(path);
      }
    }
  }
  if (visited.size !== trees.size || used.size !== files.size) fail('Unreachable extra source material.');
  return { root_tree: tree, entries: entries.sort((a, b) => a.path_hex < b.path_hex ? -1 : 1),
    tree_bytes: treeBytes, blob_bytes: blobBytes, files: files.size, directories: trees.size,
    gitlinks: entries.filter(row => row.kind === 'gitlink').length };
}

// A prior capture supplies bytes, never the current source selection. Verify
// its complete proof before any connection, then detach and rehash each unique
// blob so caller mutation during asynchronous reads cannot change reused data.
// Prior-input limits are the fixed capture ceilings; tighter output limits are
// applied later to every current file, including each reused occurrence.
function reusableBlobs(capture, selection, check) {
  const blobs = new Map();
  if (capture === undefined) return blobs;
  check(); validateCapture(capture); check();
  const previous = archiveSelection(capture.selection);
  if (['endpoint', 'tenant_id', 'repository_id', 'repository_incarnation', 'object_format']
      .some(key => previous[key] !== selection[key])) fail('Reuse capture belongs to another endpoint or repository scope.');
  for (const file of capture.files) {
    check();
    const id = oid(file.object_id, selection.object_format), bytes = Buffer.from(file.bytes);
    if (gitHash('blob', bytes, selection.object_format) !== id) fail('Reuse bytes changed during capture validation.');
    const previous = blobs.get(id);
    if (previous && !previous.bytes.equals(bytes)) fail('Conflicting reusable blob identities.');
    if (!previous) blobs.set(id, { bytes, prior: true });
  }
  check(); return blobs;
}

export async function captureSource(selected, token, options = {}) {
  fields(options, ['limits', 'signal', 'ca', 'reuse'], []);
  const selection = archiveSelection(selected), limits = archiveLimits(options.limits), algorithm = selection.object_format;
  const reader = new SourceReader(selection.endpoint, token, limits, options);
  const blobs = reusableBlobs(options.reuse, selection, () => reader.check());
  const reuse = { blob_requests: 0, downloaded_blob_bytes: 0, reused_files: 0,
    reused_blob_bytes: 0, deduplicated_files: 0, deduplicated_blob_bytes: 0 };
  const base = { ref: selection.ref, object_format: algorithm, expected_commit: selection.expected_commit };
  if (selection.expected_head !== null) base.expected_head = selection.expected_head;
  const log = await reader.read('log', { ...base, after: '0', limit: '1' }, 256 * 1024);
  scope(log, selection, selection.expected_head);
  integer(log.total_commits, 1, 4096, 'ancestry count');
  if (log.type !== 'source_log' || log.ordering !== 'child-before-parent-native-id-v1' || log.author_identity_verified !== false ||
      log.page_complete !== true || log.after !== 0 || log.limit !== 1 || !Array.isArray(log.commits) || log.commits.length !== 1 ||
      log.next_after !== (log.total_commits > 1 ? 1 : null)) fail('Invalid pinned commit page.');
  const row = log.commits[0], commit = { object_id: oid(row.object_id, algorithm), body_hex: row.body_hex };
  const original = commitTree(commit, algorithm);
  if (commit.object_id !== selection.expected_commit || oid(row.tree, algorithm) !== original.tree || !Array.isArray(row.parents) ||
      JSON.stringify(row.parents.map(value => oid(value, algorithm))) !== JSON.stringify(original.parents)) fail('Commit summary differs from original bytes.');
  const capture = { schema: 'frankengit-source-capture-v1', selection, snapshot_token: log.snapshot_token,
    source_head: log.source_head, source_rcr: null, commit, trees: [], files: [] };
  const expected = { ...base, expected_head: log.snapshot_token }, queue = [{ path_hex: null, object_id: original.tree }], files = [];
  let entryCount = 0, treeBytes = 0, blobBytes = 0;
  const checkSource = value => {
    reader.check(); scope(value, selection, log.snapshot_token, log.source_head); opaque(value.source_rcr);
    if (oid(value.root_tree, algorithm) !== original.tree || (capture.source_rcr !== null && capture.source_rcr !== value.source_rcr)) fail('Source root or record changed.');
    capture.source_rcr ??= value.source_rcr;
  };
  // Verify every directory before acquiring blob bodies. Missing pages cannot
  // manufacture an empty or partial tree: only its exact Git identity closes it.
  for (let index = 0; index < queue.length; index++) {
    reader.check(); const item = queue[index], entries = []; let after = null;
    do {
      const value = await reader.read('tree', { ...expected, limit: '100', ...(item.path_hex === null ? {} : { path_hex: item.path_hex }),
        ...(after === null ? {} : { after_hex: after }) });
      checkSource(value);
      if (value.type !== 'source_tree' || value.path_hex !== item.path_hex || oid(value.object_id, algorithm) !== item.object_id ||
          value.after_hex !== after || value.limit !== 100 || !Array.isArray(value.entries) || value.entries.length > 100) fail('Invalid directory page.');
      let last = after ?? '';
      for (const raw of value.entries) {
        const row = objectRow(raw, algorithm);
        if (row.name_hex <= last) fail('Directory page order or cursor regressed.'); last = row.name_hex;
        entryCount = add(entryCount, 1, limits.maxEntries, 'Source entries');
        treeBytes = add(treeBytes, Buffer.byteLength(MODES[row.kind]) + 2 + row.name_hex.length / 2 + row.object_id.length / 2, limits.maxTreeBytes, 'Tree bytes');
        entries.push(row);
      }
      if (value.next_after_hex !== null && (value.entries.length !== 100 || value.next_after_hex !== last)) fail('Invalid directory continuation.');
      after = value.next_after_hex;
    } while (after !== null);
    reader.check(); const body = treeBody(entries, algorithm);
    if (gitHash('tree', body, algorithm) !== item.object_id) fail('Directory does not reconstruct its native tree; missing entries or noncanonical original modes cannot be exported.');
    capture.trees.push({ ...item, body_hex: body.toString('hex') });
    for (const row of entries) {
      const path = item.path_hex === null ? row.name_hex : `${item.path_hex}2f${row.name_hex}`; pathBytes(path, limits.maxDepth);
      const next = { path_hex: path, object_id: row.object_id, kind: row.kind };
      if (row.kind === 'directory') {
        if (queue.length >= limits.maxTrees) fail('Directory budget exceeded.');
        queue.push({ path_hex: path, object_id: row.object_id });
      } else if (row.kind !== 'gitlink') files.push(next);
    }
  }
  for (const file of files) {
    reader.check();
    const cached = blobs.get(file.object_id);
    if (cached) {
      integer(cached.bytes.length, 0, limits.maxBlobBytes, 'blob size');
      blobBytes = add(blobBytes, cached.bytes.length, limits.maxTotalBlobBytes, 'Blob bytes');
      const prefix = cached.prior ? 'reused' : 'deduplicated';
      reuse[`${prefix}_files`]++; reuse[`${prefix}_blob_bytes`] += cached.bytes.length;
      // Current path/kind come exclusively from the fresh, fully checked trees.
      // Each output buffer is independent; no file aliases a prior or sibling.
      capture.files.push({ ...file, bytes: Buffer.from(cached.bytes) });
      continue;
    }
    let offset = 0, bytes = null;
    do {
      reader.check(); const limit = Math.min(1024 * 1024, limits.maxBlobBytes);
      reuse.blob_requests++;
      const value = await reader.read('blob', { ...expected, path_hex: file.path_hex, offset: String(offset), limit: String(limit) }, 2 * limit + 65536);
      checkSource(value);
      if (value.type !== 'source_blob' || value.path_hex !== file.path_hex || oid(value.object_id, algorithm) !== file.object_id ||
          value.kind !== file.kind || value.symlink_followed !== false || value.offset !== offset) fail('Blob selection changed.');
      const total = integer(value.total_bytes, 0, limits.maxBlobBytes, 'blob size'), part = hexBytes(value.content_hex, limit, true);
      if (offset > total || part.length !== Math.min(limit, total - offset) || value.returned_bytes !== part.length ||
          value.next_offset !== (offset + part.length < total ? offset + part.length : null)) fail('Blob range incomplete.');
      if (bytes === null) { blobBytes = add(blobBytes, total, limits.maxTotalBlobBytes, 'Blob bytes'); bytes = Buffer.alloc(total); }
      if (bytes.length !== total) fail('Blob size changed between ranges.');
      part.copy(bytes, offset); offset += part.length;
      if (value.next_offset === null) break;
    } while (true);
    if (gitHash('blob', bytes, algorithm) !== file.object_id) fail('Blob bytes fail native identity verification.');
    reuse.downloaded_blob_bytes += bytes.length;
    blobs.set(file.object_id, { bytes, prior: false });
    capture.files.push({ ...file, bytes });
  }
  reader.check(); validateCapture(capture, limits); reader.check();
  return { capture, metrics: { requests: reader.requests, wire_bytes: reader.wireBytes, tree_bytes: treeBytes, blob_bytes: blobBytes, ...reuse } };
}
