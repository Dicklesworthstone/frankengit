// Deterministic source export, not a checkout, backup, or general tar extractor.
import { validateCapture, hexBytes, sha256, ARCHIVE_LIMITS, archiveSelection, oid } from './source_archive.mjs';
import { fail, fields, integer, parse } from './source_archive_transport.mjs';

export const TAR_LIMIT = 80 * 1024 * 1024;
export const MANIFEST_LIMIT = 12 * 1024 * 1024;
const MANIFEST = 'frankengit-source.json';
const FLAGS = Object.freeze({ native_content_and_paths_verified: true, authority_signatures_verified: false,
  author_identity_verified: false, ref_freshness_verified: false, submodules_hydrated: false,
  symlinks_created: false, executable_files_created: false, repository_backup: false });
const encode = value => Buffer.from(`${JSON.stringify(value)}\n`);
const order = (a, b) => (a.path_hex ?? '') < (b.path_hex ?? '') ? -1 : (a.path_hex ?? '') === (b.path_hex ?? '') ? 0 : 1;
const layoutName = value => { if (!['portable', 'objects'].includes(value)) fail('Select portable or objects archive layout.'); return value; };

// Deliberately strict ASCII profile. Unsupported bytes, platform aliases or long
// names are never normalized or silently dropped: use the object-payload layout.
export function portablePath(pathHex) {
  const bytes = hexBytes(pathHex, 4096);
  if (bytes.some(byte => byte < 32 || byte > 126)) fail('Source path is outside portable ASCII; select objects layout.');
  const path = bytes.toString('ascii'), parts = path.split('/');
  for (const part of parts) {
    if (!part || ['.', '..'].includes(part) || /[\\:*?"<>|]/.test(part) || /[ .]$/.test(part) ||
        /^\.(?:git|hg|svn|bzr)$/i.test(part) || /^(?:con|prn|aux|nul|clock\$|conin\$|conout\$|com[0-9]|lpt[0-9])(?:\.|$)/i.test(part) || /^git~[0-9]/i.test(part)) {
      fail('Source path has a platform or VCS alias; select objects layout.');
    }
  }
  const member = `source/${path}`;
  splitName(member); return member;
}
function splitName(value) {
  if (typeof value !== 'string' || !value || /[^\x20-\x7e]/.test(value)) fail('Invalid archive member name.');
  if (value.length <= 100) return { name: value, prefix: '' };
  for (let at = value.length - 1; at > 0; at--) if (value[at] === '/' && at <= 155 && value.length - at - 1 <= 100 && at !== value.length - 1) {
    return { prefix: value.slice(0, at), name: value.slice(at + 1) };
  }
  fail('Source name exceeds the portable ustar profile; select objects layout.');
}
function header(name, type, size) {
  const split = splitName(name), out = Buffer.alloc(512);
  const string = (value, offset, width) => { if (value.length > width) fail('Archive header overflow.'); out.write(value, offset, width, 'ascii'); };
  const octal = (value, offset, width) => { integer(value, 0, TAR_LIMIT); string(value.toString(8).padStart(width - 1, '0') + '\0', offset, width); };
  if (!['0', '5'].includes(type) || (type === '5' && size !== 0)) fail('Only regular payloads and empty directory records are allowed.');
  string(split.name, 0, 100); octal(type === '5' ? 0o755 : 0o644, 100, 8); octal(0, 108, 8); octal(0, 116, 8);
  octal(size, 124, 12); octal(0, 136, 12); out.fill(32, 148, 156); string(type, 156, 1);
  string('ustar\0', 257, 6); string('00', 263, 2); string(split.prefix, 345, 155);
  const checksum = out.reduce((sum, byte) => sum + byte, 0);
  string(checksum.toString(8).padStart(6, '0') + '\0 ', 148, 8);
  return out;
}
function profile(capture, layout) {
  layoutName(layout); const proof = validateCapture(capture), members = new Map(), filenames = new Map();
  const directory = layout === 'portable' ? 'source' : 'payloads';
  members.set(directory, { name: directory, type: '5', bytes: Buffer.alloc(0) });
  if (layout === 'portable') {
    for (const entry of proof.entries) {
      const member = portablePath(entry.path_hex), folded = member.toLowerCase();
      if (filenames.has(folded)) fail('Case-colliding source paths require objects layout.');
      filenames.set(folded, entry.path_hex);
      if (entry.kind === 'directory' || entry.kind === 'gitlink') members.set(member, { name: member, type: '5', bytes: Buffer.alloc(0) });
    }
  }
  const files = [...capture.files].sort(order).map(file => {
    const member = layout === 'portable' ? portablePath(file.path_hex) : `payloads/${capture.selection.object_format}-${file.object_id}.blob`;
    const previous = members.get(member);
    if (previous && (previous.type !== '0' || !previous.bytes.equals(file.bytes))) fail('Conflicting archive payload identities.');
    members.set(member, { name: member, type: '0', bytes: file.bytes });
    return { path_hex: file.path_hex, object_id: file.object_id, kind: file.kind, member, size: file.bytes.length, sha256: sha256(file.bytes) };
  });
  const manifest = { schema: 'frankengit-source-archive-v1', layout, selection: archiveSelection(capture.selection),
    snapshot_token: capture.snapshot_token, source_head: capture.source_head, source_rcr: capture.source_rcr,
    commit: { object_id: oid(capture.commit.object_id, capture.selection.object_format), body_hex: capture.commit.body_hex },
    trees: [...capture.trees].sort(order).map(row => ({ path_hex: row.path_hex, object_id: oid(row.object_id, capture.selection.object_format), body_hex: row.body_hex })), files,
    gitlinks: proof.entries.filter(entry => entry.kind === 'gitlink'), claims: FLAGS };
  const manifestBytes = encode(manifest);
  if (manifestBytes.length > MANIFEST_LIMIT) fail('Archive proof manifest exceeds its limit.');
  const ordered = [{ name: MANIFEST, type: '0', bytes: manifestBytes },
    ...[...members.values()].sort((a, b) => a.name < b.name ? -1 : a.name === b.name ? 0 : 1)];
  let size = 1024;
  for (const member of ordered) {
    size += 512 + Math.ceil(member.bytes.length / 512) * 512;
    if (size > TAR_LIMIT) fail('Source archive byte budget exceeded.');
  }
  return { proof, manifest, ordered, size };
}
export function buildSourceArchive(capture, layout) {
  const planned = profile(capture, layout), bytes = Buffer.alloc(planned.size); let at = 0;
  for (const member of planned.ordered) {
    header(member.name, member.type, member.bytes.length).copy(bytes, at); at += 512;
    member.bytes.copy(bytes, at); at += Math.ceil(member.bytes.length / 512) * 512;
  }
  return { bytes, receipt: receipt(planned, sha256(bytes), bytes.length) };
}
function receipt(planned, hash, size) {
  return { type: 'source_archive_verified', schema_version: 1, layout: planned.manifest.layout,
    object_format: planned.manifest.selection.object_format, source_commit: planned.manifest.selection.expected_commit,
    root_tree: planned.proof.root_tree, archive_sha256: hash, archive_bytes: size,
    entries: planned.proof.entries.length, files: planned.proof.files, directories: planned.proof.directories,
    gitlinks: planned.proof.gitlinks, source_bytes: planned.proof.blob_bytes, ...FLAGS };
}
function tarRecords(bytes) {
  if (!Buffer.isBuffer(bytes) || bytes.length < 1536 || bytes.length > TAR_LIMIT || bytes.length % 512 !== 0) fail('Invalid or oversized source archive.');
  const result = new Map(); let at = 0;
  while (at < bytes.length - 1024) {
    if (result.size >= ARCHIVE_LIMITS.maxEntries + 2) fail('Archive member count exceeded.');
    const raw = bytes.subarray(at, at + 512);
    const string = (offset, width) => {
      const slice = raw.subarray(offset, offset + width), nul = slice.indexOf(0);
      return slice.subarray(0, nul < 0 ? slice.length : nul).toString('ascii');
    };
    const suffix = string(0, 100), prefix = string(345, 155), name = prefix ? `${prefix}/${suffix}` : suffix;
    const number = raw.subarray(124, 136).toString('latin1');
    if (!/^[0-7]{11}\0$/.test(number)) fail('Invalid source archive size field.');
    const size = Number.parseInt(number, 8), type = String.fromCharCode(raw[156]);
    if (size > (result.size === 0 ? MANIFEST_LIMIT : ARCHIVE_LIMITS.maxBlobBytes) || !header(name, type, size).equals(raw)) fail('Noncanonical or unsafe source archive header.');
    if (result.has(name) || (result.size === 0 && (name !== MANIFEST || type !== '0'))) fail('Duplicate or misplaced archive member.');
    at += 512;
    const padded = Math.ceil(size / 512) * 512;
    if (padded > bytes.length - 1024 - at) fail('Truncated source archive member.');
    if (bytes.subarray(at + size, at + padded).some(byte => byte !== 0)) fail('Nonzero source archive padding.');
    result.set(name, { name, type, bytes: bytes.subarray(at, at + size) }); at += padded;
  }
  if (at !== bytes.length - 1024 || bytes.subarray(at).some(byte => byte !== 0)) fail('Missing or extra source archive trailer.');
  return result;
}

// Offline verification parses only this closed deterministic tar profile. It
// never extracts members, follows paths/links, opens a socket or refreshes source.
export function inspectSourceArchive(bytes, expectedHash) {
  if (typeof expectedHash !== 'string' || !/^[0-9a-f]{64}$/.test(expectedHash)) fail('An independently retained archive SHA-256 is required.');
  if (!Buffer.isBuffer(bytes) || bytes.length > TAR_LIMIT || sha256(bytes) !== expectedHash) fail('Source archive SHA-256 mismatch.');
  const records = tarRecords(bytes), manifestRecord = records.get(MANIFEST);
  if (!manifestRecord || manifestRecord.bytes.length > MANIFEST_LIMIT) fail('Missing archive proof manifest.');
  const manifest = parse(manifestRecord.bytes);
  fields(manifest, ['schema', 'layout', 'selection', 'snapshot_token', 'source_head', 'source_rcr', 'commit', 'trees', 'files', 'gitlinks', 'claims']);
  if (manifest.schema !== 'frankengit-source-archive-v1' || !Array.isArray(manifest.files) || manifest.files.length > ARCHIVE_LIMITS.maxEntries) fail('Unsupported source archive manifest.');
  const files = manifest.files.map(file => {
    fields(file, ['path_hex', 'object_id', 'kind', 'member', 'size', 'sha256']);
    if (typeof file.member !== 'string') fail('Invalid source archive member selection.');
    const member = records.get(file.member);
    if (!member || member.type !== '0' || member.bytes.length !== file.size || sha256(member.bytes) !== file.sha256) fail('Archive file payload is missing or changed.');
    return { path_hex: file.path_hex, object_id: file.object_id, kind: file.kind, bytes: member.bytes };
  });
  const capture = { schema: 'frankengit-source-capture-v1', selection: manifest.selection,
    snapshot_token: manifest.snapshot_token, source_head: manifest.source_head, source_rcr: manifest.source_rcr,
    commit: manifest.commit, trees: manifest.trees, files };
  const planned = profile(capture, manifest.layout);
  // Recreate semantic metadata, membership, names, dedup and order. A manifest
  // cannot authorize extra tar entries or upgrade the declared proof class.
  if (!encode(planned.manifest).equals(manifestRecord.bytes) || planned.ordered.length !== records.size || planned.size !== bytes.length) fail('Source archive manifest or member set changed.');
  let index = 0;
  for (const actual of records.values()) {
    const wanted = planned.ordered[index++];
    if (actual.name !== wanted.name || actual.type !== wanted.type || !actual.bytes.equals(wanted.bytes)) fail('Source archive order or contents changed.');
  }
  return receipt(planned, expectedHash, bytes.length);
}
