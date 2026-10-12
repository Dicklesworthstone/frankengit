// A source-authoring session owns one inspected candidate and at most one exact
// unresolved publication. Transport failure is never a rollback receipt.
import { Transport, fail, keys, record, copy, integer, opaque, hex, unhex, utf8,
  binding, pinned, oid, reference, form, branch, format, text } from './pulls-core.mjs';
import { makeBoundary, digest } from './pulls-candidate.mjs';
import { recovery, base64, fromBase64, receiptScope, RECEIPT_LIMIT } from './pulls-actions.mjs';
import { FILE_LIMIT, PATCH_LIMIT, EDIT_LIMIT, fileBytes, sourcePath, fullFilePatch } from './source-edit-patch.mjs';
import { coordinates, commitMetadata, matchReference, objectHash, sourceUpload, prepared,
  inspected, publication, retryKey, editManifest, PREPARE_LIMIT } from './source-edit-protocol.mjs';

function readOnly(reply) {
  if (reply.read_only !== true || reply.transaction_created !== false || reply.published !== false) fail('Source read unexpectedly claims publication.');
}
// Import an overlay onto EXISTING history. Selected local files never imply
// deletion of unselected repository files. Native preparation/admission remain
// the only consumers that can accept/publish the resulting exact file effects.
export const IMPORT_PAGE = 64;
export const IMPORT_PAGES = 128;
export const IMPORT_TREE_BYTES = 2 * 1024 * 1024;
export const IMPORT_TIMEOUT_MS = 60_000;

function disjointPaths(paths) {
  const seen = new Set(paths);
  if (seen.size !== paths.length) fail('Duplicate import or queued destination.');
  for (const path of paths) {
    const bytes = sourcePath(path);
    for (let i = 0; i < bytes.length; i++) {
      if (bytes[i] === 47 && seen.has(hex(bytes.subarray(0, i)))) fail('Import overlaps a file/directory or queued edit.');
    }
  }
}
// Capture the FileList and all descriptors synchronously, before any network or
// file await. Do not infer executable permissions from browser filenames.
export function captureSourceImport(selected, options = {}, retained = []) {
  keys(options, ['directory', 'prefixHex', 'mode']);
  const directory = options.directory ?? false, prefix = options.prefixHex ?? '', mode = options.mode ?? 'preserve';
  if (typeof directory !== 'boolean' || !['preserve', '100644', '100755'].includes(mode)) fail('Choose an explicit import path and mode policy.');
  if (prefix !== '') sourcePath(prefix);
  const count = integer(selected?.length, 'selected file count', 1, EDIT_LIMIT);
  // Check count before copying a hostile/oversized iterable or FileList.
  if (!Array.isArray(retained) || retained.length + count > EDIT_LIMIT) fail('Imported and queued files exceed the 64-path limit.');
  const prior = retained.length ? fullFilePatch(retained, { allowBinary: true }).edits : [];
  let bytes = prior.reduce((n, e) => n + (e.before?.bytes.length ?? 0) + (e.after?.bytes.length ?? 0), 0), folder = null;
  const entries = [];
  for (let i = 0; i < count; i++) {
    const file = selected[i];
    if (!file || typeof file.arrayBuffer !== 'function') fail('Select readable local files.');
    const size = integer(file.size, 'selected file size', 0, FILE_LIMIT);
    let name = text(file.name, 4096, 'selected file name');
    sourcePath(hex(utf8.encode(name)));
    if (name.includes('/')) fail('Individual file names cannot contain path separators.');
    if (directory) {
      const relative = text(file.webkitRelativePath, 4096, 'directory relative path');
      sourcePath(hex(utf8.encode(relative)));
      const parts = relative.split('/');
      if (parts.length < 2 || parts.at(-1) !== name || (folder !== null && folder !== parts[0])) fail('Select exactly one source directory with consistent file paths.');
      folder = parts[0]; name = parts.slice(1).join('/');
    }
    const path = (prefix ? `${prefix}2f` : '') + hex(utf8.encode(name));
    sourcePath(path);
    bytes += size;
    if (bytes > PATCH_LIMIT) fail('Imported and retained bytes exceed the 1 MiB draft budget.');
    entries.push({ path_hex: path, file, size });
  }
  disjointPaths([...prior.map(e => e.path_hex), ...entries.map(e => e.path_hex)]);
  entries.sort((a, b) => a.path_hex < b.path_hex ? -1 : 1);
  return { entries, retained: prior, bytes, mode };
}
function selectedRead(reply, selection) {
  pinned(reply, selection.scope, selection.snapshot); readOnly(reply); matchReference(reply, selection.fields.ref);
  if (oid(reply.source_commit, selection.scope.format) !== selection.fields.expected_commit ||
      oid(reply.root_tree, selection.scope.format) !== selection.tree || reply.source_rcr !== selection.sourceRcr) fail('Import source snapshot or native history changed.');
}
function importTreePage(reply, selection, path, tree, after) {
  selectedRead(reply, selection);
  if (reply.type !== 'source_tree' || reply.path_hex !== path || reply.after_hex !== after || reply.limit !== IMPORT_PAGE ||
      oid(reply.object_id, selection.scope.format) !== tree || !Array.isArray(reply.entries) || reply.entries.length > IMPORT_PAGE) fail('Invalid import directory page.');
  let last = after ?? '';
  const entries = reply.entries.map(row => {
    record(row); const bytes = unhex(row.name_hex, 4096);
    if (!bytes.length || bytes.includes(0) || bytes.includes(47) || row.name_hex <= last ||
        !['file', 'executable', 'directory', 'symlink', 'gitlink'].includes(row.kind)) fail('Invalid import directory entry or order.');
    last = row.name_hex;
    return { name_hex: row.name_hex, kind: row.kind, object_id: oid(row.object_id, selection.scope.format) };
  });
  // Native directory pagination may end in an empty page after an exactly full
  // preceding page. Only a null continuation proves that directory is exhausted.
  if (reply.next_after_hex !== null && (!entries.length || entries.length !== IMPORT_PAGE || reply.next_after_hex !== last)) fail('Invalid import directory continuation.');
  return { entries, next: reply.next_after_hex };
}

export class SourceEditClient {
  #transport; #scope = null; #selection = null; #artifact = null; #pending = null; #busy = false; #serial = 0; #importTimeout;
  constructor(options) {
    this.#transport = new Transport({ ...options, pageSuffix: '/ui/source/' });
    this.#importTimeout = integer(options.importTimeoutMs ?? IMPORT_TIMEOUT_MS, 'project import timeout', 1, 300_000);
  }
  get connected() { return this.#transport.connected; }
  get busy() { return this.#busy; }
  get selection() { return this.#selection ? copy(this.#selection) : null; }
  get candidate() {
    return this.#artifact ? copy({ fields: this.#artifact.fields, scope: this.#artifact.scope,
      bundleBytes: this.#artifact.bundle.length, sha256: this.#artifact.sha256,
      preparation: this.#artifact.metadata, inspection: this.#artifact.inspection }) : null;
  }
  get pending() {
    if (!this.#pending) return null;
    const p = this.#pending;
    return copy({ fields: p.fields, scope: p.scope, key: p.key, requestSha256: p.requestSha256,
      bytes: p.bytes.length, sent: p.sent, exported: p.exported, observedTx: p.observedTx,
      observedPrincipal: p.observedPrincipal });
  }
  async connect(token) {
    this.disconnect();
    await this.#transport.connect(token, this.#pending?.fingerprint ?? null);
  }
  disconnect() {
    this.#serial += 1; this.#transport.disconnect(); this.#selection = null;
    this.#artifact = null; this.#scope = null;
    // A request that may have reached admission survives loss of credentials.
  }
  invalidateCandidate() {
    this.#serial += 1; this.#transport.cancelReads(); this.#artifact = null;
  }
  clearSelection() { this.invalidateCandidate(); this.#selection = null; }
  #check(serial, epoch) {
    if (serial !== this.#serial || epoch !== this.#transport.epoch || !this.connected) fail('Source operation cancelled or selection changed.');
  }
  #noPending() { if (this.#pending) fail('Resolve the saved publication before replacing it.'); }
  async #exclusive(work) {
    if (this.#busy) fail('A source operation is already in progress.');
    if (!this.connected) fail('Connect a repository credential first.');
    this.#busy = true;
    try { return await work(); } finally { this.#busy = false; }
  }
  async select(ref, algorithm) {
    return this.#exclusive(async () => {
      this.#noPending(); this.invalidateCandidate(); this.#selection = null;
      const serial = this.#serial, epoch = this.#transport.epoch;
      // The root reader, not a branch name typed in the page, selects the base.
      const fields = { ref: branch(ref), object_format: format(algorithm) };
      const { value: reply } = await this.#transport.request('source/tree', {
        method: 'POST', body: form({ ref: fields.ref, object_format: fields.object_format, limit: 1 }), maximum: 32 * 1024,
      });
      const selected = pinned(reply, this.#scope); readOnly(reply); matchReference(reply, fields.ref);
      if (reply.type !== 'source_tree' || reply.path_hex !== null || reply.after_hex !== null || reply.limit !== 1 ||
          selected.binding.format !== fields.object_format || !Array.isArray(reply.entries) || reply.entries.length > 1) fail('Invalid root selection.');
      const commit = oid(reply.source_commit, fields.object_format), tree = oid(reply.root_tree, fields.object_format);
      if (oid(reply.object_id, fields.object_format) !== tree) fail('Root tree identity mismatch.');
      opaque(reply.source_rcr); this.#check(serial, epoch);
      this.#scope = selected.binding;
      this.#selection = { fields: { ref: fields.ref, object_format: fields.object_format, expected_commit: commit },
        scope: selected.binding, snapshot: reply.snapshot_token, tree, sourceRcr: reply.source_rcr };
      return this.selection;
    });
  }
  async loadFile(pathHex) {
    return this.#exclusive(async () => {
      this.#noPending(); sourcePath(pathHex);
      if (!this.#selection) fail('Select an immutable branch base first.');
      const selection = copy(this.#selection), serial = this.#serial, epoch = this.#transport.epoch;
      return this.#loadFile(pathHex, selection, () => this.#check(serial, epoch));
    });
  }
  async #loadFile(pathHex, selection, check) {
    check();
    const { value: reply } = await this.#transport.request('source/blob', { method: 'POST',
      body: form({ ref: selection.fields.ref, object_format: selection.fields.object_format,
        expected_head: selection.snapshot, expected_commit: selection.fields.expected_commit,
        path_hex: pathHex, offset: 0, limit: FILE_LIMIT }), maximum: FILE_LIMIT * 2 + 16 * 1024 });
    check(); selectedRead(reply, selection);
    if (reply.type !== 'source_blob' || reply.path_hex !== pathHex || reply.offset !== 0 || reply.next_offset !== null ||
        reply.symlink_followed !== false || !['file', 'executable'].includes(reply.kind) ||
        oid(reply.source_commit, selection.scope.format) !== selection.fields.expected_commit ||
        oid(reply.root_tree, selection.scope.format) !== selection.tree) fail('A complete ordinary file at the selected base is required.');
    integer(reply.total_bytes, 'complete file size', 0, FILE_LIMIT);
    const bytes = fileBytes(unhex(reply.content_hex, FILE_LIMIT), true);
    if (reply.total_bytes !== bytes.length || reply.returned_bytes !== bytes.length ||
        await objectHash('blob', bytes, selection.scope.format, this.#transport.crypto) !== oid(reply.object_id, selection.scope.format)) fail('File bytes do not match their native identity.');
    check();
    return { path_hex: pathHex, before: { bytes, mode: reply.kind === 'executable' ? 0o100755 : 0o100644 } };
  }
  async importFiles(selected, options = {}, retained = []) {
    return this.#exclusive(async () => {
      this.#noPending(); this.invalidateCandidate();
      if (!this.#selection) fail('Select an immutable branch base before importing files.');
      const plan = captureSourceImport(selected, options, retained);
      const selection = copy(this.#selection), serial = this.#serial, epoch = this.#transport.epoch;
      const started = performance.now();
      let expired = false, pages = 0, directoryBytes = 0, total = plan.bytes;
      const check = () => {
        this.#check(serial, epoch);
        if (expired || performance.now() - started >= this.#importTimeout) fail('Project import exceeded its whole-operation deadline.');
      };
      const timer = setTimeout(() => { expired = true; this.#transport.cancelReads(); }, this.#importTimeout);
      // This private cache exists only within one source snapshot and is never
      // a ref store or evidence that an HTTP 404 means an absent path.
      const directories = new Map();
      const fields = { ...selection.fields, expected_head: selection.snapshot };
      const directory = async (path, tree) => {
        if (directories.has(path)) return directories.get(path);
        const children = new Map(); let after = null;
        do {
          check(); if (++pages > IMPORT_PAGES) fail('Import directory scan exceeds its page budget.');
          const command = { ...fields, limit: IMPORT_PAGE };
          if (path !== null) command.path_hex = path;
          if (after !== null) command.after_hex = after;
          const { value } = await this.#transport.request('source/tree', { method: 'POST', body: form(command), maximum: 1024 * 1024 });
          check(); const page = importTreePage(value, selection, path, tree, after);
          for (const row of page.entries) {
            directoryBytes += row.name_hex.length / 2 + 128;
            if (directoryBytes > IMPORT_TREE_BYTES) fail('Import directory inventory exceeds its byte budget.');
            children.set(row.name_hex, row);
          }
          after = page.next;
        } while (after !== null);
        // Reconstruct the COMPLETE native tree. A checksum-valid blob alone
        // cannot establish that another filename was absent from this directory.
        const modes = { file: '100644', executable: '100755', directory: '40000', symlink: '120000', gitlink: '160000' };
        const ordered = [...children.values()].sort((a, b) => {
          const x = a.name_hex + (a.kind === 'directory' ? '2f' : '00');
          const y = b.name_hex + (b.kind === 'directory' ? '2f' : '00');
          return x < y ? -1 : x > y ? 1 : 0;
        });
        const parts = ordered.flatMap(row => [utf8.encode(`${modes[row.kind]} `), unhex(row.name_hex, 4096), new Uint8Array([0]), unhex(row.object_id, 32)]);
        const size = parts.reduce((n, p) => n + p.length, 0), prefix = utf8.encode(`tree ${size}\0`);
        const framed = new Uint8Array(prefix.length + size); framed.set(prefix); let offset = prefix.length;
        for (const part of parts) { framed.set(part, offset); offset += part.length; }
        const actual = hex(new Uint8Array(await this.#transport.crypto.subtle.digest(selection.scope.format === 'sha1' ? 'SHA-1' : 'SHA-256', framed)));
        check(); if (actual !== tree) fail('Import directory inventory does not match its native tree identity.');
        directories.set(path, children); return children;
      };
      const locate = async path => {
        const raw = sourcePath(path), parts = []; let start = 0;
        for (let i = 0; i <= raw.length; i++) if (i === raw.length || raw[i] === 47) { parts.push(hex(raw.subarray(start, i))); start = i + 1; }
        let parent = null, tree = selection.tree;
        for (let i = 0; i < parts.length; i++) {
          const children = await directory(parent, tree), row = children.get(parts[i]); check();
          // A complete selected directory, never an error, establishes absence.
          if (!row) return null;
          if (i === parts.length - 1) {
            if (!['file', 'executable'].includes(row.kind)) fail('An imported path replaces a directory, symlink or gitlink.');
            return row;
          }
          if (row.kind !== 'directory') fail('An import parent is not an ordinary repository directory.');
          parent = parent === null ? parts[i] : `${parent}2f${parts[i]}`; tree = row.object_id;
        }
      };
      try {
        // Finish all inventory/old-file reads before reading local file contents.
        // This also accounts for every existing byte in the shared draft budget.
        const captured = [];
        for (const entry of plan.entries) {
          check(); const row = await locate(entry.path_hex); check();
          let before = null;
          if (row) {
            before = (await this.#loadFile(entry.path_hex, selection, check)).before;
            if (before.mode !== (row.kind === 'executable' ? 0o100755 : 0o100644) ||
                await objectHash('blob', before.bytes, selection.scope.format, this.#transport.crypto) !== row.object_id) fail('Import tree entry and complete native blob disagree.');
            check(); total += before.bytes.length;
            if (total > PATCH_LIMIT) fail('Existing and imported bytes exceed the combined 1 MiB draft budget.');
          }
          captured.push({ ...entry, before });
        }
        const changes = [], unchanged = [];
        for (const entry of captured) {
          check(); const buffer = await entry.file.arrayBuffer(); check();
          if (!(buffer instanceof ArrayBuffer) || buffer.byteLength !== entry.size || entry.file.size !== entry.size) fail('Imported file bytes were truncated or changed.');
          const bytes = fileBytes(new Uint8Array(buffer).slice(), true);
          const mode = plan.mode === 'preserve' ? entry.before?.mode ?? 0o100644 : Number.parseInt(plan.mode, 8);
          if (entry.before && mode === entry.before.mode && bytes.length === entry.before.bytes.length && bytes.every((b, i) => b === entry.before.bytes[i])) {
            unchanged.push(entry.path_hex);
          } else changes.push({ path_hex: entry.path_hex, before: entry.before, after: { bytes, mode } });
        }
        const combined = [...plan.retained, ...changes];
        const edits = combined.length ? fullFilePatch(combined, { allowBinary: true }).edits : [];
        check(); return { selection, edits, imported: changes.map(e => e.path_hex), unchanged,
          created: changes.filter(e => e.before === null).length, updated: changes.filter(e => e.before !== null).length,
          scannedPages: pages, sourceBytes: total - plan.bytes, published: false };
      } finally { clearTimeout(timer); }
    });
  }
  async prepareEdits(edits, metadata) {
    return this.#exclusive(async () => {
      this.#noPending(); this.invalidateCandidate();
      // Literal byte hunks are already owned by the native exact patch engine.
      // NUL bytes are payload, not Git binary-patch control records.
      const patch = fullFilePatch(edits, { allowBinary: true }), meta = commitMetadata(metadata);
      return this.#prepare(patch.bytes, meta, patch.edits);
    });
  }
  async preparePatch(bytes, metadata) {
    return this.#exclusive(async () => {
      this.#noPending(); this.invalidateCandidate();
      if (!(bytes instanceof Uint8Array) || !bytes.length || bytes.length > PATCH_LIMIT) fail('Choose a nonempty Git patch of at most 1 MiB.');
      return this.#prepare(bytes.slice(), commitMetadata(metadata), null);
    });
  }
  async #prepare(bytes, metadata, edits) {
    if (!this.#selection) fail('Select an immutable branch base first.');
    this.invalidateCandidate();
    const selection = copy(this.#selection), serial = this.#serial, epoch = this.#transport.epoch, crypto = this.#transport.crypto;
    const expected = edits === null ? null : await editManifest(edits, selection.scope.format, crypto);
    const patchSha = await digest(bytes, crypto), command = { ...selection.fields, ...metadata };
    const boundary = makeBoundary(form(command), bytes, crypto), upload = sourceUpload(command, bytes, 'patch', boundary);
    this.#check(serial, epoch);
    const response = await this.#transport.request('source/prepare', { method: 'POST', body: upload.bytes,
      contentType: upload.contentType, maximum: PREPARE_LIMIT, binary: true });
    this.#check(serial, epoch);
    const artifact = await prepared(response, selection.fields, selection.scope, patchSha, expected, crypto);
    this.#check(serial, epoch);
    const inspectBoundary = makeBoundary(form(artifact.fields), artifact.bundle, crypto);
    const inspectUpload = sourceUpload(artifact.fields, artifact.bundle, 'bundle', inspectBoundary);
    const { value: reply } = await this.#transport.request('source/inspect', { method: 'POST', body: inspectUpload.bytes,
      contentType: inspectUpload.contentType, maximum: 32 * 1024 * 1024 });
    await inspected(reply, artifact, crypto); this.#check(serial, epoch);
    this.#artifact = { ...artifact, inspection: reply };
    return this.candidate;
  }
  async stageApply() {
    return this.#exclusive(async () => {
      this.#noPending();
      if (!this.#artifact) fail('Native candidate inspection must finish before preparing publication.');
      const artifact = this.#artifact, serial = this.#serial, epoch = this.#transport.epoch, crypto = this.#transport.crypto;
      const fields = copy(artifact.fields), scope = copy(artifact.scope), bundle = artifact.bundle.slice();
      const nonce = hex(crypto.getRandomValues(new Uint8Array(16))), fingerprint = this.#transport.fingerprint;
      const upload = sourceUpload(fields, bundle, 'bundle', `fg-source-edit-${nonce}`);
      const key = await retryKey(this.#transport.root, fingerprint, scope, nonce, fields, upload, crypto);
      const requestSha256 = await digest(upload.bytes, crypto); this.#check(serial, epoch);
      this.#pending = { fields, scope, bundle, nonce, fingerprint, key, ...upload, requestSha256,
        sent: false, exported: false, observedTx: null, observedPrincipal: null };
      return this.pending;
    });
  }
  discardUnsent() {
    if (this.#busy || !this.#pending || this.#pending.sent || this.#pending.exported) fail('Only an unsent, unexported local request can be discarded.');
    this.#pending = null;
  }
  #settle(result, pending) {
    if (this.#pending !== pending) fail('Saved request changed while resolving its outcome.');
    if (result.terminal) {
      this.#pending = null; this.#artifact = null; this.#selection = null; this.#serial += 1;
    } else {
      if (result.tx) pending.observedTx = result.tx;
      if (result.principal) pending.observedPrincipal = result.principal;
    }
    return result;
  }
  async send() {
    return this.#exclusive(async () => {
      const pending = this.#pending; if (!pending) fail('Prepare an exact publication first.');
      if (pending.fingerprint !== this.#transport.fingerprint) fail('Use the original request credential.');
      pending.sent = true; // Admission responsibility begins before transport, not after a reply.
      try {
        const { value, status } = await this.#transport.request('source/apply', { method: 'POST', body: pending.bytes,
          contentType: pending.contentType, key: pending.key, statuses: [200, 409], maximum: 32 * 1024, read: false });
        return this.#settle(publication(value, pending, status), pending);
      } catch (error) { error.outcomeUnknown = true; throw error; }
    });
  }
  async recover() {
    return this.#exclusive(async () => {
      const pending = this.#pending; if (!pending) fail('No original request is available to recover.');
      const { value } = await this.#transport.request('outcomes', { method: 'POST', key: pending.key, maximum: 32 * 1024, read: false });
      return this.#settle(recovery(value, pending), pending);
    });
  }
  exportReceipt() {
    if (this.#busy || !this.#pending) fail('No stable request receipt is available.');
    const p = this.#pending;
    const receipt = JSON.stringify({ type: 'frankengit-source-retry-v1', origin: this.#transport.root.origin,
      route: this.#transport.root.route, fields: p.fields, scope: p.scope, fingerprint: p.fingerprint,
      nonce: p.nonce, key: p.key, bundle_base64: base64(p.bundle), observedTx: p.observedTx, observedPrincipal: p.observedPrincipal });
    if (utf8.encode(receipt).length > RECEIPT_LIMIT) fail('Recovery receipt exceeds limit.');
    p.exported = true; return receipt;
  }
  async restoreReceipt(encoded) {
    return this.#exclusive(async () => {
      this.#noPending();
      if (typeof encoded !== 'string' || encoded.length > RECEIPT_LIMIT || utf8.encode(encoded).length > RECEIPT_LIMIT) fail('Oversized recovery receipt.');
      const receipt = JSON.parse(encoded);
      keys(receipt, ['type', 'origin', 'route', 'fields', 'scope', 'fingerprint', 'nonce', 'key', 'bundle_base64', 'observedTx', 'observedPrincipal']);
      if (receipt.type !== 'frankengit-source-retry-v1' || receipt.origin !== this.#transport.root.origin || receipt.route !== this.#transport.root.route ||
          receipt.fingerprint !== this.#transport.fingerprint || !/^[0-9a-f]{32}$/.test(receipt.nonce)) fail('Recovery receipt belongs to another route or credential.');
      const scope = receiptScope(receipt.scope), fields = coordinates(receipt.fields);
      if (!fields.candidate_commit || fields.object_format !== scope.format || (this.#scope && ['tenant', 'repository', 'incarnation', 'format'].some(key => scope[key] !== this.#scope[key]))) fail('Recovery scope changed.');
      const bundle = fromBase64(receipt.bundle_base64), upload = sourceUpload(fields, bundle, 'bundle', `fg-source-edit-${receipt.nonce}`);
      const serial = this.#serial, epoch = this.#transport.epoch;
      const key = await retryKey(this.#transport.root, receipt.fingerprint, scope, receipt.nonce, fields, upload, this.#transport.crypto);
      if (key !== receipt.key) fail('Recovery request does not match its original idempotency key.');
      if (receipt.observedTx !== null) opaque(receipt.observedTx);
      if (receipt.observedPrincipal !== null) {
        if (!/^[0-9a-f]{32}$/.test(receipt.observedPrincipal)) fail('Invalid recovered principal.');
      }
      const requestSha256 = await digest(upload.bytes, this.#transport.crypto); this.#check(serial, epoch);
      this.invalidateCandidate(); this.#selection = null;
      this.#pending = { fields, scope, bundle, nonce: receipt.nonce, fingerprint: receipt.fingerprint,
        key, ...upload, requestSha256, sent: true, exported: true,
        observedTx: receipt.observedTx, observedPrincipal: receipt.observedPrincipal };
      return this.pending;
    });
  }
}
