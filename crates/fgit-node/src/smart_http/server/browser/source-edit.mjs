// A source-authoring session owns one inspected candidate and at most one exact
// unresolved publication. Transport failure is never a rollback receipt.
import { Transport, fail, keys, record, copy, integer, opaque, hex, unhex, utf8,
  binding, pinned, oid, reference, form, branch, format } from './pulls-core.mjs';
import { makeBoundary, digest } from './pulls-candidate.mjs';
import { recovery, base64, fromBase64, receiptScope, RECEIPT_LIMIT } from './pulls-actions.mjs';
import { FILE_LIMIT, PATCH_LIMIT, fileBytes, sourcePath, fullFilePatch } from './source-edit-patch.mjs';
import { coordinates, commitMetadata, matchReference, objectHash, sourceUpload, prepared,
  inspected, publication, retryKey, editManifest, PREPARE_LIMIT } from './source-edit-protocol.mjs';

function readOnly(reply) {
  if (reply.read_only !== true || reply.transaction_created !== false || reply.published !== false) fail('Source read unexpectedly claims publication.');
}
export class SourceEditClient {
  #transport; #scope = null; #selection = null; #artifact = null; #pending = null; #busy = false; #serial = 0;
  constructor(options) { this.#transport = new Transport({ ...options, pageSuffix: '/ui/source/' }); }
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
      const { value: reply } = await this.#transport.request('source/blob', { method: 'POST',
        body: form({ ref: selection.fields.ref, object_format: selection.fields.object_format,
          expected_head: selection.snapshot, expected_commit: selection.fields.expected_commit,
          path_hex: pathHex, offset: 0, limit: FILE_LIMIT }), maximum: FILE_LIMIT * 2 + 16 * 1024 });
      pinned(reply, selection.scope, selection.snapshot); readOnly(reply); matchReference(reply, selection.fields.ref);
      if (reply.type !== 'source_blob' || reply.path_hex !== pathHex || reply.offset !== 0 || reply.next_offset !== null ||
          reply.symlink_followed !== false || !['file', 'executable'].includes(reply.kind) ||
          oid(reply.source_commit, selection.scope.format) !== selection.fields.expected_commit ||
          oid(reply.root_tree, selection.scope.format) !== selection.tree) fail('A complete ordinary file at the selected base is required.');
      integer(reply.total_bytes, 'complete file size', 0, FILE_LIMIT);
      const bytes = fileBytes(unhex(reply.content_hex, FILE_LIMIT), true);
      if (reply.total_bytes !== bytes.length || reply.returned_bytes !== bytes.length ||
          await objectHash('blob', bytes, selection.scope.format, this.#transport.crypto) !== oid(reply.object_id, selection.scope.format)) fail('File bytes do not match their native identity.');
      this.#check(serial, epoch);
      return { path_hex: pathHex, before: { bytes, mode: reply.kind === 'executable' ? 0o100755 : 0o100644 } };
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
