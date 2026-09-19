// One replay session: read-only construction and inspection, then a separately
// confirmed ordinary source publication with original-key recovery.
import { Transport, fail, keys, copy, format, branch, oid, opaque, principal, pinned, form, hex, utf8 } from './pulls-core.mjs';
import { makeBoundary, digest } from './pulls-candidate.mjs';
import { recovery, base64, fromBase64, receiptScope, RECEIPT_LIMIT } from './pulls-actions.mjs';
import { coordinates, sourceUpload, publication, retryKey, matchReference } from './source-edit-protocol.mjs';
import { replayCommand, replayPrepared, replayInspected, resolutionChoices, resolutionUpload, PREPARE_LIMIT } from './replay-protocol.mjs';
export class ReplayClient {
  #transport; #scope = null; #selection = null; #report = null; #command = null; #direction = null;
  #artifact = null; #pending = null; #busy = false; #serial = 0;
  constructor(options) { this.#transport = new Transport({ ...options, pageSuffix: '/ui/replay/' }); }
  get connected() { return this.#transport.connected; }
  get busy() { return this.#busy; }
  get selection() { return this.#selection && copy(this.#selection); }
  get report() { return this.#report && copy(this.#report); }
  get candidate() { const a = this.#artifact; return a && copy({ fields: a.fields, direction: a.direction, metadata: a.metadata, inspection: a.inspection, bundleBytes: a.bundle.length, sha256: a.sha256 }); }
  get pending() { const p = this.#pending; return p && copy({ fields: p.fields, scope: p.scope, key: p.key, sent: p.sent, exported: p.exported, observedTx: p.observedTx, observedPrincipal: p.observedPrincipal }); }
  async connect(token) { this.disconnect(); await this.#transport.connect(token, this.#pending?.fingerprint ?? null); }
  disconnect() { this.cancel(); this.#transport.disconnect(); this.#scope = null; }
  invalidate() { this.#serial++; this.#transport.cancelReads(); this.#artifact = null; this.#report = null; this.#command = null; this.#direction = null; }
  cancel() { this.invalidate(); this.#selection = null; }
  #check(serial, epoch) { if (!this.connected || serial !== this.#serial || epoch !== this.#transport.epoch) fail('Replay cancelled or replaced.'); }
  #noPending() { if (this.#pending) fail('Resolve the original saved publication first.'); }
  async #exclusive(work) {
    if (this.#busy || !this.connected) fail('Connect first and finish the current operation.');
    this.#busy = true; try { return await work(); } finally { this.#busy = false; }
  }
  async select(target, source, algorithm) {
    return this.#exclusive(async () => {
      this.#noPending(); this.cancel(); target = branch(target); source = branch(source); format(algorithm);
      const serial = this.#serial, epoch = this.#transport.epoch;
      const load = async (ref, scope = this.#scope, head = null) => {
        const { value: r } = await this.#transport.request('source/tree', { method: 'POST', maximum: 32 * 1024,
          body: form({ ref, object_format: algorithm, limit: 1, ...(head ? { expected_head: head } : {}) }) });
        const selected = pinned(r, scope, head); matchReference(r, ref); this.#check(serial, epoch);
        if (r.type !== 'source_tree' || r.read_only !== true || r.transaction_created !== false || r.published !== false ||
            r.path_hex !== null || r.after_hex !== null || r.limit !== 1 || !Array.isArray(r.entries) || r.entries.length > 1 ||
            selected.binding.format !== algorithm || oid(r.object_id, algorithm) !== oid(r.root_tree, algorithm)) fail('Invalid replay branch selection.');
        opaque(r.source_rcr);
        return { ...selected, commit: oid(r.source_commit, algorithm), tree: r.root_tree };
      };
      const t = await load(target), s = source === target ? t : await load(source, t.binding, t.head);
      this.#check(serial, epoch); this.#scope = t.binding;
      this.#selection = { scope: t.binding, targetTree: t.tree, fields: { object_format: algorithm, target_ref: target,
        source_ref: source, expected_target: t.commit, expected_source: s.commit, expected_head: t.head } };
      return this.selection;
    });
  }
  async #finish(response, direction, command, selection, serial, epoch, previous = null, choices = null) {
    const { metadata, artifact } = await replayPrepared(response, direction, command, selection.scope, this.#transport.crypto, previous, choices);
    this.#check(serial, epoch);
    if (artifact) {
      const upload = sourceUpload(artifact.fields, artifact.bundle, 'bundle', makeBoundary(form(artifact.fields), artifact.bundle, this.#transport.crypto));
      const { value } = await this.#transport.request('source/inspect', { method: 'POST', body: upload.bytes, contentType: upload.contentType, maximum: 8 * 1024 * 1024 });
      artifact.inspection = await replayInspected(value, artifact, selection.targetTree, this.#transport.crypto);
      this.#check(serial, epoch);
    }
    this.#report = copy(metadata); this.#command = copy(command); this.#direction = direction; this.#artifact = artifact;
    return this.report;
  }
  async prepare(direction, input) {
    return this.#exclusive(async () => {
      this.#noPending(); this.invalidate();
      if (!this.#selection) fail('Select both branches at one snapshot first.');
      const selection = this.selection, command = replayCommand(direction, selection.fields, input), serial = this.#serial, epoch = this.#transport.epoch;
      const response = await this.#transport.request(`source/${direction}/prepare`, { method: 'POST', body: form(command), statuses: [200, 409], maximum: PREPARE_LIMIT, binary: true });
      return this.#finish(response, direction, command, selection, serial, epoch);
    });
  }
  async resolve(input) {
    return this.#exclusive(async () => {
      this.#noPending();
      if (!this.#selection || this.#report?.state !== 'conflicted' || !this.#command) fail('Prepare and inspect the original conflicts first.');
      const previous = this.report, command = copy(this.#command), direction = this.#direction, selection = this.selection;
      this.#artifact = null; const serial = this.#serial, epoch = this.#transport.epoch;
      const check = () => this.#check(serial, epoch), crypto = this.#transport.crypto;
      const choices = await resolutionChoices(previous, input, selection.scope.format, crypto, check);
      const upload = resolutionUpload(command, choices, hex(crypto.getRandomValues(new Uint8Array(16)))); check();
      const response = await this.#transport.request(`source/${direction}/resolve`, { method: 'POST', ...upload, statuses: [200, 409], maximum: PREPARE_LIMIT, binary: true });
      return this.#finish(response, direction, command, selection, serial, epoch, previous, choices);
    });
  }
  async stageApply() {
    return this.#exclusive(async () => {
      this.#noPending(); const a = this.#artifact;
      if (!a?.inspection) fail('Native replay inspection must finish before preparing publication.');
      const fields = copy(a.fields), scope = copy(a.scope), bundle = a.bundle.slice(), crypto = this.#transport.crypto;
      const nonce = hex(crypto.getRandomValues(new Uint8Array(16))), fingerprint = this.#transport.fingerprint;
      const serial = this.#serial, epoch = this.#transport.epoch;
      const upload = sourceUpload(fields, bundle, 'bundle', `fg-source-edit-${nonce}`);
      const key = await retryKey(this.#transport.root, fingerprint, scope, nonce, fields, upload, crypto); this.#check(serial, epoch);
      this.#pending = { fields, scope, bundle, nonce, fingerprint, key, ...upload, sent: false, exported: false, observedTx: null, observedPrincipal: null };
      return this.pending;
    });
  }
  discardUnsent() { if (this.#busy || !this.#pending || this.#pending.sent || this.#pending.exported) fail('Only unsent, unexported work can be discarded.'); this.#pending = null; }
  #settle(result, p) {
    if (p !== this.#pending) fail('Original replay publication changed.');
    if (result.terminal) { this.#pending = null; this.cancel(); }
    else { if (result.tx) p.observedTx = result.tx; if (result.principal) p.observedPrincipal = result.principal; }
    return result;
  }
  async send() {
    return this.#exclusive(async () => {
      const p = this.#pending; if (!p || p.fingerprint !== this.#transport.fingerprint) fail('Restore the original request and credential.');
      p.sent = true;
      try {
        const { value, status } = await this.#transport.request('source/apply', { method: 'POST', body: p.bytes, contentType: p.contentType, key: p.key, statuses: [200, 409], maximum: 32 * 1024, read: false });
        return this.#settle(publication(value, p, status), p);
      } catch (error) { error.outcomeUnknown = true; throw error; }
    });
  }
  async recover() {
    return this.#exclusive(async () => {
      const p = this.#pending; if (!p || p.fingerprint !== this.#transport.fingerprint) fail('Restore the original request and credential.');
      const { value } = await this.#transport.request('outcomes', { method: 'POST', key: p.key, maximum: 32 * 1024, read: false });
      return this.#settle(recovery(value, p), p);
    });
  }
  exportReceipt() {
    if (this.#busy || !this.#pending) fail('No stable publication is available.');
    const p = this.#pending;
    // The publication is the existing source/apply command, so its retry file
    // and key remain interoperable with the ordinary source editor.
    const encoded = JSON.stringify({ type: 'frankengit-source-retry-v1', origin: this.#transport.root.origin, route: this.#transport.root.route,
      fields: p.fields, scope: p.scope, fingerprint: p.fingerprint, nonce: p.nonce, key: p.key, bundle_base64: base64(p.bundle), observedTx: p.observedTx, observedPrincipal: p.observedPrincipal });
    if (utf8.encode(encoded).length > RECEIPT_LIMIT) fail('Recovery file exceeds 24 MiB.');
    p.exported = true; return encoded;
  }
  async restoreReceipt(encoded) {
    return this.#exclusive(async () => {
      this.#noPending();
      if (typeof encoded !== 'string' || encoded.length > RECEIPT_LIMIT || utf8.encode(encoded).length > RECEIPT_LIMIT) fail('Oversized retry file.');
      const r = JSON.parse(encoded);
      keys(r, ['type', 'origin', 'route', 'fields', 'scope', 'fingerprint', 'nonce', 'key', 'bundle_base64', 'observedTx', 'observedPrincipal']);
      if (r.type !== 'frankengit-source-retry-v1' || r.origin !== this.#transport.root.origin || r.route !== this.#transport.root.route ||
          r.fingerprint !== this.#transport.fingerprint || typeof r.nonce !== 'string' || !/^[0-9a-f]{32}$/.test(r.nonce)) fail('Retry file belongs to another route or credential.');
      const scope = receiptScope(r.scope), fields = coordinates(r.fields), bundle = fromBase64(r.bundle_base64);
      if (!fields.candidate_commit || scope.format !== fields.object_format || (this.#scope && Object.keys(scope).some(k => scope[k] !== this.#scope[k]))) fail('Retry scope changed.');
      const upload = sourceUpload(fields, bundle, 'bundle', `fg-source-edit-${r.nonce}`), serial = this.#serial, epoch = this.#transport.epoch;
      const key = await retryKey(this.#transport.root, r.fingerprint, scope, r.nonce, fields, upload, this.#transport.crypto);
      this.#check(serial, epoch); if (key !== r.key) fail('Retry file does not match the original request commitment.');
      if (r.observedTx !== null) opaque(r.observedTx); if (r.observedPrincipal !== null) principal(r.observedPrincipal);
      this.cancel(); this.#pending = { fields, scope, bundle, nonce: r.nonce, fingerprint: r.fingerprint, key, ...upload,
        sent: true, exported: true, observedTx: r.observedTx, observedPrincipal: r.observedPrincipal }; return this.pending;
    });
  }
}
