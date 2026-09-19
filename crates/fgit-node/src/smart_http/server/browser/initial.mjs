// Creation is a distinct expected-absent command, never an update with a fake
// zero parent. A lost reply retains the exact command, bundle and retry key.
import { Transport, fail, keys, copy, utf8, hex, opaque, principal, form } from './pulls-core.mjs';
import { digest, makeBoundary } from './pulls-candidate.mjs';
import { recovery, base64, fromBase64, receiptScope, RECEIPT_LIMIT } from './pulls-actions.mjs';
import { sourceUpload } from './source-edit-protocol.mjs';
import { initialFields, initialPlan, verifyInitial, initialPublication, PREPARE_LIMIT } from './initial-plan.mjs';
async function retryKey(root, fingerprint, scope, nonce, fields, upload, crypto) {
  const input = JSON.stringify(['frankengit-initial-source-apply-v1', root.origin, root.route, fingerprint,
    scope.tenant, scope.repository, scope.incarnation, scope.format, fields.ref, fields.expected_absent,
    fields.candidate_commit, nonce, upload.contentType, await digest(upload.bytes, crypto)]);
  return `fginit1-${nonce}-${await digest(utf8.encode(input), crypto)}`;
}
export class InitialSourceClient {
  #transport; #scope = null; #artifact = null; #pending = null; #busy = false; #serial = 0;
  constructor(options) { this.#transport = new Transport({ ...options, pageSuffix: '/ui/initial/' }); }
  get connected() { return this.#transport.connected; }
  get busy() { return this.#busy; }
  get candidate() {
    const a = this.#artifact;
    return a ? copy({ fields: a.fields, scope: a.scope, snapshot: a.snapshot, preparation: a.metadata,
      sha256: a.sha256, bundleBytes: a.bundle.length, files: a.files }) : null;
  }
  get pending() {
    const p = this.#pending;
    return p ? copy({ fields: p.fields, scope: p.scope, key: p.key, bytes: p.bytes.length, requestSha256: p.requestSha256,
      sent: p.sent, exported: p.exported, observedTx: p.observedTx, observedPrincipal: p.observedPrincipal }) : null;
  }
  async connect(token) { this.disconnect(); await this.#transport.connect(token, this.#pending?.fingerprint ?? null); }
  disconnect() { this.#serial++; this.#transport.disconnect(); this.#scope = null; this.#artifact = null; }
  invalidateCandidate() { this.#serial++; this.#transport.cancelReads(); this.#artifact = null; }
  #check(serial, epoch) {
    if (!this.connected || serial !== this.#serial || epoch !== this.#transport.epoch) fail('Initial preparation cancelled or changed.');
  }
  #noPending() { if (this.#pending) fail('Resolve the original publication before creating another request.'); }
  async #exclusive(work) {
    if (this.#busy) fail('An initial-commit operation is already running.');
    if (!this.connected) fail('Connect an explicitly scoped repository token first.');
    this.#busy = true; try { return await work(); } finally { this.#busy = false; }
  }
  async prepare(values, files, metadata) {
    return this.#exclusive(async () => {
      this.#noPending(); this.invalidateCandidate();
      const fields = initialFields(values), serial = this.#serial, epoch = this.#transport.epoch, crypto = this.#transport.crypto;
      const check = () => this.#check(serial, epoch);
      const plan = await initialPlan(files, metadata, fields.object_format, crypto, check);
      const command = { ...fields, ...plan.metadata };
      const upload = sourceUpload(command, plan.patch, 'patch', makeBoundary(form(command), plan.patch, crypto)); check();
      const response = await this.#transport.request('source/initial/prepare', { method: 'POST', body: upload.bytes,
        contentType: upload.contentType, maximum: PREPARE_LIMIT, binary: true }); check();
      const artifact = await verifyInitial(response, fields, plan, this.#scope, crypto); check();
      this.#scope = artifact.scope; this.#artifact = artifact; return this.candidate;
    });
  }
  async stageApply() {
    return this.#exclusive(async () => {
      this.#noPending();
      if (!this.#artifact) fail('Verify a complete native initial-commit preparation first.');
      const serial = this.#serial, epoch = this.#transport.epoch, crypto = this.#transport.crypto;
      const artifact = this.#artifact, fields = copy(artifact.fields), scope = copy(artifact.scope), bundle = artifact.bundle.slice();
      const fingerprint = this.#transport.fingerprint, nonce = hex(crypto.getRandomValues(new Uint8Array(16)));
      const upload = sourceUpload(fields, bundle, 'bundle', `fg-initial-apply-${nonce}`);
      const key = await retryKey(this.#transport.root, fingerprint, scope, nonce, fields, upload, crypto);
      const requestSha256 = await digest(upload.bytes, crypto); this.#check(serial, epoch);
      this.#pending = { fields, scope, bundle, fingerprint, nonce, key, ...upload, requestSha256,
        sent: false, exported: false, observedTx: null, observedPrincipal: null };
      return this.pending;
    });
  }
  discardUnsent() {
    if (this.#busy || !this.#pending || this.#pending.sent || this.#pending.exported) fail('Only an unsent, unexported request may be discarded.');
    this.#pending = null;
  }
  #settle(result, pending) {
    if (pending !== this.#pending) fail('The original request changed during recovery.');
    if (result.terminal) { this.#pending = null; this.#artifact = null; this.#serial++; }
    else { if (result.tx) pending.observedTx = result.tx; if (result.principal) pending.observedPrincipal = result.principal; }
    return result;
  }
  async send() {
    return this.#exclusive(async () => {
      const p = this.#pending; if (!p) fail('No initial publication is prepared.');
      if (p.fingerprint !== this.#transport.fingerprint) fail('Use the original request credential.');
      // No current branch pre-read here: terminal retries must precede branch
      // presence checks inside the native publisher, which owns those semantics.
      p.sent = true;
      try {
        const { value, status } = await this.#transport.request('source/initial/apply', { method: 'POST', body: p.bytes,
          contentType: p.contentType, key: p.key, statuses: [200, 409], maximum: 32 * 1024, read: false });
        return this.#settle(initialPublication(value, p, status), p);
      } catch (error) { error.outcomeUnknown = true; throw error; }
    });
  }
  async recover() {
    return this.#exclusive(async () => {
      const p = this.#pending; if (!p) fail('No original request is available.');
      const { value } = await this.#transport.request('outcomes', { method: 'POST', key: p.key, maximum: 32 * 1024, read: false });
      return this.#settle(recovery(value, p), p);
    });
  }
  exportReceipt() {
    if (this.#busy || !this.#pending) fail('No stable initial publication can be saved.');
    const p = this.#pending;
    const out = JSON.stringify({ type: 'frankengit-initial-source-retry-v1', origin: this.#transport.root.origin, route: this.#transport.root.route,
      fields: p.fields, scope: p.scope, fingerprint: p.fingerprint, nonce: p.nonce, key: p.key, bundle_base64: base64(p.bundle),
      observedTx: p.observedTx, observedPrincipal: p.observedPrincipal });
    if (utf8.encode(out).length > RECEIPT_LIMIT) fail('Initial recovery receipt exceeds limit.');
    p.exported = true; return out;
  }
  async restoreReceipt(encoded) {
    return this.#exclusive(async () => {
      this.#noPending();
      if (typeof encoded !== 'string' || encoded.length > RECEIPT_LIMIT || utf8.encode(encoded).length > RECEIPT_LIMIT) fail('Oversized initial recovery receipt.');
      const r = JSON.parse(encoded);
      keys(r, ['type', 'origin', 'route', 'fields', 'scope', 'fingerprint', 'nonce', 'key', 'bundle_base64', 'observedTx', 'observedPrincipal']);
      if (r.type !== 'frankengit-initial-source-retry-v1' || r.origin !== this.#transport.root.origin || r.route !== this.#transport.root.route ||
          r.fingerprint !== this.#transport.fingerprint || typeof r.nonce !== 'string' || !/^[0-9a-f]{32}$/.test(r.nonce)) fail('Initial receipt belongs to another route or credential.');
      const fields = initialFields(r.fields, true), scope = receiptScope(r.scope);
      if (fields.object_format !== scope.format || (this.#scope && Object.keys(scope).some(k => scope[k] !== this.#scope[k]))) fail('Initial recovery repository changed.');
      const bundle = fromBase64(r.bundle_base64), upload = sourceUpload(fields, bundle, 'bundle', `fg-initial-apply-${r.nonce}`);
      const serial = this.#serial, epoch = this.#transport.epoch, crypto = this.#transport.crypto;
      const key = await retryKey(this.#transport.root, r.fingerprint, scope, r.nonce, fields, upload, crypto);
      if (key !== r.key) fail('Initial receipt changed its original request identity.');
      if (r.observedTx !== null) opaque(r.observedTx);
      if (r.observedPrincipal !== null) principal(r.observedPrincipal);
      const requestSha256 = await digest(upload.bytes, crypto); this.#check(serial, epoch); this.invalidateCandidate();
      this.#pending = { fields, scope, bundle, fingerprint: r.fingerprint, nonce: r.nonce, key, ...upload, requestSha256,
        sent: true, exported: true, observedTx: r.observedTx, observedPrincipal: r.observedPrincipal };
      return this.pending;
    });
  }
}
