// One portable-transfer session. Native pack/closure admission and exact ref
// leases own publication; local checks only bind the bytes the user reviewed.
import { Transport, fail, keys, record, copy, format, pinned, hex, utf8, form, opaque, principal } from './pulls-core.mjs';
import { multipart, digest } from './pulls-candidate.mjs';
import { recovery, receiptScope, base64, fromBase64, RECEIPT_LIMIT } from './pulls-actions.mjs';
import { inspectBundle, transferCommand, exportIdentity, transferPublication, EXPORT_HEADERS, BUNDLE_LIMIT, exportInventory, exportManifest } from './transfers-protocol.mjs';
async function requestKey(root, fingerprint, scope, operation, nonce, upload, crypto) {
  const input = JSON.stringify(['frankengit-portable-bundle-v1', root.origin, root.route, fingerprint,
    [scope.tenant, scope.repository, scope.incarnation, scope.format], operation, nonce, upload.contentType, await digest(upload.bytes, crypto)]);
  return `fgbundle1-${nonce}-${await digest(utf8.encode(input), crypto)}`;
}
export class TransferClient {
  #transport; #scope = null; #selected = null; #bundle = null; #exported = null; #pending = null; #busy = false; #serial = 0;
  constructor(options) { this.#transport = new Transport({ ...options, pageSuffix: '/ui/transfers/' }); }
  get connected() { return this.#transport.connected; }
  get busy() { return this.#busy; }
  get selection() { return this.#selected && copy(this.#selected); }
  get bundle() { return this.#bundle && copy(this.#bundle.summary); }
  get exported() { return this.#exported && copy(this.#exported.summary); }
  get pending() {
    const p = this.#pending;
    return p ? copy({ operation: p.operation, scope: p.scope, fields: p.fields, count: p.count,
      updates: p.updates, key: p.key, bundleBytes: p.bundle.length, sent: p.sent, exported: p.exported,
      observedTx: p.observedTx, observedPrincipal: p.observedPrincipal }) : null;
  }
  async connect(token) { this.disconnect(); await this.#transport.connect(token, this.#pending?.fingerprint ?? null); }
  cancel() { this.#serial++; this.#transport.cancelReads(); this.#selected = null; this.#bundle = null; this.#exported = null; }
  disconnect() { this.cancel(); this.#transport.disconnect(); this.#scope = null; }
  invalidateBundle() { this.#serial++; this.#transport.cancelReads(); this.#bundle = null; }
  #check(serial, epoch) { if (!this.connected || serial !== this.#serial || epoch !== this.#transport.epoch) fail('Transfer cancelled or selection changed.'); }
  #noPending() { if (this.#pending) fail('Resolve the original transfer before preparing another.'); }
  async #exclusive(work) {
    if (!this.connected || this.#busy) fail('Connect first and finish the current transfer operation.');
    this.#busy = true; try { return await work(); } finally { this.#busy = false; }
  }
  async select(algorithm) {
    return this.#exclusive(async () => {
      this.#noPending(); this.cancel(); format(algorithm);
      const serial = this.#serial, epoch = this.#transport.epoch;
      const { value: r } = await this.#transport.request('source/refs', { method: 'POST',
        body: form({ object_format: algorithm, namespace: 'all', limit: 1 }), maximum: 32 * 1024 });
      const selected = pinned(r, this.#scope);
      if (r.type !== 'source_refs' || r.namespace !== 'all' || r.after !== null || r.limit !== 1 ||
          r.read_only !== true || r.transaction_created !== false || r.published !== false || r.direct_refs_only !== true ||
          !Array.isArray(r.refs) || r.refs.length > 1 || selected.binding.format !== algorithm) fail('Invalid target repository selection.');
      this.#check(serial, epoch); this.#scope = selected.binding;
      this.#selected = { scope: selected.binding, head: selected.head }; return this.selection;
    });
  }
  async load(input) {
    return this.#exclusive(async () => {
      this.#noPending(); this.invalidateBundle();
      if (!this.#selected) fail('Select the target repository first.');
      const serial = this.#serial, epoch = this.#transport.epoch;
      const plan = await inspectBundle(input, this.#transport.crypto, () => this.#check(serial, epoch));
      if (plan.summary.object_format !== this.#selected.scope.format) fail('Bundle and target repository hash domains differ.');
      this.#bundle = plan; return this.bundle;
    });
  }
  async exportBundle({ verifyInventory = false } = {}) {
    return this.#exclusive(async () => {
      this.#noPending(); this.#exported = null;
      if (!this.#selected) fail('Select a repository snapshot before exporting.');
      const selected = this.selection, serial = this.#serial, epoch = this.#transport.epoch;
      if (typeof verifyInventory !== 'boolean') fail('Choose explicit export inventory verification.');
      const inventory = verifyInventory ? await exportInventory(this.#transport, selected, () => this.#check(serial, epoch)) : null;
      const response = await this.#transport.request('source/bundle/export', { method: 'POST', binary: true,
        body: form({ object_format: selected.scope.format, expected_head: selected.head }), maximum: BUNDLE_LIMIT, headerNames: EXPORT_HEADERS });
      const identity = exportIdentity(response, selected);
      const plan = await inspectBundle(response.value, this.#transport.crypto, () => this.#check(serial, epoch));
      if (plan.summary.sha256 !== identity.sha256 || plan.summary.object_format !== selected.scope.format) fail('Export bytes do not match their transport identity.');
      this.#check(serial, epoch);
      if (inventory && (response.headers['x-fgit-source-head'] !== inventory.source_head ||
          JSON.stringify(plan.summary.refs) !== JSON.stringify(inventory.refs))) fail('Export bundle does not match every ref in the selected snapshot.');
      this.#exported = { bytes: plan.bytes, summary: { ...plan.summary, scope: identity.scope, snapshot: identity.head,
        ...(inventory ? { source_head: inventory.source_head, snapshot_refs_checked: true } : {}) } };
      if (inventory) {
        try { exportManifest(this.#transport.root, this.#exported.summary); }
        catch (error) { this.#exported = null; throw error; }
      }
      return this.exported;
    });
  }
  exportBytes() { if (!this.connected || !this.#exported) fail('No complete verified export is available.'); return this.#exported.bytes.slice(); }
  exportManifest() {
    if (this.#busy || !this.connected || !this.#exported) fail('No stable verified snapshot export is available.');
    return exportManifest(this.#transport.root, this.#exported.summary);
  }
  async stage(operation, mappings = []) {
    return this.#exclusive(async () => {
      this.#noPending(); if (!this.#bundle || !this.#selected) fail('Select a target and inspect the exact bundle first.');
      const command = transferCommand(operation, this.#bundle.summary, mappings), scope = copy(this.#selected.scope);
      const serial = this.#serial, epoch = this.#transport.epoch, crypto = this.#transport.crypto;
      const nonce = hex(crypto.getRandomValues(new Uint8Array(16))), fingerprint = this.#transport.fingerprint;
      const bundle = this.#bundle.bytes.slice(), upload = multipart(form(command.fields), bundle, `fg-transfer-${nonce}`);
      const key = await requestKey(this.#transport.root, fingerprint, scope, operation, nonce, upload, crypto);
      this.#check(serial, epoch);
      this.#pending = { ...command, operation, scope, bundle, nonce, fingerprint, key, ...upload,
        sent: false, exported: false, observedTx: null, observedPrincipal: null }; return this.pending;
    });
  }
  discardUnsent() {
    if (this.#busy || !this.#pending || this.#pending.sent || this.#pending.exported) fail('Only an unsent, unexported transfer can be discarded.');
    this.#pending = null;
  }
  #settle(result, pending) {
    if (pending !== this.#pending) fail('Original transfer changed.');
    if (result.terminal) { this.#pending = null; this.cancel(); }
    else { if (result.tx) pending.observedTx = result.tx; if (result.principal) pending.observedPrincipal = result.principal; }
    return result;
  }
  async send() {
    return this.#exclusive(async () => {
      const p = this.#pending; if (!p || p.fingerprint !== this.#transport.fingerprint) fail('Restore the original transfer and credential.');
      p.sent = true;
      try {
        // No new target-ref or snapshot read may rewrite the original leases.
        const { value, status } = await this.#transport.request(`source/bundle/${p.operation}`, {
          method: 'POST', body: p.bytes, contentType: p.contentType, key: p.key,
          statuses: [200, 409], maximum: 32 * 1024, read: false });
        return this.#settle(transferPublication(value, p, status), p);
      } catch (error) { error.outcomeUnknown = true; throw error; }
    });
  }
  async recover() {
    return this.#exclusive(async () => {
      const p = this.#pending; if (!p || p.fingerprint !== this.#transport.fingerprint) fail('Restore the original transfer and credential.');
      const { value } = await this.#transport.request('outcomes', { method: 'POST', key: p.key, maximum: 32 * 1024, read: false });
      return this.#settle(recovery(value, p), p);
    });
  }
  exportReceipt() {
    if (this.#busy || !this.#pending) fail('No stable transfer receipt is available.');
    const p = this.#pending;
    const encoded = JSON.stringify({ type: 'frankengit-transfer-retry-v1', origin: this.#transport.root.origin, route: this.#transport.root.route,
      operation: p.operation, mappings: p.updates.map(({ source_hex, destination_hex, expected_old }) => ({ source_hex, destination_hex, expected_old })),
      scope: p.scope, nonce: p.nonce, fingerprint: p.fingerprint, key: p.key, bundle_base64: base64(p.bundle),
      observedTx: p.observedTx, observedPrincipal: p.observedPrincipal });
    if (utf8.encode(encoded).length > RECEIPT_LIMIT) fail('Transfer receipt exceeds 24 MiB.');
    p.exported = true; return encoded;
  }
  async restoreReceipt(encoded) {
    return this.#exclusive(async () => {
      this.#noPending(); if (typeof encoded !== 'string' || encoded.length > RECEIPT_LIMIT || utf8.encode(encoded).length > RECEIPT_LIMIT) fail('Oversized transfer receipt.');
      const r = JSON.parse(encoded);
      keys(r, ['type', 'origin', 'route', 'operation', 'mappings', 'scope', 'nonce', 'fingerprint', 'key', 'bundle_base64', 'observedTx', 'observedPrincipal']);
      if (r.type !== 'frankengit-transfer-retry-v1' || r.origin !== this.#transport.root.origin || r.route !== this.#transport.root.route ||
          r.fingerprint !== this.#transport.fingerprint || typeof r.nonce !== 'string' || !/^[0-9a-f]{32}$/.test(r.nonce)) fail('Transfer receipt belongs to another route or credential.');
      const scope = receiptScope(r.scope);
      if (this.#scope && Object.keys(scope).some(k => scope[k] !== this.#scope[k])) fail('Target repository identity changed.');
      const serial = this.#serial, epoch = this.#transport.epoch, crypto = this.#transport.crypto;
      const plan = await inspectBundle(fromBase64(r.bundle_base64), crypto, () => this.#check(serial, epoch));
      if (plan.summary.object_format !== scope.format) fail('Receipt bundle hash domain changed.');
      const command = transferCommand(r.operation, plan.summary, r.operation === 'import' ? [] : r.mappings);
      const actualMappings = command.updates.map(({ source_hex, destination_hex, expected_old }) => ({ source_hex, destination_hex, expected_old }));
      if (JSON.stringify(r.mappings) !== JSON.stringify(actualMappings)) fail('Receipt changed the complete mapping set.');
      const upload = multipart(form(command.fields), plan.bytes, `fg-transfer-${r.nonce}`);
      const key = await requestKey(this.#transport.root, r.fingerprint, scope, r.operation, r.nonce, upload, crypto);
      this.#check(serial, epoch); if (key !== r.key) fail('Transfer receipt no longer commits to the original request.');
      if (r.observedTx !== null) opaque(r.observedTx); if (r.observedPrincipal !== null) principal(r.observedPrincipal);
      this.cancel();
      this.#pending = { ...command, operation: r.operation, scope, bundle: plan.bytes, nonce: r.nonce, fingerprint: r.fingerprint, key,
        ...upload, sent: true, exported: true, observedTx: r.observedTx, observedPrincipal: r.observedPrincipal }; return this.pending;
    });
  }
}
