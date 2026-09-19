// One bounded native tag session. Local previews grant no permission and send
// nothing; terminal decisions and original-key recovery use native admission.
import { Transport, fail, copy, keys, integer, format, hex, utf8, form, opaque, principal } from './pulls-core.mjs';
import { recovery, receiptScope } from './pulls-actions.mjs';
import { TAG_LIMITS, RETRY_LIMIT, nativeRef, tagPlan, tagRefPage, tagInspection, tagPublication } from './tags-protocol.mjs';
export { RETRY_LIMIT };
async function retryKey(root, fingerprint, scope, operation, nonce, body, crypto) {
  const bytes = utf8.encode(JSON.stringify(['native-tags-v1', root.origin, root.route, fingerprint,
    [scope.tenant, scope.repository, scope.incarnation, scope.format], operation, nonce, body]));
  return `fgtag1-${nonce}-${hex(new Uint8Array(await crypto.subtle.digest('SHA-256', bytes)))}`;
}
export class TagClient {
  #transport; #scope = null; #page = null; #query = null; #rows = new Map(); #inspection = null; #pending = null; #busy = false; #serial = 0;
  constructor(options) { this.#transport = new Transport({ ...options, pageSuffix: '/ui/tags/' }); }
  get connected() { return this.#transport.connected; }
  get busy() { return this.#busy; }
  get page() { return this.#page && copy(this.#page); }
  get refs() { return copy([...this.#rows.values()]); }
  get inspection() { return this.#inspection && copy(this.#inspection); }
  get pending() {
    const p = this.#pending;
    return p && copy({ operation: p.operation, fields: p.fields, scope: p.scope, body_hex: p.body_hex,
      expected_object: p.expected_object, new_object: p.new_object, key: p.key, sent: p.sent, exported: p.exported,
      observedTx: p.observedTx, observedPrincipal: p.observedPrincipal });
  }
  async connect(token) { this.disconnect(); await this.#transport.connect(token, this.#pending?.fingerprint ?? null); }
  #clear() { this.#page = null; this.#query = null; this.#rows.clear(); this.#inspection = null; }
  cancel() { this.#serial++; this.#transport.cancelReads(); this.#clear(); }
  disconnect() { this.cancel(); this.#transport.disconnect(); this.#scope = null; }
  #check(serial, epoch) { if (!this.connected || serial !== this.#serial || epoch !== this.#transport.epoch) fail('Tag operation cancelled or superseded.'); }
  #noPending() { if (this.#pending) fail('Resolve the original tag request first.'); }
  async #exclusive(work) {
    if (this.#busy || !this.connected) fail('Connect first and finish the current operation.');
    this.#busy = true; try { return await work(); } finally { this.#busy = false; }
  }
  async list({ objectFormat = 'sha1', limit = 50, next = false } = {}) {
    return this.#exclusive(async () => {
      this.#noPending(); let query;
      if (next) {
        if (!this.#page || this.#page.next_after === null) fail('No next reference page.');
        query = { ...this.#query, after: this.#page.next_after, expected_head: this.#page.snapshot_token };
      } else {
        this.cancel(); query = { object_format: format(objectFormat), namespace: 'all', limit: integer(limit, 'page size', 1, 100) };
      }
      if (this.#rows.size + query.limit > 2048) fail('Reference session limit reached.');
      const serial = this.#serial, epoch = this.#transport.epoch;
      const { value } = await this.#transport.request('source/refs', { method: 'POST', body: form(query), maximum: 1024 * 1024 });
      const selected = tagRefPage(value, query, this.#scope); this.#check(serial, epoch);
      this.#scope = selected.binding; this.#query = query; this.#page = copy(value);
      for (const row of value.refs) this.#rows.set(row.ref_hex, copy(row)); return this.page;
    });
  }
  #selected(ref) {
    nativeRef(ref); const row = this.#rows.get(ref);
    if (!row || !this.#page) fail('Select an exact reference from this snapshot.'); return row;
  }
  async inspect(ref) {
    return this.#exclusive(async () => {
      this.#noPending(); this.#inspection = null; nativeRef(ref, 'refs/tags/');
      const row = this.#selected(ref), serial = this.#serial, epoch = this.#transport.epoch;
      const expected = { scope: copy(this.#scope), head: this.#page.snapshot_token, ref_hex: ref, object_id: row.object_id };
      const { value } = await this.#transport.request('source/tags/inspect', { method: 'POST', maximum: 5 * 1024 * 1024,
        body: form({ object_format: expected.scope.format, ref_hex: ref, expected_object: row.object_id, expected_head: expected.head, ...TAG_LIMITS }) });
      await tagInspection(value, expected, this.#transport.crypto, () => this.#check(serial, epoch));
      this.#inspection = copy(value); return this.inspection;
    });
  }
  async prepare(operation, input) {
    return this.#exclusive(async () => {
      this.#noPending(); if (!this.#scope || !this.#page) fail('Load a reference snapshot first.');
      const allowed = { lightweight: ['ref_hex', 'source_ref_hex'], annotated: ['ref_hex', 'source_ref_hex', 'target_kind', 'tagger', 'timestamp', 'message_hex'], delete: ['ref_hex'] };
      if (!Object.hasOwn(allowed, operation)) fail('Unsupported tag operation.');
      keys(input, allowed[operation]);
      const fields = { ...copy(input), object_format: this.#scope.format };
      // The public client selects a visible source by ref, never treats an
      // arbitrary object ID or supplied target kind as a capability.
      if (operation === 'delete') fields.expected_object = this.#selected(fields.ref_hex).object_id;
      else { fields.target = this.#selected(fields.source_ref_hex).object_id; delete fields.source_ref_hex;
        if (this.#rows.has(fields.ref_hex)) fail('Destination already appears in this snapshot.'); }
      const serial = this.#serial, epoch = this.#transport.epoch, scope = copy(this.#scope), crypto = this.#transport.crypto;
      const plan = await tagPlan(operation, fields, crypto); this.#check(serial, epoch);
      const nonce = hex(crypto.getRandomValues(new Uint8Array(16))), fingerprint = this.#transport.fingerprint, body = form(plan.fields);
      const key = await retryKey(this.#transport.root, fingerprint, scope, operation, nonce, body, crypto); this.#check(serial, epoch);
      this.#pending = { ...plan, operation, scope, body, nonce, fingerprint, key,
        sent: false, exported: false, observedTx: null, observedPrincipal: null }; return this.pending;
    });
  }
  discardUnsent() {
    if (this.#busy || !this.#pending || this.#pending.sent || this.#pending.exported) fail('Only an unsent, unexported tag request can be discarded.');
    this.#pending = null;
  }
  #settle(result, p) {
    if (p !== this.#pending) fail('Original request changed.');
    if (result.terminal) { this.#pending = null; this.cancel(); }
    else { if (result.tx) p.observedTx = result.tx; if (result.principal) p.observedPrincipal = result.principal; } return result;
  }
  async send() {
    return this.#exclusive(async () => {
      const p = this.#pending;
      if (!p || p.fingerprint !== this.#transport.fingerprint) fail('Restore the original credential and request.');
      p.sent = true;
      try {
        const { value, status } = await this.#transport.request(`source/tags/${p.operation}`, { method: 'POST', body: p.body,
          key: p.key, statuses: [200, 409], maximum: 64 * 1024, read: false });
        return this.#settle(tagPublication(value, p, status), p);
      } catch (error) { error.outcomeUnknown = true; throw error; }
    });
  }
  async recover() {
    return this.#exclusive(async () => {
      const p = this.#pending;
      if (!p || p.fingerprint !== this.#transport.fingerprint) fail('Restore the original credential and request.');
      const { value } = await this.#transport.request('outcomes', { method: 'POST', key: p.key, maximum: 32 * 1024, read: false });
      return this.#settle(recovery(value, p), p);
    });
  }
  exportReceipt() {
    if (this.#busy || !this.#pending) fail('No stable tag request is available.');
    const p = this.#pending, root = this.#transport.root;
    const encoded = JSON.stringify({ type: 'frankengit-tag-retry-v1', origin: root.origin, route: root.route,
      operation: p.operation, fields: p.fields, scope: p.scope, nonce: p.nonce, fingerprint: p.fingerprint,
      key: p.key, observedTx: p.observedTx, observedPrincipal: p.observedPrincipal });
    if (utf8.encode(encoded).length > RETRY_LIMIT) fail('Oversized tag receipt.'); p.exported = true; return encoded;
  }
  async restoreReceipt(encoded) {
    return this.#exclusive(async () => {
      this.#noPending();
      if (typeof encoded !== 'string' || encoded.length > RETRY_LIMIT || utf8.encode(encoded).length > RETRY_LIMIT) fail('Oversized tag receipt.');
      const r = JSON.parse(encoded);
      keys(r, ['type', 'origin', 'route', 'operation', 'fields', 'scope', 'nonce', 'fingerprint', 'key', 'observedTx', 'observedPrincipal']);
      if (r.type !== 'frankengit-tag-retry-v1' || r.origin !== this.#transport.root.origin || r.route !== this.#transport.root.route ||
          r.fingerprint !== this.#transport.fingerprint || typeof r.nonce !== 'string' || !/^[0-9a-f]{32}$/.test(r.nonce)) fail('Receipt belongs to another route or credential.');
      const scope = receiptScope(r.scope), serial = this.#serial, epoch = this.#transport.epoch;
      if (this.#scope && Object.keys(scope).some(k => scope[k] !== this.#scope[k])) fail('Receipt repository changed.');
      const plan = await tagPlan(r.operation, r.fields, this.#transport.crypto), body = form(plan.fields);
      if (plan.fields.object_format !== scope.format) fail('Receipt hash domain changed.');
      const key = await retryKey(this.#transport.root, r.fingerprint, scope, r.operation, r.nonce, body, this.#transport.crypto);
      this.#check(serial, epoch); if (key !== r.key) fail('Receipt no longer matches the original request key.');
      if (r.observedTx !== null) opaque(r.observedTx); if (r.observedPrincipal !== null) principal(r.observedPrincipal);
      this.cancel(); this.#pending = { ...r, ...plan, scope, body, key, sent: true, exported: true }; return this.pending;
    });
  }
}
