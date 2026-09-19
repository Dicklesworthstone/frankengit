// Native PR client. Views are immutable observations, never merge permission.
import { Transport, integer, principal, snapshot, listReply, showReply, reviewsReply, copy, fail, keys, text, utf8,
  hex, form, subject, SUBJECT_FIELDS, oid, binding } from './pulls-core.mjs';
import { checkedBundle, digest, makeBoundary, multipart, preparationCommand, preparationReply, inspectionReply, PREPARATION_LIMIT } from './pulls-candidate.mjs';
import { resolutionUpload, verifyResolutionResult } from './pulls-resolution.mjs';
import { RECEIPT_LIMIT, requestBody, requestPath, requestKey, publication, recovery, base64, fromBase64, receiptScope } from './pulls-actions.mjs';

function candidateFields(fields) {
  keys(fields, [...SUBJECT_FIELDS, 'merge_base', 'candidate_commit']);
  return { ...subject(fields), merge_base: oid(fields.merge_base, fields.object_format), candidate_commit: oid(fields.candidate_commit, fields.object_format) };
}

export class PullClient {
  #transport; #scope = null; #pending = null; #busy = false; #artifact = null; #conflict = null; #candidateSerial = 0;
  constructor(options) { this.#transport = new Transport(options); }
  get connected() { return this.#transport.connected; }
  get binding() { return this.connected && this.#scope ? copy(this.#scope) : null; }
  get busy() { return this.#busy; }
  get pending() {
    if (!this.#pending) return null;
    const { bytes, bundle, fingerprint, ...summary } = this.#pending;
    return { ...copy(summary), body_bytes: bytes.length, bundle_bytes: bundle?.length ?? 0 };
  }
  get candidate() {
    if (!this.connected || !this.#artifact) return null;
    const { bundle, ...safe } = this.#artifact;
    return { ...copy(safe), bundle_bytes: bundle.length };
  }
  get conflict() { return this.connected && this.#conflict ? copy(this.#conflict.report) : null; }
  async connect(token) {
    this.#scope = null; this.invalidateCandidate();
    await this.#transport.connect(token, this.#pending?.fingerprint ?? null);
    this.#scope = this.#pending ? copy(this.#pending.scope) : null;
  }
  disconnect() { this.#transport.disconnect(); this.#scope = null; this.invalidateCandidate(); }
  invalidateCandidate() { this.#candidateSerial += 1; this.#artifact = null; this.#conflict = null; }
  cancelReads() { this.#transport.cancelReads(); }
  async list({ after = 0, limit = 20, head = null } = {}) {
    integer(after, 'PR cursor'); integer(limit, 'page size', 1, 100);
    if (head !== null) snapshot(head); if (after && !head) fail('Continuation requires its original snapshot.');
    const query = new URLSearchParams({ after: String(after), limit: String(limit) });
    if (head) query.set('expected_head', head);
    const raw = await this.#transport.request(`pulls?${query}`);
    const checked = listReply(raw.value, { after, limit, head, scope: this.#scope });
    this.#scope = checked.binding; return checked;
  }
  async show(number, head = null) {
    integer(number, 'PR number', 1); if (head !== null) snapshot(head);
    const query = new URLSearchParams(); if (head) query.set('expected_head', head);
    const raw = await this.#transport.request(`pulls/${number}${head ? `?${query}` : ''}`, { statuses: [200, 404] });
    const checked = showReply(raw.value, number, { head, scope: this.#scope });
    if (checked.reply.found !== (raw.status === 200)) fail('PR presence and HTTP status disagree.');
    this.#scope = checked.binding; return checked;
  }
  async reviews(number, { after = null, limit = 20, head = null } = {}) {
    integer(number, 'PR number', 1); integer(limit, 'page size', 1, 100);
    if (after !== null) principal(after); if (head !== null) snapshot(head);
    if (after !== null && head === null) fail('Review continuation requires its original snapshot.');
    const query = new URLSearchParams({ limit: String(limit) });
    if (after !== null) query.set('after', after); if (head !== null) query.set('expected_head', head);
    const raw = await this.#transport.request(`pulls/${number}/reviews?${query}`, { statuses: [200, 404] });
    const checked = reviewsReply(raw.value, number, { after, limit, head, scope: this.#scope });
    if (checked.reply.found !== (raw.status === 200)) fail('Review presence and HTTP status disagree.');
    this.#scope = checked.binding; return checked;
  }

  #selected() {
    if (!this.connected || !this.#scope) fail('Read this repository with a scoped credential before preparing new work.');
    return copy(this.#scope);
  }
  #check(epoch, serial = null) {
    if (!this.connected || epoch !== this.#transport.epoch || (serial !== null && serial !== this.#candidateSerial)) fail('Operation superseded; stale work was not selected.');
  }
  async prepareAndInspect(number, fields, metadata) {
    const scope = this.#selected(); integer(number, 'PR number', 1);
    const normalized = preparationCommand(fields, metadata), selected = subject(fields);
    if (scope.format !== selected.object_format) fail('Candidate hash domain differs from the repository.');
    this.invalidateCandidate(); const serial = this.#candidateSerial, epoch = this.#transport.epoch;
    const response = await this.#transport.request(`pulls/${number}/prepare`, {
      method: 'POST', body: form(normalized), statuses: [200, 409], binary: true, maximum: PREPARATION_LIMIT,
    });
    const result = await preparationReply(response, number, selected, scope, this.#transport.crypto);
    this.#check(epoch, serial);
    if (!result.artifact) {
      if (result.metadata.state === 'conflicted') {
        const commitMetadata = Object.fromEntries(['author', 'committer', 'timestamp', 'message'].map(name => [name, normalized[name]]));
        this.#conflict = { number, scope, fields: selected, metadata: commitMetadata, report: copy(result.metadata) };
      }
      return { metadata: result.metadata, inspection: null };
    }
    const inspected = await this.#inspect(result.artifact, epoch, serial);
    return { metadata: result.metadata, inspection: inspected.reply };
  }
  async resolveAndInspect(choices) {
    const scope = this.#selected(), conflict = this.#conflict;
    if (!conflict || Object.keys(scope).some(key => scope[key] !== conflict.scope[key])) fail('Prepare conflicts in this repository before resolving them.');
    this.#artifact = null;
    const serial = ++this.#candidateSerial, epoch = this.#transport.epoch;
    const upload = await resolutionUpload(conflict.report, conflict.fields, conflict.metadata, choices, this.#transport.crypto);
    this.#check(epoch, serial);
    const response = await this.#transport.request(`pulls/${conflict.number}/resolve`, {
      method: 'POST', body: new Blob([upload.bytes]), contentType: upload.contentType,
      statuses: [200, 409], binary: true, maximum: PREPARATION_LIMIT,
    });
    const result = await preparationReply(response, conflict.number, conflict.fields, scope, this.#transport.crypto, true);
    this.#check(epoch, serial);
    verifyResolutionResult(result.metadata, upload.expected);
    const inspected = await this.#inspect(result.artifact, epoch, serial);
    this.#check(epoch, serial); this.#conflict = null;
    return { metadata: result.metadata, inspection: inspected.reply };
  }
  async inspect(number, fields, bundle) {
    const scope = this.#selected(); integer(number, 'PR number', 1);
    const selected = candidateFields(fields), bytes = checkedBundle(bundle).slice();
    if (scope.format !== selected.object_format) fail('Candidate hash domain differs from the repository.');
    this.invalidateCandidate(); const serial = this.#candidateSerial, epoch = this.#transport.epoch;
    const sha256 = await digest(bytes, this.#transport.crypto); this.#check(epoch, serial);
    return this.#inspect({ number, scope, fields: selected, bundle: bytes, sha256 }, epoch, serial);
  }
  async #inspect(artifact, epoch, serial) {
    this.#check(epoch, serial);
    const command = form(artifact.fields);
    const upload = multipart(command, artifact.bundle, makeBoundary(command, artifact.bundle, this.#transport.crypto));
    const response = await this.#transport.request(`pulls/${artifact.number}/inspect`, {
      method: 'POST', body: new Blob([upload.bytes]), contentType: upload.contentType,
    });
    const checked = await inspectionReply(response.value, artifact, this.#transport.crypto);
    this.#check(epoch, serial);
    this.#artifact = { ...artifact, inspection: copy(checked.reply) };
    return checked;
  }
  exportCandidate() {
    if (!this.connected || !this.#artifact) fail('Inspect a candidate before exporting it.');
    const { number, scope, fields, bundle, sha256 } = this.#artifact;
    return JSON.stringify({ schema: 'frankengit-browser-candidate-v1', number, scope, fields, bundle_base64: base64(bundle), sha256 });
  }
  async importCandidate(serialized) {
    const scope = this.#selected(); this.invalidateCandidate();
    const serial = this.#candidateSerial; text(serialized, RECEIPT_LIMIT, 'candidate receipt');
    const receipt = JSON.parse(serialized);
    keys(receipt, ['schema', 'number', 'scope', 'fields', 'bundle_base64', 'sha256']);
    if (receipt.schema !== 'frankengit-browser-candidate-v1') fail('Unsupported candidate receipt.');
    const supplied = receiptScope(receipt.scope);
    if (Object.keys(scope).some(key => scope[key] !== supplied[key])) fail('Candidate belongs to another repository incarnation.');
    const number = integer(receipt.number, 'PR number', 1), fields = candidateFields(receipt.fields), bytes = fromBase64(receipt.bundle_base64);
    const epoch = this.#transport.epoch;
    if (receipt.sha256 !== await digest(bytes, this.#transport.crypto)) fail('Candidate file was changed.');
    this.#check(epoch, serial);
    // A matching checksum is not trusted inspection. Imported bytes ALWAYS go
    // through the native candidate verifier before review/merge controls open.
    return this.inspect(number, fields, bytes);
  }
  async stageMetadata(number, action, fields) { return this.#stage(number, action, fields, null); }
  async stageReview(action, version, reason) {
    if (!['approve', 'request-changes', 'withdraw'].includes(action) || !this.connected || !this.#artifact) fail('Inspect the exact candidate before preparing a review.');
    const { number, fields, bundle } = this.#artifact;
    return this.#stage(number, action, { ...fields, expected_version: version, reason }, action === 'withdraw' ? null : bundle);
  }
  async stageMerge(requiredReviewers) {
    if (!this.connected || !this.#artifact) fail('Inspect the exact candidate before preparing a merge.');
    const { number, fields, bundle } = this.#artifact;
    // Caller-selected reviewers are explicit requirements, not inferred votes.
    // The node independently enforces opener/submitter and current-policy gates.
    return this.#stage(number, 'merge', { ...fields, required_reviewer: requiredReviewers }, bundle);
  }
  async #stage(number, action, fields, bundle) {
    const scope = this.#selected(); requestPath(number, action);
    if (this.#pending || this.#busy) fail('Resolve or discard the existing prepared request first.');
    const fingerprint = this.#transport.fingerprint, epoch = this.#transport.epoch;
    const retained = bundle === null ? null : checkedBundle(bundle).slice();
    const nonce = hex(this.#transport.crypto.getRandomValues(new Uint8Array(16)));
    const body = requestBody(action, fields, retained, nonce);
    if (body.fields.object_format !== scope.format) fail('Mutation hash domain differs from this repository.');
    this.#busy = true;
    try {
      const key = await requestKey(this.#transport.root, fingerprint, scope, number, action, nonce, body, this.#transport.crypto);
      this.#check(epoch);
      this.#pending = { number, action, fields: body.fields, scope, fingerprint, nonce, key,
        contentType: body.contentType, bytes: body.bytes, bundle: retained, sent: false, exported: false,
        observedTx: null, observedPrincipal: null };
      return this.pending;
    } finally { this.#busy = false; }
  }
  discardUnsent() {
    if (this.#busy || this.#pending?.sent || this.#pending?.exported) fail('A dispatched or exported request cannot be treated as an unsent draft.');
    this.#pending = null;
  }
  exportReceipt() {
    if (!this.#pending) fail('No prepared request.');
    const p = this.#pending;
    const serialized = JSON.stringify({ schema: 'frankengit-pr-retry-v1', origin: this.#transport.root.origin, route: this.#transport.root.route,
      request: { number: p.number, action: p.action, fields: p.fields, scope: p.scope, fingerprint: p.fingerprint,
        nonce: p.nonce, key: p.key, bundle_base64: p.bundle === null ? null : base64(p.bundle), observedTx: p.observedTx, observedPrincipal: p.observedPrincipal } });
    if (utf8.encode(serialized).length > RECEIPT_LIMIT) fail('Recovery receipt exceeds the browser limit.');
    p.exported = true; // Another session could now submit it, even before this one has.
    return serialized;
  }
  async restoreReceipt(serialized) {
    if (!this.connected || this.#pending || this.#busy) fail('Connect first and resolve any existing request.');
    text(serialized, RECEIPT_LIMIT, 'recovery receipt');
    const receipt = JSON.parse(serialized); keys(receipt, ['schema', 'origin', 'route', 'request']);
    const p = receipt.request; keys(p, ['number', 'action', 'fields', 'scope', 'fingerprint', 'nonce', 'key', 'bundle_base64', 'observedTx', 'observedPrincipal']);
    if (receipt.schema !== 'frankengit-pr-retry-v1' || receipt.origin !== this.#transport.root.origin || receipt.route !== this.#transport.root.route ||
        p.fingerprint !== this.#transport.fingerprint || typeof p.key !== 'string' || !/^fgpr1-[0-9a-f]{32}-[0-9a-f]{64}$/.test(p.key)) fail('Receipt does not belong to this repository and original credential.');
    requestPath(p.number, p.action);
    const scope = receiptScope(p.scope);
    if (this.#scope && Object.keys(scope).some(key => scope[key] !== this.#scope[key])) fail('Receipt repository incarnation changed.');
    if (p.observedTx !== null) text(p.observedTx, 256, 'transaction', true);
    if (p.observedPrincipal !== null) principal(p.observedPrincipal);
    const bundle = p.bundle_base64 === null ? null : fromBase64(p.bundle_base64);
    const body = requestBody(p.action, p.fields, bundle, p.nonce);
    if (body.fields.object_format !== scope.format) fail('Receipt hash domain mismatch.');
    const epoch = this.#transport.epoch;
    this.#busy = true;
    try {
      const key = await requestKey(this.#transport.root, p.fingerprint, scope, p.number, p.action, p.nonce, body, this.#transport.crypto);
      this.#check(epoch);
      if (key !== p.key) fail('Recovery key does not commit to this exact command and bundle.');
      this.#scope = scope;
      this.#pending = { number: p.number, action: p.action, fields: body.fields, scope, fingerprint: p.fingerprint,
        nonce: p.nonce, key, contentType: body.contentType, bytes: body.bytes, bundle, sent: true, exported: true,
        observedTx: p.observedTx, observedPrincipal: p.observedPrincipal };
      return this.pending;
    } finally { this.#busy = false; }
  }
  async send() {
    if (!this.connected || !this.#pending || this.#busy) fail('Connect and prepare a request; only one mutation may be in flight.');
    const p = this.#pending; this.#busy = true; p.sent = true;
    try {
      const response = await this.#transport.request(requestPath(p.number, p.action), {
        method: 'POST', body: new Blob([p.bytes]), contentType: p.contentType, key: p.key, read: false, statuses: [200, 409], maximum: 32 * 1024,
      });
      const result = publication(response.value, p, response.status);
      this.#pending = null; this.invalidateCandidate(); return result;
    } catch (error) { error.outcomeUnknown = true; throw error; }
    finally { this.#busy = false; }
  }
  async recover() {
    if (!this.connected || !this.#pending || this.#busy) fail('Connect and retain the original request before looking up its outcome.');
    const p = this.#pending; this.#busy = true;
    try {
      const response = await this.#transport.request('outcomes', { method: 'POST', key: p.key, read: false, maximum: 32 * 1024 });
      const result = recovery(response.value, p);
      if (result.terminal) { this.#pending = null; this.invalidateCandidate(); }
      else { p.observedTx = result.tx; p.observedPrincipal = result.principal; if (result.tx) p.sent = true; }
      return result;
    } finally { this.#busy = false; }
  }
}
