// Native browser queue consumer. Exact observations never become landing authority.
import { Transport, copy, fail, hex, integer, keys, principal, showReply, snapshot, subject, subjectReferences, text, utf8 } from './pulls-core.mjs';
import { base64, fromBase64, recovery } from './pulls-actions.mjs';
import { makeBoundary, PREPARATION_LIMIT } from './pulls-candidate.mjs';
import { queueCandidateRequest, queueCandidateSummary, queueInspectionReply, queueInspectionRequest, queuePreparationReply, queuePreparationRequest } from './queues-candidate.mjs';
import { MAX_QUEUE_ENTRIES, RECEIPT_LIMIT, CANDIDATE_RECEIPT_LIMIT, normalizeQueueFields, queueInteger, queueMutationRequest, queuePage,
  queuePublication, queueRequestKey, queueScope, queueShow } from './queues-protocol.mjs';
export { RECEIPT_LIMIT, CANDIDATE_RECEIPT_LIMIT } from './queues-protocol.mjs';

export class QueueClient {
  #transport; #scope = null; #pending = null; #busy = false; #recoveryPrincipal = null; #observed = new Map();
  #artifact = null; #serial = 0; #timeout;
  constructor(options) {
    this.#transport = new Transport({ ...options, pageSuffix: '/ui/queues/' });
    this.#timeout = integer(options.operationTimeoutMs ?? 60_000, 'whole queue candidate read timeout', 1, 300_000);
  }
  get connected() { return this.#transport.connected; }
  get recoveryOnly() { return this.#recoveryPrincipal !== null; }
  get binding() { return this.connected && this.#scope ? copy(this.#scope) : null; }
  get busy() { return this.#busy; }
  get candidateReady() { return this.connected && this.#artifact !== null; }
  get candidate() {
    const a = this.#artifact;
    return this.connected && a ? queueCandidateSummary(a, a.metadata, a.inspection) : null;
  }
  get pending() {
    if (!this.#pending) return null;
    const { bytes, bundle, fingerprint, ...summary } = this.#pending;
    return { ...copy(summary), body_bytes: bytes.length, ...(bundle ? { bundle_bytes: bundle.length } : {}),
      state: summary.observedTx ? 'undecided' : (summary.sent || summary.exported) ? 'unknown' : 'staged' };
  }
  async connect(token, options = {}) {
    this.disconnect();
    keys(options, ['recoveryOnly', 'originalPrincipal']);
    const recovering = options.recoveryOnly === undefined ? false : options.recoveryOnly;
    if (typeof recovering !== 'boolean' || (!recovering && options.originalPrincipal !== undefined)) fail('Choose an explicit recovery-only connection.');
    const expected = recovering ? principal(options.originalPrincipal) : null;
    if (expected && this.#pending?.observedPrincipal && expected !== this.#pending.observedPrincipal) fail('Original principal conflicts with the retained queue observation.');
    const selected = expected && this.#pending ? { key: this.#pending.key, principal: expected } : null;
    this.#recoveryPrincipal = expected;
    // A recovery-only connection without an imported receipt has no request to
    // select yet. Client methods remain closed until its verified original key
    // is installed in the transport by restoreReceipt.
    const connecting = this.#transport.connect(token, this.recoveryOnly ? null : this.#pending?.fingerprint ?? null, selected);
    const epoch = this.#transport.epoch;
    await connecting; this.#check(epoch);
    this.#scope = this.#pending ? copy(this.#pending.scope) : null;
  }
  disconnect() { this.invalidateCandidate(); this.#transport.disconnect(); this.#scope = null; this.#recoveryPrincipal = null; this.#observed.clear(); }
  cancelReads() { this.invalidateCandidate(); }
  invalidateCandidate() {
    this.#serial += 1; this.#transport.cancelReads();
    this.#artifact?.bundle.fill(0); this.#artifact = null;
  }
  #ordinary() {
    if (this.recoveryOnly) fail('Recovery-only connection cannot read, stage, discard or resend queue commands. Reconnect explicitly for ordinary work.');
  }
  #check(epoch) { if (!this.connected || epoch !== this.#transport.epoch) fail('Queue operation superseded; stale work was not selected.'); }
  #selected() {
    this.#ordinary();
    if (!this.connected || !this.#scope) fail('Read this repository with a scoped credential before preparing queue work.');
    return copy(this.#scope);
  }
  async list({ after = 0, limit = 20, head = null } = {}) {
    this.#ordinary(); queueInteger(after, 'queue cursor'); queueInteger(limit, 'page size', 1, 100);
    if (head !== null) snapshot(head); if (after && head === null) fail('Continuation requires its original snapshot.');
    const query = new URLSearchParams({ after: String(after), limit: String(limit) });
    if (head !== null) query.set('expected_head', head);
    const response = await this.#transport.request(`queues?${query}`);
    const checked = queuePage(response.value, { after, limit, head, scope: this.#scope });
    this.#scope = checked.binding;
    for (const row of checked.reply.queues) this.#observed.set(row.number, copy(row));
    return checked;
  }
  async show(number, head = null) {
    this.#ordinary(); queueInteger(number, 'queue number', 1); if (head !== null) snapshot(head);
    const query = head === null ? '' : `?${new URLSearchParams({ expected_head: head })}`;
    const response = await this.#transport.request(`queues/${number}${query}`, { statuses: [200, 404] });
    const checked = queueShow(response.value, number, { head, scope: this.#scope });
    if (checked.reply.found !== (response.status === 200)) fail('Queue presence and HTTP status disagree.');
    this.#scope = checked.binding;
    if (checked.reply.found) this.#observed.set(number, copy(checked.reply.queue));
    else this.#observed.delete(number);
    return checked;
  }
  async pull(number, head = null) {
    this.#ordinary(); queueInteger(number, 'PR number', 1); if (head !== null) snapshot(head);
    const query = head === null ? '' : `?${new URLSearchParams({ expected_head: head })}`;
    const response = await this.#transport.request(`pulls/${number}${query}`, { statuses: [200, 404] });
    const checked = showReply(response.value, number, { head, scope: this.#scope });
    queueScope(checked.binding);
    if (checked.reply.found !== (response.status === 200)) fail('PR presence and HTTP status disagree.');
    this.#scope = checked.binding; return checked;
  }
  #validateObserved(number, action, fields) {
    const observed = this.#observed.get(number);
    const exact = observed && observed.version === fields.expected_version && observed.target_ref_hex === fields.target_ref_hex;
    if (['reorder', 'land-candidate'].includes(action) && !exact) fail('Read the exact queue version before reordering or preparing its candidate.');
    if (!exact) return;
    if (observed.active_batch !== null) fail('The selected queue has an active batch; refresh after it settles.');
    if (action === 'reorder' && (fields.entry.length !== observed.order.length || fields.entry.some(number => !observed.order.includes(number)))) fail('Reorder must retain every current queue member exactly once.');
    if (action === 'enqueue' && observed.entries.length === MAX_QUEUE_ENTRIES && !observed.order.includes(fields.pull_request)) fail('The selected queue is full.');
    if (action === 'land' || action === 'land-candidate') {
      const first = observed.entries[0];
      if (!first || first.pull_request !== fields.pull_request || first.source_ref_hex !== fields.source_ref_hex ||
          first.head_tip.replace(/^sha(?:1|256):/, '') !== fields.expected_source_tip) fail('Landing must retain the selected queue head and its exact source.');
    }
  }
  async prepareCandidate(number, fields, metadata) {
    const scope = this.#selected();
    if (this.#pending || this.#busy) fail('Resolve the retained request and finish the current operation first.');
    const request = queuePreparationRequest(number, fields, metadata, scope);
    this.#validateObserved(number, 'land-candidate', request.fields);
    this.invalidateCandidate();
    const serial = this.#serial, epoch = this.#transport.epoch;
    let expired = false, artifact = null;
    const check = () => {
      if (expired) fail('Queue candidate operation exceeded its total read deadline.');
      this.#check(epoch);
      if (serial !== this.#serial) fail('Queue candidate preparation cancelled or selection changed.');
    };
    const timer = setTimeout(() => { expired = true; this.#transport.cancelReads(); }, this.#timeout);
    this.#busy = true;
    try {
      const response = await this.#transport.request(request.path, { method: 'POST', body: request.body, binary: true,
        statuses: [200, 409], maximum: PREPARATION_LIMIT });
      check();
      const result = await queuePreparationReply(response, request, scope, this.#transport.crypto);
      artifact = result.artifact; check();
      if (artifact) {
        const boundary = makeBoundary('', artifact.bundle, this.#transport.crypto), upload = queueInspectionRequest(artifact, boundary);
        const response = await this.#transport.request(upload.path, { method: 'POST', body: new Blob([upload.bytes]), contentType: upload.contentType });
        check();
        const inspected = await queueInspectionReply(response.value, artifact, this.#transport.crypto); check();
        artifact.metadata = copy(result.metadata); artifact.inspection = copy(inspected.reply); this.#artifact = artifact;
      }
      return { binding: result.binding, head: result.head, metadata: copy(result.metadata), candidate: this.candidate };
    } finally {
      clearTimeout(timer); this.#busy = false;
      if (artifact && artifact !== this.#artifact) artifact.bundle.fill(0);
    }
  }
  exportCandidateBundle() {
    this.#ordinary();
    if (!this.candidateReady || this.#busy) fail('Prepare and completely inspect a queue candidate first.');
    return this.#artifact.bundle.slice();
  }
  exportReviewCandidate() {
    this.#ordinary();
    if (!this.candidateReady || this.#busy) fail('Prepare and completely inspect a queue candidate first.');
    const a = this.#artifact, raw = a.metadata.subject;
    const fields = { ...subject({ object_format: a.scope.format, pull_request_version: a.fields.pull_request_version,
      policy_epoch: a.fields.policy_epoch, ...subjectReferences(raw), source_tip: a.fields.source_tip, target_tip: a.fields.target_tip }),
      merge_base: a.fields.merge_base, candidate_commit: a.fields.candidate_commit };
    return JSON.stringify({ schema: 'frankengit-browser-candidate-v1', number: a.number, scope: a.scope, method: a.method,
      fields, bundle_base64: base64(a.bundle), sha256: a.sha256 });
  }
  async stageCandidate(number, fields) {
    const scope = this.#selected(), a = this.#artifact;
    if (!a || this.#pending || this.#busy) fail('Prepare and inspect this exact queue candidate before staging its landing.');
    const selected = normalizeQueueFields('land', fields, scope.format), { merge_base, expected_commit, ...original } = a.queueFields;
    if (number !== a.queue || JSON.stringify(selected) !== JSON.stringify(original)) fail('Candidate selection changed; prepare and inspect the new coordinates explicitly.');
    this.#validateObserved(number, 'land-candidate', a.queueFields);
    const fingerprint = this.#transport.fingerprint, epoch = this.#transport.epoch, serial = this.#serial;
    const nonce = hex(this.#transport.crypto.getRandomValues(new Uint8Array(16)));
    const request = queueCandidateRequest(number, a.queueFields, scope, a.commandForm, a.bundle, nonce);
    this.#busy = true;
    try {
      const key = await queueRequestKey(this.#transport.root, fingerprint, scope, number, 'land-candidate', nonce, request, this.#transport.crypto);
      this.#check(epoch);
      if (serial !== this.#serial || a !== this.#artifact) fail('Inspected queue candidate changed during staging.');
      this.#pending = { number, action: 'land-candidate', fields: request.fields, scope, fingerprint, nonce, key, body: a.commandForm,
        bytes: request.bytes, bundle: a.bundle.slice(), contentType: request.contentType, sent: false, exported: false, observedTx: null, observedPrincipal: null };
      return this.pending;
    } finally { this.#busy = false; }
  }
  async stage(number, action, fields) {
    const scope = this.#selected();
    if (this.#pending || this.#busy) fail('Resolve or discard the retained queue request first.');
    const request = queueMutationRequest(number, action, fields, scope);
    this.#validateObserved(number, action, request.fields);
    const nonce = hex(this.#transport.crypto.getRandomValues(new Uint8Array(16)));
    const fingerprint = this.#transport.fingerprint, epoch = this.#transport.epoch;
    this.#busy = true;
    try {
      const key = await queueRequestKey(this.#transport.root, fingerprint, scope, number, action, nonce, request, this.#transport.crypto);
      this.#check(epoch);
      this.#pending = { number, action, fields: request.fields, scope, fingerprint, nonce, key, body: request.body,
        bytes: request.bytes, contentType: request.contentType, sent: false, exported: false, observedTx: null, observedPrincipal: null };
      return this.pending;
    } finally { this.#busy = false; }
  }
  discardUnsent() {
    this.#ordinary();
    if (this.#busy || this.#pending?.sent || this.#pending?.exported) fail('A dispatched or exported queue request cannot be treated as an unsent draft.');
    this.#pending = null;
  }
  exportReceipt() {
    if (!this.#pending) fail('No prepared queue request.');
    const p = this.#pending;
    const candidate = p.action === 'land-candidate';
    const serialized = JSON.stringify({ schema: candidate ? 'frankengit-queue-candidate-retry-v1' : 'frankengit-queue-retry-v1', origin: this.#transport.root.origin, route: this.#transport.root.route,
      request: { number: p.number, action: p.action, fields: p.fields, scope: p.scope, fingerprint: p.fingerprint,
        nonce: p.nonce, key: p.key, observedTx: p.observedTx, observedPrincipal: p.observedPrincipal,
        ...(candidate ? { command_form: p.body, bundle_base64: base64(p.bundle) } : {}) } });
    if (utf8.encode(serialized).length > (candidate ? CANDIDATE_RECEIPT_LIMIT : RECEIPT_LIMIT)) fail('Queue recovery receipt exceeds the browser limit.');
    p.exported = true;
    return serialized;
  }
  async restoreReceipt(serialized) {
    if (!this.connected || this.#pending || this.#busy) fail('Connect first and resolve any retained queue request.');
    text(serialized, CANDIDATE_RECEIPT_LIMIT, 'queue recovery receipt');
    const receipt = JSON.parse(serialized); keys(receipt, ['schema', 'origin', 'route', 'request']);
    const candidate = receipt.schema === 'frankengit-queue-candidate-retry-v1';
    if (!candidate) text(serialized, RECEIPT_LIMIT, 'queue recovery receipt');
    const p = receipt.request; keys(p, ['number', 'action', 'fields', 'scope', 'fingerprint', 'nonce', 'key', 'observedTx', 'observedPrincipal',
      ...(candidate ? ['command_form', 'bundle_base64'] : [])]);
    if ((!candidate && receipt.schema !== 'frankengit-queue-retry-v1') || candidate !== (p.action === 'land-candidate') ||
        receipt.origin !== this.#transport.root.origin || receipt.route !== this.#transport.root.route ||
        typeof p.fingerprint !== 'string' || !/^[0-9a-f]{64}$/.test(p.fingerprint) || (!this.recoveryOnly && p.fingerprint !== this.#transport.fingerprint) ||
        typeof p.key !== 'string' || !/^fgq1-[0-9a-f]{32}-[0-9a-f]{64}$/.test(p.key)) fail('Receipt does not belong to this repository and original credential.');
    const scope = queueScope(p.scope);
    if (this.#scope && Object.keys(scope).some(key => scope[key] !== this.#scope[key])) fail('Queue receipt repository incarnation changed.');
    if (p.observedTx !== null) text(p.observedTx, 256, 'transaction identity', true);
    if (p.observedPrincipal !== null) principal(p.observedPrincipal);
    if (this.recoveryOnly && p.observedPrincipal !== null && p.observedPrincipal !== this.#recoveryPrincipal) fail('Receipt conflicts with the selected original principal.');
    const bundle = candidate ? fromBase64(p.bundle_base64) : null;
    const request = candidate ? queueCandidateRequest(p.number, p.fields, scope, p.command_form, bundle, p.nonce) : queueMutationRequest(p.number, p.action, p.fields, scope);
    const epoch = this.#transport.epoch;
    this.#busy = true;
    try {
      const key = await queueRequestKey(this.#transport.root, p.fingerprint, scope, p.number, p.action, p.nonce, request, this.#transport.crypto);
      this.#check(epoch);
      if (key !== p.key) fail('Recovery key does not commit to this exact queue command.');
      if (this.recoveryOnly) this.#transport.restrictToRecovery({ key, principal: this.#recoveryPrincipal });
      this.#scope = scope;
      this.#pending = { number: p.number, action: p.action, fields: request.fields, scope, fingerprint: p.fingerprint,
        nonce: p.nonce, key, body: request.body, bytes: request.bytes, ...(candidate ? { bundle } : {}), contentType: request.contentType, sent: true, exported: true,
        observedTx: p.observedTx, observedPrincipal: p.observedPrincipal };
      return this.pending;
    } finally { this.#busy = false; }
  }
  async send() {
    this.#ordinary();
    if (!this.connected || !this.#pending || this.#busy) fail('Connect and prepare one exact queue request.');
    const p = this.#pending; this.#busy = true; p.sent = true;
    try {
      const response = await this.#transport.request(`queues/${p.number}/${p.action}`, {
        method: 'POST', body: new Blob([p.bytes]), contentType: p.contentType, key: p.key, read: false, statuses: [200, 409], maximum: 64 * 1024,
      });
      const result = queuePublication(response.value, p, response.status);
      this.#pending = null; this.#observed.delete(p.number); this.invalidateCandidate(); return result;
    } catch (error) { error.outcomeUnknown = true; throw error; }
    finally { this.#busy = false; }
  }
  async recover() {
    if (!this.connected || !this.#pending || this.#busy) fail('Connect and retain the original queue request before outcome lookup.');
    const p = this.#pending; this.#busy = true;
    try {
      const response = await this.#transport.request('outcomes', { method: 'POST', key: p.key, read: false, maximum: 32 * 1024 });
      const result = recovery(response.value, p);
      if (result.terminal) { this.#pending = null; this.#observed.delete(p.number); this.invalidateCandidate(); }
      else { p.observedTx = result.tx; p.observedPrincipal = result.principal; if (result.tx) p.sent = true; }
      return { ...result, action: p.action, number: p.number, reply: copy(response.value) };
    } catch (error) { error.outcomeUnknown = true; throw error; }
    finally { this.#busy = false; }
  }
}
