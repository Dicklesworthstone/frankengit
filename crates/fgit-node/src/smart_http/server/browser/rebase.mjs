// One immutable rebase series and one outstanding exact publication. Native
// admission owns history rewriting; this session has no automatic write/retry.
import { Transport, fail, keys, record, copy, integer, branch, format, form, hex, utf8, opaque, principal } from './pulls-core.mjs';
import { digest, makeBoundary } from './pulls-candidate.mjs';
import { recovery, receiptScope, base64, fromBase64 } from './pulls-actions.mjs';
import { rootReply, prepareCommand, prepared, addResolutions, resolutionUpload, applyFields,
  publication, retryKey, sourceUpload, PREPARE_BYTES, READ_BYTES, BUNDLE_BYTES } from './rebase-data.mjs';
import { INSPECT_OPTIONS, inspectReply } from './rebase-inspection.mjs';
export const RECEIPT_BYTES = 12 * 1024 * 1024;
export class RebaseClient {
  #transport; #selection = null; #scope = null; #report = null; #artifact = null; #recipes = [];
  #command = null; #pending = null; #busy = false; #serial = 0; #timeout;
  constructor(options) {
    this.#transport = new Transport({ ...options, pageSuffix: '/ui/rebase/' });
    this.#timeout = integer(options.operationTimeoutMs ?? 60_000, 'whole rebase read timeout', 1, 300_000);
  }
  get connected() { return this.#transport.connected; }
  get selection() { return copy(this.#selection); }
  get report() { return copy(this.#report); }
  // Detached display data, not mutable recipes, bundle bytes or credentials.
  get state() {
    return { selection: this.selection, report: this.report, candidate: this.candidate,
      command: copy(this.#command), resolutionCommits: this.#recipes.map(r => r.original),
      resolutionPaths: this.#recipes.reduce((n, r) => n + r.paths.length, 0),
      resolutionBytes: this.#recipes.reduce((n, r) => n + r.paths.reduce((m, p) =>
        m + p.conflict.path_hex.length / 2 + (p.bytes?.length ?? 0), 0), 0) };
  }
  get candidate() {
    if (!this.#artifact) return null;
    const a = this.#artifact;
    return copy({ fields: this.#applyFields(a), scope: a.scope, sha256: a.sha256, bundleBytes: a.bundle.length,
      metadata: a.metadata, inspection: a.inspection });
  }
  get pending() {
    if (!this.#pending) return null;
    const p = this.#pending;
    return copy({ fields: p.fields, scope: p.scope, key: p.key, requestSha256: p.requestSha256,
      bytes: p.bytes.length, sent: p.sent, exported: p.exported, observedTx: p.observedTx, observedPrincipal: p.observedPrincipal });
  }
  async connect(token) {
    this.disconnect();
    await this.#transport.connect(token, this.#pending?.fingerprint ?? null);
  }
  disconnect() {
    this.#serial++; this.#transport.disconnect(); this.#scope = null; this.#selection = null;
    this.#artifact = null; this.#report = null; this.#command = null; this.#recipes = [];
    // Uncertain publication responsibility survives credential loss.
  }
  cancel() { this.#serial++; this.#transport.cancelReads(); this.#artifact = null; }
  invalidate() { this.cancel(); this.#report = null; this.#recipes = []; this.#command = null; }
  clearSelection() { this.invalidate(); this.#selection = null; }
  #noPending() { if (this.#pending) fail('Resolve the saved rebase publication before starting another operation.'); }
  async #run(action, boundedRead = true) {
    if (this.#busy) fail('A rebase operation is already running.');
    if (!this.connected) fail('Connect a repository credential first.');
    this.#busy = true;
    const serial = this.#serial, epoch = this.#transport.epoch;
    let expired = false;
    const check = () => {
      if (expired) fail('Rebase operation exceeded its total read deadline.');
      if (serial !== this.#serial || epoch !== this.#transport.epoch || !this.connected) fail('Rebase operation cancelled or selection changed.');
    };
    const timer = boundedRead ? setTimeout(() => { expired = true; this.#transport.cancelReads(); }, this.#timeout) : null;
    try { return await action(check); }
    finally { if (timer !== null) clearTimeout(timer); this.#busy = false; }
  }
  async select(sourceRef, ontoRef, algorithm) {
    this.#noPending();
    if (this.#busy) fail('A rebase operation is already running.');
    this.clearSelection();
    const source = branch(sourceRef), onto = branch(ontoRef), objectFormat = format(algorithm);
    if (source === onto) fail('Select two distinct branches.');
    return this.#run(async check => {
      const read = async (ref, scope, head) => {
        const fields = { ref, object_format: objectFormat, limit: 1 };
        if (head !== null) fields.expected_head = head;
        const { value } = await this.#transport.request('source/tree', { method: 'POST', body: form(fields), maximum: 32768 });
        check(); return rootReply(value, ref, objectFormat, scope, head);
      };
      const a = await read(source, this.#scope, null), b = await read(onto, a.scope, a.head); check();
      if (a.sourceHead !== b.sourceHead) fail('Branch selections have different authority heads.');
      this.#scope = a.scope;
      this.#selection = { scope: a.scope, head: a.head, sourceHead: a.sourceHead,
        source: { ref: source, commit: a.commit, tree: a.tree }, onto: { ref: onto, commit: b.commit, tree: b.tree } };
      return this.selection;
    });
  }
  async prepare(input) {
    this.#noPending();
    if (this.#busy) fail('A rebase operation is already running.');
    this.invalidate();
    if (!this.#selection) fail('Select both immutable branch tips first.');
    const command = prepareCommand(this.#selection, input);
    return this.#run(check => this.#prepare(command, [], { body: form(command), contentType: 'application/x-www-form-urlencoded' }, check));
  }
  async resolve(choices) {
    this.#noPending();
    const report = this.#report, command = copy(this.#command);
    if (!report || report.state !== 'conflicted' || !command) fail('Resolve a reported original commit first.');
    return this.#run(async check => {
      this.#artifact = null;
      const recipes = await addResolutions(report, choices, this.#recipes, this.#transport.crypto, check);
      const upload = resolutionUpload(command, recipes, hex(this.#transport.crypto.getRandomValues(new Uint8Array(16))));
      return this.#prepare(command, recipes, upload, check);
    });
  }
  // Change only the named empty-commit policy, not the selected source/onto,
  // upstream, committer or earlier resolutions. This remains a read and the
  // complete resulting bundle must pass inspection again before publication.
  async continueEmpty(policy) {
    this.#noPending();
    if (!['drop', 'keep'].includes(policy)) fail('Choose Drop or Keep explicitly.');
    if (this.#report?.state !== 'became_empty' || !this.#command || !this.#selection) {
      fail('Continue an explicitly reported empty-commit stop first.');
    }
    return this.#run(async check => {
      const command = { ...this.#command, empty: policy }, recipes = copy(this.#recipes);
      this.#artifact = null;
      const upload = recipes.length
        ? resolutionUpload(command, recipes, hex(this.#transport.crypto.getRandomValues(new Uint8Array(16))))
        : { body: form(command), contentType: 'application/x-www-form-urlencoded' };
      return this.#prepare(command, recipes, upload, check);
    });
  }
  async #prepare(command, recipes, upload, check) {
    check(); const selection = copy(this.#selection), crypto = this.#transport.crypto;
    const response = await this.#transport.request(`source/rebase/${recipes.length ? 'resolve' : 'prepare'}`, {
      method: 'POST', body: upload.body, contentType: upload.contentType, maximum: PREPARE_BYTES, binary: true, statuses: [200, 409] });
    check(); const result = await prepared(response, selection, command, recipes, crypto, check);
    let artifact = result.artifact;
    if (artifact) {
      const fields = { object_format: command.object_format, profile: 'linear-v1', source_ref: command.source_ref,
        onto_ref: command.onto_ref, expected_source: command.expected_source, expected_onto: command.expected_onto,
        candidate_commit: artifact.metadata.candidate_commit, expected_head: command.expected_head, ...INSPECT_OPTIONS };
      const upload = sourceUpload(fields, artifact.bundle, 'bundle', makeBoundary(form(fields), artifact.bundle, crypto));
      const { value } = await this.#transport.request('source/rebase/inspect', { method: 'POST', body: upload.bytes,
        contentType: upload.contentType, maximum: READ_BYTES });
      check(); const inspection = await inspectReply(value, artifact, selection, crypto, check);
      artifact = { ...artifact, inspection };
    }
    check(); this.#report = result.metadata; this.#command = copy(command); this.#recipes = recipes; this.#artifact = artifact;
    return { report: this.report, candidate: this.candidate };
  }
  #applyFields(a) {
    return applyFields({ object_format: a.scope.format, profile: 'linear-v1', ref: a.command.source_ref,
      expected_source: a.command.expected_source, onto: a.command.expected_onto, candidate_commit: a.metadata.candidate_commit });
  }
  async stage() {
    this.#noPending();
    return this.#run(async check => {
      const a = this.#artifact;
      if (!a?.inspection) fail('A complete series must pass native inspection before publication.');
      const fields = this.#applyFields(a);
      if (fields.candidate_commit === fields.expected_source) fail('Rebase leaves the existing source tip unchanged; no publication is needed.');
      const nonce = hex(this.#transport.crypto.getRandomValues(new Uint8Array(16))), scope = copy(a.scope);
      const fingerprint = this.#transport.fingerprint, bundle = a.bundle.slice();
      const upload = sourceUpload(fields, bundle, 'bundle', `fg-rebase-${nonce}`);
      const key = await retryKey(this.#transport.root, fingerprint, scope, nonce, fields, upload, this.#transport.crypto);
      const requestSha256 = await digest(upload.bytes, this.#transport.crypto); check();
      this.#pending = { fields, scope, nonce, fingerprint, bundle, ...upload, key, requestSha256,
        sent: false, exported: false, observedTx: null, observedPrincipal: null };
      return this.pending;
    });
  }
  #settle(result, pending) {
    if (this.#pending !== pending) fail('Original rebase request changed.');
    if (result.terminal) { this.#pending = null; this.clearSelection(); }
    else { if (result.tx) pending.observedTx = result.tx; if (result.principal) pending.observedPrincipal = result.principal; }
    return result;
  }
  async send() {
    return this.#run(async () => {
      const p = this.#pending;
      if (!p || p.fingerprint !== this.#transport.fingerprint) fail('Use the original prepared request and credential.');
      p.sent = true;
      try {
        const response = await this.#transport.request('source/rebase/apply', { method: 'POST', body: p.bytes,
          contentType: p.contentType, key: p.key, read: false, statuses: [200, 409], maximum: 32768 });
        return this.#settle(publication(response.value, p, response.status), p);
      } catch (error) { error.outcomeUnknown = true; throw error; }
    }, false);
  }
  async recover() {
    return this.#run(async () => {
      const p = this.#pending;
      if (!p || p.fingerprint !== this.#transport.fingerprint) fail('Use the original unresolved request and credential.');
      const { value } = await this.#transport.request('outcomes', { method: 'POST', key: p.key, read: false, maximum: 32768 });
      return this.#settle(recovery(value, p), p);
    }, false);
  }
  discardUnsent() {
    if (this.#busy || !this.#pending || this.#pending.sent || this.#pending.exported) fail('Only an unsent, unexported request may be discarded.');
    this.#pending = null;
  }
  exportReceipt() {
    const p = this.#pending;
    if (!p) fail('No original rebase request to save.');
    const value = JSON.stringify({ schema: 'frankengit-rebase-retry-v1', origin: this.#transport.root.origin,
      route: this.#transport.root.route, scope: p.scope, fields: p.fields, fingerprint: p.fingerprint,
      nonce: p.nonce, key: p.key, bundle_base64: base64(p.bundle), observedTx: p.observedTx, observedPrincipal: p.observedPrincipal });
    if (utf8.encode(value).length > RECEIPT_BYTES) fail('Rebase recovery file exceeds its byte limit.');
    p.exported = true; return value;
  }
  async restoreReceipt(value) {
    this.#noPending();
    return this.#run(async check => {
      if (typeof value !== 'string' || value.length > RECEIPT_BYTES || utf8.encode(value).length > RECEIPT_BYTES) fail('Oversized original-request receipt.');
      const r = record(JSON.parse(value));
      keys(r, ['schema', 'origin', 'route', 'scope', 'fields', 'fingerprint', 'nonce', 'key', 'bundle_base64', 'observedTx', 'observedPrincipal']);
      if (r.schema !== 'frankengit-rebase-retry-v1' || r.origin !== this.#transport.root.origin || r.route !== this.#transport.root.route ||
          r.fingerprint !== this.#transport.fingerprint || !/^[0-9a-f]{32}$/.test(r.nonce)) fail('Recovery file belongs to another profile, route, or credential.');
      const scope = receiptScope(r.scope), fields = applyFields(r.fields);
      if (scope.format !== fields.object_format || (this.#scope && Object.keys(scope).some(k => scope[k] !== this.#scope[k]))) fail('Recovered repository identity changed.');
      const bundle = fromBase64(r.bundle_base64);
      if (bundle.length > BUNDLE_BYTES) fail('Recovered bundle exceeds the rebase profile.');
      const upload = sourceUpload(fields, bundle, 'bundle', `fg-rebase-${r.nonce}`);
      const key = await retryKey(this.#transport.root, r.fingerprint, scope, r.nonce, fields, upload, this.#transport.crypto); check();
      if (key !== r.key) fail('Receipt no longer matches its exact original request key.');
      if (r.observedTx !== null) opaque(r.observedTx);
      if (r.observedPrincipal !== null) principal(r.observedPrincipal);
      const requestSha256 = await digest(upload.bytes, this.#transport.crypto); check();
      this.clearSelection();
      this.#pending = { fields, scope, nonce: r.nonce, fingerprint: r.fingerprint, bundle, ...upload, key,
        requestSha256, sent: true, exported: true, observedTx: r.observedTx, observedPrincipal: r.observedPrincipal };
      return this.pending;
    });
  }
}
