// Native branch lifecycle, not a second ref store. Every write is an exact
// command with an original retry key; an interrupted response never undoes it.
import { Transport, fail, copy, keys, record, integer, text, format, oid, opaque,
  principal, utf8, hex, unhex, form, binding, pinned, FORM_LIMIT } from './pulls-core.mjs';
import { recovery, receiptScope } from './pulls-actions.mjs';

export const RECEIPT_LIMIT = 64 * 1024;
export const TRANSACTION_LIMIT = 32;
const CACHE_LIMIT = 2048;
const prefixes = { all: 'refs/', branches: 'refs/heads/', tags: 'refs/tags/' };
const hash = async (bytes, crypto) => hex(new Uint8Array(await crypto.subtle.digest('SHA-256', bytes)));
export function refBytes(encoded, namespace = 'all') {
  if (!Object.hasOwn(prefixes, namespace)) fail('Unknown reference namespace.');
  const bytes = unhex(encoded, 4096), prefix = hex(utf8.encode(prefixes[namespace]));
  // Git names are bytes. Never use lossy UTF-8 to compare, order or mutate one.
  const ascii = Array.from(bytes, b => String.fromCharCode(b)).join('');
  if (!encoded.startsWith(prefix) || bytes.length <= prefix.length / 2 || bytes.some(b => b <= 32 || b === 127) ||
      /[~^:?*\[\\]/.test(ascii) || ascii.includes('..') || ascii.includes('@{') || ascii.endsWith('.') ||
      ascii.split('/').some(part => !part || part.startsWith('.') || part.endsWith('.lock'))) fail('Invalid native reference.');
  return bytes;
}
export function refName(value, namespace = 'branches') {
  text(value, 4096, 'reference'); refBytes(hex(utf8.encode(value)), namespace); return value;
}
function refText(encoded, namespace = 'branches') {
  const bytes = refBytes(encoded, namespace);
  let decoded = null;
  try { decoded = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes); } catch {}
  return decoded;
}
function nativeRef(row, namespace) {
  record(row);
  if (row.ref !== refText(row.ref_hex, namespace)) fail('Reference text does not match its exact bytes.');
}
export function refsPage(reply, query, scope = null) {
  const selected = pinned(reply, scope, query.expected_head ?? null);
  const encoding = query.cursor_encoding ?? 'utf8';
  if (!['utf8', 'hex'].includes(encoding) || (encoding === 'hex' ? reply.cursor_encoding !== 'hex' : reply.cursor_encoding !== undefined)) fail('Reference cursor encoding changed.');
  const cursorHex = value => {
    if (encoding === 'hex') { refBytes(value, query.namespace); return value; }
    return hex(utf8.encode(refName(value, query.namespace)));
  };
  if (selected.binding.format !== query.object_format || reply.type !== 'source_refs' || reply.namespace !== query.namespace ||
      reply.after !== (query.after ?? null) || reply.limit !== query.limit || reply.read_only !== true ||
      reply.transaction_created !== false || reply.published !== false || reply.direct_refs_only !== true ||
      !Array.isArray(reply.refs) || reply.refs.length > query.limit) fail('Invalid reference page.');
  let previous = query.after === undefined ? '' : cursorHex(query.after);
  for (const row of reply.refs) {
    nativeRef(row, query.namespace); oid(row.object_id, query.object_format);
    if (row.ref_hex <= previous) fail('Reference order or cursor changed.'); previous = row.ref_hex;
  }
  if (reply.next_after !== null) {
    if (reply.refs.length !== query.limit || previous !== cursorHex(reply.next_after)) fail('Invalid reference continuation.');
  }
  return selected;
}
export function branchCommand(operation, input) {
  const applicable = { create: ['new_commit'], update: ['expected_commit', 'new_commit'],
    delete: ['expected_commit'], rename: ['expected_commit', 'new_ref'] };
  if (!Object.hasOwn(applicable, operation)) fail('Unsupported branch operation.');
  keys(input, ['object_format', 'ref', ...applicable[operation]]);
  const fields = { object_format: format(input.object_format), ref: refName(input.ref) };
  for (const name of applicable[operation]) fields[name] = name === 'new_ref' ? refName(input[name]) : oid(input[name], fields.object_format);
  if (operation === 'rename' && fields.ref === fields.new_ref) fail('Rename requires different branch names.');
  if (operation === 'update' && fields.expected_commit === fields.new_commit) fail('Branch already has that exact tip.');
  form(fields); return fields;
}
export function transactionCommand(input) {
  keys(input, ['object_format', 'changes']);
  const algorithm = format(input.object_format);
  if (!Array.isArray(input.changes) || input.changes.length < 1 || input.changes.length > TRANSACTION_LIMIT) fail(`Stage between 1 and ${TRANSACTION_LIMIT} branch changes.`);
  const targets = new Set(), applicable = { create: ['new_commit'], update: ['expected_commit', 'new_commit'], delete: ['expected_commit'] };
  const changes = Array.from(input.changes, change => {
    record(change);
    if (!Object.hasOwn(applicable, change.operation)) fail('Atomic batches support create, update and delete only.');
    keys(change, ['operation', 'ref_hex', ...applicable[change.operation]]);
    if (refBytes(change.ref_hex, 'branches').length > 1024) fail('Branch transaction names are limited to 1024 bytes.');
    if (targets.has(change.ref_hex)) fail('Each branch may appear only once in an atomic batch.');
    targets.add(change.ref_hex);
    const normalized = { operation: change.operation, ref_hex: change.ref_hex };
    for (const field of applicable[change.operation]) normalized[field] = oid(change[field], algorithm);
    if (change.operation === 'update' && normalized.expected_commit === normalized.new_commit) fail('Branch already has that exact tip.');
    return normalized;
  });
  return { object_format: algorithm, changes };
}
export function transactionForm(input) {
  const fields = transactionCommand(input), encoded = new URLSearchParams();
  encoded.append('object_format', fields.object_format);
  for (const change of fields.changes) {
    const values = [change.ref_hex];
    if (change.operation !== 'create') values.push(change.expected_commit);
    if (change.operation !== 'delete') values.push(change.new_commit);
    encoded.append(change.operation, values.join(':'));
  }
  const body = encoded.toString();
  if (utf8.encode(body).length > FORM_LIMIT) fail('Branch transaction exceeds the native form limit.');
  return body;
}
export function expectedUpdates(operation, fields) {
  const update = (ref, old, next) => ({ ref, ref_hex: hex(utf8.encode(ref)), expected_commit: old, new_commit: next, force: false });
  if (operation === 'transaction') return fields.changes.map(change => ({ ref: refText(change.ref_hex), ref_hex: change.ref_hex,
    expected_commit: change.expected_commit ?? null, new_commit: change.new_commit ?? null, force: false }));
  if (operation === 'rename') return [update(fields.ref, fields.expected_commit, null), update(fields.new_ref, null, fields.expected_commit)];
  return [update(fields.ref, fields.expected_commit ?? null, fields.new_commit ?? null)];
}
export function branchPublication(reply, pending, status) {
  binding(reply, pending.scope); principal(reply.principal_id); opaque(reply.tx_id); integer(reply.decision_sequence, 'decision sequence', 1);
  if (reply.type !== 'branch_publication' || reply.operation !== pending.operation || reply.atomic !== true || reply.terminal !== true ||
      reply.forge_transition !== false || !['committed', 'refused'].includes(reply.outcome) ||
      status !== (reply.outcome === 'committed' ? 200 : 409)) fail('Response is not an atomic branch decision.');
  const expected = expectedUpdates(pending.operation, pending.fields);
  if (!Array.isArray(reply.updates) || reply.updates.length !== expected.length) fail('Incomplete branch decision.');
  for (let i = 0; i < expected.length; i += 1) {
    const row = reply.updates[i]; nativeRef(row, 'branches');
    const normalized = { ref: row.ref, ref_hex: row.ref_hex,
      expected_commit: row.expected_commit === null ? null : oid(row.expected_commit, pending.scope.format),
      new_commit: row.new_commit === null ? null : oid(row.new_commit, pending.scope.format), force: row.force };
    if (JSON.stringify(normalized) !== JSON.stringify(expected[i])) fail('Branch decision changed an expected effect.');
  }
  if (pending.observedTx && pending.observedTx !== reply.tx_id) fail('Transaction identity changed.');
  if (pending.observedPrincipal && pending.observedPrincipal !== reply.principal_id) fail('Recovery principal changed.');
  if (reply.outcome === 'committed') {
    opaque(reply.repository_commit_id);
    if ('code' in reply || 'code_point' in reply || 'refusal_record_id' in reply) fail('Conflicting branch decisions.');
  } else {
    opaque(reply.code); opaque(reply.refusal_record_id); integer(reply.code_point, 'refusal code', 0, 65535);
    if ('repository_commit_id' in reply) fail('Conflicting branch decisions.');
  }
  return { terminal: true, outcome: reply.outcome, tx: reply.tx_id, principal: reply.principal_id,
    rcr: reply.repository_commit_id ?? null, refusal: reply.code ?? null };
}
async function retryKey(root, fingerprint, scope, operation, nonce, body, crypto) {
  return `fgbranch1-${nonce}-${await hash(utf8.encode(JSON.stringify([root.origin, root.route, fingerprint,
    [scope.tenant, scope.repository, scope.incarnation, scope.format], operation, nonce, body])), crypto)}`;
}
function receipt(root, pending) {
  const p = pending;
  const encoded = JSON.stringify({ type: p.operation === 'transaction' ? 'frankengit-branch-transaction-retry-v1' : 'frankengit-branch-retry-v1',
    origin: root.origin, route: root.route, operation: p.operation, fields: p.fields, scope: p.scope, nonce: p.nonce,
    fingerprint: p.fingerprint, key: p.key, observedTx: p.observedTx, observedPrincipal: p.observedPrincipal });
  if (utf8.encode(encoded).length > RECEIPT_LIMIT) fail('Receipt exceeds the byte limit; remove changes from the unprepared batch.');
  return encoded;
}
export class BranchClient {
  #transport; #scope = null; #page = null; #query = null; #refs = new Map(); #staged = []; #pending = null; #busy = false; #serial = 0;
  constructor(options) { this.#transport = new Transport({ ...options, pageSuffix: '/ui/branches/' }); }
  get connected() { return this.#transport.connected; }
  get busy() { return this.#busy; }
  get page() { return this.#page ? copy(this.#page) : null; }
  get knownRefs() { return copy([...this.#refs.values()]); }
  get stagedChanges() { return copy(this.#staged); }
  get pending() {
    if (!this.#pending) return null;
    const { fields, operation, scope, key, sent, exported, observedTx, observedPrincipal } = this.#pending;
    return copy({ fields, operation, scope, key, sent, exported, observedTx, observedPrincipal });
  }
  async connect(token) { this.disconnect(); await this.#transport.connect(token, this.#pending?.fingerprint ?? null); }
  disconnect() { this.cancel(); this.#transport.disconnect(); this.#scope = null; }
  cancel() { this.#serial += 1; this.#transport.cancelReads(); this.#clear(); }
  #clear() { this.#page = null; this.#query = null; this.#refs.clear(); this.#staged = []; }
  #check(serial, epoch) {
    if (!this.connected || serial !== this.#serial || epoch !== this.#transport.epoch) fail('Reference operation cancelled or replaced.');
  }
  #noPending() { if (this.#pending) fail('Resolve the original saved request first.'); }
  async #exclusive(work) {
    if (this.#busy || !this.connected) fail('Connect first and finish the current operation.');
    this.#busy = true; try { return await work(); } finally { this.#busy = false; }
  }
  async list({ objectFormat = 'sha1', namespace = 'branches', limit = 50, next = false } = {}) {
    return this.#exclusive(async () => {
      this.#noPending();
      let query;
      if (next) {
        if (!this.#page || this.#page.next_after === null) fail('No continuation remains.');
        query = { ...this.#query, after: this.#page.next_after, expected_head: this.#page.snapshot_token };
      } else {
        this.cancel(); format(objectFormat); integer(limit, 'page size', 1, 100);
        if (!Object.hasOwn(prefixes, namespace)) fail('Unknown reference namespace.');
        query = { object_format: objectFormat, namespace, limit, cursor_encoding: 'hex' };
      }
      if (this.#refs.size + query.limit > CACHE_LIMIT) fail('Reference session limit reached; reload a narrower namespace.');
      const serial = this.#serial, epoch = this.#transport.epoch;
      const { value } = await this.#transport.request('source/refs', { method: 'POST', body: form(query), maximum: 1024 * 1024 });
      const selected = refsPage(value, query, this.#scope); this.#check(serial, epoch);
      this.#scope = selected.binding; this.#query = query; this.#page = copy(value);
      for (const row of value.refs) this.#refs.set(row.ref_hex, copy(row));
      return this.page;
    });
  }
  #selected(name) {
    refName(name); const row = this.#refs.get(hex(utf8.encode(name)));
    if (!row || row.ref !== name) fail('Select a branch from the pinned reference listing.');
    return oid(row.object_id, this.#scope.format);
  }
  #selectedHex(encoded) {
    refBytes(encoded, 'branches'); const row = this.#refs.get(encoded);
    if (!row) fail('Select a branch from the pinned reference listing.');
    return oid(row.object_id, this.#scope.format);
  }
  #editableBatch() {
    if (this.#busy || !this.connected) fail('Connect first and finish the current operation.');
    this.#noPending(); if (!this.#scope || !this.#page) fail('Load a pinned reference listing first.');
  }
  stage(operation, { ref, refHex, sourceRefHex } = {}) {
    this.#editableBatch();
    if (!['create', 'update', 'delete'].includes(operation)) fail('Atomic batches support create, update and delete only.');
    const change = { operation, ref_hex: operation === 'create' ? hex(utf8.encode(refName(ref))) : refHex };
    if (operation === 'create' && this.#refs.has(change.ref_hex)) fail('Destination already appears in this snapshot.');
    if (operation !== 'create') change.expected_commit = this.#selectedHex(refHex);
    if (operation !== 'delete') change.new_commit = this.#selectedHex(sourceRefHex);
    const fields = transactionCommand({ object_format: this.#scope.format, changes: [...this.#staged, change] });
    this.#staged = fields.changes; return this.stagedChanges;
  }
  removeStaged(index) {
    this.#editableBatch(); integer(index, 'staged change', 0, this.#staged.length - 1);
    this.#staged.splice(index, 1); return this.stagedChanges;
  }
  clearStaged() { this.#editableBatch(); this.#staged = []; }
  async #freeze(operation, fields, body) {
    const scope = copy(this.#scope), nonce = hex(this.#transport.crypto.getRandomValues(new Uint8Array(16)));
    const serial = this.#serial, epoch = this.#transport.epoch, fingerprint = this.#transport.fingerprint;
    const key = await retryKey(this.#transport.root, fingerprint, scope, operation, nonce, body, this.#transport.crypto);
    this.#check(serial, epoch);
    const pending = { operation, fields, scope, nonce, fingerprint, body, key,
      sent: false, exported: false, observedTx: null, observedPrincipal: null };
    // Reserve room for the largest later recovery observation before taking
    // responsibility for a batch whose receipt must remain downloadable.
    if (operation === 'transaction') receipt(this.#transport.root, { ...pending, observedTx: '\\'.repeat(256), observedPrincipal: 'f'.repeat(32) });
    this.#pending = pending; this.#staged = []; return this.pending;
  }
  async prepareTransaction() {
    return this.#exclusive(async () => {
      this.#noPending(); if (!this.#scope || !this.#page) fail('Load a pinned reference listing first.');
      const fields = transactionCommand({ object_format: this.#scope.format, changes: this.#staged });
      return this.#freeze('transaction', fields, transactionForm(fields));
    });
  }
  async prepare(operation, { ref, sourceRef, newRef } = {}) {
    return this.#exclusive(async () => {
      this.#noPending(); if (!this.#scope || !this.#page) fail('Load a pinned reference listing first.');
      if (this.#staged.length) fail('Prepare or clear the staged atomic batch first.');
      const fields = { object_format: this.#scope.format, ref: refName(ref) };
      if (operation !== 'create') fields.expected_commit = this.#selected(ref);
      if (operation === 'create' || operation === 'update') fields.new_commit = this.#selected(sourceRef);
      if (operation === 'rename') fields.new_ref = refName(newRef);
      const normalized = branchCommand(operation, fields);
      const destination = operation === 'create' ? ref : operation === 'rename' ? newRef : null;
      if (destination && this.#refs.has(hex(utf8.encode(destination)))) fail('Destination already appears in this snapshot.');
      return this.#freeze(operation, normalized, form(normalized));
    });
  }
  discardUnsent() {
    if (this.#busy || !this.#pending || this.#pending.sent || this.#pending.exported) fail('Only an unsent, unexported request can be discarded.');
    this.#pending = null;
  }
  #settle(result, pending) {
    if (pending !== this.#pending) fail('Saved request changed.');
    if (result.terminal) { this.#pending = null; this.cancel(); }
    else { if (result.tx) pending.observedTx = result.tx; if (result.principal) pending.observedPrincipal = result.principal; }
    return result;
  }
  async send() {
    return this.#exclusive(async () => {
      const p = this.#pending;
      if (!p || p.fingerprint !== this.#transport.fingerprint) fail('Restore the original request and credential.');
      p.sent = true;
      try {
        const { value, status } = await this.#transport.request(`source/branches/${p.operation}`, {
          method: 'POST', body: p.body, key: p.key, statuses: [200, 409], maximum: p.operation === 'transaction' ? 512 * 1024 : 64 * 1024, read: false });
        return this.#settle(branchPublication(value, p, status), p);
      } catch (error) { error.outcomeUnknown = true; throw error; }
    });
  }
  async recover() {
    return this.#exclusive(async () => {
      const p = this.#pending;
      if (!p || p.fingerprint !== this.#transport.fingerprint) fail('Restore the original request and credential.');
      const { value } = await this.#transport.request('outcomes', { method: 'POST', key: p.key, maximum: 32 * 1024, read: false });
      return this.#settle(recovery(value, p), p);
    });
  }
  exportReceipt() {
    if (this.#busy || !this.#pending) fail('No stable request is available.');
    const p = this.#pending, encoded = receipt(this.#transport.root, p);
    p.exported = true; return encoded;
  }
  async restoreReceipt(encoded) {
    return this.#exclusive(async () => {
      this.#noPending(); text(encoded, RECEIPT_LIMIT, 'retry receipt');
      const p = JSON.parse(encoded);
      keys(p, ['type', 'origin', 'route', 'operation', 'fields', 'scope', 'nonce', 'fingerprint', 'key', 'observedTx', 'observedPrincipal']);
      const transaction = p.type === 'frankengit-branch-transaction-retry-v1';
      if ((!transaction && p.type !== 'frankengit-branch-retry-v1') || transaction !== (p.operation === 'transaction') ||
          p.origin !== this.#transport.root.origin || p.route !== this.#transport.root.route ||
          p.fingerprint !== this.#transport.fingerprint || !/^[0-9a-f]{32}$/.test(p.nonce)) fail('Receipt belongs to another route or credential.');
      const scope = receiptScope(p.scope), fields = transaction ? transactionCommand(p.fields) : branchCommand(p.operation, p.fields);
      const body = transaction ? transactionForm(fields) : form(fields);
      if (scope.format !== fields.object_format || (this.#scope && Object.keys(scope).some(k => this.#scope[k] !== scope[k]))) fail('Receipt repository changed.');
      if (p.observedTx !== null) opaque(p.observedTx);
      if (p.observedPrincipal !== null) principal(p.observedPrincipal);
      const serial = this.#serial, epoch = this.#transport.epoch;
      const key = await retryKey(this.#transport.root, p.fingerprint, scope, p.operation, p.nonce, body, this.#transport.crypto);
      if (key !== p.key) fail('Receipt no longer matches the original idempotency key.');
      if (transaction) receipt(this.#transport.root, { ...p, fields, scope, observedTx: '\\'.repeat(256), observedPrincipal: 'f'.repeat(32) });
      this.#check(serial, epoch); this.cancel();
      this.#pending = { ...p, fields, scope, body, key, sent: true, exported: true }; return this.pending;
    });
  }
}
