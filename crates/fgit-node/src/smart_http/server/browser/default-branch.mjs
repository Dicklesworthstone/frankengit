// Default-branch administration preserves exact symbolic HEAD expectations.
// Native authorization decides the change; a reference listing grants no write.
import { Transport, binding, pinned, keys, record, integer, text, principal, opaque,
  format, oid, utf8, hex, form, copy, fail } from './pulls-core.mjs';
import { refsPage, refBytes } from './branches.mjs';
import { recovery, receiptScope } from './pulls-actions.mjs';

export const DEFAULT_BRANCH_RECEIPT_LIMIT = 32 * 1024;
const REF_LIMIT = 2048;
const PAGE_LIMIT = 100;
const same = (a, b) => JSON.stringify(a) === JSON.stringify(b);
function fields(value, names) {
  keys(value, names);
  if (names.some(name => !Object.hasOwn(value, name))) fail('Missing default-branch field.');
  return value;
}
function branchHex(value) {
  if (refBytes(value, 'branches').length > 1024) fail('Default branch names are limited to 1024 bytes.');
  return value;
}
function nativeTip(value, algorithm) {
  return algorithm + ':' + oid(value, algorithm);
}
function selectedHead(value) {
  if (typeof value !== 'string' || !/^alg:[12]:[0-9a-f]{64}$/.test(value)) fail('Invalid authenticated default-branch snapshot.');
  return value;
}
function sourceSelection(value) {
  fields(value, ['scope', 'principal', 'head', 'sourceHead', 'referenceHex', 'tip', 'unborn']);
  const scope = receiptScope(value.scope);
  const referenceHex = value.referenceHex === null ? null : branchHex(value.referenceHex);
  const tip = value.tip === null ? null : nativeTip(value.tip, scope.format);
  if ((referenceHex === null && tip !== null) || value.unborn !== (referenceHex !== null && tip === null)) fail('Absent and unborn default branches must remain distinct.');
  return { scope, principal: principal(value.principal), head: selectedHead(value.head),
    sourceHead: opaque(value.sourceHead), referenceHex, tip, unborn: value.unborn };
}
export function defaultBranchSnapshot(reply, previous = null, expectedHead = null) {
  const selected = pinned(reply, previous, expectedHead);
  if (reply.type !== 'default_branch' || reply.read_only !== true ||
      reply.transaction_created !== false || reply.published !== false) fail('Expected a read-only default-branch observation.');
  return sourceSelection({ scope: selected.binding, principal: reply.principal_id,
    head: selected.head, sourceHead: reply.source_head, referenceHex: reply.default_reference_hex,
    tip: reply.tip, unborn: reply.unborn });
}
export function defaultBranchCommand(input, algorithm) {
  format(algorithm);
  const expected = Object.hasOwn(input, 'expected_default_hex');
  const absent = Object.hasOwn(input, 'expect_no_default');
  if (expected === absent) fail('Supply exactly one original default-branch expectation.');
  fields(input, [expected ? 'expected_default_hex' : 'expect_no_default', 'reference_hex', 'expected_tip']);
  if (absent && input.expect_no_default !== true) fail('An absent default requires the explicit true expectation.');
  if (typeof input.expected_tip !== 'string' || !input.expected_tip.startsWith(algorithm + ':')) fail('A typed native commit identity is required in the frozen command.');
  return { ...(expected ? { expected_default_hex: branchHex(input.expected_default_hex) } : { expect_no_default: true }),
    reference_hex: branchHex(input.reference_hex), expected_tip: nativeTip(input.expected_tip, algorithm) };
}
export function defaultBranchForm(input, algorithm) {
  const command = defaultBranchCommand(input, algorithm);
  // The native form carries bare Git hex in the repository's selected domain.
  // Keep that domain explicit in the browser's retained command and receipt.
  return form({ ...command, expected_tip: oid(command.expected_tip, algorithm) });
}
export function defaultBranchPublication(reply, pending, status) {
  binding(reply, pending.source.scope);
  const command = pending.command, old = command.expected_default_hex ?? null;
  if (reply.type !== 'default_branch_publication' || reply.operation !== 'set-default' ||
      reply.principal_id !== pending.source.principal || reply.authentication !== 'http-token' ||
      reply.terminal !== true || !['committed', 'refused'].includes(reply.outcome) ||
      status !== (reply.outcome === 'committed' ? 200 : 409) ||
      reply.expected_default_reference_hex !== old || reply.default_reference_hex !== command.reference_hex ||
      nativeTip(reply.expected_tip, pending.source.scope.format) !== command.expected_tip ||
      reply.direct_refs_changed !== false ||
      reply.head_changed_by_transaction !== (reply.outcome === 'committed' && old !== command.reference_hex)) {
    fail('Default-branch decision changed the principal, expectations or effects.');
  }
  opaque(reply.tx_id); integer(reply.decision_sequence, 'decision sequence', 1);
  if (pending.observedTx !== null && pending.observedTx !== reply.tx_id) fail('Original transaction identity changed.');
  if (reply.outcome === 'committed') {
    opaque(reply.repository_commit_id);
    if (['code', 'code_point', 'refusal_record_id'].some(name => Object.hasOwn(reply, name))) fail('Conflicting default-branch decisions.');
  } else {
    opaque(reply.code); opaque(reply.refusal_record_id); integer(reply.code_point, 'refusal code', 0, 65535);
    if (Object.hasOwn(reply, 'repository_commit_id')) fail('Conflicting default-branch decisions.');
  }
  return { terminal: true, outcome: reply.outcome, tx: reply.tx_id, principal: reply.principal_id,
    rcr: reply.repository_commit_id ?? null, refusal: reply.code ?? null,
    headChanged: reply.head_changed_by_transaction, deliveryAcknowledged: null };
}
function transaction(value) {
  if (value === null) return null;
  fields(value, ['tx_id', 'seal_id', 'request_schema', 'canonical_request_digest']);
  const digest = fields(value.canonical_request_digest, ['algorithm', 'hex']);
  integer(digest.algorithm, 'seal digest algorithm', 1, 65535);
  if (!/^(?:[0-9a-f]{2}){1,64}$/.test(digest.hex) || value.request_schema !== 'default-branch-admission/v1.0') fail('Recovery seal is not a default-branch command.');
  return { tx_id: opaque(value.tx_id), seal_id: opaque(value.seal_id), request_schema: value.request_schema,
    canonical_request_digest: { algorithm: digest.algorithm, hex: digest.hex } };
}
async function requestKey(root, fingerprint, source, command, nonce, body, crypto) {
  const encoded = utf8.encode(JSON.stringify([root.origin, root.route, fingerprint, source, command, nonce, body]));
  const digest = hex(new Uint8Array(await crypto.subtle.digest('SHA-256', encoded)));
  return 'fgdefault1-' + nonce + '-' + digest;
}
function receipt(root, pending) {
  const p = pending;
  const value = JSON.stringify({ schema: 'frankengit-browser-default-branch-retry-v1', origin: root.origin, route: root.route,
    source: p.source, command: p.command, fingerprint: p.fingerprint, nonce: p.nonce, key: p.key,
    observedTx: p.observedTx, observedTransaction: p.observedTransaction });
  text(value, DEFAULT_BRANCH_RECEIPT_LIMIT, 'default-branch receipt');
  return value;
}
export class DefaultBranchClient {
  #transport; #scope = null; #principal = null; #observed = null; #page = null; #refs = new Map();
  #pending = null; #busy = false; #serial = 0;
  constructor(options) { this.#transport = new Transport({ ...options, pageSuffix: '/ui/default-branch/' }); }
  get connected() { return this.#transport.connected; }
  get busy() { return this.#busy; }
  get observed() { return copy(this.#observed); }
  get page() { return copy(this.#page); }
  get knownRefs() { return copy([...this.#refs.values()]); }
  get pending() {
    if (!this.#pending) return null;
    const { source, command, key, sent, exported, observedTx, observedTransaction } = this.#pending;
    return copy({ source, command, key, sent, exported, observedTx, observedTransaction });
  }
  async connect(token) {
    this.disconnect();
    await this.#transport.connect(token, this.#pending?.fingerprint ?? null);
  }
  disconnect() {
    this.cancel(); this.#transport.disconnect(); this.#scope = null; this.#principal = null;
  }
  #clear() { this.#observed = null; this.#page = null; this.#refs.clear(); }
  cancel() { this.#serial += 1; this.#transport.cancelReads(); this.#clear(); }
  #check(serial, epoch) {
    if (!this.connected || serial !== this.#serial || epoch !== this.#transport.epoch) fail('Default-branch observation was cancelled or replaced.');
  }
  #noPending() { if (this.#pending) fail('Resolve the original saved request first.'); }
  async #exclusive(work) {
    if (this.#busy || !this.connected) fail('Connect first and finish the current operation.');
    this.#busy = true;
    try { return await work(); }
    finally { this.#busy = false; if (!this.connected) this.#clear(); }
  }
  async load({ next = false } = {}) {
    return this.#exclusive(async () => {
      this.#noPending();
      if (next && (!this.#observed || !this.#page || this.#page.next_after === null)) fail('No pinned continuation remains.');
      if (!next) this.cancel();
      const serial = this.#serial, epoch = this.#transport.epoch;
      try {
        let observed = this.#observed;
        if (!next) {
          const { value } = await this.#transport.request('default-branch', { maximum: 16 * 1024 });
          observed = defaultBranchSnapshot(value, this.#scope);
          this.#check(serial, epoch);
          if (this.#principal !== null && observed.principal !== this.#principal) fail('Authenticated principal changed; reconnect explicitly.');
        }
        const remaining = REF_LIMIT - this.#refs.size;
        if (!remaining) fail('Reference session limit reached; reload explicitly.');
        const query = { object_format: observed.scope.format, namespace: 'branches',
          limit: Math.min(PAGE_LIMIT, remaining), cursor_encoding: 'hex', expected_head: observed.head,
          ...(next ? { after: this.#page.next_after } : {}) };
        const { value } = await this.#transport.request('source/refs', {
          method: 'POST', body: form(query), maximum: 1024 * 1024 });
        refsPage(value, query, observed.scope);
        if (value.source_head !== observed.sourceHead) fail('Reference listing changed the authenticated source head.');
        this.#check(serial, epoch);
        this.#scope = observed.scope; this.#principal = observed.principal; this.#observed = observed;
        this.#page = copy(value);
        for (const row of value.refs) this.#refs.set(row.ref_hex, copy(row));
        return this.observed;
      } catch (error) {
        if (serial === this.#serial && epoch === this.#transport.epoch) this.#clear();
        throw error;
      }
    });
  }
  async prepare(referenceHex) {
    return this.#exclusive(async () => {
      this.#noPending();
      if (!this.#observed || !this.#page) fail('Load the current default and its pinned branch listing first.');
      branchHex(referenceHex);
      const selected = this.#refs.get(referenceHex);
      if (!selected) fail('Select a branch from the same pinned reference listing.');
      const source = sourceSelection(this.#observed);
      const command = defaultBranchCommand({
        ...(source.referenceHex === null ? { expect_no_default: true } : { expected_default_hex: source.referenceHex }),
        reference_hex: referenceHex, expected_tip: source.scope.format + ':' + oid(selected.object_id, source.scope.format),
      }, source.scope.format);
      const body = defaultBranchForm(command, source.scope.format), nonce = hex(this.#transport.crypto.getRandomValues(new Uint8Array(16)));
      const serial = this.#serial, epoch = this.#transport.epoch, fingerprint = this.#transport.fingerprint;
      const key = await requestKey(this.#transport.root, fingerprint, source, command, nonce, body, this.#transport.crypto);
      this.#check(serial, epoch);
      this.#pending = { source, command, body, nonce, fingerprint, key,
        sent: false, exported: false, observedTx: null, observedTransaction: null };
      return this.pending;
    });
  }
  discardUnsent() {
    if (this.#busy || !this.#pending || this.#pending.sent || this.#pending.exported) fail('Only an unsent, unexported local request can be discarded.');
    this.#pending = null;
  }
  #settle(result, pending) {
    if (pending !== this.#pending) fail('Original saved request changed.');
    if (result.terminal) { this.#pending = null; this.cancel(); }
    return result;
  }
  async send() {
    return this.#exclusive(async () => {
      const p = this.#pending;
      if (!p || p.fingerprint !== this.#transport.fingerprint) fail('Restore the original request and credential.');
      p.sent = true;
      try {
        const { value, status } = await this.#transport.request('default-branch', {
          method: 'POST', body: p.body, key: p.key, statuses: [200, 409], maximum: 32 * 1024, read: false });
        return this.#settle(defaultBranchPublication(value, p, status), p);
      } catch (error) { error.outcomeUnknown = true; throw error; }
    });
  }
  async recover() {
    return this.#exclusive(async () => {
      const p = this.#pending;
      if (!p || p.fingerprint !== this.#transport.fingerprint) fail('Restore the original request and credential.');
      const { value } = await this.#transport.request('outcomes', {
        method: 'POST', key: p.key, maximum: 32 * 1024, read: false });
      const result = recovery(value, { scope: p.source.scope, observedTx: p.observedTx, observedPrincipal: p.source.principal });
      const selected = transaction(value.transaction);
      if (p.observedTransaction !== null && !same(selected, p.observedTransaction)) fail('Original recovery transaction or seal changed.');
      if (!result.terminal && selected !== null) { p.observedTx = selected.tx_id; p.observedTransaction = selected; }
      return this.#settle(result, p);
    });
  }
  exportReceipt() {
    if (this.#busy || !this.#pending) fail('No stable original request is available.');
    const value = receipt(this.#transport.root, this.#pending);
    this.#pending.exported = true; return value;
  }
  async restoreReceipt(encoded) {
    return this.#exclusive(async () => {
      this.#noPending(); text(encoded, DEFAULT_BRANCH_RECEIPT_LIMIT, 'default-branch receipt');
      const p = fields(JSON.parse(encoded), ['schema', 'origin', 'route', 'source', 'command', 'fingerprint', 'nonce', 'key', 'observedTx', 'observedTransaction']);
      if (p.schema !== 'frankengit-browser-default-branch-retry-v1' ||
          p.origin !== this.#transport.root.origin || p.route !== this.#transport.root.route ||
          p.fingerprint !== this.#transport.fingerprint || !/^[0-9a-f]{32}$/.test(p.nonce)) fail('Receipt belongs to another route or credential.');
      const source = sourceSelection(p.source), command = defaultBranchCommand(p.command, source.scope.format);
      if ((command.expected_default_hex ?? null) !== source.referenceHex ||
          (this.#scope !== null && !same(source.scope, this.#scope)) ||
          (this.#principal !== null && source.principal !== this.#principal)) fail('Receipt changed the original observation or repository.');
      const observedTransaction = transaction(p.observedTransaction);
      const observedTx = p.observedTx === null ? null : opaque(p.observedTx);
      if ((observedTransaction?.tx_id ?? null) !== observedTx) fail('Receipt changed its recovery observation.');
      const body = defaultBranchForm(command, source.scope.format), serial = this.#serial, epoch = this.#transport.epoch;
      const key = await requestKey(this.#transport.root, p.fingerprint, source, command, p.nonce, body, this.#transport.crypto);
      this.#check(serial, epoch);
      if (key !== p.key) fail('Original receipt body or key changed.');
      this.#clear(); this.#scope = source.scope; this.#principal = source.principal;
      this.#pending = { source, command, body, fingerprint: p.fingerprint, nonce: p.nonce, key,
        sent: true, exported: true, observedTx, observedTransaction };
      return this.pending;
    });
  }
}
