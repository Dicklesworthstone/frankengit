// Native issue API client. HTTP success is not a terminal repository decision.
// No ambient credentials, persistent browser storage, automatic mutation retries,
// or client-side authority. Recovery receipts contain private draft data, not tokens.
const encoder = new TextEncoder();
export const MAX_FORM_BYTES = 256 * 1024;
export const MAX_REPLY_BYTES = 8 * 1024 * 1024;
export const MAX_RECEIPT_BYTES = 512 * 1024;
const own = (object, key) => Object.prototype.hasOwnProperty.call(object, key);
const fail = message => { throw new Error(message); };

export function natural(value, field, minimum = 0, maximum = Number.MAX_SAFE_INTEGER) {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    fail(`Invalid or unsupported ${field}; this browser requires exact safe integers.`);
  }
  return value;
}
export function decimal(value, field, minimum = 0) {
  if (typeof value !== 'string' || !/^(?:0|[1-9][0-9]*)$/.test(value)) fail(`Invalid ${field}.`);
  return natural(Number(value), field, minimum);
}
function object(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) fail('Invalid API object.');
  return value;
}
function text(value, maximum, field, singleLine = false) {
  if (typeof value !== 'string' || value.length > maximum || encoder.encode(value).length > maximum ||
      /[\uD800-\uDFFF]/u.test(value) || value.includes('\0') ||
      (singleLine && (!value.trim() || /[\u0000-\u001f\u007f-\u009f]/u.test(value)))) {
    fail(`Invalid or oversized ${field}.`);
  }
  return value;
}
function opaque(value, field) { return text(value, 256, field, true); }
export function snapshotToken(value) {
  if (typeof value !== 'string' || !/^alg:[1-9][0-9]{0,4}:(?:[0-9a-f]{2}){1,64}$/.test(value) ||
      Number(value.split(':')[1]) > 65535) fail('Invalid snapshot token.');
  return value;
}
function compareUtf8(a, b) {
  const left = encoder.encode(a), right = encoder.encode(b);
  for (let i = 0; i < Math.min(left.length, right.length); i += 1) {
    if (left[i] !== right[i]) return left[i] - right[i];
  }
  return left.length - right.length;
}
function checkedLabels(values, canonical = false) {
  if (!Array.isArray(values) || values.length > 32) fail('At most 32 labels are supported.');
  const labels = values.map(label => text(label, 64, 'label', true));
  const sorted = [...labels].sort(compareUtf8);
  if (sorted.some((label, i) => i > 0 && label === sorted[i - 1]) ||
      (canonical && sorted.some((label, i) => label !== labels[i]))) fail('Invalid label ordering or duplicates.');
  return sorted;
}
export function issueAction(name, fields) {
  object(fields);
  if (!['open', 'edit', 'comment', 'close', 'reopen'].includes(name)) fail('Unsupported issue action.');
  const allowed = name === 'open' || name === 'edit' ? ['title', 'body', 'labels'] : name === 'comment' ? ['body'] : [];
  if (Object.keys(fields).some(key => !allowed.includes(key))) fail('Unknown or inapplicable issue field.');
  const result = {};
  if (own(fields, 'title')) result.title = text(fields.title, 256, 'title', true);
  if (own(fields, 'body')) result.body = text(fields.body, 64 * 1024, 'body');
  if (own(fields, 'labels')) result.labels = checkedLabels(fields.labels);
  if (name === 'open') {
    if (!own(result, 'title') || !own(result, 'body')) fail('Opening an issue requires title and body.');
    result.labels ??= [];
  } else if (name === 'edit' && !Object.keys(result).length) fail('Select at least one field to replace.');
  else if (name === 'comment' && (!own(result, 'body') || !result.body.trim())) fail('Comment must not be empty.');
  return result;
}
export function mutationRequest(number, version, action, fields) {
  natural(number, 'issue number', 1);
  natural(version, 'expected issue version', 0, Number.MAX_SAFE_INTEGER - 1);
  if ((action === 'open') !== (version === 0)) fail('Only a new issue uses expected version zero.');
  const checked = issueAction(action, fields);
  const form = new URLSearchParams({ expected_version: String(version) });
  for (const name of ['title', 'body']) if (own(checked, name)) form.append(name, checked[name]);
  if (checked.labels) {
    for (const label of checked.labels) form.append('label', label);
    if (action === 'edit' && !checked.labels.length) form.append('clear_labels', 'true');
  }
  const body = form.toString();
  if (body.length > MAX_FORM_BYTES) fail('Encoded issue form exceeds 256 KiB.');
  return { number, expected_version: version, action, fields: checked, body };
}
function identity(reply, previous = null) {
  object(reply);
  if (reply.schema_version !== 1) fail('Unsupported issue response version.');
  const result = { tenant: opaque(reply.tenant_id, 'tenant'), repository: opaque(reply.repository_id, 'repository') };
  if (previous && (previous.tenant !== result.tenant || previous.repository !== result.repository)) {
    fail('Repository identity changed. Reconnect explicitly.');
  }
  return result;
}
export function issueState(row) {
  object(row);
  natural(row.number, 'issue number', 1); natural(row.version, 'issue version', 1);
  issueAction('open', { title: row.title, body: row.body, labels: row.labels });
  checkedLabels(row.labels, true);
  if (!['open', 'closed'].includes(row.state)) fail('Invalid issue state.');
  opaque(row.opened_by, 'opening principal'); opaque(row.last_actor, 'last principal');
  natural(row.comments, 'comment count', 0, row.version - 1);
  return row;
}
export function issuePage(reply, { after = 0, limit = 20, head = null, binding = null } = {}) {
  const observed = identity(reply, binding);
  const snapshot = snapshotToken(reply.snapshot_token);
  if (head !== null && snapshot !== head) fail('Issue snapshot moved. Reload explicitly.');
  if (reply.type !== 'issue_page' || reply.after !== after || reply.limit !== limit ||
      !Array.isArray(reply.issues) || reply.issues.length > limit) fail('Invalid issue page.');
  let previous = after;
  for (const row of reply.issues) {
    issueState(row);
    if (row.number <= previous) fail('Invalid issue ordering.');
    previous = row.number;
  }
  if (reply.next_after !== null && (reply.issues.length !== limit || reply.next_after !== previous)) {
    fail('Invalid issue continuation.');
  }
  return { reply, binding: observed, head: snapshot };
}
export function issueHistory(reply, number, { after = 0, limit = 20, head = null, binding = null } = {}) {
  const observed = identity(reply, binding);
  const snapshot = snapshotToken(reply.snapshot_token);
  if (head !== null && snapshot !== head) fail('Issue snapshot moved. Reload explicitly.');
  if (reply.type !== 'issue_history' || reply.after_version !== after || reply.limit !== limit ||
      typeof reply.found !== 'boolean' || !Array.isArray(reply.events) || reply.events.length > limit) fail('Invalid issue history.');
  if (!reply.found) {
    if (reply.issue !== null || reply.events.length || reply.next_after_version !== null) fail('Invalid missing-issue response.');
  } else {
    issueState(reply.issue);
    if (reply.issue.number !== number) fail('Issue number mismatch.');
    const remaining = Math.max(0, reply.issue.version - after);
    const count = Math.min(remaining, limit);
    if (reply.events.length !== count || reply.next_after_version !== (remaining > count ? after + count : null)) {
      fail('Incomplete issue history or invalid continuation.');
    }
    reply.events.forEach((event, i) => {
      object(event); object(event.action);
      if (event.version !== after + i + 1) fail('History contains a version gap.');
      opaque(event.actor, 'event principal');
      const { name, ...fields } = event.action;
      issueAction(name, fields);
      if ((event.version === 1) !== (name === 'open')) fail('Invalid opening event position.');
    });
  }
  return { reply, binding: observed, head: snapshot };
}
export function publication(reply, pending, status = 200) {
  identity(reply, pending.binding);
  if (reply.type !== 'issue_publication' || reply.number !== pending.number ||
      reply.expected_version !== pending.expected_version || reply.action !== pending.action ||
      !['committed', 'refused'].includes(reply.outcome) || reply.delivery_acknowledged !== null) {
    fail('Unrecognized or mismatched terminal issue reply.');
  }
  if (status !== (reply.outcome === 'committed' ? 200 : 409)) fail('Terminal issue status and decision disagree.');
  opaque(reply.principal_id, 'principal'); opaque(reply.tx_id, 'transaction');
  natural(reply.decision_sequence, 'decision sequence', 1);
  if (reply.outcome === 'committed') {
    opaque(reply.repository_commit_id, 'repository commit');
    if (reply.refusal_code !== null || reply.refusal_record_id !== null) fail('Ambiguous terminal issue reply.');
  } else {
    if (reply.repository_commit_id !== null) fail('Ambiguous terminal issue reply.');
    opaque(reply.refusal_code, 'refusal code'); opaque(reply.refusal_record_id, 'refusal record');
  }
  return { outcome: reply.outcome, tx: reply.tx_id, rcr: reply.repository_commit_id, refusal: reply.refusal_code };
}
export function recoveredOutcome(reply, pending) {
  identity(reply, pending.binding);
  if (reply.type !== 'transaction_outcome' || reply.selector !== 'transaction' || reply.command_index !== null ||
      reply.read_only !== true || reply.request_reexecuted !== false || reply.absence_proves_non_commit !== false ||
      reply.session_completeness_established !== false || typeof reply.terminal !== 'boolean') fail('Invalid recovery response.');
  opaque(reply.repository_incarnation, 'repository incarnation'); opaque(reply.principal_id, 'principal');
  if (!['key_not_observed', 'seal_not_observed', 'undecided', 'committed', 'refused'].includes(reply.state) ||
      reply.terminal !== ['committed', 'refused'].includes(reply.state)) fail('Invalid recovery state.');
  if (reply.transaction !== null) opaque(object(reply.transaction).tx_id, 'transaction');
  if (!reply.terminal) {
    if (reply.decision !== null || (reply.state === 'undecided' && reply.transaction === null)) fail('Ambiguous recovery response.');
    return { state: reply.state, terminal: false };
  }
  const decision = object(reply.decision);
  if (!reply.transaction || decision.kind !== reply.state) fail('Terminal recovery lacks its decision.');
  natural(decision.decision_sequence, 'decision sequence', 1);
  if (reply.state === 'committed') opaque(decision.repository_commit_id, 'repository commit');
  else { opaque(decision.refusal_record_id, 'refusal record'); opaque(decision.code, 'refusal code'); }
  return { terminal: true, outcome: reply.state, tx: reply.transaction.tx_id,
    rcr: decision.repository_commit_id ?? null, refusal: decision.code ?? null };
}

export async function readJson(response, signal, maximum = MAX_REPLY_BYTES) {
  if (!/^application\/json(?:\s*;|$)/i.test(response.headers.get('Content-Type') ?? '') || !response.body) {
    await response.body?.cancel(); fail('Expected a bounded JSON API reply.');
  }
  const reader = response.body.getReader();
  const cancel = () => { void reader.cancel().catch(() => {}); };
  signal?.addEventListener('abort', cancel, { once: true });
  const chunks = []; let size = 0;
  try {
    while (true) {
      signal?.throwIfAborted();
      const next = await reader.read();
      signal?.throwIfAborted();
      if (next.done) break;
      size += next.value.byteLength;
      if (size > maximum) fail('API reply exceeds the browser byte limit.');
      chunks.push(next.value);
    }
    const bytes = new Uint8Array(size); let offset = 0;
    for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.length; }
    return JSON.parse(new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes));
  } finally {
    signal?.removeEventListener('abort', cancel);
    await reader.cancel().catch(() => {}); reader.releaseLock();
  }
}
function rootFor(href) {
  const page = new URL(href);
  const suffix = '/ui/issues/';
  if (page.search || page.hash || page.username || page.password || !page.pathname.endsWith(suffix) ||
      !['https:', 'http:'].includes(page.protocol)) fail('Open the exact repository /ui/issues/ endpoint.');
  if (page.protocol === 'http:' && !['127.0.0.1', '[::1]', 'localhost'].includes(page.hostname)) {
    fail('Use HTTPS, except on a trusted loopback host.');
  }
  const route = page.pathname.slice(0, -suffix.length);
  if (!/^\/(?:[A-Za-z0-9._~-]+\/)*[A-Za-z0-9._~-]+$/.test(route) ||
      route.slice(1).split('/').some(part => part === '.' || part === '..')) fail('Invalid repository route.');
  return { origin: page.origin, route, api: `${page.origin}${route}/api/v1/` };
}
const asHex = bytes => Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
const clone = value => structuredClone(value);
function httpError(status) {
  const error = new Error(({ 401: 'Token rejected or revoked. Authenticate with the original credential.',
    403: 'Required issue or outcome scope is missing, or the endpoint is disabled.',
    404: 'Repository or issue endpoint unavailable.', 409: 'Snapshot or expected version changed. Reload explicitly.',
    429: 'Quota exhausted. Retry after the server quota window.' })[status] ?? `API request failed (HTTP ${status}).`);
  error.status = status;
  return error;
}

export class IssueClient {
  #root; #fetch; #crypto; #token = ''; #fingerprint = ''; #epoch = 0; #pending = null;
  #binding = null; #controllers = new Set(); #readControllers = new Set(); #busy = false; #timeout;
  constructor({ href, fetchImpl = globalThis.fetch, cryptoImpl = globalThis.crypto, timeoutMs = 30_000 }) {
    this.#root = rootFor(href); this.#fetch = fetchImpl; this.#crypto = cryptoImpl;
    this.#timeout = natural(timeoutMs, 'request timeout', 1, 300_000);
  }
  get connected() { return Boolean(this.#token); }
  get busy() { return this.#busy; }
  get pending() {
    if (!this.#pending) return null;
    const { credential_fingerprint: _, ...safe } = this.#pending;
    return clone(safe);
  }
  get binding() { return this.#binding && { ...this.#binding }; }
  async connect(token) {
    if (typeof token !== 'string' || !/^[0-9a-f]{64}$/.test(token)) fail('A 64-character lowercase hexadecimal token is required.');
    this.disconnect();
    const epoch = this.#epoch;
    const digest = await this.#crypto.subtle.digest('SHA-256', encoder.encode(token));
    if (epoch !== this.#epoch) fail('Connection superseded.');
    const fingerprint = asHex(new Uint8Array(digest));
    if (this.#pending && this.#pending.credential_fingerprint !== fingerprint) fail('An unresolved change belongs to another credential.');
    this.#token = token; this.#fingerprint = fingerprint;
    this.#binding = this.#pending?.binding ? clone(this.#pending.binding) : null;
  }
  disconnect() {
    this.#epoch += 1;
    for (const controller of this.#controllers) controller.abort();
    this.#token = ''; this.#fingerprint = ''; this.#binding = null;
    // An unresolved request is a responsibility, not a discarded failed write.
    // Keep its token-free recovery record, including any private draft text.
  }
  cancelReads() {
    for (const controller of this.#readControllers) controller.abort();
  }
  async #request(path, { method = 'GET', body, key, maximum = MAX_REPLY_BYTES, view = false, terminalReply = false } = {}) {
    if (!this.#token) fail('Connect an explicitly scoped token first.');
    const epoch = this.#epoch;
    const controller = new AbortController(); this.#controllers.add(controller);
    if (view) this.#readControllers.add(controller);
    const timer = setTimeout(() => controller.abort(), this.#timeout);
    const headers = { Authorization: `Bearer ${this.#token}`, Accept: 'application/json' };
    if (body !== undefined) headers['Content-Type'] = 'application/x-www-form-urlencoded';
    if (key) headers['Idempotency-Key'] = key;
    let response;
    try {
      response = await this.#fetch(new URL(path, this.#root.api), {
        method, body, headers, signal: controller.signal, redirect: 'error',
        mode: 'same-origin', credentials: 'omit', cache: 'no-store', referrerPolicy: 'no-referrer',
      });
      controller.signal.throwIfAborted();
      if (epoch !== this.#epoch) fail('Connection superseded.');
      if (response.redirected || (response.url && new URL(response.url).origin !== this.#root.origin)) fail('API redirect refused.');
      // Native issue refusals carry a canonical terminal decision with 409.
      // Other 409 bodies (snapshot/key reuse) must still fail publication validation.
      if (terminalReply ? ![200, 409].includes(response.status) : !response.ok) throw httpError(response.status);
      const result = await readJson(response, controller.signal, maximum);
      if (epoch !== this.#epoch) fail('Connection superseded.');
      return terminalReply ? { reply: result, status: response.status } : result;
    } catch (error) {
      if (epoch === this.#epoch && error.status === 401) this.disconnect();
      throw error;
    } finally {
      clearTimeout(timer); this.#controllers.delete(controller); this.#readControllers.delete(controller);
      if (response?.body && !response.body.locked) await response.body.cancel().catch(() => {});
    }
  }
  async read(number = null, { after = 0, limit = 20, head = null } = {}) {
    natural(after, 'page cursor'); natural(limit, 'page limit', 1, 100);
    if (number !== null) natural(number, 'issue number', 1);
    if (head !== null) snapshotToken(head);
    if (after && !head) fail('Continuation requires its original snapshot.');
    const query = new URLSearchParams({ [number === null ? 'after' : 'after_version']: String(after), limit: String(limit) });
    if (head) query.set('expected_head', head);
    const raw = await this.#request(`issues${number === null ? '' : `/${number}`}?${query}`, { view: true });
    const options = { after, limit, head, binding: this.#binding };
    const checked = number === null ? issuePage(raw, options) : issueHistory(raw, number, options);
    this.#binding = checked.binding;
    return checked;
  }
  async #requestKey(request, fingerprint, nonce) {
    const message = JSON.stringify([this.#root.origin, this.#root.route, fingerprint, nonce,
      request.number, request.expected_version, request.action, request.body]);
    const digest = await this.#crypto.subtle.digest('SHA-256', encoder.encode(message));
    return `fgui-${nonce}-${asHex(new Uint8Array(digest))}`;
  }
  async stage(number, version, action, fields) {
    if (!this.connected) fail('Connect an explicitly scoped token first.');
    if (this.#pending || this.#busy) fail('Resolve or discard the existing prepared change first.');
    const request = mutationRequest(number, version, action, fields);
    const epoch = this.#epoch, fingerprint = this.#fingerprint, binding = this.binding;
    this.#busy = true;
    try {
      const nonce = asHex(this.#crypto.getRandomValues(new Uint8Array(16)));
      const key = await this.#requestKey(request, fingerprint, nonce);
      if (epoch !== this.#epoch) fail('Connection superseded.');
      this.#pending = { ...request, key, binding, sent: false, exported: false, credential_fingerprint: fingerprint };
      return this.pending;
    } finally { this.#busy = false; }
  }
  discardUnsent() {
    if (this.#busy || this.#pending?.sent || this.#pending?.exported) fail('A dispatched or exported change cannot be discarded as a failed write.');
    this.#pending = null;
  }
  exportReceipt() {
    if (!this.#pending) fail('No prepared change.');
    // Once a receipt leaves this page, another session may dispatch it.
    this.#pending.exported = true;
    return JSON.stringify({ schema: 'frankengit-issue-retry-v1', origin: this.#root.origin, route: this.#root.route,
      request: this.#pending }, null, 2);
  }
  async restoreReceipt(serialized) {
    if (!this.connected || this.#pending || this.#busy) fail('Connect first and resolve any existing change.');
    text(serialized, MAX_RECEIPT_BYTES, 'recovery receipt');
    const receipt = object(JSON.parse(serialized)), request = object(receipt.request);
    if (receipt.schema !== 'frankengit-issue-retry-v1' || receipt.origin !== this.#root.origin || receipt.route !== this.#root.route ||
        request.credential_fingerprint !== this.#fingerprint || typeof request.key !== 'string' || !/^fgui-[0-9a-f]{32}-[0-9a-f]{64}$/.test(request.key)) {
      fail('Recovery receipt does not belong to this repository and credential.');
    }
    const checked = mutationRequest(request.number, request.expected_version, request.action, object(request.fields));
    if (request.body !== checked.body) fail('Recovery receipt has a mismatched request body.');
    if (request.binding !== null) {
      object(request.binding); opaque(request.binding.tenant, 'tenant'); opaque(request.binding.repository, 'repository');
      if (this.#binding && (request.binding.tenant !== this.#binding.tenant || request.binding.repository !== this.#binding.repository)) {
        fail('Recovery receipt repository mismatch.');
      }
    }
    const epoch = this.#epoch, fingerprint = this.#fingerprint;
    this.#busy = true;
    try {
      const key = await this.#requestKey(checked, fingerprint, request.key.split('-')[1]);
      if (epoch !== this.#epoch) fail('Connection superseded.');
      if (key !== request.key) fail('Recovery key does not commit to this exact request.');
      this.#pending = { ...checked, key, binding: request.binding && clone(request.binding),
        credential_fingerprint: fingerprint, sent: true, exported: true };
      return this.pending; // Imported records are ALWAYS treated as possibly sent.
    } finally { this.#busy = false; }
  }
  async send() {
    if (!this.connected || !this.#pending) fail('Connect and prepare an issue change first.');
    if (this.#busy) fail('An issue request is already in flight.');
    this.#busy = true;
    const pending = this.#pending; pending.sent = true;
    try {
      const raw = await this.#request(`issues/${pending.number}/${pending.action}`, {
        method: 'POST', body: pending.body, key: pending.key, maximum: 16 * 1024, terminalReply: true,
      });
      const terminal = publication(raw.reply, pending, raw.status);
      this.#pending = null;
      return terminal;
    } catch (error) { error.outcomeUnknown = true; throw error; }
    finally { this.#busy = false; }
  }
  async recover() {
    if (!this.connected || !this.#pending) fail('Connect and restore the original recovery receipt first.');
    if (this.#busy) fail('An issue request is already in flight.');
    this.#busy = true;
    const pending = this.#pending;
    try {
      const raw = await this.#request('outcomes', { method: 'POST', key: pending.key, maximum: 16 * 1024 });
      const result = recoveredOutcome(raw, pending);
      if (result.terminal) this.#pending = null;
      return result;
    } finally { this.#busy = false; }
  }
}
