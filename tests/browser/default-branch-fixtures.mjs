// Explicit in-process HTTP and DOM peers; these are not live-browser evidence.
import { webcrypto } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { DefaultBranchClient } from '../../crates/fgit-node/src/smart_http/server/browser/default-branch.mjs';
import { mountDefaultBranch } from '../../crates/fgit-node/src/smart_http/server/browser/default-branch-view.mjs';
export const token = 'ab'.repeat(32), actor = '11'.repeat(16);
export const href = 'https://example.invalid/repo.git/ui/default-branch/';
export const hex = value => Buffer.from(value).toString('hex');
export const tip = (algorithm = 'sha1', value = 'a') => algorithm + ':' + value.repeat(algorithm === 'sha1' ? 40 : 64);
export const head = 'alg:1:' + 'c'.repeat(64);
export const metadata = (algorithm = 'sha1') => ({ schema_version: 1, tenant_id: '22'.repeat(16), repository_id: '33'.repeat(16),
  repository_incarnation: '44'.repeat(16), object_format: algorithm });
export const observation = (algorithm = 'sha1', extra = {}) => ({ ...metadata(algorithm), type: 'default_branch',
  principal_id: actor, source_head: 'source-head', snapshot_token: head, default_reference_hex: hex('refs/heads/main'),
  tip: tip(algorithm).split(':')[1], unborn: false, read_only: true, transaction_created: false, published: false, ...extra });
export const row = (name, algorithm = 'sha1', value = 'a') => ({ ref: name, ref_hex: hex(name), object_id: tip(algorithm, value).split(':')[1] });
export const page = (algorithm = 'sha1', extra = {}) => ({ ...metadata(algorithm), type: 'source_refs', namespace: 'branches',
  cursor_encoding: 'hex', source_head: 'source-head', snapshot_token: head, after: null, limit: 100, next_after: null,
  read_only: true, transaction_created: false, published: false, direct_refs_only: true,
  refs: [row('refs/heads/main', algorithm), row('refs/heads/topic', algorithm, 'b')], ...extra });
export function publication(pending, outcome = 'committed', extra = {}) {
  const { source, command } = pending;
  return { ...metadata(source.scope.format), type: 'default_branch_publication', operation: 'set-default',
    principal_id: source.principal, authentication: 'http-token', terminal: true, tx_id: 'tx-original', decision_sequence: 17,
    outcome, expected_default_reference_hex: command.expected_default_hex ?? null, default_reference_hex: command.reference_hex,
    expected_tip: command.expected_tip.split(':')[1], direct_refs_changed: false,
    head_changed_by_transaction: outcome === 'committed' && (command.expected_default_hex ?? null) !== command.reference_hex,
    ...(outcome === 'committed' ? { repository_commit_id: 'rcr-original' } : { code: 'expected_old_ref_mismatch', code_point: 7, refusal_record_id: 'refusal-original' }),
    ...extra };
}
export function outcome(pending, state = 'committed', extra = {}) {
  const terminal = ['committed', 'refused'].includes(state);
  return { schema_version: 1, type: 'transaction_outcome', tenant_id: pending.source.scope.tenant,
    repository_id: pending.source.scope.repository, repository_incarnation: pending.source.scope.incarnation,
    principal_id: pending.source.principal, selector: 'transaction', command_index: null, state, terminal,
    transaction: ['key_not_observed', 'seal_not_observed'].includes(state) ? null : { tx_id: 'tx-original', seal_id: 'seal-original',
      request_schema: 'default-branch-admission/v1.0', canonical_request_digest: { algorithm: 1, hex: 'e'.repeat(64) } },
    decision: terminal ? { kind: state, decision_sequence: 17, ...(state === 'committed' ? { repository_commit_id: 'rcr-original' }
      : { code: 'expected_old_ref_mismatch', code_point: 7, refusal_record_id: 'refusal-original' }) } : null,
    read_only: true, request_reexecuted: false, absence_proves_non_commit: false, session_completeness_established: false, ...extra };
}
export const json = (value, status = 200) => {
  const bytes = JSON.stringify(value);
  return new Response(bytes, { status, headers: { 'Content-Type': 'application/json', 'Content-Length': String(Buffer.byteLength(bytes)) } });
};
export function rig(options = {}) {
  const calls = [], responses = [];
  const client = new DefaultBranchClient({ href, cryptoImpl: webcrypto, ...options,
    fetchImpl: async (url, request) => {
      calls.push({ url: String(url), ...request });
      if (!responses.length) throw new Error('Unexpected HTTP request');
      const next = responses.shift();
      if (next instanceof Error) throw next;
      return typeof next === 'function' ? next(url, request) : next;
    } });
  async function ready(algorithm = 'sha1', read = observation(algorithm), refs = page(algorithm)) {
    await client.connect(token); responses.push(json(read), json(refs)); await client.load(); return client;
  }
  return { client, calls, responses, ready };
}
const html = readFileSync(new URL('../../crates/fgit-node/src/smart_http/server/browser/default-branch.html', import.meta.url), 'utf8');
export { html };
export class Element {
  constructor(tag) { this.tagName = tag.toUpperCase(); this.children = []; this.listeners = new Map(); this.value = ''; this.files = []; this.disabled = false; this.checked = false; this._text = ''; }
  set textContent(value) { this._text = String(value); this.children = []; }
  get textContent() { return this._text + this.children.map(child => child.textContent).join(''); }
  append(...children) { this.children.push(...children); }
  replaceChildren(...children) { this.children = children; this._text = ''; }
  addEventListener(type, callback) { this.listeners.set(type, callback); }
  async fire(type = 'click') { return this.listeners.get(type)?.({ preventDefault() {} }); }
}
export function view(options = {}) {
  const r = rig(options), elements = new Map([...html.matchAll(/\bid="([^"]+)"/g)].map(match => [match[1], new Element('control')]));
  const events = new Element('window'), doc = { getElementById: id => elements.get(id), createElement: tag => new Element(tag) };
  let saved = null;
  const app = mountDefaultBranch(doc, { client: r.client, events, saveReceipt: value => { saved = value; } });
  const get = id => elements.get(id);
  async function ready(algorithm = 'sha1', read = observation(algorithm), refs = page(algorithm)) {
    get('token').value = token; await get('connect').fire();
    r.responses.push(json(read), json(refs)); await get('load').fire();
    get('selected').value = hex('refs/heads/topic'); await get('selected').fire('change');
  }
  return { ...r, app, get, events, ready, saved: () => saved };
}
export function deferred() {
  let resolve, reject;
  const promise = new Promise((ok, no) => { resolve = ok; reject = no; });
  return { promise, resolve, reject };
}
