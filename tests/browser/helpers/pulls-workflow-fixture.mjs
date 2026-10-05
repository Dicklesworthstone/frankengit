// Client/view unit-test boundary only. Production modules and WebCrypto are real;
// the DOM and HTTP replies are controlled, not evidence of native admission.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { setImmediate } from 'node:timers/promises';
import { webcrypto } from 'node:crypto';
import { mountPulls } from '../../../crates/fgit-node/src/smart_http/server/browser/pulls-view.mjs';

export const token = 'f'.repeat(64);
export const sourceRoot = new URL('../../../crates/fgit-node/src/smart_http/server/browser/', import.meta.url);
const encode = value => Buffer.from(value).toString('hex');
export function observation(format = 'sha1', number = 7) {
  const width = format === 'sha1' ? 40 : 64;
  const data = { object_format: format, source_ref: 'refs/heads/topic+one', target_ref: 'refs/heads/main',
    source_ref_hex: encode('refs/heads/topic+one'), target_ref_hex: encode('refs/heads/main'),
    source_tip: `${format}:${'a'.repeat(width)}`, target_tip: `${format}:${'b'.repeat(width)}`,
    title: 'Native merge', body: '<script>not authority</script>', body_rendered: null };
  const binding = { tenant: '11'.repeat(16), repository: '22'.repeat(16), incarnation: '33'.repeat(16), format };
  const head = `alg:2:${'4'.repeat(64)}`;
  const reply = { schema_version: 1, type: 'pull_request', tenant_id: binding.tenant, repository_id: binding.repository,
    repository_incarnation: binding.incarnation, object_format: format, source_head: 'authenticated-head', snapshot_token: head,
    number, found: true, pull_request: { number, version: 3, state: 'open', merge_only: false,
      opened_by: '55'.repeat(16), last_metadata_actor: '55'.repeat(16), data, merge: null } };
  return { head, binding, reply };
}
export function terminal(observed, fields, outcome = 'committed') {
  const { reply } = observed;
  return { schema_version: 1, type: 'fast_forward_merge_publication', tenant_id: reply.tenant_id,
    repository_id: reply.repository_id, repository_incarnation: reply.repository_incarnation, object_format: reply.object_format,
    number: reply.number, action: 'fast-forward', pull_request_version: Number(fields.pull_request_version),
    ...Object.fromEntries(['source', 'target'].flatMap(side => [[`${side}_ref`, fields[`${side}_ref`]],
      [`${side}_ref_hex`, encode(fields[`${side}_ref`])], [`${side}_tip`, fields[`${side}_tip`]]])),
    principal_id: '66'.repeat(16), tx_id: 'native-transaction', decision_sequence: 4, outcome,
    repository_commit_id: outcome === 'committed' ? 'native-rcr' : null,
    refusal_record_id: outcome === 'refused' ? 'native-refusal' : null,
    refusal_code: outcome === 'refused' ? 'PublicationPolicyRefused' : null,
    refusal_code_point: outcome === 'refused' ? 1 : null, delivery_acknowledged: null };
}
export function missingOutcome(observed) {
  const { reply } = observed;
  return { schema_version: 1, type: 'transaction_outcome', selector: 'transaction', command_index: null,
    tenant_id: reply.tenant_id, repository_id: reply.repository_id, repository_incarnation: reply.repository_incarnation,
    principal_id: '66'.repeat(16), read_only: true, request_reexecuted: false, absence_proves_non_commit: false,
    session_completeness_established: false, state: 'key_not_observed', terminal: false, transaction: null, decision: null };
}
export function response(body, status = 200) {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });
}
export class Element extends EventTarget {
  constructor(tag, id = '') { super(); this.tagName = tag.toUpperCase(); this.id = id; this.children = []; this.parentNode = null;
    this.value = ''; this.checked = false; this.disabled = false; this.hidden = false; this.attributes = {}; this.ownText = ''; }
  set textContent(value) { this.replaceChildren(); this.ownText = String(value); }
  get textContent() { return this.ownText + this.children.map(child => child.textContent).join(''); }
  append(...children) { for (const child of children) { child.remove(); child.parentNode = this; this.children.push(child); } }
  replaceChildren(...children) { for (const child of this.children) child.parentNode = null; this.children = []; this.ownText = ''; this.append(...children); }
  remove() { if (this.parentNode) { const parent = this.parentNode; parent.children = parent.children.filter(child => child !== this); this.parentNode = null; } }
  setAttribute(name, value) { this.attributes[name] = value; }
  click() { if (!this.disabled) this.dispatchEvent(new Event('click', { cancelable: true })); }
  focus() {}
  closest(tag) { for (let el = this; el; el = el.parentNode) if (el.tagName === tag.toUpperCase()) return el; return null; }
}
export function fakeDocument() {
  const body = new Element('body'), view = new EventTarget();
  view.location = { href: 'http://127.0.0.1/repository/ui/pulls/' };
  const find = (el, id) => el.id === id ? el : el.children.map(child => find(child, id)).find(Boolean) ?? null;
  // The actual template defines which required controls exist; never silently
  // invent an unknown getElementById result. Real-browser coverage is separate.
  const html = readFileSync(new URL('pulls.html', sourceRoot), 'utf8');
  for (const match of html.matchAll(/<([a-z0-9]+)\b[^>]*\bid="([^"]+)"/g)) {
    if (match[1] === 'body') { body.id = match[2]; continue; }
    assert.equal(find(body, match[2]), null, `duplicate template ID ${match[2]}`);
    body.append(new Element(match[1], match[2]));
  }
  return { body, defaultView: view, getElementById: id => find(body, id), createElement: tag => new Element(tag),
    createTextNode: text => { const node = new Element('text'); node.textContent = text; return node; },
    createDocumentFragment: () => new Element('fragment') };
}
export async function until(predicate, message = 'operation settled') {
  const deadline = performance.now() + 3000;
  while (!predicate()) { assert.ok(performance.now() < deadline, message); await setImmediate(); }
}
export async function fixture({ observed = observation(), dispatch = null, recover = null } = {}) {
  const doc = fakeDocument(), calls = [], downloads = [];
  const fetchImpl = async (url, options) => {
    const call = { url: String(url), ...options, bytes: options.body === undefined ? null
      : typeof options.body === 'string' ? options.body : await options.body.text() };
    calls.push(call);
    if (url.pathname.endsWith('/outcomes')) return recover ? recover(call) : response(missingOutcome(observed));
    if (url.pathname.endsWith('/fast-forward')) return dispatch ? dispatch(call)
      : response(terminal(observed, Object.fromEntries(new URLSearchParams(call.bytes))));
    if (url.pathname.endsWith('/pulls')) return response({ ...observed.reply, type: 'pull_request_page', after: 0, limit: 20,
      pull_requests: [observed.reply.pull_request], next_after: null });
    if (/\/pulls\/[1-9][0-9]*$/.test(url.pathname)) return response(observed.reply, observed.reply.found ? 200 : 404);
    throw new Error(`Unexpected API request ${url}`);
  };
  const mounted = mountPulls(doc, { fetchImpl, cryptoImpl: webcrypto, downloadImpl: (name, text) => downloads.push({ name, text }) });
  await mounted.client.connect(token); await mounted.loadPr(observed.reply.number);
  const node = id => { const el = doc.getElementById(id); assert.ok(el, `missing control ${id}`); return el; };
  const submit = id => node(id).dispatchEvent(new Event('submit', { cancelable: true }));
  const click = id => node(id).click();
  const stage = async () => { click('fast-forward-stage'); await until(() => mounted.client.pending && !mounted.client.busy); };
  const send = async () => {
    node('confirm').checked = true; node('confirm').dispatchEvent(new Event('change')); click('send');
    await until(() => !mounted.client.busy && !node('status').textContent.startsWith('Fast-forward request prepared'));
  };
  return { ...mounted, doc, node, click, submit, stage, send, calls, downloads, observed };
}
