// Explicit minimal DOM/client peers. Not a real browser or native server.
import { readFileSync } from 'node:fs';
import { mountProtection } from '../../crates/fgit-node/src/smart_http/server/browser/protection-view.mjs';
const html = readFileSync(new URL('../../crates/fgit-node/src/smart_http/server/browser/protection.html', import.meta.url), 'utf8');
export const actor = '11'.repeat(16), reviewer = '22'.repeat(16), token = 'b1'.repeat(32);
export const hex = text => Buffer.from(text).toString('hex');
export const snapshot = () => ({ scope: { tenant: '33'.repeat(16), repository: '44'.repeat(16), incarnation: '55'.repeat(16), format: 'sha256' },
  head: `alg:1:${'aa'.repeat(32)}`, version: '9007199254740993', epoch: '18446744073709551614',
  policy: { administrators: [actor], branches: [{ reference_hex: hex('refs/heads/main'), required_reviewers: [reviewer] }] } });
class Element {
  constructor(tag) { this.tagName = tag; this.children = []; this.value = ''; this.disabled = false; this.checked = false; this.listeners = new Map(); this._text = ''; }
  set textContent(value) { this._text = String(value); this.children = []; }
  get textContent() { return this._text + this.children.map(child => child.textContent).join(''); }
  append(...children) { this.children.push(...children); }
  replaceChildren(...children) { this.children = children; this._text = ''; }
  addEventListener(type, callback) { this.listeners.set(type, callback); }
  async fire(type) { return this.listeners.get(type)?.({ preventDefault() {} }); }
}
export function harness(overrides = {}, providedClient = null) {
  const elements = new Map([...html.matchAll(/\bid="([^"]+)"/g)].map(match => [match[1], new Element('control')]));
  const events = new Element('window'), calls = [];
  const client = providedClient ?? { connected: false, busy: false, recoveryOnly: false, observed: null, pending: null,
    async connect(value, principal) { calls.push(['connect', value, principal]); this.connected = true; },
    async load() { calls.push(['load']); this.observed = snapshot(); return this.observed; },
    disconnect() { calls.push(['disconnect']); this.connected = false; this.observed = null; }, ...overrides };
  const doc = { getElementById: id => elements.get(id), createElement: tag => new Element(tag), defaultView: events };
  const mounted = mountProtection(doc, { client });
  const get = id => elements.get(`protection-${id}`);
  const connect = async (read = true) => { get('token').value = token; get('actor').value = actor; await get('connect').fire('submit'); if (read && client.connected) await mounted.inspect(); };
  return { get, doc, events, client, calls, mounted, connect };
}
export function deferred() { let resolve, reject; const promise = new Promise((a, b) => { resolve = a; reject = b; }); return { resolve, reject, promise }; }

