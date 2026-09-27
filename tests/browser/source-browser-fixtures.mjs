// Native JSON shape from smart_http/server/source/output.rs. The transport and
// DOM below are injected test seams, not a live fg server or browser engine.
import { createHash, webcrypto } from 'node:crypto';
export { webcrypto };
export const PAGE = 65536;
export const hex = bytes => Buffer.from(bytes).toString('hex');
export function fixture(format = 'sha1', bytes = Buffer.from('source\n'), kind = 'file', path = Buffer.from('file.txt')) {
  const oid = createHash(format).update(`blob ${bytes.length}\0`).update(bytes).digest('hex');
  const width = format === 'sha1' ? 40 : 64;
  const selected = { reference: 'refs/heads/main', format };
  const common = { schema_version: 1, tenant_id: '01'.repeat(16), repository_id: '02'.repeat(16),
    repository_incarnation: '03'.repeat(16), object_format: format, ref: selected.reference, ref_hex: hex(Buffer.from(selected.reference)),
    source_head: 'source-head', snapshot_token: `alg:2:${'a'.repeat(64)}`, source_rcr: 'source-rcr',
    source_commit: 'b'.repeat(width), root_tree: 'c'.repeat(width), read_only: true, transaction_created: false, published: false };
  const blob = (offset = 0) => {
    const content = bytes.subarray(offset, offset + PAGE), end = offset + content.length;
    return { ...common, type: 'source_blob', object_id: `${format}:${oid}`, path_hex: hex(path), kind,
      total_bytes: bytes.length, offset, returned_bytes: content.length, next_offset: end < bytes.length ? end : null,
      content_hex: hex(content), symlink_followed: false };
  };
  const tree = () => ({ ...common, type: 'source_tree', object_id: common.root_tree, path_hex: null,
    after_hex: null, limit: 100, next_after_hex: null, entries: [{ name_hex: hex(path), object_id: oid, kind }] });
  return { format, bytes: Uint8Array.from(bytes), path: hex(path), selected, common, oid, blob, tree };
}
export function response(value, extra = {}) {
  const text = JSON.stringify(value);
  return new Response(text, { status: 200, headers: { 'Content-Type': 'application/json', 'Content-Length': String(Buffer.byteLength(text)) }, ...extra });
}
class Element {
  constructor(tag, owner) { this.tagName = tag.toUpperCase(); this.owner = owner; }
  children = []; events = new Map(); value = ''; disabled = false; _text = ''; parent = null;
  set textContent(text) { this._text = String(text); this.children = []; }
  get textContent() { return this._text + this.children.map(c => c.textContent).join(''); }
  set innerHTML(_) { throw new Error('Markup sink used'); }
  append(...children) { for (const child of children) { child.parent = this; this.children.push(child); } }
  replaceChildren(...children) { this._text = ''; this.children = []; this.append(...children); }
  addEventListener(event, fn) { const fns = this.events.get(event) ?? []; fns.push(fn); this.events.set(event, fns); }
  emit(event) { for (const fn of this.events.get(event) ?? []) fn({ preventDefault() {} }); }
  click() { if (this.disabled) return; if (this.tagName === 'A') this.owner.downloads.push({ href: this.href, filename: this.download }); this.emit('click'); }
  remove() { if (this.parent) this.parent.children = this.parent.children.filter(c => c !== this); }
  setAttribute(name, value) { this[name] = value; }
  all() { return this.children.flatMap(c => [c, ...c.all()]); }
}
export function dom() {
  const nodes = new Map();
  const document = { downloads: [], createElement: tag => new Element(tag, document), getElementById: id => nodes.get(id) ?? null };
  document.defaultView = new Element('window', document);
  for (const id of ['connection', 'token', 'reference', 'format', 'disconnect', 'cancel-read', 'search', 'needle', 'search-case', 'status', 'snapshot', 'breadcrumbs', 'content', 'paging']) {
    const node = document.createElement('div'); node.id = id; nodes.set(id, node);
  }
  const get = id => nodes.get(id);
  get('reference').value = 'refs/heads/main'; get('format').value = 'sha1'; get('search-case').value = 'exact';
  const urls = new Map(), revoked = []; let next = 0;
  const urlApi = { createObjectURL(blob) { const url = `blob:source-fixture-${++next}`; urls.set(url, blob); return url; },
    revokeObjectURL(url) { revoked.push(url); urls.delete(url); } };
  return { document, get, urls, revoked, urlApi, buttons: id => get(id).all().filter(n => n.tagName === 'BUTTON') };
}
export const location = new URL('http://127.0.0.1/repo.git/ui/');
export async function waitFor(check) {
  const until = performance.now() + 2000;
  while (!check()) { if (performance.now() > until) throw new Error('Test observation timed out'); await new Promise(r => setTimeout(r, 2)); }
}
export function queuedFetch(items, calls = []) {
  return async (url, init) => {
    calls.push({ url: String(url), init, fields: new URLSearchParams(init.body) });
    if (!items.length) throw new Error('Unexpected request');
    const item = items.shift();
    return typeof item === 'function' ? item(url, init) : response(item);
  };
}
