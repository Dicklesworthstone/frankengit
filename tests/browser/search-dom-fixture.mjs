// Minimal DOM/event oracle, not a browser-rendering or accessibility engine.
import { readFileSync } from 'node:fs';
class Events {
  listeners = new Map();
  addEventListener(name, fn) { const list = this.listeners.get(name) ?? []; list.push(fn); this.listeners.set(name, list); }
  emit(name) {
    const event = { type: name, defaultPrevented: false, preventDefault() { this.defaultPrevented = true; } };
    for (const fn of this.listeners.get(name) ?? []) fn(event);
    return event;
  }
}
export class Element extends Events {
  constructor(tag, owner) { super(); this.tagName = tag.toUpperCase(); this.owner = owner; }
  children = []; parent = null; value = ''; disabled = false; hidden = false; attributes = {}; _text = '';
  set textContent(value) { this._text = String(value); this.children = []; }
  get textContent() { return this._text + this.children.map(c => c.textContent).join(''); }
  set innerHTML(_) { throw new Error('Repository bytes must not be interpreted as markup'); }
  append(...children) { for (const child of children) { child.parent = this; this.children.push(child); } }
  replaceChildren(...children) { this._text = ''; for (const child of this.children) child.parent = null; this.children = []; this.append(...children); }
  setAttribute(name, value) { this.attributes[name] = value; }
  focus() { this.owner.focused = this; }
  remove() { if (this.parent) this.parent.children = this.parent.children.filter(c => c !== this); this.parent = null; }
  click() {
    if (this.disabled) return;
    if (this.tagName === 'A') this.owner.downloads.push({ href: this.href, download: this.download });
    this.emit('click');
  }
  descendants() { return this.children.flatMap(c => [c, ...c.descendants()]); }
}
export function dom() {
  const html = readFileSync(new URL('../../crates/fgit-node/src/smart_http/server/browser/search.html', import.meta.url), 'utf8');
  const elements = new Map();
  const document = { defaultView: new Events(), downloads: [], focused: null,
    createElement(tag) { return new Element(tag, document); },
    getElementById(id) { const el = elements.get(id); if (!el) throw new Error(`Missing HTML element ${id}`); return el; } };
  for (const match of html.matchAll(/<(\w+)[^>]*\bid="([^"]+)"[^>]*>/g)) {
    const el = document.createElement(match[1]); el.id = match[2]; elements.set(el.id, el);
    el.value = match[0].match(/\bvalue="([^"]*)"/)?.[1] ?? '';
    el.disabled = /\bdisabled\b/.test(match[0]); el.hidden = /\bhidden\b/.test(match[0]);
  }
  for (const [id, value] of Object.entries({ mode: 'literal', encoding: 'utf8', format: 'sha1', case: 'exact', 'prefix-encoding': 'utf8', 'index-source-mode': 'exact', 'symbol-match': 'exact', 'symbol-kind': 'all' })) document.getElementById(id).value = value;
  const urls = new Map(), revoked = [];
  const urlApi = { createObjectURL(blob) { const url = `blob:fixture-${urls.size + revoked.length}`; urls.set(url, blob); return url; },
    revokeObjectURL(url) { revoked.push(url); urls.delete(url); } };
  return { document, html, get: id => document.getElementById(id), urlApi, urls, revoked,
    buttons: id => document.getElementById(id).descendants().filter(c => c.tagName === 'BUTTON') };
}
export const tick = () => new Promise(resolve => setTimeout(resolve, 5));
