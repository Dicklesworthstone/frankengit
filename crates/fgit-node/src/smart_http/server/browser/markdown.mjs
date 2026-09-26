// Presentation-only consumer of fgit-doc's html_safe output, not another
// Markdown parser. Construct an allowlisted DOM without giving a markup string
// to the browser's HTML parser. Canonical source remains available separately.
// Source hashing detects mismatched presentations; it is not an independent
// proof that a server applied the Markdown parser correctly.
export const MARKDOWN_LIMITS = Object.freeze({ sourceBytes: 64 * 1024, htmlBytes: 512 * 1024, nodes: 20_000, depth: 128 });
const encoder = new TextEncoder();
const ordinary = new Set(['p', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'blockquote', 'ul', 'li', 'em', 'strong']);
const special = new Set(['ol', 'pre', 'code', 'a', 'span', 'br', 'hr', 'img']);
const voidTags = new Set(['br', 'hr', 'img']);
const controls = /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069]/gu;
const visible = text => text.replace(controls, c => `\\u{${c.codePointAt(0).toString(16)}}`);
const refuse = reason => { throw new Error(reason); };
const digestText = value => typeof value === 'string' && /^[0-9a-f]{64}$/.test(value);
function bounded(value, maximum) {
  if (typeof value !== 'string' || value.length > maximum || /[\uD800-\uDFFF]/u.test(value) || encoder.encode(value).length > maximum) refuse('presentation_limit');
  return value;
}
function plain(doc, tag, text) { const node = doc.createElement(tag); node.textContent = visible(text); return node; }
function unescape(text) {
  // Decode exactly one layer of the five escapes emitted by fgit-doc.
  // Numeric/entity spellings outside this profile are rejected, not guessed.
  const values = { '&amp;': '&', '&lt;': '<', '&gt;': '>', '&quot;': '"', '&#x27;': "'" };
  return text.replace(/&(?:amp;|lt;|gt;|quot;|#x27;)?/g, entity => values[entity] ?? refuse('unsupported_entity'));
}
function attributes(text) {
  const result = new Map(), pattern = / ([a-z][a-z0-9-]*)="([^"<>]*)"/gy;
  let position = 0;
  while (position < text.length) {
    pattern.lastIndex = position;
    const match = pattern.exec(text);
    if (!match || result.has(match[1]) || result.size >= 4) refuse('unsupported_attribute');
    result.set(match[1], unescape(match[2])); position = pattern.lastIndex;
  }
  return result;
}
function allowedAttributes(attrs, names) {
  if ([...attrs.keys()].some(name => !names.includes(name))) refuse('unsupported_attribute');
}
function safeLink(value) {
  bounded(value, 4096);
  if (!value || /[\s\\\u0000-\u001f\u007f-\u009f\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069]/u.test(value) || value.startsWith('//')) refuse('unsafe_link');
  // A fixed base is used solely to classify relative references, never for a
  // fetch or to rewrite a link to another origin. The original href is kept.
  const parsed = new URL(value, 'https://frankengit.invalid/');
  if (!['https:', 'http:', 'mailto:'].includes(parsed.protocol) || parsed.username || parsed.password) refuse('unsafe_link');
  return value;
}
function decorate(node, tag, attrs) {
  if (ordinary.has(tag) || ['br', 'hr'].includes(tag)) allowedAttributes(attrs, []);
  else if (tag === 'a') {
    allowedAttributes(attrs, ['href', 'title', 'rel']);
    if (attrs.get('rel') !== 'nofollow noopener noreferrer') refuse('unsupported_link_relationship');
    node.setAttribute('href', safeLink(attrs.get('href')));
    node.setAttribute('rel', 'nofollow noopener noreferrer');
    if (attrs.has('title')) node.setAttribute('title', visible(bounded(attrs.get('title'), 4096)));
  } else if (tag === 'ol') {
    allowedAttributes(attrs, ['start']);
    if (attrs.has('start')) {
      const start = attrs.get('start');
      if (!/^[0-9]{1,10}$/.test(start) || Number(start) > 0xffffffff) refuse('unsupported_list_start');
      node.setAttribute('start', start);
    }
  } else if (tag === 'code') {
    allowedAttributes(attrs, ['class']);
    if (attrs.has('class')) {
      const name = attrs.get('class');
      if (!/^language-[A-Za-z0-9_+.\-]{1,128}$/.test(name)) refuse('unsupported_code_class');
      node.setAttribute('class', name);
    }
  } else if (tag === 'pre' || tag === 'span') {
    allowedAttributes(attrs, tag === 'pre' ? ['data-fgit-doc-rejected'] : ['data-fgit-doc-rejected', 'data-fgit-doc-neutralised']);
    for (const [name, value] of attrs) {
      if (!/^[a-z_]{1,64}$/.test(value)) refuse('unsupported_neutralisation_marker');
      node.setAttribute(name, value);
    }
  }
}

// Bounded decoding of the native renderer's small HTML vocabulary. All nodes
// remain detached until every token, closing tag and ceiling has been checked.
export function presentationDom(doc, html) {
  bounded(html, MARKDOWN_LIMITS.htmlBytes);
  const root = doc.createDocumentFragment(), stack = [{ tag: null, node: root }];
  let offset = 0, count = 0;
  const charge = () => { if (++count > MARKDOWN_LIMITS.nodes) refuse('presentation_node_limit'); };
  while (offset < html.length) {
    charge();
    if (html[offset] !== '<') {
      let end = html.indexOf('<', offset); if (end < 0) end = html.length;
      stack.at(-1).node.append(doc.createTextNode(visible(unescape(html.slice(offset, end)))));
      offset = end; continue;
    }
    const end = html.indexOf('>', offset + 1);
    if (end < 0) refuse('incomplete_presentation');
    const token = html.slice(offset + 1, end); offset = end + 1;
    // Bound the tag name before examining attributes. A combined greedy
    // name/tail regexp could backtrack quadratically on a long hostile name.
    const closing = token[0] === '/', start = closing ? 1 : 0;
    let cursor = start;
    while (cursor < token.length && /[a-z0-9]/.test(token[cursor])) {
      if (cursor - start >= 10) refuse('unsupported_element');
      cursor += 1;
    }
    const tag = token.slice(start, cursor);
    if (!ordinary.has(tag) && !special.has(tag)) refuse('unsupported_element');
    let tail = token.slice(cursor);
    const selfClosing = tail.endsWith(' /');
    if (selfClosing) tail = tail.slice(0, -2);
    if (closing) {
      if (tail || selfClosing || stack.length === 1 || stack.at(-1).tag !== tag) refuse('unbalanced_presentation');
      stack.pop(); continue;
    }
    if (Boolean(selfClosing) !== voidTags.has(tag)) refuse('invalid_void_element');
    if (!selfClosing && stack.length > MARKDOWN_LIMITS.depth) refuse('presentation_depth_limit');
    const attrs = attributes(tail);
    if (tag === 'img') {
      // Never issue remote asset requests from repository prose. Keep useful
      // alternative text while making this deliberately narrower profile clear.
      allowedAttributes(attrs, ['src', 'alt', 'title']);
      safeLink(attrs.get('src'));
      const alt = bounded(attrs.get('alt'), MARKDOWN_LIMITS.sourceBytes);
      const node = plain(doc, 'span', `[Image not loaded: ${alt}]`);
      node.setAttribute('data-fgit-doc-neutralised', 'remote_image');
      stack.at(-1).node.append(node); continue;
    }
    const node = doc.createElement(tag); decorate(node, tag, attrs);
    stack.at(-1).node.append(node);
    if (!selfClosing) stack.push({ tag, node });
  }
  if (stack.length !== 1) refuse('incomplete_presentation');
  return root;
}

// The caller has already authenticated and selected one native record. A
// generation guard prevents a delayed digest from reviving an old selection.
// Missing/unsupported presentation or crypto leaves raw Markdown readable.
export function markdownBody(doc, source, presentation, { cryptoImpl = globalThis.crypto, current = () => true } = {}) {
  bounded(source, MARKDOWN_LIMITS.sourceBytes);
  const element = doc.createElement('section'), note = plain(doc, 'p', 'Raw Markdown; checking the optional rendered presentation.');
  const preview = doc.createElement('div'), raw = doc.createElement('details'); raw.open = true;
  raw.append(plain(doc, 'summary', 'Raw Markdown'), plain(doc, 'pre', source));
  element.append(note, preview, raw);
  const ready = Promise.resolve().then(async () => {
    if (!current()) return false;
    if (!presentation || typeof presentation !== 'object' || Array.isArray(presentation)) refuse('presentation_missing');
    const { renderer, profile, source_sha256, parse_profile_sha256, html, refusal } = presentation;
    if (renderer !== 'fgit-doc' || profile !== 'html_safe' || !digestText(source_sha256) || !digestText(parse_profile_sha256)) refuse('unsupported_presentation');
    if (html === null) refuse(typeof refusal === 'string' && /^[a-z_]{1,64}$/.test(refusal) ? refusal : 'rendering_refused');
    bounded(html, MARKDOWN_LIMITS.htmlBytes);
    if (!cryptoImpl?.subtle?.digest) refuse('source_check_unavailable');
    const bytes = new Uint8Array(await cryptoImpl.subtle.digest('SHA-256', encoder.encode(source)));
    if (!current()) return false;
    if (Array.from(bytes, byte => byte.toString(16).padStart(2, '0')).join('') !== source_sha256) refuse('source_mismatch');
    const content = presentationDom(doc, html);
    if (!current()) return false;
    preview.replaceChildren(content); raw.open = false;
    note.textContent = `Derived Markdown · fgit-doc html_safe · source SHA-256 ${source_sha256} · profile ${parse_profile_sha256}. Raw source remains available; this is not review or merge evidence.`;
    return true;
  }).catch(error => {
    if (current()) {
      preview.replaceChildren(); raw.open = true;
      // Error messages from crypto, URL or DOM implementations are not copied
      // into the UI: they can contain source text or environment details.
      const reason = typeof error?.message === 'string' && /^[a-z_]{1,64}$/.test(error.message)
        ? error.message : 'presentation_unavailable';
      note.textContent = `Rendered presentation unavailable (${reason}); showing raw Markdown.`;
    }
    return false;
  });
  return { element, ready };
}
