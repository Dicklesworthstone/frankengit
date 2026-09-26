// Executes the production presentation consumer with a minimal observable DOM,
// not a browser or native-node E2E claim. Crypto is Node's real WebCrypto.
import test from 'node:test';
import assert from 'node:assert/strict';
import { webcrypto } from 'node:crypto';
import { markdownBody, presentationDom, MARKDOWN_LIMITS } from '../src/smart_http/server/browser/markdown.mjs';

class Node {
  constructor(tag, text = '') { this.tag = tag; this.value = text; this.children = []; this.attrs = {}; this.open = false; }
  set textContent(text) { this.value = String(text); this.children = []; }
  get textContent() { return this.value + this.children.map(node => node.textContent).join(''); }
  append(...nodes) {
    for (const node of nodes) {
      assert.ok(node instanceof Node, 'only DOM nodes are appended');
      if (node.tag === '#fragment') this.children.push(...node.children);
      else this.children.push(node);
    }
  }
  replaceChildren(...nodes) { this.children = []; this.value = ''; this.append(...nodes); }
  setAttribute(name, value) {
    assert.ok(!/^on/i.test(name), 'event handlers never reach the DOM');
    assert.ok(!['src', 'style', 'srcdoc'].includes(name), 'automatic effects never reach the DOM');
    this.attrs[name] = value;
  }
}
const doc = {
  createElement(tag) {
    assert.ok(!['script', 'img', 'style', 'iframe', 'object', 'svg', 'math', 'form', 'input'].includes(tag), `active element ${tag}`);
    return new Node(tag);
  },
  createTextNode(text) { return new Node('#text', text); },
  createDocumentFragment() { return new Node('#fragment'); },
};
const find = (node, tag) => [node, ...node.children.flatMap(child => find(child, tag))].filter(child => child.tag === tag);
async function presentation(source, html) {
  const digest = await webcrypto.subtle.digest('SHA-256', new TextEncoder().encode(source));
  return { renderer: 'fgit-doc', profile: 'html_safe', source_sha256: Buffer.from(digest).toString('hex'), parse_profile_sha256: 'ab'.repeat(32), html };
}
async function render(source, html, options = {}) {
  const record = await presentation(source, html);
  const result = markdownBody(doc, source, record, { cryptoImpl: webcrypto, ...options });
  const accepted = await result.ready;
  return { ...result, accepted, record };
}
function preview(result) { return result.element.children[1]; }
function raw(result) { return result.element.children[2]; }

// These are literal examples of the fgit-doc html_safe vocabulary, not output
// observed from executing a Rust renderer in this test environment.
test('headings, paragraphs, emphasis, code and lists become structured DOM', () => {
  const tree = presentationDom(doc, '<h1>Review</h1>\n<p>A <em>small</em> <strong>change</strong>.</p>\n' +
    '<blockquote>\n<ul>\n<li><code>x</code></li>\n</ul>\n</blockquote>\n<ol start="3">\n<li>third</li>\n</ol>\n<hr />\n<br />\n');
  for (const tag of ['h1', 'p', 'em', 'strong', 'blockquote', 'ul', 'li', 'code', 'ol', 'hr', 'br']) assert.ok(find(tree, tag).length, tag);
  assert.equal(find(tree, 'ol')[0].attrs.start, '3');
  assert.equal(find(tree, 'strong')[0].textContent, 'change');
});

test('native escapes decode once into text, never markup', () => {
  const tree = presentationDom(doc, '<pre data-fgit-doc-rejected="raw_markup"><code>&lt;script&gt;&amp;lt;script&amp;gt;&quot;&#x27;</code></pre>\n');
  assert.equal(find(tree, 'code')[0].textContent, '<script>&lt;script&gt;"\'');
  assert.equal(find(tree, 'script').length, 0);
  assert.equal(find(tree, 'pre')[0].attrs['data-fgit-doc-rejected'], 'raw_markup');
  assert.throws(() => presentationDom(doc, '<p>&#x3c;script&gt;</p>'), /unsupported_entity/);
});

test('safe links retain their target and fixed relationship without following them', () => {
  for (const target of ['https://example.invalid/read?q=a&amp;b=c', 'http://127.0.0.1/read', '/docs/readme', '../guide.md', '#section', 'mailto:review@example.invalid']) {
    const tree = presentationDom(doc, `<p><a href="${target}" title="Review &amp; discuss" rel="nofollow noopener noreferrer">guide</a></p>`);
    assert.equal(find(tree, 'a')[0].attrs.href, target.replace('&amp;', '&'));
    assert.equal(find(tree, 'a')[0].attrs.rel, 'nofollow noopener noreferrer');
    assert.equal(find(tree, 'a')[0].attrs.title, 'Review & discuss');
  }
});

test('unsafe schemes, credentials and ambiguous network paths are refused', () => {
  for (const target of ['javascript:alert(1)', 'data:text/html,x', 'file:///etc/passwd', '//remote.invalid/x', '\\remote.invalid/x',
    'https://user:secret@remote.invalid/', 'java&#x73;cript:alert(1)', 'javascript&colon;alert(1)', 'https://example.invalid/\u202e']) {
    assert.throws(() => presentationDom(doc, `<a href="${target}" rel="nofollow noopener noreferrer">x</a>`), target);
  }
  assert.throws(() => presentationDom(doc, '<a href="https://example.invalid/" rel="opener">x</a>'));
});

test('images are visible placeholders and never create an image or set src', () => {
  const tree = presentationDom(doc, '<p><img src="https://tracking.invalid/pixel" alt="Build &amp; diagram" /></p>');
  assert.equal(find(tree, 'img').length, 0);
  const placeholder = find(tree, 'span')[0];
  assert.equal(placeholder.textContent, '[Image not loaded: Build & diagram]');
  assert.equal(placeholder.attrs['data-fgit-doc-neutralised'], 'remote_image');
});

test('active elements and attributes cannot get through with safe-looking neighbours', () => {
  for (const planted of ['<script>x</script>', '<svg></svg>', '<math></math>', '<iframe></iframe>', '<style>p{display:none}</style>',
    '<form></form>', '<p onclick="x">text</p>', '<a href="https://example.invalid/" rel="nofollow noopener noreferrer" target="_blank">x</a>',
    '<code class="language-rust" style="display:none">x</code>', '<span id="selected">x</span>', '<!--comment-->']) {
    assert.throws(() => presentationDom(doc, `<p>before</p>${planted}<p>after</p>`), planted);
  }
  assert.equal(presentationDom(doc, '<p>before</p><code class="language-rust">x</code><p>after</p>').textContent, 'beforexafter');
});

test('truncated, misnested and duplicate-attribute presentations fail as a whole', () => {
  for (const html of ['<p>', '<p>x</em>', '<p><em>x</p></em>', '</p>', '<p/>', '<br>', '<br /></br>', '<p>x', '<p>&unknown;</p>',
    '<ol start="1" start="2"><li>x</li></ol>', '<p data-fgit-doc-rejected="x">x</p>', '<code class="language-rust\" bad=\"1">x</code>']) {
    assert.throws(() => presentationDom(doc, html), html);
  }
});

test('source and profile labels are checked and the raw source remains inspectable', async () => {
  const result = await render('**hello**', '<p><strong>hello</strong></p>\n');
  assert.equal(result.accepted, true);
  assert.equal(find(preview(result), 'strong')[0].textContent, 'hello');
  assert.equal(raw(result).open, false);
  assert.equal(find(raw(result), 'pre')[0].textContent, '**hello**');
  assert.ok(result.element.children[0].textContent.includes(result.record.source_sha256));
  assert.ok(result.element.children[0].textContent.includes(result.record.parse_profile_sha256));
  assert.ok(result.element.children[0].textContent.includes('not review or merge evidence'));
});

test('a source mismatch falls back without selecting even otherwise safe HTML', async () => {
  const record = await presentation('old source', '<p>old rendered text</p>');
  const result = markdownBody(doc, 'new source', record, { cryptoImpl: webcrypto });
  assert.equal(await result.ready, false);
  assert.equal(preview(result).children.length, 0);
  assert.equal(raw(result).open, true);
  assert.equal(find(raw(result), 'pre')[0].textContent, 'new source');
  assert.match(result.element.children[0].textContent, /source_mismatch/);
});

test('missing presentation, unknown profiles and native refusals preserve raw text', async () => {
  const valid = await presentation('source', '<p>source</p>');
  for (const record of [null, {}, { ...valid, profile: 'unsafe' }, { ...valid, renderer: 'other' }, { ...valid, parse_profile_sha256: 'bad' },
    { ...valid, source_sha256: 'AB'.repeat(32) }, { ...valid, html: null, refusal: 'nesting_limit' }]) {
    const result = markdownBody(doc, 'source', record, { cryptoImpl: webcrypto });
    assert.equal(await result.ready, false);
    assert.equal(preview(result).children.length, 0);
    assert.equal(raw(result).open, true);
    assert.equal(find(raw(result), 'pre')[0].textContent, 'source');
  }
});

test('unavailable or failing crypto never promotes unbound markup or leaks error text', async () => {
  for (const cryptoImpl of [{}, { subtle: { digest: async () => { throw new Error('secret environment details'); } } }]) {
    const result = await render('source', '<p>source</p>', { cryptoImpl });
    assert.equal(result.accepted, false);
    assert.equal(preview(result).children.length, 0);
    assert.ok(!result.element.textContent.includes('secret environment'));
  }
});

test('a disconnected or superseded selection cannot be resurrected by a late digest', async () => {
  const record = await presentation('private source', '<p>private source</p>');
  let finish, active = true, started = false;
  const cryptoImpl = { subtle: { digest: () => { started = true; return new Promise(resolve => { finish = resolve; }); } } };
  const result = markdownBody(doc, 'private source', record, { cryptoImpl, current: () => active });
  await Promise.resolve(); assert.equal(started, true);
  active = false;
  finish(Buffer.from(record.source_sha256, 'hex'));
  assert.equal(await result.ready, false);
  assert.equal(preview(result).children.length, 0);
  let called = false;
  const stopped = markdownBody(doc, 'source', record, {
    current: () => false, cryptoImpl: { subtle: { digest: () => { called = true; } } },
  });
  assert.equal(await stopped.ready, false); assert.equal(called, false);
});

test('presentation byte and node limits refuse excess work with accepted boundary twins', () => {
  assert.equal(presentationDom(doc, 'x'.repeat(MARKDOWN_LIMITS.htmlBytes)).textContent.length, MARKDOWN_LIMITS.htmlBytes);
  assert.throws(() => presentationDom(doc, 'x'.repeat(MARKDOWN_LIMITS.htmlBytes + 1)), /presentation_limit/);
  assert.equal(find(presentationDom(doc, '<br />'.repeat(MARKDOWN_LIMITS.nodes)), 'br').length, MARKDOWN_LIMITS.nodes);
  assert.throws(() => presentationDom(doc, '<br />'.repeat(MARKDOWN_LIMITS.nodes + 1)), /presentation_node_limit/);
});

test('nesting limits are checked before creating the excessive subtree', () => {
  const nested = count => '<blockquote>'.repeat(count) + 'text' + '</blockquote>'.repeat(count);
  assert.equal(presentationDom(doc, nested(MARKDOWN_LIMITS.depth)).textContent, 'text');
  assert.throws(() => presentationDom(doc, nested(MARKDOWN_LIMITS.depth + 1)), /presentation_depth_limit/);
});

test('Unicode controls are visible and surrogate corruption is refused', () => {
  assert.match(presentationDom(doc, '<p>text\u202esecret</p>').textContent, /\\u\{202e\}/);
  assert.throws(() => presentationDom(doc, '<p>\ud800</p>'), /presentation_limit/);
  assert.throws(() => markdownBody(doc, 'x'.repeat(MARKDOWN_LIMITS.sourceBytes + 1), null), /presentation_limit/);
});

test('malformed markup discards detached partial content and empty Markdown remains valid', async () => {
  const refused = await render('raw source', '<p>partial</p><script>unsafe</script>');
  assert.equal(refused.accepted, false); assert.equal(preview(refused).children.length, 0);
  const accepted = await render('', '');
  assert.equal(accepted.accepted, true); assert.equal(find(raw(accepted), 'pre')[0].textContent, '');
});

// Tag recognition must reject bounded hostile bursts without an ambiguous
// name/tail regexp whose backtracking grows with the length of that burst.
test('long malformed tag names and attributes are bounded before DOM publication', () => {
  for (const html of ['<' + 'p'.repeat(400_000) + '<>', '<p ' + 'a'.repeat(400_000) + '>']) {
    assert.throws(() => presentationDom(doc, html));
  }
  assert.equal(presentationDom(doc, '<blockquote><p>valid</p></blockquote>').textContent, 'valid');
});
