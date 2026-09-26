// Production IssueClient, issue-history validation and mounted issue controller,
// with real WebCrypto and an observable minimal DOM. HTTP responses below are
// fixtures, not native fg/fgit-doc execution or real-browser interoperability.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, webcrypto } from 'node:crypto';
import { IssueClient, issueHistory, issueAction, mutationRequest } from '../src/smart_http/server/browser/issues.mjs';
import { mountIssues } from '../src/smart_http/server/browser/issues-view.mjs';

const HREF = 'http://127.0.0.1/repo.git/ui/issues/';
const HEAD = `alg:2:${'ab'.repeat(32)}`;
const PRINCIPAL = '33'.repeat(16);
const HEADER = { schema_version: 1, tenant_id: '11'.repeat(16), repository_id: '22'.repeat(16), snapshot_token: HEAD };
const sourceHash = source => createHash('sha256').update(source).digest('hex');
function presentation(source, html) {
  return { renderer: 'fgit-doc', profile: 'html_safe', source_sha256: sourceHash(source), parse_profile_sha256: 'cd'.repeat(32), html };
}
function body(raw, html, rendered = true) {
  return { body: raw, ...(rendered ? { body_rendered: presentation(raw, html) } : {}) };
}
function history(number = 7, { after = 0, limit = 20, rendered = true } = {}) {
  const initial = body('**Initial**', '<p><strong>Initial</strong></p>\n', rendered);
  const current = body(`**Current ${number}**`, `<p><strong>Current ${number}</strong></p>\n`, rendered);
  const comment = body('`comment`', '<p><code>comment</code></p>\n', rendered);
  const all = [
    { version: 1, actor: PRINCIPAL, action: { name: 'open', title: 'Discussion', labels: [], ...initial } },
    { version: 2, actor: PRINCIPAL, action: { name: 'edit', ...current } },
    { version: 3, actor: PRINCIPAL, action: { name: 'comment', ...comment } },
  ];
  return { ...HEADER, type: 'issue_history', found: true, after_version: after, limit,
    issue: { number, version: 3, title: 'Discussion', ...current, labels: [], state: 'open',
      opened_by: PRINCIPAL, last_actor: PRINCIPAL, comments: 1 },
    events: all.slice(after, after + limit), next_after_version: after + limit < 3 ? after + limit : null };
}
function list(after = 0, limit = 20) {
  return { ...HEADER, type: 'issue_page', after, limit, issues: [], next_after: null };
}
const response = (value, status = 200) => new Response(JSON.stringify(value), { status, headers: { 'Content-Type': 'application/json' } });
async function connected(transform = value => value) {
  const requests = [];
  const client = new IssueClient({ href: HREF, cryptoImpl: webcrypto, fetchImpl: async (url, options) => {
    requests.push({ url: new URL(url), options });
    const limit = Number(url.searchParams.get('limit'));
    const value = url.pathname.endsWith('/issues')
      ? list(Number(url.searchParams.get('after')), limit)
      : history(Number(url.pathname.split('/').at(-1)), {
        after: Number(url.searchParams.get('after_version')), limit,
        rendered: url.searchParams.get('render') === 'html_safe',
      });
    return response(transform(value, url));
  } });
  await client.connect('44'.repeat(32));
  return { client, requests };
}

class DomNode {
  constructor(tag, value = '') { this.tag = tag; this.value = value; this.children = []; this.attrs = {}; this.listeners = new Map(); this.open = false; this.checked = false; }
  set textContent(value) { this.value = String(value); this.children = []; }
  get textContent() { return this.value + this.children.map(child => child.textContent).join(''); }
  append(...nodes) {
    for (const node of nodes) {
      assert.ok(node instanceof DomNode);
      this.children.push(...(node.tag === '#fragment' ? node.children : [node]));
    }
  }
  replaceChildren(...nodes) { this.children = []; this.value = ''; this.append(...nodes); }
  setAttribute(name, value) {
    assert.ok(!/^on/i.test(name));
    assert.ok(!['src', 'srcdoc', 'style'].includes(name));
    this.attrs[name] = value;
  }
  addEventListener(name, callback) { const callbacks = this.listeners.get(name) ?? []; callbacks.push(callback); this.listeners.set(name, callbacks); }
  async emit(name) { await Promise.all((this.listeners.get(name) ?? []).map(callback => callback({ preventDefault() {} }))); }
}
function documentFixture() {
  const ids = new Map();
  return {
    defaultView: new DomNode('window'),
    getElementById(id) { if (!ids.has(id)) ids.set(id, new DomNode('div')); return ids.get(id); },
    createElement(tag) {
      assert.ok(!['script', 'img', 'iframe', 'svg', 'math', 'style', 'object'].includes(tag), `active element ${tag}`);
      return new DomNode(tag);
    },
    createTextNode(text) { return new DomNode('#text', text); },
    createDocumentFragment() { return new DomNode('#fragment'); },
  };
}
function find(node, tag) { return [node, ...node.children.flatMap(child => find(child, tag))].filter(item => item.tag === tag); }
function sections(doc) { return find(doc.getElementById('issue-content'), 'section'); }
async function settled(doc) {
  const deadline = Date.now() + 3000;
  while (sections(doc).some(section => section.children[0].textContent.includes('checking the optional'))) {
    if (Date.now() > deadline) assert.fail('presentation did not settle');
    await new Promise(resolve => setTimeout(resolve, 1));
  }
}
function delayedCrypto() {
  const pending = [];
  return { pending, crypto: { subtle: { digest(...args) {
    return new Promise((resolve, reject) => pending.push(() => webcrypto.subtle.digest(...args).then(resolve, reject)));
  } } }, async release() { await Promise.all(pending.splice(0).map(release => release())); await new Promise(resolve => setImmediate(resolve)); } };
}

test('rendered issue history retains exact raw actions and all existing semantic checks', () => {
  for (const rendered of [false, true]) {
    const value = history(7, { rendered }), before = structuredClone(value);
    assert.equal(issueHistory(value, 7).reply, value);
    assert.deepEqual(value, before, 'validating presentation must not rewrite canonical actions');
    for (const mutate of [
      value => { value.events[1].version = 3; },
      value => { value.events[2].action.principal = 'admin'; },
      value => { value.events[2].action.name = 'execute'; },
      value => { value.events.pop(); },
      value => { value.issue.number = 8; },
    ]) {
      const bad = structuredClone(value); mutate(bad); assert.throws(() => issueHistory(bad, 7));
    }
    assert.throws(() => issueHistory(value, 7, { head: `alg:2:${'ef'.repeat(32)}` }), /snapshot moved/);
  }
});

test('derived presentation cannot fabricate an absent body or enter mutation grammar', () => {
  for (const action of [{ name: 'close' }, { name: 'reopen' }, { name: 'edit', title: 'Only title' }]) {
    const value = history(); value.events[2].action = { ...action, body_rendered: presentation('', '') };
    assert.throws(() => issueHistory(value, 7), /no canonical body/);
    delete value.events[2].action.body_rendered;
    assert.doesNotThrow(() => issueHistory(value, 7));
  }
  for (const name of ['open', 'edit', 'comment']) {
    const fields = { body: '**untrusted**', ...(name === 'open' ? { title: 'T' } : {}) };
    assert.doesNotThrow(() => issueAction(name, fields));
    assert.throws(() => issueAction(name, { ...fields, body_rendered: {} }), /Unknown/);
    assert.throws(() => mutationRequest(7, name === 'open' ? 0 : 3, name, { ...fields, body_rendered: {} }), /Unknown/);
  }
});

test('rendering is an explicit read option and does not consume a pending mutation', async () => {
  const { client, requests } = await connected();
  await client.stage(7, 3, 'comment', { body: 'pending raw draft' });
  const pending = client.pending;
  await client.read(7);
  await client.read(7, { after: 1, limit: 2, head: HEAD, render: true });
  await client.read(null, { render: true });
  assert.equal(requests[0].url.search, '?after_version=0&limit=20');
  assert.equal(requests[1].url.searchParams.get('render'), 'html_safe');
  assert.equal(requests[1].url.searchParams.get('expected_head'), HEAD);
  assert.equal(requests[1].url.searchParams.get('after_version'), '1');
  assert.equal(requests[2].url.searchParams.get('render'), 'html_safe');
  for (const { options } of requests) {
    assert.equal(options.method, 'GET'); assert.equal(options.body, undefined);
    assert.equal(options.headers['Idempotency-Key'], undefined);
    assert.equal(options.credentials, 'omit'); assert.equal(options.redirect, 'error');
  }
  assert.deepEqual(client.pending, pending); client.disconnect();
});

test('invalid rendering flags fail before any HTTP request and failures do not retry', async () => {
  const { client, requests } = await connected();
  for (const render of ['html_safe', 1, null, {}]) await assert.rejects(client.read(7, { render }), /explicitly/);
  assert.equal(requests.length, 0);
  const failing = await connected(value => ({ ...value, snapshot_token: `alg:2:${'ef'.repeat(32)}` }));
  await assert.rejects(failing.client.read(7, { head: HEAD, render: true }), /snapshot moved/);
  assert.equal(failing.requests.length, 1, 'a rendered read must never retry another snapshot');
  client.disconnect(); failing.client.disconnect();
});

test('mounted issue controller renders description and versioned bodies while edits stay raw', async () => {
  const { client, requests } = await connected(), doc = documentFixture();
  const mounted = mountIssues(doc, { href: HREF }, { client, cryptoImpl: webcrypto });
  await mounted.read(7); await settled(doc);
  assert.equal(requests.length, 1); assert.equal(requests[0].url.searchParams.get('render'), 'html_safe');
  assert.equal(sections(doc).length, 4);
  assert.deepEqual(sections(doc).map(section => section.children[1].textContent), ['Current 7\n', 'Initial\n', 'Current 7\n', 'comment\n']);
  assert.ok(sections(doc).every(section => !section.children[2].open));
  const edit = find(doc.getElementById('issue-content'), 'button').find(button => button.textContent === 'Edit issue');
  await edit.emit('click'); assert.equal(doc.getElementById('change-body').value, '**Current 7**');
  assert.equal(doc.getElementById('change-version').value, '3'); assert.equal(client.pending, null);
  const comment = find(doc.getElementById('issue-content'), 'button').find(button => button.textContent === 'Comment');
  await comment.emit('click'); assert.equal(doc.getElementById('change-body').value, '');
  assert.equal(requests.length, 1, 'presentation and edit selection must not submit changes');
  await mounted.read(null); assert.equal(requests[1].url.searchParams.has('render'), false);
  mounted.disconnect();
});

test('bad presentation falls back per body without discarding the canonical history', async () => {
  for (const poison of [
    value => { value.events[2].action.body_rendered.source_sha256 = '00'.repeat(32); },
    value => { value.events[2].action.body_rendered.html = '<p>before</p><script>execute()</script>'; },
    value => { value.events[2].action.body_rendered = { html: null, refusal: 'output_too_large' }; },
    value => { delete value.events[2].action.body_rendered; },
  ]) {
    const { client } = await connected(value => { poison(value); return value; }), doc = documentFixture();
    const mounted = mountIssues(doc, { href: HREF }, { client, cryptoImpl: webcrypto });
    await mounted.read(7); await settled(doc);
    assert.equal(sections(doc).length, 4);
    assert.equal(sections(doc)[0].children[2].open, false, 'permitted description remains rendered');
    const last = sections(doc).at(-1);
    assert.equal(last.children[2].open, true); assert.equal(last.children[1].textContent, '');
    assert.equal(find(last.children[2], 'pre')[0].textContent, '`comment`');
    assert.match(last.children[0].textContent, /unavailable/);
    assert.equal(find(doc.getElementById('issue-content'), 'article').length, 3);
    mounted.disconnect();
  }
});

test('a missing crypto presentation boundary keeps every raw body visible', async () => {
  const { client } = await connected(), doc = documentFixture();
  const mounted = mountIssues(doc, { href: HREF }, { client, cryptoImpl: {} });
  await mounted.read(7); await settled(doc);
  assert.equal(sections(doc).length, 4);
  assert.ok(sections(doc).every(section => section.children[2].open && section.children[1].textContent === ''));
  assert.match(doc.getElementById('issue-status').textContent, /Read complete/);
  mounted.disconnect();
});

test('cancel and disconnect prevent delayed hashing from reviving private issue views', async () => {
  for (const stop of ['cancel', 'disconnect']) {
    const { client } = await connected(), doc = documentFixture(), delayed = delayedCrypto();
    const mounted = mountIssues(doc, { href: HREF }, { client, cryptoImpl: delayed.crypto });
    await mounted.read(7); await Promise.resolve();
    const old = sections(doc); assert.equal(delayed.pending.length, 4);
    if (stop === 'disconnect') mounted.disconnect();
    else await doc.getElementById('issue-search-cancel').emit('click');
    await delayed.release();
    assert.equal(doc.getElementById('issue-content').textContent, '');
    assert.ok(old.every(section => section.children[1].textContent === '' && section.children[2].open));
    mounted.disconnect();
  }
});

test('a superseded issue selection cannot receive a late rendered preview', async () => {
  const { client } = await connected(), doc = documentFixture(), delayed = delayedCrypto();
  const mounted = mountIssues(doc, { href: HREF }, { client, cryptoImpl: delayed.crypto });
  await mounted.read(7); await Promise.resolve(); const old = sections(doc);
  await mounted.read(8); await Promise.resolve();
  assert.equal(delayed.pending.length, 8); await delayed.release(); await settled(doc);
  assert.ok(old.every(section => section.children[1].textContent === ''));
  assert.equal(sections(doc)[0].children[1].textContent, 'Current 8\n');
  assert.ok(!doc.getElementById('issue-content').textContent.includes('Current 7'));
  mounted.disconnect();
});

test('rendered history continuations retain the exact original snapshot and version cursor', async () => {
  const { client, requests } = await connected();
  const first = await client.read(7, { limit: 2, render: true });
  const next = await client.read(7, { after: first.reply.next_after_version, limit: 2, head: first.head, render: true });
  assert.deepEqual(first.reply.events.map(event => event.version), [1, 2]);
  assert.deepEqual(next.reply.events.map(event => event.version), [3]);
  assert.equal(next.reply.next_after_version, null);
  assert.equal(requests[1].url.searchParams.get('expected_head'), HEAD);
  assert.equal(requests[1].url.searchParams.get('after_version'), '2');
  assert.equal(next.reply.events[0].action.body, '`comment`');
  assert.equal(next.reply.events[0].action.body_rendered.source_sha256, sourceHash('`comment`'));
  assert.equal(client.pending, null); client.disconnect();
});
