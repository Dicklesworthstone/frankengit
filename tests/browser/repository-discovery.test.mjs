import assert from 'node:assert/strict';
import test from 'node:test';

import {
  CATALOG_PATH, MAX_RESPONSE_BYTES, RepositoryDiscovery, mountDiscovery, validateCatalog, validatePageLocation,
} from '../../crates/fgit-node/src/smart_http/server/discovery/repositories.mjs';

const TOKEN = 'a'.repeat(64);
const OTHER = 'b'.repeat(64);
const entry = (path, source = true) => ({path, source_url: source ? `${path}/ui/` : null});
const catalog = (entries = [entry('/tenant/repo.git')]) => ({
  type: 'repository_catalog', schema_version: 1, complete: true, repositories: entries,
});
const response = (value = catalog(), options = {}) => new Response(JSON.stringify(value), {
  headers: {'content-type': 'application/json'}, ...options,
});
const pending = () => {
  let resolve;
  const promise = new Promise(accept => { resolve = accept; });
  return {promise, resolve};
};

test('validates every sorted route and exact source URL before publishing any links', () => {
  const value = catalog([entry('/one.git'), entry('/tenant/clone.git', false)]);
  const entries = validateCatalog(value);
  assert.deepEqual(entries, value.repositories);
  assert.ok(Object.isFrozen(entries) && entries.every(Object.isFrozen));
  for (const invalid of [
    {...value, complete: false},
    {...value, schema_version: 2},
    {...value, total_hidden_repositories: 4},
    {...value, repositories: []},
    catalog([entry('/z/repo'), entry('/a/repo')]),
    catalog([entry('/a/repo'), entry('/a/repo')]),
    catalog(Array.from({length: 65}, (_, index) => entry(`/a/repo-${String(index).padStart(2, '0')}`))),
    catalog([{path: '/a/repo', source_url: 'https://evil.invalid/'}]),
    catalog([{path: '/a/repo', source_url: '//evil.invalid/ui/'}]),
    catalog([{path: '/a/repo', source_url: '/a/other/ui/'}]),
    catalog([{path: '/a/repo', source_url: '/a/repo/ui/?credential=x'}]),
    catalog([{path: '/a/repo', source_url: null, credentials: TOKEN}]),
  ]) assert.throws(() => validateCatalog(invalid), /invalid repository catalog/);
  for (const path of [
    '//evil.invalid/a', '/tenant/../repo', '/tenant/./repo', '/tenant/%2e%2e',
    '/tenant/%2f%2fevil.invalid', '/tenant/repo?x=y', '/tenant/repo#x',
    '/tenant/repo\\evil', '/tenant/<script>', '/tenant/repo/', '/-tenant/repo',
    `/${'a'.repeat(512)}`, '/tenant/répô', '/tenant/repo\n',
  ]) assert.throws(() => validateCatalog(catalog([entry(path)])), /invalid repository catalog/, path);
  assert.equal(validateCatalog(catalog(Array.from({length: 64}, (_, index) => entry(`/tenant/repo-${String(index).padStart(2, '0')}`)))).length, 64);
});

test('construction and invalid credentials do not fetch; explicit connection omits ambient identity', async () => {
  const calls = [];
  const states = [];
  const client = new RepositoryDiscovery({fetch: async (...args) => {
    calls.push(args);
    return response();
  }, onChange: state => states.push(state)});
  assert.equal(calls.length, 0);
  for (const invalid of ['', 'A'.repeat(64), `fgagent_${TOKEN}`, ` ${TOKEN}`, `${TOKEN}\n`, null]) {
    assert.equal(await client.connect(invalid), false);
  }
  assert.equal(calls.length, 0);
  assert.equal(await client.connect(TOKEN), true);
  assert.equal(calls.length, 1);
  const [url, options] = calls[0];
  assert.equal(url, CATALOG_PATH);
  assert.equal(options.method, 'GET');
  assert.deepEqual(options.headers, {Authorization: `Bearer ${TOKEN}`, Accept: 'application/json'});
  assert.equal(options.credentials, 'omit');
  assert.equal(options.mode, 'same-origin');
  assert.equal(options.cache, 'no-store');
  assert.equal(options.redirect, 'error');
  assert.equal(options.referrerPolicy, 'no-referrer');
  assert.ok(options.signal instanceof AbortSignal);
  assert.equal(options.body, undefined);
  assert.equal(client.state.status, 'connected');
  assert.deepEqual(client.state.repositories, catalog().repositories);
  assert.equal(JSON.stringify(states).includes(TOKEN), false);
  client.disconnect();
  assert.equal(client.state.status, 'disconnected');
  assert.deepEqual(client.state.repositories, []);
  assert.equal(calls.length, 1);
});

test('disconnect aborts pending fetch and discards its late catalog', async () => {
  const waiting = pending();
  let signal;
  const client = new RepositoryDiscovery({fetch: async (_url, options) => {
    signal = options.signal;
    return waiting.promise;
  }});
  const connection = client.connect(TOKEN);
  assert.equal(client.state.status, 'connecting');
  client.disconnect();
  assert.equal(signal.aborted, true);
  waiting.resolve(response());
  assert.equal(await connection, false);
  assert.equal(client.state.status, 'disconnected');
  assert.deepEqual(client.state.repositories, []);
});

test('a new credential replaces the prior request and old success cannot resurrect its rows', async () => {
  const first = pending();
  const signals = [];
  let count = 0;
  const client = new RepositoryDiscovery({fetch: async (_url, options) => {
    signals.push(options.signal);
    count += 1;
    return count === 1 ? first.promise : response(catalog([entry('/new/allowed')]));
  }});
  const oldConnection = client.connect(TOKEN);
  assert.equal(await client.connect(OTHER), true);
  assert.equal(signals[0].aborted, true);
  first.resolve(response(catalog([entry('/old/forbidden')])));
  assert.equal(await oldConnection, false);
  assert.deepEqual(client.state.repositories, [entry('/new/allowed')]);
  client.disconnect();
});

test('disconnect during streamed response cancels the reader and discloses no partial rows', async () => {
  const started = pending();
  let cancelled = false;
  const body = new ReadableStream({
    pull() { started.resolve(); },
    cancel() { cancelled = true; },
  }, {highWaterMark: 0});
  const client = new RepositoryDiscovery({fetch: async () => new Response(body, {headers: {'content-type': 'application/json'}})});
  const connection = client.connect(TOKEN);
  await started.promise;
  client.disconnect();
  assert.equal(await connection, false);
  assert.equal(cancelled, true);
  assert.equal(client.state.status, 'disconnected');
  assert.deepEqual(client.state.repositories, []);
});

test('authentication, read scope, quota and configuration failures stay distinct without reflecting server text', async () => {
  for (const [status, message] of [
    [401, /credential was not accepted/], [403, /no repository read grant/],
    [408, /timed out/], [413, /supported size/], [429, /read request limit/],
    [503, /complete repository catalog/], [500, /could not complete repository discovery/],
  ]) {
    const client = new RepositoryDiscovery({fetch: async () => response({secret: TOKEN, hidden: '/private/repo'}, {status})});
    assert.equal(await client.connect(TOKEN), false);
    assert.equal(client.state.status, 'error');
    assert.match(client.state.message, message);
    assert.ok(!client.state.message.includes(TOKEN) && !client.state.message.includes('/private/'));
    assert.deepEqual(client.state.repositories, []);
  }
  const client = new RepositoryDiscovery({fetch: async () => { throw new Error(`untrusted network detail ${TOKEN}`); }});
  assert.equal(await client.connect(TOKEN), false);
  assert.equal(client.state.message.includes(TOKEN), false);
});

test('malformed, incomplete, oversized and non-JSON bodies never publish a catalog', async () => {
  const inputs = [
    () => new Response('<html>login</html>', {headers: {'content-type': 'text/html'}}),
    () => new Response('{}', {headers: {'content-type': 'application/json'}}),
    () => new Response(new Uint8Array([0xff]), {headers: {'content-type': 'application/json'}}),
    () => new Response('{', {headers: {'content-type': 'application/json'}}),
    () => new Response(JSON.stringify(catalog()), {headers: {'content-type': 'application/json', 'content-length': '999'}}),
    () => new Response(JSON.stringify(catalog()), {headers: {'content-type': 'application/json', 'content-length': String(MAX_RESPONSE_BYTES + 1)}}),
    () => new Response(JSON.stringify(catalog()), {headers: {'content-type': 'application/json', 'content-length': '01'}}),
    () => new Response(' '.repeat(MAX_RESPONSE_BYTES + 1), {headers: {'content-type': 'application/json'}}),
    () => response(catalog([entry('/public/repo'), entry('//evil.invalid/x')])),
  ];
  for (const input of inputs) {
    const client = new RepositoryDiscovery({fetch: async () => input()});
    assert.equal(await client.connect(TOKEN), false);
    assert.equal(client.state.status, 'error');
    assert.deepEqual(client.state.repositories, []);
  }
  const body = JSON.stringify(catalog());
  const client = new RepositoryDiscovery({fetch: async () => new Response(body, {headers: {
    'content-type': 'application/json; charset=utf-8', 'content-length': String(Buffer.byteLength(body)),
  }})});
  assert.equal(await client.connect(TOKEN), true);
  client.disconnect();
});

test('client deadline clears in-flight state even when a fetch ignores cancellation', async () => {
  const waiting = pending();
  let signal;
  const client = new RepositoryDiscovery({timeoutMs: 5, fetch: async (_url, options) => {
    signal = options.signal;
    return waiting.promise;
  }});
  const connection = client.connect(TOKEN);
  assert.equal(await connection, false);
  assert.equal(signal.aborted, true);
  assert.equal(client.state.status, 'error');
  assert.match(client.state.message, /timed out/);
  waiting.resolve(response());
  await new Promise(resolve => setImmediate(resolve));
  assert.deepEqual(client.state.repositories, []);
});

test('proxy-compressed responses compare the decoded byte budget rather than encoded Content-Length', async () => {
  for (const [coding, length] of [['gzip', '17'], ['br', String(MAX_RESPONSE_BYTES + 100)], ['identity, gzip', '1']]) {
    const client = new RepositoryDiscovery({fetch: async () => response(catalog(), {headers: {
      'content-type': 'application/json', 'content-encoding': coding, 'content-length': length,
    }})});
    assert.equal(await client.connect(TOKEN), true);
    assert.deepEqual(client.state.repositories, catalog().repositories);
    client.disconnect();
  }
  for (const [body, length] of [
    [JSON.stringify(catalog()), '01'],
    [JSON.stringify(catalog()), '-1'],
    [' '.repeat(MAX_RESPONSE_BYTES + 1), '1'],
  ]) {
    const client = new RepositoryDiscovery({fetch: async () => new Response(body, {headers: {
      'content-type': 'application/json', 'content-encoding': 'gzip', 'content-length': length,
    }})});
    assert.equal(await client.connect(TOKEN), false);
    assert.deepEqual(client.state.repositories, []);
  }
});

test('producer cleanup that never settles cannot hang HTTP refusals or streaming size refusals', {timeout: 1000}, async () => {
  for (const status of [401, 200]) {
    let cancelled = false;
    const body = new ReadableStream({
      start(controller) { controller.enqueue(new Uint8Array(MAX_RESPONSE_BYTES + 1)); },
      cancel() { cancelled = true; return new Promise(() => {}); },
    });
    const client = new RepositoryDiscovery({fetch: async () => new Response(body, {status, headers: {'content-type': 'application/json'}})});
    assert.equal(await client.connect(TOKEN), false);
    assert.equal(cancelled, true);
    assert.equal(client.state.status, 'error');
    assert.deepEqual(client.state.repositories, []);
  }
});

test('deadline settles a blocked read even when producer cancellation cleanup never resolves', {timeout: 1000}, async () => {
  let cancelled = false;
  const body = new ReadableStream({
    pull() { return new Promise(() => {}); },
    cancel() { cancelled = true; return new Promise(() => {}); },
  }, {highWaterMark: 0});
  const client = new RepositoryDiscovery({timeoutMs: 5, fetch: async () => new Response(body, {headers: {'content-type': 'application/json'}})});
  assert.equal(await client.connect(TOKEN), false);
  assert.equal(cancelled, true);
  assert.equal(client.state.status, 'error');
  assert.match(client.state.message, /timed out/);
  assert.deepEqual(client.state.repositories, []);
});

test('only the exact HTTPS or loopback HTTP home page can enable credential submission', async () => {
  for (const href of ['https://forge.example/ui/', 'http://localhost:8080/ui/', 'http://127.0.0.1/ui/', 'http://[::1]:8080/ui/']) {
    assert.equal(validatePageLocation(href), new URL(href).origin);
  }
  for (const href of [
    'http://forge.example/ui/', 'http://192.168.1.5/ui/', 'file:///ui/',
    'https://forge.example/ui/?credential=x', 'https://forge.example/ui/#secret',
    'https://user:password@forge.example/ui/', 'https://forge.example/tenant/repo/ui/',
    'https://forge.example/ui', 'https://forge.example/ui/repositories.mjs',
  ]) {
    assert.throws(() => validatePageLocation(href));
    const ids = new Map(['connection-form', 'credential', 'connect', 'disconnect', 'connection-status', 'repositories'].map(id => [id, new Element(id)]));
    ids.get('credential').value = TOKEN;
    const document = {getElementById: id => ids.get(id), createElement: tag => new Element(tag), defaultView: {location: {href}}};
    let calls = 0;
    assert.equal(mountDiscovery(document, {fetch: async () => { calls += 1; return response(); }}), null);
    let prevented = false;
    ids.get('connection-form').listeners.get('submit')({preventDefault() { prevented = true; }});
    assert.equal(prevented, true);
    assert.equal(ids.get('credential').value, '');
    assert.equal(ids.get('credential').disabled, true);
    assert.equal(ids.get('connect').disabled, true);
    assert.equal(ids.get('connection-status').dataset.status, 'error');
    assert.equal(calls, 0);
  }
});

class Element {
  children = [];
  listeners = new Map();
  value = '';
  dataset = {};
  textContent = '';
  disabled = false;
  constructor(tagName) { this.tagName = tagName; }
  addEventListener(name, listener) { this.listeners.set(name, listener); }
  append(child) { this.children.push(child); }
  replaceChildren() { this.children = []; }
}

test('public shell starts idle, clears the password field and renders only checked relative links', async () => {
  const ids = new Map(['connection-form', 'credential', 'disconnect', 'connection-status', 'repositories'].map(id => [id, new Element(id)]));
  const page = new Element('window');
  page.location = {href: 'https://forge.example/ui/'};
  const document = {getElementById: id => ids.get(id), createElement: tag => new Element(tag), defaultView: page};
  let calls = 0;
  const client = mountDiscovery(document, {fetch: async () => {
    calls += 1;
    return response(catalog([entry('/one/repo'), entry('/two/git-only', false)]));
  }});
  assert.equal(calls, 0);
  assert.equal(ids.get('repositories').children.length, 0);
  assert.equal(ids.get('disconnect').disabled, true);
  ids.get('credential').value = TOKEN;
  let prevented = false;
  ids.get('connection-form').listeners.get('submit')({preventDefault() { prevented = true; }});
  assert.equal(prevented, true);
  assert.equal(ids.get('credential').value, '');
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(calls, 1);
  const rows = ids.get('repositories').children;
  assert.equal(rows.length, 2);
  assert.equal(rows[0].children[0].textContent, '/one/repo');
  assert.equal(rows[0].children[1].href, '/one/repo/ui/');
  assert.equal(rows[1].children[1].textContent, 'Git access');
  assert.equal(rows[1].children[1].href, undefined);
  ids.get('credential').value = OTHER;
  page.listeners.get('pagehide')();
  assert.equal(ids.get('credential').value, '');
  assert.equal(ids.get('repositories').children.length, 0);
  assert.equal(client.state.status, 'disconnected');
  assert.equal(calls, 1);
});
