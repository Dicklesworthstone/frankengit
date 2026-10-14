import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { execFileSync } from 'node:child_process';
import { setTimeout as sleep } from 'node:timers/promises';
import { EVENT_LIMITS, eventBytes, eventJson, eventConfiguration, eventCredentialBinding,
  readEventPage, captureEventPages, validateEventCapture } from '../../scripts/operator/event_feed.mjs';
import { config, page, row, peer, json, TOKEN } from './event_feed_fixture.mjs';
const code = expected => error => error.code === expected;

for (const format of ['sha1', 'sha256']) test(`${format}: filtered pages advance exact watermarks across changing heads`, async () => {
  let cfg;
  const server = await peer((request, response, ordinal) => {
    const after = new URL(request.url, 'http://example.test').searchParams.get('after');
    assert.equal(after, ['0', '9007199254740993:4294967295', '18446744073709551614:1'][ordinal - 1]);
    json(response, ordinal === 1 ? page(cfg, { rows: [], resume: '9007199254740993:4294967295', more: true }) :
      ordinal === 2 ? page(cfg, { rows: [row('18446744073709551614', '1')], more: true, head: '02' }) :
        page(cfg, { rows: [row('18446744073709551615', '4294967295')], head: '03' }));
  });
  cfg = config(server.endpoint, format);
  try {
    const capture = await captureEventPages(cfg, TOKEN);
    assert.equal(capture.pages.length, 3);
    assert.equal(capture.pages[0].events.length, 0);
    assert.equal(capture.pages[2].resume_after, '18446744073709551615:4294967295');
    assert.equal(capture.pages[1].events[0].event_frame_hex, '00ff80');
    assert.deepEqual(validateEventCapture(eventJson(eventBytes(capture)), cfg), capture);
    for (const request of server.requests) {
      assert.equal(request.method, 'GET'); assert.equal(request.headers.authorization, `Bearer ${TOKEN}`);
      assert.equal(request.headers['idempotency-key'], undefined); assert.equal(request.headers.cookie, undefined);
      assert.equal(request.headers['accept-encoding'], 'identity'); assert(!request.url.includes('expected_head'));
    }
  } finally { await server.close(); }
});

test('page budget returns a real continuation; complete empty page is a valid observation', async () => {
  let cfg;
  const server = await peer((_q, r) => json(r, page(cfg, { more: true })));
  cfg = config(server.endpoint);
  try {
    const result = await captureEventPages(cfg, TOKEN, { maxPages: 1 });
    assert.equal(result.pages.at(-1).has_more, true); assert.equal(server.requests.length, 1);
  } finally { await server.close(); }
  const empty = { type: 'frankengit_event_capture', schema_version: 1, configuration: cfg, pages: [page(cfg, { rows: [] })] };
  assert.deepEqual(validateEventCapture(empty, cfg), empty);
});

for (const field of ['tenant_id', 'repository_id', 'repository_incarnation', 'object_format', 'issues_read', 'pulls_read']) {
  test(`independent ${field} binding refuses a changed peer`, async () => {
    let cfg;
    const server = await peer((_q, r) => {
      const raw = page(cfg); raw[field] = typeof raw[field] === 'boolean' ? !raw[field] : field === 'object_format' ? 'sha256' : 'b4'.repeat(16);
      json(r, raw);
    });
    cfg = config(server.endpoint);
    try { await assert.rejects(readEventPage(cfg, TOKEN), code('invalid_event_page_or_scope')); assert.equal(server.requests.length, 1); }
    finally { await server.close(); }
  });
}

for (const status of [301, 302, 401, 403, 404, 409, 413, 429, 503]) test(`HTTP ${status} never becomes empty success or an implicit retry`, async () => {
  const server = await peer((_q, r) => json(r, { secret: 'must-not-escape' }, status, { Location: '/elsewhere' }));
  try { await assert.rejects(readEventPage(config(server.endpoint), TOKEN), error => error.status === status && !error.message.includes('must-not-escape')); assert.equal(server.requests.length, 1); }
  finally { await server.close(); }
});

test('configuration, endpoints, credentials and option bounds refuse before I/O', async () => {
  for (const endpoint of ['http://localhost/repo', 'http://example.com/repo', 'https://u:p@example.com/repo',
    'https://example.com/repo/', 'https://example.com/repo?x=1', 'https://example.com/a/../repo', 'https://example.com/%2e/repo']) {
    assert.throws(() => eventConfiguration(config(endpoint)), code('invalid_event_endpoint'));
  }
  for (const options of [{ maxPages: 0 }, { maxBytes: 0 }, { timeoutMs: 0 }, { retry: true }]) {
    await assert.rejects(captureEventPages(config(), TOKEN, options));
  }
  await assert.rejects(readEventPage(config(), 'secret-not-hex'), code('invalid_event_credential'));
  const bad = config(); Object.defineProperty(bad, 'endpoint', { get() { throw new Error('getter executed'); } });
  assert.throws(() => eventConfiguration(bad), code('invalid_event_fields'));
  assert.notEqual(eventCredentialBinding(TOKEN), eventCredentialBinding('ab'.repeat(32)));
});

test('strict JSON rejects duplicate keys, invalid UTF-8, exotic numeric forms and excessive depth', () => {
  for (const text of ['{"a":1,"a":2}', '{"a":1,"\\u0061":2}', '{"a":{"x":0,"x":1}}']) assert.throws(() => eventJson(Buffer.from(text)), code('duplicate_event_json_key'));
  for (const text of ['1e0', '-0', '1.0', '9007199254740993']) assert.throws(() => eventJson(Buffer.from(text)), code('invalid_event_json_number'));
  assert.throws(() => eventJson(Buffer.from([0xff])), code('invalid_event_json'));
  assert.throws(() => eventJson(Buffer.from('['.repeat(33) + '0' + ']'.repeat(33))), code('event_json_structure_limit'));
  assert.deepEqual(eventJson(Buffer.from('{"a":"}:[\\\"","b":[true,null,2]}')), { a: '}:["', b: [true, null, 2] });
});

test('offline revalidation refuses grafts, backwards cursors, illegal continuation and altered configuration', () => {
  const cfg = config(), value = { type: 'frankengit_event_capture', schema_version: 1, configuration: cfg, pages: [page(cfg, { more: true }), page(cfg, { rows: [row('2')] })] };
  for (const mutate of [v => v.pages[1].events[0].cursor = '1:0', v => v.pages[1].resume_after = '1:0',
    v => v.pages[0].next_after = null, v => v.pages[0].has_more = false, v => v.pages[1].events[0].event_frame_hex = 'ffz0',
    v => v.pages[1].events[0].repository_sequence = '02', v => v.pages[1].events[0].policy_epoch = 1,
    v => v.configuration.endpoint = 'https://elsewhere.test/repo', v => v.pages[1].repository_incarnation = 'b4'.repeat(16)]) {
    const changed = structuredClone(value); mutate(changed); assert.throws(() => validateEventCapture(changed, cfg));
  }
  assert.deepEqual(validateEventCapture(value, cfg), value);
});

test('wire, cumulative and exact N/N+1 response bounds are enforced', async () => {
  let cfg;
  const server = await peer((_q, r) => json(r, page(cfg, { more: true })));
  cfg = config(server.endpoint);
  const length = Buffer.byteLength(JSON.stringify(page(cfg, { more: true })));
  try {
    assert.equal((await readEventPage(cfg, TOKEN, { maximumBytes: length })).bytes, length);
    await assert.rejects(readEventPage(cfg, TOKEN, { maximumBytes: length - 1 }), code('event_response_limit'));
    await assert.rejects(captureEventPages(cfg, TOKEN, { maxBytes: length, maxPages: 2 }), code('event_capture_limit'));
  } finally { await server.close(); }
  const oversized = await peer((_q, r) => { r.writeHead(200, { 'Content-Type': 'application/json' }); r.end(' '.repeat(EVENT_LIMITS.response + 1)); });
  try { await assert.rejects(readEventPage(config(oversized.endpoint), TOKEN), code('event_response_limit')); }
  finally { await oversized.close(); }
});

for (const headers of [{ 'Content-Type': 'text/html' }, { 'Content-Encoding': 'gzip' }, { 'Content-Type': ['application/json', 'application/json'] }]) {
  test(`unsupported response headers refuse: ${JSON.stringify(headers)}`, async () => {
    const server = await peer((_q, r) => json(r, {}, 200, headers));
    try { await assert.rejects(readEventPage(config(server.endpoint), TOKEN), code('event_response_encoding')); }
    finally { await server.close(); }
  });
}

test('a chunked response succeeds, but truncation, timeout and cancellation never retain a page', async () => {
  let cfg;
  const chunked = await peer((_q, r) => { r.writeHead(200, { 'Content-Type': 'application/json' }); const text = JSON.stringify(page(cfg)); r.write(text.slice(0, 10)); r.end(text.slice(10)); });
  cfg = config(chunked.endpoint);
  try { assert.equal((await readEventPage(cfg, TOKEN)).page.events.length, 1); } finally { await chunked.close(); }
  const partial = await peer((_q, r) => { r.writeHead(200, { 'Content-Type': 'application/json', 'Content-Length': 100 }); r.write('{'); r.socket.end(); });
  try { await assert.rejects(readEventPage(config(partial.endpoint), TOKEN)); } finally { await partial.close(); }
  const hung = await peer(() => {});
  try {
    await assert.rejects(readEventPage(config(hung.endpoint), TOKEN, { timeoutMs: 40 }), code('event_timeout'));
    const abort = new AbortController(); const request = readEventPage(config(hung.endpoint), TOKEN, { signal: abort.signal });
    await sleep(20); abort.abort(); await assert.rejects(request, code('event_cancelled'));
    const already = new AbortController(); already.abort(); const before = hung.requests.length;
    await assert.rejects(readEventPage(config(hung.endpoint), TOKEN, { signal: already.signal }), code('event_cancelled'));
    assert.equal(hung.requests.length, before);
    for (let n = 0; hung.sockets.size && n < 30; n++) await sleep(5);
    assert.equal(hung.sockets.size, 0);
  } finally { await hung.close(); }
});

test('HTTPS verifies trust and hostname with a test-only CA; no plaintext downgrade', async () => {
  const root = mkdtempSync(join(tmpdir(), 'fg-events-tls-'));
  try {
    const key = join(root, 'key.pem'), cert = join(root, 'cert.pem');
    // OpenSSL is a test-only certificate fixture generator, never production.
    execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', key, '-out', cert,
      '-days', '1', '-subj', '/CN=127.0.0.1', '-addext', 'subjectAltName=IP:127.0.0.1'], { stdio: ['ignore', 'ignore', 'pipe'] });
    const ca = readFileSync(cert); let cfg;
    const server = await peer((_q, r) => json(r, page(cfg)), { key: readFileSync(key), cert: ca }); cfg = config(server.endpoint);
    try {
      assert.equal((await readEventPage(cfg, TOKEN, { ca })).page.events.length, 1);
      await assert.rejects(readEventPage(cfg, TOKEN), code('event_transport_unavailable'));
      await assert.rejects(readEventPage(config(server.endpoint.replace('127.0.0.1', 'localhost')), TOKEN, { ca }), code('event_transport_unavailable'));
      assert.equal(server.requests.length, 1);
    } finally { await server.close(); }
  } finally { rmSync(root, { recursive: true, force: true }); }
});
