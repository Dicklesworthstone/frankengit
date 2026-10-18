// Actual PR template, mountPulls, browser client and WebCrypto. DOM and HTTP
// are controlled doubles; these tests do not claim native admission evidence.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { setImmediate } from 'node:timers/promises';
import { mountPulls } from '../../crates/fgit-node/src/smart_http/server/browser/pulls-view.mjs';
import { fakeDocument, sourceRoot, until } from './helpers/pulls-workflow-fixture.mjs';
import { actor, token, ids, head as prHead, page, row, data, show, reviews, json, webcrypto, deferred } from './pulls-fixtures.mjs';
import { fixture as candidateFixture } from './pulls-candidate-fixtures.mjs';

const conversationHead = `alg:1:${'8'.repeat(64)}`;
const changedHead = `alg:1:${'9'.repeat(64)}`;
const template = readFileSync(new URL('pulls.html', sourceRoot), 'utf8');
const comment = (version, extra = {}) => ({ version, actor, body: `Discussion entry ${version}`, ...extra });
function conversation(extra = {}) {
  const after = extra.after ?? 0, limit = extra.limit ?? 5, high = extra.discussion_version ?? 2;
  const count = Math.min(Math.max(high - after, 0), limit), last = after + count;
  return { ...ids, type: 'pull_request_comments', number: 1, found: true,
    source_head: 'conversation-authority-head', snapshot_token: conversationHead,
    discussion_version: high, after, limit, next_after: last < high ? last : null, complete: last >= high,
    merge_permission: null, transaction_created: false,
    comments: Array.from({ length: count }, (_, index) => comment(after + index + 1)), ...extra };
}
function terminal(pending, outcome = 'committed') {
  return { ...ids, object_format: pending.scope.format, type: 'pull_request_comment_publication',
    number: pending.number, action: 'comment', expected_version: pending.fields.expected_version,
    comment_version: outcome === 'committed' ? pending.fields.expected_version + 1 : null,
    principal_id: actor, tx_id: 'conversation-transaction', decision_sequence: 7, outcome,
    repository_commit_id: outcome === 'committed' ? 'conversation-rcr' : null,
    refusal_record_id: outcome === 'refused' ? 'conversation-refusal' : null,
    refusal_code: outcome === 'refused' ? 'EvidenceStale' : null,
    refusal_code_point: outcome === 'refused' ? 1 : null,
    refs_changed: false, delivery_acknowledged: null };
}
function descendants(node) { return [node, ...node.children.flatMap(descendants)]; }
function button(node, prefix) {
  const result = descendants(node).find(child => child.tagName === 'BUTTON' && child.textContent.startsWith(prefix));
  assert.ok(result, `missing button ${prefix}`); return result;
}
const commentReads = calls => calls.filter(call => new URL(call.url).pathname.endsWith('/comments') && call.method === 'GET');
const writes = calls => calls.filter(call => call.method === 'POST' && call.headers['Idempotency-Key']);

async function harness({ observed = show(), read = null, dispatch = null } = {}) {
  const doc = fakeDocument(), calls = [], digests = new Set(), candidate = candidateFixture(observed.object_format);
  const node = id => { const value = doc.getElementById(id); assert.ok(value, `missing template control ${id}`); return value; };
  // The shared DOM double discovers controls but does not implement option
  // selection. Derive this initial value from the real template, not the test.
  const select = template.match(/<select\b[^>]*\bid="comments-limit"[^>]*>([\s\S]*?)<\/select>/u);
  assert.ok(select, 'the real template must provide comments per page');
  const choices = [...select[1].matchAll(/<option\b([^>]*)>/gu)];
  const chosen = choices.find(choice => /\bselected\b/u.test(choice[1])) ?? choices[0];
  const initialLimit = chosen?.[1].match(/\bvalue="([^"]*)"/u)?.[1];
  assert.notEqual(initialLimit, undefined, 'comments per page must have a selectable default');
  node('comments-limit').value = initialLimit;
  // A production regression to an HTML parser sink fails even in this double.
  const guardSinks = element => {
    for (const name of ['innerHTML', 'outerHTML']) Object.defineProperty(element, name, {
      set() { throw new Error(`Unsafe HTML sink: ${name}`); },
    });
    element.insertAdjacentHTML = () => { throw new Error('Unsafe HTML sink'); };
    return element;
  };
  descendants(doc.body).forEach(guardSinks);
  const createElement = doc.createElement;
  doc.createElement = tag => guardSinks(createElement(tag));
  const cryptoImpl = { getRandomValues: value => webcrypto.getRandomValues(value), subtle: { digest(...args) {
    const pending = webcrypto.subtle.digest(...args); digests.add(pending);
    pending.then(() => digests.delete(pending), () => digests.delete(pending)); return pending;
  } } };
  let app;
  const fetchImpl = async (url, options) => {
    const call = { url: String(url), ...options, bytes: options.body === undefined ? null
      : typeof options.body === 'string' ? options.body : await options.body.text() };
    calls.push(call);
    if (url.pathname.endsWith('/comments')) {
      if (call.method === 'POST') return dispatch ? dispatch(call, app.client.pending)
        : json(terminal(app.client.pending));
      return read ? read(call) : json(conversation({ object_format: observed.object_format,
        after: Number(url.searchParams.get('after') ?? 0), limit: Number(url.searchParams.get('limit') ?? 5) }));
    }
    if (url.pathname.endsWith('/pulls')) return json(page({ object_format: observed.object_format,
      snapshot_token: observed.snapshot_token, pull_requests: [observed.pull_request] }));
    if (url.pathname.endsWith('/pulls/1')) return json(observed);
    if (url.pathname.endsWith('/reviews')) return json(reviews({ object_format: observed.object_format }));
    if (url.pathname.endsWith('/prepare')) return new Response(candidate.mixed(), { headers: { 'Content-Type': candidate.type } });
    if (url.pathname.endsWith('/inspect')) return json(candidate.inspection);
    throw new Error(`Unexpected API request ${url}`);
  };
  app = mountPulls(doc, { fetchImpl, cryptoImpl, downloadImpl() {} });
  node('object-format').value = observed.object_format; node('review-action').value = 'approve';
  const submit = id => node(id).dispatchEvent(new Event('submit', { cancelable: true }));
  const ready = async () => {
    await until(() => !app.client.busy && (!app.client.connected || !node('refresh').disabled));
    await setImmediate();
    while (digests.size) await Promise.all([...digests]);
    await setImmediate();
  };
  const load = async () => { assert.equal(node('comments-load').disabled, false); node('comments-load').click(); await ready(); };
  const next = async () => { button(node('comment-paging'), 'Next comments page').click(); await ready(); };
  const stage = async body => { node('comment-body').value = body; submit('comment-form'); await ready(); };
  const send = async () => {
    node('confirm').checked = true; node('confirm').dispatchEvent(new Event('change'));
    assert.equal(node('send').disabled, false); node('send').click(); await ready();
  };
  const prepare = async () => {
    node('policy-epoch').value = '1'; node('author').value = 'Test <test@example.invalid>';
    node('committer').value = 'Test <test@example.invalid>'; node('timestamp').value = '1';
    node('message').value = 'Exact candidate\n'; submit('prepare'); await ready();
    assert.ok(app.client.candidate, node('status').textContent);
  };
  node('token').value = token; submit('connection');
  await until(() => app.client.connected && !node('refresh').disabled && calls.length === 1);
  button(node('pr-list'), '#1').click(); await ready();
  assert.match(node('selected').textContent, /#1 ·/);
  return { ...app, doc, node, calls, ready, load, next, stage, send, prepare, submit };
}

test('explicit conversation reads select the latest head while retaining the selected PR pin', async t => {
  for (const format of ['sha1', 'sha256']) {
    const width = format === 'sha1' ? 40 : 64;
    const observed = show({ object_format: format, pull_request: row(1, { data: data({ object_format: format,
      source_tip: 'a'.repeat(width), target_tip: 'b'.repeat(width) }) }) });
    const h = await harness({ observed }); t.after(h.disconnect);
    assert.equal(h.node('token').value, ''); assert.equal(h.calls.length, 2);
    assert.equal(new URL(h.calls[1].url).searchParams.get('expected_head'), prHead);
    assert.equal(h.node('comment-stage').disabled, true); assert.equal(h.node('comment-body').disabled, true);
    const snapshot = h.node('snapshot').textContent, title = h.node('title').value;
    await h.load();
    const call = commentReads(h.calls)[0], query = new URL(call.url).searchParams;
    assert.equal(query.get('expected_head'), null, 'an old PR list pin must not hide newer discussion');
    assert.equal(query.get('after'), '0'); assert.equal(query.get('limit'), '5'); assert.equal(query.get('render'), 'html_safe');
    assert.equal(call.body, undefined); assert.equal(call.headers['Idempotency-Key'], undefined);
    assert.equal(h.node('snapshot').textContent, snapshot); assert.equal(h.node('title').value, title);
    assert.equal(h.node('expected-version').value, '1'); assert.equal(h.node('comment-version').value, '2');
    assert.ok(h.node('conversation').textContent.includes(conversationHead));
    assert.equal(h.node('comment-stage').disabled, false); assert.equal(h.node('comment-body').disabled, false);
    assert.equal(h.client.pending, null); assert.equal(h.client.candidate, null); assert.equal(writes(h.calls).length, 0);
  }
});

test('comment paging keeps its own exact snapshot and high water while preserving an unsubmitted draft', async t => {
  const h = await harness({ read: call => json(conversation({ discussion_version: 7,
    after: Number(new URL(call.url).searchParams.get('after')) })) }); t.after(h.disconnect);
  await h.load(); h.node('comment-body').value = 'Draft spanning two pages';
  assert.match(h.node('conversation').textContent, /Discussion entry 1/);
  assert.match(h.node('conversation').textContent, /More comments remain/);
  await h.next();
  const query = new URL(commentReads(h.calls).at(-1).url).searchParams;
  assert.equal(query.get('after'), '5'); assert.equal(query.get('expected_head'), conversationHead);
  assert.notEqual(query.get('expected_head'), prHead); assert.equal(query.get('limit'), '5');
  assert.match(h.node('conversation').textContent, /Discussion entry 6/);
  assert.doesNotMatch(h.node('conversation').textContent, /Discussion entry 1/);
  assert.equal(h.node('comment-paging').textContent, ''); assert.equal(h.node('comment-version').value, '7');
  assert.equal(h.node('comment-body').value, 'Draft spanning two pages');
  await h.stage(h.node('comment-body').value);
  assert.equal(h.client.pending.fields.expected_version, 7); assert.equal(writes(h.calls).length, 0);
});

test('an oversized conversation can be retried with a smaller page while draft, pin and continuation size stay exact', async t => {
  let reads = 0;
  const h = await harness({ read: call => {
    const query = new URL(call.url).searchParams; reads += 1;
    if (reads === 2) return new Response('', { status: 413 });
    return json(conversation({ after: Number(query.get('after')), limit: Number(query.get('limit')),
      discussion_version: reads === 5 ? 4 : 3, snapshot_token: reads === 5 ? changedHead : conversationHead }));
  } }); t.after(h.disconnect);
  assert.equal(h.node('comments-limit').value, '5'); await h.load();
  const selected = h.node('snapshot').textContent; h.node('comment-body').value = 'Draft kept across a bounded read refusal';
  await h.load();
  assert.match(h.node('conversation').textContent, /Conversation unavailable/);
  assert.equal(h.node('comment-version').value, ''); assert.equal(h.node('comment-paging').textContent, '');
  assert.equal(h.node('comment-stage').disabled, true); assert.equal(h.node('comments-limit').disabled, false);
  assert.equal(h.node('comment-body').value, 'Draft kept across a bounded read refusal');
  h.node('comments-limit').value = '1'; h.node('comments-limit').dispatchEvent(new Event('change'));
  assert.equal(reads, 2, 'changing the page size does not itself refresh the conversation');
  await h.load();
  const retry = new URL(commentReads(h.calls).at(-1).url).searchParams;
  assert.equal(retry.get('after'), '0'); assert.equal(retry.get('limit'), '1'); assert.equal(retry.get('expected_head'), null);
  assert.equal(h.node('comment-version').value, '3'); assert.match(h.node('conversation').textContent, /Discussion entry 1/);
  h.node('comments-limit').value = '20'; h.node('comments-limit').dispatchEvent(new Event('change'));
  assert.equal(reads, 3); await h.next();
  const next = new URL(commentReads(h.calls).at(-1).url).searchParams;
  assert.equal(next.get('after'), '1'); assert.equal(next.get('limit'), '1'); assert.equal(next.get('expected_head'), conversationHead);
  assert.match(h.node('conversation').textContent, /Discussion entry 2/);
  assert.doesNotMatch(h.node('conversation').textContent, /Discussion entry 1|Discussion entry 3/);
  assert.equal(h.node('comment-version').value, '3'); assert.equal(h.node('comments-limit').value, '20');
  await h.load();
  const latest = new URL(commentReads(h.calls).at(-1).url).searchParams;
  assert.equal(latest.get('after'), '0'); assert.equal(latest.get('limit'), '20'); assert.equal(latest.get('expected_head'), null);
  assert.equal(h.node('comment-version').value, '4'); assert.ok(h.node('conversation').textContent.includes(changedHead));
  assert.equal(h.node('comment-body').value, 'Draft kept across a bounded read refusal');
  assert.equal(h.node('snapshot').textContent, selected); assert.equal(h.client.pending, null); assert.equal(writes(h.calls).length, 0);
});

test('preparing stores exact body and discussion version locally until an explicitly confirmed send', async t => {
  const h = await harness(); t.after(h.disconnect); await h.load();
  const original = ' é\r\n<script>literal comment</script> \n', snapshot = h.node('snapshot').textContent;
  h.node('comment-version').value = '999';
  await h.stage(original); const saved = h.client.pending;
  assert.equal(saved.action, 'comment'); assert.equal(saved.fields.expected_version, 2);
  assert.equal(saved.fields.body, original); assert.equal(writes(h.calls).length, 0);
  assert.equal(h.node('confirm').checked, false); assert.equal(h.node('send').disabled, true);
  h.node('comment-body').value = 'Later editor text'; h.node('comment-version').value = '1000';
  h.node('expected-version').value = '30'; assert.deepEqual(h.client.pending, saved);
  // Exercise the handler as well as its disabled button against a synthetic click.
  h.node('send').dispatchEvent(new Event('click', { cancelable: true })); await h.ready();
  assert.match(h.node('status').textContent, /Explicitly confirm/); assert.equal(writes(h.calls).length, 0);
  await h.send();
  const call = writes(h.calls)[0], form = new URLSearchParams(call.bytes);
  assert.equal(call.headers['Idempotency-Key'], saved.key); assert.equal(form.get('expected_version'), '2');
  assert.equal(form.get('body'), original); assert.deepEqual([...form.keys()], ['expected_version', 'body']);
  assert.equal(h.client.pending, null); assert.match(h.node('status').textContent, /Canonical committed/);
  assert.equal(h.node('snapshot').textContent, snapshot); assert.equal(h.node('comment-version').value, '');
  assert.equal(h.node('comment-body').value, ''); assert.equal(h.node('comment-stage').disabled, true);
});

test('closed and merged native PRs retain explicit discussion controls without enabling merge preparation', async t => {
  for (const state of ['closed', 'merged']) {
    const metadata = data(), merge = state === 'merged' ? { ...metadata, target_tip_before: metadata.target_tip,
      base_tip: 'e'.repeat(40), merge_commit: 'd'.repeat(40) } : null;
    const h = await harness({ observed: show({ pull_request: row(1, { state, merge }) }) }); t.after(h.disconnect);
    assert.equal(h.node('prepare-candidate').disabled, true); assert.equal(h.node('fast-forward-stage').disabled, true);
    await h.load(); assert.equal(h.node('comment-stage').disabled, false);
    await h.stage(`Discuss this ${state} PR`); assert.equal(h.client.pending.action, 'comment');
    assert.equal(h.client.pending.fields.expected_version, 2); assert.equal(writes(h.calls).length, 0);
  }
});

test('hostile comment source and presentation stay inert while a valid source-bound presentation renders', async t => {
  const source = '**Review** <img src=x onerror=credential()>\u202e';
  const rendered = (body, html) => ({ renderer: 'fgit-doc', profile: 'html_safe',
    source_sha256: createHash('sha256').update(body).digest('hex'), parse_profile_sha256: 'a'.repeat(64), html, refusal: null });
  const hostile = '<script>steal token</script>';
  const h = await harness({ read: () => json(conversation({ comments: [
    comment(1, { body: source, body_rendered: rendered(source, '<p><strong>Review</strong> &lt;img src=x onerror=credential()&gt;\u202e</p>') }),
    comment(2, { body: hostile, body_rendered: rendered(hostile, '<script>steal token</script>') }),
  ] })) }); t.after(h.disconnect); await h.load();
  const text = h.node('conversation').textContent, elements = descendants(h.node('conversation'));
  assert.match(text, /Derived Markdown · fgit-doc html_safe/);
  assert.match(text, /<img src=x onerror=credential\(\)>/); assert.ok(text.includes('\\u{202e}'));
  assert.equal(text.includes('\u202e'), false); assert.equal(text.includes(token), false);
  assert.match(text, /Rendered presentation unavailable \(unsupported_element\)/);
  assert.match(text, /<script>steal token<\/script>/);
  assert.ok(elements.some(element => element.tagName === 'STRONG'));
  assert.equal(elements.some(element => ['SCRIPT', 'IMG', 'IFRAME', 'OBJECT', 'STYLE'].includes(element.tagName)), false);
  assert.equal(h.calls.length, 3, 'repository text never initiates an asset request');
});

test('stale or malformed continuation clears prior rows and writable version while preserving the draft and PR', async t => {
  for (const refusal of [() => new Response('', { status: 409 }),
    () => json(conversation({ discussion_version: 7, after: 5, snapshot_token: changedHead })),
    () => json(conversation({ discussion_version: 7, after: 5, comments: [comment(7), comment(6)] }))]) {
    let reads = 0;
    const h = await harness({ read: () => ++reads === 1 ? json(conversation({ discussion_version: 7 })) : refusal() });
    t.after(h.disconnect); await h.load(); const selected = h.node('selected').textContent, snapshot = h.node('snapshot').textContent;
    h.node('comment-body').value = 'Retain my draft'; await h.next();
    assert.match(h.node('conversation').textContent, /Conversation unavailable/);
    assert.doesNotMatch(h.node('conversation').textContent, /Discussion entry/);
    assert.equal(h.node('comment-version').value, ''); assert.equal(h.node('comment-paging').textContent, '');
    assert.equal(h.node('comment-stage').disabled, true); assert.equal(h.node('comment-body').disabled, true);
    assert.equal(h.node('comment-body').value, 'Retain my draft'); assert.equal(h.node('selected').textContent, selected);
    assert.equal(h.node('snapshot').textContent, snapshot); assert.equal(h.client.connected, true);
    h.submit('comment-form'); await h.ready(); assert.equal(h.client.pending, null);
    assert.match(h.node('status').textContent, /Load the selected PR conversation first/); assert.equal(writes(h.calls).length, 0);
  }
});

test('an existing empty discussion permits its first comment while unavailable discussion discloses no writable version', async t => {
  const empty = await harness({ read: () => json(conversation({ discussion_version: 0 })) }); t.after(empty.disconnect);
  await empty.load(); assert.match(empty.node('conversation').textContent, /No comments at this snapshot/);
  assert.equal(empty.node('comment-version').value, '0'); await empty.stage('First comment');
  assert.equal(empty.client.pending.fields.expected_version, 0);
  const missing = await harness({ read: () => json(conversation({ found: false, source_head: null,
    snapshot_token: null, discussion_version: null, comments: [] }), 404) }); t.after(missing.disconnect);
  await missing.load(); assert.match(missing.node('conversation').textContent, /absent or not disclosed/);
  assert.doesNotMatch(missing.node('conversation').textContent, /No comments|Conversation version/);
  assert.equal(missing.node('comment-version').value, ''); assert.equal(missing.node('comment-stage').disabled, true);
  assert.equal(missing.client.pending, null);
});

test('credential rejection clears private conversation, draft and PR views instead of presenting an empty page', async t => {
  let reads = 0;
  const h = await harness({ read: () => ++reads === 1 ? json(conversation()) : new Response('', { status: 401 }) });
  t.after(h.disconnect); await h.load(); h.node('comment-body').value = 'Private unsent draft'; await h.load();
  assert.equal(h.client.connected, false); assert.equal(h.client.binding, null); assert.equal(h.node('token').value, '');
  for (const id of ['selected', 'snapshot', 'conversation', 'comment-paging']) assert.equal(h.node(id).textContent, '', id);
  for (const id of ['title', 'body', 'comment-body', 'comment-version']) assert.equal(h.node(id).value, '', id);
  assert.equal(h.node('comment-stage').disabled, true); assert.match(h.node('status').textContent, /Credential rejected/);
});

test('disconnect aborts a late conversation read and clears views without replacing a prepared comment', async t => {
  const late = deferred(); let reads = 0;
  const h = await harness({ read: () => ++reads === 1 ? json(conversation()) : late.promise }); t.after(h.disconnect);
  await h.load(); await h.stage('Saved original comment'); const original = h.client.pending;
  h.node('comments-load').click(); await until(() => commentReads(h.calls).length === 2);
  const request = commentReads(h.calls).at(-1); assert.match(h.node('conversation').textContent, /Loading conversation/);
  h.disconnect(); late.resolve(json(conversation({ discussion_version: 3 }))); await h.ready();
  assert.equal(request.signal.aborted, true); assert.equal(h.client.connected, false); assert.equal(h.client.binding, null);
  assert.deepEqual(h.client.pending, original); assert.equal(writes(h.calls).length, 0);
  for (const id of ['selected', 'snapshot', 'conversation', 'comment-paging']) assert.equal(h.node(id).textContent, '', id);
  assert.equal(h.node('comment-body').value, ''); assert.equal(h.node('comment-version').value, '');
  assert.equal(h.node('token').value, ''); assert.match(h.node('status').textContent, /Disconnected.*Original request retained/);
});

test('committed and refused comment terminals preserve the inspected candidate and existing review display', async t => {
  for (const outcome of ['committed', 'refused']) {
    const h = await harness({ dispatch: (_call, pending) => json(terminal(pending, outcome), outcome === 'committed' ? 200 : 409) });
    t.after(h.disconnect); await h.prepare(); await h.loadReviews(); await h.ready(); await h.load();
    h.node('required-reviewers').value = '4'.repeat(32);
    const candidate = h.client.candidate, candidateText = h.node('candidate').textContent,
      reviewsText = h.node('reviews').textContent, selectedText = h.node('selected').textContent;
    await h.stage('Conversation alongside inspection'); await h.send();
    assert.equal(h.client.pending, null); assert.deepEqual(h.client.candidate, candidate);
    assert.equal(h.node('candidate').textContent, candidateText); assert.equal(h.node('reviews').textContent, reviewsText);
    assert.equal(h.node('selected').textContent, selectedText); assert.equal(h.node('required-reviewers').value, '4'.repeat(32));
    assert.equal(h.node('review-stage').disabled, false); assert.equal(h.node('merge-stage').disabled, false);
    assert.equal(h.node('comment-version').value, ''); assert.equal(h.node('comment-stage').disabled, true);
    assert.equal(h.node('comment-body').value, outcome === 'committed' ? '' : 'Conversation alongside inspection');
    assert.match(h.node('status').textContent, new RegExp(`Canonical ${outcome}`));
    assert.equal(writes(h.calls).length, 1); assert.equal(h.node('confirm').checked, false);
  }
});
