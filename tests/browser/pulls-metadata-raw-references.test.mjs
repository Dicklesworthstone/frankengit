// Exercises the shipped HTML, controller, request codec and recovery with a
// controlled DOM/HTTP boundary; native admission remains a separate test lane.
import test from 'node:test';
import assert from 'node:assert/strict';
import { webcrypto } from 'node:crypto';
import { mountPulls } from '../../crates/fgit-node/src/smart_http/server/browser/pulls-view.mjs';
import { fakeDocument, observation, response, missingOutcome, token, until } from './helpers/pulls-workflow-fixture.mjs';

const rawRef = (side) => Buffer.concat([Buffer.from('refs/heads/' + side + '+&%'), Buffer.from([side === 'source' ? 0xff : 0xfe])]).toString('hex');
function sample(format, source = 'hex', target = 'hex') {
  const observed = observation(format);
  for (const [side, encoding] of [['source', source], ['target', target]]) if (encoding === 'hex') {
    observed.reply.pull_request.data[side + '_ref'] = null;
    observed.reply.pull_request.data[side + '_ref_hex'] = rawRef(side);
  }
  return observed;
}
function publication(observed, action, fields, outcome = 'committed') {
  return { schema_version: 1, type: 'pull_request_publication',
    tenant_id: observed.binding.tenant, repository_id: observed.binding.repository,
    repository_incarnation: observed.binding.incarnation, object_format: observed.binding.format,
    principal_id: '66'.repeat(16), number: observed.reply.number, action,
    expected_version: Number(fields.expected_version), tx_id: 'metadata-transaction',
    decision_sequence: 4, outcome, repository_commit_id: outcome === 'committed' ? 'metadata-rcr' : null,
    refusal_record_id: outcome === 'refused' ? 'metadata-refusal' : null,
    refusal_code: outcome === 'refused' ? 'ExpectedVersionMismatch' : null,
    refusal_code_point: outcome === 'refused' ? 1 : null, delivery_acknowledged: null };
}
async function harness(observed, dispatch = null) {
  const doc = fakeDocument(), calls = [], downloads = [];
  const app = mountPulls(doc, { cryptoImpl: webcrypto,
    downloadImpl: (name, text) => downloads.push({ name, text }),
    fetchImpl: async (url, options) => {
      const call = { url: String(url), ...options, bytes: options.body === undefined ? null
        : typeof options.body === 'string' ? options.body : await options.body.text() };
      calls.push(call);
      if (url.pathname.endsWith('/outcomes')) return response(missingOutcome(observed));
      if (options.method === 'POST') return dispatch ? dispatch(call)
        : response(publication(observed, url.pathname.split('/').at(-1), Object.fromEntries(new URLSearchParams(call.bytes))));
      if (url.pathname.endsWith('/pulls/' + observed.reply.number)) return response(observed.reply);
      throw new Error('Unexpected fixture request: ' + url);
    } });
  const node = id => { const found = doc.getElementById(id); assert.ok(found, id); return found; };
  const submit = id => node(id).dispatchEvent(new Event('submit', { cancelable: true }));
  await app.client.connect(token); await app.loadPr(observed.reply.number);
  async function stage(action = 'update') {
    node('metadata-action').value = action; submit('metadata');
    await until(() => app.client.pending && !app.client.busy, 'metadata staged');
    return app.client.pending;
  }
  async function send() {
    node('confirm').checked = true; node('confirm').dispatchEvent(new Event('change')); node('send').click();
    await until(() => !app.client.busy, 'metadata dispatch settled');
  }
  return { ...app, doc, node, submit, calls, downloads, stage, send };
}
function assertReferences(fields, data, source, target) {
  for (const [side, encoding] of [['source', source], ['target', target]]) {
    const name = side + '_ref', key = encoding === 'hex' ? name + '_hex' : name;
    assert.equal(fields[key], data[key]);
    assert.equal(Object.hasOwn(fields, encoding === 'hex' ? name : name + '_hex'), false);
  }
}

for (const format of ['sha1', 'sha256']) for (const [source, target] of [['hex', 'text'], ['text', 'hex'], ['hex', 'hex']]) {
  for (const action of ['update', 'close', 'reopen', 'retarget', 'open']) {
    test(format + ' ' + source + '/' + target + ': browser ' + action + ' preserves exact branch bytes', async () => {
      const observed = sample(format, source, target), before = structuredClone(observed), data = observed.reply.pull_request.data;
      if (action === 'reopen') observed.reply.pull_request.state = 'closed';
      const h = await harness(observed);
      for (const [side, encoding] of [['source', source], ['target', target]]) {
        assert.equal(h.node(side + '-ref-encoding').value, encoding);
        assert.equal(h.node(side + '-ref').value, data[side + '_ref' + (encoding === 'hex' ? '_hex' : '')]);
      }
      if (action === 'open') {
        h.node('new-pr').click();
        assert.equal(h.node('source-ref-encoding').value, 'text');
        assert.equal(h.node('target-ref-encoding').value, 'text');
        h.node('pr-number').value = String(observed.reply.number);
        for (const [side, encoding] of [['source', source], ['target', target]]) {
          h.node(side + '-ref-encoding').value = encoding;
          h.node(side + '-ref').value = data[side + '_ref' + (encoding === 'hex' ? '_hex' : '')];
          h.node(side + '-tip').value = data[side + '_tip'].split(':')[1];
        }
        h.node('title').value = data.title; h.node('body').value = data.body;
      }
      let selectedData = data;
      if (action === 'retarget') {
        const name = target === 'hex' ? 'target_ref_hex' : 'target_ref';
        selectedData = { ...data, [name]: target === 'hex' ? rawRef('target') + '61' : 'refs/heads/release' };
        h.node('target-ref').value = selectedData[name];
      }
      const reads = h.calls.length, pending = await h.stage(action);
      assert.equal(h.calls.length, reads, 'preparation cannot dispatch');
      assert.equal(pending.fields.expected_version, action === 'open' ? 0 : 3);
      assert.equal(pending.fields.object_format, format); assert.equal(pending.bundle_bytes, 0);
      assertReferences(pending.fields, selectedData, source, target);
      assert.equal(h.node('confirm').checked, false);
      assert.equal(h.node('send').disabled, true);
      h.node('source-ref').value = 'refs/heads/other-after-staging';
      h.node('source-ref-encoding').value = 'text';
      await h.send();
      assert.equal(h.client.pending, null, 'matched receipt consumes the exact command');
      const write = h.calls.find(call => call.method === 'POST');
      assert.ok(write.url.endsWith('/pulls/' + observed.reply.number + '/' + action));
      const form = Object.fromEntries(new URLSearchParams(write.bytes));
      assertReferences(form, selectedData, source, target);
      assert.equal(form.title, data.title); assert.equal(form.body, data.body);
      assert.equal(write.headers['Idempotency-Key'], pending.key);
      assert.equal(write.headers.Authorization, 'Bearer ' + token);
      assert.deepEqual(observed.reply.pull_request.data, before.reply.pull_request.data);
      h.disconnect();
    });
  }
}

test('invalid encodings and branch bytes refuse locally without a saved mutation', async () => {
  const invalid = [
    ['other', rawRef('source')], ['', rawRef('source')], ['hex', ''], ['hex', 'f'],
    ['hex', rawRef('source').toUpperCase()], ['hex', '726566732f68656164732f00'],
    ['hex', Buffer.from('refs/heads/../escape').toString('hex')],
    ['hex', Buffer.from('refs/tags/topic').toString('hex')],
    ['hex', Buffer.from('refs/heads/' + 'a'.repeat(1014)).toString('hex')],
    ['text', 'refs/heads/' + String.fromCharCode(0xfffd, 0xd800)],
  ];
  for (const [encoding, value] of invalid) {
    const h = await harness(sample('sha1')), reads = h.calls.length;
    h.node('source-ref-encoding').value = encoding; h.node('source-ref').value = value;
    h.submit('metadata'); await until(() => !h.client.busy);
    assert.equal(h.client.pending, null, encoding + ':' + value);
    assert.equal(h.calls.length, reads);
    h.disconnect();
  }
  const h = await harness(sample('sha1'));
  h.node('source-ref-encoding').value = 'text'; h.node('source-ref').value = 'refs/heads/main';
  h.node('target-ref-encoding').value = 'hex'; h.node('target-ref').value = Buffer.from('refs/heads/main').toString('hex');
  h.submit('metadata'); await until(() => !h.client.busy);
  assert.equal(h.client.pending, null, 'alias spelling does not make the same branch distinct');
  h.disconnect();
});

test('lost byte-name metadata reply retains exact aliases, bytes and key through export, recovery and retry', async () => {
  const observed = sample('sha256'); let writes = 0;
  const dispatch = call => {
    if (++writes === 1) throw new Error('lost after transmission');
    return response(publication(observed, 'update', Object.fromEntries(new URLSearchParams(call.bytes))));
  };
  const original = await harness(observed, dispatch), pending = await original.stage();
  await original.send(); assert.equal(original.client.pending.key, pending.key);
  assert.equal(original.client.pending.sent, true);
  original.node('receipt-download').click(); await until(() => original.downloads.length === 1);
  const saved = original.downloads[0].text;
  assert.equal(saved.includes(token), false);
  original.disconnect();
  const restored = await harness(observed, dispatch);
  restored.node('receipt-import-file').files = [new File([saved], 'metadata-retry.json')];
  restored.submit('receipt-import');
  await until(() => restored.client.pending && !restored.client.busy);
  assert.equal(restored.client.pending.key, pending.key); assert.equal(writes, 1);
  restored.node('recover').click();
  await until(() => !restored.client.busy);
  assert.equal(restored.client.pending.key, pending.key); assert.equal(writes, 1);
  await restored.send();
  assert.equal(restored.client.pending, null); assert.equal(writes, 2);
  const first = original.calls.find(call => call.url.endsWith('/update'));
  const retry = restored.calls.find(call => call.url.endsWith('/update'));
  assert.equal(first.bytes, retry.bytes);
  assert.equal(first.headers['Idempotency-Key'], retry.headers['Idempotency-Key']);
  restored.disconnect();
});

test('switching raw and text PR observations resets encodings without retaining another command', async () => {
  const observed = sample('sha1'), h = await harness(observed);
  const original = observation('sha1');
  observed.reply.pull_request = original.reply.pull_request;
  await h.loadPr(observed.reply.number);
  assert.equal(h.node('source-ref-encoding').value, 'text');
  assert.equal(h.node('target-ref-encoding').value, 'text');
  assert.equal(h.node('source-ref').value, original.reply.pull_request.data.source_ref);
  assert.equal(h.node('target-ref').value, original.reply.pull_request.data.target_ref);
  h.disconnect();
  assert.equal(h.node('source-ref').value, '');
  assert.equal(h.node('target-ref').value, '');
});

test('ordinary text metadata keeps its existing form bytes', async () => {
  const observed = observation('sha1'), h = await harness(observed);
  const pending = await h.stage();
  await h.send();
  const form = new URLSearchParams();
  for (const [name, value] of Object.entries({ expected_version: 3, object_format: 'sha1',
    source_ref: observed.reply.pull_request.data.source_ref, target_ref: observed.reply.pull_request.data.target_ref,
    source_tip: 'a'.repeat(40), target_tip: 'b'.repeat(40), title: observed.reply.pull_request.data.title,
    body: observed.reply.pull_request.data.body })) form.append(name, String(value));
  assert.equal(h.calls.find(call => call.method === 'POST').bytes, form.toString());
  assert.equal(pending.bundle_bytes, 0);
  h.disconnect();
});

