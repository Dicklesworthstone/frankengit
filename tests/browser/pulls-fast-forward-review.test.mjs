// Browser module contracts with injected HTTP. Commit bytes are hashed here;
// native ancestry validation is a test double, not a live-node/browser proof.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { inspectionReply } from '../../crates/fgit-node/src/smart_http/server/browser/pulls-candidate.mjs';
import { PullClient } from '../../crates/fgit-node/src/smart_http/server/browser/pulls.mjs';
import { mountPulls } from '../../crates/fgit-node/src/smart_http/server/browser/pulls-view.mjs';
import { fixture, terminal } from './pulls-candidate-fixtures.mjs';
import { token, reviewer, page, json, options, webcrypto } from './pulls-fixtures.mjs';
import { fakeDocument, until, terminal as fastForwardTerminal } from './helpers/pulls-workflow-fixture.mjs';

function fastForwardFixture(algorithm, { parents, uppercase = false, extraHeaders = '', message = 'Existing source commit\n',
  separator = true, finalNewline = true, parentsLast = false } = {}) {
  const sample = fixture(algorithm), width = algorithm === 'sha1' ? 40 : 64;
  const actualParents = parents ?? ['c'.repeat(width)];
  const parentHeaders = actualParents.map(parent => `parent ${uppercase ? parent.toUpperCase() : parent}\n`).join('');
  const identities = 'author Test <test@example.invalid> 1 +0000\ncommitter Test <test@example.invalid> 1 +0000\n';
  const headers = `tree ${'f'.repeat(width)}\n${parentsLast ? identities + parentHeaders : parentHeaders + identities}${extraHeaders}`;
  const body = Buffer.from(separator ? `${headers}\n${message}` : finalNewline ? headers : headers.slice(0, -1));
  const source = createHash(algorithm).update(`commit ${body.length}\0`).update(body).digest('hex');
  const bundle = new Uint8Array(Buffer.concat([
    Buffer.from(`# ${algorithm === 'sha1' ? 'v2' : 'v3'} git bundle\n${source} refs/heads/candidate\n\nPACK`), Buffer.from([0, 255, 13, 10]),
  ]));
  const sha256 = createHash('sha256').update(bundle).digest('hex');
  const fields = { ...sample.fields, source_tip: source, merge_base: sample.fields.target_tip, candidate_commit: source };
  const artifact = { ...sample.artifact, fields, bundle, sha256 };
  const inspection = { ...sample.inspection, subject: { ...sample.inspection.subject, source_tip: source },
    merge_base: fields.merge_base, candidate_commit: source, parents: actualParents,
    candidate_commit_body_hex: body.toString('hex'),
    bundle: { ...sample.inspection.bundle, bytes: bundle.length, sha256, expanded_bytes: body.length },
    comparison: { ...sample.inspection.comparison, after: source } };
  return { artifact, inspection };
}
function receipt(artifact) {
  return JSON.stringify({ schema: 'frankengit-browser-candidate-v1', number: artifact.number,
    scope: artifact.scope, fields: artifact.fields, bundle_base64: Buffer.from(artifact.bundle).toString('base64'), sha256: artifact.sha256 });
}

for (const algorithm of ['sha1', 'sha256']) {
  test(`${algorithm} exact fast-forward inspection permits a source parent different from the target`, async () => {
    const sample = fastForwardFixture(algorithm), { fields } = sample.artifact;
    assert.equal(fields.candidate_commit, fields.source_tip);
    assert.equal(fields.merge_base, fields.target_tip);
    assert.notEqual(sample.inspection.parents[0], fields.target_tip);
    const result = await inspectionReply(sample.inspection, sample.artifact, webcrypto);
    assert.deepEqual(result.reply.parents, sample.inspection.parents);
    assert.equal(result.reply.comparison.before, fields.target_tip);
    assert.equal(result.reply.comparison.after, fields.source_tip);
    assert.equal(result.reply.merge_authorized, false);
  });

  test(`${algorithm} native parent metadata must match the exact fast-forward commit bytes`, async () => {
    const sample = fastForwardFixture(algorithm), width = algorithm === 'sha1' ? 40 : 64;
    for (const parents of [[], ['d'.repeat(width)], [sample.artifact.fields.target_tip, sample.artifact.fields.source_tip],
      [sample.inspection.parents[0], sample.inspection.parents[0]], [`${algorithm === 'sha1' ? 'sha256' : 'sha1'}:${'d'.repeat(width)}`]]) {
      await assert.rejects(inspectionReply({ ...sample.inspection, parents }, sample.artifact, webcrypto));
    }
    await assert.rejects(inspectionReply({ ...sample.inspection,
      candidate_commit_body_hex: sample.inspection.candidate_commit_body_hex + '20' }, sample.artifact, webcrypto), /object identity/);
    await inspectionReply(sample.inspection, sample.artifact, webcrypto);
  });

  test(`${algorithm} imported source commits retain separator-free and unterminated final-header compatibility`, async () => {
    for (const finalNewline of [true, false]) {
      const sample = fastForwardFixture(algorithm, { separator: false, finalNewline, parentsLast: true });
      const result = await inspectionReply(sample.inspection, sample.artifact, webcrypto);
      assert.deepEqual(result.reply.parents, sample.inspection.parents);
      const wrong = { ...sample.inspection, parents: ['d'.repeat(algorithm === 'sha1' ? 40 : 64)] };
      await assert.rejects(inspectionReply(wrong, sample.artifact, webcrypto), /native candidate commit bytes/);
    }
  });

  test(`${algorithm} fast-forward requires the exact target base and distinct tips`, async () => {
    const original = fastForwardFixture(algorithm), width = algorithm === 'sha1' ? 40 : 64;
    for (const change of [
      sample => {
        sample.artifact.fields.merge_base = 'e'.repeat(width);
        sample.inspection.merge_base = sample.artifact.fields.merge_base;
      },
      sample => {
        const source = sample.artifact.fields.source_tip;
        sample.artifact.fields.target_tip = source;
        sample.artifact.fields.merge_base = source;
        sample.inspection.subject.target_tip = source;
        sample.inspection.merge_base = source;
        sample.inspection.comparison.before = source;
      },
    ]) {
      const sample = structuredClone(original); change(sample);
      await assert.rejects(inspectionReply(sample.inspection, sample.artifact, webcrypto), /identities changed/);
    }
    await inspectionReply(original.inspection, original.artifact, webcrypto);
  });

  test(`${algorithm} merge candidates retain the ordered two-parent contract`, async () => {
    const sample = fixture(algorithm);
    assert.notEqual(sample.fields.candidate_commit, sample.fields.source_tip);
    await inspectionReply(sample.inspection, sample.artifact, webcrypto);
    for (const parents of [[sample.fields.target_tip], [...sample.inspection.parents].reverse(),
      [...sample.inspection.parents, sample.fields.target_tip]]) {
      await assert.rejects(inspectionReply({ ...sample.inspection, parents }, sample.artifact, webcrypto), /identities changed/);
    }
  });

  test(`${algorithm} fast-forward reviews import, inspect and retry with the same immutable request`, async () => {
    const sample = fastForwardFixture(algorithm), calls = []; let sends = 0;
    const client = new PullClient(options((url, init) => {
      calls.push({ url: String(url), ...init });
      const path = new URL(url).pathname;
      if (path.endsWith('/api/v1/pulls')) return json(page({ object_format: algorithm, pull_requests: [] }));
      if (path.endsWith('/inspect')) return json(sample.inspection);
      assert.ok(path.endsWith('/reviews/approve'));
      if (++sends === 1) throw new Error('connection lost after possible commit');
      return json(terminal(client.pending));
    }));
    await client.connect(token); await client.list();
    await client.importCandidate(receipt(sample.artifact));
    assert.deepEqual(client.candidate.inspection.parents, sample.inspection.parents);
    assert.equal(client.pending, null);
    assert.equal(calls.at(-1).headers['Idempotency-Key'], undefined);
    await client.stageReview('approve', 0, 'Reviewed the exact existing source commit');
    assert.equal(client.pending.fields.candidate_commit, sample.artifact.fields.source_tip);
    assert.equal(client.pending.fields.merge_base, sample.artifact.fields.target_tip);
    const key = client.pending.key;
    await assert.rejects(client.send(), error => error.outcomeUnknown === true);
    assert.equal(client.pending.key, key);
    assert.throws(() => client.discardUnsent());
    const external = client.pending; external.fields.candidate_commit = 'f'.repeat(algorithm === 'sha1' ? 40 : 64);
    assert.equal(client.pending.fields.candidate_commit, sample.artifact.fields.source_tip);
    assert.equal((await client.send()).outcome, 'committed');
    const writes = calls.filter(call => call.headers['Idempotency-Key']);
    assert.equal(writes.length, 2);
    assert.equal(writes[0].headers['Idempotency-Key'], key);
    assert.equal(writes[1].headers['Idempotency-Key'], key);
    assert.equal(writes[0].headers['Content-Type'], writes[1].headers['Content-Type']);
    assert.deepEqual(await writes[0].body.arrayBuffer(), await writes[1].body.arrayBuffer());
    assert.equal(client.pending, null);
  });

  test(`${algorithm} inspected fast-forward and constructed merge require their explicit publication methods`, async () => {
    for (const fastForward of [true, false]) {
      const sample = fastForward ? fastForwardFixture(algorithm) : fixture(algorithm), calls = [];
      const client = new PullClient(options((url, init) => {
        calls.push({ url: String(url), ...init });
        if (new URL(url).pathname.endsWith('/pulls')) return json(page({ object_format: algorithm, pull_requests: [] }));
        assert.ok(String(url).endsWith('/inspect')); return json(sample.inspection);
      }));
      await client.connect(token); await client.list();
      await client.inspect(1, sample.artifact.fields, sample.artifact.bundle);
      if (fastForward) {
        await assert.rejects(client.stageMerge([reviewer]), /explicit fast-forward publication/);
        assert.equal(client.pending, null);
        await client.stageInspectedFastForward();
        assert.equal(client.pending.action, 'fast-forward');
        assert.equal(client.pending.bundle_bytes, 0);
        assert.deepEqual(Object.keys(client.pending.fields).sort(),
          ['object_format', 'pull_request_version', 'source_ref', 'source_tip', 'target_ref', 'target_tip']);
        assert.equal(client.pending.fields.source_tip, sample.artifact.fields.candidate_commit);
        assert.equal(client.pending.fields.target_tip, sample.artifact.fields.merge_base);
      } else {
        await assert.rejects(client.stageInspectedFastForward(), /inspected source tip/);
        assert.equal(client.pending, null);
        await client.stageMerge([reviewer]);
        assert.equal(client.pending.action, 'merge');
        assert.equal(client.pending.bundle_bytes, sample.artifact.bundle.length);
        assert.deepEqual(client.pending.fields.required_reviewer, [reviewer]);
      }
      assert.equal(calls.length, 2, 'method selection only prepares an immutable local request');
      assert.ok(calls.every(call => call.headers['Idempotency-Key'] === undefined));
      client.disconnect();
    }
  });

  test(`${algorithm} the candidate form labels and stages explicit fast-forward from inspected coordinates`, async () => {
    const sample = fastForwardFixture(algorithm), doc = fakeDocument(), calls = [];
    const ui = mountPulls(doc, { cryptoImpl: webcrypto, fetchImpl: (url, init) => {
      calls.push({ url: String(url), ...init });
      const path = new URL(url).pathname;
      if (path.endsWith('/pulls')) return json(page({ object_format: algorithm, pull_requests: [] }));
      if (path.endsWith('/inspect')) return json(sample.inspection);
      assert.ok(path.endsWith('/fast-forward'), 'publication must use the explicit fast-forward endpoint');
      return json(fastForwardTerminal({ reply: { ...sample.inspection, number: 1 } }, ui.client.pending.fields));
    } });
    const node = id => doc.getElementById(id);
    await ui.client.connect(token); await ui.loadList();
    const bytes = new TextEncoder().encode(receipt(sample.artifact));
    node('candidate-import-file').files = [{ size: bytes.length, arrayBuffer: async () => bytes.buffer }];
    node('candidate-import').dispatchEvent(new Event('submit', { cancelable: true }));
    await until(() => ui.client.candidate && node('merge-stage').disabled === false);
    assert.equal(node('merge-heading').textContent, 'Fast-forward inspected source');
    assert.equal(node('merge-stage').textContent, 'Prepare fast-forward — do not send');
    assert.equal(node('merge-reviewer-fields').hidden, true);
    assert.equal(node('required-reviewers').disabled, true);
    assert.equal(node('required-reviewers').required, false);
    assert.match(node('merge-method-guidance').textContent, /Current branch protection determines required approvals/);
    assert.match(node('candidate').textContent, /Native parents:/);
    assert.doesNotMatch(node('candidate').textContent, /Parents \(target, source\)/);
    node('source-tip').value = 'f'.repeat(algorithm === 'sha1' ? 40 : 64);
    node('pr-number').value = '99'; node('required-reviewers').value = reviewer;
    node('confirm').checked = true;
    const reads = calls.length;
    node('merge').dispatchEvent(new Event('submit', { cancelable: true }));
    await until(() => ui.client.pending && !ui.client.busy);
    const pending = ui.client.pending;
    assert.equal(pending.action, 'fast-forward'); assert.equal(pending.number, 1);
    assert.equal(pending.fields.source_tip, sample.artifact.fields.source_tip);
    assert.equal(pending.fields.pull_request_version, sample.artifact.fields.pull_request_version);
    assert.equal(pending.fields.target_tip, sample.artifact.fields.target_tip);
    assert.equal(pending.bundle_bytes, 0);
    assert.equal(node('confirm').checked, false);
    assert.equal(calls.length, reads);
    node('send').dispatchEvent(new Event('click', { cancelable: true }));
    await until(() => /confirm/.test(node('status').textContent));
    assert.equal(calls.length, reads);
    node('confirm').checked = true; node('confirm').dispatchEvent(new Event('change'));
    node('send').click();
    await until(() => /Canonical committed/.test(node('status').textContent));
    const writes = calls.filter(call => call.headers['Idempotency-Key']);
    assert.equal(writes.length, 1);
    assert.equal(writes[0].headers['Idempotency-Key'], pending.key);
    assert.equal(writes[0].headers['Content-Type'], 'application/x-www-form-urlencoded');
    assert.equal(new URLSearchParams(await writes[0].body.text()).has('required_reviewer'), false);
    assert.equal(ui.client.pending, null); ui.disconnect();
  });
}

test('native parent binding ignores signature continuation and message text while preserving parent order', async () => {
  const parents = ['c'.repeat(40), 'd'.repeat(40), 'e'.repeat(40)];
  const sample = fastForwardFixture('sha1', { parents, uppercase: true,
    extraHeaders: `gpgsig signature\n parent ${'1'.repeat(40)}\n`, message: `parent ${'2'.repeat(40)}\n` });
  const result = await inspectionReply(sample.inspection, sample.artifact, webcrypto);
  assert.deepEqual(result.reply.parents, parents);
  await assert.rejects(inspectionReply({ ...sample.inspection, parents: [...parents].reverse() }, sample.artifact, webcrypto), /native candidate commit bytes/);
});

test('a native fast-forward inspection refusal leaves no candidate or review request', async () => {
  const sample = fastForwardFixture('sha1'), calls = [];
  const client = new PullClient(options((url, init) => {
    calls.push({ url: String(url), ...init });
    return new URL(url).pathname.endsWith('/api/v1/pulls') ? json(page({ pull_requests: [] }))
      : json({ code: 'NonFastForwardRefused' }, 409);
  }));
  await client.connect(token); await client.list();
  await assert.rejects(client.inspect(1, sample.artifact.fields, sample.artifact.bundle));
  assert.equal(client.candidate, null);
  await assert.rejects(client.stageReview('approve', 0, 'not inspected'));
  assert.equal(client.pending, null);
  assert.equal(calls.length, 2);
  assert.ok(calls.every(call => call.headers['Idempotency-Key'] === undefined));
});
