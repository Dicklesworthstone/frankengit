// Real acquisition clients and independently framed Git objects over HTTP peers.
// Native grant enforcement and credential lifetime belong to the Rust HTTP tests.
import test from 'node:test';
import assert from 'node:assert/strict';
import { webcrypto } from 'node:crypto';
import { Transport } from '../../crates/fgit-node/src/smart_http/server/browser/pulls-core.mjs';
import { captureSourcePackage, inspectSourcePackage } from '../../scripts/operator/source_package.mjs';
import { captureContextProof, inspectContextProof } from '../../scripts/operator/source_context_proof.mjs';
import { captureSource, sha256, ARCHIVE_LIMITS } from '../../scripts/operator/source_archive.mjs';
import { SourceReader } from '../../scripts/operator/source_archive_transport.mjs';
import { buildSourceArchive, inspectSourceArchive } from '../../scripts/operator/source_archive_tar.mjs';
import { fixture as packageFixture, peer as packagePeer } from '../../scripts/tests/source_package_fixture.mjs';
import { setup, bytes } from './source_context_proof_fixtures.mjs';

const AGENT = 'fgagent_' + 'a'.repeat(64);
function archiveCalls(calls, selected, head) {
  assert.ok(calls.length > 1);
  assert.equal(calls[0].operation, 'commit');
  assert.deepEqual([...calls[0].form.keys()].sort(), ['expected_commit', 'expected_head', 'object_format', 'ref']);
  for (const call of calls) {
    assert.ok(['commit', 'tree', 'blob'].includes(call.operation));
    assert.equal(call.headers.authorization, 'Bearer ' + AGENT);
    assert.equal(call.headers['idempotency-key'], undefined);
    assert.equal(call.headers.cookie, undefined);
    assert.equal(call.form.get('expected_commit'), selected.expected_commit);
    assert.equal(call.form.get('expected_head'), head);
  }
}
for (const format of ['sha1', 'sha256']) {
  test(`${format}: sponsored selected package verifies complete bytes offline without ancestry access`, async t => {
    const parents = ['d', 'e'].map(value => value.repeat(format === 'sha1' ? 40 : 64));
    const p = await packagePeer(t, packageFixture(format, { parents }), undefined, { token: AGENT });
    const result = await captureSourcePackage(p.context, p.contextHash, p.selected, p.expected, AGENT);
    const count = p.requests.length;
    assert.deepEqual(await inspectSourcePackage(result.bytes, result.receipt.package_sha256,
      p.context, p.contextHash, p.selected, p.expected), result.receipt);
    assert.equal(p.requests.length, count);
    assert.equal(result.receipt.context_excerpt_bytes_verified, true);
    assert.equal(result.receipt.remote_mutation_attempted, false);
    assert.equal(result.receipt.source_executed, false);
    assert.ok(!result.bytes.includes(Buffer.from(AGENT)));
    assert.ok(!JSON.stringify(result.receipt).includes(AGENT));
    assert.equal(p.requests[0].path, '/repo/api/v1/source/commit');
    assert.deepEqual([...p.requests[0].form.keys()].sort(), ['expected_commit', 'expected_head', 'object_format', 'ref']);
    for (const call of p.requests) {
      assert.match(call.path, /^\/repo\/api\/v1\/source\/(commit|tree|blob)$/);
      assert.equal(call.req.headers.authorization, 'Bearer ' + AGENT);
      assert.equal(call.req.headers['idempotency-key'], undefined);
      assert.equal(call.req.headers.cookie, undefined);
      assert.equal(call.form.get('expected_head'), p.selected.expected_head);
      assert.equal(call.form.get('expected_commit'), p.selected.expected_commit);
    }
  });
  test(`${format}: sponsored context proof and full archive keep portable verification independent of the credential`, async t => {
    const f = await setup(t, format, undefined, { token: AGENT });
    const selected = { ...f.selection, expected_head: f.repo.snapshot }, context = bytes(f.context);
    const proof = await captureContextProof(context, sha256(context), selected, AGENT);
    assert.deepEqual(inspectContextProof(proof.bytes, proof.receipt.proof_sha256,
      context, sha256(context), selected), proof.receipt);
    assert.equal(proof.receipt.selected_path_membership_verified, true);
    assert.equal(proof.receipt.authority_verified, false);
    assert.equal(proof.receipt.freshness_verified, false);
    archiveCalls(f.calls, selected, f.repo.snapshot);
    f.calls.length = 0;
    const result = await captureSource(selected, AGENT), archive = buildSourceArchive(result.capture, 'objects');
    const count = f.calls.length;
    assert.deepEqual(inspectSourceArchive(archive.bytes, archive.receipt.archive_sha256), archive.receipt);
    assert.equal(f.calls.length, count);
    archiveCalls(f.calls, selected, f.repo.snapshot);
    for (const artifact of [proof, archive]) {
      assert.ok(!artifact.bytes.includes(Buffer.from(AGENT)));
      assert.ok(!JSON.stringify(artifact.receipt).includes(AGENT));
    }
  });
}

for (const status of [401, 403]) {
  test(`sponsored package HTTP ${status} during blob acquisition discards the result without retry`, async t => {
    const p = await packagePeer(t, packageFixture(), (_value, call) => {
      if (call.path.endsWith('/blob')) {
        call.res.writeHead(status, { 'Content-Type': 'application/json' });
        call.res.end(JSON.stringify({ untrusted: AGENT })); return false;
      }
    }, { token: AGENT });
    await assert.rejects(captureSourcePackage(p.context, p.contextHash, p.selected, p.expected, AGENT), error => {
      assert.equal(error.status, status); assert.ok(!String(error).includes(AGENT)); return true;
    });
    assert.equal(p.requests.filter(call => call.path.endsWith('/blob')).length, 1);
    assert.ok(p.requests.at(-1).path.endsWith('/blob'));
  });
  for (const mode of ['proof', 'archive']) {
    test(`sponsored ${mode} HTTP ${status} during blob acquisition has no partial success or credential fallback`, async t => {
      const f = await setup(t, 'sha1', undefined, { token: AGENT }), context = bytes(f.context);
      f.control.respond = (_request, response, call) => {
        response.writeHead(call.operation === 'blob' ? status : 200, { 'Content-Type': 'application/json' });
        response.end(JSON.stringify(call.operation === 'blob' ? { untrusted: AGENT } : f.repo.answer(call.operation, call.form)));
      };
      const pending = mode === 'proof'
        ? captureContextProof(context, sha256(context), f.selection, AGENT)
        : captureSource(f.selection, AGENT);
      await assert.rejects(pending, error => {
        assert.equal(error.status, status); assert.ok(!String(error).includes(AGENT)); return true;
      });
      assert.equal(f.calls.filter(call => call.operation === 'blob').length, 1);
      assert.equal(f.calls.at(-1).operation, 'blob');
      assert.ok(f.calls.every(call => call.headers.authorization === 'Bearer ' + AGENT));
    });
  }
}

test('optional native authority proofs refuse sponsored credentials before context parsing, helper inspection or network access', async t => {
  const p = await packagePeer(t, packageFixture(), undefined, { token: AGENT });
  for (const context of [p.context, Buffer.from('not JSON')]) {
    await assert.rejects(captureSourcePackage(context, p.contextHash, p.selected, p.expected, AGENT,
      { nativeFg: { executable: '/does-not-exist/frankengit', sha256: '0'.repeat(64) } }),
    { code: 'native_source_proof_agent_scope_unsupported' });
  }
  assert.equal(p.requests.length, 0);
});

test('all acquisition clients reject malformed sponsored credentials before any HTTP request', async t => {
  const p = await packagePeer(t, packageFixture(), undefined, { token: AGENT });
  const f = await setup(t, 'sha1', undefined, { token: AGENT }), context = bytes(f.context);
  for (const bad of [AGENT + '\n', AGENT + ' ', 'FGAGENT_' + 'a'.repeat(64), 'fgagent_' + 'A'.repeat(64),
    'fgagent_' + 'a'.repeat(63), 'fgagent_' + 'a'.repeat(65)]) {
    await assert.rejects(captureSourcePackage(p.context, p.contextHash, p.selected, p.expected, bad));
    await assert.rejects(captureContextProof(context, sha256(context), f.selection, bad));
    await assert.rejects(captureSource(f.selection, bad));
  }
  assert.equal(p.requests.length, 0); assert.equal(f.calls.length, 0);
});

test('sponsored browser search keeps history, binary proofs, mutations and recovery outside its closed read profile', async () => {
  const calls = [], transport = new Transport({ href: 'https://example.invalid/repo/ui/search/',
    pageSuffix: '/ui/search/', cryptoImpl: webcrypto, fetchImpl: async (url, options) => {
      calls.push({ url, options }); return new Response('{}', { headers: { 'Content-Type': 'application/json' } });
    } });
  try {
    await transport.connect(AGENT);
    const request = { method: 'POST', body: 'ref=refs%2Fheads%2Fmain&object_format=sha1' };
    await transport.request('source/commit', request);
    assert.equal(calls.length, 1);
    assert.equal(calls[0].options.headers.Authorization, 'Bearer ' + AGENT);
    assert.equal(calls[0].options.credentials, 'omit');
    assert.equal(calls[0].options.redirect, 'error');
    for (const path of ['source/log', 'source/verified-blob', 'source/apply', 'source/initial/apply',
      'source/bundle/export', 'outcomes', 'pulls/1/checks/evidence', '../source/commit', 'source/commit?history=true']) {
      await assert.rejects(transport.request(path, request));
    }
    for (const patch of [{ key: 'write-key' }, { read: false }, { binary: true }, { method: 'GET' }, { statuses: [200, 409] }]) {
      await assert.rejects(transport.request('source/commit', { ...request, ...patch }));
    }
    assert.throws(() => transport.restrictToRecovery({ key: 'write-key', principal: '1'.repeat(32) }));
    await assert.rejects(transport.connect(AGENT, null, { key: 'write-key', principal: '1'.repeat(32) }));
    assert.equal(transport.connected, false);
    assert.equal(calls.length, 1);
  } finally { transport.disconnect(); }
});

test('a sponsored token cannot connect a browser mutation or workflow-evidence profile', async () => {
  let requests = 0;
  for (const profile of [
    ...['pulls', 'source', 'initial', 'branches', 'transfers', 'tags', 'replay', 'rebase', 'queues'].map(name => ({ pageSuffix: `/ui/${name}/` })),
    { pageSuffix: '/ui/pulls/', checkEvidenceOnly: true },
  ]) {
    const transport = new Transport({ href: 'https://example.invalid/repo' + profile.pageSuffix,
      ...profile, cryptoImpl: webcrypto, fetchImpl: async () => { requests++; throw new Error('unexpected request'); } });
    await assert.rejects(transport.connect(AGENT)); assert.equal(transport.connected, false);
  }
  assert.equal(requests, 0);
});

test('the archive transport cannot turn a sponsored source read into history or arbitrary endpoint access', async t => {
  const f = await setup(t, 'sha1', undefined, { token: AGENT });
  const reader = new SourceReader(f.selection.endpoint, AGENT, ARCHIVE_LIMITS);
  for (const operation of ['log', 'verified-blob', 'apply', '../outcomes', 'commit?history=true']) {
    await assert.rejects(reader.read(operation, { ref: f.selection.ref }), /Unsupported source-read operation/);
  }
  assert.equal(reader.requests, 0); assert.equal(f.calls.length, 0);
});
