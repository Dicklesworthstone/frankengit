// Real certificate verification and sockets. Origin remains a native-schema fixture.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:https';
import { request } from 'node:http';
import { execFileSync } from 'node:child_process';
import { mkdtemp, readFile, mkdir, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fixture, TOKEN, ROTATED } from './fixtures/pull_sync_native.mjs';
import { discover, freezePlan } from '../../scripts/operator/pull_sync_plan.mjs';
import { savePlan } from '../../scripts/operator/pull_sync_custody.mjs';
import { send, recover } from '../../scripts/operator/pull_sync_publish.mjs';
import { syncRequest } from '../../scripts/operator/pull_sync_transport.mjs';

test('private-CA HTTPS is verified for discovery, publication and rotated-token recovery', async t => {
  const f = await fixture(t, 'sha256', 1), root = await mkdtemp(join(tmpdir(), 'fg-pr-tls-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const keyFile = join(root, 'key.pem'), certFile = join(root, 'cert.pem');
  execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', keyFile, '-out', certFile,
    '-subj', '/CN=127.0.0.1', '-addext', 'subjectAltName=IP:127.0.0.1', '-days', '1'], { stdio: 'ignore' });
  const ca = await readFile(certFile), sockets = new Set(), upstream = new URL(f.dest.endpoint);
  const tls = createServer({ key: await readFile(keyFile), cert: ca }, (req, res) => {
    const remote = request({ hostname: '127.0.0.1', port: upstream.port, path: req.url, method: req.method, headers: req.headers, agent: false }, incoming => {
      res.writeHead(incoming.statusCode, incoming.headers); incoming.pipe(res);
    });
    remote.on('error', () => res.destroy()); req.pipe(remote); res.on('close', () => remote.destroy());
  });
  tls.on('connection', socket => { sockets.add(socket); socket.on('close', () => sockets.delete(socket)); });
  await new Promise(resolve => tls.listen(0, '127.0.0.1', resolve));
  t.after(async () => { for (const socket of sockets) socket.destroy(); await new Promise(resolve => tls.close(resolve)); });
  f.dest.endpoint = `https://127.0.0.1:${tls.address().port}/team/repo.git`;
  await assert.rejects(discover(f.dest, TOKEN, [1]), /transport_unavailable/); assert.equal(f.calls.length, 0);
  const discovery = await discover(f.dest, TOKEN, [1], { ca });
  const state = join(root, 'state'); await mkdir(state, { mode: 0o700 }); const plan = await savePlan(state, freezePlan(discovery, TOKEN));
  f.state.drop = true;
  await assert.rejects(send(state, TOKEN, { endpoint: f.dest.endpoint, confirmation: plan.plan_sha256, ca }), e => e.publication_unknown);
  const result = await recover(state, ROTATED, { endpoint: f.dest.endpoint, ca }); assert.equal(result.jobs[0].state, 'committed');
  assert.equal(f.calls.filter(c => c.path.endsWith('/update')).length, 1);
  assert.equal(f.calls.at(-1).body, ''); assert.equal(f.calls.at(-1).headers.authorization, `Bearer ${ROTATED}`);
});
test('malformed server JSON cannot leak a reflected credential through parser diagnostics', async t => {
  const f = await fixture(t);
  f.state.hook = (_call, _req, res) => { res.writeHead(200, { 'Content-Type': 'application/json' }); res.end(`invalid response with ${TOKEN}`); return true; };
  await assert.rejects(syncRequest(f.dest.endpoint, TOKEN, { kind: 'show', number: 1, head: null }), error =>
    error.message === 'invalid_sync_json' && !error.message.includes(TOKEN));
});
