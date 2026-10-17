// Native exporter response-schema peer, not a native Git exporter.
import { createServer } from 'node:http';
import { mkdtemp, chmod, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import assert from 'node:assert/strict';
import { hash } from '../../scripts/operator/remote_bundle_protocol.mjs';
import { SCOPE, TOKEN, payload } from './remote-bundle-fixture.mjs';

export const HEAD = 'alg:2:' + '66'.repeat(32);
export async function sourceFixture(t, config = {}) {
  const root = await mkdtemp(join(tmpdir(), 'fg-source-download-')); await chmod(root, 0o700);
  const token = join(root, 'token'); await writeFile(token, TOKEN, { mode: 0o600 });
  const { principal_id, ...s } = SCOPE, scope = { ...s, object_format: config.format ?? 'sha1' };
  const bytes = config.bytes ?? payload, requests = [], sockets = new Set();
  const server = createServer(async (req, res) => {
    try {
      const chunks = []; for await (const c of req) chunks.push(c);
      const body = Buffer.concat(chunks).toString(); requests.push({ url: req.url, method: req.method, body, headers: req.headers });
      assert.equal(req.method, 'POST'); assert.equal(req.url, '/repo/api/v1/source/bundle/export');
      assert.equal(req.headers['idempotency-key'], undefined); assert.equal(req.headers.authorization, `Bearer ${TOKEN}`);
      const form = new URLSearchParams(body); assert.equal(form.get('object_format'), scope.object_format);
      assert([...form.keys()].every(k => ['object_format', 'expected_head'].includes(k)));
      if (form.has('expected_head')) assert.equal(form.get('expected_head'), HEAD);
      const headers = { 'content-type': 'application/x-git-bundle', 'content-length': String(bytes.length),
        'x-fgit-bundle-profile': 'full-v1', 'x-fgit-tenant': scope.tenant_id, 'x-fgit-repository': scope.repository_id,
        'x-fgit-repository-incarnation': scope.repository_incarnation, 'x-fgit-object-format': scope.object_format,
        'x-fgit-source-head': 'authority-source', 'x-fgit-snapshot': HEAD, 'x-fgit-artifact-sha256': hash(bytes), 'x-fgit-read-only': 'true' };
      if (await config.intercept?.({ req, res, headers, bytes, requests }) === false) return;
      res.writeHead(200, headers); res.end(bytes);
    } catch (e) { if (!res.destroyed) { res.writeHead(500); res.end('fixture refused'); } }
  });
  server.on('connection', s => { sockets.add(s); s.on('close', () => sockets.delete(s)); });
  await new Promise(r => server.listen(0, '127.0.0.1', r)); let closed = false;
  const close = async () => { if (closed) return; closed = true; for (const s of sockets) s.destroy(); await new Promise(r => server.close(r)); };
  t.after(async () => { await close(); await rm(root, { recursive: true, force: true }); });
  const selection = { endpoint: `http://127.0.0.1:${server.address().port}/repo`, scope, expected_head: HEAD };
  return { root, token, bytes, requests, selection, close, options: { workdir: join(root, 'download'), selection, tokenFile: token } };
}
