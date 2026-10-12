// Test-only TLS fixture. OpenSSL generates an ephemeral localhost certificate;
// neither its subprocess nor its private key is used by the operator library.
import { execFileSync } from 'node:child_process';
import { createServer } from 'node:https';
import { createHash, generateKeyPairSync } from 'node:crypto';
import { mkdtemp, mkdir, writeFile, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { once } from 'node:events';
import { signRepositoryBackupFile } from '../lib/repository-backup-approval.mjs';

export const NOW = Date.parse('2026-10-12T12:00:00Z');
export const ID = { tenant_id: '1'.repeat(32), repository_id: '2'.repeat(32), incarnation_id: '3'.repeat(32), object_format: 'sha256' };
export const DATA = Buffer.alloc(131089, 0x63);
export const digest = value => createHash('sha256').update(value).digest('hex');
let credentials;
export async function tlsFixture(t) {
  if (!credentials) {
    const root = await mkdtemp(join(tmpdir(), 'fg-download-certificate-'));
    try {
      execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '2', '-subj', '/CN=localhost',
        '-addext', 'subjectAltName=DNS:localhost,IP:127.0.0.1', '-keyout', join(root, 'key.pem'), '-out', join(root, 'cert.pem')], { stdio: 'ignore' });
      credentials = { key: await readFile(join(root, 'key.pem')), cert: await readFile(join(root, 'cert.pem')) };
    } finally { await rm(root, { recursive: true, force: true }); }
  }
  const root = await mkdtemp(join(tmpdir(), 'fg-backup-download-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const destination = join(root, 'destination'); await mkdir(destination, { mode: 0o700 });
  const caFile = join(root, 'tls.pem'); await writeFile(caFile, credentials.cert);
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const trustKey = join(root, 'trusted.pem'); await writeFile(trustKey, publicKey.export({ type: 'spki', format: 'pem' }));
  const local = join(root, 'signing-source'), approval = join(root, 'approval.json');
  async function sign(data = DATA, metadata = {}, now = NOW) {
    await writeFile(local, data);
    const signed = await signRepositoryBackupFile(local, Buffer.from(privateKey.export({ type: 'pkcs8', format: 'pem' })),
      { ...ID, head_generation: '9007199254740993', issued_at: '2026-10-12T11:00:00Z', expires_at: '2026-10-13T12:00:00Z', ...metadata }, { now });
    await writeFile(approval, signed.envelope); return signed;
  }
  const signed = await sign();
  const requests = [], sockets = new Set();
  let handler = (_, res) => { res.writeHead(200, { 'content-length': DATA.length }); res.end(DATA); };
  const server = createServer(credentials, (req, res) => { requests.push(req.url); handler(req, res); });
  server.on('connection', socket => { sockets.add(socket); socket.once('close', () => sockets.delete(socket)); });
  server.on('tlsClientError', () => {});
  server.listen(0, '127.0.0.1'); await once(server, 'listening');
  t.after(async () => { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); });
  const url = `https://127.0.0.1:${server.address().port}/backup?secret=capability-do-not-log`;
  return { root, destination, caFile, trustKey, approval, local, sign, signed, server, sockets, requests, url,
    setHandler: fn => { handler = fn; },
    options: { sources: [url], approval, trustKey, caFile, destination, policy: { ...ID, minimum_head_generation: '1' },
      maximumBytes: DATA.length, now: NOW, timeoutMs: 5000 } };
}
