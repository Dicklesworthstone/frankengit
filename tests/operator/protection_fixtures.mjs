// Native-schema contract peer only: no Rust policy evaluation or authority CAS.
import { createServer } from 'node:http';
import { once } from 'node:events';
import { mkdtemp, writeFile, chmod, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
export const TOKEN = '12'.repeat(32), ROTATED = '34'.repeat(32), ACTOR = 'a'.repeat(32), REVIEWER = 'b'.repeat(32);
export const SCOPE = { tenant_id: '1'.repeat(32), repository_id: '2'.repeat(32), repository_incarnation: '3'.repeat(32), object_format: 'sha1' };
export const HEAD = `alg:2:${'5'.repeat(64)}`;
export const ref = value => Buffer.from(value).toString('hex');
export const POLICY = { administrators: [ACTOR], branches: [{ reference_hex: ref('refs/heads/main'), required_reviewers: [REVIEWER] }] };
export const NEXT = { administrators: [ACTOR, 'c'.repeat(32)], branches: [{ reference_hex: ref('refs/heads/main'), required_reviewers: [REVIEWER, 'd'.repeat(32)] }] };
export const state = (extra = {}) => ({ type: 'repository_review_protection', schema_version: 1, ...SCOPE, source_head: HEAD,
  policy_epoch: '2', version: '1', installed: true, enabled: true, policy: structuredClone(POLICY),
  complete: true, transaction_created: false, published: false, ...extra });
export function json(response, value, status = 200, headers = {}) {
  const bytes = Buffer.from(JSON.stringify(value));
  response.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Content-Length': bytes.length, ...headers }); response.end(bytes);
}
export async function peer(t, handle = (_, response) => json(response, state())) {
  const calls = [], sockets = new Set();
  const server = createServer((request, response) => {
    const chunks = []; request.on('data', chunk => chunks.push(chunk));
    request.on('end', () => { const call = { method: request.method, url: request.url, headers: request.headers, body: Buffer.concat(chunks).toString() };
      calls.push(call); Promise.resolve(handle(call, response, request)).catch(error => response.destroy(error)); });
  });
  server.on('connection', socket => { sockets.add(socket); socket.once('close', () => sockets.delete(socket)); });
  server.listen(0, '127.0.0.1'); await once(server, 'listening');
  t.after(async () => { for (const socket of sockets) socket.destroy(); await new Promise(resolve => server.close(resolve)); });
  return { endpoint: `http://127.0.0.1:${server.address().port}/team/repo.git`, calls, sockets, server };
}
export async function files(t) {
  const root = await mkdtemp(join(tmpdir(), 'fg-protection-')); await chmod(root, 0o700);
  t.after(() => rm(root, { recursive: true, force: true }));
  const write = async (name, value) => { const path = join(root, name); await writeFile(path, typeof value === 'string' || Buffer.isBuffer(value) ? value : JSON.stringify(value), { mode: 0o600 }); return path; };
  return { root, write, token: await write('token', `${TOKEN}\n`), scope: await write('scope.json', SCOPE), policy: await write('policy.json', NEXT), intent: join(root, 'request') };
}
