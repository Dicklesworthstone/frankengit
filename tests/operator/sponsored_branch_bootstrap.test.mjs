// Actual client, HTTP and private custody contracts against an independent
// native-schema peer. This does not execute Rust admission or prove a grant.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile, writeFile, readdir, lstat, chmod } from 'node:fs/promises';
import { join } from 'node:path';
import { Writable } from 'node:stream';
import { prepareBootstrap, runBootstrap, bootstrapStatus } from '../../scripts/lib/branch-bootstrap.mjs';
import { readToken } from '../../scripts/lib/branch-bootstrap-store.mjs';
import { canonical, hash, operateBranch } from '../../scripts/lib/branch-bootstrap-protocol.mjs';
import { main } from '../../scripts/bootstrap_native_branches.mjs';
import { fixture, TOKEN } from './branch-bootstrap-fixture.mjs';

const AGENT = 'fgagent_' + 'ab'.repeat(32), ROTATED = 'fgagent_' + 'cd'.repeat(32);
async function prepared(t, options = {}) {
  const f = await fixture(t, { token: AGENT, rotatedToken: ROTATED, ...options });
  const plan = await prepareBootstrap(f.prepare);
  return { ...f, plan, run: { workdir: plan.workdir, confirm: plan.plan_sha256, tokenFile: f.tokenFile } };
}
const request = async f => canonical(await readFile(join(f.plan.workdir, 'requests', 'request-000001.json')));
async function privateContents(root) {
  let text = '';
  for (const entry of await readdir(root, { withFileTypes: true })) {
    const path = join(root, entry.name);
    text += entry.isDirectory() ? await privateContents(path) : await readFile(path, 'utf8');
  }
  return text;
}
function provenance(result) {
  if (!result.terminal) return result;
  return { ...result, provenance_error: null, principal_provenance: {
    state: 'recorded', principal_id: result.principal_id, authentication: 'agent_credential',
    agent_provenance: { agent: result.principal_id, sponsor: '55'.repeat(16), sponsor_kind: 'human',
      credential_id: '66'.repeat(32), grant_root: { algorithm: 2, hex: '77'.repeat(32) },
      run_commitment: '88'.repeat(32), authenticated_at: '9007199254740993', expires_at: '18446744073709551615' },
  } };
}
async function cli(args) {
  let stdout = '', stderr = '';
  const code = await main(args, {
    stdout: new Writable({ write(bytes, _encoding, done) { stdout += bytes; done(); } }),
    stderr: new Writable({ write(bytes, _encoding, done) { stderr += bytes; done(); } }),
  });
  return { code, stdout, stderr, value: stdout ? JSON.parse(stdout) : null };
}

for (const format of ['sha1', 'sha256']) test('sponsored branch bootstrap completes exact ' + format + ' requests and retains original provenance', async t => {
  const f = await prepared(t, { format, branches: 2, behavior: { outcome: ({ result }) => provenance(result) } });
  assert.equal(f.requests.length, 0);
  const original = await request(f);
  assert.equal(original.credential_sha256, hash(Buffer.from(AGENT)));
  assert.notEqual(original.credential_sha256, hash(Buffer.from(AGENT.slice(8))));
  // The same secret suffix is a different credential family, never an exact retry.
  await assert.rejects(operateBranch(original, AGENT.slice(8), { send: true }), /original_credential/);
  assert.equal(f.requests.length, 0);
  const result = await runBootstrap(f.run);
  assert.equal(result.complete, true); assert.equal(result.committed, 2); assert.equal(f.posts(), 2);
  assert(f.requests.every(call => call.token === 'Bearer ' + AGENT));
  assert.equal(f.requests.find(call => call.path.endsWith('/create')).body, original.body);
  assert.equal(f.refs.get(original.ref), original.new_commit);
  const saved = canonical(await readFile(join(f.plan.workdir, 'journal', 'attempt-000001', 'result.json')));
  const facts = saved.observation.outcome.principal_provenance.agent_provenance;
  assert.equal(facts.agent, f.selection.scope.principal_id); assert.equal(facts.sponsor, '55'.repeat(16));
  assert.equal(facts.authenticated_at, '9007199254740993'); assert.equal(facts.expires_at, '18446744073709551615');
  const custody = await privateContents(f.plan.workdir);
  assert(!custody.includes(AGENT)); assert(!custody.includes(ROTATED));
  const before = f.requests.length;
  assert.equal((await bootstrapStatus({ workdir: f.plan.workdir, confirm: f.plan.plan_sha256 })).complete, true);
  assert.equal((await runBootstrap({ workdir: f.plan.workdir, confirm: f.plan.plan_sha256 })).network_accessed, false);
  assert.equal(f.requests.length, before);
});

test('sponsored lost acknowledgement recovers with a rotated token without sending another create', async t => {
  const f = await prepared(t, { branches: 2, behavior: {
    send: ({ res }) => { res.destroy(); return false; }, outcome: ({ result }) => provenance(result),
  } });
  const original = await request(f), unknown = await runBootstrap(f.run);
  assert.equal(unknown.state, 'unresolved'); assert.equal(f.posts(), 1);
  await writeFile(f.tokenFile, ROTATED + '\n');
  const recovered = await runBootstrap({ ...f.run, operation: 'recover' });
  assert.equal(recovered.committed, 1); assert.equal(recovered.state, 'ready'); assert.equal(f.posts(), 1);
  assert.deepEqual(await request(f), original);
  const saved = canonical(await readFile(join(f.plan.workdir, 'journal', 'attempt-000002', 'result.json')));
  assert.equal(saved.observation.outcome.principal_provenance.agent_provenance.credential_id, '66'.repeat(32));
  const before = f.requests.length;
  await assert.rejects(runBootstrap(f.run), /original_credential/);
  assert.equal(f.requests.length, before); assert.equal(f.posts(), 1);
});

test('a rotated sponsored token cannot recover another principal or retransmit an original request', async t => {
  const f = await prepared(t, { branches: 1, behavior: {
    send: ({ res }) => { res.destroy(); return false; },
    outcome: ({ result, req }) => req.headers.authorization === 'Bearer ' + ROTATED
      ? { ...result, principal_id: 'ff'.repeat(16) } : result,
  } });
  await runBootstrap(f.run); await writeFile(f.tokenFile, ROTATED);
  const result = await runBootstrap({ ...f.run, operation: 'recover' });
  assert.equal(result.state, 'unresolved'); assert.equal(f.posts(), 1);
  await assert.rejects(operateBranch(await request(f), ROTATED, { send: true }), /original_credential/);
  assert.equal(f.posts(), 1);
});

test('missing branch grant is an unresolved HTTP refusal, never a fabricated terminal or branch', async t => {
  const f = await prepared(t, { branches: 1, behavior: {
    beforeSend: ({ res }) => { res.writeHead(403); res.end('denied ' + AGENT); return false; },
  } });
  const result = await runBootstrap(f.run);
  assert.equal(result.state, 'unresolved'); assert.equal(result.committed, 0); assert.equal(f.refs.size, 0);
  assert.equal(result.current.publication, null); assert.equal(result.current.outcome.terminal, false);
  const custody = await privateContents(f.plan.workdir);
  assert(!custody.includes(AGENT)); assert(!custody.includes('denied'));
  const posts = f.posts(); await runBootstrap(f.run); assert.equal(f.posts(), posts);
});

test('revoked credentials or missing outcomes-read refuse preflight before branch dispatch', async t => {
  const f = await prepared(t, { branches: 1, behavior: {
    outcome: ({ res }) => { res.writeHead(401); res.end(); return false; },
  } });
  const result = await runBootstrap(f.run);
  assert.equal(result.state, 'unresolved'); assert.equal(f.posts(), 0); assert.equal(f.refs.size, 0);
  assert.equal(result.current.publication, null);
});

test('sponsored native create refusal preserves an occupied branch and stops the batch', async t => {
  const f = await prepared(t, { existing: [['refs/heads/import/0001', '9'.repeat(40)]] });
  const result = await runBootstrap(f.run);
  assert.equal(result.state, 'refused'); assert.equal(f.posts(), 1); assert.equal(result.committed, 0);
  assert.equal(f.refs.get('refs/heads/import/0001'), '9'.repeat(40)); assert.equal(f.refs.size, 1);
});

test('private token files admit only exact ordinary or sponsored bearers with one optional line ending', async t => {
  const f = await fixture(t);
  for (const token of [TOKEN, AGENT]) for (const suffix of ['', '\n', '\r\n']) {
    await writeFile(f.tokenFile, token + suffix);
    assert.equal(await readToken(f.tokenFile, () => {}), token);
  }
  for (const token of ['fgagent_', AGENT.toUpperCase(), 'fgagent_' + 'g'.repeat(64), AGENT.slice(0, -1), AGENT + '0',
    AGENT + '\n\n', AGENT + '\r', ' ' + AGENT, AGENT + '\nAuthorization: Bearer other', 'aa'.repeat(36)]) {
    await writeFile(f.tokenFile, token);
    await assert.rejects(prepareBootstrap(f.prepare));
    await assert.rejects(lstat(f.prepare.workdir), error => error.code === 'ENOENT');
  }
  await writeFile(f.tokenFile, AGENT); await chmod(f.tokenFile, 0o644);
  await assert.rejects(prepareBootstrap(f.prepare));
  assert.equal(f.requests.length, 0);
});

test('the shipped CLI prepares and runs a sponsored task branch using only a private token file', async t => {
  const f = await fixture(t, { token: AGENT, rotatedToken: ROTATED, branches: 1 });
  const selection = join(f.root, 'selection.json');
  await writeFile(selection, JSON.stringify(f.selection), { mode: 0o600 });
  const prepared = await cli(['prepare', '--workdir', f.prepare.workdir, '--selection', selection, '--token-file', f.tokenFile]);
  assert.equal(prepared.code, 0, prepared.stderr); assert.equal(prepared.stderr, ''); assert.equal(f.requests.length, 0);
  const result = await cli(['run', '--workdir', prepared.value.workdir, '--confirm', prepared.value.plan_sha256, '--token-file', f.tokenFile]);
  assert.equal(result.code, 0, result.stderr); assert.equal(result.stderr, ''); assert.equal(result.value.complete, true);
  assert.equal(f.posts(), 1); assert(!(prepared.stdout + result.stdout).includes(AGENT));
});

test('cancelling a sponsored branch response retains its original key for read-only recovery', async t => {
  const stop = new AbortController();
  const f = await prepared(t, { branches: 1, behavior: {
    send: ({ res }) => {
      res.writeHead(200, { 'Content-Type': 'application/json' }); res.write('{');
      setTimeout(() => stop.abort(), 10); return false;
    },
  } });
  const original = await request(f);
  await assert.rejects(runBootstrap({ ...f.run, signal: stop.signal }));
  const status = await bootstrapStatus({ workdir: f.plan.workdir, confirm: f.plan.plan_sha256 });
  assert.equal(status.state, 'unresolved'); assert.equal(status.current.key, original.key); assert.equal(f.posts(), 1);
  const recovered = await runBootstrap({ ...f.run, operation: 'recover' });
  assert.equal(recovered.complete, true); assert.equal(f.posts(), 1);
  assert.deepEqual(await request(f), original);
});
