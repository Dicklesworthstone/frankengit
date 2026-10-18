// A native-schema HTTP contract peer, not the Rust authority or an fg server.
import { createServer } from 'node:http';
import { mkdtemp, writeFile, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawn } from 'node:child_process';
import assert from 'node:assert/strict';
import { captureGithubIssues } from '../../scripts/lib/github-issue-source.mjs';
import { prepareGithubIssueImport, runGithubIssueImport } from '../../scripts/lib/github-issue-import.mjs';

export const tenant = 'a'.repeat(32), repository = 'b'.repeat(32), token = 'c'.repeat(64), actor = 'd'.repeat(32);
const source = 'owner/project', time = '2026-10-01T10:00:00Z';
const binding = { schema_version: 1, tenant_id: tenant, repository_id: repository };
export async function sourceCapture(numbers = [3, 5]) {
  return captureGithubIssues({ repository: source, numbers, fetchImpl: async url => {
    const path = new URL(url).pathname, match = /issues\/(\d+)(\/comments)?$/.exec(path);
    const number = match && Number(match[1]);
    const user = { id: 11, login: 'original-source-author' };
    const value = !match ? { id: 42, full_name: source } : match[2] ? [1, 2].map(i => ({
      id: number * 100 + i, html_url: `https://github.com/${source}/issues/${number}#issuecomment-${number * 100 + i}`,
      issue_url: `https://api.github.com/repos/${source}/issues/${number}`, user,
      body: `Exact source comment ${i}\r\n%26=+`, created_at: time, updated_at: time,
    })) : { id: number * 10, number, html_url: `https://github.com/${source}/issues/${number}`, user,
      title: `Source ${number}`, body: 'Original source body\r\n', state: number === 3 ? 'closed' : 'open',
      state_reason: number === 3 ? 'completed' : null, closed_at: number === 3 ? time : null,
      created_at: time, updated_at: time, labels: [{ id: 1, name: 'bug', color: 'abcdef', description: null }],
      assignees: [user], milestone: null, locked: false, comments: 2 };
    return new Response(JSON.stringify(value), { headers: { 'Content-Type': 'application/json' } });
  } });
}
export async function fixture(t, { before = async () => false, after = async () => false, prepare = true, numbers = [3, 5] } = {}) {
  const dir = await mkdtemp(join(tmpdir(), 'fg-github-import-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const tokenFile = join(dir, 'native-token'), captureFile = join(dir, 'source.json'), workdir = join(dir, 'migration');
  await writeFile(tokenFile, token, { mode: 0o600 });
  await writeFile(captureFile, (await sourceCapture(numbers)).bytes, { mode: 0o600 });
  const calls = [], rows = new Map(), outcomes = new Map(), errors = [];
  let sequence = 0;
  const send = (reply, value, status = 200) => { reply.writeHead(status, { 'Content-Type': 'application/json' }); reply.end(JSON.stringify(value)); };
  const server = createServer(async (request, reply) => {
    try {
      let body = ''; for await (const chunk of request) body += chunk;
      assert.equal(request.headers.authorization, `Bearer ${token}`);
      const call = { method: request.method, url: new URL(request.url, 'http://local'), body,
        key: request.headers['idempotency-key'], request, reply }; calls.push(call);
      if (await before(call, { rows, outcomes, send })) return;
      const match = /^\/repo.git\/api\/v1\/issues\/(\d+)(?:\/(open|comment|close))?$/.exec(call.url.pathname);
      if (request.method === 'GET') {
        assert.ok(match); assert.equal(call.key, undefined);
        const number = Number(match[1]), row = rows.get(number), limit = Number(call.url.searchParams.get('limit'));
        send(reply, { ...binding, type: 'issue_history', snapshot_token: `alg:2:${'e'.repeat(64)}`,
          after_version: 0, limit, found: Boolean(row), issue: row?.issue ?? null,
          events: row?.events.slice(0, limit) ?? [], next_after_version: row && row.issue.version > limit ? limit : null }, row ? 200 : 404);
        return;
      }
      if (call.url.pathname.endsWith('/outcomes')) {
        assert.equal(body, ''); const saved = outcomes.get(call.key);
        send(reply, { ...binding, type: 'transaction_outcome', repository_incarnation: 'f'.repeat(32), principal_id: actor,
          selector: 'transaction', command_index: null, read_only: true, request_reexecuted: false,
          absence_proves_non_commit: false, session_completeness_established: false,
          state: saved?.outcome ?? 'key_not_observed', terminal: Boolean(saved),
          transaction: saved ? { tx_id: saved.tx_id } : null,
          decision: !saved ? null : saved.outcome === 'committed'
            ? { kind: 'committed', decision_sequence: saved.decision_sequence, repository_commit_id: saved.repository_commit_id }
            : { kind: 'refused', decision_sequence: saved.decision_sequence, code: saved.refusal_code, refusal_record_id: saved.refusal_record_id } });
        return;
      }
      assert.ok(match?.[2], call.url.pathname);
      if (outcomes.has(call.key)) {
        const saved = outcomes.get(call.key); assert.equal(saved._body, body);
        send(reply, saved, saved.outcome === 'committed' ? 200 : 409); return;
      }
      const number = Number(match[1]), action = match[2], form = new URLSearchParams(body);
      const version = Number(form.get('expected_version')), old = rows.get(number), current = old?.issue.version ?? 0;
      const index = calls.filter(c => /\/(open|comment|close)$/.test(c.url.pathname) && outcomes.has(c.key)).length;
      // Find the real native request in the journal and check its sync/identity
      // custody before the fixture pretends to admit the mutation.
      let found = false;
      for (let i = 0; i < 10; i++) {
        try {
          const p = JSON.parse(await readFile(join(workdir, `step-${String(i).padStart(6, '0')}.request.json`), 'utf8'));
          if (p.receipt.request.key === call.key) { assert.equal(p.receipt.request.body, body); found = true; break; }
        } catch (e) { if (e.code !== 'ENOENT') throw e; }
      }
      assert.ok(found, `receipt before mutation ${index}`);
      const valid = current === version && ((action === 'open') === (version === 0));
      const terminal = { ...binding, type: 'issue_publication', number, expected_version: version, action,
        principal_id: actor, tx_id: `tx-${++sequence}`, decision_sequence: sequence,
        outcome: valid ? 'committed' : 'refused', repository_commit_id: valid ? `rcr-${sequence}` : null,
        refusal_record_id: valid ? null : `refusal-${sequence}`, refusal_code: valid ? null : 'EvidenceStale', delivery_acknowledged: null, _body: body };
      outcomes.set(call.key, terminal);
      if (valid) {
        const fields = action === 'open' ? { title: form.get('title'), body: form.get('body'), labels: form.getAll('label') }
          : action === 'comment' ? { body: form.get('body') } : {};
        const row = old ?? { issue: { number, version: 0, ...fields, state: 'open', comments: 0, opened_by: actor, last_actor: actor, assignees: [] }, events: [] };
        row.issue.version++; if (action === 'comment') row.issue.comments++; if (action === 'close') row.issue.state = 'closed';
        row.events.push({ version: version + 1, actor, action: { name: action, ...fields } }); rows.set(number, row);
      }
      if (await after(call, { terminal, rows, outcomes, send })) return;
      send(reply, terminal, terminal.outcome === 'committed' ? 200 : 409);
    } catch (error) { errors.push(error); reply.destroy(); }
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => { server.closeAllConnections(); return new Promise(resolve => server.close(resolve)); });
  t.after(() => { assert.deepEqual(errors, [], 'contract peer errors'); });
  const common = { workdir, href: `http://127.0.0.1:${server.address().port}/repo.git/ui/issues/`, tenant, repository, tokenFile };
  const prepared = prepare ? await prepareGithubIssueImport({ ...common, captureFile, offset: 100 }) : null;
  const run = extra => runGithubIssueImport({ ...common, confirm: prepared?.plan_sha256, operation: 'run', ...extra });
  const file = (index, kind) => join(workdir, `step-${String(index).padStart(6, '0')}.${kind}.json`);
  return { dir, common, prepared, captureFile, workdir, calls, rows, outcomes, run, file };
}
export const mutations = f => f.calls.filter(c => /\/(?:open|comment|close)$/.test(c.url.pathname));
export function cliArgs(f, operation = 'run', extra = []) {
  return [new URL('../../scripts/import_github_issues.mjs', import.meta.url).pathname, operation,
    '--workdir', f.workdir, '--url', f.common.href, '--tenant-id', tenant, '--repository-id', repository,
    '--token-file', f.common.tokenFile, '--confirm', f.prepared.plan_sha256, ...extra];
}
export function cli(f, operation, extra = []) {
  const child = spawn(process.execPath, cliArgs(f, operation, extra), { stdio: ['ignore', 'pipe', 'pipe'] });
  let stdout = '', stderr = ''; child.stdout.setEncoding('utf8'); child.stderr.setEncoding('utf8');
  child.stdout.on('data', chunk => { stdout += chunk; }); child.stderr.on('data', chunk => { stderr += chunk; });
  const result = new Promise((resolve, reject) => { child.once('error', reject); child.once('close', (code, signal) => resolve({ code, signal, stdout, stderr })); });
  return { child, result };
}
