// Real CLI processes and complete production modules against a response-schema
// HTTP peer. This is operator execution, not native Rust authority evidence.
import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { readFile, writeFile, readdir, rename } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { setupMilestones, milestonePeer, milestoneSnapshot, issueSnapshot, encode }
  from './native_milestone_transfer_helper.mjs';

const migrationCli = fileURLToPath(new URL('../../scripts/migrate_native_issues.mjs', import.meta.url));
const destinationTenant = '4'.repeat(32), destinationRepository = '5'.repeat(32);
function launch(t, script, args) {
  const child = spawn(process.execPath, [script, ...args], { stdio: ['ignore', 'pipe', 'pipe'] });
  let stdout = '', stderr = '';
  child.stdout.setEncoding('utf8'); child.stderr.setEncoding('utf8');
  child.stdout.on('data', text => { stdout += text; if (stdout.length > 4 * 1024 * 1024) child.kill('SIGKILL'); });
  child.stderr.on('data', text => { stderr += text; if (stderr.length > 4 * 1024 * 1024) child.kill('SIGKILL'); });
  const timer = setTimeout(() => child.kill('SIGKILL'), 20000);
  t.after(() => { clearTimeout(timer); if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL'); });
  return new Promise((resolve, reject) => {
    child.once('error', reject);
    child.once('close', (code, signal) => { clearTimeout(timer); resolve({ code, signal, stdout, stderr }); });
  });
}
const decoded = (result, code = 0) => { assert.equal(result.code, code, result.stderr); return JSON.parse(result.stdout); };
const mutations = peer => peer.calls.filter(call => call.method === 'POST' && !call.path.endsWith('/outcomes'));
async function fixture(t, destinationOptions = {}) {
  const f = await setupMilestones(t);
  const dest = await milestonePeer({ tenantId: destinationTenant, repositoryId: destinationRepository, ...destinationOptions });
  t.after(() => dest.close());
  const tokenFile = join(f.root, 'destination-token'); await writeFile(tokenFile, dest.token, { mode: 0o600 });
  const mapping = [{ source: 1, destination: 101 }, { source: 2, destination: 102 }, { source: 3, destination: 103 }];
  const mapFile = join(f.root, 'milestone-map.json');
  await writeFile(mapFile, encode({ schema: 'frankengit-native-milestone-map-v1', mappings: mapping }), { mode: 0o600 });
  const workdir = join(f.root, 'prepared');
  const flags = ['--workdir', workdir, '--url', dest.href, '--tenant', destinationTenant,
    '--repository', destinationRepository, '--token-file', tokenFile];
  const prepare = ['prepare', ...flags, '--archive', f.archiveDir, '--archive-sha256', f.archive.archive_sha256,
    '--offset', '1000', '--milestone-map', mapFile];
  return { ...f, dest, tokenFile, mapFile, mapping, workdir, flags, prepare };
}
async function requests(workdir) {
  const result = {};
  for (const entry of await readdir(workdir, { withFileTypes: true })) if (entry.isDirectory()) {
    for (const name of await readdir(join(workdir, entry.name))) if (name.endsWith('.request.json')) {
      result[entry.name + '/' + name] = createHash('sha256').update(await readFile(join(workdir, entry.name, name))).digest('hex');
    }
  }
  return result;
}

test('real migration CLI preserves mapped milestones and issue state across a phase budget stop and restart', async t => {
  const f = await fixture(t);
  const prepared = decoded(await launch(t, migrationCli, f.prepare));
  assert.equal(prepared.schema_version, 2); assert.equal(prepared.milestones, 3); assert.equal(prepared.steps, 14);
  assert.deepEqual(prepared.milestone_map, f.mapping); assert.equal(f.dest.calls.length, 0);
  const original = await requests(f.workdir); assert.equal(Object.keys(original).length, 14);
  const phase = operation => [operation, ...f.flags, '--confirm', prepared.plan_sha256];
  const inspected = decoded(await launch(t, migrationCli, phase('inspect')));
  assert.equal(inspected.network_accessed, false); assert.equal(f.dest.calls.length, 0);
  await rename(f.archiveDir, join(f.root, 'retained-archive'));
  await rename(f.mapFile, join(f.root, 'retained-map.json')); await f.src.close();
  const partial = decoded(await launch(t, migrationCli, [...phase('run'), '--max-mutations', '2']), 3);
  assert.equal(partial.complete, false); assert.equal(partial.mutation_calls, 2);
  assert.equal(f.dest.source.size, 0); assert.equal(f.dest.milestoneSource.size, 2);
  assert.equal(milestoneSnapshot(f.dest.milestoneSource.get(101)).state, 'open');
  const complete = decoded(await launch(t, migrationCli, phase('run')));
  assert.equal(complete.complete, true); assert.equal(complete.committed_observed, 14);
  assert.deepEqual(await requests(f.workdir), original);
  const first = milestoneSnapshot(f.dest.milestoneSource.get(101), f.dest.source.values());
  assert.equal(first.state, 'closed'); assert.equal(first.closed_issues, 1); assert.equal(first.open_issues, 0);
  assert.equal(first.due_at, 253402300799); assert.ok(first.body.includes(f.archive.archive_sha256));
  assert.equal(milestoneSnapshot(f.dest.milestoneSource.get(102), f.dest.source.values()).open_issues, 1);
  assert.equal(milestoneSnapshot(f.dest.milestoneSource.get(103)).state, 'open');
  const issue = issueSnapshot(f.dest.source.get(1001));
  assert.equal(issue.milestone, 101); assert.equal(issue.state, 'closed'); assert.equal(issue.locked, true);
  assert.equal(issue.comments, 1); assert.equal(issueSnapshot(f.dest.source.get(1002)).milestone, null);
  assert.equal(issueSnapshot(f.dest.source.get(1003)).milestone, 102);
  const posts = mutations(f.dest);
  assert.equal(posts.length, 14); assert.ok(posts.slice(0, 3).every(call => /milestones\/\d+\/open$/.test(call.path)));
  assert.match(posts.at(-1).path, /milestones\/101\/close$/);
  for (const operation of ['status', 'run']) {
    const recovered = decoded(await launch(t, migrationCli, phase(operation)));
    assert.equal(recovered.complete, true); assert.equal(recovered.mutation_calls, 0);
  }
  assert.equal(mutations(f.dest).length, 14);
});

test('v2 map is required and incomplete maps refuse without creating a plan or contacting the destination', async t => {
  const f = await fixture(t), missing = f.prepare.slice(0, -2);
  assert.equal((await launch(t, migrationCli, missing)).code, 2);
  await writeFile(f.mapFile, encode({ schema: 'frankengit-native-milestone-map-v1', mappings: f.mapping.slice(0, 2) }));
  const incomplete = await launch(t, migrationCli, f.prepare);
  assert.equal(incomplete.code, 2, incomplete.stderr); assert.equal(f.dest.calls.length, 0);
  await assert.rejects(readdir(f.workdir), { code: 'ENOENT' });
});

test('migration rejects map changes at inspect/run/status and stops canonically on a destination milestone collision', async t => {
  const f = await fixture(t, { milestones: [{ number: 101, events: [{ version: 1, actor: '3'.repeat(32),
    action: { name: 'open', title: 'Already exists', body: '', due_at: null } }] }] });
  const prepared = decoded(await launch(t, migrationCli, f.prepare));
  const phase = operation => [operation, ...f.flags, '--confirm', prepared.plan_sha256];
  for (const operation of ['inspect', 'run', 'status']) {
    const invalid = await launch(t, migrationCli, [...phase(operation), '--milestone-map', f.mapFile]);
    assert.equal(invalid.code, 2, invalid.stderr);
  }
  assert.equal(f.dest.calls.length, 0);
  const refused = decoded(await launch(t, migrationCli, phase('run')), 1);
  assert.equal(refused.stop_reason, 'terminal_refusal'); assert.equal(f.dest.source.size, 0);
  assert.equal(f.dest.milestoneSource.size, 1);
  const again = decoded(await launch(t, migrationCli, [...phase('run'), '--retry-unresolved']), 1);
  assert.equal(again.mutation_calls, 0); assert.equal(mutations(f.dest).length, 1);
});
