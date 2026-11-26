// Malformed peer replies must not become automatic PR updates or terminal facts.
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, readFile, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { parseSyncJson } from '../../scripts/operator/pull_sync_transport.mjs';
import { discover, freezePlan } from '../../scripts/operator/pull_sync_plan.mjs';
import { loadPlan, savePlan } from '../../scripts/operator/pull_sync_custody.mjs';
import { send, recover, status } from '../../scripts/operator/pull_sync_publish.mjs';
import { fixture, TOKEN, ROTATED } from './fixtures/pull_sync_native.mjs';

const code = expected => error => error.code === expected;
const duplicates = [
  '{"principal_id":"wrong","principal_id":"expected"}',
  '{"pull_request":{"data":{"source_tip":"wrong","source_tip":"expected"}}}',
  '{"outcome":"refused","outc\\u006fme":"committed"}',
  '{"decision_sequence":1,"decision_sequence":18446744073709551615}',
  '{"requests":[{"fields":{"body":"first","body":"second"}}]}',
];
for (const source of duplicates) test('sync JSON rejects ambiguous fields: ' + source, () => {
  assert.throws(() => parseSyncJson(Buffer.from(source)), code('duplicate_sync_json_key'));
});

test('sync JSON accepts repeated names in separate objects and syntax-looking string contents', () => {
  const value = { rows: [{ body: 'quoted "body": value \\ escaped {[]}' }, { body: 'second' }],
    decision_sequence: '18446744073709551615' };
  const source = JSON.stringify(value).replace('"decision_sequence":"18446744073709551615"',
    '"decision_sequence":18446744073709551615');
  assert.deepEqual(parseSyncJson(Buffer.from(source)), value);
});

test('sync JSON bounds depth and structure before recursive interpretation', () => {
  assert.throws(() => parseSyncJson(Buffer.from('['.repeat(33) + '0' + ']'.repeat(33))), code('sync_json_structure_limit'));
  assert.throws(() => parseSyncJson(Buffer.from(JSON.stringify(Array.from({ length: 65536 }, () => ({}))))),
    code('sync_json_structure_limit'));
  assert.throws(() => parseSyncJson(Buffer.from(JSON.stringify(Array(65536).fill(0)))), code('sync_json_structure_limit'));
});

test('sync JSON refuses invalid byte limits without exposing reflected credentials', () => {
  for (const maximum of [NaN, Infinity, -1, 0, 1.5, 20 * 1024 * 1024 + 1]) {
    assert.throws(() => parseSyncJson(Buffer.from('{}'), maximum), code('sync_json_byte_limit'));
  }
  assert.throws(() => parseSyncJson(Buffer.from('{"' + TOKEN + '":1,"' + TOKEN + '":2}')), error =>
    error.code === 'duplicate_sync_json_key' && !error.message.includes(TOKEN));
});

async function planned(t, format) {
  const f = await fixture(t, format, 2), root = await mkdtemp(join(tmpdir(), 'fg-sync-json-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const stateDir = join(root, 'state'); await mkdir(stateDir, { mode: 0o700 });
  const plan = await savePlan(stateDir, freezePlan(await discover(f.dest, TOKEN, 'all-open'), TOKEN));
  return { ...f, stateDir, plan, controls: { endpoint: f.dest.endpoint, confirmation: plan.plan_sha256 } };
}

for (const format of ['sha1', 'sha256']) {
  test(format + ': duplicate discovery coordinates cannot prepare a tip refresh', async t => {
    const f = await fixture(t, format, 1);
    f.server.prependListener('request', (req, res) => {
      if (!req.url.includes('/pulls/1')) return;
      const end = res.end;
      res.end = function (chunk, ...args) {
        return end.call(this, String(chunk).replace('"source_tip":', '"source_tip":"substituted","source_tip":'), ...args);
      };
    });
    await assert.rejects(discover(f.dest, TOKEN, [1]), code('duplicate_sync_json_key'));
    assert.equal(f.calls.length, 1);
    assert.equal(f.decisions.size, 0);
  });

  test(format + ': ambiguous publication stays unknown and recovers without repeating the write', async t => {
    const f = await planned(t, format), original = await readFile(join(f.stateDir, 'plan.json'));
    f.server.prependListener('request', (req, res) => {
      if (!req.url.endsWith('/update')) return;
      const end = res.end;
      res.end = function (chunk, ...args) {
        return end.call(this, '{"outcome":"refused",' + String(chunk).slice(1), ...args);
      };
    });
    await assert.rejects(send(f.stateDir, TOKEN, f.controls), error =>
      error.code === 'duplicate_sync_json_key' && error.publication_unknown === true);
    assert.deepEqual((await status(f.stateDir)).jobs.map(job => job.state), ['unknown', 'prepared']);
    assert.equal(f.decisions.size, 1);
    const writes = () => f.calls.filter(call => call.path.endsWith('/update'));
    assert.equal(writes().length, 1);
    const key = writes()[0].headers['idempotency-key'];
    const result = await recover(f.stateDir, ROTATED, { endpoint: f.dest.endpoint });
    assert.deepEqual(result.jobs.map(job => job.state), ['committed', 'prepared']);
    const lookup = f.calls.filter(call => call.path.endsWith('/outcomes'));
    assert.equal(lookup.length, 1);
    assert.equal(lookup[0].headers['idempotency-key'], key);
    assert.equal(lookup[0].headers.authorization, 'Bearer ' + ROTATED);
    assert.equal(writes().length, 1);
    assert.deepEqual(await readFile(join(f.stateDir, 'plan.json')), original);
  });
}

test('a saved plan cannot shadow fields while retaining its original checksum', async t => {
  const f = await planned(t, 'sha1'), path = join(f.stateDir, 'plan.json'), original = await readFile(path);
  await writeFile(path, '{"schema":"substituted",' + original.toString().slice(1), { mode: 0o600 });
  await assert.rejects(loadPlan(f.stateDir), code('duplicate_sync_json_key'));
  await assert.rejects(send(f.stateDir, TOKEN, f.controls), code('duplicate_sync_json_key'));
  assert.equal(f.decisions.size, 0);
  await writeFile(path, original, { mode: 0o600 });
  assert.deepEqual(await loadPlan(f.stateDir), f.plan);
});
