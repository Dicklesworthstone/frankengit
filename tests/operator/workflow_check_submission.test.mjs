import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, writeFile, readFile, rm, chmod } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { encode, sha256 } from '../../scripts/operator/workflow_check_protocol.mjs';
import { verifyPlannedConclusions, SUBMISSION_REPORT_BYTES } from '../../scripts/operator/workflow_check_submission.mjs';

async function fixture(t, format = 'sha1', outcome = 'skipped') {
  const root = await mkdtemp(join(tmpdir(), 'fg-check-upgrade-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const id = '1'.repeat(64), runId = '2'.repeat(32), commit = '3'.repeat(format === 'sha1' ? 40 : 64);
  const directory = join(root, `dispatch-${id.slice(0, 32)}`);
  await mkdir(directory, { mode: 0o700 });
  const config = { watch: { run_parent: root, object_format: format } };
  const job = { directory: join(directory, `workflow-${runId}`), job: 'build', source_commit: commit,
    conclusion: 'action_required', key: 'original-key-never-replaced' };
  const report = { runs: [{ run_id: runId, object_format: format, source_commit: commit, executed_commit: commit,
    execution: { jobs: [{ id: job.job, outcome }] } }] };
  const plan = { watch_id: id, report_sha256: sha256(encode(report)), jobs: [job] };
  const path = join(directory, 'report.json');
  await writeFile(path, encode(report), { mode: 0o600 });
  return { config, plan, job, report, path };
}

for (const format of ['sha1', 'sha256']) {
  test(`${format}: skipped pending jobs retain original keys and remain publishable`, async t => {
    const f = await fixture(t, format), before = encode(f.plan), bytes = await readFile(f.path);
    await verifyPlannedConclusions(f.config, f.plan, [f.job]);
    assert.deepEqual(encode(f.plan), before);
    assert.deepEqual(await readFile(f.path), bytes);
  });
  test(`${format}: pre-upgrade successful jobs refuse BEFORE the caller can start or resend`, async t => {
    const f = await fixture(t, format, 'succeeded'), before = encode(f.plan); let sent = false;
    await assert.rejects(async () => {
      await verifyPlannedConclusions(f.config, f.plan, [f.job]);
      sent = true;
    }, { code: 'workflow_check_conclusion_changed' });
    assert.equal(sent, false); assert.deepEqual(encode(f.plan), before);
  });
  test(`${format}: an old successful job cannot hide behind a skipped job in the same group`, async t => {
    const f = await fixture(t, format);
    const second = { ...f.job, job: 'second' };
    f.report.runs[0].execution.jobs.push({ id: 'second', outcome: 'succeeded' });
    f.plan.report_sha256 = sha256(encode(f.report)); await writeFile(f.path, encode(f.report));
    await assert.rejects(verifyPlannedConclusions(f.config, f.plan, [f.job, second]), { code: 'workflow_check_conclusion_changed' });
  });
}

test('successful, negative and already terminal groups need no original report for outcome recovery', async () => {
  const config = { watch: { run_parent: '/unavailable-original-runs' } };
  for (const pending of [[], ...['success', 'failure', 'timed_out', 'cancelled'].map(conclusion => [{ conclusion }])]) {
    await verifyPlannedConclusions(config, {}, pending);
  }
});

test('all retained report and execution identity substitutions fail closed', async t => {
  for (const change of [
    f => { f.report.runs[0].execution.jobs[0].outcome = 'succeeded'; },
    f => { f.job.directory += '-other'; },
    f => { f.job.source_commit = '4'.repeat(40); },
    f => { f.job.job = 'other'; },
    f => { f.plan.report_sha256 = '0'.repeat(64); },
  ]) {
    const f = await fixture(t); change(f); await writeFile(f.path, encode(f.report));
    await assert.rejects(verifyPlannedConclusions(f.config, f.plan, [f.job]));
  }
});

test('even a pinned malformed report cannot substitute a different execution or ambiguous slot', async t => {
  for (const change of [
    r => { r.runs[0].executed_commit = '4'.repeat(40); },
    r => { r.runs[0].object_format = 'sha256'; },
    r => { r.runs.push(structuredClone(r.runs[0])); },
    r => { r.runs[0].execution.jobs.push({ id: 'build', outcome: 'skipped' }); },
    r => { r.runs[0].execution.jobs[0].outcome = 'toString'; },
    r => { r.runs[0].execution.jobs[0].outcome = 'failed'; },
  ]) {
    const f = await fixture(t); change(f.report); f.plan.report_sha256 = sha256(encode(f.report));
    await writeFile(f.path, encode(f.report)); await assert.rejects(verifyPlannedConclusions(f.config, f.plan, [f.job]));
  }
});

test('report read remains private, bounded, and cancellation-aware', async t => {
  const f = await fixture(t);
  await chmod(f.path, 0o644);
  await assert.rejects(verifyPlannedConclusions(f.config, f.plan, [f.job]), /private/);
  await chmod(f.path, 0o600);
  await writeFile(f.path, Buffer.alloc(SUBMISSION_REPORT_BYTES + 1));
  await assert.rejects(verifyPlannedConclusions(f.config, f.plan, [f.job]), /bounded/);
  await writeFile(f.path, encode(f.report));
  for (const stopAt of [1, 2, 3, 4, 5]) {
    let count = 0;
    await assert.rejects(verifyPlannedConclusions(f.config, f.plan, [f.job], () => {
      if (++count === stopAt) throw new Error('cancelled');
    }), /cancelled/);
  }
});

test('pins and job selections are owned before asynchronous reads', async t => {
  const f = await fixture(t, 'sha1', 'succeeded'); let calls = 0;
  await assert.rejects(verifyPlannedConclusions(f.config, f.plan, [f.job], () => {
    if (++calls === 2) { f.job.conclusion = 'success'; f.plan.report_sha256 = '0'.repeat(64); }
  }), { code: 'workflow_check_conclusion_changed' });
});

test('pending-work bound is checked before touching any source files', async () => {
  await assert.rejects(verifyPlannedConclusions({}, {}, Array.from({ length: 129 }, () => ({ conclusion: 'action_required' }))), /count/);
});
