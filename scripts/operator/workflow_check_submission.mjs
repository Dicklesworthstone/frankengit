// A runtime upgrade must not reinterpret an already sealed publication plan.
// Older plans called BOTH succeeded and skipped ActionRequired. Only the latter
// still has that meaning. Read the ORIGINAL pinned dispatch report before any
// pending ActionRequired job in a group can start or resend a native mutation.
// Terminal/outcome recovery does not use this path or need original run files.
import { join } from 'node:path';
import { directory, readPrivate, parseJson, fail } from './workflow_watch_io.mjs';
import { encode, sha256, digest, conclusion, oid } from './workflow_check_protocol.mjs';

export const SUBMISSION_REPORT_BYTES = 40 * 1024 * 1024;
export async function verifyPlannedConclusions(config, plan, pending, checkpoint = () => {}) {
  checkpoint();
  if (!Array.isArray(pending) || pending.length > 128) fail('Invalid pending workflow publication count.');
  const selected = pending.filter(job => job.conclusion === 'action_required').map(job => ({ ...job }));
  if (!selected.length) return;
  // Own scalar pins before asynchronous I/O. No input path from a report is
  // opened; the watcher ID and configured run parent select the sole report.
  const watchId = digest(plan.watch_id), expected = digest(plan.report_sha256);
  const format = config.watch.object_format;
  const parent = join(config.watch.run_parent, `dispatch-${watchId.slice(0, 32)}`);
  await directory(parent); checkpoint();
  const bytes = await readPrivate(join(parent, 'report.json'), SUBMISSION_REPORT_BYTES);
  checkpoint();
  const report = parseJson(bytes, SUBMISSION_REPORT_BYTES);
  if (sha256(encode(report)) !== expected || !Array.isArray(report.runs) || report.runs.length > 32) {
    fail('Original pinned workflow report is unavailable or changed; retain the original publication plan.');
  }
  for (const job of selected) {
    checkpoint();
    const runs = report.runs.filter(run => run && typeof run.run_id === 'string' && /^[0-9a-f]{32}$/.test(run.run_id) &&
      join(parent, `workflow-${run.run_id}`) === job.directory);
    if (runs.length !== 1) fail('Original publication job lost its exact workflow run.');
    const run = runs[0];
    if (run.object_format !== format || oid(run.source_commit, format) !== job.source_commit ||
        oid(run.executed_commit, format) !== job.source_commit || !Array.isArray(run.execution?.jobs) || run.execution.jobs.length > 128) {
      fail('Original publication job changed its executed source.');
    }
    const jobs = run.execution.jobs.filter(value => value && value.id === job.job);
    if (jobs.length !== 1) fail('Original publication job is missing or repeated.');
    if (conclusion(jobs[0].outcome) !== job.conclusion) {
      const error = new Error('Saved workflow conclusion predates native success publication. Retain the original plan and key; use outcome recovery, not automatic re-keying or workflow execution.');
      error.code = 'workflow_check_conclusion_changed';
      throw error;
    }
  }
  checkpoint();
}
