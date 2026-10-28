// Join retained native log receipts to already-validated execution observations.
// This is a consistency check, not payload-store verification or CI authority.
import { createHash } from 'node:crypto';
import { fail } from './workflow_watch_io.mjs';

const MIB = 1024 * 1024;
const OUTCOMES = ['succeeded', 'failed', 'cancelled', 'timed_out', 'output_limit', 'refused'];
const LOG_FIELDS = ['step_index', 'step_name_hex', 'script_sha256', 'stream',
  'observed_step_outcome', 'exit_code', 'output_complete', 'artifact_id_sha256', 'payload_sha256', 'payload_bytes'];
const hex = value => Buffer.from(value).toString('hex');
function fields(value, expected) {
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
      Object.keys(value).length !== expected.length || expected.some(key => !Object.hasOwn(value, key))) {
    fail('Missing or unsupported native log receipt fields.');
  }
}
function digest(value) {
  if (typeof value !== 'string' || !/^[0-9a-f]{64}$/.test(value)) fail('Invalid native log commitment.');
}
function observedOutcome(observed, job) {
  if (!OUTCOMES.includes(observed) || (observed === 'succeeded' && job.steps.some(step =>
      step.outcome !== 'succeeded' || step.exit_code !== 0 || step.output_complete !== true))) return false;
  if (observed === job.outcome) return true;
  // The native receipt precedes the final custody/deadline checkpoint. A late
  // refusal or stop can downgrade it, never promote it into a green result.
  return (observed === 'succeeded' && job.outcome === 'refused' && job.failure != null) ||
    (['succeeded', 'failed'].includes(observed) && ['cancelled', 'timed_out'].includes(job.outcome));
}

// Caller owns one totals object across ALL workflow children and has already
// validated the immutable artifact contract and bounded execution report.
export function verifyArtifactLogs(config, run, totals) {
  if (config.capture_logs !== true) {
    if (Object.hasOwn(run, 'artifact_logs')) fail('Native execution introduced unrequested artifact logs.');
    return;
  }
  const jobs = run.execution.jobs;
  if (!Array.isArray(jobs) || jobs.length > 128 || !Array.isArray(run.artifact_logs) || run.artifact_logs.length > jobs.length) {
    fail('Invalid bounded native job log receipt array.');
  }
  const owners = new Map(jobs.map(job => [hex(job.id), job])), captured = new Set();
  for (const receipt of run.artifact_logs) {
    fields(receipt, ['job_id_hex', 'manifest_id_sha256', 'observed_job_outcome', 'logs']);
    const job = owners.get(receipt.job_id_hex);
    if (!job || job.outcome === 'skipped' || !Array.isArray(job.steps) || !job.steps.length || job.steps.length > 512 ||
        captured.has(receipt.job_id_hex) || !observedOutcome(receipt.observed_job_outcome, job)) {
      fail('Unexpected, duplicate or contradictory native job log receipt.');
    }
    digest(receipt.manifest_id_sha256);
    if (!Array.isArray(receipt.logs) || receipt.logs.length !== 2 * job.steps.length) fail('Native step log capture is incomplete.');
    let position = 0;
    for (const step of job.steps) {
      for (const stream of ['stdout', 'stderr']) {
        const log = receipt.logs[position++];
        fields(log, LOG_FIELDS);
        digest(log.script_sha256); digest(log.artifact_id_sha256); digest(log.payload_sha256);
        if (log.step_index !== step.index || log.step_name_hex !== (step.name === null ? null : hex(step.name)) ||
            `alg:2:${log.script_sha256}` !== step.script || log.stream !== stream ||
            log.observed_step_outcome !== step.outcome || log.exit_code !== step.exit_code ||
            log.output_complete !== step.output_complete) fail('Native retained log changed its step or stream observation.');
        const raw = step[`${stream}_hex`];
        // Check before decoding: neither a receipt nor a direct caller may
        // enlarge the native stream envelope or per-artifact allowance.
        if (typeof raw !== 'string' || raw.length > 4 * MIB || raw.length > config.maximum_file_mib * 2 * MIB ||
            !/^(?:[0-9a-f]{2})*$/.test(raw) || !Number.isSafeInteger(log.payload_bytes) ||
            log.payload_bytes !== raw.length / 2) fail('Native retained log changed its bounded payload length.');
        const bytes = Buffer.from(raw, 'hex');
        if (createHash('sha256').update(bytes).digest('hex') !== log.payload_sha256) {
          fail('Native retained log differs from the executed stream bytes.');
        }
        const next = (totals.artifactPayload ?? 0) + bytes.length;
        if (!Number.isSafeInteger(next) || next > config.total_payload_mib * MIB) {
          fail('Native artifact observations exceed the shared dispatch allowance.');
        }
        totals.artifactPayload = next;
      }
    }
    captured.add(receipt.job_id_hex);
  }
  for (const job of jobs) {
    if (job.outcome === 'succeeded' && job.steps.length && !captured.has(hex(job.id))) {
      fail('Successful native job is missing its retained logs.');
    }
  }
}
