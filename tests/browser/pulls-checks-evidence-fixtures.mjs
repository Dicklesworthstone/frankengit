// Deterministic native observation framing for browser consumer tests. These
// fixtures do not claim canonical admission or live server execution coverage.
import { createHash } from 'node:crypto';
import { checkRow, checks, observation } from './pulls-checks-fixtures.mjs';
import { checksReply } from '../../crates/fgit-node/src/smart_http/server/browser/pulls-checks.mjs';

export const evidenceToken = 'd'.repeat(64);
export function report(extra = {}) {
  return { schema_version: 1, profile: 'trusted-local-foreground-v1', authoritative_check: false,
    workflow_source: `alg:2:${'9'.repeat(64)}`, workflow_graph: `alg:2:${'3'.repeat(64)}`,
    shell: '/bin/sh', shell_flags: ['-eu', '-c'], environment: { PATH: '/usr/bin:/bin', LANG: 'C' },
    step_timeout_millis: 60_000, run_timeout_millis: 600_000, stream_bytes: 262144, total_output_bytes: 16777216,
    succeeded: false, jobs: [{ id: 'test', outcome: 'failed', steps: [step()], failure: null }], ...extra };
}
export function step(extra = {}) {
  return { index: 0, name: 'Run tests', script: `alg:2:${'8'.repeat(64)}`, outcome: 'failed', exit_code: 1,
    stdout_hex: Buffer.from('running tests\n').toString('hex'), stderr_hex: Buffer.from('assertion failed\n').toString('hex'),
    elapsed_millis: 12, output_complete: true, workspace_retained: false, ...extra };
}
function nativeJson(value) {
  if (typeof value === 'string') return '"' + value.replace(/["\\\u0000-\u001f]/gu, c => c === '"' || c === '\\' ? `\\${c}` : `\\u${c.codePointAt(0).toString(16).padStart(4, '0')}`) + '"';
  if (Array.isArray(value)) return `[${value.map(nativeJson).join(',')}]`;
  if (value !== null && typeof value === 'object') return `{${Object.entries(value).map(([key, value]) => `${nativeJson(key)}:${nativeJson(value)}`).join(',')}}`;
  return JSON.stringify(value);
}
function u64(value) { const result = Buffer.alloc(8); result.writeBigUInt64BE(BigInt(value)); return result; }
function duration(millis) { const result = Buffer.alloc(16); result.writeBigUInt64BE(BigInt(millis) * 1000000n, 8); return result; }
function field(value) { const bytes = Buffer.from(value); return Buffer.concat([u64(bytes.length), bytes]); }

export function evidenceFixture({ selected = observation(), report: recorded = report(), check: changes = {}, raw = null } = {}) {
  let check = checkRow({ conclusion: 'failure', ...changes });
  const data = selected.reply.pull_request.data ?? selected.reply.pull_request.merge;
  const serialized = recorded === null ? null : nativeJson(recorded);
  const bytes = raw ?? Buffer.concat([
    Buffer.from('frankengit/coordinated-trusted-observation/v1\0'), Buffer.from(check.run_id, 'hex'), Buffer.from(check.attempt_id, 'hex'),
    Buffer.from(selected.head.split(':').at(-1), 'hex'), Buffer.from(selected.binding.tenant, 'hex'), Buffer.from(selected.binding.repository, 'hex'),
    Buffer.from([selected.binding.format === 'sha1' ? 1 : 2]), Buffer.from(data.source_tip, 'hex'), field('browser-test'),
    duration(recorded.step_timeout_millis), duration(recorded.run_timeout_millis), u64(1), u64(1), field(check.job), Buffer.from([0, 0, 0, 1]), field(serialized)
  ]);
  check = { ...check, evidence_bytes: String(bytes.length), evidence_sha256: createHash('sha256').update(bytes).digest('hex') };
  const page = checks({ object_format: selected.binding.format, source_head: selected.reply.source_head, snapshot_token: selected.head,
    source_ref_hex: data.source_ref_hex, target_ref_hex: data.target_ref_hex, source_tip: data.source_tip,
    target_tip: data.target_tip ?? data.target_tip_before, checks: [check] });
  const prior = checksReply(page, selected.reply.pull_request.number, selected, { scope: selected.binding });
  const reply = { schema_version: 1, type: 'pull_request_check_evidence', read_only: true,
    page: { ...page, limit: 1 }, evidence_hex: bytes.toString('hex'), report: serialized === null ? null
      : { offset: bytes.length - Buffer.byteLength(serialized), bytes: Buffer.byteLength(serialized), json: serialized } };
  return { selected, check, prior, reply, bytes, report: recorded };
}
