// Exact canonical workflow evidence, disclosed with its own explicit credential.
// Decoding retained output never turns an observation into merge authority.
import { Transport, copy, fail, hex, integer, keys, showReply, unhex, utf8 } from './pulls-core.mjs';
import { checkId, checksReply } from './pulls-checks.mjs';

export const CHECK_EVIDENCE_LIMIT = 1024 * 1024;
export const CHECK_EVIDENCE_REPLY_LIMIT = 8 * 1024 * 1024;
export const CHECK_LOG_PREVIEW_BYTES = 64 * 1024;
const CHECK_FIELDS = ['id', 'publisher', 'run_id', 'attempt_id', 'graph_root', 'job', 'conclusion', 'evidence_sha256', 'evidence_bytes'];
const REPORT_FIELDS = ['schema_version', 'profile', 'authoritative_check', 'workflow_source', 'workflow_graph',
  'shell', 'shell_flags', 'environment', 'step_timeout_millis', 'run_timeout_millis', 'stream_bytes', 'total_output_bytes', 'succeeded', 'jobs'];
const STEP_FIELDS = ['index', 'name', 'script', 'outcome', 'exit_code', 'stdout_hex', 'stderr_hex', 'elapsed_millis', 'output_complete', 'workspace_retained'];
const STEP_OUTCOMES = ['succeeded', 'failed', 'cancelled', 'timed_out', 'output_limit', 'containment_failure'];
const JOB_CONCLUSIONS = { succeeded: 'success', failed: 'failure', refused: 'failure', output_limit: 'failure',
  skipped: 'action_required', cancelled: 'cancelled', timed_out: 'timed_out' };
function exact(value, fields) {
  keys(value, fields);
  if (fields.some(field => !Object.hasOwn(value, field))) fail('Incomplete workflow evidence record.');
}
function reportText(value, maximum) {
  if (typeof value !== 'string' || value.length > maximum || utf8.encode(value).length > maximum || /[\uD800-\uDFFF]/u.test(value)) fail('Invalid workflow report text.');
}
function commitment(value) {
  if (typeof value !== 'string' || !/^alg:2:[0-9a-f]{64}$/.test(value)) fail('Invalid workflow report commitment.');
}
function boolean(value) { if (typeof value !== 'boolean') fail('Invalid workflow report flag.'); }

// The native decoder owns the binary grammar. This consumer admits only the
// known single-job report schema, after matching its exact span in hashed bytes.
function workflowReport(serialized, check) {
  let report;
  try { report = JSON.parse(serialized); } catch { fail('Invalid workflow report JSON.'); }
  exact(report, REPORT_FIELDS);
  if (report.schema_version !== 1 || report.profile !== 'trusted-local-foreground-v1' || report.authoritative_check !== false ||
      report.shell !== '/bin/sh' || !Array.isArray(report.shell_flags) || report.shell_flags.length !== 2 ||
      report.shell_flags[0] !== '-eu' || report.shell_flags[1] !== '-c') fail('Unsupported workflow report profile.');
  exact(report.environment, ['PATH', 'LANG']);
  if (report.environment.PATH !== '/usr/bin:/bin' || report.environment.LANG !== 'C') fail('Unsupported workflow report environment.');
  commitment(report.workflow_source); commitment(report.workflow_graph);
  if (report.workflow_graph !== `alg:2:${check.graph_root}`) fail('Workflow report changed the selected graph.');
  integer(report.step_timeout_millis, 'step timeout', 0, 3_600_000);
  integer(report.run_timeout_millis, 'run timeout', report.step_timeout_millis, 3_600_000);
  integer(report.stream_bytes, 'stream limit', 1, 2 * 1024 * 1024);
  integer(report.total_output_bytes, 'output limit', 2, 16 * 1024 * 1024); boolean(report.succeeded);
  if (!Array.isArray(report.jobs) || report.jobs.length !== 1) fail('Workflow evidence must describe exactly the selected job.');
  const job = report.jobs[0]; exact(job, ['id', 'outcome', 'steps', 'failure']);
  if (job.id !== check.job || !Object.hasOwn(JOB_CONCLUSIONS, job.outcome) || !Array.isArray(job.steps) || job.steps.length > 512 ||
      report.succeeded !== (job.outcome === 'succeeded')) fail('Workflow report changed the selected job or its outcome.');
  // Older observations deliberately used action_required even for a successful
  // local run. Their report does not upgrade the canonical check conclusion.
  if (check.conclusion !== 'action_required' && JOB_CONCLUSIONS[job.outcome] !== check.conclusion) fail('Workflow report and canonical conclusion disagree.');
  if (job.failure !== null) {
    exact(job.failure, ['detail', 'workspace_retained']); reportText(job.failure.detail, 4096); boolean(job.failure.workspace_retained);
  }
  let previous = -1, output = 0;
  for (const step of job.steps) {
    exact(step, STEP_FIELDS); integer(step.index, 'step index', 0, 511);
    if (step.index <= previous || !STEP_OUTCOMES.includes(step.outcome)) fail('Invalid workflow step order or outcome.');
    previous = step.index;
    if (step.name !== null) reportText(step.name, 8192);
    commitment(step.script);
    if (step.exit_code !== null) integer(step.exit_code, 'exit code', -2147483648, 2147483647);
    integer(step.elapsed_millis, 'elapsed time'); boolean(step.output_complete); boolean(step.workspace_retained);
    for (const stream of ['stdout_hex', 'stderr_hex']) output += unhex(step[stream], Math.min(report.stream_bytes, CHECK_EVIDENCE_LIMIT)).length;
    if (output > report.total_output_bytes) fail('Workflow output exceeds its recorded budget.');
    if (step.outcome === 'succeeded' && (step.exit_code !== 0 || !step.output_complete || step.workspace_retained)) fail('Successful step has inconsistent completion facts.');
  }
  if (job.outcome === 'succeeded' && (job.failure !== null || job.steps.some(step => step.outcome !== 'succeeded'))) fail('Successful job has inconsistent step facts.');
  return report;
}

export async function checkEvidenceReply(reply, number, observed, check, cryptoImpl = globalThis.crypto) {
  exact(reply, ['schema_version', 'type', 'read_only', 'page', 'evidence_hex', 'report']);
  if (reply.schema_version !== 1 || reply.type !== 'pull_request_check_evidence' || reply.read_only !== true) fail('Unsupported workflow evidence response.');
  const page = checksReply(reply.page, number, observed, { limit: 1, scope: observed.binding });
  if (!page.reply.found || !page.reply.source_current || page.reply.checks.length !== 1 || !page.reply.complete ||
      CHECK_FIELDS.some(field => page.reply.checks[0][field] !== check[field])) fail('Workflow evidence changed the selected canonical check.');
  const bytes = unhex(reply.evidence_hex, CHECK_EVIDENCE_LIMIT);
  if (String(bytes.length) !== check.evidence_bytes) fail('Workflow evidence length differs from the selected check.');
  const digest = hex(new Uint8Array(await cryptoImpl.subtle.digest('SHA-256', bytes)));
  if (digest !== check.evidence_sha256) fail('Workflow evidence digest differs from the selected check.');
  let report = null;
  if (reply.report !== null) {
    const span = reply.report; exact(span, ['offset', 'bytes', 'json']);
    integer(span.offset, 'report offset', 8, bytes.length); integer(span.bytes, 'report length', 1, bytes.length);
    reportText(span.json, CHECK_EVIDENCE_LIMIT);
    const encoded = utf8.encode(span.json);
    if (span.offset + span.bytes !== bytes.length || encoded.length !== span.bytes ||
        new DataView(bytes.buffer, bytes.byteOffset + span.offset - 8, 8).getBigUint64(0) !== BigInt(span.bytes) ||
        encoded.some((byte, index) => bytes[span.offset + index] !== byte)) fail('Workflow report is not the exact length-framed evidence suffix.');
    report = workflowReport(span.json, check);
  }
  return { binding: page.binding, head: page.head, check: copy(check), bytes, report };
}

export class CheckEvidenceClient {
  #transport; #serial = 0;
  constructor(options) { this.#transport = new Transport({ ...options, checkEvidenceOnly: true }); }
  get connected() { return this.#transport.connected; }
  async connect(token) { this.#serial += 1; await this.#transport.connect(token); }
  disconnect() { this.#serial += 1; this.#transport.disconnect(); }
  cancelReads() { this.#serial += 1; this.#transport.cancelReads(); }
  async read(number, observed, checksPage, id) {
    integer(number, 'PR number', 1); checkId(id);
    const saved = copy(observed), savedPage = copy(checksPage);
    const selected = showReply(saved.reply, number, { head: saved.head, scope: saved.binding });
    if (!selected.reply.found) fail('Select an available PR before loading workflow evidence.');
    const prior = checksReply(savedPage.reply, number, selected, { after: savedPage.reply.after, limit: savedPage.reply.limit, scope: selected.binding });
    const check = prior.reply.checks.find(row => row.id === id);
    if (!prior.reply.found || !prior.reply.source_current || !check) fail('Select a published check from this exact PR snapshot.');
    const epoch = this.#transport.epoch, serial = ++this.#serial;
    const guard = () => { if (!this.connected || epoch !== this.#transport.epoch || serial !== this.#serial) fail('Workflow evidence read superseded.'); };
    const query = new URLSearchParams({ check: id, expected_head: selected.head });
    let raw;
    try {
      raw = await this.#transport.request(`pulls/${number}/checks/evidence?${query}`, { maximum: CHECK_EVIDENCE_REPLY_LIMIT });
    } catch (error) {
      // A current disclosure refusal invalidates this evidence connection.
      // Recheck ownership after the await: a queued reconnect or newer read
      // must not be disconnected by this earlier request's rejection.
      if (error.status === 403 && epoch === this.#transport.epoch && serial === this.#serial) this.disconnect();
      throw error;
    }
    guard();
    const result = await checkEvidenceReply(raw.value, number, selected, check, this.#transport.crypto);
    guard(); return result;
  }
}

// One credential and a bounded set of loaded outputs belong to this selected
// PR panel. The owner closes it on selection changes, disconnect and pagehide.
export function appendCheckEvidenceAccess(doc, parent, { observed, run, current, status, displayText, displayBytes, download, clientOptions }) {
  const client = new CheckEvidenceClient(clientOptions), entries = new Set();
  let closed = false, busy = false, revision = 0;
  const live = () => !closed && current();
  const item = (target, tag, text = '') => { const node = doc.createElement(tag); node.textContent = displayText(text); target.append(node); return node; };
  const button = (target, label, action) => { const node = item(target, 'button', label); node.type = 'button';
    node.addEventListener('click', event => { event.preventDefault(); action(); }); return node; };
  const access = item(parent, 'section'); item(access, 'h4', 'Workflow evidence and retained logs');
  item(access, 'p', 'Use a separate repository credential with both pulls-read and artifact-read. It stays in memory for this selected PR only. The PR connection is not reused, and viewing logs never grants merge permission.');
  const label = item(access, 'label', 'Evidence credential (pulls-read + artifact-read)');
  const token = item(label, 'input'); token.type = 'password'; token.autocomplete = 'off'; token.spellcheck = false; token.maxLength = 64;
  const note = item(access, 'p', 'Evidence is disconnected. Checks can still be read with the PR credential.');
  const connect = button(access, 'Connect evidence credential', () => void run('read', async guard => {
    if (!live()) fail('The selected PR changed.');
    const credential = token.value; token.value = ''; const generation = ++revision;
    reset(); busy = true; controls();
    try {
      await client.connect(credential); guard();
      if (!live() || generation !== revision) return;
      note.textContent = 'Credential held in memory. The node will check pulls-read and artifact-read when evidence is loaded.';
      status('Evidence credential selected. Choose a published check to read its exact retained evidence.');
    } catch (error) {
      guard(); if (!live() || generation !== revision) return;
      note.textContent = displayText(error.message || 'Evidence credential unavailable.'); throw error;
    } finally { if (generation === revision) { busy = false; controls(); } }
  }));
  const disconnect = button(access, 'Disconnect evidence', () => {
    revision += 1; busy = false; client.disconnect(); token.value = ''; reset(); controls();
    note.textContent = 'Evidence disconnected. Its credential and retained log views were cleared.';
  });
  function controls() {
    const available = live(); token.disabled = !available || busy; connect.disabled = !available || busy;
    disconnect.disabled = !available || (!client.connected && !busy);
    for (const entry of entries) {
      entry.load.disabled = !available || busy || !client.connected;
      entry.download.disabled = !available || busy || !client.connected || entry.result === null;
      for (const control of entry.exports) control.disabled = !available || busy || !client.connected || entry.result === null;
    }
  }
  function clear(entry) { entry.result = null; entry.output.replaceChildren(); entry.exports = []; }
  function reset() { for (const entry of entries) clear(entry); }
  function requireEntry(entry) {
    if (!live() || !client.connected || !entry.result) fail('Reload evidence for the selected PR with its scoped credential.');
    return entry.result;
  }
  function render(entry) {
    const result = entry.result; entry.output.replaceChildren(); entry.exports = [];
    item(entry.output, 'p', `Canonical evidence verified: ${result.bytes.length} bytes · SHA-256 ${result.check.evidence_sha256}. The published conclusion remains ${result.check.conclusion}.`);
    if (result.report === null) {
      item(entry.output, 'p', 'These exact evidence bytes are available for download. This evidence format has no supported retained-log view.'); return;
    }
    const report = result.report, job = report.jobs[0];
    item(entry.output, 'p', `Trusted foreground job observation: ${job.outcome}. Retained output is publisher evidence, not independent execution verification.`);
    if (job.failure) item(entry.output, 'pre', `Job failure: ${job.failure.detail}\nWorkspace retained: ${job.failure.workspace_retained}`);
    if (!job.steps.length) item(entry.output, 'p', 'No step output is recorded for this job.');
    for (const step of job.steps) {
      const section = item(entry.output, 'details');
      item(section, 'summary', `Step ${step.index + 1}${step.name === null ? '' : ` · ${step.name}`} · ${step.outcome}`);
      item(section, 'pre', `Exit: ${step.exit_code ?? '(not recorded)'} · elapsed: ${step.elapsed_millis} ms\nScript: ${step.script}\nWorkspace retained: ${step.workspace_retained}`);
      item(section, 'p', step.output_complete ? 'The observation marks this step output complete.'
        : 'INCOMPLETE OUTPUT: the observation did not capture all step output. A verified download preserves only the retained bytes.');
      for (const stream of ['stdout', 'stderr']) {
        const value = step[`${stream}_hex`], size = value.length / 2, preview = value.slice(0, CHECK_LOG_PREVIEW_BYTES * 2);
        item(section, 'h5', `${stream} · ${size} retained bytes`);
        item(section, 'pre', size ? displayBytes(preview) : '(empty retained stream)');
        if (preview.length < value.length) item(section, 'p', `Preview clipped to ${CHECK_LOG_PREVIEW_BYTES} bytes. Download preserves all ${size} retained bytes; capture completeness is unchanged.`);
        const save = button(section, `Download step ${step.index + 1} ${stream}`, () => void run('export', async () => {
          requireEntry(entry);
          download(`${entry.filename}-step-${step.index + 1}-${stream}.log`, unhex(value, CHECK_EVIDENCE_LIMIT), 'application/octet-stream');
          status(`Downloaded ${stream} exactly as retained in the selected check evidence.`);
        }));
        entry.exports.push(save);
      }
    }
  }
  function appendCheck(parent, page, check) {
    const section = item(parent, 'section'), entry = { result: null, exports: [], filename: `frankengit-pr-${page.reply.number}-${check.id.replace('/', '-')}` };
    entry.load = button(section, 'Load evidence and logs', () => void run('read', async guard => {
      if (!live()) fail('The selected PR changed.');
      const generation = revision; clear(entry); busy = true; controls();
      item(entry.output, 'p', 'Reading and verifying the selected canonical evidence…');
      try {
        const result = await client.read(observed.reply.pull_request.number, observed, page, check.id); guard();
        if (!live() || generation !== revision) return;
        entry.result = result; render(entry);
        status('Exact canonical workflow evidence verified. Its retained logs do not grant merge permission.');
      } catch (error) {
        guard(); if (!live() || generation !== revision) return;
        if (!client.connected) {
          reset(); token.value = '';
          note.textContent = error.status === 403
            ? 'Evidence access refused. Its credential and retained log views were cleared. Reconnect with both pulls-read and artifact-read.'
            : 'Evidence credential rejected or revoked. Retained log views were cleared.';
        }
        clear(entry); item(entry.output, 'p', `Evidence unavailable: ${error.message || 'read failed'}. No log content or download has been selected.`);
        throw error;
      } finally { if (generation === revision) { busy = false; controls(); } }
    }));
    entry.download = button(section, 'Download exact check evidence', () => void run('export', async () => {
      const result = requireEntry(entry);
      download(`${entry.filename}.evidence`, result.bytes.slice(), 'application/octet-stream');
      status('Downloaded the exact hash-verified canonical evidence bytes, without credentials.');
    }));
    entry.output = item(section, 'div'); entries.add(entry); controls();
  }
  controls();
  return { appendCheck,
    clearRows() { client.cancelReads(); reset(); entries.clear(); },
    close() { closed = true; revision += 1; busy = false; client.disconnect(); token.value = ''; reset(); controls(); entries.clear(); }
  };
}
