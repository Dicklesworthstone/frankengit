// Canonical publisher observations at one exact PR snapshot. This profile has
// no successful protected-check conclusion and never grants merge permission.
import { binding, fail, integer, keys, oid, pinned, principal, record, text, unhex } from './pulls-core.mjs';

const BINDING_FIELDS = ['source_head', 'snapshot_token', 'pull_request_version',
  'source_ref_hex', 'target_ref_hex', 'source_tip', 'target_tip', 'source_current'];
const REPLY_FIELDS = ['schema_version', 'type', 'tenant_id', 'repository_id', 'repository_incarnation',
  'object_format', 'number', 'found', ...BINDING_FIELDS, 'after', 'limit', 'next_after',
  'complete', 'scope', 'merge_permission', 'checks'];
const CONCLUSIONS = ['action_required', 'failure', 'cancelled', 'timed_out'];

export function checkId(value) {
  // Native base32hex labels contain all 256 identity bits. The final four
  // padding bits must be zero; aliases cannot become pagination cursors.
  if (typeof value !== 'string' || !/^check\/[0-9a-v]{51}[0g]$/.test(value)) fail('Invalid workflow check identity.');
  return value;
}
function digest(value) {
  if (typeof value !== 'string' || !/^[0-9a-f]{64}$/.test(value)) fail('Invalid workflow evidence digest.');
  return value;
}
function decimalString(value, name, maximum = 18446744073709551615n) {
  if (typeof value !== 'string' || !/^[1-9][0-9]{0,19}$/.test(value) || BigInt(value) > maximum) fail(`Invalid ${name}; a positive exact decimal string is required.`);
  return value;
}
export function checksReply(reply, number, observed, { after = null, limit = 20, scope = null } = {}) {
  integer(number, 'PR number', 1); integer(limit, 'page size', 1, 100);
  if (after !== null) checkId(after);
  keys(reply, REPLY_FIELDS);
  const selectedBinding = binding(reply, scope ?? observed.binding);
  if (reply.type !== 'pull_request_checks' || decimalString(reply.number, 'PR number') !== String(number) ||
      typeof reply.found !== 'boolean' || reply.scope !== 'trusted_workflow_observations' || reply.merge_permission !== null ||
      reply.after !== after || reply.limit !== limit || typeof reply.complete !== 'boolean' ||
      reply.complete !== (reply.next_after === null) || !Array.isArray(reply.checks) || reply.checks.length > limit) fail('Invalid workflow checks page.');
  if (!reply.found) {
    if (reply.checks.length || reply.next_after !== null || BINDING_FIELDS.some(name => reply[name] !== null)) fail('Unavailable checks disclosed a subject or observation.');
    return { reply, binding: selectedBinding, head: null };
  }
  if (typeof reply.snapshot_token !== 'string' || !/^alg:2:[0-9a-f]{64}$/.test(reply.snapshot_token)) fail('Invalid workflow checks snapshot.');
  const selected = pinned(reply, selectedBinding, observed.head), row = record(observed.reply.pull_request);
  const data = row.data ?? row.merge;
  if (!data || reply.source_head !== observed.reply.source_head ||
      decimalString(reply.pull_request_version, 'PR version') !== String(row.version) || typeof reply.source_current !== 'boolean') fail('Workflow checks changed the selected PR subject.');
  if (!reply.source_current && (reply.checks.length || reply.next_after !== null)) fail('A stale source cannot disclose workflow observations.');
  for (const name of ['source_ref_hex', 'target_ref_hex']) {
    const bytes = unhex(reply[name], 1024);
    if (!bytes.length || bytes.includes(0) || reply[name] !== data[name]) fail('Workflow checks changed the recorded ref bytes.');
  }
  for (const name of ['source_tip', 'target_tip']) {
    const expected = name === 'target_tip' && row.data === null ? data.target_tip_before : data[name];
    if (reply[name] !== oid(reply[name], selected.binding.format) || reply[name] !== oid(expected, selected.binding.format)) fail('Workflow checks changed the recorded native tips.');
  }
  let previous = after;
  for (const check of reply.checks) {
    keys(check, ['id', 'publisher', 'run_id', 'attempt_id', 'graph_root', 'job', 'conclusion', 'evidence_sha256', 'evidence_bytes']);
    checkId(check.id); principal(check.publisher);
    if (previous !== null && check.id <= previous) fail('Workflow check order repeated or moved backwards.');
    previous = check.id;
    for (const name of ['run_id', 'attempt_id', 'graph_root', 'evidence_sha256']) digest(check[name]);
    text(check.job, 1024, 'workflow job');
    if (!check.job.length || /[\u0000-\u001f\u007f-\u009f]/u.test(check.job) || !CONCLUSIONS.includes(check.conclusion)) fail('Unsupported workflow check observation.');
    decimalString(check.evidence_bytes, 'workflow evidence byte count', 1024n * 1024n);
  }
  if (reply.next_after !== null && (checkId(reply.next_after) !== previous || reply.checks.length !== limit)) fail('Invalid workflow check continuation.');
  return { ...selected, reply };
}

export function appendChecksPanel(doc, parent, { client, observed, run, current, status, displayText }) {
  const element = (tag, value = '') => { const node = doc.createElement(tag); node.textContent = displayText(value); return node; };
  const item = (target, tag, value) => { const node = element(tag, value); target.append(node); return node; };
  const panel = element('section'), output = element('div'), paging = element('div');
  item(panel, 'h3', 'Published workflow observations');
  item(panel, 'p', 'These authenticated publisher observations refer to the recorded source ref and commit. They do not establish independent execution verification or merge permission.');
  const load = item(panel, 'button', 'Load checks at this snapshot'); load.type = 'button';
  item(output, 'p', 'Checks have not been loaded for this PR snapshot.');
  panel.append(output, paging); parent.append(panel);
  function render(result) {
    const reply = result.reply; output.replaceChildren();
    if (!reply.found) { item(output, 'p', 'Checks unavailable: this PR or its recorded source is absent or not disclosed. No observation result is established.'); return; }
    item(output, 'pre', `PR #${reply.number} · version ${reply.pull_request_version}\nSnapshot: ${result.head}\n` +
      `Source ref bytes: ${reply.source_ref_hex}\nRecorded source: ${reply.source_tip}\nRecorded target: ${reply.target_tip}`);
    item(output, 'p', reply.source_current ? 'The source ref names this recorded source commit at the selected snapshot.'
      : 'STALE SOURCE: observations are withheld because the source ref no longer names the recorded PR source commit. Refresh the PR metadata explicitly to select its replacement.');
    if (!reply.source_current) return;
    if (!reply.checks.length) item(output, 'p', reply.after === null
      ? 'No published workflow observations exist for this exact recorded source ref and commit at this snapshot. This does not mean checks passed or that no local workflow ran.'
      : 'No further workflow observations remain after this cursor at the selected snapshot.');
    for (const check of reply.checks) {
      const section = item(output, 'section', '');
      item(section, 'h4', `${check.job} · ${check.conclusion}`);
      item(section, 'pre', `Check: ${check.id}\nPublisher: ${check.publisher}\nRun: ${check.run_id}\n` +
        `Attempt: ${check.attempt_id}\nWorkflow graph: ${check.graph_root}\nEvidence: ${check.evidence_sha256} · ${check.evidence_bytes} bytes`);
      if (check.conclusion === 'action_required') item(section, 'p', 'Independent verification is still required. This observation is not a passing required check.');
    }
    item(output, 'p', reply.complete ? 'All observations after this page cursor are shown.' : 'More observations remain at this exact snapshot.');
    if (reply.next_after !== null) {
      const next = item(paging, 'button', 'Next checks page'); next.type = 'button';
      next.addEventListener('click', event => { event.preventDefault(); void read(reply.next_after); });
    }
  }
  function read(after = null) {
    return run('read', async guard => {
      if (!current()) fail('The selected PR changed.');
      output.replaceChildren(); paging.replaceChildren(); load.disabled = true;
      item(output, 'p', 'Loading observations at the selected PR snapshot…');
      try {
        const result = await client.checks(observed.reply.pull_request.number, observed, { after }); guard();
        if (!current()) fail('The selected PR changed.');
        render(result);
        status(result.reply.found ? 'Workflow observations loaded at the selected PR snapshot. They do not grant merge permission.'
          : 'Workflow observations are unavailable; no check result has been inferred.');
      } catch (error) {
        guard();
        if (current()) {
          output.replaceChildren(); paging.replaceChildren();
          item(output, 'p', `Checks unavailable: ${error.message || 'read failed'}. The selected PR snapshot remains unchanged; reload the PR explicitly to select a new snapshot.`);
        }
        throw error;
      } finally { load.disabled = !current(); }
    });
  }
  load.addEventListener('click', event => { event.preventDefault(); void read(); });
}
