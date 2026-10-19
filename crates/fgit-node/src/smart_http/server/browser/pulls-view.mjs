// Human PR workflow over the native client. Every source string is inert data;
// preparing, inspecting and displaying approvals never submits a mutation.
import { PullClient } from './pulls.mjs';
import { markdownBody } from './markdown.mjs';
import { decimal, oid, unhex, fail, showReply } from './pulls-core.mjs';
import { RECEIPT_LIMIT, fastForwardCommand, ProtectionClient, protectionPolicy, protectionChanges } from './pulls-actions.mjs';
import { candidateMethod } from './pulls-candidate.mjs';
import { ResolutionEditor } from './pulls-resolution-view.mjs';
import { appendChecksPanel } from './pulls-checks.mjs';

export const DISPLAY_BYTES = 512 * 1024;
const DISPLAY_HUNKS = 256;
export function displayText(value) {
  return String(value).replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f\u202a-\u202e\u2066-\u2069]/gu,
    c => `\\u${c.codePointAt(0).toString(16).padStart(4, '0')}`);
}
export function displayBytes(value) {
  const bytes = unhex(value);
  try { return displayText(new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes)); }
  catch { return Array.from(bytes, byte => byte >= 32 && byte <= 126 && byte !== 92 ? String.fromCharCode(byte)
    : byte === 10 ? '\n' : `\\x${byte.toString(16).padStart(2, '0')}`).join(''); }
}
function element(doc, tag, value = '') {
  const el = doc.createElement(tag); el.textContent = displayText(value); return el;
}
function item(doc, parent, tag, value) { const el = element(doc, tag, value); parent.append(el); return el; }
function nativeRef(data, name) { return data[name] === null ? `byte ref: ${data[`${name}_hex`]}` : data[name]; }
function identity(entry) { return entry === null ? '(absent)' : `${entry.mode.toString(8)} ${entry.oid}`; }

export function renderCommentAnchor(doc, parent, anchor, status = null) {
  item(doc, parent, 'p', `Source comment · ${anchor.side === 'before' ? 'Before' : 'After'} · ${displayBytes(anchor.path_hex)} · ` +
    `lines ${anchor.line_start + 1}–${anchor.line_start + anchor.line_count}`);
  if (status !== null) item(doc, parent, 'p', status === 'exact'
    ? 'Exact at this conversation snapshot: the recorded PR coordinates still match.'
    : 'Outdated: the PR coordinates changed. This comment remains attached to its original source; it has not been moved to new lines.');
  item(doc, parent, 'pre', `PR version ${anchor.pull_request_version} · ${anchor.comparison === 'merge_base' ? 'merge-base' : 'direct'} comparison\n` +
    `Source ${anchor.source_tip}\nTarget ${anchor.target_tip}\nCompared base ${anchor.compared_base}\n` +
    `Blob ${anchor.blob} · mode ${anchor.mode}\nBytes ${anchor.byte_start}–${anchor.byte_end} (end exclusive)\nPath bytes ${anchor.path_hex}`);
}

// The validated full report is retained for download; rendering has a separate
// ceiling. Clipping never changes the comparison receipt or omits a path label.
export function renderInspection(doc, parent, report) {
  parent.replaceChildren();
  item(doc, parent, 'h3', `Inspected candidate ${report.candidate_commit}`);
  item(doc, parent, 'pre', `PR #${report.subject.pull_request} · version ${report.subject.pull_request_version} · policy ${report.subject.policy_epoch}\n` +
    `Base: ${report.merge_base}\nNative parents: ${report.parents.join(', ')}\n` +
    `Bundle: ${report.bundle.bytes} bytes · SHA-256 ${report.bundle.sha256}\nSnapshot: ${report.snapshot_token}`);
  item(doc, parent, 'p', 'Read-only inspection. No objects staged, review recorded, or merge authorized. Binary bodies are not included.');
  return renderComparison(doc, parent, report.comparison, 'inspection');
}
export function renderPullDiff(doc, parent, result) {
  const report = result.reply;
  parent.replaceChildren();
  item(doc, parent, 'h3', `PR #${report.pull_request.number} changes · ${report.mode}`);
  item(doc, parent, 'pre', `PR version ${report.pull_request.version} · snapshot ${report.snapshot_token}\n` +
    `Recorded target: ${report.requested_before}\nRecorded source: ${report.requested_after}\n` +
    `Compared base: ${report.compared_before}\nBefore tree: ${report.before_tree}\nAfter tree: ${report.after_tree}`);
  item(doc, parent, 'p', report.mode === 'merge-base'
    ? 'Changes from the native merge base to the recorded PR source. This is not the result of merging into the target.'
    : 'Direct tree comparison from the recorded target to the recorded source, including target-only divergence.');
  item(doc, parent, 'p', 'Read-only, snapshot-bound source evidence. No candidate, approval, transaction or publication is created. Object identities are server-reported, not independently proven by these hunks.');
  return renderComparison(doc, parent, result.comparison, 'diff');
}
function renderComparison(doc, parent, comparison, kind) {
  let remaining = DISPLAY_BYTES, shownHunks = 0, clipped = false;
  if (!comparison.entries.length) item(doc, parent, 'p', kind === 'inspection'
    ? 'No changed paths in this exact candidate comparison. The commit identity is still significant.'
    : 'No changed paths in this complete selected comparison. This does not establish mergeability or approval.');
  for (const entry of comparison.entries) {
    const section = element(doc, 'section'); parent.append(section);
    item(doc, section, 'h4', `${entry.kind}: ${displayBytes(entry.path_hex)}`);
    item(doc, section, 'pre', `Path bytes: ${entry.path_hex}\nBefore: ${identity(entry.before)}\nAfter: ${identity(entry.after)}`);
    const content = entry.content;
    if (content.type !== 'text') {
      item(doc, section, 'p', content.type === 'binary' ? `Binary change: ${content.before_bytes} → ${content.after_bytes} bytes; bodies omitted.`
        : content.type === 'object_only' ? 'Object-only change; content was not read. This is not an empty text diff.'
          : 'Content identity unchanged; inspect the path, mode and object identities above.');
      continue;
    }
    item(doc, section, 'p', `${content.algorithm}: +${content.additions} / −${content.deletions}; ${content.hunks.length} hunks.`);
    for (const hunk of content.hunks) {
      if (shownHunks >= DISPLAY_HUNKS || remaining === 0) { clipped = true; break; }
      shownHunks += 1;
      item(doc, section, 'h5', `Old bytes ${hunk.old.byte_start}–${hunk.old.byte_end}; new bytes ${hunk.new.byte_start}–${hunk.new.byte_end}`);
      for (const [label, bytes] of [['Before', hunk.before_hex], ['After', hunk.after_hex]]) {
        const count = Math.min(bytes.length / 2, remaining); remaining -= count;
        item(doc, section, 'p', label);
        item(doc, section, 'pre', displayBytes(bytes.slice(0, count * 2)) || '(empty byte span)');
        if (count * 2 !== bytes.length) { clipped = true; item(doc, section, 'p', 'This byte span is clipped in the display.'); }
      }
    }
  }
  if (clipped) item(doc, parent, 'p', `DISPLAY CLIPPED: not every hunk or byte is shown. Download the full ${kind} JSON before completing review. All changed path labels remain above.`);
  return { clipped, shownHunks };
}
// The selected show() observation, not the editable metadata/candidate forms,
// supplies every fast-forward coordinate. This is a proposal, not proof that
// the source descends from the target or that current protection permits it.
export function fastForwardProposal(observed, scope) {
  if (!scope || !observed || observed.head === null || observed.head === undefined) fail('Load a repository-bound PR snapshot first.');
  const selected = showReply(observed.reply, observed.reply?.number, { head: observed.head, scope });
  const row = selected.reply.pull_request;
  if (!row || row.state !== 'open' || !row.data) fail('Fast-forward requires an open PR with recorded metadata.');
  return { number: row.number, fields: fastForwardCommand({ object_format: selected.binding.format,
    pull_request_version: row.version, source_ref: row.data.source_ref, target_ref: row.data.target_ref,
    source_tip: row.data.source_tip, target_tip: row.data.target_tip }) };
}

function downloader(doc) {
  const view = doc.defaultView, urls = new Set();
  view.addEventListener('pagehide', () => { for (const url of urls) view.URL.revokeObjectURL(url); urls.clear(); });
  return (name, text) => {
    const url = view.URL.createObjectURL(new Blob([text], { type: 'application/json' })); urls.add(url);
    const link = doc.createElement('a'); link.href = url; link.download = name; doc.body.append(link); link.click(); link.remove();
    view.setTimeout(() => { view.URL.revokeObjectURL(url); urls.delete(url); }, 30_000);
  };
}
async function fileText(input) {
  const file = input.files?.[0], count = input.files?.length; input.value = '';
  if (!file || count !== 1 || file.size > RECEIPT_LIMIT) fail('Choose one receipt no larger than 24 MiB.');
  const bytes = new Uint8Array(await file.arrayBuffer());
  if (bytes.length > RECEIPT_LIMIT || bytes.length !== file.size) fail('Invalid receipt size.');
  return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
}
const IDS = ['connection', 'token', 'recovery-only', 'original-principal', 'connection-mode', 'disconnect', 'status', 'refresh', 'pr-list', 'list-paging', 'select-pr', 'select-number', 'select-load',
  'comments-load', 'comments-limit', 'conversation', 'comment-paging', 'comment-form', 'comment-version', 'comment-body', 'comment-stage',
  'selected', 'snapshot', 'reviews-load', 'reviews', 'review-paging', 'metadata', 'pr-number', 'metadata-action', 'expected-version',
  'object-format', 'source-ref', 'target-ref', 'source-tip', 'target-tip', 'title', 'body', 'metadata-stage', 'new-pr',
  'prepare', 'candidate-method', 'policy-epoch', 'author', 'committer', 'timestamp', 'message', 'prepare-candidate', 'candidate', 'candidate-download',
  'candidate-import', 'candidate-import-file', 'candidate-import-submit', 'inspection-download', 'resolution', 'resolution-paths', 'resolve-candidate', 'review', 'review-action', 'review-version', 'reason', 'review-stage',
  'merge', 'merge-heading', 'merge-method-guidance', 'merge-reviewer-fields', 'required-reviewers', 'merge-stage', 'pending', 'confirm', 'send', 'recover', 'discard', 'receipt-download', 'receipt-import', 'receipt-import-file', 'receipt-import-submit'];

export function mountPulls(doc, { href = doc.defaultView.location.href, fetchImpl = globalThis.fetch,
  cryptoImpl = globalThis.crypto, downloadImpl = null } = {}) {
  const nodes = Object.fromEntries(IDS.map(id => { const el = doc.getElementById(id); if (!el) fail(`Missing UI element: ${id}`); return [id, el]; }));
  const client = new PullClient({ href, fetchImpl, cryptoImpl }), download = downloadImpl ?? downloader(doc);
  nodes['candidate-method'].value ||= 'merge-commit';
  const resolution = new ResolutionEditor(doc, nodes['resolution-paths'], displayBytes);
  let operation = null, generation = 0, selected = null, listPage = null, reviewPage = null, fastForward = null, conversation = null;
  const number = (id, min = 0) => decimal(nodes[id].value, id, min);
  const status = message => { nodes.status.textContent = displayText(message); };
  const button = (parent, label, handler) => { const el = element(doc, 'button', label); el.type = 'button';
    el.addEventListener('click', event => { event.preventDefault(); handler(); }); parent.append(el); return el; };
  const on = (id, event, handler) => nodes[id].addEventListener(event, ev => { ev.preventDefault(); handler(); });
  function controls() {
    const busy = Boolean(operation) || client.busy, recovering = client.recoveryOnly,
      connected = client.connected && !recovering, pending = client.pending, candidate = client.candidate;
    nodes['recovery-only'].disabled = busy;
    nodes['original-principal'].disabled = busy || !nodes['recovery-only'].checked;
    nodes['original-principal'].required = nodes['recovery-only'].checked;
    nodes['connection-mode'].textContent = !client.connected ? 'Disconnected. No credential is active.' : recovering
      ? 'RECOVERY ONLY: the selected original principal must match the authenticated outcome response. No PR reads or mutation sends are permitted. Reconnect explicitly for ordinary work.'
      : 'Ordinary connection. Changing the recovery selection takes effect only when Connect is submitted.';
    for (const id of ['refresh', 'new-pr', 'select-number', 'select-load', 'candidate-import-file', 'candidate-import-submit']) nodes[id].disabled = !connected || busy;
    nodes['metadata-stage'].disabled = !connected || busy || Boolean(pending);
    nodes['prepare-candidate'].disabled = !connected || busy || !selected?.row?.data || selected.row.state !== 'open' || selected.row.data.source_ref === null || selected.row.data.target_ref === null;
    nodes['reviews-load'].disabled = !connected || busy || !selected;
    nodes['comments-load'].disabled = !connected || busy || !selected;
    nodes['comments-limit'].disabled = !connected || busy || !selected;
    const canComment = connected && selected && conversation?.reply.found && conversation.reply.number === selected.row.number;
    nodes['comment-stage'].disabled = !canComment || busy || Boolean(pending);
    nodes['comment-body'].disabled = !canComment || busy;
    if (fastForward) fastForward.button.disabled = !connected || busy || Boolean(pending) ||
      !fastForward.available || selected?.row !== fastForward.row || Boolean(selected?.stale);
    const resolving = Boolean(client.conflict);
    nodes.resolution.hidden = !resolving;
    nodes['resolve-candidate'].disabled = !connected || busy || !resolving;
    resolution.setDisabled(!connected || busy || !resolving);
    for (const id of ['review-stage', 'merge-stage']) nodes[id].disabled = !candidate || busy || Boolean(pending);
    const method = candidateMethod(candidate), inspectedFastForward = method === 'fast-forward-only', squash = method === 'squash';
    nodes['merge-heading'].textContent = inspectedFastForward ? 'Fast-forward inspected source' : squash ? 'Reviewed squash' : 'Reviewed merge';
    nodes['merge-stage'].textContent = inspectedFastForward ? 'Prepare fast-forward — do not send' : squash ? 'Prepare squash — do not send' : 'Prepare merge — do not send';
    nodes['merge-reviewer-fields'].hidden = inspectedFastForward;
    nodes['required-reviewers'].disabled = inspectedFastForward || !candidate || busy || Boolean(pending);
    nodes['required-reviewers'].required = !inspectedFastForward;
    nodes['merge-method-guidance'].textContent = inspectedFastForward
      ? 'Publish the exact inspected source tip with the native fast-forward method. Current branch protection determines required approvals. The request preserves the inspected PR version and both branch tips; it sends no candidate bundle or caller-selected reviewer list.'
      : squash ? 'Publish the inspected squash with the target as its only parent and the explicit reviewer requirements below. Current branch protection also applies.'
        : 'Publish the inspected two-parent candidate with the explicit reviewer requirements below. Current branch protection also applies.';
    for (const id of ['candidate-download', 'inspection-download']) nodes[id].disabled = !candidate || busy;
    nodes.confirm.disabled = !connected || busy || !pending;
    if (recovering) nodes.confirm.checked = false;
    nodes.send.disabled = !connected || busy || !pending || !nodes.confirm.checked;
    nodes.recover.disabled = !client.connected || busy || !pending;
    nodes.discard.disabled = recovering || busy || !pending || pending.sent || pending.exported;
    nodes['receipt-download'].disabled = busy || !pending;
    nodes['receipt-import-file'].disabled = !client.connected || busy || Boolean(pending);
    nodes['receipt-import-submit'].disabled = nodes['receipt-import-file'].disabled;
    nodes.pending.textContent = pending ? displayText(`Prepared ${pending.action} for PR #${pending.number}\n` +
      `Key: ${pending.key}\n${pending.body_bytes} body bytes; ${pending.bundle_bytes} bundle bytes\n` +
      `Dispatch attempted: ${pending.sent}; recovery copy exported: ${pending.exported}\n` +
      `Repository: ${pending.scope.repository}; incarnation: ${pending.scope.incarnation}\n` +
      `${JSON.stringify(pending.fields, null, 2)}\n` +
      (recovering ? 'RECOVERY ONLY: check this original key or export the unchanged receipt. This credential cannot send or retry the command. An absent outcome is not proof of failure.'
        : 'Only Send/Retry dispatches these exact bytes. Edits elsewhere do not change this request. An absent outcome is not proof of failure.'))
      : recovering ? 'No retained request. Import its original recovery receipt; do not construct a replacement command.' : 'No prepared mutation.';
  }
  function clearViews() {
    clearComments();
    selected = null; listPage = null; reviewPage = null; fastForward = null; resolution.clear();
    for (const id of ['selected', 'snapshot', 'pr-list', 'list-paging', 'reviews', 'review-paging', 'candidate']) nodes[id].replaceChildren();
    for (const id of ['select-number', 'pr-number', 'expected-version', 'source-ref', 'target-ref', 'source-tip', 'target-tip', 'title', 'body',
      'policy-epoch', 'author', 'committer', 'timestamp', 'message', 'review-version', 'reason', 'required-reviewers']) nodes[id].value = '';
    nodes['candidate-method'].value = 'merge-commit';
    nodes.confirm.checked = false;
  }
  function disconnect() {
    generation += 1; operation = null; client.disconnect(); nodes.token.value = ''; clearViews(); controls();
    status(client.pending ? 'Disconnected. Original request retained in memory; save its recovery receipt before leaving. Disconnect does not prove non-commit.' : 'Disconnected. Credentials and repository views cleared.');
  }
  function invalidateCandidate() {
    client.invalidateCandidate(); nodes.candidate.replaceChildren(); resolution.clear();
    if (operation?.kind === 'candidate') { generation += 1; operation = null; client.cancelReads(); status('Candidate inputs changed; earlier work was not selected.'); }
    controls();
  }
  async function run(kind, action) {
    if (client.recoveryOnly && !['connect', 'recover', 'restore', 'export'].includes(kind)) {
      status('Recovery-only connection cannot read, prepare, discard or resend mutations. Keep the original request; only outcome lookup is permitted.'); controls(); return;
    }
    if (operation || client.busy) { status('An operation is still settling. Its exact request has not been replaced.'); return; }
    const id = ++generation; operation = { id, kind }; controls();
    const guard = () => { if (generation !== id) fail('Operation superseded.'); };
    try { await action(guard); }
    catch (error) {
      if (generation === id) {
        if (!client.connected) { clearViews(); nodes.token.value = ''; }
        const uncertainty = client.pending?.sent || error.outcomeUnknown;
        status(`${error.message || 'Operation unavailable.'}${uncertainty
          ? client.recoveryOnly ? ' Outcome remains unknown. Keep the original receipt and use only its outcome lookup; do not resend with a replacement credential.'
            : ' Outcome remains unknown unless a terminal decision was already shown. Keep the original request and recover or retry it unchanged.' : ''}`);
      }
    } finally { if (generation === id) { operation = null; controls(); } }
  }
  function renderList(result) {
    listPage = result; nodes['pr-list'].replaceChildren(); nodes['list-paging'].replaceChildren();
    item(doc, nodes['pr-list'], 'p', `Snapshot: ${result.head}`);
    if (!result.reply.pull_requests.length) item(doc, nodes['pr-list'], 'p', 'No PRs on this visible page.');
    for (const row of result.reply.pull_requests) button(nodes['pr-list'], `#${row.number} · ${row.state} · ${row.data?.title ?? '(merge-only record)'}`,
      () => loadPr(row.number, result.head));
    if (result.reply.next_after !== null) button(nodes['list-paging'], 'Next PR page', () => loadList(result.reply.next_after, result.head));
  }
  function loadList(after = 0, head = null) {
    return run('read', async guard => {
      client.cancelReads(); nodes['pr-list'].replaceChildren(); nodes['list-paging'].replaceChildren();
      const result = await client.list({ after, head }); guard(); renderList(result);
      status('PR page loaded at one snapshot. Opening a row retains that snapshot.');
    });
  }
  function fieldsFromRow(row, format) {
    const data = row.data;
    if (!data || data.source_ref === null || data.target_ref === null) fail('This record has byte-only refs or no editable metadata. The text form cannot represent it.');
    return { expected_version: row.version, object_format: format, source_ref: data.source_ref, target_ref: data.target_ref,
      source_tip: oid(data.source_tip, format), target_tip: oid(data.target_tip, format), title: data.title, body: data.body };
  }
  const metadataIds = { expected_version: 'expected-version', object_format: 'object-format', source_ref: 'source-ref', target_ref: 'target-ref',
    source_tip: 'source-tip', target_tip: 'target-tip', title: 'title', body: 'body' };
  function clearProposal() {
    clearComments();
    for (const id of ['pr-number', 'expected-version', 'source-ref', 'target-ref', 'source-tip', 'target-tip', 'title', 'body']) nodes[id].value = '';
  }
  function clearComments(keepDraft = false) {
    conversation = null; nodes.conversation.replaceChildren(); nodes['comment-paging'].replaceChildren();
    nodes['comment-version'].value = '';
    if (!keepDraft) nodes['comment-body'].value = '';
  }
  function renderSelected(result) {
    clearProposal(); fastForward = null;
    const row = result.reply.pull_request; nodes.selected.replaceChildren(); nodes['reviews'].replaceChildren(); nodes['review-paging'].replaceChildren(); reviewPage = null;
    nodes.snapshot.textContent = `Selected snapshot: ${result.head}`;
    if (!row) { selected = null; item(doc, nodes.selected, 'p', 'This PR was not found or is not disclosed.'); return; }
    selected = { row, head: result.head, format: result.binding.format };
    item(doc, nodes.selected, 'h2', `#${row.number} · ${row.state} · ${row.data?.title ?? '(merge-only record)'}`);
    item(doc, nodes.selected, 'p', `PR version ${row.version}. Opener: ${row.opened_by ?? '(not recorded)'}`);
    const mergePanel = element(doc, 'section'); mergePanel.id = 'fast-forward-panel';
    item(doc, mergePanel, 'h3', 'Fast-forward merge');
    item(doc, mergePanel, 'p', 'Publish the recorded source tip and mark this PR merged together, without creating a new commit. The node must verify ancestry, the exact PR version and both live branch tips, and current branch protection. No force or alternative merge method is attempted.');
    let unavailable = null;
    try { fastForwardProposal(result, client.binding); }
    catch (error) { unavailable = error.message; }
    const mergeReason = item(doc, mergePanel, 'p', unavailable ??
      'Preparing only saves an exact request locally. Review it below, save a recovery copy, then explicitly confirm and Send/Retry. No candidate, reviewer list or policy assertion is supplied.');
    const mergeButton = button(mergePanel, 'Prepare fast-forward merge', () => run('stage', async guard => {
      if (selected?.row !== row || selected.stale) fail('Reload and select the intended PR before preparing this merge.');
      const proposal = fastForwardProposal(result, client.binding);
      await client.stageMetadata(proposal.number, 'fast-forward', proposal.fields); guard();
      invalidateCandidate(); nodes.confirm.checked = false;
      status('Fast-forward request prepared from the selected PR version and recorded branch tips, not the editable forms. Nothing sent. Inspect the saved request and explicitly confirm Send/Retry; divergence or protection will refuse without a fallback.');
    }));
    mergeButton.id = 'fast-forward-stage'; mergeButton.disabled = true;
    fastForward = { row, button: mergeButton, reason: mergeReason, available: unavailable === null };
    nodes.selected.append(mergePanel);
    appendChecksPanel(doc, nodes.selected, { client, observed: result, run,
      current: () => client.connected && selected?.row === row, status, displayText });
    if (row.data) {
      item(doc, nodes.selected, 'pre', `${nativeRef(row.data, 'source_ref')} → ${nativeRef(row.data, 'target_ref')}\nSource ${row.data.source_tip}\nTarget ${row.data.target_tip}`);
      const diffPanel = element(doc, 'section'), diffOutput = element(doc, 'div');
      item(doc, diffPanel, 'h3', 'Compare recorded PR changes');
      item(doc, diffPanel, 'p', 'Inspect changed paths without preparing a merge candidate. Both Git-read and PR-read grants are required. Reads keep this exact snapshot and both recorded tips; a stale snapshot must be reloaded explicitly.');
      let lastDiff = null;
      const compareButtons = [];
      const exportDiff = button(diffPanel, 'Download full diff JSON', () => run('export', async () => {
        if (!client.connected || selected?.row !== row || !lastDiff) fail('Load a comparison for the selected PR first.');
        downloadText(`frankengit-pr-${row.number}-diff.json`, JSON.stringify(lastDiff.reply, null, 2));
        status('Full diff report exported without credentials. This report is not a candidate or an approval.');
      }));
      exportDiff.disabled = true;
      for (const mode of ['merge-base', 'direct']) compareButtons.push(button(diffPanel, `Compare ${mode} — read only`, () => run('read', async guard => {
        if (selected?.row !== row) fail('The selected PR changed.');
        lastDiff = null; exportDiff.disabled = true; diffOutput.replaceChildren();
        for (const control of compareButtons) control.disabled = true;
        try {
          const diff = await client.diff(row.number, result, mode); guard();
          if (selected?.row !== row) fail('The selected PR changed.');
          const rendered = renderPullDiff(doc, diffOutput, diff);
          lastDiff = diff; exportDiff.disabled = false;
          status(`PR ${mode} comparison loaded without preparing a candidate.${rendered.clipped ? ' Display clipped: download the full diff JSON.' : ''}`);
        } finally { for (const control of compareButtons) control.disabled = !client.connected; }
      })));
      diffPanel.append(diffOutput); nodes.selected.append(diffPanel);
      const renderGeneration = generation;
      nodes.selected.append(markdownBody(doc, row.data.body, row.data.body_rendered, {
        cryptoImpl, current: () => client.connected && generation === renderGeneration && selected?.row === row,
      }).element);
      if (row.data.source_ref !== null && row.data.target_ref !== null) {
        for (const [name, value] of Object.entries(fieldsFromRow(row, result.binding.format))) nodes[metadataIds[name]].value = String(value);
        nodes['pr-number'].value = String(row.number); nodes['metadata-action'].value = 'update';
      } else item(doc, nodes.selected, 'p', 'Byte-only refs are displayed without conversion. Metadata editing and candidate preparation through this text form are unavailable.');
    }
    if (row.merge) item(doc, nodes.selected, 'pre', `Merged commit: ${row.merge.merge_commit}\nOriginal target: ${row.merge.target_tip_before}`);
  }
  function loadPr(number, head = null) {
    return run('read', async guard => {
      client.cancelReads(); invalidateCandidate(); clearProposal(); selected = null; nodes.selected.replaceChildren(); nodes.snapshot.replaceChildren();
      nodes['reviews'].replaceChildren(); nodes['review-paging'].replaceChildren();
      const result = await client.show(number, head, { render: true }); guard(); renderSelected(result);
      status(result.reply.found ? 'PR loaded. Preparing a candidate uses these observed tips, not edits in the metadata proposal form.' : 'PR not found or not disclosed.');
    });
  }
  function loadReviews(after = null, head = null) {
    return run('read', async guard => {
      if (!selected) fail('Select a PR first.'); const number = selected.row.number;
      client.cancelReads(); nodes.reviews.replaceChildren(); nodes['review-paging'].replaceChildren();
      const result = await client.reviews(number, { after, head: head ?? selected.head }); guard(); reviewPage = result;
      item(doc, nodes.reviews, 'p', `Review snapshot: ${result.head ?? '(not available)'}. These observations do not grant merge permission.`);
      if (!result.reply.found) item(doc, nodes.reviews, 'p', 'Reviews not found or not disclosed.');
      else {
        item(doc, nodes.reviews, 'p', `PR version ${result.reply.pull_request_version}; observed policy epoch ${result.reply.policy_epoch}. Enter the intended policy epoch explicitly below.`);
        if (!result.reply.reviews.length) item(doc, nodes.reviews, 'p', 'No review rows on this page. This does not establish the version of a reviewer outside the page.');
        for (const row of result.reply.reviews) {
          const section = element(doc, 'section'); nodes.reviews.append(section);
          item(doc, section, 'h3', `${row.reviewer} · version ${row.version} · ${row.decision}`);
          item(doc, section, 'p', `Freshness: ${row.freshness}; opener: ${row.reviewer_is_opener ?? 'unknown'}`);
          item(doc, section, 'pre', `PR v${row.subject.pull_request_version}; policy ${row.subject.policy_epoch}\n` +
            `Source ${row.subject.source_tip}\nTarget ${row.subject.target_tip}\nCandidate ${row.candidate?.candidate_commit ?? '(no candidate binding)'}`);
          item(doc, section, 'pre', row.reason);
        }
      }
      if (result.reply.next_after !== null) button(nodes['review-paging'], 'Next review page', () => loadReviews(result.reply.next_after, result.head));
      status('Reviews displayed as evidence only. Required reviewers are never selected automatically.');
    });
  }
  function downloadText(name, text) { download(name, text); }
  function loadComments(after = 0, head = null, pageLimit = null) {
    return run('read', async guard => {
      if (!selected) fail('Select a PR first.');
      const limit = pageLimit ?? decimal(nodes['comments-limit'].value, 'comments per page', 1);
      if (![1, 5, 20].includes(limit)) fail('Choose 1, 5, or 20 comments per page.');
      const number = selected.row.number, row = selected.row;
      client.cancelReads(); clearComments(true);
      item(doc, nodes.conversation, 'p', 'Loading conversation…');
      try {
        const result = await client.comments(number, { after, head, limit, render: true }); guard();
        if (selected?.row !== row) fail('The selected PR changed.');
        conversation = result; nodes.conversation.replaceChildren();
        if (!result.reply.found) {
          item(doc, nodes.conversation, 'p', 'Conversation unavailable: this PR is absent or not disclosed.');
          status('No conversation result was inferred.'); return;
        }
        nodes['comment-version'].value = String(result.reply.discussion_version);
        item(doc, nodes.conversation, 'p', `Conversation version ${result.reply.discussion_version} · snapshot ${result.head}`);
        if (!result.reply.comments.length) item(doc, nodes.conversation, 'p', after === 0 ? 'No comments at this snapshot.' : 'No further comments at this snapshot.');
        const renderGeneration = generation;
        for (const comment of result.reply.comments) {
          const section = element(doc, 'section'); nodes.conversation.append(section);
          item(doc, section, 'h3', `Comment ${comment.version} · ${comment.actor}`);
          if (comment.anchor) renderCommentAnchor(doc, section, comment.anchor, comment.anchor_status);
          section.append(markdownBody(doc, comment.body, comment.body_rendered, {
            cryptoImpl, current: () => client.connected && generation === renderGeneration && conversation === result && selected?.row === row,
          }).element);
        }
        if (result.reply.next_after !== null) button(nodes['comment-paging'], 'Next comments page', () => loadComments(result.reply.next_after, result.head, limit));
        item(doc, nodes.conversation, 'p', result.reply.complete ? 'All comments after this cursor are shown.' : 'More comments remain at this snapshot.');
        status('Conversation loaded. Preparing a comment uses its displayed discussion version and preserves PR metadata.');
      } catch (error) {
        guard(); clearComments(true);
        item(doc, nodes.conversation, 'p', `Conversation unavailable: ${error.message || 'read failed'}. Reload explicitly before preparing a comment.`);
        throw error;
      }
    });
  }
  function renderTerminal(result) {
    if (client.recoveryOnly) {
      nodes.confirm.checked = false;
      if (result.terminal) {
        clearComments(); resolution.clear(); nodes.candidate.replaceChildren();
        status(`Canonical ${result.outcome}: transaction ${result.tx}${result.rcr ? `, record ${result.rcr}` : `, refusal ${result.refusal}`}. ` +
          'Recovered using the original key without reexecuting the command. External delivery acknowledgement is not established. Recovery-only mode remains active; reconnect explicitly before reading or preparing new work.');
      } else status(`Outcome unknown (${result.state}). No request was reexecuted. Absence never proves non-commit. Keep the original receipt and check its outcome again; this credential cannot resend it.`);
      return;
    }
    if (result.action === 'comment') {
      nodes.confirm.checked = false;
      if (result.terminal) {
        clearComments(result.outcome !== 'committed');
        status(`Canonical ${result.outcome}: transaction ${result.tx}${result.rcr ? `, record ${result.rcr}` : `, refusal ${result.refusal}`}. Load the latest conversation to observe the result. PR metadata and existing approvals are unchanged; external delivery is not established.`);
      } else status(`Comment outcome unknown (${result.state}). Keep the original request and recover or retry it unchanged.`);
      return;
    }
    nodes.confirm.checked = false; nodes.candidate.replaceChildren();
    if (result.terminal) {
      resolution.clear();
      if (selected) selected.stale = true;
      if (fastForward) fastForward.reason.textContent = 'A terminal decision was observed. Reload the PR explicitly before preparing another merge from current coordinates.';
    }
    status(result.terminal ? `Canonical ${result.outcome}: transaction ${result.tx}${result.rcr ? `, record ${result.rcr}` : `, refusal ${result.refusal}`}. ` +
      'External delivery acknowledgement is not established. Reload PR state explicitly.'
      : `Outcome unknown (${result.state}). No request was reexecuted. Absence never proves non-commit; keep and reuse the original request.`);
  }
  on('connection', 'submit', () => {
    const token = nodes.token.value; nodes.token.value = '';
    if (operation || client.busy) { status('Settle the current operation or disconnect before changing credentials.'); return; }
    const options = nodes['recovery-only'].checked
      ? { recoveryOnly: true, originalPrincipal: nodes['original-principal'].value } : {};
    clearViews();
    void run('connect', async guard => {
      await client.connect(token, options); guard();
      if (client.recoveryOnly) {
        status('Connected locally for outcome recovery only. The server will authenticate the selected principal on lookup. Import the original receipt or check the retained request; nothing has been sent.');
        return;
      }
      status('Connected locally. Loading the PR API requires its independent read grant. Recovery receipts can also be restored.');
      try { const result = await client.list(); guard(); renderList(result); }
      catch (error) { guard(); if (!client.connected) throw error; status(`Credential retained for recovery. PR listing was not available: ${error.message}`); }
    });
  });
  nodes['recovery-only'].addEventListener('change', controls);
  on('disconnect', 'click', disconnect);
  on('refresh', 'click', () => loadList());
  on('select-pr', 'submit', () => run('read', async guard => {
    const requested = number('select-number', 1); client.cancelReads(); invalidateCandidate(); clearProposal(); selected = null;
    nodes.selected.replaceChildren(); nodes.snapshot.replaceChildren(); nodes.reviews.replaceChildren(); nodes['review-paging'].replaceChildren();
    const result = await client.show(requested, null, { render: true }); guard(); renderSelected(result); status('Selected an explicitly refreshed PR snapshot.');
  }));
  on('reviews-load', 'click', () => loadReviews());
  on('comments-load', 'click', () => loadComments());
  on('comment-form', 'submit', () => run('stage', async guard => {
    if (!selected || !conversation?.reply.found || conversation.reply.number !== selected.row.number) fail('Load the selected PR conversation first.');
    await client.stageComment(selected.row.number, conversation.reply.discussion_version, nodes['comment-body'].value); guard();
    nodes.confirm.checked = false;
    status('Comment prepared locally. Review its exact body and discussion version below, then send it explicitly.');
  }));
  on('new-pr', 'click', () => {
    if (operation || !client.connected || client.recoveryOnly) return;
    clearComments();
    invalidateCandidate(); selected = null; nodes.selected.replaceChildren(); nodes.snapshot.replaceChildren(); nodes.reviews.replaceChildren(); nodes['review-paging'].replaceChildren();
    for (const id of ['pr-number', 'source-ref', 'target-ref', 'source-tip', 'target-tip', 'title', 'body']) nodes[id].value = '';
    nodes['expected-version'].value = '0'; nodes['object-format'].value = client.binding?.format ?? 'sha1'; nodes['metadata-action'].value = 'open';
    status('New PR proposal. Choose an explicit unused number and both exact tips; nothing has been submitted.'); controls();
  });
  on('metadata', 'submit', () => run('stage', async guard => {
    const fields = Object.fromEntries(Object.entries(metadataIds).map(([name, id]) => [name, name === 'expected_version' ? number(id) : nodes[id].value]));
    await client.stageMetadata(number('pr-number', 1), nodes['metadata-action'].value, fields); guard(); nodes.confirm.checked = false;
    status('Metadata request prepared locally. Review the exact saved request, then explicitly send it.');
  }));
  on('prepare', 'submit', () => run('candidate', async guard => {
    if (!selected || selected.row.state !== 'open') fail('Select an open PR first.');
    const data = fieldsFromRow(selected.row, selected.format);
    const fields = { object_format: data.object_format, pull_request_version: data.expected_version, policy_epoch: number('policy-epoch', 1),
      source_ref: data.source_ref, target_ref: data.target_ref, source_tip: data.source_tip, target_tip: data.target_tip };
    const metadata = { author: nodes.author.value, committer: nodes.committer.value, timestamp: number('timestamp'), message: nodes.message.value };
    nodes.candidate.replaceChildren(); resolution.clear();
    const result = await client.prepareAndInspect(selected.row.number, fields, metadata, nodes['candidate-method'].value); guard();
    if (result.inspection) {
      const rendered = renderInspection(doc, nodes.candidate, result.inspection);
      status(`Candidate prepared and inspected, without publication.${rendered.clipped ? ' Display clipped: download the full report before reviewing.' : ''}`);
    } else {
      item(doc, nodes.candidate, 'h3', `Preparation: ${result.metadata.state}`);
      for (const conflict of result.metadata.conflicts) item(doc, nodes.candidate, 'pre', `${displayBytes(conflict.path_hex)} · ${conflict.kind}\nPath bytes: ${conflict.path_hex}`);
      if (result.metadata.state === 'conflicted') {
        resolution.show(result.metadata);
        status(`Choose every conflict explicitly below. Resolution constructs and inspects a new ${result.metadata.method === 'squash' ? 'squash' : 'merge'} candidate; it does not record approval or publish.`);
      } else status('Already up to date. No candidate, transaction or approval was produced.');
    }
  }));
  on('resolution', 'submit', () => run('candidate', async guard => {
    const choices = await resolution.collect(guard); guard();
    const result = await client.resolveAndInspect(choices); guard(); resolution.clear();
    const rendered = renderInspection(doc, nodes.candidate, result.inspection);
    status(`Resolved candidate constructed and inspected. No vote or publication exists.${rendered.clipped ? ' Display clipped: download the full inspection before reviewing.' : ''}`);
  }));
  for (const id of ['metadata', 'prepare']) nodes[id].addEventListener('input', invalidateCandidate);
  on('candidate-method', 'change', invalidateCandidate);
  on('candidate-download', 'click', () => run('export', async () => { downloadText('frankengit-candidate.json', client.exportCandidate()); status('Candidate receipt exported without credentials. Its bytes must be inspected before another reviewer can act.'); }));
  on('inspection-download', 'click', () => run('export', async () => {
    const candidate = client.candidate; if (!candidate) fail('No inspected candidate.');
    downloadText('frankengit-candidate-inspection.json', JSON.stringify(candidate.inspection, null, 2)); status('Full inspection report exported. Binary object bodies remain excluded by the native report.');
  }));
  on('candidate-import', 'submit', () => run('candidate', async guard => {
    client.invalidateCandidate(); nodes.candidate.replaceChildren(); resolution.clear(); const serialized = await fileText(nodes['candidate-import-file']); guard();
    const result = await client.importCandidate(serialized); guard(); renderInspection(doc, nodes.candidate, result.reply);
    status('Imported candidate passed native reinspection. Review and merge remain separate explicit commands.');
  }));
  on('review', 'submit', () => run('stage', async guard => {
    await client.stageReview(nodes['review-action'].value, number('review-version'), nodes.reason.value); guard(); nodes.confirm.checked = false;
    status('Exact-candidate review prepared locally. The authenticated credential determines the reviewer, not this form.');
  }));
  on('merge', 'submit', () => run('stage', async guard => {
    if (candidateMethod(client.candidate) === 'fast-forward-only') {
      await client.stageInspectedFastForward(); guard(); nodes.confirm.checked = false;
      status('Fast-forward request prepared for the exact inspected source tip. Nothing sent. The node rechecks ancestry, both branch tips, the PR version and current branch protection before publication.');
    } else {
      const method = candidateMethod(client.candidate), reviewers = nodes['required-reviewers'].value.split(/[\s,]+/u).filter(Boolean);
      await client.stageMerge(reviewers); guard(); nodes.confirm.checked = false;
      status(`${method === 'squash' ? 'Squash' : 'Merge'} request prepared locally with explicit reviewer requirements. The node will recheck current authority and all gates at publication.`);
    }
  }));
  nodes.confirm.addEventListener('change', controls);
  on('send', 'click', () => run('send', async guard => {
    if (!nodes.confirm.checked) fail('Explicitly confirm the saved request before sending.');
    nodes.confirm.checked = false; const result = await client.send(); guard(); renderTerminal(result);
  }));
  on('recover', 'click', () => run('recover', async guard => { const result = await client.recover(); guard(); renderTerminal(result); }));
  on('discard', 'click', () => run('discard', async () => { client.discardUnsent(); nodes.confirm.checked = false; status('Never-exported, never-dispatched draft discarded.'); }));
  on('receipt-download', 'click', () => run('export', async () => {
    downloadText('frankengit-pr-recovery.json', client.exportReceipt());
    status(client.recoveryOnly
      ? 'Original recovery receipt exported without either token. It retains the original command, key and credential fingerprint. Keep it private; this page remains lookup-only, and the copy may still be submitted elsewhere with the original credential.'
      : 'Recovery receipt exported without the token. It contains private command and candidate data. Keep the original credential; this copy may be submitted elsewhere.');
  }));
  on('receipt-import', 'submit', () => run('restore', async guard => {
    const serialized = await fileText(nodes['receipt-import-file']); guard(); await client.restoreReceipt(serialized); guard(); nodes.confirm.checked = false;
    status(client.recoveryOnly
      ? 'Original request restored for outcome lookup only. Its key, fingerprint and bytes are unchanged. No mutation was sent; this credential cannot resend the command.'
      : 'Exact request restored. Check its original outcome or explicitly retry the same bytes; no mutation has been sent by importing it.');
  }));
  doc.defaultView.addEventListener('beforeunload', event => {
    if (client.pending || client.busy) { event.preventDefault(); event.returnValue = ''; }
  });
  doc.defaultView.addEventListener('pagehide', disconnect);
  status('Connect with a repository token. Credentials remain only in page memory.'); controls();
  return { client, disconnect, loadPr, loadList, loadReviews, loadComments };
}

// Review-protection administration has its own connection and native client.
// A PR-read/review token is never borrowed, and a displayed policy is evidence,
// not permission to publish. Only an explicitly confirmed saved intent is sent.
export function mountProtection(doc, { href = doc.defaultView.location.href, fetchImpl = globalThis.fetch,
  cryptoImpl = globalThis.crypto, downloadImpl = null } = {}) {
  const parent = doc.getElementById('pr-collaboration');
  if (!parent || doc.getElementById('protection-panel')) fail('Protection needs one PR shell and may only be mounted once.');
  const client = new ProtectionClient({ href, fetchImpl, cryptoImpl }), download = downloadImpl ?? downloader(doc);
  const panel = element(doc, 'details'); panel.id = 'protection-panel';
  item(doc, panel, 'summary', 'Repository review protection — administrator');
  item(doc, panel, 'p', 'Inspect the complete native policy, then propose a complete replacement. Omitted branches lose protection; omitted administrators lose policy administration. The node checks current authority. First installation is trusted-local only.');
  const nodes = {}, rows = [];
  let operation = false, generation = 0, rowNumber = 0, preview = null;
  const named = (parent, tag, name, label = '') => {
    const el = item(doc, parent, tag, label); el.id = `protection-${name}`; nodes[name] = el; return el;
  };
  const field = (parent, name, label, tag = 'input') => {
    const wrapper = item(doc, parent, 'label', label), input = named(wrapper, tag, name);
    if (tag === 'input') input.type = 'text';
    input.autocomplete = 'off'; input.spellcheck = false; return input;
  };
  const button = (parent, name, label) => { const el = named(parent, 'button', name, label); el.type = 'button'; return el; };
  const connection = named(panel, 'form', 'connection'); connection.autocomplete = 'off';
  const token = field(connection, 'token', 'Independent protection bearer token'); token.type = 'password'; token.maxLength = 64;
  const person = field(connection, 'principal', 'Intended authenticated principal ID (independently known)'); person.maxLength = 32;
  const recoveryOnly = field(connection, 'recovery-only', 'Recovery only, including a rotated credential'); recoveryOnly.type = 'checkbox';
  button(connection, 'connect', 'Connect protection credential').type = 'submit';
  button(panel, 'disconnect', 'Disconnect protection credential');
  named(panel, 'p', 'mode');
  const statusNode = named(panel, 'p', 'status'); statusNode.setAttribute('role', 'status'); statusNode.setAttribute('aria-live', 'polite');
  button(panel, 'load', 'Load complete protection policy — read only');
  named(panel, 'pre', 'snapshot');
  const editor = named(panel, 'form', 'editor');
  item(doc, editor, 'h3', 'Complete replacement');
  const administrators = field(editor, 'administrators', 'All policy administrators, one principal ID per line', 'textarea');
  administrators.maxLength = 32 * 33; administrators.rows = 4;
  named(editor, 'div', 'branches');
  button(editor, 'add-branch', 'Add protected branch');
  const clear = field(editor, 'clear', 'Explicitly remove ALL branch protection (requires no branch rules)'); clear.type = 'checkbox';
  button(editor, 'preview', 'Preview all changes — do not prepare or send').type = 'submit';
  named(panel, 'pre', 'changes');
  button(panel, 'stage', 'Prepare this exact preview — do not send');
  named(panel, 'pre', 'pending');
  const confirm = field(panel, 'confirm', 'I have reviewed the saved complete replacement and authorize this exact Send/Retry'); confirm.type = 'checkbox';
  button(panel, 'send', 'Send/Retry original protection request');
  button(panel, 'recover', 'Look up original protection outcome — do not resend');
  button(panel, 'discard', 'Discard never-sent, never-exported draft');
  button(panel, 'export', 'Download original protection recovery receipt');
  item(doc, panel, 'p', 'Recovery receipts contain private policy data, but no bearer token. Save one before leaving after preparing a request. A timeout, disconnect or absent outcome never proves non-commit.');
  parent.append(panel);
  const status = message => { statusNode.textContent = displayText(message); };
  const pendingView = () => {
    const pending = client.pending;
    if (!pending) { nodes.pending.textContent = 'No prepared protection request.'; return; }
    const intent = pending.intent;
    nodes.pending.textContent = displayText(`SAVED COMPLETE REPLACEMENT — edits cannot change this request\n` +
      `Origin: ${intent.origin}\nRoute: ${intent.route}\nPrincipal: ${intent.principal}\nKey: ${intent.key}\n` +
      `Tenant: ${intent.source.scope.tenant}\nRepository: ${intent.source.scope.repository}\nIncarnation: ${intent.source.scope.incarnation}\n` +
      `Source head: ${intent.source.head}\nExpected version: ${intent.source.version}\nExpected epoch: ${intent.source.epoch}\n` +
      `Dispatch attempted: ${pending.sent}; receipt exported: ${pending.exported}; clear all: ${intent.clear}\n` +
      `Changes:\n${JSON.stringify(protectionChanges(intent.source.policy, intent.replacement), null, 2)}\n` +
      `Complete replacement:\n${JSON.stringify(intent.replacement, null, 2)}`);
  };
  function controls() {
    const busy = operation || client.busy, pending = client.pending;
    const ordinary = client.connected && !client.recoveryOnly;
    const editable = ordinary && !busy && !pending && Boolean(client.observed?.policy);
    for (const input of [token, person, recoveryOnly, nodes.connect]) input.disabled = busy;
    nodes.mode.textContent = !client.connected ? 'Disconnected. No protection credential is active.' : client.recoveryOnly
      ? 'RECOVERY ONLY. Only the retained original outcome may be read; no policy read, replacement preparation or resend is allowed.'
      : 'Ordinary protection connection. Connecting locally does not establish an authenticated role or grant.';
    nodes.load.disabled = !ordinary || busy || Boolean(pending);
    for (const input of [administrators, clear, nodes['add-branch'], nodes.preview]) input.disabled = !editable;
    for (const row of rows) for (const input of [row.reference, row.reviewers, row.approvals, row.remove]) input.disabled = !editable;
    nodes['add-branch'].disabled ||= rows.length >= 64;
    nodes.stage.disabled = !editable || !preview;
    confirm.disabled = !ordinary || busy || !pending;
    if (!ordinary || !pending) confirm.checked = false;
    nodes.send.disabled = !ordinary || busy || !pending || !confirm.checked;
    nodes.recover.disabled = !client.connected || busy || !pending;
    nodes.discard.disabled = !ordinary || busy || !pending || pending.sent || pending.exported;
    nodes.export.disabled = busy || !pending;
    pendingView();
  }
  function clearEditor() {
    preview = null; rows.length = 0; nodes.branches.replaceChildren(); administrators.value = '';
    clear.checked = false; confirm.checked = false; nodes.changes.textContent = ''; nodes.snapshot.textContent = '';
  }
  function changed() {
    preview = null; nodes.changes.textContent = 'Inputs changed. Preview the complete replacement again.';
    confirm.checked = false; controls();
  }
  function addRow(data = { reference_hex: '', required_reviewers: [] }) {
    if (rows.length >= 64) fail('At most 64 branch rules can be edited.');
    const group = element(doc, 'fieldset'); nodes.branches.append(group);
    item(doc, group, 'legend', `Protected branch ${++rowNumber}`);
    const refLabel = item(doc, group, 'label', 'Exact branch bytes, lowercase hexadecimal (including refs/heads/)');
    const reference = item(doc, refLabel, 'input'); reference.type = 'text'; reference.maxLength = 2048;
    reference.autocomplete = 'off'; reference.spellcheck = false; reference.value = data.reference_hex;
    const readable = item(doc, group, 'pre', data.reference_hex ? `Display only: ${displayBytes(data.reference_hex)}` : 'Enter exact branch bytes.');
    const reviewersLabel = item(doc, group, 'label', 'Eligible reviewer IDs for this branch, one per line');
    const reviewers = item(doc, reviewersLabel, 'textarea'); reviewers.rows = 3; reviewers.maxLength = 32 * 33;
    reviewers.spellcheck = false; reviewers.value = data.required_reviewers.join('\n');
    const approvalsLabel = item(doc, group, 'label', 'Approvals needed — leave blank to require all listed reviewers');
    const approvals = item(doc, approvalsLabel, 'input'); approvals.type = 'number';
    approvals.min = '0'; approvals.max = '32'; approvals.step = '1'; approvals.autocomplete = 'off';
    approvals.value = Object.hasOwn(data, 'required_approvals') ? String(data.required_approvals) : '';
    const quorum = item(doc, group, 'p');
    const describeQuorum = () => {
      const count = reviewers.value.split(/[\r\n,]+/u).filter(value => value !== '').length;
      const needed = approvals.value === '' ? count : approvals.value;
      quorum.textContent = `${needed} of ${count} listed reviewers must approve the exact candidate. The PR opener and merge submitter cannot contribute votes. Other reviewers do not veto a satisfied quorum.`;
    };
    describeQuorum();
    const remove = item(doc, group, 'button', 'Remove this branch rule'); remove.type = 'button';
    const required_checks = data.required_checks ?? [];
    if (required_checks.length) item(doc, group, 'pre',
      `Required workflow checks (preserved by this editor; configure through the protection CLI or API):\n${JSON.stringify(required_checks, null, 2)}`);
    const row = { reference, reviewers, approvals, remove, required_checks }; rows.push(row);
    reference.addEventListener('input', () => {
      readable.textContent = 'Edited exact branch bytes; inspect the complete replacement in the preview.'; changed();
    });
    reviewers.addEventListener('input', () => { describeQuorum(); changed(); });
    approvals.addEventListener('input', () => { describeQuorum(); changed(); });
    remove.addEventListener('click', event => {
      event.preventDefault();
      if (operation || client.busy || client.pending || !client.connected || client.recoveryOnly || !client.observed?.policy) return;
      rows.splice(rows.indexOf(row), 1); group.remove(); changed();
    });
  }
  const people = input => {
    if (input.value.length > 32 * 33) fail('A principal list exceeds its editing limit.');
    // Newline and comma separate IDs; principal validation never trims or
    // repairs a malformed ID. The wire policy validator remains authoritative.
    return input.value.split(/[\r\n,]+/u).filter(value => value !== '');
  };
  function approvalCount(value) {
    if (!/^(0|[1-9][0-9]?)$/.test(value)) fail('Use a whole approval count, or leave it blank for all reviewers.');
    return Number(value);
  }
  function draft() {
    if (rows.some(row => row.approvals.validity?.badInput)) fail('Use a whole approval count, or leave it blank for all reviewers.');
    if (rows.some(row => row.reference.value.length > 2048)) fail('A branch byte string exceeds its editing limit.');
    return { replacement: protectionPolicy({ administrators: people(administrators),
      branches: rows.map(row => ({ reference_hex: row.reference.value, required_reviewers: people(row.reviewers),
        ...(row.required_checks.length ? { required_checks: row.required_checks } : {}),
        ...(row.approvals.value !== '' ? { required_approvals: approvalCount(row.approvals.value) } : {}) })) }), clear: clear.checked };
  }
  function requireDraftAccess() {
    if (!client.connected || client.recoveryOnly || client.pending || !client.observed?.policy) fail('Load an installed policy with an ordinary protection connection and no pending request.');
  }
  async function run(action) {
    if (operation || client.busy) { status('A protection operation is still settling. The original request is not replaced.'); return; }
    const id = ++generation; operation = true; controls();
    const guard = () => { if (id !== generation) fail('Protection view superseded.'); };
    try { await action(guard); }
    catch (error) {
      if (id === generation) {
        if (!client.connected) clearEditor();
        status(`${error.message || 'Protection operation unavailable.'}${client.pending?.sent || error.outcomeUnknown
          ? ' Outcome remains unknown. Keep the original receipt and key; absence or disconnect does not prove non-commit.' : ''}`);
      }
    } finally {
      if (id === generation) operation = false;
      controls();
    }
  }
  function disconnect() {
    generation++; operation = false; client.disconnect(); token.value = ''; person.value = ''; clearEditor(); controls();
    status(client.pending ? 'Disconnected. The original request remains in memory. Export its receipt before leaving; no rollback is inferred.'
      : 'Disconnected. Protection credentials and policy views cleared.');
  }
  function terminal(result) {
    confirm.checked = false;
    if (result.terminal) {
      clearEditor();
      status(`Canonical ${result.outcome}: transaction ${result.tx}, sequence ${result.sequence}, ` +
        (result.rcr ? `record ${result.rcr}. ` : `refusal ${result.refusal}. `) +
        'External delivery acknowledgement is not established. Reload the complete policy explicitly before preparing another replacement.');
    } else status(`Outcome unknown (${result.state}). No command was reexecuted. Keep the original request; absence does not prove non-commit.`);
  }
  const on = (name, event, handler) => nodes[name].addEventListener(event, ev => { ev.preventDefault(); return handler(); });
  on('connection', 'submit', () => {
    const credential = token.value, principal = person.value, mode = recoveryOnly.checked; token.value = '';
    return run(async guard => {
      clearEditor(); await client.connect(credential, principal, { recoveryOnly: mode }); guard();
      status(mode ? 'Connected locally for original-outcome recovery only. The server must authenticate the independently entered principal.'
        : 'Connected locally. Load the complete native protection policy explicitly; no request has been sent.');
    });
  });
  on('disconnect', 'click', disconnect);
  on('load', 'click', () => run(async guard => {
    if (!client.connected || client.recoveryOnly || client.pending) fail('Ordinary access with no pending request is required to reload protection.');
    clearEditor(); const source = await client.load(); guard();
    nodes.snapshot.textContent = displayText(`Tenant: ${source.scope.tenant}\nRepository: ${source.scope.repository}\nIncarnation: ${source.scope.incarnation}\n` +
      `Object format: ${source.scope.format}\nSource head: ${source.head}\nPolicy version: ${source.version}\nPolicy epoch: ${source.epoch}\n` +
      `Complete policy:\n${JSON.stringify(source.policy, null, 2)}`);
    if (!source.policy) { status('No policy is installed. Remote bootstrap is forbidden; first installation is trusted-local only.'); return; }
    administrators.value = source.policy.administrators.join('\n');
    for (const row of source.policy.branches) addRow(row);
    status(source.policy.branches.length ? 'Complete installed policy loaded. Editing and previewing do not publish.'
      : 'Installed policy has no protected branches. Administrators still exist; this is not an uninstalled policy.');
  }));
  administrators.addEventListener('input', changed); clear.addEventListener('change', changed);
  on('add-branch', 'click', () => {
    if (operation || client.busy) return;
    try { requireDraftAccess(); addRow(); changed(); } catch (error) { status(error.message); }
  });
  on('editor', 'submit', () => run(async () => {
    requireDraftAccess(); preview = null; nodes.changes.textContent = '';
    const proposed = draft();
    if (proposed.clear !== (proposed.replacement.branches.length === 0)) fail('An empty branch policy needs explicit clear-all confirmation; clear-all cannot accompany branch rules.');
    const source = client.observed;
    preview = { ...proposed, source };
    nodes.changes.textContent = displayText(`PREVIEW ONLY — no request prepared or sent\nExpected version: ${source.version}\nExpected epoch: ${source.epoch}\n` +
      `Clear ALL branch protection: ${proposed.clear}\n` +
      `All changes:\n${JSON.stringify(protectionChanges(source.policy, proposed.replacement), null, 2)}\n` +
      `Complete replacement:\n${JSON.stringify(proposed.replacement, null, 2)}`);
    status('Review every administrator and branch/reviewer addition and removal. Omitted entries are deleted, not preserved. Prepare explicitly to save this exact preview.');
  }));
  on('stage', 'click', () => run(async guard => {
    requireDraftAccess();
    if (!preview || JSON.stringify(draft()) !== JSON.stringify({ replacement: preview.replacement, clear: preview.clear }) ||
        JSON.stringify(client.observed) !== JSON.stringify(preview.source)) fail('Inputs or the source policy changed. Preview again before preparing.');
    await client.stage(preview.replacement, preview.clear); guard(); preview = null; confirm.checked = false;
    status('Exact protection replacement prepared locally, not sent. Inspect the saved request, save its receipt, then explicitly confirm Send/Retry.');
  }));
  confirm.addEventListener('change', controls);
  on('send', 'click', () => run(async guard => {
    if (!client.connected || client.recoveryOnly || !client.pending || !confirm.checked) fail('Explicitly confirm the original request using an ordinary protection connection.');
    confirm.checked = false; const result = await client.send(); guard(); terminal(result);
  }));
  on('recover', 'click', () => run(async guard => { const result = await client.recover(); guard(); terminal(result); }));
  on('discard', 'click', () => run(async () => {
    if (!client.connected || client.recoveryOnly) fail('Discard requires an ordinary protection connection.');
    client.discardUnsent(); changed(); status('Never-dispatched, never-exported draft discarded. Preview the complete replacement again before preparing.');
  }));
  on('export', 'click', () => run(async () => {
    download('frankengit-protection-recovery.json', client.exportReceipt());
    status('Original recovery receipt exported without the bearer token. Keep it private and retain the original credential; the command may be submitted elsewhere.');
  }));
  doc.defaultView.addEventListener('beforeunload', event => {
    if (client.pending || client.busy || operation) { event.preventDefault(); event.returnValue = ''; }
  });
  doc.defaultView.addEventListener('pagehide', disconnect);
  status('Connect independently for protection administration. No protection request runs automatically.'); controls();
  return { client, disconnect };
}

if (typeof document !== 'undefined' && document.getElementById('pr-collaboration')) {
  mountPulls(document);
  mountProtection(document);
}
