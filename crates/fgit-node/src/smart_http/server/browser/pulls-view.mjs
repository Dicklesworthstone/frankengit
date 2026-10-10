// Human PR workflow over the native client. Every source string is inert data;
// preparing, inspecting and displaying approvals never submits a mutation.
import { PullClient } from './pulls.mjs';
import { markdownBody } from './markdown.mjs';
import { decimal, oid, unhex, fail, showReply } from './pulls-core.mjs';
import { RECEIPT_LIMIT, fastForwardCommand } from './pulls-actions.mjs';
import { isFastForwardCandidate } from './pulls-candidate.mjs';
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
const IDS = ['connection', 'token', 'disconnect', 'status', 'refresh', 'pr-list', 'list-paging', 'select-pr', 'select-number',
  'comments-load', 'comments-limit', 'conversation', 'comment-paging', 'comment-form', 'comment-version', 'comment-body', 'comment-stage',
  'selected', 'snapshot', 'reviews-load', 'reviews', 'review-paging', 'metadata', 'pr-number', 'metadata-action', 'expected-version',
  'object-format', 'source-ref', 'target-ref', 'source-tip', 'target-tip', 'title', 'body', 'metadata-stage', 'new-pr',
  'prepare', 'policy-epoch', 'author', 'committer', 'timestamp', 'message', 'prepare-candidate', 'candidate', 'candidate-download',
  'candidate-import', 'candidate-import-file', 'inspection-download', 'resolution', 'resolution-paths', 'resolve-candidate', 'review', 'review-action', 'review-version', 'reason', 'review-stage',
  'merge', 'merge-heading', 'merge-method-guidance', 'merge-reviewer-fields', 'required-reviewers', 'merge-stage', 'pending', 'confirm', 'send', 'recover', 'discard', 'receipt-download', 'receipt-import', 'receipt-import-file'];

export function mountPulls(doc, { href = doc.defaultView.location.href, fetchImpl = globalThis.fetch,
  cryptoImpl = globalThis.crypto, downloadImpl = null } = {}) {
  const nodes = Object.fromEntries(IDS.map(id => { const el = doc.getElementById(id); if (!el) fail(`Missing UI element: ${id}`); return [id, el]; }));
  const client = new PullClient({ href, fetchImpl, cryptoImpl }), download = downloadImpl ?? downloader(doc);
  const resolution = new ResolutionEditor(doc, nodes['resolution-paths'], displayBytes);
  let operation = null, generation = 0, selected = null, listPage = null, reviewPage = null, fastForward = null, conversation = null;
  const number = (id, min = 0) => decimal(nodes[id].value, id, min);
  const status = message => { nodes.status.textContent = displayText(message); };
  const button = (parent, label, handler) => { const el = element(doc, 'button', label); el.type = 'button';
    el.addEventListener('click', event => { event.preventDefault(); handler(); }); parent.append(el); return el; };
  const on = (id, event, handler) => nodes[id].addEventListener(event, ev => { ev.preventDefault(); handler(); });
  function controls() {
    const busy = Boolean(operation) || client.busy, connected = client.connected, pending = client.pending, candidate = client.candidate;
    for (const id of ['refresh', 'new-pr', 'candidate-import-file', 'receipt-import-file']) nodes[id].disabled = !connected || busy;
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
    const inspectedFastForward = isFastForwardCandidate(candidate?.fields);
    nodes['merge-heading'].textContent = inspectedFastForward ? 'Fast-forward inspected source' : 'Reviewed merge';
    nodes['merge-stage'].textContent = inspectedFastForward ? 'Prepare fast-forward — do not send' : 'Prepare merge — do not send';
    nodes['merge-reviewer-fields'].hidden = inspectedFastForward;
    nodes['required-reviewers'].disabled = inspectedFastForward || !candidate || busy || Boolean(pending);
    nodes['required-reviewers'].required = !inspectedFastForward;
    nodes['merge-method-guidance'].textContent = inspectedFastForward
      ? 'Publish the exact inspected source tip with the native fast-forward method. Current branch protection determines required approvals. The request preserves the inspected PR version and both branch tips; it sends no candidate bundle or caller-selected reviewer list.'
      : 'Publish the inspected two-parent candidate with the explicit reviewer requirements below. Current branch protection also applies.';
    for (const id of ['candidate-download', 'inspection-download']) nodes[id].disabled = !candidate || busy;
    nodes.send.disabled = !connected || busy || !pending || !nodes.confirm.checked;
    nodes.recover.disabled = !connected || busy || !pending;
    nodes.discard.disabled = busy || !pending || pending.sent || pending.exported;
    nodes['receipt-download'].disabled = busy || !pending;
    nodes['receipt-import-file'].disabled ||= Boolean(pending);
    nodes.pending.textContent = pending ? displayText(`Prepared ${pending.action} for PR #${pending.number}\n` +
      `Key: ${pending.key}\n${pending.body_bytes} body bytes; ${pending.bundle_bytes} bundle bytes\n` +
      `Dispatch attempted: ${pending.sent}; recovery copy exported: ${pending.exported}\n` +
      `Repository: ${pending.scope.repository}; incarnation: ${pending.scope.incarnation}\n` +
      `${JSON.stringify(pending.fields, null, 2)}\n` +
      'Only Send/Retry dispatches these exact bytes. Edits elsewhere do not change this request. An absent outcome is not proof of failure.') : 'No prepared mutation.';
  }
  function clearViews() {
    clearComments();
    selected = null; listPage = null; reviewPage = null; fastForward = null; resolution.clear();
    for (const id of ['selected', 'snapshot', 'pr-list', 'list-paging', 'reviews', 'review-paging', 'candidate']) nodes[id].replaceChildren();
    for (const id of ['select-number', 'pr-number', 'expected-version', 'source-ref', 'target-ref', 'source-tip', 'target-tip', 'title', 'body',
      'policy-epoch', 'author', 'committer', 'timestamp', 'message', 'review-version', 'reason', 'required-reviewers']) nodes[id].value = '';
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
    if (operation || client.busy) { status('An operation is still settling. Its exact request has not been replaced.'); return; }
    const id = ++generation; operation = { id, kind }; controls();
    const guard = () => { if (generation !== id) fail('Operation superseded.'); };
    try { await action(guard); }
    catch (error) {
      if (generation === id) {
        if (!client.connected) { clearViews(); nodes.token.value = ''; }
        const uncertainty = client.pending?.sent || error.outcomeUnknown;
        status(`${error.message || 'Operation unavailable.'}${uncertainty ? ' Outcome remains unknown unless a terminal decision was already shown. Keep the original request and recover or retry it unchanged.' : ''}`);
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
    clearViews();
    void run('connect', async guard => {
      await client.connect(token); guard(); status('Connected locally. Loading the PR API requires its independent read grant. Recovery receipts can also be restored.');
      try { const result = await client.list(); guard(); renderList(result); }
      catch (error) { guard(); if (!client.connected) throw error; status(`Credential retained for recovery. PR listing was not available: ${error.message}`); }
    });
  });
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
    if (operation || !client.connected) return;
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
    const result = await client.prepareAndInspect(selected.row.number, fields, metadata); guard();
    if (result.inspection) {
      const rendered = renderInspection(doc, nodes.candidate, result.inspection);
      status(`Candidate prepared and inspected, without publication.${rendered.clipped ? ' Display clipped: download the full report before reviewing.' : ''}`);
    } else {
      item(doc, nodes.candidate, 'h3', `Preparation: ${result.metadata.state}`);
      for (const conflict of result.metadata.conflicts) item(doc, nodes.candidate, 'pre', `${displayBytes(conflict.path_hex)} · ${conflict.kind}\nPath bytes: ${conflict.path_hex}`);
      if (result.metadata.state === 'conflicted') {
        resolution.show(result.metadata);
        status('Choose every conflict explicitly below. Resolution constructs and inspects a new candidate; it does not record approval or publish.');
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
    if (isFastForwardCandidate(client.candidate?.fields)) {
      await client.stageInspectedFastForward(); guard(); nodes.confirm.checked = false;
      status('Fast-forward request prepared for the exact inspected source tip. Nothing sent. The node rechecks ancestry, both branch tips, the PR version and current branch protection before publication.');
    } else {
      const reviewers = nodes['required-reviewers'].value.split(/[\s,]+/u).filter(Boolean);
      await client.stageMerge(reviewers); guard(); nodes.confirm.checked = false;
      status('Merge request prepared locally with explicit reviewer requirements. The node will recheck current authority and all gates at publication.');
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
    status('Recovery receipt exported without the token. It contains private command and candidate data. Keep the original credential; this copy may be submitted elsewhere.');
  }));
  on('receipt-import', 'submit', () => run('restore', async guard => {
    const serialized = await fileText(nodes['receipt-import-file']); guard(); await client.restoreReceipt(serialized); guard(); nodes.confirm.checked = false;
    status('Exact request restored. Check its original outcome or explicitly retry the same bytes; no mutation has been sent by importing it.');
  }));
  doc.defaultView.addEventListener('beforeunload', event => {
    if (client.pending || client.busy) { event.preventDefault(); event.returnValue = ''; }
  });
  doc.defaultView.addEventListener('pagehide', disconnect);
  status('Connect with a repository token. Credentials remain only in page memory.'); controls();
  return { client, disconnect, loadPr, loadList, loadReviews, loadComments };
}
if (typeof document !== 'undefined' && document.getElementById('pr-collaboration')) mountPulls(document);
