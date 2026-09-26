import { IssueClient, MAX_RECEIPT_BYTES, decimal, issueSearchQuery } from './issues.mjs';
import { markdownBody } from './markdown.mjs';

function visible(value) {
  return String(value).replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069]/gu,
    character => `\\u{${character.codePointAt(0).toString(16)}}`);
}
export function mountIssues(document, location, options = {}) {
  const client = options.client ?? new IssueClient({ href: location.href, fetchImpl: options.fetchImpl, cryptoImpl: options.cryptoImpl });
  const byId = id => document.getElementById(id);
  const node = (tag, value = '') => { const element = document.createElement(tag); element.textContent = visible(value); return element; };
  const button = (label, action) => { const element = node('button', label); element.type = 'button'; element.addEventListener('click', action); return element; };
  const status = value => { byId('issue-status').textContent = value; };
  let session = 0, view = 0;
  const clearView = () => ['issue-content', 'issue-paging', 'issue-snapshot'].forEach(id => byId(id).replaceChildren());
  function syncPending() {
    const pending = client.pending;
    byId('prepared-change').hidden = !pending;
    byId('prepare-change').disabled = !client.connected || Boolean(pending) || client.busy;
    byId('send-change').disabled = !pending || !client.connected || client.busy;
    byId('check-outcome').disabled = !pending || !client.connected || client.busy;
    byId('save-receipt').disabled = !pending;
    byId('discard-change').disabled = !pending || pending.sent || pending.exported || client.busy;
    byId('send-change').textContent = pending?.sent ? 'Retry identical change' : 'Send prepared change';
    byId('prepared-summary').textContent = pending ? [
      `Issue #${pending.number} · ${pending.action} · expected version ${pending.expected_version}`,
      `Idempotency-Key: ${pending.key}`,
      pending.sent ? 'Dispatched or restored: canonical outcome unresolved.' : pending.exported
        ? 'Receipt exported. Preserve this identity; other sessions may send it.' : 'Prepared locally. Nothing sent.',
      client.connected ? visible(JSON.stringify(pending.fields, null, 2)) : 'Reconnect the original credential to inspect this private draft.',
    ].join('\n') : '';
  }
  function configureEditor() {
    const action = byId('change-action').value;
    const full = ['open', 'edit'].includes(action);
    byId('title-field').hidden = !full;
    byId('labels-field').hidden = !full;
    byId('body-field').hidden = !full && action !== 'comment';
    byId('replace-body-label').hidden = action !== 'edit';
  }
  function edit(issue, action) {
    byId('change-number').value = String(issue.number); byId('change-version').value = String(issue.version);
    byId('change-action').value = action;
    byId('change-title').value = issue.title;
    byId('change-body').value = action === 'comment' ? '' : issue.body;
    byId('change-labels').value = issue.labels.join('\n');
    for (const field of ['replace-title', 'replace-body', 'replace-labels']) byId(field).checked = true;
    configureEditor(); status(`Preparing against issue #${issue.number} version ${issue.version}. Nothing sent.`);
  }
  function issueTable(issues, head) {
    const table = node('table');
    const header = node('tr'); header.append(node('th', 'Issue'), node('th', 'State / version')); table.append(header);
    for (const issue of issues) {
      const row = node('tr'), title = node('td');
      title.append(button(`#${issue.number} ${issue.title}`, () => { void read(issue.number, 0, head); }));
      row.append(title, node('td', `${issue.state} · version ${issue.version}`)); table.append(row);
    }
    return table;
  }
  async function read(number, after = 0, head = null) {
    const currentSession = session, currentView = ++view;
    client.cancelReads(); clearView(); status('Reading one issue snapshot…');
    try {
      // List rows do not display bodies; request presentations only when
      // reading an issue and its exact versioned action/comment history.
      const result = await client.read(number, { after, limit: 20, head, render: number !== null });
      if (session !== currentSession || view !== currentView) return;
      const reply = result.reply;
      const content = node('div');
      const body = value => markdownBody(document, value.body, value.body_rendered, {
        cryptoImpl: options.cryptoImpl ?? globalThis.crypto,
        current: () => client.connected && session === currentSession && view === currentView,
      }).element;
      if (number === null) {
        content.append(issueTable(reply.issues, result.head));
        if (!reply.issues.length) content.append(node('p', 'No issues on this snapshot page.'));
        if (reply.next_after !== null) byId('issue-paging').append(button('Next issue page', () => { void read(null, reply.next_after, result.head); }));
      } else if (!reply.found) {
        content.append(node('p', `Issue #${number} was not found at this snapshot.`));
      } else {
        const issue = reply.issue;
        byId('show-number').value = String(number);
        content.append(node('h2', `#${number} ${issue.title}`),
          node('p', `${issue.state} · version ${issue.version} · ${issue.comments} comments`),
          node('p', `Opened by ${issue.opened_by} · last changed by ${issue.last_actor}`),
          node('p', `Labels: ${issue.labels.join(', ') || '(none)'}`), body(issue));
        const actions = node('div'); actions.className = 'issue-actions';
        for (const [label, action] of [['Comment', 'comment'], ['Edit issue', 'edit'],
          [issue.state === 'open' ? 'Close issue' : 'Reopen issue', issue.state === 'open' ? 'close' : 'reopen']]) {
          actions.append(button(label, () => edit(issue, action)));
        }
        content.append(actions, node('h3', 'Canonical event history'));
        for (const event of reply.events) {
          const entry = node('article');
          entry.append(node('h4', `Version ${event.version} · ${event.action.name} · ${event.actor}`));
          if (Object.hasOwn(event.action, 'title')) entry.append(node('p', event.action.title));
          if (Object.hasOwn(event.action, 'body')) entry.append(body(event.action));
          if (Object.hasOwn(event.action, 'labels')) entry.append(node('p', `Labels: ${event.action.labels.join(', ') || '(none)'}`));
          content.append(entry);
        }
        if (reply.next_after_version !== null) byId('issue-paging').append(button('Next history page', () => { void read(number, reply.next_after_version, result.head); }));
      }
      byId('issue-content').append(content);
      byId('issue-snapshot').textContent = `Repository ${result.binding.repository}\nSnapshot ${result.head}`;
      status('Read complete. Continuations use this same snapshot; reload explicitly when it moves.');
    } catch (error) {
      if (session !== currentSession || view !== currentView) return;
      if (!client.connected) disconnect();
      clearView(); status(error.message); syncPending();
    }
  }
  async function search(input, after = 0, head = null, maxScan = 200) {
    const currentSession = session, currentView = ++view;
    client.cancelReads(); clearView(); status('Searching a bounded issue snapshot…');
    try {
      const query = issueSearchQuery(input);
      const result = await client.search(query, { after, limit: 20, head, maxScan });
      if (session !== currentSession || view !== currentView) return;
      const reply = result.reply, content = node('div');
      content.append(node('h2', 'Issue search results'),
        node('p', `Applied filters: ${JSON.stringify(query)}`),
        node('p', `Examined ${reply.scanned} candidates; ${reply.count} matches on this page.`),
        issueTable(reply.issues, result.head));
      if (!reply.issues.length) content.append(node('p', reply.complete
        ? 'No matches in the remaining snapshot suffix.'
        : 'No matches in this bounded scan. Unexamined candidates remain.'));
      if (reply.next_after !== null) {
        // Capture the applied predicate, native candidate cursor, original
        // snapshot and scan bound, never the subsequently edited form fields.
        byId('issue-paging').append(button('Continue searching this snapshot', () => {
          void search(query, reply.next_after, result.head, maxScan);
        }));
      }
      byId('issue-content').append(content);
      byId('issue-snapshot').textContent = `Repository ${result.binding.repository}\nSnapshot ${result.head}`;
      status(reply.complete ? 'Search complete for this snapshot suffix. No repository-wide total is implied.'
        : `Search paused at ${reply.stop_reason === 'scan_limit' ? 'the scan limit' : 'the result limit'}. More candidates remain; another match is not guaranteed.`);
    } catch (error) {
      if (session !== currentSession || view !== currentView) return;
      if (!client.connected) disconnect();
      clearView(); status(error.message); syncPending();
    }
  }
  function cancelView() {
    view += 1; client.cancelReads(); clearView();
    status('Issue read cancelled. Any prepared or dispatched change is unchanged.');
  }
  function disconnect() {
    session += 1; view += 1; client.disconnect(); clearView();
    for (const id of ['issue-token', 'change-title', 'change-body', 'change-labels', 'change-number', 'change-version', 'show-number', 'restore-receipt',
      'issue-search-query', 'issue-search-labels', 'issue-search-opener']) byId(id).value = '';
    byId('issue-search-state').value = 'all'; byId('issue-search-case').checked = false;
    byId('issue-search-scan').value = '200';
    status(client.pending ? 'Disconnected. An unresolved request is retained locally; save its recovery receipt before leaving.' : 'Disconnected. Token and displayed issue data discarded.');
    syncPending();
  }
  byId('issue-connection').addEventListener('submit', async event => {
    event.preventDefault();
    const token = byId('issue-token').value; byId('issue-token').value = '';
    disconnect(); const current = session;
    try {
      await client.connect(token);
      if (current !== session) return;
      syncPending();
      if (client.pending) status('Original credential connected. Resolve the retained exact request before starting another change.');
      else await read(null);
    } catch (error) { if (current === session) { status(error.message); syncPending(); } }
  });
  byId('issue-disconnect').addEventListener('click', disconnect);
  byId('issue-list').addEventListener('click', () => { void read(null); });
  byId('issue-show').addEventListener('submit', event => {
    event.preventDefault();
    try { void read(decimal(byId('show-number').value, 'issue number', 1)); } catch (error) { status(error.message); }
  });
  byId('issue-search').addEventListener('submit', event => {
    event.preventDefault();
    try {
      const labels = byId('issue-search-labels').value;
      const state = byId('issue-search-state').value;
      void search({ state: state === 'all' ? null : state,
        text: byId('issue-search-query').value || null,
        opened_by: byId('issue-search-opener').value || null,
        labels: labels === '' ? [] : labels.split('\n'),
        case_sensitive: byId('issue-search-case').checked }, 0, null,
        decimal(byId('issue-search-scan').value, 'search scan limit', 1));
    } catch (error) { cancelView(); status(error.message); }
  });
  byId('issue-search-cancel').addEventListener('click', cancelView);
  byId('change-action').addEventListener('change', configureEditor);
  byId('issue-change').addEventListener('submit', async event => {
    event.preventDefault();
    const current = session;
    try {
      const action = byId('change-action').value, fields = {};
      if (action === 'open' || action === 'edit') {
        if (action === 'open' || byId('replace-title').checked) fields.title = byId('change-title').value;
        if (action === 'open' || byId('replace-body').checked) fields.body = byId('change-body').value;
        if (action === 'open' || byId('replace-labels').checked) {
          const labels = byId('change-labels').value; fields.labels = labels === '' ? [] : labels.split('\n');
        }
      } else if (action === 'comment') fields.body = byId('change-body').value;
      await client.stage(decimal(byId('change-number').value, 'issue number', 1),
        decimal(byId('change-version').value, 'expected version'), action, fields);
      if (current !== session) return;
      status('Prepared locally. Save the recovery receipt, review the exact request, then send explicitly.');
      syncPending();
    } catch (error) { if (current === session) status(error.message); }
  });
  async function decide(recovery) {
    const current = session;
    try {
      const running = recovery ? client.recover() : client.send();
      syncPending(); status(recovery ? 'Reading the canonical outcome without re-executing the request…' : 'Sending the exact prepared change…');
      const result = await running;
      if (session !== current) return;
      if (result.terminal === false) {
        status(`Outcome still unknown (${result.state}). Absence does not prove non-commit. Retain this receipt and key.`);
      } else {
        view += 1; client.cancelReads(); clearView(); byId('change-version').value = '';
        status(`${result.outcome === 'committed' ? 'Committed' : 'Refused'} · transaction ${visible(result.tx)}${result.refusal ? ` · ${visible(result.refusal)}` : ''}. Reload the issue before preparing another change. Delivery acknowledgement is not implied.`);
      }
    } catch (error) {
      if (session === current) {
        if (!client.connected) disconnect();
        status(`${error.message} The exact pending request is retained; its outcome is not inferred from this failure.`);
      }
    } finally { syncPending(); }
  }
  byId('send-change').addEventListener('click', () => { void decide(false); });
  byId('check-outcome').addEventListener('click', () => { void decide(true); });
  byId('discard-change').addEventListener('click', () => {
    try { client.discardUnsent(); syncPending(); status('Unsent local preparation discarded.'); } catch (error) { status(error.message); }
  });
  byId('save-receipt').addEventListener('click', () => {
    try {
      const serialized = client.exportReceipt(); syncPending();
      if (options.saveReceipt) options.saveReceipt(serialized);
      else {
        const url = URL.createObjectURL(new Blob([serialized], { type: 'application/json' }));
        const link = node('a'); link.href = url; link.download = `frankengit-issue-${client.pending.number}-retry.json`;
        document.body.append(link); link.click(); link.remove();
        setTimeout(() => URL.revokeObjectURL(url), 30_000);
      }
      status('Recovery receipt offered for download. Verify it was saved; it contains private draft text, not an access token.');
    } catch (error) { status(error.message); }
  });
  byId('restore-receipt').addEventListener('change', async () => {
    const input = byId('restore-receipt'), file = input.files?.[0]; input.value = '';
    if (!file) return;
    const current = session;
    try {
      if (file.size > MAX_RECEIPT_BYTES) throw new Error('Recovery receipt exceeds the byte limit.');
      const bytes = await file.arrayBuffer();
      if (current !== session) return;
      if (bytes.byteLength > MAX_RECEIPT_BYTES) throw new Error('Recovery receipt exceeds the byte limit.');
      await client.restoreReceipt(new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes));
      if (current !== session) return;
      syncPending(); status('Original request restored, not sent. Check its canonical outcome or retry the identical change.');
    } catch (error) { if (current === session) status(error.message); }
  });
  document.defaultView?.addEventListener('pagehide', disconnect);
  document.defaultView?.addEventListener('beforeunload', event => {
    if (client.pending) { event.preventDefault(); event.returnValue = ''; }
  });
  configureEditor(); syncPending();
  return { client, disconnect, read, search };
}
if (typeof document !== 'undefined') mountIssues(document, window.location);
