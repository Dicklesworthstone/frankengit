import { MilestoneClient } from './milestones.mjs';
import { decimal, MAX_RECEIPT_BYTES } from './issues.mjs';
import { markdownBody } from './markdown.mjs';

const visible = value => String(value).replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069]/gu,
  character => `\\u{${character.codePointAt(0).toString(16)}}`);
const dueText = value => value === null ? 'No due date' : `Due ${new Date(value * 1000).toISOString().replace('T', ' ').replace('.000Z', ' UTC')}`;
function dueSeconds(value) {
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(?::\d{2})?$/.test(value)) throw new Error('Enter a complete UTC due date and time.');
  const exact = value.length === 16 ? `${value}:00` : value;
  const milliseconds = Date.parse(`${exact}Z`), seconds = milliseconds / 1000;
  if (!Number.isSafeInteger(seconds) || seconds < 0 || seconds > 253402300799 ||
      new Date(milliseconds).toISOString().slice(0, 19) !== exact) throw new Error('Due date must be a valid UTC time between 1970 and 9999.');
  return seconds;
}

export function mountMilestones(document, location, options = {}) {
  const client = options.client ?? new MilestoneClient({ href: location.href, fetchImpl: options.fetchImpl, cryptoImpl: options.cryptoImpl });
  const get = id => document.getElementById(id);
  const node = (tag, value = '') => { const element = document.createElement(tag); element.textContent = visible(value); return element; };
  const status = value => { get('milestone-status').textContent = visible(value); };
  let session = 0, view = 0;
  function syncPending() {
    const request = client.pending;
    get('prepared-change').hidden = !request;
    get('prepare-change').disabled = !client.connected || Boolean(request) || client.busy;
    get('send-change').disabled = !client.connected || !request || client.busy;
    get('check-outcome').disabled = !client.connected || !request || client.busy;
    get('save-receipt').disabled = !request || client.busy;
    get('discard-change').disabled = !request || request.sent || request.exported || client.busy;
    get('send-change').textContent = request?.sent ? 'Retry identical change' : 'Send prepared change';
    get('prepared-summary').textContent = request ? visible([
      `Milestone #${request.number} · ${request.action} · expected version ${request.expected_version}`,
      `Idempotency-Key: ${request.key}`,
      request.sent ? 'Dispatched or restored: the canonical outcome is unresolved.' : request.exported
        ? 'Receipt exported. Preserve this original request; another session may send it.' : 'Prepared locally. Nothing sent.',
      client.connected ? JSON.stringify(request.fields, null, 2) : 'Reconnect the original credential to inspect this private draft.',
    ].join('\n')) : '';
  }
  async function run(action) {
    const current = session;
    try {
      const operation = action(() => current === session);
      syncPending();
      await operation;
    } catch (error) {
      if (current !== session) return;
      if (!client.connected) disconnect();
      status(error.outcomeUnknown ? `Outcome unknown: ${error.message} Preserve the original request for recovery or an explicit retry.` : error.message);
    } finally { syncPending(); }
  }
  function button(label, action, selectedView) {
    const control = node('button', label); control.type = 'button';
    control.addEventListener('click', () => run(() => {
      if (!client.connected || selectedView !== view) throw new Error('This milestone view was replaced. Reload explicitly.');
      return action();
    }));
    return control;
  }
  function configure() {
    const action = get('change-action').value, fields = ['open', 'edit'].includes(action);
    for (const id of ['title-field', 'body-field', 'due-field']) get(id).hidden = !fields;
    get('replace-title-label').hidden = action !== 'edit';
    get('replace-body-label').hidden = action !== 'edit';
    get('due-preserve').disabled = action !== 'edit';
    if (action === 'open' && get('change-due-mode').value === 'preserve') get('change-due-mode').value = 'clear';
    get('change-due').disabled = !fields || get('change-due-mode').value !== 'set';
    get('change-due').required = fields && get('change-due-mode').value === 'set';
    syncPending();
  }
  function choose(row, action) {
    get('change-number').value = String(row.number); get('change-version').value = String(row.version);
    get('change-action').value = action; get('change-title-text').value = row.title; get('change-body').value = row.body;
    get('replace-title').checked = true; get('replace-body').checked = true;
    get('change-due-mode').value = 'preserve';
    get('change-due').value = row.due_at === null ? '' : new Date(row.due_at * 1000).toISOString().slice(0, 19);
    configure(); status(`Preparing ${action} for milestone #${row.number} at observed version ${row.version}. Nothing sent.`);
  }
  function freshEditor() {
    get('change-action').value = 'open'; get('change-version').value = '0';
    for (const id of ['change-number', 'change-title-text', 'change-body', 'change-due']) get(id).value = '';
    get('change-due-mode').value = 'clear'; get('replace-title').checked = true; get('replace-body').checked = true;
    configure(); status('Choose an unused milestone number, title, description and optional UTC due date. Nothing sent.');
  }
  function clearView() {
    for (const id of ['milestone-content', 'milestone-paging', 'milestone-snapshot']) get(id).replaceChildren();
  }
  function cancel() { view += 1; client.cancelReads(); clearView(); }
  function disconnect() {
    session += 1; cancel(); client.disconnect();
    for (const id of ['milestone-token', 'change-number', 'change-version', 'change-title-text', 'change-body',
      'change-due', 'show-number', 'restore-receipt']) get(id).value = '';
    get('change-due-mode').value = 'clear'; configure();
  }
  const pageLimit = () => decimal(get('milestone-limit').value, 'page size', 1);
  const progress = row => `${row.open_issues} open · ${row.closed_issues} closed · ${row.open_issues + row.closed_issues} issues`;
  async function read(number = null, after = 0, head = null, limit = pageLimit()) {
    cancel(); const selectedView = view, currentSession = session;
    status('Reading one milestone snapshot…');
    let result;
    try { result = await client.read(number, { after, limit, head, render: number !== null }); }
    catch (error) { if (selectedView !== view || currentSession !== session) return; throw error; }
    if (selectedView !== view || currentSession !== session || !client.connected) return;
    const { reply } = result, content = get('milestone-content'), paging = get('milestone-paging');
    get('milestone-snapshot').textContent = `Snapshot ${result.head}`;
    if (number === null) {
      for (const row of reply.milestones) {
        const article = node('article');
        article.append(button(`#${row.number} ${row.title}`, () => read(row.number, 0, result.head, limit), selectedView),
          node('p', `${row.state} · version ${row.version} · ${dueText(row.due_at)}`), node('p', progress(row)));
        content.append(article);
      }
      if (!reply.milestones.length) content.append(node('p', after === 0 ? 'No milestones at this snapshot. Open one below.' : 'No milestones on this snapshot page.'));
      if (reply.next_after !== null) paging.append(button('Next milestone page', () => read(null, reply.next_after, result.head, limit), selectedView));
      status(`${reply.milestones.length} milestones on this snapshot page.`);
    } else if (!reply.found) {
      content.append(node('p', `Milestone #${number} was not found at this snapshot.`)); status(`Milestone #${number} not found.`);
    } else {
      const row = reply.milestone; get('show-number').value = String(row.number);
      const body = value => markdownBody(document, value.body, value.body_rendered, {
        cryptoImpl: options.cryptoImpl ?? globalThis.crypto,
        current: () => selectedView === view && currentSession === session && client.connected,
      }).element;
      content.append(node('h2', `#${row.number} ${row.title}`),
        node('p', `${row.state} · version ${row.version} · ${dueText(row.due_at)}`), node('p', progress(row)),
        node('p', `Opened by ${row.opened_by} · last changed by ${row.last_actor}`), body(row));
      const actions = node('div'); actions.className = 'issue-actions';
      actions.append(button('Edit milestone', () => choose(row, 'edit'), selectedView),
        button(row.state === 'open' ? 'Close milestone' : 'Reopen milestone', () => choose(row, row.state === 'open' ? 'close' : 'reopen'), selectedView));
      const issues = node('a', `Manage issues for milestone #${row.number}`); issues.href = '../issues/';
      content.append(actions, issues, node('p', `On the issue page, filter by milestone ${row.number} to inspect members or change their milestone. Closing preserves existing memberships.`), node('h3', 'Milestone history'));
      for (const event of reply.events) {
        const article = node('article'); article.append(node('h4', `Version ${event.version} · ${event.action.name} · ${event.actor}`));
        if (Object.hasOwn(event.action, 'title')) article.append(node('p', event.action.title));
        if (Object.hasOwn(event.action, 'body')) article.append(body(event.action));
        if (Object.hasOwn(event.action, 'due_at')) article.append(node('p', dueText(event.action.due_at)));
        content.append(article);
      }
      if (reply.next_after_version !== null) paging.append(button('Next milestone history page', () => read(number, reply.next_after_version, result.head, limit), selectedView));
      status(`Milestone #${row.number} loaded at version ${row.version}.`);
    }
    syncPending();
  }
  function terminal(result) {
    cancel();
    status(`${result.outcome === 'committed' ? 'Committed' : 'Refused'}${result.refusal ? `: ${result.refusal}` : ''}. Reload explicitly for current milestone versions and issue counts.`);
  }
  get('milestone-connect').addEventListener('submit', event => {
    event.preventDefault(); const token = get('milestone-token').value; disconnect();
    return run(async current => { await client.connect(token); if (current()) await read(); });
  });
  get('milestone-disconnect').addEventListener('click', () => { disconnect(); status('Disconnected.'); });
  get('milestone-list').addEventListener('click', () => run(() => read()));
  get('milestone-cancel').addEventListener('click', () => { cancel(); status('Read cancelled.'); });
  get('milestone-show').addEventListener('submit', event => { event.preventDefault(); return run(() => read(decimal(get('show-number').value, 'milestone number', 1))); });
  get('milestone-new').addEventListener('click', freshEditor);
  get('change-action').addEventListener('change', configure);
  get('change-due-mode').addEventListener('change', configure);
  get('milestone-change').addEventListener('submit', event => {
    event.preventDefault();
    return run(async current => {
      const action = get('change-action').value, fields = {};
      if (action === 'open' || (action === 'edit' && get('replace-title').checked)) fields.title = get('change-title-text').value;
      if (action === 'open' || (action === 'edit' && get('replace-body').checked)) fields.body = get('change-body').value;
      if (['open', 'edit'].includes(action)) {
        const mode = get('change-due-mode').value;
        if (mode === 'set') fields.due_at = dueSeconds(get('change-due').value);
        else if (mode === 'clear') fields.due_at = null;
        else if (mode !== 'preserve' || action !== 'edit') throw new Error('Choose an explicit due-date action.');
      }
      await client.stage(decimal(get('change-number').value, 'milestone number', 1), decimal(get('change-version').value, 'expected version'), action, fields);
      if (current()) status('Milestone change prepared locally. Review the exact request before sending.');
    });
  });
  get('send-change').addEventListener('click', () => run(async current => { const result = await client.send(); if (current()) terminal(result); }));
  get('check-outcome').addEventListener('click', () => run(async current => {
    const result = await client.recover();
    if (!current()) return;
    if (result.terminal) terminal(result); else status('No terminal outcome observed. Preserve the original request for recovery or an explicit retry.');
  }));
  get('discard-change').addEventListener('click', () => run(() => { client.discardUnsent(); status('Unsent preparation discarded.'); }));
  get('save-receipt').addEventListener('click', () => run(() => {
    const receipt = client.exportReceipt();
    if (options.saveReceipt) options.saveReceipt(receipt);
    else {
      const url = URL.createObjectURL(new Blob([receipt], { type: 'application/json' }));
      const link = node('a'); link.href = url; link.download = `frankengit-milestone-${client.pending.number}-retry.json`;
      try { document.body.append(link); link.click(); }
      finally { link.remove(); setTimeout(() => URL.revokeObjectURL(url), 30_000); }
    }
    status('Recovery receipt offered for download. Verify it was saved; it contains private draft text, not an access token.');
  }));
  get('restore-receipt').addEventListener('change', () => run(async current => {
    const file = get('restore-receipt').files?.[0]; get('restore-receipt').value = '';
    if (!file) return;
    if (file.size > MAX_RECEIPT_BYTES) throw new Error('Recovery receipt is too large.');
    const bytes = await file.arrayBuffer();
    if (!current()) return;
    if (bytes.byteLength > MAX_RECEIPT_BYTES) throw new Error('Recovery receipt is too large.');
    await client.restoreReceipt(new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes));
    if (current()) status('Original milestone request restored; nothing sent.');
  }));
  document.defaultView?.addEventListener('pagehide', disconnect);
  document.defaultView?.addEventListener('beforeunload', event => {
    if (client.pending) { event.preventDefault(); event.returnValue = ''; }
  });
  configure();
  return { client, read, cancel };
}
if (typeof document !== 'undefined') mountMilestones(document, globalThis.location);
