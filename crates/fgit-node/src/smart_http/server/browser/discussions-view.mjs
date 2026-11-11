import { DiscussionClient } from './discussions.mjs';
import { decimal, MAX_RECEIPT_BYTES } from './issues.mjs';
import { markdownBody } from './markdown.mjs';

const visible = value => String(value).replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069]/gu,
  character => `\\u{${character.codePointAt(0).toString(16)}}`);

export function mountDiscussions(document, location, options = {}) {
  const client = options.client ?? new DiscussionClient({ href: location.href, fetchImpl: options.fetchImpl, cryptoImpl: options.cryptoImpl });
  const get = id => document.getElementById(id);
  const node = (tag, value = '') => { const element = document.createElement(tag); element.textContent = visible(value); return element; };
  const button = (label, action) => { const element = node('button', label); element.type = 'button'; element.addEventListener('click', () => run(action)); return element; };
  const status = value => { get('discussion-status').textContent = visible(value); };
  let epoch = 0, session = 0, selected = null;
  const isComment = action => ['comment', 'append-comment'].includes(action);
  const locked = () => isComment(get('change-action').value) && selected?.locked === true && String(selected.number) === get('change-number').value;
  function pending() {
    const request = client.pending;
    get('prepared-change').hidden = !request;
    get('prepare-change').disabled = !client.connected || Boolean(request) || client.busy || locked();
    get('change-body').disabled = locked();
    get('send-change').disabled = !client.connected || !request || client.busy;
    get('check-outcome').disabled = !client.connected || !request || client.busy;
    get('save-receipt').disabled = !request;
    get('discard-change').disabled = !request || request.sent || request.exported || client.busy;
    get('send-change').textContent = request?.sent ? 'Retry identical change' : 'Send prepared change';
    get('prepared-summary').textContent = request ? visible([
      `Discussion #${request.number} · ${request.action} · ${request.expected_version === null ? 'accept concurrent replies' : `expected version ${request.expected_version}`}`,
      `Idempotency-Key: ${request.key}`,
      request.sent ? 'Possibly sent. Resolve the original outcome.' : request.exported ? 'Receipt saved. Keep this original request.' : 'Prepared locally. Nothing sent.',
      client.connected ? JSON.stringify(request.fields, null, 2) : 'Reconnect the original credential to inspect the draft.',
    ].join('\n')) : '';
  }
  async function run(action) {
    const current = session;
    try { await action(); }
    catch (error) {
      if (current !== session) return;
      if (!client.connected) disconnect();
      status(error.outcomeUnknown ? `Outcome unknown: ${error.message} Check the outcome or retry the original request.` : error.message);
    }
    finally { pending(); }
  }
  function configure() {
    const action = get('change-action').value;
    const append = action === 'append-comment';
    get('version-field').hidden = append;
    get('change-version').disabled = append;
    get('change-version').required = !append;
    get('append-comment-hint').hidden = !append;
    get('title-field').hidden = !['open', 'edit'].includes(action);
    get('body-field').hidden = !['open', 'edit', 'comment', 'append-comment'].includes(action);
    get('replace-title-label').hidden = action !== 'edit';
    get('replace-body-label').hidden = action !== 'edit';
    pending();
  }
  function choose(row, action) {
    selected = row;
    get('change-number').value = String(row.number); get('change-version').value = action === 'append-comment' ? '' : String(row.version);
    get('change-action').value = action; get('change-title-text').value = row.title;
    get('change-body').value = isComment(action) ? '' : row.body;
    get('replace-title').checked = true; get('replace-body').checked = true;
    configure();
    status(locked() ? 'This discussion is locked. Unlock comments before replying.'
      : action === 'append-comment' ? `Preparing a comment on discussion #${row.number}; concurrent replies are accepted.`
      : `Preparing ${action} for discussion #${row.number} at version ${row.version}.`);
  }
  function clear() {
    selected = null;
    for (const id of ['discussion-content', 'discussion-paging', 'discussion-snapshot']) get(id).replaceChildren();
  }
  function cancel() { epoch += 1; client.cancelReads(); }
  function disconnect() {
    session += 1;
    cancel(); client.disconnect(); clear();
    for (const id of ['discussion-token', 'change-title-text', 'change-body', 'change-number',
      'change-version', 'show-number', 'restore-receipt']) get(id).value = '';
    pending();
  }
  async function read(number = null, after = 0, head = null) {
    cancel(); const current = epoch;
    clear(); status('Reading discussions…');
    const page = await client.read(number, { after, head, render: number !== null });
    if (current !== epoch || !client.connected) return;
    const { reply } = page, content = get('discussion-content'), paging = get('discussion-paging');
    get('discussion-snapshot').textContent = `Snapshot ${page.head}`;
    if (number === null) {
      for (const row of reply.discussions) {
        const article = node('article');
        article.append(button(`#${row.number} ${row.title}`, () => read(row.number, 0, page.head)),
          node('p', `${row.state} · ${row.locked ? 'locked' : 'unlocked'} · ${row.comments} comments · version ${row.version}`));
        content.append(article);
      }
      if (!reply.discussions.length) content.append(node('p', 'No discussions yet. Open one below.'));
      if (reply.next_after !== null) paging.append(button('Next discussion page', () => read(null, reply.next_after, page.head)));
      status(`${reply.discussions.length} discussions shown.`);
    } else if (!reply.found) status('Discussion not found.');
    else {
      const row = reply.discussion; selected = row; get('show-number').value = String(number);
      const body = value => markdownBody(document, value.body, value.body_rendered, {
        cryptoImpl: options.cryptoImpl ?? globalThis.crypto,
        current: () => current === epoch && client.connected,
      }).element;
      content.append(node('h2', `#${row.number} ${row.title}`),
        node('p', `${row.state} · ${row.locked ? 'locked' : 'unlocked'} · version ${row.version} · opened by ${row.opened_by}`), body(row));
      const actions = node('div'); actions.className = 'issue-actions';
      for (const [action, label] of [['comment', 'Comment'], ['append-comment', 'Append comment'], ['edit', 'Edit'],
          [row.state === 'open' ? 'close' : 'reopen', row.state === 'open' ? 'Close' : 'Reopen'],
          [row.locked ? 'unlock' : 'lock', row.locked ? 'Unlock comments' : 'Lock comments']]) {
        const control = button(label, () => choose(row, action));
        control.disabled = isComment(action) && row.locked; actions.append(control);
      }
      content.append(actions, node('h3', 'History'));
      for (const event of reply.events) {
        const article = node('article');
        article.append(node('h4', `Version ${event.version} · ${event.action.name} · ${event.actor}`));
        if (event.action.title !== undefined) article.append(node('p', event.action.title));
        if (event.action.body !== undefined) article.append(body(event.action));
        content.append(article);
      }
      if (reply.next_after_version !== null) paging.append(button('Next history page', () => read(number, reply.next_after_version, page.head)));
      status(`Discussion #${number} loaded.`);
    }
    pending();
  }
  async function terminal(result) {
    status(`${result.outcome === 'committed' ? 'Committed' : 'Refused'}${result.refusal ? `: ${result.refusal}` : ''}. Reload explicitly to see the current discussion.`);
  }
  get('discussion-connect').addEventListener('submit', event => {
    event.preventDefault();
    const token = get('discussion-token').value;
    disconnect();
    return run(async () => { await client.connect(token); await read(); });
  });
  get('discussion-disconnect').addEventListener('click', () => { disconnect(); status('Disconnected.'); });
  get('discussion-list').addEventListener('click', () => run(() => read()));
  get('discussion-cancel').addEventListener('click', () => { cancel(); status('Read cancelled.'); });
  get('discussion-show').addEventListener('submit', event => { event.preventDefault(); return run(() => read(decimal(get('show-number').value, 'discussion number', 1))); });
  get('change-action').addEventListener('change', configure);
  get('change-number').addEventListener('input', pending);
  get('discussion-change').addEventListener('submit', event => { event.preventDefault(); return run(async () => {
    if (locked()) throw new Error('This discussion is locked. Unlock comments before replying.');
    const action = get('change-action').value, fields = {};
    if (action === 'open' || (action === 'edit' && get('replace-title').checked)) fields.title = get('change-title-text').value;
    if (['open', 'comment', 'append-comment'].includes(action) || (action === 'edit' && get('replace-body').checked)) fields.body = get('change-body').value;
    await client.stage(decimal(get('change-number').value, 'discussion number', 1),
      action === 'append-comment' ? null : decimal(get('change-version').value, 'expected version'), action, fields);
    status('Change prepared. Review it before sending.');
  }); });
  get('send-change').addEventListener('click', () => run(async () => terminal(await client.send())));
  get('check-outcome').addEventListener('click', () => run(async () => {
    const result = await client.recover();
    if (result.terminal) await terminal(result); else status('No terminal outcome observed. Keep the original request for recovery or retry.');
  }));
  get('discard-change').addEventListener('click', () => run(() => { client.discardUnsent(); status('Unsent preparation discarded.'); }));
  get('save-receipt').addEventListener('click', () => run(() => {
    const receipt = client.exportReceipt();
    if (options.saveReceipt) return options.saveReceipt(receipt);
    const url = URL.createObjectURL(new Blob([receipt], { type: 'application/json' }));
    const link = document.createElement('a'); link.href = url; link.download = 'frankengit-discussion-retry.json'; link.click();
    setTimeout(() => URL.revokeObjectURL(url), 0);
  }));
  get('restore-receipt').addEventListener('change', () => run(async () => {
    const current = session;
    const file = get('restore-receipt').files?.[0]; get('restore-receipt').value = '';
    if (!file) return;
    if (file.size > MAX_RECEIPT_BYTES) throw new Error('Recovery receipt is too large.');
    const bytes = await file.arrayBuffer();
    if (current !== session) return;
    if (bytes.byteLength > MAX_RECEIPT_BYTES) throw new Error('Recovery receipt is too large.');
    await client.restoreReceipt(new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes));
    if (current === session) status('Original request restored; nothing sent.');
  }));
  document.defaultView?.addEventListener('pagehide', disconnect);
  document.defaultView?.addEventListener('beforeunload', event => {
    if (client.pending) { event.preventDefault(); event.returnValue = ''; }
  });
  configure();
  return { client, read, choose, cancel };
}
if (typeof document !== 'undefined') mountDiscussions(document, globalThis.location);
