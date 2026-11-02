import { NotificationClient, notificationState } from './notifications.mjs';
import { decimal, MAX_RECEIPT_BYTES } from './issues.mjs';

// Capture the observed issue/preference versions, never a later refreshed one.
export function threadAction(row, action) {
  notificationState(row);
  if (!['read', 'unread', 'subscribe', 'mute', 'automatic'].includes(action)) throw new Error('Unknown inbox action.');
  return [row.number, row.preference_version ?? 0, action, action === 'read' ? { read_through: row.issue_version } : {}];
}
export class NotificationInboxController {
  #client; #epoch = 0; #page = null; #options = { unreadOnly: false, includeMuted: false };
  constructor(client) { this.#client = client; }
  get page() { return this.#page; }
  cancel() { this.#epoch += 1; this.#client.cancelReads(); }
  disconnect() { this.cancel(); this.#client.disconnect(); this.#page = null; }
  async load(options = this.#options, continuation = false) {
    const previous = this.#page;
    if (continuation && (!previous || previous.reply.type !== 'notification_page' || previous.reply.next_after === null)) throw new Error('No inbox continuation.');
    this.cancel(); const epoch = this.#epoch;
    const selected = continuation ? this.#options : { unreadOnly: options.unreadOnly, includeMuted: options.includeMuted };
    const page = await this.#client.read(null, { ...selected, after: continuation ? previous.reply.next_after : 0, head: continuation ? previous.head : null });
    if (epoch !== this.#epoch) return null;
    this.#options = { ...selected }; this.#page = page;
    return page;
  }
  async show(number) {
    this.cancel(); const epoch = this.#epoch;
    const page = await this.#client.read(number);
    if (epoch !== this.#epoch) return null;
    this.#page = page; return page;
  }
  async change(row, action) {
    if (this.#client.pending) throw new Error('Resolve the original preference request first.');
    await this.#client.stage(...threadAction(row, action));
    return this.#client.send();
  }
}
export function mountNotificationInbox({ document, href, client = new NotificationClient({ href }) }) {
  const controller = new NotificationInboxController(client);
  const get = id => document.getElementById(id);
  const status = text => { get('inbox-status').textContent = text; };
  const element = (tag, text) => { const node = document.createElement(tag); node.textContent = text; return node; };
  const pending = () => {
    const request = client.pending;
    get('inbox-pending').hidden = !request;
    get('inbox-pending-summary').textContent = request ? 'Issue #' + request.number + ': ' + request.action + '\nExpected preference version ' +
      request.expected_version + '\n' + (request.sent ? 'Possibly sent; retain the original request.' : 'Prepared but not sent.') : '';
    get('inbox-discard').disabled = Boolean(request?.sent || request?.exported);
    for (const button of get('inbox-content').querySelectorAll('button')) button.disabled = Boolean(request || client.busy);
  };
  const run = async operation => {
    try { await operation(); }
    catch (error) { status(error.outcomeUnknown ? 'Outcome unknown: ' + error.message + ' Check the outcome or retry the original request.' : error.message); }
    finally { pending(); }
  };
  const terminal = value => status((value.outcome === 'committed' ? 'Preference saved' : 'Preference refused') + (value.refusal ? ': ' + value.refusal : '') + '.');
  const showTerminal = async value => {
    if (value.outcome === 'committed') {
      try { draw(await controller.load()); }
      catch (error) { status('Preference saved. Inbox refresh failed: ' + error.message); return; }
    }
    terminal(value);
  };
  const draw = page => {
    if (!page) return;
    const content = get('inbox-content'), paging = get('inbox-paging');
    content.replaceChildren(); paging.replaceChildren();
    const rows = page.reply.type === 'notification_page' ? page.reply.threads : page.reply.found ? [page.reply.thread] : [];
    get('inbox-snapshot').textContent = 'Recipient ' + page.binding.principal + ' · snapshot ' + page.head;
    if (!rows.length) content.append(element('p', page.reply.type === 'notification_thread' ? 'Issue not found.' : 'No issues match this inbox view.'));
    for (const row of rows) {
      const article = element('article', '');
      article.append(element('h2', (row.unread ? 'Unread · ' : '') + '#' + row.number + ' ' + row.title));
      article.append(element('p', row.state + ' · ' + row.mode + ' · ' + (row.reasons.length ? row.reasons.join(', ') : 'No automatic participation') + ' · issue version ' + row.issue_version));
      const actions = element('div', ''); actions.className = 'issue-actions';
      for (const [action, label] of [['read', 'Mark read'], ['unread', 'Mark unread'], ['subscribe', 'Subscribe'], ['mute', 'Mute'], ['automatic', 'Automatic participation']]) {
        const button = element('button', label); button.type = 'button';
        button.addEventListener('click', () => run(async () => { await showTerminal(await controller.change(row, action)); }));
        actions.append(button);
      }
      article.append(actions); content.append(article);
    }
    if (page.reply.type === 'notification_page' && page.reply.next_after !== null) {
      const more = element('button', 'Next page'); more.type = 'button';
      more.addEventListener('click', () => run(async () => { draw(await controller.load(undefined, true)); })); paging.append(more);
    }
    status(rows.length + ' issue' + (rows.length === 1 ? '' : 's') + ' shown.'); pending();
  };
  get('inbox-connect').addEventListener('submit', event => { event.preventDefault(); void run(async () => {
    controller.disconnect(); get('inbox-content').replaceChildren(); get('inbox-paging').replaceChildren(); get('inbox-snapshot').textContent = '';
    const token = get('inbox-token').value; get('inbox-token').value = '';
    await client.connect(token); draw(await controller.load({ unreadOnly: get('inbox-unread').checked, includeMuted: get('inbox-muted').checked }));
  }); });
  get('inbox-disconnect').addEventListener('click', () => {
    controller.disconnect(); get('inbox-token').value = ''; get('inbox-content').replaceChildren();
    get('inbox-paging').replaceChildren(); get('inbox-snapshot').textContent = ''; status('Disconnected.'); pending();
  });
  get('inbox-filters').addEventListener('submit', event => { event.preventDefault(); void run(async () => {
    draw(await controller.load({ unreadOnly: get('inbox-unread').checked, includeMuted: get('inbox-muted').checked }));
  }); });
  get('inbox-show').addEventListener('submit', event => { event.preventDefault(); void run(async () => {
    draw(await controller.show(decimal(get('inbox-number').value, 'issue number', 1)));
  }); });
  get('inbox-cancel').addEventListener('click', () => { controller.cancel(); status('Read cancelled.'); });
  get('inbox-retry').addEventListener('click', () => run(async () => showTerminal(await client.send())));
  get('inbox-recover').addEventListener('click', () => run(async () => {
    const outcome = await client.recover();
    if (outcome.terminal) await showTerminal(outcome); else status('No terminal outcome observed. Keep the original request for recovery or retry.');
  }));
  get('inbox-discard').addEventListener('click', () => run(async () => { client.discardUnsent(); status('Unsent preparation discarded.'); }));
  get('inbox-save').addEventListener('click', () => run(async () => {
    const blob = new Blob([client.exportReceipt()], { type: 'application/json' }), url = URL.createObjectURL(blob);
    const link = document.createElement('a'); link.href = url; link.download = 'frankengit-notification-retry.json'; link.click();
    setTimeout(() => URL.revokeObjectURL(url), 0);
  }));
  get('inbox-restore').addEventListener('change', () => run(async () => {
    const file = get('inbox-restore').files?.[0]; get('inbox-restore').value = '';
    if (!file) return;
    if (file.size > MAX_RECEIPT_BYTES) throw new Error('Recovery receipt is too large.');
    await client.restoreReceipt(await file.text()); status('Original request restored; no change sent.');
  }));
  return { client, controller };
}
if (typeof document !== 'undefined') mountNotificationInbox({ document, href: globalThis.location.href });
