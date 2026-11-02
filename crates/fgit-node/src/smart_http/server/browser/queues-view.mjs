// Queue collaboration over the native client. Forms never grant authority;
// only explicit sends publish, and uncertain requests retain their identity.
import { QueueClient, RECEIPT_LIMIT } from './queues.mjs';
import { decimal, integer, hex, unhex, utf8, oid } from './pulls-core.mjs';

export function displayText(value) {
  return String(value).replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069]/gu,
    character => `\\u{${character.codePointAt(0).toString(16)}}`);
}
function refText(row, field) {
  return row[field] === null ? `Native reference bytes: ${row[`${field}_hex`]}` : displayText(row[field]);
}
const IDS = ['connection', 'token', 'recovery-only', 'original-principal', 'connect', 'disconnect', 'connection-mode', 'status', 'snapshot',
  'list-form', 'page-limit', 'refresh', 'cancel-read', 'queue-list', 'paging', 'show-form', 'show-number', 'show-load', 'selected',
  'queue-change', 'queue-number', 'queue-version', 'target-kind', 'target-ref', 'queue-action', 'pr-fields', 'pull-number', 'load-pull',
  'pull-observation', 'pull-version', 'source-kind', 'source-ref', 'source-tip', 'target-tip', 'priority-field', 'priority',
  'dequeue-fields', 'dequeue-number', 'dequeue-reason', 'reorder-fields', 'queue-order', 'landing-fields', 'policy-epoch', 'prepare',
  'pending-section', 'pending', 'receipt-download', 'confirm', 'send', 'recover', 'discard', 'receipt-import', 'receipt-import-file', 'receipt-import-submit'];
const DRAFTS = ['queue-number', 'queue-version', 'target-ref', 'pull-number', 'pull-version', 'source-ref', 'source-tip', 'target-tip',
  'dequeue-number', 'dequeue-reason', 'queue-order', 'policy-epoch', 'show-number'];

function downloader(doc) {
  const window = doc.defaultView, urls = new Set();
  window.addEventListener('pagehide', () => { for (const url of urls) window.URL.revokeObjectURL(url); urls.clear(); });
  return (name, contents) => {
    const url = window.URL.createObjectURL(new Blob([contents], { type: 'application/json' })); urls.add(url);
    const link = doc.createElement('a'); link.href = url; link.download = name;
    doc.body.append(link); link.click(); link.remove();
    window.setTimeout(() => { window.URL.revokeObjectURL(url); urls.delete(url); }, 30_000);
  };
}
async function fileText(input) {
  const files = input.files, file = files?.[0]; input.value = '';
  if (files?.length !== 1 || !file || file.size > RECEIPT_LIMIT) throw new Error('Choose one recovery receipt no larger than 256 KiB.');
  const bytes = new Uint8Array(await file.arrayBuffer());
  if (bytes.length > RECEIPT_LIMIT || bytes.length !== file.size) throw new Error('Recovery receipt size changed while reading.');
  return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
}

export function mountQueues(doc, { href = doc.defaultView.location.href, fetchImpl = globalThis.fetch,
  cryptoImpl = globalThis.crypto, downloadImpl = null } = {}) {
  const nodes = Object.fromEntries(IDS.map(id => {
    const node = doc.getElementById(id); if (!node) throw new Error(`Missing queue UI element: ${id}`); return [id, node];
  }));
  const client = new QueueClient({ href, fetchImpl, cryptoImpl }), download = downloadImpl ?? downloader(doc);
  nodes['queue-action'].value ||= 'enqueue'; nodes['target-kind'].value ||= 'text'; nodes['source-kind'].value ||= 'text';
  nodes['page-limit'].value ||= '20'; nodes.priority.value ||= '0';
  let generation = 0, operation = null, selected = null, page = null;
  const dynamic = new Set();
  const text = (tag, value = '') => { const node = doc.createElement(tag); node.textContent = displayText(value); return node; };
  const status = message => { nodes.status.textContent = displayText(message); };
  const number = (id, minimum = 0) => decimal(nodes[id].value, id, minimum);
  const reference = side => ({ [nodes[`${side}-kind`].value === 'hex' ? `${side}_ref_hex` : `${side}_ref`]: nodes[`${side}-ref`].value });
  const refHex = side => nodes[`${side}-kind`].value === 'hex'
    ? hex(unhex(nodes[`${side}-ref`].value, 1024)) : hex(utf8.encode(nodes[`${side}-ref`].value));
  function fillRef(side, row) {
    nodes[`${side}-kind`].value = row[`${side}_ref`] === null ? 'hex' : 'text';
    nodes[`${side}-ref`].value = row[`${side}_ref`] ?? row[`${side}_ref_hex`];
  }
  function fillQueue(queue) {
    nodes['queue-number'].value = String(queue.number); nodes['queue-version'].value = String(queue.version); fillRef('target', queue);
  }
  function button(parent, label, handler) {
    const node = text('button', label); node.type = 'button';
    node.addEventListener('click', event => { event.preventDefault(); void handler(); });
    parent.append(node); dynamic.add(node); return node;
  }
  function controls() {
    const busy = operation !== null || client.busy, ordinary = client.connected && !client.recoveryOnly;
    const pending = client.pending, action = nodes['queue-action'].value;
    nodes['recovery-only'].disabled = busy;
    nodes['original-principal'].disabled = busy || !nodes['recovery-only'].checked;
    nodes['original-principal'].required = nodes['recovery-only'].checked;
    nodes['connection-mode'].textContent = !client.connected ? 'Disconnected. No credential is active.' : client.recoveryOnly
      ? 'RECOVERY ONLY: only original-request outcome lookup and receipt custody are available. Reconnect explicitly for ordinary work.'
      : 'Ordinary connection. Changing the recovery checkbox takes effect only when Connect is submitted.';
    for (const id of ['refresh', 'page-limit', 'show-load', 'show-number', 'queue-action']) nodes[id].disabled = !ordinary || busy;
    nodes['cancel-read'].disabled = operation !== 'read';
    for (const node of dynamic) node.disabled = !ordinary || busy;
    nodes['pr-fields'].hidden = !['enqueue', 'land'].includes(action);
    nodes['pr-fields'].disabled = nodes['pr-fields'].hidden || !ordinary || busy;
    nodes['dequeue-fields'].hidden = action !== 'dequeue'; nodes['dequeue-fields'].disabled = action !== 'dequeue' || !ordinary || busy;
    nodes['reorder-fields'].hidden = action !== 'reorder'; nodes['reorder-fields'].disabled = action !== 'reorder' || !ordinary || busy;
    nodes['landing-fields'].hidden = action !== 'land'; nodes['landing-fields'].disabled = action !== 'land' || !ordinary || busy;
    nodes['priority-field'].hidden = action !== 'enqueue'; nodes.priority.disabled = action !== 'enqueue';
    nodes['load-pull'].disabled = !ordinary || busy;
    nodes.prepare.disabled = !ordinary || busy || Boolean(pending) || !client.binding;
    nodes['pending-section'].hidden = !pending;
    nodes.pending.textContent = pending ? [
      `Queue #${pending.number} · ${pending.action} · ${pending.state}`,
      `Idempotency-Key: ${pending.key}`,
      pending.observedTx ? `Observed transaction: ${pending.observedTx}` : 'No transaction outcome established.',
      client.connected ? JSON.stringify(pending.fields, null, 2) : 'Reconnect to inspect this private prepared request.',
    ].map(displayText).join('\n') : '';
    nodes['receipt-download'].disabled = !pending || busy;
    nodes.confirm.disabled = !ordinary || !pending || busy;
    nodes.send.disabled = !ordinary || !pending || busy || !nodes.confirm.checked;
    nodes.send.textContent = pending?.state === 'staged' ? 'Send prepared request' : 'Retry identical request';
    nodes.recover.disabled = !client.connected || !pending || busy;
    nodes.discard.disabled = !ordinary || !pending || busy || pending.sent || pending.exported || pending.state !== 'staged';
    nodes['receipt-import-file'].disabled = !client.connected || Boolean(pending) || busy;
    nodes['receipt-import-submit'].disabled = !client.connected || Boolean(pending) || busy;
  }
  function clearViews() {
    selected = null; page = null; dynamic.clear();
    for (const id of ['queue-list', 'paging', 'selected', 'snapshot', 'pull-observation']) nodes[id].replaceChildren();
  }
  function disconnect() {
    generation += 1; operation = null; client.disconnect(); clearViews();
    for (const id of DRAFTS) nodes[id].value = '';
    nodes.token.value = ''; nodes['receipt-import-file'].value = ''; nodes.confirm.checked = false;
    status('Disconnected. Any unresolved prepared request is retained for recovery.'); controls();
  }
  async function run(kind, work) {
    if (operation !== null && !(kind === 'read' && operation === 'read')) { status('Finish the current operation first.'); return; }
    if (kind === 'read') client.cancelReads();
    const current = ++generation; operation = kind; controls();
    const guard = () => { if (current !== generation) throw new Error('Operation superseded.'); };
    try { await work(guard); }
    catch (error) {
      if (current === generation) {
        if (!client.connected) { clearViews(); for (const id of DRAFTS) nodes[id].value = ''; }
        status(error.outcomeUnknown ? `Outcome remains unknown: ${error.message} The original request is retained. Look up its outcome or explicitly retry identical bytes.` : error.message);
      }
    } finally { if (current === generation) { operation = null; controls(); } }
  }
  function drawBinding(result) {
    nodes.snapshot.textContent = displayText(`Repository ${result.binding.repository} · ${result.binding.format}\nIncarnation ${result.binding.incarnation}\nSnapshot ${result.head}`);
  }
  function drawList(result) {
    page = result; nodes['queue-list'].replaceChildren(); nodes.paging.replaceChildren(); drawBinding(result);
    if (!result.reply.queues.length) nodes['queue-list'].append(text('p', 'No queues on this snapshot page.'));
    for (const queue of result.reply.queues) {
      const article = text('article');
      button(article, `Queue #${queue.number} · ${refText(queue, 'target_ref')}`, () => show(queue.number, result.head));
      article.append(text('p', `Version ${queue.version} · ${queue.entries.length} entries · head ${queue.order.length ? `PR #${queue.order[0]}` : '(empty)'}`));
      nodes['queue-list'].append(article);
    }
    if (result.reply.next_after !== null) button(nodes.paging, 'Next queue page', () => loadList({
      after: result.reply.next_after, limit: result.reply.limit, head: result.head,
    }));
    status('Queue page loaded. Continuations retain this exact snapshot.');
  }
  function loadList(options = null) {
    return run('read', async guard => {
      clearViews(); status('Reading queues…');
      const result = await client.list(options ?? { limit: number('page-limit', 1) }); guard(); drawList(result);
    });
  }
  function drawQueue(result) {
    const queue = result.reply.queue;
    selected = { number: result.reply.number, version: result.reply.version, row: queue, head: result.head };
    nodes.selected.replaceChildren(); drawBinding(result);
    nodes['show-number'].value = String(result.reply.number); nodes['queue-number'].value = String(result.reply.number);
    nodes['queue-version'].value = String(result.reply.version); nodes['pull-observation'].replaceChildren();
    nodes['policy-epoch'].value = '';
    if (!queue) {
      nodes['target-ref'].value = ''; nodes['queue-order'].value = '';
      nodes.selected.append(text('p', `Queue #${result.reply.number} was not found at this snapshot. Enqueue with version 0 to propose its creation.`));
      return;
    }
    fillRef('target', queue); nodes['queue-order'].value = queue.order.join('\n');
    nodes.selected.append(text('h2', `Queue #${queue.number} · ${refText(queue, 'target_ref')}`),
      text('p', `Version ${queue.version} · ${queue.entries.length} entries · ${queue.active_batch === null ? 'No active batch' : `Active batch ${queue.active_batch}`}`),
      text('pre', `Target reference bytes: ${queue.target_ref_hex}\nRecorded order: ${queue.order.join(', ') || '(empty)'}`));
    if (!queue.order.length) nodes.selected.append(text('p', 'The queue is empty.'));
    const entries = new Map(queue.entries.map(entry => [entry.pull_request, entry]));
    for (const [index, pull] of queue.order.entries()) {
      const entry = entries.get(pull), article = text('article');
      article.append(text('h3', `${index + 1}. PR #${pull}${index === 0 ? ' · queue head' : ''}`),
        text('pre', `Source: ${refText(entry, 'source_ref')}\nSource bytes: ${entry.source_ref_hex}\nRecorded head: ${entry.head_tip}\nPriority ${entry.priority} · enqueued at queue version ${entry.enqueued_version}\nEnqueued by ${entry.enqueued_by}`));
      button(article, `Prepare removal of PR #${pull}`, () => {
        fillQueue(queue);
        nodes['queue-action'].value = 'dequeue'; nodes['dequeue-number'].value = String(pull); nodes['dequeue-reason'].value = ''; controls();
        status('Choose an explicit removal reason, then prepare the request. Nothing sent.');
      });
      if (index === 0) button(article, `Prepare fast-forward landing of PR #${pull}`, () => {
        fillQueue(queue);
        nodes['queue-action'].value = 'land'; configureAction();
      });
      nodes.selected.append(article);
    }
    if (nodes['queue-action'].value === 'land') configureAction();
  }
  function show(queue, head = null) {
    return run('read', async guard => {
      clearViews();
      status('Reading one queue snapshot…'); const result = await client.show(queue, head); guard(); drawQueue(result);
      status('Queue loaded. Its recorded head and order do not establish merge permission.');
    });
  }
  function requireSelection() {
    if (!selected?.row || number('queue-number', 1) !== selected.number || number('queue-version', 1) !== selected.version ||
        refHex('target') !== selected.row.target_ref_hex) throw new Error('Load the exact queue and retain its number, version, and target before reordering or landing.');
    return selected;
  }
  function configureAction() {
    nodes['pull-observation'].replaceChildren();
    if (nodes['queue-action'].value === 'land' && selected?.row) {
      const entry = selected.row.entries.find(entry => entry.pull_request === selected.row.order[0]);
      nodes['pull-number'].value = entry ? String(entry.pull_request) : '';
      nodes['pull-version'].value = ''; nodes['target-tip'].value = ''; nodes['policy-epoch'].value = '';
      if (entry) { fillRef('source', entry); nodes['source-tip'].value = entry.head_tip; }
      status(entry ? 'Exact queue head selected. Load or enter its PR version and target tip, then enter the expected policy epoch.' : 'This queue has no head to land.');
    }
    controls();
  }
  async function loadPull() {
    return run('read', async guard => {
      const action = nodes['queue-action'].value;
      if (!['enqueue', 'land'].includes(action)) throw new Error('PR coordinates apply only to enqueue or landing.');
      const selection = action === 'land' ? requireSelection() : selected && number('queue-number', 1) === selected.number && number('queue-version') === selected.version ? selected : null;
      const pull = number('pull-number', 1);
      if (action === 'land' && selection.row.order[0] !== pull) throw new Error('Only the selected queue head can be landed.');
      const selectionInput = () => JSON.stringify(['queue-action', 'queue-number', 'queue-version', 'target-kind', 'target-ref', 'pull-number'].map(id => nodes[id].value));
      const originalInput = selectionInput();
      const result = await client.pull(pull, selection?.head ?? null); guard();
      if (selectionInput() !== originalInput) throw new Error('Queue or PR selection changed during the read. Load its coordinates again explicitly.');
      const row = result.reply.pull_request;
      if (!row || row.state !== 'open' || !row.data) throw new Error('An open PR with recorded coordinates is required.');
      if (selection?.row && row.data.target_ref_hex !== selection.row.target_ref_hex) throw new Error('The PR targets a different branch than this queue.');
      if (action === 'land') {
        const entry = selection.row.entries.find(entry => entry.pull_request === pull);
        if (entry.source_ref_hex !== row.data.source_ref_hex || oid(entry.head_tip, result.binding.format) !== oid(row.data.source_tip, result.binding.format)) {
          throw new Error('The PR coordinates differ from the queued head. Reload and explicitly update queue membership.');
        }
      }
      nodes['pull-version'].value = String(row.version); fillRef('source', row.data); fillRef('target', row.data);
      nodes['source-tip'].value = row.data.source_tip; nodes['target-tip'].value = row.data.target_tip;
      nodes['pull-observation'].textContent = displayText(`PR #${row.number} · version ${row.version} · ${row.data.title}\nRecorded at snapshot ${result.head}. Later edits to these form fields are manual input.`);
      status('Exact PR coordinates loaded. No queue change or landing was prepared or sent.');
    });
  }
  function stageFields(action) {
    const fields = { expected_version: number('queue-version', action === 'enqueue' ? 0 : 1), ...reference('target') };
    if (action === 'enqueue' || action === 'land') {
      Object.assign(fields, { pull_request: number('pull-number', 1), expected_pull_request_version: number('pull-version', 1),
        ...reference('source'), expected_source_tip: nodes['source-tip'].value, expected_target_tip: nodes['target-tip'].value });
      if (action === 'enqueue') fields.priority = integer(number('priority'), 'priority', 0, 0xffffffff);
      else {
        const selection = requireSelection(), entry = selection.row.entries.find(entry => entry.pull_request === selection.row.order[0]);
        if (!entry || fields.pull_request !== entry.pull_request || refHex('source') !== entry.source_ref_hex ||
            oid(fields.expected_source_tip, client.binding.format) !== oid(entry.head_tip, client.binding.format)) throw new Error('Landing must retain the selected queue head, source reference, and source commit.');
        fields.expected_policy_epoch = number('policy-epoch', 1);
      }
    } else if (action === 'dequeue') {
      fields.pull_request = number('dequeue-number', 1); fields.reason = nodes['dequeue-reason'].value;
      if (!fields.reason) throw new Error('Choose an explicit dequeue reason.');
    } else if (action === 'reorder') {
      const selection = requireSelection();
      fields.entry = nodes['queue-order'].value === '' ? [] : nodes['queue-order'].value.split('\n').map(value => decimal(value, 'queue order PR', 1));
      if (fields.entry.length !== selection.row.order.length || new Set(fields.entry).size !== fields.entry.length ||
          fields.entry.some(number => !selection.row.order.includes(number))) throw new Error('The order must include every selected queue member exactly once.');
    } else throw new Error('Choose a supported queue action.');
    return fields;
  }
  function terminal(result, action) {
    if (!result.terminal) { status(`Outcome remains unknown (${result.state}). Keep the exact original request for recovery or an identical retry.`); return; }
    clearViews(); nodes['queue-version'].value = ''; nodes.confirm.checked = false;
    status(`Canonical ${result.outcome} · ${action} · transaction ${result.tx}${result.refusal ? ` · ${result.refusal}` : ''}. ` +
      (result.outcome === 'committed' && action === 'land' ? 'The original queue-head landing committed its target update and PR merge together. '
        : action === 'land' ? 'This landing was refused. ' : 'Queue management does not land a PR. ') +
      'Reload to observe current state. Delivery acknowledgement is not implied.');
  }
  function on(id, event, handler) {
    nodes[id].addEventListener(event, event => { event.preventDefault(); void handler(); });
  }
  on('connection', 'submit', async () => {
    const token = nodes.token.value, recoveryOnly = nodes['recovery-only'].checked, originalPrincipal = nodes['original-principal'].value;
    disconnect();
    await run('connect', async guard => {
      await client.connect(token, recoveryOnly ? { recoveryOnly, originalPrincipal } : {}); guard();
      if (client.recoveryOnly) { status('Recovery-only connection established. Restore the original receipt and look up its outcome; no ordinary reads or sends are available.'); return; }
      const result = await client.list({ limit: number('page-limit', 1) }); guard(); drawList(result);
    });
  });
  on('disconnect', 'click', disconnect);
  nodes['recovery-only'].addEventListener('change', controls);
  on('list-form', 'submit', () => loadList());
  on('show-form', 'submit', () => run('read', async guard => {
    clearViews();
    const result = await client.show(number('show-number', 1)); guard(); drawQueue(result); status('Queue loaded at the displayed snapshot.');
  }));
  on('cancel-read', 'click', () => {
    if (operation !== 'read') return;
    generation += 1; operation = null; client.cancelReads(); status('Read cancelled. Prepared request custody is unchanged.'); controls();
  });
  on('queue-action', 'change', configureAction);
  on('load-pull', 'click', loadPull);
  on('queue-change', 'submit', () => run('stage', async guard => {
    const action = nodes['queue-action'].value, fields = stageFields(action);
    await client.stage(number('queue-number', 1), action, fields); guard(); nodes.confirm.checked = false;
    status(action === 'land' ? 'Exact queue-head landing prepared. Save and review the receipt, then send explicitly. No branch has moved.'
      : 'Exact queue change prepared locally. Save and review the receipt, then send explicitly. Nothing sent.');
  }));
  nodes.confirm.addEventListener('change', controls);
  on('send', 'click', () => run('send', async guard => {
    if (!nodes.confirm.checked) throw new Error('Explicitly confirm the exact prepared request before sending.');
    nodes.confirm.checked = false; const action = client.pending?.action;
    const result = await client.send(); guard(); terminal(result, action);
  }));
  on('recover', 'click', () => run('recover', async guard => {
    const action = client.pending?.action, result = await client.recover(); guard(); terminal(result, action);
  }));
  on('discard', 'click', () => run('discard', async () => {
    client.discardUnsent(); nodes.confirm.checked = false; status('Never-exported, never-dispatched preparation discarded.');
  }));
  on('receipt-download', 'click', () => run('export', async () => {
    download('frankengit-queue-recovery.json', client.exportReceipt());
    status('Private recovery receipt saved without a token. Preserve its original request and key until the canonical outcome is known.');
  }));
  on('receipt-import', 'submit', () => run('import', async guard => {
    const serialized = await fileText(nodes['receipt-import-file']); guard();
    await client.restoreReceipt(serialized); guard(); nodes.confirm.checked = false;
    status(client.recoveryOnly ? 'Original queue request restored, not sent. This recovery-only connection permits outcome lookup; reconnect with the original credential before an identical retry.'
      : 'Original queue request restored, not sent. Look up its canonical outcome or explicitly retry with the original credential.');
  }));
  doc.defaultView.addEventListener('pagehide', disconnect);
  doc.defaultView.addEventListener('beforeunload', event => {
    if (client.pending) { event.preventDefault(); event.returnValue = ''; }
  });
  controls();
  return { client, disconnect, show, loadList, get selected() { return selected && structuredClone(selected); }, get page() { return page && structuredClone(page); } };
}
if (typeof document !== 'undefined') mountQueues(document);
