// Display every name as inert text and keep the submitted request frozen.
import { DefaultBranchClient, DEFAULT_BRANCH_RECEIPT_LIMIT } from './default-branch.mjs';
const display = value => JSON.stringify(value, null, 2).replace(/[\u007f-\u009f\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069]/g,
  c => '\\u' + c.charCodeAt(0).toString(16).padStart(4, '0'));
function label(encoded) {
  if (encoded === null) return 'No symbolic default target';
  try {
    const bytes = Uint8Array.from(encoded.match(/../g) ?? [], pair => Number.parseInt(pair, 16));
    return display(new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes));
  } catch { return 'Byte-only branch name'; }
}
export async function readDefaultBranchReceipt(file, current = () => true) {
  if (!file || !Number.isSafeInteger(file.size) || file.size < 1 || file.size > DEFAULT_BRANCH_RECEIPT_LIMIT) throw new Error('Choose a recovery receipt of at most 32 KiB.');
  if (!current()) throw new Error('Receipt selection changed.');
  const bytes = await file.arrayBuffer();
  if (!current() || !(bytes instanceof ArrayBuffer) || bytes.byteLength !== file.size) throw new Error('Receipt selection changed while reading.');
  return new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes);
}
export function mountDefaultBranch(doc, options = {}) {
  const client = options.client ?? new DefaultBranchClient({ href: options.href ?? globalThis.location.href });
  const ids = ['token','connect','disconnect','load','more','cancel','snapshot','page-state','refs','selected','selection','prepare',
    'pending','confirm-send','send','recover','discard','save','receipt-file','restore','status','terminal'];
  const el = Object.fromEntries(ids.map(id => {
    const found = doc.getElementById(id); if (!found) throw new Error('Missing default-branch control: ' + id);
    return [id, found];
  }));
  let busy = false, revision = 0;
  const node = (tag, value) => { const n = doc.createElement(tag); if (value !== undefined) n.textContent = value; return n; };
  const status = value => { el.status.textContent = value; };
  function render() {
    const pending = client.pending, observed = client.observed, page = client.page;
    const refs = client.knownRefs, connected = client.connected, previous = el.selected.value;
    el.selected.replaceChildren(); const empty = node('option', 'Choose a listed branch'); empty.value = ''; el.selected.append(empty);
    for (const row of refs) { const item = node('option', label(row.ref_hex) + ' [' + row.ref_hex + ']'); item.value = row.ref_hex; el.selected.append(item); }
    el.selected.value = refs.some(row => row.ref_hex === previous) ? previous : '';
    el.refs.replaceChildren();
    for (const row of page?.refs ?? []) el.refs.append(node('li', label(row.ref_hex) + ' [' + row.ref_hex + '] → ' + row.object_id));
    el.snapshot.textContent = observed ? display({ scope: observed.scope, authenticated_principal: observed.principal,
      snapshot: observed.head, source_head: observed.sourceHead, default: label(observed.referenceHex),
      default_reference_hex: observed.referenceHex, tip: observed.tip,
      state: observed.referenceHex === null ? 'absent symbolic target' : observed.unborn ? 'named unborn target' : 'existing default branch' }) : 'No selected default-branch snapshot.';
    el['page-state'].textContent = page ? page.refs.length + ' branches in this page; ' + refs.length + ' retained. ' +
      (page.next_after === null ? 'End of the visible branch listing at this snapshot.' : 'More branches remain at this snapshot.') : '';
    const chosen = refs.find(row => row.ref_hex === el.selected.value);
    el.selection.textContent = chosen ? label(chosen.ref_hex) + '\nExact reference bytes: ' + chosen.ref_hex + '\nExact tip: ' + chosen.object_id : 'Select an existing branch from the pinned listing.';
    el.pending.textContent = pending && connected ? display({ operation: 'set-default', scope: pending.source.scope,
      authenticated_principal: pending.source.principal, original_snapshot: pending.source.head,
      old_default_reference_hex: pending.source.referenceHex, old_default_state: pending.source.referenceHex === null ? 'absent symbolic target' : pending.source.unborn ? 'named unborn target' : 'existing default branch',
      command: pending.command, direct_refs_changed: false, original_key: pending.key,
      sent: pending.sent, exported: pending.exported, observed_transaction: pending.observedTx }) :
      pending ? 'An outstanding request is retained. Reconnect with the original credential to review, recover or retry it.' : 'No outstanding default-branch request.';
    el.connect.disabled = busy; el.token.disabled = busy;
    el.cancel.disabled = busy && !!pending;
    el.load.disabled = busy || !connected || !!pending;
    el.more.disabled = busy || !connected || !!pending || !page || page.next_after === null;
    el.selected.disabled = busy || !connected || !!pending || !refs.length;
    el.prepare.disabled = busy || !connected || !!pending || !chosen;
    el['confirm-send'].disabled = busy || !connected || !pending;
    el.send.disabled = busy || !connected || !pending;
    el.send.textContent = pending?.sent || pending?.exported ? 'Retry unchanged request' : 'Send exact request';
    el.recover.disabled = busy || !connected || !pending;
    el.discard.disabled = busy || !pending || pending.sent || pending.exported;
    el.save.disabled = busy || !connected || !pending;
    el.restore.disabled = busy || !connected || !!pending;
    el['receipt-file'].disabled = busy || !connected || !!pending;
  }
  async function perform(work) {
    if (busy) return; busy = true; const version = revision; render();
    const current = () => version === revision;
    const report = value => { if (current()) status(value); };
    try { await work(report, current); }
    catch (error) { report((error.outcomeUnknown ? 'Outcome unknown. Keep the original request and recover or retry unchanged. ' : '') + error.message); }
    finally { busy = false; render(); }
  }
  function disconnect() {
    revision += 1; client.disconnect(); el.token.value = ''; el['receipt-file'].value = '';
    el['confirm-send'].checked = false; el.terminal.textContent = '';
    status('Disconnected. Any outstanding request remains recoverable with its original credential.'); render();
  }
  function result(value, report, current) {
    if (!current()) return;
    if (value.terminal) {
      el.terminal.textContent = display(value);
      report('Canonical ' + value.outcome + '; transaction ' + value.tx + (value.refusal ? '; ' + value.refusal : '') +
        '. This records the original decision. Load explicitly to inspect today’s default.');
    } else report('Outcome remains unknown (' + value.state + '). Absence does not prove non-commit. Keep the original key.');
  }
  el.connect.addEventListener('click', () => perform(async report => {
    const token = el.token.value; el.token.value = ''; await client.connect(token); el['confirm-send'].checked = false;
    report('Connected. Load the current default and branches, or restore the original recovery receipt.');
  }));
  el.disconnect.addEventListener('click', disconnect);
  el.cancel.addEventListener('click', () => {
    // A write or outcome lookup owns the original request until it settles.
    // Clearing only its view must not hide a terminal that clears that request.
    if (busy && client.pending) return;
    revision += 1; client.cancel(); el['confirm-send'].checked = false; el.terminal.textContent = '';
    status('Observation cleared. An already submitted change is not cancelled or rolled back.'); render();
  });
  el.load.addEventListener('click', () => perform(async report => {
    el['confirm-send'].checked = false; el.terminal.textContent = '';
    await client.load(); report('Loaded the current default and candidate branches at the same snapshot. No transaction was created.');
  }));
  el.more.addEventListener('click', () => perform(async report => { await client.load({ next: true }); report('Loaded more branches at the original snapshot.'); }));
  el.selected.addEventListener('change', () => { el['confirm-send'].checked = false; render(); });
  el.prepare.addEventListener('click', () => perform(async report => {
    await client.prepare(el.selected.value); el['confirm-send'].checked = false; el.terminal.textContent = '';
    report('Exact default-branch request prepared locally. Review the original default, selected branch and tip, then confirm and send.');
  }));
  el.send.addEventListener('click', () => perform(async (report, current) => {
    if (!el['confirm-send'].checked) throw new Error('Confirm the displayed default-branch expectations before sending.');
    el['confirm-send'].checked = false; result(await client.send(), report, current);
  }));
  el.recover.addEventListener('click', () => perform(async (report, current) => {
    el['confirm-send'].checked = false; result(await client.recover(), report, current);
  }));
  el.discard.addEventListener('click', () => {
    if (busy) return;
    try { client.discardUnsent(); el['confirm-send'].checked = false; status('Unsent local request discarded.'); }
    catch (error) { status(error.message); } render();
  });
  el.save.addEventListener('click', () => {
    if (busy || !client.connected) return;
    try {
      const encoded = client.exportReceipt();
      if (options.saveReceipt) options.saveReceipt(encoded);
      else {
        const url = URL.createObjectURL(new Blob([encoded], { type: 'application/json' }));
        const anchor = node('a'); anchor.href = url; anchor.download = 'frankengit-default-branch-recovery.json';
        try { doc.body.append(anchor); anchor.click(); }
        finally { anchor.remove(); setTimeout(() => URL.revokeObjectURL(url), 1000); }
      }
      status('Recovery receipt offered for download without the token. Keep it private and verify it was saved.');
    } catch (error) { status(error.message); } render();
  });
  el['receipt-file'].addEventListener('change', () => { revision += 1; el['confirm-send'].checked = false; });
  el.restore.addEventListener('click', () => perform(async (report, current) => {
    const file = el['receipt-file'].files[0];
    const encoded = await readDefaultBranchReceipt(file, () => current() && file === el['receipt-file'].files[0] && client.connected);
    await client.restoreReceipt(encoded); el['receipt-file'].value = ''; el['confirm-send'].checked = false;
    report('Original request restored without sending. Look up its outcome or explicitly confirm an unchanged retry.');
  }));
  const events = options.events ?? globalThis;
  events.addEventListener?.('beforeunload', event => { if (client.pending) { event.preventDefault(); event.returnValue = ''; } });
  events.addEventListener?.('pagehide', disconnect);
  render(); return { client, disconnect, render };
}
if (typeof document !== 'undefined') mountDefaultBranch(document);
