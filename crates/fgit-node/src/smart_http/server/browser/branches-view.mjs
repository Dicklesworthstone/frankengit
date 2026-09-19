// No repository text is HTML. This view submits only the client's frozen
// native command; editor controls cannot substitute a later tip during retry.
import { BranchClient, expectedUpdates, RECEIPT_LIMIT } from './branches.mjs';
import { decimal } from './pulls-core.mjs';
const display = value => JSON.stringify(value).replace(/[\u202a-\u202e\u2066-\u2069]/g, c => `\\u${c.charCodeAt(0).toString(16).padStart(4, '0')}`);
export async function readReceipt(file, current = () => true) {
  if (!file || !Number.isSafeInteger(file.size) || file.size < 1 || file.size > RECEIPT_LIMIT) throw new Error('Choose a recovery receipt of at most 64 KiB.');
  if (!current()) throw new Error('Receipt selection changed.');
  const bytes = await file.arrayBuffer();
  if (!current() || !(bytes instanceof ArrayBuffer) || bytes.byteLength !== file.size) throw new Error('Receipt selection changed while reading.');
  return new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes);
}
export function mountBranches(doc, options = {}) {
  const client = options.client ?? new BranchClient({ href: options.href ?? globalThis.location.href });
  const ids = ['token','connect','disconnect','format','namespace','page-size','load','more','cancel','snapshot','page-state','refs',
    'operation','selected','destination','target','selection','prepare','pending','confirm-send','send','recover','discard','save','receipt-file','restore','status'];
  const el = Object.fromEntries(ids.map(id => { const node = doc.getElementById(id); if (!node) throw new Error(`Missing branch control: ${id}`); return [id, node]; }));
  let busy = false, revision = 0;
  const node = (tag, value) => { const n = doc.createElement(tag); if (value !== undefined) n.textContent = value; return n; };
  const status = message => { el.status.textContent = message; };
  function choices(control, rows) {
    const selected = control.value; control.replaceChildren();
    const empty = node('option', 'Choose a listed branch'); empty.value = ''; control.append(empty);
    for (const row of rows) { const item = node('option', display(row.ref)); item.value = row.ref; control.append(item); }
    control.value = rows.some(row => row.ref === selected) ? selected : '';
  }
  function render() {
    const p = client.pending, page = client.page, connected = client.connected;
    const refs = client.knownRefs, branches = refs.filter(row => row.ref?.startsWith('refs/heads/'));
    choices(el.selected, branches); choices(el.target, branches);
    el.refs.replaceChildren();
    for (const row of page?.refs ?? []) {
      const li = node('li'); li.append(node('code', `${row.ref === null ? 'Byte-only name' : display(row.ref)} [${row.ref_hex}] → ${row.object_id}`));
      el.refs.append(li);
    }
    el.snapshot.textContent = page ? `Snapshot ${page.snapshot_token}\nSource head ${page.source_head}\nRepository incarnation ${page.repository_incarnation}` : 'No selected reference snapshot.';
    el['page-state'].textContent = page ? `${page.refs.length} refs in this page; ${refs.length} retained in this bounded session. ${page.next_after === null ? 'End of this namespace listing at this snapshot.' : 'More references remain at this snapshot.'}` : '';
    const chosen = branches.find(row => row.ref === el.selected.value), target = branches.find(row => row.ref === el.target.value);
    el.selection.textContent = chosen ? `Selected ${display(chosen.ref)} [${chosen.ref_hex}]\nExact tip ${chosen.object_id}${target ? `\nNew tip source ${display(target.ref)} → ${target.object_id}` : ''}` : 'Select an existing branch from the pinned listing.';
    el.pending.textContent = p ? JSON.stringify({ operation: p.operation, scope: p.scope,
      updates: expectedUpdates(p.operation, p.fields), original_key: p.key, sent: p.sent, exported: p.exported,
      observed_transaction: p.observedTx, observed_principal: p.observedPrincipal }, null, 2) : 'No outstanding branch request.';
    for (const id of ['format','namespace','page-size','operation','selected','destination','target']) el[id].disabled = busy || !connected || !!p;
    el.connect.disabled = busy; el.load.disabled = busy || !connected || !!p;
    el.more.disabled = busy || !connected || !!p || !page || page.next_after === null;
    el.prepare.disabled = busy || !connected || !!p || !chosen;
    el.send.disabled = busy || !connected || !p; el.send.textContent = p?.sent ? 'Retry unchanged request' : 'Send exact request';
    el.recover.disabled = busy || !connected || !p;
    el.discard.disabled = busy || !p || p.sent || p.exported; el.save.disabled = busy || !p;
    el.restore.disabled = busy || !connected || !!p; el['receipt-file'].disabled = busy || !connected || !!p;
  }
  async function perform(work) {
    if (busy) return; busy = true; const version = revision; render();
    const report = value => { if (version === revision) status(value); };
    try { await work(report, () => version === revision); }
    catch (error) { report(`${error.outcomeUnknown ? 'Outcome unknown. Keep this original request and recover or retry unchanged. ' : ''}${error.message}`); }
    finally { busy = false; render(); }
  }
  function disconnect() {
    revision += 1; client.disconnect(); el.token.value = ''; el.destination.value = ''; el['receipt-file'].value = '';
    el['confirm-send'].checked = false; status('Disconnected. Any outstanding request remains recoverable with its original credential.'); render();
  }
  function confirmedResult(result, report) {
    report(result.terminal ? `Canonical ${result.outcome}; transaction ${result.tx}${result.refusal ? `; ${result.refusal}` : ''}. Load a fresh snapshot explicitly before another change.` :
      `Outcome remains unknown (${result.state}). Keep the original key; absence does not prove non-commit.`);
  }
  el.connect.addEventListener('click', () => perform(async report => {
    const token = el.token.value; el.token.value = ''; await client.connect(token); el['confirm-send'].checked = false;
    report('Connected. Load references or restore the original recovery receipt.');
  }));
  el.disconnect.addEventListener('click', disconnect);
  el.cancel.addEventListener('click', () => { revision += 1; client.cancel(); el['confirm-send'].checked = false; status('Snapshot cleared. An already submitted mutation is not cancelled or rolled back.'); render(); });
  el.load.addEventListener('click', () => perform(async report => {
    el['confirm-send'].checked = false;
    await client.list({ objectFormat: el.format.value, namespace: el.namespace.value, limit: decimal(el['page-size'].value, 'page size', 1) });
    report('Loaded a pinned reference page; no publication occurred.');
  }));
  el.more.addEventListener('click', () => perform(async report => { await client.list({ next: true }); report('Loaded the next page at the same snapshot.'); }));
  for (const id of ['operation','selected','destination','target']) el[id].addEventListener('change', () => { el['confirm-send'].checked = false; render(); });
  el.destination.addEventListener('input', () => { el['confirm-send'].checked = false; });
  el['receipt-file'].addEventListener('change', () => { revision += 1; el['confirm-send'].checked = false; });
  el.prepare.addEventListener('click', () => perform(async report => {
    const action = el.operation.value;
    await client.prepare(action, { ref: action === 'create' ? el.destination.value : el.selected.value,
      sourceRef: action === 'create' ? el.selected.value : el.target.value, newRef: el.destination.value });
    el['confirm-send'].checked = false; report('Exact request prepared locally. Review both effects of a rename, then confirm and send.');
  }));
  el.send.addEventListener('click', () => perform(async report => {
    if (!el['confirm-send'].checked) throw new Error('Confirm the displayed exact ref changes before sending.');
    el['confirm-send'].checked = false; confirmedResult(await client.send(), report);
  }));
  el.recover.addEventListener('click', () => perform(async report => { el['confirm-send'].checked = false; confirmedResult(await client.recover(), report); }));
  el.discard.addEventListener('click', () => { if (busy) return; try { client.discardUnsent(); el['confirm-send'].checked = false; status('Unsent local request discarded.'); } catch (error) { status(error.message); } render(); });
  el.save.addEventListener('click', () => {
    if (busy) return;
    try {
      const receipt = client.exportReceipt();
      if (options.saveReceipt) options.saveReceipt(receipt);
      else {
        const url = URL.createObjectURL(new Blob([receipt], { type: 'application/json' }));
        const link = node('a'); link.href = url; link.download = 'frankengit-branch-recovery.json'; link.click();
        setTimeout(() => URL.revokeObjectURL(url), 1000);
      }
      status('Recovery receipt exported without the token. It contains repository metadata; keep it secure.');
    } catch (error) { status(error.message); } render();
  });
  el.restore.addEventListener('click', () => perform(async (report, current) => {
    const file = el['receipt-file'].files[0];
    const encoded = await readReceipt(file, () => current() && file === el['receipt-file'].files[0] && client.connected);
    await client.restoreReceipt(encoded); el['confirm-send'].checked = false; el['receipt-file'].value = '';
    report('Original request restored without sending. Recover its outcome or explicitly confirm an unchanged retry.');
  }));
  const events = options.events ?? globalThis;
  events.addEventListener?.('beforeunload', event => { if (client.pending) { event.preventDefault(); event.returnValue = ''; } });
  events.addEventListener?.('pagehide', disconnect);
  render(); return { client, disconnect, render };
}
if (typeof document !== 'undefined') mountBranches(document);
