// No repository text is HTML. This view submits only the client's frozen
// native command; editor controls cannot substitute a later tip during retry.
import { BranchClient, expectedUpdates, RECEIPT_LIMIT, TRANSACTION_LIMIT } from './branches.mjs';
import { decimal } from './pulls-core.mjs';
const display = (value, space) => JSON.stringify(value, null, space).replace(/[\u202a-\u202e\u2066-\u2069]/g, c => `\\u${c.charCodeAt(0).toString(16).padStart(4, '0')}`);
const choiceValue = row => row.ref ?? `hex:${row.ref_hex}`;
const branchRows = client => client.knownRefs.filter(row => row.ref_hex.startsWith('726566732f68656164732f'));
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
    'operation','selected','destination','target','selection','prepare','batch-add','batch-state','batch-changes','batch-clear','batch-prepare',
    'pending','confirm-send','send','recover','discard','save','receipt-file','restore','status'];
  const el = Object.fromEntries(ids.map(id => { const node = doc.getElementById(id); if (!node) throw new Error(`Missing branch control: ${id}`); return [id, node]; }));
  let busy = false, revision = 0;
  const node = (tag, value) => { const n = doc.createElement(tag); if (value !== undefined) n.textContent = value; return n; };
  const status = message => { el.status.textContent = message; };
  function choices(control, rows) {
    const selected = control.value; control.replaceChildren();
    const empty = node('option', 'Choose a listed branch'); empty.value = ''; control.append(empty);
    for (const row of rows) { const item = node('option', row.ref === null ? `Byte-only name [${row.ref_hex}]` : display(row.ref)); item.value = choiceValue(row); control.append(item); }
    control.value = rows.some(row => choiceValue(row) === selected) ? selected : '';
  }
  function render() {
    const p = client.pending, page = client.page, connected = client.connected;
    const refs = client.knownRefs, branches = branchRows(client), staged = client.stagedChanges;
    choices(el.selected, branches); choices(el.target, branches);
    el.refs.replaceChildren();
    for (const row of page?.refs ?? []) {
      const li = node('li'); li.append(node('code', `${row.ref === null ? 'Byte-only name' : display(row.ref)} [${row.ref_hex}] → ${row.object_id}`));
      el.refs.append(li);
    }
    el.snapshot.textContent = page ? `Snapshot ${page.snapshot_token}\nSource head ${page.source_head}\nRepository incarnation ${page.repository_incarnation}` : 'No selected reference snapshot.';
    el['page-state'].textContent = page ? `${page.refs.length} refs in this page; ${refs.length} retained in this bounded session. ${page.next_after === null ? 'End of this namespace listing at this snapshot.' : 'More references remain at this snapshot.'}` : '';
    const chosen = branches.find(row => choiceValue(row) === el.selected.value), target = branches.find(row => choiceValue(row) === el.target.value);
    el.selection.textContent = chosen ? `Selected ${chosen.ref === null ? 'byte-only name' : display(chosen.ref)} [${chosen.ref_hex}]\nExact tip ${chosen.object_id}${target ? `\nNew tip source ${target.ref === null ? `[${target.ref_hex}]` : display(target.ref)} → ${target.object_id}` : ''}` : 'Select an existing branch from the pinned listing.';
    el['batch-state'].textContent = staged.length ? `${staged.length} of ${TRANSACTION_LIMIT} changes staged at snapshot ${page.snapshot_token}. Each old and new tip is fixed. Prepare the batch to review one atomic request.` : 'No staged changes. Add creates, updates or deletions from this snapshot.';
    el['batch-changes'].replaceChildren();
    for (const [index, change] of staged.entries()) {
      const li = node('li'), effect = expectedUpdates('transaction', { changes: [change] })[0];
      li.append(node('pre', display({ operation: change.operation, ...effect }, 2)));
      const remove = node('button', `Remove change ${index + 1}`); remove.type = 'button'; remove.disabled = busy || !connected || !!p;
      remove.addEventListener('click', () => editBatch(() => client.removeStaged(index), 'Staged change removed. The remaining exact tips are unchanged.'));
      li.append(remove); el['batch-changes'].append(li);
    }
    el.pending.textContent = p ? display({ operation: p.operation, scope: p.scope,
      updates: expectedUpdates(p.operation, p.fields), original_key: p.key, sent: p.sent, exported: p.exported,
      observed_transaction: p.observedTx, observed_principal: p.observedPrincipal }, 2) : 'No outstanding branch request.';
    for (const id of ['format','namespace','page-size','operation','selected','destination','target']) el[id].disabled = busy || !connected || !!p;
    el.connect.disabled = busy; el.load.disabled = busy || !connected || !!p;
    el.more.disabled = busy || !connected || !!p || !page || page.next_after === null;
    el.prepare.disabled = busy || !connected || !!p || !chosen || chosen.ref === null || !!staged.length || (el.operation.value === 'update' && (!target || target.ref === null));
    el['batch-add'].disabled = busy || !connected || !!p || !chosen || el.operation.value === 'rename' || staged.length >= TRANSACTION_LIMIT || (el.operation.value === 'update' && !target);
    el['batch-clear'].disabled = busy || !connected || !!p || !staged.length;
    el['batch-prepare'].disabled = busy || !connected || !!p || !staged.length;
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
  function editBatch(work, message) {
    if (busy) return;
    try { work(); el['confirm-send'].checked = false; status(message); }
    catch (error) { status(error.message); }
    render();
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
  el.cancel.addEventListener('click', () => { revision += 1; client.cancel(); el['confirm-send'].checked = false; status('Snapshot and unprepared batch cleared. An already submitted mutation is not cancelled or rolled back.'); render(); });
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
    el['confirm-send'].checked = false; report('Exact request prepared locally. Review every effect, then confirm and send.');
  }));
  el['batch-add'].addEventListener('click', () => editBatch(() => {
    const action = el.operation.value, rows = branchRows(client);
    const selected = rows.find(row => choiceValue(row) === el.selected.value), target = rows.find(row => choiceValue(row) === el.target.value);
    client.stage(action, { ref: el.destination.value, refHex: selected?.ref_hex, sourceRefHex: (action === 'create' ? selected : target)?.ref_hex });
  }, 'Exact branch change staged locally. Add more changes or prepare the atomic batch.'));
  el['batch-clear'].addEventListener('click', () => editBatch(() => client.clearStaged(), 'Unprepared batch cleared. No request was sent.'));
  el['batch-prepare'].addEventListener('click', () => perform(async report => {
    await client.prepareTransaction(); el['confirm-send'].checked = false;
    report('Atomic batch prepared locally. Review all expected old tips, new tips and deletions, then confirm one send.');
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
        const link = node('a'); link.href = url; link.download = 'frankengit-branch-recovery.json';
        doc.body.append(link); link.click(); link.remove();
        setTimeout(() => URL.revokeObjectURL(url), 30_000);
      }
      status('Recovery receipt offered for download without the token; verify it was saved. It contains repository metadata; keep it secure.');
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
