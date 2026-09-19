// Native portable transfer UI. File contents, advertised refs and API text are
// data, never markup, host paths or authority. Sending is always explicit.
import { TransferClient } from './transfers.mjs';
import { BUNDLE_LIMIT, MAPPING_LIMIT, bundleRef } from './transfers-protocol.mjs';
import { RECEIPT_LIMIT } from './pulls-actions.mjs';
import { hex, unhex, utf8, text } from './pulls-core.mjs';

export function visible(value) {
  return String(value).replace(/[\u0000-\u0008\u000b-\u001f\u007f-\u009f\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069]/gu,
    c => `\\u{${c.codePointAt(0).toString(16)}}`);
}
export function referenceLabel(value) {
  const bytes = unhex(value, 4096);
  try { return `${visible(new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes))} [${value}]`; }
  catch { return `Byte-valued reference [${value}]`; }
}
export async function selectedBytes(file, maximum, current) {
  if (!file || !Number.isSafeInteger(file.size) || file.size < 1 || file.size > maximum) throw new Error('Choose a nonempty file within this operation’s byte limit.');
  if (!current()) throw new Error('File selection changed.');
  const buffer = await file.arrayBuffer();
  if (!current()) throw new Error('File selection changed while reading.');
  if (!(buffer instanceof ArrayBuffer) || buffer.byteLength !== file.size || buffer.byteLength > maximum) throw new Error('File size changed or exceeded the byte limit.');
  return new Uint8Array(buffer);
}
export function mountTransfers(doc, options = {}) {
  const client = options.client ?? new TransferClient({ href: options.href ?? globalThis.location.href });
  const ids = ['transfer-token','transfer-connect','transfer-disconnect','transfer-format','select-target','transfer-selection','transfer-status','cancel-transfer-read',
    'export-bundle','export-info','download-bundle','bundle-file','load-bundle','bundle-info','bundle-refs','mapping-rows','stage-import','stage-fetch',
    'pending-transfer','confirm-transfer','send-transfer','recover-transfer','discard-transfer','save-transfer','receipt-file','restore-transfer'];
  const c = Object.fromEntries(ids.map(id => { const node = doc.getElementById(id); if (!node) throw new Error(`Missing transfer control ${id}`); return [id, node]; }));
  let generation = 0, session = 0, busy = false, mappings = [], summary = null, exportSummary = null;
  const urls = new Set();
  const node = (tag, value) => { const n = doc.createElement(tag); if (value !== undefined) n.textContent = visible(value); return n; };
  const status = value => { c['transfer-status'].textContent = visible(value); };
  function releaseDownloads() { for (const url of urls) URL.revokeObjectURL(url); urls.clear(); }
  function clearBundle() { summary = null; mappings = []; c['bundle-info'].replaceChildren(); c['bundle-refs'].replaceChildren(); c['mapping-rows'].replaceChildren(); }
  function clearViews() {
    clearBundle(); exportSummary = null; c['export-info'].replaceChildren(); c['transfer-selection'].replaceChildren();
    c['bundle-file'].value = ''; c['receipt-file'].value = ''; c['confirm-transfer'].checked = false; releaseDownloads();
  }
  function render() {
    const p = client.pending, connected = client.connected, selected = client.selection;
    c['transfer-connect'].disabled = busy; c['transfer-format'].disabled = busy || !connected || !!p;
    c['select-target'].disabled = busy || !connected || !!p;
    for (const id of ['export-bundle','bundle-file','load-bundle']) c[id].disabled = busy || !connected || !!p || !selected;
    c['download-bundle'].disabled = busy || !connected || !exportSummary || !client.exported;
    c['stage-import'].disabled = busy || !connected || !!p || !summary || summary.refs.length > MAPPING_LIMIT;
    c['stage-fetch'].disabled = busy || !connected || !!p || !summary || !mappings.length;
    for (const id of ['send-transfer','recover-transfer']) c[id].disabled = busy || !connected || !p;
    c['confirm-transfer'].disabled = busy || !connected || !p;
    c['discard-transfer'].disabled = busy || !p || p.sent || p.exported;
    c['save-transfer'].disabled = busy || !p;
    c['restore-transfer'].disabled = busy || !connected || !!p;
    c['receipt-file'].disabled = busy || !connected || !!p;
    c['pending-transfer'].textContent = p ? (connected ? visible(JSON.stringify(p, null, 2)) : 'An unresolved request is retained privately. Reconnect the original credential to inspect its effects, or save its recovery receipt before leaving.') : 'No outstanding publication.';
    c['send-transfer'].textContent = p?.sent ? 'Retry identical transfer' : 'Send prepared transfer';
    for (const row of mappings) for (const control of [row.destination, row.encoding, row.old, row.remove]) control.disabled = busy || !!p;
  }
  async function perform(work, settlement = false) {
    if (busy) return; busy = true; const started = generation, originalSession = session; render();
    const current = () => originalSession === session && (settlement || started === generation);
    try { await work(current); }
    catch (error) { if (current()) status(`${error.outcomeUnknown ? 'Outcome unknown. Retain the original request and recover it. ' : ''}${error.message}`); }
    finally {
      busy = false;
      if (!client.connected) clearViews();
      render();
    }
  }
  function download(value, filename, media) {
    if (options.download) { options.download(value, filename, media); return; }
    const url = URL.createObjectURL(new Blob([value], { type: media })); urls.add(url);
    const link = node('a'); link.href = url; link.download = filename; doc.body.append(link); link.click(); link.remove();
    setTimeout(() => { if (urls.delete(url)) URL.revokeObjectURL(url); }, 30_000);
  }
  function addMapping(source) {
    if (busy || client.pending || !summary || !client.connected) return;
    try {
      if (mappings.length === MAPPING_LIMIT) throw new Error('At most 64 mappings are supported.');
      if (!summary.refs.some(r => r.ref_hex === source)) throw new Error('Source is no longer in this bundle.');
      const row = node('fieldset'), title = node('legend', `Map ${referenceLabel(source)}`); row.append(title);
      const destination = node('input'); destination.maxLength = 8192; destination.autocomplete = 'off'; destination.spellcheck = false;
      const encoding = node('select');
      for (const [value, caption] of [['text','UTF-8 destination ref'],['hex','Raw hexadecimal destination ref']]) { const opt = node('option', caption); opt.value = value; encoding.append(opt); }
      encoding.value = 'text';
      const old = node('input'); old.maxLength = 72; old.autocomplete = 'off'; old.spellcheck = false;
      old.placeholder = 'Type absent or the exact old native OID';
      const remove = node('button', 'Remove mapping'); remove.type = 'button';
      const entry = { source, destination, encoding, old, remove, row };
      for (const [caption, control] of [['Destination encoding', encoding],['Destination full ref',destination],['Expected old tip (required)',old]]) {
        const label = node('label', caption); label.append(control); row.append(label);
        control.addEventListener('input', () => { c['confirm-transfer'].checked = false; });
      }
      row.append(remove); c['mapping-rows'].append(row); mappings.push(entry);
      remove.addEventListener('click', () => { if (busy || client.pending) return; mappings = mappings.filter(r => r !== entry); row.remove(); c['confirm-transfer'].checked = false; render(); });
      c['confirm-transfer'].checked = false; render(); status('Mapping added without a destination or old-tip assumption. Complete both explicitly.');
    } catch (error) { status(error.message); }
  }
  function showBundle(value) {
    clearBundle(); summary = value;
    const { refs, ...meta } = value;
    c['bundle-info'].append(node('pre', JSON.stringify(meta, null, 2)), node('p', 'Transport checks passed. Objects and closure are NOT verified by this browser; native admission will validate them. Advertised HEAD is not installed.'));
    const table = node('table'), header = node('tr'); for (const title of ['Advertised reference','Native target','Mapped fetch']) header.append(node('th', title)); table.append(header);
    for (const r of refs) {
      const row = node('tr'), action = node('td'), button = node('button', 'Map this reference'); button.type = 'button';
      button.addEventListener('click', () => addMapping(r.ref_hex)); action.append(button);
      row.append(node('td', referenceLabel(r.ref_hex)), node('td', r.object_id), action); table.append(row);
    }
    c['bundle-refs'].append(table); render();
  }
  function disconnect() {
    generation++; session++; client.disconnect(); c['transfer-token'].value = ''; clearViews(); render();
    status(client.pending ? 'Disconnected. Original unresolved request remains in memory; save its receipt before leaving.' : 'Disconnected. Credentials, bundle bytes and visible data cleared.');
  }
  c['transfer-connect'].addEventListener('click', () => perform(async current => {
    const token = c['transfer-token'].value; c['transfer-token'].value = ''; clearViews();
    await client.connect(token); if (!current()) return;
    status(client.pending ? 'Original credential connected. Recover or retry the retained request.' : 'Connected. Select the target repository snapshot before loading or exporting a bundle.');
  }));
  c['transfer-disconnect'].addEventListener('click', disconnect);
  c['cancel-transfer-read'].addEventListener('click', () => {
    generation++; client.cancel(); clearViews(); render(); status('Read cancelled. An outstanding publication, if any, is unchanged. Select a snapshot again for new work.');
  });
  c['transfer-format'].addEventListener('input', () => { generation++; client.cancel(); clearViews(); render(); status('Select the chosen hash domain explicitly.'); });
  c['select-target'].addEventListener('click', () => perform(async current => {
    clearViews(); const selected = await client.select(c['transfer-format'].value); if (!current()) return;
    c['transfer-selection'].append(node('pre', JSON.stringify(selected, null, 2))); status('Target identity and authority snapshot selected. No publication attempted.');
  }));
  c['export-bundle'].addEventListener('click', () => perform(async current => {
    exportSummary = null; c['export-info'].replaceChildren(); releaseDownloads(); render();
    const result = await client.exportBundle(); if (!current()) return;
    exportSummary = result; const { refs, ...meta } = result;
    c['export-info'].append(node('pre', JSON.stringify({ ...meta, direct_ref_count: refs.length }, null, 2)));
    status('Complete snapshot-pinned export received and transport-checked. Download is now available; no forge state or default HEAD is transferred.');
  }));
  c['download-bundle'].addEventListener('click', () => {
    try { if (busy || !exportSummary) throw new Error('No stable export is ready.'); download(client.exportBytes(), 'repository.bundle', 'application/x-git-bundle'); status('Bundle offered for download. Verify the saved file before discarding your other copy.'); }
    catch (error) { status(error.message); }
  });
  c['bundle-file'].addEventListener('change', () => { generation++; client.invalidateBundle(); clearBundle(); c['confirm-transfer'].checked = false; render(); status('File selection changed. Load and inspect these bytes explicitly.'); });
  c['load-bundle'].addEventListener('click', () => perform(async current => {
    const file = c['bundle-file'].files?.[0]; client.invalidateBundle(); clearBundle();
    const bytes = await selectedBytes(file, BUNDLE_LIMIT, () => current() && client.connected && c['bundle-file'].files?.[0] === file);
    const result = await client.load(bytes); if (!current()) return;
    showBundle(result); status('Bundle envelope and pack checksum checked. Select an import or explicit mapped fetch; nothing has been sent.');
  }));
  async function stage(operation) {
    return perform(async current => {
      const input = operation === 'import' ? [] : mappings.map(row => {
        const value = row.destination.value;
        if (!['text','hex'].includes(row.encoding.value)) throw new Error('Choose a destination encoding.');
        const destination = row.encoding.value === 'hex' ? value : hex(utf8.encode(text(value, 4096, 'destination')));
        bundleRef(destination); if (!row.old.value) throw new Error('Each destination requires absent or its exact old OID.');
        return { source_hex: row.source, destination_hex: destination, expected_old: row.old.value === 'absent' ? null : row.old.value };
      });
      await client.stage(operation, input); if (!current()) return;
      c['confirm-transfer'].checked = false; status('Exact atomic request prepared locally. Save its receipt, inspect every effect, then confirm and Send separately.');
    });
  }
  c['stage-import'].addEventListener('click', () => stage('import'));
  c['stage-fetch'].addEventListener('click', () => stage('fetch'));
  c['send-transfer'].addEventListener('click', () => perform(async current => {
    if (!c['confirm-transfer'].checked) throw new Error('Confirm the exact displayed request before every send or retry.');
    c['confirm-transfer'].checked = false;
    const result = await client.send(); if (!current()) return; clearViews();
    status(`Canonical ${result.outcome}: ${result.tx}. Delivery acknowledgement is not implied. Select a fresh snapshot explicitly for further work.`);
  }, true));
  c['recover-transfer'].addEventListener('click', () => perform(async current => {
    const result = await client.recover(); if (!current()) return;
    if (result.terminal) { clearViews(); status(`Recovered canonical ${result.outcome}: ${result.tx}.`); }
    else status(`Still unresolved: ${result.state}. Absence is not proof of non-commit. Keep the original request.`);
  }, true));
  c['discard-transfer'].addEventListener('click', () => { try { client.discardUnsent(); c['confirm-transfer'].checked = false; render(); status('Unsent and unexported request discarded.'); } catch (error) { status(error.message); } });
  c['save-transfer'].addEventListener('click', () => {
    try { const receipt = client.exportReceipt(); download(receipt, 'frankengit-transfer-retry.json', 'application/json'); status('Receipt offered for download. It contains private bundle bytes and mappings, not the token. Verify it was saved.'); render(); }
    catch (error) { render(); status(error.message); }
  });
  c['receipt-file'].addEventListener('change', () => {
    generation++; client.cancel(); clearBundle(); exportSummary = null;
    c['export-info'].replaceChildren(); c['transfer-selection'].replaceChildren(); releaseDownloads();
    c['confirm-transfer'].checked = false; render();
  });
  c['restore-transfer'].addEventListener('click', () => perform(async current => {
    const file = c['receipt-file'].files?.[0];
    const bytes = await selectedBytes(file, RECEIPT_LIMIT, () => current() && client.connected && c['receipt-file'].files?.[0] === file);
    await client.restoreReceipt(new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes));
    if (!current()) return; clearViews(); status('Original transfer restored as possibly sent. No publication was dispatched. Recover or explicitly confirm an identical retry.');
  }));
  const events = options.events ?? globalThis;
  events.addEventListener?.('pagehide', disconnect);
  events.addEventListener?.('beforeunload', event => { if (client.pending || summary) { event.preventDefault(); event.returnValue = ''; } });
  render(); return { client, disconnect };
}
if (typeof document !== 'undefined') mountTransfers(document);
