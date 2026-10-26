// Native portable transfer UI. File contents, advertised refs and API text are
// data, never markup, host paths or authority. Sending is always explicit.
import { TransferClient } from './transfers.mjs';
import { BUNDLE_LIMIT, MAPPING_LIMIT, bundleRef, normalizeBundleExpectation } from './transfers-protocol.mjs';
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
  const size = file.size;
  const buffer = await file.arrayBuffer();
  if (!current()) throw new Error('File selection changed while reading.');
  if (!(buffer instanceof ArrayBuffer) || buffer.byteLength !== size || buffer.byteLength > maximum) throw new Error('File size changed or exceeded the byte limit.');
  return new Uint8Array(buffer);
}
// Explicit caller pins are never inferred from bundle headers, manifests or
// destination leases. Parse all controls before starting a local file read.
export function intakeExpectations(algorithm, sha256, pins, encoding, exact) {
  text(sha256, 64, 'trusted bundle SHA-256'); text(pins, 64 * 1024, 'trusted reference pins');
  if (!['text', 'hex'].includes(encoding) || typeof exact !== 'boolean') throw new Error('Choose explicit pin encoding and ref-set semantics.');
  const lines = pins.split(/\r?\n/).map(line => line.trim()).filter(Boolean);
  if (lines.length > MAPPING_LIMIT) throw new Error(`At most ${MAPPING_LIMIT} trusted reference pins are supported.`);
  if (!sha256 && !lines.length && !exact) return null;
  const expected = { object_format: algorithm, ...(sha256 ? { sha256 } : {}) };
  if (lines.length) expected.refs = lines.map(line => {
    const split = line.lastIndexOf('=');
    if (split < 1 || split === line.length - 1) throw new Error('Each pin must be a full reference name followed by = and its native object ID.');
    const name = line.slice(0, split), object_id = line.slice(split + 1);
    return { ref_hex: encoding === 'hex' ? name : hex(utf8.encode(name)), object_id };
  });
  if (exact) expected.exact_refs = true;
  normalizeBundleExpectation(expected); return expected;
}
export function mountTransfers(doc, options = {}) {
  const client = options.client ?? new TransferClient({ href: options.href ?? globalThis.location.href });
  const ids = ['transfer-token','transfer-connect','transfer-disconnect','transfer-recovery-only','transfer-original-principal','transfer-connection-mode',
    'transfer-format','select-target','transfer-selection','transfer-status','cancel-transfer-read',
    'export-bundle','export-info','download-bundle','bundle-file','bundle-sha256','bundle-pins','bundle-pin-encoding','bundle-exact-refs','load-bundle','bundle-info','bundle-refs','mapping-rows','stage-import','stage-fetch',
    'pending-transfer','confirm-transfer','send-transfer','recover-transfer','discard-transfer','save-transfer','receipt-file','restore-transfer'];
  const c = Object.fromEntries(ids.map(id => { const node = doc.getElementById(id); if (!node) throw new Error(`Missing transfer control ${id}`); return [id, node]; }));
  let generation = 0, session = 0, busy = false, mappings = [], summary = null, exportSummary = null;
  const urls = new Set();
  const node = (tag, value) => { const n = doc.createElement(tag); if (value !== undefined) n.textContent = visible(value); return n; };
  const status = value => { c['transfer-status'].textContent = visible(value); };
  function releaseDownloads() { for (const url of urls) URL.revokeObjectURL(url); urls.clear(); }
  function clearBundle() { summary = null; mappings = []; c['bundle-info'].replaceChildren(); c['bundle-refs'].replaceChildren(); c['mapping-rows'].replaceChildren(); }
  function clearPins() {
    c['bundle-sha256'].value = ''; c['bundle-pins'].value = '';
    c['bundle-exact-refs'].checked = false; c['bundle-pin-encoding'].value = 'text';
  }
  function clearViews() {
    clearBundle(); exportSummary = null; c['export-info'].replaceChildren(); c['transfer-selection'].replaceChildren();
    c['bundle-file'].value = ''; c['receipt-file'].value = ''; c['confirm-transfer'].checked = false; releaseDownloads();
  }
  function render() {
    const p = client.pending, connected = client.connected, recovering = client.recoveryOnly, ordinary = connected && !recovering, selected = client.selection;
    c['transfer-connect'].disabled = busy; c['transfer-recovery-only'].disabled = busy;
    c['transfer-original-principal'].disabled = busy || !c['transfer-recovery-only'].checked;
    c['transfer-original-principal'].required = c['transfer-recovery-only'].checked;
    c['transfer-connection-mode'].textContent = !connected ? 'Disconnected. No credential is active.' : recovering
      ? `RECOVERY ONLY: check the original outcome for principal ${client.recoveryPrincipal}. The server must authenticate that identity. Reconnect explicitly for ordinary work.`
      : 'Ordinary connection. Changing the recovery selection takes effect only when Connect is pressed.';
    c['transfer-format'].disabled = busy || !ordinary || !!p;
    c['select-target'].disabled = busy || !ordinary || !!p;
    for (const id of ['export-bundle','bundle-file','bundle-sha256','bundle-pins','bundle-pin-encoding','bundle-exact-refs','load-bundle']) c[id].disabled = busy || !ordinary || !!p || !selected;
    c['download-bundle'].disabled = busy || !ordinary || !exportSummary || !client.exported || client.exportVerification?.object_closure_verified !== true;
    c['stage-import'].disabled = busy || !ordinary || !!p || !summary || client.bundleVerification?.object_closure_verified !== true || summary.refs.length > MAPPING_LIMIT;
    c['stage-fetch'].disabled = busy || !ordinary || !!p || !summary || client.bundleVerification?.object_closure_verified !== true || !mappings.length;
    c['send-transfer'].disabled = busy || !ordinary || !p;
    c['recover-transfer'].disabled = busy || !connected || !p;
    c['confirm-transfer'].disabled = busy || !ordinary || !p;
    c['discard-transfer'].disabled = busy || recovering || !p || p.sent || p.exported;
    c['save-transfer'].disabled = busy || !p;
    c['restore-transfer'].disabled = busy || !connected || !!p;
    c['receipt-file'].disabled = busy || !connected || !!p;
    c['pending-transfer'].textContent = p ? (connected ? visible(JSON.stringify(p, null, 2)) : 'An unresolved request is retained privately. Reconnect the original credential or choose recovery-only access for its original principal. Save its recovery receipt before leaving.') : 'No outstanding publication.';
    c['send-transfer'].textContent = p?.sent ? 'Retry identical transfer' : 'Send prepared transfer';
    for (const row of mappings) for (const control of [row.destination, row.encoding, row.old, row.remove]) control.disabled = busy || !ordinary || !!p;
  }
  function requireOrdinary() {
    if (client.recoveryOnly) throw new Error('Recovery-only connection cannot read, export bundles, prepare, discard or resend transfers. Keep the original receipt and check its outcome.');
  }
  async function perform(work, settlement = false, kind = 'ordinary') {
    if (client.recoveryOnly && !['connect', 'recover', 'restore'].includes(kind)) {
      status('Recovery-only connection permits only original outcome lookup and receipt retention. Reconnect explicitly for ordinary work.'); render(); return;
    }
    if (busy) return; busy = true; const started = generation, originalSession = session; render();
    const current = () => originalSession === session && (settlement || started === generation);
    try { await work(current); }
    catch (error) { if (current()) status(`${error.outcomeUnknown ? 'Outcome unknown. Retain the original request and recover it. ' : ''}${error.message}`); }
    finally {
      busy = false;
      if (!client.connected) { clearViews(); clearPins(); }
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
    if (busy || client.pending || !summary || !client.connected || client.recoveryOnly) return;
    try {
      if (mappings.length === MAPPING_LIMIT) throw new Error(`At most ${MAPPING_LIMIT} mappings are supported.`);
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
      remove.addEventListener('click', () => { if (busy || client.pending || client.recoveryOnly) return; mappings = mappings.filter(r => r !== entry); row.remove(); c['confirm-transfer'].checked = false; render(); });
      c['confirm-transfer'].checked = false; render(); status('Mapping added without a destination or old-tip assumption. Complete both explicitly.');
    } catch (error) { status(error.message); }
  }
  function showBundle(value) {
    if (client.bundleVerification?.object_closure_verified !== true) throw new Error('No complete verified bundle is selected.');
    clearBundle(); summary = value;
    const { refs, ...meta } = value;
    c['bundle-info'].append(node('pre', JSON.stringify({ ...meta, verification: client.bundleVerification }, null, 2)), node('p', 'Packed bytes and complete reachable Git history were verified locally. Caller pins, when supplied, were matched; their trust comes from your independent source. Native admission still verifies objects, permissions and leases. Signatures, provenance, submodule repositories and forge state are not verified. Advertised HEAD is not installed.'));
    const table = node('table'), header = node('tr'); for (const title of ['Advertised reference','Native target','Mapped fetch']) header.append(node('th', title)); table.append(header);
    for (const r of refs) {
      const row = node('tr'), action = node('td'), button = node('button', 'Map this reference'); button.type = 'button';
      button.addEventListener('click', () => addMapping(r.ref_hex)); action.append(button);
      row.append(node('td', referenceLabel(r.ref_hex)), node('td', r.object_id), action); table.append(row);
    }
    c['bundle-refs'].append(table); render();
  }
  function disconnect() {
    generation++; session++; client.disconnect(); c['transfer-token'].value = ''; clearViews(); clearPins(); render();
    status(client.pending ? 'Disconnected. Original unresolved request remains in memory; save its receipt before leaving.' : 'Disconnected. Credentials, bundle bytes and visible data cleared.');
  }
  c['transfer-connect'].addEventListener('click', () => {
    const token = c['transfer-token'].value; c['transfer-token'].value = '';
    const connection = c['transfer-recovery-only'].checked
      ? { recoveryOnly: true, originalPrincipal: c['transfer-original-principal'].value } : {};
    return perform(async current => {
      clearViews(); clearPins(); await client.connect(token, connection); if (!current()) return;
      status(client.recoveryOnly
        ? 'Connected locally for recovery only. Restore the original receipt or check the retained request. The server must authenticate the independently selected original principal; no transfer was sent.'
        : client.pending ? 'Original credential connected. Recover or retry the retained request.' : 'Connected. Select the target repository snapshot before loading or exporting a bundle.');
    }, false, 'connect');
  });
  c['transfer-recovery-only'].addEventListener('change', render);
  c['transfer-disconnect'].addEventListener('click', disconnect);
  c['cancel-transfer-read'].addEventListener('click', () => {
    generation++; client.cancel(); clearViews(); render(); status(client.recoveryOnly
      ? 'Read cancelled. The original request is unchanged and recovery-only mode remains active.'
      : 'Read cancelled. An outstanding publication, if any, is unchanged. Select a snapshot again for new work.');
  });
  c['transfer-format'].addEventListener('input', () => { generation++; client.cancel(); clearViews(); render(); status('Select the chosen hash domain explicitly.'); });
  c['select-target'].addEventListener('click', () => perform(async current => {
    clearViews(); const selected = await client.select(c['transfer-format'].value); if (!current()) return;
    c['transfer-selection'].append(node('pre', JSON.stringify(selected, null, 2))); status('Target identity and authority snapshot selected. No publication attempted.');
  }));
  c['export-bundle'].addEventListener('click', () => perform(async current => {
    exportSummary = null; c['export-info'].replaceChildren(); releaseDownloads(); render();
    const result = await client.exportBundle({ verifyClosure: true }); if (!current()) return;
    exportSummary = result; const { refs, ...meta } = result;
    c['export-info'].append(node('pre', JSON.stringify({ ...meta, direct_ref_count: refs.length, verification: client.exportVerification }, null, 2)));
    status('Complete snapshot-pinned export and reachable Git history verified. Download is ready; no forge state or default HEAD is transferred. Use the export-verification page for a complete reference-inventory audit.');
  }));
  c['download-bundle'].addEventListener('click', () => {
    try { requireOrdinary(); if (busy || !exportSummary || client.exportVerification?.object_closure_verified !== true) throw new Error('No stable verified export is ready.'); download(client.exportBytes(), 'repository.bundle', 'application/x-git-bundle'); status('Bundle offered for download. Verify the saved file before discarding your other copy.'); }
    catch (error) { status(error.message); }
  });
  c['bundle-file'].addEventListener('change', () => { generation++; client.invalidateBundle(); clearBundle(); c['confirm-transfer'].checked = false; render(); status('File selection changed. Load and inspect these bytes explicitly.'); });
  for (const id of ['bundle-sha256', 'bundle-pins', 'bundle-pin-encoding', 'bundle-exact-refs']) {
    const invalidate = () => {
      generation++; client.invalidateBundle(); clearBundle(); c['confirm-transfer'].checked = false; render();
      status('Trusted pins changed. Verify the selected bytes again; any prepared publication remains unchanged.');
    };
    c[id].addEventListener('input', invalidate); c[id].addEventListener('change', invalidate);
  }
  c['load-bundle'].addEventListener('click', () => perform(async current => {
    const file = c['bundle-file'].files?.[0]; client.invalidateBundle(); clearBundle();
    if (c['bundle-file'].files?.length !== 1) throw new Error('Choose exactly one bundle.');
    const expectations = intakeExpectations(client.selection?.scope.format, c['bundle-sha256'].value,
      c['bundle-pins'].value, c['bundle-pin-encoding'].value, c['bundle-exact-refs'].checked);
    const bytes = await selectedBytes(file, BUNDLE_LIMIT, () => current() && client.connected && c['bundle-file'].files?.[0] === file);
    if (!current()) return;
    const result = await client.load(bytes, { verifyClosure: true, expectations }); if (!current()) return;
    showBundle(result); status('Complete bundle verified locally against any supplied pins. Select import or explicit mapped fetch; no bytes have been uploaded and no publication is authorized.');
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
      await client.stage(operation, input, { requireVerified: true }); if (!current()) return;
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
    c['confirm-transfer'].checked = false;
    const result = await client.recover(); if (!current()) return;
    if (result.terminal) { clearViews(); status(`Recovered canonical ${result.outcome}: ${result.tx}.` + (client.recoveryOnly ? ' Recovery-only mode remains active. Reconnect explicitly before ordinary work.' : '')); }
    else status(`Still unresolved: ${result.state}. Absence is not proof of non-commit. Keep the original request.` + (client.recoveryOnly ? ' This credential cannot resend it.' : ''));
  }, true, 'recover'));
  c['discard-transfer'].addEventListener('click', () => { try { requireOrdinary(); client.discardUnsent(); c['confirm-transfer'].checked = false; render(); status('Unsent and unexported request discarded.'); } catch (error) { status(error.message); } });
  c['save-transfer'].addEventListener('click', () => {
    try { if (busy || client.busy) throw new Error('Finish the current operation before saving its stable receipt.'); const receipt = client.exportReceipt(); download(receipt, 'frankengit-transfer-retry.json', 'application/json'); status(client.recoveryOnly
      ? 'Original recovery receipt offered for download with its unchanged key, bundle and credential fingerprint. It contains neither token. Keep it private; this connection remains outcome-only.'
      : 'Receipt offered for download. It contains private bundle bytes and mappings, not the token. Verify it was saved.'); render(); }
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
    if (!current()) return; clearViews(); status(client.recoveryOnly
      ? 'Original transfer restored for outcome lookup only. Its key, fingerprint, bundle and mappings are unchanged. No publication was dispatched; this credential cannot resend it.'
      : 'Original transfer restored as possibly sent. No publication was dispatched. Recover or explicitly confirm an identical retry.');
  }, false, 'restore'));
  const events = options.events ?? globalThis;
  events.addEventListener?.('pagehide', disconnect);
  events.addEventListener?.('beforeunload', event => { if (client.pending || summary) { event.preventDefault(); event.returnValue = ''; } });
  render(); return { client, disconnect };
}
if (typeof document !== 'undefined') mountTransfers(document);
