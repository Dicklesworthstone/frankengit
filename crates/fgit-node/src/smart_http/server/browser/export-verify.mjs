// Read-only controls over the existing transfer client. No uploaded file or
// saved provenance URL is sent to a server. Checksums are not object admission.
import { TransferClient } from './transfers.mjs';
import { BUNDLE_LIMIT, EXPORT_MANIFEST_LIMIT, verifyExportManifest } from './transfers-protocol.mjs';
import { rootFor, unhex, utf8 } from './pulls-core.mjs';

export function transferPage(href) {
  const page = new URL(href);
  if (!page.pathname.endsWith('/ui/transfers/verify/') || page.search || page.hash || page.username || page.password) {
    throw new Error('Open the exact repository /ui/transfers/verify/ endpoint.');
  }
  const parent = new URL('../', page);
  rootFor(parent.href, '/ui/transfers/');
  return parent.href;
}
export function displayRef(value) {
  const bytes = unhex(value, 4096);
  try {
    return new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes)
      .replace(/[\u0000-\u001f\u007f-\u009f\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069]/gu,
        char => `\\u${char.codePointAt(0).toString(16).padStart(4, '0')}`);
  } catch { return `[raw bytes: ${value}]`; }
}
function oneFile(input, maximum, name) {
  const [file] = input.files ?? [];
  if (input.files?.length !== 1 || !file || !Number.isSafeInteger(file.size) || file.size < 1 || file.size > maximum) {
    throw new Error(`Choose one nonempty ${name} within its byte limit.`);
  }
  return { file, size: file.size };
}
async function fileBytes({ file, size }, check) {
  check(); const data = await file.arrayBuffer(); check();
  if (!(data instanceof ArrayBuffer) || data.byteLength !== size) throw new Error('Selected file length changed during the read.');
  return new Uint8Array(data);
}
export function mountExportVerifier(doc, { client, cryptoImpl = globalThis.crypto, events = globalThis, save = null,
  urlApi = globalThis.URL, schedule = globalThis.setTimeout, unschedule = globalThis.clearTimeout } = {}) {
  const el = id => doc.getElementById(id);
  let serial = 0, offlineSerial = 0, working = false, checking = false, offline = null;
  const downloads = new Map();
  function revoke(url) { const timer = downloads.get(url); if (timer !== undefined) unschedule(timer); downloads.delete(url); urlApi.revokeObjectURL(url); }
  function clearDownloads() { for (const url of [...downloads.keys()]) revoke(url); }
  function download(bytes, filename, media) {
    if (save) return save(bytes, filename, media);
    const url = urlApi.createObjectURL(new Blob([bytes], { type: media })), link = doc.createElement('a');
    const timer = schedule(() => revoke(url), 1000); downloads.set(url, timer);
    try { link.href = url; link.download = filename; doc.body.append(link); link.click(); }
    catch (error) { revoke(url); throw error; }
    finally { link.remove(); }
  }
  function status(message) { el('export-status').textContent = message; }
  function clearOffline(clearFiles = false) {
    offlineSerial++; offline = null; el('offline-report').replaceChildren();
    el('offline-status').textContent = 'No verified local result retained.';
    if (clearFiles) { el('verify-bundle').value = ''; el('verify-manifest').value = ''; }
  }
  function clearViews(disconnect) {
    serial++; client.cancel(); clearOffline(true); clearDownloads();
    if (disconnect) { client.disconnect(); el('export-token').value = ''; }
    render();
  }
  function refs(container, rows) {
    const list = doc.createElement('ul');
    for (const row of rows) {
      const item = doc.createElement('li');
      item.textContent = `${displayRef(row.ref_hex)} — ${row.object_id} — name hex: ${row.ref_hex}`; list.append(item);
    }
    container.append(list);
  }
  function render() {
    el('export-connect').disabled = working || client.busy;
    el('export-token').disabled = working || client.busy;
    el('export-format').disabled = working || client.busy;
    el('export-build').disabled = working || client.busy || !client.connected;
    el('export-save-bundle').disabled = working || client.busy || client.exported?.snapshot_refs_checked !== true;
    el('export-save-manifest').disabled = el('export-save-bundle').disabled;
    el('verify-files').disabled = checking;
    const target = el('export-report'); target.replaceChildren();
    const exported = client.exported;
    if (exported?.snapshot_refs_checked) {
      const summary = doc.createElement('pre');
      summary.textContent = JSON.stringify({ scope: exported.scope, snapshot: exported.snapshot, source_head: exported.source_head,
        bytes: exported.bytes, sha256: exported.sha256, references: exported.refs.length,
        pack_checksum_verified: exported.pack_checksum_verified, objects_verified: false }, null, 2);
      target.append(summary); refs(target, exported.refs);
    }
  }
  async function runNetwork(work) {
    if (working || client.busy) return;
    working = true; const current = ++serial; clearDownloads(); render();
    try { await work(current); }
    catch (error) { if (current === serial) status(error.message); }
    finally { working = false; render(); }
  }
  const networkCheck = current => { if (current !== serial) throw new Error('Export cancelled or replaced.'); };
  el('export-connect').addEventListener('click', () => runNetwork(async current => {
    const token = el('export-token').value; el('export-token').value = ''; client.disconnect();
    await client.connect(token); networkCheck(current); status('Connected. Build an export to select and audit a complete snapshot.');
  }));
  el('export-build').addEventListener('click', () => runNetwork(async current => {
    const algorithm = el('export-format').value;
    // Both actions are reads; only the initial explicit click selects a fresh
    // snapshot. Every inventory continuation and the export pin that selection.
    status('Reading the complete reference snapshot and verifying the bundle.');
    await client.select(algorithm); networkCheck(current);
    await client.exportBundle({ verifyInventory: true }); networkCheck(current);
    status('Bundle checksums and the complete snapshot ref set match. Save both files. Git object closure and forge state are not verified here.');
  }));
  el('export-format').addEventListener('change', () => { clearViews(false); status('Format changed; build a new snapshot export.'); });
  el('export-disconnect').addEventListener('click', () => { clearViews(true); status('Disconnected. Credentials, files, results and download handles cleared.'); });
  el('export-cancel').addEventListener('click', () => { clearViews(false); status('Cancelled. No partial export or verification result retained.'); });
  function saveExport(manifest) {
    try {
      if (working || client.busy || !client.connected || client.exported?.snapshot_refs_checked !== true) throw new Error('Build a complete audited export first.');
      if (manifest) download(utf8.encode(client.exportManifest()), 'repository.export.json', 'application/json');
      else download(client.exportBytes(), 'repository.bundle', 'application/x-git-bundle');
    } catch (error) { status(error.message); }
  }
  el('export-save-bundle').addEventListener('click', () => saveExport(false));
  el('export-save-manifest').addEventListener('click', () => saveExport(true));
  for (const id of ['verify-bundle', 'verify-manifest']) {
    el(id).addEventListener('change', () => { clearOffline(); render(); el('offline-status').textContent = 'Files changed. Verify this exact pair again.'; });
  }
  el('verify-files').addEventListener('click', async () => {
    if (checking) return; clearOffline(); checking = true; const current = offlineSerial; render();
    const check = () => { if (current !== offlineSerial) throw new Error('Offline verification cancelled or files changed.'); };
    try {
      // Check BOTH file sizes before either read. File names are not identities.
      const file = oneFile(el('verify-bundle'), BUNDLE_LIMIT, 'bundle (16 MiB maximum)');
      const manifest = oneFile(el('verify-manifest'), EXPORT_MANIFEST_LIMIT, 'manifest (1 MiB maximum)');
      el('offline-status').textContent = 'Checking local bytes. No upload or connection is required.';
      const encoded = await fileBytes(manifest, check), bytes = await fileBytes(file, check);
      const result = await verifyExportManifest(bytes, new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(encoded), cryptoImpl, check);
      check(); offline = result;
      const report = doc.createElement('pre');
      report.textContent = JSON.stringify({ sha256: result.manifest.bundle.sha256, bytes: result.manifest.bundle.bytes,
        references: result.manifest.bundle.refs.length, objects_verified: false, independently_authenticated: false,
        live_snapshot_rechecked: false, recorded_scope: result.manifest.scope, recorded_snapshot: result.manifest.snapshot }, null, 2);
      el('offline-report').replaceChildren(report); refs(el('offline-report'), result.manifest.bundle.refs);
      el('offline-status').textContent = 'Local bundle matches the unsigned saved manifest. This does not authenticate its origin, prove object closure, or check the current server snapshot.';
    } catch (error) {
      if (current === offlineSerial) { offline = null; el('offline-report').replaceChildren(); el('offline-status').textContent = error.message; }
    } finally { checking = false; render(); }
  });
  events.addEventListener('pagehide', () => clearViews(true));
  render();
  return { get offline() { return offline && structuredClone(offline); }, dispose() { clearViews(true); } };
}
if (typeof document !== 'undefined') {
  try {
    const client = new TransferClient({ href: transferPage(globalThis.location.href) });
    mountExportVerifier(document, { client });
  } catch (error) { document.getElementById('export-status').textContent = error.message; }
}
