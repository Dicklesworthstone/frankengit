// Initial history is deliberate creation, not a fallback after a failed read.
// DOM text is inert; tokens and draft file bytes live only in this page.
import { InitialSourceClient } from './initial.mjs';
import { utf8, hex, unhex, text, decimal } from './pulls-core.mjs';
import { FILE_LIMIT, PATCH_LIMIT, EDIT_LIMIT, sourcePath, fileBytes, fileMode } from './source-edit-patch.mjs';
import { initialFilePatch, initialImportDescriptors, importInitialFiles } from './initial-plan.mjs';
import { RECEIPT_LIMIT } from './pulls-actions.mjs';
export async function readInitialFile(file, maximum, current = () => true) {
  if (!file || !Number.isSafeInteger(file.size) || file.size < 0 || file.size > maximum) throw new Error('Selected file exceeds the byte limit.');
  if (!current()) throw new Error('File selection changed.');
  const buffer = await file.arrayBuffer();
  if (!current()) throw new Error('File selection changed while reading.');
  if (!(buffer instanceof ArrayBuffer) || buffer.byteLength !== file.size || buffer.byteLength > maximum) throw new Error('Selected file length changed.');
  return new Uint8Array(buffer);
}
export function initialHexBytes(value) {
  if (typeof value !== 'string' || value.length > FILE_LIMIT * 3 || /[^0-9a-fA-F \t\r\n]/.test(value)) throw new Error('Enter bounded hexadecimal byte pairs.');
  return unhex(value.replace(/[ \t\r\n]/g, '').toLowerCase(), FILE_LIMIT);
}
export function displayBytes(bytes, maximum = 4096) {
  const part = bytes.subarray(0, maximum); let value;
  try {
    value = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(part)
      .replace(/[\\\u0000-\u0009\u000b-\u001f\u007f-\u009f\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069\ufeff]/gu,
        ch => ch === '\\' ? '\\\\' : `\\u{${ch.codePointAt(0).toString(16)}}`);
  } catch { value = `Non-UTF-8 bytes (hex): ${hex(part)}`; }
  return value + (bytes.length > maximum ? `\n[preview limited to ${maximum} of ${bytes.length} bytes]` : '');
}
export function mountInitialEditor(doc, options = {}) {
  const client = options.client ?? new InitialSourceClient({ href: options.href ?? globalThis.location.href });
  const ids = ['token','connect','disconnect','branch','format','expected-head','expected-absent','path','path-kind','file-mode','input-kind','file-text','line-endings','file',
    'queue','clear','files','batch-files','directory-files','import-prefix','import-mode','import-files','import-directory','author','committer','timestamp','message','prepare','cancel','candidate','stage','confirm-send','send','recover','discard','save','receipt','restore','pending','status'];
  const c = Object.fromEntries(ids.map(id => { const el = doc.getElementById(id); if (!el) throw new Error(`Missing initial control ${id}`); return [id, el]; }));
  let files = new Map(), busy = false, revision = 0;
  const el = (tag, value) => { const node = doc.createElement(tag); if (value !== undefined) node.textContent = value; return node; };
  const status = value => { c.status.textContent = value; };
  const editable = ['branch','format','expected-head','expected-absent','path','path-kind','file-mode','input-kind','file-text','line-endings','file','batch-files','directory-files','import-prefix','import-mode','author','committer','timestamp','message'];
  function clearFiles() { files.clear(); c.file.value = ''; c['batch-files'].value = ''; c['directory-files'].value = ''; c['file-text'].value = ''; c.candidate.replaceChildren(); }
  function render() {
    const p = client.pending, a = client.candidate;
    for (const id of editable) c[id].disabled = busy || !client.connected || !!p;
    for (const id of ['queue','clear','prepare','import-files','import-directory']) c[id].disabled = busy || !client.connected || !!p;
    c.prepare.disabled ||= files.size === 0 || !c['expected-absent'].checked;
    c.stage.disabled = busy || !client.connected || !!p || !a;
    c.connect.disabled = busy; c.cancel.disabled = !busy || !!p;
    for (const id of ['send','recover']) c[id].disabled = busy || !client.connected || !p;
    c.discard.disabled = busy || !p || p.sent || p.exported;
    c.save.disabled = busy || !p; c.restore.disabled = busy || !client.connected || !!p;
    c.pending.textContent = p ? JSON.stringify(p, null, 2) : 'No outstanding initial publication.';
    c.files.replaceChildren();
    for (const [path, value] of files) {
      const row = el('li'), preview = el('details'), remove = el('button', 'Remove'); remove.type = 'button'; remove.disabled = busy || !!p;
      preview.append(el('summary', `${displayBytes(unhex(path, 4096))} [${path}] — ${value.bytes.length} bytes, mode ${value.mode.toString(8)}`), el('pre', displayBytes(value.bytes)));
      row.append(preview, remove); c.files.append(row);
      remove.addEventListener('click', () => { if (busy || client.pending) return; files.delete(path); changed(); });
    }
  }
  function changed() { revision++; client.invalidateCandidate(); c.candidate.replaceChildren(); c['confirm-send'].checked = false; render(); }
  async function perform(work) {
    if (busy) return; busy = true; render();
    try { await work(); }
    catch (error) { status(`${error.outcomeUnknown ? 'Outcome unknown. Keep the original request and recover it. ' : ''}${error.message}`); }
    finally { busy = false; if (!client.connected) clearFiles(); render(); }
  }
  function disconnect() {
    revision++; client.disconnect(); clearFiles(); c.token.value = ''; c.receipt.value = ''; c['confirm-send'].checked = false; render();
    status(client.pending ? 'Disconnected. The original publication is retained; save its recovery receipt before leaving.' : 'Disconnected. Credentials and initial file bytes cleared.');
  }
  c.connect.addEventListener('click', () => perform(async () => {
    const token = c.token.value; c.token.value = ''; revision++; clearFiles(); await client.connect(token);
    status('Connected. Choose an absent branch and queue initial files, or restore an original publication.');
  }));
  c.disconnect.addEventListener('click', disconnect);
  for (const id of editable) c[id].addEventListener(['file','batch-files','directory-files'].includes(id) ? 'change' : 'input', changed);
  c.receipt.addEventListener('change', () => { revision++; });
  c.cancel.addEventListener('click', () => { if (client.pending) return; changed(); status('Read/import cancelled. No publication was sent.'); });
  c.queue.addEventListener('click', () => perform(async () => {
    if (client.pending) throw new Error('Resolve the original publication before editing.');
    changed(); // A failed replacement cannot leave an older candidate enabled.
    if (!['utf8', 'hex'].includes(c['path-kind'].value)) throw new Error('Choose text or exact hexadecimal path bytes.');
    const path = c['path-kind'].value === 'hex' ? c.path.value : hex(utf8.encode(text(c.path.value, 4096, 'repository path'))); sourcePath(path);
    if (!['100644', '100755'].includes(c['file-mode'].value)) throw new Error('Choose an ordinary or executable regular file.');
    const mode = fileMode(Number.parseInt(c['file-mode'].value, 8)), started = revision;
    if (!files.has(path) && files.size >= EDIT_LIMIT) throw new Error('At most 64 initial files are supported.');
    const retained = [...files.entries()].reduce((sum, [key, f]) => sum + (key === path ? 0 : f.bytes.length), 0);
    let bytes;
    if (c['input-kind'].value === 'upload') {
      if (c.file.files?.length !== 1) throw new Error('Choose exactly one file for this repository path.');
      const selected = c.file.files[0];
      bytes = fileBytes(await readInitialFile(selected, Math.min(FILE_LIMIT, PATCH_LIMIT - retained),
        () => revision === started && client.connected && c.file.files?.[0] === selected), true);
    } else if (c['input-kind'].value === 'text') {
      if (!['lf', 'crlf'].includes(c['line-endings'].value)) throw new Error('Choose LF or CRLF explicitly.');
      const value = text(c['file-text'].value, FILE_LIMIT, 'initial file text').replace(/\r\n/g, '\n').replace(/\r/g, '\n');
      bytes = fileBytes(utf8.encode(c['line-endings'].value === 'crlf' ? value.replace(/\n/g, '\r\n') : value));
    } else if (c['input-kind'].value === 'hex') bytes = initialHexBytes(c['file-text'].value);
    else throw new Error('Choose text, hexadecimal bytes or an exact-byte upload.');
    const next = new Map(files); next.set(path, { path_hex: path, bytes, mode });
    initialFilePatch([...next.values()]);
    files = next; changed(); status(`${files.size} initial file(s) queued locally. Nothing has been submitted.`);
  }));
  async function importSelection(directory) {
    if (!client.connected || client.pending) throw new Error('Resolve the original publication before importing.');
    changed();
    const control = c[directory ? 'directory-files' : 'batch-files'], started = revision;
    // Bound FileList length before allocation. Replacing it during a read
    // cannot substitute inputs or enlarge an already checked batch.
    const list = control.files, length = list?.length;
    if (!Number.isSafeInteger(length) || length < 1 || length + files.size > EDIT_LIMIT) throw new Error('Choose files within the remaining 64-file queue limit.');
    const selected = Array.from({ length }, (_, i) => list[i]);
    if (!['100644', '100755'].includes(c['import-mode'].value)) throw new Error('Choose an explicit imported-file mode.');
    const incoming = initialImportDescriptors(selected, { directory, prefix: c['import-prefix'].value,
      mode: Number.parseInt(c['import-mode'].value, 8) });
    const check = () => {
      if (started !== revision || !client.connected || client.pending || control.files?.length !== selected.length ||
          selected.some((file, i) => control.files[i] !== file)) throw new Error('Initial import cancelled or selection changed.');
    };
    const next = await importInitialFiles([...files.values()], incoming, check); check();
    files = new Map(next.map(file => [file.path_hex, file])); control.value = ''; changed();
    status(`${selected.length} file(s) imported atomically into the local queue; ${files.size} total. Review paths and modes before preparation. Nothing submitted.`);
  }
  c['import-files'].addEventListener('click', () => perform(() => importSelection(false)));
  c['import-directory'].addEventListener('click', () => perform(() => importSelection(true)));
  c.clear.addEventListener('click', () => { if (!busy && !client.pending) { clearFiles(); changed(); } });
  c.prepare.addEventListener('click', () => perform(async () => {
    if (!c['expected-absent'].checked) throw new Error('Confirm branch absence explicitly.');
    const fields = { ref: c.branch.value, object_format: c.format.value, expected_absent: true };
    if (c['expected-head'].value !== '') fields.expected_head = c['expected-head'].value;
    const metadata = { author: c.author.value, committer: c.committer.value, timestamp: decimal(c.timestamp.value, 'timestamp'), message: c.message.value };
    const started = revision, a = await client.prepare(fields, [...files.values()], metadata);
    if (started !== revision || !client.connected) throw new Error('Initial draft changed while preparing.');
    c.candidate.replaceChildren(el('pre', JSON.stringify({ branch: a.fields.ref, expected_absent: true, parents: [], root_tree: a.preparation.root_tree,
      candidate_commit: a.fields.candidate_commit, object_count: a.preparation.object_count, files: a.files,
      patch_sha256: a.preparation.patch_sha256, bundle_sha256: a.sha256, bundle_bytes: a.bundleBytes, default_branch_changed: false }, null, 2)),
      el('pre', displayBytes(unhex(a.preparation.candidate_commit_body_hex, 128 * 1024))));
    status('Complete file/tree/commit identity matched native preparation. This is not publication; the native publisher still verifies the actual bundle.');
  }));
  c.stage.addEventListener('click', () => perform(async () => {
    await client.stageApply(); c['confirm-send'].checked = false;
    status('Creation-only request frozen locally. Confirm its branch, candidate and original key before sending.');
  }));
  c.send.addEventListener('click', () => perform(async () => {
    if (!c['confirm-send'].checked) throw new Error('Confirm the displayed exact request before sending or retrying.');
    c['confirm-send'].checked = false;
    const result = await client.send(); clearFiles(); status(`Canonical ${result.outcome}: ${result.tx}. Default branch unchanged. No delivery acknowledgement is inferred.`);
  }));
  c.recover.addEventListener('click', () => perform(async () => {
    const result = await client.recover(); if (result.terminal) clearFiles();
    status(result.terminal ? `Recovered canonical ${result.outcome}: ${result.tx}.` : `Unresolved: ${result.state}. Absence does not prove non-commit. Keep the original request.`);
  }));
  c.discard.addEventListener('click', () => { try { client.discardUnsent(); c['confirm-send'].checked = false; render(); status('Unsent, unexported request discarded.'); } catch (e) { status(e.message); } });
  c.save.addEventListener('click', () => {
    try {
      const value = client.exportReceipt();
      if (options.saveReceipt) options.saveReceipt(value);
      else {
        const url = URL.createObjectURL(new Blob([value], { type: 'application/json' })), link = el('a');
        link.href = url; link.download = 'frankengit-initial-retry.json'; link.click(); setTimeout(() => URL.revokeObjectURL(url), 0);
      }
      render(); status('Token-free receipt saved. It contains repository data; protect it and keep the original token separately.');
    } catch (e) { status(e.message); }
  });
  c.restore.addEventListener('click', () => perform(async () => {
    const selected = c.receipt.files?.[0], started = revision;
    const bytes = await readInitialFile(selected, RECEIPT_LIMIT, () => started === revision && client.connected && c.receipt.files?.[0] === selected);
    await client.restoreReceipt(new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes));
    clearFiles(); c['confirm-send'].checked = false; status('Original creation-only request restored, not executed. Recover or explicitly confirm an unchanged retry.');
  }));
  const events = options.events ?? globalThis;
  events.addEventListener?.('pagehide', disconnect);
  events.addEventListener?.('beforeunload', e => { if (files.size || client.pending) { e.preventDefault(); e.returnValue = ''; } });
  render(); return { client, disconnect, get queued() { return [...files.values()].map(f => structuredClone(f)); } };
}
if (typeof document !== 'undefined') mountInitialEditor(document);
