// Static browser shell over the native source client. Repository bytes enter
// text nodes only; credentials and drafts never enter URL or persistent storage.
import { SourceEditClient } from './source-edit.mjs';
import { utf8, hex, unhex, decimal, text } from './pulls-core.mjs';
import { FILE_LIMIT, PATCH_LIMIT, EDIT_LIMIT, sourcePath, fileBytes, fullFilePatch } from './source-edit-patch.mjs';
import { RECEIPT_LIMIT } from './pulls-actions.mjs';
export function editorBytes(value, original, dirty, endings) {
  if (original !== null && original !== undefined) {
    fileBytes(original, true);
    if (!dirty) return original.slice();
    if (editableText(original) === null) throw new Error('Binary/non-text files require exact hex edits or a replacement upload.');
  }
  if (typeof value !== 'string' || !['lf', 'crlf'].includes(endings)) throw new Error('Choose LF or CRLF explicitly for edited text.');
  text(value, FILE_LIMIT, 'edited text');
  const normalized = value.replace(/\r\n/g, '\n').replace(/\r/g, '\n');
  // The editor's chosen newline conversion is deliberate. Upload a replacement
  // file instead when mixed/bare-CR line endings must remain byte-for-byte exact.
  return fileBytes(utf8.encode(endings === 'crlf' ? normalized.replace(/\n/g, '\r\n') : normalized));
}
export async function chosenBytes(file, maximum, stillCurrent = () => true) {
  if (!file || !Number.isSafeInteger(file.size) || file.size < 0 || file.size > maximum) throw new Error('Selected file exceeds this operation’s byte limit.');
  if (!stillCurrent()) throw new Error('File selection changed.');
  const buffer = await file.arrayBuffer();
  if (!stillCurrent()) throw new Error('File selection changed while reading.');
  if (!(buffer instanceof ArrayBuffer) || buffer.byteLength !== file.size || buffer.byteLength > maximum) throw new Error('Selected file bytes changed or exceeded the limit.');
  return new Uint8Array(buffer);
}
export const HEX_TEXT_LIMIT = FILE_LIMIT * 3;
export function hexEditorBytes(value) {
  if (typeof value !== 'string' || value.length > HEX_TEXT_LIMIT || /[^0-9a-fA-F \t\r\n]/.test(value)) throw new Error('Enter bounded hexadecimal byte pairs, without prefixes or comments.');
  const digits = value.replace(/[ \t\r\n]/g, '').toLowerCase();
  return fileBytes(unhex(digits, FILE_LIMIT), true);
}
export function formatHexBytes(bytes) {
  fileBytes(bytes, true); const lines = [];
  for (let i = 0; i < bytes.length; i += 16) lines.push(Array.from(bytes.subarray(i, i + 16), byte => byte.toString(16).padStart(2, '0')).join(' '));
  return lines.join('\n');
}
export function editableText(bytes) {
  if (bytes.some(byte => byte < 32 && ![9, 10, 13].includes(byte))) return null;
  const value = decoded(bytes);
  return value !== null && !/[\u007f-\u009f\u202a-\u202e\u2066-\u2069]/u.test(value) ? value : null;
}
function decoded(bytes) {
  try { return new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes); }
  catch { return null; }
}
function label(path) {
  const bytes = unhex(path, 4096), value = decoded(bytes);
  return value === null ? `bytes:${path}` : `${JSON.stringify(value).replace(/[\u202a-\u202e\u2066-\u2069]/gu, c => `\\u${c.charCodeAt(0).toString(16)}`)} [${path}]`;
}
function contentLabel(bytes) { return editableText(bytes) ?? `Binary/non-text bytes (hex):\n${hex(bytes)}`; }
export function mountSourceEditor(doc, options = {}) {
  const client = options.client ?? new SourceEditClient({ href: options.href ?? globalThis.location.href });
  const byId = id => { const element = doc.getElementById(id); if (!element) throw new Error(`Missing source editor control ${id}`); return element; };
  const controls = Object.fromEntries(['token','connect','disconnect','branch','format','select-base','base','path','path-kind','load-file',
    'change-kind','file-mode','file-text','file-hex','content-mode','text-editor','hex-editor','file-info','save-file','line-endings','replacement','queue-file','edits','clear-edits','author','committer','timestamp','message',
    'prepare-edits','patch','prepare-patch','candidate','stage','confirm-send','send','recover','discard','save-receipt','restore-file','restore-receipt','pending','status'].map(id => [id, byId(id)]));
  let edits = new Map(), loaded = null, replacement = null, replacementFile = null, revision = 0, textDirty = false, busy = false, viewMode = 'text';
  const urls = options.urls ?? globalThis.URL, timers = options.timers ?? globalThis, downloads = new Map();
  function releaseDownloads() {
    for (const [url, timer] of downloads) { timers.clearTimeout(timer); urls.revokeObjectURL(url); }
    downloads.clear();
  }
  function download(value, media, name) {
    const url = urls.createObjectURL(new Blob([value], { type: media }));
    try {
      const link = element('a'); link.href = url; link.download = name; link.click();
      const timer = timers.setTimeout(() => { urls.revokeObjectURL(url); downloads.delete(url); }, 30_000);
      timer?.unref?.(); downloads.set(url, timer);
    } catch (error) { urls.revokeObjectURL(url); throw error; }
  }
  controls['content-mode'].value = viewMode;
  const element = (tag, text) => { const node = doc.createElement(tag); if (text !== undefined) node.textContent = text; return node; };
  const status = message => { controls.status.textContent = message; };
  const path = () => {
    const value = controls['path-kind'].value === 'hex' ? controls.path.value : hex(utf8.encode(text(controls.path.value, 4096, 'path')));
    sourcePath(value); return value;
  };
  function clearDraft() {
    edits.clear(); loaded = null; replacement = null; replacementFile = null; textDirty = false; viewMode = 'text';
    controls['content-mode'].value = viewMode; controls['file-hex'].value = ''; controls['file-info'].textContent = 'No file bytes loaded.'; releaseDownloads();
    controls['file-text'].value = ''; controls.replacement.value = ''; controls.patch.value = '';
    controls.candidate.replaceChildren(); controls.edits.replaceChildren(); controls.base.textContent = '';
  }
  function changed() {
    revision += 1; client.invalidateCandidate(); controls.candidate.replaceChildren(); controls['confirm-send'].checked = false; render();
  }
  function render() {
    const pending = client.pending, candidate = client.candidate, connected = client.connected;
    for (const id of ['branch','format','path','path-kind','change-kind','file-mode','file-text','file-hex','content-mode','line-endings','replacement','author','committer','timestamp','message','patch']) controls[id].disabled = busy || !connected || !!pending;
    controls['text-editor'].hidden = viewMode !== 'text'; controls['hex-editor'].hidden = viewMode !== 'hex';
    controls['file-text'].disabled ||= viewMode !== 'text'; controls['file-hex'].disabled ||= viewMode !== 'hex';
    controls['line-endings'].disabled ||= viewMode !== 'text';
    controls['save-file'].disabled = busy || !connected || !!pending || !client.selection;
    controls.connect.disabled = busy; controls['select-base'].disabled = busy || !connected || !!pending;
    for (const id of ['load-file','queue-file','clear-edits','prepare-edits','prepare-patch']) controls[id].disabled = busy || !connected || !!pending || !client.selection;
    controls.stage.disabled = busy || !connected || !!pending || !candidate;
    controls.send.disabled = busy || !connected || !pending;
    controls.recover.disabled = busy || !connected || !pending;
    controls.discard.disabled = busy || !pending || pending.sent || pending.exported;
    controls['save-receipt'].disabled = busy || !pending;
    controls['restore-receipt'].disabled = busy || !connected || !!pending;
    controls.pending.textContent = pending ? JSON.stringify(pending, null, 2) : 'No outstanding publication.';
    controls.edits.replaceChildren();
    for (const [key, edit] of edits) {
      const row = element('li'), remove = element('button', 'Remove'); remove.type = 'button'; remove.disabled = busy || !!pending;
      row.append(element('span', `${edit.before === null ? 'Create' : edit.after === null ? 'Delete' : 'Edit'} ${label(key)}; ${edit.before?.bytes.length ?? 0} → ${edit.after?.bytes.length ?? 0} bytes${editableText(edit.after?.bytes ?? edit.before.bytes) === null ? ' (binary/raw)' : ''} `), remove);
      remove.addEventListener('click', () => { if (busy || client.pending) return; edits.delete(key); changed(); });
      controls.edits.append(row);
    }
  }
  async function perform(work) {
    if (busy) return; busy = true; render();
    try { await work(); }
    catch (error) { status(`${error.outcomeUnknown ? 'Outcome unknown; keep the original request and use recovery. ' : ''}${error.message}`); }
    finally { busy = false; if (!client.connected) clearDraft(); render(); }
  }
  function inspectView(candidate) {
    controls.candidate.replaceChildren();
    const summary = element('pre', JSON.stringify({ branch: candidate.fields.ref, parent: candidate.fields.expected_commit,
      candidate: candidate.fields.candidate_commit, bundle_sha256: candidate.sha256, bundle_bytes: candidate.bundleBytes,
      publication_authorized: false }, null, 2));
    controls.candidate.append(summary);
    for (const entry of candidate.inspection.comparison.entries) {
      const section = element('section'); section.append(element('h3', `${entry.kind}: ${label(entry.path_hex)}`));
      section.append(element('p', `Before ${entry.before?.oid ?? 'absent'} (${entry.before?.mode?.toString(8) ?? 'absent'}); after ${entry.after?.oid ?? 'absent'} (${entry.after?.mode?.toString(8) ?? 'absent'})`));
      if (entry.content.type === 'text') {
        for (const hunk of entry.content.hunks) {
          section.append(element('h4', `Old lines ${hunk.old.line_start}+${hunk.old.line_count}`), element('pre', contentLabel(unhex(hunk.before_hex))));
          section.append(element('h4', `New lines ${hunk.new.line_start}+${hunk.new.line_count}`), element('pre', contentLabel(unhex(hunk.after_hex))));
        }
      } else section.append(element('p', `${entry.content.type}: ${entry.content.type === 'binary' ? 'binary contents are not included' : 'no text content was read for this entry'}.`));
      controls.candidate.append(section);
    }
  }
  function draftBytes() {
    if (replacementFile && replacement === null) throw new Error('The selected replacement has not completed validation; choose it again or edit explicitly.');
    if (replacement !== null) return replacement.slice();
    if (!textDirty && loaded) return loaded.before.bytes.slice();
    return viewMode === 'hex' ? hexEditorBytes(controls['file-hex'].value)
      : editorBytes(controls['file-text'].value, null, true, controls['line-endings'].value);
  }
  function showBytes(bytes, requested = null) {
    const value = editableText(bytes);
    if (requested === 'text' && value === null) throw new Error('These bytes cannot be edited as safe UTF-8 text. Keep hex view or upload a replacement.');
    viewMode = requested ?? (value === null ? 'hex' : 'text'); controls['content-mode'].value = viewMode;
    controls['file-text'].value = value ?? ''; controls['file-hex'].value = formatHexBytes(bytes);
    controls['line-endings'].value = value?.includes('\r\n') ? 'crlf' : 'lf';
    controls['file-info'].textContent = `${bytes.length} exact bytes; ${value === null ? 'binary/non-text data' : 'UTF-8 text'}. No content is executed.`;
  }
  function uploadBudget(file) {
    if (!file || !Number.isSafeInteger(file.size) || file.size < 0 || file.size > FILE_LIMIT) throw new Error('Selected file exceeds this operation’s byte limit.');
    // A user may select bytes before entering a path. Until it is valid,
    // reserve against every queued edit instead of guessing an override.
    let selected = null; try { selected = path(); } catch {}
    const kind = controls['change-kind'].value;
    let size = file.size + (kind !== 'create' && loaded?.path_hex === selected ? loaded.before.bytes.length : 0);
    for (const [key, edit] of edits) if (key !== selected) size += (edit.before?.bytes.length ?? 0) + (edit.after?.bytes.length ?? 0);
    if (size > PATCH_LIMIT || (edits.size >= EDIT_LIMIT && !edits.has(selected))) throw new Error('Replacement exceeds the combined draft byte or path budget.');
  }
  const metadata = () => ({ author: controls.author.value, committer: controls.committer.value,
    timestamp: decimal(controls.timestamp.value, 'explicit timestamp'), message: controls.message.value });
  controls.connect.addEventListener('click', () => perform(async () => {
    const token = controls.token.value; controls.token.value = ''; revision += 1; clearDraft();
    await client.connect(token); status('Connected. Select a branch base or restore an original request.');
  }));
  function disconnect() {
    revision += 1; client.disconnect(); controls.token.value = ''; controls['confirm-send'].checked = false; clearDraft(); render();
    status(client.pending ? 'Disconnected. The outstanding original request is retained; save its recovery receipt.' : 'Disconnected; source bytes and credentials cleared.');
  }
  controls.disconnect.addEventListener('click', disconnect);
  controls['select-base'].addEventListener('click', () => perform(async () => {
    revision += 1; clearDraft(); const selected = await client.select(controls.branch.value, controls.format.value);
    controls.base.textContent = JSON.stringify(selected, null, 2); status('Immutable base selected. Every queued edit will use this exact parent.');
  }));
  for (const id of ['path','path-kind','change-kind']) controls[id].addEventListener('input', () => {
    loaded = null; replacement = null; replacementFile = null; controls.replacement.value = ''; controls['file-text'].value = ''; controls['file-hex'].value = ''; controls['file-info'].textContent = 'No file bytes loaded.'; textDirty = false; changed();
  });
  for (const id of ['file-text','file-hex','line-endings']) controls[id].addEventListener('input', () => {
    if (client.pending || busy || (id === 'file-hex' ? viewMode !== 'hex' : viewMode !== 'text')) return;
    textDirty = true; replacement = null; replacementFile = null; controls.replacement.value = '';
    controls['file-info'].textContent = 'Edited draft; queue or download to validate its complete bytes.'; changed();
  });
  controls['content-mode'].addEventListener('change', () => {
    const requested = controls['content-mode'].value;
    if (busy || client.pending || !client.connected) { controls['content-mode'].value = viewMode; return; }
    try {
      if (!['text', 'hex'].includes(requested)) throw new Error('Choose text or exact hex view.');
      const bytes = draftBytes(); showBytes(bytes, requested);
      replacement = bytes; replacementFile = null; controls.replacement.value = ''; textDirty = false; changed();
      status('View changed without converting any bytes. Only explicit text edits apply the selected line endings.');
    } catch (error) { controls['content-mode'].value = viewMode; status(error.message); render(); }
  });
  for (const id of ['file-mode','author','committer','timestamp','message']) controls[id].addEventListener('input', changed);
  for (const id of ['branch','format']) controls[id].addEventListener('input', () => { client.clearSelection(); clearDraft(); changed(); status('Select the new branch and format explicitly before editing.'); });
  controls['load-file'].addEventListener('click', () => perform(async () => {
    const selectedPath = path(), started = ++revision; client.invalidateCandidate(); loaded = null; replacement = null; replacementFile = null;
    controls.replacement.value = ''; controls['file-text'].value = ''; controls['file-hex'].value = '';
    controls['file-info'].textContent = 'Loading the complete native blob.';
    const file = await client.loadFile(selectedPath); if (started !== revision) throw new Error('Source selection changed while loading.');
    loaded = file; textDirty = false; showBytes(file.before.bytes); controls['file-mode'].value = file.before.mode.toString(8);
    status(viewMode === 'hex' ? 'Exact binary/non-text file loaded and native identity verified. Edit hex, upload a replacement, delete, or change its mode.'
      : 'Complete native-identity-verified file loaded. Unedited bytes retain their exact newline form.');
  }));
  controls.replacement.addEventListener('change', () => {
    if (client.pending || !client.connected) { status('Connect and resolve any original publication before replacing file bytes.'); return; }
    // Invalidate even when an earlier read is still busy. A failed or superseded
    // selection must never fall back to the previous successful replacement.
    replacement = null; replacementFile = controls.replacement.files?.[0] ?? null; changed();
    const file = replacementFile, started = revision;
    if (!file) { status('Replacement selection cleared. The explicit editor or original bytes will be used.'); return; }
    return perform(async () => {
      uploadBudget(file);
      const bytes = fileBytes(await chosenBytes(file, FILE_LIMIT, () => started === revision && client.connected && controls.replacement.files?.[0] === file), true);
      replacement = bytes; textDirty = false; showBytes(bytes);
      status(`Exact replacement loaded: ${replacement.length} bytes. Queue the edit explicitly.`);
    });
  });
  controls['save-file'].addEventListener('click', () => {
    try {
      if (busy || !client.connected || client.pending || !client.selection) throw new Error('Select an editable base before downloading a draft.');
      const bytes = draftBytes();
      if (options.saveFile) options.saveFile(bytes.slice());
      else download(bytes, 'application/octet-stream', 'frankengit-file.bin');
      status(`Downloaded ${bytes.length} exact draft bytes. No repository request was sent.`);
    } catch (error) { status(error.message); }
  });
  controls['queue-file'].addEventListener('click', () => perform(async () => {
    if (client.pending) throw new Error('Resolve the original publication before editing.');
    const selectedPath = path(), kind = controls['change-kind'].value;
    if (!['create','modify','delete'].includes(kind)) throw new Error('Choose an explicit file action.');
    if (kind !== 'create' && (!loaded || loaded.path_hex !== selectedPath)) throw new Error('Load the complete existing file at this base first.');
    const before = kind === 'create' ? null : loaded.before;
    let after = null;
    if (kind !== 'delete') {
      if (!['100644', '100755'].includes(controls['file-mode'].value)) throw new Error('Choose a supported regular-file mode.');
      after = { bytes: draftBytes(), mode: Number.parseInt(controls['file-mode'].value, 8) };
    }
    const next = new Map(edits); next.set(selectedPath, { path_hex: selectedPath, before, after });
    // Validate the entire prospective set before changing the queue.
    fullFilePatch([...next.values()], { allowBinary: true }); if (next.size > EDIT_LIMIT) throw new Error('Too many edited paths.');
    edits = next; changed(); status(`${edits.size} exact file edit(s) queued. Nothing has been submitted.`);
  }));
  controls['clear-edits'].addEventListener('click', () => { if (!busy && !client.pending) { edits.clear(); changed(); } });
  controls['prepare-edits'].addEventListener('click', () => perform(async () => {
    const prepared = await client.prepareEdits([...edits.values()], metadata()); inspectView(prepared);
    status('Native preparation and inspection completed. Inspect every changed path before preparing publication.');
  }));
  controls.patch.addEventListener('change', changed);
  controls['prepare-patch'].addEventListener('click', () => perform(async () => {
    changed(); const started = revision, commit = metadata();
    const bytes = await chosenBytes(controls.patch.files?.[0], PATCH_LIMIT, () => started === revision && client.connected);
    const prepared = await client.preparePatch(bytes, commit); inspectView(prepared);
    status('Uploaded patch was prepared and inspected natively. Review its complete candidate before publication.');
  }));
  controls.stage.addEventListener('click', () => perform(async () => {
    await client.stageApply(); controls['confirm-send'].checked = false;
    status('Publication prepared locally. Verify its branch, parent, candidate, and key, then separately confirm Send.');
  }));
  controls.send.addEventListener('click', () => perform(async () => {
    if (!controls['confirm-send'].checked) throw new Error('Confirm the displayed exact request before sending or retrying.');
    controls['confirm-send'].checked = false;
    const result = await client.send(); clearDraft(); status(`Canonical ${result.outcome}: ${result.tx}. Delivery acknowledgement is not asserted. Select a fresh base explicitly for further work.`);
  }));
  controls.recover.addEventListener('click', () => perform(async () => {
    const result = await client.recover(); if (result.terminal) clearDraft();
    status(result.terminal ? `Recovered canonical ${result.outcome}: ${result.tx}.` : `Still unresolved: ${result.state}. Absence does not prove non-commit. Keep the original request.`);
  }));
  controls.discard.addEventListener('click', () => { try { client.discardUnsent(); status('Unsent, unexported local request discarded.'); render(); } catch (error) { status(error.message); } });
  controls['save-receipt'].addEventListener('click', () => {
    try {
      const value = client.exportReceipt();
      if (options.saveReceipt) options.saveReceipt(value);
      else download(value, 'application/json', 'frankengit-source-retry.json');
      status('Token-free original-request receipt saved. It contains candidate bytes; treat it as repository data.'); render();
    } catch (error) { status(error.message); }
  });
  controls['restore-receipt'].addEventListener('click', () => perform(async () => {
    const started = ++revision; const bytes = await chosenBytes(controls['restore-file'].files?.[0], RECEIPT_LIMIT, () => started === revision && client.connected);
    const encoded = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
    await client.restoreReceipt(encoded); clearDraft(); controls['confirm-send'].checked = false;
    status('Original request restored, not executed. Query its outcome or explicitly confirm an unchanged retry.');
  }));
  (options.events ?? globalThis).addEventListener?.('pagehide', disconnect);
  (options.events ?? globalThis).addEventListener?.('beforeunload', event => {
    if (client.pending || edits.size || replacement !== null || replacementFile || textDirty) { event.preventDefault(); event.returnValue = ''; }
  });
  render(); return { client, disconnect, get queued() { return [...edits.values()].map(edit => structuredClone(edit)); } };
}
if (typeof document !== 'undefined') mountSourceEditor(document);
