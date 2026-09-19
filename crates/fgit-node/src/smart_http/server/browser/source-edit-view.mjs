// Static browser shell over the native source client. Repository bytes enter
// text nodes only; credentials and drafts never enter URL or persistent storage.
import { SourceEditClient } from './source-edit.mjs';
import { utf8, hex, unhex, decimal, text } from './pulls-core.mjs';
import { FILE_LIMIT, PATCH_LIMIT, EDIT_LIMIT, sourcePath, fileBytes, fullFilePatch } from './source-edit-patch.mjs';
import { RECEIPT_LIMIT } from './pulls-actions.mjs';
export function editorBytes(value, original, dirty, endings) {
  if (!dirty && original) return original.slice();
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
function decoded(bytes) {
  try { return new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes); }
  catch { return null; }
}
function label(path) {
  const bytes = unhex(path, 4096), value = decoded(bytes);
  return value === null ? `bytes:${path}` : `${JSON.stringify(value)} [${path}]`;
}
function contentLabel(bytes) { return decoded(bytes) ?? `Non-UTF-8 bytes (hex):\n${hex(bytes)}`; }
export function mountSourceEditor(doc, options = {}) {
  const client = options.client ?? new SourceEditClient({ href: options.href ?? globalThis.location.href });
  const byId = id => { const element = doc.getElementById(id); if (!element) throw new Error(`Missing source editor control ${id}`); return element; };
  const controls = Object.fromEntries(['token','connect','disconnect','branch','format','select-base','base','path','path-kind','load-file',
    'change-kind','file-mode','file-text','line-endings','replacement','queue-file','edits','clear-edits','author','committer','timestamp','message',
    'prepare-edits','patch','prepare-patch','candidate','stage','confirm-send','send','recover','discard','save-receipt','restore-file','restore-receipt','pending','status'].map(id => [id, byId(id)]));
  let edits = new Map(), loaded = null, replacement = null, revision = 0, textDirty = false, busy = false;
  const element = (tag, text) => { const node = doc.createElement(tag); if (text !== undefined) node.textContent = text; return node; };
  const status = message => { controls.status.textContent = message; };
  const path = () => {
    const value = controls['path-kind'].value === 'hex' ? controls.path.value : hex(utf8.encode(text(controls.path.value, 4096, 'path')));
    sourcePath(value); return value;
  };
  function clearDraft() {
    edits.clear(); loaded = null; replacement = null; textDirty = false;
    controls['file-text'].value = ''; controls.replacement.value = ''; controls.patch.value = '';
    controls.candidate.replaceChildren(); controls.edits.replaceChildren(); controls.base.textContent = '';
  }
  function changed() {
    revision += 1; client.invalidateCandidate(); controls.candidate.replaceChildren(); controls['confirm-send'].checked = false; render();
  }
  function render() {
    const pending = client.pending, candidate = client.candidate, connected = client.connected;
    for (const id of ['branch','format','path','path-kind','change-kind','file-mode','file-text','line-endings','replacement','author','committer','timestamp','message','patch']) controls[id].disabled = busy || !connected || !!pending;
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
      row.append(element('span', `${edit.before === null ? 'Create' : edit.after === null ? 'Delete' : 'Edit'} ${label(key)}; ${edit.before?.bytes.length ?? 0} → ${edit.after?.bytes.length ?? 0} bytes `), remove);
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
    loaded = null; replacement = null; controls.replacement.value = ''; controls['file-text'].value = ''; textDirty = false; changed();
  });
  for (const id of ['file-text','line-endings']) controls[id].addEventListener('input', () => { textDirty = true; replacement = null; controls.replacement.value = ''; changed(); });
  for (const id of ['file-mode','author','committer','timestamp','message']) controls[id].addEventListener('input', changed);
  for (const id of ['branch','format']) controls[id].addEventListener('input', () => { client.clearSelection(); clearDraft(); changed(); status('Select the new branch and format explicitly before editing.'); });
  controls['load-file'].addEventListener('click', () => perform(async () => {
    const selectedPath = path(), started = ++revision; client.invalidateCandidate(); loaded = null; replacement = null;
    const file = await client.loadFile(selectedPath); if (started !== revision) throw new Error('Source selection changed while loading.');
    loaded = file; textDirty = false; const text = decoded(file.before.bytes);
    controls['file-text'].value = text ?? ''; controls['file-mode'].value = file.before.mode.toString(8);
    controls['line-endings'].value = text?.includes('\r\n') ? 'crlf' : 'lf';
    status(text === null ? 'Exact non-UTF-8 file loaded. Upload replacement bytes, delete it, or change only its mode.' : 'Complete native-identity-verified file loaded. Unedited bytes retain their exact newline form.');
  }));
  controls.replacement.addEventListener('change', () => perform(async () => {
    changed(); const started = revision; const file = controls.replacement.files?.[0];
    replacement = fileBytes(await chosenBytes(file, FILE_LIMIT, () => started === revision && client.connected));
    status(`Exact replacement loaded: ${replacement.length} bytes. Queue the edit explicitly.`);
  }));
  controls['queue-file'].addEventListener('click', () => perform(async () => {
    if (client.pending) throw new Error('Resolve the original publication before editing.');
    const selectedPath = path(), kind = controls['change-kind'].value;
    if (!['create','modify','delete'].includes(kind)) throw new Error('Choose an explicit file action.');
    if (kind !== 'create' && (!loaded || loaded.path_hex !== selectedPath)) throw new Error('Load the complete existing file at this base first.');
    const before = kind === 'create' ? null : loaded.before;
    const bytes = replacement?.slice() ?? editorBytes(controls['file-text'].value, before?.bytes, textDirty, controls['line-endings'].value);
    if (!['100644', '100755'].includes(controls['file-mode'].value)) throw new Error('Choose a supported regular-file mode.');
    const after = kind === 'delete' ? null : { bytes, mode: Number.parseInt(controls['file-mode'].value, 8) };
    const next = new Map(edits); next.set(selectedPath, { path_hex: selectedPath, before, after });
    // Validate the entire prospective set before changing the queue.
    fullFilePatch([...next.values()]); if (next.size > EDIT_LIMIT) throw new Error('Too many edited paths.');
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
      else {
        const url = URL.createObjectURL(new Blob([value], { type: 'application/json' })), link = element('a');
        link.href = url; link.download = 'frankengit-source-retry.json'; link.click(); setTimeout(() => URL.revokeObjectURL(url), 0);
      }
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
    if (client.pending || edits.size) { event.preventDefault(); event.returnValue = ''; }
  });
  render(); return { client, disconnect, get queued() { return [...edits.values()].map(edit => structuredClone(edit)); } };
}
if (typeof document !== 'undefined') mountSourceEditor(document);
