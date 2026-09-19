// Human-driven native replay. Inert views and bounded file reads never replace
// native source authorization, conflict construction, or publication admission.
import { ReplayClient } from './replay.mjs';
import { decimal, utf8, unhex, hex, text } from './pulls-core.mjs';
import { FILE_LIMIT, RESOLUTION_LIMIT, CONFLICT_LIMIT } from './replay-protocol.mjs';
import { RECEIPT_LIMIT } from './pulls-actions.mjs';

export function displayText(value) {
  return String(value).replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069]/gu,
    c => `\\u{${c.codePointAt(0).toString(16)}}`);
}
function byteLabel(encoded, maximum = 4096) {
  const bytes = unhex(encoded, maximum);
  try { return displayText(new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes)); }
  catch { return `hex:${encoded}`; }
}
function fileSize(file, maximum) {
  if (!file || !Number.isSafeInteger(file.size) || file.size < 0 || file.size > maximum) throw new Error('Select a file within the declared byte limit.');
  return file.size;
}
export async function readChosenFile(file, maximum, current = () => true) {
  const size = fileSize(file, maximum);
  if (!current()) throw new Error('File selection cancelled.');
  const bytes = await file.arrayBuffer();
  if (!current()) throw new Error('File selection cancelled or replaced.');
  if (!(bytes instanceof ArrayBuffer) || bytes.byteLength !== size || bytes.byteLength > maximum) throw new Error('File bytes do not match the selected size.');
  return new Uint8Array(bytes);
}
// Capture every choice, text, mode, File and total declared size before any I/O.
// Binary uploads retain exact bytes. Text mode deliberately selects LF or CRLF.
export async function collectResolutions(rows, current = () => true) {
  if (!Array.isArray(rows) || !rows.length || rows.length > CONFLICT_LIMIT) throw new Error('Choose a bounded nonempty conflict set.');
  let total = 0;
  const selected = rows.map(row => {
    const choice = row.choice.value;
    if (!['base', 'ours', 'theirs', 'delete', 'file'].includes(choice)) throw new Error('Choose one explicit resolution for every conflict.');
    const result = { path_hex: row.path, choice };
    if (choice === 'file') {
      if (!['100644', '100755'].includes(row.mode.value)) throw new Error('Choose a regular or executable file mode.');
      result.mode = Number.parseInt(row.mode.value, 8);
      if (row.inputKind.value === 'upload') {
        result.file = row.file.files?.[0]; total += fileSize(result.file, FILE_LIMIT);
      } else if (['lf', 'crlf'].includes(row.inputKind.value)) {
        let value = text(row.text.value, FILE_LIMIT, 'resolution text').replace(/\r\n|\r/g, '\n');
        if (row.inputKind.value === 'crlf') value = value.replace(/\n/g, '\r\n');
        result.bytes = utf8.encode(value);
        if (result.bytes.length > FILE_LIMIT) throw new Error('Resolution text exceeds the file byte limit.');
        total += result.bytes.length;
      } else throw new Error('Choose a byte upload or explicit newline mode.');
    }
    if (total > RESOLUTION_LIMIT) throw new Error('Resolution files exceed the aggregate 1 MiB byte limit.');
    return result;
  });
  for (const item of selected) {
    if (!current()) throw new Error('Conflict selection changed.');
    if (item.file) { item.bytes = await readChosenFile(item.file, FILE_LIMIT, current); delete item.file; }
  }
  return selected;
}

export function mountReplay(doc, options = {}) {
  const client = options.client ?? new ReplayClient({ href: options.href ?? globalThis.location.href });
  const ids = ['token', 'connect', 'disconnect', 'cancel', 'target', 'source', 'format', 'select', 'selection',
    'direction', 'commit', 'mainline', 'author', 'committer', 'timestamp', 'message', 'prepare', 'report',
    'conflicts', 'resolve', 'candidate', 'stage', 'confirm', 'send', 'recover', 'discard', 'pending',
    'save-receipt', 'receipt-file', 'restore', 'status'];
  const controls = Object.fromEntries(ids.map(id => {
    const e = doc.getElementById(id); if (!e) throw new Error(`Missing replay control ${id}`); return [id, e];
  }));
  const events = options.events ?? globalThis, urls = options.urls ?? globalThis.URL;
  const node = (tag, value) => { const e = doc.createElement(tag); if (value !== undefined) e.textContent = displayText(value); return e; };
  const status = value => { controls.status.textContent = displayText(value); };
  const select = choices => {
    const e = node('select');
    for (const [value, label] of choices) { const o = node('option', label); o.value = value; e.append(o); }
    e.value = choices[0][0]; return e;
  };
  const label = (title, e) => { const wrapper = node('label', title); wrapper.append(e); return wrapper; };
  let busy = false, revision = 0, rows = [], download = null;
  function revoke() { if (download !== null) { urls.revokeObjectURL(download); download = null; } }
  function clearViews() {
    rows = []; controls.selection.textContent = ''; controls.report.textContent = '';
    controls.conflicts.replaceChildren(); controls.candidate.replaceChildren(); controls.confirm.checked = false;
  }
  function clearPrivate() {
    clearViews(); revoke(); controls.token.value = ''; controls['receipt-file'].value = '';
    for (const id of ['commit', 'author', 'committer', 'timestamp', 'message', 'mainline']) controls[id].value = '';
  }
  function render() {
    const connected = client.connected, pending = client.pending;
    for (const id of ['target', 'source', 'format', 'direction', 'commit', 'mainline', 'author', 'committer', 'timestamp', 'message']) controls[id].disabled = busy || !connected || !!pending;
    controls.connect.disabled = busy; controls.token.disabled = busy;
    controls.select.disabled = busy || !connected || !!pending;
    controls.prepare.disabled = busy || !connected || !!pending || !client.selection;
    controls.resolve.disabled = busy || !connected || !!pending || client.report?.state !== 'conflicted';
    controls.stage.disabled = busy || !connected || !!pending || !client.candidate;
    controls.send.disabled = busy || !connected || !pending;
    controls.recover.disabled = busy || !connected || !pending;
    controls.discard.disabled = busy || !pending || pending.sent || pending.exported;
    controls.confirm.disabled = busy || !pending || !connected;
    controls['save-receipt'].disabled = busy || !pending;
    controls['receipt-file'].disabled = busy || !connected || !!pending;
    controls.restore.disabled = busy || !connected || !!pending;
    controls.pending.textContent = pending ? displayText(JSON.stringify(pending, null, 2)) : 'No outstanding publication.';
    for (const row of rows) {
      const disabled = busy || !connected || !!pending;
      row.choice.disabled = disabled; row.mode.disabled = disabled || row.choice.value !== 'file';
      row.inputKind.disabled = disabled || row.choice.value !== 'file';
      row.file.disabled = disabled || row.choice.value !== 'file' || row.inputKind.value !== 'upload';
      row.text.disabled = disabled || row.choice.value !== 'file' || row.inputKind.value === 'upload';
    }
  }
  async function perform(work) {
    if (busy) return; busy = true; render();
    try { await work(); }
    catch (error) { status(`${error.outcomeUnknown ? 'Outcome unknown; keep the original key and recover or explicitly retry. ' : ''}${error.message}`); }
    finally { busy = false; if (!client.connected) clearPrivate(); render(); }
  }
  function changed(resetSelection = false) {
    revision++; if (resetSelection) client.cancel(); else client.invalidate();
    clearViews(); if (!resetSelection && client.selection) controls.selection.textContent = displayText(JSON.stringify(client.selection, null, 2));
    render(); status(resetSelection ? 'Select the new branches explicitly.' : 'Replay inputs changed; prepare again. Nothing was published.');
  }
  function resultView() {
    controls.selection.textContent = client.selection ? displayText(JSON.stringify(client.selection, null, 2)) : '';
    const report = client.report; controls.report.textContent = report ? displayText(JSON.stringify({ direction: report.direction, state: report.state,
      target: report.expected_target, source: report.expected_source, selected_commit: report.selected_commit,
      selected_parent: report.selected_parent, mainline: report.selected_mainline, snapshot: report.snapshot_token }, null, 2)) : '';
    controls.conflicts.replaceChildren(); controls.candidate.replaceChildren(); rows = [];
    if (report?.state === 'conflicted') {
      const names = report.direction === 'revert' ? { base: 'Base: selected commit', theirs: 'Theirs: selected parent (undo side)' }
        : { base: 'Base: selected parent', theirs: 'Theirs: selected commit (apply side)' };
      for (const c of report.conflicts) {
        const section = node('section'), choice = select([['', 'Choose deliberately'], ['base', names.base], ['ours', 'Ours: current destination'], ['theirs', names.theirs], ['delete', 'Delete path'], ['file', 'Resolved regular file']]);
        const mode = select([['100644', 'Regular file'], ['100755', 'Executable file']]), inputKind = select([['upload', 'Exact byte upload'], ['lf', 'UTF-8 text with LF'], ['crlf', 'UTF-8 text with CRLF']]);
        const file = node('input'); file.type = 'file'; const textarea = node('textarea'); textarea.maxLength = FILE_LIMIT;
        const row = { path: c.path_hex, choice, mode, inputKind, file, text: textarea }; rows.push(row);
        section.append(node('h3', `${c.kind}: ${byteLabel(c.path_hex)} [hex:${c.path_hex}]`));
        for (const [key, title] of [['base', names.base], ['ours', 'Ours: current destination'], ['theirs', names.theirs]]) {
          const side = c[key]; section.append(node('p', `${title}: ${side ? `${side.oid} (mode ${side.mode.toString(8)})` : 'absent; cannot select as deletion'}`));
        }
        for (const [title, e] of [['Resolution', choice], ['File mode', mode], ['File input', inputKind], ['Exact content', file], ['Text content', textarea]]) section.append(label(title, e));
        for (const e of [choice, mode, inputKind, file, textarea]) for (const event of ['input', 'change']) e.addEventListener(event, () => {
          if (!rows.includes(row) || client.pending) return;
          revision++; controls.confirm.checked = false;
          if (busy) { client.invalidate(); clearViews(); status('Conflict inputs changed during work; prepare the replay again.'); }
          render();
        });
        controls.conflicts.append(section);
      }
    }
    const candidate = client.candidate;
    if (candidate) {
      controls.candidate.append(node('pre', JSON.stringify({ direction: candidate.direction, ...candidate.fields,
        bundle_sha256: candidate.sha256, bundle_bytes: candidate.bundleBytes, publication_authorized: false }, null, 2)));
      let previewBytes = 0;
      for (const entry of candidate.inspection.comparison.entries) {
        const section = node('section'); section.append(node('h3', `${entry.kind}: ${byteLabel(entry.path_hex)} [hex:${entry.path_hex}]`));
        section.append(node('p', `Before ${entry.before?.oid ?? 'absent'} (${entry.before?.mode?.toString(8) ?? '-'}); after ${entry.after?.oid ?? 'absent'} (${entry.after?.mode?.toString(8) ?? '-'})`));
        if (entry.content.type === 'text') {
          for (const h of entry.content.hunks) {
            const size = (h.before_hex.length + h.after_hex.length) / 2;
            if (previewBytes + size > 256 * 1024) { section.append(node('p', 'Text preview limit reached; remaining text is not displayed. Path identities remain above.')); break; }
            previewBytes += size;
            section.append(node('p', `Old ${h.old.line_start}+${h.old.line_count}; new ${h.new.line_start}+${h.new.line_count}`),
              node('pre', byteLabel(h.before_hex, 256 * 1024)), node('pre', byteLabel(h.after_hex, 256 * 1024)));
          }
        } else section.append(node('p', `${entry.content.type}: full binary or opaque content is not included in this inspection.`));
        controls.candidate.append(section);
      }
    }
    render();
  }
  controls.connect.addEventListener('click', () => perform(async () => {
    const token = controls.token.value; revision++; clearPrivate(); await client.connect(token);
    status('Connected. Select both branches at one snapshot, or restore an existing publication.');
  }));
  function disconnect() { revision++; client.disconnect(); clearPrivate(); render(); status(client.pending ? 'Disconnected; original publication responsibility remains. Save its recovery file.' : 'Disconnected; credentials and replay data cleared.'); }
  controls.disconnect.addEventListener('click', disconnect);
  controls.cancel.addEventListener('click', () => { revision++; client.cancel(); clearViews(); render(); status('Read work cancelled. Any pending publication remains recoverable.'); });
  for (const id of ['target', 'source', 'format']) for (const event of ['input', 'change']) controls[id].addEventListener(event, () => changed(true));
  for (const id of ['direction', 'commit', 'mainline', 'author', 'committer', 'timestamp', 'message']) for (const event of ['input', 'change']) controls[id].addEventListener(event, () => changed());
  controls.select.addEventListener('click', () => perform(async () => {
    revision++; clearViews(); const s = await client.select(controls.target.value, controls.source.value, controls.format.value);
    controls.selection.textContent = displayText(JSON.stringify(s, null, 2)); status('Both branch tips are pinned. Choose the exact commit to replay.');
  }));
  controls.prepare.addEventListener('click', () => perform(async () => {
    const input = { commit: controls.commit.value, author: controls.author.value, committer: controls.committer.value,
      timestamp: decimal(controls.timestamp.value, 'timestamp'), message: controls.message.value };
    if (controls.mainline.value !== '') input.mainline = decimal(controls.mainline.value, 'mainline', 1);
    revision++; clearViews(); await client.prepare(controls.direction.value, input); resultView();
    status(client.report.state === 'conflicted' ? 'Conflicts require explicit per-path choices. Nothing was published.' : client.report.state === 'no_change' ? 'Native replay produced no tree change. No candidate or transaction was created.' : 'Candidate prepared and inspected. Review every path before preparing publication.');
  }));
  controls.resolve.addEventListener('click', () => perform(async () => {
    const started = revision, selectedRows = [...rows];
    const choices = await collectResolutions(selectedRows, () => started === revision && client.connected);
    if (started !== revision) throw new Error('Resolution selection changed.');
    await client.resolve(choices); resultView();
    status(client.report.state === 'no_change' ? 'Resolutions produced no tree change; no publication is available.' : 'Native resolution and candidate inspection completed. Review the resulting changes before publication.');
  }));
  controls.stage.addEventListener('click', () => perform(async () => { await client.stageApply(); controls.confirm.checked = false; status('Publication prepared locally. Check the exact branch, old tip, candidate and original key, then confirm Send.'); }));
  controls.send.addEventListener('click', () => perform(async () => {
    if (!controls.confirm.checked) throw new Error('Confirm the displayed exact publication before sending or retrying.');
    controls.confirm.checked = false; const result = await client.send(); clearViews(); status(`Canonical ${result.outcome}: ${result.rcr ?? result.refusal}.`);
  }));
  controls.recover.addEventListener('click', () => perform(async () => {
    const result = await client.recover(); if (result.terminal) clearViews();
    status(result.terminal ? `Canonical ${result.outcome}: ${result.rcr ?? result.refusal}.` : 'Outcome is still unknown. Keep the original request; absence does not prove rollback.');
  }));
  controls.discard.addEventListener('click', () => perform(async () => { client.discardUnsent(); controls.confirm.checked = false; status('Unsent, unexported request discarded.'); }));
  controls['save-receipt'].addEventListener('click', () => perform(async () => {
    const encoded = client.exportReceipt();
    if (options.saveReceipt) await options.saveReceipt(encoded);
    else {
      revoke(); download = urls.createObjectURL(new Blob([encoded], { type: 'application/json' }));
      const a = node('a'); a.href = download; a.download = 'replay-publication.retry.json'; a.click();
      const current = download; (options.schedule ?? globalThis.setTimeout)(() => { if (download === current) revoke(); }, 1000);
    }
    status('Original request saved without its token. Protect the recovery file: it contains repository bytes.');
  }));
  controls['receipt-file'].addEventListener('change', () => { revision++; if (busy) client.invalidate(); });
  controls.restore.addEventListener('click', () => perform(async () => {
    const started = revision, file = controls['receipt-file'].files?.[0];
    const bytes = await readChosenFile(file, RECEIPT_LIMIT, () => started === revision && client.connected);
    const encoded = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes);
    await client.restoreReceipt(encoded); clearViews(); controls['receipt-file'].value = '';
    status('Original publication restored without sending. Recover its outcome or explicitly confirm an unchanged retry.');
  }));
  events.addEventListener?.('beforeunload', e => { if (client.pending) { e.preventDefault(); e.returnValue = ''; } });
  events.addEventListener?.('pagehide', disconnect);
  render();
  return { client, get conflictControls() { return [...rows]; } };
}
if (typeof document !== 'undefined') mountReplay(document);
