import { TagClient, RETRY_LIMIT } from './tags.mjs';
import { refInput, decode } from './tags-protocol.mjs';
import { decimal, text, hex, unhex, utf8 } from './pulls-core.mjs';
const visible = value => value.replace(/[\u0000-\u0008\u000b-\u001f\u007f-\u009f\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069]/g, c => `\\u${c.charCodeAt(0).toString(16).padStart(4, '0')}`);
export function displayBytes(encoded, maximum = 32768) {
  const bytes = unhex(encoded), slice = bytes.subarray(0, maximum); let value;
  try { value = decode(slice).replace(/[\u0000-\u0008\u000b-\u001f\u007f-\u009f\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069]/g,
    c => `\\u${c.charCodeAt(0).toString(16).padStart(4, '0')}`); }
  catch { value = `hex:${hex(slice)}`; }
  return value + (slice.length < bytes.length ? `\n[Preview: ${slice.length} of ${bytes.length} bytes]` : '');
}
export function mountTags(document, window, client = new TagClient({ href: window.location.href }), saveImpl = null) {
  const el = id => document.getElementById(id), tagPrefix = hex(utf8.encode('refs/tags/'));
  let busy = false, epoch = 0, fileEpoch = 0, dirty = false; const urls = new Set();
  const status = message => { el('status').textContent = message; };
  function releaseUrls() { for (const url of urls) window.URL.revokeObjectURL(url); urls.clear(); }
  function save(name, content, type) {
    if (saveImpl) return saveImpl(name, content, type);
    releaseUrls(); const url = window.URL.createObjectURL(new Blob([content], { type })); urls.add(url);
    const a = document.createElement('a'); a.href = url; a.download = name; document.body.append(a);
    try { a.click(); } finally { a.remove(); window.setTimeout(() => { if (urls.delete(url)) window.URL.revokeObjectURL(url); }, 1000); }
  }
  function options(id, rows) {
    const selected = el(id).value; el(id).replaceChildren();
    const placeholder = document.createElement('option'); placeholder.value = ''; placeholder.textContent = 'Choose an exact reference'; el(id).append(placeholder);
    for (const row of rows) {
      const option = document.createElement('option'); option.value = row.ref_hex;
      option.textContent = `${displayBytes(row.ref_hex, 4096)} · ${row.object_id}`; el(id).append(option);
    }
    el(id).value = rows.some(r => r.ref_hex === selected) ? selected : '';
  }
  function render() {
    const p = client.pending, page = client.page, rows = client.refs, active = client.connected && !busy;
    options('source', rows); options('tag', rows.filter(row => row.ref_hex.startsWith(tagPrefix)));
    el('snapshot').textContent = page ? `${page.snapshot_token} · ${rows.length} references loaded${page.next_after === null ? ' · end of listing' : ' · more references remain'}` : 'No selected reference snapshot.';
    for (const id of ['load', 'prepare', 'inspect']) el(id).disabled = !active || Boolean(p) || (id !== 'load' && !page);
    el('next').disabled = !active || Boolean(p) || !page || page.next_after === null;
    el('send').disabled = !active || !p || !el('confirm').checked;
    el('recover').disabled = !active || !p;
    el('save').disabled = busy || !p;
    el('restore').disabled = !active || Boolean(p);
    el('discard').disabled = busy || !p || p.sent || p.exported;
    el('pending').textContent = p ? visible(JSON.stringify({ operation: p.operation, name: displayBytes(p.fields.ref_hex, 4096), ref_hex: p.fields.ref_hex,
      annotation_preview: p.body_hex === null ? null : displayBytes(p.body_hex),
      object_format: p.scope.format, expected_object: p.expected_object, new_object: p.new_object, fields: p.fields,
      original_key: p.key, sent: p.sent, exported: p.exported }, null, 2)) : 'No saved request.';
    el('inspection').replaceChildren();
    const inspection = client.inspection;
    if (inspection) {
      const summary = document.createElement('p');
      summary.textContent = `Direct ${inspection.object_id} → ${inspection.peeled_kind} ${inspection.peeled_object}. ${inspection.annotation_count} annotation(s). Signatures and tagger identity are NOT authenticated.`;
      el('inspection').append(summary);
      for (const annotation of inspection.annotations) {
        const detail = document.createElement('details'), heading = document.createElement('summary'), body = document.createElement('pre'), download = document.createElement('button');
        heading.textContent = `${annotation.object_id} · ${annotation.body_bytes} bytes · signature: ${annotation.signature} (not verified)`;
        body.textContent = displayBytes(annotation.body_hex); download.type = 'button'; download.textContent = 'Save original tag object bytes';
        const expectedEpoch = epoch;
        download.addEventListener('click', () => {
          if (expectedEpoch === epoch && client.connected && client.inspection?.object_id === inspection.object_id) save(`${annotation.object_id}.tag`, unhex(annotation.body_hex), 'application/octet-stream');
        });
        detail.append(heading, body, download); el('inspection').append(detail);
      }
    }
  }
  async function run(work) {
    if (busy) return;
    busy = true; const current = epoch; render();
    try { const message = await work(); if (epoch === current && message) status(message); }
    catch (error) { if (epoch === current) status(`${error.outcomeUnknown ? 'Outcome unknown; original request retained. ' : ''}${error.message}`); }
    finally { busy = false; render(); }
  }
  const click = (id, work) => el(id).addEventListener('click', () => run(work));
  el('connection').addEventListener('submit', event => { event.preventDefault(); if (busy) return;
    const token = el('token').value; el('token').value = '';
    return run(async () => { await client.connect(token); return 'Connected. Load references or restore an original request.'; });
  });
  click('load', async () => { await client.list({ objectFormat: el('format').value }); return 'Reference snapshot loaded; selection grants no write permission.'; });
  click('next', async () => { await client.list({ next: true }); return 'Continuation loaded at the same snapshot.'; });
  click('inspect', async () => { await client.inspect(el('tag').value); return 'Tag annotation bytes checked. Signature trust and final object verification remain native concerns.'; });
  click('prepare', async () => {
    el('confirm').checked = false; const operation = el('operation').value;
    const input = operation === 'delete' ? { ref_hex: el('tag').value } : { ref_hex: refInput(el('destination').value, el('name-encoding').value === 'hex'), source_ref_hex: el('source').value };
    if (operation === 'annotated') {
      const value = el('message').value, encoding = el('message-encoding').value;
      const message_hex = encoding === 'hex' ? value : hex(utf8.encode(text(encoding === 'crlf' ? value.replace(/\r\n|\r|\n/g, '\r\n') : value, 65536, 'tag message')));
      Object.assign(input, { target_kind: el('kind').value, tagger: el('tagger').value, timestamp: decimal(el('timestamp').value, 'timestamp'), message_hex });
    }
    await client.prepare(operation, input); dirty = false;
    return 'Prepared locally. Review the saved command, then separately confirm and send. Nothing was published.';
  });
  click('send', async () => {
    if (!el('confirm').checked) throw new Error('Confirm the saved command before sending.');
    el('confirm').checked = false;
    const r = await client.send(); return `Native tag decision: ${r.outcome}; transaction ${r.tx}${r.refusal ? `; ${r.refusal}` : ''}. Reload refs explicitly.`;
  });
  click('recover', async () => {
    el('confirm').checked = false; const r = await client.recover();
    return r.terminal ? `Recovered native decision: ${r.outcome}; transaction ${r.tx}.` : `Outcome remains unknown (${r.state}); keep the original request.`;
  });
  click('discard', () => { client.discardUnsent(); el('confirm').checked = false; return 'Unsent, unexported local request discarded.'; });
  click('save', () => { const receipt = client.exportReceipt(); save('repository.tag-retry.json', receipt, 'application/json'); return 'Retry file offered for download. It contains metadata but no token; keep the original request.'; });
  click('restore', async () => {
    const file = el('receipt').files?.[0], selected = fileEpoch, current = epoch;
    if (!file || !Number.isSafeInteger(file.size) || file.size < 1 || file.size > RETRY_LIMIT) throw new Error('Select a retry file of at most 256 KiB.');
    const encoded = await file.text();
    if (current !== epoch || selected !== fileEpoch || el('receipt').files?.[0] !== file) throw new Error('Recovery file selection changed.');
    await client.restoreReceipt(encoded); el('confirm').checked = false; el('receipt').value = '';
    return 'Original request restored without sending or re-reading reference tips.';
  });
  const reset = disconnect => {
    epoch++; fileEpoch++; releaseUrls(); el('confirm').checked = false;
    if (disconnect) { client.disconnect(); for (const id of ['token', 'message', 'destination', 'tagger', 'timestamp', 'receipt']) el(id).value = ''; dirty = false; }
    else client.cancel();
    render(); status(disconnect ? 'Disconnected; any original saved request remains recoverable.' : 'Reads cancelled. Any original publication request is unchanged.');
  };
  el('disconnect').addEventListener('click', () => reset(true)); el('cancel').addEventListener('click', () => reset(false));
  el('confirm').addEventListener('change', render);
  el('receipt').addEventListener('change', () => { fileEpoch++; el('confirm').checked = false; if (busy && !client.pending) client.cancel(); render(); });
  for (const id of ['format', 'source', 'tag', 'operation', 'destination', 'name-encoding', 'kind', 'tagger', 'timestamp', 'message', 'message-encoding']) {
    el(id).addEventListener('input', () => {
      dirty = true; el('confirm').checked = false;
      if (busy && !client.pending) client.cancel();
      if (client.pending) status('Editors changed; the saved command is unchanged. Discard only unsent, unexported work to prepare different details.');
      render();
    });
  }
  window.addEventListener('pagehide', () => reset(true));
  window.addEventListener('beforeunload', event => { if (client.pending || dirty) { event.preventDefault(); event.returnValue = ''; } });
  render(); return { client, render };
}
if (typeof document !== 'undefined' && typeof window !== 'undefined') mountTags(document, window);
