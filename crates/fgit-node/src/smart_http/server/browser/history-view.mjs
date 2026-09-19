import { HistoryClient } from './history.mjs';
import { bytePath } from './history-data.mjs';
import { decimal, text, utf8, hex, unhex } from './pulls-core.mjs';
const LINE_PAGE = 200, PREVIEW_BYTES = 65536;
const visible = value => String(value).replace(/[\u0000-\u0008\u000b-\u001f\u007f-\u009f\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069]/gu,
  char => `\\u{${char.codePointAt(0).toString(16)}}`);
export function bytePreview(encoded, maximum = PREVIEW_BYTES) {
  const bytes = unhex(encoded), prefix = bytes.subarray(0, maximum);
  let value;
  try { value = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(prefix); }
  catch { value = `Raw hex bytes:\n${hex(prefix)}`; }
  return visible(value) + (prefix.length < bytes.length ? `\n[Preview clipped at ${prefix.length} of ${bytes.length} bytes; download the validated response for this range.]` : '');
}
function pathLabel(path) { return path === null ? '/' : `${bytePreview(path, 4096)} [hex:${path}]`; }
function components(path) {
  if (path === null) return [];
  const bytes = unhex(path); let at = 0; const parts = [];
  for (let i = 0; i <= bytes.length; i++) if (i === bytes.length || bytes[i] === 47) { parts.push(hex(bytes.subarray(at, i))); at = i + 1; }
  return parts;
}
export function mountHistory(doc, options = {}) {
  const client = options.client ?? new HistoryClient({ href: options.href ?? globalThis.location.href, fetchImpl: options.fetchImpl, cryptoImpl: options.cryptoImpl });
  const get = id => { const node = doc.getElementById(id); if (!node) throw new Error(`Missing history control ${id}`); return node; };
  const ids = ['connect', 'token', 'ref', 'format', 'open', 'disconnect', 'snapshot', 'query', 'path', 'path-kind', 'limit',
    'log', 'first', 'end', 'blame', 'status', 'cancel', 'download', 'breadcrumbs', 'content', 'paging'];
  const ui = Object.fromEntries(ids.map(id => [id, get(`history-${id}`)]));
  let revision = 0, raw = null;
  const node = (tag, value) => { const n = doc.createElement(tag); if (value !== undefined) n.textContent = visible(value); return n; };
  function button(label, action) {
    const n = node('button', label), current = revision; n.type = 'button';
    n.addEventListener('click', () => { if (current === revision) return action(); }); return n;
  }
  function clear() { raw = null; for (const id of ['content', 'paging', 'breadcrumbs']) ui[id].replaceChildren(); ui.download.disabled = true; }
  function sync() {
    const selected = client.selection;
    ui.snapshot.textContent = selected ? `Reference: ${visible(selected.ref)}\nFormat: ${selected.object_format}\nRepository: ${selected.scope.repository}\nIncarnation: ${selected.scope.incarnation}\nAuthority snapshot: ${selected.head}\nCurrent ref tip: ${selected.tip}` : '';
    for (const id of ['log', 'blame']) ui[id].disabled = !selected;
    ui.open.disabled = !client.connected;
  }
  function forgetInputs() { for (const id of ['token', 'ref', 'path', 'end']) ui[id].value = ''; ui.first.value = '0'; }
  function disconnect() { revision++; client.disconnect(); clear(); forgetInputs(); sync(); ui.status.textContent = 'Disconnected. Token and displayed repository data cleared.'; }
  function cancel() { revision++; client.cancel(); clear(); sync(); ui.status.textContent = 'Read cancelled; no repository mutation was attempted.'; }
  async function run(work, render, keepBlame = false) {
    const current = ++revision; if (!keepBlame) client.cancel(); clear(); sync(); ui.status.textContent = 'Reading and checking one pinned repository snapshot…';
    try {
      const result = await work(); if (revision !== current) return;
      render(result); raw = result.raw; ui.download.disabled = false; sync();
    } catch (error) {
      if (revision !== current) return;
      client.cancel(); clear(); if (!client.connected) forgetInputs(); sync(); ui.status.textContent = error.message;
    }
  }
  function path(root = false) {
    if (root && ui.path.value === '') return null;
    if (!['text', 'hex'].includes(ui['path-kind'].value)) throw new Error('Choose a path encoding.');
    return bytePath(ui['path-kind'].value === 'hex' ? ui.path.value : hex(utf8.encode(text(ui.path.value, 4096, 'repository path'))));
  }
  function commitView(commit) {
    const section = node('article'); section.append(node('h3', commit.id), node('pre', bytePreview(commit.message_hex, 4096)));
    const details = node('details'); details.append(node('summary', 'Exact commit body — identities are untrusted claims'), node('pre', bytePreview(commit.body_hex, 8192)));
    section.append(details, button('Browse this commit tree', () => historical('tree', commit.id)));
    return section;
  }
  function renderLog(result) {
    ui.content.append(node('h2', result.path_hex === null ? 'Commit ancestry' : `Exact path history: ${pathLabel(result.path_hex)}`),
      node('p', `${result.total} ${result.path_hex === null ? 'reachable' : 'matching-path'} commits; showing ${result.after}–${result.after + result.commits.length} (zero-based, end exclusive). Native commit IDs checked; author identities are not authenticated.`));
    for (const commit of result.commits) ui.content.append(commitView(commit));
    if (!result.commits.length) ui.content.append(node('p', 'No matching commits on this complete snapshot page.'));
    if (result.after > 0) ui.paging.append(button('Previous history page', () => log({ path_hex: result.path_hex, limit: result.limit, after: Math.max(0, result.after - result.limit) })));
    if (result.next !== null) ui.paging.append(button('Next history page', () => log({ path_hex: result.path_hex, limit: result.limit, after: result.next })));
    ui.status.textContent = 'History page checked. Continuations retain its exact path filter, snapshot, and current ref tip.';
  }
  function renderBlame(result, offset = 0) {
    clear(); raw = result.raw; ui.download.disabled = false;
    ui.content.append(node('h2', `Line provenance: ${pathLabel(result.query.path_hex)}`),
      node('p', `Native range [${result.query.first}, ${result.raw.end_line}) of ${result.total} lines. ${result.fullBlobVerified ? 'Complete-file blob identity checked.' : 'Partial range: no complete-file blob hash claim.'} Same path, all parents; identities are unauthenticated.`));
    const end = Math.min(offset + LINE_PAGE, result.lines.length), table = node('table'), header = node('tr');
    header.append(node('th', 'Line (zero-based)'), node('th', 'Exact content'), node('th', 'Origin commit / line')); table.append(header);
    const origins = new Map(result.origins.map(value => [value.id, value]));
    for (let i = offset; i < end; i++) {
      const line = result.lines[i], row = node('tr'), content = node('td'), origin = node('td');
      content.append(node('pre', bytePreview(line.content_hex)));
      origin.append(button(`Verify origin ${line.origin_commit.slice(0, 12)}:${line.origin_line}`, () => run(() => client.origin(i), renderSource, true)),
        node('pre', bytePreview(origins.get(line.origin_commit).message_hex, 512)));
      row.append(node('td', line.line), content, origin); table.append(row);
    }
    ui.content.append(table);
    if (!result.lines.length) ui.content.append(node('p', 'The requested complete line range is empty.'));
    if (offset > 0) ui.paging.append(button('Previous blame rows', () => renderBlame(result, Math.max(0, offset - LINE_PAGE))));
    if (end < result.lines.length) ui.paging.append(button('Next blame rows', () => renderBlame(result, end)));
    ui.status.textContent = `Displaying ${offset}–${end} of ${result.lines.length} validated attribution rows. Origin buttons re-read historical bytes through the same authorized ref.`;
  }
  function renderSource(result) {
    const { query, source } = result;
    ui.content.append(node('h2', `Historical source: ${pathLabel(query.path_hex)}`), node('p', `Historical commit: ${query.commit}`),
      node('p', `Object: ${source.object_id}. Current ref tip remains ${result.selection.tip}.`));
    ui.breadcrumbs.append(button('Commit root', () => historical('tree', query.commit)));
    const parts = components(query.path_hex); let parent = null;
    for (let i = 0; i < parts.length - (query.kind === 'blob' ? 1 : 0); i++) {
      parent = parent === null ? parts[i] : `${parent}2f${parts[i]}`;
      const fixed = parent; ui.breadcrumbs.append(button(bytePreview(parts[i], 4096), () => historical('tree', query.commit, fixed)));
    }
    if (query.kind === 'tree') {
      const table = node('table');
      for (const entry of source.entries) {
        const path = query.path_hex === null ? entry.name_hex : `${query.path_hex}2f${entry.name_hex}`, row = node('tr'), name = node('td');
        if (entry.kind === 'gitlink') name.append(node('span', `${pathLabel(entry.name_hex)} — gitlink not followed`));
        else name.append(button(pathLabel(entry.name_hex), () => historical(entry.kind === 'directory' ? 'tree' : 'blob', query.commit, path)));
        row.append(name, node('td', entry.kind), node('td', entry.object_id)); table.append(row);
      }
      ui.content.append(table);
      if (!source.entries.length) ui.content.append(node('p', 'No directory entries on this snapshot page.'));
      if (source.next_after_hex !== null) ui.paging.append(button('Next directory page', () => historical('tree', query.commit, query.path_hex, { after: source.next_after_hex, limit: query.limit })));
    } else {
      ui.content.append(node('p', `Bytes [${source.offset}, ${source.offset + source.returned_bytes}) of ${source.total_bytes}. ${source.kind === 'symlink' ? 'Symlink payload only; never followed.' : 'Native file range.'}`),
        node('pre', bytePreview(source.content_hex)));
      if (result.originBytesVerified) ui.content.append(node('p', `Historical origin bytes reproduce the attributed line ${result.attribution.line} exactly.`),
        button('Open origin file from beginning', () => historical('blob', query.commit, query.path_hex)));
      if (source.next_offset !== null) ui.paging.append(button('Next file range', () => historical('blob', query.commit, query.path_hex, { offset: source.next_offset, limit: query.limit })));
    }
    ui.status.textContent = result.originBytesVerified ? 'Exact attributed origin bytes checked at the historical commit.' : 'Historical source checked without changing the selected ref snapshot.';
  }
  const log = options => run(() => client.log(options), renderLog);
  const historical = (kind, commit, path = null, options = {}) => run(() => client.historical(kind, commit, path, options), renderSource);
  const open = () => run(() => client.open(ui.ref.value, ui.format.value), renderLog);
  ui.connect.addEventListener('submit', event => {
    event.preventDefault(); const token = ui.token.value; ui.token.value = '';
    try { client.connect(token); return open(); } catch (error) { disconnect(); ui.status.textContent = error.message; }
  });
  ui.open.addEventListener('click', open);
  ui.disconnect.addEventListener('click', disconnect); ui.cancel.addEventListener('click', cancel);
  ui.query.addEventListener('submit', event => {
    event.preventDefault(); return run(() => client.log({ path_hex: path(true), limit: decimal(ui.limit.value, 'history page size', 1) }), renderLog);
  });
  ui.blame.addEventListener('click', () => run(() => client.blame(path(), { first: decimal(ui.first.value, 'first line'),
    end: ui.end.value === '' ? null : decimal(ui.end.value, 'end line') }), renderBlame));
  ui.download.addEventListener('click', () => {
    if (!raw) return;
    const encoded = JSON.stringify(raw);
    if (options.download) options.download(encoded);
    else {
      const url = URL.createObjectURL(new Blob([encoded], { type: 'application/json' })), link = doc.createElement('a');
      link.href = url; link.download = 'frankengit-history.json'; doc.body.append(link); link.click(); link.remove();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
    }
  });
  (options.events ?? globalThis).addEventListener?.('pagehide', disconnect);
  sync(); return { client, open, log, historical, cancel, disconnect };
}
if (typeof document !== 'undefined') mountHistory(document);
