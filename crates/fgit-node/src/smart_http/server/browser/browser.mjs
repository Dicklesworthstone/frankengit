// No framework, remote dependencies, HTML interpolation, or persistent credentials.
export const MAX_RESPONSE_BYTES = 8 * 1024 * 1024;
const PAGE_BYTES = 64 * 1024;
const encoder = new TextEncoder();
const utf8 = () => new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });

export function unhex(value, maximum = MAX_RESPONSE_BYTES) {
  if (typeof value !== 'string' || value.length % 2 || value.length > maximum * 2 || !/^[0-9a-f]*$/.test(value)) {
    throw new Error('Invalid byte encoding in repository response.');
  }
  return Uint8Array.from(value.match(/../g) ?? [], pair => Number.parseInt(pair, 16));
}
export function hex(bytes) {
  return Array.from(bytes, byte => byte.toString(16).padStart(2, '0')).join('');
}
export function displayBytes(value) {
  const bytes = unhex(value);
  try {
    return utf8().decode(bytes).replace(/[\u0000-\u001f\u007f-\u009f\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069]/gu,
      character => `\\u{${character.codePointAt(0).toString(16)}}`);
  } catch {
    return Array.from(bytes, byte => byte >= 32 && byte <= 126
      ? String.fromCharCode(byte) : `\\x${byte.toString(16).padStart(2, '0')}`).join('');
  }
}
export function pathJoin(parent, name) {
  unhex(parent, 4096);
  const bytes = unhex(name, 4096);
  if (!bytes.length || bytes.includes(0) || bytes.includes(47) || name === '2e' || name === '2e2e') {
    throw new Error('Invalid directory entry name.');
  }
  const result = parent ? `${parent}2f${name}` : name;
  unhex(result, 4096);
  return result;
}
export function safeNumber(value, field) {
  if (!Number.isSafeInteger(value) || value < 0) throw new Error(`Unsupported or invalid ${field}.`);
  return value;
}
export function commitHex(value, format) {
  if (typeof value !== 'string') throw new Error('Missing selected commit.');
  const raw = value.startsWith(`${format}:`) ? value.slice(format.length + 1) : value;
  if (!['sha1', 'sha256'].includes(format) || !new RegExp(`^[0-9a-f]{${format === 'sha1' ? 40 : 64}}$`).test(raw) || /^0+$/.test(raw)) {
    throw new Error('Invalid selected commit.');
  }
  return raw;
}
export function snapshotOf(reply, selection, previous = null) {
  if (!reply || reply.schema_version !== 1 || reply.object_format !== selection.format || reply.read_only !== true ||
      reply.transaction_created !== false || reply.published !== false ||
      typeof reply.snapshot_token !== 'string' || !/^alg:[0-9]+:[0-9a-f]+$/.test(reply.snapshot_token)) {
    throw new Error('Unsupported source response or snapshot.');
  }
  const selected = { head: reply.snapshot_token, commit: commitHex(reply.source_commit, selection.format) };
  if (previous && (previous.head !== selected.head || previous.commit !== selected.commit)) {
    throw new Error('Snapshot changed. Reopen the reference rather than combining pages.');
  }
  return selected;
}
export function sourceFields(selection, snapshot, path = '') {
  if (!['sha1', 'sha256'].includes(selection.format) || !selection.reference.startsWith('refs/')) {
    throw new Error('Choose a full reference and an object format.');
  }
  const fields = { ref: selection.reference, object_format: selection.format };
  if (snapshot) Object.assign(fields, { expected_head: snapshot.head, expected_commit: snapshot.commit });
  if (path) { unhex(path, 4096); fields.path_hex = path; }
  return fields;
}
export function searchFields(selection, snapshot, text, matchCase = 'exact') {
  const bytes = encoder.encode(text);
  if (!bytes.length || bytes.length > 256 || bytes.includes(10) || bytes.includes(13) ||
      !['exact', 'ascii-insensitive'].includes(matchCase)) {
    throw new Error('Enter a nonempty single-line literal query of at most 256 UTF-8 bytes.');
  }
  return { ...sourceFields(selection, snapshot), needle_hex: hex(bytes), case: matchCase, max_matches: '100' };
}
export function searchRows(reply) {
  if (reply.type !== 'source_search' || reply.profile !== 'literal-bytes-v1' ||
      !Array.isArray(reply.matches) || reply.matches.length > 100 || reply.returned_matches !== reply.matches.length ||
      !['complete', 'match_limit'].includes(reply.completion) || reply.complete !== (reply.completion === 'complete')) {
    throw new Error('Invalid source search response.');
  }
  return reply.matches.map(row => {
    const path = unhex(row.path_hex, 4096);
    if (!path.length || path.includes(0) || path[0] === 47 || path.at(-1) === 47) throw new Error('Invalid search path.');
    // Validate each component, but retain the exact original byte path.
    let parent = '';
    const parts = [];
    let start = 0;
    for (let i = 0; i <= path.length; i += 1) {
      if (i === path.length || path[i] === 47) { parts.push(hex(path.slice(start, i))); start = i + 1; }
    }
    for (const part of parts) parent = pathJoin(parent, part);
    const offset = safeNumber(row.byte_offset, 'match offset');
    const line = safeNumber(row.line, 'line number');
    const column = safeNumber(row.byte_column, 'byte column');
    const length = safeNumber(row.match_length, 'match length');
    const excerptOffset = safeNumber(row.excerpt_offset, 'excerpt offset');
    const excerpt = unhex(row.excerpt_hex, 416);
    if (!line || !column || !length || length > 256 || offset < excerptOffset ||
        offset - excerptOffset + length > excerpt.length) throw new Error('Invalid search excerpt.');
    return { path: row.path_hex, name: displayBytes(row.path_hex), offset, line, column,
      excerpt: blobPreview(excerpt, excerptOffset).text };
  });
}
export async function boundedJson(response, maximum = MAX_RESPONSE_BYTES) {
  if (!response.body) throw new Error('Empty API response.');
  const reader = response.body.getReader();
  const chunks = [];
  let count = 0;
  try {
    while (true) {
      const next = await reader.read();
      if (next.done) break;
      count += next.value.byteLength;
      if (count > maximum) throw new Error('API response exceeded the browser byte limit.');
      chunks.push(next.value);
    }
    const bytes = new Uint8Array(count);
    let offset = 0;
    for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
    return JSON.parse(utf8().decode(bytes));
  } finally {
    await reader.cancel().catch(() => {});
    reader.releaseLock();
  }
}
export function blobPreview(bytes, offset) {
  try {
    const text = utf8().decode(bytes);
    // Rendering is textContent even for HTML/SVG. Other control bytes use a hex view.
    if (/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/u.test(text)) throw new Error('bytes');
    return { label: 'UTF-8 byte-range preview', text: text.replace(/[\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069]/gu,
      ch => `\\u{${ch.codePointAt(0).toString(16)}}`) };
  } catch {
    const lines = [];
    for (let i = 0; i < bytes.length; i += 16) {
      const row = bytes.slice(i, i + 16);
      lines.push(`${(offset + i).toString(16).padStart(12, '0')}  ${Array.from(row, b => b.toString(16).padStart(2, '0')).join(' ').padEnd(47)}  ${Array.from(row, b => b >= 32 && b < 127 ? String.fromCharCode(b) : '.').join('')}`);
    }
    return { label: 'Hex preview (binary data or a UTF-8 sequence crossing this page boundary)', text: lines.join('\n') };
  }
}

export function mount(document, location, fetcher = globalThis.fetch) {
  const byId = id => document.getElementById(id);
  const apiRoot = new URL('../api/v1/source/', location.href);
  if (apiRoot.origin !== location.origin || !location.pathname.endsWith('/ui/')) {
    throw new Error('Open the browser at this repository’s /ui/ endpoint.');
  }
  let token = '';
  let selection = null;
  let snapshot = null;
  let controller = null;
  let generation = 0;
  const clear = () => ['content', 'paging', 'breadcrumbs', 'snapshot'].forEach(id => byId(id).replaceChildren());
  const node = (tag, text = '') => { const element = document.createElement(tag); element.textContent = text; return element; };
  const button = (text, action) => { const element = node('button', text); element.type = 'button'; element.addEventListener('click', action); return element; };
  const status = text => { byId('status').textContent = text; };
  function disconnect() {
    generation += 1;
    controller?.abort(); controller = null;
    token = ''; selection = null; snapshot = null;
    byId('token').value = ''; byId('needle').value = ''; clear(); status('Disconnected. Repository data and token discarded.');
  }
  async function request(operation, fields, signal) {
    // This is an intentionally closed read-only operation set, despite POST framing.
    if (!['tree', 'blob', 'search'].includes(operation)) throw new Error('Unsupported browser operation.');
    const response = await fetcher(new URL(operation, apiRoot), {
      method: 'POST', mode: 'same-origin', credentials: 'omit', cache: 'no-store', redirect: 'error', signal,
      headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/x-www-form-urlencoded', Accept: 'application/json' },
      body: new URLSearchParams(fields),
    });
    if (!response.ok) {
      await response.body?.cancel();
      if (response.status === 401) {
        const error = new Error('Token rejected or revoked. Enter a valid read token.');
        error.status = 401; throw error;
      }
      if (response.status === 409) throw new Error('The selected snapshot moved or this entry cannot be read. Reopen the reference.');
      if (response.status === 403) throw new Error('This token lacks read scope, or source browsing is disabled.');
      if (response.status === 404) throw new Error('Reference or path unavailable. Hidden refs are not disclosed.');
      if (response.status === 429) throw new Error('Read quota exceeded. Retry after the server’s quota window.');
      throw new Error(`Repository read failed (HTTP ${response.status}). No write was attempted.`);
    }
    if (!/^application\/json(?:\s*;|$)/i.test(response.headers.get('Content-Type') ?? '')) {
      await response.body?.cancel(); throw new Error('Unexpected API content type.');
    }
    return boundedJson(response);
  }
  async function run(operation, fields, render) {
    if (!token || !selection) { status('Enter a read-scoped token first.'); return; }
    const current = ++generation;
    controller?.abort(); controller = new AbortController();
    const selected = selection;
    const pinned = snapshot;
    clear(); status('Reading repository snapshot…');
    try {
      const reply = await request(operation, fields, controller.signal);
      if (current !== generation) return;
      const observed = snapshotOf(reply, selected, pinned);
      render(reply); // Validate and render before accepting a new snapshot.
      snapshot = observed;
      byId('snapshot').textContent = `${selected.reference} · ${selected.format}\nCommit ${snapshot.commit}\nSnapshot ${snapshot.head}`;
      status('Read complete. All navigation remains pinned to this snapshot.');
    } catch (error) {
      if (current !== generation || error.name === 'AbortError') return;
      if (error.status === 401) disconnect();
      clear(); status(error.message);
    }
  }
  function breadcrumbs(path) {
    byId('breadcrumbs').append(button('Repository', () => tree('')));
    const bytes = unhex(path, 4096);
    for (let i = 0; i <= bytes.length; i += 1) {
      if (i === bytes.length || bytes[i] === 47) {
        const prefix = hex(bytes.slice(0, i));
        if (prefix) byId('breadcrumbs').append(button(displayBytes(prefix), () => tree(prefix)));
      }
    }
  }
  function tree(path, after = null) {
    if (!selection) return;
    const fields = { ...sourceFields(selection, snapshot, path), limit: '100' };
    if (after !== null) { unhex(after, 4096); fields.after_hex = after; }
    void run('tree', fields, reply => {
      if (reply.type !== 'source_tree' || (reply.path_hex ?? '') !== path || !Array.isArray(reply.entries) || reply.entries.length > 100) {
        throw new Error('Invalid directory response.');
      }
      const table = node('table');
      const header = node('tr'); header.append(node('th', 'Name'), node('th', 'Kind')); table.append(header);
      let previousName = after;
      for (const entry of reply.entries) {
        if (!['directory', 'file', 'executable', 'symlink', 'gitlink'].includes(entry.kind) ||
            (previousName !== null && entry.name_hex <= previousName)) throw new Error('Invalid directory entry ordering or kind.');
        previousName = entry.name_hex;
        const child = pathJoin(path, entry.name_hex);
        const row = node('tr'); const name = node('td');
        const action = entry.kind === 'directory' ? () => tree(child)
          : ['file', 'executable', 'symlink'].includes(entry.kind) ? () => blob(child, 0) : null;
        name.append(action ? button(displayBytes(entry.name_hex), action) : node('span', displayBytes(entry.name_hex)));
        row.append(name, node('td', String(entry.kind))); table.append(row);
      }
      if (reply.next_after_hex !== null) {
        unhex(reply.next_after_hex, 4096);
        if (!reply.entries.length || reply.next_after_hex !== reply.entries.at(-1).name_hex || reply.next_after_hex === after) {
          throw new Error('Invalid directory continuation.');
        }
        byId('paging').append(button('Next directory page', () => tree(path, reply.next_after_hex)));
      }
      breadcrumbs(path);
      byId('content').append(table);
      if (!reply.entries.length) byId('content').append(node('p', 'This directory is empty.'));
    });
  }
  function blob(path, offset) {
    const fields = { ...sourceFields(selection, snapshot, path), offset: String(offset), limit: String(PAGE_BYTES) };
    void run('blob', fields, reply => {
      if (reply.type !== 'source_blob' || reply.path_hex !== path || reply.offset !== offset || reply.symlink_followed !== false) {
        throw new Error('Invalid file response.');
      }
      const total = safeNumber(reply.total_bytes, 'file length');
      const bytes = unhex(reply.content_hex, PAGE_BYTES);
      if (reply.returned_bytes !== bytes.length || offset > total || bytes.length !== Math.min(PAGE_BYTES, total - offset)) {
        throw new Error('Invalid file byte range.');
      }
      const end = offset + bytes.length;
      if (reply.next_offset !== (end < total ? end : null)) throw new Error('Invalid file continuation.');
      const parts = unhex(path, 4096); const slash = parts.lastIndexOf(47);
      breadcrumbs(slash < 0 ? '' : hex(parts.slice(0, slash)));
      const preview = blobPreview(bytes, offset);
      byId('content').append(node('h2', displayBytes(path)), node('p', `${preview.label} · bytes ${offset}–${end} of ${total}`));
      if (reply.kind === 'symlink') byId('content').append(node('p', 'Symbolic link target bytes only. The server did not follow the link.'));
      byId('content').append(node('pre', preview.text));
      if (offset) byId('paging').append(button('Previous byte range', () => blob(path, Math.max(0, offset - PAGE_BYTES))));
      if (reply.next_offset !== null) byId('paging').append(button('Next byte range', () => blob(path, reply.next_offset)));
    });
  }
  byId('connection').addEventListener('submit', event => {
    event.preventDefault();
    const supplied = byId('token').value;
    byId('token').value = '';
    const nextToken = supplied || token;
    if (!/^[0-9a-f]{64}$/.test(nextToken)) { disconnect(); status('Enter the provisioned 64-character lowercase hexadecimal token.'); return; }
    const candidate = { reference: byId('reference').value, format: byId('format').value };
    try { sourceFields(candidate, null); } catch (error) { status(error.message); return; }
    generation += 1; controller?.abort(); snapshot = null; selection = candidate; token = nextToken;
    tree('');
  });
  byId('search').addEventListener('submit', event => {
    event.preventDefault();
    if (!selection) { status('Open a reference before searching.'); return; }
    let fields;
    try { fields = searchFields(selection, snapshot, byId('needle').value, byId('search-case').value); }
    catch (error) { status(error.message); return; }
    void run('search', fields, reply => {
      const rows = searchRows(reply);
      breadcrumbs('');
      byId('content').append(node('h2', 'Literal search results'));
      if (!reply.complete) {
        const warning = node('p', 'Match limit reached. These results are partial; narrow the query.');
        warning.className = 'warning'; byId('content').append(warning);
      }
      if (!rows.length) byId('content').append(node('p', 'No matches in this snapshot.'));
      for (const row of rows) {
        const result = node('article');
        result.append(button(`${row.name} · line ${row.line}, byte column ${row.column}`,
          () => blob(row.path, Math.floor(row.offset / PAGE_BYTES) * PAGE_BYTES)), node('pre', row.excerpt));
        byId('content').append(result);
      }
    });
  });
  byId('disconnect').addEventListener('click', disconnect);
  // Clear secrets and abort fetches before a page can enter the back-forward cache.
  document.defaultView?.addEventListener('pagehide', disconnect);
  return { disconnect };
}
if (typeof document !== 'undefined') mount(document, window.location);
