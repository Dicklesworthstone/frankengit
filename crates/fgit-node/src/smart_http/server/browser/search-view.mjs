// DOM-only read interface. Repository bytes never become markup or navigation URLs.
import { CodeSearch } from './search.mjs';
import { byteInput } from './search-data.mjs';
import { sourceMode } from './search-current.mjs';
import { decimal, fail, unhex } from './pulls-core.mjs';

const indexedMode = mode => ['indexed-content', 'indexed-path'].includes(mode);
const PREVIEW_BYTES = 4096, PAGE_MATCHES = 50;
export function display(bytes, multiline = false) {
  try {
    const value = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes);
    return value.replace(/[\\\u0000-\u001f\u007f-\u009f\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069]/gu, ch => {
      if (multiline && ch === '\n') return ch;
      if (ch === '\\') return '\\\\';
      return `\\u{${ch.codePointAt(0).toString(16)}}`;
    });
  } catch {
    return Array.from(bytes, b => b >= 32 && b <= 126 && b !== 92 ? String.fromCharCode(b) : `\\x${b.toString(16).padStart(2, '0')}`).join('');
  }
}
const safe = value => display(new TextEncoder().encode(String(value)));
export function preview(bytes, hit) {
  const start = Math.max(0, hit.offset - 160);
  const end = Math.min(bytes.length, start + PREVIEW_BYTES, hit.offset + hit.length + 160);
  const matchEnd = Math.min(end, hit.offset + hit.length);
  return { start, end, truncated: matchEnd < hit.offset + hit.length,
    before: display(bytes.subarray(start, hit.offset), true),
    matched: hit.length === 0 ? '▏' : display(bytes.subarray(hit.offset, matchEnd), true),
    after: display(bytes.subarray(matchEnd, end), true) };
}
function lines(value, maximum) {
  if (value.length > 128 * 8193) fail('Input exceeds the browser form limit.');
  const result = value.replace(/\r?\n$/u, '').split(/\r?\n/u);
  if (result.length > maximum) fail('Too many input lines.');
  return result;
}
export function readQuery(document) {
  const value = id => document.getElementById(id).value;
  const mode = value('mode'), encoding = value('encoding');
  const raw = value('query'), prefixes = value('prefixes');
  const indexMode = indexedMode(mode) ? sourceMode(document.getElementById('index-source-mode')?.value) : 'exact';
  if (indexedMode(mode)) return {
    ...(indexMode === 'revalidated' ? { sourceMode: indexMode } : {}),
    mode: 'indexed', channel: mode === 'indexed-path' ? 'path' : 'content',
    termsHex: lines(raw, 32).map(line => byteInput(line, encoding, 128)),
    prefixesHex: prefixes === '' ? [] : lines(prefixes, 128).map(line => byteInput(line, value('prefix-encoding'), 4096)),
    maxMatches: decimal(value('max-matches'), 'indexed page size', 1),
    maxFileBytes: decimal(value('max-file-bytes'), 'navigation file bytes', 1),
    maxWork: decimal(value('index-work'), 'indexed work limit', 1),
    maxPayloadBytes: decimal(value('index-payload'), 'indexed payload bytes', 1),
  };
  const input = { mode, case: value('case'), prefixesHex: prefixes === '' ? [] : lines(prefixes, 128)
    .map(line => byteInput(line, value('prefix-encoding'), 4096)),
    maxMatches: decimal(value('max-matches'), 'match limit', 1),
    maxFileBytes: decimal(value('max-file-bytes'), 'file byte limit', 1),
    maxBytes: decimal(value('max-bytes'), 'source byte limit', 1) };
  if (mode === 'regex') {
    input.patternHex = byteInput(raw, encoding, 256);
    input.maxSteps = decimal(value('max-steps'), 'VM work limit', 1);
  } else input.needlesHex = (mode === 'batch' ? lines(raw, 32) : [raw]).map(line => byteInput(line, encoding, 256));
  return input;
}
export function mount(document, location, options = {}) {
  const { urlApi = globalThis.URL, ...clientOptions } = options;
  const client = new CodeSearch({ ...clientOptions, href: location.href });
  const get = id => document.getElementById(id);
  const element = (tag, text = '') => { const el = document.createElement(tag); el.textContent = text; return el; };
  const button = (label, action) => { const el = element('button', label); el.type = 'button'; el.addEventListener('click', action); return el; };
  let work = 0, resultVersion = 0, busy = false, result = null, verified = null, downloadUrl = null, resultButtons = new Set();
  const status = message => { get('status').textContent = message; };
  function clearFile() {
    verified = null; get('file').replaceChildren();
    if (downloadUrl !== null) { urlApi.revokeObjectURL(downloadUrl); downloadUrl = null; }
  }
  function clearResults() { resultVersion++; result = null; resultButtons = new Set(); get('results').replaceChildren(); clearFile(); }
  function sync() {
    get('submit-search').disabled = !client.connected || busy;
    get('refresh').disabled = !client.connected || busy;
    get('cancel').disabled = !busy;
    for (const b of resultButtons) b.disabled = !client.connected || busy;
    const regex = get('mode').value === 'regex', indexed = indexedMode(get('mode').value);
    get('case').disabled = indexed; get('max-bytes').disabled = indexed;
    get('index-work').disabled = !indexed; get('index-payload').disabled = !indexed;
    if (get('index-source-mode')) get('index-source-mode').disabled = !indexed;
    get('index-help').hidden = !indexed; get('max-matches').max = indexed ? '100' : '4096';
    get('max-steps').disabled = !regex;
    get('regex-help').hidden = !regex;
    get('query-help').textContent = indexed
      ? 'One whole ASCII alphanumeric/underscore word per line, up to 32. All words must occur in the selected channel. ASCII case is folded; terms are sorted and deduplicated. Up to 100 documents per page.'
      : get('mode').value === 'batch'
      ? 'One literal per line, up to 32. Order and duplicate queries are preserved. A final separator newline is ignored.'
      : regex ? 'Native byte regex, up to 256 bytes. One leftmost-longest span per physical line, not JavaScript/PCRE semantics.'
        : 'One literal, up to 256 bytes. Use lowercase hex for binary bytes; matches may overlap.';
  }
  function showPin() {
    const state = client.state;
    get('snapshot').textContent = state.pin
      ? `Reference ${safe(state.selection.reference)} · ${state.scope.format}\nRepository ${safe(state.scope.repository)} · incarnation ${safe(state.scope.incarnation)}\nCommit ${state.pin.commit}\nTree ${state.pin.tree}\nSnapshot ${state.pin.head}`
      : client.connected ? 'The next successful search will select the current snapshot.' : '';
    if (state.indexMinimum) get('snapshot').textContent += `\nRetained index checkpoint ${state.indexMinimum.number}: ${state.indexMinimum.token}`;
  }
  function disconnect(message = 'Disconnected. Token, queries, results and source bytes discarded.') {
    work++; busy = false; client.disconnect(); clearResults();
    get('token').value = ''; get('query').value = ''; get('prefixes').value = ''; showPin(); sync(); status(message);
  }
  function invalidate() {
    work++; busy = false; client.discardResults(); clearResults(); sync();
    status(client.connected ? 'Query changed. Search again; the existing snapshot remains pinned.' : 'Enter a read-scoped token to begin.');
  }
  function cancel() { work++; busy = false; client.cancel(); clearFile(); sync(); status('Read canceled. No write or retry was attempted.'); }
  function refresh() {
    work++; busy = false; client.refreshSnapshot(); clearResults(); showPin(); sync();
    status('Snapshot released. The next search selects current state; repository identity must still match.');
  }
  function errorAt(error, id) {
    if (id !== work) return;
    if (!client.connected) { disconnect(`Disconnected: ${safe(error.message)}`); return; }
    busy = false; clearFile();
    if (error.status === 409) { client.discardResults(); clearResults(); }
    const indexed = indexedMode(get('mode').value);
    const indexDiagnostic = indexed && error.status === 409 ? {
      source_index_uninitialized: 'No persisted source index is initialized. Ask the trusted local operator to build it. No scan or build was attempted by this page.',
      source_index_stale: 'The persisted index does not match the source selection. Release the snapshot explicitly, or ask the trusted local operator to reconcile the index. No scan fallback was attempted.',
      index_checkpoint_unavailable: 'The selected index checkpoint cannot be resolved. The operator must recover it; this page will not fall back to an older index.',
    }[error.code] : null;
    const indexFailure = indexDiagnostic ?? (indexed && error.status === 409
      ? 'Indexed search refused: the source/index changed, no current index exists, or a checkpoint is unavailable. An authorized operator must build or refresh a missing/stale index. Release snapshot only to explicitly select fresh source. No scan fallback or automatic retry was run.'
      : indexed && error.status === 503
        ? 'The persisted index is unavailable or failed verification. No partial result, scan fallback or automatic rebuild was accepted.' : null);
    const message = indexFailure ?? {
      400: 'Native query or request refused. Check the byte encoding, supported syntax and input limits.',
      404: 'Selected repository, reference or path is unavailable. Hidden references are not disclosed.',
      413: 'A source, index, result or VM work limit was exceeded. Narrow the query or path scope, or adjust the bounded limits.',
    }[error.status] ?? error.message;
    sync(); status(error.name === 'AbortError' ? 'Read canceled. No write was attempted.' : safe(message));
  }
  async function connect() {
    const token = get('token').value, reference = get('reference').value, format = get('format').value;
    get('token').value = ''; work++; const id = work;
    busy = true; client.disconnect(); clearResults(); showPin(); sync(); status('Connecting read-only client…');
    try {
      await client.connect(token, reference, format);
      if (id !== work) return;
      busy = false; showPin(); sync(); status('Read token ready. Submit a search to select a repository snapshot.');
    } catch (error) { errorAt(error, id); }
  }
  function renderGroup(group, index, version) {
    const section = element('section'); section.className = 'query-group';
    const label = result.query.mode === 'regex' ? display(unhex(result.query.patternHex)) : display(unhex(group.needleHex));
    section.append(element('h3', `Query ${index + 1}: ${label}`), element('p', group.complete
      ? `Server reports complete: ${group.matches.length} match${group.matches.length === 1 ? '' : 'es'}.`
      : `Limited: ${group.matches.length} matches shown; at least one additional match exists. Narrow the query or raise its bounded limit.`));
    const rows = element('div'), paging = element('nav');
    let pageButtons = []; paging.setAttribute('aria-label', `Query ${index + 1} result pages`);
    function page(at) {
      if (version !== resultVersion) return;
      for (const b of pageButtons) resultButtons.delete(b);
      pageButtons = []; rows.replaceChildren(); paging.replaceChildren();
      const end = Math.min(group.matches.length, at + PAGE_MATCHES);
      for (let i = at; i < end; i++) {
        const hit = group.matches[i], article = element('article'); article.className = 'match';
        const open = button(`${display(unhex(hit.pathHex))} : ${hit.line}:${hit.column}`, () => {
          if (version === resultVersion && !busy) void openMatch(index, i);
        });
        resultButtons.add(open); pageButtons.push(open);
        article.append(open, element('p', `Byte ${hit.offset}, length ${hit.length}${hit.truncated ? ' · excerpt truncates the span' : ''}`),
          element('pre', display(unhex(hit.excerptHex), true)));
        rows.append(article);
      }
      if (!group.matches.length) rows.append(element('p', 'No matching source in the selected scope.'));
      if (at > 0) paging.append(button('Previous results', () => page(Math.max(0, at - PAGE_MATCHES))));
      if (end < group.matches.length) paging.append(button('Next results', () => page(end)));
      if (group.matches.length) paging.append(element('span', ` ${at + 1}–${end} of ${group.matches.length}`));
      sync();
    }
    section.append(rows, paging); page(0); return section;
  }
  function renderSearch(value) {
    const stats = value.stats, region = get('results'), version = resultVersion;
    if (value.query.mode === 'indexed') { renderIndexed(value, region, version); return; }
    region.append(element('h2', `${value.totalMatches} returned matches`),
      element('p', `${stats.filesRead}/${stats.filesSelected} regular files read · ${stats.bytesRead} bytes read · ${stats.bytesSearched} bytes searched · ${stats.nonRegular} symlink/gitlink entries not followed.`));
    if (value.query.mode === 'batch') region.append(element('p', 'One shared source scan. Completion is reported separately for each query.'));
    if (value.query.mode === 'regex') region.append(element('p', `${stats.steps} native VM steps · ${stats.states} program states · ${stats.lines} lines searched.`));
    for (const [index, group] of value.groups.entries()) region.append(renderGroup(group, index, version));
  }
  function renderIndexed(value, region, version) {
    const stats = value.stats;
    region.append(element('h2', `${value.hits.length} indexed documents in this page`),
      element('p', `AND in ${value.query.channel}: ${value.query.termsHex.map(t => display(unhex(t))).join(' AND ')}`),
      element('pre', `Queried index ${value.index.number}: ${value.index.token}\nObserved index head ${value.selectedIndex.number}: ${value.selectedIndex.token}`),
      element('p', `${stats.documents} indexed regular files · ${stats.sourceBytes} indexed source bytes · ${stats.nonRegular} non-regular entries excluded.`),
      element('p', `This page read ${stats.segments} segments / ${stats.payloadBytes} payload bytes / ${stats.generationBytes} generation bytes and used ${stats.work} native work units. This is not a live source scan.`),
      element('p', value.complete ? `Native server reports the query complete; ${value.seen} matching documents visited.`
        : `${value.seen} matching documents visited; more remain in this exact index. Fetch the next page explicitly.`));
    if (value.sources) {
      const { current, indexed, distinct } = value.sources;
      region.append(element('p', distinct
        ? 'Native server revalidated the same commit and tree across changed repository metadata. Original index provenance is retained below.'
        : 'Native server revalidated this index at its original source snapshot.'),
        element('pre', `Current source snapshot ${safe(current.snapshot_token)}\nCurrent RCR ${safe(current.source_rcr)}\nCurrent forge root ${safe(current.forge_position_root)}\nOriginal indexed snapshot ${safe(indexed.snapshot_token)}\nOriginal indexed RCR ${safe(indexed.source_rcr)}\nOriginal indexed forge root ${safe(indexed.forge_position_root)}`),
        element('p', 'File navigation uses the current pinned source. Revalidation is a server claim, not a locally verified authority proof.'));
    }
    for (const [index, hit] of value.hits.entries()) {
      const article = element('article'); article.className = 'match';
      const open = button(display(unhex(hit.pathHex)), () => {
        if (version === resultVersion && !busy) void openIndexed(index);
      });
      resultButtons.add(open);
      article.append(open, element('p', `Document ${hit.documentId} · ${hit.contentBytes} bytes · ${hit.blob}`),
        element('p', 'First word positions in ' + value.query.channel + ': ' + hit.spans.map(span =>
          `${display(unhex(value.query.termsHex[span.queryIndex]))} [${span.offset}, ${span.offset + span.length})`).join('; ')));
      region.append(article);
    }
    if (value.nextAfter !== null) {
      const next = button('Next indexed page', () => { if (version === resultVersion && !busy) void nextIndexed(); });
      resultButtons.add(next); region.append(next);
    }
  }
  async function nextIndexed() {
    if (busy || result?.query.mode !== 'indexed' || result.nextAfter === null) return;
    work++; const id = work; busy = true; clearResults(); sync(); status('Reading the next page from the original source and index generation…');
    try {
      const value = await client.nextIndexed();
      if (id !== work) return;
      busy = false; result = value; renderSearch(value); showPin(); sync();
      status(value.complete ? 'Indexed query complete according to the native server.' : 'More indexed documents remain. The original generation is still pinned.');
    } catch (error) { errorAt(error, id); }
  }
  async function search() {
    work++; const id = work; busy = true; client.discardResults(); clearResults(); sync(); status('Searching the selected repository…');
    try {
      const value = await client.search(readQuery(document));
      if (id !== work) return;
      busy = false; result = value; renderSearch(value); showPin(); sync();
      status(value.query.mode === 'indexed' ? (value.complete ? 'Indexed query complete according to the native server. Open a document to verify its bytes and word positions.' : 'More indexed documents remain; use Next indexed page.') : value.groups.every(g => g.complete) ? 'Server scan complete. Open a result to verify its file bytes.' : 'Search returned limited results. See each query’s completion status.');
    } catch (error) { errorAt(error, id); }
  }
  function renderFile(value) {
    const hit = value.hit, region = get('file');
    if (value.query?.mode === 'indexed') { renderIndexedFile(value, region); downloadControl(value, region); return; }
    const part = preview(value.bytes, hit);
    region.append(element('h2', display(unhex(hit.pathHex))), element('p', `Native blob verified (${value.scope.format}): ${hit.blob}`),
      element('p', `Full file: ${value.bytes.length} bytes. Line ${hit.line}, byte column ${hit.column}; span [${hit.offset}, ${hit.offset + hit.length}).`),
      element('p', value.literalVerified ? 'Literal bytes, excerpt and coordinates reproduced from the verified file.' : 'Excerpt and coordinates reproduced. Regex selection and completeness are reported by the native server, not re-evaluated here.'),
      element('p', `Escaped byte preview [${part.start}, ${part.end}); control/bidi bytes are escaped.${part.truncated ? ' The match continues beyond this preview.' : ''}${hit.length === 0 ? ' The marker shows a zero-length span.' : ''}`));
    const pre = element('pre'); pre.append(element('span', part.before), element('mark', part.matched), element('span', part.after)); region.append(pre);
    downloadControl(value, region);
  }
  function downloadControl(value, region) {
    const download = button('Download verified file bytes', () => {
      if (verified !== value || busy) return;
      if (downloadUrl !== null) urlApi.revokeObjectURL(downloadUrl);
      downloadUrl = urlApi.createObjectURL(new Blob([value.bytes], { type: 'application/octet-stream' }));
      const anchor = element('a'); anchor.href = downloadUrl; anchor.download = 'snapshot-source.bin'; anchor.rel = 'noopener';
      region.append(anchor); anchor.click(); anchor.remove();
    });
    region.append(download); region.focus();
  }
  function renderIndexedFile(value, region) {
    const hit = value.hit, path = unhex(hit.pathHex);
    region.append(element('h2', display(path)), element('p', `Native blob verified (${value.scope.format}): ${hit.blob}`),
      element('p', `${value.bytes.length} complete file bytes. All reported first whole-word spans reproduced in ${value.channel}.`),
      element('p', 'This verifies the returned file and word positions, not index coverage, authority signatures or other documents.'));
    const bytes = value.channel === 'path' ? path : value.bytes;
    const spans = hit.spans.map(span => ({ ...span }));
    // Query terms are lexically ordered, not source ordered. Scan verified
    // content once in offset order, then render in the original term order.
    // Path positions never acquire file line/column coordinates.
    if (value.channel === 'content') {
      let offset = 0, line = 1, start = 0;
      for (const span of [...spans].sort((a, b) => a.offset - b.offset)) {
        while (offset < span.offset) {
          if (bytes[offset] === 10) { line++; start = offset + 1; }
          offset++;
        }
        span.line = line; span.column = span.offset - start + 1;
      }
    }
    for (const span of spans) {
      const part = preview(bytes, span), pre = element('pre');
      region.append(element('h3', `${display(unhex(value.query.termsHex[span.queryIndex]))}: ${value.channel} bytes [${span.offset}, ${span.offset + span.length})${value.channel === 'content' ? `; line ${span.line}, byte column ${span.column}` : ''}`));
      pre.append(element('span', part.before), element('mark', part.matched), element('span', part.after)); region.append(pre);
    }
    if (value.channel === 'path') {
      region.append(element('p', `Content preview [0, ${Math.min(value.bytes.length, PREVIEW_BYTES)}). Path terms are not content matches.`),
        element('pre', display(value.bytes.subarray(0, PREVIEW_BYTES), true)));
    }
  }
  async function openIndexed(index) {
    if (!result || result.query.mode !== 'indexed' || busy) return;
    work++; const id = work; busy = true; clearFile(); sync(); status('Reading the pinned complete file and reproducing indexed whole-word positions…');
    try {
      const value = await client.openIndexed(index);
      if (id !== work) return;
      busy = false; verified = value; renderFile(value); sync(); status('Native blob bytes and all indexed first-word spans verified. Index coverage remains a server claim.');
    } catch (error) { errorAt(error, id); }
  }
  async function openMatch(group, index) {
    if (!result) return;
    work++; const id = work; busy = true; clearFile(); sync(); status('Reading pinned file pages and checking its complete native blob identity…');
    try {
      const value = await client.openMatch(group, index);
      if (id !== work) return;
      busy = false; verified = value; renderFile(value); sync(); status('File bytes and search coordinates verified against the returned native blob identity.');
    } catch (error) { errorAt(error, id); }
  }
  for (const [id, action] of [['connection', connect], ['search-form', search]]) get(id).addEventListener('submit', event => { event.preventDefault(); void action(); });
  get('disconnect').addEventListener('click', () => disconnect());
  get('cancel').addEventListener('click', cancel); get('refresh').addEventListener('click', refresh);
  for (const id of ['mode', 'encoding', 'case', 'query', 'prefixes', 'prefix-encoding', 'max-matches', 'max-file-bytes', 'max-bytes', 'max-steps', 'index-work', 'index-payload']) {
    get(id).addEventListener('input', invalidate); get(id).addEventListener('change', invalidate);
  }
  for (const event of ['input', 'change']) get('index-source-mode')?.addEventListener(event, invalidate);
  const connectionChanged = () => {
    work++; busy = false; client.disconnect(); clearResults(); showPin(); sync(); status('Connection settings changed. Connect explicitly before searching.');
  };
  for (const id of ['reference', 'format', 'token']) {
    get(id).addEventListener('input', connectionChanged); get(id).addEventListener('change', connectionChanged);
  }
  document.defaultView?.addEventListener('pagehide', () => disconnect());
  sync();
  return { connect, search, openMatch, openIndexed, nextIndexed, cancel, refresh, disconnect };
}
if (typeof document !== 'undefined') mount(document, globalThis.location);
