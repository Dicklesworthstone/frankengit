// Verify an already-validated Initial context using complete source files.
// The host owns authorization, pinned page reads, cancellation and deadlines.
// This is NOT a parser for untrusted exported reports or a repository authority.
export const CONTEXT_VERIFY_PROFILE = 'source-context-full-blob-verification-v1';
export const CONTEXT_VERIFY_LIMITS = Object.freeze({ maxSourceBytes: 64 * 1024 * 1024, maxRequests: 1056 });
const FILE_BYTES = 8 * 1024 * 1024, PAGE_BYTES = 64 * 1024;
const reject = message => { throw new Error(`Context verification: ${message}`); };
const encoder = new TextEncoder();
const word = b => b >= 48 && b <= 57 || b >= 65 && b <= 90 || b >= 97 && b <= 122 || b === 95;
const fold = b => b >= 65 && b <= 90 ? b + 32 : b;
function count(n, min, max) { if (!Number.isSafeInteger(n) || n < min || n > max) reject('invalid resource or coordinate bound.'); return n; }
function bytes(value, max) {
  if (typeof value !== 'string' || value.length % 2 || value.length > 2 * max || /[^0-9a-f]/u.test(value)) reject('invalid exact bytes.');
  return Uint8Array.from({ length: value.length / 2 }, (_, i) => parseInt(value.slice(2 * i, 2 * i + 2), 16));
}
function blob(value, format) {
  if (!['sha1', 'sha256'].includes(format) || typeof value !== 'string' ||
      !new RegExp(`^[0-9a-f]{${format === 'sha1' ? 40 : 64}}$`).test(value) || /^0+$/.test(value)) reject('invalid normalized blob identity.');
  return value;
}
function equalRange(actual, offset, expected, check) {
  count(offset, 0, actual.length);
  if (offset + expected.length > actual.length) reject('range escapes the verified file.');
  for (let i = 0; i < expected.length; i++) {
    if ((i & 4095) === 0) check();
    if (actual[offset + i] !== expected[i]) reject('excerpt or declaration differs from the verified bytes.');
  }
}
function firstWords(actual, query, spans, check) {
  if (!Array.isArray(query.termsHex) || !query.termsHex.length || query.termsHex.length > 32 ||
      !Array.isArray(spans) || spans.length !== query.termsHex.length) reject('invalid lexical witness.');
  const wanted = new Map();
  query.termsHex.forEach((term, index) => {
    const value = bytes(term, 128);
    if (!value.length || !value.every(word)) reject('invalid lexical word.');
    const text = String.fromCharCode(...value.map(fold));
    if (wanted.has(text)) reject('duplicate lexical word.');
    wanted.set(text, index);
  });
  const found = new Map(); let start = -1;
  for (let at = 0; at <= actual.length; at++) {
    if ((at & 4095) === 0) check();
    if (at < actual.length && word(actual[at])) { if (start < 0) start = at; continue; }
    if (start < 0) continue;
    if (at - start <= 128) {
      const index = wanted.get(String.fromCharCode(...actual.subarray(start, at).map(fold)));
      if (index !== undefined && !found.has(index)) found.set(index, start);
    }
    start = -1;
  }
  spans.forEach((span, index) => {
    if (span.queryIndex !== index || span.length !== query.termsHex[index].length / 2 || found.get(index) !== span.offset) {
      reject('lexical span is not the first complete word in the verified bytes.');
    }
  });
  check();
}
function declarations(actual, hits, check) {
  let at = 0, line = 1, start = 0, previous = -1;
  for (const hit of hits) {
    check(); count(hit.offset, 0, actual.length); count(hit.length, 1, 128);
    if (hit.offset <= previous || hit.offset + hit.length > actual.length) reject('invalid declaration ordering.');
    previous = hit.offset;
    while (at < hit.offset) {
      if ((at & 4095) === 0) check();
      if (actual[at++] === 10) { line++; start = at; }
    }
    const name = bytes(hit.nameHex, 128), raw = hit.offset >= 2 && actual[hit.offset - 2] === 114 && actual[hit.offset - 1] === 35;
    const begin = hit.offset - (raw ? 2 : 0);
    if (name.length !== hit.length || !name.every(word) || !name.length ||
        (name[0] >= 48 && name[0] <= 57) || hit.rawIdentifier !== raw ||
        word(actual[hit.offset + hit.length]) || (begin > 0 && word(actual[begin - 1])) ||
        hit.line !== line || hit.column !== hit.offset - start + 1) reject('declaration coordinates or identifier boundary changed.');
    equalRange(actual, hit.offset, name, check);
    equalRange(actual, count(hit.excerptOffset, start, hit.offset), bytes(hit.excerptHex, 416), check);
  }
}
function options(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
      Object.keys(value).some(k => !Object.hasOwn(CONTEXT_VERIFY_LIMITS, k))) reject('unknown verification limit.');
  return { maxSourceBytes: count(Object.hasOwn(value, 'maxSourceBytes') ? value.maxSourceBytes : CONTEXT_VERIFY_LIMITS.maxSourceBytes, 1, CONTEXT_VERIFY_LIMITS.maxSourceBytes),
    maxRequests: count(Object.hasOwn(value, 'maxRequests') ? value.maxRequests : CONTEXT_VERIFY_LIMITS.maxRequests, 1, CONTEXT_VERIFY_LIMITS.maxRequests) };
}
function prepare(result, input, check) {
  check(); const limits = options(input), context = result?.context;
  if (result?.query?.mode !== 'initial' || !context || !Array.isArray(context.files) || context.files.length > 32) reject('load a validated Initial context first.');
  const maximum = count(result.query.maxFileBytes, 1, FILE_BYTES);
  const format = result.scope?.format;
  let sourceBytes = 0, requests = 0, previous = '', excerptBytes = 0, windows = 0;
  const files = context.files.map(file => {
    check(); const path = bytes(file.pathHex, 4096);
    if (!path.length || path.includes(0) || file.pathHex <= previous) reject('invalid selected path order.');
    let start = 0, components = 0;
    for (let at = 0; at <= path.length; at++) {
      if (at < path.length && path[at] !== 47) continue;
      const part = path.subarray(start, at), text = String.fromCharCode(...part.map(fold));
      if (++components > 64 || !part.length || ['.', '..', '.git'].includes(text)) reject('unsafe source path.');
      start = at + 1;
    }
    previous = file.pathHex; blob(file.blob, format); count(file.sourceBytes, 0, maximum);
    sourceBytes += file.sourceBytes; requests += Math.max(1, Math.ceil(file.sourceBytes / PAGE_BYTES));
    if (sourceBytes > limits.maxSourceBytes || requests > limits.maxRequests) reject('complete selection exceeds the verification budget; nothing was read.');
    if (!Array.isArray(file.excerpts) || !Array.isArray(file.anchors) || file.anchors.length > 4096) reject('missing context evidence.');
    let end = -1;
    for (const excerpt of file.excerpts) {
      check(); const value = bytes(excerpt.bytesHex, 1024 * 1024); count(excerpt.offset, 0, file.sourceBytes);
      if (++windows > 128 || excerpt.offset <= end || excerpt.offset + value.length > file.sourceBytes) reject('invalid excerpt windows.');
      end = excerpt.offset + value.length; excerptBytes += value.length;
      if (excerptBytes > 1024 * 1024) reject('excerpt budget exceeded.');
    }
    const selected = { file, path, content: [], pathHits: [], symbols: [] };
    const expected = [];
    for (const channel of ['content', 'path']) {
      const child = result[channel];
      if (!child || !Array.isArray(child.hits) || child.hits.length > 100) reject('invalid Initial channel.');
      const hits = child.hits.filter(hit => hit.pathHex === file.pathHex);
      if (hits.length > 1) reject('duplicate lexical document.');
      for (const hit of hits) {
        if (hit.blob !== file.blob || hit.contentBytes !== file.sourceBytes || !Array.isArray(hit.spans) || hit.spans.length > 32) reject('lexical file identity changed.');
        selected[channel === 'content' ? 'content' : 'pathHits'].push({ hit, query: child.query });
        for (const span of hit.spans) expected.push({ channel, offset: span.offset, length: span.length });
      }
    }
    const symbols = result.symbols;
    if (!symbols || !['available', 'not_requested', 'unavailable'].includes(symbols.state)) reject('missing symbol state.');
    if (symbols.state === 'available') {
      if (!Array.isArray(symbols.result?.hits) || symbols.result.hits.length > 100) reject('invalid declaration results.');
      selected.symbols = symbols.result.hits.filter(hit => hit.pathHex === file.pathHex);
      for (const hit of selected.symbols) {
        if (hit.blob !== file.blob) reject('declaration blob changed.');
        expected.push({ channel: 'symbol', offset: hit.offset, length: hit.length });
      }
    }
    expected.sort((a, b) => a.channel < b.channel ? -1 : a.channel > b.channel ? 1 : a.offset - b.offset || a.length - b.length);
    const unique = expected.filter((a, i) => !i || a.channel !== expected[i - 1].channel || a.offset !== expected[i - 1].offset || a.length !== expected[i - 1].length);
    if (!unique.length || unique.length !== file.anchors.length || unique.some((a, i) =>
      ['channel', 'offset', 'length'].some(key => a[key] !== file.anchors[i][key]))) reject('context anchors do not join their Initial witnesses.');
    return selected;
  });
  if (context.sourceBlobsRead !== files.length || context.sourceBytesRead !== sourceBytes || context.excerptBytes !== excerptBytes) reject('context accounting changed.');
  check(); return { limits, files, sourceBytes, requests, excerptBytes, format };
}
// No partial success escapes. One full file is held at a time; its hash is
// computed once even when many channels or declarations reference that file.
// readFile(file, chargeRequest) must return the pinned full regular file and
// charge BEFORE each 64-KiB page request, including the single empty-file read.
export async function verifyContextFiles(result, readFile, crypto, check = () => {}, input = {}) {
  if (typeof readFile !== 'function' || typeof check !== 'function' || !crypto?.subtle) reject('missing verification host.');
  const plan = prepare(result, input, check);
  // The production caller owns immutable result state. Copy the bounded plan
  // now so an asynchronous host cannot alter witnesses after preflight.
  const saved = structuredClone({ plan, scope: result.scope, pin: result.pin, vector: result.vector });
  let requests = 0; const verified = [];
  for (const entry of saved.plan.files) {
    check(); let fileRequests = 0;
    const expectedRequests = Math.max(1, Math.ceil(entry.file.sourceBytes / PAGE_BYTES));
    const charge = () => {
      check();
      if (++fileRequests > expectedRequests || ++requests > saved.plan.limits.maxRequests) reject('page-request budget exceeded.');
    };
    const loaded = await readFile(structuredClone(entry.file), charge); check();
    if (fileRequests !== expectedRequests || !['file', 'executable'].includes(loaded?.kind) ||
        !(loaded.bytes instanceof Uint8Array) || loaded.bytes.length !== entry.file.sourceBytes) reject('incomplete pinned regular file.');
    // Own bytes before WebCrypto yields; caller mutation cannot change what was
    // hashed versus what was checked afterward.
    const kind = loaded.kind;
    const header = encoder.encode(`blob ${loaded.bytes.length}\0`), framed = new Uint8Array(header.length + loaded.bytes.length);
    framed.set(header); framed.set(loaded.bytes, header.length);
    const digest = new Uint8Array(await crypto.subtle.digest(saved.plan.format === 'sha1' ? 'SHA-1' : 'SHA-256', framed)); check();
    const id = Array.from(digest, b => b.toString(16).padStart(2, '0')).join('');
    if (id !== entry.file.blob) reject('complete native blob hash mismatch.');
    const actual = framed.subarray(header.length);
    for (const excerpt of entry.file.excerpts) equalRange(actual, excerpt.offset, bytes(excerpt.bytesHex, 1024 * 1024), check);
    for (const { hit, query } of entry.content) firstWords(actual, query, hit.spans, check);
    for (const { hit, query } of entry.pathHits) firstWords(entry.path, query, hit.spans, check);
    declarations(actual, entry.symbols, check); check();
    verified.push({ pathHex: entry.file.pathHex, blob: id, kind, sourceBytes: actual.length,
      excerptBytes: entry.file.excerpts.reduce((n, e) => n + e.bytesHex.length / 2, 0),
      lexicalDocuments: entry.content.length + entry.pathHits.length, declarations: entry.symbols.length });
  }
  check();
  if (requests !== saved.plan.requests) reject('request accounting changed.');
  return { profile: CONTEXT_VERIFY_PROFILE, scope: saved.scope, pin: saved.pin, generationVector: saved.vector,
    completeSelectedContext: true, sourceMaterialUntrusted: true, repositoryMembershipVerified: false,
    searchCoverageVerified: false, declarationSemanticsVerified: false,
    sourceBytesRead: saved.plan.sourceBytes, requests, excerptBytesVerified: saved.plan.excerptBytes,
    limits: saved.plan.limits, files: verified };
}

// This export records a local observation, not a transferable proof: complete
// blob bodies and authenticated commit/tree membership are not in this report.
export function contextVerificationSummary(result, receipt) {
  const plan = prepare(result, receipt?.limits, () => {});
  if (receipt?.profile !== CONTEXT_VERIFY_PROFILE || receipt.completeSelectedContext !== true ||
      receipt.sourceMaterialUntrusted !== true || receipt.repositoryMembershipVerified !== false ||
      receipt.searchCoverageVerified !== false || receipt.declarationSemanticsVerified !== false ||
      receipt.sourceBytesRead !== plan.sourceBytes || receipt.requests !== plan.requests || receipt.excerptBytesVerified !== plan.excerptBytes ||
      !Array.isArray(receipt.files) || receipt.files.length !== plan.files.length ||
      JSON.stringify(receipt.scope) !== JSON.stringify(result.scope) || JSON.stringify(receipt.pin) !== JSON.stringify(result.pin) ||
      JSON.stringify(receipt.generationVector) !== JSON.stringify(result.vector)) reject('verification does not belong to this context.');
  const files = receipt.files.map((row, index) => {
    const expected = plan.files[index];
    if (row.pathHex !== expected.file.pathHex || row.blob !== expected.file.blob || row.sourceBytes !== expected.file.sourceBytes ||
        !['file', 'executable'].includes(row.kind) || row.excerptBytes !== expected.file.excerpts.reduce((n, e) => n + e.bytesHex.length / 2, 0) ||
        row.lexicalDocuments !== expected.content.length + expected.pathHits.length || row.declarations !== expected.symbols.length) reject('verification file inventory changed.');
    // Whitelist output, even though this is normally an internally owned receipt.
    return { pathHex: row.pathHex, blob: row.blob, sourceBytes: row.sourceBytes, kind: row.kind,
      excerptBytes: row.excerptBytes, lexicalDocuments: row.lexicalDocuments, declarations: row.declarations };
  });
  return { schema: 'frankengit-context-verification-summary-v1', localObservationOnly: true, independentlyReplayableProof: false,
    profile: CONTEXT_VERIFY_PROFILE, scope: structuredClone(result.scope), pin: structuredClone(result.pin),
    generationVector: structuredClone(result.vector), sourceMaterialUntrusted: true, repositoryMembershipVerified: false,
    searchCoverageVerified: false, declarationSemanticsVerified: false, completeSelectedContext: true,
    sourceBytesRead: plan.sourceBytes, requests: plan.requests, excerptBytesVerified: plan.excerptBytes, limits: plan.limits, files };
}
export function mountContextVerification(document, result, { verify, current, display, urlApi = globalThis.URL }) {
  const node = (tag, text = '') => { const value = document.createElement(tag); value.textContent = text; return value; };
  const section = node('section'); section.id = 'context-verification';
  section.append(node('h3', 'Verify all selected context files'));
  const requiredBytes = result.context.sourceBytesRead;
  const requiredRequests = result.context.files.reduce((n, f) => n + Math.max(1, Math.ceil(f.sourceBytes / PAGE_BYTES)), 0);
  section.append(node('p', `This explicit read verifies ${result.context.files.length} full files (${requiredBytes} source bytes, ${requiredRequests} page requests). It checks all excerpts and match coordinates against complete native blob hashes, not only visible text.`),
    node('p', 'A matching blob hash does not authenticate repository membership, index coverage, declaration semantics or permissions. Source material remains untrusted. No automatic verification or retry runs.'));
  const field = (label, id, value, max) => {
    const wrapper = node('label', label), input = node('input'); input.type = 'number'; input.id = id;
    input.min = '1'; input.max = String(max); input.step = '1'; input.value = String(Math.max(1, value));
    wrapper.append(input); section.append(wrapper); return input;
  };
  const source = field('Maximum verification source bytes', 'verify-context-bytes', requiredBytes, CONTEXT_VERIFY_LIMITS.maxSourceBytes);
  const requests = field('Maximum verification page requests', 'verify-context-requests', requiredRequests, CONTEXT_VERIFY_LIMITS.maxRequests);
  const consentLabel = node('label', ' Read every selected full file under these limits'), consent = node('input');
  consent.type = 'checkbox'; consent.id = 'verify-context-consent'; consentLabel.append(consent); section.append(consentLabel);
  const submit = node('button', 'Verify complete selected context'); submit.type = 'button'; submit.id = 'verify-context';
  const download = node('button', 'Download local verification summary'); download.type = 'button'; download.id = 'verify-context-download';
  const status = node('p'); status.setAttribute('role', 'status'); status.setAttribute('aria-live', 'polite');
  const output = node('pre'); output.id = 'verify-context-result'; section.append(submit, download, status, output);
  let generation = 0, working = false, disposed = false, summary = null, url = null;
  const revoke = () => { if (url !== null) { urlApi.revokeObjectURL(url); url = null; } };
  function sync() {
    const enabled = !disposed && current() && !working;
    submit.disabled = !enabled || !consent.checked || !result.context.files.length;
    download.disabled = !enabled || summary === null;
    for (const input of [source, requests, consent]) input.disabled = !enabled;
  }
  function invalidate() {
    generation++; working = false; summary = null; consent.checked = false; revoke(); output.textContent = '';
    status.textContent = 'No complete context verification is selected.'; sync();
  }
  for (const input of [source, requests]) for (const name of ['input', 'change']) input.addEventListener(name, () => {
    // Editing a budget cannot transfer consent or relabel a retained result.
    consent.checked = false; sync();
  });
  consent.addEventListener('change', sync);
  submit.addEventListener('click', async event => {
    event.preventDefault();
    if (disposed || !current() || working || !consent.checked || !result.context.files.length) return;
    const serial = ++generation; working = true; summary = null; revoke(); output.textContent = ''; consent.checked = false; sync();
    status.textContent = 'Verifying every selected full file at the retained snapshot…';
    try {
      const read = value => { if (!/^(0|[1-9][0-9]{0,8})$/.test(value)) reject('invalid verification budget.'); return Number(value); };
      const limits = options({ maxSourceBytes: read(source.value), maxRequests: read(requests.value) });
      prepare(result, limits, () => {}); // Refuse the entire over-budget selection before invoking the host.
      const receipt = await verify(limits);
      if (disposed || serial !== generation || !current()) return;
      summary = contextVerificationSummary(result, receipt);
      output.textContent = `Checked ${summary.files.length} complete files; ${summary.sourceBytesRead} source bytes; ${summary.requests} page requests.\n` +
        summary.files.map(file => `${display(bytes(file.pathHex, 4096))}: ${file.blob} · ${file.sourceBytes} bytes · ${file.lexicalDocuments} lexical witnesses · ${file.declarations} declarations`).join('\n');
      status.textContent = 'Every selected context file and excerpt passed byte verification. Coverage and repository membership remain unverified.';
    } catch {
      if (!disposed && serial === generation) { summary = null; output.textContent = ''; status.textContent = 'Whole-context verification failed or was canceled. No successful subset is selected; no retry was attempted.'; }
    } finally { if (serial === generation) working = false; sync(); }
  });
  download.addEventListener('click', event => {
    event.preventDefault(); if (disposed || working || !current() || summary === null) return;
    let anchor = null;
    try {
      const serialized = JSON.stringify(summary, null, 2);
      if (serialized.length > 1024 * 1024 || encoder.encode(serialized).length > 1024 * 1024) reject('summary exceeds its byte bound.');
      revoke(); url = urlApi.createObjectURL(new Blob([serialized], { type: 'application/json' }));
      anchor = node('a'); anchor.href = url; anchor.download = 'frankengit-context-verification.json'; section.append(anchor); anchor.click();
      status.textContent = 'Private token-free local-check summary exported. It is not an independently replayable proof, authority grant or complete repository export.';
    } catch { revoke(); status.textContent = 'Verification summary export failed. No network request was attempted.'; }
    finally { anchor?.remove(); }
  });
  invalidate();
  return { element: section, submit, download, sync, invalidate, dispose() { disposed = true; invalidate(); } };
}
