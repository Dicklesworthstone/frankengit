// Bounded, inert source excerpts from the native source/context-initial read.
// The caller MUST validate reply.retrieval with initialReply before this join.
// Partial excerpts do not independently prove a Git OID or grant agent authority.
export const CONTEXT_PROFILE = 'source-initial-context-v1';
export const CONTEXT_RANKED_PROFILE = 'context-weighted-rrf-q16-v1';
const PATH_SELECTION = 'raw-path-prefix';
const RANK_CONSTANT = 60, SCORE_SCALE = 65536;
export const CONTEXT_DEFAULTS = Object.freeze({ maxFiles: 8, radiusBytes: 128,
  maxSourceBytes: 64 * 1024 * 1024, maxExcerptBytes: 256 * 1024, selection: PATH_SELECTION });
const MAX_FILE = 8 * 1024 * 1024, MAX_ANCHORS = 4096, MAX_WINDOWS = 128;
const CHANNELS = ['content', 'path', 'symbol'];
const LABEL_PROFILE = 'source-read-result-labels-v1';
const positionDomain = channel => channel === 'path' ? 'raw-path-bytes' : 'source-blob-bytes';
const limitNames = ['maxFiles', 'radiusBytes', 'maxSourceBytes', 'maxExcerptBytes'];
const optionNames = [...limitNames, 'selection'];
const wireNames = ['context_max_files', 'context_radius_bytes', 'context_max_source_bytes', 'context_max_excerpt_bytes'];
const reject = message => { throw new Error(`Source context: ${message}`); };
function object(value, names, all = true) {
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
      Object.keys(value).some(key => !names.includes(key)) ||
      (all && names.some(key => !Object.hasOwn(value, key)))) reject('invalid or unsupported fields.');
  return value;
}
function count(value, name, min, max) {
  if (!Number.isSafeInteger(value) || value < min || value > max) reject(`invalid ${name}.`);
  return value;
}
function hexBytes(value, maximum) {
  // Length is checked before matching or allocating; lowercase is canonical.
  if (typeof value !== 'string' || value.length > maximum * 2 || value.length % 2 || /[^0-9a-f]/u.test(value)) reject('invalid byte encoding.');
  return value;
}
// Native GitOid Display includes its hash domain, while initialReply installs
// bare digests. Compare semantic identities only after enforcing the selected
// repository's domain and exact digest width; never strip an arbitrary prefix.
function nativeBlob(value, algorithm) {
  if (!['sha1', 'sha256'].includes(algorithm) || typeof value !== 'string') reject('invalid native blob identity.');
  const raw = value.startsWith(`${algorithm}:`) ? value.slice(algorithm.length + 1) : value;
  if (!new RegExp(`^[0-9a-f]{${algorithm === 'sha1' ? 40 : 64}}$`).test(raw) || /^0+$/.test(raw)) reject('invalid native blob identity.');
  return raw;
}
function decode(value) {
  return Uint8Array.from({ length: value.length / 2 }, (_, i) => Number.parseInt(value.slice(i * 2, i * 2 + 2), 16));
}
const word = byte => (byte >= 48 && byte <= 57) || (byte >= 65 && byte <= 90) ||
  (byte >= 97 && byte <= 122) || byte === 95;
const fold = byte => byte >= 65 && byte <= 90 ? byte + 32 : byte;
const same = (a, b) => a.length === b.length && a.every((value, i) => value === b[i]);
function label(value) {
  if (typeof value !== 'string' || value.length !== 64 || !/^[0-9a-f]{64}$/.test(value)) reject('invalid lineage label.');
  return value;
}
function labelledRetrieval(retrieval) {
  const evidence = retrieval.authorization;
  if (evidence === undefined || evidence.state === 'legacy-unlabelled') return false;
  if (evidence.state !== 'labelled' || evidence.profile !== LABEL_PROFILE || evidence.reusableCapability !== false) reject('invalid Initial label profile.');
  label(evidence.binding);
  return true;
}

export function contextLimits(input = {}) {
  object(input, optionNames, false);
  const read = (name, min, max) => count(Object.hasOwn(input, name) ? input[name] : CONTEXT_DEFAULTS[name], name, min, max);
  const selection = Object.hasOwn(input, 'selection') ? input.selection : PATH_SELECTION;
  if (![PATH_SELECTION, CONTEXT_RANKED_PROFILE].includes(selection)) reject('unsupported context selection.');
  return { selection, maxFiles: read('maxFiles', 1, 32), radiusBytes: read('radiusBytes', 0, 4096),
    maxSourceBytes: read('maxSourceBytes', 1, 64 * 1024 * 1024), maxExcerptBytes: read('maxExcerptBytes', 1, 1024 * 1024) };
}
// Hydration must be explicit. Other search modes keep their closed grammar.
export function splitContextQuery(input) {
  if (!input || !Object.hasOwn(input, 'context')) return { input, limits: null };
  if (input.mode !== 'initial') reject('source hydration requires combined Initial search.');
  const { context, ...query } = input;
  object(context, optionNames, false);
  return { input: query, limits: contextLimits(context) };
}
export function contextCommand(initialBody, input) {
  const limits = contextLimits(input);
  if (typeof initialBody !== 'string' || initialBody.length > 1024 * 1024) reject('invalid Initial request.');
  const body = new URLSearchParams(initialBody);
  if (body.has('context_selection')) reject('duplicate context selection.');
  for (let i = 0; i < limitNames.length; i++) {
    if (body.has(wireNames[i])) reject('duplicate context option.');
    body.append(wireNames[i], String(limits[limitNames[i]]));
  }
  // Preserve the default endpoint grammar byte-for-byte; ranked is explicit.
  if (limits.selection === CONTEXT_RANKED_PROFILE) body.append('context_selection', CONTEXT_RANKED_PROFILE);
  return body.toString();
}

function plan(retrieval, limits, checkpoint) {
  if (retrieval?.query?.mode !== 'initial' || typeof retrieval.complete !== 'boolean') reject('validate the Initial receipt first.');
  const files = new Map(), ranked = limits.selection === CONTEXT_RANKED_PROFILE, labelled = labelledRetrieval(retrieval);
  function select(hit, size, channel) {
    checkpoint();
    if (labelled) {
      label(hit.authorizationLabel);
      if (hit.positionDomain !== (channel === 'symbol' ? 'source-declaration-bytes' : positionDomain(channel))) reject('Initial result position domain changed.');
    } else if (Object.hasOwn(hit, 'authorizationLabel') || Object.hasOwn(hit, 'positionDomain')) reject('undeclared Initial row labels.');
    const path = hexBytes(hit.pathHex, 4096);
    if (!path.length || typeof hit.blob !== 'string' || !/^(?:[0-9a-f]{40}|[0-9a-f]{64})$/u.test(hit.blob)) reject('invalid selected file.');
    if (ranked && ((!['sha1', 'sha256'].includes(retrieval.scope?.format)) ||
        hit.blob.length !== (retrieval.scope.format === 'sha1' ? 40 : 64) || /^0+$/u.test(hit.blob))) reject('invalid ranked file identity.');
    const previous = files.get(path);
    if (previous) {
      if (previous.blob !== hit.blob || (size !== null && previous.sourceBytes !== null && previous.sourceBytes !== size)) reject('mixed file identities.');
      if (size !== null) previous.sourceBytes = size;
      if (labelled && !previous.authorizationLabels.includes(hit.authorizationLabel)) previous.authorizationLabels.push(hit.authorizationLabel);
      return;
    }
    files.set(path, { pathHex: path, blob: hit.blob, sourceBytes: size, witnesses: [], score: 0, contributions: [],
      authorizationLabels: labelled ? [hit.authorizationLabel] : [] });
  }
  for (const channel of ['content', 'path']) {
    const hits = retrieval[channel]?.hits;
    if (!Array.isArray(hits) || hits.length > 100) reject('invalid selected channel.');
    for (const hit of hits) select(hit, count(hit.contentBytes, 'indexed file bytes', 0, MAX_FILE), channel);
  }
  const symbols = retrieval.symbols;
  if (!symbols || !['available', 'unavailable', 'not_requested'].includes(symbols.state)) reject('invalid symbol availability.');
  const symbolHits = symbols.state === 'available' ? symbols.result?.hits : [];
  if (!Array.isArray(symbolHits) || symbolHits.length > 100) reject('invalid selected symbols.');
  for (const hit of symbolHits) select(hit, null, 'symbol');
  const candidateFiles = files.size;
  let ranking = null;
  if (ranked) {
    // Reproduce the fixed native document fusion over ALL returned candidates,
    // not merely the response's claimed winners. Repeated symbol declarations
    // contribute once, but their identities were checked above before dedup.
    for (const [channel, hits] of [['content', retrieval.content.hits], ['path', retrieval.path.hits], ['symbol', symbolHits]]) {
      let previous = null, rank = 0;
      for (const hit of hits) {
        checkpoint();
        if (previous !== null && hit.pathHex < previous) reject('ranked channel order changed.');
        if (hit.pathHex === previous) continue;
        previous = hit.pathHex; rank++;
        const weight = channel === 'symbol' ? 2 : 1, score = Math.floor(weight * SCORE_SCALE / (RANK_CONSTANT + rank));
        const file = files.get(hit.pathHex);
        file.score += score;
        file.contributions.push({ channel, document_rank: rank, weight, score_q16: score });
      }
    }
    checkpoint();
    const winners = [...files.values()].sort((a, b) => b.score - a.score || (a.pathHex < b.pathHex ? -1 : a.pathHex > b.pathHex ? 1 : 0))
      .slice(0, limits.maxFiles);
    checkpoint();
    ranking = { profile: CONTEXT_RANKED_PROFILE, rank_constant: RANK_CONSTANT, score_scale: SCORE_SCALE,
      input_order: 'raw-path-distinct-documents', tie_break: 'raw-path-ascending',
      ranked_over: 'returned-channel-hits', semantic_relevance: false,
      selected: winners.map((file, i) => ({ position: i + 1, path_hex: file.pathHex, blob: file.blob,
        score_q16: file.score, contributions: file.contributions })) };
  }
  const selectedPaths = ranked ? new Set(ranking.selected.map(file => file.path_hex)) : null;
  // Relevance decides membership only. Hydration/excerpt/file traversal remains
  // raw-path sorted, including when the highest-scoring path sorts last.
  const selected = new Map([...files].filter(([path]) => !selectedPaths || selectedPaths.has(path))
    .sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0).slice(0, limits.maxFiles));
  let anchors = 0;
  function push(hit, channel, offset, length, expected, raw = false) {
    checkpoint();
    const file = selected.get(hit.pathHex);
    if (!file) return;
    if (++anchors > MAX_ANCHORS) reject('anchor budget exceeded.');
    hexBytes(expected, 128);
    count(offset, 'anchor offset', 0, channel === 'path' ? hit.pathHex.length / 2 : MAX_FILE);
    count(length, 'anchor length', 1, 128);
    if (expected.length / 2 !== length || typeof raw !== 'boolean' || (raw && offset < 2)) reject('invalid anchor evidence.');
    file.witnesses.push({ channel, offset, length, expected, raw,
      ...(labelled ? { authorizationLabel: hit.authorizationLabel } : {}) });
  }
  for (const channel of ['content', 'path']) for (const hit of retrieval[channel].hits) {
    if (!Array.isArray(hit.spans) || hit.spans.length > 32 || (labelled && !hit.spans.length)) reject('invalid lexical spans.');
    for (const span of hit.spans) push(hit, channel, span.offset, span.length,
      retrieval[channel].query.termsHex[span.queryIndex]);
  }
  for (const hit of symbolHits) push(hit, 'symbol', hit.offset, hit.length, hit.nameHex, hit.rawIdentifier);
  for (const file of selected.values()) {
    file.witnesses.sort((a, b) => CHANNELS.indexOf(a.channel) - CHANNELS.indexOf(b.channel) ||
      a.offset - b.offset || a.length - b.length || (a.expected < b.expected ? -1 : a.expected > b.expected ? 1 : 0) || Number(a.raw) - Number(b.raw));
    // New origin references cannot alter the native original witness dedup key.
    file.witnesses = file.witnesses.filter((value, i, values) => !i ||
      ['channel', 'offset', 'length', 'expected', 'raw'].some(key => value[key] !== values[i - 1][key]));
  }
  return { files: [...selected.values()], candidateFiles, ranking };
}
// Never accept a server-selected ordering, rounded score or omitted origin just
// because the totals are plausible. The entire closed receipt must match the
// locally reproduced selection, including unselected-candidate competition.
function checkRanking(received, expected, algorithm, checkpoint) {
  checkpoint();
  object(received, Object.keys(expected));
  for (const name of ['profile', 'rank_constant', 'score_scale', 'input_order', 'tie_break', 'ranked_over', 'semantic_relevance']) {
    if (received[name] !== expected[name]) reject('ranked profile evidence changed.');
  }
  if (!Array.isArray(received.selected) || received.selected.length !== expected.selected.length) reject('ranked winner count changed.');
  for (let i = 0; i < expected.selected.length; i++) {
    checkpoint();
    const row = object(received.selected[i], ['position', 'path_hex', 'blob', 'score_q16', 'contributions']), wanted = expected.selected[i];
    for (const name of ['position', 'path_hex', 'score_q16']) if (row[name] !== wanted[name]) reject('ranked winner evidence changed.');
    if (nativeBlob(row.blob, algorithm) !== wanted.blob) reject('ranked winner evidence changed.');
    if (!Array.isArray(row.contributions) || row.contributions.length !== wanted.contributions.length) reject('ranked contributions changed.');
    for (let j = 0; j < wanted.contributions.length; j++) {
      checkpoint();
      const contribution = object(row.contributions[j], ['channel', 'document_rank', 'weight', 'score_q16']);
      for (const name of ['channel', 'document_rank', 'weight', 'score_q16']) {
        if (contribution[name] !== wanted.contributions[j][name]) reject('ranked channel evidence changed.');
      }
    }
  }
  checkpoint();
}
function windows(witnesses, sourceBytes, radius) {
  const spans = witnesses.filter(witness => witness.channel !== 'path').map(witness => {
    if (witness.offset + witness.length > sourceBytes) reject('anchor escapes source.');
    return [Math.max(0, witness.offset - radius), Math.min(sourceBytes, witness.offset + witness.length + radius)];
  });
  if (!spans.length) spans.push([0, Math.min(sourceBytes, Math.max(1, radius) * 2)]);
  spans.sort((a, b) => a[0] - b[0] || a[1] - b[1]);
  const merged = [];
  for (const [start, end] of spans) {
    const last = merged.at(-1);
    if (last && start <= last[1]) last[1] = Math.max(last[1], end);
    else merged.push([start, end]);
  }
  return merged;
}
function witnessBytes(witness, bytesHex, offset, sourceBytes) {
  const start = witness.offset - offset, end = start + witness.length;
  if (start < 0 || end * 2 > bytesHex.length) reject('excerpt omits its anchor.');
  const actual = decode(bytesHex.slice(start * 2, end * 2)), expected = decode(witness.expected);
  if (witness.channel === 'symbol') {
    if (!same([...actual], [...expected])) reject('symbol bytes changed.');
    // A zero/small radius may legitimately omit r#. Check only when visible;
    // unseen bytes are native evidence, not a local verification claim.
    if (witness.raw) for (const [relative, byte] of [[start - 2, '72'], [start - 1, '23']]) {
      if (relative >= 0 && bytesHex.slice(relative * 2, (relative + 1) * 2) !== byte) reject('raw identifier prefix changed.');
    }
  } else {
    if (!same([...actual].map(fold), [...expected].map(fold))) reject('content word bytes changed.');
    const before = start > 0 ? Number.parseInt(bytesHex.slice((start - 1) * 2, start * 2), 16) : null;
    const after = end * 2 < bytesHex.length ? Number.parseInt(bytesHex.slice(end * 2, (end + 1) * 2), 16) : null;
    if ((before !== null && word(before)) || (after !== null && word(after))) reject('visible word boundary changed.');
  }
  if (witness.offset + witness.length > sourceBytes) reject('anchor escapes selected bytes.');
}

export function contextReply(reply, retrieval, input, checkpoint = () => {}) {
  const limits = contextLimits(input), labelled = labelledRetrieval(retrieval);
  checkpoint();
  object(reply, ['type', 'schema_version', 'profile', 'read_only', 'transaction_created', 'source_material_untrusted',
    'complete', 'candidate_files', 'returned_files', 'omitted_files', 'selection', 'source_blobs_read', 'source_bytes_read',
    'excerpt_bytes', 'source_file_limit', ...wireNames, 'retrieval', 'files',
    ...(limits.selection === CONTEXT_RANKED_PROFILE ? ['ranking'] : []), ...(labelled ? ['lineage_metadata_bytes'] : [])]);
  if (reply.type !== 'source_context_initial' || reply.schema_version !== 1 || reply.profile !== CONTEXT_PROFILE ||
      reply.read_only !== true || reply.transaction_created !== false || reply.source_material_untrusted !== true ||
      reply.selection !== limits.selection || typeof reply.complete !== 'boolean') reject('unsupported hydration profile.');
  for (let i = 0; i < limitNames.length; i++) if (reply[wireNames[i]] !== limits[limitNames[i]]) reject('context limit echo changed.');
  const selected = plan(retrieval, limits, checkpoint), number = selected.files.length;
  let lineageMetadataBytes = 0;
  if (labelled) {
    let maximumWindows = 0;
    for (const file of selected.files) {
      checkpoint();
      lineageMetadataBytes += file.authorizationLabels.length * 256 + file.witnesses.length * 256 + 1024;
      maximumWindows += Math.max(1, file.witnesses.filter(witness => witness.channel !== 'path').length);
    }
    lineageMetadataBytes += Math.min(maximumWindows, MAX_WINDOWS) * 192;
    const maximum = count(retrieval.query.maxResultBytes, 'Initial retained byte limit', 1, 2 * 1024 * 1024);
    const retained = count(retrieval.stats?.retainedBytes, 'Initial retained bytes', 0, maximum);
    if (reply.lineage_metadata_bytes !== lineageMetadataBytes || retained + lineageMetadataBytes > maximum) reject('lineage metadata accounting changed or exceeded the Initial budget.');
  } else if (reply.retrieval?.authorization !== undefined) reject('declared Initial labels were not retained by its validator.');
  if (selected.ranking) checkRanking(reply.ranking, selected.ranking, retrieval.scope?.format, checkpoint);
  const perFile = Math.min(MAX_FILE, Math.floor(limits.maxSourceBytes / Math.max(1, number)));
  if (!perFile || reply.source_file_limit !== perFile || !Array.isArray(reply.files) || reply.files.length !== number ||
      reply.candidate_files !== selected.candidateFiles || reply.returned_files !== number ||
      reply.omitted_files !== selected.candidateFiles - number || reply.source_blobs_read !== number ||
      reply.complete !== (selected.candidateFiles === number && retrieval.complete)) reject('inconsistent selection, completeness or source shares.');
  let sourceBytes = 0, excerptBytes = 0, totalWindows = 0;
  const files = reply.files.map((raw, i) => {
    checkpoint();
    object(raw, ['path_hex', 'blob', 'source_bytes', 'anchors', 'excerpts',
      ...(labelled ? ['position_domain', 'lineage_commitment', 'authorization_labels'] : [])]);
    const file = selected.files[i];
    if (raw.path_hex !== file.pathHex || nativeBlob(raw.blob, retrieval.scope?.format) !== file.blob) reject('file escaped the selected membership/order or changed identity.');
    const bytes = count(raw.source_bytes, 'file source bytes', 0, perFile);
    sourceBytes += bytes;
    if (sourceBytes > limits.maxSourceBytes || (file.sourceBytes !== null && file.sourceBytes !== bytes)) reject('file source accounting changed.');
    if (labelled) {
      label(raw.lineage_commitment);
      if (raw.position_domain !== 'source-blob-bytes' || !Array.isArray(raw.authorization_labels) ||
          !same(raw.authorization_labels, file.authorizationLabels)) reject('file original label membership changed.');
    }
    if (!Array.isArray(raw.anchors) || raw.anchors.length !== file.witnesses.length) reject('missing or excess anchors.');
    for (let a = 0; a < raw.anchors.length; a++) {
      const anchor = object(raw.anchors[a], ['channel', 'byte_offset', 'byte_length',
        ...(labelled ? ['authorization_label', 'position_domain'] : [])]), witness = file.witnesses[a];
      if (anchor.channel !== witness.channel || anchor.byte_offset !== witness.offset || anchor.byte_length !== witness.length) reject('anchor changed or reordered.');
      if (labelled && (anchor.authorization_label !== witness.authorizationLabel || anchor.position_domain !== positionDomain(witness.channel))) reject('anchor original label or position domain changed.');
      if (witness.channel === 'path') witnessBytes(witness, file.pathHex, 0, file.pathHex.length / 2);
    }
    const expected = windows(file.witnesses, bytes, limits.radiusBytes);
    totalWindows += expected.length;
    if (totalWindows > MAX_WINDOWS || !Array.isArray(raw.excerpts) || raw.excerpts.length !== expected.length) reject('window budget or shape changed.');
    const excerpts = raw.excerpts.map((excerpt, e) => {
      checkpoint();
      object(excerpt, ['byte_offset', 'untrusted_bytes_hex', ...(labelled ? ['position_domain', 'lineage_commitment'] : [])]);
      if (labelled && (excerpt.position_domain !== 'source-blob-bytes' || excerpt.lineage_commitment !== raw.lineage_commitment)) reject('excerpt file commitment or position domain changed.');
      const [start, end] = expected[e], value = hexBytes(excerpt.untrusted_bytes_hex, limits.maxExcerptBytes - excerptBytes);
      if (excerpt.byte_offset !== start || value.length / 2 !== end - start) reject('excerpt range changed or truncated.');
      excerptBytes += end - start;
      for (const witness of file.witnesses) {
        checkpoint();
        if (witness.channel !== 'path' && witness.offset >= start && witness.offset + witness.length <= end) {
          witnessBytes(witness, value, start, bytes);
        }
      }
      return { offset: start, bytesHex: value,
        ...(labelled ? { lineageCommitment: raw.lineage_commitment, positionDomain: 'source-blob-bytes' } : {}) };
    });
    return { pathHex: file.pathHex, blob: file.blob, sourceBytes: bytes,
      ...(labelled ? { authorizationLabels: [...raw.authorization_labels], lineageCommitment: raw.lineage_commitment, positionDomain: 'source-blob-bytes' } : {}),
      anchors: raw.anchors.map(anchor => ({ channel: anchor.channel, offset: anchor.byte_offset, length: anchor.byte_length,
        ...(labelled ? { authorizationLabel: anchor.authorization_label, positionDomain: anchor.position_domain } : {}) })), excerpts };
  });
  if (reply.source_bytes_read !== sourceBytes || reply.excerpt_bytes !== excerptBytes) reject('aggregate byte accounting changed.');
  checkpoint();
  return { profile: CONTEXT_PROFILE, selection: limits.selection, ...(selected.ranking ? { ranking: selected.ranking } : {}), complete: reply.complete, candidateFiles: selected.candidateFiles,
    omittedFiles: selected.candidateFiles - number, sourceBlobsRead: number, sourceBytesRead: sourceBytes,
    excerptBytes, sourceFileLimit: perFile, limits, files, sourceMaterialUntrusted: true,
    authorization: labelled ? { ...retrieval.authorization } : { state: 'legacy-unlabelled' }, ...(labelled ? { lineageMetadataBytes } : {}) };
}

// The Initial validator always receives THIS envelope's child. No independently
// fetched channels or saved report can be substituted for the hydrated receipt.
export function joinInitialContext(reply, validateRetrieval, input, checkpoint = () => {}) {
  checkpoint();
  if (!reply || typeof reply !== 'object' || typeof validateRetrieval !== 'function') reject('Initial validator required.');
  const retrieval = validateRetrieval(reply.retrieval);
  const context = contextReply(reply, retrieval, input, checkpoint);
  checkpoint();
  return { ...retrieval, context };
}

export const CONTEXT_DISPLAY_BYTES = 64 * 1024;
export const CONTEXT_REPORT_BYTES = 16 * 1024 * 1024;
const controlRows = [
  ['maxFiles', 'context-files', 'Maximum distinct source files', 1, 32],
  ['radiusBytes', 'context-radius', 'Context radius in bytes (0: match bytes only)', 0, 4096],
  ['maxSourceBytes', 'context-source-bytes', 'Total source-decode byte budget', 1, 64 * 1024 * 1024],
  ['maxExcerptBytes', 'context-excerpt-bytes', 'Retained excerpt byte budget', 1, 1024 * 1024],
];
export function readContextQuery(document) {
  if (!document.getElementById('context-enabled')?.checked) return {};
  const values = {};
  for (const [key, id] of controlRows) {
    const text = document.getElementById(id)?.value;
    if (typeof text !== 'string' || !/^(?:0|[1-9][0-9]{0,8})$/u.test(text)) reject('enter canonical decimal context limits.');
    values[key] = Number(text);
  }
  values.selection = document.getElementById('context-selection')?.value;
  return { context: contextLimits(values) };
}
export function mountContextControls(document, parent, invalidate) {
  if (!parent || document.getElementById('context-enabled')) reject('missing or duplicate context controls.');
  const make = (tag, text = '') => { const node = document.createElement(tag); node.textContent = text; return node; };
  const section = make('fieldset'); section.id = 'context-controls';
  section.append(make('legend', 'Optional exact source context'));
  const label = make('label');
  const enabled = make('input'); enabled.type = 'checkbox'; enabled.id = 'context-enabled'; enabled.checked = false;
  label.append(enabled, make('span', ' Include source excerpts in this combined search')); section.append(label);
  section.append(make('p', 'Off by default. Enabling this reads source blobs in the same authenticated native request as Initial retrieval; it does not join independent searches or build an index. Path matches yield a bounded file preamble, not file offsets.'));
  const selectionLabel = make('label', 'Which matched files to hydrate first');
  const selection = make('select'); selection.id = 'context-selection';
  for (const [value, text] of [[PATH_SELECTION, 'Raw-path prefix (compatibility default)'],
    [CONTEXT_RANKED_PROFILE, 'Corroborated documents (fixed integer fusion)']]) {
    const option = make('option', text); option.value = value; selection.append(option);
  }
  selection.value = PATH_SELECTION; selection.disabled = true;
  selectionLabel.append(selection); section.append(selectionLabel);
  section.append(make('p', 'Ranked selection rewards agreement between returned content, path and declaration channels. It uses fixed weights and raw-path document ranks, not semantic relevance, authorization or a broader search. The file display remains raw-path sorted.'));
  for (const event of ['input', 'change']) selection.addEventListener(event, invalidate);
  const inputs = [selection];
  for (const [key, id, name, min, max] of controlRows) {
    const label = make('label', name), input = make('input');
    input.id = id; input.type = 'number'; input.min = String(min); input.max = String(max); input.step = '1';
    input.value = String(CONTEXT_DEFAULTS[key]); input.required = true; input.disabled = true;
    label.append(input); section.append(label); inputs.push(input);
    for (const event of ['input', 'change']) input.addEventListener(event, invalidate);
  }
  for (const event of ['input', 'change']) enabled.addEventListener(event, invalidate);
  parent.append(section);
  return {
    sync(combined) {
      section.hidden = !combined; enabled.disabled = !combined;
      for (const input of inputs) input.disabled = !combined || !enabled.checked;
    },
    reset() { enabled.checked = false; selection.value = PATH_SELECTION; for (const input of inputs) input.disabled = true; },
  };
}
function pick(value, names) {
  const result = {};
  for (const name of names) if (value && Object.hasOwn(value, name)) result[name] = value[name];
  return result;
}
function coverage(channel) {
  return { ...pick(channel, ['complete', 'coverageComplete']), returnedHits: channel.hits.length,
    omissions: channel.omissions.map(row => pick(row, ['pathHex', 'blob', 'sourceBytes', 'reason', 'offset', 'limit'])) };
}
// Export a closed, token-free source report, not a replayable request, authority
// proof, model prompt, or Agent Protocol ContextPacket. No ambient session state.
export function contextReport(value) {
  if (!value?.context || value.query?.mode !== 'initial') reject('select a hydrated Initial result.');
  const context = value.context, symbols = value.symbols, labelled = labelledRetrieval(value);
  const report = { schema: 'frankengit-source-context-report-v1', readOnly: true, sourceMaterialUntrusted: true,
    independentBlobVerification: false,
    scope: pick(value.scope, ['tenant', 'repository', 'incarnation', 'format']),
    source: pick(value.pin, ['head', 'sourceHead', 'rcr', 'commit', 'tree']),
    generationVector: { lexical: pick(value.vector.lexical, ['token', 'number']),
      symbols: value.vector.symbols === null ? null : pick(value.vector.symbols, ['token', 'number']) },
    query: { ...pick(value.query, ['mode', 'termsHex', 'prefixesHex', 'maxMatches', 'maxWork', 'maxPayloadBytes', 'maxResultBytes', 'maxFileBytes']),
      symbol: value.query.symbol ? pick(value.query.symbol, ['nameHex', 'match', 'kinds', 'policy']) : null },
    retrieval: { complete: value.complete,
      stats: pick(value.stats, ['retainedBytes', 'payloadBytes', 'work']),
      content: coverage(value.content), path: coverage(value.path),
      symbols: { state: symbols.state, ...(symbols.state === 'unavailable' ? { reason: symbols.reason } : {}),
        ...(symbols.state === 'available' ? coverage(symbols.result) : {}) } },
    context: { ...pick(context, ['profile', 'selection', 'complete', 'candidateFiles', 'omittedFiles', 'sourceBlobsRead',
      'sourceBytesRead', 'excerptBytes', 'sourceFileLimit']), limits: pick(context.limits, optionNames),
      files: context.files.map(file => ({ ...pick(file, ['pathHex', 'blob', 'sourceBytes',
        ...(labelled ? ['authorizationLabels', 'lineageCommitment', 'positionDomain'] : [])]),
        anchors: file.anchors.map(anchor => pick(anchor, ['channel', 'offset', 'length',
          ...(labelled ? ['authorizationLabel', 'positionDomain'] : [])])),
        excerpts: file.excerpts.map(excerpt => pick(excerpt, ['offset', 'bytesHex',
          ...(labelled ? ['lineageCommitment', 'positionDomain'] : [])])) })) } };
  if (labelled) {
    // Retain native lineage without exporting credentials or claiming that the
    // browser recomputed commitments or authenticated this source.
    report.retrieval.authorization = pick(value.authorization, ['state', 'profile', 'host', 'principal', 'scope', 'binding', 'reusableCapability']);
    report.context.lineageMetadataBytes = context.lineageMetadataBytes;
  }
  if (context.selection === CONTEXT_RANKED_PROFILE) {
    if (!context.ranking) reject('ranked selection receipt required for export.');
    report.context.ranking = { ...pick(context.ranking, ['profile', 'rank_constant', 'score_scale',
      'input_order', 'tie_break', 'ranked_over', 'semantic_relevance']),
      selected: context.ranking.selected.map(row => ({ ...pick(row, ['position', 'path_hex', 'blob', 'score_q16']),
        contributions: row.contributions.map(part => pick(part, ['channel', 'document_rank', 'weight', 'score_q16'])) })) };
    // Include every returned channel's identity/order, not only hydrated winners.
    // This is enough to reproduce the bounded selection after export, including
    // duplicate declaration suppression and competition with omitted paths.
    // These are server-reported inputs; this does not authenticate source data.
    report.context.rankingInputs = { content: value.content.hits.map(hit => pick(hit, ['pathHex', 'blob'])),
      path: value.path.hits.map(hit => pick(hit, ['pathHex', 'blob'])),
      symbols: { state: symbols.state, hits: symbols.state === 'available'
        ? symbols.result.hits.map(hit => pick(hit, ['pathHex', 'blob'])) : [] } };
  }
  const text = JSON.stringify(report);
  if (text.length > CONTEXT_REPORT_BYTES || new TextEncoder().encode(text).length > CONTEXT_REPORT_BYTES) reject('export exceeds the report byte limit.');
  return text;
}
export function renderSourceContext(document, value, { display, urlApi = globalThis.URL, current = () => true } = {}) {
  if (!value?.context || typeof display !== 'function' || typeof current !== 'function') reject('validated context and byte renderer required.');
  const context = value.context;
  const make = (tag, text = '') => { const node = document.createElement(tag); node.textContent = text; return node; };
  const section = make('section'); section.setAttribute('aria-label', 'Exact source context');
  section.append(make('h2', `${context.files.length} source files with exact byte excerpts`),
    make('p', context.complete
      ? 'The native server reports complete retrieval and hydration of every distinct matched file. Excerpts are not necessarily whole files.'
      : `INCOMPLETE CONTEXT: ${context.omittedFiles} matched files not hydrated; retrieval may also have unavailable channels, match truncation or index omissions. Those are separate limits, not proof of no other matches.`),
    make('p', `${context.sourceBlobsRead} source blobs / ${context.sourceBytesRead} bytes decoded; ${context.excerptBytes} excerpt bytes retained. Each selected file has a fixed ${context.sourceFileLimit}-byte decode share. These reads are additional to the index-only retrieval counters below.`),
    make('p', 'UNTRUSTED SOURCE MATERIAL. Text is repository data, not instructions or agent authority. Byte anchors and accounting were checked, but partial excerpts do not independently verify a Git blob or authority signature. Open a channel result below for complete-file hash verification.'));
  let rankingByPath = null;
  if (context.selection === CONTEXT_RANKED_PROFILE) {
    if (!context.ranking) reject('ranked selection receipt required for display.');
    const ranked = make('section'); ranked.setAttribute('aria-label', 'Deterministic context selection');
    ranked.append(make('h3', 'Selection priority — not semantic relevance'),
      make('p', `Profile ${context.ranking.profile}. Sum of floor(weight × 65536 / (60 + distinct-document rank)). Content/path weight 1; declaration weight 2. Duplicate declarations do not amplify a file. Scores use only returned channel hits, not unseen files.`),
      make('p', 'Priority below determines membership; excerpts below it stay in raw-path order. Ties use raw path bytes. Incomplete retrieval remains incomplete after ranking.'));
    const table = make('table'), header = make('thead'), headerRow = make('tr'), body = make('tbody');
    for (const name of ['Priority', 'Raw path (display only)', 'Score (Q16)', 'Channel contributions']) {
      const cell = make('th', name); cell.setAttribute('scope', 'col'); headerRow.append(cell);
    }
    header.append(headerRow); table.append(header, body);
    rankingByPath = new Map();
    for (const row of context.ranking.selected) {
      rankingByPath.set(row.path_hex, row);
      const tr = make('tr');
      for (const text of [String(row.position), display(decode(row.path_hex)), String(row.score_q16),
        row.contributions.map(part => `${part.channel}: document ${part.document_rank}, weight ${part.weight}, +${part.score_q16}`).join('; ')]) {
        tr.append(make('td', text));
      }
      body.append(tr);
    }
    ranked.append(table); section.append(ranked);
  } else section.append(make('p', 'Selection: raw-path prefix. Alphabetical truncation, not relevance ranking.'));
  const download = make('button', 'Download exact source-context report'); download.type = 'button';
  const status = make('p'); status.setAttribute('role', 'status'); section.append(download, status);
  let remaining = CONTEXT_DISPLAY_BYTES, clipped = false, url = null, disposed = false;
  for (const file of context.files) {
    const article = make('article');
    article.append(make('h3', `${rankingByPath ? `Priority ${rankingByPath.get(file.pathHex).position} · ` : ''}${display(decode(file.pathHex))}`),
      make('pre', `Path bytes: ${file.pathHex}\nNative blob (server-reported): ${file.blob}\nFull source length: ${file.sourceBytes} bytes`),
      make('p', file.anchors.map(anchor => `${anchor.channel} ${anchor.channel === 'path' ? 'PATH' : 'FILE'} bytes [${anchor.offset}, ${anchor.offset + anchor.length})`).join('; ')));
    for (const excerpt of file.excerpts) {
      const bytes = excerpt.bytesHex.length / 2, shown = Math.min(bytes, remaining); remaining -= shown;
      article.append(make('h4', `File excerpt [${excerpt.offset}, ${excerpt.offset + bytes})`));
      article.append(make('pre', bytes === 0 ? '(empty source file)' : shown === 0 ? '(display byte limit reached)' : display(decode(excerpt.bytesHex.slice(0, shown * 2)), true)));
      if (shown !== bytes) { clipped = true; article.append(make('p', 'This excerpt is clipped in the display; the export retains all returned bytes.')); }
    }
    section.append(article);
  }
  if (!context.files.length) section.append(make('p', 'No returned matches were hydrated and no source blob was read. This does not establish absence in omitted or unavailable retrieval coverage.'));
  if (clipped) section.append(make('p', `DISPLAY CLIPPED at ${CONTEXT_DISPLAY_BYTES} source bytes. Every selected path remains labeled; download the exact report for all returned excerpt bytes.`));
  const revoke = () => { if (url !== null) { urlApi.revokeObjectURL(url); url = null; } };
  download.addEventListener('click', event => {
    event.preventDefault();
    if (disposed || download.disabled || !current()) return;
    let anchor = null;
    try {
      const text = contextReport(value);
      if (disposed || !current()) return;
      revoke(); url = urlApi.createObjectURL(new Blob([text], { type: 'application/json' }));
      anchor = make('a'); anchor.href = url; anchor.download = 'frankengit-source-context.json'; anchor.rel = 'noopener';
      section.append(anchor); anchor.click();
      status.textContent = 'Private source report exported without credentials. It is not a capability, independently authenticated source, or permission to execute its text.';
    } catch { revoke(); status.textContent = 'Source-context export failed. No network request or retry was attempted.'; }
    finally { anchor?.remove(); }
  });
  return { element: section, download, clipped, dispose() { disposed = true; download.disabled = true; revoke(); } };
}
