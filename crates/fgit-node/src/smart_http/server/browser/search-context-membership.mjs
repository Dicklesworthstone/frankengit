// Selected native blob membership below an independently supplied commit ID.
// This is not repository authority, freshness, signature or search-coverage proof.
import { binding, copy, form, hex, integer, keys, oid, record, snapshot, unhex, utf8 } from './pulls-core.mjs';

export const MEMBERSHIP_PROFILE = 'frankengit-context-membership-proof-v1';
export const MEMBERSHIP_LIMITS = Object.freeze({ maxRequests: 512, maxTrees: 128,
  maxEntries: 16384, maxTreeBytes: 4 * 1024 * 1024 });
const MODES = Object.freeze({ directory: '40000', file: '100644', executable: '100755', symlink: '120000', gitlink: '160000' });
const refuse = message => { throw new Error(`Context membership: ${message}`); };
const same = (a, b) => a.length === b.length && a.every((value, i) => value === b[i]);
const compare = (a, b) => { for (let i = 0; i < Math.min(a.length, b.length); i++) if (a[i] !== b[i]) return a[i] - b[i]; return a.length - b.length; };
function exact(value, names) { keys(value, names); if (names.some(name => !Object.hasOwn(value, name))) refuse('missing field.'); return value; }
export function membershipLimits(input = {}) {
  keys(input, Object.keys(MEMBERSHIP_LIMITS));
  return Object.fromEntries(Object.entries(MEMBERSHIP_LIMITS).map(([name, max]) =>
    [name, integer(Object.hasOwn(input, name) ? input[name] : max, name, 1, max)]));
}
function path(value) {
  const bytes = unhex(value, 4096), parts = []; let start = 0;
  if (!bytes.length || bytes.includes(0)) refuse('invalid path.');
  for (let at = 0; at <= bytes.length; at++) {
    if (at < bytes.length && bytes[at] !== 47) continue;
    const part = bytes.subarray(start, at);
    if (!part.length || same(part, [46]) || same(part, [46, 46])) refuse('invalid path component.');
    parts.push(hex(part)); start = at + 1;
  }
  if (parts.length > 64) refuse('path depth exceeded.');
  return parts;
}
function selection(input, limits) {
  exact(input, ['format', 'commit', 'files']);
  const commit = oid(input.commit, input.format);
  if (!Array.isArray(input.files) || !input.files.length || input.files.length > 32) refuse('select 1 through 32 context files.');
  const wanted = new Map(), directories = new Set([null]); let previous = '', size = 0;
  const files = input.files.map(row => {
    exact(row, ['pathHex', 'blob']); const parts = path(row.pathHex);
    if (row.pathHex <= previous || (size += row.pathHex.length / 2) > 32768) refuse('path order, duplicates or path-byte limit.');
    previous = row.pathHex;
    const file = { pathHex: row.pathHex, blob: oid(row.blob, input.format) };
    for (let count = 1; count < parts.length; count++) directories.add(parts.slice(0, count).join('2f'));
    wanted.set(file.pathHex, file); return file;
  });
  if (files.some(file => directories.has(file.pathHex)) || directories.size > limits.maxTrees || directories.size + 1 > limits.maxRequests) {
    refuse('complete parent selection exceeds bounds or contains a file/ancestor collision.');
  }
  return { format: input.format, commit, files, wanted, directories };
}
export function contextMembershipSelection(result, independentCommit, input = {}) {
  const limits = membershipLimits(input);
  if (result?.query?.mode !== 'initial' || !Array.isArray(result.context?.files) || !result.context.files.length || result.context.files.length > 32) refuse('load validated source context first.');
  const selected = selection({ format: result.scope?.format, commit: independentCommit,
    files: result.context.files.map(file => ({ pathHex: file.pathHex, blob: file.blob })) }, limits);
  if (selected.commit !== oid(result.pin?.commit, selected.format)) refuse('independent commit differs from the selected source.');
  return { format: selected.format, commit: selected.commit, files: selected.files };
}
async function digest(kind, body, format, crypto, check) {
  check();
  const prefix = utf8.encode(`${kind} ${body.length}\0`), framed = new Uint8Array(prefix.length + body.length);
  framed.set(prefix); framed.set(body, prefix.length);
  const result = hex(new Uint8Array(await crypto.subtle.digest(format === 'sha1' ? 'SHA-1' : 'SHA-256', framed)));
  check(); return result;
}
function commitRoot(body, format) {
  // Only header lines determine membership. Preserve every original byte for hashing.
  const separator = body.findIndex((byte, at) => byte === 10 && body[at + 1] === 10);
  if (separator < 0 || body.subarray(0, separator).includes(0)) refuse('unsupported commit header framing.');
  const lines = Array.from(body.subarray(0, separator), byte => String.fromCharCode(byte)).join('').split('\n');
  if (!/^tree [0-9a-fA-F]+$/.test(lines[0]) || lines.slice(1).some(line => line.startsWith('tree '))) refuse('ambiguous commit tree header.');
  const root = oid(lines[0].slice(5).toLowerCase(), format);
  const parents = lines.slice(1).filter(line => line.startsWith('parent ')).map(line => oid(line.slice(7).toLowerCase(), format));
  return { root, parents };
}
function name(value) { const parts = path(value); if (parts.length !== 1) refuse('tree name is not immediate.'); return unhex(value, 4096); }
function entry(raw, format) {
  exact(raw, ['name_hex', 'object_id', 'kind']);
  if (!Object.hasOwn(MODES, raw.kind)) refuse('unsupported tree mode.');
  const bytes = name(raw.name_hex), id = oid(raw.object_id, format);
  const order = new Uint8Array(bytes.length + 1); order.set(bytes); order[bytes.length] = raw.kind === 'directory' ? 47 : 0;
  return { name_hex: raw.name_hex, object_id: id, kind: raw.kind, bytes, order };
}
function encodeTree(rows, check) {
  const ordered = [...rows].sort((a, b) => compare(a.order, b.order));
  const length = ordered.reduce((n, row) => n + MODES[row.kind].length + 2 + row.bytes.length + row.object_id.length / 2, 0);
  const body = new Uint8Array(length); let at = 0;
  for (const row of ordered) {
    check(); const mode = utf8.encode(`${MODES[row.kind]} `), id = unhex(row.object_id, 32);
    body.set(mode, at); at += mode.length; body.set(row.bytes, at); at += row.bytes.length;
    body[at++] = 0; body.set(id, at); at += id.length;
  }
  return body;
}
function decodeTree(body, format, charge, check) {
  const rows = [], width = format === 'sha1' ? 20 : 32, names = new Set(); let at = 0, previous = null;
  while (at < body.length) {
    check(); const space = body.indexOf(32, at), nul = body.indexOf(0, space + 1);
    if (space <= at || space - at > 6 || nul <= space + 1 || nul + 1 + width > body.length) refuse('invalid tree framing.');
    const mode = String.fromCharCode(...body.subarray(at, space));
    const kind = Object.keys(MODES).find(key => MODES[key] === mode);
    const row = entry({ name_hex: hex(body.subarray(space + 1, nul)), kind,
      object_id: hex(body.subarray(nul + 1, nul + 1 + width)) }, format);
    if (names.has(row.name_hex) || (previous && compare(previous, row.order) >= 0)) refuse('duplicate or noncanonical tree order.');
    charge(); names.add(row.name_hex); rows.push(row); previous = row.order; at = nul + 1 + width;
  }
  return rows;
}
function host(crypto, check) { if (!crypto?.subtle || typeof check !== 'function') refuse('missing verification host.'); check(); }

// Offline verification: expected root and files must come from the caller, not
// from the proof. Only needed complete parent trees are admitted. No network I/O.
async function verifiedMembership(proof, expected, crypto, check, input) {
  host(crypto, check); const limits = membershipLimits(input), selected = selection(expected, limits);
  exact(proof, ['schema', 'objectFormat', 'commit', 'trees', 'files']);
  if (proof.schema !== MEMBERSHIP_PROFILE || proof.objectFormat !== selected.format || !Array.isArray(proof.trees) ||
      proof.trees.length !== selected.directories.size || !Array.isArray(proof.files) || proof.files.length !== selected.files.length) refuse('incomplete or extra membership proof.');
  exact(proof.commit, ['oid', 'bodyHex']);
  if (oid(proof.commit.oid, selected.format) !== selected.commit) refuse('proof changed independent commit.');
  const commit = unhex(proof.commit.bodyHex, 65536), original = commitRoot(commit, selected.format);
  let treeBytes = 0, entries = 0;
  const trees = new Map();
  for (const raw of proof.trees) {
    check(); exact(raw, ['pathHex', 'oid', 'bodyHex']);
    if (!selected.directories.has(raw.pathHex) || trees.has(raw.pathHex)) refuse('unselected or duplicate parent tree.');
    const body = unhex(raw.bodyHex, limits.maxTreeBytes);
    if ((treeBytes += body.length) > limits.maxTreeBytes) refuse('tree-byte budget exceeded.');
    const rows = decodeTree(body, selected.format, () => { if (++entries > limits.maxEntries) refuse('entry budget exceeded.'); }, check);
    trees.set(raw.pathHex, { id: oid(raw.oid, selected.format), body, rows });
  }
  // Own all inputs before the first asynchronous digest; caller changes cannot
  // change the bytes that were hashed versus the membership checked afterward.
  const claimed = proof.files.map((raw, i) => {
    exact(raw, ['pathHex', 'blob', 'kind']);
    if (raw.pathHex !== selected.files[i].pathHex || oid(raw.blob, selected.format) !== selected.files[i].blob ||
        !['file', 'executable'].includes(raw.kind)) refuse('selected file claim changed.');
    return { pathHex: raw.pathHex, blob: selected.files[i].blob, kind: raw.kind };
  });
  if (await digest('commit', commit, selected.format, crypto, check) !== selected.commit) refuse('commit hash mismatch.');
  for (const tree of trees.values()) if (await digest('tree', tree.body, selected.format, crypto, check) !== tree.id) refuse('tree hash mismatch.');
  const queue = [{ pathHex: null, id: original.root }], found = new Map(), visited = new Set();
  for (const directory of queue) {
    check(); const tree = trees.get(directory.pathHex);
    if (!tree || tree.id !== directory.id || visited.has(directory.pathHex)) refuse('missing or changed directory membership.');
    visited.add(directory.pathHex);
    for (const row of tree.rows) {
      check(); const pathHex = directory.pathHex === null ? row.name_hex : `${directory.pathHex}2f${row.name_hex}`;
      if (selected.directories.has(pathHex)) {
        if (row.kind !== 'directory') refuse('selected ancestor is not a directory.');
        queue.push({ pathHex, id: row.object_id });
      }
      const file = selected.wanted.get(pathHex);
      if (file) {
        if (!['file', 'executable'].includes(row.kind) || row.object_id !== file.blob) refuse('selected path or mode does not bind its blob.');
        found.set(pathHex, row.kind);
      }
    }
  }
  if (visited.size !== trees.size || found.size !== selected.files.length || claimed.some(file => found.get(file.pathHex) !== file.kind)) refuse('incomplete selected membership.');
  check(); const receipt = { profile: MEMBERSHIP_PROFILE, commit: selected.commit, rootTree: original.root,
    commitMembershipVerified: true, blobBytesVerified: false, authorityVerified: false, freshnessVerified: false,
    searchCoverageVerified: false, signatureVerified: false, files: claimed, trees: trees.size, entries, treeBytes };
  return { receipt, trees, format: selected.format };
}
export async function verifyMembershipProof(proof, expected, crypto = globalThis.crypto, check = () => {}, input = {}) {
  return (await verifiedMembership(proof, expected, crypto, check, input)).receipt;
}

// A missing selected blob or omitted subtree says nothing about absence. Reuse
// the same complete, hash-verified parent trees and only conclude absence at an
// actually missing entry. An existing unproved directory is a typed refusal;
// files, symlinks and gitlinks are never traversed. No new reads or permissions.
export const ABSENCE_PROFILE = 'frankengit-context-path-absence-v1';
export async function verifyPathAbsence(proof, expected, paths, crypto = globalThis.crypto, check = () => {}, input = {}) {
  host(crypto, check);
  if (!Array.isArray(paths) || !paths.length || paths.length > 32) refuse('select 1 through 32 absent paths.');
  let previous = '', total = 0;
  // Own target paths before any asynchronous work, just as the shared kernel
  // owns its proof and independent expected selection before the first digest.
  const selected = paths.map(pathHex => {
    check(); const parts = path(pathHex);
    if (pathHex <= previous || (total += pathHex.length / 2) > 32768) refuse('absent path order, duplicates or byte limit.');
    previous = pathHex; return { pathHex, parts };
  });
  const targets = new Set(selected.map(row => row.pathHex));
  for (const row of selected) for (let n = 1; n < row.parts.length; n++) {
    check(); if (targets.has(row.parts.slice(0, n).join('2f'))) refuse('absent file/ancestor collision.');
  }
  const verified = await verifiedMembership(proof, expected, crypto, check, input); check();
  const trees = new Map();
  for (const [pathHex, tree] of verified.trees) {
    const entries = new Map();
    for (const entry of tree.rows) { check(); entries.set(entry.name_hex, entry); }
    trees.set(pathHex, { id: tree.id, entries });
  }
  const absent = selected.map(({ pathHex, parts }) => {
    let parentPathHex = null;
    for (let at = 0; at < parts.length; at++) {
      check(); const tree = trees.get(parentPathHex);
      if (!tree) refuse('existing parent tree is not proved.');
      const entry = tree.entries.get(parts[at]);
      const prefix = parentPathHex === null ? parts[at] : `${parentPathHex}2f${parts[at]}`;
      if (!entry) return { pathHex, absentPrefixHex: prefix, parentPathHex, parentTree: tree.id };
      if (at === parts.length - 1) refuse('requested path already exists.');
      if (entry.kind !== 'directory') refuse('existing ancestor is not a directory.');
      parentPathHex = prefix;
    }
    return refuse('incomplete absence traversal.');
  });
  check(); return { profile: ABSENCE_PROFILE, objectFormat: verified.format,
    commit: verified.receipt.commit, rootTree: verified.receipt.rootTree,
    pathAbsenceVerified: true, paths: absent, authorityVerified: false,
    freshnessVerified: false, publicationAuthorized: false };
}

// Obtain only the commit and needed parent-tree pages through the existing
// authenticated read transport. Refusals never trigger a refresh or fallback.
export async function acquireContextMembership(result, reference, independentCommit, request,
  crypto = globalThis.crypto, check = () => {}, input = {}) {
  host(crypto, check); const limits = membershipLimits(input);
  const expected = contextMembershipSelection(result, independentCommit, limits), selected = selection(expected, limits);
  if (typeof request !== 'function' || typeof reference !== 'string' || !reference.startsWith('refs/') || utf8.encode(reference).length > 1024) refuse('missing source reader or reference.');
  const scope = copy(result.scope), pin = copy(result.pin), generationVector = copy(result.vector); snapshot(pin.head);
  const wantedRef = hex(utf8.encode(reference)), base = { ref: reference, object_format: selected.format,
    expected_head: pin.head, expected_commit: selected.commit };
  let requests = 0, entries = 0, treeBytes = 0;
  const read = async (kind, fields, maximum) => {
    check(); if (++requests > limits.maxRequests) refuse('metadata request budget exceeded.');
    const response = await request(`source/${kind}`, { method: 'POST', body: form({ ...base, ...fields }), maximum });
    check(); const value = response.value; binding(value, scope);
    if (value.ref_hex !== wantedRef || (Object.hasOwn(value, 'ref') && value.ref !== reference) ||
        value.snapshot_token !== pin.head || value.source_head !== pin.sourceHead || oid(value.source_commit, scope.format) !== selected.commit ||
        value.read_only !== true || value.transaction_created !== false || value.published !== false) refuse('source or read scope changed.');
    if (kind === 'tree' && (value.source_rcr !== pin.rcr || oid(value.root_tree, scope.format) !== oid(pin.tree, scope.format))) refuse('tree source root changed.');
    return value;
  };
  const log = await read('log', { after: 0, limit: 1 }, 256 * 1024);
  integer(log.total_commits, 'log size', 1, 4096);
  if (log.type !== 'source_log' || log.ordering !== 'child-before-parent-native-id-v1' || log.author_identity_verified !== false ||
      log.page_complete !== true || log.after !== 0 || log.limit !== 1 || !Array.isArray(log.commits) || log.commits.length !== 1 ||
      log.next_after !== (log.total_commits > 1 ? 1 : null)) refuse('invalid selected commit page.');
  const row = record(log.commits[0]), commit = { oid: oid(row.object_id, scope.format), bodyHex: row.body_hex };
  const body = unhex(commit.bodyHex, 65536), original = commitRoot(body, scope.format);
  if (commit.oid !== selected.commit || original.root !== oid(pin.tree, scope.format) || oid(row.tree, scope.format) !== original.root ||
      !Array.isArray(row.parents) || !same(row.parents.map(parent => oid(parent, scope.format)), original.parents) ||
      await digest('commit', body, scope.format, crypto, check) !== selected.commit) refuse('commit bytes or summary changed.');
  const proof = { schema: MEMBERSHIP_PROFILE, objectFormat: scope.format, commit, trees: [], files: [] };
  const queue = [{ pathHex: null, id: original.root }], found = new Map();
  for (const directory of queue) {
    check(); const rows = []; let after = null;
    do {
      const value = await read('tree', { limit: 100, ...(directory.pathHex === null ? {} : { path_hex: directory.pathHex }),
        ...(after === null ? {} : { after_hex: after }) }, 1024 * 1024);
      if (value.type !== 'source_tree' || value.path_hex !== directory.pathHex || oid(value.object_id, scope.format) !== directory.id ||
          value.after_hex !== after || value.limit !== 100 || !Array.isArray(value.entries) || value.entries.length > 100) refuse('invalid directory page.');
      let last = after ?? '';
      for (const raw of value.entries) {
        check(); const next = entry(raw, scope.format);
        if (next.name_hex <= last) refuse('directory cursor or ordering regressed.'); last = next.name_hex;
        treeBytes += MODES[next.kind].length + 2 + next.bytes.length + next.object_id.length / 2;
        if (++entries > limits.maxEntries || treeBytes > limits.maxTreeBytes) refuse('parent-tree resource budget exceeded.');
        rows.push(next);
      }
      if (value.next_after_hex !== null && (value.entries.length !== 100 || value.next_after_hex !== last)) refuse('incomplete directory continuation.');
      after = value.next_after_hex;
    } while (after !== null);
    const bytes = encodeTree(rows, check);
    if (await digest('tree', bytes, scope.format, crypto, check) !== directory.id) refuse('directory does not reconstruct its committed tree.');
    proof.trees.push({ pathHex: directory.pathHex, oid: directory.id, bodyHex: hex(bytes) });
    for (const row of rows) {
      const pathHex = directory.pathHex === null ? row.name_hex : `${directory.pathHex}2f${row.name_hex}`;
      if (selected.directories.has(pathHex)) {
        if (row.kind !== 'directory' || queue.length >= limits.maxTrees) refuse('invalid or over-budget selected ancestor.');
        queue.push({ pathHex, id: row.object_id });
      }
      if (selected.wanted.has(pathHex)) {
        if (!['file', 'executable'].includes(row.kind) || row.object_id !== selected.wanted.get(pathHex).blob) refuse('selected path does not bind its context blob.');
        found.set(pathHex, { pathHex, blob: row.object_id, kind: row.kind });
      }
    }
  }
  if (found.size !== selected.files.length || proof.trees.length !== selected.directories.size) refuse('missing selected context path.');
  proof.files = selected.files.map(file => found.get(file.pathHex));
  const verified = await verifyMembershipProof(proof, expected, crypto, check, limits); check();
  return { proof, verified, requests, limits, scope, pin, generationVector };
}

// Inert consent/import/export controls. The independent commit is never filled
// from the server or from an imported proof. Offline replay never calls acquire.
export const MEMBERSHIP_PROOF_BYTES = 12 * 1024 * 1024;
export function mountContextMembership(document, result, { acquire, run, current, idle, cancelRead,
  display, cryptoImpl = globalThis.crypto, urlApi = globalThis.URL, timeoutMs = 30000 }) {
  integer(timeoutMs, 'membership deadline', 1, 300000);
  const basis = copy({ query: { mode: result.query.mode }, scope: { format: result.scope.format },
    pin: { commit: result.pin.commit }, context: { files: result.context.files.map(({ pathHex, blob }) => ({ pathHex, blob })) } });
  const node = (tag, text = '') => { const el = document.createElement(tag); el.textContent = text; return el; };
  const section = node('section'); section.id = 'context-membership';
  section.append(node('h3', 'Prove selected paths under an independent commit'),
    node('p', 'Supply a commit ID obtained independently of this server. This check binds each selected path, mode and blob ID to that commit. Full blob bytes, repository authority, freshness, signatures and search coverage are separate checks.'),
    node('p', 'Acquire reads original commit bytes and complete needed parent trees, including sibling names and IDs. It does not read unrelated subtrees or any blob body. Exported proofs retain those private tree names and IDs. No request runs automatically.'));
  const field = (id, label, value, type = 'text') => {
    const wrapper = node('label', label), input = node('input'); input.id = id; input.type = type;
    input.value = value; input.autocomplete = 'off'; input.spellcheck = false; wrapper.append(input); section.append(wrapper); return input;
  };
  const commit = field('context-membership-commit', 'Independently selected commit ID (not supplied by this page)', ''); commit.maxLength = 71;
  const budgets = Object.fromEntries(Object.entries(MEMBERSHIP_LIMITS).map(([name, max]) => {
    const labels = { maxRequests: 'Maximum metadata requests', maxTrees: 'Maximum parent trees',
      maxEntries: 'Maximum entries across all parent trees', maxTreeBytes: 'Maximum encoded tree bytes' };
    const el = field(`context-membership-${name}`, labels[name], String(max), 'number');
    el.min = '1'; el.max = String(max); el.step = '1'; return [name, el];
  }));
  const consent = field('context-membership-consent', 'I independently selected this commit. For Acquire, permit the additional bounded parent-tree reads.', '', 'checkbox');
  const button = (id, label) => { const el = node('button', label); el.id = id; el.type = 'button'; section.append(el); return el; };
  const submit = button('context-membership-acquire', 'Acquire and verify selected membership');
  const file = field('context-membership-file', 'Or choose one saved membership proof (up to 12 MiB)', '', 'file'); file.accept = 'application/json,.json';
  const inspect = button('context-membership-inspect', 'Verify saved proof locally — no network');
  const download = button('context-membership-download', 'Download replayable membership proof');
  const status = node('p'); status.id = 'context-membership-status'; status.setAttribute('role', 'status'); status.setAttribute('aria-live', 'polite');
  const output = node('pre'); output.id = 'context-membership-result'; section.append(status, output);
  let generation = 0, working = false, disposed = false, chosen = null, url = null, active = null;
  const signature = () => JSON.stringify([commit.value, ...Object.values(budgets).map(el => el.value)]);
  const revoke = () => { if (url !== null) { urlApi.revokeObjectURL(url); url = null; } };
  function sync() {
    const enabled = !disposed && current() && idle() && !working, hasFiles = basis.context.files.length > 0;
    for (const el of [commit, ...Object.values(budgets), consent, file]) el.disabled = !enabled || !hasFiles;
    submit.disabled = inspect.disabled = !enabled || !hasFiles || !consent.checked || commit.value === '';
    download.disabled = !enabled || chosen === null || chosen.signature !== signature();
  }
  function invalidate() {
    generation++; active?.abort(); active = null; working = false; chosen = null; consent.checked = false; revoke(); output.textContent = '';
    status.textContent = 'No selected membership proof. Enter and independently confirm its commit before checking.'; sync();
  }
  const changed = () => { if (working) cancelRead(); invalidate(); };
  for (const el of [commit, ...Object.values(budgets)]) for (const event of ['input', 'change']) el.addEventListener(event, changed);
  file.addEventListener('change', changed);
  consent.addEventListener('change', () => { if (working) changed(); else sync(); });
  function proofCopy(proof) {
    const text = JSON.stringify(proof);
    if (typeof text !== 'string' || text.length > MEMBERSHIP_PROOF_BYTES || utf8.encode(text).length > MEMBERSHIP_PROOF_BYTES) refuse('proof export exceeds its byte bound.');
    return JSON.parse(text);
  }
  async function fileBytes(selected, signal) {
    signal.throwIfAborted();
    // Observe eventual rejection even when cancellation wins the race. A File
    // read cannot authorize I/O to the repository or select another proof.
    let abort;
    const canceled = new Promise((resolve, reject) => { abort = () => reject(signal.reason ?? new Error('Canceled'));
      signal.addEventListener('abort', abort, { once: true }); if (signal.aborted) abort(); });
    try {
      const buffer = await Promise.race([Promise.resolve().then(() => { signal.throwIfAborted(); return selected.arrayBuffer(); }), canceled]);
      signal.throwIfAborted();
      if (!(buffer instanceof ArrayBuffer) || buffer.byteLength !== selected.size || buffer.byteLength > MEMBERSHIP_PROOF_BYTES) refuse('saved proof size changed.');
      return new Uint8Array(buffer);
    } finally { signal.removeEventListener('abort', abort); }
  }
  async function execute(local) {
    if (disposed || !current() || !idle() || working || !consent.checked || !basis.context.files.length) return;
    const selectedFile = file.files?.[0], inputCount = file.files?.length, stamp = signature();
    const serial = ++generation, controller = new AbortController(); active = controller; working = true;
    chosen = null; consent.checked = false; revoke(); output.textContent = ''; sync();
    const guard = () => {
      controller.signal.throwIfAborted();
      if (disposed || serial !== generation || !current() || signature() !== stamp) refuse('selection superseded.');
    };
    const timer = setTimeout(() => { controller.abort(new Error('Membership deadline exceeded')); cancelRead(); }, timeoutMs);
    try {
      const limits = membershipLimits(Object.fromEntries(Object.entries(budgets).map(([name, el]) => {
        if (!/^[1-9][0-9]{0,8}$/.test(el.value)) refuse('invalid metadata limit.'); return [name, Number(el.value)];
      })));
      const expected = contextMembershipSelection(basis, commit.value, limits);
      if (local && (inputCount !== 1 || !selectedFile || !Number.isSafeInteger(selectedFile.size) || selectedFile.size < 1 || selectedFile.size > MEMBERSHIP_PROOF_BYTES)) refuse('choose one bounded saved proof.');
      if (local) file.value = '';
      status.textContent = local ? 'Verifying saved proof locally. No network request is made.' : 'Reading and verifying the complete needed parent trees…';
      const answer = await run(async hostCheck => {
        const check = () => { hostCheck(); guard(); };
        check(); let proof;
        if (local) {
          const data = await fileBytes(selectedFile, controller.signal); check();
          proof = JSON.parse(new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(data));
        } else { const acquired = await acquire(expected.commit, limits); check(); proof = proofCopy(acquired.proof); }
        const verified = await verifyMembershipProof(proof, expected, cryptoImpl, check, limits); check();
        return { proof: proofCopy(proof), verified };
      });
      guard(); chosen = { ...answer, signature: stamp };
      output.textContent = `Commit ${answer.verified.commit}\nRoot tree ${answer.verified.rootTree}\n` +
        `${answer.verified.files.length} selected paths; ${answer.verified.trees} parent trees; ${answer.verified.treeBytes} tree bytes.\n` +
        answer.verified.files.map(row => `${display(unhex(row.pathHex, 4096))}: ${row.kind} ${row.blob}`).join('\n');
      status.textContent = 'Selected path/mode/blob identities verified under the independently supplied commit. Blob bodies, repository authority, freshness, signatures and search coverage were NOT verified by this operation.';
    } catch {
      if (!disposed && serial === generation) { chosen = null; output.textContent = ''; status.textContent = 'Membership verification failed or was canceled. No successful subset, replacement root or automatic retry was selected.'; }
    } finally {
      clearTimeout(timer); if (active === controller) active = null; if (serial === generation) working = false; sync();
    }
  }
  submit.addEventListener('click', event => { event.preventDefault(); return execute(false); });
  inspect.addEventListener('click', event => { event.preventDefault(); return execute(true); });
  download.addEventListener('click', event => {
    event.preventDefault(); if (disposed || !current() || !idle() || working || !chosen || chosen.signature !== signature()) return;
    let anchor;
    try {
      const serialized = JSON.stringify(proofCopy(chosen.proof)); revoke();
      url = urlApi.createObjectURL(new Blob([serialized], { type: 'application/json' }));
      anchor = node('a'); anchor.href = url; anchor.download = 'frankengit-context-membership.json'; section.append(anchor); anchor.click();
      status.textContent = 'Private membership proof exported without credentials. Replay requires an independently selected commit and expected path/blob IDs; this is not an authority, freshness, full-blob or search-coverage proof.';
    } catch { revoke(); status.textContent = 'Proof export failed. No network request was made.'; }
    finally { anchor?.remove(); }
  });
  invalidate();
  return { element: section, submit, inspect, download, sync, invalidate,
    dispose() { const wasWorking = working; disposed = true; if (wasWorking) cancelRead(); invalidate(); commit.value = ''; file.value = ''; } };
}
