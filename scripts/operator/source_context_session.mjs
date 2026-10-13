// Durable, explicitly bounded follow-up sessions over the existing read client.
// Local custody/quotas are not repository authority, an IntentRun, or a lease.
import { constants } from 'node:fs';
import { mkdir, open, opendir } from 'node:fs/promises';
import { dirname, join, relative } from 'node:path';
import { command, fail, sha256 } from './source_context.mjs';
import { normalizeFollowup, continuationQuery, continueCapture } from './source_context_continue.mjs';
import { absolute, privateDirectory, readPrivate, absentBundle, loadBundle, publishBundle, bundleCommitment } from './source_context_export.mjs';

export const SESSION_PROFILE = 'frankengit-context-session-v1';
export const MAX_SESSION_STEPS = 16;
const RECORD_BYTES = 512 * 1024;
const DIMENSIONS = ['queries', 'work', 'payload_bytes', 'source_bytes', 'excerpt_bytes'];
const PER_CALL = [1, 16777216, 33554432, 67108864, 1048576];
const encode = value => Buffer.from(`${JSON.stringify(value)}\n`);
const same = (a, b) => JSON.stringify(a) === JSON.stringify(b);
const stamp = value => sha256(encode(value));
function fields(value, names) {
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
      Object.keys(value).length !== names.length || names.some(n => !Object.hasOwn(value, n))) fail('invalid_context_session_record');
}
function hash(value) {
  if (typeof value !== 'string' || !/^[0-9a-f]{64}$/.test(value)) fail('context_session_pin_required');
  return value;
}
export function sessionLimits(value) {
  fields(value, DIMENSIONS);
  const limits = {};
  for (const [i, name] of DIMENSIONS.entries()) {
    const n = value[name], max = PER_CALL[i] * MAX_SESSION_STEPS;
    if (!Number.isSafeInteger(n) || n < 1 || n > max) fail('invalid_context_session_budget');
    limits[name] = n;
  }
  return limits;
}
function cost(q) {
  return { queries: 1, work: q.limits.max_work, payload_bytes: q.limits.max_payload_bytes,
    source_bytes: q.limits.context_max_source_bytes, excerpt_bytes: q.limits.context_max_excerpt_bytes };
}
function charge(used, reservation, limits) {
  const next = {};
  for (const name of DIMENSIONS) {
    next[name] = used[name] + reservation[name];
    if (!Number.isSafeInteger(next[name]) || next[name] > limits[name]) fail('context_session_budget_exhausted');
  }
  return next;
}
function clock(options = {}, network = false) {
  const allowed = network ? ['signal', 'timeoutMs', 'ca'] : ['signal', 'timeoutMs'];
  if (!options || typeof options !== 'object' || Array.isArray(options) ||
      Object.keys(options).some(k => !allowed.includes(k))) fail('invalid_context_session_options');
  const timeout = options.timeoutMs ?? 30000, signal = options.signal;
  if (!Number.isSafeInteger(timeout) || timeout < 1 || timeout > 300000 ||
      signal !== undefined && !(signal instanceof AbortSignal)) fail('invalid_context_session_options');
  if (options.ca !== undefined && (!(options.ca instanceof Uint8Array) || !options.ca.length || options.ca.length > 262144)) fail('invalid_context_ca');
  const ca = options.ca === undefined ? undefined : Buffer.from(options.ca), started = performance.now();
  const check = () => { signal?.throwIfAborted(); if (performance.now() - started >= timeout) fail('context_deadline_exceeded'); };
  const remaining = () => { check(); const n = Math.floor(timeout - (performance.now() - started)); if (n < 1) fail('context_deadline_exceeded'); return n; };
  check(); return { check, remaining, signal, ca };
}
function stepPath(root, n) { return join(root, 'steps', String(n).padStart(4, '0')); }
async function sync(path, directory = false) {
  const handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK |
    (directory ? constants.O_DIRECTORY : 0));
  try { await handle.sync(); } finally { await handle.close(); }
}
async function writeRecord(path, value) {
  const bytes = encode(value);
  if (bytes.length > RECORD_BYTES) fail('context_session_record_limit');
  await privateDirectory(dirname(path));
  const handle = await open(path, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
  try { await handle.writeFile(bytes); await handle.sync(); } finally { await handle.close(); }
  await sync(dirname(path), true);
  if (!(await readPrivate(path, RECORD_BYTES)).equals(bytes)) fail('context_session_record_changed');
  return sha256(bytes);
}
async function record(path, check) {
  const bytes = await readPrivate(path, RECORD_BYTES, check);
  let value;
  try { value = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)); }
  catch { fail('invalid_context_session_record'); }
  // Reject duplicate members, ignored bytes, unsafe numeric spellings and torn
  // writes instead of treating a parseable prefix as a published record.
  if (!encode(value).equals(bytes)) fail('noncanonical_context_session_record');
  return { value, hash: sha256(bytes) };
}
async function names(path, allowed, check) {
  check(); await privateDirectory(path);
  const entries = [], directory = await opendir(path);
  for await (const entry of directory) {
    check();
    if (entries.length >= allowed.length || !allowed.includes(entry.name)) fail('unexpected_context_session_files');
    entries.push(entry.name);
  }
  return entries;
}
function boundCapture(capture, parent, selected) {
  if (capture.endpoint !== parent.endpoint || !same(capture.summary.source, parent.summary.source) ||
      !same(capture.summary.query, selected) || capture.request_sha256 !== sha256(command(selected).body)) fail('context_session_capture_changed');
}
function candidateRecord(requestHash, capture, check) {
  return { schema: `${SESSION_PROFILE}/candidate`, request_sha256: requestHash, ...bundleCommitment(capture, check) };
}
function checkCandidate(value, requestHash) {
  fields(value, ['schema', 'request_sha256', 'manifest_sha256', 'capture_sha256', 'text_sha256']);
  if (value.schema !== `${SESSION_PROFILE}/candidate` || value.request_sha256 !== requestHash) fail('context_session_candidate_changed');
  for (const k of ['manifest_sha256', 'capture_sha256', 'text_sha256']) hash(value[k]);
}
function capturedTerminal(requestHash, candidateHash) {
  return { schema: `${SESSION_PROFILE}/terminal`, request_sha256: requestHash, state: 'captured', candidate_sha256: candidateHash };
}
async function verifyCandidate(dir, requestHash, parent, selected, check) {
  const candidate = await record(join(dir, 'candidate.json'), check);
  checkCandidate(candidate.value, requestHash);
  const loaded = await loadBundle(join(dir, 'bundle'), candidate.value.manifest_sha256, check);
  boundCapture(loaded.capture, parent, selected);
  if (loaded.receipt.capture_sha256 !== candidate.value.capture_sha256 ||
      loaded.receipt.text_sha256 !== candidate.value.text_sha256) fail('context_session_candidate_changed');
  return { candidate, loaded };
}
// Every reservation is retained, including rejected or interrupted reads. No
// failed channel's unreported work is refunded from a successful-channel tally.
async function readState(root, sessionHash, minimumTip, check) {
  absolute(root); hash(sessionHash); hash(minimumTip);
  await names(root, ['session.json', 'base', 'steps'], check);
  const manifest = await record(join(root, 'session.json'), check);
  if (manifest.hash !== sessionHash) fail('context_session_manifest_changed');
  fields(manifest.value, ['schema', 'base_manifest_sha256', 'limits']);
  if (manifest.value.schema !== SESSION_PROFILE) fail('unsupported_context_session');
  hash(manifest.value.base_manifest_sha256);
  const limits = sessionLimits(manifest.value.limits);
  let current = await loadBundle(join(root, 'base'), manifest.value.base_manifest_sha256, check);
  const source = current.capture.summary.source;
  const allowed = Array.from({ length: MAX_SESSION_STEPS }, (_, i) => String(i + 1).padStart(4, '0'));
  const entries = (await names(join(root, 'steps'), allowed, check)).sort();
  let used = Object.fromEntries(DIMENSIONS.map(k => [k, 0])), tip = sessionHash, minimumSeen = minimumTip === tip;
  const history = []; let pending = null;
  for (let i = 0; i < entries.length; i++) {
    check();
    if (entries[i] !== allowed[i] || pending) fail('context_session_history_gap');
    const dir = stepPath(root, i + 1);
    const files = await names(dir, ['request.json', 'started.json', 'candidate.json', 'bundle', 'terminal.json'], check);
    if (!files.includes('request.json')) fail('context_session_incomplete_reservation');
    const request = await record(join(dir, 'request.json'), check), r = request.value;
    fields(r, ['schema', 'sequence', 'session_sha256', 'previous_tip_sha256', 'parent_manifest_sha256', 'followup', 'query_sha256', 'reservation']);
    const selected = continuationQuery(current.capture.summary, r.followup);
    if (r.schema !== `${SESSION_PROFILE}/request` || r.sequence !== i + 1 || r.session_sha256 !== sessionHash ||
        r.previous_tip_sha256 !== tip || r.parent_manifest_sha256 !== current.receipt.manifest_sha256 ||
        r.query_sha256 !== sha256(command(selected).body) || !same(r.reservation, cost(selected))) fail('context_session_request_changed');
    used = charge(used, r.reservation, limits);
    const started = files.includes('started.json');
    if (started) {
      const start = await record(join(dir, 'started.json'), check);
      if (!same(start.value, { schema: `${SESSION_PROFILE}/started`, request_sha256: request.hash })) fail('context_session_dispatch_changed');
    } else if (files.some(n => ['candidate.json', 'bundle', 'terminal.json'].includes(n))) fail('context_session_dispatch_missing');
    if (files.includes('terminal.json')) {
      const terminal = await record(join(dir, 'terminal.json'), check), t = terminal.value;
      if (t.state === 'captured') {
        const { candidate, loaded } = await verifyCandidate(dir, request.hash, current.capture, selected, check);
        if (!same(t, capturedTerminal(request.hash, candidate.hash))) fail('context_session_terminal_changed');
        current = loaded;
      } else {
        fields(t, ['schema', 'request_sha256', 'state', 'error_code', 'http_status']);
        if (t.schema !== `${SESSION_PROFILE}/terminal` || t.request_sha256 !== request.hash || t.state !== 'read_refused' ||
            !['read_refused', 'cancelled'].includes(t.error_code) || t.http_status !== null &&
            (!Number.isInteger(t.http_status) || t.http_status < 100 || t.http_status > 599) ||
            files.includes('candidate.json') || files.includes('bundle')) fail('context_session_terminal_changed');
      }
      tip = terminal.hash; minimumSeen ||= minimumTip === tip;
      history.push({ sequence: i + 1, request_sha256: request.hash, tip_sha256: tip, state: t.state,
        ...(t.state === 'captured' ? { manifest_sha256: current.receipt.manifest_sha256, complete: current.capture.summary.complete } : {}) });
    } else {
      if (files.includes('bundle') && !files.includes('candidate.json')) fail('context_session_candidate_missing');
      let candidateHash = null;
      if (files.includes('candidate.json')) {
        const saved = await record(join(dir, 'candidate.json'), check);
        checkCandidate(saved.value, request.hash); candidateHash = saved.hash;
      }
      pending = { sequence: i + 1, request_sha256: request.hash, state: files.includes('candidate.json') ? 'candidate' : started ? 'in_flight_or_interrupted' : 'reserved',
        request: r, selected, dir, candidate_sha256: candidateHash };
    }
  }
  if (!minimumSeen) fail('context_session_checkpoint_unavailable');
  check(); return { root, sessionHash, limits, used, tip, current, source, history, pending };
}
// A concurrent reader can see complete file bytes before their writer finishes
// fsync. Before any new responsibility, independently settle the validated
// predecessor prefix rather than equating visible records with durable ones.
async function syncState(state, check) {
  const bundle = async path => {
    for (const name of ['capture.json', 'context.txt', 'manifest.json']) { check(); await sync(join(path, name)); }
    await sync(path, true);
  };
  check(); await sync(join(state.root, 'session.json')); await bundle(join(state.root, 'base'));
  for (const item of state.history) {
    const path = stepPath(state.root, item.sequence);
    for (const name of ['request.json', 'started.json', 'terminal.json']) { check(); await sync(join(path, name)); }
    if (item.state === 'captured') { check(); await sync(join(path, 'candidate.json')); await bundle(join(path, 'bundle')); }
    await sync(path, true);
  }
  await sync(join(state.root, 'steps'), true); await sync(state.root, true); check();
}
function receipt(state) {
  return { type: 'source_context_session', schema_version: 1, session: state.root, session_sha256: state.sessionHash,
    tip_sha256: state.tip, source: state.source, reserved: state.used,
    remaining: Object.fromEntries(DIMENSIONS.map(n => [n, state.limits[n] - state.used[n]])),
    history: state.history, pending: state.pending ? { sequence: state.pending.sequence, request_sha256: state.pending.request_sha256, state: state.pending.state, candidate_sha256: state.pending.candidate_sha256 } : null,
    latest_bundle: state.current.receipt.bundle, latest_manifest_sha256: state.current.receipt.manifest_sha256,
    latest_query_complete: state.current.capture.summary.complete, source_material_untrusted: true,
    authority_verified: false, agent_context_packet: false, aggregate_coverage_claimed: false };
}
export async function createSession(root, parentBundle, parentManifest, requestedLimits, options = {}) {
  const time = clock(options), limits = sessionLimits(requestedLimits);
  absolute(root); absolute(parentBundle); hash(parentManifest);
  if (root === parentBundle || relative(parentBundle, root).split('/')[0] !== '..') fail('context_session_inside_parent');
  await absentBundle(root);
  const parent = await loadBundle(parentBundle, parentManifest, time.check);
  time.check(); await mkdir(root, { mode: 0o700 }); await sync(dirname(root), true);
  await mkdir(join(root, 'steps'), { mode: 0o700 }); await sync(root, true);
  const base = await publishBundle(join(root, 'base'), parent.capture, { signal: time.signal });
  const manifest = { schema: SESSION_PROFILE, base_manifest_sha256: base.manifest_sha256, limits };
  time.check();
  const sessionHash = await writeRecord(join(root, 'session.json'), manifest);
  // Publication is confirmed. No late cancellation can erase this receipt.
  return { type: 'source_context_session_created', session: root, session_sha256: sessionHash, tip_sha256: sessionHash,
    limits, source: parent.capture.summary.source, base_manifest_sha256: base.manifest_sha256,
    source_material_untrusted: true, authority_verified: false, agent_context_packet: false };
}
export async function inspectSession(root, sessionHash, minimumTip, options = {}) {
  const time = clock(options);
  return receipt(await readState(root, sessionHash, minimumTip, time.check));
}
export async function reserveSessionStep(root, sessionHash, expectedTip, followup, options = {}) {
  const time = clock(options), delta = normalizeFollowup(followup);
  const state = await readState(root, sessionHash, expectedTip, time.check);
  if (state.tip !== expectedTip) fail('context_session_tip_moved');
  if (state.pending) fail('context_session_step_pending');
  const selected = continuationQuery(state.current.capture.summary, delta), reservation = cost(selected);
  const used = charge(state.used, reservation, state.limits), sequence = state.history.length + 1;
  const request = { schema: `${SESSION_PROFILE}/request`, sequence, session_sha256: sessionHash, previous_tip_sha256: expectedTip,
    parent_manifest_sha256: state.current.receipt.manifest_sha256, followup: delta, query_sha256: sha256(command(selected).body), reservation };
  const dir = stepPath(root, sequence);
  await syncState(state, time.check);
  time.check();
  // mkdir is the exact next-position claim. Competing owners cannot both get
  // a reservation or dispatch, even if both read the same predecessor.
  await mkdir(dir, { mode: 0o700 }); await sync(join(root, 'steps'), true);
  const requestHash = await writeRecord(join(dir, 'request.json'), request);
  return { type: 'source_context_reserved', session_sha256: sessionHash, previous_tip_sha256: expectedTip,
    sequence, request_sha256: requestHash, reserved: used };
}
function pending(state, requestHash) {
  hash(requestHash);
  if (!state.pending || state.pending.request_sha256 !== requestHash) fail('context_session_original_request_required');
  return state.pending;
}
export async function acquireSessionStep(root, sessionHash, previousTip, requestHash, credential, options = {}) {
  const time = clock(options, true);
  if (typeof credential !== 'string' || !/^[0-9a-f]{64}$/.test(credential)) fail('invalid_source_read_token');
  const state = await readState(root, sessionHash, previousTip, time.check), p = pending(state, requestHash);
  if (state.tip !== previousTip || p.state !== 'reserved') fail('context_session_dispatch_already_started');
  // This durable one-shot marker is never deleted, inferred from a PID, or
  // retried after interruption. Credentials are never saved in either record.
  await syncState(state, time.check);
  time.check(); await writeRecord(join(p.dir, 'started.json'), { schema: `${SESSION_PROFILE}/started`, request_sha256: requestHash });
  await sync(join(p.dir, 'request.json')); await sync(join(root, 'session.json'));
  await sync(p.dir, true); await sync(join(root, 'steps'), true); await sync(root, true);
  let capture;
  try {
    const result = await continueCapture(state.current.receipt.bundle, state.current.receipt.manifest_sha256, credential,
      p.request.followup, { signal: time.signal, timeoutMs: time.remaining(), ...(time.ca ? { ca: time.ca } : {}) });
    capture = result.capture;
  } catch (error) {
    // The client has settled/closed its one read. Keep the entire reservation;
    // its successful-channel counters cannot prove unconsumed physical work.
    const terminal = { schema: `${SESSION_PROFILE}/terminal`, request_sha256: requestHash, state: 'read_refused',
      error_code: time.signal?.aborted ? 'cancelled' : 'read_refused',
      http_status: Number.isInteger(error.status) && error.status >= 100 && error.status <= 599 ? error.status : null };
    const tip = await writeRecord(join(p.dir, 'terminal.json'), terminal);
    return { type: 'source_context_session_refused', request_sha256: requestHash, tip_sha256: tip, sequence: p.sequence,
      reservation_retained: true, http_status: terminal.http_status, error_code: terminal.error_code };
  }
  boundCapture(capture, state.current.capture, p.selected);
  const candidate = candidateRecord(requestHash, capture, time.check);
  time.check(); const candidateHash = await writeRecord(join(p.dir, 'candidate.json'), candidate);
  // Once a candidate exists, any failure remains pending; never convert a
  // possibly exported capture into a read refusal or choose a replacement.
  const exported = await publishBundle(join(p.dir, 'bundle'), capture, { signal: time.signal });
  if (exported.manifest_sha256 !== candidate.manifest_sha256) fail('context_session_candidate_changed');
  return { type: 'source_context_session_staged', sequence: p.sequence, request_sha256: requestHash,
    candidate_sha256: candidateHash, manifest_sha256: candidate.manifest_sha256 };
}
export async function recoverSessionStep(root, sessionHash, minimumTip, requestHash, expectedCandidate = null, options = {}) {
  const time = clock(options), state = await readState(root, sessionHash, minimumTip, time.check);
  hash(requestHash); if (expectedCandidate !== null) hash(expectedCandidate);
  const done = state.history.find(h => h.request_sha256 === requestHash);
  if (done) {
    if (expectedCandidate !== null) {
      const candidate = await record(join(stepPath(root, done.sequence), 'candidate.json'), time.check);
      if (candidate.hash !== expectedCandidate) fail('context_session_candidate_pin_changed');
    }
    return { ...receipt(state), recovered_step: done, acquisition_retried: false };
  }
  const p = pending(state, requestHash);
  if (p.state !== 'candidate') {
    if (expectedCandidate !== null) fail('context_session_candidate_pin_changed');
    return { ...receipt(state), acquisition_retried: false };
  }
  if (expectedCandidate === null || p.candidate_sha256 !== expectedCandidate) fail('context_session_candidate_pin_changed');
  const { candidate, loaded } = await verifyCandidate(p.dir, requestHash, state.current.capture, p.selected, time.check);
  await syncState(state, time.check);
  // Merely observing a valid last-written manifest does not prove that its
  // writer finished the selected local durability calls before dying.
  for (const name of ['capture.json', 'context.txt', 'manifest.json']) { time.check(); await sync(join(p.dir, 'bundle', name)); }
  for (const name of ['request.json', 'started.json', 'candidate.json']) { time.check(); await sync(join(p.dir, name)); }
  await sync(join(p.dir, 'bundle'), true); await sync(p.dir, true); await sync(join(root, 'steps'), true); await sync(root, true);
  const terminal = capturedTerminal(requestHash, candidate.hash);
  time.check();
  let tip;
  try { tip = await writeRecord(join(p.dir, 'terminal.json'), terminal); }
  catch (error) {
    if (error.code !== 'EEXIST') throw error;
    const existing = await record(join(p.dir, 'terminal.json'), () => {});
    if (!same(existing.value, terminal)) fail('context_session_terminal_conflict');
    await sync(join(p.dir, 'terminal.json')); await sync(p.dir, true); tip = existing.hash;
  }
  // Confirmed local publication wins; no await/check after this point.
  const finished = { sequence: p.sequence, request_sha256: requestHash, tip_sha256: tip, state: 'captured',
    manifest_sha256: loaded.receipt.manifest_sha256, complete: loaded.capture.summary.complete };
  state.history.push(finished); state.tip = tip; state.current = loaded; state.pending = null;
  return { ...receipt(state), recovered_step: finished, acquisition_retried: false };
}
export async function runSessionStep(root, sessionHash, expectedTip, followup, credential, options = {}) {
  const time = clock(options, true);
  if (typeof credential !== 'string' || !/^[0-9a-f]{64}$/.test(credential)) fail('invalid_source_read_token');
  const reservation = await reserveSessionStep(root, sessionHash, expectedTip, followup, { signal: time.signal, timeoutMs: time.remaining() });
  try {
    const staged = await acquireSessionStep(root, sessionHash, expectedTip, reservation.request_sha256, credential,
      { signal: time.signal, timeoutMs: time.remaining(), ...(time.ca ? { ca: time.ca } : {}) });
    if (staged.type === 'source_context_session_refused') return staged;
    return await recoverSessionStep(root, sessionHash, expectedTip, reservation.request_sha256, staged.candidate_sha256,
      { signal: time.signal, timeoutMs: time.remaining() });
  } catch (error) {
    error.session_reservation = reservation; throw error;
  }
}
