// Durable local ownership of ONE native source publication. Local files are
// custody, not repository authority. A dispatched request is never resent.
import { mkdir, lstat, open } from 'node:fs/promises';
import { constants } from 'node:fs';
import { dirname, join } from 'node:path';
import { randomBytes } from 'node:crypto';
import { absolute, contains, directory, readPrivate, writeNew, syncDirectory } from './workflow_watch_io.mjs';
import { validateOutcomeReply } from './transaction_outcome.mjs';
import { validateSourceEdit, editCoordinates, canonical, identity, oid, CAPTURE_LIMIT, BUNDLE_LIMIT } from './source_edit_candidate.mjs';
import { validateSourceEditEvidence, SOURCE_PACKAGE_BYTES, SOURCE_EXPECTED_BYTES, SOURCE_EVIDENCE_PROFILE } from './source_edit_from_package.mjs';
import { hash, fields, fail, parse, clock, upload, exchange, integer } from './source_edit_wire.mjs';

const SCHEMA = 'frankengit-source-apply-v1', RECORD_LIMIT = 65536;
const same = (a, b) => canonical(a).equals(canonical(b));
function pin(value) { if (typeof value !== 'string' || !/^[0-9a-f]{64}$/.test(value)) fail('source_edit_pin'); return value; }
async function absent(path) {
  absolute(path); await directory(dirname(path));
  try { await lstat(path); fail('source_edit_destination_exists'); } catch (e) { if (e.code !== 'ENOENT') throw e; }
}
async function syncFile(path) {
  const handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try { await handle.sync(); } finally { await handle.close(); }
}
async function readRecord(path, optional = false) {
  const bytes = await readPrivate(path, RECORD_LIMIT, optional);
  if (bytes === null) return null;
  const value = parse(bytes, RECORD_LIMIT);
  if (!canonical(value).equals(bytes)) fail('source_edit_record_encoding');
  return { value, sha256: hash(bytes) };
}
async function putRecord(path, value) {
  const bytes = canonical(value); if (bytes.length > RECORD_LIMIT) fail('source_edit_record_limit');
  await writeNew(path, bytes);
  if (!bytes.equals(await readPrivate(path, RECORD_LIMIT))) fail('source_edit_record_changed');
  return hash(bytes);
}
const FILES_V1 = 'frankengit-source-edit-files-v1', FILES_V2 = 'frankengit-source-edit-files-v2';
const PACKAGE_FILE = 'source-package.json', EXPECTED_FILE = 'source-expected.json';
const evidenceReceipt = checked => checked.source_verification ? { source_verification: checked.source_verification } : {};
function manifest(capture, bundle) {
  return { schema: FILES_V1, capture_sha256: hash(canonical(capture)), capture_bytes: canonical(capture).length,
    bundle_sha256: hash(bundle), bundle_bytes: bundle.length };
}
// Only a fully checked local result enters this private writer. In particular,
// a caller-provided verification receipt never chooses whether evidence exists.
async function saveChecked(path, checked, check) {
  check(); const body = canonical(checked.capture), root = manifest(checked.capture, checked.bundle);
  const payloads = [['capture.json', body, CAPTURE_LIMIT], ['candidate.bundle', checked.bundle, BUNDLE_LIMIT]];
  if (checked.source_evidence) {
    const source = checked.source_evidence, expected = canonical(source.expected);
    if (!expected.length || expected.length > SOURCE_EXPECTED_BYTES) fail('source_edit_evidence_limit');
    root.schema = FILES_V2;
    root.source_evidence = { profile: SOURCE_EVIDENCE_PROFILE,
      package_sha256: hash(source.package_bytes), package_bytes: source.package_bytes.length,
      expected_sha256: hash(expected), expected_bytes: expected.length };
    payloads.push([PACKAGE_FILE, source.package_bytes, SOURCE_PACKAGE_BYTES], [EXPECTED_FILE, expected, SOURCE_EXPECTED_BYTES]);
  }
  await absent(path); check();
  const receipt = { type: 'source_edit_saved', directory: path, manifest_sha256: hash(canonical(root)),
    candidate_commit: checked.candidate_commit, bundle_sha256: root.bundle_sha256, publication_attempted: false,
    ...evidenceReceipt(checked) };
  await mkdir(path, { mode: 0o700 });
  try {
    // Drain publication once claimed. Root-last binding covers the original
    // native capture, bundle AND exact independent source evidence together.
    await syncDirectory(dirname(path));
    for (const [name, bytes, maximum] of payloads) {
      await writeNew(join(path, name), bytes);
      if (!bytes.equals(await readPrivate(join(path, name), maximum))) fail('source_edit_export_readback');
    }
    await putRecord(join(path, 'manifest.json'), root); await syncDirectory(path); await syncDirectory(dirname(path));
    return receipt;
  } catch (error) { error.publication_unconfirmed = receipt; throw error; }
}
export async function saveSourceEdit(path, capture, bundle, options = {}) {
  const time = clock(options); time.check();
  return saveChecked(path, validateSourceEdit(capture, bundle), time.check);
}
export async function saveVerifiedSourceEdit(path, capture, bundle, evidence, options = {}) {
  const time = clock(options); time.check();
  const checked = await validateSourceEditEvidence(capture, bundle, evidence, time.check);
  return saveChecked(path, checked, time.check);
}
export async function loadSourceEdit(path, expectedHash, check = () => {}) {
  check(); pin(expectedHash); await directory(absolute(path));
  const root = await readRecord(join(path, 'manifest.json'));
  if (root.sha256 !== expectedHash || ![FILES_V1, FILES_V2].includes(root.value.schema)) fail('source_edit_manifest_changed');
  const evidenced = root.value.schema === FILES_V2;
  fields(root.value, ['schema', 'capture_sha256', 'capture_bytes', 'bundle_sha256', 'bundle_bytes', ...(evidenced ? ['source_evidence'] : [])]);
  const captureBytes = await readPrivate(join(path, 'capture.json'), CAPTURE_LIMIT), bundle = await readPrivate(join(path, 'candidate.bundle'), BUNDLE_LIMIT);
  check();
  if (captureBytes.length !== root.value.capture_bytes || hash(captureBytes) !== root.value.capture_sha256 ||
      bundle.length !== root.value.bundle_bytes || hash(bundle) !== root.value.bundle_sha256) fail('source_edit_payload_changed');
  const capture = parse(captureBytes, CAPTURE_LIMIT);
  if (!canonical(capture).equals(captureBytes)) fail('source_edit_capture_encoding');
  let checked;
  if (evidenced) {
    const r = fields(root.value.source_evidence, ['profile', 'package_sha256', 'package_bytes', 'expected_sha256', 'expected_bytes']);
    if (r.profile !== SOURCE_EVIDENCE_PROFILE) fail('source_edit_evidence_profile');
    pin(r.package_sha256); pin(r.expected_sha256);
    integer(r.package_bytes, 1, SOURCE_PACKAGE_BYTES); integer(r.expected_bytes, 1, SOURCE_EXPECTED_BYTES);
    const packageBytes = await readPrivate(join(path, PACKAGE_FILE), SOURCE_PACKAGE_BYTES),
      expectedBytes = await readPrivate(join(path, EXPECTED_FILE), SOURCE_EXPECTED_BYTES);
    check();
    if (packageBytes.length !== r.package_bytes || hash(packageBytes) !== r.package_sha256 ||
        expectedBytes.length !== r.expected_bytes || hash(expectedBytes) !== r.expected_sha256) fail('source_edit_evidence_changed');
    const expected = parse(expectedBytes, SOURCE_EXPECTED_BYTES);
    if (!canonical(expected).equals(expectedBytes)) fail('source_edit_evidence_encoding');
    checked = await validateSourceEditEvidence(capture, bundle, { package_bytes: packageBytes, expected }, check);
    // Normalization cannot silently rewrite the independently pinned selection.
    if (!canonical(checked.source_evidence.expected).equals(expectedBytes)) fail('source_edit_evidence_encoding');
  } else checked = validateSourceEdit(capture, bundle);
  check(); return { ...checked, manifest_sha256: expectedHash };
}
function intentBody(checked, principal, nonce) {
  const request = checked.capture.request, body = upload(editCoordinates(request, checked.candidate_commit), checked.bundle, 'bundle');
  return { schema: SCHEMA, endpoint: request.endpoint, scope: request.scope, principal_id: principal, nonce,
    candidate_manifest_sha256: checked.manifest_sha256, ref: request.ref, expected_commit: request.expected_commit,
    candidate_commit: checked.candidate_commit, content_type: body.contentType, upload_sha256: hash(body.bytes), upload_bytes: body.bytes.length };
}
function originalKey(body) { return `fgsrcop1-${body.nonce}-${hash(canonical(body))}`; }
function scopeOf(request) {
  return { tenant_id: request.scope.tenant_id, repository_id: request.scope.repository_id,
    repository_incarnation: request.scope.repository_incarnation, principal_id: request.principal_id };
}
export async function stageSourceApply(path, candidatePath, candidateHash, principal, options = {}) {
  const time = clock(options); identity(principal); absolute(path); absolute(candidatePath);
  if (contains(candidatePath, path) || contains(path, candidatePath)) fail('source_edit_overlapping_custody');
  await absent(path);
  const checked = await loadSourceEdit(candidatePath, candidateHash, time.check);
  const intent = intentBody(checked, principal, randomBytes(16).toString('hex'));
  const request = { ...intent, key: originalKey(intent) }, requestHash = hash(canonical(request));
  time.check(); await mkdir(path, { mode: 0o700 });
  const receipt = { type: 'source_apply_staged', journal: path, request_sha256: requestHash, key: request.key,
    principal_id: principal, candidate_commit: request.candidate_commit, transmission_attempted: false, ...evidenceReceipt(checked) };
  try {
    await syncDirectory(dirname(path));
    // Retain a self-contained copy: dispatch/recovery do not reopen a mutable
    // external candidate path or require its continued existence.
    // Use precisely the owned bytes just verified, including v2 evidence. No
    // external package path or caller receipt survives into the journal.
    const saved = await saveChecked(join(path, 'candidate'), checked, () => {});
    if (saved.manifest_sha256 !== candidateHash) fail('source_edit_candidate_changed');
    await putRecord(join(path, 'request.json'), request); await syncDirectory(path); await syncDirectory(dirname(path));
    return receipt;
  } catch (error) { error.publication_unconfirmed = receipt; throw error; }
}
async function state(path, expectedRequest, check) {
  check(); pin(expectedRequest); await directory(absolute(path));
  const record = await readRecord(join(path, 'request.json')), r = record.value;
  fields(r, ['schema', 'endpoint', 'scope', 'principal_id', 'nonce', 'candidate_manifest_sha256', 'ref', 'expected_commit',
    'candidate_commit', 'content_type', 'upload_sha256', 'upload_bytes', 'key']);
  if (record.sha256 !== expectedRequest || r.schema !== SCHEMA || typeof r.nonce !== 'string' || !/^[0-9a-f]{32}$/.test(r.nonce)) fail('source_edit_request_changed');
  identity(r.principal_id);
  const checked = await loadSourceEdit(join(path, 'candidate'), r.candidate_manifest_sha256, check);
  const expected = intentBody(checked, r.principal_id, r.nonce);
  if (!same(r, { ...expected, key: originalKey(expected) })) fail('source_edit_request_changed');
  const dispatched = await lstat(join(path, 'dispatch')).then(async m => {
    if (!m.isDirectory() || m.isSymbolicLink()) fail('source_edit_dispatch_changed');
    await directory(join(path, 'dispatch')); return true;
  }, e => { if (e.code === 'ENOENT') return false; throw e; });
  const start = dispatched ? await readRecord(join(path, 'dispatch', 'started.json'), true) : null;
  if (start && !same(start.value, { schema: `${SCHEMA}/started`, request_sha256: expectedRequest })) fail('source_edit_dispatch_changed');
  const terminal = await readRecord(join(path, 'terminal.json'), true);
  if (terminal && !start) fail('source_edit_terminal_without_dispatch');
  if (terminal) {
    fields(terminal.value, ['schema', 'request_sha256', 'decision']);
    if (terminal.value.schema !== `${SCHEMA}/terminal` || terminal.value.request_sha256 !== expectedRequest) fail('source_edit_terminal_changed');
    decision(terminal.value.decision);
  }
  const observed = await readRecord(join(path, 'transaction.json'), true);
  if (observed) {
    fields(observed.value, ['schema', 'request_sha256', 'observation']);
    if (!start || observed.value.schema !== `${SCHEMA}/transaction` || observed.value.request_sha256 !== expectedRequest) fail('source_edit_observation_changed');
    validateOutcomeReply(observed.value.observation, scopeOf(r));
    if (!observed.value.observation.transaction) fail('source_edit_observation_changed');
    if (terminal && !same(decisionFromOutcome(observed.value.observation), terminal.value.decision) && observed.value.observation.terminal) fail('source_edit_terminal_conflict');
    if (terminal && observed.value.observation.transaction.tx_id !== terminal.value.decision.tx_id) fail('source_edit_terminal_conflict');
  }
  check(); return { path, request: r, checked, dispatched, start, terminal, observed, hash: expectedRequest };
}
function decision(value) {
  fields(value, ['outcome', 'tx_id', 'decision_sequence', 'decision_record', 'refusal_code']);
  if (!['committed', 'refused'].includes(value.outcome) || typeof value.decision_sequence !== 'string' ||
      !/^[1-9][0-9]{0,19}$/.test(value.decision_sequence) || BigInt(value.decision_sequence) > 18446744073709551615n) fail('source_edit_decision');
  for (const k of ['tx_id', 'decision_record', ...(value.outcome === 'refused' ? ['refusal_code'] : [])]) {
    if (typeof value[k] !== 'string' || !value[k].length || value[k].length > 256 || /[\s\x00-\x1f\x7f-\x9f\uD800-\uDFFF]/u.test(value[k])) fail('source_edit_decision');
  }
  if (value.outcome === 'committed' && value.refusal_code !== null) fail('source_edit_decision');
  return value;
}
function publication(value, request, status) {
  fields(value, ['type', 'schema_version', ...Object.keys(request.scope), 'principal_id', 'ref', 'ref_hex', 'expected_commit', 'candidate_commit',
    'tx_id', 'outcome', 'decision_sequence', 'decision_record', 'refusal_code', 'delivery_acknowledged']);
  if (value.type !== 'source_publication' || value.schema_version !== 1 || Object.entries(request.scope).some(([k, v]) => value[k] !== v) ||
      value.principal_id !== request.principal_id || value.ref !== request.ref || value.ref_hex !== Buffer.from(request.ref).toString('hex') ||
      oid(value.expected_commit, request.scope.object_format) !== request.expected_commit ||
      oid(value.candidate_commit, request.scope.object_format) !== request.candidate_commit || value.delivery_acknowledged !== null ||
      status !== (value.outcome === 'committed' ? 200 : 409)) fail('source_edit_publication_mismatch');
  return decision(Object.fromEntries(['outcome', 'tx_id', 'decision_sequence', 'decision_record', 'refusal_code'].map(k => [k, value[k]])));
}
function decisionFromOutcome(value) {
  if (!value.terminal) return null;
  const d = value.decision;
  return decision({ outcome: value.state, tx_id: value.transaction.tx_id, decision_sequence: d.decision_sequence,
    decision_record: value.state === 'committed' ? d.repository_commit_id : d.refusal_record_id,
    refusal_code: value.state === 'committed' ? null : d.code });
}
async function settle(s, accepted) {
  const terminal = { schema: `${SCHEMA}/terminal`, request_sha256: s.hash, decision: accepted };
  const path = join(s.path, 'terminal.json'); let terminalHash;
  try { terminalHash = await putRecord(path, terminal); }
  catch (error) {
    if (error.code !== 'EEXIST') throw error;
    const other = await readRecord(path);
    if (!same(other.value, terminal)) fail('source_edit_terminal_conflict');
    await syncFile(path); await syncDirectory(s.path); terminalHash = other.sha256;
  }
  return { type: 'source_apply_terminal', journal: s.path, request_sha256: s.hash, key: s.request.key,
    terminal_sha256: terminalHash, decision: accepted, submission_retried: false, delivery_acknowledged: null, ...evidenceReceipt(s.checked) };
}
function pending(s, state = 'outcome_unknown') {
  return { type: 'source_apply_pending', journal: s.path, request_sha256: s.hash, key: s.request.key,
    principal_id: s.request.principal_id, state, submission_retried: false, absence_proves_non_commit: false, ...evidenceReceipt(s.checked) };
}
async function syncCandidate(s) {
  const files = ['capture.json', 'candidate.bundle', ...(s.checked.source_evidence ? [PACKAGE_FILE, EXPECTED_FILE] : []), 'manifest.json'];
  for (const name of files) await syncFile(join(s.path, 'candidate', name));
  await syncDirectory(join(s.path, 'candidate')); await syncFile(join(s.path, 'request.json')); await syncDirectory(s.path);
}
export async function dispatchSourceApply(path, requestHash, credential, options = {}) {
  const time = clock(options);
  if (typeof credential !== 'string' || !/^[0-9a-f]{64}$/.test(credential)) fail('source_edit_credential');
  const s = await state(path, requestHash, time.check);
  if (s.terminal) return settle(s, s.terminal.value.decision);
  if (s.dispatched) fail('source_edit_already_dispatched');
  // Re-sync the exact checked predecessor before admitting new responsibility.
  await syncCandidate(s); time.check();
  await mkdir(join(path, 'dispatch'), { mode: 0o700 });
  try {
    await syncDirectory(path);
    await putRecord(join(path, 'dispatch', 'started.json'), { schema: `${SCHEMA}/started`, request_sha256: requestHash });
    await syncDirectory(path); time.check();
    const response = await exchange(s.request.endpoint, credential, 'apply',
      upload(editCoordinates(s.checked.capture.request, s.request.candidate_commit), s.checked.bundle, 'bundle'),
      time, Math.min(16384, time.maxWireBytes), s.request.key);
    // A validated terminal wins over cancellation racing socket close.
    const accepted = publication(parse(response.bytes, 16384), s.request, response.status);
    if (s.observed && s.observed.value.observation.transaction.tx_id !== accepted.tx_id) fail('source_edit_terminal_conflict');
    return await settle(s, accepted);
  } catch (error) { error.retained_request = pending(s); throw error; }
}
export async function recoverSourceApply(path, requestHash, credential, options = {}) {
  const time = clock(options), s = await state(path, requestHash, time.check);
  if (s.terminal) return settle(s, s.terminal.value.decision);
  if (!s.start) return pending(s, s.dispatched ? 'dispatch_incomplete' : 'not_dispatched');
  // Nothing about a missing outcome authorizes resubmission. This route has no
  // bundle or mutation payload, even with a rotated recovery-only credential.
  const response = await exchange(s.request.endpoint, credential, 'outcomes', null, time, Math.min(16384, time.maxWireBytes), s.request.key);
  const observed = validateOutcomeReply(parse(response.bytes, 16384), scopeOf(s.request), s.observed?.value.observation ?? null);
  if (observed.transaction) {
    const value = { schema: `${SCHEMA}/transaction`, request_sha256: requestHash, observation: observed };
    try { await putRecord(join(path, 'transaction.json'), value); }
    catch (e) {
      if (e.code !== 'EEXIST') throw e;
      const other = await readRecord(join(path, 'transaction.json'));
      if (other.value.schema !== value.schema || other.value.request_sha256 !== requestHash) fail('source_edit_observation_changed');
      validateOutcomeReply(observed, scopeOf(s.request), other.value.observation);
      await syncFile(join(path, 'transaction.json')); await syncDirectory(path);
    }
  }
  if (observed.terminal) return settle(s, decisionFromOutcome(observed));
  time.check(); return { ...pending(s, observed.state), observation: observed };
}
export async function inspectSourceApply(path, requestHash, options = {}) {
  const time = clock(options), s = await state(path, requestHash, time.check);
  return { ...pending(s, s.terminal ? 'terminal' : s.start ? 'outcome_unknown' : s.dispatched ? 'dispatch_incomplete' : 'not_dispatched'),
    decision: s.terminal?.value.decision ?? null, terminal_sha256: s.terminal?.sha256 ?? null, read_only: true };
}
