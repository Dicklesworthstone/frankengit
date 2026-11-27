// Terminal access to the shipped native tag client. Files retain retry custody;
// only native admission and outcome observations decide publication.
import { webcrypto } from 'node:crypto';
import { TagClient, RETRY_LIMIT } from '../../crates/fgit-node/src/smart_http/server/browser/tags.mjs';
import { nativeRef, tagFields } from '../../crates/fgit-node/src/smart_http/server/browser/tags-protocol.mjs';
import { format, integer, oid } from '../../crates/fgit-node/src/smart_http/server/browser/pulls-core.mjs';
import { operatorError, operatorPath, operatorJson, parseOperatorJson, privateRecordPath, absentRecord,
  readPrivateOperatorFile, readSynchronizedOperatorRecord, saveOperatorRecord, recordDigest } from './forge-operator-io.mjs';

const SCHEMA = 'frankengit-tag-operator-v1', MAX_RECORD = RETRY_LIMIT * 2;
const WRITES = ['lightweight', 'annotated', 'delete'], READS = ['list', 'show'];
const fail = code => { throw operatorError(code); };
const exact = (v, names) => v !== null && typeof v === 'object' && !Array.isArray(v) &&
  Object.keys(v).length === names.length && names.every(name => Object.hasOwn(v, name));
const pick = (v, names) => Object.fromEntries(names.map(name => [name, v[name]]));
function reference(value, prefix) {
  if (nativeRef(value, prefix).length > 1024) fail('tag_operator_reference_limit');
  return value;
}

export function tagOperatorOptions(raw) {
  const common = ['operation', 'href', 'tenant', 'repository', 'tokenFile', 'timeoutMs', 'signal', 'onProgress'];
  const operation = raw?.operation;
  const allowed = operation === 'status' || operation === 'retry' ? ['record']
    : operation === 'list' ? ['objectFormat', 'limit', 'maxPages', 'maxOutputBytes']
    : operation === 'show' ? ['objectFormat', 'limit', 'maxPages', 'maxOutputBytes', 'refHex']
    : operation === 'delete' ? ['objectFormat', 'limit', 'maxPages', 'record', 'refHex', 'expectedObject']
    : ['objectFormat', 'limit', 'maxPages', 'record', 'refHex', 'sourceRefHex', 'target',
      ...(operation === 'annotated' ? ['targetKind', 'tagger', 'timestamp', 'messageHex'] : [])];
  if (!raw || typeof raw !== 'object' || Array.isArray(raw) ||
      Object.keys(raw).some(key => ![...common, ...allowed].includes(key)) ||
      ![...WRITES, ...READS, 'status', 'retry'].includes(operation)) fail('tag_operator_options');
  const o = { ...raw, timeoutMs: raw.timeoutMs ?? 30000, onProgress: raw.onProgress ?? (() => {}) };
  for (const key of ['tenant', 'repository']) if (typeof o[key] !== 'string' || !/^[0-9a-f]{32}$/.test(o[key])) fail('tag_operator_identity');
  if (typeof o.href !== 'string' || o.href.length > 4096 || /[\u0000-\u0020\u007f-\u009f\uD800-\uDFFF]/u.test(o.href)) fail('tag_operator_url');
  if (new URL(o.href).href !== o.href) fail('tag_operator_url');
  // The native client owns HTTPS/loopback, exact repository route and grammar.
  new TagClient({ href: o.href, timeoutMs: o.timeoutMs, cryptoImpl: webcrypto });
  if ((o.signal !== undefined && !(o.signal instanceof AbortSignal)) || typeof o.onProgress !== 'function') fail('tag_operator_lifetime');
  o.tokenFile = operatorPath(o.tokenFile);
  if (!READS.includes(operation)) {
    o.record = operatorPath(o.record);
    if (o.record === o.tokenFile) fail('tag_operator_separate_record');
  }
  if (operation === 'status' || operation === 'retry') return o;
  o.objectFormat = format(o.objectFormat);
  o.limit = integer(o.limit ?? 100, 'reference page size', 1, 100);
  o.maxPages = integer(o.maxPages ?? (operation === 'list' ? 1 : 20), 'reference page budget', 1, 100);
  if (READS.includes(operation)) o.maxOutputBytes = integer(o.maxOutputBytes ?? 8 * 1024 * 1024, 'output budget', 1, 8 * 1024 * 1024);
  if (operation !== 'list') reference(o.refHex, 'refs/tags/');
  if (WRITES.includes(operation)) {
    const fields = { object_format: o.objectFormat, ref_hex: o.refHex };
    if (operation === 'delete') fields.expected_object = o.expectedObject = oid(o.expectedObject, o.objectFormat);
    else {
      reference(o.sourceRefHex, 'refs/');
      fields.target = o.target = oid(o.target, o.objectFormat);
      if (operation === 'annotated') Object.assign(fields, { target_kind: o.targetKind, tagger: o.tagger,
        timestamp: o.timestamp, message_hex: o.messageHex });
    }
    tagFields(operation, fields);
  }
  return o;
}

function checkedBinding(reply, o) {
  if (reply.tenant_id !== o.tenant || reply.repository_id !== o.repository) fail('tag_operator_repository_mismatch');
}
async function connect(client, o, check) {
  const bytes = await readPrivateOperatorFile(o.tokenFile, 65, check);
  try {
    const token = bytes.toString('ascii').replace(/\n$/, '');
    if (bytes.some(byte => byte > 127) || !/^[0-9a-f]{64}$/.test(token)) fail('tag_operator_invalid_token');
    await client.connect(token); check();
  } finally { bytes.fill(0); }
}
function receipt(bytes, o) {
  const value = parseOperatorJson(bytes, 'tag_operator_invalid_record');
  if (!exact(value, ['schema', 'href', 'tenant', 'repository', 'receipt']) || value.schema !== SCHEMA ||
      value.href !== o.href || value.tenant !== o.tenant || value.repository !== o.repository ||
      !Buffer.from(JSON.stringify(value) + '\n').equals(bytes)) fail('tag_operator_record_mismatch');
  const scope = value.receipt?.scope;
  if (scope?.tenant !== o.tenant || scope?.repository !== o.repository) fail('tag_operator_repository_mismatch');
  return JSON.stringify(value.receipt);
}
const commonFields = ['type', 'schema_version', 'tenant_id', 'repository_id', 'repository_incarnation',
  'object_format', 'source_head', 'snapshot_token', 'read_only', 'transaction_created', 'published'];
function inventoryPage(page) {
  return { ...pick(page, commonFields), namespace: 'tags', source_namespace: 'all', cursor_encoding: 'hex',
    after: page.after, limit: page.limit, next_after: page.next_after,
    refs: page.refs.filter(row => row.ref_hex.startsWith('726566732f746167732f'))
      .map(row => pick(row, ['ref', 'ref_hex', 'object_id'])) };
}
function inspectionReport(value) {
  return { ...pick(value, [...commonFields, 'ref_hex', 'object_id', 'peeled_object', 'peeled_kind',
    'annotation_count', 'signature_verified', 'tagger_is_authenticated_principal']),
  annotations: value.annotations.map(row => pick(row, ['object_id', 'target', 'target_kind', 'signature',
    'signature_verified', 'body_bytes', 'body_hex'])) };
}

// A session owns at most 2048 reference rows in TagClient. Hex continuations
// can cross non-UTF-8 names without fabricating a text cursor or changing head.
async function select(client, o, check, progress) {
  const pages = []; let count = 0, page = null, stopReason = 'page_budget', retained = 0, sourceHead = null;
  const wanted = o.operation === 'list' ? null : ['lightweight', 'annotated'].includes(o.operation) ? o.sourceRefHex : o.refHex;
  while (pages.length < o.maxPages) {
    if (count + o.limit > 2048) { stopReason = 'reference_budget'; break; }
    check();
    page = await client.list(pages.length ? { next: true } : { objectFormat: o.objectFormat, limit: o.limit, cursorEncoding: 'hex' });
    check(); checkedBinding(page, o);
    if (sourceHead !== null && page.source_head !== sourceHead) fail('tag_read_source_head_moved');
    sourceHead = page.source_head; count += page.refs.length;
    const safe = o.operation === 'list' ? inventoryPage(page) : null;
    if (safe) {
      retained += Buffer.byteLength(operatorJson(safe));
      if (retained > o.maxOutputBytes) fail('tag_read_output_limit');
    }
    pages.push(safe); progress('page_checked');
    const row = wanted === null ? null : client.refs.find(value => value.ref_hex === wanted);
    if (row) return { page, pages, row, count, stopReason: 'selected' };
    if (page.next_after === null) { stopReason = 'exhausted'; break; }
  }
  if (wanted !== null && stopReason !== 'exhausted') fail('tag_operator_reference_budget');
  return { page, pages, row: null, count, stopReason };
}

export async function runTagOperation(raw) {
  const o = tagOperatorOptions(raw), reading = READS.includes(o.operation), fresh = WRITES.includes(o.operation);
  const stop = new AbortController(), signal = o.signal ? AbortSignal.any([o.signal, stop.signal]) : stop.signal;
  const check = () => { if (signal.aborted) fail('tag_operator_cancelled_or_deadline'); };
  const progress = phase => { o.onProgress(Object.freeze({ phase })); check(); };
  const timer = setTimeout(() => stop.abort(), o.timeoutMs);
  const client = new TagClient({ href: o.href, timeoutMs: o.timeoutMs, cryptoImpl: webcrypto,
    fetchImpl: (url, init) => {
      const headers = new Headers(init.headers);
      headers.set('User-Agent', 'frankengit-agent (+https://github.com/Dicklesworthstone/frankengit)');
      return fetch(url, { ...init, headers, signal: AbortSignal.any([signal, init.signal]) });
    } });
  let state = reading ? 'read_incomplete' : fresh ? 'not_submitted' : 'existing_unknown';
  let path = o.record ?? null, digest = null, bytes;
  const result = (outcome, submitted) => ({ type: 'forge_tag_operator_result', operation: o.operation,
    state: outcome.terminal ? 'terminal_observed' : 'unresolved', record: path, record_sha256: digest,
    result: outcome, mutation_submitted: submitted, absence_proves_non_commit: false });
  try {
    check();
    if (!reading) {
      path = await privateRecordPath(path); check();
      if (fresh) await absentRecord(path);
      else { bytes = await readPrivateOperatorFile(path, MAX_RECORD, check); digest = recordDigest(bytes); receipt(bytes, o); }
    }
    await connect(client, o, check);
    if (reading || fresh) {
      const selected = await select(client, o, check, progress);
      if (reading) {
        let report = null;
        if (o.operation === 'show' && selected.row) {
          const inspected = await client.inspect(o.refHex); check();
          if (inspected.source_head !== selected.page.source_head) fail('tag_read_source_head_moved');
          report = inspectionReport(inspected);
        }
        const complete = o.operation === 'show' || selected.stopReason === 'exhausted';
        const output = { type: 'forge_tag_operator_read', schema_version: 1, operation: o.operation,
          href: o.href, tenant_id: o.tenant, repository_id: o.repository, object_format: o.objectFormat,
          snapshot_token: selected.page.snapshot_token, page_count: selected.pages.length,
          source_refs_scanned: selected.count, complete, stop_reason: selected.stopReason,
          read_only: true, mutation_submitted: false,
          ...(o.operation === 'list' ? { pages: selected.pages, next_after_hex: selected.page.next_after,
            restart_required: !complete, cross_invocation_resume_supported: false }
            : { ref_hex: o.refHex, found: selected.row !== null, inspection: report }) };
        if (Buffer.byteLength(operatorJson(output)) > o.maxOutputBytes) fail('tag_read_output_limit');
        check(); return output;
      }
      if (!selected.row) fail('tag_operator_selected_reference_missing');
      const expected = o.operation === 'delete' ? o.expectedObject : o.target;
      if (selected.row.object_id !== expected) fail('tag_operator_object_moved');
      progress('source_checked');
      const fields = { ref_hex: o.refHex };
      if (o.operation !== 'delete') fields.source_ref_hex = o.sourceRefHex;
      if (o.operation === 'annotated') Object.assign(fields, { target_kind: o.targetKind, tagger: o.tagger,
        timestamp: o.timestamp, message_hex: o.messageHex });
      await client.prepare(o.operation, fields); check();
      bytes = Buffer.from(JSON.stringify({ schema: SCHEMA, href: o.href, tenant: o.tenant,
        repository: o.repository, receipt: JSON.parse(client.exportReceipt()) }) + '\n');
      if (bytes.length > MAX_RECORD) fail('tag_operator_record_limit');
      const saved = await saveOperatorRecord(path, bytes, check); digest = saved.sha256;
      state = 'recorded_unknown'; progress('receipt_saved');
    } else {
      await client.restoreReceipt(receipt(bytes, o)); check();
      const outcome = await client.recover();
      if (outcome.terminal || o.operation === 'status') return result(outcome, false);
      progress('recovery_observed');
    }
    // Each sender establishes its own exact-file/parent sync barrier. A retry
    // never refreshes source refs, tag metadata, expectations, credential or key.
    const current = await readSynchronizedOperatorRecord(path, MAX_RECORD, check);
    if (!current.equals(bytes)) fail('tag_operator_record_changed');
    state = 'submitted_unknown';
    return result(await client.send(), true);
  } catch (cause) {
    const error = cause instanceof Error ? cause : operatorError('tag_operator_failed');
    error.operator_state = state; error.record = path; error.record_sha256 = digest; throw error;
  } finally { clearTimeout(timer); client.disconnect(); }
}
