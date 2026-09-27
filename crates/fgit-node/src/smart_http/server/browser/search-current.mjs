// Closed presentation checks for explicit current-source index revalidation.
// These compare native-server claims; they do not authenticate roots or grant
// source access. BigInt is used only for comparisons, never stored in UI state.
const refuse = message => { throw new Error(message); };
const U64_MAX = 18446744073709551615n;
const utf8 = new TextEncoder();

export function sourceMode(value) {
  if (value === undefined || value === 'exact') return 'exact';
  if (value === 'revalidated') return value;
  return refuse('Select exact or explicitly revalidated indexed source.');
}

export function wireCounter(value, mode, minimum = 1) {
  if (sourceMode(mode) === 'exact') {
    if (!Number.isSafeInteger(value) || value < minimum) refuse('Invalid exact indexed counter.');
  } else {
    if (typeof value !== 'string' || value.length > 20 || !/^(0|[1-9][0-9]*)$/.test(value) ||
        BigInt(value) < BigInt(minimum) || BigInt(value) > U64_MAX) refuse('Invalid decimal u64 indexed counter.');
  }
  return value;
}

// Retained checkpoints may originate in the older exact profile or the new
// string profile. Compare values exactly across a mode switch, not lexically.
export function compareCounters(left, right) {
  const number = value => BigInt(wireCounter(value, typeof value === 'number' ? 'exact' : 'revalidated', 0));
  const a = number(left), b = number(right);
  return a < b ? -1 : a > b ? 1 : 0;
}

const SOURCE_FIELDS = ['tenant_id', 'repository_id', 'repository_incarnation', 'object_format', 'ref_hex',
  'source_head', 'snapshot_token', 'source_rcr', 'forge_position_root', 'source_commit', 'root_tree'];
const NATIVE_FIELDS = ['tenant_id', 'repository_id', 'repository_incarnation', 'object_format', 'ref_hex', 'source_commit', 'root_tree'];
const identical = (a, b) => SOURCE_FIELDS.every(key => a[key] === b[key]);

function sourceRecord(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value) || Object.keys(value).length !== SOURCE_FIELDS.length ||
      Object.keys(value).some(key => !SOURCE_FIELDS.includes(key))) refuse('Incomplete indexed source provenance.');
  for (const key of SOURCE_FIELDS) {
    const text = value[key], limit = key === 'ref_hex' ? 8192 : 256;
    if (typeof text !== 'string' || !text.trim() || text.length > limit || utf8.encode(text).length > limit ||
        /[\u0000-\u001f\u007f-\u009f\uD800-\uDFFF]/u.test(text)) refuse('Invalid indexed source identity.');
  }
  const snapshot = value.snapshot_token;
  if (!/^alg:[1-9][0-9]{0,4}:(?:[0-9a-f]{2}){1,64}$/.test(snapshot) ||
      Number(snapshot.split(':')[1]) > 65535 || /^0+$/.test(snapshot.split(':')[2])) refuse('Invalid indexed source snapshot.');
  if (!/^(?:[0-9a-f]{2})+$/.test(value.ref_hex)) refuse('Invalid indexed source reference bytes.');
  return Object.fromEntries(SOURCE_FIELDS.map(key => [key, value[key]]));
}

function nativeOid(value, format) {
  if (!['sha1', 'sha256'].includes(format)) refuse('Invalid indexed source object format.');
  const raw = value.startsWith(`${format}:`) ? value.slice(format.length + 1) : value;
  if (!new RegExp(`^[0-9a-f]{${format === 'sha1' ? 40 : 64}}$`).test(raw) || /^0+$/.test(raw)) refuse('Invalid indexed source object identity.');
  return raw;
}

// `source` is the result of coordinates(): current route/scope/read flags and
// the current snapshot were already checked there. Old provenance is displayed
// separately and MUST NOT replace that pin for file reads or continuations.
export function currentSources(reply, source, previous = null) {
  if (reply.source_mode !== 'revalidated' || typeof reply.distinct_provenance !== 'boolean') refuse('Missing explicit source revalidation.');
  const current = sourceRecord(reply.current_source), indexed = sourceRecord(reply.indexed_source);
  const expected = { tenant_id: source.scope.tenant, repository_id: source.scope.repository,
    repository_incarnation: source.scope.incarnation, object_format: source.scope.format,
    ref_hex: reply.ref_hex, source_head: source.pin.sourceHead, snapshot_token: source.pin.head, source_rcr: source.pin.rcr };
  if (Object.keys(expected).some(key => current[key] !== expected[key]) ||
      nativeOid(current.source_commit, source.scope.format) !== source.pin.commit ||
      nativeOid(current.root_tree, source.scope.format) !== source.pin.tree ||
      NATIVE_FIELDS.some(key => current[key] !== indexed[key])) refuse('Revalidated native source or current pin changed.');
  const sameHead = current.snapshot_token === indexed.snapshot_token;
  if (sameHead !== (current.source_head === indexed.source_head) ||
      (sameHead && (current.source_rcr !== indexed.source_rcr || current.forge_position_root !== indexed.forge_position_root))) {
    refuse('Contradictory indexed provenance at the same head.');
  }
  const distinct = !identical(current, indexed);
  if (reply.distinct_provenance !== distinct) refuse('Incorrect indexed provenance label.');
  if (previous && (!previous.sources || !identical(previous.sources.current, current) ||
      !identical(previous.sources.indexed, indexed))) refuse('Indexed continuation changed source provenance.');
  return { current, indexed, distinct };
}

// Symbol revalidation wraps an UNCHANGED strict result, unlike lexical reads.
// Accept only the native wrapper and bind its original receipt before any
// caller installs current navigation pins or advances an index checkpoint.
export function symbolSources(reply) {
  const envelope = ['type', 'schema_version', 'source_mode', 'read_only', 'transaction_created',
    'published', 'current_source', 'indexed_source', 'result'];
  if (!reply || typeof reply !== 'object' || Array.isArray(reply) ||
      Object.keys(reply).length !== envelope.length || Object.keys(reply).some(key => !envelope.includes(key)) ||
      reply.type !== 'source_search_symbols_index_revalidated' || reply.schema_version !== 1 ||
      reply.source_mode !== 'revalidated' || reply.read_only !== true || reply.transaction_created !== false || reply.published !== false) {
    refuse('Invalid revalidated declaration envelope.');
  }
  const readSource = value => {
    if (!value || typeof value !== 'object' || Array.isArray(value) || !Object.hasOwn(value, 'ref')) refuse('Missing declaration source reference.');
    const { ref, ...rest } = value, source = sourceRecord(rest);
    if (typeof ref !== 'string' || !ref.length || utf8.encode(ref).length > 1024 ||
        Array.from(utf8.encode(ref), byte => byte.toString(16).padStart(2, '0')).join('') !== source.ref_hex) {
      refuse('Declaration source reference text and bytes disagree.');
    }
    nativeOid(source.source_commit, source.object_format); nativeOid(source.root_tree, source.object_format);
    return { ...source, ref };
  };
  const current = readSource(reply.current_source), indexed = readSource(reply.indexed_source);
  if (NATIVE_FIELDS.some(key => current[key] !== indexed[key]) || current.ref !== indexed.ref) refuse('Revalidated declaration native source changed.');
  const sameHead = current.snapshot_token === indexed.snapshot_token;
  if (sameHead !== (current.source_head === indexed.source_head) ||
      (sameHead && (current.source_rcr !== indexed.source_rcr || current.forge_position_root !== indexed.forge_position_root))) {
    refuse('Contradictory declaration provenance at the same head.');
  }
  const result = reply.result;
  if (!result || typeof result !== 'object' || Array.isArray(result) || result.ref !== indexed.ref ||
      SOURCE_FIELDS.some(key => key !== 'forge_position_root' && result[key] !== indexed[key])) {
    refuse('Nested declaration receipt changed its original source.');
  }
  return { current, indexed, distinct: !identical(current, indexed) };
}
