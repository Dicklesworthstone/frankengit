// Explicit same-source follow-up, not an automatic retry, moving workspace,
// server cursor, authorization grant, or cross-query completeness claim.
import { acquire, query, endpoint, fail } from './source_context.mjs';
import { loadBundle } from './source_context_export.mjs';

const LIMIT_NAMES = ['max_results_per_channel', 'max_work', 'max_payload_bytes', 'max_result_bytes',
  'context_max_files', 'context_radius_bytes', 'context_max_source_bytes', 'context_max_excerpt_bytes'];
function fields(value, allowed) {
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
      Object.keys(value).some(k => !allowed.includes(k))) fail('invalid_context_followup_fields');
}
// Bound and detach every caller-controlled collection before the first await.
// The ordinary query normalizer still owns the full grammar after inheritance.
function changes(value) {
  fields(value, ['terms', 'prefixes_hex', 'symbols', 'selection', 'limits']);
  if (!Array.isArray(value.terms) || !value.terms.length || value.terms.length > 32) fail('invalid_context_followup_terms');
  for (const term of value.terms) if (typeof term !== 'string' || !/^[A-Za-z0-9_]{1,128}$/.test(term)) fail('invalid_context_followup_terms');
  if (Object.hasOwn(value, 'prefixes_hex')) {
    if (!Array.isArray(value.prefixes_hex) || value.prefixes_hex.length > 128) fail('invalid_context_followup_scope');
    let bytes = 0;
    for (const prefix of value.prefixes_hex) {
      if (typeof prefix !== 'string' || !prefix.length || prefix.length > 8192 ||
          !/^(?:[0-9a-f]{2})+$/.test(prefix) || (bytes += prefix.length / 2) > 32768) fail('invalid_context_followup_scope');
    }
  }
  if (Object.hasOwn(value, 'symbols')) {
    fields(value.symbols, ['name', 'match', 'policy', 'kinds']);
    for (const key of ['name', 'match', 'policy']) {
      if (Object.hasOwn(value.symbols, key) && (typeof value.symbols[key] !== 'string' || value.symbols[key].length > 128)) fail('invalid_context_followup_symbols');
    }
    if (Object.hasOwn(value.symbols, 'kinds')) {
      if (!Array.isArray(value.symbols.kinds) || value.symbols.kinds.length > 8) fail('invalid_context_followup_symbols');
      for (const kind of value.symbols.kinds) if (typeof kind !== 'string' || kind.length > 16) fail('invalid_context_followup_symbols');
    }
  }
  if (Object.hasOwn(value, 'limits')) {
    fields(value.limits, LIMIT_NAMES);
    for (const n of Object.values(value.limits)) if (!Number.isSafeInteger(n) || n < 0 || n > 67108864) fail('invalid_context_followup_limits');
  }
  if (Object.hasOwn(value, 'selection') && (typeof value.selection !== 'string' || value.selection.length > 64)) fail('invalid_context_followup_selection');
  return structuredClone(value);
}
function nextQuery(summary, delta) {
  const before = summary.query;
  const proposed = { ...before, ...delta, limits: { ...before.limits, ...delta.limits },
    expected_head: summary.source.snapshot_token, expected_commit: summary.source.source_commit,
    minimum_lexical: summary.lexical_checkpoint };
  if (before.symbols || delta.symbols) {
    proposed.symbols = { ...before.symbols, ...delta.symbols };
    // Even originally optional symbols become floor-bound once observed.
    // A missing channel cannot erase responsibility for that observation.
    proposed.minimum_symbol = summary.symbols?.generation ?? before.minimum_symbol ?? null;
  }
  const next = query(proposed);
  if (before.prefixes_hex.length && (!next.prefixes_hex.length || next.prefixes_hex.some(p =>
      !before.prefixes_hex.some(parent => p === parent || p.startsWith(`${parent}2f`))))) fail('context_followup_scope_widened');
  for (const name of LIMIT_NAMES) if (next.limits[name] > before.limits[name]) fail('context_followup_budget_widened');
  if (before.symbols?.policy === 'required' && next.symbols?.policy !== 'required') fail('context_followup_symbols_weakened');
  return next;
}

/// Verify one independently pinned private bundle and issue ONE follow-up read.
/// Endpoint, namespace, full ref, source snapshot and checkpoint floors come
/// from the verified capture, never from repository excerpts or delta fields.
/// A new capture can be exported with publishBundle; the old bundle is read-only.
/// Returned linkage is a local integrity receipt, not authenticated ancestry.
export async function continueCapture(bundle, expectedManifest, credential, followup, options = {}) {
  fields(options, ['signal', 'timeoutMs', 'ca']);
  const timeout = options.timeoutMs ?? 30000, signal = options.signal;
  if (!Number.isSafeInteger(timeout) || timeout < 1 || timeout > 300000) fail('invalid_context_cli_timeout');
  if (signal !== undefined && !(signal instanceof AbortSignal)) fail('invalid_context_signal');
  if (typeof credential !== 'string' || !/^[0-9a-f]{64}$/.test(credential)) fail('invalid_source_read_token');
  if (options.ca !== undefined && (!(options.ca instanceof Uint8Array) || !options.ca.length || options.ca.length > 262144)) fail('invalid_context_ca');
  const started = performance.now(), check = () => {
    signal?.throwIfAborted();
    if (performance.now() - started >= timeout) fail('context_deadline_exceeded');
  };
  check();
  const delta = changes(followup), ca = options.ca === undefined ? undefined : Buffer.from(options.ca);
  const previous = await loadBundle(bundle, expectedManifest, check);
  check();
  const address = endpoint(previous.capture.endpoint), selected = nextQuery(previous.capture.summary, delta);
  const remaining = Math.floor(timeout - (performance.now() - started));
  if (remaining < 1) fail('context_deadline_exceeded');
  const capture = await acquire(address, credential, selected, { signal, timeoutMs: remaining, ca });
  check();
  // Native expected_head/expected_commit pins are necessary but do not excuse
  // inconsistent RCR/tree metadata in a response claiming the same head.
  if (JSON.stringify(capture.summary.source) !== JSON.stringify(previous.capture.summary.source)) fail('context_followup_source_changed');
  return { capture, continued_from: { manifest_sha256: expectedManifest, capture_sha256: previous.receipt.capture_sha256,
    source: previous.capture.summary.source, lexical_checkpoint: previous.capture.summary.lexical_checkpoint,
    ...(previous.capture.summary.symbols?.generation ? { symbol_checkpoint: previous.capture.summary.symbols.generation } : {}) } };
}
