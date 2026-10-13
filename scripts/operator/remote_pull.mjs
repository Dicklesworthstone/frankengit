// Authenticated remote PR lifecycle, discussion and fast-forward publication.
// Recovery is the unchanged shared original-key reader, never a command replay.
import { request as httpRequest } from 'node:http';
import { request as httpsRequest } from 'node:https';
import { performance } from 'node:perf_hooks';
import { lookupOutcome, validateOutcomeReply, OutcomeError } from './transaction_outcome.mjs';
import { PULL_LIMITS, PullError, pullFields, failPull, pullOutcomeScope, pullTokenFingerprint,
  validatePullIntent, validatePullPublication, parsePullJson } from './pull_command.mjs';
export { preparePull, validatePullIntent, pullCanonical, parsePullJson, PullError } from './pull_command.mjs';

function configuration(options, send) {
  pullFields(options, ['timeoutMs', 'signal', 'ca', 'known', 'publication', ...(send ? ['confirmKey', 'confirmFastForward'] : [])], []);
  const timeoutMs = options.timeoutMs ?? 30000;
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 300000 ||
      (options.signal !== undefined && !(options.signal instanceof AbortSignal))) failPull('invalid_pull_options');
  const ca = options.ca === undefined ? undefined : Buffer.isBuffer(options.ca) && options.ca.length > 0 && options.ca.length <= 128 * 1024
    ? Buffer.from(options.ca) : failPull('invalid_pull_ca');
  return { ...options, timeoutMs, ca };
}
function matching(outcome, publication) {
  if (publication === null) return outcome;
  const d = outcome.decision;
  if (!outcome.terminal || outcome.transaction?.tx_id !== publication.tx_id || d.kind !== publication.outcome ||
      d.decision_sequence !== publication.decision_sequence ||
      (d.repository_commit_id ?? null) !== publication.repository_commit_id ||
      (d.refusal_record_id ?? null) !== publication.refusal_record_id || (d.code ?? null) !== publication.refusal_code ||
      (d.code_point ?? null) !== publication.refusal_code_point) failPull('pull_outcome_publication_conflict');
  return outcome;
}
function errorFor(error, phase, dispatched, publication) {
  return new PullError(error instanceof PullError || error instanceof OutcomeError ? error.code : 'pull_operation_unavailable',
    { status: error instanceof PullError || error instanceof OutcomeError ? error.status : null, phase, dispatched, publication });
}
function postPull(intent, token, options) {
  return new Promise((resolve, reject) => {
    let request, response, value, failure, timer, finished = false, closed = false, delivered = false;
    const signal = options.signal;
    const deliver = () => { if (delivered) return; delivered = true; failure ? reject(failure) : resolve(value); };
    const finish = (error, result) => {
      if (finished) return; finished = true; failure = error; value = result;
      clearTimeout(timer); signal?.removeEventListener('abort', abort); response?.destroy(); request?.destroy();
      if (!request || closed) deliver();
    };
    const abort = () => finish(new PullError('pull_cancelled'));
    if (signal?.aborted) { abort(); return; }
    try {
      const suffix = intent.action === 'comment' ? 'comments' : intent.action;
      const url = new URL(`${intent.endpoint}/api/v1/pulls/${intent.number}/${suffix}`);
      request = (url.protocol === 'https:' ? httpsRequest : httpRequest)(url, {
        method: 'POST', agent: false, maxHeaderSize: 16384, rejectUnauthorized: true, ...(options.ca ? { ca: options.ca } : {}),
        headers: { Authorization: `Bearer ${token}`, 'Idempotency-Key': intent.key, Accept: 'application/json',
          'Content-Type': 'application/x-www-form-urlencoded', 'Content-Length': String(Buffer.byteLength(intent.body)),
          'Accept-Encoding': 'identity', Connection: 'close', 'Cache-Control': 'no-store' },
      });
      request.once('close', () => { closed = true; if (!finished) finish(new PullError('pull_response_incomplete')); else deliver(); });
      request.on('error', () => finish(new PullError('pull_transport_unavailable')));
      request.once('response', incoming => {
        response = incoming;
        if (![200, 409].includes(incoming.statusCode)) { finish(new PullError('pull_http_refused', { status: incoming.statusCode })); return; }
        const names = incoming.rawHeaders.filter((_, i) => i % 2 === 0).map(name => name.toLowerCase())
          .filter(name => ['content-type', 'content-length', 'content-encoding'].includes(name));
        const declared = incoming.headers['content-length'];
        if (new Set(names).size !== names.length || !/^application\/json(?:\s*;|$)/i.test(incoming.headers['content-type'] ?? '') ||
            (incoming.headers['content-encoding'] ?? 'identity').toLowerCase() !== 'identity') {
          finish(new PullError('pull_response_encoding')); return;
        }
        if (declared !== undefined && (!/^(0|[1-9][0-9]*)$/.test(declared) || BigInt(declared) > BigInt(PULL_LIMITS.reply))) {
          finish(new PullError('pull_response_limit')); return;
        }
        const chunks = []; let size = 0;
        incoming.on('error', () => finish(new PullError('pull_response_incomplete')));
        incoming.on('data', chunk => {
          if (finished) return;
          size += chunk.length;
          if (size > PULL_LIMITS.reply || chunks.length >= PULL_LIMITS.reply) finish(new PullError('pull_response_limit'));
          else chunks.push(chunk);
        });
        incoming.once('end', () => {
          if (finished) return;
          if (!incoming.complete || (declared !== undefined && BigInt(declared) !== BigInt(size))) { finish(new PullError('pull_response_incomplete')); return; }
          try { finish(null, validatePullPublication(parsePullJson(Buffer.concat(chunks, size), { wire: true, maximum: PULL_LIMITS.reply }), intent, incoming.statusCode)); }
          catch (error) { finish(error); }
        });
      });
      signal?.addEventListener('abort', abort, { once: true });
      timer = setTimeout(() => finish(new PullError('pull_timeout')), options.timeoutMs);
      if (signal?.aborted) abort(); else request.end(intent.body);
    } catch { finish(new PullError('pull_transport_unavailable')); }
  });
}
async function operate(input, token, options, send) {
  // Detach every caller-owned value before the first await. A concurrent form
  // edit cannot change the authenticated scope, bytes, deadline or trust roots.
  const intent = validatePullIntent(input), config = configuration(options, send);
  const fingerprint = pullTokenFingerprint(token), scope = pullOutcomeScope(intent.scope);
  let publication = config.publication == null ? null : validatePullPublication(config.publication, intent,
    config.publication.outcome === 'committed' ? 200 : 409);
  const known = config.known == null ? null : validateOutcomeReply(config.known, scope);
  if (send && (fingerprint !== intent.credential_fingerprint || config.confirmKey !== intent.key)) failPull('confirm_original_pull_key_and_credential');
  if (send && (intent.action === 'fast-forward' ? config.confirmFastForward !== true : config.confirmFastForward !== undefined)) failPull('explicit_fast_forward_confirmation_required');
  const deadline = performance.now() + config.timeoutMs;
  const remaining = () => {
    if (config.signal?.aborted) failPull('pull_cancelled');
    const duration = Math.ceil(deadline - performance.now());
    if (duration <= 0) failPull('pull_timeout');
    return { timeoutMs: duration, signal: config.signal, ca: config.ca };
  };
  const lookup = prior => lookupOutcome(intent.endpoint, token, { ...scope, key: intent.key }, { ...remaining(), known: prior });
  let phase = 'preflight', dispatched = false;
  try {
    const before = await lookup(known);
    if (!send || before.terminal || publication !== null) {
      matching(before, publication);
      return { outcome: before, publication, dispatched: false };
    }
    phase = 'publication';
    const transport = remaining(); dispatched = true;
    publication = await postPull(intent, token, transport);
    phase = 'confirmation';
    const outcome = matching(await lookup(before), publication);
    return { outcome, publication, dispatched: true };
  } catch (error) { throw errorFor(error, phase, dispatched, publication); }
}
export async function submitPull(intent, token, options = {}) { return operate(intent, token, options, true); }
export async function recoverPull(intent, token, options = {}) { return operate(intent, token, options, false); }
