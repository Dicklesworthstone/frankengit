// One explicitly requested send, or original-key reads only. No redirects,
// ambient authentication, automatic resend, Git subprocess or native seal.
import { request as httpRequest } from 'node:http';
import { request as httpsRequest } from 'node:https';
import { lookupOutcome, validateOutcomeReply } from './transaction_outcome.mjs';
import { BRANCH_LIMITS, BranchTransactionError, fail, fields, hash, credential, binding,
  parse, publication, validateBranchIntent, matchObservation } from './branch_transaction.mjs';

function options(value, sending) {
  fields(value, ['signal', 'timeoutMs', 'ca', 'known', 'publication', ...(sending ? ['confirmKey', 'outcomeToken'] : [])], []);
  const timeoutMs = value.timeoutMs ?? 30000;
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 300000 ||
      value.signal !== undefined && !(value.signal instanceof AbortSignal)) fail('branch_transaction_options');
  const ca = value.ca === undefined ? undefined :
    Buffer.isBuffer(value.ca) && value.ca.length && value.ca.length <= 128 * 1024 ? Buffer.from(value.ca) : fail('branch_transaction_ca');
  return { ...value, ca, timeoutMs };
}
function post(intent, token, config) {
  return new Promise((resolve, reject) => {
    let request, response, timer, result, failure, finished = false, closed = false, delivered = false;
    const problem = (code, status = null) => new BranchTransactionError(code, { status });
    const deliver = () => { if (delivered) return; delivered = true; failure ? reject(failure) : resolve(result); };
    const finish = (error, value) => {
      if (finished) return; finished = true; failure = error; result = value;
      clearTimeout(timer); config.signal?.removeEventListener('abort', abort); response?.destroy(); request?.destroy();
      if (!request || closed) deliver();
    };
    const abort = () => finish(problem('branch_transaction_cancelled'));
    try {
      const url = new URL(intent.endpoint + '/api/v1/source/branches/transaction');
      request = (url.protocol === 'https:' ? httpsRequest : httpRequest)(url, { method: 'POST', agent: false,
        rejectUnauthorized: true, maxHeaderSize: 16384, ...(config.ca ? { ca: config.ca } : {}), headers: {
          Authorization: 'Bearer ' + token, 'Idempotency-Key': intent.key,
          'User-Agent': 'frankengit-agent (+https://github.com/Dicklesworthstone/frankengit)',
          'Content-Type': 'application/x-www-form-urlencoded', 'Content-Length': String(Buffer.byteLength(intent.body)),
          Accept: 'application/json', 'Accept-Encoding': 'identity', 'Cache-Control': 'no-store', Connection: 'close',
        } });
      request.once('close', () => { closed = true; if (!finished) finish(problem('branch_transaction_response_incomplete')); else deliver(); });
      request.on('error', () => finish(problem('branch_transaction_transport')));
      request.once('response', incoming => {
        response = incoming;
        if (![200, 409].includes(incoming.statusCode)) { finish(problem('branch_transaction_http_refused', incoming.statusCode)); return; }
        const names = incoming.rawHeaders.filter((_, i) => i % 2 === 0).map(n => n.toLowerCase())
          .filter(n => ['content-type', 'content-length', 'content-encoding'].includes(n));
        const length = incoming.headers['content-length'];
        if (new Set(names).size !== names.length || !/^application\/json(?:\s*;|$)/i.test(incoming.headers['content-type'] ?? '') ||
            (incoming.headers['content-encoding'] ?? 'identity').toLowerCase() !== 'identity') {
          finish(problem('branch_transaction_response_encoding')); return;
        }
        if (length !== undefined && (!/^(0|[1-9][0-9]*)$/.test(length) || BigInt(length) > BigInt(BRANCH_LIMITS.reply))) {
          finish(problem('branch_transaction_response_limit')); return;
        }
        const chunks = []; let size = 0;
        incoming.on('error', () => finish(problem('branch_transaction_response_incomplete')));
        incoming.on('data', chunk => {
          if (finished) return; size += chunk.length;
          if (size > BRANCH_LIMITS.reply || chunks.length >= 16384) finish(problem('branch_transaction_response_limit'));
          else chunks.push(chunk);
        });
        incoming.once('end', () => {
          if (finished) return;
          if (!incoming.complete || length !== undefined && BigInt(length) !== BigInt(size)) {
            finish(problem('branch_transaction_response_incomplete')); return;
          }
          try { finish(null, publication(parse(Buffer.concat(chunks, size), true, BRANCH_LIMITS.reply), intent, incoming.statusCode)); }
          catch (error) { finish(error); }
        });
      });
      config.signal?.addEventListener('abort', abort, { once: true });
      timer = setTimeout(() => finish(problem('branch_transaction_timeout')), config.timeoutMs);
      if (config.signal?.aborted) abort(); else request.end(intent.body);
    } catch { finish(problem('branch_transaction_transport')); }
  });
}
async function operate(input, token, supplied, send) {
  // Normalize and detach all caller inputs before any asynchronous operation.
  const intent = validateBranchIntent(input), config = options(supplied, send);
  credential(token, send);
  if (send && (config.confirmKey !== intent.key || hash(token) !== intent.credential_sha256)) fail('branch_transaction_original_key_and_credential_required');
  if (config.outcomeToken !== undefined && intent.bind_writer_scope !== true) fail('branch_transaction_writer_scope_required');
  const outcomeToken = config.outcomeToken === undefined ? token : credential(config.outcomeToken);
  const scope = binding(intent.scope), deadline = performance.now() + config.timeoutMs;
  let outcome = config.known == null ? null : validateOutcomeReply(config.known, scope);
  let receipt = config.publication == null ? null : publication(config.publication, intent, config.publication.outcome === 'committed' ? 200 : 409);
  matchObservation(outcome, receipt);
  const remaining = () => {
    if (config.signal?.aborted) fail('branch_transaction_cancelled');
    const timeoutMs = Math.ceil(deadline - performance.now());
    if (timeoutMs < 1) fail('branch_transaction_timeout');
    return { timeoutMs, signal: config.signal, ca: config.ca };
  };
  const lookup = () => lookupOutcome(intent.endpoint, outcomeToken, { ...scope, key: intent.key }, { ...remaining(), known: outcome });
  let phase = 'preflight', dispatched = false;
  try {
    // A contradictory new observation must not replace compatible retained
    // evidence; the CLI still needs to save any already validated publication.
    const before = await lookup(); matchObservation(before, receipt); outcome = before;
    if (!send || outcome.terminal || receipt !== null) return { outcome, publication: receipt, dispatched: false };
    phase = 'publication'; const network = remaining(); dispatched = true;
    const published = await post(intent, token, network); matchObservation(outcome, published); receipt = published;
    phase = 'confirmation';
    const confirmed = await lookup(); matchObservation(confirmed, receipt); outcome = confirmed;
    return { outcome, publication: receipt, dispatched };
  } catch (error) {
    throw new BranchTransactionError(typeof error.code === 'string' && /^[a-z_]{1,128}$/.test(error.code) ? error.code : 'branch_transaction_unavailable',
      { phase, dispatched, publication: receipt, outcome, status: error.status ?? null });
  }
}
export async function sendBranchTransaction(intent, token, options = {}) { return operate(intent, token, options, true); }
export async function recoverBranchTransaction(intent, token, options = {}) { return operate(intent, token, options, false); }
