// External, read-only consumer of the native issues-pulls-v1 event feed.
// The native codec and disclosure policy stay on the server. Frames remain
// opaque; consistency checking is not proof of authority or completeness.
import { createHash } from 'node:crypto';
import { request as httpRequest } from 'node:http';
import { request as httpsRequest } from 'node:https';
import { ACTIVITY_LIMITS, activityCursor, activityPage } from '../../crates/fgit-node/src/smart_http/server/browser/activity.mjs';

export const EVENT_LIMITS = Object.freeze({ response: ACTIVITY_LIMITS.reply, pages: 64,
  bytes: 32 * 1024 * 1024, timeoutMs: 300000, configuration: 8192 });
export class EventFeedError extends Error {
  constructor(code, status = null) { super(code); this.name = 'EventFeedError'; this.code = code; this.status = status; }
}
export const eventFail = code => { throw new EventFeedError(code); };
export const eventHash = bytes => createHash('sha256').update(bytes).digest('hex');
export function eventKeys(value, names, required = names) {
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
      ![Object.prototype, null].includes(Object.getPrototypeOf(value)) ||
      Object.keys(value).some(key => !names.includes(key)) || required.some(key => !Object.hasOwn(value, key)) ||
      Object.values(Object.getOwnPropertyDescriptors(value)).some(d => !Object.hasOwn(d, 'value'))) eventFail('invalid_event_fields');
}
export function eventInteger(value, minimum, maximum) {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) eventFail('invalid_event_bound');
  return value;
}
export function eventCursor(value) {
  try { activityCursor(value); } catch { eventFail('invalid_event_cursor'); }
  return value;
}
export function eventEndpoint(value) {
  if (typeof value !== 'string' || value.length > 4096 || /[\s\\]/u.test(value)) eventFail('invalid_event_endpoint');
  let url; try { url = new URL(value); } catch { eventFail('invalid_event_endpoint'); }
  if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password || url.search || url.hash ||
      url.href !== value || !/^\/(?:[A-Za-z0-9._~-]+\/)*[A-Za-z0-9._~-]+$/.test(url.pathname) ||
      url.pathname.split('/').some(part => ['.', '..'].includes(part)) ||
      (url.protocol === 'http:' && !['127.0.0.1', '[::1]'].includes(url.hostname))) eventFail('invalid_event_endpoint');
  return value;
}
const SCOPE_FIELDS = ['tenant_id', 'repository_id', 'repository_incarnation', 'object_format', 'issues_read', 'pulls_read'];
export function eventConfiguration(value) {
  eventKeys(value, ['type', 'schema_version', 'endpoint', 'scope', 'after', 'page_size']);
  if (value.type !== 'frankengit_event_subscription' || value.schema_version !== 1) eventFail('invalid_event_configuration');
  eventKeys(value.scope, SCOPE_FIELDS);
  for (const name of SCOPE_FIELDS.slice(0, 3)) {
    if (typeof value.scope[name] !== 'string' || !/^[0-9a-f]{32}$/.test(value.scope[name])) eventFail('invalid_event_scope');
  }
  if (!['sha1', 'sha256'].includes(value.scope.object_format) || typeof value.scope.issues_read !== 'boolean' ||
      typeof value.scope.pulls_read !== 'boolean' || (!value.scope.issues_read && !value.scope.pulls_read)) eventFail('invalid_event_scope');
  return Object.freeze({ type: value.type, schema_version: 1, endpoint: eventEndpoint(value.endpoint),
    scope: Object.freeze(Object.fromEntries(SCOPE_FIELDS.map(name => [name, value.scope[name]]))),
    after: eventCursor(value.after), page_size: eventInteger(value.page_size, 1, 100) });
}
export function eventCredential(value) {
  if (typeof value !== 'string' || !/^[0-9a-f]{64}$/.test(value)) eventFail('invalid_event_credential');
  return value;
}
export function eventCredentialBinding(value) {
  return eventHash(`frankengit/event-credential/v1\0${eventCredential(value)}`);
}
export function eventJson(bytes, maximum = EVENT_LIMITS.response) {
  eventInteger(maximum, 1, EVENT_LIMITS.bytes);
  if (!(bytes instanceof Uint8Array) || bytes.length > maximum) eventFail('event_json_limit');
  try {
    const text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes), stack = [];
    let nodes = 0;
    for (let i = 0; i < text.length; i++) {
      if (text[i] === '{' || text[i] === '[') {
        if (++nodes > 100000 || stack.length >= 32) eventFail('event_json_structure_limit');
        stack.push({ type: text[i], keys: new Set() });
      } else if (text[i] === '}' || text[i] === ']') {
        if (stack.pop()?.type !== (text[i] === '}' ? '{' : '[')) eventFail('invalid_event_json');
      } else if (text[i] === '"') {
        const start = i++;
        for (; i < text.length && text[i] !== '"'; i++) if (text[i] === '\\') i++;
        if (i >= text.length || ++nodes > 100000) eventFail('event_json_structure_limit');
        let next = i + 1; while (next < text.length && /[\x20\t\r\n]/.test(text[next])) next++;
        if (text[next] === ':') {
          const current = stack.at(-1), key = JSON.parse(text.slice(start, i + 1));
          if (current?.type !== '{' || current.keys.has(key)) eventFail('duplicate_event_json_key');
          current.keys.add(key);
        }
      }
    }
    if (stack.length) eventFail('invalid_event_json');
    return JSON.parse(text, (_key, value, context) => {
      if (typeof value === 'number' && (!Number.isSafeInteger(value) || !/^(0|[1-9][0-9]*)$/.test(context?.source ?? ''))) eventFail('invalid_event_json_number');
      return value;
    });
  } catch (error) { if (error instanceof EventFeedError) throw error; eventFail('invalid_event_json'); }
}
// A deterministic local envelope, not the native canonical event encoding.
export function eventBytes(value) {
  const order = item => Array.isArray(item) ? item.map(order) : item && typeof item === 'object'
    ? Object.fromEntries(Object.keys(item).sort().map(key => [key, order(item[key])])) : item;
  return Buffer.from(`${JSON.stringify(order(value))}\n`);
}
export function validateEventPage(value, configuration, after = configuration.after) {
  const config = eventConfiguration(configuration);
  try { return activityPage(value, { after: eventCursor(after), limit: config.page_size, previous: config.scope }); }
  catch (error) { if (error instanceof EventFeedError) throw error; eventFail('invalid_event_page_or_scope'); }
}

// One explicit GET. Every completion path closes the socket before resolving;
// no redirects, ambient cookies, automatic retry, proxy environment or mutation.
export async function readEventPage(configuration, credential, options = {}) {
  const config = eventConfiguration(configuration), token = eventCredential(credential);
  eventKeys(options, ['after', 'timeoutMs', 'maximumBytes', 'signal', 'ca'], []);
  const after = eventCursor(options.after ?? config.after);
  const timeout = eventInteger(options.timeoutMs ?? 30000, 1, EVENT_LIMITS.timeoutMs);
  const maximum = eventInteger(options.maximumBytes ?? EVENT_LIMITS.response, 1, EVENT_LIMITS.response);
  const signal = options.signal;
  if (signal !== undefined && !(signal instanceof AbortSignal)) eventFail('invalid_event_signal');
  const ca = options.ca === undefined ? undefined : Buffer.isBuffer(options.ca) && options.ca.length > 0 && options.ca.length <= 128 * 1024
    ? Buffer.from(options.ca) : eventFail('invalid_event_ca');
  if (signal?.aborted) eventFail('event_cancelled');
  const url = new URL(`${config.endpoint}/api/v1/events`);
  url.search = new URLSearchParams({ after, limit: String(config.page_size) }).toString();
  return new Promise((resolve, reject) => {
    let request, response, result, failure, timer, finished = false, closed = false, delivered = false;
    const deliver = () => { if (!delivered) { delivered = true; failure ? reject(failure) : resolve(result); } };
    const finish = (error, value) => {
      if (finished) return;
      finished = true; failure = error; result = value;
      clearTimeout(timer); signal?.removeEventListener('abort', abort);
      response?.destroy(); request?.destroy();
      if (!request || closed) deliver();
    };
    const abort = () => finish(new EventFeedError('event_cancelled'));
    try {
      request = (url.protocol === 'https:' ? httpsRequest : httpRequest)(url, { method: 'GET', agent: false,
        maxHeaderSize: 16384, rejectUnauthorized: true, ...(ca ? { ca } : {}), headers: {
          Authorization: `Bearer ${token}`, Accept: 'application/json', 'Accept-Encoding': 'identity',
          'Cache-Control': 'no-store', Connection: 'close' } });
      request.once('close', () => { closed = true; if (!finished) finish(new EventFeedError('event_response_incomplete')); else deliver(); });
      request.on('error', () => finish(new EventFeedError('event_transport_unavailable')));
      request.once('upgrade', (_incoming, socket) => { socket.destroy(); finish(new EventFeedError('event_http_upgrade_refused')); });
      request.once('response', incoming => {
        response = incoming;
        if (incoming.statusCode !== 200) { finish(new EventFeedError('event_http_refused', incoming.statusCode)); return; }
        const names = incoming.rawHeaders.filter((_, i) => i % 2 === 0).map(name => name.toLowerCase())
          .filter(name => ['content-type', 'content-length', 'content-encoding'].includes(name));
        const type = incoming.headers['content-type'] ?? '', length = incoming.headers['content-length'];
        if (new Set(names).size !== names.length || !/^application\/json(?:\s*;\s*charset=utf-8)?\s*$/i.test(type) ||
            (incoming.headers['content-encoding'] ?? 'identity').toLowerCase() !== 'identity') {
          finish(new EventFeedError('event_response_encoding')); return;
        }
        if (length !== undefined && (!/^(0|[1-9][0-9]*)$/.test(length) || BigInt(length) > BigInt(maximum))) {
          finish(new EventFeedError('event_response_limit')); return;
        }
        const chunks = []; let size = 0;
        incoming.on('error', () => finish(new EventFeedError('event_response_incomplete')));
        incoming.on('data', chunk => {
          if (finished) return;
          size += chunk.length;
          if (size > maximum || chunks.length >= 8192) finish(new EventFeedError('event_response_limit'));
          else chunks.push(chunk);
        });
        incoming.once('end', () => {
          if (finished) return;
          if (!incoming.complete || (length !== undefined && BigInt(length) !== BigInt(size))) {
            finish(new EventFeedError('event_response_incomplete')); return;
          }
          try {
            const page = validateEventPage(eventJson(Buffer.concat(chunks, size), maximum), config, after);
            finish(null, { page, bytes: size });
          } catch (error) { finish(error); }
        });
      });
      signal?.addEventListener('abort', abort, { once: true });
      timer = setTimeout(() => finish(new EventFeedError('event_timeout')), timeout);
      if (signal?.aborted) abort(); else request.end();
    } catch { finish(new EventFeedError('event_transport_unavailable')); }
  });
}

export function validateEventCapture(value, expectedConfiguration) {
  const config = eventConfiguration(expectedConfiguration);
  eventKeys(value, ['type', 'schema_version', 'configuration', 'pages']);
  if (value.type !== 'frankengit_event_capture' || value.schema_version !== 1 ||
      !eventBytes(eventConfiguration(value.configuration)).equals(eventBytes(config)) ||
      !Array.isArray(value.pages) || !value.pages.length || value.pages.length > EVENT_LIMITS.pages) eventFail('invalid_event_capture');
  let after = config.after, bytes = 0;
  const pages = value.pages.map((page, index) => {
    const checked = validateEventPage(page, config, after);
    if (index + 1 < value.pages.length && !checked.has_more) eventFail('event_capture_past_end');
    after = checked.resume_after ?? '0'; bytes += eventBytes(checked).length;
    if (bytes > EVENT_LIMITS.bytes) eventFail('event_capture_limit');
    return checked;
  });
  return { type: value.type, schema_version: 1, configuration: structuredClone(config), pages };
}
export async function captureEventPages(configuration, credential, options = {}) {
  const config = eventConfiguration(configuration); eventCredential(credential);
  eventKeys(options, ['maxPages', 'maxBytes', 'timeoutMs', 'signal', 'ca'], []);
  const maximumPages = eventInteger(options.maxPages ?? 16, 1, EVENT_LIMITS.pages);
  const maximumBytes = eventInteger(options.maxBytes ?? EVENT_LIMITS.bytes, 1, EVENT_LIMITS.bytes);
  const timeout = eventInteger(options.timeoutMs ?? 30000, 1, EVENT_LIMITS.timeoutMs);
  const signal = options.signal;
  if (signal !== undefined && !(signal instanceof AbortSignal)) eventFail('invalid_event_signal');
  const ca = options.ca === undefined ? undefined : Buffer.isBuffer(options.ca) && options.ca.length > 0 && options.ca.length <= 128 * 1024
    ? Buffer.from(options.ca) : eventFail('invalid_event_ca');
  const started = performance.now(), pages = [];
  let after = config.after, bytes = 0;
  for (let i = 0; i < maximumPages; i++) {
    const remaining = Math.floor(timeout - (performance.now() - started));
    if (remaining < 1) eventFail('event_timeout');
    if (bytes === maximumBytes) eventFail('event_capture_limit');
    const received = await readEventPage(config, credential, { after, timeoutMs: remaining,
      maximumBytes: Math.min(EVENT_LIMITS.response, maximumBytes - bytes), signal, ca });
    pages.push(received.page); bytes += received.bytes;
    after = received.page.resume_after ?? '0';
    if (!received.page.has_more) break;
  }
  if (signal?.aborted) eventFail('event_cancelled');
  return validateEventCapture({ type: 'frankengit_event_capture', schema_version: 1, configuration: config, pages }, config);
}
