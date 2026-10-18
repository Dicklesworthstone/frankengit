// Closed native source-change transport. Preparation is not publication.
import { request as http } from 'node:http';
import { request as https } from 'node:https';
import { createHash } from 'node:crypto';
export const hash = bytes => createHash('sha256').update(bytes).digest('hex');
export class SourceEditError extends Error {
  constructor(code, status = null) { super(code); this.name = 'SourceEditError'; this.code = code; this.status = status; }
}
export const fail = code => { throw new SourceEditError(code); };
export function fields(value, names, required = names) {
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
      Object.keys(value).some(k => !names.includes(k)) || required.some(k => !Object.hasOwn(value, k))) fail('source_edit_fields');
  return value;
}
export function integer(n, minimum, maximum) {
  if (!Number.isSafeInteger(n) || n < minimum || n > maximum) fail('source_edit_counter');
  return n;
}
export function endpoint(value) {
  if (typeof value !== 'string' || value.length > 4096 || /[\s\\]/u.test(value)) fail('source_edit_endpoint');
  let url; try { url = new URL(value); } catch { fail('source_edit_endpoint'); }
  if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password || url.search || url.hash || url.href !== value ||
      (url.protocol === 'http:' && !['127.0.0.1', '[::1]'].includes(url.hostname)) ||
      !/^\/(?:[A-Za-z0-9._~-]+\/)*[A-Za-z0-9._~-]+$/.test(url.pathname) ||
      url.pathname.split('/').some(p => p === '.' || p === '..')) fail('source_edit_endpoint');
  return value;
}
// Walk the actual JSON grammar before JSON.parse to reject duplicate keys,
// excessive nesting and ambiguous numeric spelling. No server text in errors.
export function parse(bytes, maximum) {
  if (!Buffer.isBuffer(bytes) || bytes.length > maximum) fail('source_edit_response_limit');
  try {
    const s = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes);
    let at = 0, nodes = 0;
    const white = () => { while (/[ \t\r\n]/.test(s[at] ?? 'x')) at++; };
    const string = () => {
      const start = at++;
      while (at < s.length) { const c = s[at++]; if (c === '\\') at++; else if (c === '"') return JSON.parse(s.slice(start, at)); }
      fail('source_edit_json');
    };
    const value = depth => {
      white(); if (depth > 32 || ++nodes > 200000) fail('source_edit_json_limit');
      const c = s[at];
      if (c === '"') { string(); return; }
      if (c === '{' || c === '[') {
        const object = c === '{', close = object ? '}' : ']', names = new Set(); at++; white();
        if (s[at] === close) { at++; return; }
        while (true) {
          if (object) { white(); if (s[at] !== '"') fail('source_edit_json'); const k = string();
            if (names.has(k)) fail('source_edit_json_duplicate'); names.add(k); white(); if (s[at++] !== ':') fail('source_edit_json'); }
          value(depth + 1); white(); const end = s[at++]; if (end === close) return;
          if (end !== ',') fail('source_edit_json');
        }
      }
      const token = /^(?:true|false|null|0|[1-9][0-9]*)/.exec(s.slice(at));
      if (!token) fail('source_edit_json'); at += token[0].length;
    };
    value(0); white(); if (at !== s.length) fail('source_edit_json');
    return JSON.parse(s, (key, v, context) => {
      if (typeof v !== 'number') return v;
      if (key === 'decision_sequence') {
        if (BigInt(context.source) < 1n || BigInt(context.source) > 18446744073709551615n) fail('source_edit_sequence');
        return context.source;
      }
      return integer(v, 0, Number.MAX_SAFE_INTEGER);
    });
  } catch (error) { if (error instanceof SourceEditError) throw error; fail('source_edit_json'); }
}
export function clock(options = {}) {
  fields(options, ['signal', 'timeoutMs', 'ca', 'maxWireBytes'], []);
  const timeout = integer(options.timeoutMs ?? 30000, 1, 300000), signal = options.signal;
  if (signal !== undefined && !(signal instanceof AbortSignal)) fail('source_edit_signal');
  if (options.ca !== undefined && (!Buffer.isBuffer(options.ca) || !options.ca.length || options.ca.length > 131072)) fail('source_edit_ca');
  const ca = options.ca === undefined ? undefined : Buffer.from(options.ca), deadline = performance.now() + timeout;
  const check = () => { if (signal?.aborted) fail('source_edit_cancelled'); if (performance.now() >= deadline) fail('source_edit_timeout'); };
  return { signal, ca, check, remaining: () => { check(); return Math.max(1, Math.ceil(deadline - performance.now())); },
    maxWireBytes: integer(options.maxWireBytes ?? 18 * 1024 * 1024, 1, 18 * 1024 * 1024) };
}
export function upload(command, payload, kind) {
  if (!['patch', 'bundle'].includes(kind) || !Buffer.isBuffer(payload) || !payload.length || payload.length > (kind === 'patch' ? 1048576 : 8388608)) fail('source_edit_upload');
  const body = new URLSearchParams(command).toString();
  if (body.length > 262144) fail('source_edit_form_limit');
  for (let attempt = 0; attempt < 16; attempt++) {
    const boundary = `fg-source-client-${hash(payload).slice(0, 40)}-${attempt.toString(16)}`, marker = `--${boundary}`;
    if (body.includes(marker) || payload.includes(Buffer.from(marker))) continue;
    const bytes = Buffer.concat([Buffer.from(`${marker}\r\nContent-Disposition: form-data; name="command"\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\n${body}\r\n${marker}\r\nContent-Disposition: form-data; name="${kind}"\r\nContent-Type: ${kind === 'patch' ? 'application/octet-stream' : 'application/x-git-bundle'}\r\n\r\n`), payload, Buffer.from(`\r\n${marker}--\r\n`)]);
    return { bytes, contentType: `multipart/form-data; boundary=${boundary}` };
  }
  fail('source_edit_boundary_collision');
}
// One socket, no redirects/retries/ambient credentials. An apply call is only
// exposed to the durable owner, which records responsibility before entering.
export async function exchange(address, credential, operation, body, time, maximum, key = null) {
  endpoint(address); time.check(); integer(maximum, 1, 18 * 1024 * 1024);
  if (typeof credential !== 'string' || !/^[0-9a-f]{64}$/.test(credential)) fail('source_edit_credential');
  if (!['prepare', 'inspect', 'apply', 'outcomes'].includes(operation) ||
      (['apply', 'outcomes'].includes(operation) ? typeof key !== 'string' || !/^[\x21-\x7e]{1,256}$/.test(key) : key !== null) ||
      (operation === 'outcomes' ? body !== null : !body || !Buffer.isBuffer(body.bytes))) fail('source_edit_operation');
  const url = new URL(`${address}/api/v1/${operation === 'outcomes' ? 'outcomes' : `source/${operation}`}`);
  return new Promise((resolve, reject) => {
    let req, res, done = false, closed = false, result, failure, timer;
    const deliver = () => failure ? reject(failure) : resolve(result);
    const finish = (error, value) => {
      if (done) return; done = true; failure = error; result = value;
      clearTimeout(timer); time.signal?.removeEventListener('abort', abort); res?.destroy(); req?.destroy();
      if (closed || !req) deliver();
    };
    const abort = () => finish(new SourceEditError('source_edit_cancelled'));
    try {
      const headers = { Authorization: `Bearer ${credential}`, Accept: operation === 'prepare' ? 'multipart/mixed' : 'application/json',
        'Accept-Encoding': 'identity', 'Cache-Control': 'no-store', Connection: 'close', 'Content-Length': String(body?.bytes.length ?? 0) };
      if (body) headers['Content-Type'] = body.contentType;
      if (key !== null) headers['Idempotency-Key'] = key;
      req = (url.protocol === 'https:' ? https : http)(url, { method: 'POST', headers, agent: false, maxHeaderSize: 16384,
        rejectUnauthorized: true, ...(time.ca ? { ca: time.ca } : {}) });
      req.on('error', () => finish(new SourceEditError('source_edit_transport')));
      req.once('close', () => { closed = true; if (!done) finish(new SourceEditError('source_edit_incomplete')); else deliver(); });
      req.once('response', incoming => {
        res = incoming;
        if (res.statusCode !== 200 && !(operation === 'apply' && res.statusCode === 409)) { finish(new SourceEditError('source_edit_http', res.statusCode)); return; }
        const names = res.rawHeaders.filter((_, i) => i % 2 === 0).map(n => n.toLowerCase()).filter(n => ['content-type', 'content-length', 'content-encoding'].includes(n));
        const length = res.headers['content-length'], type = res.headers['content-type'] ?? '';
        if (names.length !== new Set(names).size || (res.headers['content-encoding'] ?? 'identity').toLowerCase() !== 'identity' ||
            (operation === 'prepare' ? !/^multipart\/mixed; boundary=/.test(type) : !/^application\/json(?:;|$)/i.test(type)) ||
            length !== undefined && (!/^(0|[1-9][0-9]*)$/.test(length) || BigInt(length) > BigInt(maximum))) { finish(new SourceEditError('source_edit_framing')); return; }
        const chunks = []; let size = 0;
        res.on('error', () => finish(new SourceEditError('source_edit_incomplete')));
        res.on('data', b => { if (done) return; size += b.length;
          if (size > maximum || chunks.length >= 16384) finish(new SourceEditError('source_edit_response_limit')); else chunks.push(b); });
        res.once('end', () => {
          if (!res.complete || length !== undefined && BigInt(length) !== BigInt(size)) finish(new SourceEditError('source_edit_incomplete'));
          else finish(null, { status: res.statusCode, type, bytes: Buffer.concat(chunks, size) });
        });
      });
      timer = setTimeout(() => finish(new SourceEditError('source_edit_timeout')), time.remaining());
      time.signal?.addEventListener('abort', abort, { once: true });
      if (time.signal?.aborted) abort(); else req.end(body?.bytes);
    } catch { finish(new SourceEditError('source_edit_transport')); }
  });
}
