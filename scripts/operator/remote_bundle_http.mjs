// Bounded multipart transport only. Native Git validation is exclusively remote.
import { request as httpRequest } from 'node:http';
import { request as httpsRequest } from 'node:https';
import { BUNDLE_REMOTE_LIMITS as L, multipart, parse, publication } from './remote_bundle_protocol.mjs';

export function postBundle(request, payload, token, { timeoutMs, signal, ca }) {
  const { parts, contentType } = multipart(request, payload);
  return new Promise((resolve, reject) => {
    let req, res, timer, result, error, finished = false, closed = false, delivered = false;
    const problem = code => Object.assign(new Error(`remote_bundle_${code}`), { code: `remote_bundle_${code}` });
    const deliver = () => { if (delivered) return; delivered = true; error ? reject(error) : resolve(result); };
    const finish = (failure, value) => {
      if (finished) return; finished = true; error = failure; result = value;
      clearTimeout(timer); signal?.removeEventListener('abort', abort);
      res?.destroy(); req?.destroy(); if (!req || closed) deliver();
    };
    const abort = () => finish(problem('cancelled'));
    if (signal?.aborted) { abort(); return; }
    try {
      const url = new URL(`${request.selection.endpoint}/api/v1/source/bundle/${request.selection.operation}`);
      req = (url.protocol === 'https:' ? httpsRequest : httpRequest)(url, {
        method: 'POST', agent: false, rejectUnauthorized: true, maxHeaderSize: 16384, ...(ca ? { ca } : {}),
        headers: { Authorization: `Bearer ${token}`, 'Idempotency-Key': request.key, Accept: 'application/json',
          'Content-Type': contentType, 'Content-Length': String(parts.reduce((n, p) => n + p.length, 0)),
          'Accept-Encoding': 'identity', Connection: 'close', 'Cache-Control': 'no-store' },
      });
      req.once('close', () => { closed = true; if (!finished) finish(problem('response_incomplete')); else deliver(); });
      req.on('error', () => finish(problem('transport')));
      req.once('response', incoming => {
        res = incoming;
        if (![200, 409].includes(res.statusCode)) { finish(problem('http_refused')); return; }
        const names = res.rawHeaders.filter((_, i) => i % 2 === 0).map(k => k.toLowerCase())
          .filter(k => ['content-type', 'content-length', 'content-encoding'].includes(k));
        const length = res.headers['content-length'];
        if (new Set(names).size !== names.length || !/^application\/json(?:\s*;|$)/i.test(res.headers['content-type'] ?? '') ||
            (res.headers['content-encoding'] ?? 'identity').toLowerCase() !== 'identity') { finish(problem('response_encoding')); return; }
        if (length !== undefined && (!/^(0|[1-9][0-9]*)$/.test(length) || BigInt(length) > BigInt(L.reply))) { finish(problem('response_limit')); return; }
        const chunks = []; let size = 0;
        res.on('error', () => finish(problem('response_incomplete')));
        res.on('data', chunk => {
          if (finished) return; size += chunk.length;
          if (size > L.reply || chunks.length >= L.reply) finish(problem('response_limit')); else chunks.push(chunk);
        });
        res.once('end', () => {
          if (finished) return;
          if (!res.complete || length !== undefined && BigInt(length) !== BigInt(size)) { finish(problem('response_incomplete')); return; }
          try { finish(null, publication(parse(Buffer.concat(chunks, size), L.reply, true), request, res.statusCode)); }
          catch (e) { finish(e); }
        });
      });
      signal?.addEventListener('abort', abort, { once: true });
      timer = setTimeout(() => finish(problem('timeout')), timeoutMs);
      if (signal?.aborted) abort();
      else { req.write(parts[0]); req.write(parts[1]); req.end(parts[2]); }
    } catch { finish(problem('transport')); }
  });
}
