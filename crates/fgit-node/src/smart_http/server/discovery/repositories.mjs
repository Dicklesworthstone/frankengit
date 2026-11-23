// A public shell. Only an explicit connection reads the credential-filtered API.
export const CATALOG_PATH = '/api/v1/repositories';
export const MAX_RESPONSE_BYTES = 128 * 1024;
const MAX_REPOSITORIES = 64;
const MAX_PATH_BYTES = 512;
const EMPTY = Object.freeze([]);

class DiscoveryFailure extends Error {}

function exactKeys(value, keys) {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
    && Object.keys(value).length === keys.length
    && keys.every(key => Object.hasOwn(value, key));
}

function safePath(path) {
  return typeof path === 'string' && path.length <= MAX_PATH_BYTES
    && path.startsWith('/') && path.slice(1).split('/').every(component =>
      component.length > 0 && component !== '.' && component !== '..'
      && !component.startsWith('-') && /^[A-Za-z0-9._-]+$/.test(component));
}

/** Validate the complete response before creating any repository link. */
export function validateCatalog(value) {
  const invalid = () => { throw new DiscoveryFailure('The server returned an invalid repository catalog.'); };
  if (!exactKeys(value, ['type', 'schema_version', 'complete', 'repositories'])
      || value.type !== 'repository_catalog' || value.schema_version !== 1
      || value.complete !== true || !Array.isArray(value.repositories)
      || value.repositories.length < 1 || value.repositories.length > MAX_REPOSITORIES) invalid();
  let previous = null;
  const repositories = value.repositories.map(entry => {
    if (!exactKeys(entry, ['path', 'source_url']) || !safePath(entry.path)
        || (previous !== null && entry.path <= previous)
        || (entry.source_url !== null && entry.source_url !== `${entry.path}/ui/`)) invalid();
    previous = entry.path;
    return Object.freeze({path: entry.path, source_url: entry.source_url});
  });
  return Object.freeze(repositories);
}

// Stream cancellation closes local reads immediately, but a producer's cleanup
// promise may never settle. Observe it without extending the request lifetime.
function cancelBody(body) {
  try { if (body) void body.cancel().catch(() => {}); } catch { /* Already retired. */ }
}

function fetchWithAbort(fetcher, options) {
  return new Promise((resolve, reject) => {
    const signal = options.signal;
    let settled = false;
    const fail = error => {
      if (settled) return;
      settled = true;
      signal.removeEventListener('abort', aborted);
      reject(error);
    };
    const aborted = () => fail(new DiscoveryFailure('The connection ended.'));
    signal.addEventListener('abort', aborted, {once: true});
    if (signal.aborted) { aborted(); return; }
    try {
      Promise.resolve(fetcher(CATALOG_PATH, options)).then(response => {
        if (settled || signal.aborted) { cancelBody(response?.body); aborted(); return; }
        settled = true;
        signal.removeEventListener('abort', aborted);
        resolve(response);
      }, fail);
    } catch (error) { fail(error); }
  });
}

async function readCatalog(response, signal, current) {
  const media = response.headers.get('content-type')?.split(';')[0].trim().toLowerCase();
  if (media !== 'application/json' || !response.body) {
    cancelBody(response.body);
    throw new DiscoveryFailure('The server did not return a repository catalog.');
  }
  const length = response.headers.get('content-length');
  // Fetch exposes decoded bytes while retaining the encoded representation's
  // Content-Length. Apply the byte ceiling to the actual decoded stream, and
  // compare the declared length only for identity representations.
  const encoded = (response.headers.get('content-encoding') ?? '').split(',')
    .some(coding => coding.trim() !== '' && coding.trim().toLowerCase() !== 'identity');
  if (length !== null && (!/^(0|[1-9][0-9]*)$/.test(length)
      || (!encoded && BigInt(length) > BigInt(MAX_RESPONSE_BYTES)))) {
    cancelBody(response.body);
    throw new DiscoveryFailure('The repository catalog exceeds the supported size.');
  }
  const reader = response.body.getReader();
  const cancel = () => cancelBody(reader);
  signal.addEventListener('abort', cancel, {once: true});
  const parts = [];
  let size = 0;
  try {
    while (true) {
      if (signal.aborted || !current()) throw new DiscoveryFailure('The connection ended.');
      const {done, value} = await reader.read();
      if (signal.aborted || !current()) throw new DiscoveryFailure('The connection ended.');
      if (done) break;
      size += value.byteLength;
      if (size > MAX_RESPONSE_BYTES) {
        throw new DiscoveryFailure('The repository catalog exceeds the supported size.');
      }
      parts.push(value);
    }
  } finally {
    signal.removeEventListener('abort', cancel);
    cancelBody(reader);
    reader.releaseLock();
  }
  if (!encoded && length !== null && BigInt(length) !== BigInt(size)) {
    throw new DiscoveryFailure('The server returned an incomplete repository catalog.');
  }
  const bytes = new Uint8Array(size);
  let offset = 0;
  for (const part of parts) {
    bytes.set(part, offset);
    offset += part.byteLength;
  }
  return validateCatalog(JSON.parse(new TextDecoder('utf-8', {fatal: true}).decode(bytes)));
}

function statusMessage(status) {
  switch (status) {
    case 401: return 'The credential was not accepted. Enter a current operator bearer credential.';
    case 403: return 'This credential has no repository read grant on this server.';
    case 408: return 'The discovery request timed out. Connect again to retry.';
    case 413: return 'The repository catalog exceeds the supported size.';
    case 429: return 'The read request limit was reached. Wait a minute before reconnecting.';
    case 503: return 'The server could not verify its complete repository catalog. Ask the operator to check its configuration.';
    default: return 'The server could not complete repository discovery.';
  }
}

/** An in-memory connection with cancellation and no stale-response publication. */
export class RepositoryDiscovery {
  #fetch;
  #onChange;
  #generation = 0;
  #controller = null;
  #timer = null;
  #timeout;
  #state = Object.freeze({status: 'disconnected', repositories: EMPTY, message: 'Enter a credential, then connect.'});

  constructor({fetch: fetcher = globalThis.fetch.bind(globalThis), onChange = () => {}, timeoutMs = 30_000} = {}) {
    if (typeof fetcher !== 'function' || typeof onChange !== 'function'
        || !Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 300_000) {
      throw new TypeError('Invalid discovery client configuration.');
    }
    this.#fetch = fetcher;
    this.#onChange = onChange;
    this.#timeout = timeoutMs;
  }

  get state() { return this.#state; }

  #publish(status, repositories, message) {
    this.#state = Object.freeze({status, repositories, message});
    this.#onChange(this.#state);
  }

  #cancel() {
    this.#generation += 1;
    this.#controller?.abort();
    this.#controller = null;
    if (this.#timer !== null) clearTimeout(this.#timer);
    this.#timer = null;
  }

  disconnect() {
    this.#cancel();
    this.#publish('disconnected', EMPTY, 'Disconnected. The repository list has been cleared.');
  }

  async connect(token) {
    this.#cancel();
    if (typeof token !== 'string' || !/^[0-9a-f]{64}$/.test(token)) {
      this.#publish('error', EMPTY, 'Enter a 64-character lowercase hexadecimal operator credential.');
      return false;
    }
    const generation = this.#generation;
    const current = () => generation === this.#generation;
    const controller = new AbortController();
    this.#controller = controller;
    this.#publish('connecting', EMPTY, 'Checking your repository read grants…');
    this.#timer = setTimeout(() => {
      if (!current()) return;
      this.#cancel();
      this.#publish('error', EMPTY, 'The discovery request timed out. Connect again to retry.');
    }, this.#timeout);
    try {
      const response = await fetchWithAbort(this.#fetch, {
        method: 'GET',
        headers: {Authorization: `Bearer ${token}`, Accept: 'application/json'},
        credentials: 'omit',
        mode: 'same-origin',
        cache: 'no-store',
        redirect: 'error',
        referrerPolicy: 'no-referrer',
        signal: controller.signal,
      });
      token = null;
      if (!current()) {
        cancelBody(response.body);
        return false;
      }
      if (response.status !== 200 || response.redirected) {
        cancelBody(response.body);
        throw new DiscoveryFailure(statusMessage(response.status));
      }
      const repositories = await readCatalog(response, controller.signal, current);
      if (!current()) return false;
      this.#publish('connected', repositories,
        `${repositories.length} readable ${repositories.length === 1 ? 'repository' : 'repositories'} on this server.`);
      return true;
    } catch (error) {
      controller.abort();
      if (!current()) return false;
      this.#publish('error', EMPTY, error instanceof DiscoveryFailure
        ? error.message : 'The repository catalog could not be verified. Check the connection and try again.');
      return false;
    } finally {
      token = null;
      if (current()) {
        this.#controller = null;
        if (this.#timer !== null) clearTimeout(this.#timer);
        this.#timer = null;
      }
    }
  }
}

export function validatePageLocation(href) {
  let page;
  try { page = new URL(href); } catch { throw new DiscoveryFailure('Open the exact server /ui/ page.'); }
  if (!['http:', 'https:'].includes(page.protocol) || page.pathname !== '/ui/'
      || page.search || page.hash || page.username || page.password) {
    throw new DiscoveryFailure('Open the exact server /ui/ page without a query or fragment.');
  }
  if (page.protocol === 'http:' && !['localhost', '127.0.0.1', '[::1]'].includes(page.hostname)) {
    throw new DiscoveryFailure('Use HTTPS outside loopback before entering a credential.');
  }
  return page.origin;
}

export function mountDiscovery(document, options = {}) {
  const form = document.getElementById('connection-form');
  const token = document.getElementById('credential');
  const disconnect = document.getElementById('disconnect');
  const status = document.getElementById('connection-status');
  const list = document.getElementById('repositories');
  if (!form || !token || !disconnect || !status || !list) throw new Error('The discovery page is incomplete.');
  try { validatePageLocation(options.href ?? document.defaultView?.location?.href); } catch (error) {
    token.value = '';
    token.disabled = true;
    disconnect.disabled = true;
    const connect = document.getElementById('connect');
    if (connect) connect.disabled = true;
    list.replaceChildren();
    status.textContent = error.message;
    status.dataset.status = 'error';
    form.addEventListener('submit', event => event.preventDefault());
    return null;
  }
  const render = state => {
    status.textContent = state.message;
    status.dataset.status = state.status;
    disconnect.disabled = state.status === 'disconnected' || state.status === 'error';
    list.replaceChildren();
    for (const repository of state.repositories) {
      const row = document.createElement('li');
      const path = document.createElement('code');
      path.textContent = repository.path;
      row.append(path);
      if (repository.source_url !== null) {
        const link = document.createElement('a');
        link.href = repository.source_url;
        link.textContent = 'Browse source';
        row.append(link);
      } else {
        const note = document.createElement('span');
        note.textContent = 'Git access';
        row.append(note);
      }
      list.append(row);
    }
  };
  const client = new RepositoryDiscovery({...options, onChange: render});
  render(client.state);
  form.addEventListener('submit', event => {
    event.preventDefault();
    const credential = token.value;
    token.value = '';
    void client.connect(credential);
  });
  disconnect.addEventListener('click', () => {
    token.value = '';
    client.disconnect();
  });
  document.defaultView?.addEventListener('pagehide', () => {
    token.value = '';
    client.disconnect();
  });
  return client;
}

if (typeof document !== 'undefined') mountDiscovery(document);
