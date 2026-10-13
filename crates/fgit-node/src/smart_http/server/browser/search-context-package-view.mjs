// Explicit selected-source acquisition and local replay. No package supplies its
// own trust anchor, query, authority, credentials, or executable presentation.
import { copy, hex, integer, unhex, utf8 } from './pulls-core.mjs';
import { MEMBERSHIP_LIMITS } from './search-context-membership.mjs';
import { SOURCE_PACKAGE_BYTES, SOURCE_PACKAGE_LIMITS, sourcePackageLimits,
  contextPackageCost, readSourcePackage, encodeSourcePackage } from './search-context-package.mjs';

export function mountContextPackage(document, result, { acquire, run, current, idle, cancelRead,
  display, cryptoImpl = globalThis.crypto, urlApi = globalThis.URL, timeoutMs = 30000 }) {
  integer(timeoutMs, 'package deadline', 1, 300000);
  // This view receives the client's validated result, not an imported package.
  // Capture its exact selection now; do not keep caller-owned arrays over awaits.
  const basis = copy({ query: { mode: result.query.mode, maxFileBytes: result.query.maxFileBytes },
    scope: { format: result.scope.format }, pin: { commit: result.pin.commit },
    context: { files: result.context.files.map(({ pathHex, blob, sourceBytes }) => ({ pathHex, blob, sourceBytes })) } });
  const node = (tag, text = '') => { const el = document.createElement(tag); el.textContent = text; return el; };
  const section = node('section'); section.id = 'context-package';
  section.append(node('h3', 'Save complete selected source for offline verification'),
    node('p', 'Package the selected full file bodies together with the original commit and complete needed parent trees. An independently obtained commit ID is required. This is not a repository backup, authority receipt, freshness claim, search-completeness proof or permission to execute source.'),
    node('p', 'Acquire performs additional pinned reads, including private full source bodies, commit messages and sibling tree names. No unrelated subtree bodies are read. Nothing is fetched, downloaded, extracted or executed automatically.'));
  const field = (id, label, value, type = 'text') => {
    const wrapper = node('label', label), el = node('input'); el.id = `context-package-${id}`; el.type = type;
    el.value = value; el.autocomplete = 'off'; el.spellcheck = false; wrapper.append(el); section.append(wrapper); return el;
  };
  const commit = field('commit', 'Independently obtained commit ID — never filled by this page or a package', ''); commit.maxLength = 71;
  const sourceBytes = basis.context.files.reduce((n, file) => n + file.sourceBytes, 0);
  const requests = basis.context.files.reduce((n, file) => n + Math.max(1, Math.ceil(file.sourceBytes / 65536)), 0);
  const cost = node('p', `Selected complete source: ${basis.context.files.length} files, ${sourceBytes} logical bytes, ${requests} blob-page requests, plus parent-tree metadata reads. Repeated blob identities still spend a read and logical-byte allowance for each selected path.`);
  cost.id = 'context-package-cost'; section.append(cost);
  const labels = { maxSourceBytes: 'Maximum complete source bytes', maxBlobRequests: 'Maximum blob-page requests',
    maxRequests: 'Maximum metadata requests', maxTrees: 'Maximum parent trees', maxEntries: 'Maximum parent-tree entries', maxTreeBytes: 'Maximum parent-tree bytes' };
  const bounds = { ...SOURCE_PACKAGE_LIMITS, ...MEMBERSHIP_LIMITS };
  const budgets = Object.fromEntries(Object.entries(bounds).map(([name, max]) => {
    const initial = name === 'maxSourceBytes' ? Math.min(max, Math.max(1, sourceBytes))
      : name === 'maxBlobRequests' ? Math.min(max, Math.max(1, requests)) : max;
    const el = field(name, labels[name], String(initial), 'number'); el.min = '1'; el.max = String(max); el.step = '1'; return [name, el];
  }));
  const consent = field('consent', 'I independently selected this commit and, for Acquire, authorize these additional complete-source and parent-tree reads.', '', 'checkbox');
  const button = (id, label) => { const el = node('button', label); el.type = 'button'; el.id = `context-package-${id}`; section.append(el); return el; };
  const submit = button('acquire', 'Acquire and verify complete selected-source package');
  const file = field('file', 'Or select one saved source package, up to 32 MiB', '', 'file'); file.accept = 'application/json,.json';
  const inspect = button('inspect', 'Verify saved source package locally — no network');
  const download = button('download', 'Download verified selected-source package');
  const selectionDownload = button('selection-download', 'Download retained verification selection');
  section.append(node('p', 'Keep the verification selection independently of the package. It contains the commit you supplied and the retained selected path/blob identities, not pins copied from imported evidence. Offline CLI verification uses both files. A saved package contains private source material; protect it accordingly.'));
  const status = node('p'); status.id = 'context-package-status'; status.setAttribute('role', 'status'); status.setAttribute('aria-live', 'polite');
  const output = node('pre'); output.id = 'context-package-result'; section.append(status, output);
  let generation = 0, working = false, disposed = false, active = null, chosen = null;
  const urls = new Map();
  const signature = () => JSON.stringify([commit.value, ...Object.values(budgets).map(el => el.value)]);
  const revoke = () => { for (const url of urls.values()) urlApi.revokeObjectURL(url); urls.clear(); };
  function sync() {
    const enabled = !disposed && current() && idle() && !working, hasFiles = basis.context.files.length > 0;
    for (const el of [commit, ...Object.values(budgets), consent, file]) el.disabled = !enabled || !hasFiles;
    submit.disabled = inspect.disabled = !enabled || !hasFiles || !consent.checked || commit.value === '';
    download.disabled = selectionDownload.disabled = !enabled || chosen === null || chosen.signature !== signature();
  }
  function invalidate() {
    generation++; active?.abort(); active = null; working = false; chosen = null; consent.checked = false; revoke(); output.textContent = '';
    status.textContent = 'No complete source package is selected. Supply and confirm an independent commit before acquiring or checking one.'; sync();
  }
  const changed = () => { if (working) cancelRead(); invalidate(); };
  for (const el of [commit, ...Object.values(budgets), file]) for (const event of ['input', 'change']) el.addEventListener(event, changed);
  consent.addEventListener('change', () => { if (working) changed(); else sync(); });
  function readLimits() {
    const values = Object.fromEntries(Object.entries(budgets).map(([name, el]) => {
      if (!/^[1-9][0-9]{0,8}$/.test(el.value)) throw new Error('Invalid package budget.'); return [name, Number(el.value)];
    }));
    const { maxSourceBytes, maxBlobRequests, ...membership } = values;
    return sourcePackageLimits({ maxSourceBytes, maxBlobRequests, membership });
  }
  async function readFile(selected, size, signal) {
    signal.throwIfAborted(); let abort;
    const canceled = new Promise((resolve, reject) => {
      abort = () => reject(signal.reason ?? new Error('Canceled'));
      signal.addEventListener('abort', abort, { once: true }); if (signal.aborted) abort();
    });
    try {
      const value = await Promise.race([Promise.resolve().then(() => { signal.throwIfAborted(); return selected.arrayBuffer(); }), canceled]);
      signal.throwIfAborted();
      if (!(value instanceof ArrayBuffer) || value.byteLength !== size || selected.size !== size || value.byteLength > SOURCE_PACKAGE_BYTES) throw new Error('Package size changed.');
      return new Uint8Array(value);
    } finally { signal.removeEventListener('abort', abort); }
  }
  async function execute(local) {
    if (disposed || !current() || !idle() || working || !consent.checked || !basis.context.files.length) return;
    const selectedFile = file.files?.[0], count = file.files?.length, size = selectedFile?.size, stamp = signature();
    const serial = ++generation, controller = new AbortController(), deadline = performance.now() + timeoutMs;
    active = controller; working = true; chosen = null; consent.checked = false; revoke(); output.textContent = ''; sync();
    const guard = () => {
      controller.signal.throwIfAborted();
      if (performance.now() >= deadline) throw new Error('Package deadline exceeded.');
      if (disposed || serial !== generation || !current() || signature() !== stamp) throw new Error('Package selection superseded.');
    };
    const timer = setTimeout(() => { controller.abort(new Error('Package deadline exceeded')); cancelRead(); }, timeoutMs);
    try {
      const { expected, limits } = contextPackageCost(basis, commit.value, readLimits());
      if (local && (count !== 1 || !selectedFile || !Number.isSafeInteger(size) || size < 1 || size > SOURCE_PACKAGE_BYTES)) throw new Error('Choose one bounded source package.');
      if (local) file.value = '';
      status.textContent = local ? 'Rechecking the saved package locally. No repository request is made.' : 'Acquiring the selected parent trees and full source bodies at the original snapshot…';
      const answer = await run(async hostCheck => {
        const check = () => { hostCheck(); guard(); }; check();
        let value;
        if (local) {
          const data = await readFile(selectedFile, size, controller.signal); check();
          value = (await readSourcePackage(data, expected, cryptoImpl, check, limits)).package;
        } else { value = (await acquire(expected.commit, limits)).package; check(); }
        // Verify even an acquisition host's returned object. Never trust a saved
        // success flag, serialized sibling, or caller-owned bytes after an await.
        const encoded = await encodeSourcePackage(value, expected, cryptoImpl, check, limits); check();
        if (encoded.verified.files.some((row, i) => row.sourceBytes !== basis.context.files[i].sourceBytes)) throw new Error('Selected source size changed.');
        const sha256 = hex(new Uint8Array(await cryptoImpl.subtle.digest('SHA-256', utf8.encode(encoded.serialized)))); check();
        return { serialized: encoded.serialized, verified: encoded.verified, expected, sha256 };
      });
      guard(); chosen = { ...answer, signature: stamp };
      const verified = answer.verified;
      output.textContent = `Commit ${verified.commit}\nRoot tree ${verified.rootTree}\nPackage SHA-256 ${answer.sha256}\n` +
        `${verified.files.length} complete selected files; ${verified.logicalSourceBytes} logical bytes; ${verified.uniqueSourceBytes} unique blob bytes.\n` +
        verified.files.map(row => `${display(unhex(row.pathHex, 4096))}: ${row.kind} ${row.blob} (${row.sourceBytes} bytes)`).join('\n');
      status.textContent = 'Complete selected source and path/mode/blob membership verified under the independently supplied commit. Download explicitly below. Current authority, freshness, signatures and search coverage remain unverified.';
    } catch {
      if (!disposed && serial === generation) { chosen = null; output.textContent = ''; status.textContent = 'Source package acquisition or verification failed or was canceled. No successful subset, replacement root or automatic retry was selected.'; }
    } finally {
      clearTimeout(timer); if (active === controller) active = null; if (serial === generation) working = false; sync();
    }
  }
  submit.addEventListener('click', event => { event.preventDefault(); return execute(false); });
  inspect.addEventListener('click', event => { event.preventDefault(); return execute(true); });
  function exportFile(selectionOnly) {
    if (disposed || !current() || !idle() || working || !chosen || chosen.signature !== signature()) return;
    const name = selectionOnly ? 'frankengit-source-selection.json' : 'frankengit-selected-source.json'; let anchor;
    try {
      if (urls.has(name)) { urlApi.revokeObjectURL(urls.get(name)); urls.delete(name); }
      const url = urlApi.createObjectURL(new Blob([selectionOnly ? JSON.stringify(chosen.expected) : chosen.serialized], { type: 'application/json' })); urls.set(name, url);
      anchor = node('a'); anchor.href = url; anchor.download = name; section.append(anchor); anchor.click();
      status.textContent = selectionOnly ? 'Retained root and selected file identities exported separately. Keep them independently of untrusted package replacements.'
        : 'Private complete-source package exported without ambient credentials. Retain its SHA-256 and separate verification selection; no source was extracted, executed or published.';
    } catch { revoke(); status.textContent = 'Package export failed. The original source was not changed and no network request was made.'; }
    finally { anchor?.remove(); }
  }
  download.addEventListener('click', event => { event.preventDefault(); exportFile(false); });
  selectionDownload.addEventListener('click', event => { event.preventDefault(); exportFile(true); });
  invalidate();
  return { element: section, submit, inspect, download, selectionDownload, sync, invalidate,
    dispose() { const wasWorking = working; disposed = true; if (wasWorking) cancelRead(); invalidate(); commit.value = ''; file.value = ''; } };
}
