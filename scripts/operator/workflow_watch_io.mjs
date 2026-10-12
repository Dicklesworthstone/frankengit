// Trusted-local POSIX custody and child ownership. These files are not forge authority.
import { constants as F } from 'node:fs';
import { lstat, realpath, open, link, unlink, mkdir, rmdir, opendir } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { randomBytes } from 'node:crypto';
import { spawn } from 'node:child_process';

export const fail = message => { throw new Error(message); };
export function absolute(value) {
  if (typeof value !== 'string' || !value || Buffer.byteLength(value) > 4096 ||
      /[\0-\x1f\x7f\uD800-\uDFFF]/u.test(value) || resolve(value) !== value) fail('A normalized absolute local path is required.');
  return value;
}
export function contains(parent, child) { return child === parent || child.startsWith(parent === '/' ? '/' : `${parent}/`); }
export async function directory(path, privateMode = true) {
  absolute(path);
  const stat = await lstat(path);
  if (!stat.isDirectory() || await realpath(path) !== path ||
      (privateMode && (stat.uid !== process.getuid() || (stat.mode & 0o777) !== 0o700))) {
    fail('Custody directories must be owner-private 0700 directories without symlink aliases.');
  }
  return stat;
}
export async function syncDirectory(path) {
  const handle = await open(path, F.O_RDONLY | F.O_DIRECTORY | F.O_NOFOLLOW);
  try { await handle.sync(); } finally { await handle.close(); }
}
export async function readPrivate(path, maximum, optional = false) {
  absolute(path);
  let handle;
  try {
    handle = await open(path, F.O_RDONLY | F.O_NOFOLLOW | F.O_NONBLOCK);
  } catch (error) { if (optional && error.code === 'ENOENT') return null; throw error; }
  try {
    const before = await handle.stat();
    if (!before.isFile() || before.uid !== process.getuid() || (before.mode & 0o077) !== 0 ||
        before.nlink !== 1 || before.size > maximum) fail('Expected a bounded private regular custody file.');
    const bytes = Buffer.alloc(Math.min(maximum + 1, before.size + 1));
    let size = 0;
    while (size < bytes.length) {
      const part = await handle.read(bytes, size, bytes.length - size, size);
      if (!part.bytesRead) break;
      size += part.bytesRead;
    }
    const after = await handle.stat(), selected = await lstat(path);
    if (size !== before.size || before.size !== after.size || before.mtimeMs !== after.mtimeMs ||
        before.ctimeMs !== after.ctimeMs || selected.dev !== before.dev || selected.ino !== before.ino) {
      fail('Custody file changed while reading.');
    }
    return bytes.subarray(0, size);
  } finally { await handle.close(); }
}
export function parseJson(bytes, maximum = 128 * 1024) {
  if (!Buffer.isBuffer(bytes) || bytes.length > maximum) fail('JSON input exceeds its byte limit.');
  const text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes);
  return JSON.parse(text, (_key, value) => {
    if (typeof value === 'number' && !Number.isSafeInteger(value)) fail('Inexact JSON counters are not supported.');
    return value;
  });
}
// Create-only atomic visibility. A failure after linking does not mean absence.
export async function writeNew(path, bytes) {
  if (!Buffer.isBuffer(bytes)) bytes = Buffer.from(bytes);
  const parent = dirname(absolute(path));
  await directory(parent);
  const temporary = `${path}.writing-${randomBytes(16).toString('hex')}`;
  const handle = await open(temporary, F.O_CREAT | F.O_EXCL | F.O_WRONLY | F.O_NOFOLLOW, 0o600);
  try {
    await handle.writeFile(bytes); await handle.sync();
    await link(temporary, path);
  } finally {
    await handle.close();
    await unlink(temporary);
    await syncDirectory(parent);
  }
}
export async function names(path, maximum) {
  const result = [], dir = await opendir(path);
  try {
    for await (const entry of dir) {
      if (result.length >= maximum) fail('Watcher custody capacity exceeded; no history is evicted.');
      result.push(entry.name);
    }
  } finally { if (dir) await dir.close().catch(error => { if (error.code !== 'ERR_DIR_CLOSED') throw error; }); }
  return result.sort();
}
export async function lock(path) {
  await directory(dirname(path));
  await mkdir(path, { mode: 0o700 });
  await syncDirectory(dirname(path));
  const identity = await lstat(path);
  return async () => {
    const current = await lstat(path);
    if (current.dev !== identity.dev || current.ino !== identity.ino || !current.isDirectory()) fail('Watcher owner lock changed.');
    await rmdir(path); await syncDirectory(dirname(path));
  };
}
export async function executable(path) {
  absolute(path);
  const stat = await lstat(path);
  if (!stat.isFile() || await realpath(path) !== path || (stat.mode & 0o022) !== 0 ||
      (stat.mode & 0o111) === 0 || ![0, process.getuid()].includes(stat.uid)) fail('Select an owner-controlled native executable without aliases.');
}

// Native dispatch already owns its 600-second deadline and trusted step cleanup.
// A stop request drains it rather than killing its owner underneath those steps.
// The outer watchdog is a last resort, NEVER proof of descendant containment.
export function runNative(fg, args, { signal, timeoutMs = 660_000, maximum = 40 * 1024 * 1024, drain = false } = {}) {
  signal?.throwIfAborted();
  return new Promise((resolveResult, reject) => {
    let child;
    try { child = spawn(fg, args, { shell: false, detached: true, stdio: ['ignore', 'pipe', 'pipe'],
      env: { PATH: '/usr/bin:/bin', LANG: 'C.UTF-8', LC_ALL: 'C.UTF-8', TZ: 'UTC' } }); }
    catch (error) { reject(error); return; }
    const chunks = [], diagnostics = []; let size = 0, diagnosticSize = 0, forced = false, reason = null;
    let killTimer, closeTimer, settled = false, spawnError = null;
    const kill = name => { if (child.pid) { try { process.kill(-child.pid, name); } catch (error) { if (error.code !== 'ESRCH') spawnError ??= error; } } };
    const force = detail => {
      if (forced) return;
      forced = true; reason = detail; kill('SIGTERM');
      killTimer = setTimeout(() => kill('SIGKILL'), 250);
      closeTimer = setTimeout(() => { child.stdout.destroy(); child.stderr.destroy(); finish(null, 'containment_unknown'); }, 1500);
    };
    const abort = () => { if (!drain) force('read_cancelled'); };
    const timer = setTimeout(() => force('native_deadline_exceeded'), timeoutMs);
    signal?.addEventListener('abort', abort, { once: true });
    if (signal?.aborted) abort();
    child.stdout.on('data', bytes => {
      size += bytes.length;
      if (size > maximum) force('native_output_limit');
      else chunks.push(bytes);
    });
    child.stderr.on('data', bytes => {
      diagnosticSize += bytes.length;
      if (diagnosticSize > 256 * 1024) force('native_diagnostic_limit');
      else diagnostics.push(bytes);
    });
    child.once('error', error => { spawnError = error; });
    child.once('exit', () => {
      // A descendant holding a pipe must not make drain unbounded.
      if (!closeTimer) closeTimer = setTimeout(() => force('native_pipes_not_closed'), 1000);
    });
    child.once('close', (code, termination) => finish(code, termination));
    function finish(code, termination) {
      if (settled) return;
      settled = true;
      clearTimeout(timer); clearTimeout(killTimer); clearTimeout(closeTimer);
      signal?.removeEventListener('abort', abort);
      resolveResult({ code, signal: termination, forced, reason, spawn_error: spawnError?.code ?? null,
        stdout: Buffer.concat(chunks), stderr: Buffer.concat(diagnostics) });
    }
  });
}
