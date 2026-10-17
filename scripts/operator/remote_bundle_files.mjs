// Private, create-only operator custody. Not a hostile-same-UID sandbox or a
// hardware durability guarantee; damaged files stay in place for inspection.
import { constants as F } from 'node:fs';
import { open, lstat, realpath, opendir } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import { performance } from 'node:perf_hooks';
import { fail, bounded, pin } from './remote_bundle_protocol.mjs';

export function absolute(value) {
  if (typeof value !== 'string' || !value || Buffer.byteLength(value) > 4096 || /[\0\r\n\uD800-\uDFFF]/u.test(value) || resolve(value) !== value) fail('path');
  return value;
}
function privateStat(s, dir) {
  if (typeof process.getuid !== 'function' || [F.O_NOFOLLOW, F.O_DIRECTORY, F.O_NONBLOCK].some(v => v === undefined)) fail('posix_required');
  if (!(dir ? s.isDirectory() : s.isFile()) || s.uid !== BigInt(process.getuid()) || (s.mode & 0o077n) !== 0n || !dir && s.nlink !== 1n) fail('private_file');
}
export async function directory(path, expected = null) {
  absolute(path); const s = await lstat(path, { bigint: true }); privateStat(s, true);
  if (await realpath(path) !== path || expected && (s.dev !== expected.dev || s.ino !== expected.ino)) fail('directory_changed');
  return s;
}
export async function privateRoot(path) {
  await directory(path);
  for (let cursor = path;; cursor = dirname(cursor)) {
    if (cursor.split('/').includes('.git')) fail('worktree');
    try { await lstat(join(cursor, '.git')); fail('worktree'); } catch (e) { if (e.code !== 'ENOENT') throw e; }
    if (dirname(cursor) === cursor) break;
  }
}
export async function inventory(path, names, check = () => {}) {
  const expected = new Set(names);
  for await (const e of await opendir(path)) { check(); if (!expected.delete(e.name)) fail('unexpected_file'); }
  if (expected.size) fail('missing_file');
}
export async function absent(path) {
  try { await lstat(path); fail('exists'); } catch (e) { if (e.code !== 'ENOENT') throw e; }
}
export async function syncDirectory(path) {
  const fd = await open(path, F.O_RDONLY | F.O_DIRECTORY | F.O_NOFOLLOW);
  try { privateStat(await fd.stat({ bigint: true }), true); await fd.sync(); } finally { await fd.close(); }
}
export async function readPrivate(path, maximum, check = () => {}, sync = false) {
  absolute(path); bounded(maximum, 1, 64 * 1024 * 1024); check();
  const parent = await directory(dirname(path));
  const fd = await open(path, F.O_RDONLY | F.O_NOFOLLOW | F.O_NONBLOCK);
  try {
    const before = await fd.stat({ bigint: true }); privateStat(before, false);
    if (before.size < 1n || before.size > BigInt(maximum)) fail('file_limit');
    const bytes = Buffer.alloc(Number(before.size) + 1); let at = 0;
    while (at < bytes.length) {
      check(); const next = await fd.read(bytes, at, Math.min(65536, bytes.length - at), at);
      if (!next.bytesRead) break; at += next.bytesRead;
    }
    if (BigInt(at) !== before.size) fail('file_changed');
    if (sync) { check(); await fd.sync(); await syncDirectory(dirname(path)); }
    const after = await fd.stat({ bigint: true }), named = await lstat(path, { bigint: true });
    for (const k of ['dev', 'ino', 'uid', 'mode', 'nlink', 'size', 'ctimeNs', 'mtimeNs'])
      if (before[k] !== after[k] || after[k] !== named[k]) fail('file_changed');
    await directory(dirname(path), parent); check(); return bytes.subarray(0, at);
  } finally { await fd.close(); }
}
export async function writeNew(path, bytes) {
  const parent = await directory(dirname(path));
  const fd = await open(path, F.O_WRONLY | F.O_CREAT | F.O_EXCL | F.O_NOFOLLOW, 0o600);
  try { await fd.writeFile(bytes); await fd.sync(); } finally { await fd.close(); }
  await directory(dirname(path), parent); await syncDirectory(dirname(path));
  if (!(await readPrivate(path, bytes.length)).equals(bytes)) fail('write_readback');
}
export async function readToken(path, check = () => {}) {
  const bytes = await readPrivate(absolute(path), 65, check);
  try { return pin(bytes.toString('utf8').replace(/\n$/, '')); } finally { bytes.fill(0); }
}
export function lifetime(raw) {
  const timeoutMs = bounded(raw.timeoutMs ?? 300000, 1, 300000), deadline = performance.now() + timeoutMs;
  if (raw.signal !== undefined && !(raw.signal instanceof AbortSignal)) fail('signal');
  const stop = new AbortController(), signal = raw.signal ? AbortSignal.any([raw.signal, stop.signal]) : stop.signal;
  const timer = setTimeout(() => stop.abort(), timeoutMs);
  const check = () => { signal.throwIfAborted(); if (performance.now() >= deadline) fail('timeout'); };
  return { signal, check, remaining() { check(); return Math.max(1, Math.ceil(deadline - performance.now())); },
    close() { clearTimeout(timer); stop.abort(); } };
}
