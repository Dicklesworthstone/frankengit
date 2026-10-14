#!/usr/bin/env node
// Explicit external operator consumer; no shell execution or server mutation.
import { pathToFileURL } from 'node:url';
import { resolve } from 'node:path';
import { setTimeout as sleep } from 'node:timers/promises';
import { EVENT_LIMITS, EventFeedError, eventConfiguration, eventCredential, eventFail, eventJson } from './operator/event_feed.mjs';
import { ARCHIVE_LIMITS, readEventPrivate, initializeEventArchive, openEventArchive, captureEventArchive } from './operator/event_archive.mjs';

const USAGE = `usage: node scripts/fg_events.mjs init --archive PATH --config FILE --token-file FILE --trusted-local
       node scripts/fg_events.mjs capture --archive PATH --config FILE --token-file FILE --trusted-local
         [--max-pages 1..64] [--max-bytes 1..33554432] [--timeout-ms 1..300000]
         [--expected-tail SHA256] [--ca-file FILE]
       node scripts/fg_events.mjs watch --archive PATH --config FILE --token-file FILE --trusted-local
         [capture options] [--poll-ms 100..60000] [--max-sweeps 1..1000000]
       node scripts/fg_events.mjs inspect --archive PATH --config FILE --trusted-local
         [--expected-tail SHA256] [--page 1..4096]

The config independently pins endpoint, tenant, repository, incarnation, native
hash format, exact read grants, initial cursor and page size. init is local-only.
Token/config/CA files must be private, owned, singly linked regular files.
Archive paths and their parents must be operator-controlled; POSIX only.
Capture syncs each complete immutable page before emitting its cursor receipt.
Restart resumes after the last verified saved page, including filtered pages.
Watch defaults to 1000 sweeps and 1000 ms between sweeps. It stops on any failure,
SIGTERM or SIGINT; failed requests are not automatically retried. Quiet identical
polls do not grow the archive. Limits are 4096 pages / 128 MiB; no automatic GC.
inspect performs no network I/O or writes. --page explicitly reveals retained
frames. A changed credential or grant profile requires a new archive/backfill.
Exit 0: command complete; 1: bounded capture/watch has more work; 2: refusal;
130: cancellation. An error can follow saved pages: receipts and archive persist.
This filtered feed is not a forge backup, authority proof, or webhook settlement.
See docs/REMOTE_EVENT_ARCHIVE.md.`;
function parse(args) {
  if (args.length < 1 || args.length > 32 || args.some(a => typeof a !== 'string' || a.length > 8192) ||
      args.reduce((n, a) => n + a.length, 0) > 32768) eventFail('invalid_event_arguments');
  const [action] = args;
  if (!['init', 'capture', 'watch', 'inspect'].includes(action)) eventFail('invalid_event_action');
  const allowed = ['--archive', '--config', '--trusted-local'];
  if (action !== 'inspect') allowed.push('--token-file');
  if (action !== 'init') allowed.push('--expected-tail');
  if (['capture', 'watch'].includes(action)) allowed.push('--ca-file', '--max-pages', '--max-bytes', '--timeout-ms');
  if (action === 'watch') allowed.push('--poll-ms', '--max-sweeps');
  if (action === 'inspect') allowed.push('--page');
  const flags = new Map();
  for (let i = 1; i < args.length; i++) {
    const key = args[i];
    if (!allowed.includes(key) || flags.has(key)) eventFail('invalid_or_duplicate_event_option');
    const value = key === '--trusted-local' ? true : args[++i];
    if (value !== true && (typeof value !== 'string' || !value || value.startsWith('--'))) eventFail('missing_event_option_value');
    flags.set(key, value);
  }
  for (const key of ['--archive', '--config', '--trusted-local', ...(action !== 'inspect' ? ['--token-file'] : [])]) {
    if (!flags.has(key)) eventFail('missing_required_event_option');
  }
  if (flags.has('--expected-tail') && !/^[0-9a-f]{64}$/.test(flags.get('--expected-tail'))) eventFail('invalid_event_archive_pin');
  const number = (key, fallback, min, max) => {
    const value = flags.get(key) ?? String(fallback);
    if (!/^(0|[1-9][0-9]{0,9})$/.test(value) || Number(value) < min || Number(value) > max) eventFail('invalid_event_bound');
    return Number(value);
  };
  return { action, flags, maxPages: number('--max-pages', 16, 1, EVENT_LIMITS.pages),
    maxBytes: number('--max-bytes', EVENT_LIMITS.bytes, 1, EVENT_LIMITS.bytes), timeoutMs: number('--timeout-ms', 30000, 1, EVENT_LIMITS.timeoutMs),
    pollMs: number('--poll-ms', 1000, 100, 60000), maxSweeps: number('--max-sweeps', 1000, 1, 1000000),
    page: flags.has('--page') ? number('--page', 1, 1, ARCHIVE_LIMITS.pages) : undefined };
}
async function token(path, checkpoint) {
  const bytes = await readEventPrivate(path, 65, checkpoint);
  if (bytes.length !== 64 && !(bytes.length === 65 && bytes[64] === 10)) eventFail('invalid_event_credential_file');
  return eventCredential(bytes.subarray(0, 64).toString('utf8'));
}
async function emit(stream, value, signal = undefined) {
  // A stopped consumer must not hold a saved page hostage to a full output
  // pipe. This command owns its output writes; closing a blocked stream loses
  // only a receipt, never the already-synced page or its resume watermark.
  await new Promise((accept, reject) => {
    let finished = false;
    const finish = error => {
      if (finished) return;
      finished = true; clearTimeout(timer); signal?.removeEventListener('abort', abort);
      error ? reject(error) : accept();
    };
    const stop = code => {
      const error = new EventFeedError(code); finish(error); stream.destroy(error);
    };
    const abort = () => stop('event_cancelled');
    const timer = setTimeout(() => stop('event_output_timeout'), 10000);
    signal?.addEventListener('abort', abort, { once: true });
    if (signal?.aborted) { abort(); return; }
    try { stream.write(`${JSON.stringify(value)}\n`, finish); } catch (error) { finish(error); }
  });
}
export async function main(args, { stdout = process.stdout, stderr = process.stderr } = {}) {
  if (args.length === 1 && args[0] === '--help') {
    await new Promise((ok, no) => stdout.write(`${USAGE}\n`, e => e ? no(e) : ok())); return 0;
  }
  const stop = new AbortController(), abort = () => stop.abort();
  const quietError = () => {};
  stdout.on('error', quietError); stderr.on('error', quietError);
  process.on('SIGTERM', abort); process.on('SIGINT', abort);
  try {
    const options = parse(args), f = options.flags;
    const checkpoint = () => { if (stop.signal.aborted) eventFail('event_cancelled'); };
    const config = eventConfiguration(eventJson(await readEventPrivate(f.get('--config'), EVENT_LIMITS.configuration, checkpoint), EVENT_LIMITS.configuration));
    if (options.action === 'init') {
      const archive = await initializeEventArchive(f.get('--archive'), config, await token(f.get('--token-file'), checkpoint), checkpoint);
      await emit(stdout, { ...archive.summary(), initialized: true, local_synced: true, network_attempted: false }, stop.signal); return 0;
    }
    let expectedTail = f.get('--expected-tail');
    if (options.action === 'inspect') {
      const archive = await openEventArchive(f.get('--archive'), config, { checkpoint,
        ...(expectedTail !== undefined ? { expectedTail } : {}), ...(options.page !== undefined ? { page: options.page } : {}) });
      await emit(stdout, { ...archive.summary(), network_attempted: false, archive_modified: false, durability_verified: false,
        ...(options.page !== undefined ? { selected_page: archive.selectedPage() } : {}) }, stop.signal); return 0;
    }
    const ca = f.has('--ca-file') ? await readEventPrivate(f.get('--ca-file'), 128 * 1024, checkpoint) : undefined;
    const rounds = options.action === 'watch' ? options.maxSweeps : 1;
    for (let sweep = 0; sweep < rounds; sweep++) {
      checkpoint();
      const result = await captureEventArchive(f.get('--archive'), config, await token(f.get('--token-file'), checkpoint), {
        maxPages: options.maxPages, maxBytes: options.maxBytes, timeoutMs: options.timeoutMs, signal: stop.signal, ca,
        ...(expectedTail !== undefined ? { expectedTail } : {}), onPage: receipt => emit(stdout, { ...receipt, type: 'frankengit_event_page_saved' }, stop.signal) });
      expectedTail = result.tail_sha256;
      await emit(stdout, { ...result, type: 'frankengit_event_capture_complete', sweep: sweep + 1 }, stop.signal);
      if (options.action === 'capture') return result.caught_up_at_observed_head ? 0 : 1;
      if (sweep + 1 < rounds) await sleep(options.pollMs, undefined, { signal: stop.signal });
    }
    return 1;
  } catch (error) {
    const cancelled = stop.signal.aborted || error?.code === 'event_cancelled';
    try { await emit(stderr, { type: 'frankengit_event_consumer_error', schema_version: 1,
      code: cancelled ? 'event_cancelled' : error instanceof EventFeedError ? error.code : 'event_consumer_io_failed',
      http_status: error instanceof EventFeedError ? error.status : null,
      local_publication_unknown: Boolean(error?.localPublicationUnknown), saved_pages_may_exist: true,
      ...(error?.retained ? { retained: error.retained } : {}) }); } catch { /* A broken diagnostic stream cannot undo saved pages. */ }
    return cancelled ? 130 : 2;
  } finally {
    process.removeListener('SIGTERM', abort); process.removeListener('SIGINT', abort);
    // Pending stream error events are still observed, but their write callbacks
    // already determined the command result. Do not suppress any failed write.
    setImmediate(() => { stdout.removeListener('error', quietError); stderr.removeListener('error', quietError); });
  }
}
if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  main(process.argv.slice(2)).then(code => { process.exitCode = code; }, () => { process.exitCode = 2; });
}
