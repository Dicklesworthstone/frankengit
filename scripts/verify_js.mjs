#!/usr/bin/env node
// Test-only profile shared by browser/operator checks. This does not admit Node
// into the production dependency universe or establish live-fg coverage.
import { readFile, readdir, mkdtemp, realpath, chmod, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { resolve, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawn } from 'node:child_process';
import { runNativeProcess } from './lib/native-process-owner.mjs';

const root = fileURLToPath(new URL('../', import.meta.url));
const scopes = { browser: 'tests/browser', operator: 'tests/operator', scripts: 'scripts/tests' };
const scope = process.argv[2];
let child, temporary, deadline, escalation, finalizer, rejectRun, containmentFailure, requested = null;
const initialization = new AbortController();
const until = performance.now() + 600000;
const containment = cause => Object.assign(new Error('JS verification process-group containment failed'), {
  code: 'js_profile_containment_failed', cause,
});
const signalGroup = signal => {
  try { process.kill(-child.pid, signal); }
  catch (error) { if (error.code !== 'ESRCH') containmentFailure ??= containment(error); }
};
const groupPresent = () => {
  try { process.kill(-child.pid, 0); return true; }
  catch (error) { if (error.code === 'ESRCH') return false; throw containment(error); }
};
const stop = reason => {
  if (requested !== null) return;
  requested = reason;
  console.error(`JS verification stopping: ${reason}`);
  initialization.abort();
  if (child?.pid) {
    signalGroup('SIGTERM');
    escalation = setTimeout(() => {
      signalGroup('SIGKILL');
      finalizer = setTimeout(() => {
        // Pipe/leader closure may never arrive after a denied signal. Retire
        // only our local handle and report uncertainty; do not claim cleanup.
        child.unref();
        rejectRun?.(containmentFailure ?? containment(new Error('leader did not close after stop')));
      }, 5000);
    }, 5000);
  }
};
const interrupt = () => stop('SIGINT');
const terminate = () => stop('SIGTERM');
// Install before metadata subprocesses or temporary-directory acquisition.
process.on('SIGINT', interrupt);process.on('SIGTERM', terminate);

async function metadata(args) {
  // No other work runs during this standalone CLI's initialization. Isolate
  // the inherited Git environment for this owned call, then restore it.
  const previous = Object.fromEntries(Object.entries(process.env).filter(([key]) => key.startsWith('GIT_')));
  for (const key of Object.keys(previous)) delete process.env[key];
  Object.assign(process.env, { GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: '/dev/null', GIT_OPTIONAL_LOCKS: '0' });
  try {
    const result = await runNativeProcess('/usr/bin/git', ['--no-optional-locks', '-c', 'core.fsmonitor=false', '-C', root, ...args], {
      timeoutMs: 5000, signal: initialization.signal, stdoutLimit: 1024 * 1024, stderrLimit: 65536,
    });
    if (result.code !== 0 || result.signal !== null) throw new Error('JS verification cannot read source metadata');
    return result.stdout.toString('utf8').trim();
  } finally {
    for (const key of Object.keys(process.env)) if (key.startsWith('GIT_')) delete process.env[key];
    Object.assign(process.env, previous);
  }
}

async function initialize() {
  if (process.argv.length !== 3 || !Object.hasOwn(scopes, scope) || !['darwin', 'linux'].includes(process.platform)) {
    console.error('usage: node scripts/verify_js.mjs browser|operator|scripts (macOS or Linux)');
    process.exit(64);
  }
  const expected = (await readFile(join(root, 'tests/node-version'), 'utf8')).trim();
  if (process.versions.node !== expected) {
    console.error(`JS verification requires Node ${expected}; running ${process.versions.node}`);
    process.exit(69);
  }
  const files = (await readdir(resolve(root, scopes[scope]))).filter(name => name.endsWith('.test.mjs')).sort().map(name => join(root, scopes[scope], name));
  if (!files.length) throw new Error('JS verification discovered no test files');
  const revision = await metadata(['rev-parse', '--verify', 'HEAD']);
  if (!/^(?:[0-9a-f]{40}|[0-9a-f]{64})$/.test(revision)) throw new Error('JS verification cannot bind a source revision');
  const dirty = await metadata(['status', '--porcelain', '--untracked-files=normal']) !== '';
  initialization.signal.throwIfAborted();
  temporary = await mkdtemp(join(await realpath(tmpdir()), 'fg-js-verification-'));
  await chmod(temporary, 0o700);
  initialization.signal.throwIfAborted();
  const runtimeFlags = scope === 'scripts' ? ['--experimental-vm-modules'] : [];
  console.error(`JS profile: revision=${revision} dirty=${dirty} node=${expected} host=${process.platform}/${process.arch} scope=${scope} files=${files.length} vm_modules=${runtimeFlags.length > 0} concurrency=2 test_timeout_ms=300000 campaign_timeout_ms=600000 temporary=${temporary}`);
  return { files, runtimeFlags };
}
let code = 1;
try {
  deadline = setTimeout(() => stop('campaign_deadline'), Math.max(1, Math.ceil(until - performance.now())));
  const { files, runtimeFlags } = await initialize();
  const testEnvironment = { ...process.env, TMPDIR: temporary, TMP: temporary, TEMP: temporary };
  // This is a new isolated runner, even when invoked by another node:test
  // process. Inheriting its internal context makes Node skip a recursive run.
  delete testEnvironment.NODE_TEST_CONTEXT;
  child = spawn(process.execPath, [...runtimeFlags, '--test', '--test-reporter=tap', '--test-concurrency=2', '--test-timeout=300000', ...files], {
    cwd: root, detached: true, stdio: 'inherit',
    env: testEnvironment,
  });
  code = await new Promise((resolve, reject) => {
    rejectRun = reject;
    child.once('error', reject);
    child.once('close', (status, signal) => {
      if (requested === null && performance.now() >= until) requested = 'campaign_deadline';
      resolve(requested === 'campaign_deadline' ? 124 : requested ? 130 : status ?? (signal ? 1 : 0));
    });
  });
  if (containmentFailure) throw containmentFailure;
  if (groupPresent()) {
    console.error('JS verification runner exited with descendants remaining');
    if (code === 0) code = 1;
    signalGroup('SIGKILL');
    const drainUntil = performance.now() + 5000;
    while (groupPresent()) {
      if (containmentFailure) throw containmentFailure;
      if (performance.now() >= drainUntil) throw containment(new Error('process group did not reach quiescence'));
      await new Promise(resolve => setTimeout(resolve, 25));
    }
  }
  console.error('JS verification owned process group is quiescent');
} catch (error) {
  if (error.code === 'js_profile_containment_failed' && child?.pid) signalGroup('SIGKILL');
  code = ['native_process_containment_failed', 'js_profile_containment_failed'].includes(error.code) ? 1 : requested === 'campaign_deadline' ? 124 : requested ? 130 : 1;
  console.error(`JS verification failed: ${error.code ?? error.message}${error.cause?.code ? ` cause=${error.cause.code}` : ''}`);
} finally {
  clearTimeout(deadline);clearTimeout(escalation);clearTimeout(finalizer);
  process.off('SIGINT', interrupt);process.off('SIGTERM', terminate);
  if (temporary) {
    if (code === 0) await rm(temporary, { recursive: true, force: true });
    else console.error(`JS verification failure artifacts retained: ${temporary}`);
  }
}
process.exitCode = code;
