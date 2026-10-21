#!/usr/bin/env node
// Test-only profile shared by browser/operator checks. This does not admit Node
// into the production dependency universe or establish live-fg coverage.
import { readFile, readdir, mkdtemp, realpath, chmod, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { resolve, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawn, execFileSync } from 'node:child_process';

const root = fileURLToPath(new URL('../', import.meta.url));
const scopes = { browser: 'tests/browser', operator: 'tests/operator', scripts: 'scripts/tests' };
const scope = process.argv[2];
if (process.argv.length !== 3 || !Object.hasOwn(scopes, scope) || !['darwin', 'linux'].includes(process.platform)) {
  console.error('usage: node scripts/verify_js.mjs browser|operator|scripts (macOS or Linux)');
  process.exit(64);
}
const expected = (await readFile(join(root, 'tests/node-version'), 'utf8')).trim();
if (process.versions.node !== expected) {
  console.error(`JS verification requires Node ${expected}; running ${process.versions.node}`);
  process.exit(69);
}
const directory = resolve(root, scopes[scope]);
// The existing binary-edit test loads isolated ES modules through node:vm.
const runtimeFlags = scope === 'scripts' ? ['--experimental-vm-modules'] : [];
const files = (await readdir(directory)).filter(name => name.endsWith('.test.mjs')).sort().map(name => join(directory, name));
if (!files.length) throw new Error('JS verification discovered no test files');
const metadataEnv = Object.fromEntries(Object.entries(process.env).filter(([key]) => !key.startsWith('GIT_')));
const git = args => execFileSync('git', args, { cwd: root, env: metadataEnv, timeout: 5000, maxBuffer: 1024 * 1024, encoding: 'utf8' }).trim();
const revision = git(['rev-parse', '--verify', 'HEAD']);
if (!/^(?:[0-9a-f]{40}|[0-9a-f]{64})$/.test(revision)) throw new Error('JS verification cannot bind a source revision');
const dirty = git(['status', '--porcelain', '--untracked-files=normal']) !== '';
const temporary = await mkdtemp(join(await realpath(tmpdir()), 'fg-js-verification-'));
await chmod(temporary, 0o700);
console.error(`JS profile: revision=${revision} dirty=${dirty} node=${expected} host=${process.platform}/${process.arch} scope=${scope} files=${files.length} vm_modules=${runtimeFlags.length > 0} concurrency=2 test_timeout_ms=300000 campaign_timeout_ms=600000 temporary=${temporary}`);
let child, deadline, escalation, requested = null;
const signalGroup = signal => {
  try { process.kill(-child.pid, signal); } catch (error) { if (error.code !== 'ESRCH') throw error; }
};
const stop = reason => {
  if (requested !== null) return;
  requested = reason;
  console.error(`JS verification stopping: ${reason}`);
  signalGroup('SIGTERM');
  escalation = setTimeout(() => signalGroup('SIGKILL'), 5000);
};
const interrupt = () => stop('SIGINT');
const terminate = () => stop('SIGTERM');
let code = 1;
try {
  child = spawn(process.execPath, [...runtimeFlags, '--test', '--test-reporter=tap', '--test-concurrency=2', '--test-timeout=300000', ...files], {
    cwd: root, detached: true, stdio: 'inherit',
    env: { ...process.env, TMPDIR: temporary, TMP: temporary, TEMP: temporary },
  });
  process.on('SIGINT', interrupt);process.on('SIGTERM', terminate);
  deadline = setTimeout(() => stop('campaign_deadline'), 600000);
  code = await new Promise((resolve, reject) => {
    child.once('error', reject);
    child.once('close', (status, signal) => resolve(requested === 'campaign_deadline' ? 124 : requested ? 130 : status ?? (signal ? 1 : 0)));
  });
  // A test worker must not leave a same-group child alive after its runner exits.
  signalGroup('SIGKILL');
} finally {
  clearTimeout(deadline);clearTimeout(escalation);
  process.off('SIGINT', interrupt);process.off('SIGTERM', terminate);
  if (code === 0) await rm(temporary, { recursive: true, force: true });
  else console.error(`JS verification failure artifacts retained: ${temporary}`);
}
process.exitCode = code;
