// Exercise the actual verification controller and native process owner in a
// private miniature Git workspace. Its one-test corpus is a controller fixture,
// not FrankenGit product, compatibility or live-fg evidence.
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, copyFile, writeFile, readFile, rename, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawn, spawnSync, execFileSync } from 'node:child_process';

const source = new URL('../verify_js.mjs', import.meta.url);
const owner = new URL('../lib/native-process-owner.mjs', import.meta.url);
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
const alive = pid => { try { process.kill(pid, 0);return true; } catch (e) { if (e.code === 'ESRCH') return false;throw e; } };
const environment = () => ({ ...Object.fromEntries(Object.entries(process.env).filter(([k]) => !k.startsWith('GIT_'))),
  GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: '/dev/null' });

async function fixture(t, body = "import test from 'node:test';import assert from 'node:assert/strict';import {readFileSync,writeFileSync} from 'node:fs';test('fixture corpus',()=>{assert.equal(readFileSync(new URL('../node-version',import.meta.url),'utf8').trim(),process.versions.node);writeFileSync(new URL('../../executed',import.meta.url),'selected browser corpus executed');});\n") {
  const root = await mkdtemp(join(tmpdir(), 'fg-js-controller-')), runs = [];
  t.after(async () => {
    for (const r of runs) {
      if (r.child.exitCode === null && r.child.signalCode === null) r.child.kill('SIGTERM');
      let timer;
      try { await Promise.race([r.closed, new Promise(resolve => { timer = setTimeout(resolve, 3000); })]); }
      finally { clearTimeout(timer); }
      if (r.child.exitCode === null && r.child.signalCode === null) r.child.kill('SIGKILL');
      for (const pid of r.ownedPids) {
        const info = spawnSync('ps', ['-p', String(pid), '-o', 'command='], { encoding: 'utf8', timeout: 1000 });
        if (!info.stdout?.includes(root)) continue; // Never signal a recycled peer PID.
        try { process.kill(pid, 'SIGKILL'); } catch (e) { if (e.code !== 'ESRCH') throw e; }
      }
      await r.closed;
    }
    await rm(root, { recursive: true, force: true });
  });
  await mkdir(join(root, 'scripts/lib'), { recursive: true });await mkdir(join(root, 'tests/browser'), { recursive: true });
  await mkdir(join(root, 'tests/operator'));await writeFile(join(root, 'tests/operator/unselected.test.mjs'), "throw new Error('unselected scope was executed');\n");
  await copyFile(source, join(root, 'scripts/verify_js.mjs'));await copyFile(owner, join(root, 'scripts/lib/native-process-owner.mjs'));
  await writeFile(join(root, 'tests/node-version'), process.versions.node + '\n');
  await writeFile(join(root, 'tests/browser/probe.test.mjs'), body);
  const git = args => execFileSync('/usr/bin/git', ['-c', 'core.hooksPath=/dev/null', '-C', root, ...args], {
    env: environment(), timeout: 10000, killSignal: 'SIGKILL', stdio: ['ignore', 'pipe', 'pipe'],
  });
  git(['init', '-q']);git(['add', 'scripts', 'tests']);
  git(['-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid', 'commit', '-qm', 'controller fixture']);
  const start = () => {
    const child = spawn(process.execPath, [join(root, 'scripts/verify_js.mjs'), 'browser'], {
      // Retain the enclosing test's group so its cancellation reaches this
      // controller; the controller itself owns its detached metadata/test groups.
      env: { ...process.env, TMPDIR: root, TMP: root, TEMP: root, GIT_DIR: '/nonexistent-fixture-git-dir' },
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    const r = { child, stdout: '', stderr: '', ownedPids: new Set(), ownedGroups: new Set() };
    child.stdout.on('data', b => { r.stdout += b; });child.stderr.on('data', b => { r.stderr += b; });
    r.closed = new Promise((resolve, reject) => { child.once('error', reject);child.once('close', (code, signal) => resolve({ code, signal })); });
    runs.push(r);return r;
  };
  return { root, start, async blockIndex() {
    await rename(join(root, '.git/index'), join(root, '.git/index.saved'));
    execFileSync('mkfifo', [join(root, '.git/index')], { timeout: 5000 });
  } };
}

async function metadataChild(run) {
  const until = performance.now() + 3000;
  while (performance.now() < until) {
    const rows = execFileSync('ps', ['-axo', 'pid=,ppid=,pgid=,comm='], { encoding: 'utf8', timeout: 1000 });
    for (const line of rows.split('\n')) {
      const m = /^\s*(\d+)\s+(\d+)\s+(\d+)\s+(.+)$/.exec(line);
      if (m && Number(m[2]) === run.child.pid && /(?:^|\/)git$/.test(m[4])) {
        const pid = Number(m[1]);
        const args = execFileSync('ps', ['-p', String(pid), '-o', 'command='], { encoding: 'utf8', timeout: 1000 });
        if (!args.includes('status --porcelain')) continue;
        run.ownedPids.add(pid);if (Number(m[3]) === pid) run.ownedGroups.add(pid);
        return pid;
      }
    }
    if (run.child.exitCode !== null || run.child.signalCode !== null) throw new Error(`controller exited before metadata fault: ${run.stderr}`);
    await sleep(10);
  }
  throw new Error('metadata process did not reach the blocked index');
}

test('actual profile verifies its selected source and completes a real one-test corpus', { timeout: 15000 }, async t => {
  const f = await fixture(t), r = f.start(), result = await r.closed;
  assert.equal(result.code, 0, r.stderr);assert.equal(result.signal, null);
  assert.match(r.stdout, /# pass 1\b/, r.stderr);assert.match(r.stderr, /dirty=false/);
  assert.equal(await readFile(join(f.root, 'executed'), 'utf8'), 'selected browser corpus executed');
  assert.match(r.stderr, /owned process group is quiescent/);
});

test('SIGTERM during stopped Git metadata drains its owned process before controller exit', { timeout: 15000 }, async t => {
  const f = await fixture(t);await f.blockIndex();const r = f.start(), pid = await metadataChild(r);
  process.kill(pid, 'SIGSTOP');r.child.kill('SIGTERM');const result = await r.closed;
  assert.equal(result.code, 130, r.stderr);assert.equal(alive(pid), false);
  if (r.ownedGroups.has(pid)) assert.throws(() => process.kill(-pid, 0), e => e.code === 'ESRCH');
  r.ownedPids.delete(pid);
  assert.match(r.stderr, /native_process_cancelled/);assert.doesNotMatch(r.stderr, /JS profile:/);
});

test('blocked Git metadata reaches a real deadline without launching a test worker', { timeout: 15000 }, async t => {
  const f = await fixture(t);await f.blockIndex();const r = f.start(), pid = await metadataChild(r);
  const result = await r.closed;
  assert.equal(result.code, 1, r.stderr);assert.equal(alive(pid), false);
  if (r.ownedGroups.has(pid)) assert.throws(() => process.kill(-pid, 0), e => e.code === 'ESRCH');
  r.ownedPids.delete(pid);
  assert.match(r.stderr, /native_process_deadline/);assert.doesNotMatch(r.stderr, /JS profile:/);
});

test('runtime identity mismatch refuses before a corpus is launched', { timeout: 15000 }, async t => {
  const f = await fixture(t);await writeFile(join(f.root, 'tests/node-version'), '0.0.0\n');
  const r = f.start(), result = await r.closed;
  assert.equal(result.code, 69);assert.doesNotMatch(r.stdout, /TAP version/);
});
