import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { spawn, spawnSync } from 'node:child_process';
import { Writable } from 'node:stream';
import { mkdtemp, realpath, writeFile, readFile, chmod, rm, stat, readdir, link, symlink } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { main } from '../../scripts/fg_source_refactor.mjs';
import { REFACTOR_PROFILE } from '../../scripts/operator/source_edit_replacements.mjs';
const CLI = fileURLToPath(new URL('../../scripts/fg_source_refactor.mjs', import.meta.url));
const blob = (fmt, b) => createHash(fmt).update(`blob ${b.length}\0`).update(b).digest('hex');
const sha = b => createHash('sha256').update(b).digest('hex');
const hex = p => Buffer.from(p).toString('hex');
function collect() {
  const chunks = [], stream = new Writable({ write(chunk, _, cb) { chunks.push(Buffer.from(chunk)); cb(); } });
  return { stream, rows: () => Buffer.concat(chunks).toString().trim().split('\n').filter(Boolean).map(JSON.parse) };
}
async function fixture(fmt, original = Buffer.from('original\n'), label = 'fg-refactor-cli-') {
  const root = await mkdtemp(join(await realpath(tmpdir()), label)); await chmod(root, 0o700);
  const old = join(root, 'before'), next = join(root, 'after'), input = join(root, 'plan.json'), output = join(root, 'change.patch');
  await writeFile(old, original, { mode: 0o600 }); await writeFile(next, 'changed\n', { mode: 0o600 });
  const plan = { schema: REFACTOR_PROFILE, object_format: fmt, changes: [{ path_hex: hex('old.bin'), destination_hex: hex('new.bin'),
    before: { file: old, blob: blob(fmt, original), mode: 0o100644 }, after: { mode: 0o100755 } }] };
  const save = async () => writeFile(input, JSON.stringify(plan)+'\n', { mode: 0o600 }); await save();
  return { root, old, next, input, output, plan, save, args: ['compile', '--plan-file', input, '--output', output] };
}
function invoke(args) {
  const r = spawnSync(process.execPath, [CLI, ...args], { timeout: 15000, maxBuffer: 2 * 1024 * 1024 });
  if (r.error) throw r.error; return { code: r.status, stdout: r.stdout.toString(), stderr: r.stderr.toString() };
}
async function absent(filename) { await assert.rejects(stat(filename), { code: 'ENOENT' }); }
for (const fmt of ['sha1', 'sha256']) {
  test(`${fmt}: actual CLI compiles a one-MiB binary move without retransmitting its payload`, async () => {
    const f = await fixture(fmt, Buffer.alloc(1048576));
    try {
      const before = await readFile(f.input), r = invoke(f.args); assert.equal(r.code, 0, r.stderr);
      const receipt = JSON.parse(r.stdout), patch = await readFile(f.output);
      assert.equal(receipt.plan_sha256, sha(before)); assert.equal(receipt.patch_sha256, sha(patch));
      assert.ok(patch.length < 300); assert.equal(receipt.patch_bytes, patch.length);
      assert.equal(receipt.file_sections, 1); assert.equal(receipt.changed_paths, 2); assert.equal(receipt.move_count, 1);
      assert.equal(receipt.source_bytes, 1048576); assert.equal(receipt.result_bytes, 1048576);
      assert.equal(receipt.native_patch_profile, 'exact-tree-v1'); assert.equal(receipt.preimages_verified, true);
      assert.equal(receipt.destinations_absent_verified, false); assert.equal(receipt.source_membership_verified, false);
      assert.equal(receipt.publication_attempted, false); assert.equal((await stat(f.output)).mode & 0o777, 0o600);
      assert.equal(invoke(f.args).code, 2); assert.deepEqual(await readFile(f.output), patch);
      assert.deepEqual((await readdir(f.root)).sort(), ['after','before','change.patch','plan.json']);
    } finally { await rm(f.root, { recursive: true, force: true }); }
  });
  test(`${fmt}: file-backed text move and ordinary creation share one actual CLI output`, async () => {
    const f = await fixture(fmt);
    try {
      f.plan.changes[0].after.file = f.next;
      f.plan.changes.push({ path_hex: hex('created'), before: null, after: { file: f.next, mode: 0o100644 } }); await f.save();
      const r = invoke(f.args); assert.equal(r.code, 0, r.stderr);
      const receipt = JSON.parse(r.stdout), patch = await readFile(f.output);
      assert.equal(receipt.changed_paths, 3); assert.equal(receipt.file_sections, 2);
      assert.ok(patch.includes(Buffer.from('+++ "b/new.bin"'))); assert.ok(patch.includes(Buffer.from('new file mode 100644')));
      assert.equal(receipt.result_bytes, Buffer.byteLength('changed\n') * 2);
    } finally { await rm(f.root, { recursive: true, force: true }); }
  });
  test(`${fmt}: incorrect full preimage, edited binary and overlapping destinations refuse without output`, async () => {
    for (const kind of ['hash','binary','overlap']) {
      const f = await fixture(fmt, Buffer.from([0, 1]));
      try {
        if (kind === 'hash') f.plan.changes[0].before.blob = '1'.repeat(fmt === 'sha1' ? 40 : 64);
        if (kind === 'binary') f.plan.changes[0].after.file = f.next;
        if (kind === 'overlap') f.plan.changes.push({ path_hex: hex('new.bin/child'), before: null, after: { file: f.next, mode: 0o100644 } });
        await f.save(); const r = invoke([...f.args, '--binary', 'literal']); assert.equal(r.code, 2, kind); await absent(f.output);
        assert.equal(JSON.parse(r.stderr).repository_publication_attempted, false);
      } finally { await rm(f.root, { recursive: true, force: true }); }
    }
  });
  test(`${fmt}: actual concurrent processes cannot overwrite either winner`, async () => {
    const f = await fixture(fmt);
    try {
      const run = () => new Promise((resolve, reject) => {
        const child = spawn(process.execPath, [CLI, ...f.args], { stdio: ['ignore','pipe','pipe'] });
        let out = '', err = ''; const timer = setTimeout(() => { child.kill('SIGKILL'); reject(new Error('bounded child timeout')); }, 10000);
        child.stdout.on('data', b => out += b); child.stderr.on('data', b => err += b);
        child.on('error', e => { clearTimeout(timer); reject(e); }); child.on('close', code => { clearTimeout(timer); resolve({ code, out, err }); });
      });
      const results = await Promise.all([run(), run()]); assert.deepEqual(results.map(r => r.code).sort(), [0,2]);
      const receipt = JSON.parse(results.find(r => r.code === 0).out);
      assert.equal(sha(await readFile(f.output)), receipt.patch_sha256);
      assert.equal((await readdir(f.root)).filter(n => n.includes('.writing-')).length, 0);
    } finally { await rm(f.root, { recursive: true, force: true }); }
  });
  test(`${fmt}: broken stdout retains the exact patch and independent plan/patch hashes`, async () => {
    const f = await fixture(fmt);
    try {
      const stderr = collect(); const stdout = new Writable({ write(_, __, cb) { cb(Object.assign(new Error('closed'), { code: 'EPIPE' })); } });
      assert.equal(await main(f.args, { stdout, stderr: stderr.stream }), 4);
      const receipt = stderr.rows()[0].retained_result;
      assert.equal(receipt.patch_sha256, sha(await readFile(f.output))); assert.equal(receipt.plan_sha256, sha(await readFile(f.input)));
      assert.equal(invoke(f.args).code, 2);
    } finally { await rm(f.root, { recursive: true, force: true }); }
  });
  test(`${fmt}: cancellation before file ownership creates no patch and detaches signal handlers`, async () => {
    const f = await fixture(fmt);
    try {
      const controller = new AbortController(); controller.abort(); const stdout = collect(), stderr = collect();
      const sigint = process.listenerCount('SIGINT'), sigterm = process.listenerCount('SIGTERM');
      assert.equal(await main(f.args, { stdout: stdout.stream, stderr: stderr.stream, signal: controller.signal }), 2);
      assert.equal(stdout.rows().length, 0); await absent(f.output);
      assert.equal(process.listenerCount('SIGINT'), sigint); assert.equal(process.listenerCount('SIGTERM'), sigterm);
    } finally { await rm(f.root, { recursive: true, force: true }); }
  });
}
for (const kind of ['public-body','symlink-body','hardlink-body','public-plan','symlink-parent']) {
  test(`private-file custody refuses ${kind} before writing`, async () => {
    const f = await fixture('sha256');
    try {
      if (kind === 'public-body') await chmod(f.old, 0o644);
      if (kind === 'public-plan') await chmod(f.input, 0o644);
      if (kind === 'hardlink-body') await link(f.old, join(f.root, 'alias'));
      if (kind === 'symlink-body') { const p = join(f.root, 'alias'); await symlink(f.old, p); f.plan.changes[0].before.file = p; await f.save(); }
      if (kind === 'symlink-parent') { const p = join(f.root, 'alias'); await symlink(f.root, p); f.plan.changes[0].before.file = join(p, 'before'); await f.save(); }
      assert.equal(invoke(f.args).code, 2); await absent(f.output);
    } finally { await rm(f.root, { recursive: true, force: true }); }
  });
}
test('strict plan JSON rejects unknowns, duplicates, ambiguous integers and missing non-move file bodies', async () => {
  const f = await fixture('sha256');
  try {
    const original = JSON.stringify(f.plan);
    for (const invalid of [original.replace('"schema":', '"schema":"duplicate","schema":'), original.replace('"changes":', '"unexpected":1,"changes":'),
      original.replace('33188', '33188.0'), original.replace(REFACTOR_PROFILE, 'frankengit-source-refactoring-v2'),
      JSON.stringify({ ...f.plan, changes: [{ path_hex: hex('a'), before: null, after: { mode: 0o100644 } }] })]) {
      await writeFile(f.input, invalid); assert.equal(invoke(f.args).code, 2, invalid); await absent(f.output);
    }
  } finally { await rm(f.root, { recursive: true, force: true }); }
});
test('unknown flags, mixed profiles, duplicate options and widened limits are refused', async () => {
  const f = await fixture('sha1');
  try {
    for (const args of [[...f.args, '--force', 'yes'], [...f.args, '--binary', 'delta-multi'], [...f.args, '--plan-file', f.input],
      [...f.args, '--max-patch-bytes', '1048577'], [...f.args, '--timeout-ms', '300001'], [...f.args, '--max-patch-bytes', '1e6'],
      ['apply', ...f.args.slice(1)], ['compile', '--plan-file', f.input, '--output']]) {
      assert.equal(invoke(args).code, 2); await absent(f.output);
    }
    assert.equal(invoke(['--help']).code, 0);
  } finally { await rm(f.root, { recursive: true, force: true }); }
});
test('exact output budget succeeds and one-byte-less budget refuses atomically', async () => {
  const f = await fixture('sha1');
  try {
    const first = invoke(f.args); assert.equal(first.code, 0); const receipt = JSON.parse(first.stdout);
    const exact = join(f.root, 'exact.patch'), short = join(f.root, 'short.patch');
    assert.equal(invoke(['compile','--plan-file',f.input,'--output',exact,'--max-patch-bytes',String(receipt.patch_bytes)]).code, 0);
    assert.equal(invoke(['compile','--plan-file',f.input,'--output',short,'--max-patch-bytes',String(receipt.patch_bytes-1)]).code, 2);
    await absent(short); assert.deepEqual(await readFile(exact), await readFile(f.output));
  } finally { await rm(f.root, { recursive: true, force: true }); }
});
test('shared source/result budgets refuse oversized body before file-backed allocation', async () => {
  const f = await fixture('sha256', Buffer.alloc(1048576));
  try {
    f.plan.changes = Array.from({ length: 9 }, (_, i) => ({ ...f.plan.changes[0], path_hex: hex(`a${i}`), destination_hex: hex(`b${i}`) }));
    await f.save(); assert.equal(invoke(f.args).code, 2); await absent(f.output);
    f.plan.changes.length = 8; await f.save(); assert.equal(invoke(f.args).code, 0);
    const receipt = JSON.parse(invoke(['--help']).stdout); assert.ok(receipt.usage);
    assert.equal((await readFile(f.output)).includes(Buffer.from('GIT binary patch')), false);
  } finally { await rm(f.root, { recursive: true, force: true }); }
});
test('actual child with a closed stdout pipe reports retained output without overwrite', async () => {
  const f = await fixture('sha256');
  try {
    const result = await new Promise((resolve, reject) => {
      const child = spawn(process.execPath, [CLI, ...f.args], { stdio: ['ignore', 'pipe', 'pipe'] });
      child.stdout.destroy(); let stderr = '';
      const timer = setTimeout(() => { child.kill('SIGKILL'); reject(new Error('bounded child timeout')); }, 10000);
      child.stderr.on('data', data => stderr += data);
      child.on('error', error => { clearTimeout(timer); reject(error); });
      child.on('close', code => { clearTimeout(timer); resolve({ code, stderr }); });
    });
    assert.equal(result.code, 4, result.stderr);
    const receipt = JSON.parse(result.stderr).retained_result;
    assert.equal(sha(await readFile(f.output)), receipt.patch_sha256);
    assert.equal(invoke(f.args).code, 2);
  } finally { await rm(f.root, { recursive: true, force: true }); }
});
