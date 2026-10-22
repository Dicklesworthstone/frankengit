// Git is only a separately invoked test oracle. Each direction gets a new object store.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { mkdtemp, mkdir, writeFile, chmod, rm, realpath, readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { compileSourceRefactoring } from '../../scripts/operator/source_edit_replacements.mjs';
const hashObject = (format, kind, body) => createHash(format).update(`${kind} ${body.length}\0`).update(body).digest('hex');
const hex = b => Buffer.from(b).toString('hex');
const side = (format, bytes, mode = 0o100644, original = false) => ({ mode, bytes: Buffer.from(bytes),
  ...(original ? { blob: hashObject(format, 'blob', Buffer.from(bytes)) } : {}) });
function row(format, from, before, to, after, mode = 0o100644) {
  return { path_hex: hex(from), ...(to === null ? {} : { destination_hex: hex(to) }),
    before: before === null ? null : side(format, before, 0o100644, true), after: after === null ? null : side(format, after, mode) };
}
function git(root, args, input) {
  const r = spawnSync('git', ['-c', 'core.autocrlf=false', '-c', 'core.filemode=true', '-c', 'core.hooksPath=/dev/null', '-c', 'core.attributesFile=/dev/null', '-C', root, ...args], {
    input, timeout: 15000, maxBuffer: 8 * 1024 * 1024,
    env: { ...Object.fromEntries(Object.entries(process.env).filter(([name]) => !name.startsWith('GIT_'))),
      LC_ALL: 'C', GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: '/dev/null', GIT_ATTR_NOSYSTEM: '1',
      GIT_AUTHOR_NAME: 'Oracle', GIT_AUTHOR_EMAIL: 'oracle@example.invalid', GIT_COMMITTER_NAME: 'Oracle', GIT_COMMITTER_EMAIL: 'oracle@example.invalid',
      GIT_AUTHOR_DATE: '2000-01-01T00:00:00Z', GIT_COMMITTER_DATE: '2000-01-01T00:00:00Z' },
  });
  if (r.error) throw r.error;
  return r;
}
function ok(root, args, input) {
  const r = git(root, args, input); assert.equal(r.status, 0, `${args.join(' ')}: ${r.stderr.toString()}`); return r.stdout;
}
function images(rows) {
  const before = new Map(), after = new Map();
  const sibling = hex('untouched/sibling.bin'), body = Buffer.from([0, 255, 2]);
  before.set(sibling, { mode: 0o100755, bytes: body }); after.set(sibling, { mode: 0o100755, bytes: body });
  for (const r of rows) {
    if (r.before) before.set(r.path_hex, r.before);
    if (r.after) after.set(r.destination_hex ?? r.path_hex, r.after);
  }
  return { before, after };
}
function treeRoot(format, files) {
  const root = new Map();
  for (const [name, v] of files) {
    const parts = Buffer.from(name, 'hex').toString('latin1').split('/'); let tree = root;
    for (const part of parts.slice(0, -1)) { if (!tree.has(part)) tree.set(part, new Map()); tree = tree.get(part); }
    tree.set(parts.at(-1), v);
  }
  function tree(node) {
    const entries = [...node].map(([name, value]) => ({ name: Buffer.from(name, 'latin1'), directory: value instanceof Map, value }));
    entries.sort((a, b) => Buffer.compare(Buffer.concat([a.name, Buffer.from(a.directory ? '/' : '\0')]), Buffer.concat([b.name, Buffer.from(b.directory ? '/' : '\0')])));
    const body = Buffer.concat(entries.map(e => Buffer.concat([Buffer.from(`${e.directory ? '40000' : e.value.mode.toString(8)} `), e.name,
      Buffer.from([0]), Buffer.from(e.directory ? tree(e.value) : hashObject(format, 'blob', e.value.bytes), 'hex')])));
    return hashObject(format, 'tree', body);
  }
  return tree(root);
}
async function populate(root, format, files) {
  await mkdir(root); ok(root, ['init', '-q', '--template=', `--object-format=${format}`]);
  for (const [name, side] of files) {
    const raw = Buffer.from(name, 'hex'), slash = raw.lastIndexOf(47);
    if (slash >= 0) await mkdir(Buffer.concat([Buffer.from(root + '/'), raw.subarray(0, slash)]), { recursive: true });
    const filename = Buffer.concat([Buffer.from(root + '/'), raw]);
    await writeFile(filename, side.bytes); await chmod(filename, side.mode & 0o777);
  }
  ok(root, ['add', '--all']); ok(root, ['commit', '-q', '-m', 'fixture']);
  assert.equal(ok(root, ['write-tree']).toString().trim(), treeRoot(format, files));
}
function requireAbsentTargets(root, format, from, to) {
  const existing = new Set([...from.values()].map(v => hashObject(format, 'blob', v.bytes)));
  for (const v of to.values()) {
    const id = hashObject(format, 'blob', v.bytes);
    if (!existing.has(id)) assert.notEqual(git(root, ['cat-file', '-e', id]).status, 0, 'desired object must be absent before apply');
  }
}
for (const format of ['sha1', 'sha256']) for (const scenario of ['mixed', 'raw-edited', 'binary-modes', 'empty']) {
  test(`${format}: ${scenario} applies and reverses in independent repositories`, async () => {
    const home = await mkdtemp(join(await realpath(tmpdir()), 'fg-refactor-oracle-'));
    try {
      let rows;
      if (scenario === 'mixed') rows = [row(format, 'src/moved', 'old\nlast', 'lib/tool', 'new\r\nlast!', 0o100755),
        row(format, 'src/raw.bin', Buffer.from([0, 255, 1]), 'lib/raw.bin', Buffer.from([0, 255, 1])),
        row(format, 'delete', 'gone\n', null, null), row(format, 'create', null, null, 'born\n'),
        row(format, 'data', Buffer.from([0, 1, 2]), null, Buffer.from([0, 2, 3]))];
      if (scenario === 'raw-edited') rows = [row(format, Buffer.from([0xff, 32, 34, 92, 10]), 'old\r\n', Buffer.from([0xfe, 9, 13]), Buffer.from([255, 10]))];
      if (scenario === 'binary-modes') rows = [row(format, 'a', Buffer.from([0, 255]), 'b', Buffer.from([0, 255]), 0o100755)];
      if (scenario === 'empty') rows = [row(format, 'old', '', 'new', ''), row(format, 'another', null, null, '')];
      const r = compileSourceRefactoring(format, rows, { binary: 'delta-runs' }), { before, after } = images(rows);
      const patch = join(home, 'edit.patch'); await writeFile(patch, r.patch);
      for (const [direction, from, to] of [['forward', before, after], ['reverse', after, before]]) {
        const root = join(home, direction); await populate(root, format, from);
        requireAbsentTargets(root, format, from, to);
        ok(root, ['apply', '--index', '--binary', ...(direction === 'reverse' ? ['--reverse'] : []), patch]);
        assert.equal(ok(root, ['write-tree']).toString().trim(), treeRoot(format, to));
        for (const [name, side] of to) assert.deepEqual(await readFile(Buffer.concat([Buffer.from(root + '/'), Buffer.from(name, 'hex')])), side.bytes);
      }
    } finally { await rm(home, { recursive: true, force: true }); }
  });
}
for (const format of ['sha1', 'sha256']) test(`${format}: occupied destination refuses the entire batch in the oracle`, async () => {
  const home = await mkdtemp(join(await realpath(tmpdir()), 'fg-refactor-occupied-'));
  try {
    const rows = [row(format, 'a', 'before\n', null, 'after\n'), row(format, 'src', 'original\n', 'dest', 'moved\n')];
    const { before } = images(rows); before.set(hex('dest'), { mode: 0o100644, bytes: Buffer.from('occupied\n') });
    const root = join(home, 'repo'); await populate(root, format, before); const initial = ok(root, ['write-tree']);
    const patch = join(home, 'change.patch'); await writeFile(patch, compileSourceRefactoring(format, rows).patch);
    assert.notEqual(git(root, ['apply', '--index', patch]).status, 0);
    assert.deepEqual(ok(root, ['write-tree']), initial); assert.equal((await readFile(join(root, 'a'))).toString(), 'before\n');
  } finally { await rm(home, { recursive: true, force: true }); }
});
for (const format of ['sha1', 'sha256']) test(`${format}: actual private-plan CLI output applies and reverses independently`, async () => {
  const home = await mkdtemp(join(await realpath(tmpdir()), 'fg-refactor-cli-oracle-'));
  try {
    const rows = [row(format, 'src/tool', 'before\n', 'lib/tool', 'after\n', 0o100755),
      row(format, Buffer.from([0xff]), Buffer.from([0, 255]), Buffer.from([0xfe]), Buffer.from([0, 255])),
      row(format, 'obsolete', 'remove\n', null, null), row(format, 'created', null, null, 'added\n'),
      row(format, 'binary', Buffer.from([0, 2]), null, Buffer.from([0, 3]))];
    const plan = { schema: 'frankengit-source-refactoring-v1', object_format: format, changes: [] };
    for (const [i, r] of rows.entries()) {
      const edit = { path_hex: r.path_hex, ...(r.destination_hex ? { destination_hex: r.destination_hex } : {}), before: null, after: null };
      for (const name of ['before', 'after']) if (r[name]) {
        const filename = join(home, `${i}-${name}`); await writeFile(filename, r[name].bytes, { mode: 0o600 });
        edit[name] = { file: filename, mode: r[name].mode, ...(name === 'before' ? { blob: r.before.blob } : {}) };
      }
      if (r.destination_hex && r.before.bytes.equals(r.after.bytes)) delete edit.after.file;
      plan.changes.push(edit);
    }
    const input = join(home, 'plan.json'), patch = join(home, 'change.patch'); await writeFile(input, JSON.stringify(plan), { mode: 0o600 });
    const cli = new URL('../../scripts/fg_source_refactor.mjs', import.meta.url);
    const response = spawnSync(process.execPath, [fileURLToPath(cli), 'compile', '--plan-file', input, '--output', patch, '--binary', 'delta'], { timeout: 15000 });
    assert.equal(response.status, 0, response.stderr.toString());
    const receipt = JSON.parse(response.stdout), output = await readFile(patch);
    assert.equal(receipt.patch_sha256, createHash('sha256').update(output).digest('hex'));
    assert.equal(receipt.plan_sha256, createHash('sha256').update(await readFile(input)).digest('hex'));
    const { before, after } = images(rows);
    for (const [direction, from, to] of [['forward', before, after], ['reverse', after, before]]) {
      const root = join(home, direction); await populate(root, format, from); requireAbsentTargets(root, format, from, to);
      ok(root, ['apply', '--index', '--binary', ...(direction === 'reverse' ? ['--reverse'] : []), patch]);
      assert.equal(ok(root, ['write-tree']).toString().trim(), treeRoot(format, to));
    }
  } finally { await rm(home, { recursive: true, force: true }); }
});
