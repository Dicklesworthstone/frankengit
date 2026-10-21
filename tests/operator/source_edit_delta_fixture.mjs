// Independent test-only readers and a cold Git object/index oracle. The wanted
// image is never written into the oracle before apply, even for reverse tests.
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { inflateSync } from 'node:zlib';
import { blob, hex } from './source_edit_binary_fixture.mjs';
export function replayDelta(base, program) {
  let at = 0;
  const size = () => {
    let value = 0n, shift = 0n, byte;
    do { assert.ok(at < program.length && shift <= 28n); byte = program[at++];
      value |= BigInt(byte & 127) << shift; shift += 7n; } while (byte & 128);
    assert.ok(value <= 1048576n); return Number(value);
  };
  assert.equal(size(), base.length);
  const expected = size(), parts = [], instructions = []; let total = 0;
  while (at < program.length) {
    const opcode = program[at++]; assert.notEqual(opcode, 0);
    if (opcode & 128) {
      let offset = 0n, count = 0n;
      for (let i = 0; i < 4; i++) if (opcode & (1 << i)) {
        assert.ok(at < program.length); offset |= BigInt(program[at++]) << BigInt(i * 8);
      }
      for (let i = 0; i < 3; i++) if (opcode & (1 << (i + 4))) {
        assert.ok(at < program.length); count |= BigInt(program[at++]) << BigInt(i * 8);
      }
      if (count === 0n) count = 65536n;
      assert.ok(offset + count <= BigInt(base.length)); total += Number(count);
      parts.push(base.subarray(Number(offset), Number(offset + count)));
      instructions.push({ kind: 'copy', offset: Number(offset), count: Number(count), opcode });
    } else {
      assert.ok(at + opcode <= program.length); total += opcode;
      parts.push(program.subarray(at, at + opcode)); at += opcode;
      instructions.push({ kind: 'insert', count: opcode });
    }
    assert.ok(total <= expected);
  }
  assert.equal(total, expected);
  return { body: Buffer.concat(parts), instructions };
}
export function decodeMember(lines, base) {
  const header = /^(literal|delta) (0|[1-9][0-9]*)\n$/.exec(lines[0]); assert.ok(header);
  assert.equal(lines.at(-1), '\n');
  const alphabet = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!#$%&()*+-;<=>?@^_`{|}~';
  const packed = lines.slice(1, -1).map(line => {
    const letter = line.charCodeAt(0), count = letter <= 90 ? letter - 64 : letter - 70;
    assert.ok(count >= 1 && count <= 52); assert.equal(line.length, 2 + Math.ceil(count / 4) * 5);
    const bytes = [];
    for (let at = 1; at < line.length - 1; at += 5) {
      let value = 0n;
      for (const c of line.slice(at, at + 5)) { assert.ok(alphabet.includes(c)); value = value * 85n + BigInt(alphabet.indexOf(c)); }
      assert.ok(value <= 0xffffffffn);
      bytes.push(...[24n, 16n, 8n, 0n].map(shift => Number((value >> shift) & 255n)));
    }
    assert.ok(bytes.slice(count).every(byte => byte === 0));
    return Buffer.from(bytes.slice(0, count));
  });
  const framed = Buffer.concat(packed), inflated = inflateSync(framed, { info: true });
  assert.equal(inflated.engine.bytesWritten, framed.length);
  assert.equal(inflated.buffer.length, Number(header[2]));
  return header[1] === 'literal' ? { body: inflated.buffer, instructions: [] } : replayDelta(base, inflated.buffer);
}
export function coldOracle(format, changes, patch, reverse = false, refused = false) {
  const dir = mkdtempSync(join(tmpdir(), 'fg-delta-cold-'));
  try {
    const env = { ...process.env };
    for (const key of Object.keys(env)) if (key.startsWith('GIT_')) delete env[key];
    Object.assign(env, { GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: '/dev/null', GIT_ATTR_NOSYSTEM: '1' });
    const git = (args, input) => execFileSync('git', ['-C', dir, ...args], { input, timeout: 15000, maxBuffer: 4 * 1024 * 1024,
      stdio: ['pipe', 'pipe', 'pipe'], env });
    const id = (args, body) => git(args, body).toString().trim();
    git(['init', '--quiet', `--object-format=${format}`]);
    const sibling = { path_hex: hex('untouched'), mode: 0o100644, bytes: Buffer.from('unselected\n') };
    const entries = side => [sibling, ...changes.filter(r => r[side]).map(r => ({ path_hex: r.path_hex, ...r[side] }))];
    const before = entries(reverse ? 'after' : 'before'), after = entries(reverse ? 'before' : 'after');
    git(['update-index', '-z', '--index-info'], Buffer.concat(before.map(row => Buffer.concat([
      Buffer.from(`${row.mode.toString(8)} ${id(['hash-object', '-w', '--stdin'], row.bytes)}\t`), Buffer.from(row.path_hex, 'hex'), Buffer.from([0])]))));
    const oldTree = id(['write-tree']);
    const present = new Set(before.map(row => blob(row.bytes, format)));
    for (const row of after) if (!present.has(blob(row.bytes, format))) {
      assert.throws(() => git(['cat-file', '-e', blob(row.bytes, format)]), 'wanted bytes must not exist before apply');
    }
    const args = ['apply', '--cached', '--unidiff-zero', ...(reverse ? ['--reverse'] : []), '-'];
    if (refused) {
      assert.throws(() => git(args, patch)); assert.equal(id(['write-tree']), oldTree); return;
    }
    git(args, patch);
    const actual = git(['ls-files', '--stage', '-z']).toString('latin1').split('\0').filter(Boolean).map(row => {
      const tab = row.indexOf('\t'), [mode, object, stage] = row.slice(0, tab).split(' '); assert.equal(stage, '0');
      return { path_hex: Buffer.from(row.slice(tab + 1), 'latin1').toString('hex'), mode: parseInt(mode, 8), object };
    }).sort((a, b) => a.path_hex < b.path_hex ? -1 : 1);
    const wanted = after.map(row => ({ path_hex: row.path_hex, mode: row.mode, object: blob(row.bytes, format) }))
      .sort((a, b) => a.path_hex < b.path_hex ? -1 : 1);
    assert.deepEqual(actual, wanted);
    for (const row of after) assert.deepEqual(git(['cat-file', 'blob', blob(row.bytes, format)]), row.bytes);
  } finally { rmSync(dir, { recursive: true, force: true }); }
}
