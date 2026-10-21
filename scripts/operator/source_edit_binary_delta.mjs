// Explicit linear-time binary patch profile. Copy equal, nonoverlapping ends,
// insert the changed middle, and select by the complete encoded member cost.
// No hash search, compression engine, Git subprocess or admission authority.
import { fail } from './source_edit_wire.mjs';
import { binaryMemberCost } from './source_edit_binary_literal.mjs';
const MAX_BYTES = 1048576, CHECK_INTERVAL = 4096;
function sizeBytes(value) {
  const bytes = [];
  do { const low = value % 128; value = Math.floor(value / 128); bytes.push(low | (value ? 128 : 0)); } while (value);
  return Buffer.from(bytes);
}
function copyBytes(offset, length) {
  const bytes = [128];
  // Git's zero encoded copy size denotes exactly 64 KiB, never an empty copy.
  const size = length === 65536 ? 0 : length;
  for (let i = 0; i < 4; i++) {
    const byte = Math.floor(offset / 2 ** (8 * i)) % 256;
    if (byte) { bytes[0] |= 1 << i; bytes.push(byte); }
  }
  for (let i = 0; i < 3; i++) {
    const byte = Math.floor(size / 2 ** (8 * i)) % 256;
    if (byte) { bytes[0] |= 1 << (i + 4); bytes.push(byte); }
  }
  return Buffer.from(bytes);
}
// Inputs are owned by the replacement compiler; this synchronous plan borrows
// the literal body. A delta is allocated only when its full wire cost is lower.
// The returned cost includes the PROGRAM length for delta headers, not result
// length. The compiler must reserve both directions before framing either one.
export function planBinaryMember(base, target, check) {
  if (!Buffer.isBuffer(base) || !Buffer.isBuffer(target) || base.length > MAX_BYTES ||
      target.length > MAX_BYTES || typeof check !== 'function') fail('source_replacement_binary_input');
  check();
  const literal = { kind: 'literal', body: target, cost: binaryMemberCost('literal', target.length) };
  const common = Math.min(base.length, target.length);
  let prefix = 0, suffix = 0;
  while (prefix < common) {
    if (prefix % CHECK_INTERVAL === 0) check();
    if (base[prefix] !== target[prefix]) break;
    prefix++;
  }
  while (suffix < common - prefix) {
    if (suffix % CHECK_INTERVAL === 0) check();
    if (base[base.length - 1 - suffix] !== target[target.length - 1 - suffix]) break;
    suffix++;
  }
  check();
  const header = Buffer.concat([sizeBytes(base.length), sizeBytes(target.length)]);
  const first = prefix ? copyBytes(0, prefix) : Buffer.alloc(0);
  const last = suffix ? copyBytes(base.length - suffix, suffix) : Buffer.alloc(0);
  const middle = target.length - prefix - suffix;
  const length = header.length + first.length + middle + Math.ceil(middle / 127) + last.length;
  if (length > MAX_BYTES) return literal;
  const cost = binaryMemberCost('delta', length);
  // Ties remain literal. A smaller member may not consume more record budget.
  if (cost.bytes >= literal.cost.bytes || cost.records > literal.cost.records) return literal;
  const program = Buffer.alloc(length);
  let at = 0;
  for (const bytes of [header, first]) { bytes.copy(program, at); at += bytes.length; }
  for (let start = prefix, end = target.length - suffix; start < end;) {
    check(); const count = Math.min(127, end - start);
    program[at++] = count; target.copy(program, at, start, start + count);
    at += count; start += count;
  }
  last.copy(program, at); at += last.length;
  if (at !== length) fail('source_replacement_delta_accounting');
  check(); return { kind: 'delta', body: program, cost };
}
