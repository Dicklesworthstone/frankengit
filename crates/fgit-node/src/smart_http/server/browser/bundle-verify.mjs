// Independent, read-only verification of portable Git bytes. This is not the
// node's admission engine: it never imports objects, consults ambient Git state,
// follows submodules, authenticates authors, or grants publication authority.
// Formats: git-scm.com/docs/{bundle-format,pack-format}; RFC 1950 and RFC 1951.
// No platform inflater is used: exact stream boundaries and pre-allocation
// resource accounting are part of this hostile-input verification boundary.
export const BUNDLE_VERIFY_LIMITS = Object.freeze({
  maxInputBytes: 16 * 1024 * 1024, maxHeaderBytes: 256 * 1024, maxRefs: 1024,
  maxObjects: 32768, maxObjectBytes: 16 * 1024 * 1024,
  maxExpandedBytes: 128 * 1024 * 1024, maxDeltaDepth: 64,
  maxWork: 256 * 1024 * 1024, timeoutMs: 30000,
});
export class BundleVerificationError extends Error {
  constructor(code) { super(`Git bundle verification refused: ${code}`); this.name = 'BundleVerificationError'; this.code = code; }
}
const refuse = code => { throw new BundleVerificationError(code); };
const encoder = new TextEncoder();
const hex = bytes => Array.from(bytes, byte => byte.toString(16).padStart(2, '0')).join('');
const ascii = bytes => {
  if (bytes.some(byte => byte > 127)) refuse('non_ascii_control_record');
  let text = ''; for (const byte of bytes) text += String.fromCharCode(byte); return text;
};
const kindNames = Object.freeze({ 1: 'commit', 2: 'tree', 3: 'blob', 4: 'tag' });
const hashName = format => format === 'sha1' ? 'SHA-1' : 'SHA-256';
function checkedOid(bytes, format) {
  const width = format === 'sha1' ? 40 : 64;
  if (bytes.length !== width || bytes.some(b => !((b >= 48 && b <= 57) || (b >= 65 && b <= 70) || (b >= 97 && b <= 102)))) refuse('invalid_object_identity');
  const id = ascii(bytes).toLowerCase(); if (/^0+$/.test(id)) refuse('zero_object_identity'); return id;
}
function reference(bytes) {
  if (!bytes.length || bytes.length > 4096) refuse('invalid_reference');
  const text = Array.from(bytes, byte => String.fromCharCode(byte)).join('');
  if (!text.startsWith('refs/') || bytes.some(b => b <= 32 || b === 127) || /[~^:?*\[\\]/.test(text) ||
      text.includes('..') || text.includes('@{') || text.endsWith('.') ||
      text.split('/').some(part => !part || part.startsWith('.') || part.endsWith('.lock'))) refuse('invalid_reference');
  return hex(bytes);
}
class Budget {
  constructor(options) {
    if (!options || typeof options !== 'object' || Array.isArray(options) ||
        Object.keys(options).some(key => !['limits', 'signal', 'checkpoint', 'cryptoImpl'].includes(key))) refuse('invalid_options');
    const limits = options.limits ?? {};
    if (!limits || typeof limits !== 'object' || Array.isArray(limits) || Object.keys(limits).some(key => !Object.hasOwn(BUNDLE_VERIFY_LIMITS, key))) refuse('invalid_limits');
    this.limits = { ...BUNDLE_VERIFY_LIMITS, ...limits };
    for (const [key, value] of Object.entries(this.limits)) {
      if (!Number.isSafeInteger(value) || value < 1 || value > BUNDLE_VERIFY_LIMITS[key]) refuse('invalid_limits');
    }
    this.signal = options.signal; this.checkpoint = options.checkpoint ?? (() => {});
    if (typeof this.checkpoint !== 'function' || (this.signal !== undefined && !(this.signal instanceof AbortSignal))) refuse('invalid_options');
    this.crypto = options.cryptoImpl ?? globalThis.crypto;
    if (!this.crypto?.subtle?.digest) refuse('crypto_unavailable');
    this.deadline = performance.now() + this.limits.timeoutMs;
    this.work = 0; this.expanded = 0; this.inflated = 0; this.reconstructed = 0; this.nextYield = 65536;
    this.check();
  }
  check() {
    if (this.signal?.aborted) refuse('cancelled');
    this.checkpoint();
    if (this.signal?.aborted) refuse('cancelled');
    if (performance.now() >= this.deadline) refuse('deadline');
  }
  spend(amount = 1) {
    this.work += amount;
    if (!Number.isSafeInteger(this.work) || this.work > this.limits.maxWork) refuse('work_limit');
  }
  allocate(size, reconstruction = false) {
    if (!Number.isSafeInteger(size) || size < 0 || size > this.limits.maxObjectBytes) refuse('object_size_limit');
    this.expanded += size;
    if (this.expanded > this.limits.maxExpandedBytes) refuse('expanded_byte_limit');
    if (reconstruction) this.reconstructed += size; else this.inflated += size;
    this.check(); return new Uint8Array(size);
  }
  async yield() {
    this.check();
    // Let aborts, page navigation and the deadline timer run even for a single
    // highly compressed object. Microtask-only awaits do not give that guarantee.
    await new Promise(resolve => setTimeout(resolve, 0));
    this.check(); this.nextYield = this.work + 65536;
  }
  async digest(bytes, format) {
    this.check(); this.spend(bytes.length);
    const value = new Uint8Array(await this.crypto.subtle.digest(hashName(format), bytes));
    this.check();
    if (value.length !== (format === 'sha1' ? 20 : 32)) refuse('invalid_digest_result');
    return hex(value);
  }
}
class Reader {
  constructor(bytes, start, end, budget) { this.bytes = bytes; this.at = start; this.end = end; this.budget = budget; }
  byte() { if (this.at >= this.end) refuse('truncated_pack'); this.budget.spend(); return this.bytes[this.at++]; }
  take(size) {
    if (size > this.end - this.at) refuse('truncated_pack');
    this.budget.spend(size); const value = this.bytes.subarray(this.at, this.at + size); this.at += size; return value;
  }
  uint32() { return this.byte() * 0x1000000 + this.byte() * 0x10000 + this.byte() * 0x100 + this.byte(); }
  size(first = null, bits = 7) {
    let byte = first ?? this.byte(), size = byte & ((1 << bits) - 1), scale = 2 ** bits;
    for (let count = 0; byte & 128; count++) {
      if (count >= 7) refuse('size_overflow');
      byte = this.byte(); size += (byte & 127) * scale;
      if (!Number.isSafeInteger(size) || size > this.budget.limits.maxObjectBytes) refuse('object_size_limit');
      scale *= 128;
    }
    if (size > this.budget.limits.maxObjectBytes) refuse('object_size_limit'); return size;
  }
}
class Bits {
  constructor(reader) { this.reader = reader; this.value = 0; this.count = 0; }
  read(count) {
    while (this.count < count) { this.value |= this.reader.byte() << this.count; this.count += 8; }
    const value = this.value & ((1 << count) - 1); this.value >>>= count; this.count -= count; return value;
  }
  align() { this.value = 0; this.count = 0; }
}
function huffman(lengths, budget, kind) {
  budget.spend(lengths.length * 2 + 15);
  const counts = new Uint16Array(16), first = new Uint16Array(16), offsets = new Uint16Array(16);
  let maximum = 0;
  for (const length of lengths) {
    if (length > 15) refuse('invalid_huffman_length');
    if (length) { counts[length]++; maximum = Math.max(maximum, length); }
  }
  if (!maximum) { if (kind === 'distance') return null; refuse('empty_huffman_tree'); }
  let left = 1, code = 0, index = 0;
  for (let length = 1; length <= 15; length++) {
    left = left * 2 - counts[length]; if (left < 0) refuse('oversubscribed_huffman_tree');
    code = (code + counts[length - 1]) * 2; first[length] = code;
    offsets[length] = index; index += counts[length];
  }
  if (left && (kind === 'lengths' || maximum !== 1)) refuse('incomplete_huffman_tree');
  const symbols = new Uint16Array(index), next = offsets.slice();
  for (let symbol = 0; symbol < lengths.length; symbol++) if (lengths[symbol]) symbols[next[lengths[symbol]]++] = symbol;
  return { counts, first, offsets, symbols, maximum };
}
function symbol(bits, tree, budget) {
  if (!tree) refuse('missing_distance_tree');
  let code = 0;
  for (let length = 1; length <= tree.maximum; length++) {
    budget.spend(); code = code * 2 + bits.read(1);
    const offset = code - tree.first[length];
    if (offset >= 0 && offset < tree.counts[length]) return tree.symbols[tree.offsets[length] + offset];
  }
  refuse('invalid_huffman_code');
}
const lengthBase = [3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258];
const lengthExtra = [0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0];
const distanceBase = [1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577];
const distanceExtra = [0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13];
function blockTrees(bits, kind, budget) {
  let literals, distances;
  if (kind === 1) {
    literals = new Uint8Array(288); distances = new Uint8Array(32).fill(5);
    literals.fill(8, 0, 144); literals.fill(9, 144, 256); literals.fill(7, 256, 280); literals.fill(8, 280);
  } else {
    const literalCount = bits.read(5) + 257, distanceCount = bits.read(5) + 1, codeCount = bits.read(4) + 4;
    if (literalCount > 286) refuse('invalid_literal_count');
    const order = [16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15], codeLengths = new Uint8Array(19);
    for (let i = 0; i < codeCount; i++) codeLengths[order[i]] = bits.read(3);
    const codeTree = huffman(codeLengths, budget, 'lengths'), values = new Uint8Array(literalCount + distanceCount);
    let at = 0;
    while (at < values.length) {
      const value = symbol(bits, codeTree, budget);
      if (value <= 15) values[at++] = value;
      else {
        if (value === 16 && at === 0) refuse('missing_repeated_code_length');
        const repeated = value === 16 ? values[at - 1] : 0;
        const count = value === 16 ? bits.read(2) + 3 : value === 17 ? bits.read(3) + 3 : bits.read(7) + 11;
        if (count > values.length - at) refuse('code_length_repeat_overflow');
        values.fill(repeated, at, at + count); at += count;
      }
    }
    literals = values.subarray(0, literalCount); distances = values.subarray(literalCount);
    if (!literals[256]) refuse('missing_end_of_block');
  }
  return [huffman(literals, budget, 'literal'), huffman(distances, budget, 'distance')];
}
async function inflate(reader, expected, budget) {
  const cmf = reader.byte(), flg = reader.byte();
  if ((cmf & 15) !== 8 || (cmf >> 4) > 7 || (cmf * 256 + flg) % 31 !== 0) refuse('invalid_zlib_header');
  if (flg & 32) refuse('zlib_dictionary_unsupported');
  const window = 2 ** ((cmf >> 4) + 8), out = budget.allocate(expected), bits = new Bits(reader);
  let at = 0, final = false;
  while (!final) {
    budget.spend(); final = bits.read(1) !== 0; const kind = bits.read(2);
    if (kind === 3) refuse('reserved_deflate_block');
    if (kind === 0) {
      bits.align(); const size = reader.byte() + reader.byte() * 256, inverse = reader.byte() + reader.byte() * 256;
      if ((size ^ inverse) !== 65535) refuse('stored_block_length_mismatch');
      if (size > out.length - at) refuse('inflated_size_mismatch');
      out.set(reader.take(size), at); at += size; budget.spend(size);
    } else {
      const [literals, distances] = blockTrees(bits, kind, budget);
      while (true) {
        const value = symbol(bits, literals, budget);
        if (value === 256) break;
        if (value < 256) {
          if (at === out.length) refuse('inflated_size_mismatch'); out[at++] = value;
        } else {
          if (value > 285) refuse('reserved_length_code');
          const index = value - 257, length = lengthBase[index] + bits.read(lengthExtra[index]);
          const distanceCode = symbol(bits, distances, budget);
          if (distanceCode > 29) refuse('reserved_distance_code');
          const distance = distanceBase[distanceCode] + bits.read(distanceExtra[distanceCode]);
          if (distance > at || distance > window) refuse('invalid_back_reference');
          if (length > out.length - at) refuse('inflated_size_mismatch');
          budget.spend(length);
          // Overlapping copies are defined byte-by-byte, not by a snapshot of
          // the source range (distance 1 may fill the whole output run).
          for (let n = 0; n < length; n++, at++) out[at] = out[at - distance];
        }
        if (budget.work >= budget.nextYield) await budget.yield();
      }
    }
    if (budget.work >= budget.nextYield) await budget.yield();
  }
  if (at !== expected) refuse('inflated_size_mismatch');
  bits.align(); const expectedAdler = reader.uint32();
  let a = 1, b = 0;
  for (let offset = 0; offset < out.length; offset += 5552) {
    const end = Math.min(out.length, offset + 5552);
    for (let i = offset; i < end; i++) { a += out[i]; b += a; }
    a %= 65521; b %= 65521; budget.spend(end - offset);
    if (budget.work >= budget.nextYield) await budget.yield();
  }
  if (((b * 65536 + a) >>> 0) !== expectedAdler) refuse('zlib_adler_mismatch');
  return out;
}
async function applyDelta(program, base, budget) {
  const reader = new Reader(program, 0, program.length, budget);
  if (reader.size() !== base.length) refuse('delta_base_size_mismatch');
  const size = reader.size(), out = budget.allocate(size, true); let at = 0;
  while (reader.at < reader.end) {
    const opcode = reader.byte(); if (!opcode) refuse('reserved_delta_opcode');
    if (opcode & 128) {
      let offset = 0, size = 0;
      for (let i = 0; i < 4; i++) if (opcode & (1 << i)) offset += reader.byte() * 2 ** (8 * i);
      for (let i = 0; i < 3; i++) if (opcode & (1 << (i + 4))) size += reader.byte() * 2 ** (8 * i);
      if (size === 0) size = 65536;
      if (offset > base.length || size > base.length - offset || size > out.length - at) refuse('delta_copy_out_of_bounds');
      for (let copied = 0; copied < size; copied += 32768) {
        const length = Math.min(32768, size - copied); budget.spend(length);
        out.set(base.subarray(offset + copied, offset + copied + length), at); at += length;
        if (budget.work >= budget.nextYield) await budget.yield();
      }
    } else {
      if (opcode > out.length - at) refuse('delta_insert_out_of_bounds');
      out.set(reader.take(opcode), at); at += opcode; budget.spend(opcode);
    }
    if (budget.work >= budget.nextYield) await budget.yield();
  }
  if (at !== out.length) refuse('delta_result_size_mismatch'); return out;
}
async function objectId(kind, body, format, budget) {
  const prefix = encoder.encode(`${kind} ${body.length}\0`), framed = new Uint8Array(prefix.length + body.length);
  framed.set(prefix); framed.set(body, prefix.length); return budget.digest(framed, format);
}
async function readBundle(input, options) {
  const budget = new Budget(options);
  if (!(input instanceof Uint8Array) || !input.length || input.length > budget.limits.maxInputBytes) refuse('input_byte_limit');
  // Own the complete input before the first asynchronous operation.
  const bytes = new Uint8Array(input); budget.spend(bytes.length); let cursor = 0, format = 'sha1', capability = false, records = 0, head = null;
  const line = () => {
    const start = cursor, end = Math.min(bytes.length, budget.limits.maxHeaderBytes);
    while (cursor < end && bytes[cursor] !== 10) cursor++;
    if (cursor === end) refuse('bundle_header_limit_or_truncation');
    budget.spend(cursor - start + 1); return bytes.subarray(start, cursor++);
  };
  const signature = ascii(line());
  if (!['# v2 git bundle', '# v3 git bundle'].includes(signature)) refuse('unsupported_bundle_version');
  const refs = new Map();
  while (true) {
    budget.check(); const row = line(); if (!row.length) break;
    if (row[0] === 64) {
      if (signature !== '# v3 git bundle' || capability || records) refuse('misplaced_bundle_capability');
      const value = ascii(row);
      if (!['@object-format=sha1', '@object-format=sha256'].includes(value)) refuse('unsupported_bundle_capability');
      format = value.slice(15); capability = true; continue;
    }
    if (row[0] === 45) refuse('prerequisites_not_self_contained');
    if (++records > budget.limits.maxRefs) refuse('reference_limit');
    const width = format === 'sha1' ? 40 : 64;
    if (row[width] !== 32 || row.length <= width + 1) refuse('invalid_bundle_reference');
    const id = checkedOid(row.subarray(0, width), format), name = row.subarray(width + 1);
    if (hex(name) === '48454144') { if (head !== null) refuse('duplicate_head'); head = id; }
    else { const path = reference(name); if (refs.has(path)) refuse('duplicate_reference'); refs.set(path, { ref_hex: path, object_id: id }); }
  }
  if (!refs.size) refuse('missing_direct_references');
  if (head !== null && ![...refs.values()].some(row => row.ref_hex.startsWith('726566732f68656164732f') && row.object_id === head)) refuse('detached_bundle_head');
  const headerBytes = cursor, pack = bytes.subarray(cursor), width = format === 'sha1' ? 20 : 32;
  if (pack.length < 12 + width) refuse('truncated_pack');
  const reader = new Reader(pack, 0, pack.length - width, budget);
  if (ascii(reader.take(4)) !== 'PACK' || reader.uint32() !== 2) refuse('unsupported_pack_version');
  const count = reader.uint32(); if (count > budget.limits.maxObjects) refuse('object_count_limit');
  const checksum = await budget.digest(pack.subarray(0, reader.end), format);
  if (checksum !== hex(pack.subarray(reader.end))) refuse('pack_checksum_mismatch');
  const objects = [], byOffset = new Map(), waitingIds = new Map(), waitingOffsets = new Map(), queue = [];
  const wait = (map, key, object) => { if (!map.has(key)) map.set(key, []); map.get(key).push(object); };
  for (let index = 0; index < count; index++) {
    budget.check(); const offset = reader.at, first = reader.byte(), type = (first >> 4) & 7, size = reader.size(first, 4);
    if (![1, 2, 3, 4, 6, 7].includes(type)) refuse('invalid_pack_object_type');
    let baseOffset = null, baseId = null;
    if (type === 6) {
      let byte = reader.byte(), distance = byte & 127;
      for (let n = 0; byte & 128; n++) {
        if (n >= 7 || distance >= offset) refuse('invalid_delta_offset');
        byte = reader.byte(); distance = (distance + 1) * 128 + (byte & 127);
      }
      baseOffset = offset - distance;
      if (!distance || !byOffset.has(baseOffset)) refuse('invalid_delta_offset');
    } else if (type === 7) baseId = hex(reader.take(width));
    const body = await inflate(reader, size, budget);
    const object = { offset, kind: kindNames[type] ?? null, body, id: null, depth: 0 };
    objects.push(object); byOffset.set(offset, object);
    if (type === 6) wait(waitingOffsets, baseOffset, object);
    else if (type === 7) wait(waitingIds, baseId, object);
    else queue.push(object);
    if (budget.work >= budget.nextYield) await budget.yield();
  }
  if (reader.at !== reader.end) refuse('pack_count_or_trailing_bytes');
  const byId = new Map(); let maximumDepth = 0, deltas = 0;
  // Resolve once per object, not repeated full-pack scans. REF_DELTA may precede
  // its base; OFS_DELTA must name an earlier exact object boundary. Missing and
  // cyclic dependencies never trigger an external fetch or ambient lookup.
  for (let at = 0; at < queue.length; at++) {
    budget.check(); const object = queue[at]; object.id = await objectId(object.kind, object.body, format, budget);
    if (byId.has(object.id)) refuse('duplicate_pack_object'); byId.set(object.id, object);
    const children = [...(waitingIds.get(object.id) ?? []), ...(waitingOffsets.get(object.offset) ?? [])];
    waitingIds.delete(object.id); waitingOffsets.delete(object.offset);
    for (const child of children) {
      child.depth = object.depth + 1;
      if (child.depth > budget.limits.maxDeltaDepth) refuse('delta_depth_limit');
      maximumDepth = Math.max(maximumDepth, child.depth); deltas++;
      child.body = await applyDelta(child.body, object.body, budget); child.kind = object.kind; queue.push(child);
    }
    if (budget.work >= budget.nextYield) await budget.yield();
  }
  if (queue.length !== count || waitingIds.size || waitingOffsets.size) refuse('unresolved_delta_base');
  for (const row of refs.values()) {
    const object = byId.get(row.object_id); if (!object) refuse('advertised_object_missing');
    if (row.ref_hex.startsWith('726566732f68656164732f') && object.kind !== 'commit') refuse('branch_target_not_commit');
  }
  const sha256 = await budget.digest(bytes, 'sha256'); budget.check();
  return { budget, byId, objects, summary: {
    profile: 'bounded-native-bundle-objects-v1', object_format: format, bytes: bytes.length, sha256,
    header_bytes: headerBytes, pack_checksum: checksum, pack_checksum_verified: true,
    pack_objects: count, objects_verified: true, object_closure_verified: false,
    delta_objects: deltas, maximum_delta_depth: maximumDepth,
    inflated_bytes: budget.inflated, reconstructed_bytes: budget.reconstructed,
    expanded_bytes: budget.expanded, advertised_head: head,
    refs: [...refs.values()].sort((a, b) => a.ref_hex < b.ref_hex ? -1 : 1),
    independently_authenticated: false, forge_state_verified: false,
  } };
}
export async function verifyGitBundleObjects(input, options = {}) {
  const { budget, summary } = await readBundle(input, options);
  budget.check(); return { ...summary, work: budget.work };
}
