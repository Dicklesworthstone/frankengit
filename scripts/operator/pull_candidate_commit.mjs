// Pure byte-level binding for native merge/squash commit construction.
// Authority and Git semantics remain native; this only cross-checks one retained report.
export function candidateCommitMatches({ bodyHex, format, tree, targetTip, sourceTip, method, metadata }) {
  if (!['sha1', 'sha256'].includes(format) || !['merge-commit', 'squash'].includes(method) ||
      typeof bodyHex !== 'string' || bodyHex.length % 2 || !/^[0-9a-f]*$/.test(bodyHex)) return false;
  const width = format === 'sha1' ? 40 : 64, oid = value => typeof value === 'string' &&
    new RegExp(`^[0-9a-f]{${width}}$`).test(value) && !/^0+$/.test(value);
  if (![tree, targetTip, sourceTip].every(oid) || !metadata || typeof metadata !== 'object' || Array.isArray(metadata) ||
      typeof metadata.author !== 'string' || typeof metadata.committer !== 'string' ||
      typeof metadata.timestamp !== 'string' || !/^(0|[1-9][0-9]*)$/.test(metadata.timestamp) ||
      typeof metadata.message !== 'string') return false;
  const incoming = method === 'merge-commit' ? `parent ${sourceTip}\n` : '';
  const prefix = `tree ${tree}\nparent ${targetTip}\n${incoming}author ${metadata.author} ${metadata.timestamp} +0000\ncommitter ${metadata.committer} ${metadata.timestamp} +0000\n\n`;
  const expected = Buffer.concat([Buffer.from(prefix, 'utf8'), Buffer.from(metadata.message, 'utf8')]);
  return Buffer.from(bodyHex, 'hex').equals(expected);
}

// The native rebaser preserves original authors, encodings and arbitrary message
// bytes. Only its newly supplied committer line is ours to cross-bind here; the
// shared series inspector owns commit identity, tree and parent verification.
export function rebaseCommitterMatches(bodyHex, metadata) {
  if (typeof bodyHex !== 'string' || !bodyHex.length || bodyHex.length > 4 * 1024 * 1024 ||
      bodyHex.length % 2 || !/^[0-9a-f]+$/.test(bodyHex) ||
      typeof metadata?.committer !== 'string' || typeof metadata?.timestamp !== 'string' ||
      !/^[1-9][0-9]*$/.test(metadata.timestamp)) return false;
  const body = Buffer.from(bodyHex, 'hex'), prefix = Buffer.from('committer ');
  const expected = Buffer.from(`committer ${metadata.committer} ${metadata.timestamp} +0000`);
  let count = 0, start = 0;
  while (start < body.length) {
    const end = body.indexOf(10, start);
    if (end < 0) return false;
    if (end === start) return count === 1;
    const line = body.subarray(start, end);
    if (line.subarray(0, prefix.length).equals(prefix)) {
      if (++count !== 1 || !line.equals(expected)) return false;
    }
    start = end + 1;
  }
  return false;
}
