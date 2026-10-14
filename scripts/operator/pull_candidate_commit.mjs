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
