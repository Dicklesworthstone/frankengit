// Test-only Git object/index oracle. Paths cross stdin as bytes, never through
// the host filesystem or text decoding: APFS cannot represent every Git name.
export function installIndex(git, edits, selected) {
  git(['read-tree', '--empty']);
  const entries = [];
  for (const row of edits) {
    const value = row[selected];
    if (value === null) continue;
    const oid = String(git(['hash-object', '-w', '--stdin'], value.bytes)).trim();
    entries.push(Buffer.concat([
      Buffer.from(`${value.mode.toString(8)} ${oid}\t`),
      Buffer.from(row.path_hex, 'hex'), Buffer.of(0),
    ]));
  }
  git(['update-index', '-z', '--index-info'], Buffer.concat(entries));
  return String(git(['write-tree'])).trim();
}
