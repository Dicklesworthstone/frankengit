// The branch picker uses hex: for the bytes of a complete Git ref. A colon
// cannot occur in a native ref, so the two input spellings are unambiguous.
const encoder = new TextEncoder();
const decoder = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });

export function sourceReference(value) {
  if (typeof value !== 'string') throw new Error('A complete native reference is required.');
  const encoded = value.startsWith('hex:');
  let bytes, hex;
  if (encoded) {
    hex = value.slice(4);
    if (!hex.length || hex.length > 2048 || hex.length % 2 || /[^0-9a-f]/.test(hex)) {
      throw new Error('Invalid hex bytes in native reference.');
    }
    bytes = Uint8Array.from(hex.match(/../g), pair => Number.parseInt(pair, 16));
  } else {
    if (value.length > 1024 || /[\uD800-\uDFFF]/u.test(value)) throw new Error('Invalid native reference.');
    bytes = encoder.encode(value);
    hex = Array.from(bytes, byte => byte.toString(16).padStart(2, '0')).join('');
  }
  const raw = String.fromCharCode(...bytes);
  if (bytes.length > 1024 || !raw.startsWith('refs/') || /[\x00-\x20\x7f~^:?*\[\\]/u.test(raw) ||
      raw.includes('..') || raw.includes('@{') || raw.endsWith('.') ||
      raw.split('/').some(part => !part || part.startsWith('.') || part.endsWith('.lock'))) {
    throw new Error('A complete native reference is required.');
  }
  let text = value;
  if (encoded) {
    try { text = decoder.decode(bytes); } catch { text = null; }
  }
  return { hex, text, encoded };
}

export function fullRef(value) { sourceReference(value); return value; }
export function referenceHex(value) { return sourceReference(value).hex; }
export function referenceField(name, value) {
  const ref = sourceReference(value);
  return ref.encoded ? { [name + '_hex']: ref.hex } : { [name]: ref.text };
}
