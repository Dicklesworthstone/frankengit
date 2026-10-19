// Validate custody before JSON.parse can discard duplicate members or round
// counters. No decoded value here is authentication or independent attestation.
const MAX_DEPTH = 128;
const NUMBER = /-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/y;
const MAX_COUNTER = 9007199254740991n;
const refuse = () => { throw new Error('Invalid or over-depth custody JSON.'); };

function exactCounter(token) {
  const parts = /^-?(\d+)(?:\.(\d+))?(?:[eE]([+-]?\d+))?$/.exec(token);
  const fractional = parts[2] ?? '';
  let digits = `${parts[1]}${fractional}`.replace(/^0+/, '');
  if (!digits) return;
  const trimmed = digits.replace(/0+$/, '');
  const exponent = Number(parts[3] ?? 0);
  const scale = exponent - fractional.length + digits.length - trimmed.length;
  digits = trimmed;
  // Bound before BigInt conversion or exponentiation; input size, not a caller's
  // numeric exponent, bounds work. Integral decimal/exponent notation is valid.
  if (!Number.isSafeInteger(exponent) || scale < 0 || digits.length + scale > 16 ||
      BigInt(digits) * (10n ** BigInt(scale)) > MAX_COUNTER) {
    throw new Error('Inexact JSON counters are not supported.');
  }
}

export function parseExactJson(text) {
  if (typeof text !== 'string') refuse();
  let cursor = 0;
  function whitespace() {
    while (cursor < text.length && [9, 10, 13, 32].includes(text.charCodeAt(cursor))) cursor++;
  }
  function quoted(key = false) {
    const start = cursor++;
    while (cursor < text.length) {
      const character = text[cursor++];
      if (character === '"') return key ? JSON.parse(text.slice(start, cursor)) : undefined;
      if (character === '\\') cursor++;
    }
    refuse();
  }
  function value(depth) {
    whitespace();
    const character = text[cursor];
    if (character === '"') { quoted(); return; }
    if (character === '{' || character === '[') {
      if (depth === MAX_DEPTH) refuse();
      const map = character === '{', end = map ? '}' : ']';
      const seen = map ? new Set() : null;
      cursor++; whitespace();
      if (text[cursor] === end) { cursor++; return; }
      while (cursor < text.length) {
        if (map) {
          if (text[cursor] !== '"') refuse();
          const key = quoted(true);
          if (seen.has(key)) throw new Error('Duplicate JSON object member in custody input.');
          seen.add(key); whitespace();
          if (text[cursor++] !== ':') refuse();
        }
        value(depth + 1); whitespace();
        if (text[cursor] === end) { cursor++; return; }
        if (text[cursor++] !== ',') refuse();
        whitespace();
      }
      refuse();
    }
    for (const literal of ['true', 'false', 'null']) {
      if (text.startsWith(literal, cursor)) { cursor += literal.length; return; }
    }
    NUMBER.lastIndex = cursor;
    const number = NUMBER.exec(text);
    if (!number) refuse();
    cursor = NUMBER.lastIndex;
    exactCounter(number[0]);
  }
  value(0); whitespace();
  if (cursor !== text.length) refuse();
  // This final parser validates escapes, control characters and all remaining
  // lexical details. The structural pass never rewrites the retained bytes.
  return JSON.parse(text);
}
