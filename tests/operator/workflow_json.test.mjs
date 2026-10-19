import test from 'node:test';
import assert from 'node:assert/strict';
import { parseJson } from '../../scripts/operator/workflow_watch_io.mjs';

const parse = text => parseJson(Buffer.from(text));
for (const text of [
  '{"authoritative_check":true,"authoritative_check":false}',
  '{"job":{"outcome":"failed","outcome":"succeeded"}}',
  '{"artifacts":[{"payload_bytes":9,"payload_bytes":0}]}',
  '{"a":1,"\\u0061":2}', '{"\\ud83d\\ude00":1,"😀":2}',
  '{"__proto__":1,"__proto__":2}', '{"x":1,"x":1}',
]) test(`duplicate member refuses: ${text}`, () => assert.throws(() => parse(text), /Duplicate JSON/));

for (const text of [
  '1.0000000000000001', '1e-999', '9007199254740991.1',
  '-9007199254740991.1', '9007199254740992', '-9007199254740992',
  '1e999999999999999999999', '1e-999999999999999999999', '12.5',
]) test(`inexact counter refuses: ${text}`, () => assert.throws(() => parse(text), /Inexact JSON/));

for (const text of [
  '0', '-0', '1', '-1', '1.0', '1e3', '1000e-3', '0.001e3',
  '9007199254740991', '-9007199254740991', '90071992547409910e-1',
  '0e999999999999999999999', '0.000000000000000000',
  '{"x":1,"child":{"x":2},"rows":[{"x":3},{"x":4}]}',
  '{"__proto__":{"polluted":true},"constructor":4}',
  '{"escaped\\\"key": "brace } and \\ backslash", "x":1}'.replace('and \\ backslash', 'and \\\\ backslash'),
]) test(`exact JSON preserved: ${text}`, () => assert.deepEqual(parse(text), JSON.parse(text)));

test('prototype-named members remain data and never pollute prototypes', () => {
  const record = parse('{"__proto__":{"polluted":true}}');
  assert.equal(Object.hasOwn(record, '__proto__'), true);
  assert.equal({}.polluted, undefined);
});
test('container depth boundary is enforced before parsing', () => {
  assert.deepEqual(parse('['.repeat(128) + '0' + ']'.repeat(128)), JSON.parse('['.repeat(128) + '0' + ']'.repeat(128)));
  assert.throws(() => parse('['.repeat(129) + '0' + ']'.repeat(129)), /over-depth/);
  assert.throws(() => parse('{"x":'.repeat(129) + '0' + '}'.repeat(129)), /over-depth/);
});
test('UTF-8, size and byte-order-mark refusals remain strict', () => {
  assert.throws(() => parseJson(Buffer.from([0xff])));
  assert.throws(() => parse('\ufeff{}'));
  assert.throws(() => parseJson(Buffer.from('{}'), 1));
  assert.deepEqual(parseJson(Buffer.from('{}'), 2), {});
  for (const bound of [NaN, Infinity, -1, 1.5]) assert.throws(() => parseJson(Buffer.from('0'), bound));
});
test('malformed grammar cannot escape the structural pass', () => {
  for (const text of ['', ' ', '01', '+1', '--1', '1.', '.1', '1e', '[1,]', '{"a":1,}',
    '{"a" 1}', '{"a":}', 'true false', 'null0', '"\\q"', '"\\u12xx"', '"unterminated',
    '"raw\nnewline"', '[}', '{]', 'undefined', 'NaN', 'Infinity']) assert.throws(() => parse(text), text);
});
test('large decimal tokens are bounded without exponent-sized allocation', () => {
  assert.equal(parse('1' + '0'.repeat(10000) + 'e-10000'), 1);
  assert.throws(() => parse('1' + '0'.repeat(10000)), /Inexact JSON/);
});
test('deterministic valid corpus preserves JSON.parse values', () => {
  let state = 123456789;
  const next = () => { state = (Math.imul(state, 1664525) + 1013904223) >>> 0; return state; };
  function value(depth = 0) {
    const n = next();
    if (depth < 6 && n % 5 === 0) return [value(depth + 1), value(depth + 1)];
    if (depth < 6 && n % 5 === 1) return { [String(n)]: value(depth + 1), 'quote"\\😀': value(depth + 1) };
    return [null, n % 2 === 0, n - 2147483648, `raw ${n} } \\ " \t 😀`][n % 4];
  }
  for (let i = 0; i < 2000; i++) { const original = value(); assert.deepEqual(parse(JSON.stringify(original)), original); }
});
