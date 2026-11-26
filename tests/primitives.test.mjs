import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  HookVerifyError,
  ERROR_CODES,
  verify,
  defineProvider,
  registerProvider,
  getProvider,
  listProviders,
  helpers,
} from '../src/index.mjs';
import { expectCode, hexHmac, FIXED_NOW, clock } from './helpers.mjs';

test('error object has a stable code and JSON shape', () => {
  const error = new HookVerifyError('INVALID_HEADER', 'bad header', { header: 'x-test' });
  assert.equal(error.name, 'HookVerifyError');
  assert.equal(error.code, 'INVALID_HEADER');
  assert.deepEqual(error.toJSON(), {
    name: 'HookVerifyError',
    code: 'INVALID_HEADER',
    message: 'bad header',
    details: { header: 'x-test' },
  });
  assert.ok(error instanceof Error);
});

test('every documented error code is exported', () => {
  const expected = [
    'INVALID_ARGUMENT', 'INVALID_BODY', 'MISSING_HEADER', 'INVALID_HEADER',
    'INVALID_SECRET', 'INVALID_SIGNATURE', 'SIGNATURE_MISMATCH',
    'TIMESTAMP_MISSING', 'TIMESTAMP_INVALID', 'TIMESTAMP_OUT_OF_TOLERANCE',
    'REPLAYED_DELIVERY', 'UNKNOWN_PROVIDER', 'PROVIDER_ERROR',
  ];
  for (const code of expected) assert.equal(ERROR_CODES[code], code);
  assert.equal(Object.keys(ERROR_CODES).length, expected.length);
});

test('provider registry lists all seven built-ins', () => {
  const names = listProviders();
  assert.deepEqual(names, [
    'discord', 'github', 'linear', 'shopify', 'slack',
    'standard-webhooks', 'stripe', 'svix',
  ]);
  for (const name of names) {
    assert.equal(getProvider(name).name, name);
    assert.equal(typeof getProvider(name).verify, 'function');
  }
});

test('defineProvider freezes adapters and validates definitions', () => {
  const provider = defineProvider({
    name: 'unit-test-provider',
    description: 'tests only',
    requiredHeaders: ['x-unit'],
    verify: () => ({ secretIndex: 0 }),
  });
  assert.ok(Object.isFrozen(provider));
  assert.equal(provider.name, 'unit-test-provider');
  assert.deepEqual(provider.requiredHeaders, ['x-unit']);
  expectCode(() => defineProvider({ name: 'Bad Name', verify: () => ({}) }), 'INVALID_ARGUMENT');
  expectCode(() => defineProvider({ name: 'ok', verify: 'not a function' }), 'INVALID_ARGUMENT');
  expectCode(() => defineProvider({ name: 'ok', verify: () => ({}), requiredHeaders: [7] }), 'INVALID_ARGUMENT');
});

test('registerProvider rejects duplicates and invalid providers', () => {
  const provider = defineProvider({ name: 'custom-once', verify: () => ({}) });
  registerProvider(provider);
  assert.equal(getProvider('custom-once'), provider);
  expectCode(() => registerProvider(provider), 'INVALID_ARGUMENT');
  expectCode(() => registerProvider({ name: 'bad-two' }), 'INVALID_ARGUMENT');
  expectCode(() => getProvider('does-not-exist'), 'UNKNOWN_PROVIDER');
});

test('strict hex decoder rejects non-canonical input', () => {
  assert.equal(helpers.decodeHex('00ff').toString('hex'), '00ff');
  assert.equal(helpers.decodeHex('AABB').toString('hex'), 'aabb');
  for (const bad of ['', '0', '0g', 'zz', '0x1234', '00 11', '00\n']) {
    expectCode(() => helpers.decodeHex(bad), 'INVALID_SIGNATURE');
  }
  expectCode(() => helpers.decodeHex(null), 'INVALID_SIGNATURE');
  expectCode(() => helpers.decodeHex(12), 'INVALID_SIGNATURE');
});

test('strict base64 decoder rejects padding and alphabet garbage', () => {
  assert.equal(helpers.decodeBase64('YWJj').toString(), 'abc');
  assert.equal(helpers.decodeBase64('YWJjZA==').toString(), 'abcd');
  assert.equal(helpers.decodeBase64('AAAA').length, 3);
  assert.equal(helpers.decodeBase64('YQ==').toString(), 'a');
  for (const bad of ['', 'YQ', 'YQ===', 'YWI', 'YWJjZA=', 'YWJjZA===', 'YW Jj', 'YWJj\n', '_-__', 'YQ==AAAA']) {
    expectCode(() => helpers.decodeBase64(bad), 'INVALID_SIGNATURE');
  }
  // Non-zero pad bits: "Zh==" decodes to 0x66 but canonical base64 is "Zg==".
  expectCode(() => helpers.decodeBase64('Zh=='), 'INVALID_SIGNATURE');
  expectCode(() => helpers.decodeBase64(123), 'INVALID_SIGNATURE');
});

test('constantTimeEqual compares decoded bytes without string comparison', () => {
  const a = Buffer.from('0011aa', 'hex');
  assert.equal(helpers.constantTimeEqual(a, Buffer.from('0011aa', 'hex')), true);
  assert.equal(helpers.constantTimeEqual(a, Buffer.from('0011ab', 'hex')), false);
  assert.equal(helpers.constantTimeEqual(a, Buffer.from('0011aabb', 'hex')), false);
  assert.equal(helpers.constantTimeEqual(Buffer.alloc(0), Buffer.alloc(0)), true);
  assert.equal(helpers.constantTimeEqual(Buffer.alloc(0), a), false);
  expectCode(() => helpers.constantTimeEqual('a', 'a'), 'INVALID_ARGUMENT');
});

test('hex signature case is normalized before comparison', () => {
  const secret = 'case-secret';
  const body = 'payload';
  const lower = hexHmac(secret, body);
  const upper = lower.toUpperCase();
  assert.notEqual(lower, upper);
  assert.equal(helpers.constantTimeEqual(Buffer.from(lower, 'hex'), Buffer.from(upper, 'hex')), true);
});

test('body normalization accepts Buffer, Uint8Array and UTF-8 string', () => {
  assert.equal(helpers.normalizeBody(Buffer.from('abc')).toString(), 'abc');
  assert.equal(helpers.normalizeBody(new Uint8Array([97, 98, 99])).toString(), 'abc');
  assert.equal(helpers.normalizeBody('abc').toString(), 'abc');
  assert.equal(helpers.normalizeBody('é').toString('hex'), 'c3a9');
  const array = new Uint8Array([97, 98, 99, 100, 101]);
  assert.equal(helpers.normalizeBody(array.subarray(1, 4)).toString(), 'bcd');
});

test('parsed JSON objects and other invalid bodies are rejected loudly', () => {
  for (const bad of [{ a: 1 }, [1, 2], 42, true, null, undefined]) {
    expectCode(() => helpers.normalizeBody(bad), 'INVALID_BODY');
  }
});

test('header normalization lowercases keys and accepts Map, Headers-like and objects', () => {
  const fromObject = helpers.normalizeHeaders({ 'X-Test': 'one' });
  assert.deepEqual(fromObject.get('x-test'), ['one']);
  const fromMap = helpers.normalizeHeaders(new Map([['X-A', ['1', '2']]]));
  assert.deepEqual(fromMap.get('x-a'), ['1', '2']);
  const headersLike = {
    get: () => undefined,
    forEach(cb) { cb('v', 'X-LIKE'); },
  };
  assert.deepEqual(helpers.normalizeHeaders(headersLike).get('x-like'), ['v']);
  expectCode(() => helpers.normalizeHeaders(null), 'INVALID_ARGUMENT');
  expectCode(() => helpers.normalizeHeaders({ 'x-bad': 1 }), 'INVALID_HEADER');
});

test('timestamp parser accepts only canonical positive integers', () => {
  assert.equal(helpers.parseTimestampSeconds('1700000000'), 1_700_000_000_000);
  assert.equal(helpers.parseTimestampSeconds('1'), 1000);
  for (const bad of ['0', '-1', '1.5', '01', '+1', ' 1', '1 ', '1e3', 'Infinity', '999999999999999999999', '', 'abc']) {
    expectCode(() => helpers.parseTimestampSeconds(bad), 'TIMESTAMP_INVALID');
  }
});

test('deliveryKey hashes identifiers without exposing them', () => {
  const key = helpers.deliveryKey('github', 'delivery-123');
  assert.ok(key.startsWith('github:'));
  assert.equal(key.length, 7 + 64);
  assert.ok(!key.includes('delivery-123'));
  assert.notEqual(helpers.deliveryKey('github', 'a'), helpers.deliveryKey('github', 'b'));
});

test('clock injection is respected and validated', () => {
  const body = 'clock-body';
  const result = verify('github', body, { 'x-hub-signature-256': `sha256=${hexHmac('s', body)}` }, {
    secret: 's', now: clock(FIXED_NOW),
  });
  assert.equal(result.timestamp, null);
  expectCode(() => verify('github', body, { 'x-hub-signature-256': `sha256=${hexHmac('s', body)}` }, {
    secret: 's', now: 'not a function',
  }), 'INVALID_ARGUMENT');
});
