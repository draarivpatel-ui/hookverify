import { test } from 'node:test';
import assert from 'node:assert/strict';
import { verify, verifyAsync, MemoryReplayStore, HookVerifyError } from '../src/index.mjs';
import { SECRET, FIXED_NOW, clock, hexHmac, expectCode, expectCodeAsync } from './helpers.mjs';

const opts = (overrides = {}) => ({ secret: SECRET, now: clock(), ...overrides });
const githubHeaders = (body) => ({ 'x-hub-signature-256': `sha256=${hexHmac(SECRET, body)}` });

test('MemoryReplayStore validates constructor options', () => {
  assert.equal(new MemoryReplayStore().maxEntries, 10000);
  assert.equal(new MemoryReplayStore().ttlSeconds, 600);
  for (const bad of [{ maxEntries: 0 }, { maxEntries: 1.5 }, { maxEntries: 1000001 }, { maxEntries: '10' }]) {
    expectCode(() => new MemoryReplayStore(bad), 'INVALID_ARGUMENT');
  }
  for (const bad of [{ ttlSeconds: 0 }, { ttlSeconds: 1.5 }, { ttlSeconds: -1 }, { ttlSeconds: '10' }]) {
    expectCode(() => new MemoryReplayStore(bad), 'INVALID_ARGUMENT');
  }
  expectCode(() => new MemoryReplayStore(null), 'INVALID_ARGUMENT');
});

test('MemoryReplayStore records keys once and exposes size and has()', () => {
  const store = new MemoryReplayStore({ ttlSeconds: 60 });
  assert.equal(store.checkAndRecord('k1', FIXED_NOW), true);
  assert.equal(store.checkAndRecord('k1', FIXED_NOW + 1000), false);
  assert.equal(store.has('k1', FIXED_NOW), true);
  assert.equal(store.size, 1);
  assert.equal(store.checkAndRecord('k2', FIXED_NOW), true);
  assert.equal(store.size, 2);
  expectCode(() => store.checkAndRecord('', FIXED_NOW), 'INVALID_ARGUMENT');
  expectCode(() => store.checkAndRecord('k', 'bad'), 'INVALID_ARGUMENT');
});

test('MemoryReplayStore expires keys after TTL', () => {
  const store = new MemoryReplayStore({ ttlSeconds: 10 });
  assert.equal(store.checkAndRecord('ttl', FIXED_NOW), true);
  assert.equal(store.has('ttl', FIXED_NOW + 9999), true);
  assert.equal(store.has('ttl', FIXED_NOW + 10000), false);
  assert.equal(store.size, 0);
  assert.equal(store.checkAndRecord('ttl', FIXED_NOW + 10000), true);
});

test('MemoryReplayStore prune() and clear() release expired entries', () => {
  const store = new MemoryReplayStore({ ttlSeconds: 5 });
  store.checkAndRecord('a', FIXED_NOW);
  store.checkAndRecord('b', FIXED_NOW);
  assert.equal(store.prune(FIXED_NOW), 0);
  assert.equal(store.prune(FIXED_NOW + 5000), 2);
  assert.equal(store.size, 0);
  store.checkAndRecord('c', FIXED_NOW);
  store.clear();
  assert.equal(store.size, 0);
  assert.equal(store.has('c', FIXED_NOW), false);
});

test('MemoryReplayStore is bounded by maxEntries under flood (DoS cap)', () => {
  const store = new MemoryReplayStore({ maxEntries: 16, ttlSeconds: 1000 });
  for (let i = 0; i < 100000; i += 1) {
    store.checkAndRecord(`flood-${i}`, FIXED_NOW);
  }
  assert.equal(store.size, 16);
  // The 16 newest keys remain; the oldest were evicted in FIFO order.
  assert.equal(store.has('flood-99999', FIXED_NOW), true);
  assert.equal(store.has('flood-0', FIXED_NOW), false);
});

test('MemoryReplayStore behaves as LRU on re-check', () => {
  const store = new MemoryReplayStore({ maxEntries: 3, ttlSeconds: 1000 });
  store.checkAndRecord('a', FIXED_NOW);
  store.checkAndRecord('b', FIXED_NOW);
  store.checkAndRecord('c', FIXED_NOW);
  store.checkAndRecord('a', FIXED_NOW + 1);
  store.checkAndRecord('d', FIXED_NOW + 2);
  assert.equal(store.has('a', FIXED_NOW), true);
  assert.equal(store.has('b', FIXED_NOW), false);
  assert.equal(store.has('c', FIXED_NOW), true);
  assert.equal(store.size, 3);
});

test('replay store rejects a repeated delivery key but accepts a new one', () => {
  const store = new MemoryReplayStore();
  const body = 'delivery';
  const headers = githubHeaders(body);
  const result = verify('github', body, headers, opts({ replayStore: store }));
  assert.equal(result.valid, true);
  assert.ok(result.replayKey.startsWith('github:'));
  expectCode(() => verify('github', body, headers, opts({ replayStore: store })), 'REPLAYED_DELIVERY');
  assert.equal(verify('github', 'other', githubHeaders('other'), opts({ replayStore: store })).valid, true);
});

test('replay store keys are provider scoped and secret index aware', () => {
  const store = new MemoryReplayStore();
  const body = 'same-body';
  const linearHeaders = { 'linear-signature': hexHmac(SECRET, body) };
  const githubResult = verify('github', body, githubHeaders(body), opts({ replayStore: store, secrets: [SECRET, 'other'] }));
  const linearResult = verify('linear', body, linearHeaders, opts({ replayStore: store }));
  assert.notEqual(githubResult.replayKey, linearResult.replayKey);
  expectCode(() => verify('github', body, githubHeaders(body), opts({ replayStore: store, secrets: [SECRET, 'other'] })), 'REPLAYED_DELIVERY');
  expectCode(() => verify('linear', body, linearHeaders, opts({ replayStore: store })), 'REPLAYED_DELIVERY');
  const rotatedResult = verify('github', body, githubHeaders(body), opts({ replayStore: store, secrets: ['other', SECRET] }));
  assert.notEqual(githubResult.replayKey, rotatedResult.replayKey);
});

test('standard-webhooks replay uses delivery id and ignores signature rotation', () => {
  const store = new MemoryReplayStore();
  const body = 'payload';
  const id = 'msg_replay';
  const timestamp = '1700000000';
  const signature = (secret) => createHmacSignature(secret, id, timestamp, body);
  const header = `v1,${signature('first-secret')}`;
  const secret = `whsec_${Buffer.from('first-secret').toString('base64')}`;
  const options = opts({ secret, replayStore: store });
  assert.equal(verify('svix', body, { 'webhook-id': id, 'webhook-timestamp': timestamp, 'webhook-signature': header }, options).valid, true);
  const rotated = `whsec_${Buffer.from('second-secret').toString('base64')}`;
  const rotatedHeader = `v1,${signature('second-secret')}`;
  expectCode(() => verify('svix', body, { 'webhook-id': id, 'webhook-timestamp': timestamp, 'webhook-signature': rotatedHeader }, opts({ secret: rotated, replayStore: store })), 'REPLAYED_DELIVERY');
});

function createHmacSignature(secret, id, timestamp, body) {
  // Local import kept synchronous through node:crypto require via createRequire is
  // unnecessary: use the helper exported by the test utilities.
  return hmacBase64(Buffer.from(secret), `${id}.${timestamp}.${body}`);
}

import { createHmac } from 'node:crypto';
function hmacBase64(key, payload) {
  return createHmac('sha256', key).update(payload).digest('base64');
}

test('async replay store is supported only through verifyAsync', async () => {
  const seen = new Set();
  const asyncStore = {
    async checkAndRecord(key) {
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    },
  };
  const syncBody = 'async-sync';
  expectCode(() => verify('github', syncBody, githubHeaders(syncBody), opts({ replayStore: asyncStore })), 'INVALID_ARGUMENT');
  const body = 'async';
  const headers = githubHeaders(body);
  assert.equal((await verifyAsync('github', body, headers, opts({ replayStore: asyncStore }))).valid, true);
  await expectCodeAsync(() => verifyAsync('github', body, headers, opts({ replayStore: asyncStore })), 'REPLAYED_DELIVERY');
});

test('replay store must return a boolean', () => {
  const badStore = { checkAndRecord: () => 'yes' };
  const body = 'bad-store';
  expectCode(() => verify('github', body, githubHeaders(body), opts({ replayStore: badStore })), 'INVALID_ARGUMENT');
  expectCode(() => verify('github', body, githubHeaders(body), opts({ replayStore: {} })), 'INVALID_ARGUMENT');
});

test('failed signature verification never records a replay key', () => {
  const store = new MemoryReplayStore();
  const body = 'unverified';
  expectCode(() => verify('github', body, githubHeaders(`${body}!`), opts({ replayStore: store })), 'SIGNATURE_MISMATCH');
  assert.equal(store.size, 0);
  assert.equal(verify('github', body, githubHeaders(body), opts({ replayStore: store })).valid, true);
});

test('replay error is a HookVerifyError with details', () => {
  const store = new MemoryReplayStore();
  const body = 'details';
  verify('github', body, githubHeaders(body), opts({ replayStore: store }));
  try {
    verify('github', body, githubHeaders(body), opts({ replayStore: store }));
    assert.fail('expected a rejection');
  } catch (error) {
    assert.ok(error instanceof HookVerifyError);
    assert.equal(error.code, 'REPLAYED_DELIVERY');
    assert.ok(error.details.replayKey.startsWith('github:'));
  }
});

test('timestamp tolerance rejects both stale and future timestamps across providers', () => {
  const body = 'timestamp';
  const timestamp = '1700000000';
  const payload = `${timestamp}.${body}`;
  const sig = hexHmac(SECRET, payload);
  for (const value of ['1699999400', '1700000600']) {
    const header = `t=${value},v1=${hexHmac(SECRET, `${value}.${body}`)}`;
    expectCode(() => verify('stripe', body, { 'stripe-signature': header }, opts()), 'TIMESTAMP_OUT_OF_TOLERANCE');
  }
  assert.equal(verify('stripe', body, { 'stripe-signature': `t=${timestamp},v1=${sig}` }, opts({ toleranceSeconds: 300 })).valid, true);
  assert.equal(verify('stripe', body, { 'stripe-signature': `t=${timestamp},v1=${sig}` }, opts({ toleranceSeconds: 0 })).valid, true);
});
