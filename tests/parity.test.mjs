// ESM and CommonJS must expose identical behavior. Each case runs the same
// vector through import() and require() and compares results or error codes.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import { createHmac, generateKeyPairSync, sign } from 'node:crypto';
import * as esm from '../src/index.mjs';
import { SECRET, FIXED_NOW, clock, hexHmac, base64Hmac } from './helpers.mjs';

const require = createRequire(import.meta.url);
const cjs = require('../cjs/index.cjs');
const TS = '1700000000';
const opts = (overrides = {}) => ({ secret: SECRET, now: clock(), ...overrides });

const ed = generateKeyPairSync('ed25519');
const edPublic = ed.publicKey.export({ format: 'der', type: 'spki' }).subarray(-32).toString('hex');

function outcome(fn) {
  try {
    const result = fn();
    return { ok: true, provider: result.provider, valid: result.valid, secretIndex: result.secretIndex, replayKey: result.replayKey };
  } catch (error) {
    return { ok: false, code: error.code, name: error.name };
  }
}

function svixHeaders(body) {
  const secret = 'parity-secret';
  const signature = createHmac('sha256', Buffer.from(secret))
    .update(`msg_parity.${TS}.${body}`).digest('base64');
  return {
    'webhook-id': 'msg_parity',
    'webhook-timestamp': TS,
    'webhook-signature': `v1,${signature}`,
  };
}

const VECTORS = [
  ['github', 'parity-body', { 'x-hub-signature-256': `sha256=${hexHmac(SECRET, 'parity-body')}` }, opts()],
  ['github', 'parity-body', { 'x-hub-signature-256': `sha256=${'0'.repeat(64)}` }, opts()],
  ['stripe', 'parity-body', { 'stripe-signature': `t=${TS},v1=${hexHmac(SECRET, `${TS}.parity-body`)}` }, opts()],
  ['slack', 'parity-body', { 'x-slack-signature': `v0=${hexHmac(SECRET, `v0:${TS}:parity-body`)}`, 'x-slack-request-timestamp': TS }, opts()],
  ['shopify', 'parity-body', { 'x-shopify-hmac-sha256': base64Hmac(SECRET, 'parity-body') }, opts()],
  ['linear', 'parity-body', { 'linear-signature': hexHmac(SECRET, 'parity-body') }, opts()],
  ['svix', 'parity-body', svixHeaders('parity-body'), opts({ secret: `whsec_${Buffer.from('parity-secret').toString('base64')}` })],
  ['discord', 'parity-body', {
    'x-signature-ed25519': sign(null, Buffer.concat([Buffer.from(TS, 'ascii'), Buffer.from('parity-body')]), ed.privateKey).toString('hex'),
    'x-signature-timestamp': TS,
  }, opts({ secret: edPublic })],
];

for (let i = 0; i < VECTORS.length; i += 1) {
  const [provider, body, headers, options] = VECTORS[i];
  test(`parity valid ${provider} vector#${i}`, () => {
    assert.deepEqual(outcome(() => esm.verify(provider, body, headers, options)), outcome(() => cjs.verify(provider, body, headers, options)));
  });
}

for (let i = 0; i < VECTORS.length; i += 1) {
  const [provider, body, headers, options] = VECTORS[i];
  test(`parity isValid ${provider} vector#${i}`, () => {
    assert.equal(esm.isValid(provider, body, headers, options), cjs.isValid(provider, body, headers, options));
  });
}

test('parity: exported API surface matches', () => {
  const keys = [
    'HookVerifyError', 'ERROR_CODES', 'MemoryReplayStore', 'defineProvider',
    'registerProvider', 'getProvider', 'listProviders', 'verify', 'verifyAsync',
    'isValid', 'createVerifier', 'providers', 'github', 'stripe', 'slack',
    'shopify', 'linear', 'svix', 'standardWebhooks', 'discord', 'helpers',
  ];
  for (const key of keys) {
    assert.ok(esm[key] !== undefined, `esm missing ${key}`);
    assert.ok(cjs[key] !== undefined, `cjs missing ${key}`);
  }
  assert.deepEqual(esm.listProviders(), cjs.listProviders());
  assert.deepEqual(esm.ERROR_CODES, cjs.ERROR_CODES);
});

test('parity: provider adapters are the same functions across module systems', () => {
  for (const name of ['github', 'stripe', 'slack', 'shopify', 'linear', 'svix', 'standardWebhooks', 'discord']) {
    assert.equal(esm.providers[name].name, cjs.providers[name].name);
    assert.equal(typeof esm.providers[name].verify, 'function');
    assert.equal(typeof cjs.providers[name].verify, 'function');
  }
});

test('parity: replay store behavior matches', () => {
  const esmStore = new esm.MemoryReplayStore({ maxEntries: 4, ttlSeconds: 30 });
  const cjsStore = new cjs.MemoryReplayStore({ maxEntries: 4, ttlSeconds: 30 });
  for (let i = 0; i < 20; i += 1) {
    assert.equal(esmStore.checkAndRecord(`k${i}`, FIXED_NOW), cjsStore.checkAndRecord(`k${i}`, FIXED_NOW));
  }
  assert.equal(esmStore.size, cjsStore.size);
  assert.equal(esmStore.has('k19', FIXED_NOW), cjsStore.has('k19', FIXED_NOW));
});

test('parity: default export matches named exports', () => {
  assert.equal(esm.default.verify, esm.verify);
  assert.equal(esm.default.MemoryReplayStore, esm.MemoryReplayStore);
});

test('parity: per-provider ESM subpath exports resolve', async () => {
  for (const name of ['github', 'stripe', 'slack', 'shopify', 'linear', 'svix', 'standard-webhooks', 'discord']) {
    const module = await import(`../src/providers/${name}.mjs`);
    assert.equal(typeof module.default.verify, 'function');
  }
});
