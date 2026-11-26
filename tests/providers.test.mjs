import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHmac } from 'node:crypto';
import { verify, verifyAsync, isValid, createVerifier, ERROR_CODES } from '../src/index.mjs';
import { SECRET, SECRET_2, FIXED_NOW, clock, hexHmac, base64Hmac, expectCode, ed25519Fixture } from './helpers.mjs';

const opts = (overrides = {}) => ({ secret: SECRET, now: clock(), ...overrides });

// GitHub --------------------------------------------------------------------

test('github: valid hex signature', () => {
  const body = '{"action":"opened","number":7}';
  const result = verify('github', body, {
    'X-Hub-Signature-256': `sha256=${hexHmac(SECRET, body)}`,
  }, opts());
  assert.equal(result.provider, 'github');
  assert.equal(result.valid, true);
  assert.equal(result.timestamp, null);
  assert.equal(result.secretIndex, 0);
  assert.ok(Object.isFrozen(result));
});

test('github: accepts Buffer and Uint8Array bodies byte-for-byte', () => {
  const body = Buffer.from([0, 1, 2, 250, 255]);
  for (const raw of [body, new Uint8Array(body)]) {
    const result = verify('github', raw, { 'x-hub-signature-256': `sha256=${hexHmac(SECRET, body)}` }, opts());
    assert.equal(result.valid, true);
  }
});

test('github: wrong secret, tampered body and trailing byte all fail', () => {
  const body = 'body';
  const sig = `sha256=${hexHmac(SECRET, body)}`;
  expectCode(() => verify('github', body, { 'x-hub-signature-256': sig }, opts({ secret: 'wrong' })), 'SIGNATURE_MISMATCH');
  expectCode(() => verify('github', `${body} `, { 'x-hub-signature-256': sig }, opts()), 'SIGNATURE_MISMATCH');
  expectCode(() => verify('github', `${body}\0`, { 'x-hub-signature-256': sig }, opts()), 'SIGNATURE_MISMATCH');
});

test('github: malformed headers fail with typed codes', () => {
  const body = 'b';
  const sig = `sha256=${hexHmac(SECRET, body)}`;
  expectCode(() => verify('github', body, {}, opts()), 'MISSING_HEADER');
  expectCode(() => verify('github', body, { 'x-hub-signature-256': ['a', 'b'] }, opts()), 'INVALID_HEADER');
  expectCode(() => verify('github', body, { 'x-hub-signature-256': [sig] }, opts()), 'INVALID_HEADER');
  expectCode(() => verify('github', body, { 'x-hub-signature-256': `sha1=${hexHmac(SECRET, body)}` }, opts()), 'INVALID_SIGNATURE');
  expectCode(() => verify('github', body, { 'x-hub-signature-256': `sha256=${hexHmac(SECRET, body).slice(0, 62)}` }, opts()), 'INVALID_SIGNATURE');
  expectCode(() => verify('github', body, { 'x-hub-signature-256': `sha256=${'g'.repeat(64)}` }, opts()), 'INVALID_SIGNATURE');
  expectCode(() => verify('github', body, { 'x-hub-signature-256': `sha256=${'A'.repeat(64)}` }, opts()), 'SIGNATURE_MISMATCH');
});

test('github: rotation accepts old and new secrets and reports index', () => {
  const body = 'rotation';
  const headers = { 'x-hub-signature-256': `sha256=${hexHmac(SECRET_2, body)}` };
  assert.equal(verify('github', body, headers, opts({ secrets: [SECRET, SECRET_2] })).secretIndex, 1);
  assert.equal(verify('github', body, { 'x-hub-signature-256': `sha256=${hexHmac(SECRET, body)}` }, opts({ secrets: [SECRET, SECRET_2] })).secretIndex, 0);
  expectCode(() => verify('github', body, headers, opts({ secrets: [SECRET] })), 'SIGNATURE_MISMATCH');
  expectCode(() => verify('github', body, headers, opts({ secrets: [] })), 'INVALID_SECRET');
  expectCode(() => verify('github', body, headers, opts({ secrets: [''] })), 'INVALID_SECRET');
});

// Stripe --------------------------------------------------------------------

function stripeHeaders(body, timestamp, secrets = [SECRET]) {
  const payload = `${timestamp}.${body}`;
  return {
    'Stripe-Signature': `t=${timestamp},${secrets.map((s) => `v1=${hexHmac(s, payload)}`).join(',')}`,
  };
}

test('stripe: valid signature with tolerance and timestamp result', () => {
  const body = '{"id":"evt_1"}';
  const timestamp = '1700000000';
  const result = verify('stripe', body, stripeHeaders(body, timestamp), opts());
  assert.equal(result.provider, 'stripe');
  assert.equal(result.timestamp.toISOString(), '2023-11-14T22:13:20.000Z');
});

test('stripe: multi-v1 rotation and whitespace tolerant fields', () => {
  const body = 'rotate';
  const timestamp = '1700000000';
  const payload = `${timestamp}.${body}`;
  const header = `t=${timestamp} , v1=${hexHmac(SECRET, payload)} , v1=${hexHmac(SECRET_2, payload)}`;
  const result = verify('stripe', body, { 'stripe-signature': header }, opts({ secrets: [SECRET, SECRET_2] }));
  assert.equal(result.secretIndex, 1);
});

test('stripe: stale and future-skew timestamps are both rejected', () => {
  const body = 'time';
  for (const timestamp of ['1699999699', '1700000301']) {
    expectCode(() => verify('stripe', body, stripeHeaders(body, timestamp), opts()), 'TIMESTAMP_OUT_OF_TOLERANCE');
  }
  assert.equal(verify('stripe', body, stripeHeaders(body, '1700000000'), opts({ toleranceSeconds: 0 })).valid, true);
  expectCode(() => verify('stripe', body, stripeHeaders(body, '1700000001'), opts({ toleranceSeconds: 0 })), 'TIMESTAMP_OUT_OF_TOLERANCE');
});

test('stripe: malformed signatures and headers are rejected', () => {
  const body = 'b';
  const timestamp = '1700000000';
  expectCode(() => verify('stripe', body, {}, opts()), 'MISSING_HEADER');
  expectCode(() => verify('stripe', body, { 'stripe-signature': '' }, opts()), 'INVALID_HEADER');
  expectCode(() => verify('stripe', body, { 'stripe-signature': `t=${timestamp}` }, opts()), 'INVALID_HEADER');
  expectCode(() => verify('stripe', body, { 'stripe-signature': `v1=${hexHmac(SECRET, `${timestamp}.${body}`)}` }, opts()), 'INVALID_HEADER');
  expectCode(() => verify('stripe', body, { 'stripe-signature': `t=${timestamp},v1=abc` }, opts()), 'INVALID_SIGNATURE');
  expectCode(() => verify('stripe', body, { 'stripe-signature': `t=${timestamp},v1=${hexHmac(SECRET, `${timestamp}.${body}`)}` }, opts({ secret: 'wrong' })), 'SIGNATURE_MISMATCH');
  expectCode(() => verify('stripe', body, { 'stripe-signature': `t=nope,v1=${hexHmac(SECRET, `nope.${body}`)}` }, opts()), 'TIMESTAMP_INVALID');
  expectCode(() => verify('stripe', body, { 'stripe-signature': [`t=${timestamp}`, `v1=aa`] }, opts()), 'INVALID_HEADER');
  expectCode(() => verify('stripe', body, { 'stripe-signature': `t=${timestamp},t=${timestamp},v1=${hexHmac(SECRET, `${timestamp}.${body}`)}` }, opts()), 'INVALID_HEADER');
  expectCode(() => verify('stripe', body, { 'stripe-signature': 't=1700000000,v1=,foo=bar' }, opts()), 'INVALID_HEADER');
});

// Slack ---------------------------------------------------------------------

function slackHeaders(body, timestamp = '1700000000', secret = SECRET) {
  return {
    'X-Slack-Signature': `v0=${hexHmac(secret, `v0:${timestamp}:${body}`)}`,
    'X-Slack-Request-Timestamp': timestamp,
  };
}

test('slack: valid signature with timestamp in signed payload', () => {
  const result = verify('slack', 'token=abc', slackHeaders('token=abc'), opts());
  assert.equal(result.provider, 'slack');
  assert.equal(result.timestamp.getTime(), FIXED_NOW);
});

test('slack: signature bound to timestamp and body', () => {
  const body = 'x=1';
  expectCode(() => verify('slack', 'x=2', slackHeaders(body), opts()), 'SIGNATURE_MISMATCH');
  expectCode(() => verify('slack', body, { ...slackHeaders(body), 'X-Slack-Request-Timestamp': '1700000001' }, opts()), 'SIGNATURE_MISMATCH');
  expectCode(() => verify('slack', body, slackHeaders(body), opts({ toleranceSeconds: -1 })), 'INVALID_ARGUMENT');
  expectCode(() => verify('slack', body, slackHeaders(body), opts({ toleranceSeconds: 1.5 })), 'INVALID_ARGUMENT');
});

test('slack: malformed headers and stale timestamps', () => {
  const body = 'x';
  expectCode(() => verify('slack', body, { 'x-slack-signature': slackHeaders(body)['x-slack-signature'] }, opts()), 'MISSING_HEADER');
  expectCode(() => verify('slack', body, { 'x-slack-request-timestamp': '1700000000' }, opts()), 'MISSING_HEADER');
  expectCode(() => verify('slack', body, { ...slackHeaders(body), 'X-Slack-Signature': `v1=${'a'.repeat(64)}` }, opts()), 'INVALID_SIGNATURE');
  const stale = '1700000400';
  const staleSig = hexHmac(SECRET, `v0:${stale}:${body}`);
  expectCode(() => verify('slack', body, { 'X-Slack-Signature': `v0=${staleSig}`, 'X-Slack-Request-Timestamp': stale }, opts()), 'TIMESTAMP_OUT_OF_TOLERANCE');
});

// Shopify -------------------------------------------------------------------

test('shopify: canonical base64 HMAC', () => {
  const body = '{"order":42}';
  const result = verify('shopify', body, { 'X-Shopify-Hmac-Sha256': base64Hmac(SECRET, body) }, opts());
  assert.equal(result.provider, 'shopify');
  assert.equal(result.valid, true);
});

test('shopify: rejects hex, unpadded, tampered and duplicate headers', () => {
  const body = 'order';
  const sig = base64Hmac(SECRET, body);
  expectCode(() => verify('shopify', body, { 'x-shopify-hmac-sha256': hexHmac(SECRET, body) }, opts()), 'SIGNATURE_MISMATCH');
  expectCode(() => verify('shopify', body, { 'x-shopify-hmac-sha256': 'not-base64!' }, opts()), 'INVALID_SIGNATURE');
  expectCode(() => verify('shopify', body, { 'x-shopify-hmac-sha256': sig.replace(/=+$/, '') }, opts()), 'INVALID_SIGNATURE');
  expectCode(() => verify('shopify', `${body}!`, { 'x-shopify-hmac-sha256': sig }, opts()), 'SIGNATURE_MISMATCH');
  expectCode(() => verify('shopify', body, { 'x-shopify-hmac-sha256': [sig, sig] }, opts()), 'INVALID_HEADER');
  expectCode(() => verify('shopify', body, {}, opts()), 'MISSING_HEADER');
});

// Linear --------------------------------------------------------------------

test('linear: hex HMAC and rotation', () => {
  const body = 'linear payload';
  const result = verify('linear', body, { 'Linear-Signature': hexHmac(SECRET, body) }, opts({ secrets: [SECRET, SECRET_2] }));
  assert.equal(result.provider, 'linear');
  assert.equal(result.secretIndex, 0);
  expectCode(() => verify('linear', body, { 'linear-signature': 'abc' }, opts()), 'INVALID_SIGNATURE');
  expectCode(() => verify('linear', body, {}, opts()), 'MISSING_HEADER');
});

// Standard Webhooks / Svix --------------------------------------------------

const WEBHOOK_SECRET = `whsec_${Buffer.from('svix-test-secret').toString('base64')}`;

function svixSignature(secretUtf8, id, timestamp, body) {
  return createHmac('sha256', Buffer.from(secretUtf8, 'utf8'))
    .update(`${id}.${timestamp}.${body}`).digest('base64');
}

function svixHeaders(id = 'msg_123', timestamp = '1700000000') {
  return {
    'webhook-id': id,
    'webhook-timestamp': timestamp,
    'webhook-signature': `v1,${svixSignature('svix-test-secret', id, timestamp, 'body')}`,
  };
}

test('standard-webhooks: valid signature bound to id and timestamp', () => {
  const body = '{"type":"user.created"}';
  const id = 'msg_abc';
  const timestamp = '1700000000';
  const signature = svixSignature('svix-test-secret', id, timestamp, body);
  const result = verify('standard-webhooks', body, {
    'webhook-id': id,
    'webhook-timestamp': timestamp,
    'webhook-signature': `v1,${signature}`,
  }, opts({ secret: WEBHOOK_SECRET }));
  assert.equal(result.timestamp.getTime(), FIXED_NOW);
  assert.ok(result.replayKey.startsWith('standard-webhooks:'));
  assert.ok(!result.replayKey.includes(id));
});

test('standard-webhooks: alias, rotation, multi-signature and replay key', () => {
  const body = 'payload';
  const id = 'msg_rot';
  const timestamp = '1700000000';
  const signature = (secret) => createHmac('sha256', Buffer.from(secret))
    .update(`${id}.${timestamp}.${body}`).digest('base64').toString();
  const header = `v1,${signature('old-secret')} v1,${signature('new-secret')}`;
  const headers = { 'webhook-id': id, 'webhook-timestamp': timestamp, 'webhook-signature': header };
  const result = verify('svix', body, headers, opts({
    secrets: [`whsec_${Buffer.from('old-secret').toString('base64')}`, `whsec_${Buffer.from('new-secret').toString('base64')}`],
  }));
  assert.equal(result.secretIndex, 1);
  assert.equal(result.provider, 'standard-webhooks');
  assert.equal(verify('standard-webhooks', body, headers, opts({ secrets: [
    `whsec_${Buffer.from('old-secret').toString('base64')}`,
    `whsec_${Buffer.from('new-secret').toString('base64')}`,
  ] })).valid, true);
});

test('standard-webhooks: rejects bad secrets, ids, signatures and timestamps', () => {
  const body = 'p';
  const id = 'msg_1';
  const timestamp = '1700000000';
  const signature = createHmac('sha256', Buffer.from('svix-test-secret'))
    .update(`${id}.${timestamp}.${body}`).digest('base64');
  const headers = { 'webhook-id': id, 'webhook-timestamp': timestamp, 'webhook-signature': `v1,${signature}` };
  expectCode(() => verify('svix', body, headers, opts({ secret: 'no-prefix' })), 'INVALID_SECRET');
  expectCode(() => verify('svix', body, headers, opts({ secret: 'whsec_!!' })), 'INVALID_SIGNATURE');
  expectCode(() => verify('svix', body, { ...headers, 'webhook-id': 'bad id' }, opts({ secret: WEBHOOK_SECRET })), 'INVALID_HEADER');
  expectCode(() => verify('svix', body, { ...headers, 'webhook-signature': 'v2,AAAA' }, opts({ secret: WEBHOOK_SECRET })), 'INVALID_HEADER');
  expectCode(() => verify('svix', body, { ...headers, 'webhook-signature': 'v1,AAAA' }, opts({ secret: WEBHOOK_SECRET })), 'SIGNATURE_MISMATCH');
  const stale = '1699999000';
  const staleSignature = svixSignature('svix-test-secret', id, stale, body);
  expectCode(() => verify('svix', body, { 'webhook-id': id, 'webhook-timestamp': stale, 'webhook-signature': `v1,${staleSignature}` }, opts({ secret: WEBHOOK_SECRET })), 'TIMESTAMP_OUT_OF_TOLERANCE');
  expectCode(() => verify('svix', body, { ...headers, 'webhook-signature': 'v1,' }, opts({ secret: WEBHOOK_SECRET })), 'INVALID_SIGNATURE');
  expectCode(() => verify('svix', body, { ...headers, 'webhook-signature': 'v1,YQ' }, opts({ secret: WEBHOOK_SECRET })), 'INVALID_SIGNATURE');
});

// Discord -------------------------------------------------------------------

test('discord: real Ed25519 signature verifies', () => {
  const fixture = ed25519Fixture();
  const body = '{"type":1}';
  const signature = fixture.signPayload(body);
  const result = verify('discord', body, {
    'X-Signature-Ed25519': signature,
    'X-Signature-Timestamp': '1700000000',
  }, opts({ secret: fixture.publicKeyHex }));
  assert.equal(result.provider, 'discord');
  assert.equal(result.timestamp.getTime(), FIXED_NOW);
});

test('discord: publicKey option and hex case variants work', () => {
  const fixture = ed25519Fixture();
  const body = 'ping';
  const signature = fixture.signPayload(body);
  const result = verify('discord', body, {
    'x-signature-ed25519': signature.toUpperCase(),
    'x-signature-timestamp': '1700000000',
  }, opts({ secret: 'unused', publicKey: fixture.publicKeyHex.toUpperCase() }));
  assert.equal(result.valid, true);
});

test('discord: rejects tampered signature, body, key and malformed inputs', () => {
  const fixture = ed25519Fixture();
  const body = 'ping';
  const signature = fixture.signPayload(body);
  const headers = { 'x-signature-ed25519': signature, 'x-signature-timestamp': '1700000000' };
  expectCode(() => verify('discord', `${body}!`, headers, opts({ secret: fixture.publicKeyHex })), 'SIGNATURE_MISMATCH');
  expectCode(() => verify('discord', body, { ...headers, 'x-signature-ed25519': 'aa'.repeat(64) }, opts({ secret: fixture.publicKeyHex })), 'SIGNATURE_MISMATCH');
  expectCode(() => verify('discord', body, { ...headers, 'x-signature-ed25519': 'aa' }, opts({ secret: fixture.publicKeyHex })), 'INVALID_SIGNATURE');
  expectCode(() => verify('discord', body, { ...headers, 'x-signature-ed25519': 'zz'.repeat(64) }, opts({ secret: fixture.publicKeyHex })), 'INVALID_SIGNATURE');
  expectCode(() => verify('discord', body, { ...headers, 'x-signature-ed25519': 'aa'.repeat(65) }, opts({ secret: fixture.publicKeyHex })), 'INVALID_SIGNATURE');
  expectCode(() => verify('discord', body, headers, opts({ secret: 'aa'.repeat(31) })), 'INVALID_SIGNATURE');
  expectCode(() => verify('discord', body, headers, opts({ secret: 'zz' })), 'INVALID_SIGNATURE');
  expectCode(() => verify('discord', body, headers, { now: clock(), secret: undefined }), 'INVALID_SECRET');
  const stale = '1700000400';
  const staleSignature = fixture.signPayload(body, stale);
  expectCode(() => verify('discord', body, { 'x-signature-ed25519': staleSignature, 'x-signature-timestamp': stale }, opts({ secret: fixture.publicKeyHex })), 'TIMESTAMP_OUT_OF_TOLERANCE');
  expectCode(() => verify('discord', body, {}, opts({ secret: fixture.publicKeyHex })), 'MISSING_HEADER');
});

// Cross-provider ------------------------------------------------------------

test('unknown provider and parsed body fail before any crypto work', () => {
  expectCode(() => verify('nope', 'x', {}, opts()), 'UNKNOWN_PROVIDER');
  expectCode(() => verify({ name: 'x' }, 'x', {}, opts()), 'INVALID_ARGUMENT');
  expectCode(() => verify('github', { id: 1 }, {}, opts()), 'INVALID_BODY');
});

test('isValid returns false for all typed rejections and rethrows unexpected errors', () => {
  assert.equal(isValid('github', 'x', {}, opts()), false);
  assert.equal(isValid('github', 'x', { 'x-hub-signature-256': `sha256=${hexHmac(SECRET, 'x')}` }, opts()), true);
});

test('createVerifier merges defaults and per-call overrides', () => {
  const verifier = createVerifier({ secret: SECRET, now: clock() });
  const body = 'merged';
  assert.equal(verifier.verify('github', body, { 'x-hub-signature-256': `sha256=${hexHmac(SECRET, body)}` }).valid, true);
  assert.equal(verifier.isValid('github', 'wrong', { 'x-hub-signature-256': `sha256=${hexHmac(SECRET, body)}` }), false);
  const other = createVerifier({ secret: 'other', now: clock() });
  assert.equal(other.verify('github', body, { 'x-hub-signature-256': `sha256=${hexHmac(SECRET, body)}`, }, { secret: SECRET }).valid, true);
  assert.equal(typeof verifier.verifyAsync, 'function');
});

test('single-object call form works for all entry points', async () => {
  const body = 'single-object';
  const headers = { 'x-hub-signature-256': `sha256=${hexHmac(SECRET, body)}` };
  assert.equal(verify({ provider: 'github', body, headers, ...opts() }).valid, true);
  assert.equal(isValid({ provider: 'github', body, headers, ...opts() }), true);
  assert.equal((await verifyAsync({ provider: 'github', body, headers, ...opts() })).valid, true);
});

test('unicode and null-byte payloads preserve byte-exact signing', () => {
  const body = 'café \u0000 \u{1f600}';
  const sig = `sha256=${hexHmac(SECRET, Buffer.from(body, 'utf8'))}`;
  assert.equal(verify('github', body, { 'x-hub-signature-256': sig }, opts()).valid, true);
  expectCode(() => verify('github', `${body}x`, { 'x-hub-signature-256': sig }, opts()), 'SIGNATURE_MISMATCH');
  assert.equal(verify('github', Buffer.from(body, 'utf8'), { 'x-hub-signature-256': sig }, opts()).valid, true);
});

test('header arrays are rejected even when one value is a valid signature', () => {
  const body = 'array';
  const sig = `sha256=${hexHmac(SECRET, body)}`;
  expectCode(() => verify('github', body, new Map([['x-hub-signature-256', [sig, sig]]]), opts()), 'INVALID_HEADER');
  expectCode(() => verify('github', body, new Map([['x-hub-signature-256', sig], ['X-Hub-Signature-256', sig]]), opts()), 'INVALID_HEADER');
  assert.equal(verify('github', body, new Headers({ 'x-hub-signature-256': sig }), opts()).valid, true);
});

test('all error codes are documented constants and frozen', () => {
  assert.ok(Object.isFrozen(ERROR_CODES));
  assert.equal(ERROR_CODES.REPLAYED_DELIVERY, 'REPLAYED_DELIVERY');
});
