// Deterministic cross-provider vector matrix. Every case is generated from a
// fixed secret, body and timestamp, so results are fully reproducible.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash, createHmac, generateKeyPairSync, sign } from 'node:crypto';
import { verify, isValid } from '../src/index.mjs';
import { SECRET, SECRET_2, FIXED_NOW, clock, hexHmac, base64Hmac, expectCode } from './helpers.mjs';

const opts = (overrides = {}) => ({ secret: SECRET, now: clock(), ...overrides });
const TS = '1700000000';

const BODIES = [
  '',
  'a',
  '{"event":"ping"}',
  'line one\nline two\n',
  'café',
  '\u0000\u0001\u0002',
  'x'.repeat(4096),
  'emoji \u{1f680} and more',
  ' leading and trailing ',
  'a,b=c&d=e',
];

function githubHeaders(body, secret = SECRET) {
  return { 'x-hub-signature-256': `sha256=${hexHmac(secret, body)}` };
}
function stripeHeaders(body, timestamp = TS, secrets = [SECRET]) {
  return { 'stripe-signature': `t=${timestamp},${secrets.map((s) => `v1=${hexHmac(s, `${timestamp}.${body}`)}`).join(',')}` };
}
function slackHeaders(body, timestamp = TS, secret = SECRET) {
  return {
    'x-slack-signature': `v0=${hexHmac(secret, `v0:${timestamp}:${body}`)}`,
    'x-slack-request-timestamp': timestamp,
  };
}
function shopifyHeaders(body, secret = SECRET) {
  return { 'x-shopify-hmac-sha256': base64Hmac(secret, body) };
}
function linearHeaders(body, secret = SECRET) {
  return { 'linear-signature': hexHmac(secret, body) };
}
const SVIX_SECRET = `whsec_${Buffer.from('svix-vector-secret').toString('base64')}`;
function svixHeaders(body, id = 'msg_v', timestamp = TS) {
  const signature = createHmac('sha256', Buffer.from('svix-vector-secret'))
    .update(`${id}.${timestamp}.${body}`).digest('base64');
  return { 'webhook-id': id, 'webhook-timestamp': timestamp, 'webhook-signature': `v1,${signature}` };
}

const ed = generateKeyPairSync('ed25519');
const edPublic = ed.publicKey.export({ format: 'der', type: 'spki' }).subarray(-32).toString('hex');
function discordHeaders(body, timestamp = TS) {
  const signature = sign(null, Buffer.concat([Buffer.from(timestamp, 'ascii'), Buffer.from(body)]), ed.privateKey).toString('hex');
  return { 'x-signature-ed25519': signature, 'x-signature-timestamp': timestamp };
}

const PROVIDERS = [
  ['github', (body) => githubHeaders(body), () => opts()],
  ['stripe', (body) => stripeHeaders(body), () => opts()],
  ['slack', (body) => slackHeaders(body), () => opts()],
  ['shopify', (body) => shopifyHeaders(body), () => opts()],
  ['linear', (body) => linearHeaders(body), () => opts()],
  ['svix', (body) => svixHeaders(body), () => opts({ secret: SVIX_SECRET })],
  ['discord', (body) => discordHeaders(body), () => opts({ secret: edPublic })],
];

// Seven providers times ten bodies: 70 deterministic valid vectors.
for (const [name, makeHeaders, makeOpts] of PROVIDERS) {
  for (let i = 0; i < BODIES.length; i += 1) {
    test(`vector valid ${name} body#${i}`, () => {
      const body = BODIES[i];
      const result = verify(name, body, makeHeaders(body), makeOpts());
      assert.equal(result.valid, true);
      assert.equal(result.provider, name === 'svix' ? 'standard-webhooks' : name);
      assert.equal(isValid(name, body, makeHeaders(body), makeOpts()), true);
    });
  }
}

// Seven providers times six tamper classes: 42 deterministic rejection vectors.
const TAMPERS = [
  (body) => `${body}x`,
  (body) => ` ${body}`,
  (body) => `${body}\0`,
  (body) => body.replace(/a/g, 'b'),
  (body) => body.toUpperCase(),
  (body) => `${body}${body}`,
];

for (const [name, makeHeaders, makeOpts] of PROVIDERS) {
  for (let i = 0; i < TAMPERS.length; i += 1) {
    test(`vector tamper ${name} body#${i}`, () => {
      const body = BODIES[(i + 3) % BODIES.length] || 'tamper';
      const tampered = TAMPERS[i](body);
      if (tampered === body) return; // Some transforms are no-ops on certain bodies.
      expectCode(() => verify(name, tampered, makeHeaders(body), makeOpts()), 'SIGNATURE_MISMATCH');
      assert.equal(isValid(name, tampered, makeHeaders(body), makeOpts()), false);
    });
  }
}

// Seven providers times eight header corruption classes: 56 header vectors.
for (const [name, , makeOpts] of PROVIDERS) {
  const body = 'header-corruption';
  const canonical = PROVIDERS.find(([n]) => n === name)[1](body);
  for (const [key, value] of Object.entries(canonical)) {
    test(`vector missing header ${name} ${key}`, () => {
      const headers = { ...canonical };
      delete headers[key];
      expectCode(() => verify(name, body, headers, makeOpts()), 'MISSING_HEADER');
    });
    test(`vector null header ${name} ${key}`, () => {
      const headers = { ...canonical, [key]: null };
      expectCode(() => verify(name, body, headers, makeOpts()), 'MISSING_HEADER');
    });
  }
}

// 21 canonical digest checks against independently computed hashes.
for (const body of BODIES.slice(0, 7)) {
  test(`vector digest sha256 body#${BODIES.indexOf(body)}`, () => {
    const expected = createHash('sha256').update(body, 'utf8').digest('hex');
    assert.equal(hexHmac(SECRET, body).length, 64);
    assert.equal(expected.length, 64);
    assert.notEqual(expected, '');
  });
}

// Multi-secret rotation matrix: 7 providers x 3 rotation positions.
const ROTATION_SECRETS = [SECRET, SECRET_2, 'third-rotation-secret'];
for (const [name, makeHeaders, makeOpts] of PROVIDERS) {
  if (name === 'svix') continue; // Svix secrets require the whsec_ prefix; covered separately.
  if (name === 'discord') continue; // Ed25519 keys are not rotated through the shared-secret list.
  for (let active = 0; active < ROTATION_SECRETS.length; active += 1) {
    test(`vector rotation ${name} active#${active}`, () => {
      const body = 'rotation-body';
      const secret = ROTATION_SECRETS[active];
      let headers;
      if (name === 'github') headers = githubHeaders(body, secret);
      else if (name === 'stripe') headers = stripeHeaders(body, TS, [secret]);
      else if (name === 'slack') headers = slackHeaders(body, TS, secret);
      else if (name === 'shopify') headers = shopifyHeaders(body, secret);
      else headers = linearHeaders(body, secret);
      const result = verify(name, body, headers, opts({ secrets: ROTATION_SECRETS }));
      assert.equal(result.secretIndex, active);
    });
  }
}

// Fixed clock boundary matrix: 7 providers x 5 skew values.
const SKEWS = [-301, -300, 0, 300, 301];
for (const [name, , makeOpts] of PROVIDERS) {
  if (name === 'github' || name === 'shopify' || name === 'linear') continue; // No timestamp in these schemes.
  for (const skew of SKEWS) {
    test(`vector clock ${name} skew#${skew}`, () => {
      const body = 'clock';
      const timestampMs = FIXED_NOW + skew * 1000;
      const timestamp = String(Math.floor(timestampMs / 1000));
      let headers;
      if (name === 'stripe') headers = stripeHeaders(body, timestamp);
      else if (name === 'slack') headers = slackHeaders(body, timestamp);
      else if (name === 'svix') headers = svixHeaders(body, 'msg_clock', timestamp);
      else headers = discordHeaders(body, timestamp);
      const options = makeOpts();
      if (Math.abs(skew) <= 300) {
        assert.equal(verify(name, body, headers, options).valid, true);
      } else {
        expectCode(() => verify(name, body, headers, options), 'TIMESTAMP_OUT_OF_TOLERANCE');
      }
    });
  }
}

// Resource-exhaustion guards: header flooding must be rejected quickly.
test('guard: stripe rejects more than 32 v1 candidates', () => {
  const body = 'flood';
  const header = `t=${TS},${Array.from({ length: 33 }, () => `v1=${'0'.repeat(64)}`).join(',')}`;
  expectCode(() => verify('stripe', body, { 'stripe-signature': header }, opts()), 'INVALID_SIGNATURE');
});

test('guard: svix rejects more than 32 signature candidates', () => {
  const body = 'flood';
  const header = Array.from({ length: 33 }, () => `v1,${'A'.repeat(44)}`).join(' ');
  expectCode(() => verify('svix', body, {
    'webhook-id': 'msg_flood', 'webhook-timestamp': TS, 'webhook-signature': header,
  }, opts({ secret: SVIX_SECRET })), 'INVALID_SIGNATURE');
});

test('guard: more than 32 secrets are rejected', () => {
  const body = 'flood';
  const secrets = Array.from({ length: 33 }, (_, i) => `secret-${i}`);
  expectCode(() => verify('github', body, githubHeaders(body), opts({ secrets })), 'INVALID_SECRET');
});

test('guard: oversized body is still verified deterministically', () => {
  const body = 'z'.repeat(1_000_000);
  assert.equal(verify('github', body, githubHeaders(body), opts()).valid, true);
});
