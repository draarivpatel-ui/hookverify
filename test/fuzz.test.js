import test from 'node:test';
import assert from 'node:assert/strict';
import { createHmac } from 'node:crypto';
import fc from 'fast-check';
import { isValid, verify } from '../src/index.mjs';

const SECRET = 'hookverify-fast-check-secret';
const FIXED_NOW_MS = 1_700_000_000_000;
const FIXED_TIMESTAMP = String(Math.floor(FIXED_NOW_MS / 1000));
const now = () => FIXED_NOW_MS;

function stripeSignature(secret, timestamp, body) {
  return createHmac('sha256', secret).update(timestamp + '.' + body).digest('hex');
}

function stripeHeaders(body, timestamp = FIXED_TIMESTAMP, signature = stripeSignature(SECRET, timestamp, body)) {
  return { 'stripe-signature': 't=' + timestamp + ',v1=' + signature };
}

function verifyStripe(body, headers) {
  return verify('stripe', body, headers, { secret: SECRET, now });
}

function stripeIsValid(body, headers) {
  return isValid('stripe', body, headers, { secret: SECRET, now });
}

function errorCodeFor(fn) {
  try {
    fn();
    return null;
  } catch (error) {
    return error && error.code;
  }
}

const bodyArbitrary = fc.string({ maxLength: 180 });
const mutationCharacter = fc.constantFrom('A', 'b', '0', 'é', '\n', '<', '/', ' ');
const hexCharacter = fc.constantFrom(...'0123456789abcdefABCDEF');

test('mutated Stripe webhook bodies never pass the original HMAC signature', () => {
  fc.assert(
    fc.property(bodyArbitrary, fc.integer({ min: 0, max: 1024 }), mutationCharacter, (body, position, replacement) => {
      const headers = stripeHeaders(body);
      assert.equal(verifyStripe(body, headers).valid, true);

      let mutated;
      if (body.length === 0) {
        mutated = replacement;
      } else {
        const index = position % body.length;
        fc.pre(body[index] !== replacement);
        mutated = body.slice(0, index) + replacement + body.slice(index + 1);
      }

      assert.equal(stripeIsValid(mutated, headers), false);
      assert.equal(errorCodeFor(() => verifyStripe(mutated, headers)), 'SIGNATURE_MISMATCH');
    }),
    { seed: 20261127, numRuns: 150, endOnFailure: true },
  );
});

test('mutated Stripe timestamps never pass the original HMAC signature', () => {
  fc.assert(
    fc.property(bodyArbitrary, fc.integer({ min: 1, max: 1200 }), fc.boolean(), (body, delta, moveForward) => {
      const correctHeaders = stripeHeaders(body);
      assert.equal(verifyStripe(body, correctHeaders).valid, true);

      const mutatedTimestamp = String(Number(FIXED_TIMESTAMP) + (moveForward ? delta : -delta));
      fc.pre(Number(mutatedTimestamp) > 0);
      const originalSignature = stripeSignature(SECRET, FIXED_TIMESTAMP, body);
      const mutatedHeaders = stripeHeaders(body, mutatedTimestamp, originalSignature);

      assert.equal(stripeIsValid(body, mutatedHeaders), false);
      const code = errorCodeFor(() => verifyStripe(body, mutatedHeaders));
      assert.ok(code === 'SIGNATURE_MISMATCH' || code === 'TIMESTAMP_OUT_OF_TOLERANCE', code);
    }),
    { seed: 20261128, numRuns: 150, endOnFailure: true },
  );
});

test('mutated Stripe HMAC signatures never verify', () => {
  fc.assert(
    fc.property(bodyArbitrary, fc.integer({ min: 0, max: 63 }), hexCharacter, (body, index, replacement) => {
      const signature = stripeSignature(SECRET, FIXED_TIMESTAMP, body);
      fc.pre(signature[index].toLowerCase() !== replacement.toLowerCase());
      const mutatedSignature = signature.slice(0, index) + replacement + signature.slice(index + 1);
      const headers = stripeHeaders(body, FIXED_TIMESTAMP, mutatedSignature);

      assert.equal(stripeIsValid(body, headers), false);
      assert.equal(errorCodeFor(() => verifyStripe(body, headers)), 'SIGNATURE_MISMATCH');
    }),
    { seed: 20261129, numRuns: 150, endOnFailure: true },
  );
});
