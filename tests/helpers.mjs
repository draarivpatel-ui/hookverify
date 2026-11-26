import { createHmac, generateKeyPairSync, sign } from 'node:crypto';

export const SECRET = 'test-secret-alpha';
export const SECRET_2 = 'test-secret-beta-rotation';
export const FIXED_NOW = 1_700_000_000_000;

export const clock = (ms = FIXED_NOW) => () => ms;

export function hexHmac(secret, payload, algorithm = 'sha256') {
  return createHmac(algorithm, secret).update(payload).digest('hex');
}

export function base64Hmac(secret, payload) {
  return createHmac('sha256', secret).update(payload).digest('base64');
}

import assert from 'node:assert/strict';

export function expectCode(fn, code) {
  try {
    fn();
  } catch (error) {
    assert.ok(error && error.code === code, `expected code ${code}, got ${error && error.code}: ${error && error.message}`);
    return error;
  }
  assert.fail(`expected HookVerifyError with code ${code}`);
}

export async function expectCodeAsync(fn, code) {
  try {
    await fn();
  } catch (error) {
    assert.ok(error && error.code === code, `expected code ${code}, got ${error && error.code}: ${error && error.message}`);
    return error;
  }
  assert.fail(`expected HookVerifyError with code ${code}`);
}

export function ed25519Fixture() {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const publicKeyHex = publicKey.export({ format: 'der', type: 'spki' }).subarray(-32).toString('hex');
  return {
    publicKeyHex,
    signPayload(payload, timestamp = '1700000000') {
      const signed = Buffer.concat([Buffer.from(timestamp, 'ascii'), Buffer.from(payload)]);
      return sign(null, signed, privateKey).toString('hex');
    },
  };
}
