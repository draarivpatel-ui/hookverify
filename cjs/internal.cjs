'use strict';

// hookverify: zero-dependency webhook signature verification engine.
// One implementation shared by the ESM and CommonJS public surfaces.

const crypto = require('node:crypto');

const ERROR_CODES = Object.freeze({
  INVALID_ARGUMENT: 'INVALID_ARGUMENT',
  INVALID_BODY: 'INVALID_BODY',
  MISSING_HEADER: 'MISSING_HEADER',
  INVALID_HEADER: 'INVALID_HEADER',
  INVALID_SECRET: 'INVALID_SECRET',
  INVALID_SIGNATURE: 'INVALID_SIGNATURE',
  SIGNATURE_MISMATCH: 'SIGNATURE_MISMATCH',
  TIMESTAMP_MISSING: 'TIMESTAMP_MISSING',
  TIMESTAMP_INVALID: 'TIMESTAMP_INVALID',
  TIMESTAMP_OUT_OF_TOLERANCE: 'TIMESTAMP_OUT_OF_TOLERANCE',
  REPLAYED_DELIVERY: 'REPLAYED_DELIVERY',
  UNKNOWN_PROVIDER: 'UNKNOWN_PROVIDER',
  PROVIDER_ERROR: 'PROVIDER_ERROR',
});

class HookVerifyError extends Error {
  constructor(code, message, details) {
    super(message);
    this.name = 'HookVerifyError';
    this.code = code;
    if (details !== undefined) this.details = details;
    if (typeof Error.captureStackTrace === 'function') {
      Error.captureStackTrace(this, HookVerifyError);
    }
  }

  toJSON() {
    const out = { name: this.name, code: this.code, message: this.message };
    if (this.details !== undefined) out.details = this.details;
    return out;
  }
}

function fail(code, message, details) {
  throw new HookVerifyError(code, message, details);
}

// ---------------------------------------------------------------------------
// Strict encoding and constant-time comparison
// ---------------------------------------------------------------------------

const HEX_RE = /^(?:[0-9a-fA-F]{2})+$/;
const BASE64_RE = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;
const TIMESTAMP_RE = /^(?:0|[1-9][0-9]{0,11})$/;

function decodeHex(value, label = 'signature') {
  if (typeof value !== 'string' || value.length === 0 || value.length % 2 !== 0 || !HEX_RE.test(value)) {
    fail('INVALID_SIGNATURE', `${label} must be an even-length, non-empty hex string`);
  }
  return Buffer.from(value, 'hex');
}

function decodeBase64(value, label = 'signature') {
  if (typeof value !== 'string' || value.length === 0 || value.length % 4 !== 0 || !BASE64_RE.test(value)) {
    fail('INVALID_SIGNATURE', `${label} must be canonical padded base64`);
  }
  const decoded = Buffer.from(value, 'base64');
  if (decoded.length === 0 || decoded.toString('base64') !== value) {
    fail('INVALID_SIGNATURE', `${label} is not canonical base64 (bad padding or non-zero pad bits)`);
  }
  return decoded;
}

function decodeHexOfLength(value, bytes, label) {
  const decoded = decodeHex(value, label);
  if (decoded.length !== bytes) {
    fail('INVALID_SIGNATURE', `${label} must decode to exactly ${bytes} bytes`);
  }
  return decoded;
}

// Both operands are always passed to timingSafeEqual when non-empty. A length
// mismatch is reported only after the comparison, and never by throwing from
// timingSafeEqual itself.
function constantTimeEqual(a, b) {
  if (!Buffer.isBuffer(a) || !Buffer.isBuffer(b)) {
    fail('INVALID_ARGUMENT', 'constantTimeEqual expects two Buffers');
  }
  if (a.length === 0 || b.length === 0) return a.length === b.length;
  const other = a.length === b.length ? b : Buffer.alloc(a.length);
  const equal = crypto.timingSafeEqual(a, other);
  return a.length === b.length && equal;
}

function hmac(secret, payload, algorithm = 'sha256') {
  return crypto.createHmac(algorithm, secret).update(payload).digest();
}

function deliveryKey(provider, identifier) {
  const digest = crypto.createHash('sha256').update(String(identifier), 'utf8').digest('hex');
  return `${provider}:${digest}`;
}

function signatureKey(provider, secretIndex, signature) {
  const hash = crypto.createHash('sha256')
    .update(provider, 'utf8')
    .update('\0', 'utf8')
    .update(String(secretIndex), 'utf8')
    .update('\0', 'utf8')
    .update(signature);
  return `${provider}:${hash.digest('hex')}`;
}

// ---------------------------------------------------------------------------
// Raw body and header normalization
// ---------------------------------------------------------------------------

function normalizeBody(body) {
  if (Buffer.isBuffer(body)) return body;
  if (body instanceof Uint8Array) return Buffer.from(body.buffer, body.byteOffset, body.byteLength);
  if (typeof body === 'string') return Buffer.from(body, 'utf8');
  fail('INVALID_BODY', 'Raw body must be a Buffer, Uint8Array, or string. Pass the exact bytes received; never pass parsed JSON.');
}

function addHeader(target, key, value, arrayKeys) {
  if (typeof key !== 'string') fail('INVALID_ARGUMENT', 'Header names must be strings');
  const normalized = key.toLowerCase();
  let list = target.get(normalized);
  if (!list) {
    list = [];
    target.set(normalized, list);
  }
  const isArray = Array.isArray(value);
  if (isArray) arrayKeys.add(normalized);
  const values = isArray ? value : [value];
  for (const item of values) {
    if (item === null || item === undefined) {
      list.push(null);
    } else if (typeof item === 'string') {
      list.push(item);
    } else {
      fail('INVALID_HEADER', `Header "${normalized}" has a non-string value`);
    }
  }
}

function normalizeHeaders(headers) {
  const out = new Map();
  const arrayKeys = new Set();
  if (headers instanceof Map) {
    headers.forEach((value, key) => addHeader(out, key, value, arrayKeys));
  } else if (headers && typeof headers.get === 'function' && typeof headers.forEach === 'function') {
    headers.forEach((value, key) => addHeader(out, key, value, arrayKeys));
  } else if (headers && typeof headers === 'object') {
    for (const key of Object.keys(headers)) addHeader(out, key, headers[key], arrayKeys);
  } else {
    fail('INVALID_ARGUMENT', 'headers must be an object, Map, or Headers instance');
  }
  return { headers: out, arrayKeys };
}

function getHeader(ctx, name) {
  const key = name.toLowerCase();
  const values = ctx.headers.get(key);
  if (!values || values.length === 0 || values.every((value) => value === null)) {
    fail('MISSING_HEADER', `Required header "${key}" is missing`, { header: key });
  }
  if (values.length !== 1 || values[0] === null || ctx.headerArrays.has(key)) {
    fail('INVALID_HEADER', `Header "${key}" must appear exactly once as a single string value`, { header: key });
  }
  return values[0];
}

function getOptionalHeader(ctx, name) {
  const key = name.toLowerCase();
  const values = ctx.headers.get(key);
  if (!values || values.length === 0 || values.every((value) => value === null)) return null;
  if (values.length !== 1 || ctx.headerArrays.has(key)) {
    fail('INVALID_HEADER', `Header "${key}" must appear exactly once as a single string value`, { header: key });
  }
  return values[0];
}

function parseTimestampSeconds(value) {
  if (typeof value !== 'string' || !TIMESTAMP_RE.test(value)) {
    fail('TIMESTAMP_INVALID', 'Timestamp must be a canonical positive integer number of seconds');
  }
  const seconds = Number(value);
  if (!Number.isSafeInteger(seconds) || seconds <= 0) {
    fail('TIMESTAMP_INVALID', 'Timestamp is outside the supported range');
  }
  return seconds * 1000;
}

function enforceTimestamp(ctx, timestampMs) {
  if (typeof timestampMs !== 'number' || !Number.isFinite(timestampMs)) {
    fail('TIMESTAMP_INVALID', 'Provider returned an invalid timestamp');
  }
  const delta = Math.abs(ctx.nowMs - timestampMs);
  if (delta > ctx.toleranceSeconds * 1000) {
    fail('TIMESTAMP_OUT_OF_TOLERANCE', 'Timestamp is outside the configured replay window', {
      deltaSeconds: Math.floor(delta / 1000),
      toleranceSeconds: ctx.toleranceSeconds,
    });
  }
}

// ---------------------------------------------------------------------------
// Verification helpers used by provider adapters
// ---------------------------------------------------------------------------

const MAX_SIGNATURE_CANDIDATES = 32;
const MAX_SECRETS = 32;

function assertUsableSecret(secret) {
  if (typeof secret === 'string') {
    if (secret.length === 0 || secret.trim().length === 0) {
      fail('INVALID_SECRET', 'Secrets must be non-empty strings');
    }
    return;
  }
  if (Buffer.isBuffer(secret)) {
    if (secret.length === 0) {
      fail('INVALID_SECRET', 'Secret buffers must not be empty');
    }
    return;
  }
  fail('INVALID_SECRET', 'Secrets must be non-empty strings or buffers');
}

function verifyHmacWithSecrets(secrets, provided, payload) {
  if (!Array.isArray(secrets)) {
    fail('INVALID_ARGUMENT', 'verifyHmacWithSecrets expects an array of secrets');
  }
  const candidates = Array.isArray(provided) ? provided : [provided];
  if (candidates.length === 0) fail('INVALID_SIGNATURE', 'No signature was supplied');
  if (candidates.length > MAX_SIGNATURE_CANDIDATES) {
    fail('INVALID_SIGNATURE', `Too many signature candidates (limit ${MAX_SIGNATURE_CANDIDATES})`);
  }
  if (secrets.length > MAX_SECRETS) {
    fail('INVALID_SECRET', `Too many secrets (limit ${MAX_SECRETS})`);
  }
  for (const secret of secrets) assertUsableSecret(secret);
  let matchedIndex = -1;
  let matchedSignature = null;
  // Every matching pair is reported. A rotation header can carry one valid
  // signature per configured secret, and a delivery keyed only on the highest
  // matching secret could be replayed by resubmitting the same header with
  // that signature removed. The engine records a replay key for each pair.
  const matchedSignatures = [];
  for (let i = 0; i < secrets.length; i += 1) {
    const expected = hmac(secrets[i], payload);
    for (let j = 0; j < candidates.length; j += 1) {
      if (constantTimeEqual(candidates[j], expected)) {
        matchedIndex = i;
        matchedSignature = candidates[j];
        matchedSignatures.push({ secretIndex: i, signature: candidates[j] });
      }
    }
  }
  if (matchedIndex === -1) {
    fail('SIGNATURE_MISMATCH', 'Signature does not match any configured secret');
  }
  // The primary replay key must bind to a candidate that actually matched.
  // Binding to candidates[0] lets an attacker prepend a decoy signature to a
  // captured header and obtain a fresh replay key for the same delivery.
  return { secretIndex: matchedIndex, signature: matchedSignature, matchedSignatures };
}

function verifyHmac(ctx, provided, payload = ctx.body) {
  return verifyHmacWithSecrets(ctx.secrets, provided, payload);
}

const helpers = Object.freeze({
  decodeHex,
  decodeBase64,
  decodeHexOfLength,
  constantTimeEqual,
  hmac,
  deliveryKey,
  signatureKey,
  getHeader,
  getOptionalHeader,
  parseTimestampSeconds,
  verifyHmac,
  verifyHmacWithSecrets,
  fail,
  HookVerifyError,
});

// ---------------------------------------------------------------------------
// Replay store
// ---------------------------------------------------------------------------

class MemoryReplayStore {
  constructor(options = {}) {
    if (options === null || typeof options !== 'object') {
      fail('INVALID_ARGUMENT', 'MemoryReplayStore options must be an object');
    }
    const maxEntries = options.maxEntries === undefined ? 10000 : options.maxEntries;
    const ttlSeconds = options.ttlSeconds === undefined ? 600 : options.ttlSeconds;
    if (!Number.isSafeInteger(maxEntries) || maxEntries < 1 || maxEntries > 1000000) {
      fail('INVALID_ARGUMENT', 'maxEntries must be an integer between 1 and 1000000');
    }
    if (!Number.isSafeInteger(ttlSeconds) || ttlSeconds < 1 || ttlSeconds > 31536000) {
      fail('INVALID_ARGUMENT', 'ttlSeconds must be an integer between 1 and 31536000');
    }
    this.maxEntries = maxEntries;
    this.ttlSeconds = ttlSeconds;
    this._entries = new Map();
  }

  get size() {
    return this._entries.size;
  }

  _now(nowMs) {
    if (nowMs === undefined) return Date.now();
    if (typeof nowMs !== 'number' || !Number.isFinite(nowMs)) {
      fail('INVALID_ARGUMENT', 'nowMs must be a finite millisecond timestamp');
    }
    return nowMs;
  }

  checkAndRecord(key, nowMs) {
    if (typeof key !== 'string' || key.length === 0) {
      fail('INVALID_ARGUMENT', 'Replay key must be a non-empty string');
    }
    const now = this._now(nowMs);
    const existing = this._entries.get(key);
    if (existing !== undefined) {
      if (existing > now) {
        // Refresh recency so bounded eviction is a true LRU.
        this._entries.delete(key);
        this._entries.set(key, existing);
        return false;
      }
      this._entries.delete(key);
    }
    this._evict(now);
    this._entries.set(key, now + this.ttlSeconds * 1000);
    return true;
  }

  _evict(now) {
    if (this._entries.size < this.maxEntries) return;
    for (const [key, expiresAt] of this._entries) {
      if (expiresAt <= now) this._entries.delete(key);
    }
    while (this._entries.size >= this.maxEntries) {
      const oldest = this._entries.keys().next().value;
      if (oldest === undefined) break;
      this._entries.delete(oldest);
    }
  }

  has(key, nowMs) {
    if (typeof key !== 'string') fail('INVALID_ARGUMENT', 'Replay key must be a string');
    const now = this._now(nowMs);
    const expiresAt = this._entries.get(key);
    if (expiresAt === undefined) return false;
    if (expiresAt <= now) {
      this._entries.delete(key);
      return false;
    }
    return true;
  }

  prune(nowMs) {
    const now = this._now(nowMs);
    let removed = 0;
    for (const [key, expiresAt] of this._entries) {
      if (expiresAt <= now) {
        this._entries.delete(key);
        removed += 1;
      }
    }
    return removed;
  }

  clear() {
    this._entries.clear();
  }
}

// ---------------------------------------------------------------------------
// Provider registry
// ---------------------------------------------------------------------------

function defineProvider(definition) {
  if (!definition || typeof definition !== 'object' || Array.isArray(definition)) {
    fail('INVALID_ARGUMENT', 'Provider definition must be an object');
  }
  const { name, verify: verifyFn, description, requiredHeaders, secretOptional } = definition;
  if (typeof name !== 'string' || !/^[a-z][a-z0-9-]{0,39}$/.test(name)) {
    fail('INVALID_ARGUMENT', 'Provider name must be lowercase alphanumeric with dashes');
  }
  if (typeof verifyFn !== 'function') {
    fail('INVALID_ARGUMENT', 'Provider definition requires a verify function');
  }
  if (requiredHeaders !== undefined && (!Array.isArray(requiredHeaders) || requiredHeaders.some((h) => typeof h !== 'string'))) {
    fail('INVALID_ARGUMENT', 'requiredHeaders must be an array of strings');
  }
  return Object.freeze({
    name,
    description: typeof description === 'string' ? description : '',
    requiredHeaders: Object.freeze(requiredHeaders ? [...requiredHeaders] : []),
    secretOptional: secretOptional === true,
    verify: verifyFn,
  });
}

const registry = new Map();

function registerProvider(provider) {
  if (!provider || typeof provider.verify !== 'function' || typeof provider.name !== 'string') {
    fail('INVALID_ARGUMENT', 'Provider must define a name and a verify function');
  }
  if (registry.has(provider.name)) {
    fail('INVALID_ARGUMENT', `Provider "${provider.name}" is already registered`);
  }
  registry.set(provider.name, provider);
  return provider;
}

function resolveProvider(input) {
  if (typeof input === 'string') {
    const provider = registry.get(input);
    if (!provider) fail('UNKNOWN_PROVIDER', `Unknown provider "${input}"`);
    return provider;
  }
  if (input && typeof input === 'object' && typeof input.verify === 'function' && typeof input.name === 'string') {
    return input;
  }
  fail('INVALID_ARGUMENT', 'provider must be a registered name or a provider object');
}

function listProviders() {
  return Object.freeze([...registry.keys()].sort());
}

function getProvider(name) {
  return resolveProvider(name);
}

// ---------------------------------------------------------------------------
// Built-in provider adapters
// ---------------------------------------------------------------------------

const github = defineProvider({
  name: 'github',
  description: 'GitHub X-Hub-Signature-256, sha256=<hex>',
  requiredHeaders: ['x-hub-signature-256'],
  verify(ctx) {
    const header = getHeader(ctx, 'x-hub-signature-256');
    const match = /^sha256=([0-9a-fA-F]{64})$/.exec(header);
    if (!match) fail('INVALID_SIGNATURE', 'GitHub signature must be sha256=<64 hex characters>');
    return verifyHmac(ctx, decodeHex(match[1], 'GitHub signature'));
  },
});

const stripe = defineProvider({
  name: 'stripe',
  description: 'Stripe-Signature with t= and one or more v1= values',
  requiredHeaders: ['stripe-signature'],
  verify(ctx) {
    const header = getHeader(ctx, 'stripe-signature');
    let timestamp = null;
    const signatures = [];
    for (const part of header.split(',')) {
      const token = part.trim();
      if (token.length === 0) fail('INVALID_HEADER', 'Stripe-Signature contains an empty field');
      const equals = token.indexOf('=');
      if (equals <= 0 || equals === token.length - 1) {
        fail('INVALID_HEADER', 'Stripe-Signature fields must be key=value');
      }
      const key = token.slice(0, equals);
      const value = token.slice(equals + 1);
      if (key === 't') {
        if (timestamp !== null) fail('INVALID_HEADER', 'Stripe-Signature contains more than one t value');
        timestamp = value;
      } else if (key === 'v1') {
        if (signatures.length >= MAX_SIGNATURE_CANDIDATES) {
          fail('INVALID_SIGNATURE', `Too many signature candidates (limit ${MAX_SIGNATURE_CANDIDATES})`);
        }
        signatures.push(decodeHex(value, 'Stripe v1 signature'));
      }
    }
    if (timestamp === null || signatures.length === 0) {
      fail('INVALID_HEADER', 'Stripe-Signature requires one t value and at least one v1 value');
    }
    const timestampMs = parseTimestampSeconds(timestamp);
    const payload = Buffer.concat([Buffer.from(timestamp, 'ascii'), Buffer.from('.'), ctx.body]);
    const result = verifyHmac(ctx, signatures, payload);
    return { ...result, timestampMs };
  },
});

const slack = defineProvider({
  name: 'slack',
  description: 'Slack v0 signature and X-Slack-Request-Timestamp',
  requiredHeaders: ['x-slack-signature', 'x-slack-request-timestamp'],
  verify(ctx) {
    const signature = getHeader(ctx, 'x-slack-signature');
    const timestamp = getHeader(ctx, 'x-slack-request-timestamp');
    const match = /^v0=([0-9a-fA-F]{64})$/.exec(signature);
    if (!match) fail('INVALID_SIGNATURE', 'Slack signature must be v0=<64 hex characters>');
    const timestampMs = parseTimestampSeconds(timestamp);
    const payload = Buffer.concat([Buffer.from(`v0:${timestamp}:`, 'ascii'), ctx.body]);
    const result = verifyHmac(ctx, decodeHex(match[1], 'Slack signature'), payload);
    return { ...result, timestampMs };
  },
});

const shopify = defineProvider({
  name: 'shopify',
  description: 'Shopify X-Shopify-Hmac-Sha256, canonical base64',
  requiredHeaders: ['x-shopify-hmac-sha256'],
  verify(ctx) {
    const header = getHeader(ctx, 'x-shopify-hmac-sha256');
    return verifyHmac(ctx, decodeBase64(header, 'Shopify signature'));
  },
});

const linear = defineProvider({
  name: 'linear',
  description: 'Linear-Signature, hex HMAC-SHA256',
  requiredHeaders: ['linear-signature'],
  verify(ctx) {
    const header = getHeader(ctx, 'linear-signature');
    return verifyHmac(ctx, decodeHex(header, 'Linear signature'));
  },
});

const standardWebhooks = defineProvider({
  name: 'standard-webhooks',
  description: 'Standard Webhooks / Svix with whsec_ secrets and multi v1 signatures',
  requiredHeaders: ['webhook-id', 'webhook-timestamp', 'webhook-signature'],
  verify(ctx) {
    const messageId = getHeader(ctx, 'webhook-id');
    const timestamp = getHeader(ctx, 'webhook-timestamp');
    const header = getHeader(ctx, 'webhook-signature');
    if (!/^[A-Za-z0-9_-]{1,200}$/.test(messageId)) {
      fail('INVALID_HEADER', 'webhook-id contains unsupported characters');
    }
    if (header.trim() !== header || /\s{2,}/.test(header)) {
      fail('INVALID_HEADER', 'webhook-signature has invalid whitespace');
    }
    const signatures = [];
    for (const token of header.split(' ')) {
      if (!token.startsWith('v1,')) fail('INVALID_HEADER', 'webhook-signature entries must use v1');
      if (signatures.length >= MAX_SIGNATURE_CANDIDATES) {
        fail('INVALID_SIGNATURE', `Too many signature candidates (limit ${MAX_SIGNATURE_CANDIDATES})`);
      }
      signatures.push(decodeBase64(token.slice(3), 'Standard Webhooks signature'));
    }
    if (signatures.length === 0) fail('INVALID_HEADER', 'webhook-signature is empty');
    const keys = ctx.secrets.map((secret) => {
      if (typeof secret !== 'string' || !secret.startsWith('whsec_')) {
        fail('INVALID_SECRET', 'Standard Webhooks secrets must be strings beginning with whsec_');
      }
      return decodeBase64(secret.slice(6), 'whsec secret');
    });
    const timestampMs = parseTimestampSeconds(timestamp);
    const payload = Buffer.concat([Buffer.from(`${messageId}.${timestamp}.`, 'utf8'), ctx.body]);
    const result = verifyHmacWithSecrets(keys, signatures, payload);
    return { ...result, timestampMs, replayKey: deliveryKey('standard-webhooks', messageId) };
  },
});

const discord = defineProvider({
  name: 'discord',
  description: 'Discord Ed25519 interaction signature verification',
  requiredHeaders: ['x-signature-ed25519', 'x-signature-timestamp'],
  // The Ed25519 public key may be supplied through publicKey instead of secret,
  // so a placeholder secret must not be required to reach verify().
  secretOptional: true,
  verify(ctx) {
    const signatureHeader = getHeader(ctx, 'x-signature-ed25519');
    const timestamp = getHeader(ctx, 'x-signature-timestamp');
    const publicKey = ctx.options.publicKey !== undefined ? ctx.options.publicKey : ctx.secrets[0];
    if (typeof publicKey !== 'string') {
      fail('INVALID_SECRET', 'Discord requires an Ed25519 public key via publicKey or secret');
    }
    const publicKeyBytes = decodeHexOfLength(publicKey, 32, 'Discord public key');
    const signature = decodeHexOfLength(signatureHeader, 64, 'Discord signature');
    const timestampMs = parseTimestampSeconds(timestamp);
    const payload = Buffer.concat([Buffer.from(timestamp, 'ascii'), ctx.body]);
    let valid = false;
    try {
      const der = Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), publicKeyBytes]);
      const keyObject = crypto.createPublicKey({ key: der, format: 'der', type: 'spki' });
      valid = crypto.verify(null, payload, keyObject, signature);
    } catch (error) {
      fail('INVALID_SIGNATURE', 'Discord Ed25519 verification could not be performed');
    }
    if (!valid) fail('SIGNATURE_MISMATCH', 'Discord Ed25519 signature does not match the public key');
    return { timestampMs, secretIndex: 0, signature };
  },
});

for (const provider of [github, stripe, slack, shopify, linear, standardWebhooks, discord]) {
  registerProvider(provider);
}

// "svix" is an alias for the same verification logic, reporting the canonical name.
const svixAlias = Object.freeze({
  name: 'svix',
  description: 'Alias for standard-webhooks',
  requiredHeaders: standardWebhooks.requiredHeaders,
  verify: standardWebhooks.verify,
  canonicalName: 'standard-webhooks',
});
registerProvider(svixAlias);

const providerAliases = Object.freeze({
  github,
  stripe,
  slack,
  shopify,
  linear,
  svix: standardWebhooks,
  standardWebhooks,
  'standard-webhooks': standardWebhooks,
  discord,
});

const providers = Object.freeze(providerAliases);

// ---------------------------------------------------------------------------
// Verification engine
// ---------------------------------------------------------------------------

function normalizeTolerance(value) {
  const tolerance = value === undefined ? 300 : value;
  if (!Number.isSafeInteger(tolerance) || tolerance < 0) {
    fail('INVALID_ARGUMENT', 'toleranceSeconds must be a non-negative safe integer');
  }
  return tolerance;
}

function resolveNow(value) {
  if (value === undefined) return Date.now();
  if (typeof value !== 'function') fail('INVALID_ARGUMENT', 'now must be a function returning milliseconds');
  const result = value();
  if (typeof result !== 'number' || !Number.isFinite(result)) {
    fail('INVALID_ARGUMENT', 'now() must return a finite millisecond timestamp');
  }
  return result;
}

function normalizeSecrets(options, provider) {
  const configured = options.secrets !== undefined ? options.secrets : options.secret;
  // Providers such as Discord accept a public key instead of a shared secret.
  if (configured === undefined && provider.secretOptional === true) return [];
  const list = Array.isArray(configured) ? configured : [configured];
  if (list.length === 0 || list.some((secret) => typeof secret !== 'string' || secret.length === 0 || secret.trim().length === 0)) {
    fail('INVALID_SECRET', 'Provide at least one non-empty secret via secret or secrets');
  }
  return list;
}

function isThenable(value) {
  if (value === null || (typeof value !== 'object' && typeof value !== 'function')) return false;
  try {
    return typeof value.then === 'function';
  } catch {
    // An accessor that throws is not a usable result object either. Treat it
    // as a thenable so the caller fails closed instead of leaking the error.
    return true;
  }
}

// A rejected promise from a provider or from a synchronous replay-store call
// must not survive as an unhandled rejection after this path has already
// failed closed; an unhandled rejection terminates Node by default.
function discardRejection(value) {
  Promise.resolve(value).catch(() => {});
}

function buildContext(provider, body, headers, options) {
  if (options === null || typeof options !== 'object' || Array.isArray(options)) {
    fail('INVALID_ARGUMENT', 'options must be an object');
  }
  const normalized = normalizeHeaders(headers);
  return Object.freeze({
    provider: provider.name,
    body: normalizeBody(body),
    headers: normalized.headers,
    headerArrays: normalized.arrayKeys,
    secrets: normalizeSecrets(options, provider),
    toleranceSeconds: normalizeTolerance(options.toleranceSeconds),
    nowMs: resolveNow(options.now),
    options: Object.freeze({ ...options }),
    helpers,
  });
}

function isSignatureValue(value) {
  return Buffer.isBuffer(value) || value instanceof Uint8Array || typeof value === 'string';
}

function replayKeyFor(provider, secretIndex, material) {
  return deliveryKey(provider.name, signatureKey(provider.name, secretIndex, material));
}

function finish(provider, ctx, result, replayStore, asyncMode) {
  // A provider that forgets to be synchronous returns a promise here. Treating
  // it as a result object would report valid: true before any comparison ran.
  if (isThenable(result)) {
    discardRejection(result);
    fail('PROVIDER_ERROR', `${provider.name} verify() returned a promise; provider verify functions must be synchronous`);
  }
  if (!result || typeof result !== 'object') fail('PROVIDER_ERROR', `${provider.name} verify() must return a result object`);
  if (result.timestampMs !== undefined && result.timestampMs !== null) enforceTimestamp(ctx, result.timestampMs);
  if (result.secretIndex !== undefined && result.secretIndex !== null &&
    (!Number.isSafeInteger(result.secretIndex) || result.secretIndex < 0)) {
    fail('PROVIDER_ERROR', `${provider.name} verify() returned an invalid secretIndex`);
  }

  const keys = [];
  let replayKey = result.replayKey;
  if (replayKey === undefined || replayKey === null) {
    const signature = result.signature;
    if (signature !== undefined && signature !== null && !isSignatureValue(signature)) {
      fail('PROVIDER_ERROR', `${provider.name} verify() returned an unsupported signature value`);
    }
    const matched = result.matchedSignatures;
    if (matched !== undefined && matched !== null) {
      if (!Array.isArray(matched) || matched.length > MAX_SIGNATURE_CANDIDATES) {
        fail('PROVIDER_ERROR', `${provider.name} verify() returned an invalid matched signature list`);
      }
      for (const entry of matched) {
        if (!entry || typeof entry !== 'object' ||
          !Number.isSafeInteger(entry.secretIndex) || entry.secretIndex < 0 ||
          !isSignatureValue(entry.signature) || entry.signature.length === 0) {
          fail('PROVIDER_ERROR', `${provider.name} verify() returned an invalid matched signature entry`);
        }
        keys.push(replayKeyFor(provider, entry.secretIndex, entry.signature));
      }
    }
    // An empty signature would collapse every delivery to one replay key.
    const material = signature !== undefined && signature !== null && signature.length > 0 ? signature : ctx.body;
    const secretIndex = result.secretIndex === undefined || result.secretIndex === null ? 0 : result.secretIndex;
    replayKey = replayKeyFor(provider, secretIndex, material);
  }
  if (typeof replayKey !== 'string' || replayKey.length === 0) {
    fail('INVALID_ARGUMENT', 'Replay key must be a non-empty string');
  }
  // The primary key is recorded first, then every other signature that matched
  // so a rotation delivery cannot be replayed by dropping one of them.
  keys.unshift(replayKey);

  const output = Object.freeze({
    provider: provider.canonicalName || provider.name,
    valid: true,
    timestamp: result.timestampMs === undefined || result.timestampMs === null ? null : new Date(result.timestampMs),
    secretIndex: result.secretIndex === undefined ? null : result.secretIndex,
    replayKey,
  });

  const applyStore = (seen, key) => {
    if (seen === false) fail('REPLAYED_DELIVERY', 'This delivery has already been verified', { replayKey: key });
    if (seen !== true) {
      fail('INVALID_ARGUMENT', 'Replay store checkAndRecord must return true for a new delivery or false for a replay');
    }
  };

  const complete = () => (asyncMode ? Promise.resolve(output) : output);

  if (ctx.options.replayStore === undefined) return complete();

  if (!replayStore || typeof replayStore.checkAndRecord !== 'function') {
    fail('INVALID_ARGUMENT', 'replayStore must implement checkAndRecord(key, nowMs)');
  }
  const check = replayStore.checkAndRecord;
  // Refuse an async store before calling it: the synchronous entry point
  // cannot honor a promise, and the call itself may already have persisted
  // the delivery key, which would burn a legitimate delivery id.
  if (!asyncMode && check.constructor && check.constructor.name === 'AsyncFunction') {
    fail('INVALID_ARGUMENT', 'This replay store is asynchronous; use verifyAsync instead');
  }

  const uniqueKeys = [...new Set(keys)];
  let index = 0;
  const recordNext = () => {
    while (index < uniqueKeys.length) {
      const key = uniqueKeys[index];
      index += 1;
      const seen = check.call(replayStore, key, ctx.nowMs);
      if (isThenable(seen)) {
        if (!asyncMode) {
          discardRejection(seen);
          fail('INVALID_ARGUMENT', 'This replay store is asynchronous; use verifyAsync instead');
        }
        return Promise.resolve(seen).then((value) => {
          applyStore(value, key);
          return recordNext();
        });
      }
      applyStore(seen, key);
    }
    return complete();
  };
  return recordNext();
}

function unpack(args) {
  if (args.length === 1 && args[0] && typeof args[0] === 'object' && !Array.isArray(args[0])) {
    const single = args[0];
    const options = { ...single };
    delete options.provider;
    delete options.body;
    delete options.headers;
    return [single.provider, single.body, single.headers, options];
  }
  return [args[0], args[1], args[2], args.length > 3 && args[3] !== undefined ? args[3] : {}];
}

function runVerify(providerInput, body, headers, options) {
  const provider = resolveProvider(providerInput);
  const ctx = buildContext(provider, body, headers, options);
  let result;
  try {
    result = provider.verify(ctx);
  } catch (error) {
    if (error instanceof HookVerifyError) throw error;
    fail('PROVIDER_ERROR', `${provider.name} verification failed`, { message: String(error && error.message ? error.message : error) });
  }
  return finish(provider, ctx, result, ctx.options.replayStore, false);
}

function verify(...args) {
  return runVerify(...unpack(args));
}

// Declared async so argument, provider, and replay-store failures surface as a
// rejected promise rather than a synchronous throw that callers cannot catch
// with .catch().
async function verifyAsync(...args) {
  const [providerInput, body, headers, options] = unpack(args);
  const provider = resolveProvider(providerInput);
  const ctx = buildContext(provider, body, headers, options);
  let result;
  try {
    result = provider.verify(ctx);
  } catch (error) {
    if (error instanceof HookVerifyError) throw error;
    fail('PROVIDER_ERROR', `${provider.name} verification failed`, { message: String(error && error.message ? error.message : error) });
  }
  return finish(provider, ctx, result, ctx.options.replayStore, true);
}

function isValid(...args) {
  try {
    verify(...args);
    return true;
  } catch (error) {
    if (error instanceof HookVerifyError) return false;
    throw error;
  }
}

function createVerifier(defaults = {}) {
  if (!defaults || typeof defaults !== 'object' || Array.isArray(defaults)) {
    fail('INVALID_ARGUMENT', 'createVerifier expects an options object');
  }
  const merge = (overrides) => {
    if (overrides === undefined || overrides === null) return { ...defaults };
    if (typeof overrides !== 'object' || Array.isArray(overrides)) {
      fail('INVALID_ARGUMENT', 'createVerifier overrides must be an options object');
    }
    return { ...defaults, ...overrides };
  };
  return Object.freeze({
    verify(provider, body, headers, overrides) {
      return verify(provider, body, headers, merge(overrides));
    },
    verifyAsync(provider, body, headers, overrides) {
      return verifyAsync(provider, body, headers, merge(overrides));
    },
    isValid(provider, body, headers, overrides) {
      return isValid(provider, body, headers, merge(overrides));
    },
  });
}

module.exports = Object.freeze({
  HookVerifyError,
  ERROR_CODES,
  MemoryReplayStore,
  defineProvider,
  registerProvider,
  getProvider,
  listProviders,
  verify,
  verifyAsync,
  isValid,
  createVerifier,
  providers,
  github,
  stripe,
  slack,
  shopify,
  linear,
  svix: standardWebhooks,
  standardWebhooks,
  discord,
  helpers: Object.freeze({
    decodeHex,
    decodeBase64,
    constantTimeEqual,
    deliveryKey,
    normalizeBody,
    normalizeHeaders: (headers) => normalizeHeaders(headers).headers,
    parseTimestampSeconds,
  }),
});
