# hookverify

Zero-dependency webhook signature verification for Node.js. One small engine, seven verified providers, constant-time comparisons, replay-window enforcement, and an open adapter registry.

**Tests: 275 passing** (verified with `npm test` on Node 26, also compatible with Node 18+).

## Why

Most webhook verification snippets get at least one of these wrong:

- Compare hex strings with `===`, leaking timing information.
- Parse the JSON body and re-serialize it before verifying, changing the bytes.
- Accept a signature of any length, so `timingSafeEqual` throws and leaks a length oracle.
- Skip timestamp checks entirely, so a captured request can be replayed forever.
- Hardcode one secret, making zero-downtime rotation impossible.

`hookverify` fixes all five. It uses only `node:crypto` and has zero runtime dependencies.

## Install

```sh
npm install @aarivbuildz/hookverify
```

No build step, no native addons, no transitive packages.

## Quick start

```js
import { verify } from '@aarivbuildz/hookverify';

// `request.rawBody` must be the exact bytes received, not parsed JSON.
const result = verify('github', request.rawBody, request.headers, {
  secrets: process.env.GITHUB_WEBHOOK_SECRETS.split(','),
  toleranceSeconds: 300,
});

// result: { provider, valid: true, timestamp, secretIndex, replayKey }
```

CommonJS works identically:

```js
const { verify } = require('@aarivbuildz/hookverify');
```

Strict TypeScript definitions ship with the package. No `@types/*` install needed.

## Built-in providers

| Provider name | Header(s) | Secret form | Timestamp |
| --- | --- | --- | --- |
| `github` | `X-Hub-Signature-256` | shared string | none |
| `stripe` | `Stripe-Signature` | shared string | `t=` in header |
| `slack` | `X-Slack-Signature`, `X-Slack-Request-Timestamp` | shared string | dedicated header |
| `shopify` | `X-Shopify-Hmac-Sha256` | shared string (base64 HMAC) | none |
| `linear` | `Linear-Signature` | shared string | none |
| `standard-webhooks` (alias `svix`) | `webhook-id`, `webhook-timestamp`, `webhook-signature` | `whsec_<base64>` | dedicated header |
| `discord` | `X-Signature-Ed25519`, `X-Signature-Timestamp` | Ed25519 public key (hex) | dedicated header |

Every adapter can also be imported directly:

```js
import github from 'hookverify/providers/github';
```

## Replay protection

Timestamp checks are on by default (`toleranceSeconds: 300`). Both stale and future-skew timestamps are rejected. Providers without a timestamp in their scheme are protected by the optional replay store, which keys on a digest of the verified signature and, where available, the delivery id.

When a header carries several valid signatures, as during secret rotation, a digest is recorded for every signature that verified. A captured delivery therefore cannot be replayed by resubmitting the same header with one of its signatures removed.

```js
import { verify, MemoryReplayStore } from '@aarivbuildz/hookverify';

const replayStore = new MemoryReplayStore({ maxEntries: 10_000, ttlSeconds: 600 });

verify('github', rawBody, headers, {
  secret: process.env.GITHUB_SECRET,
  replayStore,
});
```

`MemoryReplayStore` is a bounded LRU with TTL. It evicts the least recently used entry once `maxEntries` is reached, so a flood of unique delivery ids cannot grow memory without limit.

For multi-process deployments, pass any object with `checkAndRecord(key, nowMs)` returning a boolean or a promise of one. Use `verifyAsync` for asynchronous stores:

```js
const result = await verifyAsync('stripe', rawBody, headers, {
  secret: process.env.STRIPE_SECRET,
  replayStore: redisReplayStore,
});
```

## Key rotation

Pass an ordered list. The result tells you which secret matched, so you can retire old keys safely:

```js
const result = verify('github', rawBody, headers, {
  secrets: [process.env.SECRET_CURRENT, process.env.SECRET_PREVIOUS],
});
console.log(result.secretIndex); // 0 or 1
```

## Custom providers

```js
import { defineProvider, registerProvider, verify } from '@aarivbuildz/hookverify';
import { createHmac } from 'node:crypto';

const acme = defineProvider({
  name: 'acme',
  requiredHeaders: ['x-acme-signature'],
  verify(ctx) {
    const header = ctx.helpers.getHeader(ctx, 'x-acme-signature');
    const provided = ctx.helpers.decodeHex(header);
    const payload = createHmac('sha256', ctx.secrets[0]).update(ctx.body).digest();
    if (!ctx.helpers.constantTimeEqual(provided, payload)) {
      ctx.helpers.fail('SIGNATURE_MISMATCH', 'Acme signature mismatch');
    }
    return { secretIndex: 0, signature: provided };
  },
});

registerProvider(acme);
verify('acme', rawBody, headers, { secret: 'shared' });
```

Helpers enforce strict canonical hex and base64 decoding, so custom adapters inherit the same encoding discipline as the built-ins. See `GOOD_FIRST_ISSUES.md` for fifteen concrete adapter contributions.

## Error handling

Every rejection is a `HookVerifyError` with a stable `error.code`:

```js
import { verify, HookVerifyError } from '@aarivbuildz/hookverify';

try {
  verify('stripe', rawBody, headers, { secret });
} catch (error) {
  if (error instanceof HookVerifyError) {
    switch (error.code) {
      case 'SIGNATURE_MISMATCH':
      case 'TIMESTAMP_OUT_OF_TOLERANCE':
      case 'REPLAYED_DELIVERY':
        return sendStatus(401);
      default:
        return sendStatus(400);
    }
  }
  throw error;
}
```

Use `isValid(provider, body, headers, options)` when you only need a boolean.

## Threat model

**In scope**

- Signature forgery through timing oracles, encoding confusion, or length mismatches.
- Replay of captured deliveries outside the tolerance window or after a prior successful verification.
- Accidental verification of re-serialized JSON instead of the exact received bytes.
- Secret rotation outages and accidental use of a retired key.
- Memory exhaustion through unbounded replay stores or huge signature arrays.

**Out of scope**

- Transport security. Terminate TLS before this library sees the request.
- Authorization logic after verification. A valid signature proves origin, not permission.
- Endpoint rate limiting. Apply it at the HTTP layer.
- Compromise of the application process or its secret store.
- Providers that sign a canonicalized subset of the body instead of the raw bytes. Do not use this library with such schemes.

**Design decisions**

- Body is limited to `Buffer`, `Uint8Array`, or `string`. Parsed objects throw `INVALID_BODY`.
- Header values must be single strings. Ambiguous multi-value headers throw `INVALID_HEADER`.
- Hex and base64 decoders reject non-canonical spellings, including bad padding and non-zero pad bits.
- Signature comparison always calls `timingSafeEqual` on equal-length decoded buffers. A length mismatch is reported only after the comparison and never by letting `timingSafeEqual` throw.
- The number of signature candidates and secrets is capped at 32 each, preventing CPU exhaustion via header flooding.

## Development

```sh
npm test
```

The suite runs with Node's built-in test runner and needs no network access, no fixtures downloaded at test time, and no dependencies installed. It covers ESM and CommonJS parity, all seven providers, rotation, replay windows, encoding edge cases, and adversarial resource guards.

## Contributing

See `CONTRIBUTING.md` and `GOOD_FIRST_ISSUES.md`. Security reports should follow `SECURITY.md`.

## License

MIT. See `LICENSE`.
