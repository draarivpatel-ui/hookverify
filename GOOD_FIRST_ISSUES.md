# Good first issues: provider adapters

Fifteen concrete, self-contained adapter contributions. Each one adds a provider without touching the verification engine's core logic. Claim one by opening an issue with its number.

All adapters must use `defineProvider` and the helpers on `ctx`. Do not add dependencies. Do not introduce a new comparison path.

## Shared acceptance criteria

Every adapter PR must include:

1. A valid signature vector computed with an independent implementation (`node:crypto` in the test is fine).
2. A tampered body case expecting `SIGNATURE_MISMATCH`.
3. A wrong-secret case expecting `SIGNATURE_MISMATCH`.
4. A missing-header case expecting `MISSING_HEADER`.
5. A malformed-signature case expecting `INVALID_SIGNATURE` or `INVALID_HEADER`, matching the engine's conventions.
6. A rotation case using two secrets when the provider signs with a shared secret.
7. A timestamp case in both directions when the scheme includes a timestamp.
8. An entry in the README provider table and a one-line re-export under `src/providers/`.
9. Updated `types/index.d.ts` exports.

## 1. Twilio

Header `X-Twilio-Signature`. The signed payload is the full request URL plus, for POST, the sorted `key=value` pairs of the form parameters concatenated without separators. Use `ctx.options.url` for the absolute URL. HMAC-SHA256 with the auth token, base64 encoded. Compare via `decodeBase64` and `verifyHmac`.

## 2. Paddle (Billing)

Header `Paddle-Signature`, format `ts=<seconds>;h1=<hex>`. The signed payload is `<timestamp>:<raw body>`. Enforce timestamp tolerance. Support multiple `h1` values separated by semicolons for rotation.

## 3. Clerk

Headers `svix-id`, `svix-timestamp`, `svix-signature`. The scheme is Standard Webhooks with different header names and a `whsec_` secret. Reuse the engine's Standard Webhooks logic with a thin header-name adapter. Report `replayKey` from `webhook-id` so delivery deduplication uses the provider's id.

## 4. Resend

Header `svix-signature` with `svix-id` and `svix-timestamp`. Same family as Clerk. Factor the shared payload construction into a helper if three or more adapters duplicate it, but keep each adapter file small.

## 5. Vercel

Header `x-vercel-signature`, hex HMAC-SHA256 of the raw body with the deployment's webhook secret. No timestamp in the base scheme. Add a case-insensitive hex test, since Vercel emits lowercase.

## 6. Cloudflare

Header `X-Webhook-Signature` may carry an HMAC-SHA256 hex digest of the raw body when a static secret is configured. Verify strict hex, and reject the request if the header also contains unsupported algorithm prefixes.

## 7. GitLab

Header `X-Gitlab-Token`. GitLab sends a shared token in plaintext, not an HMAC. Implement constant-time byte comparison against the configured secret via `constantTimeEqual(Buffer.from(header), Buffer.from(secret))`. Document clearly in the README table that this is token equality, not a cryptographic signature.

## 8. Bitbucket

Header `X-Hub-Signature`, format `sha256=<hex>`, signed over the raw body. Similar to GitHub but with the legacy header name. Reuse the GitHub payload layout.

## 9. Jira

Header `X-Atlassian-Webhook-Signature`, base64 HMAC-SHA256 of the raw body. Validate canonical base64 strictly. Include a test proving that unpadded input is rejected.

## 10. Intercom

Header `X-Intercom-Signature`, format `sha256=<hex>` of the raw body. HMAC-SHA256 with the client secret. No timestamp in the base scheme.

## 11. HubSpot

Header `X-HubSpot-Signature-V3`, format `sha256=<hex>`. The signed payload is `<app secret><method><absolute URL><raw body>` with a timestamp header `X-HubSpot-Request-Timestamp` appended as `<payload>;<timestamp>`. Enforce tolerance. Route the absolute URL through `ctx.options.url`.

## 12. Brevo

Header `X-Signature`, base64 HMAC-SHA256 of the raw body using the webhook key. Reject non-canonical base64. No timestamp in the base scheme.

## 13. Postmark

Header `X-Postmark-Webhook-Signature`, hex HMAC-SHA256 of the raw body with the webhook signing token. Include a test with an empty body, since delivery-status webhooks can be small.

## 14. LemonSqueezy

Header `X-Signature`, hex HMAC-SHA256 of the raw body. No timestamp in the base scheme. Include a test with a multi-byte UTF-8 body to prove raw byte handling.

## 15. Sentry

Header `sentry-hook-signature`, hex HMAC-SHA256 of the raw body with the client secret. No timestamp in the base scheme. Include a test where the payload contains a null byte.

## What not to change in these PRs

- Do not modify `cjs/internal.cjs` verification helpers unless a genuine shared need arises, and explain it in the PR.
- Do not add an `npm install` step or any package to `dependencies` or `devDependencies`.
- Do not weaken the strict decoder rules to accommodate a provider. If a provider genuinely uses URL-safe base64, add a local decoding helper inside that adapter and document why.
- Do not add `Co-Authored-By` trailers to commits.
