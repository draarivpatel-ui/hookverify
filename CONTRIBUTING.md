# Contributing to hookverify

Thanks for helping maintain a security-critical package. The bar is deliberately high: a small, auditable core and a comprehensive test suite.

## Ground rules

- Zero runtime dependencies. Only `node:crypto` and other Node builtins may be imported by files under `src/` and `cjs/`.
- No new dependency may be added to `package.json` without an explicit security discussion.
- Every behavior change needs a deterministic regression test. Tests must not require network access.
- Do not weaken an existing check to make a test pass. If a test encodes a wrong expectation, fix the test and explain why.
- Keep error codes stable. Adding a new code is fine; renaming one is a breaking change.

## Development setup

There is nothing to install:

```sh
npm test
```

The test runner is Node's built-in `node --test`. Node 18 or newer is required.

## Repository layout

- `src/index.mjs` public ESM entry point.
- `src/internal.mjs` ESM facade over the shared engine.
- `src/providers/*.mjs` one-line adapter re-exports.
- `cjs/internal.cjs` the single verification engine used by both module systems.
- `cjs/index.cjs` public CommonJS entry point.
- `types/index.d.ts` hand-written strict definitions.
- `tests/*.test.mjs` deterministic security tests.
- `GOOD_FIRST_ISSUES.md` curated adapter contributions.

Why one engine? If ESM and CommonJS had separate implementations, they could drift. The ESM surface is a thin `createRequire` facade over the CommonJS engine, so parity is structural rather than tested by convention alone.

## Adding a provider adapter

1. Read the provider's official signature verification documentation and note the exact byte layout of the signed payload.
2. Implement `verify(ctx)` using `defineProvider`. Always use `ctx.helpers.getHeader` and `ctx.helpers.verifyHmac` or `verifyHmacWithSecrets`. Never compare strings with `===`.
3. Register the provider in the engine and export it from `src/index.mjs`, `cjs/index.cjs`, and `types/index.d.ts`.
4. Add a one-line re-export under `src/providers/`.
5. Add tests covering: a valid vector, a tampered body, a wrong secret, a missing header, a malformed signature, rotation, and (if the scheme has a timestamp) both skew directions.
6. Add the provider to the README table.

See `GOOD_FIRST_ISSUES.md` for fifteen ready-to-claim adapter specs.

## Commit and pull request style

- One logical change per pull request.
- Include the test count before and after your change in the description.
- Update documentation in the same pull request when behavior changes.
- Avoid em dashes and en dashes in documentation; use commas, periods, or parentheses instead.

## Review checklist for maintainers

- [ ] No runtime dependencies added.
- [ ] All signature comparisons go through `timingSafeEqual` on equal-length buffers.
- [ ] No string `===` on any signature, secret, or digest.
- [ ] Strict canonical hex and base64 decoding used for all encoded inputs.
- [ ] Timestamp tolerance enforced in both directions.
- [ ] Replay key is provider scoped and derived from verified material only.
- [ ] ESM and CJS parity tests updated.
- [ ] Types updated.
- [ ] `npm test` green.
