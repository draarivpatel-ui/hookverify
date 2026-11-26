# Security policy

## Supported versions

Security fixes are applied to the latest published major version. There is only one supported line today: 1.x.

## Reporting a vulnerability

Please report security issues privately through the repository's private vulnerability reporting feature. Do not open a public issue for an unpatched vulnerability.

Include:

1. The affected version and module system (ESM or CommonJS).
2. A minimal reproduction, ideally as a test case.
3. The impact you observed (signature bypass, timing leak, resource exhaustion, and so on).
4. A suggested fix if you have one.

You should receive an acknowledgement within seven days. Patches and a release follow once the issue is confirmed. Credit is given in the release notes unless you prefer otherwise.

## Scope

The following are security issues:

- Any path that accepts a signature that was not produced by a configured secret.
- Any path where comparison time depends on the contents or length of a decoded signature.
- Any bypass of timestamp tolerance or replay-store checks.
- Any unbounded memory or CPU growth driven by attacker-controlled headers.
- Any decoding path that accepts a non-canonical encoding and treats it as equivalent to a canonical one.

The following are not security issues in this library:

- Vulnerabilities in an application's secret storage or TLS configuration.
- Missing replay protection when the application does not pass a `replayStore` or a timestamp-bearing provider.
- Rate limiting, authentication, or authorization decisions made after verification.

## Disclosure process

1. Report received and triaged.
2. Reproduction confirmed and severity assigned.
3. Fix developed with a regression test in `tests/`.
4. Patch released; advisory published afterwards.

## Security design notes

`hookverify` never exposes secret material in errors, logs, or result objects. Replay keys are SHA-256 digests of provider-scoped identifiers, never raw delivery ids or signatures. All cryptographic operations use `node:crypto` from the Node standard library.
