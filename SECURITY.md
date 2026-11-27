# Security policy

## Supported versions

| Version | Supported |
| --- | --- |
| Latest published 1.x release | Yes |
| Older releases | No |

Security fixes are applied to the latest published 1.x release. Users should upgrade to the fixed release as soon as it is available.

## Reporting a vulnerability

Report suspected vulnerabilities privately through [GitHub private vulnerability reporting](https://github.com/draarivpatel-ui/hookverify/security/advisories/new). Do not open a public issue for an unpatched vulnerability.

Include:

1. The affected version and module system (ESM or CommonJS).
2. A minimal reproduction, ideally as a test case.
3. The impact you observed (signature bypass, timing leak, resource exhaustion, and so on).
4. A suggested fix if you have one.

Do not include real webhook secrets, credentials or customer data in a report.

## Acknowledgment and coordinated disclosure timeline

- We aim to acknowledge a vulnerability report within 3 business days.
- We aim to complete initial triage and severity assessment within 14 days.
- We aim to release a fix within 90 days of confirming a vulnerability, sooner for high severity issues when practical.
- We coordinate public disclosure with the reporter. A public advisory is normally published after a fixed release is available or on a mutually agreed date.
- Credit is given in release notes and the advisory unless the reporter prefers otherwise.
- If a report is not accepted as a vulnerability, we will explain the reasoning before closing the advisory.

## Vulnerability handling process

1. Receive the private report through the GitHub security advisory.
2. Reproduce the issue, determine affected versions and assess severity.
3. Develop a fix with regression tests in `tests/`.
4. Publish the fixed release and prepare the advisory.
5. Publish coordinated disclosure notes with affected and fixed versions.

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

## Security design notes

`hookverify` never exposes secret material in errors, logs, or result objects. Replay keys are SHA-256 digests of provider-scoped identifiers, never raw delivery ids or signatures. All cryptographic operations use `node:crypto` from the Node standard library.
