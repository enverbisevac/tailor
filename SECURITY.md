# Security policy

Tailor 0.1.0-alpha.1 is experimental. No version currently has a production
security-support commitment. Fixes target the latest alpha; older alphas may
not receive backports. Review the README's security model and limitations
before using Tailor with sensitive inputs or production workloads.

## Reporting a vulnerability

Use the repository's **Security → Advisories → Report a vulnerability** form
when private vulnerability reporting is enabled. Before public distribution,
the maintainer must enable that form or publish a working private contact in
this file. This source snapshot does not yet identify a hosted repository or
private reporting address.

Do not post exploit details, credentials, or proprietary artifacts in public
issues. A useful private report includes the Tailor version, operating system
and architecture, scanner version, minimal reproduction, expected behavior,
and observed impact. Remove secrets from logs and scan evidence.

## Scope

Relevant issues include dependency omissions that bypass documented checks,
scan-policy bypasses, input/output path escapes, binary-parser defects, and
promotion of an image after a failed gate. Scanner databases can be incomplete
or change after a scan; a passing scan is not a permanent safety guarantee.
Tailor is not a sandbox for hostile builds or runtimes. Run untrusted inputs
on isolated, disposable build infrastructure.
