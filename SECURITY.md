# Security policy

Tailor alpha versions are experimental. No version currently has a production
security-support commitment. Fixes target the latest alpha; older alphas may
not receive backports. Review the README's security model and limitations
before using Tailor with sensitive inputs or production workloads.

## Reporting a vulnerability

Report vulnerabilities privately through GitHub's
[Report a vulnerability form](https://github.com/enverbisevac/tailor/security/advisories/new).
Private vulnerability reporting is enabled for this repository. Reports made
through that form are shared privately with the maintainers.

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
