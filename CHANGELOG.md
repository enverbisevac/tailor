# Changelog

## 0.1.0-alpha.2 — Unreleased

- Add CGO/Git, Node xxhash, Python orjson, and Java JNI compatibility suites
  with Linux amd64/arm64 CI coverage.
- Extend real clean/vulnerable/inventory policy tests to OSV and Grype/Syft,
  including CVE aliases and early source-gate rejection.
- Scan immutable Docker exports with OSV, retain the exact image ID in evidence,
  and request all vulnerabilities with explicit empty-source policy.
- Add bounded coverage-guided ELF, lockfile, and scanner-report fuzz targets.
- Add `tailor explain` with dependency edges, package versions, source call sites,
  unresolved dynamic calls, and explicit completeness/security limitations.
- Keep extra-file parents traversable; use `/app` as the runtime working
  directory and reject variable-expanding destinations.

## 0.1.0-alpha.1 — 2026-11-17

Initial experimental release:

- Inspect static/dynamic Linux ELF, executable JARs, and Node.js/Python projects.
- Generate formatted Dockerfiles with pinned bases and a non-root runtime user;
  create missing outputs, update regular outputs, and skip unchanged content.
- Resolve explicit commands and ELF dependency closures from Debian/glibc
  sysroots, with conservative process-call discovery across supported languages.
- Snapshot transactional build inputs, retain scan evidence, and promote the
  exact built image ID only after vulnerability gates pass.
- Support OSV-Scanner, Grype, and Trivy adapters; verify Grype database freshness
  and use Syft for Grype image inventories.
- Check Python/Node builder/runtime compatibility and Java runtime startup.
- Provide Go, Node.js, Python, and Java health-service examples.
- Add cross-platform CI, real Trivy gate tests, version reporting, MIT licensing,
  and release archives with SHA-256 checksums.

Known limits: prepared Debian/glibc sysroots only; discovery is incomplete for
dynamic behavior; Java class/JNI and installed native-extension validation are
not comprehensive. The real scanner integration suite currently covers Trivy;
OSV-Scanner and Grype do not yet have equivalent automated end-to-end coverage.
