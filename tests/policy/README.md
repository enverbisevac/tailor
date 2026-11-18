# Locked build and policy integration

Run `make policy-integration` with Zig, Docker, Trivy, Syft and Skopeo installed.
The Zig/scanner versions used by CI are pinned in `scripts/tools.json`; CI uses
Ubuntu's signed package repositories for Skopeo and records its version in the
generated provenance.

The suite compiles a static Linux C service with Zig and uses the same
hash-pinned clean PyPI wheel as the scanner suites. It verifies:

- Lock creation is idempotent; changed bytes, modes and newly added project
  files are rejected. The lock excludes itself and cannot be overwritten by
  locked generation. Mismatches fail with Docker/scanners absent from PATH.
- A locked build passes real Trivy scans and a command smoke test before
  promotion, then exports a real Syft SBOM and OCI-attached provenance.
- Every referenced image/evidence blob matches its digest and size. Both
  attachments identify the exported image, and the saved source descriptor
  chain binds it to the exact scanned Docker ID.
- An HTTP health check passes; nonzero exits, a never-ending command and an
  unsuccessful HTTP endpoint prevent tag creation.

Fixture images and smoke containers are disposable. Raw scanner reports and OCI
evidence remain in `.tailor-reports/` for inspection. This checks selected
workloads and unsigned evidence integrity, not complete application behavior or
the trustworthiness of the builder.
