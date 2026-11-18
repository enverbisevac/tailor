# A locked health-service image

Run these commands from a Tailor source checkout with Go, Docker running Linux
containers, and the Tailor executable on PATH. Install Trivy, Syft, and Skopeo
on PATH as well; `--attest` uses the latter two. See [release validation](../RELEASING.md)
for pinned scanner installation. Advisory databases and container images need
network access during setup and scanning.

Compile the dependency-free Go health example for your Docker engine's target:

```sh
mkdir -p zig-out/quick-start
# Use arm64 instead when the Docker engine is ARM64.
(cd examples/go && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
  go build -trimpath -o ../../zig-out/quick-start/server .)
```

Create and review a lock. Lock generation inspects files without executing the
application or invoking Docker/scanners:

```sh
tailor lock zig-out/quick-start/server --smoke-http /health --attest
cat tailor.lock
```

Build using the same policy, requiring the reviewed plan:

```sh
tailor build zig-out/quick-start/server --locked \
  --smoke-http /health --attest --scanner trivy \
  --tag tailor-quick-start:verified
```

Tailor scans the staged source and final image, checks `GET /health` in an
offline container, and exports evidence before creating the requested tag.
The tag must not already exist. Changed inputs or policy require reviewing a
new lock; `--locked` never rewrites it. New advisories can block a previously
successful build.

Inspect the `.tailor-reports/build-*` directory printed by the build:

```sh
# Substitute the exact directory printed by your build.
cat .tailor-reports/build-<id>/build-report.json
cat .tailor-reports/build-<id>/sbom.cdx.json
cat .tailor-reports/build-<id>/provenance.json
```

The `oci/` subdirectory contains the image and subject-bound SBOM/provenance
manifests. See [the evidence format](build-type-v1.md) for digest relationships.
This evidence is unsigned, self-reported, and does not establish a SLSA level.
Static Go binaries rely on scanner support for embedded Go build information;
smoke success and clean scans do not establish complete runtime safety.

To try the promoted service on the Docker host:

```sh
docker run --rm --name tailor-quick-start --read-only --cap-drop ALL \
  --security-opt no-new-privileges:true -p 127.0.0.1:8080:8080 \
  tailor-quick-start:verified
# In another terminal:
curl --fail http://127.0.0.1:8080/health
docker stop tailor-quick-start
docker image rm tailor-quick-start:verified
```
