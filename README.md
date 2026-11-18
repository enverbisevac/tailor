# Tailor

Licensed under the [MIT License](LICENSE).

Tailor takes an already-built application artifact and produces the smallest container build plan it can justify without guessing. Its default posture is fail-closed: immutable bases, no package manager in the runtime stage, a numeric non-root user, locked Node.js/Python dependencies, and explicit source and image vulnerability gates.

Version `0.1.0-alpha.2` is experimental and intended for evaluation.
Release downloads are available on the [releases page](https://github.com/enverbisevac/tailor/releases). Tailor does
not prove globally minimal image size, discover every dynamic dependency, or
guarantee that an image is vulnerability-free. It currently recognizes:

| Input | Runtime strategy | Current safety boundary |
|---|---|---|
| Static Linux ELF (including static Go binaries) | `scratch` | Rejects executable stacks |
| Dynamic Linux ELF | Resolved sysroot closure in `scratch`, or a supplied runtime | Native closure checks architecture and GNU symbol versions; supplied bases must be digest-pinned |
| Executable JAR | User-supplied JRE | Base must be pinned by SHA-256 digest |
| Node.js project directory | Pinned builder plus separate pinned runtime | `package-lock.json` v2/v3 with exact versions and SHA-256/SHA-512 integrity metadata |
| Python project directory | Pinned builder plus separate pinned runtime | Exact versions and SHA-256 hashes required for every dependency |

Tailor never executes the supplied artifact while inspecting it. Unsupported formats and ambiguous runtime requirements are rejected.

## Build

Use Zig `0.17.1`. Supported alpha host targets are Linux amd64/arm64 and macOS
amd64/arm64, with Docker running Linux containers. Native dependency resolution
currently supports prepared Debian/glibc sysroots. Windows hosts and Alpine/RPM
sysroots are not supported in this alpha.

```sh
zig build test
zig build -Doptimize=ReleaseSafe
zig-out/bin/tailor --version
```

See [RELEASING.md](RELEASING.md) for CI checks, real scanner integration tests,
release archives, and the publication checklist; see [SECURITY.md](SECURITY.md)
for the security policy and [CHANGELOG.md](CHANGELOG.md) for release notes.

## Use

For a complete first build, follow the [health-service quick-start](docs/quick-start.md):
compile the Go example, review its lock, build with an HTTP gate, and inspect
the exported SBOM and provenance.

Inspect an artifact:

```sh
zig build run -- inspect ./server-linux-amd64
```

Generate a Dockerfile for a static executable:

```sh
zig build run -- generate ./server-linux-amd64 --output Dockerfile.tailor
docker build -f Dockerfile.tailor -t example/server:candidate .
```

Generation is idempotent: Tailor creates a missing output, updates an existing
regular Dockerfile in place, and leaves it untouched when its contents already
match. Symlink, hard-linked, and non-regular output paths are rejected. Aliases
of the input artifact or included files cannot be used as output paths.

Dynamic programs, JARs, Node.js, and Python need an immutable runtime base:

```sh
zig build run -- generate ./application.jar \
  --base 'registry.example/jre@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'
```

Python also needs a module entrypoint. Its requirements file must use exact `==` pins and `--hash=sha256:...` for every package. Installation accepts binary wheels only; dependencies requiring source builds are rejected:

```sh
zig build run -- generate ./service \
  --entrypoint service.main \
  --builder-base 'registry.example/python-build@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef' \
  --base 'registry.example/python-runtime@sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789'
```

Node.js projects similarly require a script entrypoint, a digest-pinned Node
builder, and a digest-pinned shell-free runtime. Dependency installation uses
`npm ci --omit=dev --ignore-scripts`:

```sh
zig build run -- generate ./service \
  --entrypoint server.js \
  --builder-base 'registry.example/node-build@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef' \
  --base 'registry.example/node-runtime@sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789'
```

## Runnable examples

Dependency-free Go, Node.js, Python, and Java health services live under
[`examples`](examples/README.md). A top-level Makefile coordinates Zig and the
four language toolchains, pins resolved container bases, builds all images, and
checks each `GET /health` endpoint:

```sh
make examples
```

Use `make examples-run`, `make examples-check`, and `make examples-stop` for an
interactive run, or `make examples-scan SCANNER=grype` to scan the built images.

Native fixtures live under [tests/compatibility](tests/compatibility/README.md).
`make compatibility` exercises CGO/Git, a Node addon, a compiled Python wheel,
and Java JNI. Real scanner suites cover all three supported backends, and
`make fuzz` exercises ELF, lockfile, and scanner-report parsers. Compatibility
success does not imply that the images passed a CVE gate.

Include additional regular files as read-only runtime content. Sources must be inside the build context and may not be symlinks; destinations must be absolute normalized container paths. `/app` and `/runtime` are reserved, and extra-file destinations may not duplicate or overlap one another:

```sh
tailor generate ./server-linux-amd64 \
  --include ./config.json /etc/server/config.json \
  --include ./ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
```

Build transactionally. Tailor pre-scans declared dependencies and every digest-pinned base, builds under a random temporary tag, captures the built image ID, scans that exact image, and tags that same ID only if every gate passes:

```sh
tailor build ./server-linux-amd64 --tag example/server:verified
```

Tailor refuses to overwrite an existing target tag. The lower-level `scan source`, `generate`, and `scan image` commands remain available for CI systems that manage the build transaction themselves.

Create and review a build lock, then require it during builds:

```sh
tailor lock ./server-linux-amd64 \
  --smoke-command '["/app/application","--self-test"]' --attest
tailor build ./server-linux-amd64 --locked \
  --smoke-command '["/app/application","--self-test"]' --attest \
  --tag example/server:verified
```

Repeat the same build options in both commands. `tailor.lock` records input
hashes and permissions, native package versions, pinned bases, target platform,
generated Dockerfile, and gate policy. `--locked` rejects changed or added
inputs before running Docker or scanners; it never updates the lock. Use
`--lockfile PATH` for a different location. JAR, Node.js, and Python locks need
an explicit `--platform linux/amd64` or `linux/arm64`. This fixes the reviewed
plan; it does not guarantee byte-identical rebuilds.

For a service, replace `--smoke-command` with `--smoke-http /health`
and optionally `--smoke-port 8080 --smoke-timeout 30`. Workload checks execute
the image in a restricted, offline container before promotion. HTTP checks use
a digest-pinned curl helper in the service's network namespace. A failing check
or timeout blocks the target tag. These checks are opt-in.

`--attest` additionally requires Syft and Skopeo on PATH. It writes a local OCI
layout, CycloneDX SBOM, lock, build report, and subject-bound provenance under
`.tailor-reports/build-*`. Export failure blocks promotion. The provenance is
unsigned, self-reported SLSA-format evidence; it does not claim a SLSA level.
Nothing is pushed to a registry. See the [build and evidence format](docs/build-type-v1.md)
and run `make policy-integration` to exercise these gates.

Tailor auto-detects OSV-Scanner, Grype, or Trivy, in that order. A missing scanner is an error, and every known severity is blocking by default. Tailor supplies a controlled scanner policy explicitly, so repository-level ignore files cannot silently weaken the gate. Grype image scans additionally require `syft` to establish a complete package inventory. Grype databases must pass hash validation and be at most 120 hours old. An old successful scan is not evidence that an image is still vulnerability-free.

Scanner child processes receive an allowlisted environment for executable
lookup, transport, and cache locations. Inherited scanner filtering variables
and executable-injection variables are discarded.

The generated Dockerfile also pins its BuildKit frontend by digest. Inspection never executes the supplied application or runs `ldd`. Transactional builds separately probe the declared Python/Node runtimes and builders in isolated, network-disabled containers; Java builds verify that the declared JRE can start.

## Build snapshots and scan evidence

Generated runtimes use `/app` as the working directory. Included-file parents
are created before read-only copies so non-root processes can traverse them.
Destination paths cannot contain Dockerfile variable references (`$`) or backslashes.

`tailor build` stages its own private context, scans that copy, then gives the
same context to Docker. It excludes common credentials (`.env*`, `.aws`, `.ssh`,
private-key files), local environments (`node_modules`, `.venv`), VCS metadata,
caches, and generated Dockerfiles. Runtime-required excluded files must be
declared with `--include`. Symlinks and special files in project inputs are
rejected. The current limits are 128 MiB per file and 512 MiB per context.

Input hashes, raw scanner JSON, normalized scan summaries, and Syft inventories
are retained under `.tailor-reports/`. Findings and suppressed findings block
the gate independently of scanner exit status. Malformed reports, scanner
failures, and missing image inventory also block it. Empty source inventories
are permitted for standard-library-only projects; their complete images are
still scanned. `check-report` evaluates an existing report without rebuilding:

```sh
tailor check-report grype scan.json
```

Current Grype JSON alone lists matched packages rather than a full inventory.
A clean standalone Grype report therefore cannot establish coverage;
transactional Grype image scans use a separate Syft inventory.

Check Python or Node builder/runtime version, native ABI, architecture, and
glibc compatibility independently of a build:

```sh
tailor verify-runtime python --base "$RUNTIME_DIGEST" --builder-base "$BUILDER_DIGEST"
```

## External commands and native libraries

Provide an approved Linux root filesystem containing the required packages.
The initial resolver supports Debian-style glibc sysroots with dpkg metadata;
it does not download packages from arbitrary repositories. Use a sysroot that
matches the architecture and distribution of any supplied runtime base.

```sh
tailor deps ./server-linux-arm64 --sysroot ./runtime-root --exec git

tailor generate ./server-linux-arm64 \
  --sysroot ./runtime-root --exec git --output Dockerfile

tailor build ./server-linux-arm64 \
  --sysroot ./runtime-root --exec git --tag example/server:verified
```

The resolver reads `PT_INTERP`, `DT_NEEDED`, `DT_RPATH`, `DT_RUNPATH`, and GNU
symbol-version tables without executing the binaries. It follows dependencies
recursively, resolves symlinks inside the virtual root, checks architecture and
required symbol versions, preserves owning-package versions and licenses, and
copies the resolved filesystem in one layer. Generated files are content-hashed
and rechecked when the build snapshot is made. Missing libraries, unknown
executable package owners, unsupported search tokens, and symbol-version
mismatches are errors. Runtime-loaded libraries can be declared with
`--library libexample.so.1`.

Enable conservative discovery of direct process calls by providing source:

```sh
tailor generate ./server-linux-arm64 \
  --sysroot ./runtime-root --source ./src --output Dockerfile
```

Common direct Go, Python, Java/Kotlin, and Node/TypeScript APIs are recognized.
For Node/Python project inputs, source discovery runs automatically when a
sysroot is supplied. Literal command names are resolved; recognized dynamic
calls require explicit `--exec` declarations. This is syntactic analysis, not
a proof of every runtime dependency: aliases, reflection, dynamically loaded
code, shell commands inside helper scripts, and arbitrary `dlopen` calls still
need declarations and workload tests. Compiled artifacts alone cannot reliably
reveal every subprocess name.

The core Git profile includes its transport aliases, helpers, templates,
certificates, interpreters, libraries, and licenses. Optional Perforce/CVS
bridges are excluded. Other optional Git features can require additional tools;
test the Git operations your application actually uses.

## Dependency explanations

Inspect the reasons behind a native closure without executing the application
or building an image:

```sh
tailor explain ./server-linux-arm64 --sysroot ./runtime-root --source ./src > explanation.json
```

The JSON includes file hashes, owning package versions, dependency edges
(`DT_NEEDED`, interpreters, declarations and source call sites), and recognized
unresolved dynamic calls. `explain` may report dynamic calls while `generate`
and `build` still reject them without declarations. Missing literal commands,
libraries and ABI mismatches remain errors. Native files are staged locally as
for `deps`. Without a sysroot, only artifact strategy and limitations are reported.
The report marks analysis incomplete and records that no security scan occurred.
It does not inventory a supplied base image.

## Security model

“Zero known CVEs” is a time-bound observation, not a permanent property. Vulnerability databases can be delayed or incomplete, scanners can disagree about package identity and severity, and a new CVE can be published after an image passes. Tailor therefore aims for:

1. the least possible runtime content;
2. immutable, reviewable inputs;
3. an SBOM/scanner-compatible final image;
4. a build-time policy gate that fails closed;
5. repeatable re-scanning of already-published image digests.

For production, run containers with a read-only root filesystem, no added Linux capabilities, `no-new-privileges`, a seccomp profile, resource limits, and only the required network access. Those are deployment controls and do not belong in an image Dockerfile.

## Next milestones

- Add authenticated package-repository resolution and a portable dependency lockfile.
- Expand source discovery with language parsers, alias resolution, and optional workload tracing.
- Validate nested JAR class versions/JNI and installed Python/Node extension modules against the runtime.
- Support Alpine/RPM sysroots, musl compatibility, and additional loader search policies.
- Read Go build metadata and emit CycloneDX/SPDX without invoking the artifact.
- Use `jdeps`/`jlink` for module-minimized Java runtimes.
- Support `uv.lock` and Poetry/PDM lock formats without invoking project hooks.
- Emit a deterministic OCI image layout directly, then attach SBOM and provenance attestations.
- Add signed policy exceptions with owners, reasons, and expiry dates.

## Upstream specifications and scanners

- [OCI Image Specification](https://specs.opencontainers.org/image-spec/)
- [OSV-Scanner](https://google.github.io/osv-scanner/)
- [Grype](https://oss.anchore.com/docs/guides/vulnerability/)
- [Trivy](https://trivy.dev/)
