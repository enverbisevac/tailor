# Native dependency compatibility

These fixtures exercise dependencies that the standard-library examples do not
cover. Run from the repository root with Docker running Linux containers:

```sh
make compatibility
python3 scripts/compatibility.py --case java
```

| Fixture | Operation exercised |
|---|---|
| Go | CGO calls libc; discovered Git performs init, commit, and local clone in a resolved scratch image |
| Node.js | `@node-rs/xxhash` 1.7.8 loads its prebuilt native addon and hashes data; npm scripts remain disabled |
| Python | orjson 3.13.0 installs from hash-locked CPython 3.13 Linux wheels and serializes the health response |
| Java | A JAR loads an explicitly included JNI shared library and calls it before starting HTTP |

The suite checks JSON results, not just HTTP status. It also checks that dynamic
commands remain visible in explanations, undeclared dynamic calls and missing
loaders/libraries block generation, and Java fails startup without its JNI library.

Images use a non-root user, read-only root filesystem, dropped capabilities,
resource limits, and temporary `/tmp`. Ports are allocated dynamically on
loopback. Containers and fixture image tags are removed on completion or failure.
Builder layers and package caches may remain in Docker's cache.

Builders are resolved to digests for each run. The disposable Go sysroot and Java
compiler builder install distro packages whose repository contents are not frozen.
Node packages have an integrity lock; the Python lock contains hashes for amd64
and arm64 wheels. These tests use `generate` and Docker; they do not certify
CVE-clean images or reproducible package repositories. No vulnerability policy
is bypassed in `tailor build`.

Results, base digests, and image IDs are recorded in
`.tailor-reports/compatibility-*.json`. Generated Dockerfiles, exported sysroots,
and Go explanation JSON stay under `zig-out/compatibility/` for review. CI runs
the suite on Linux amd64/arm64 and retains result reports.

## Scanner policy tests

Install each checksum-pinned scanner with `scripts/install-tool.py` and add its
printed directory to PATH. Grype also needs Syft. Then run:

```sh
make scanner-integration SCANNER=trivy
make scanner-integration SCANNER=grype
make scanner-integration SCANNER=osv
```

All suites use real scanner binaries, package wheels, and live advisory data.
They verify clean-image approval, known-CVE rejection, absence of rejected tags,
immutable-image promotion, and missing-inventory rejection. A source gate may
reject a vulnerable transaction before building; the separate direct image scan
must still identify the expected CVE. Grype checks include GHSA/CVE aliases and
independent Syft inventory. OSV scans an archive exported from the resolved
Docker image ID; normalized evidence records that ID and the archive is removed.

## Parser fuzzing

```sh
zig build fuzz                         # Seed corpus only
make fuzz FUZZ_ITERATIONS=10000        # Bounded coverage-guided fuzzing
zig build fuzz --fuzz                   # Continuous fuzzing with Zig's web UI
```

Separate targets cover ELF metadata (including dynamic strings and GNU symbol
versions), npm/Python locks, and scanner JSON/database timestamps. Inputs are
bounded; targets never invoke applications, subprocesses, or network access.
Keep `.zig-cache` to retain corpus/coverage between runs. The CI budget is a
smoke test, not evidence of exhaustive parser safety.
