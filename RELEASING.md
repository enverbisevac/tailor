# Preparing an alpha release

The current version is `0.1.0-alpha.1`. Publishing is a separate maintainer
action: these scripts do not create tags, upload releases, or push images.

## Local validation

Use Python 3.9 or newer, Zig 0.17.1, Docker with Linux containers, Go, JDK 21
or newer, Make, and curl. Install the checksum-pinned tools if needed:

```sh
export PATH="$(python3 scripts/install-tool.py zig):$(python3 scripts/install-tool.py trivy):$PATH"
zig fmt --check build.zig src
make test build
zig-out/bin/tailor --version
make examples
make scanner-integration
make release
cd zig-out/release
shasum -a 256 -c SHA256SUMS
```

Tool archives are pinned by URL and SHA-256 in `scripts/tools.json`. The
integration test downloads hash-pinned, real PyPI wheels and uses a live Trivy
database. It tests clean image approval, a clean transactional build, known-CVE
rejection, missing image-inventory rejection, and absence of rejected target
tags. It checks that the promoted ID is the exact scanned ID. Test images are disposable;
scanner evidence remains in `.tailor-reports/`. No fixture package code runs.
The images test the scan/promotion policy, not Python runtime functionality;
the four health examples cover runnable applications separately.

The clean fixture is idna 3.20; the vulnerable fixture is requests 2.19.1 with
CVE-2018-18074. If a new advisory affects the clean fixture, investigate and
update its pinned wheel rather than adding an ignore or weakening the gate.
Database or network failures must fail the test. Do not substitute mock scanner
output for release validation. OSV/Grype end-to-end suites remain future work.

## Distribution

`make release` creates four ReleaseSafe archives under `zig-out/release`:
Linux amd64/arm64 and macOS amd64/arm64. Each includes the executable, MIT
license, README, security policy, changelog, and this guide. `SHA256SUMS` covers
exactly the archives created in that invocation. For one target:

```sh
python3 scripts/release.py --target linux-amd64
```

Use `--native` to package only the current host. When packaging a native target,
the script executes its `--version` command and checks the result before archiving.

CI runs tests natively on all four host platforms, example and scanner tests
on Linux amd64/arm64, and packages archives only after those checks succeed.
Artifacts are uploaded to the workflow run for review, not published publicly.
Repacked archive metadata is normalized; reproducible executable bytes across
different hosts and toolchain paths have not been established. Checksums detect
corruption but do not authenticate a release; signing remains future work.

## Publication checklist

- Create the hosted repository and enable CI; this workspace may be a source
  snapshot without Git metadata.
- Enable private vulnerability reporting and confirm it works, or add a real
  private contact to SECURITY.md. Do not publish with that contact unresolved.
- Confirm all CI jobs pass on the exact commit being released, and review raw
  scanner evidence and the four health results.
- Confirm `build.zig.zon`, CLI output, changelog, and CI version assertions agree.
- Change the changelog heading from Unreleased to the release date.
- Download the release artifacts, verify checksums, and run `tailor --version`
  on each supported host platform.
- Create `v0.1.0-alpha.1` from the validated commit and publish a prerelease with
  the archives and SHA256SUMS. State experimental status and known limitations.
- Protect the default branch with the CI checks before accepting contributions.
