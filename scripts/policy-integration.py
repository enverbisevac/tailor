"""Real locked builds, smoke failures, and OCI-attached evidence; requires Trivy/Syft/Skopeo."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
import urllib.request
import uuid
import zipfile

ROOT = Path(__file__).resolve().parent.parent
TAILOR = str(ROOT / "zig-out/bin/tailor")
REPORTS = ROOT / ".tailor-reports"


def run(args, **kwargs):
    return subprocess.run([str(a) for a in args], cwd=ROOT, check=True, timeout=900, **kwargs)


def image_exists(tag):
    return subprocess.run(["docker", "image", "inspect", tag], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0


def verify_layout(directory, image_id):
    root = directory / "oci"
    index = json.loads((root / "index.json").read_text())
    entries = {m["annotations"]["org.opencontainers.image.ref.name"]: m for m in index["manifests"]}
    assert set(entries) == {"image", "sbom", "provenance"}

    def blob(descriptor):
        algorithm, digest = descriptor["digest"].split(":")
        assert algorithm == "sha256" and len(digest) == 64
        content = (root / "blobs/sha256" / digest).read_bytes()
        assert len(content) == descriptor["size"] and hashlib.sha256(content).hexdigest() == digest
        return content

    image = json.loads(blob(entries["image"]))
    report = json.loads((directory / "build-report.json").read_text())
    assert image["config"]["digest"] == report["docker_config_digest"]
    chain = report["source_descriptor_chain"]
    assert chain[0] == image_id and chain[-1] == report["docker_config_digest"]
    for current, child in zip(chain, chain[1:]):
        data = (root / "blobs/sha256" / current[7:]).read_bytes()
        assert hashlib.sha256(data).hexdigest() == current[7:]
        source = json.loads(data)
        assert child in ([source["config"]["digest"]] if "config" in source else [m["digest"] for m in source["manifests"]])
    blob(image["config"])
    for layer in image["layers"]:
        blob(layer)
    for name, expected_type, file in [("sbom", "application/vnd.cyclonedx+json", "sbom.cdx.json"),
                                      ("provenance", "application/vnd.in-toto+json", "provenance.json")]:
        artifact = json.loads(blob(entries[name]))
        assert artifact["subject"]["digest"] == entries["image"]["digest"]
        assert artifact["artifactType"] == expected_type
        blob(artifact["config"])
        assert blob(artifact["layers"][0]) == (directory / file).read_bytes()
    sbom = json.loads((directory / "sbom.cdx.json").read_text())
    assert sbom["bomFormat"] == "CycloneDX"
    assert any(c["name"] == "idna" and c["version"] == "3.20" for c in sbom["components"])
    provenance = json.loads((directory / "provenance.json").read_text())
    assert provenance["predicateType"] == "https://slsa.dev/provenance/v1"
    assert provenance["subject"][0]["digest"]["sha256"] == entries["image"]["digest"][7:]
    assert report["image_id"] == image_id and report["vulnerability_gates_passed"]
    assert report["smoke"]["passed"] is True and report["signed"] is False
    byproducts = provenance["predicate"]["runDetails"]["byproducts"]
    for item in byproducts:
        assert hashlib.sha256((directory / item["name"]).read_bytes()).hexdigest() == item["digest"]["sha256"]


def main():
    spec = importlib.util.spec_from_file_location("scanner_fixtures", ROOT / "scripts/scanner-integration.py")
    fixtures = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(fixtures)
    url, checksum, name, version = fixtures.WHEELS["clean"]
    arch = run(["docker", "version", "--format", "{{.Server.Arch}}"], stdout=subprocess.PIPE, text=True).stdout.strip()
    target = {"amd64": "x86_64-linux-musl", "arm64": "aarch64-linux-musl"}[arch]
    images = []
    (ROOT / ".zig-cache").mkdir(exist_ok=True)
    try:
        with tempfile.TemporaryDirectory(prefix="policy-integration-", dir=ROOT / ".zig-cache") as tmp:
            work = Path(tmp)
            relative = lambda path: str(path.relative_to(ROOT))
            binary = work / "server"
            run(["zig", "cc", "-target", target, "-static", "-O2", str(ROOT / "tests/policy/server.c"), "-o", binary])
            wheel = work / "package.whl"
            with urllib.request.urlopen(url, timeout=120) as response:
                wheel.write_bytes(response.read())
            assert hashlib.sha256(wheel.read_bytes()).hexdigest() == checksum
            metadata = work / "METADATA"
            with zipfile.ZipFile(wheel) as package:
                metadata.write_bytes(package.read(f"{name}-{version}.dist-info/METADATA"))
            options = [relative(binary), "--include", relative(metadata),
                       f"/usr/local/lib/python3.13/site-packages/{name}-{version}.dist-info/METADATA"]
            lock = work / "tailor.lock"
            command_policy = ["--smoke-command", '["/app/application","--self-test"]', "--attest"]
            create = [TAILOR, "lock", *options, *command_policy, "--output", relative(lock)]
            run(create)
            original = lock.read_bytes()
            run(create)
            assert lock.read_bytes() == original
            # A locked mismatch must fail before Docker or scanner execution.
            clean_binary = binary.read_bytes()
            original_mode = binary.stat().st_mode & 0o7777
            for mutation in ("bytes", "mode"):
                if mutation == "bytes": binary.write_bytes(clean_binary + b"changed")
                else: binary.chmod(0o600)
                result = subprocess.run([TAILOR, "build", *options, *command_policy, "--locked", "--lockfile", relative(lock),
                                         "--scanner", "trivy", "--tag", "tailor-policy:must-not-exist"], cwd=ROOT,
                                        env={**os.environ, "PATH": "/nonexistent"}, capture_output=True, text=True)
                assert result.returncode == 1 and "lockfile differs" in result.stderr
                assert lock.read_bytes() == original
                binary.write_bytes(clean_binary)
                binary.chmod(original_mode)
            alias = subprocess.run([TAILOR, "generate", *options, *command_policy, "--locked", "--lockfile", relative(lock),
                                    "--output", relative(lock)], cwd=ROOT, capture_output=True, text=True)
            assert alias.returncode == 1 and lock.read_bytes() == original
            print("PASS: lock idempotence, changed bytes/modes, no Docker on mismatch, and lock overwrite protection", flush=True)
            before = set(REPORTS.glob("build-*"))
            tag = f"tailor-policy-{uuid.uuid4().hex}:verified"
            images.append(tag)
            run([TAILOR, "build", *options, *command_policy, "--locked", "--lockfile", relative(lock), "--tag", tag, "--scanner", "trivy"])
            image_id = run(["docker", "image", "inspect", "--format", "{{.Id}}", tag], stdout=subprocess.PIPE, text=True).stdout.strip()
            evidence = [p for p in REPORTS.glob("build-*") if p not in before]
            assert len(evidence) == 1
            verify_layout(evidence[0], image_id)
            print("PASS: locked promotion, real command smoke, CycloneDX SBOM and OCI subject-bound provenance", flush=True)
            # Exercise HTTP success and nonzero/timeout/HTTP failure paths.
            for policy, succeeds in [(["--smoke-http", "/health"], True),
                                     (["--smoke-command", '["/app/application","--fail"]'], False),
                                     (["--smoke-command", '["/app/application","--hang"]', "--smoke-timeout", "1"], False),
                                     (["--smoke-http", "/missing", "--smoke-timeout", "2"], False)]:
                candidate = f"tailor-policy-{uuid.uuid4().hex}:smoke"
                images.append(candidate)
                started = time.monotonic()
                result = subprocess.run([TAILOR, "build", *options, *policy, "--tag", candidate, "--scanner", "trivy"], cwd=ROOT, timeout=120)
                assert (result.returncode == 0) == succeeds and image_exists(candidate) == succeeds
                if "--hang" in " ".join(policy):
                    assert time.monotonic() - started < 60, "one-second workload timeout was not enforced"
            print("PASS: HTTP smoke success; exit, timeout and HTTP failures block promotion", flush=True)
            # Lock a project without Docker access and prove new files count.
            project = work / "project"
            project.mkdir()
            (project / "server.py").write_text('print("fixture")\n')
            (project / "requirements.lock").write_text('# no external dependencies\n')
            project_options = [relative(project), "--platform", "linux/" + arch, "--entrypoint", "server",
                               "--base", "example/runtime@sha256:" + "a" * 64,
                               "--builder-base", "example/builder@sha256:" + "b" * 64]
            project_lock = project / "tailor.lock"
            run([TAILOR, "lock", *project_options, "--output", relative(project_lock)])
            first = project_lock.read_bytes()
            run([TAILOR, "lock", *project_options, "--output", relative(project_lock)])
            assert project_lock.read_bytes() == first
            (project / "new.py").write_text('print("new")\n')
            changed = subprocess.run([TAILOR, "generate", *project_options, "--locked", "--lockfile", relative(project_lock),
                                      "--output", relative(work / "rejected.Dockerfile")], cwd=ROOT, capture_output=True, text=True)
            assert changed.returncode != 0 and "LockMismatch" in changed.stderr
            print("PASS: project lock excludes itself and rejects added files", flush=True)
    finally:
        for image in images:
            subprocess.run(["docker", "image", "rm", "--force", image], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


if __name__ == "__main__":
    main()
