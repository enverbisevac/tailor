"""Exercise real Trivy scans and Tailor's promotion gate using disposable images."""
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import urllib.request
import uuid
import zipfile

ROOT = Path(__file__).resolve().parent.parent
TAILOR = str(ROOT / "zig-out/bin/tailor")
WHEELS = {
    "clean": ("https://files.pythonhosted.org/packages/58/a2/bb081bab032533a855d44de1d56f8e8426114ff1ba5d1f07a438a0a654f8/idna-3.20-py3-none-any.whl",
              "ab7ae7122974553370f0bdb919e1a960b2cd1bc1ef0276416d896db81c14582c", "idna", "3.20"),
    "vulnerable": ("https://files.pythonhosted.org/packages/65/47/7e02164a2a3db50ed6d8a6ab1d6d60b69c4c3fdf57a284257925dfc12bda/requests-2.19.1-py2.py3-none-any.whl",
                   "63b52e3c866428a224f97cab011de738c36aec0185aa91cfacd418b5d58911d1", "requests", "2.19.1"),
}


def run(args, **kwargs):
    return subprocess.run(args, cwd=ROOT, check=True, timeout=900, **kwargs)


def summaries_since(before):
    return [json.loads(p.read_text()) for p in (ROOT / ".tailor-reports").glob("*.summary.json") if p not in before]


def main():
    expected = json.loads((ROOT / "scripts/tools.json").read_text())["trivy"]["version"]
    if f"Version: {expected}" not in subprocess.check_output(["trivy", "--version"], text=True):
        raise SystemExit(f"integration tests require Trivy {expected}")
    arch = subprocess.check_output(["docker", "version", "--format", "{{.Server.Arch}}"], text=True).strip()
    target = {"amd64": "x86_64-linux-musl", "arm64": "aarch64-linux-musl"}[arch]
    images = []
    cache = ROOT / ".zig-cache"
    cache.mkdir(exist_ok=True)
    try:
        with tempfile.TemporaryDirectory(prefix="scanner-integration-", dir=cache) as tmp:
            tmp = Path(tmp)
            # A static Linux ELF with no runtime or package dependencies. It is
            # inspected and built, never executed. Package data comes from real wheels.
            source = tmp / "probe.c"
            source.write_text("void _start(void) { for (;;) {} }\n")
            binary = tmp / "probe"
            run(["zig", "cc", "-target", target, "-nostdlib", "-static", "-Wl,-e,_start",
                 str(source), "-o", str(binary)])
            for case, (url, digest, name, version) in WHEELS.items():
                wheel = tmp / f"{case}.whl"
                with urllib.request.urlopen(url, timeout=120) as response:
                    wheel.write_bytes(response.read())
                if hashlib.sha256(wheel.read_bytes()).hexdigest() != digest:
                    raise RuntimeError("fixture wheel checksum mismatch")
                context = tmp / case
                context.mkdir()
                # No fixture code or installation hooks execute.
                with zipfile.ZipFile(wheel) as package:
                    for entry in package.infolist():
                        if not (context / entry.filename).resolve().is_relative_to(context.resolve()):
                            raise RuntimeError("unsafe wheel path")
                    package.extractall(context)
                (context / "Dockerfile").write_text("FROM scratch\nCOPY . /usr/local/lib/python3.13/site-packages/\n")
                nonce = uuid.uuid4().hex
                fixture = f"tailor-integration-{nonce}:fixture"
                promoted = f"tailor-integration-{nonce}:verified"
                images.extend([fixture, promoted])
                run(["docker", "build", "--network=none", "-t", fixture, str(context)])
                image_id = subprocess.check_output(["docker", "image", "inspect", "--format", "{{.Id}}", fixture], text=True).strip()
                before = set((ROOT / ".tailor-reports").glob("*.summary.json"))
                scan = subprocess.run([TAILOR, "scan", "image", image_id, "--scanner", "trivy"], cwd=ROOT, timeout=900)
                reports = summaries_since(before)
                if len(reports) != 1:
                    raise RuntimeError("expected structured evidence from real scanner")
                report = reports[0]
                raw = json.loads((ROOT / ".tailor-reports" / report["raw_report"]).read_text())
                packages = [p for r in raw["Results"] for p in (r.get("Packages") or [])]
                if not any(p["Name"] == name and p["Version"] == version for p in packages):
                    raise RuntimeError(f"scanner did not inventory {name}=={version}")
                if case == "clean":
                    if scan.returncode != 0 or report["summary"]["vulnerabilities"] != 0:
                        raise RuntimeError("clean fixture failed; investigate new advisories before updating it")
                else:
                    findings = [v for r in raw["Results"] for v in (r.get("Vulnerabilities") or [])]
                    if scan.returncode != 1 or not any(v["VulnerabilityID"] == "CVE-2018-18074" for v in findings):
                        raise RuntimeError("known vulnerable fixture was not blocked for the expected CVE")
                metadata = context / f"{name}-{version}.dist-info/METADATA"
                destination = f"/usr/local/lib/python3.13/site-packages/{name}-{version}.dist-info/METADATA"
                before = set((ROOT / ".tailor-reports").glob("*.summary.json"))
                build = subprocess.run([TAILOR, "build", str(binary.relative_to(ROOT)), "--tag", promoted,
                                        "--include", str(metadata.relative_to(ROOT)), destination,
                                        "--scanner", "trivy"], cwd=ROOT, timeout=900)
                exists = subprocess.run(["docker", "image", "inspect", promoted], stdout=subprocess.DEVNULL,
                                        stderr=subprocess.DEVNULL).returncode == 0
                image_reports = [r for r in summaries_since(before) if "image" in r["arguments"]]
                if len(image_reports) != 1:
                    raise RuntimeError("transaction did not scan exactly one assembled image")
                final = image_reports[0]
                scanned_id = final["arguments"][-1]
                if not scanned_id.startswith("sha256:") or len(scanned_id) != 71:
                    raise RuntimeError("transaction did not scan an immutable image ID")
                if case == "clean":
                    if build.returncode != 0 or not exists:
                        raise RuntimeError("clean transactional build was not promoted")
                    promoted_id = subprocess.check_output(["docker", "image", "inspect", "--format", "{{.Id}}", promoted], text=True).strip()
                    if promoted_id != scanned_id or final["summary"]["vulnerabilities"] != 0:
                        raise RuntimeError("promoted image differs from the clean scanned image")
                    run([TAILOR, "scan", "image", promoted, "--scanner", "trivy"])
                else:
                    final_raw = json.loads((ROOT / ".tailor-reports" / final["raw_report"]).read_text())
                    final_findings = [v for r in final_raw["Results"] for v in (r.get("Vulnerabilities") or [])]
                    if build.returncode != 1 or exists or not any(v["VulnerabilityID"] == "CVE-2018-18074" for v in final_findings):
                        raise RuntimeError("vulnerable transaction did not fail for the expected CVE")
                print(f"PASS: {case} image scan and transactional promotion gate", flush=True)
            empty_tag = f"tailor-integration-{uuid.uuid4().hex}:no-inventory"
            images.append(empty_tag)
            before = set((ROOT / ".tailor-reports").glob("*.summary.json"))
            empty = subprocess.run([TAILOR, "build", str(binary.relative_to(ROOT)), "--tag", empty_tag,
                                    "--scanner", "trivy"], cwd=ROOT, timeout=900)
            reports = [r for r in summaries_since(before) if "image" in r["arguments"]]
            exists = subprocess.run(["docker", "image", "inspect", empty_tag], stdout=subprocess.DEVNULL,
                                    stderr=subprocess.DEVNULL).returncode == 0
            if empty.returncode != 1 or exists or len(reports) != 1 or reports[0]["summary"]["packages"] != 0:
                raise RuntimeError("image without package coverage was not blocked")
            print("PASS: empty image inventory blocks promotion", flush=True)
    finally:
        for image in images:
            subprocess.run(["docker", "image", "rm", "--force", image], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


if __name__ == "__main__":
    main()
