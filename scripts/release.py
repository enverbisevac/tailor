"""Build alpha release archives locally. Does not publish or create Git tags."""
import argparse
import gzip
import hashlib
import json
from pathlib import Path
import platform
import re
import subprocess
import tarfile
import tempfile

ROOT = Path(__file__).resolve().parent.parent
TARGETS = {
    "linux-amd64": "x86_64-linux-musl",
    "linux-arm64": "aarch64-linux-musl",
    "macos-amd64": "x86_64-macos",
    "macos-arm64": "aarch64-macos",
}


def version():
    return re.search(r'\.version\s*=\s*"([^"]+)"', (ROOT / "build.zig.zon").read_text()).group(1)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    selection = parser.add_mutually_exclusive_group()
    selection.add_argument("--target", choices=TARGETS, action="append")
    selection.add_argument("--native", action="store_true", help="package and smoke-test only this host")
    parser.add_argument("--output", type=Path, default=ROOT / "zig-out/release")
    args = parser.parse_args()
    expected = json.loads((ROOT / "scripts/tools.json").read_text())["zig"]["version"]
    if subprocess.check_output(["zig", "version"], text=True).strip() != expected:
        raise SystemExit(f"release builds require Zig {expected}")
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    checksums = []
    host = {"Linux": "linux", "Darwin": "macos"}[platform.system()] + "-" + {
        "x86_64": "amd64", "arm64": "arm64", "aarch64": "arm64"
    }[platform.machine()]
    for label in ([host] if args.native else args.target or TARGETS):
        stem = f"tailor-{version()}-{label}"
        with tempfile.TemporaryDirectory(prefix="tailor-release-") as tmp:
            tmp = Path(tmp)
            subprocess.run(["zig", "build", "-Doptimize=ReleaseSafe", f"-Dtarget={TARGETS[label]}",
                            "--prefix", str(tmp)], cwd=ROOT, check=True)
            if label == host:
                actual = subprocess.check_output([str(tmp / "bin/tailor"), "--version"], text=True).strip()
                if actual != f"tailor {version()}":
                    raise RuntimeError(f"release executable version mismatch: {actual}")
            archive = output / f"{stem}.tar.gz"
            with archive.open("wb") as raw, gzip.GzipFile(filename="", fileobj=raw, mode="wb", mtime=0) as compressed:
                with tarfile.open(fileobj=compressed, mode="w", format=tarfile.PAX_FORMAT) as package:
                    for source, name in [(tmp / "bin/tailor", "tailor")] + [
                        (ROOT / name, name) for name in ("LICENSE", "README.md", "SECURITY.md", "CHANGELOG.md", "RELEASING.md")
                    ]:
                        entry = package.gettarinfo(str(source), arcname=f"{stem}/{name}")
                        entry.uid = entry.gid = entry.mtime = 0
                        entry.uname = entry.gname = ""
                        entry.mode = 0o755 if name == "tailor" else 0o644
                        with source.open("rb") as content:
                            package.addfile(entry, content)
            checksums.append(f"{hashlib.sha256(archive.read_bytes()).hexdigest()}  {archive.name}\n")
            print(archive)
    # Lists exactly the archives built by this invocation, never stale files.
    (output / "SHA256SUMS").write_text("".join(checksums))


if __name__ == "__main__":
    main()
