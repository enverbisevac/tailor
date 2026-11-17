"""Install a checksum-pinned CI tool into .zig-cache/tools; print its bin path."""
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.request

ROOT = Path(__file__).resolve().parent.parent


def main():
    configs = json.loads((ROOT / "scripts/tools.json").read_text())
    if len(sys.argv) != 2 or sys.argv[1] not in configs:
        raise SystemExit("usage: python3 scripts/install-tool.py " + "|".join(configs))
    name = sys.argv[1]
    config = configs[name]
    executable = config.get("command", name)
    arch = {"arm64": "aarch64", "AMD64": "x86_64"}.get(platform.machine(), platform.machine())
    url, expected = config["archives"][f"{platform.system()}-{arch}"]
    parent = ROOT / ".zig-cache/tools"
    parent.mkdir(parents=True, exist_ok=True)
    destination = parent / f"{name}-{config['version']}"
    if not destination.exists():
        with tempfile.TemporaryDirectory(dir=parent) as tmp:
            tmp = Path(tmp)
            archive = tmp / "download.tar"
            print(f"Downloading {name} {config['version']}", file=sys.stderr)
            with urllib.request.urlopen(url, timeout=120) as source, archive.open("wb") as output:
                shutil.copyfileobj(source, output)
            if hashlib.sha256(archive.read_bytes()).hexdigest() != expected:
                raise SystemExit(f"{name}: SHA-256 mismatch")
            extracted = tmp / "unpacked"
            extracted.mkdir()
            if config.get("binary"):
                shutil.copyfile(archive, extracted / executable)
                (extracted / executable).chmod(0o755)
            else:
                unpack(archive, extracted)
            source = next(extracted.iterdir()) if name == "zig" else extracted
            os.rename(source, destination)
    command = [str(destination / executable), "version" if name in ("zig", "grype", "syft") else "--version"]
    version = subprocess.check_output(command, text=True).strip()
    if not re.search(r"(?<![\d.])" + re.escape(config["version"]) + r"(?![\d.])", version):
        raise SystemExit(f"unexpected installed {name} version: {version}")
    print(destination)


def unpack(archive, extracted):
    with tarfile.open(archive) as package:
        # Only checksum-verified official archives reach extraction.
        for member in package.getmembers():
            if not (extracted / member.name).resolve().is_relative_to(extracted.resolve()):
                raise SystemExit("unsafe archive path")
            if member.issym() or member.islnk():
                raise SystemExit("unexpected archive link")
        package.extractall(extracted)


if __name__ == "__main__":
    main()
