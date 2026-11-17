"""Build and exercise native dependencies in generated images, without claiming CVE approval."""
import argparse
import http.client
import json
import os
from pathlib import Path, PurePosixPath
import posixpath
import subprocess
import tarfile
import time
import urllib.error
import urllib.request
import uuid

ROOT = Path(__file__).resolve().parent.parent
TAILOR = str(ROOT / "zig-out/bin/tailor")
FIXTURES = "tests/compatibility"


def run(args, **kwargs):
    return subprocess.run([str(a) for a in args], cwd=ROOT, check=True, timeout=1200, **kwargs)


def capture(args):
    return run(args, stdout=subprocess.PIPE, text=True).stdout.strip()


def unpack_sysroot(archive, root):
    """Copy regular files first and rewrite virtual-root links as relative links.

    No tar path or symlink is allowed to direct writes outside the fresh root.
    Symlink resolution uses the archive namespace, never the host filesystem.
    """
    def normalized(path):
        parts = []
        for part in PurePosixPath(path).parts:
            if part in ("/", ".", ""):
                continue
            if part == "..":
                if not parts:
                    raise RuntimeError("sysroot link escapes virtual root")
                parts.pop()
            else:
                parts.append(part)
        return "/".join(parts)

    with tarfile.open(archive) as package:
        members = package.getmembers()
        if len(members) > 100000:
            raise RuntimeError("test sysroot file limit exceeded")
        links = {normalized(m.name): m.linkname for m in members if m.issym()}

        def resolved(path):
            path = normalized(path)
            for _ in range(64):
                parts = path.split("/")
                for index in range(len(parts)):
                    prefix = "/".join(parts[:index + 1])
                    if prefix in links:
                        target = links[prefix]
                        origin = "" if target.startswith("/") else posixpath.dirname(prefix)
                        path = normalized(posixpath.join(origin, target, *parts[index + 1:]))
                        break
                else:
                    return path
            raise RuntimeError("sysroot link cycle")

        size = 0
        for member in members:
            path = root / resolved(member.name)
            if member.isdir():
                path.mkdir(parents=True, exist_ok=True)
            elif member.isfile() or member.islnk():
                if member.size > 128 * 1024 * 1024:
                    raise RuntimeError("test sysroot size limit exceeded")
                path.parent.mkdir(parents=True, exist_ok=True)
                with package.extractfile(member) as source, path.open("wb") as output:
                    written = 0
                    while chunk := source.read(1024 * 1024):
                        written += len(chunk)
                        size += len(chunk)
                        if written > 128 * 1024 * 1024 or size > 512 * 1024 * 1024:
                            raise RuntimeError("test sysroot size limit exceeded")
                        output.write(chunk)
        for name, target in links.items():
            parent = root / resolved(posixpath.dirname(name))
            parent.mkdir(parents=True, exist_ok=True)
            link = parent / posixpath.basename(name)
            destination = root / resolved(name)
            if link == destination:
                continue
            link.symlink_to(os.path.relpath(destination, parent))


class Suite:
    def __init__(self):
        self.nonce = uuid.uuid4().hex
        self.work = ROOT / "zig-out/compatibility" / self.nonce
        self.work.mkdir(parents=True)
        self.images = []
        self.containers = []
        self.bases = {}
        self.results = {}

    def pin(self, tag):
        if tag not in self.bases:
            run(["docker", "pull", tag])
            self.bases[tag] = capture(["docker", "image", "inspect", "--format", "{{index .RepoDigests 0}}", tag])
        return self.bases[tag]

    def image(self, case):
        name = f"tailor-compatibility-{self.nonce}:{case}"
        self.images.append(name)
        return name

    def container(self, image):
        name = f"tailor-compatibility-{uuid.uuid4().hex}"
        self.containers.append(name)
        run(["docker", "create", "--name", name, "--entrypoint", "/bin/true", image], stdout=subprocess.DEVNULL)
        return name

    def relative(self, path):
        return str(Path(path).relative_to(ROOT))

    def generate(self, case, input_path, options):
        dockerfile = self.work / f"{case}.Dockerfile"
        run([TAILOR, "generate", input_path, "--output", self.relative(dockerfile), *options])
        image = self.image(case)
        run(["docker", "build", "-f", dockerfile, "-t", image, "."])
        return image

    def health(self, case, image):
        name = f"tailor-compatibility-{uuid.uuid4().hex}"
        self.containers.append(name)
        run(["docker", "run", "-d", "--name", name, "--read-only", "--cap-drop", "ALL",
             "--security-opt", "no-new-privileges:true", "--pids-limit", "128", "--memory", "256m", "--cpus", "1",
             "--tmpfs", "/tmp:rw,noexec,nosuid,size=32m", "-p", "127.0.0.1::8080", image], stdout=subprocess.DEVNULL)
        try:
            address = capture(["docker", "port", name, "8080/tcp"])
        except subprocess.CalledProcessError:
            run(["docker", "logs", name])
            raise
        for attempt in range(30):
            try:
                with urllib.request.urlopen(f"http://{address}/health", timeout=2) as response:
                    result = json.load(response)
                break
            except (urllib.error.URLError, TimeoutError, http.client.RemoteDisconnected, ConnectionResetError):
                if attempt == 29:
                    run(["docker", "logs", name])
                    raise
                time.sleep(1)
        assert result["status"] == "ok" and result["runtime"] == case and result["native"] is True
        if case == "node":
            assert isinstance(result["hash"], int) and result["hash"] > 0
        else:
            assert result["answer"] == 42
        if case == "go":
            assert result["git"] is True
        self.results[case] = {"image_id": capture(["docker", "image", "inspect", "--format", "{{.Id}}", image]), "health": result}
        print(f"PASS: {case} native dependencies: {json.dumps(result)}", flush=True)
        run(["docker", "rm", "-f", name], stdout=subprocess.DEVNULL)
        self.containers.remove(name)

    def go(self):
        builder = self.image("go-builder")
        run(["docker", "build", "-f", f"{FIXTURES}/go/Dockerfile.builder", "-t", builder,
             "--build-arg", "GO_BASE=" + self.pin("golang:1-trixie"),
             "--build-arg", "SYSROOT_BASE=" + self.pin("debian:trixie-slim"), "."])
        container = self.container(builder)
        binary = self.work / "go-application"
        run(["docker", "cp", f"{container}:/fixture/application", binary])
        archive = self.work / "sysroot.tar"
        run(["docker", "export", "--output", archive, container])
        root = self.work / "sysroot"
        root.mkdir()
        unpack_sysroot(archive, root)
        archive.unlink()
        options = ["--sysroot", self.relative(root), "--source", f"{FIXTURES}/go"]
        self.health("go", self.generate("go", self.relative(binary), options))
        explanation = json.loads(capture([TAILOR, "explain", self.relative(binary), *options]))
        assert any(f["destination"] == "/usr/bin/git" and f["package_version"] for f in explanation["files"])
        assert any(e["to"] == "/usr/bin/git" and "main.go:" in e["from"] for e in explanation["dependency_edges"])
        assert any(e["reason"] == "DT_NEEDED" for e in explanation["dependency_edges"])
        (self.work / "go-explanation.json").write_text(json.dumps(explanation, indent=2))
        dynamic = self.work / "dynamic"
        dynamic.mkdir()
        (dynamic / "call.go").write_text('package fixture\nfunc f() { exec.Command(command) }\n')
        dynamic_options = ["--sysroot", self.relative(root), "--source", self.relative(dynamic)]
        report = json.loads(capture([TAILOR, "explain", self.relative(binary), *dynamic_options]))
        assert report["unresolved_calls"][0]["line"] == 2 and not report["analysis_complete"]
        rejected = subprocess.run([TAILOR, "generate", self.relative(binary), *dynamic_options,
                                   "--output", self.relative(self.work / "rejected.Dockerfile")], cwd=ROOT, capture_output=True, text=True)
        assert rejected.returncode != 0 and "UnresolvedExternalCommand" in rejected.stderr
        missing = self.work / "missing-sysroot"
        missing.mkdir()
        rejected = subprocess.run([TAILOR, "generate", self.relative(binary), "--sysroot", self.relative(missing),
                                   "--output", self.relative(self.work / "missing-library.Dockerfile")], cwd=ROOT, capture_output=True, text=True)
        assert rejected.returncode != 0 and any(reason in rejected.stderr for reason in ("FileNotFound", "UnresolvedLibrary"))
        assert not (self.work / "missing-library.Dockerfile").exists()
        print("PASS: dependency explanations retain call sites, package versions and unresolved calls", flush=True)
        print("PASS: missing native loader/library blocks generation", flush=True)

    def node(self):
        builder = self.pin("node:24-trixie-slim")
        runtime = self.pin("gcr.io/distroless/nodejs24-debian13:nonroot")
        run([TAILOR, "verify-runtime", "node", "--base", runtime, "--builder-base", builder])
        image = self.generate("node", f"{FIXTURES}/node", ["--entrypoint", "server.js", "--base", runtime, "--builder-base", builder])
        self.health("node", image)

    def python(self):
        builder = self.pin("python:3.13-slim-trixie")
        runtime = self.pin("gcr.io/distroless/python3-debian13:nonroot")
        run([TAILOR, "verify-runtime", "python", "--base", runtime, "--builder-base", builder])
        image = self.generate("python", f"{FIXTURES}/python", ["--entrypoint", "server", "--base", runtime, "--builder-base", builder])
        self.health("python", image)

    def java(self):
        builder = self.image("java-builder")
        run(["docker", "build", "-f", f"{FIXTURES}/java/Dockerfile.builder", "-t", builder,
             "--build-arg", "JAVA_BASE=" + self.pin("eclipse-temurin:21-jdk-noble"), "."])
        container = self.container(builder)
        jar = self.work / "application.jar"
        library = self.work / "libhealth.so"
        run(["docker", "cp", f"{container}:/out/application.jar", jar])
        run(["docker", "cp", f"{container}:/out/libhealth.so", library])
        runtime = self.pin("gcr.io/distroless/java21-debian13:nonroot")
        image = self.generate("java", self.relative(jar), ["--base", runtime, "--include", self.relative(library), "/opt/tailor/libhealth.so"])
        self.health("java", image)
        missing = self.generate("java-missing-jni", self.relative(jar), ["--base", runtime])
        failure = subprocess.run(["docker", "run", "--rm", "--network", "none", missing], capture_output=True, text=True, timeout=20)
        assert failure.returncode != 0 and "UnsatisfiedLinkError" in failure.stderr
        print("PASS: Java fixture fails startup when the JNI library is omitted", flush=True)

    def cleanup(self):
        for name in self.containers:
            subprocess.run(["docker", "rm", "-f", name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for image in reversed(self.images):
            subprocess.run(["docker", "image", "rm", "-f", image], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--case", choices=["go", "node", "python", "java"], action="append")
    args = parser.parse_args()
    suite = Suite()
    success = False
    try:
        for case in args.case or ["go", "node", "python", "java"]:
            getattr(suite, case)()
        success = True
    finally:
        reports = ROOT / ".tailor-reports"
        reports.mkdir(exist_ok=True)
        (reports / f"compatibility-{suite.nonce}.json").write_text(json.dumps({
            "success": success, "vulnerability_gate_run": False,
            "bases": suite.bases, "cases": suite.results, "work_directory": str(suite.work.relative_to(ROOT)),
        }, indent=2))
        suite.cleanup()


if __name__ == "__main__":
    main()
