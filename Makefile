SHELL := /bin/sh

TAILOR := zig-out/bin/tailor
EXAMPLE_OUT := zig-out/examples
GO_BINARY := $(EXAMPLE_OUT)/go/health-server
JAVA_CLASSES := $(EXAMPLE_OUT)/java/classes
JAVA_JAR := $(EXAMPLE_OUT)/java/health-server.jar

GO_DOCKERFILE := examples/go/Dockerfile
NODE_DOCKERFILE := examples/node/Dockerfile
PYTHON_DOCKERFILE := examples/python/Dockerfile
JAVA_DOCKERFILE := examples/java/Dockerfile

GO_IMAGE ?= tailor-example-go:local
NODE_IMAGE ?= tailor-example-node:local
PYTHON_IMAGE ?= tailor-example-python:local
JAVA_IMAGE ?= tailor-example-java:local

NODE_BUILDER_TAG ?= node:24-trixie-slim
NODE_RUNTIME_TAG ?= gcr.io/distroless/nodejs24-debian13:nonroot
PYTHON_BUILDER_TAG ?= python:3.13-slim-trixie
PYTHON_RUNTIME_TAG ?= gcr.io/distroless/python3-debian13:nonroot
JAVA_RUNTIME_TAG ?= gcr.io/distroless/java21-debian13:nonroot

DOCKER_ARCH ?= $(shell docker version --format '{{.Server.Arch}}' 2>/dev/null)
GOARCH ?= $(if $(DOCKER_ARCH),$(DOCKER_ARCH),$(shell go env GOARCH))
DOCKER_PLATFORM ?= linux/$(GOARCH)
SCANNER ?= grype
GO_BUILD_CACHE ?= $(CURDIR)/.zig-cache/go-build
ZIG_GLOBAL_CACHE_DIR ?= $(CURDIR)/.zig-cache/zig-global
ZIG_LOCAL_CACHE_DIR ?= $(CURDIR)/.zig-cache/zig-local
TAILOR_SOURCES := $(wildcard src/*.zig) build.zig build.zig.zon

.DEFAULT_GOAL := help

.PHONY: help build test examples examples-artifacts examples-dockerfiles examples-images
.PHONY: examples-start examples-run examples-check examples-smoke examples-stop examples-scan
.PHONY: FORCE scanner-integration release compatibility fuzz

FORCE:

help:
	@printf '%s\n' \
	  'make build                Build Tailor with Zig' \
	  'make test                 Run the Zig test suite' \
	  'make scanner-integration  Test real scanner gates (SCANNER=grype|trivy|osv)' \
	  'make compatibility        Test CGO/Git, native Node/Python, and Java JNI' \
	  'make fuzz                 Fuzz ELF, lockfile, and scanner-report parsers' \
	  'make release              Package four alpha archives and checksums' \
	  'make examples             Build and smoke-test all four images' \
	  'make examples-artifacts   Compile the Go binary and Java JAR' \
	  'make examples-dockerfiles Generate all Dockerfiles with pinned bases' \
	  'make examples-images      Build all four local images' \
	  'make examples-run         Start all services on ports 18080-18083' \
	  'make examples-check       Request every /health endpoint' \
	  'make examples-stop        Remove the four example containers' \
	  'make examples-scan        Scan all images (SCANNER=grype|trivy|osv)'

build: $(TAILOR)

scanner-integration: build
	ZIG_GLOBAL_CACHE_DIR="$(ZIG_GLOBAL_CACHE_DIR)" \
	  ZIG_LOCAL_CACHE_DIR="$(ZIG_LOCAL_CACHE_DIR)" python3 scripts/scanner-integration.py --scanner "$(SCANNER)"

compatibility: build
	python3 scripts/compatibility.py

FUZZ_ITERATIONS ?= 10000
fuzz:
	ZIG_GLOBAL_CACHE_DIR="$(ZIG_GLOBAL_CACHE_DIR)" \
	  ZIG_LOCAL_CACHE_DIR="$(ZIG_LOCAL_CACHE_DIR)" zig build fuzz --fuzz=$(FUZZ_ITERATIONS) --summary all

release:
	ZIG_GLOBAL_CACHE_DIR="$(ZIG_GLOBAL_CACHE_DIR)" \
	  ZIG_LOCAL_CACHE_DIR="$(ZIG_LOCAL_CACHE_DIR)" python3 scripts/release.py

test:
	ZIG_GLOBAL_CACHE_DIR="$(ZIG_GLOBAL_CACHE_DIR)" \
	  ZIG_LOCAL_CACHE_DIR="$(ZIG_LOCAL_CACHE_DIR)" zig build test

$(TAILOR): $(TAILOR_SOURCES)
	ZIG_GLOBAL_CACHE_DIR="$(ZIG_GLOBAL_CACHE_DIR)" \
	  ZIG_LOCAL_CACHE_DIR="$(ZIG_LOCAL_CACHE_DIR)" zig build -Doptimize=ReleaseSafe

$(GO_BINARY): Makefile examples/go/go.mod examples/go/main.go
	@mkdir -p "$(@D)"
	cd examples/go && GOCACHE="$(GO_BUILD_CACHE)" CGO_ENABLED=0 GOOS=linux GOARCH=$(GOARCH) \
	  go build -trimpath -ldflags='-s -w -buildid=' -o "$(CURDIR)/$@" .

$(JAVA_JAR): examples/java/src/com/example/HealthServer.java Makefile
	@mkdir -p "$(JAVA_CLASSES)"
	javac --release 21 -d "$(JAVA_CLASSES)" $<
	jar --create --file "$@" --main-class com.example.HealthServer -C "$(JAVA_CLASSES)" .

examples-artifacts: $(GO_BINARY) $(JAVA_JAR)

$(GO_DOCKERFILE): $(TAILOR) $(GO_BINARY)
	@mkdir -p "$(@D)"
	$(TAILOR) generate "$(GO_BINARY)" --output "$@"

$(NODE_DOCKERFILE): FORCE $(TAILOR) examples/node/package.json examples/node/package-lock.json examples/node/server.js
	@mkdir -p "$(@D)"
	docker pull "$(NODE_BUILDER_TAG)"
	docker pull "$(NODE_RUNTIME_TAG)"
	@builder="$$(docker image inspect --format='{{index .RepoDigests 0}}' "$(NODE_BUILDER_TAG)")"; \
	  runtime="$$(docker image inspect --format='{{index .RepoDigests 0}}' "$(NODE_RUNTIME_TAG)")"; \
	  $(TAILOR) generate examples/node --output "$@" \
	    --entrypoint server.js --builder-base "$$builder" --base "$$runtime"

$(PYTHON_DOCKERFILE): FORCE $(TAILOR) examples/python/requirements.lock examples/python/server.py
	@mkdir -p "$(@D)"
	docker pull "$(PYTHON_BUILDER_TAG)"
	docker pull "$(PYTHON_RUNTIME_TAG)"
	@builder="$$(docker image inspect --format='{{index .RepoDigests 0}}' "$(PYTHON_BUILDER_TAG)")"; \
	  runtime="$$(docker image inspect --format='{{index .RepoDigests 0}}' "$(PYTHON_RUNTIME_TAG)")"; \
	  $(TAILOR) generate examples/python --output "$@" \
	    --entrypoint server --builder-base "$$builder" --base "$$runtime"

$(JAVA_DOCKERFILE): FORCE $(TAILOR) $(JAVA_JAR)
	@mkdir -p "$(@D)"
	docker pull "$(JAVA_RUNTIME_TAG)"
	@runtime="$$(docker image inspect --format='{{index .RepoDigests 0}}' "$(JAVA_RUNTIME_TAG)")"; \
	  $(TAILOR) generate "$(JAVA_JAR)" --output "$@" --base "$$runtime"

examples-dockerfiles: $(GO_DOCKERFILE) $(NODE_DOCKERFILE) $(PYTHON_DOCKERFILE) $(JAVA_DOCKERFILE)

examples-images: examples-dockerfiles
	docker build --platform "$(DOCKER_PLATFORM)" --file "$(GO_DOCKERFILE)" --tag "$(GO_IMAGE)" .
	docker build --platform "$(DOCKER_PLATFORM)" --file "$(NODE_DOCKERFILE)" --tag "$(NODE_IMAGE)" .
	docker build --platform "$(DOCKER_PLATFORM)" --file "$(PYTHON_DOCKERFILE)" --tag "$(PYTHON_IMAGE)" .
	docker build --platform "$(DOCKER_PLATFORM)" --file "$(JAVA_DOCKERFILE)" --tag "$(JAVA_IMAGE)" .

examples-start: examples-images
	@set -eu; \
	  $(MAKE) --no-print-directory examples-stop; \
	  trap '$(MAKE) --no-print-directory examples-stop' EXIT HUP INT TERM; \
	  docker run -d --name tailor-example-go --read-only --cap-drop ALL \
	    --security-opt no-new-privileges:true --pids-limit 128 --memory 256m --cpus 1 \
	    -p 127.0.0.1:18080:8080 "$(GO_IMAGE)" >/dev/null; \
	  docker run -d --name tailor-example-node --read-only --cap-drop ALL \
	    --security-opt no-new-privileges:true --pids-limit 128 --memory 256m --cpus 1 \
	    --tmpfs /tmp:rw,noexec,nosuid,size=16m -p 127.0.0.1:18081:8080 "$(NODE_IMAGE)" >/dev/null; \
	  docker run -d --name tailor-example-python --read-only --cap-drop ALL \
	    --security-opt no-new-privileges:true --pids-limit 128 --memory 256m --cpus 1 \
	    --tmpfs /tmp:rw,noexec,nosuid,size=16m -p 127.0.0.1:18082:8080 "$(PYTHON_IMAGE)" >/dev/null; \
	  docker run -d --name tailor-example-java --read-only --cap-drop ALL \
	    --security-opt no-new-privileges:true --pids-limit 128 --memory 256m --cpus 1 \
	    --tmpfs /tmp:rw,noexec,nosuid,size=16m -p 127.0.0.1:18083:8080 "$(JAVA_IMAGE)" >/dev/null; \
	  trap - EXIT HUP INT TERM
	@printf '%s\n' 'Go=:18080 Node.js=:18081 Python=:18082 Java=:18083'

examples-run: examples-start

examples-check:
	@set -eu; \
	  check() { \
	    name="$$1"; url="$$2"; tries=0; \
	    until body="$$(curl --fail --silent --show-error "$$url")"; do \
	      tries=$$((tries + 1)); \
	      if [ "$$tries" -ge 30 ]; then echo "$$name did not become healthy" >&2; exit 1; fi; \
	      sleep 1; \
	    done; \
	    printf '%s: %s\n' "$$name" "$$body"; \
	  }; \
	  check Go http://127.0.0.1:18080/health; \
	  check Node.js http://127.0.0.1:18081/health; \
	  check Python http://127.0.0.1:18082/health; \
	  check Java http://127.0.0.1:18083/health

examples-smoke: examples-start
	@set -eu; \
	  trap '$(MAKE) --no-print-directory examples-stop' EXIT HUP INT TERM; \
	  $(MAKE) --no-print-directory examples-check

examples: examples-smoke

examples-stop:
	@docker rm -f tailor-example-go tailor-example-node tailor-example-python tailor-example-java \
	  >/dev/null 2>&1 || true

examples-scan: examples-images
	$(TAILOR) scan image "$(GO_IMAGE)" --scanner "$(SCANNER)"
	$(TAILOR) scan image "$(NODE_IMAGE)" --scanner "$(SCANNER)"
	$(TAILOR) scan image "$(PYTHON_IMAGE)" --scanner "$(SCANNER)"
	$(TAILOR) scan image "$(JAVA_IMAGE)" --scanner "$(SCANNER)"
