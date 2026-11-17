# Runnable examples

The four projects expose `GET /health` on container port `8080` and use only
a language's standard library. The top-level `Makefile` compiles the Go and
Java artifacts, resolves mutable builder/runtime tags to immutable digests,
asks Tailor to generate each Dockerfile, and builds the images.

Each project contains its generated Dockerfile:

- [`go/Dockerfile`](go/Dockerfile)
- [`node/Dockerfile`](node/Dockerfile)
- [`python/Dockerfile`](python/Dockerfile)
- [`java/Dockerfile`](java/Dockerfile)

Run Docker builds from the repository root because the generated paths are
relative to the shared build context. `make examples-dockerfiles` refreshes the
files in place, skips unchanged content, and resolves the configured
builder/runtime tags to immutable digests.

Run the complete smoke test (containers are removed afterward):

```sh
make examples
```

Keep the examples running, inspect them, and stop them later:

```sh
make examples-run
make examples-check
make examples-stop
```

The services are bound to loopback ports `18080` through `18083` for Go,
Node.js, Python, and Java respectively. To scan the four completed images with
a supported vulnerability scanner:

```sh
make examples-scan SCANNER=grype
```

Use `make help` to see the individual artifact, Dockerfile, and image targets.
The default image tags and upstream base tags can all be overridden with Make
variables.
