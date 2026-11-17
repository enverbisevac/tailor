ARG GO_BASE=golang:1-trixie
ARG SYSROOT_BASE=debian:trixie-slim
FROM ${GO_BASE} AS build
WORKDIR /src
COPY tests/compatibility/go/go.mod tests/compatibility/go/main.go ./
RUN CGO_ENABLED=1 go build -trimpath -ldflags='-s -w' -o /application .

FROM ${SYSROOT_BASE} AS sysroot
# This is a disposable test sysroot, not a Tailor-generated runtime install.
RUN apt-get update \
    && apt-get install --yes --no-install-recommends git ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /application /fixture/application
