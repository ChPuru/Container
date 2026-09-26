# hull — build entrypoints. Run these inside the WSL distro (Ubuntu for dev,
# hull-engine for deployment); the Windows side uses scripts/wslgo.sh.

GO        ?= go
VERSION   ?= 0.1.0-dev
COMMIT    ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
DATE      ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
PKG       := github.com/ChPuru/hull/internal/version
LDFLAGS   := -X $(PKG).Version=$(VERSION) -X $(PKG).Commit=$(COMMIT) -X $(PKG).BuildDate=$(DATE)
BIN       := bin

.PHONY: all build windows daemon cli init shim test e2e vet fmt clean distro tidy

all: build

build: daemon cli init shim

daemon:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o $(BIN)/hulld ./cmd/hulld

cli:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o $(BIN)/hull ./cmd/hull

# hull-init is the PID 1 stage that runs inside the container namespaces. It must be
# a separate static binary so the runtime never re-execs /proc/self/exe (CVE-2019-5736).
init:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GO) build -trimpath -ldflags "$(LDFLAGS) -s -w" -o $(BIN)/hull-init ./cmd/hull-init

# hull-shim supervises one container: holds its pidfd, pty and log writer, and
# survives a daemon restart.
shim:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o $(BIN)/hull-shim ./cmd/hull-shim

windows:
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o $(BIN)/hull.exe ./cmd/hull

vet:
	$(GO) vet ./...

fmt:
	$(GO) fmt ./...

tidy:
	$(GO) mod tidy

test:
	$(GO) test ./...

# The CVE-regression suite needs root and real namespaces, so it is gated behind a tag.
e2e:
	$(GO) test -tags cve -count=1 -v ./test/cve/...

distro:
	./scripts/build-distro.sh

clean:
	rm -rf $(BIN) dist
