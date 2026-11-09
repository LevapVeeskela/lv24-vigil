SHELL := /bin/sh

BINARY := vigil
BIN_DIR := bin
VERSION ?= $(shell tag=$$(git describe --tags --always --dirty 2>/dev/null); tag=$${tag#v}; printf '%s' "$$tag" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+' && printf '%s\n' "$$tag" || printf '0.0.0-dev\n')
COMMIT ?= $(shell git rev-parse --verify -q HEAD 2>/dev/null || echo none)
DATE ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)

LDFLAGS := -s -w \
	-X github.com/levapveeskela/lv24-vigil/internal/version.Version=$(VERSION) \
	-X github.com/levapveeskela/lv24-vigil/internal/version.Commit=$(COMMIT) \
	-X github.com/levapveeskela/lv24-vigil/internal/version.Date=$(DATE)

ifeq ($(OS),Windows_NT)
BIN_EXT := .exe
endif

.PHONY: build test lint snapshot npm-build clean

build:
	@mkdir -p $(BIN_DIR)
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/$(BINARY)$(BIN_EXT) ./cmd/vigil

test:
	go test ./...

lint:
	@unformatted="$$(gofmt -l .)"; \
	if [ -n "$$unformatted" ]; then \
		echo "gofmt needed:"; \
		echo "$$unformatted"; \
		exit 1; \
	fi
	go vet ./...

snapshot:
	goreleaser release --snapshot --clean --skip=publish -f deploy/goreleaser.yaml

npm-build:
	node npm/build.mjs --version "$(VERSION)" --dist dist --out npm-out

clean:
	rm -rf $(BIN_DIR) dist npm-out
