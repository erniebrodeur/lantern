VERSION := $(shell tr -d '[:space:]' < VERSION)
VERSION_PACKAGE := github.com/erniebrodeur/lantern/internal/version.Value
LDFLAGS := -s -w -X $(VERSION_PACKAGE)=$(VERSION)

.PHONY: build check check-version web

check-version:
	@test "$(VERSION)" = "$$(cd web && npm pkg get version | tr -d '\"')" || (echo "VERSION and web/package.json differ" >&2; exit 1)

web:
	npm --prefix web ci
	npm --prefix web run build
	node scripts/embed-web.mjs

build: check-version web
	mkdir -p bin
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/lantern ./cmd/lantern

check: check-version web
	go test ./...
	go vet ./...
