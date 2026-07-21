VERSION := $(shell tr -d '[:space:]' < VERSION)
VERSION_PACKAGE := github.com/erniebrodeur/lantern/internal/version.Value
LDFLAGS := -s -w -X $(VERSION_PACKAGE)=$(VERSION)
PLUMB := github.com/z3le/plumb/cmd/plumb@v0.1.1

.PHONY: build check check-version coverage web

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
	go test ./... -covermode=atomic -coverprofile=coverage.txt
	./scripts/check-go-coverage coverage.txt 80
	go vet ./...

coverage:
	go test ./... -covermode=atomic -coverprofile=coverage.txt
	./scripts/check-go-coverage coverage.txt 80
	go run $(PLUMB) report -out coverage.html -title "Lantern Coverage Report" coverage.txt
	go tool cover -func=coverage.txt
