.PHONY: all build test test-integration lint fmt fmt-check migrate compose-up compose-down clean

GO            ?= go
GOLANGCI_LINT ?= golangci-lint
BIN            = bin/gateway
VERSION       ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS        = -s -w -X main.version=$(VERSION)

all: fmt-check lint test build

## build: compile the gateway binary into bin/
build:
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o $(BIN) ./cmd/gateway

## test: run unit tests with the race detector
test:
	$(GO) test -race -count=1 ./...

## test-integration: run tests tagged `integration`; they need PostgreSQL and
## read GATEWAY_TEST_DATABASE_URL (skipped when unset, e.g.
## GATEWAY_TEST_DATABASE_URL=postgres://gateway:gateway-dev@localhost:15432/gateway?sslmode=disable)
test-integration:
	@if [ -z "$$GATEWAY_TEST_DATABASE_URL" ]; then \
		echo "GATEWAY_TEST_DATABASE_URL is unset; integration tests will be skipped (run 'make compose-up' and export it)"; \
	fi
	$(GO) test -race -count=1 -tags integration -run 'Integration' ./...

## lint: run golangci-lint (install: https://golangci-lint.run/docs/welcome/install/)
lint:
	$(GOLANGCI_LINT) run --build-tags integration ./...

## fmt: rewrite sources with gofmt
fmt:
	gofmt -w .

## fmt-check: fail when any file is not gofmt-clean (used by CI)
fmt-check:
	@out="$$(gofmt -l .)"; if [ -n "$$out" ]; then echo "gofmt needed on:"; echo "$$out"; exit 1; fi

## migrate: placeholder until the store task adds goose migrations
migrate:
	@echo "No migrations yet. The store task (Brain lutqeqg0) adds goose migrations under"
	@echo "internal/store/migrations and turns this target into 'goose -dir internal/store/migrations postgres \"\$$GATEWAY_DATABASE_URL\" up'."
	@echo "Migrations run as a pre-upgrade job; the service never migrates itself."

## compose-up: start PostgreSQL (15432), dex (15556) and the gateway (18080)
compose-up:
	docker compose up -d --build --wait

## compose-down: stop the local stack and drop its volumes
compose-down:
	docker compose down -v --remove-orphans

clean:
	rm -rf bin dist coverage.out
