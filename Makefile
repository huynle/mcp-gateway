.PHONY: all build test test-integration lint fmt fmt-check migrate migrate-down migrate-status compose-up compose-down clean

GO            ?= go
GOLANGCI_LINT ?= golangci-lint
BIN            = bin/gateway
MIGRATE_BIN    = bin/migrate
VERSION       ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS        = -s -w -X main.version=$(VERSION)

all: fmt-check lint test build

## build: compile the gateway and migrate binaries into bin/
build:
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o $(BIN) ./cmd/gateway
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o $(MIGRATE_BIN) ./cmd/migrate

## test: run unit tests with the race detector
test:
	$(GO) test -race -count=1 ./...

## test-integration: run tests tagged `integration`; they need PostgreSQL and
## read GATEWAY_TEST_DATABASE_URL (skipped when unset, e.g.
## GATEWAY_TEST_DATABASE_URL=postgres://gateway:gateway-dev@localhost:15432/gateway?sslmode=disable)
## Packages run one at a time (-p 1): they share one PostgreSQL server and the
## store package migrates the primary database up and down.
test-integration:
	@if [ -z "$$GATEWAY_TEST_DATABASE_URL" ]; then \
		echo "GATEWAY_TEST_DATABASE_URL is unset; integration tests will be skipped (run 'make compose-up' and export it)"; \
	fi
	$(GO) test -race -count=1 -p 1 -tags integration -run 'Integration' ./...

## lint: run golangci-lint (install: https://golangci-lint.run/docs/welcome/install/)
lint:
	$(GOLANGCI_LINT) run --build-tags integration ./...

## fmt: rewrite sources with gofmt
fmt:
	gofmt -w .

## fmt-check: fail when any file is not gofmt-clean (used by CI)
fmt-check:
	@out="$$(gofmt -l .)"; if [ -n "$$out" ]; then echo "gofmt needed on:"; echo "$$out"; exit 1; fi

## migrate: apply pending goose migrations (internal/store/migrations) as the
## database owner/superuser named by GATEWAY_MIGRATE_DATABASE_URL (falls back
## to GATEWAY_DATABASE_URL). Runs as a pre-upgrade job; the service never
## migrates itself.
migrate:
	$(GO) run ./cmd/migrate up

## migrate-down: roll back the most recent migration
migrate-down:
	$(GO) run ./cmd/migrate down

## migrate-status: list migrations and whether they are applied
migrate-status:
	$(GO) run ./cmd/migrate status

## compose-up: start PostgreSQL (15432), dex (15556), run migrations, then the gateway (18080)
compose-up:
	docker compose up -d --build --wait

## compose-down: stop the local stack and drop its volumes
compose-down:
	docker compose down -v --remove-orphans

clean:
	rm -rf bin dist coverage.out
