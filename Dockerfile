# syntax=docker/dockerfile:1

# --- build stage -----------------------------------------------------------
FROM golang:1.25-alpine AS builder

WORKDIR /src

# Cache module downloads separately from source changes.
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download

COPY . .

ARG VERSION=dev
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=linux go build -trimpath \
      -ldflags "-s -w -X main.version=${VERSION}" \
      -o /out/gateway ./cmd/gateway \
 && CGO_ENABLED=0 GOOS=linux go build -trimpath \
      -ldflags "-s -w -X main.version=${VERSION}" \
      -o /out/migrate ./cmd/migrate

# --- runtime stage ---------------------------------------------------------
# Static distroless: no shell, no package manager, runs as the non-root user
# 65532 (nonroot). CA certificates and tzdata are included for outbound
# HTTPS to vendor APIs and the key provider. The same image carries the
# migrate binary so the pre-upgrade job (`/migrate up`) runs the exact
# migrations the service expects.
FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=builder /out/gateway /gateway
COPY --from=builder /out/migrate /migrate

USER nonroot:nonroot
EXPOSE 18080

ENTRYPOINT ["/gateway"]
