FROM golang:1.25-bookworm AS builder

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /out/idp ./cmd/idp
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /out/idpctl ./cmd/idpctl

FROM debian:bookworm-slim AS runtime

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates tzdata \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /out/idp /usr/local/bin/idp
COPY --from=builder /out/idpctl /usr/local/bin/idpctl
COPY --from=builder /src/migrations ./migrations

ENV MIGRATIONS_DIR=/app/migrations

EXPOSE 8080

CMD ["idp"]

