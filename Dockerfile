# syntax=docker/dockerfile:1

# Build stage (runs under emulation for non-native platforms)
FROM golang:1.26-alpine AS builder

WORKDIR /app

# Install git, ca-certificates, and build tools (gcc, musl-dev for CGo/LMDB)
RUN apk add --no-cache git ca-certificates gcc musl-dev

# Copy dependency files first (for layer caching)
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build the binary with CGo enabled (required by LMDB)
RUN CGO_ENABLED=1 GOOS=linux go build -ldflags="-s -w" -o relay ./cmd/relay

# Final stage
FROM alpine:latest

RUN apk --no-cache add ca-certificates lmdb-tools

# Create a non-root group and user
RUN addgroup -S relay && adduser -S relay -G relay

WORKDIR /app

# Copy binary from builder
COPY --from=builder /app/relay /app/relay

# Create data directory for LMDB and change ownership
RUN mkdir -p /app/data/lmdb && chown -R relay:relay /app/data

# Expose the default relay port
EXPOSE 3334

# Use the non-root user
USER relay

# Define volume for persistent data
VOLUME ["/app/data"]

# Entry point
ENTRYPOINT ["/app/relay"]
