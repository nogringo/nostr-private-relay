# syntax=docker/dockerfile:1

# Build stage (runs on the native architecture of the runner)
FROM --platform=$BUILDPLATFORM golang:1.26-alpine AS builder

ARG TARGETOS
ARG TARGETARCH

WORKDIR /app

# Install git and ca-certificates for building
RUN apk add --no-cache git ca-certificates

# Copy dependency files first (for layer caching)
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Native Go cross-compilation for the target architecture
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -ldflags="-s -w" -o relay ./cmd/relay

# Final stage
FROM alpine:latest

RUN apk --no-cache add ca-certificates

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
