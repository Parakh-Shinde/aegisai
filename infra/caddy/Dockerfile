# Rebuild Caddy with a patched Go toolchain and HTTP networking dependency.
FROM golang:1.26.9-alpine3.24 AS builder

RUN apk add --no-cache git
RUN go install github.com/caddyserver/xcaddy/cmd/xcaddy@latest

WORKDIR /src
RUN xcaddy build v2.11.7 --with golang.org/x/net@v0.60.0

# Keep the upstream runtime filesystem and configuration, replacing only its
# executable with the rebuilt binary.
FROM caddy:2.11.7-alpine
COPY --from=builder /src/caddy /usr/bin/caddy

# Run the proxy as the unprivileged user provided by the official image.
USER caddy
