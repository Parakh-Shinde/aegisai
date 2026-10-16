# Rebuild gosu with a current Go toolchain to avoid shipping the vulnerable
# precompiled gosu binary embedded in the upstream PostgreSQL image.
FROM golang:1.26.9-bookworm AS gosu-builder

RUN go install github.com/tianon/gosu@latest

FROM postgres:16.15-bookworm
COPY --from=gosu-builder /go/bin/gosu /usr/local/bin/gosu
