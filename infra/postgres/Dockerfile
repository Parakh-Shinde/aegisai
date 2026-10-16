# Rebuild gosu with the patched local Go toolchain rather than allowing Go to
# auto-select an older toolchain declared by a dependency.
FROM golang:1.26.9-bookworm AS gosu-builder

ENV GOTOOLCHAIN=local
RUN go install github.com/tianon/gosu@latest

FROM postgres:16.15-bookworm
COPY --from=gosu-builder /go/bin/gosu /usr/local/bin/gosu

# Run PostgreSQL without root; the official entrypoint supports this mode.
USER postgres
